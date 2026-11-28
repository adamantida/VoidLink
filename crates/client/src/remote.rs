//! Тонкий клиент демона (PLAN.md 7.4): [`IpcEngine`] — [`EngineApi`] поверх
//! `tunnel_ipc::IpcClient`, и [`Endpoint`] — где искать демона.
//!
//! Поток соединения держит `IpcClient`: кладёт события в очередь, обновляет
//! кэш снимка и отправляет команды из канала. `snapshot()` отдаёт кэш — кадр
//! TUI не ждёт пайп. Потеря пайпа/сокета → «демон недоступен» (событие
//! `Disconnected`, в снимке `connected = false`), переподключение раз в
//! [`RECONNECT_EVERY`], после — Hello и свежий снимок. События до первого
//! снимка после переподключения — история кольца демона, их мы уже видели
//! (или они относятся к прошлому запуску демона) — отбрасываются; история при
//! первом подключении отдаётся отдельно ([`EngineApi::take_history`]) — для
//! лога без тостов.
//!
//! Демона нет — TUI всё равно работает: [`connect_offline`] поднимает
//! [`crate::offline::ResilientEngine`] (движка нет, конфиг правится локально,
//! очередь `ui-pending.json` уходит демону, когда тот появится).

use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use tunnel_ipc::{AckResult, ClientError, ClientKind, Conn, DaemonMsg, IpcClient};

use crate::api::{EngineApi, EngineMode, Me};
use crate::engine::{Cmd, Event};
use crate::snapshot::Snapshot;
use crate::store::Config;

/// Период переподключения к пропавшему демону.
pub const RECONNECT_EVERY: Duration = Duration::from_secs(1);
/// Сколько ждать `Welcome` и первого снимка.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Желаемый период снимков (демон шлёт и сразу после изменений).
pub const SNAPSHOTS_MS: u32 = 1000;
/// Такт потока соединения (отправка команд, проверка остановки).
const POLL: Duration = Duration::from_millis(20);
/// Версия фронтенда в `Hello`.
pub const CLIENT_VER: &str = env!("CARGO_PKG_VERSION");
/// Текст статуса при потере связи.
pub const DAEMON_DOWN: &str = "демон недоступен";

/// Адрес демона: Unix — сокет `<данные>/daemon.sock`, Windows — пайп службы.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    #[cfg(unix)]
    path: PathBuf,
    #[cfg(windows)]
    name: String,
}

impl Endpoint {
    /// Демон для каталога данных клиента. На Windows пайп у службы один на
    /// машину (каталог не важен).
    pub fn for_data_dir(dir: &Path) -> Endpoint {
        #[cfg(unix)]
        {
            Endpoint {
                path: dir.join(tunnel_ipc::transport::DEFAULT_SOCKET_FILE),
            }
        }
        #[cfg(windows)]
        {
            let _ = dir;
            Endpoint {
                name: tunnel_ipc::transport::DEFAULT_PIPE_NAME.to_string(),
            }
        }
    }

    /// Unix: сокет по произвольному пути (тесты).
    #[cfg(unix)]
    pub fn unix(path: impl Into<PathBuf>) -> Endpoint {
        Endpoint { path: path.into() }
    }

    /// Windows: пайп с произвольным именем.
    #[cfg(windows)]
    pub fn pipe(name: impl Into<String>) -> Endpoint {
        Endpoint { name: name.into() }
    }

    pub fn describe(&self) -> String {
        #[cfg(unix)]
        {
            format!("сокет {}", self.path.display())
        }
        #[cfg(windows)]
        {
            format!("пайп {}", self.name)
        }
    }

    /// Открыть соединение. `Ok(None)` — демона нет (нет сокета или пайпа,
    /// устаревший сокет после падения); прочие ошибки — демон есть, но
    /// подключиться нельзя (нет прав, пайп не от SYSTEM…).
    pub fn open(&self) -> io::Result<Option<Conn>> {
        #[cfg(unix)]
        let r = tunnel_ipc::connect(&self.path);
        #[cfg(windows)]
        let r = tunnel_ipc::connect(&self.name);
        match r {
            Ok(c) => Ok(Some(c)),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Подключение с `Hello`. `Ok(None)` — демона нет (см. [`Endpoint::open`]).
    pub fn connect(
        &self,
        kind: ClientKind,
        timeout: Duration,
    ) -> Result<Option<IpcClient>, ClientError> {
        match self.open().map_err(ClientError::Connect)? {
            None => Ok(None),
            Some(conn) => IpcClient::handshake(conn, kind, CLIENT_VER, timeout).map(Some),
        }
    }
}

/// Локальные настройки тонкого клиента (тема): `ui.json` в каталоге клиента —
/// `client.json` принадлежит демону (PLAN.md 7: «Настройки UI — ui.json»).
pub const UI_FILE: &str = "ui.json";

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UiPrefs {
    #[serde(default)]
    pub theme: String,
}

impl UiPrefs {
    pub fn load(dir: &Path) -> UiPrefs {
        std::fs::read_to_string(dir.join(UI_FILE))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join(format!("{UI_FILE}.tmp"));
        std::fs::write(&tmp, serde_json::to_string_pretty(self)?)?;
        std::fs::rename(&tmp, dir.join(UI_FILE))?;
        Ok(())
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Состояние, общее для потока соединения и фронтенда.
struct Shared {
    snap: Mutex<Arc<Snapshot>>,
    events: Mutex<VecDeque<Event>>,
    history: Mutex<Vec<Event>>,
    down: AtomicBool,
    stop: AtomicBool,
    /// Демон принимает команды конфига: снимок полный (у `Waiting` конфиг есть
    /// и правки применяются), а не заглушка `{"engine": null, "error": …}`.
    editable: AtomicBool,
}

impl Shared {
    fn push(&self, ev: Event) {
        lock(&self.events).push_back(ev);
    }

    fn set_down(&self) {
        if self.down.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut snap = lock(&self.snap);
        let mut s = (**snap).clone();
        s.meta.connected = false;
        *snap = Arc::new(s);
        drop(snap);
        self.push(Event::Disconnected(DAEMON_DOWN.into()));
    }
}

/// Движок в демоне, по IPC.
pub struct IpcEngine {
    me: Me,
    shared: Arc<Shared>,
    cmds: Mutex<Sender<Cmd>>,
    worker: Option<JoinHandle<()>>,
    /// Каталог `ui.json` (тема); `None` — тема не сохраняется.
    ui_dir: Option<PathBuf>,
}

/// Принимает ли демон правки конфига: полный снимок (`Snapshot`) — да,
/// заглушка `{"engine": null, "error": …}` — нет (правки некуда применить:
/// конфиг демона не читается).
fn snapshot_editable(v: &serde_json::Value) -> bool {
    v.get("engine").is_none()
}

/// Снимок из JSON демона. Демон без движка (служба не поднялась, TUN не
/// создался, нет сервера) шлёт `{"engine": null, "error": …}` — это не ошибка,
/// а офлайн-состояние: TUI открывается и правит конфиг сам.
fn parse_snapshot(v: serde_json::Value) -> Result<Snapshot, String> {
    if v.get("engine").is_some() {
        let why = v
            .get("error")
            .and_then(|e| e.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("движок не запущен");
        let mut s = Snapshot::default();
        s.meta.connected = false;
        s.meta.offline = true;
        s.meta.offline_reason = Some(why.to_string());
        return Ok(s);
    }
    serde_json::from_value(v).map_err(|e| format!("неверный снимок демона: {e}"))
}

/// Офлайн-режим TUI: демона (или движка в нём) нет. `cfg` — общий
/// `Arc<Mutex<Config>>` с вызывающим: правки не теряются; `identity` — для
/// friend code в шапке. Причина офлайна неизвестна (её уточнит фон).
pub fn connect_offline(
    dir: &Path,
    cfg: Arc<Mutex<Config>>,
    identity: tunnel_protocol::Identity,
) -> Result<crate::offline::ResilientEngine> {
    connect_offline_with_reason(dir, cfg, identity, None)
}

/// То же, но с готовой причиной офлайна (демон есть, движка в нём нет;
/// демон не отвечает) — она сразу попадает в снимок и лог.
pub fn connect_offline_with_reason(
    dir: &Path,
    cfg: Arc<Mutex<Config>>,
    identity: tunnel_protocol::Identity,
    reason: Option<String>,
) -> Result<crate::offline::ResilientEngine> {
    Ok(crate::offline::ResilientEngine::new(
        dir, cfg, identity, reason,
    ))
}

/// `Subscribe` и чтение до первого снимка: события до него — история кольца.
/// Третий элемент — принимает ли демон команды конфига (см.
/// [`IpcEngine::editable`]).
pub(crate) fn subscribe(
    c: &mut IpcClient,
    timeout: Duration,
) -> Result<(Snapshot, Vec<Event>, bool), String> {
    c.subscribe(SNAPSHOTS_MS).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + timeout;
    let mut history = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("демон не прислал снимок".into());
        }
        match c.recv(Some(left)).map_err(|e| e.to_string())? {
            DaemonMsg::Event { ev, .. } => {
                if let Ok(e) = serde_json::from_value::<Event>(ev) {
                    history.push(e);
                }
            }
            DaemonMsg::Snapshot { snap, .. } => {
                let editable = snapshot_editable(&snap);
                return Ok((parse_snapshot(snap)?, history, editable));
            }
            DaemonMsg::Shutdown { reason } => return Err(format!("демон завершается: {reason}")),
            _ => {}
        }
    }
}

impl IpcEngine {
    /// Подключиться к демону: Hello, подписка, первый снимок. Ошибка —
    /// без фолбэка на embedded (два движка с одной identity выбивали бы друг
    /// друга с сервера). Демона нет — тоже ошибка.
    pub fn connect(ep: &Endpoint, ui_dir: Option<PathBuf>) -> Result<IpcEngine> {
        let mut c = match ep.connect(ClientKind::Tui, HANDSHAKE_TIMEOUT) {
            Ok(Some(c)) => c,
            Ok(None) => bail!("демон не запущен ({})", ep.describe()),
            Err(e) => bail!("{e}"),
        };
        let me = Me::from_json(c.me())
            .ok_or_else(|| anyhow!("демон не сообщил identity (me: {})", c.me()))?;
        let (snap, history, editable) =
            subscribe(&mut c, HANDSHAKE_TIMEOUT).map_err(|e| anyhow!(e))?;
        let shared = Arc::new(Shared {
            snap: Mutex::new(Arc::new(snap)),
            events: Mutex::new(VecDeque::new()),
            history: Mutex::new(history),
            down: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            editable: AtomicBool::new(editable),
        });
        let (tx, rx) = mpsc::channel();
        let (sh, ep2, me2) = (shared.clone(), ep.clone(), me.clone());
        let worker = std::thread::Builder::new()
            .name("ipc-engine".into())
            .spawn(move || worker(c, ep2, me2, sh, rx))?;
        Ok(IpcEngine {
            me,
            shared,
            cmds: Mutex::new(tx),
            worker: Some(worker),
            ui_dir,
        })
    }

    /// Принимает ли демон команды конфига. `false` — демон прислал заглушку
    /// `{"engine": null, "error": …}` (битый `client.json`): править конфиг
    /// через него нельзя, TUI работает офлайн на своей копии.
    pub fn editable(&self) -> bool {
        self.shared.editable.load(Ordering::SeqCst)
    }
}

/// Поток соединения: команды → демон, сообщения демона → кэш и очередь;
/// разрыв — «демон недоступен» и переподключение.
fn worker(c: IpcClient, ep: Endpoint, me: Me, sh: Arc<Shared>, cmds: Receiver<Cmd>) {
    let mut conn = Some(c);
    let mut next_try = Instant::now();
    loop {
        if sh.stop.load(Ordering::SeqCst) {
            if let Some(c) = conn.take() {
                c.bye();
            }
            return;
        }
        let Some(c) = conn.as_mut() else {
            // Команды, пришедшие без связи, не отправлены — сказать.
            loop {
                match cmds.try_recv() {
                    Ok(_) => sh.push(Event::Error(format!(
                        "{DAEMON_DOWN} — команда не отправлена"
                    ))),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return,
                }
            }
            if Instant::now() < next_try {
                std::thread::sleep(POLL);
                continue;
            }
            next_try = Instant::now() + RECONNECT_EVERY;
            if let Ok(Some(mut c)) = ep.connect(ClientKind::Tui, HANDSHAKE_TIMEOUT) {
                if Me::from_json(c.me()).as_ref() != Some(&me) {
                    // Демон поднялся с другой identity: шапка, copy code и
                    // owner_is_me считались бы по чужому ключу. Не подписываемся
                    // вовсе — показываем «нет связи», пока TUI не перезапустят
                    // (аудит 2026-11, FRNT-1).
                    sh.down.store(true, Ordering::SeqCst);
                    sh.push(Event::Error(
                        "демон работает с другой identity — перезапустите TUI".into(),
                    ));
                    continue;
                }
                if let Ok((snap, _seen, editable)) = subscribe(&mut c, HANDSHAKE_TIMEOUT) {
                    *lock(&sh.snap) = Arc::new(snap);
                    sh.editable.store(editable, Ordering::SeqCst);
                    sh.down.store(false, Ordering::SeqCst);
                    sh.push(Event::Notice("связь с демоном восстановлена".into()));
                    conn = Some(c);
                }
            }
            continue;
        };
        let mut lost = false;
        loop {
            match cmds.try_recv() {
                Ok(Cmd::Quit) => {}
                Ok(cmd) => {
                    let sent = serde_json::to_value(&cmd)
                        .map_err(|e| e.to_string())
                        .and_then(|v| c.send_req(v).map_err(|e| e.to_string()));
                    if sent.is_err() {
                        sh.push(Event::Error(format!(
                            "{DAEMON_DOWN} — команда не отправлена"
                        )));
                        lost = true;
                        break;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    sh.stop.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
        if !lost {
            match c.recv(Some(POLL)) {
                Ok(DaemonMsg::Event { ev, .. }) => {
                    if let Ok(e) = serde_json::from_value::<Event>(ev) {
                        sh.push(e);
                    }
                }
                Ok(DaemonMsg::Snapshot { snap, .. }) => {
                    let editable = snapshot_editable(&snap);
                    if let Ok(s) = parse_snapshot(snap) {
                        *lock(&sh.snap) = Arc::new(s);
                        sh.editable.store(editable, Ordering::SeqCst);
                    }
                }
                Ok(DaemonMsg::Ack {
                    result: AckResult::Err(e),
                    ..
                }) => sh.push(Event::Error(e)),
                Ok(DaemonMsg::Shutdown { reason }) => {
                    sh.push(Event::Notice(format!("демон завершается: {reason}")));
                    lost = true;
                }
                Ok(_) => {}
                Err(ClientError::Timeout) => {}
                Err(_) => lost = true,
            }
        }
        if lost {
            conn = None;
            sh.set_down();
            next_try = Instant::now() + RECONNECT_EVERY;
        }
    }
}

impl EngineApi for IpcEngine {
    fn snapshot(&self) -> Arc<Snapshot> {
        lock(&self.shared.snap).clone()
    }

    fn poll_events(&self) -> Vec<Event> {
        lock(&self.shared.events).drain(..).collect()
    }

    fn send(&self, cmd: Cmd) -> Result<()> {
        // Закрытие фронтенда туннель не трогает.
        if matches!(cmd, Cmd::Quit) {
            return Ok(());
        }
        if self.unavailable() {
            bail!("{DAEMON_DOWN} — команда не отправлена");
        }
        lock(&self.cmds)
            .send(cmd)
            .map_err(|_| anyhow!("{DAEMON_DOWN} — команда не отправлена"))
    }

    fn me(&self) -> &Me {
        &self.me
    }

    fn mode(&self) -> EngineMode {
        EngineMode::Remote
    }

    fn unavailable(&self) -> bool {
        self.shared.down.load(Ordering::SeqCst)
    }

    fn take_history(&self) -> Vec<Event> {
        std::mem::take(&mut *lock(&self.shared.history))
    }

    fn save_theme(&self, theme: &str) -> Result<()> {
        match &self.ui_dir {
            Some(d) => UiPrefs {
                theme: theme.to_string(),
            }
            .save(d),
            None => Ok(()),
        }
    }

    fn save_adapter(&self, _name: &str, _dll: &str) -> Result<()> {
        bail!("адаптер и dll задаёт демон (служба), а не TUI")
    }
}

impl Drop for IpcEngine {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_prefs_в_файле() {
        let d = std::env::temp_dir().join(format!(
            "vl-ui-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        assert_eq!(UiPrefs::load(&d), UiPrefs::default());
        UiPrefs {
            theme: "light".into(),
        }
        .save(&d)
        .unwrap();
        assert_eq!(UiPrefs::load(&d).theme, "light");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn снимок_без_движка_это_офлайн_состояние() {
        // Демон без движка — не ошибка: TUI открывается офлайном с причиной.
        let s = parse_snapshot(serde_json::json!({"engine": null})).unwrap();
        assert!(s.meta.offline);
        assert!(!s.meta.connected);
        assert_eq!(s.meta.offline_reason.as_deref(), Some("движок не запущен"));
        let s = parse_snapshot(serde_json::json!({"engine": null, "error": "нет TUN"})).unwrap();
        assert!(s.meta.offline);
        assert_eq!(s.meta.offline_reason.as_deref(), Some("нет TUN"));
        let s = serde_json::to_value(Snapshot::default()).unwrap();
        assert_eq!(parse_snapshot(s).unwrap(), Snapshot::default());
    }

    #[test]
    fn заглушка_демона_без_движка_не_редактируется() {
        // `Waiting` шлёт полный снимок (конфиг есть, правки применяются),
        // `Failed` — заглушку `{"engine": null, "error"}`: править нечего.
        assert!(!snapshot_editable(&serde_json::json!({"engine": null})));
        assert!(!snapshot_editable(
            &serde_json::json!({"engine": null, "error": "нет TUN"})
        ));
        assert!(snapshot_editable(
            &serde_json::to_value(Snapshot::default()).unwrap()
        ));
        // Живой снимок демона (с конфигом) — тоже редактируемый.
        let mut live = Snapshot::default();
        live.meta.connected = true;
        assert!(snapshot_editable(&serde_json::to_value(live).unwrap()));
    }

    // ---------- поддельный демон на Unix-сокете ----------

    #[cfg(unix)]
    mod fake {
        use super::super::*;
        use crate::snapshot::{CfgServer, GroupSnap, MetaSnap};
        use std::os::unix::fs::PermissionsExt;
        use tunnel_ipc::{ClientMsg, Listener, read_msg, write_msg};

        /// Свежий приватный каталог (0700) под сокет: `check_private_dir`
        /// требует, чтобы каталог сокета принадлежал нам и был закрыт от
        /// группы и остальных — `/tmp` (0777, root) не подходит.
        fn private_dir(tag: &str) -> PathBuf {
            let d = std::env::temp_dir().join(format!(
                "vlf-{tag}-{}-{}",
                std::process::id(),
                rand::random::<u16>()
            ));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir(&d).unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
            d
        }

        /// Демон, который отвечает `Welcome`, на `Subscribe` — историей и
        /// снимком, на `Req` — `Ack` (Err для `Join`) и событием `Notice`.
        pub struct FakeDaemon {
            pub path: PathBuf,
            dir: PathBuf,
            pub snap: Arc<Mutex<Snapshot>>,
            conns: Arc<Mutex<Vec<Conn>>>,
            pub reqs: Arc<Mutex<Vec<serde_json::Value>>>,
        }

        pub fn snapshot(name: &str) -> Snapshot {
            Snapshot {
                groups: vec![GroupSnap {
                    gid: 7,
                    name: "игроки".into(),
                    owner: [1; 32],
                    private: false,
                    my_ip: 0x6442_0002,
                    joined_s_ago: 5,
                    federated: false,
                    detached: false,
                    members: Vec::new(),
                }],
                meta: MetaSnap {
                    connected: true,
                    server: "127.0.0.1:5599".into(),
                    uptime_s: 3,
                    ..MetaSnap::default()
                },
                cfg: crate::snapshot::CfgView {
                    name: name.into(),
                    servers: vec![CfgServer {
                        addr: "127.0.0.1:5599".into(),
                        pubkey: "ab".repeat(32),
                        label: "дом".into(),
                    }],
                    ..Default::default()
                },
                ..Snapshot::default()
            }
        }

        impl FakeDaemon {
            pub fn start(tag: &str) -> FakeDaemon {
                // Короткий путь: лимит sun_path ~104 байта на macOS.
                let dir = private_dir(tag);
                let path = dir.join("d.sock");
                let listener = Listener::bind(&path).unwrap();
                let d = FakeDaemon {
                    path,
                    dir,
                    snap: Arc::new(Mutex::new(snapshot("alpha"))),
                    conns: Arc::new(Mutex::new(Vec::new())),
                    reqs: Arc::new(Mutex::new(Vec::new())),
                };
                let (snap, conns, reqs) = (d.snap.clone(), d.conns.clone(), d.reqs.clone());
                std::thread::spawn(move || {
                    while let Ok(c) = listener.accept() {
                        conns.lock().unwrap().push(c.try_clone().unwrap());
                        let (snap, reqs) = (snap.clone(), reqs.clone());
                        std::thread::spawn(move || serve(c, snap, reqs));
                    }
                });
                d
            }

            /// Оборвать все соединения (демон «упал», сокет остался).
            pub fn kill_conns(&self) {
                for c in self.conns.lock().unwrap().drain(..) {
                    let _ = c.shutdown();
                }
            }

            pub fn endpoint(&self) -> Endpoint {
                Endpoint::unix(&self.path)
            }
        }

        impl Drop for FakeDaemon {
            fn drop(&mut self) {
                self.kill_conns();
                let _ = std::fs::remove_file(&self.path);
                let _ = std::fs::remove_dir_all(&self.dir);
            }
        }

        fn serve(
            mut c: Conn,
            snap: Arc<Mutex<Snapshot>>,
            reqs: Arc<Mutex<Vec<serde_json::Value>>>,
        ) {
            let mut seq = 0u64;
            let me = Me {
                my_pub: [9; 32],
                my_code: "TUN-FAKE".into(),
            };
            loop {
                let Ok(m) = read_msg::<_, ClientMsg>(&mut c) else {
                    return;
                };
                let reply: Vec<DaemonMsg> = match m {
                    ClientMsg::Hello { .. } => {
                        vec![DaemonMsg::Welcome {
                            proto: tunnel_ipc::PROTO_VERSION,
                            daemon_ver: "t".into(),
                            me: me.to_json(),
                        }]
                    }
                    ClientMsg::Subscribe { .. } => {
                        seq += 1;
                        let hist =
                            serde_json::to_value(Event::Notice("старое событие".into())).unwrap();
                        let s = serde_json::to_value(&*snap.lock().unwrap()).unwrap();
                        vec![
                            DaemonMsg::Event { seq, ev: hist },
                            DaemonMsg::Snapshot { seq, snap: s },
                        ]
                    }
                    ClientMsg::Req { id, cmd } => {
                        reqs.lock().unwrap().push(cmd.clone());
                        seq += 1;
                        let result = if cmd.get("Join").is_some() {
                            AckResult::Err("нет сервера".into())
                        } else {
                            AckResult::Ok
                        };
                        let ev =
                            serde_json::to_value(Event::Notice(format!("принято: {cmd}"))).unwrap();
                        vec![DaemonMsg::Ack { id, result }, DaemonMsg::Event { seq, ev }]
                    }
                    ClientMsg::Bye => return,
                };
                for r in reply {
                    if write_msg(&mut c, &r).is_err() {
                        return;
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    fn eventually(what: &str, mut f: impl FnMut() -> bool) {
        let t0 = Instant::now();
        while !f() {
            assert!(
                t0.elapsed() < Duration::from_secs(10),
                "не дождались: {what}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(unix)]
    #[test]
    fn ipc_engine_снимок_события_история_ack() {
        let d = fake::FakeDaemon::start("a");
        let eng = IpcEngine::connect(&d.endpoint(), None).unwrap();
        assert_eq!(eng.mode(), EngineMode::Remote);
        assert_eq!(eng.me().my_code, "TUN-FAKE");
        assert_eq!(eng.snapshot().cfg.name, "alpha");
        assert_eq!(eng.snapshot().groups[0].name, "игроки");
        // История кольца — отдельно и один раз, не в очереди событий.
        assert!(matches!(&eng.take_history()[..], [Event::Notice(n)] if n == "старое событие"));
        assert!(eng.take_history().is_empty());
        assert!(eng.poll_events().is_empty());

        // Команда → Req; событие демона — в очередь; Ack Err — Event::Error.
        eng.send(Cmd::RefreshList).unwrap();
        eng.send(Cmd::Join(7)).unwrap();
        let mut got = Vec::new();
        eventually("Notice и Error", || {
            got.extend(eng.poll_events());
            got.iter()
                .any(|e| matches!(e, Event::Error(m) if m == "нет сервера"))
                && got.iter().filter(|e| matches!(e, Event::Notice(_))).count() == 2
        });
        // Quit не уходит демону: закрытие фронтенда туннель не трогает.
        eng.send(Cmd::Quit).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let reqs = d.reqs.lock().unwrap().clone();
        assert_eq!(
            reqs,
            vec![
                serde_json::json!("RefreshList"),
                serde_json::json!({"Join": 7})
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn ipc_engine_потеря_демона_и_переподключение() {
        let d = fake::FakeDaemon::start("b");
        let eng = IpcEngine::connect(&d.endpoint(), None).unwrap();
        assert!(!eng.unavailable());
        *d.snap.lock().unwrap() = fake::snapshot("после рестарта");
        d.kill_conns();
        // Разрыв: «демон недоступен», связь в снимке — нет.
        let mut got = Vec::new();
        eventually("Disconnected", || {
            got.extend(eng.poll_events());
            got.iter()
                .any(|e| matches!(e, Event::Disconnected(r) if r == DAEMON_DOWN))
        });
        // Переподключение (раз в секунду) — Hello, свежий снимок, без истории.
        eventually("связь восстановлена", || {
            got.extend(eng.poll_events());
            got.iter()
                .any(|e| matches!(e, Event::Notice(n) if n.contains("восстановлена")))
        });
        assert!(!eng.unavailable());
        assert_eq!(eng.snapshot().cfg.name, "после рестарта");
        assert!(eng.snapshot().meta.connected);
        assert!(
            !got.iter()
                .any(|e| matches!(e, Event::Notice(n) if n == "старое событие")),
            "история после переподключения"
        );
        // Команды снова доходят.
        eng.send(Cmd::RefreshList).unwrap();
        eventually(
            "команда после переподключения",
            || d.reqs.lock().unwrap().len() == 1,
        );
    }

    #[cfg(unix)]
    #[test]
    fn ipc_engine_без_демона_отказ_команд() {
        let d = fake::FakeDaemon::start("c");
        let eng = IpcEngine::connect(&d.endpoint(), None).unwrap();
        // Демон пропал совсем: соединения и сокет.
        let path = d.path.clone();
        drop(d);
        eventually("демон недоступен", || eng.unavailable());
        assert!(!eng.snapshot().meta.connected);
        assert!(
            eng.send(Cmd::RefreshList)
                .unwrap_err()
                .to_string()
                .contains(DAEMON_DOWN)
        );
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn tui_рисует_снимок_демона() {
        use crate::tui::app::App;
        let d = fake::FakeDaemon::start("t");
        let eng = IpcEngine::connect(&d.endpoint(), None).unwrap();
        let mut app = App::new(
            eng.me().my_pub,
            &eng.me().my_code,
            &crate::store::Config::default(),
        );
        app.sync(&eng);
        assert_eq!(app.my_name, "alpha");
        assert!(app.groups.iter().any(|g| g.name == "игроки" && g.mine));
        // История — в лог, без тостов.
        assert!(app.log.iter().any(|l| l.text == "старое событие"));
        assert!(app.toasts.is_empty(), "история не тостится");
        let text = render(&app, 140, 40);
        assert!(text.contains("игроки"), "нет группы из снимка:\n{text}");
        assert!(text.contains("демон"), "в шапке нет режима:\n{text}");
        // Пилюля связи в шапке (docs/CLIENT.md, раздел TUI): `● в сети`, а не «подключено».
        assert!(text.contains("● в сети"), "{text}");
        // Демон пропал — в шапке «демон недоступен».
        d.kill_conns();
        drop(d);
        eventually("демон недоступен", || eng.unavailable());
        app.sync(&eng);
        assert!(app.daemon_down);
        let text = render(&app, 140, 40);
        assert!(text.contains("демон недоступен"), "{text}");
    }

    #[cfg(unix)]
    fn render(app: &crate::tui::app::App, w: u16, h: u16) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::tui::ui::draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..h {
            for x in 0..w {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[cfg(unix)]
    #[test]
    fn нет_демона_нет_соединения() {
        let ep =
            Endpoint::unix(std::env::temp_dir().join(format!("vl-nosock-{}", std::process::id())));
        assert!(ep.open().unwrap().is_none());
        assert!(IpcEngine::connect(&ep, None).is_err());
    }
}
