//! Офлайн-режим TUI: движка нет, но интерфейс работает (этап 9, §3.8).
//!
//! [`ResilientEngine`] — реализация [`EngineApi`] на случай, когда демона нет
//! (или он есть, но без движка: TUN не поднялся, сервер недоступен). Режим
//! [`EngineMode::Offline`]:
//!
//! * конфиг — общий `Arc<Mutex<Config>>` с вызывающим: правки применяются
//!   сразу и сохраняются в `client.json` (ничего не теряется);
//! * каждая правка кладётся в очередь `ui-pending.json` (атомарная запись) —
//!   она переживает перезапуск TUI;
//! * фоновый поток раз в [`RECONNECT_EVERY`] пробует демона; появился живой
//!   движок — очередь отправляется по порядку, успешные команды из неё
//!   убираются;
//! * проба серверов (`Cmd::ProbeServer`) работает и без движка — своим
//!   сокетом ([`crate::probe::ProbeState`]), результат приходит событием;
//! * сетевые команды (группы, приглашения) отклоняются сразу: без движка их
//!   некому выполнить.
//!
//! Демон с *живым* движком, найденный при старте, — это обычный тонкий клиент
//! ([`crate::remote::IpcEngine`]); [`ResilientEngine`] начинает офлайном и
//! переключается на него сам, когда тот появится.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use tunnel_protocol as proto;

use crate::api::{EngineApi, EngineMode, Me};
use crate::engine::{self, Cmd, Event};
use crate::probe::ProbeState;
use crate::remote::{DAEMON_DOWN, Endpoint, IpcEngine, UiPrefs};
use crate::snapshot::{CfgServer, CfgView, MetaSnap, Snapshot};
use crate::store::{self, Config, StoredServer};

/// Файл очереди офлайн-правок (в каталоге данных клиента).
pub const PENDING_FILE: &str = "ui-pending.json";
/// Как часто пробуем демона (и проверяем живость найденного).
pub const RECONNECT_EVERY: Duration = Duration::from_millis(500);
/// Текст отказа сетевой команде без движка.
pub const NO_ENGINE: &str = "движка нет — команда не отправлена (офлайн-режим)";
/// Адрес-заглушка «текущего сервера» для `engine::check_cfg_cmd` без движка.
const NO_CURRENT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------- очередь

/// Содержимое `ui-pending.json`: команды в порядке отправки.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PendingFile {
    #[serde(default = "one")]
    v: u32,
    #[serde(default)]
    commands: Vec<Cmd>,
}

fn one() -> u32 {
    1
}

/// Прочитать очередь (битый/чужой файл — пустая очередь, без паники).
fn load_pending(dir: &Path) -> VecDeque<Cmd> {
    let raw = match std::fs::read(dir.join(PENDING_FILE)) {
        Ok(raw) => raw,
        Err(_) => return VecDeque::new(),
    };
    match serde_json::from_slice::<PendingFile>(&raw) {
        Ok(p) => p.commands.into(),
        Err(_) => VecDeque::new(),
    }
}

/// Записать очередь атомарно (tmp + rename) или удалить файл, если она пуста.
fn save_pending(dir: &Path, cmds: &VecDeque<Cmd>) {
    let path = dir.join(PENDING_FILE);
    if cmds.is_empty() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    let _ = std::fs::create_dir_all(dir);
    let file = PendingFile {
        v: 1,
        commands: cmds.iter().cloned().collect(),
    };
    let Ok(raw) = serde_json::to_vec_pretty(&file) else {
        return;
    };
    let tmp = dir.join(format!("{PENDING_FILE}.tmp"));
    if std::fs::write(&tmp, raw).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

// ---------------------------------------------------------------- состояние

struct Shared {
    dir: PathBuf,
    /// Конфиг: тот же `Arc`, что у вызывающего (TUI видит правки сразу).
    cfg: Arc<Mutex<Config>>,
    save: Arc<dyn Fn(&Config) + Send + Sync>,
    me: Me,
    stop: AtomicBool,
    /// Демон, если он есть (даже без движка: в состоянии «нет сервера» или
    /// после неудачного запуска он сам применяет правки конфига).
    remote: Mutex<Option<Arc<IpcEngine>>>,
    /// В демоне живой движок (`remote` без движка — всё ещё офлайн).
    live: AtomicBool,
    /// Очередь на применение демоном.
    pending: Mutex<VecDeque<Cmd>>,
    /// События офлайн-режима (Notice/Error/Disconnected) + пробы.
    events: Mutex<VecDeque<Event>>,
    /// История кольца демона на момент подключения — один раз, в лог без
    /// тостов (`EngineApi::take_history`).
    history: Mutex<Vec<Event>>,
    /// Почему офлайн (нет демона / демон без движка).
    reason: Mutex<Option<String>>,
    /// Пробы серверов: свой сокет и поток, движок не нужен.
    probes: ProbeState,
    /// Просили переподключиться сейчас (`Cmd::Reconnect`).
    retry_now: AtomicBool,
}

impl Shared {
    fn remote(&self) -> Option<Arc<IpcEngine>> {
        lock(&self.remote).clone()
    }

    fn live(&self) -> bool {
        self.live.load(Ordering::SeqCst)
    }

    fn push(&self, ev: Event) {
        lock(&self.events).push_back(ev);
    }

    fn drain(&self) -> Vec<Event> {
        lock(&self.events).drain(..).collect()
    }

    fn set_reason(&self, why: Option<String>) {
        *lock(&self.reason) = why;
    }

    fn pending_len(&self) -> usize {
        lock(&self.pending).len()
    }

    /// Конфиг по значению (для снимка/сравнения).
    fn cfg(&self) -> Config {
        lock(&self.cfg).clone()
    }

    fn persist_pending(&self) {
        let q = lock(&self.pending);
        save_pending(&self.dir, &q);
    }

    /// Сохранить конфиг в client.json.
    fn persist_cfg(&self, cfg: &Config) {
        (self.save)(cfg);
    }

    /// Проба сервера: свой сокет/поток, движок не нужен.
    fn probe_local(&self, addr: SocketAddr) -> Result<()> {
        let pinned = pinned_key(&self.cfg, addr);
        self.probes
            .start_probe(addr, pinned, now_ms())
            .map_err(|e| anyhow!("проба {addr}: {e:#}"))
    }

    /// Снимок офлайн-состояния (TUI рисует его как обычный).
    fn snapshot(&self) -> Arc<Snapshot> {
        if let Some(r) = self.remote() {
            let mut s = (*r.snapshot()).clone();
            let n = self.pending_len() as u32;
            if n > 0 {
                s.meta.pending_edits = n;
            }
            if !self.live() {
                s.meta.offline = true;
                if s.meta.offline_reason.is_none() {
                    s.meta.offline_reason = lock(&self.reason).clone();
                }
            }
            return Arc::new(s);
        }
        let cfg = self.cfg();
        let mut s = Snapshot {
            cfg: CfgView::from_cfg(&cfg),
            ..Snapshot::default()
        };
        let mut meta = MetaSnap {
            connected: false,
            offline: true,
            offline_reason: lock(&self.reason).clone(),
            pending_edits: self.pending_len() as u32,
            ..MetaSnap::default()
        };
        meta.server = cfg.active_server.clone();
        meta.server_label = cfg
            .servers
            .iter()
            .find(|s| s.addr == cfg.active_server)
            .map(|s| s.label.clone())
            .unwrap_or_default();
        s.meta = meta;
        Arc::new(s)
    }

    /// Показать причину офлайна, только если она изменилась (без спама).
    fn notice_reason(&self, why: Option<String>, toast: bool) {
        let changed = *lock(&self.reason) != why;
        self.set_reason(why.clone());
        if !changed {
            return;
        }
        if let Some(w) = why
            && toast
        {
            self.push(Event::Notice(format!("офлайн: {w}")));
        }
    }

    /// Отвалиться от демона: очередь остаётся, дальше — офлайн.
    fn drop_remote(&self, why: &str) {
        let was = lock(&self.remote).take();
        self.live.store(false, Ordering::SeqCst);
        if was.is_none() {
            return;
        }
        drop(was);
        self.set_reason(Some(why.to_string()));
        self.push(Event::Disconnected(why.to_string()));
        self.push(Event::Notice(format!(
            "{why} — правки копятся в очереди (ui-pending.json)"
        )));
    }

    /// Отправить очередь демону по порядку; успешные убрать.
    fn flush(&self, eng: &dyn EngineApi) {
        loop {
            let cmd = match lock(&self.pending).front() {
                Some(c) => c.clone(),
                None => break,
            };
            if eng.send(cmd.clone()).is_err() {
                // Демон пропал на середине: остаток очереди ждёт следующего.
                self.persist_pending();
                return;
            }
            lock(&self.pending).pop_front();
            self.persist_pending();
        }
        self.persist_pending();
    }

    /// Принять демона (с движком или без): история — в лог, очередь — по
    /// порядку. Демон в состоянии «нет сервера» сам применяет правки конфига
    /// и поднимает движок по `AddServer`.
    fn adopt(&self, eng: IpcEngine) {
        let snap = (*eng.snapshot()).clone();
        let live = !snap.meta.offline;
        let reason = snap.meta.offline_reason.clone();
        let history = eng.take_history();
        let same = {
            let local = self.cfg();
            CfgView::from_cfg(&local) == snap.cfg
        };
        let eng = Arc::new(eng);
        *lock(&self.remote) = Some(eng.clone());
        self.live.store(live, Ordering::SeqCst);
        self.set_reason(if live { None } else { reason.clone() });
        // История кольца демона — отдельно (`take_history`): TUI разберёт её
        // без тостов и окон, как у тонкого клиента.
        lock(&self.history).extend(history);
        if !live {
            self.push(Event::Notice(match &reason {
                Some(r) => format!("демон доступен, движок не запущен: {r}"),
                None => "демон доступен, движок не запущен".into(),
            }));
        }
        if same {
            if !lock(&self.pending).is_empty() {
                lock(&self.pending).clear();
                self.persist_pending();
                self.push(Event::Notice(
                    "демон поднялся с нашим конфигом — отложенные правки уже применены".into(),
                ));
            } else if live {
                self.push(Event::Notice("демон доступен".into()));
            }
            return;
        }
        let n = self.pending_len();
        if n > 0 && live {
            self.push(Event::Notice(format!(
                "демон доступен — применяем отложенные правки ({n})"
            )));
        }
        self.flush(eng.as_ref());
        // Серверы, добавленные локально (`%APPDATA%`), досылаем демону: у
        // службы и `console` свой каталог данных, иначе они «терялись».
        if live {
            for notice in migrate_servers(eng.as_ref(), &self.cfg().servers) {
                self.push(Event::Notice(notice));
            }
        }
    }

    /// Правка конфига без движка: применить, сохранить, поставить в очередь.
    fn apply_local(&self, cmd: Cmd) -> Result<()> {
        if let Some(e) = engine::check_cfg_cmd(&lock(&self.cfg), NO_CURRENT, &cmd) {
            return Err(anyhow!(e));
        }
        let notice = match &cmd {
            Cmd::SetName(_) => "имя сохранено".to_string(),
            Cmd::SetStatus(_) => "статус сохранён".to_string(),
            Cmd::SetInvisible(on) => format!("невидимка: {}", if *on { "вкл" } else { "выкл" }),
            Cmd::ToggleAutojoin(gid) => format!("автовход: группа {gid}"),
            Cmd::AddFriend { alias, .. } => format!("друг добавлен: {alias}"),
            Cmd::DelFriend(_) => "друг удалён".to_string(),
            Cmd::SetAlias { alias, .. } => format!("alias: {alias}"),
            Cmd::AddServer { addr, .. } => format!("сервер добавлен: {addr}"),
            Cmd::DelServer { idx } => format!("сервер №{idx} удалён"),
            Cmd::SetPrimaryServer { idx } => format!("сервер по умолчанию: №{idx}"),
            Cmd::SwitchServer { addr, label, .. } => {
                if label.is_empty() {
                    format!("переключение на сервер {addr}")
                } else {
                    format!("переключение на сервер {addr} ({label})")
                }
            }
            Cmd::SetRelayEnabled(on) => format!("релей: {}", if *on { "вкл" } else { "выкл" }),
            Cmd::SetMeshEnabled(on) => format!("mesh: {}", if *on { "вкл" } else { "выкл" }),
            Cmd::PinPath { ip, .. } => format!("путь до {} закреплён", proto::ip_str(*ip)),
            Cmd::UnpinPath { ip } => format!("закрепление {} снято", proto::ip_str(*ip)),
            _ => String::new(),
        };
        let saved = {
            let mut cfg = lock(&self.cfg);
            apply_cfg_cmd(&mut cfg, cmd.clone());
            cfg.clone()
        };
        self.persist_cfg(&saved);
        lock(&self.pending).push_back(cmd);
        self.persist_pending();
        self.push(Event::Notice(if notice.is_empty() {
            "правка сохранена (офлайн)".into()
        } else {
            format!("{notice} (офлайн, ждёт демона)")
        }));
        Ok(())
    }

    /// Команда от TUI. Есть демон — ему (живой движок — всё, без движка —
    /// правки конфига: он сам их применит и поднимет движок); нет — конфиг и
    /// проба локально, сетевое — отказ.
    fn send(&self, cmd: Cmd) -> Result<()> {
        if matches!(cmd, Cmd::Quit) {
            return Ok(());
        }
        // Проба не требует движка: свой сокет работает всегда (и когда демон
        // есть, но его движок не поднялся).
        if let Cmd::ProbeServer { addr } = cmd {
            return self.probe_local(addr);
        }
        if let Some(eng) = self.remote() {
            let live = self.live();
            if live || is_cfg_cmd(&cmd) || matches!(cmd, Cmd::Reconnect) {
                match eng.send(cmd.clone()) {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        // Демон пропал между кадрами: команду — в офлайн-путь.
                        self.drop_remote(&e.to_string());
                    }
                }
            } else {
                return Err(anyhow!("{NO_ENGINE} (движок демона не запущен)"));
            }
        }
        match cmd {
            Cmd::ProbeServer { addr } => self.probe_local(addr),
            Cmd::Reconnect => {
                self.retry_now.store(true, Ordering::SeqCst);
                Ok(())
            }
            cmd if is_cfg_cmd(&cmd) => self.apply_local(cmd),
            _ => Err(anyhow!("{NO_ENGINE}")),
        }
    }
}

/// `true` — команду можно применить к конфигу без движка (и повторить
/// демону позже).
///
/// Друзей-заявок здесь нет: `AddFriend` теперь сетевой кадр (`FRIEND_REQ`),
/// без движка заявку доставить некому — офлайн он даёт ошибку «нужен
/// запущенный движок», а не молчаливую локальную запись (issue #24).
/// `DelFriend` и `SetAlias` остались локальными: первый снимает запись у себя,
/// второй — ручное имя.
fn is_cfg_cmd(cmd: &Cmd) -> bool {
    matches!(
        cmd,
        Cmd::SetName(_)
            | Cmd::SetStatus(_)
            | Cmd::SetInvisible(_)
            | Cmd::ToggleAutojoin(_)
            | Cmd::DelFriend(_)
            | Cmd::SetAlias { .. }
            | Cmd::AddServer { .. }
            | Cmd::DelServer { .. }
            | Cmd::SetPrimaryServer { .. }
            | Cmd::SwitchServer { .. }
            | Cmd::SetRelayEnabled(_)
            | Cmd::SetMeshEnabled(_)
            | Cmd::PinPath { .. }
            | Cmd::UnpinPath { .. }
    )
}

/// Правка конфига командой без движка (проверена `check_cfg_cmd`) — то же,
/// что делает движок (`do_cmd`/локальные команды). Общий путь демона в
/// состоянии «нет сервера» и офлайн-TUI.
pub fn apply_cfg_cmd(c: &mut Config, cmd: Cmd) {
    match cmd {
        Cmd::SetName(n) => c.name = n,
        Cmd::SetStatus(t) => c.status = t,
        Cmd::SetInvisible(on) => c.invisible = on,
        Cmd::ToggleAutojoin(gid) => {
            if let Some(i) = c.autojoin.iter().position(|g| *g == gid) {
                c.autojoin.remove(i);
            } else {
                c.autojoin.push(gid);
            }
        }
        Cmd::DelFriend(pubkey) => {
            let hex = proto::hex_of(&pubkey);
            c.friends.retain(|f| f.pubkey != hex);
        }
        Cmd::SetAlias { pubkey, alias } => {
            let hex = proto::hex_of(&pubkey);
            if let Some(f) = c.friends.iter_mut().find(|f| f.pubkey == hex) {
                f.alias = alias;
            }
        }
        Cmd::AddServer {
            addr,
            pubkey,
            label,
        } => {
            let hex = proto::hex_of(&pubkey);
            let sa: Option<SocketAddr> = addr.parse().ok();
            match c
                .servers
                .iter_mut()
                .find(|s| s.addr.parse::<SocketAddr>().ok() == sa)
            {
                Some(s) => {
                    s.pubkey = hex;
                    s.label = label;
                }
                None => c.servers.push(store::StoredServer {
                    addr: sa.map(|a| a.to_string()).unwrap_or(addr),
                    pubkey: hex,
                    label,
                }),
            }
        }
        Cmd::DelServer { idx } => {
            if idx < c.servers.len() {
                c.servers.remove(idx);
            }
        }
        Cmd::SetPrimaryServer { idx } if idx < c.servers.len() => {
            let s = c.servers.remove(idx);
            // Первый в списке и активный — его возьмёт запуск движка.
            if let Ok(a) = s.addr.parse::<SocketAddr>() {
                c.activate_server(a);
            }
            c.servers.insert(0, s);
        }
        Cmd::SwitchServer { addr, .. } => {
            // Автовход: список прежнего сервера уходит в `autojoin_by_server`,
            // поднимается список нового (gid у каждого сервера свои).
            c.activate_server(addr);
        }
        Cmd::SetRelayEnabled(on) => c.mesh.relay_enabled = on,
        Cmd::SetMeshEnabled(on) => c.mesh.enabled = on,
        Cmd::PinPath { ip, path } => {
            c.pinned_paths
                .insert(crate::path::ip_key(ip), path.to_config());
        }
        Cmd::UnpinPath { ip } => {
            c.pinned_paths.remove(&crate::path::ip_key(ip));
        }
        _ => {}
    }
}

/// Серверы локального конфига, которых нет в конфиге демона (по адресу).
/// Совпадение адреса считается «уже есть»: чужой ключ не перезаписываем.
pub fn missing_servers(local: &[StoredServer], daemon: &[CfgServer]) -> Vec<StoredServer> {
    local
        .iter()
        .filter(|s| !daemon.iter().any(|d| d.addr == s.addr))
        .cloned()
        .collect()
}

/// `Cmd::AddServer` из записи конфига (hex-ключ → байты).
pub fn add_server_cmd(s: &StoredServer) -> Result<Cmd, String> {
    let key = proto::hex_to_bytes(&s.pubkey)
        .map_err(|e| format!("сервер {}: неверный ключ «{}» ({e})", s.addr, s.pubkey))?;
    let pubkey: [u8; 32] = key
        .try_into()
        .map_err(|_| format!("сервер {}: ключ не 32 байта", s.addr))?;
    Ok(Cmd::AddServer {
        addr: s.addr.clone(),
        pubkey,
        label: s.label.clone(),
    })
}

/// Досылает демону серверы из локального конфига, которых у него нет.
///
/// У службы и `console` свой каталог данных (`%ProgramData%\tunnel`), а
/// `add-server` без демона пишет в пользовательский (`%APPDATA%\tunnel`) —
/// без этого переноса серверы до демона не доходили. Возвращает уведомления
/// для лога/тостов.
pub fn migrate_servers(eng: &dyn EngineApi, local: &[StoredServer]) -> Vec<String> {
    let daemon = eng.snapshot().cfg.servers.clone();
    let missing = missing_servers(local, &daemon);
    let mut out = Vec::new();
    let mut sent = 0usize;
    for s in &missing {
        match add_server_cmd(s) {
            Ok(cmd) => match eng.send(cmd) {
                Ok(()) => sent += 1,
                Err(e) => out.push(format!("сервер {} не перенесён: {e}", s.addr)),
            },
            Err(e) => out.push(e),
        }
    }
    if sent > 0 {
        out.push(format!(
            "серверы из локального конфига перенесены демону ({sent})"
        ));
    }
    out
}

/// Закреплённый ключ сервера `addr` (проба просит его: `want_key`).
fn pinned_key(cfg: &Mutex<Config>, addr: SocketAddr) -> Option<[u8; 32]> {
    let cfg = lock(cfg);
    cfg.servers
        .iter()
        .find(|s| s.addr.parse::<SocketAddr>().ok() == Some(addr))
        .and_then(|s| proto::hex_to_bytes(&s.pubkey).ok())
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
}

// ---------------------------------------------------------------- движок

/// `EngineApi` офлайн-режима с фоновым переподключением к демону.
pub struct ResilientEngine {
    sh: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl ResilientEngine {
    pub(crate) fn new(
        dir: &Path,
        cfg: Arc<Mutex<Config>>,
        identity: proto::Identity,
        reason: Option<String>,
    ) -> Self {
        {
            let mut cfg = lock(&cfg);
            store::ensure_identity(&mut cfg);
        }
        let pending = load_pending(dir);
        let sh = Arc::new(Shared {
            dir: dir.to_path_buf(),
            save: {
                let d = dir.to_path_buf();
                Arc::new(move |c: &Config| {
                    let _ = store::Store::new(&d).save(c);
                })
            },
            cfg,
            me: Me {
                my_pub: identity.ed_pub(),
                my_code: identity.friend_code(),
            },
            stop: AtomicBool::new(false),
            remote: Mutex::new(None),
            live: AtomicBool::new(false),
            pending: Mutex::new(pending),
            events: Mutex::new(VecDeque::new()),
            history: Mutex::new(Vec::new()),
            reason: Mutex::new(reason),
            probes: ProbeState::new(),
            retry_now: AtomicBool::new(false),
        });
        let w = sh.clone();
        let worker = std::thread::Builder::new()
            .name("offline-engine".into())
            .spawn(move || worker(w))
            .ok();
        Self {
            sh,
            worker: Mutex::new(worker),
        }
    }

    /// Подключиться ли сейчас к демону (тесты/диагностика).
    pub fn is_remote(&self) -> bool {
        self.sh.remote().is_some()
    }

    /// В демоне живой движок (иначе — офлайн, даже если демон найден).
    pub fn is_live(&self) -> bool {
        self.sh.live()
    }

    /// Причина офлайна (для шапки/тестов).
    pub fn reason(&self) -> Option<String> {
        lock(&self.sh.reason).clone()
    }

    /// Сколько правок ждёт демона.
    pub fn pending_edits(&self) -> usize {
        self.sh.pending_len()
    }

    /// Дождаться, пока фон подхватит демона (тесты/e2e).
    pub fn wait_remote(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if self.is_remote() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.is_remote()
    }

    /// Дождаться живого движка в демоне (тесты/e2e).
    pub fn wait_live(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if self.is_live() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.is_live()
    }

    /// Дождаться, пока очередь опустеет (тесты/e2e).
    pub fn wait_pending_empty(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if self.pending_edits() == 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.pending_edits() == 0
    }
}

impl EngineApi for ResilientEngine {
    fn snapshot(&self) -> Arc<Snapshot> {
        self.sh.snapshot()
    }

    fn poll_events(&self) -> Vec<Event> {
        let mut evs = self.sh.drain();
        if let Some(r) = self.sh.remote() {
            evs.extend(r.poll_events());
        }
        evs
    }

    fn send(&self, cmd: Cmd) -> Result<()> {
        self.sh.send(cmd)
    }

    fn me(&self) -> &Me {
        &self.sh.me
    }

    fn mode(&self) -> EngineMode {
        if self.is_live() {
            EngineMode::Remote
        } else {
            EngineMode::Offline
        }
    }

    fn unavailable(&self) -> bool {
        // Демон без движка доступен: он принимает правки конфига — это не
        // «демон недоступен», а «сервер недоступен» (пилюля в TUI).
        !self.is_remote()
    }

    fn take_history(&self) -> Vec<Event> {
        std::mem::take(&mut *lock(&self.sh.history))
    }

    fn save_theme(&self, theme: &str) -> Result<()> {
        {
            let mut cfg = lock(&self.sh.cfg);
            cfg.theme = theme.to_string();
            let saved = cfg.clone();
            drop(cfg);
            self.sh.persist_cfg(&saved);
        }
        // Тонкий клиент хранит тему в ui.json — офлайн пишем туда же, чтобы
        // она пережила и переход на демона.
        std::fs::create_dir_all(&self.sh.dir)?;
        UiPrefs {
            theme: theme.to_string(),
        }
        .save(&self.sh.dir)
    }

    fn save_adapter(&self, name: &str, dll: &str) -> Result<()> {
        let saved = {
            let mut cfg = lock(&self.sh.cfg);
            cfg.adapter = name.to_string();
            cfg.dll = dll.to_string();
            cfg.clone()
        };
        self.sh.persist_cfg(&saved);
        self.sh.push(Event::Notice(
            "адаптер сохранён — применится после перезапуска движка".into(),
        ));
        Ok(())
    }
}

impl Drop for ResilientEngine {
    fn drop(&mut self) {
        self.sh.stop.store(true, Ordering::SeqCst);
        let w = lock(&self.worker).take();
        if let Some(w) = w {
            let _ = w.join();
        }
    }
}

/// Фон: следить за демоном, принимать его, отправлять очередь, отдавать
/// результаты проб.
fn worker(sh: Arc<Shared>) {
    let ep = Endpoint::for_data_dir(&sh.dir);
    loop {
        if sh.stop.load(Ordering::SeqCst) {
            return;
        }
        // Демон пропал (TUI всё ещё рисует) — обратно в офлайн.
        if let Some(r) = sh.remote() {
            if r.unavailable() {
                sh.drop_remote(DAEMON_DOWN);
            } else {
                // Демон мог поднять движок (или потерять его) — режим и
                // причина обновляются из его снимка.
                let s = r.snapshot();
                let live = !s.meta.offline;
                let was = sh.live.swap(live, Ordering::SeqCst);
                let reason = if live {
                    None
                } else {
                    s.meta.offline_reason.clone()
                };
                if was != live {
                    if live {
                        sh.set_reason(None);
                        sh.push(Event::Notice("движок демона запущен".into()));
                    } else {
                        sh.set_reason(reason.clone());
                        sh.push(Event::Notice(match &reason {
                            Some(r) => format!("движок демона остановлен: {r}"),
                            None => "движок демона остановлен".into(),
                        }));
                    }
                } else if !live {
                    sh.notice_reason(reason, false);
                }
            }
        }
        // Демона нет — пробуем (и по `Cmd::Reconnect` — сразу).
        let forced = sh.retry_now.swap(false, Ordering::SeqCst);
        if sh.remote().is_none() {
            match IpcEngine::connect(&ep, Some(sh.dir.clone())) {
                Ok(eng) => {
                    if eng.me().my_pub != sh.me.my_pub {
                        sh.push(Event::Error(
                            "демон работает с другой identity — перезапустите TUI".into(),
                        ));
                        drop(eng);
                    } else {
                        sh.adopt(eng);
                    }
                }
                Err(e) => {
                    // Демона нет — штатный офлайн; причина меняется редко
                    // («демон не запущен»), тост — один раз.
                    sh.notice_reason(Some(format!("демон недоступен ({e})")), true);
                }
            }
        }
        // Результаты проб — событиями (как у настоящего движка).
        for r in sh.probes.poll() {
            sh.push(Event::ProbeResult {
                addr: r.addr,
                success: r.available,
                rtt_ms: r.rtt_ms,
                key_match: r.key_match.as_bool(),
            });
        }
        let step = if forced {
            Duration::from_millis(20)
        } else {
            RECONNECT_EVERY
        };
        // Спим маленькими шагами: `stop`/`retry_now` не должны ждать такт.
        let deadline = std::time::Instant::now() + step;
        while std::time::Instant::now() < deadline {
            if sh.stop.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "vl-offline-{tag}-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn engine(dir: &Path, cfg: Config) -> (ResilientEngine, Arc<Mutex<Config>>) {
        let id = proto::Identity::generate();
        let cfg = Arc::new(Mutex::new(cfg));
        (ResilientEngine::new(dir, cfg.clone(), id, None), cfg)
    }

    #[test]
    fn перенос_серверов_только_недостающих() {
        let local = vec![
            StoredServer {
                addr: "10.0.0.1:9000".into(),
                pubkey: "aa".repeat(32),
                label: "свой".into(),
            },
            StoredServer {
                addr: "10.0.0.2:9000".into(),
                pubkey: "bb".repeat(32),
                label: "чужой ключ".into(),
            },
        ];
        let daemon = vec![CfgServer {
            addr: "10.0.0.2:9000".into(),
            pubkey: "cc".repeat(32),
            label: "у демона".into(),
        }];
        // Адрес есть у демона (пусть и с другим ключом) — не трогаем.
        let missing = missing_servers(&local, &daemon);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].addr, "10.0.0.1:9000");
        // Всё уже есть — переносить нечего.
        assert!(missing_servers(&local, &[]).len() == 2);
        assert!(missing_servers(&[], &daemon).is_empty());
    }

    #[test]
    fn команда_переноса_сервера() {
        let s = StoredServer {
            addr: "10.0.0.1:9000".into(),
            pubkey: "aa".repeat(32),
            label: "сервер".into(),
        };
        match add_server_cmd(&s).unwrap() {
            Cmd::AddServer {
                addr,
                pubkey,
                label,
            } => {
                assert_eq!(addr, "10.0.0.1:9000");
                assert_eq!(pubkey, [0xaa; 32]);
                assert_eq!(label, "сервер");
            }
            other => panic!("ожидали AddServer, получили {other:?}"),
        }
        // Битая запись — ошибка с адресом, без паники.
        let bad = StoredServer {
            addr: "10.0.0.9:9000".into(),
            pubkey: "zz".into(),
            label: String::new(),
        };
        assert!(add_server_cmd(&bad).unwrap_err().contains("10.0.0.9:9000"));
    }

    #[test]
    fn офлайн_правка_применяется_и_не_теряется() {
        let d = temp_dir("edit");
        let (eng, cfg) = engine(&d, Config::default());
        assert_eq!(eng.mode(), EngineMode::Offline);
        assert!(eng.unavailable());
        eng.send(Cmd::SetName("новое имя".into())).unwrap();
        // Конфиг общий: правка видна вызывающему сразу...
        assert_eq!(cfg.lock().unwrap().name, "новое имя");
        // ...и в снимке TUI.
        let snap = eng.snapshot();
        assert_eq!(snap.cfg.name, "новое имя");
        assert!(snap.meta.offline);
        assert_eq!(snap.meta.pending_edits, 1);
        // client.json сохранён, очередь — на диске (переживёт перезапуск).
        let on_disk = store::Store::new(&d).load().unwrap();
        assert_eq!(on_disk.name, "новое имя");
        let q = load_pending(&d);
        assert_eq!(q.len(), 1);
        assert!(matches!(q[0], Cmd::SetName(ref n) if n == "новое имя"));
        drop(eng);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn очередь_переживает_перезапуск_tui() {
        let d = temp_dir("restart");
        {
            let (eng, _cfg) = engine(&d, Config::default());
            eng.send(Cmd::AddServer {
                addr: "127.0.0.1:5555".into(),
                pubkey: [3; 32],
                label: "дом".into(),
            })
            .unwrap();
            eng.send(Cmd::SetStatus("в отпуске".into())).unwrap();
            assert_eq!(eng.pending_edits(), 2);
        }
        // Новый TUI: очередь подхвачена, правки уже в конфиге.
        let (eng2, cfg2) = engine(&d, store::Store::new(&d).load().unwrap());
        assert_eq!(eng2.pending_edits(), 2);
        assert_eq!(eng2.snapshot().meta.pending_edits, 2);
        assert_eq!(cfg2.lock().unwrap().status, "в отпуске");
        assert_eq!(cfg2.lock().unwrap().servers.len(), 1);
        drop(eng2);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn сетевая_команда_офлайн_отклоняется() {
        let d = temp_dir("net");
        let (eng, _cfg) = engine(&d, Config::default());
        let e = eng.send(Cmd::Join(7)).unwrap_err().to_string();
        assert_eq!(e, NO_ENGINE);
        assert_eq!(eng.pending_edits(), 0);
        drop(eng);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn тема_и_адаптер_сохраняются_офлайн() {
        let d = temp_dir("prefs");
        let (eng, cfg) = engine(&d, Config::default());
        eng.save_theme("light").unwrap();
        assert_eq!(cfg.lock().unwrap().theme, "light");
        assert_eq!(UiPrefs::load(&d).theme, "light");
        assert!(d.join(crate::remote::UI_FILE).exists());
        eng.save_adapter("vl1", "C:/wintun.dll").unwrap();
        assert_eq!(cfg.lock().unwrap().adapter, "vl1");
        assert_eq!(cfg.lock().unwrap().dll, "C:/wintun.dll");
        let disk = store::Store::new(&d).load().unwrap();
        assert_eq!(
            (disk.adapter.as_str(), disk.dll.as_str()),
            ("vl1", "C:/wintun.dll")
        );
        drop(eng);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn битый_файл_очереди_не_роняет_tui() {
        let d = temp_dir("badq");
        std::fs::write(d.join(PENDING_FILE), b"{ not json").unwrap();
        let (eng, _cfg) = engine(&d, Config::default());
        assert_eq!(eng.pending_edits(), 0);
        assert!(eng.snapshot().meta.offline);
        drop(eng);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn проба_работает_без_движка() {
        // Фейковый сервер: ответ с ключом.
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let key = [4u8; 32];
        let srv = std::thread::spawn(move || {
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 1024];
            let (n, src) = sock.recv_from(&mut buf).unwrap();
            let (typ, body) = proto::split_frame(&buf[..n]).unwrap();
            assert_eq!(typ, proto::ctrl::PROBE_REQ);
            let req = proto::payloads::dec_probe_req(body).unwrap();
            let resp = proto::payloads::enc_probe_resp(&proto::payloads::ProbeResp {
                nonce: req.nonce,
                ts_ms: req.ts_ms,
                ed_pub: Some(key),
            });
            sock.send_to(&proto::plain_frame(proto::ctrl::PROBE_RESP, &resp), src)
                .unwrap();
        });
        let d = temp_dir("probe");
        let cfg = Config {
            servers: vec![store::StoredServer {
                addr: addr.to_string(),
                pubkey: proto::hex_of(&key),
                label: String::new(),
            }],
            ..Config::default()
        };
        let (eng, _cfg) = engine(&d, cfg);
        eng.send(Cmd::ProbeServer { addr }).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut got = None;
        while std::time::Instant::now() < deadline && got.is_none() {
            for ev in eng.poll_events() {
                if let Event::ProbeResult {
                    addr: a,
                    success,
                    rtt_ms,
                    key_match,
                } = ev
                {
                    got = Some((a, success, rtt_ms, key_match));
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        srv.join().unwrap();
        let (a, success, rtt, km) = got.expect("проба без движка дошла событием");
        assert_eq!(a, addr);
        assert!(success);
        assert!(rtt.is_some());
        assert_eq!(km, Some(true), "ключ сервера совпал с закреплённым");
        drop(eng);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn apply_cfg_cmd_двигает_автовход_по_серверам() {
        let mut c = Config {
            servers: vec![
                store::StoredServer {
                    addr: "10.0.0.1:7000".into(),
                    pubkey: "00".repeat(32),
                    label: String::new(),
                },
                store::StoredServer {
                    addr: "10.0.0.2:7000".into(),
                    pubkey: "00".repeat(32),
                    label: String::new(),
                },
            ],
            active_server: "10.0.0.1:7000".into(),
            autojoin: vec![3, 5],
            ..Config::default()
        };
        apply_cfg_cmd(
            &mut c,
            Cmd::SwitchServer {
                addr: "10.0.0.2:7000".parse().unwrap(),
                pubkey: [0; 32],
                label: String::new(),
            },
        );
        assert_eq!(c.active_server, "10.0.0.2:7000");
        assert!(c.autojoin.is_empty());
        assert_eq!(c.autojoin_by_server.get("10.0.0.1:7000"), Some(&vec![3, 5]));
        // Проба: ключ закреплён — сверка возможна.
        let cfg = Arc::new(Mutex::new(c));
        assert_eq!(
            pinned_key(&cfg, "10.0.0.2:7000".parse().unwrap()),
            Some([0u8; 32])
        );
        assert_eq!(pinned_key(&cfg, "10.0.0.9:7000".parse().unwrap()), None);
    }

    #[test]
    fn состояние_офлайн_сети_по_пилюлям() {
        // Нет серверов — «нет сервера»; есть — «сервер недоступен»/офлайн.
        let d = temp_dir("pill");
        let (eng, _cfg) = engine(&d, Config::default());
        let s = eng.snapshot();
        assert!(s.cfg.servers.is_empty());
        assert!(s.meta.offline && s.meta.offline_reason.is_none());
        drop(eng);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Движок-приёмник: команды в `sent`; `fail_at` — номер, на котором
    /// «демон пропал» (0 — первая же).
    struct SinkEngine {
        sent: Mutex<Vec<Cmd>>,
        me: Me,
        fail_at: Option<usize>,
    }

    impl SinkEngine {
        fn new(me: Me) -> Self {
            SinkEngine {
                sent: Mutex::new(Vec::new()),
                me,
                fail_at: None,
            }
        }
    }

    impl EngineApi for SinkEngine {
        fn snapshot(&self) -> Arc<Snapshot> {
            Arc::new(Snapshot::default())
        }
        fn poll_events(&self) -> Vec<Event> {
            Vec::new()
        }
        fn send(&self, cmd: Cmd) -> Result<()> {
            let mut sent = self.sent.lock().unwrap();
            if self.fail_at == Some(sent.len()) {
                return Err(anyhow!("демон недоступен"));
            }
            sent.push(cmd);
            Ok(())
        }
        fn me(&self) -> &Me {
            &self.me
        }
        fn mode(&self) -> EngineMode {
            EngineMode::Remote
        }
        fn save_theme(&self, _theme: &str) -> Result<()> {
            Ok(())
        }
        fn save_adapter(&self, _name: &str, _dll: &str) -> Result<()> {
            Ok(())
        }
    }

    /// `Shared` без фонового потока — для проверки `flush` напрямую.
    fn shared(dir: &Path, cfg: Config, pending: VecDeque<Cmd>) -> Shared {
        let mut probe_cfg = cfg.clone();
        let id = store::ensure_identity(&mut probe_cfg);
        Shared {
            dir: dir.to_path_buf(),
            cfg: Arc::new(Mutex::new(cfg)),
            save: Arc::new(|_: &Config| {}),
            me: Me {
                my_pub: id.ed_pub(),
                my_code: id.friend_code(),
            },
            stop: AtomicBool::new(false),
            remote: Mutex::new(None),
            live: AtomicBool::new(false),
            pending: Mutex::new(pending),
            events: Mutex::new(VecDeque::new()),
            history: Mutex::new(Vec::new()),
            reason: Mutex::new(None),
            probes: ProbeState::new(),
            retry_now: AtomicBool::new(false),
        }
    }

    #[test]
    fn очередь_отправляется_по_порядку_и_очищается() {
        let d = temp_dir("flush");
        let cmds: VecDeque<Cmd> = VecDeque::from(vec![
            Cmd::AddServer {
                addr: "127.0.0.1:5599".into(),
                pubkey: [1; 32],
                label: "дом".into(),
            },
            Cmd::SetName("tui".into()),
        ]);
        save_pending(&d, &cmds);
        let sh = shared(&d, Config::default(), cmds);
        let eng = SinkEngine::new(sh.me.clone());
        sh.flush(&eng);
        let sent = eng.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 2, "все команды ушли");
        assert!(matches!(sent[0], Cmd::AddServer { .. }), "{sent:?}");
        assert!(
            matches!(&sent[1], Cmd::SetName(n) if n == "tui"),
            "порядок сохранён: {sent:?}"
        );
        assert_eq!(sh.pending_len(), 0);
        assert!(!d.join(PENDING_FILE).exists(), "очередь очищена и на диске");
        drop(sh);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn демон_пропал_посреди_очереди_остаток_ждёт() {
        let d = temp_dir("flushfail");
        let cmds: VecDeque<Cmd> = VecDeque::from(vec![
            Cmd::SetName("tui".into()),
            Cmd::SetStatus("тут".into()),
        ]);
        save_pending(&d, &cmds);
        let sh = shared(&d, Config::default(), cmds);
        let mut eng = SinkEngine::new(sh.me.clone());
        eng.fail_at = Some(1);
        sh.flush(&eng);
        // Первая ушла, вторая не подтверждена — остаётся в очереди и на диске.
        assert_eq!(sh.pending_len(), 1);
        let left = load_pending(&d);
        assert_eq!(left.len(), 1);
        assert!(matches!(&left[0], Cmd::SetStatus(s) if s == "тут"));
        assert!(d.join(PENDING_FILE).exists());
        drop(sh);
        let _ = std::fs::remove_dir_all(&d);
    }
}
