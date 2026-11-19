//! `EngineBackend` — бэкенд демона поверх настоящего движка `tunnel-client`
//! (PLAN.md 7.1/7.3).
//!
//! - снимок — [`tunnel_client::snapshot::Snapshot`] из состояния движка
//!   (группы, meta, счётчики, `CfgView` без identity) плюс неотвеченные
//!   приглашения — всё это строит `tunnel_client::api::LocalEngine` (тот же
//!   код, что у embedded TUI, поэтому снимки совпадают — PLAN.md 7.7);
//! - события — `Event` движка в JSON (serde, внешний тег);
//! - команды — JSON-форма `Cmd` движка; правки конфига (`AddFriend`,
//!   `DelServer`…) проверяются до отправки, отказ уходит клиенту в `Ack`.
//!
//! [`DaemonEngine`] — бэкенд режимов `console` и `service`: конфиг и identity
//! каталога данных демона, движок с настоящим TUN ([`real_start`]: Wintun /
//! utun / Linux TUN — нужны права администратора) по первому серверу, а без
//! серверов — состояние «нет сервера» до `AddServer`. Тесты подставляют свой
//! [`StartFn`] (TUN-заглушка) или собирают движок сами для
//! [`EngineBackend::new`].

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use tunnel_client::api::{EngineApi, LocalEngine, Me};
use tunnel_client::engine::{self, Cmd, Engine, Event};
use tunnel_client::snapshot::{CfgView, Snapshot};
use tunnel_client::store::{self, Config};
use tunnel_protocol as proto;

use crate::hub::Backend;
use crate::log::{Level, LogFn};
use crate::service::ResumeSignal;

/// Имя адаптера Wintun службы.
pub const ADAPTER_NAME: &str = "TunnelVPN";

/// Бэкенд на живом движке: [`LocalEngine`] (снимок, приглашения, проверка
/// команд — тот же код, что у embedded TUI) в JSON-обёртке.
pub struct EngineBackend {
    local: LocalEngine,
}

impl EngineBackend {
    /// Обернуть запущенный движок.
    pub fn new(eng: Engine) -> Self {
        EngineBackend {
            local: LocalEngine::new(eng),
        }
    }

    /// Типизированный снимок (то же, что [`Backend::snapshot`] до JSON).
    pub fn snapshot_typed(&self) -> Snapshot {
        self.local.snapshot_now()
    }

    /// Движок как [`EngineApi`].
    pub fn local(&self) -> &LocalEngine {
        &self.local
    }
}

impl Backend for EngineBackend {
    fn snapshot(&self) -> Value {
        serde_json::to_value(self.snapshot_typed()).unwrap_or(Value::Null)
    }

    fn poll_events(&self) -> Vec<Value> {
        self.local
            .poll_events()
            .into_iter()
            .filter_map(|e| serde_json::to_value(e).ok())
            .collect()
    }

    fn send(&self, cmd: Value) -> Result<(), String> {
        let cmd: Cmd = serde_json::from_value(cmd).map_err(|e| format!("неверная команда: {e}"))?;
        if matches!(cmd, Cmd::Quit) {
            return Err("демон не завершается по команде фронтенда".into());
        }
        self.local.send(cmd).map_err(|e| e.to_string())
    }

    fn me(&self) -> Value {
        self.local.me().to_json()
    }

    fn changed(&self) -> bool {
        self.local.changed()
    }
}

/// Сервер для запуска: текущий (`active_server`), иначе первый в списке.
pub fn pick_server(cfg: &Config) -> Result<(SocketAddr, [u8; 32]), String> {
    let entry = cfg
        .servers
        .iter()
        .find(|s| {
            s.addr
                .parse::<SocketAddr>()
                .is_ok_and(|a| a.to_string() == cfg.active_server)
        })
        .or(cfg.servers.first())
        .ok_or(
            "в конфиге нет серверов (добавьте: tunnel-client --dir <каталог данных> add-server …)",
        )?;
    let addr: SocketAddr = entry
        .addr
        .parse()
        .map_err(|_| format!("неверный адрес сервера «{}»", entry.addr))?;
    let pk = proto::hex_to_bytes(&entry.pubkey)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or(format!("неверный ключ сервера {addr}"))?;
    Ok((addr, pk))
}

/// Колбэк сохранения конфига движком.
pub type SaveFn = Arc<dyn Fn(&Config) + Send + Sync>;

/// Всё для запуска движка на выбранном сервере.
pub struct EngineStart {
    /// Общий конфиг: тот же `Arc`, что у [`DaemonEngine`] (правки до и после
    /// запуска видны обоим).
    pub cfg: Arc<Mutex<Config>>,
    pub server: SocketAddr,
    pub server_pub: [u8; 32],
    pub identity: proto::Identity,
    pub save: SaveFn,
}

/// Запуск движка: настоящий TUN ([`real_start`]) или тестовый.
pub type StartFn = Arc<dyn Fn(EngineStart) -> anyhow::Result<EngineBackend> + Send + Sync>;

/// Откуда брать `wintun.dll` (только Windows; на других ОС не используется).
/// `dll` из `client.json` демон не читает: конфиг правится по IPC без прав
/// администратора, а DLL грузится в процесс с правами администратора/SYSTEM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WintunDll {
    /// Только этот путь (рядом с exe; у службы — защищённый резолвер
    /// `tunnel-winsvc`).
    Only(PathBuf),
    /// DLL нет (или каталог небезопасен) — TUN не поднять (причина).
    Missing(String),
}

impl WintunDll {
    /// `console`: `wintun.dll` только рядом с exe демона.
    pub fn beside_current_exe() -> Self {
        let r = std::env::current_exe()
            .map_err(anyhow::Error::from)
            .and_then(|exe| tunnel_winsvc::wintun_dll_beside(&exe));
        match r {
            Ok(p) => WintunDll::Only(p),
            Err(e) => WintunDll::Missing(format!("{e:#}")),
        }
    }
}

/// Параметры настоящего TUN.
#[derive(Debug, Clone)]
pub struct TunOpts {
    pub wintun: WintunDll,
}

/// Настоящий TUN платформы (Wintun / utun / Linux TUN; нужны права
/// администратора) через [`engine::start`] — тот же путь, что у embedded TUI
/// и `run`: адрес, маршруты, DNS для `.vl`, чтение из TUN. Адаптер —
/// `adapter` из конфига, пусто — по умолчанию.
pub fn real_start(tun: TunOpts) -> StartFn {
    Arc::new(move |a: EngineStart| platform_start(a, &tun))
}

/// Имя адаптера для [`engine::start`]: из конфига, пусто — [`ADAPTER_NAME`]
/// (на Linux движок сам заменит его на `voidlink0`, macOS имя игнорирует).
fn adapter_name(cfg: &Config) -> String {
    let n = cfg.adapter.trim();
    if n.is_empty() {
        ADAPTER_NAME.to_string()
    } else {
        n.to_string()
    }
}

fn platform_start(a: EngineStart, tun: &TunOpts) -> anyhow::Result<EngineBackend> {
    let adapter = adapter_name(&a.cfg.lock().unwrap_or_else(|p| p.into_inner()));
    let dll = if cfg!(windows) {
        match &tun.wintun {
            WintunDll::Only(p) => Some(p.to_string_lossy().into_owned()),
            WintunDll::Missing(why) => anyhow::bail!("wintun.dll: {why}"),
        }
    } else {
        None
    };
    let eng = engine::start(
        a.cfg,
        a.server,
        a.server_pub,
        a.identity,
        &adapter,
        dll,
        a.save,
    )?;
    Ok(EngineBackend::new(eng))
}

// ---------- демон: «нет сервера» → движок ----------

/// Пауза между попытками запуска движка, пока он не поднялся (сервер
/// недоступен, сеть ещё не готова при загрузке, нет прав на TUN).
pub const START_RETRY: Duration = Duration::from_secs(30);

/// Ответ на сетевые команды без движка (PLAN.md 7.1).
pub const NO_SERVER: &str = "нет сервера: добавьте сервер (AddServer / add-server)";

/// Адрес-заглушка «текущего сервера» для проверки команд без движка.
const NO_CURRENT: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

enum State {
    /// Движка нет: в конфиге нет серверов или запуск не удался (`reason`).
    Waiting {
        reason: String,
        /// Идёт попытка запуска (поток `engine-start`).
        starting: bool,
        /// Когда пробовать снова (`None` — только по `AddServer`).
        retry_at: Option<Instant>,
    },
    Live(Arc<EngineBackend>),
}

struct Inner {
    cfg: Arc<Mutex<Config>>,
    save: SaveFn,
    identity: proto::Identity,
    me: Me,
    start: StartFn,
    log: LogFn,
    resume: Option<ResumeSignal>,
    state: Mutex<State>,
    /// События состояния «нет сервера» (Notice/Error) до хаба.
    events: Mutex<Vec<Value>>,
    changed: AtomicBool,
}

/// Бэкенд демона (console и служба): владеет конфигом и identity каталога
/// данных; есть сервер — поднимает движок ([`EngineBackend`]), нет — ждёт
/// `AddServer` в состоянии «нет сервера» (PLAN.md 7.1): снимок с конфигом,
/// правки конфига применяются сразу, сетевые команды — `Ack` Err
/// [`NO_SERVER`]. Неудачный запуск повторяется раз в [`START_RETRY`] (и сразу
/// по выходу из сна). Выход из сна при живом движке — `Cmd::Reconnect`.
pub struct DaemonEngine {
    inner: Arc<Inner>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl DaemonEngine {
    /// Конфиг из `data_dir/client.json` (нет identity — создаётся и
    /// сохраняется). Движок не запускается: [`DaemonEngine::start_now`] или
    /// [`DaemonEngine::start_async`].
    pub fn open(
        data_dir: &Path,
        log: LogFn,
        start: StartFn,
        resume: Option<ResumeSignal>,
    ) -> Result<Self, String> {
        let st = Arc::new(store::Store::new(data_dir));
        let mut cfg = st.load().map_err(|e| format!("чтение конфига: {e:#}"))?;
        let fresh = cfg.identity.is_none();
        let identity = store::ensure_identity(&mut cfg);
        if fresh {
            st.save(&cfg)
                .map_err(|e| format!("запись конфига: {e:#}"))?;
            log(
                Level::Info,
                &format!("создана новая identity: {}", identity.friend_code()),
            );
        }
        let save: SaveFn = {
            let log = log.clone();
            Arc::new(move |c: &Config| {
                if let Err(e) = st.save(c) {
                    log(Level::Error, &format!("запись конфига: {e:#}"));
                }
            })
        };
        let reason = if cfg.servers.is_empty() {
            NO_SERVER.to_string()
        } else {
            "движок не запущен".to_string()
        };
        let me = Me {
            my_pub: identity.ed_pub(),
            my_code: identity.friend_code(),
        };
        Ok(DaemonEngine {
            inner: Arc::new(Inner {
                cfg: Arc::new(Mutex::new(cfg)),
                save,
                identity,
                me,
                start,
                log,
                resume,
                state: Mutex::new(State::Waiting {
                    reason,
                    starting: false,
                    retry_at: None,
                }),
                events: Mutex::new(Vec::new()),
                changed: AtomicBool::new(true),
            }),
        })
    }

    /// В конфиге есть серверы.
    pub fn has_server(&self) -> bool {
        !lock(&self.inner.cfg).servers.is_empty()
    }

    /// Движок запущен.
    pub fn is_live(&self) -> bool {
        matches!(*lock(&self.inner.state), State::Live(_))
    }

    /// Запустить движок синхронно (`console`: ошибка — выход из демона).
    pub fn start_now(&self) -> Result<(), String> {
        {
            let mut g = lock(&self.inner.state);
            match &mut *g {
                State::Live(_) => return Ok(()),
                State::Waiting { starting: true, .. } => {
                    return Err("движок уже запускается".into());
                }
                State::Waiting { starting, .. } => *starting = true,
            }
        }
        Inner::attempt(&self.inner)
    }

    /// Запустить движок в фоне (служба: IPC доступен сразу). Нет серверов
    /// или запуск уже идёт — ничего.
    pub fn start_async(&self) {
        Inner::kick(&self.inner);
    }

    fn live(&self) -> Option<Arc<EngineBackend>> {
        match &*lock(&self.inner.state) {
            State::Live(b) => Some(b.clone()),
            State::Waiting { .. } => None,
        }
    }
}

impl Inner {
    fn push(&self, ev: &Event) {
        if let Ok(v) = serde_json::to_value(ev) {
            lock(&self.events).push(v);
        }
        self.changed.store(true, Ordering::Relaxed);
    }

    /// Попытка запуска в фоне, если ждём и сервер есть.
    fn kick(this: &Arc<Inner>) {
        if lock(&this.cfg).servers.is_empty() {
            return;
        }
        {
            let mut g = lock(&this.state);
            match &mut *g {
                State::Waiting { starting, .. } if !*starting => *starting = true,
                _ => return,
            }
        }
        let me = this.clone();
        let spawned = std::thread::Builder::new()
            .name("engine-start".into())
            .spawn(move || {
                let _ = Inner::attempt(&me);
            });
        if let Err(e) = spawned {
            this.fail(format!("поток запуска движка: {e}"));
        }
    }

    /// Запуск (флаг `starting` уже взведён вызывающим).
    fn attempt(this: &Arc<Inner>) -> Result<(), String> {
        let picked = pick_server(&lock(&this.cfg));
        let (server, server_pub) = match picked {
            Ok(p) => p,
            Err(e) => {
                this.fail(e.clone());
                return Err(e);
            }
        };
        (this.log)(Level::Info, &format!("движок: сервер {server}"));
        let args = EngineStart {
            cfg: this.cfg.clone(),
            server,
            server_pub,
            identity: this.identity.clone(),
            save: this.save.clone(),
        };
        match (this.start)(args) {
            Ok(b) => {
                *lock(&this.state) = State::Live(Arc::new(b));
                this.changed.store(true, Ordering::Relaxed);
                (this.log)(Level::Info, "движок запущен");
                Ok(())
            }
            Err(e) => {
                let e = format!("движок: {e:#}");
                this.fail(e.clone());
                Err(e)
            }
        }
    }

    fn fail(&self, e: String) {
        (self.log)(
            Level::Error,
            &format!("{e}; следующая попытка через {} с", START_RETRY.as_secs()),
        );
        self.push(&Event::Error(e.clone()));
        *lock(&self.state) = State::Waiting {
            reason: e,
            starting: false,
            retry_at: Some(Instant::now() + START_RETRY),
        };
    }

    /// Команда без движка: правки конфига — сразу, остальное — отказ.
    fn offline_cmd(this: &Arc<Inner>, cmd: Cmd, reason: &str) -> Result<(), String> {
        if let Some(e) = engine::check_cfg_cmd(&lock(&this.cfg), NO_CURRENT, &cmd) {
            return Err(e);
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
            Cmd::SwitchServer { addr, pubkey, label } => {
                // Validate IPv4/IPv6 family match (same as client engine)
                let family_ok = this
                    .cfg
                    .lock()
                    .unwrap()
                    .servers
                    .iter()
                    .find(|s| s.addr.parse::<SocketAddr>().ok() == Some(*addr))
                    .map(|s| s.addr.parse::<SocketAddr>().unwrap().is_ipv6() == addr.is_ipv6())
                    .unwrap_or(false);
                if !family_ok {
                    return Err(format!(
                        "сервер {addr}: другое семейство адресов (IPv4/IPv6) — перезапустите клиент с этим сервером"
                    ));
                }
                // Update config: activate server (handles autojoin_by_server)
                let mut cfg = lock(&this.cfg);
                if cfg.activate_server(*addr) {
                    // Save will be done below
                }
                // Verify server exists in config
                let server_exists = cfg.servers.iter().any(|s| s.addr.parse::<SocketAddr>().ok() == Some(*addr));
                if !server_exists {
                    return Err(format!("сервер {addr} не найден в конфиге"));
                }
                drop(cfg);
                format!("переключение на сервер {addr} ({label})")
            }
            Cmd::Reconnect => {
                Inner::retry_now(this);
                return Ok(());
            }
            Cmd::Quit => return Err("демон не завершается по команде фронтенда".into()),
            _ => return Err(reason.to_string()),
        };
        let start = matches!(cmd, Cmd::AddServer { .. } | Cmd::SetPrimaryServer { .. });
        let saved = {
            let mut c = lock(&this.cfg);
            apply_offline(&mut c, cmd);
            c.clone()
        };
        (this.save)(&saved);
        this.push(&Event::Notice(notice));
        if start {
            Inner::retry_now(this);
        }
        Ok(())
    }

    /// Попытка запуска сейчас, не дожидаясь [`START_RETRY`].
    fn retry_now(this: &Arc<Inner>) {
        if let State::Waiting { retry_at, .. } = &mut *lock(&this.state) {
            *retry_at = None;
        }
        Inner::kick(this);
    }
}

/// Правка конфига командой без движка (проверена `check_cfg_cmd`) — то же,
/// что делает движок (`cfg_cmd`/локальные команды `do_cmd`).
fn apply_offline(c: &mut Config, cmd: Cmd) {
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
        Cmd::AddFriend { pubkey, alias } => {
            let hex = proto::hex_of(&pubkey);
            match c.friends.iter_mut().find(|f| f.pubkey == hex) {
                Some(f) => f.alias = alias,
                None => c.friends.push(store::StoredFriend { pubkey: hex, alias }),
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
            // `activate_server`: автовход прежнего сервера уходит в
            // `autojoin_by_server`, восстанавливается список нового (gid у
            // каждого сервера свои) — как при `SwitchServer` движка.
            if let Ok(a) = s.addr.parse::<SocketAddr>() {
                c.activate_server(a);
            }
            c.servers.insert(0, s);
        }
        Cmd::SwitchServer { addr, .. } => {
            // activate_server handles autojoin_by_server (like client engine's switch_server)
            c.activate_server(addr);
        }
        _ => {}
    }
}

impl Backend for DaemonEngine {
    fn snapshot(&self) -> Value {
        if let Some(b) = self.live() {
            return b.snapshot();
        }
        let snap = Snapshot {
            cfg: CfgView::from_cfg(&lock(&self.inner.cfg)),
            ..Snapshot::default()
        };
        serde_json::to_value(snap).unwrap_or(Value::Null)
    }

    fn poll_events(&self) -> Vec<Value> {
        let resumed = self.inner.resume.as_ref().is_some_and(ResumeSignal::take);
        let mut evs = std::mem::take(&mut *lock(&self.inner.events));
        match self.live() {
            Some(b) => {
                if resumed {
                    (self.inner.log)(Level::Info, "выход из сна — переподключение");
                    let _ = b.local().send(Cmd::Reconnect);
                }
                evs.extend(b.poll_events());
            }
            None => {
                let due = match &*lock(&self.inner.state) {
                    State::Waiting {
                        starting: false,
                        retry_at: Some(t),
                        ..
                    } => resumed || Instant::now() >= *t,
                    _ => false,
                };
                if due {
                    Inner::retry_now(&self.inner);
                }
            }
        }
        evs
    }

    fn send(&self, cmd: Value) -> Result<(), String> {
        if let Some(b) = self.live() {
            return b.send(cmd);
        }
        let cmd: Cmd = serde_json::from_value(cmd).map_err(|e| format!("неверная команда: {e}"))?;
        let reason = match &*lock(&self.inner.state) {
            State::Waiting { starting: true, .. } => {
                "движок запускается — повторите позже".to_string()
            }
            State::Waiting { reason, .. } => reason.clone(),
            State::Live(_) => String::new(),
        };
        Inner::offline_cmd(&self.inner, cmd, &reason)
    }

    fn me(&self) -> Value {
        self.inner.me.to_json()
    }

    fn changed(&self) -> bool {
        let own = self.inner.changed.swap(false, Ordering::Relaxed);
        let live = self.live().is_some_and(|b| b.changed());
        own || live
    }
}

/// Бэкенд режимов `console`/`service`: [`DaemonEngine`] или ошибка открытия
/// каталога данных (битый `client.json`) — тогда снимок `{"engine": null,
/// "error": …}` (фронтенд показывает причину), команды — `Ack` Err.
pub enum DaemonBackend {
    Ready(Box<DaemonEngine>),
    Failed(String),
}

impl DaemonBackend {
    /// Бэкенд службы: wintun.dll — только от защищённого резолвера
    /// (`ServiceEnv::wintun_dll`), выход из сна — подсказка движку; движок
    /// запускается в фоне (IPC доступен сразу), без серверов — ждёт `AddServer`.
    pub fn service(env: crate::service::ServiceEnv) -> Self {
        let wintun = match env.wintun_dll {
            Some(p) => WintunDll::Only(p),
            None => WintunDll::Missing(
                "нет wintun.dll рядом с exe службы или каталог установки небезопасен (см. лог)"
                    .to_string(),
            ),
        };
        match DaemonEngine::open(
            &env.data_dir,
            env.log.clone(),
            real_start(TunOpts { wintun }),
            Some(env.resume),
        ) {
            Ok(e) => {
                if e.has_server() {
                    e.start_async();
                } else {
                    (env.log)(
                        Level::Warn,
                        "в конфиге нет серверов — ждём AddServer (tunnel-client tui / add-server)",
                    );
                }
                DaemonBackend::Ready(Box::new(e))
            }
            Err(e) => {
                (env.log)(Level::Error, &e);
                DaemonBackend::Failed(e)
            }
        }
    }

    pub fn engine(&self) -> Option<&DaemonEngine> {
        match self {
            DaemonBackend::Ready(e) => Some(e),
            DaemonBackend::Failed(_) => None,
        }
    }
}

impl Backend for DaemonBackend {
    fn snapshot(&self) -> Value {
        match self {
            DaemonBackend::Ready(b) => b.snapshot(),
            DaemonBackend::Failed(e) => serde_json::json!({ "engine": null, "error": e }),
        }
    }
    fn poll_events(&self) -> Vec<Value> {
        match self {
            DaemonBackend::Ready(b) => b.poll_events(),
            DaemonBackend::Failed(_) => Vec::new(),
        }
    }
    fn send(&self, cmd: Value) -> Result<(), String> {
        match self {
            DaemonBackend::Ready(b) => b.send(cmd),
            DaemonBackend::Failed(e) => Err(e.clone()),
        }
    }
    fn me(&self) -> Value {
        match self {
            DaemonBackend::Ready(b) => b.me(),
            DaemonBackend::Failed(_) => Value::Null,
        }
    }
    fn changed(&self) -> bool {
        match self {
            DaemonBackend::Ready(b) => b.changed(),
            DaemonBackend::Failed(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(addr: &str) -> store::StoredServer {
        store::StoredServer {
            addr: addr.into(),
            pubkey: "00".repeat(32),
            label: String::new(),
        }
    }

    /// Смена сервера по умолчанию без движка переносит автовход: список
    /// прежнего сервера откладывается в `autojoin_by_server`, у нового —
    /// свой (gid у каждого сервера свои).
    #[test]
    fn offline_primary_server_moves_autojoin() {
        let mut c = Config {
            servers: vec![server("10.0.0.1:7000"), server("10.0.0.2:7000")],
            active_server: "10.0.0.1:7000".into(),
            autojoin: vec![3, 5],
            ..Config::default()
        };
        apply_offline(&mut c, Cmd::SetPrimaryServer { idx: 1 });
        assert_eq!(c.servers[0].addr, "10.0.0.2:7000");
        assert_eq!(c.active_server, "10.0.0.2:7000");
        assert!(
            c.autojoin.is_empty(),
            "автовход первого сервера не переехал"
        );
        assert_eq!(c.autojoin_by_server.get("10.0.0.1:7000"), Some(&vec![3, 5]));
        c.autojoin.push(9);
        apply_offline(&mut c, Cmd::SetPrimaryServer { idx: 1 });
        assert_eq!(c.active_server, "10.0.0.1:7000");
        assert_eq!(c.autojoin, vec![3, 5]);
        assert_eq!(c.autojoin_by_server.get("10.0.0.2:7000"), Some(&vec![9]));
        // Тот же сервер — ничего не меняется.
        apply_offline(&mut c, Cmd::SetPrimaryServer { idx: 0 });
        assert_eq!(c.autojoin, vec![3, 5]);
    }

    #[test]
    fn adapter_default() {
        let mut c = Config::default();
        assert_eq!(adapter_name(&c), ADAPTER_NAME);
        c.adapter = " vl1 ".into();
        assert_eq!(adapter_name(&c), "vl1");
    }
}
