//! Режимы демона. `console` — рабочий (лог, замок, хаб, IPC); `service`,
//! `install`, `uninstall` — служба Windows через `tunnel-winsvc` (7.6; на
//! других ОС — ошибка «только Windows»).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tunnel_winsvc::{InstallOptions, ServiceEvent};

use crate::hub::{Backend, Hub};
use crate::lock::InstanceLock;
use crate::log::{Level, LogFn, Logger};
use crate::server::IpcServer;

/// Бэкенд-заглушка без движка (тесты режимов): снимок `{"engine": null}`,
/// команды отклоняются. Рабочий бэкенд `console`/`service` —
/// [`crate::DaemonBackend`].
pub struct NullBackend;

impl Backend for NullBackend {
    fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({ "engine": null })
    }
    fn poll_events(&self) -> Vec<serde_json::Value> {
        Vec::new()
    }
    fn send(&self, _cmd: serde_json::Value) -> Result<(), String> {
        Err("движок не подключён".into())
    }
    fn me(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
    fn changed(&self) -> bool {
        false
    }
}

/// Где демон слушает фронтендов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcMode {
    /// Без IPC (Windows `console` без прав администратора).
    None,
    /// Unix-сокет `<данные>/daemon.sock`.
    #[cfg(unix)]
    Unix,
    /// Named pipe: имя, SID пользователя с доступом и владелец объекта
    /// (`O:SY` у службы, `O:BA` у `console` от администратора).
    #[cfg(windows)]
    Pipe {
        name: String,
        owner_sid: Option<String>,
        owner: tunnel_ipc::transport::PipeOwner,
    },
}

impl IpcMode {
    /// IPC режима `console`: на Unix — сокет; на Windows — пайп, если процесс
    /// запущен от администратора (иначе `O:BA` не поставить, SECURITY.md §13).
    pub fn console_default() -> Self {
        #[cfg(unix)]
        {
            IpcMode::Unix
        }
        #[cfg(not(unix))]
        {
            console_pipe()
        }
    }
}

/// Решение по пайпу `console` (чистая функция — таблица в тестах).
#[cfg(windows)]
fn console_pipe_decision(elevated: bool, sid: std::io::Result<String>) -> IpcMode {
    match (elevated, sid) {
        (true, Ok(sid)) => IpcMode::Pipe {
            name: tunnel_ipc::transport::DEFAULT_PIPE_NAME.into(),
            owner_sid: Some(sid),
            owner: tunnel_ipc::transport::PipeOwner::Administrators,
        },
        _ => IpcMode::None,
    }
}

/// Пайп `console` на Windows: только из повышенного процесса.
#[cfg(all(not(unix), windows))]
fn console_pipe() -> IpcMode {
    let elevated = tunnel_ipc::transport::is_elevated().unwrap_or(false);
    console_pipe_decision(elevated, tunnel_ipc::transport::current_user_sid())
}

/// Не-Windows и не-Unix (не бывает на практике): пайпа нет.
#[cfg(all(not(unix), not(windows)))]
fn console_pipe() -> IpcMode {
    IpcMode::None
}

/// Почему IPC выключен (для лога; `console` без прав администратора).
#[cfg(windows)]
fn ipc_none_reason() -> &'static str {
    "на Windows пайп поднимает служба (tunnel-daemon install) или console от администратора"
}

/// Почему IPC выключен (не-Windows; в норме недостижимо).
#[cfg(not(windows))]
fn ipc_none_reason() -> &'static str {
    "режим без IPC"
}

/// Понятная ошибка подъёма пайпа: занятое имя — это чаще всего работающая служба.
#[cfg(windows)]
fn pipe_error(name: &str, e: &std::io::Error) -> String {
    // ERROR_ACCESS_DENIED (5) — имя занято первым экземпляром (наш или чужой),
    // ERROR_PIPE_BUSY (231) — свободных экземпляров нет.
    match e.raw_os_error() {
        Some(5) | Some(231) => format!(
            "IPC: пайп {name}: {e} (пайп уже поднят — вероятно, работает служба TunnelDaemon; \
остановите её или запускайте «tunnel-client tui --embedded»)"
        ),
        _ => format!("IPC: пайп {name}: {e}"),
    }
}

/// `console --seed-config`: перенести `%APPDATA%\tunnel\client.json` в каталог
/// данных демона (как `install`), если у демона конфига ещё нет. Возвращает
/// путь источника, если перенос сделан.
///
/// SECURITY.md §12: пользовательский конфиг — в `%APPDATA%`, его может писать
/// любой процесс пользователя, поэтому перенос только явным флагом.
pub fn seed_user_config(dir: &Path) -> Result<Option<PathBuf>, String> {
    #[cfg(windows)]
    {
        tunnel_winsvc::import_user_config(dir, None).map_err(|e| format!("{e:#}"))
    }
    #[cfg(not(windows))]
    {
        let _ = dir;
        Ok(None)
    }
}

/// Параметры запуска ядра демона.
#[derive(Debug, Clone)]
pub struct RunOpts {
    pub data_dir: std::path::PathBuf,
    pub debug: bool,
    /// Дублировать лог в stderr.
    pub console_log: bool,
    pub ipc: IpcMode,
    /// Причина в `Shutdown` фронтендам при остановке.
    pub stop_reason: String,
}

impl RunOpts {
    pub fn console(data_dir: &Path, debug: bool) -> Self {
        RunOpts {
            data_dir: data_dir.to_path_buf(),
            debug,
            console_log: true,
            ipc: IpcMode::console_default(),
            stop_reason: "демон остановлен".into(),
        }
    }

    /// Режим службы: лог только в файл, IPC — заданный (на Windows — пайп).
    pub fn service(data_dir: &Path, ipc: IpcMode) -> Self {
        RunOpts {
            data_dir: data_dir.to_path_buf(),
            debug: false,
            console_log: false,
            ipc,
            stop_reason: "служба остановлена".into(),
        }
    }
}

/// `tunnel-daemon console`: замок, лог (файл + stderr), IPC (Unix-сокет;
/// на Windows без пайпа), цикл хаба до `stop`.
/// `make_backend` получает колбэк лога — интеграция отдаёт его движку
/// (вместо `eprintln!`); тот же лог получает хаб (переполнения подписчиков).
pub fn run_console<B: Backend + 'static>(
    data_dir: &Path,
    debug: bool,
    make_backend: impl FnOnce(LogFn) -> B,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    run_daemon(&RunOpts::console(data_dir, debug), make_backend, stop)
}

/// Ядро демона для любого режима: замок single-instance, лог, хаб, IPC-сервер;
/// блокирует до `stop`, затем `Shutdown` фронтендам и выход. Второй экземпляр
/// на том же каталоге данных (Windows — на той же машине) получает ошибку замка.
pub fn run_daemon<B: Backend + 'static>(
    opts: &RunOpts,
    make_backend: impl FnOnce(LogFn) -> B,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let data_dir = opts.data_dir.as_path();
    // Unix: каталог закрывается (0700) до замка и до бэкенда, который пишет
    // client.json с identity.
    #[cfg(unix)]
    crate::server::prepare_private_dir(data_dir, None)
        .map_err(|e| format!("каталог данных {}: {e}", data_dir.display()))?;
    // Windows: замок исключает только службу vs embedded TUI / run / console
    // (единственность службы — SCM, сервера пайпа — FIRST_PIPE_INSTANCE);
    // мьютекс постороннего владельца замок игнорирует.
    let _lock = InstanceLock::acquire(data_dir).map_err(|e| e.to_string())?;
    let level = if opts.debug {
        Level::Debug
    } else {
        Level::Info
    };
    let log = Logger::open(&crate::log_dir(data_dir), level, opts.console_log)
        .map_err(|e| format!("лог {}: {e}", crate::log_dir(data_dir).display()))?;
    log.log(
        Level::Info,
        &format!("демон запущен, данные: {}", data_dir.display()),
    );
    let hub = Arc::new(Hub::with_log(make_backend(log.callback()), log.callback()));
    let server = match &opts.ipc {
        IpcMode::None => {
            log.log(
                Level::Info,
                &format!(
                    "IPC выключен (фронтенды не подключатся): {}",
                    ipc_none_reason()
                ),
            );
            None
        }
        #[cfg(unix)]
        IpcMode::Unix => Some(
            IpcServer::start_unix(hub.clone(), data_dir, Some(log.callback())).map_err(|e| {
                log.log(Level::Error, &format!("IPC: {e}"));
                format!("IPC: {e}")
            })?,
        ),
        #[cfg(windows)]
        IpcMode::Pipe {
            name,
            owner_sid,
            owner,
        } => Some(
            IpcServer::start_pipe(
                hub.clone(),
                name,
                *owner,
                owner_sid.as_deref(),
                Some(log.callback()),
            )
            .map_err(|e| {
                log.log(Level::Error, &format!("IPC: пайп {name}: {e}"));
                pipe_error(name, &e)
            })?,
        ),
    };
    hub.run(&stop);
    if let Some(s) = server {
        s.shutdown(&opts.stop_reason);
    }
    log.log(Level::Info, "демон остановлен");
    Ok(())
}

static STOP: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Ctrl+C (и SIGTERM на Unix, закрытие консоли на Windows) взводит `stop`,
/// чтобы [`run_console`] вышел штатно: лог «демон остановлен», drop замка.
/// Повторный вызов ничего не меняет (флаг — первый переданный).
pub fn install_ctrl_handler(stop: Arc<AtomicBool>) {
    if STOP.set(stop).is_err() {
        return;
    }
    #[cfg(unix)]
    {
        extern "C" fn on_signal(_: libc::c_int) {
            // Только атомарная запись — async-signal-safe.
            if let Some(s) = STOP.get() {
                s.store(true, Ordering::Relaxed);
            }
        }
        let h = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: обработчик лишь пишет в атомик, инициализированный выше.
        unsafe {
            libc::signal(libc::SIGINT, h);
            libc::signal(libc::SIGTERM, h);
        }
    }
    #[cfg(windows)]
    {
        unsafe extern "system" fn on_ctrl(_: u32) -> windows_sys::core::BOOL {
            if let Some(s) = STOP.get() {
                s.store(true, Ordering::Relaxed);
            }
            1 // обработано: процесс не убивается сразу
        }
        // SAFETY: обработчик лишь пишет в атомик, инициализированный выше.
        unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_ctrl), 1) };
    }
}

/// Подсказка бэкенду «система вышла из сна — переподключись сейчас, не
/// дожидаясь таймеров». Служба взводит её на POWEREVENT resume; бэкенд
/// снимает [`ResumeSignal::take`] (например, в `poll_events`).
#[derive(Clone, Default)]
pub struct ResumeSignal(Arc<AtomicBool>);

impl ResumeSignal {
    pub fn raise(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    /// Сигнал взведён и ещё не снят (флаг не трогается).
    pub fn is_raised(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
    /// `true` — был выход из сна после прошлого вызова (флаг сбрасывается).
    pub fn take(&self) -> bool {
        self.0.swap(false, Ordering::Relaxed)
    }
}

/// Что служба отдаёт фабрике бэкенда.
pub struct ServiceEnv {
    /// Каталог данных службы (`client.json`, identity, логи).
    pub data_dir: PathBuf,
    /// Лог демона (вместо `eprintln!` движка).
    pub log: LogFn,
    /// `wintun.dll` только рядом с exe (`tunnel_winsvc::service_wintun_dll`);
    /// `None` — не нашлась (ошибка уже в логе), TUN поднять нельзя.
    pub wintun_dll: Option<PathBuf>,
    /// Хук выхода из сна.
    pub resume: ResumeSignal,
}

/// Ошибка режимов службы вне Windows.
pub const ONLY_WINDOWS: &str =
    "этот режим — только Windows (служба SCM); на этой ОС используйте `tunnel-daemon console`";

/// Тело службы (без SCM, тестируется на любой ОС): ядро демона в отдельном
/// потоке; Stop/Shutdown (или закрытый канал) — остановка, Resume — подсказка
/// бэкенду. Если ядро завершилось само (ошибка замка/пайпа) — его результат.
#[cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "вызывается только из службы SCM (Windows); на других ОС — в тестах"
    )
)]
pub(crate) fn service_body<B, F>(
    opts: RunOpts,
    make_backend: F,
    events: Receiver<ServiceEvent>,
    wintun_dll: impl FnOnce() -> Result<PathBuf, String> + Send + 'static,
    warnings: Vec<String>,
) -> Result<(), String>
where
    B: Backend + 'static,
    F: FnOnce(ServiceEnv) -> B + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let resume = ResumeSignal::default();
    let data_dir = opts.data_dir.clone();
    let core = {
        let stop = stop.clone();
        let resume = resume.clone();
        std::thread::Builder::new()
            .name("daemon-core".into())
            .spawn(move || {
                run_daemon(
                    &opts,
                    move |log: LogFn| {
                        for w in &warnings {
                            log(Level::Warn, w);
                        }
                        let dll = match wintun_dll() {
                            Ok(p) => Some(p),
                            Err(e) => {
                                log(Level::Error, &format!("wintun: {e}"));
                                None
                            }
                        };
                        make_backend(ServiceEnv {
                            data_dir,
                            log,
                            wintun_dll: dll,
                            resume,
                        })
                    },
                    stop,
                )
            })
            .map_err(|e| format!("поток демона: {e}"))?
    };
    loop {
        if core.is_finished() {
            break;
        }
        match events.recv_timeout(Duration::from_millis(200)) {
            Ok(ServiceEvent::Stop | ServiceEvent::Shutdown)
            | Err(RecvTimeoutError::Disconnected) => {
                stop.store(true, Ordering::Relaxed);
                break;
            }
            Ok(ServiceEvent::Resume) => resume.raise(),
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
    core.join()
        .map_err(|_| "поток демона упал (panic)".to_string())?
}

/// `tunnel-daemon service`: точка входа SCM. Данные — `data_dir` или
/// `%ProgramData%\tunnel`; IPC — пайп `tunnel_ipc::transport::DEFAULT_PIPE_NAME`
/// с SID владельца из `owner.sid`; блокирует до Stop/Shutdown.
pub fn run_service<B, F>(data_dir: Option<&Path>, make_backend: F) -> Result<(), String>
where
    B: Backend + 'static,
    F: FnOnce(ServiceEnv) -> B + Send + 'static,
{
    #[cfg(windows)]
    {
        let dir = data_dir
            .map(Path::to_path_buf)
            .unwrap_or_else(tunnel_winsvc::data_dir);
        let mut warnings = Vec::new();
        let owner_sid = match tunnel_winsvc::read_owner_sid(&dir) {
            Ok(sid) => Some(sid),
            Err(e) => {
                warnings.push(format!(
                    "{e:#}; пайп доступен только SYSTEM и администраторам"
                ));
                None
            }
        };
        let ipc = IpcMode::Pipe {
            name: tunnel_ipc::transport::DEFAULT_PIPE_NAME.into(),
            owner_sid,
            owner: tunnel_ipc::transport::PipeOwner::System,
        };
        let opts = RunOpts::service(&dir, ipc);
        tunnel_winsvc::run_as_service(tunnel_winsvc::SERVICE_NAME, move |rx| {
            service_body(
                opts,
                make_backend,
                rx,
                || tunnel_winsvc::service_wintun_dll().map_err(|e| format!("{e:#}")),
                warnings,
            )
            .map_err(anyhow::Error::msg)
        })
        .map_err(|e| format!("{e:#}"))
    }
    #[cfg(not(windows))]
    {
        let _ = (data_dir, make_backend);
        Err(ONLY_WINDOWS.into())
    }
}

/// Параметры установки: служба — этот exe, трей — `tunnel-tray.exe` рядом
/// (нет файла — без Run-ключа и ярлыка, с предупреждением).
#[cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "вызывается только из службы SCM (Windows); на других ОС — в тестах"
    )
)]
pub(crate) fn install_options(
    exe: &Path,
    appdata: Option<&Path>,
) -> Result<(InstallOptions, Vec<String>), String> {
    let dir = exe
        .parent()
        .filter(|d| d.is_absolute())
        .ok_or_else(|| format!("путь exe должен быть абсолютным: {}", exe.display()))?;
    let mut o = InstallOptions::for_layout(dir, appdata);
    o.daemon_exe = exe.to_path_buf();
    let mut warnings = Vec::new();
    if let Some(tray) = &o.tray_exe
        && !tray.is_file()
    {
        warnings.push(format!(
            "нет {} — трей не будет автозапускаться",
            tray.display()
        ));
        o.tray_exe = None;
        o.shortcut = None;
    }
    Ok((o, warnings))
}

/// Каталог данных `console` на Windows: нет — создаётся с ACL службы
/// (SYSTEM и Administrators), есть — должен быть так же закрыт (иначе
/// отказ: client.json и identity мог подложить обычный пользователь).
/// На других ОС каталог закрывает [`run_daemon`] (`0700`).
pub fn secure_console_data_dir(dir: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        tunnel_winsvc::secure_data_dir(dir).map_err(|e| format!("{e:#}"))
    }
    #[cfg(not(windows))]
    {
        let _ = dir;
        Ok(())
    }
}

/// `tunnel-daemon install`: установить (обновить) и запустить службу.
/// Каталог exe должен быть доступен на запись только администраторам
/// (проверяет `tunnel_winsvc::install`), иначе отказ.
pub fn install() -> Result<(), String> {
    #[cfg(windows)]
    {
        let exe = std::env::current_exe().map_err(|e| format!("путь exe: {e}"))?;
        let appdata = std::env::var_os("APPDATA").map(PathBuf::from);
        let (opts, mut warnings) = install_options(&exe, appdata.as_deref())?;
        let r = tunnel_winsvc::install(&opts).map_err(|e| format!("{e:#}"))?;
        warnings.extend(r.warnings);
        println!(
            "служба {} {}; данные: {}; владелец: {}{}",
            opts.service_name,
            if r.service_updated {
                "обновлена"
            } else {
                "установлена"
            },
            r.data_dir.display(),
            r.owner_sid,
            if r.config_imported {
                "; client.json импортирован"
            } else {
                ""
            },
        );
        for w in warnings {
            eprintln!("предупреждение: {w}");
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err(ONLY_WINDOWS.into())
    }
}

/// `tunnel-daemon uninstall [--purge]`. `remove_adapter` — удаление
/// Wintun-адаптера (его знает движок), вызывается после остановки службы.
pub fn uninstall(
    purge: bool,
    remove_adapter: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        let appdata = std::env::var_os("APPDATA").map(PathBuf::from);
        let opts = tunnel_winsvc::UninstallOptions::standard(purge, appdata.as_deref());
        tunnel_winsvc::uninstall(&opts, || remove_adapter().map_err(anyhow::Error::msg))
            .map_err(|e| format!("{e:#}"))?;
        println!(
            "служба {} удалена{}",
            opts.service_name,
            if purge {
                " вместе с данными"
            } else {
                ""
            }
        );
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (purge, remove_adapter);
        Err(ONLY_WINDOWS.into())
    }
}

#[cfg(test)]
mod service_tests {
    use std::sync::Mutex;
    use std::sync::mpsc;
    use std::time::Instant;

    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tunnel-svc-{tag}-{}", std::process::id()))
    }

    /// На Windows замок движка — `Global\TunnelEngine`, один на машину,
    /// поэтому тесты, поднимающие `run_daemon`, идут по очереди: иначе
    /// второй получает `LockError::Busy` и бэкенд не создаётся.
    static ENGINE_LOCK: Mutex<()> = Mutex::new(());

    fn engine_guard() -> std::sync::MutexGuard<'static, ()> {
        ENGINE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn body_resume_then_stop() {
        let _engine = engine_guard();
        let dir = tmp("body");
        let _ = std::fs::remove_dir_all(&dir);
        let (tx, rx) = mpsc::channel();
        type Seen = Option<(ResumeSignal, Option<PathBuf>)>;
        let seen: Arc<Mutex<Seen>> = Default::default();
        let s2 = seen.clone();
        let opts = RunOpts::service(&dir, IpcMode::None);
        let body = std::thread::spawn(move || {
            service_body(
                opts,
                move |env: ServiceEnv| {
                    *s2.lock().unwrap() = Some((env.resume.clone(), env.wintun_dll.clone()));
                    crate::FakeBackend::new()
                },
                rx,
                || Err("нет".into()),
                vec!["тест".into()],
            )
        });
        let t0 = Instant::now();
        let (sig, dll) = loop {
            if let Some(s) = seen.lock().unwrap().clone() {
                break s;
            }
            assert!(t0.elapsed() < Duration::from_secs(10), "бэкенд не создан");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(dll, None);
        tx.send(ServiceEvent::Resume).unwrap();
        let t0 = Instant::now();
        while !sig.take() {
            assert!(t0.elapsed() < Duration::from_secs(10), "resume не дошёл");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!sig.take());
        tx.send(ServiceEvent::Shutdown).unwrap();
        assert_eq!(body.join().unwrap(), Ok(()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Тело службы с её настоящим бэкендом (`DaemonBackend::service`) на
    /// пустом каталоге данных: identity создана, IPC отвечает в состоянии
    /// «нет сервера» (TUN не трогается), Stop — штатный выход.
    #[cfg(unix)]
    #[test]
    fn body_service_backend_no_server() {
        use tunnel_ipc::{AckResult, ClientKind, IpcClient};
        // Короткий путь: лимит sun_path ~104 байта на macOS.
        let dir = std::env::temp_dir().join(format!("tsv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (tx, rx) = mpsc::channel();
        let opts = RunOpts::service(&dir, IpcMode::Unix);
        let body = std::thread::spawn(move || {
            service_body(
                opts,
                crate::DaemonBackend::service,
                rx,
                || Err("нет".into()),
                Vec::new(),
            )
        });
        let t = Duration::from_secs(10);
        let t0 = Instant::now();
        let mut c = loop {
            if let Ok(c) =
                IpcClient::connect(crate::server::socket_path(&dir), ClientKind::Cli, "test", t)
            {
                break c;
            }
            assert!(
                t0.elapsed() < t && !body.is_finished(),
                "служба не подняла IPC"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            c.me()["my_code"].as_str().is_some_and(|s| !s.is_empty()),
            "identity создана"
        );
        let cfg = std::fs::read_to_string(dir.join("client.json")).unwrap();
        assert!(cfg.contains("ed_seed"));
        match c.request(serde_json::json!("RefreshList"), t).unwrap() {
            AckResult::Err(e) => assert_eq!(e, crate::engine_backend::NO_SERVER),
            r => panic!("ждали Err, пришло {r:?}"),
        }
        assert_eq!(
            c.request(serde_json::json!({ "SetName": "svc" }), t)
                .unwrap(),
            AckResult::Ok
        );
        tx.send(ServiceEvent::Resume).unwrap();
        tx.send(ServiceEvent::Stop).unwrap();
        assert_eq!(body.join().unwrap(), Ok(()));
        assert!(
            std::fs::read_to_string(dir.join("client.json"))
                .unwrap()
                .contains("svc")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unix: каталог данных закрыт (0700) уже к созданию бэкенда, который
    /// пишет client.json с identity, — а не только к подъёму сокета.
    #[cfg(unix)]
    #[test]
    fn data_dir_private_before_backend() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("priv");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let seen = Arc::new(Mutex::new(None::<u32>));
        let (s2, d2) = (seen.clone(), dir.clone());
        run_daemon(
            &RunOpts::service(&dir, IpcMode::None),
            move |_log| {
                let m = std::fs::metadata(&d2).unwrap().permissions().mode() & 0o777;
                *s2.lock().unwrap() = Some(m);
                crate::FakeBackend::new()
            },
            Arc::new(AtomicBool::new(true)),
        )
        .unwrap();
        assert_eq!(*seen.lock().unwrap(), Some(0o700));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn body_returns_core_error() {
        let _engine = engine_guard();
        // Каталог данных — файл: замок/лог не создать, ядро выходит с ошибкой.
        let f = tmp("file");
        std::fs::write(&f, b"x").unwrap();
        let (_tx, rx) = mpsc::channel();
        let r = service_body(
            RunOpts::service(&f, IpcMode::None),
            |_env: ServiceEnv| crate::FakeBackend::new(),
            rx,
            || Err("нет".into()),
            Vec::new(),
        );
        assert!(r.is_err());
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn install_layout() {
        let dir = tmp("inst");
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("my-daemon.exe");
        let appdata = dir.join("appdata");
        let (o, w) = install_options(&exe, Some(&appdata)).unwrap();
        assert_eq!(o.daemon_exe, exe);
        assert_eq!(o.tray_exe, None);
        assert!(o.shortcut.is_none());
        assert_eq!(w.len(), 1);
        std::fs::write(dir.join(tunnel_winsvc::TRAY_EXE), b"").unwrap();
        let (o, w) = install_options(&exe, Some(&appdata)).unwrap();
        assert_eq!(o.tray_exe, Some(dir.join(tunnel_winsvc::TRAY_EXE)));
        assert!(o.shortcut.is_some());
        assert!(w.is_empty());
        assert!(install_options(Path::new("rel.exe"), None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(not(windows))]
    #[test]
    fn windows_only_modes() {
        assert_eq!(install(), Err(ONLY_WINDOWS.into()));
        assert_eq!(uninstall(true, || Ok(())), Err(ONLY_WINDOWS.into()));
        assert_eq!(
            run_service(None, |_e: ServiceEnv| NullBackend),
            Err(ONLY_WINDOWS.into())
        );
    }
}
