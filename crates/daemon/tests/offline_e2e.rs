//! Офлайн-TUI и демон (этап 9, §3.8): TUI без движка правит конфиг сам
//! (`offline::ResilientEngine`), правки не теряются и уходят демону — в том
//! числе когда он сам стоит в состоянии «нет сервера». Очередь
//! `ui-pending.json` очищается после применения.
//!
//! Unix-only, как остальные e2e демона (IPC поверх Unix-сокета); сервер
//! `tunnel-server` — в том же процессе, TUN — заглушка.
#![cfg(unix)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tunnel_client::api::{EngineApi, EngineMode};
use tunnel_client::engine::{self, Cmd, TunDev};
use tunnel_client::offline::PENDING_FILE;
use tunnel_client::remote::connect_offline;
use tunnel_client::store::{self, Config};
use tunnel_daemon::engine_backend::{DaemonEngine, EngineStart, StartFn};
use tunnel_daemon::server::socket_path;
use tunnel_daemon::{Backend, EngineBackend, IpcMode, RunOpts, run_daemon};
use tunnel_ipc::{ClientKind, IpcClient};
use tunnel_protocol as proto;

const T: Duration = Duration::from_secs(10);

struct NullTun;

impl TunDev for NullTun {
    fn inject(&self, _packet: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
    fn ensure_address(&self, _ip: u32) -> anyhow::Result<()> {
        Ok(())
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    // Короткий путь: лимит sun_path ~104 байта на macOS.
    let d = std::env::temp_dir().join(format!("tdo-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn start_server(dir: &std::path::Path) -> tunnel_server::Server {
    tunnel_server::Server::start(tunnel_server::Config {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        data_dir: dir.to_path_buf(),
        workers: 2,
        quiet: true,
        ..Default::default()
    })
    .expect("сервер стартует")
}

/// Адрес сервера глазами клиента (`localhost`-вариант для теста).
fn local(addr: SocketAddr) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], addr.port()))
}

/// Демон целиком: `EngineBackend` с TUN-заглушкой (как в остальных e2e).
fn test_start(starts: Arc<AtomicU32>) -> StartFn {
    Arc::new(move |a: EngineStart| {
        starts.fetch_add(1, Ordering::SeqCst);
        let eng = engine::start_with_tun(
            a.cfg,
            local(a.server),
            a.server_pub,
            a.identity,
            Arc::new(NullTun),
            a.save,
        )?;
        Ok(EngineBackend::new(eng))
    })
}

struct Daemon {
    dir: PathBuf,
    stop: Arc<AtomicBool>,
    th: Option<JoinHandle<Result<(), String>>>,
}

impl Daemon {
    fn start_in<B: Backend + 'static>(
        dir: PathBuf,
        make: impl FnOnce(tunnel_daemon::LogFn) -> B + Send + 'static,
    ) -> Daemon {
        let stop = Arc::new(AtomicBool::new(false));
        let opts = RunOpts {
            data_dir: dir.clone(),
            debug: true,
            console_log: false,
            ipc: IpcMode::Unix,
            stop_reason: "тест окончен".into(),
        };
        let s = stop.clone();
        let th = std::thread::spawn(move || run_daemon(&opts, make, s));
        let d = Daemon {
            dir,
            stop,
            th: Some(th),
        };
        let t0 = Instant::now();
        loop {
            if let Ok(c) = IpcClient::connect(socket_path(&d.dir), ClientKind::Cli, "probe", T) {
                c.bye();
                break;
            }
            assert!(
                !d.th.as_ref().unwrap().is_finished() && t0.elapsed() < T,
                "демон не поднялся"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        d
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.th.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Конфиг с identity (как его создаёт `main`) и без серверов.
fn write_identity(dir: &std::path::Path) -> (Config, proto::Identity) {
    let mut cfg = Config::default();
    let id = store::ensure_identity(&mut cfg);
    std::fs::write(dir.join("client.json"), serde_json::to_vec(&cfg).unwrap()).unwrap();
    (cfg, id)
}

fn read_cfg(dir: &std::path::Path) -> Config {
    serde_json::from_slice(&std::fs::read(dir.join("client.json")).expect("client.json")).unwrap()
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while !f() {
        assert!(t0.elapsed() < T, "не дождались: {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// TUI без демона: правки применяются локально, очередь на диске; демон
/// стартует уже с нашим `client.json` — очередь не задваивается и очищается.
#[test]
fn офлайн_правки_уходят_демону_после_его_старта() {
    let sdir = temp_dir("s");
    let server = start_server(&sdir);
    let server_addr = local(server.addr);
    let dir = temp_dir("d");
    let (cfg, id) = write_identity(&dir);

    let eng = connect_offline(&dir, Arc::new(Mutex::new(cfg)), id).expect("офлайн-движок");
    assert_eq!(eng.mode(), EngineMode::Offline);
    assert!(eng.unavailable(), "демона нет");
    assert!(eng.snapshot().meta.offline);

    // Правки офлайн-TUI: добавляем сервер и имя (как экран «Серверы»).
    eng.send(Cmd::AddServer {
        addr: server_addr.to_string(),
        pubkey: server.pubkey,
        label: "дом".into(),
    })
    .unwrap();
    eng.send(Cmd::SetName("tui".into())).unwrap();
    assert_eq!(eng.pending_edits(), 2, "правки в очереди");
    assert!(dir.join(PENDING_FILE).exists(), "очередь на диске");
    let saved = read_cfg(&dir);
    assert_eq!(saved.name, "tui");
    assert_eq!(saved.servers.len(), 1);
    assert_eq!(saved.servers[0].addr, server_addr.to_string());

    // Демон стартует с этим же каталогом: движок поднимается сразу.
    let starts = Arc::new(AtomicU32::new(0));
    let (dd, st) = (dir.clone(), starts.clone());
    let d = Daemon::start_in(dir.clone(), move |log| {
        let e = DaemonEngine::open(&dd, log, test_start(st), None).expect("каталог данных");
        assert!(e.has_server());
        e.start_async();
        e
    });

    assert!(eng.wait_remote(T), "TUI подключился к демону");
    assert!(eng.wait_live(T), "движок демона поднялся");
    assert!(eng.wait_pending_empty(T), "очередь применена");
    assert!(!dir.join(PENDING_FILE).exists(), "очередь очищена");
    wait_until("снимок живого демона", || {
        let s = eng.snapshot();
        s.meta.connected && !s.meta.offline && s.cfg.servers.len() == 1
    });
    assert_eq!(eng.mode(), EngineMode::Remote);
    assert!(!eng.unavailable());

    drop(eng);
    drop(d);
    server.stop();
    let _ = std::fs::remove_dir_all(&sdir);
}

/// Демон уже работает, но без движка (в конфиге нет серверов). TUI-офлайн
/// добавляет сервер: правка уходит демону, он сохраняет её и поднимает
/// движок — без перезапуска и без очереди.
#[test]
fn tui_добавляет_сервер_демону_в_состоянии_нет_сервера() {
    let sdir = temp_dir("s");
    let server = start_server(&sdir);
    let server_addr = local(server.addr);
    let dir = temp_dir("d");
    let (cfg, id) = write_identity(&dir);

    let starts = Arc::new(AtomicU32::new(0));
    let (dd, st) = (dir.clone(), starts.clone());
    let d = Daemon::start_in(dir.clone(), move |log| {
        let e = DaemonEngine::open(&dd, log, test_start(st), None).expect("каталог данных");
        assert!(!e.has_server());
        e
    });

    let eng = connect_offline(&dir, Arc::new(Mutex::new(cfg)), id).expect("офлайн-движок");
    assert!(eng.wait_remote(T), "демон доступен");
    assert!(!eng.is_live(), "движка в демоне нет");
    assert!(
        !eng.unavailable(),
        "демон-то доступен — пилюля «сервер недоступен»"
    );
    let snap = eng.snapshot();
    assert!(snap.meta.offline);
    assert!(
        snap.meta
            .offline_reason
            .as_deref()
            .is_some_and(|r| r.contains("нет сервера")),
        "причина видна TUI: {:?}",
        snap.meta.offline_reason
    );

    // Сетевая команда без движка — отказ; правка конфига — демону.
    assert!(eng.send(Cmd::Join(1)).is_err());
    eng.send(Cmd::AddServer {
        addr: server_addr.to_string(),
        pubkey: server.pubkey,
        label: "дом".into(),
    })
    .unwrap();

    assert!(eng.wait_live(T), "демон поднял движок по AddServer");
    assert!(starts.load(Ordering::SeqCst) >= 1, "запуск движка был");
    assert_eq!(eng.pending_edits(), 0, "правка ушла демону, не в очередь");
    assert!(!dir.join(PENDING_FILE).exists());
    wait_until("снимок живого демона", || {
        let s = eng.snapshot();
        s.meta.connected && !s.meta.offline && s.cfg.servers.len() == 1
    });
    // Демон сохранил сервер в client.json (и движок уже с ним).
    let saved = read_cfg(&dir);
    assert_eq!(saved.servers.len(), 1);
    assert_eq!(saved.servers[0].addr, server_addr.to_string());
    assert_eq!(saved.servers[0].pubkey, proto::hex_of(&server.pubkey));

    drop(eng);
    drop(d);
    server.stop();
    let _ = std::fs::remove_dir_all(&sdir);
}
