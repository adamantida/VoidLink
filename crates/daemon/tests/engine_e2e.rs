//! Демон целиком на настоящем движке (`EngineBackend`) против сервера
//! `tunnel-server` в том же процессе; TUN — заглушка (без прав и адаптера).
//! Фронтенд — `IpcClient` поверх Unix-сокета (PLAN.md 7.3/7.7).
#![cfg(unix)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tunnel_client::engine::{self, Cmd, Engine, Event, TunDev};
use tunnel_client::store::{Config, StoredServer};
use tunnel_daemon::engine_backend::{DaemonEngine, EngineStart, NO_SERVER, StartFn};
use tunnel_daemon::server::socket_path;
use tunnel_daemon::{Backend, EngineBackend, IpcMode, ResumeSignal, RunOpts, run_daemon};
use tunnel_ipc::{AckResult, ClientKind, DaemonMsg, IpcClient};
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
    let d = std::env::temp_dir().join(format!("tdg-{tag}-{}-{n}", std::process::id()));
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

fn local(addr: SocketAddr) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], addr.port()))
}

/// Движок с заглушкой TUN; `saved` — последний сохранённый конфиг.
fn start_engine(
    name: &str,
    server: &tunnel_server::Server,
    id: proto::Identity,
    saved: Arc<Mutex<Option<Config>>>,
) -> Engine {
    let addr = local(server.addr);
    let cfg = Config {
        name: name.into(),
        servers: vec![StoredServer {
            addr: addr.to_string(),
            pubkey: proto::hex_of(&server.pubkey),
            label: "тест".into(),
        }],
        ..Config::default()
    };
    let save: Arc<dyn Fn(&Config) + Send + Sync> =
        Arc::new(move |c: &Config| *saved.lock().unwrap() = Some(c.clone()));
    engine::start_with_tun(
        Arc::new(Mutex::new(cfg)),
        addr,
        server.pubkey,
        id,
        Arc::new(NullTun),
        save,
    )
    .expect("движок подключается")
}

fn wait_for(c: &mut IpcClient, what: &str, mut pred: impl FnMut(&DaemonMsg) -> bool) -> DaemonMsg {
    let deadline = Instant::now() + T;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match c.recv(Some(left)) {
            Ok(m) if pred(&m) => return m,
            Ok(_) => {}
            Err(e) => panic!("ждали {what}: {e}"),
        }
    }
}

fn snap_where(mut f: impl FnMut(&Value) -> bool) -> impl FnMut(&DaemonMsg) -> bool {
    move |m| matches!(m, DaemonMsg::Snapshot { snap, .. } if f(snap))
}

fn engine_event(eng: &Engine, what: &str, mut f: impl FnMut(&Event) -> bool) -> Event {
    let deadline = Instant::now() + T;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match eng.events.recv_timeout(left) {
            Ok(e) if f(&e) => return e,
            Ok(_) => {}
            Err(e) => panic!("ждали {what}: {e}"),
        }
    }
}

struct Daemon {
    dir: PathBuf,
    stop: Arc<AtomicBool>,
    th: Option<JoinHandle<Result<(), String>>>,
}

impl Daemon {
    fn start(backend: EngineBackend) -> Daemon {
        Daemon::start_in(temp_dir("d"), move |_| backend)
    }

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

    fn client(&self) -> IpcClient {
        let mut c = IpcClient::connect(socket_path(&self.dir), ClientKind::Tui, "test", T)
            .expect("подключение");
        c.subscribe(0).unwrap();
        c
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

#[test]
fn демон_на_настоящем_движке() {
    let sdir = temp_dir("s");
    let server = start_server(&sdir);
    let alice_id = proto::Identity::generate();
    let alice_pub = alice_id.ed_pub();
    let alice_code = alice_id.friend_code();
    let saved = Arc::new(Mutex::new(None));
    let alice = start_engine("alice", &server, alice_id, saved.clone());
    let bob = start_engine(
        "bob",
        &server,
        proto::Identity::generate(),
        Arc::new(Mutex::new(None)),
    );

    let d = Daemon::start(EngineBackend::new(alice));
    let mut c = d.client();
    assert_eq!(c.me()["my_code"], alice_code.as_str());
    assert_eq!(c.me()["my_pub"], proto::hex_of(&alice_pub).as_str());
    wait_for(
        &mut c,
        "снимок «подключён»",
        snap_where(|s| s["meta"]["connected"] == true),
    );

    // Группа: Ack Ok, событие GroupJoined (JSON-форма Event), группа в снимке.
    let create = json!({ "Create": { "name": "игра", "private": false } });
    assert_eq!(c.request(create, T).unwrap(), AckResult::Ok);
    let ev = wait_for(
        &mut c,
        "GroupJoined",
        |m| matches!(m, DaemonMsg::Event { ev, .. } if ev.get("GroupJoined").is_some()),
    );
    let DaemonMsg::Event { ev, .. } = ev else {
        unreachable!()
    };
    let gid = ev["GroupJoined"]["gid"].as_u64().unwrap();
    assert_eq!(ev["GroupJoined"]["name"], "игра");
    wait_for(
        &mut c,
        "группа в снимке",
        snap_where(|s| s["groups"][0]["gid"] == gid),
    );

    // Неверные и запрещённые команды — Err в Ack, соединение живо.
    assert!(matches!(
        c.request(json!({ "Frobnicate": 1 }), T).unwrap(),
        AckResult::Err(_)
    ));
    assert!(matches!(
        c.request(json!("Quit"), T).unwrap(),
        AckResult::Err(_)
    ));
    assert!(
        matches!(
            c.request(json!({ "DelServer": { "idx": 0 } }), T).unwrap(),
            AckResult::Err(_)
        ),
        "текущий сервер"
    );
    assert!(matches!(
        c.request(json!({ "DelServer": { "idx": 5 } }), T).unwrap(),
        AckResult::Err(_)
    ));
    assert!(matches!(
        c.request(
            json!({ "SetAlias": { "pubkey": vec![7u8; 32], "alias": "x" } }),
            T
        )
        .unwrap(),
        AckResult::Err(_)
    ));

    // Правки конфига: друг, alias, второй сервер — видны в снимке и сохранены.
    let fpk = [7u8; 32];
    let add = serde_json::to_value(Cmd::AddFriend {
        pubkey: fpk,
        alias: "друг".into(),
    })
    .unwrap();
    assert_eq!(c.request(add, T).unwrap(), AckResult::Ok);
    let hex = proto::hex_of(&fpk);
    wait_for(
        &mut c,
        "друг в снимке",
        snap_where(|s| s["cfg"]["friends"][0]["pubkey"] == hex.as_str()),
    );
    let alias = serde_json::to_value(Cmd::SetAlias {
        pubkey: fpk,
        alias: "кореш".into(),
    })
    .unwrap();
    assert_eq!(c.request(alias, T).unwrap(), AckResult::Ok);
    wait_for(
        &mut c,
        "alias в снимке",
        snap_where(|s| s["cfg"]["friends"][0]["alias"] == "кореш"),
    );
    let srv = json!({ "AddServer": { "addr": "127.0.0.1:1", "pubkey": vec![1u8; 32], "label": "второй" } });
    assert_eq!(c.request(srv, T).unwrap(), AckResult::Ok);
    wait_for(
        &mut c,
        "два сервера",
        snap_where(|s| s["cfg"]["servers"].as_array().map(Vec::len) == Some(2)),
    );
    assert_eq!(
        c.request(json!({ "DelServer": { "idx": 1 } }), T).unwrap(),
        AckResult::Ok
    );
    assert_eq!(
        c.request(serde_json::to_value(Cmd::DelFriend(fpk)).unwrap(), T)
            .unwrap(),
        AckResult::Ok
    );
    wait_for(
        &mut c,
        "друг и второй сервер удалены",
        snap_where(|s| {
            s["cfg"]["friends"].as_array().is_some_and(Vec::is_empty)
                && s["cfg"]["servers"].as_array().map(Vec::len) == Some(1)
        }),
    );
    {
        let saved = saved.lock().unwrap();
        let cfg = saved.as_ref().expect("конфиг сохранён");
        assert!(cfg.friends.is_empty());
        assert_eq!(cfg.servers.len(), 1);
    }

    // Приглашение от bob → pending_invites снимка; отказ снимает сразу.
    bob.cmds
        .send(Cmd::Create {
            name: "тайная".into(),
            private: true,
        })
        .unwrap();
    let Event::GroupJoined { gid: bgid, .. } = engine_event(&bob, "bob: GroupJoined", |e| {
        matches!(e, Event::GroupJoined { .. })
    }) else {
        unreachable!()
    };
    bob.cmds.send(Cmd::Invite(bgid, alice_pub)).unwrap();
    wait_for(
        &mut c,
        "Invite",
        |m| matches!(m, DaemonMsg::Event { ev, .. } if ev["Invite"]["gid"] == bgid),
    );
    wait_for(
        &mut c,
        "приглашение в снимке",
        snap_where(|s| s["pending_invites"][0]["gid"] == bgid),
    );
    assert_eq!(
        c.request(json!({ "DeclineInvite": bgid }), T).unwrap(),
        AckResult::Ok
    );
    wait_for(
        &mut c,
        "приглашение снято",
        snap_where(|s| s["pending_invites"].as_array().is_some_and(Vec::is_empty)),
    );
    engine_event(
        &bob,
        "bob: InviteDeclined",
        |e| matches!(e, Event::InviteDeclined { gid, .. } if *gid == bgid),
    );

    drop(c);
    drop(d);
    drop(bob);
    server.stop();
    let _ = std::fs::remove_dir_all(&sdir);
}

/// Запуск движка как у демона, но с TUN-заглушкой; адрес сервера из
/// конфига — `localhost`-вариант (сервер слушает 127.0.0.1).
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

/// Первый запуск демона (PLAN.md 7.1): каталог данных пуст → identity
/// создана, IPC работает в состоянии «нет сервера» (снимок с конфигом,
/// сетевые команды — Err, правки конфига — Ok), `AddServer` поднимает движок
/// без перезапуска; выход из сна — подсказка переподключения живому движку.
#[test]
fn нет_сервера_затем_add_server() {
    let sdir = temp_dir("s");
    let server = start_server(&sdir);
    let dir = temp_dir("d");
    let starts = Arc::new(AtomicU32::new(0));
    let resume = ResumeSignal::default();
    let (st, rs) = (starts.clone(), resume.clone());
    let d = Daemon::start_in(dir.clone(), move |log| {
        let e = DaemonEngine::open(&dir, log, test_start(st), Some(rs)).expect("каталог данных");
        assert!(!e.has_server());
        e
    });

    // identity создана и сохранена; `me` — она.
    let saved: Config =
        serde_json::from_slice(&std::fs::read(d.dir.join("client.json")).unwrap()).unwrap();
    assert!(saved.identity.is_some() && saved.servers.is_empty());
    let mut cfg2 = saved.clone();
    let id = tunnel_client::store::ensure_identity(&mut cfg2);
    let mut c = d.client();
    assert_eq!(c.me()["my_code"], id.friend_code().as_str());

    // Снимок «нет сервера» — настоящий Snapshot (фронтенд его разбирает).
    let snap = wait_for(
        &mut c,
        "снимок без сервера",
        snap_where(|s| s["meta"]["connected"] == false),
    );
    let DaemonMsg::Snapshot { snap, .. } = snap else {
        unreachable!()
    };
    let typed: tunnel_client::snapshot::Snapshot =
        serde_json::from_value(snap).expect("снимок разбирается");
    assert!(typed.cfg.servers.is_empty());

    // Сетевые команды — Err «нет сервера»; Quit и мусор — Err.
    match c
        .request(json!({ "Create": { "name": "x", "private": false } }), T)
        .unwrap()
    {
        AckResult::Err(e) => assert_eq!(e, NO_SERVER),
        r => panic!("ждали Err, пришло {r:?}"),
    }
    assert!(matches!(
        c.request(json!("Quit"), T).unwrap(),
        AckResult::Err(_)
    ));
    assert!(matches!(
        c.request(
            json!({ "AddServer": { "addr": "мусор", "pubkey": vec![1u8; 32], "label": "" } }),
            T
        )
        .unwrap(),
        AckResult::Err(_)
    ));

    // Правки конфига без движка: имя — в снимке и на диске.
    assert_eq!(
        c.request(json!({ "SetName": "алиса" }), T).unwrap(),
        AckResult::Ok
    );
    // Заявка в друзья — сетевая команда (issue #24): без движка её некуда
    // отправить, поэтому Err и никакой локальной записи «друг, которого нет».
    let fpk = [9u8; 32];
    let add = serde_json::to_value(Cmd::AddFriend {
        pubkey: fpk,
        alias: "друг".into(),
    })
    .unwrap();
    assert!(matches!(c.request(add, T).unwrap(), AckResult::Err(_)));
    wait_for(
        &mut c,
        "имя в снимке, друга нет",
        snap_where(|s| {
            s["cfg"]["name"] == "алиса"
                && s["cfg"]["friends"].as_array().is_some_and(|f| f.is_empty())
        }),
    );
    assert_eq!(
        starts.load(Ordering::SeqCst),
        0,
        "без сервера движок не запускается"
    );

    // AddServer → движок поднимается сам, без перезапуска демона.
    let addr = local(server.addr);
    let srv = serde_json::to_value(Cmd::AddServer {
        addr: addr.to_string(),
        pubkey: server.pubkey,
        label: "тест".into(),
    })
    .unwrap();
    assert_eq!(c.request(srv, T).unwrap(), AckResult::Ok);
    wait_for(
        &mut c,
        "снимок «подключён»",
        snap_where(|s| s["meta"]["connected"] == true && s["cfg"]["name"] == "алиса"),
    );
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    let saved: Config =
        serde_json::from_slice(&std::fs::read(d.dir.join("client.json")).unwrap()).unwrap();
    assert_eq!(saved.servers.len(), 1);
    assert_eq!(saved.name, "алиса");
    // Заявка без движка не сохранялась (issue #24): список друзей пуст.
    assert_eq!(saved.friends.len(), 0);
    assert_eq!(
        saved.identity.as_ref().map(|i| &i.ed_seed),
        cfg2.identity.as_ref().map(|i| &i.ed_seed),
        "identity та же"
    );

    // Теперь сетевые команды идут движку.
    let create = json!({ "Create": { "name": "игра", "private": false } });
    assert_eq!(c.request(create, T).unwrap(), AckResult::Ok);
    wait_for(
        &mut c,
        "GroupJoined",
        |m| matches!(m, DaemonMsg::Event { ev, .. } if ev.get("GroupJoined").is_some()),
    );

    // Выход из сна: Reconnect живому движку — связь остаётся, группа тоже.
    resume.raise();
    let t0 = Instant::now();
    while resume.is_raised() {
        assert!(t0.elapsed() < T, "сигнал выхода из сна не снят");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));
    wait_for(
        &mut c,
        "после resume: подключён, группа на месте",
        snap_where(|s| {
            s["meta"]["connected"] == true && s["groups"].as_array().map(Vec::len) == Some(1)
        }),
    );
    assert_eq!(c.request(json!("Reconnect"), T).unwrap(), AckResult::Ok);
    assert_eq!(c.request(json!("RefreshList"), T).unwrap(), AckResult::Ok);

    drop(c);
    drop(d);
    server.stop();
    let _ = std::fs::remove_dir_all(&sdir);
}

/// Сервер в конфиге недоступен: демон не падает, остаётся в «нет сервера»
/// с причиной, событие Error уходит фронтенду; правки конфига работают.
#[test]
fn запуск_движка_не_удался() {
    let dir = temp_dir("f");
    let cfg = Config {
        servers: vec![StoredServer {
            addr: "127.0.0.1:9".into(),
            pubkey: proto::hex_of(&[3u8; 32]),
            label: String::new(),
        }],
        ..Config::default()
    };
    std::fs::write(dir.join("client.json"), serde_json::to_vec(&cfg).unwrap()).unwrap();
    let start: StartFn = Arc::new(|_a: EngineStart| anyhow::bail!("TUN недоступен"));
    let dd = dir.clone();
    let d = Daemon::start_in(dir, move |log| {
        let e = DaemonEngine::open(&dd, log, start, None).unwrap();
        assert!(e.has_server());
        e.start_async();
        e
    });
    let mut c = d.client();
    wait_for(
        &mut c,
        "Error запуска",
        |m| matches!(m, DaemonMsg::Event { ev, .. } if ev["Error"].as_str().is_some_and(|e| e.contains("TUN недоступен"))),
    );
    match c.request(json!({ "Join": 1 }), T).unwrap() {
        AckResult::Err(e) => assert!(e.contains("TUN недоступен"), "{e}"),
        r => panic!("ждали Err, пришло {r:?}"),
    }
    assert_eq!(
        c.request(json!({ "SetStatus": "тут" }), T).unwrap(),
        AckResult::Ok
    );
    wait_for(
        &mut c,
        "статус в снимке",
        snap_where(|s| s["cfg"]["status"] == "тут"),
    );
}
