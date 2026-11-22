//! Фронтенды поверх демона (PLAN.md 7.4/7.7): `IpcEngine` и CLI против
//! настоящего движка (`EngineBackend`) за Unix-сокетом; сервер
//! `tunnel-server` в том же процессе, TUN — заглушка. Здесь, а не в
//! `tunnel-client`: клиент не может зависеть от демона.
#![cfg(unix)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tunnel_client::api::{EngineApi, EngineMode, LocalEngine};
use tunnel_client::engine::{self, Cmd, Engine, Event, TunDev};
use tunnel_client::remote::{Endpoint, IpcEngine};
use tunnel_client::remote_cli::{self, Route};
use tunnel_client::snapshot::Snapshot;
use tunnel_client::store::{Config, StoredServer};
use tunnel_daemon::server::socket_path;
use tunnel_daemon::{EngineBackend, InstanceLock, IpcMode, RunOpts, run_daemon};
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
    let d = std::env::temp_dir().join(format!("tdf-{tag}-{}-{n}", std::process::id()));
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

fn start_engine(name: &str, server: &tunnel_server::Server, id: proto::Identity) -> Engine {
    let addr = SocketAddr::from(([127, 0, 0, 1], server.addr.port()));
    let cfg = Config {
        name: name.into(),
        servers: vec![StoredServer {
            addr: addr.to_string(),
            pubkey: proto::hex_of(&server.pubkey),
            label: "тест".into(),
        }],
        ..Config::default()
    };
    let save: Arc<dyn Fn(&Config) + Send + Sync> = Arc::new(|_: &Config| {});
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

/// Ждёт снимок, для которого `f` — истина (события по пути — в `seen`).
fn wait_snap(
    eng: &dyn EngineApi,
    seen: &mut Vec<Event>,
    what: &str,
    mut f: impl FnMut(&Snapshot) -> bool,
) -> Snapshot {
    let t0 = Instant::now();
    loop {
        seen.extend(eng.poll_events());
        let s = eng.snapshot();
        if f(&s) {
            return (*s).clone();
        }
        assert!(
            t0.elapsed() < T,
            "{:?}: не дождались {what}; снимок: {s:?}",
            eng.mode()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

struct Daemon {
    dir: PathBuf,
    stop: Arc<AtomicBool>,
    th: Option<JoinHandle<Result<(), String>>>,
}

impl Daemon {
    fn start(backend: EngineBackend) -> Daemon {
        let dir = temp_dir("d");
        let stop = Arc::new(AtomicBool::new(false));
        let opts = RunOpts {
            data_dir: dir.clone(),
            debug: true,
            console_log: false,
            ipc: IpcMode::Unix,
            stop_reason: "тест окончен".into(),
        };
        let s = stop.clone();
        let th = std::thread::spawn(move || run_daemon(&opts, move |_| backend, s));
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

    fn endpoint(&self) -> Endpoint {
        Endpoint::unix(socket_path(&self.dir))
    }

    /// CLI-команда через демона (как `main.rs` при `Route::Daemon`).
    fn cli(&self, cmd: &str, args: &[&str]) -> anyhow::Result<String> {
        let Route::Daemon(mut c) = remote_cli::route_to(&self.endpoint(), &self.dir)? else {
            panic!("демон доступен — CLI должен идти через IPC");
        };
        let rest: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let mut out = Vec::new();
        remote_cli::run(&mut c, cmd, &rest, &mut out)?;
        Ok(String::from_utf8(out).unwrap())
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

/// Снимок без того, что зависит от времени, порядка входа и личности:
/// чтобы сравнить два движка, прошедших один сценарий.
fn normalize(mut s: Snapshot, twin: [u8; 32]) -> Snapshot {
    s.meta.uptime_s = 0;
    s.meta.rx_hist.clear();
    s.meta.tx_hist.clear();
    for g in &mut s.meta.group_list {
        g.online = 0;
        g.total = 0;
    }
    s.stats = Default::default();
    for g in &mut s.groups {
        g.joined_s_ago = 0;
        g.my_ip = 0;
        // Второй участник сценария — «близнец»: у каждого свой.
        g.members.retain(|p| p.pubkey != twin);
        for p in &mut g.members {
            p.ip = 0;
            p.last_rx_ms_ago = 0;
            p.last_direct_ms_ago = None;
            p.rtt_ms = None;
            p.endpoint = None;
            p.direct = false;
        }
    }
    for i in &mut s.pending_invites {
        i.received_ms_ago = 0;
        i.expires_in_s = None;
    }
    s
}

/// Один сценарий для любого `EngineApi`: друг, сервер, статус, приглашение
/// от bob (в снимке, отказ снимает), второе приглашение — вход.
fn scenario_cfg(eng: &dyn EngineApi, bob_pub: [u8; 32], seen: &mut Vec<Event>) -> Snapshot {
    wait_snap(eng, seen, "подключён", |s| s.meta.connected);
    eng.send(Cmd::AddFriend {
        pubkey: bob_pub,
        alias: "боб".into(),
    })
    .unwrap();
    eng.send(Cmd::AddServer {
        addr: "127.0.0.1:1".into(),
        pubkey: [1; 32],
        label: "второй".into(),
    })
    .unwrap();
    eng.send(Cmd::SetStatus("тут".into())).unwrap();
    // Неверная правка конфига отклоняется сразу (`Ack` Err у демона).
    assert!(eng.send(Cmd::DelServer { idx: 0 }).is_err() || eng.mode() == EngineMode::Remote);
    wait_snap(eng, seen, "друг, сервер, статус", |s| {
        s.cfg.friends.len() == 1 && s.cfg.servers.len() == 2 && s.cfg.status == "тут"
    })
}

#[test]
fn ipc_engine_и_local_engine_одинаковые_снимки() {
    let sdir = temp_dir("s");
    let server = start_server(&sdir);
    let bob_id = proto::Identity::generate();
    let bob_pub = bob_id.ed_pub();
    let bob = start_engine("bob", &server, bob_id);
    let alice_id = proto::Identity::generate();
    let carol_id = proto::Identity::generate();
    let (alice_pub, carol_pub) = (alice_id.ed_pub(), carol_id.ed_pub());
    // Оба — «близнецы» с одним именем: embedded и через демона.
    let local = LocalEngine::new(start_engine("близнец", &server, alice_id));
    let d = Daemon::start(EngineBackend::new(start_engine(
        "близнец",
        &server,
        carol_id,
    )));
    let remote = IpcEngine::connect(&d.endpoint(), None).expect("IpcEngine подключается");
    assert_eq!(remote.mode(), EngineMode::Remote);
    assert_eq!(local.mode(), EngineMode::Embedded);
    assert_eq!(remote.me().my_pub, carol_pub);
    let (mut seen_l, mut seen_r) = (Vec::new(), Vec::new());

    let a = scenario_cfg(&local, bob_pub, &mut seen_l);
    let b = scenario_cfg(&remote, bob_pub, &mut seen_r);
    assert_eq!(
        normalize(a, carol_pub),
        normalize(b, alice_pub),
        "конфиг-вид"
    );
    // Отказ демона приходит событием Error (Ack Err).
    remote.send(Cmd::DelServer { idx: 0 }).unwrap();
    let t0 = Instant::now();
    while !seen_r
        .iter()
        .any(|e| matches!(e, Event::Error(m) if m.contains("текущий сервер")))
    {
        assert!(
            t0.elapsed() < T,
            "нет Error на DelServer текущего: {seen_r:?}"
        );
        seen_r.extend(remote.poll_events());
        std::thread::sleep(Duration::from_millis(10));
    }

    // Приглашение от bob обоим: одинаково в pending_invites; вход снимает его
    // и даёт одну и ту же группу.
    let bob_group = |name: &str| {
        bob.cmds
            .send(Cmd::Create {
                name: name.into(),
                private: true,
            })
            .unwrap();
        let Event::GroupJoined { gid, .. } = engine_event(&bob, "bob: GroupJoined", |e| {
            matches!(e, Event::GroupJoined { .. })
        }) else {
            unreachable!()
        };
        bob.cmds.send(Cmd::Invite(gid, alice_pub)).unwrap();
        bob.cmds.send(Cmd::Invite(gid, carol_pub)).unwrap();
        gid
    };
    let gid = bob_group("тайная");
    let has_inv = |gid: u32| move |s: &Snapshot| s.pending_invites.iter().any(|i| i.gid == gid);
    let a = wait_snap(&local, &mut seen_l, "приглашение (local)", has_inv(gid));
    let b = wait_snap(&remote, &mut seen_r, "приглашение (remote)", has_inv(gid));
    assert_eq!(
        normalize(a, carol_pub),
        normalize(b, alice_pub),
        "с приглашением"
    );
    assert!(
        seen_l
            .iter()
            .any(|e| matches!(e, Event::Invite { gid: g, .. } if *g == gid))
    );
    assert!(
        seen_r
            .iter()
            .any(|e| matches!(e, Event::Invite { gid: g, .. } if *g == gid))
    );
    local.send(Cmd::Join(gid)).unwrap();
    remote.send(Cmd::Join(gid)).unwrap();
    let joined = |s: &Snapshot| {
        s.pending_invites.is_empty()
            && s.groups
                .iter()
                .any(|g| g.gid == gid && g.members.iter().any(|p| p.pubkey == bob_pub && p.online))
            && s.cfg.autojoin.contains(&gid)
    };
    let a = wait_snap(&local, &mut seen_l, "вход (local)", joined);
    let b = wait_snap(&remote, &mut seen_r, "вход (remote)", joined);
    let (a, b) = (normalize(a, carol_pub), normalize(b, alice_pub));
    assert_eq!(a.groups, b.groups, "группы");
    assert_eq!(a.cfg, b.cfg, "конфиг-вид");
    assert_eq!(a.pending_invites, b.pending_invites);
    assert_eq!(a.meta.server, b.meta.server);
    assert!(
        seen_r
            .iter()
            .any(|e| matches!(e, Event::GroupJoined { gid: g, .. } if *g == gid))
    );

    // Второе приглашение — отказ снимает его сразу у обоих.
    let gid2 = bob_group("вторая");
    let a = wait_snap(
        &local,
        &mut seen_l,
        "второе приглашение (local)",
        has_inv(gid2),
    );
    let b = wait_snap(
        &remote,
        &mut seen_r,
        "второе приглашение (remote)",
        has_inv(gid2),
    );
    assert_eq!(
        normalize(a, carol_pub).pending_invites,
        normalize(b, alice_pub).pending_invites
    );
    local.send(Cmd::DeclineInvite(gid2)).unwrap();
    remote.send(Cmd::DeclineInvite(gid2)).unwrap();
    let a = wait_snap(&local, &mut seen_l, "отказ (local)", |s| {
        s.pending_invites.is_empty()
    });
    let b = wait_snap(&remote, &mut seen_r, "отказ (remote)", |s| {
        s.pending_invites.is_empty()
    });
    let (a, b) = (normalize(a, carol_pub), normalize(b, alice_pub));
    assert_eq!(a.groups, b.groups, "после отказа");
    assert_eq!(a.cfg, b.cfg);
    engine_event(
        &bob,
        "bob: InviteDeclined",
        |e| matches!(e, Event::InviteDeclined { gid: g, .. } if *g == gid2),
    );

    drop(remote);
    drop(d);
    drop(local);
    drop(bob);
    server.stop();
    let _ = std::fs::remove_dir_all(&sdir);
}

#[test]
fn cli_идёт_через_демона() {
    let sdir = temp_dir("s");
    let server = start_server(&sdir);
    let bob_id = proto::Identity::generate();
    let bob_code = bob_id.friend_code();
    let bob = start_engine("bob", &server, bob_id);

    // Маршрут без демона: замок свободен — прямой сеанс; занят — отказ.
    let free = temp_dir("free");
    let ep = Endpoint::unix(socket_path(&free));
    assert!(matches!(
        remote_cli::route_to(&ep, &free).unwrap(),
        Route::Direct
    ));
    let held = InstanceLock::acquire(&free).unwrap();
    assert!(
        matches!(remote_cli::route_to(&ep, &free).unwrap(), Route::Locked),
        "embedded TUI / run держит замок"
    );
    drop(held);
    assert!(matches!(
        remote_cli::route_to(&ep, &free).unwrap(),
        Route::Direct
    ));
    let _ = std::fs::remove_dir_all(&free);

    let carol_id = proto::Identity::generate();
    let carol_code = carol_id.friend_code();
    let backend = EngineBackend::new(start_engine("carol", &server, carol_id));
    let d = Daemon::start(backend);
    // Демон держит замок и сокет — CLI идёт через IPC (а не отказ / свой HELLO).
    assert!(InstanceLock::is_held(&d.dir));
    let watch = IpcEngine::connect(&d.endpoint(), None).unwrap();
    let mut seen = Vec::new();
    wait_snap(&watch, &mut seen, "подключён", |s| {
        s.meta.connected
    });

    let id = d.cli("id", &[]).unwrap();
    assert!(id.contains(&carol_code) && id.contains("carol"), "{id}");
    let out = d.cli("create", &["игра"]).unwrap();
    assert!(out.contains("создана"), "{out}");
    let gid = wait_snap(&watch, &mut seen, "группа", |s| !s.groups.is_empty()).groups[0].gid;
    assert!(
        watch.snapshot().cfg.autojoin.contains(&gid),
        "автовход правит сам демон"
    );

    // Правки конфига — командами демону, видны в его снимке. Дружба теперь
    // заявка (issue #24): CLI отвечает «заявка отправлена», повтор — отказ.
    assert!(
        d.cli("add-friend", &[&bob_code, "боб"])
            .unwrap()
            .contains("заявка отправлена")
    );
    assert!(
        d.cli("add-friend", &[&bob_code])
            .unwrap_err()
            .to_string()
            .contains("уже отправлена")
    );
    assert!(
        d.cli("alias", &["боб", "бобби"])
            .unwrap()
            .contains("переименован")
    );
    wait_snap(&watch, &mut seen, "алиас", |s| {
        s.cfg.friends.iter().any(|f| f.alias == "бобби")
    });
    assert!(d.cli("friends", &[]).unwrap().contains("бобби"));
    assert!(d.cli("set-status", &["занят"]).unwrap().contains("статус"));
    wait_snap(&watch, &mut seen, "статус", |s| {
        s.cfg.status == "занят"
    });
    assert!(
        d.cli(
            "add-server",
            &["127.0.0.1:1", &proto::friend_code_of(&[1; 32]), "второй"]
        )
        .unwrap()
        .contains("добавлен")
    );
    let err = d.cli("del-server", &["0"]).unwrap_err().to_string();
    assert!(err.contains("текущий сервер"), "Ack Err демона: {err}");
    assert!(
        d.cli("del-server", &["второй"])
            .unwrap()
            .contains("удалено")
    );
    wait_snap(&watch, &mut seen, "один сервер", |s| {
        s.cfg.servers.len() == 1
    });

    // Сетевые команды: приглашение доходит до bob, отказ bob — у нас событием.
    assert!(
        d.cli("invite", &[&gid.to_string(), "бобби"])
            .unwrap()
            .contains("ок")
    );
    engine_event(
        &bob,
        "bob: Invite",
        |e| matches!(e, Event::Invite { gid: g, .. } if *g == gid),
    );
    let bans = d.cli("bans", &[&gid.to_string()]).unwrap();
    assert!(
        bans.contains("баны группы") && bans.contains("бобби"),
        "приглашённый — алиасом: {bans}"
    );
    let groups = d.cli("groups", &[]).unwrap();
    assert!(groups.contains("игра"), "{groups}");
    assert!(
        d.cli("join", &["999999"]).is_err(),
        "несуществующая группа — ошибка сервера"
    );
    assert!(
        d.cli("decline", &["999999"])
            .unwrap_err()
            .to_string()
            .contains("нет приглашения")
    );
    assert!(
        d.cli("set-mtu", &["1300"])
            .unwrap_err()
            .to_string()
            .contains("демон")
    );
    assert!(
        d.cli("run", &[]).is_err(),
        "второй движок при демоне не поднимается"
    );
    let fg = d.cli("friend-groups", &["бобби"]).unwrap();
    assert!(
        fg.contains("нет видимых групп"),
        "у bob своя закрытой нет: {fg}"
    );
    assert!(
        d.cli("leave", &[&gid.to_string()])
            .unwrap()
            .contains("вышел")
    );
    wait_snap(&watch, &mut seen, "вышли", |s| {
        s.groups.is_empty() && !s.cfg.autojoin.contains(&gid)
    });

    // Ни одна команда CLI не вытеснила сеанс демона своим HELLO.
    assert!(
        !seen.iter().any(|e| matches!(e, Event::Disconnected(_))),
        "сеанс демона вытеснен: {seen:?}"
    );
    assert!(watch.snapshot().meta.connected);

    drop(watch);
    drop(d);
    drop(bob);
    server.stop();
    let _ = std::fs::remove_dir_all(&sdir);
}
