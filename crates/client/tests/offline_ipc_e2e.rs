//! Офлайн-TUI против фейкового демона (этап 9, §3.8): очередь
//! `ui-pending.json` уходит демону по порядку, очищается после отправки,
//! режим переключается на тонкий клиент, а при падении демона TUI снова
//! копит правки.
//!
//! Unix-only: Windows-пайп `tunnel_ipc` поднимается только от SYSTEM
//! (SDDL с владельцем SY) — как и остальные IPC-e2e. Логика очереди
//! (`offline::tests::очередь_отправляется_по_порядку`) проверяется на всех
//! платформах, а полный путь «демон» — здесь и в `daemon/tests/offline_e2e.rs`.
#![cfg(unix)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use tunnel_client::api::{EngineApi, EngineMode, Me};
use tunnel_client::engine::Cmd;
use tunnel_client::offline::{PENDING_FILE, apply_cfg_cmd};
use tunnel_client::remote::connect_offline;
use tunnel_client::snapshot::{CfgView, MetaSnap, Snapshot};
use tunnel_client::store::{self, Config};
use tunnel_ipc::{AckResult, ClientMsg, Conn, DaemonMsg, Listener, read_msg, write_msg};
use tunnel_protocol as proto;

const T: Duration = Duration::from_secs(10);

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while !f() {
        assert!(t0.elapsed() < T, "не дождались: {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "vli-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Фейковый демон: `Welcome` с нужной identity, снимок с конфигом, `Req`
/// применяет правку (`offline::apply_cfg_cmd`) и отвечает `Ack` + свежим
/// снимком — как демон в состоянии «нет сервера».
///
/// Сокет — в каталоге данных TUI (`Endpoint::for_data_dir`): офлайн-движок
/// ищет демона именно там.
struct FakeDaemon {
    snap: Arc<Mutex<Snapshot>>,
    reqs: Arc<Mutex<Vec<Value>>>,
    conns: Arc<Mutex<Vec<Conn>>>,
    stop: Arc<AtomicBool>,
    /// Конфиг демона (как настоящий: правки конфига применяются и в нём).
    cfg: Arc<Mutex<Config>>,
    path: PathBuf,
}

impl FakeDaemon {
    fn start(dir: &std::path::Path, me: Me, cfg: Config) -> FakeDaemon {
        use std::os::unix::fs::PermissionsExt;
        // Приватный каталог 0700: Listener требует его для сокета.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join(tunnel_ipc::transport::DEFAULT_SOCKET_FILE);
        let listener = Listener::bind(&path).expect("сокет демона");
        let initial = Snapshot {
            cfg: CfgView::from_cfg(&cfg),
            meta: MetaSnap {
                offline: true,
                offline_reason: Some("в конфиге нет серверов (тест)".into()),
                ..MetaSnap::default()
            },
            ..Snapshot::default()
        };
        let d = FakeDaemon {
            snap: Arc::new(Mutex::new(initial)),
            reqs: Arc::new(Mutex::new(Vec::new())),
            conns: Arc::new(Mutex::new(Vec::new())),
            stop: Arc::new(AtomicBool::new(false)),
            cfg: Arc::new(Mutex::new(cfg)),
            path,
        };
        let (snap, reqs, conns, stop, cfg) = (
            d.snap.clone(),
            d.reqs.clone(),
            d.conns.clone(),
            d.stop.clone(),
            d.cfg.clone(),
        );
        std::thread::spawn(move || {
            while let Ok(c) = listener.accept() {
                if stop.load(Ordering::SeqCst) {
                    let _ = c.shutdown();
                    break;
                }
                if let Ok(c2) = c.try_clone() {
                    conns.lock().unwrap().push(c2);
                }
                let (snap, reqs, cfg, seq) = (
                    snap.clone(),
                    reqs.clone(),
                    cfg.clone(),
                    Arc::new(Mutex::new(0u64)),
                );
                let me = me.clone();
                std::thread::spawn(move || serve(c, me, snap, reqs, cfg, seq));
            }
        });
        d
    }

    fn push_snapshot(&self) {
        let s = serde_json::to_value(&*self.snap.lock().unwrap()).unwrap();
        for c in self.conns.lock().unwrap().iter() {
            if let Ok(mut c) = c.try_clone() {
                let _ = write_msg(
                    &mut c,
                    &DaemonMsg::Snapshot {
                        seq: 0,
                        snap: s.clone(),
                    },
                );
            }
        }
    }

    /// Демон поднял движок (или потерял) — снимок для фронтенда.
    fn set_live(&self, live: bool) {
        {
            let mut s = self.snap.lock().unwrap();
            s.meta.offline = !live;
            s.meta.connected = live;
            s.meta.offline_reason = (!live).then(|| "в конфиге нет серверов (тест)".into());
        }
        self.push_snapshot();
    }

    fn kill_conns(&self) {
        for c in self.conns.lock().unwrap().drain(..) {
            let _ = c.shutdown();
        }
    }

    fn reqs(&self) -> Vec<Value> {
        self.reqs.lock().unwrap().clone()
    }
}

impl Drop for FakeDaemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Сначала сокет: после `remove_file` переподключиться уже некуда, и
        // фронтенд не может «поймать» живой слушатель между шагами.
        let _ = std::fs::remove_file(&self.path);
        self.kill_conns();
    }
}

/// Поток обслуживания одного соединения.
fn serve(
    mut c: Conn,
    me: Me,
    snap: Arc<Mutex<Snapshot>>,
    reqs: Arc<Mutex<Vec<Value>>>,
    cfg: Arc<Mutex<Config>>,
    seq: Arc<Mutex<u64>>,
) {
    loop {
        let Ok(m) = read_msg::<_, ClientMsg>(&mut c) else {
            return;
        };
        let next = || {
            let mut s = seq.lock().unwrap();
            *s += 1;
            *s
        };
        let reply: Vec<DaemonMsg> = match m {
            ClientMsg::Hello { .. } => vec![DaemonMsg::Welcome {
                proto: tunnel_ipc::PROTO_VERSION,
                daemon_ver: "test".into(),
                me: me.to_json(),
            }],
            ClientMsg::Subscribe { .. } => vec![DaemonMsg::Snapshot {
                seq: next(),
                snap: serde_json::to_value(&*snap.lock().unwrap()).unwrap(),
            }],
            ClientMsg::Req { id, cmd } => {
                reqs.lock().unwrap().push(cmd.clone());
                // Демон без движка применяет правку конфига сам (как
                // `DaemonEngine::offline_cmd`).
                if let Ok(parsed) = serde_json::from_value::<Cmd>(cmd) {
                    let mut c = cfg.lock().unwrap();
                    apply_cfg_cmd(&mut c, parsed);
                    let view = CfgView::from_cfg(&c);
                    snap.lock().unwrap().cfg = view;
                }
                vec![
                    DaemonMsg::Ack {
                        id,
                        result: AckResult::Ok,
                    },
                    DaemonMsg::Snapshot {
                        seq: next(),
                        snap: serde_json::to_value(&*snap.lock().unwrap()).unwrap(),
                    },
                ]
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

/// Конфиг с identity (как `main` до запуска TUI).
fn write_identity(dir: &std::path::Path) -> (Config, proto::Identity) {
    let mut cfg = Config::default();
    let id = store::ensure_identity(&mut cfg);
    std::fs::write(dir.join("client.json"), serde_json::to_vec(&cfg).unwrap()).unwrap();
    (cfg, id)
}

#[test]
fn очередь_уходит_демону_и_очищается() {
    let dir = temp_dir("q");
    let (cfg, id) = write_identity(&dir);
    let me = Me {
        my_pub: id.ed_pub(),
        my_code: id.friend_code(),
    };
    let eng = connect_offline(&dir, Arc::new(Mutex::new(cfg)), id).expect("офлайн-движок");
    assert_eq!(eng.mode(), EngineMode::Offline);
    assert!(eng.unavailable(), "демона нет");

    // Правки офлайн: на диске и в очереди.
    eng.send(Cmd::AddServer {
        addr: "127.0.0.1:5599".into(),
        pubkey: [1u8; 32],
        label: "дом".into(),
    })
    .unwrap();
    eng.send(Cmd::SetName("tui".into())).unwrap();
    assert_eq!(eng.pending_edits(), 2);
    assert!(dir.join(PENDING_FILE).exists());

    // Демон появляется без движка и с пустым конфигом: очередь уходит по
    // порядку, TUI переключается на него (режим всё ещё «офлайн»).
    let d = FakeDaemon::start(&dir, me, Config::default());
    assert!(eng.wait_remote(T), "TUI подключился к демону");
    assert!(!eng.is_live());
    wait_until("очередь доставлена", || {
        d.reqs().len() == 2
    });
    let reqs = d.reqs();
    assert!(reqs[0].get("AddServer").is_some(), "{reqs:?}");
    assert!(reqs[1].get("SetName").is_some(), "{reqs:?}");
    assert!(eng.wait_pending_empty(T), "очередь очищена");
    assert!(!dir.join(PENDING_FILE).exists(), "файл очереди удалён");
    assert_eq!(
        d.cfg.lock().unwrap().servers.len(),
        1,
        "демон применил сервер"
    );
    assert_eq!(d.cfg.lock().unwrap().name, "tui");

    // Демон поднял движок: TUI — тонкий клиент.
    d.set_live(true);
    assert!(eng.wait_live(T), "движок демона поднялся");
    assert_eq!(eng.mode(), EngineMode::Remote);
    assert!(!eng.unavailable());
    wait_until("снимок демона", || {
        let s = eng.snapshot();
        s.meta.connected && !s.meta.offline
    });

    // Демон пропал: снова офлайн, новые правки копятся в очереди.
    // `drop` убирает сокет: если только порвать соединения, офлайн-движок
    // успевает переподключиться к живому слушателю, и `unavailable()` не
    // наступает — гонка, которая ловилась на ubuntu.
    drop(d);
    wait_until("демон недоступен", || eng.unavailable());
    eng.send(Cmd::SetStatus("офлайн".into())).unwrap();
    assert_eq!(eng.pending_edits(), 1);
    assert!(dir.join(PENDING_FILE).exists());
    drop(eng);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn причина_демона_без_движка_видна_tui() {
    let dir = temp_dir("r");
    let (cfg, id) = write_identity(&dir);
    let me = Me {
        my_pub: id.ed_pub(),
        my_code: id.friend_code(),
    };
    let d = FakeDaemon::start(&dir, me, Config::default());
    let eng = connect_offline(&dir, Arc::new(Mutex::new(cfg)), id).expect("офлайн-движок");
    assert!(eng.wait_remote(T), "демон доступен");
    assert!(!eng.is_live(), "движка в демоне нет");
    assert!(
        !eng.unavailable(),
        "демон доступен — пилюля «сервер недоступен»"
    );
    let snap = eng.snapshot();
    assert!(snap.meta.offline);
    assert_eq!(
        snap.meta.offline_reason.as_deref(),
        Some("в конфиге нет серверов (тест)"),
        "причина из демона — в снимке и шапке"
    );
    // Демон с живым движком — уже не офлайн.
    d.set_live(true);
    assert!(eng.wait_live(T));
    wait_until("offline снят", || !eng.snapshot().meta.offline);
    drop(eng);
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}
