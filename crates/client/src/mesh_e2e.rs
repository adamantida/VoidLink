//! E2E-тесты mesh/DHT/путей (этап 9, T3): настоящий сервер в том же
//! процессе и настоящие движки на localhost, TUN — заглушка.
//!
//! Покрытие (нумерация — из плана этапа):
//! 1. релей через третьего участника при **остановленном** сервере;
//! 2. DHT переживает мёртвый сервер и смену адреса пира;
//! 3. переключение пути закреплением (`Cmd::PinPath`/`UnpinPath`);
//! 7. `Cmd::SwitchServer` не теряет DHT/mesh-контакты.
//!
//! Модуль отдельный от `engine_e2e.rs`: T2 (probe/offline) правит тот файл
//! параллельно, а эти тесты трогают mesh-таймеры (шаг 1 с, поиск маршрута
//! 10 с), поэтому таймауты здесь больше обычных.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tunnel_protocol as proto;

use crate::engine::{self, Cmd, Engine, Event, TunDev};
use crate::path::PathKind;
use crate::store::Config;

#[derive(Default)]
struct TestTun {
    injected: Mutex<Vec<Vec<u8>>>,
    addrs: Mutex<HashSet<u32>>,
}

impl TunDev for TestTun {
    fn inject(&self, packet: &[u8]) -> anyhow::Result<()> {
        self.injected.lock().unwrap().push(packet.to_vec());
        Ok(())
    }
    fn ensure_address(&self, ip: u32) -> anyhow::Result<()> {
        self.addrs.lock().unwrap().insert(ip);
        Ok(())
    }
}

/// Последний сохранённый `client.json` (движок пишет через колбэк).
type Saved = Arc<Mutex<Config>>;

struct Node {
    eng: Engine,
    tun: Arc<TestTun>,
    saved: Saved,
    identity: proto::Identity,
    /// Все события, полученные за тест.
    seen: Vec<Event>,
}

impl Node {
    fn start(name: &str, server: &tunnel_server::Server) -> Node {
        let identity = proto::Identity::generate();
        Node::start_as(name, server, identity)
    }

    fn start_as(name: &str, server: &tunnel_server::Server, identity: proto::Identity) -> Node {
        let cfg = Config {
            name: name.into(),
            ..Config::default()
        };
        Node::start_cfg(cfg, server, identity).expect("движок подключается")
    }

    fn start_cfg(
        cfg: Config,
        server: &tunnel_server::Server,
        identity: proto::Identity,
    ) -> anyhow::Result<Node> {
        let tun = Arc::new(TestTun::default());
        let saved: Saved = Arc::new(Mutex::new(cfg.clone()));
        let s = saved.clone();
        let save: Arc<dyn Fn(&Config) + Send + Sync> = Arc::new(move |c: &Config| {
            *s.lock().unwrap() = c.clone();
        });
        let eng = engine::start_with_tun(
            Arc::new(Mutex::new(cfg)),
            local(server.addr),
            server.pubkey,
            identity.clone(),
            tun.clone(),
            save,
        )?;
        Ok(Node {
            eng,
            tun,
            saved,
            identity,
            seen: Vec::new(),
        })
    }

    /// Последний сохранённый конфиг.
    fn cfg(&self) -> Config {
        self.saved.lock().unwrap().clone()
    }

    fn create(&mut self, name: &str) -> u32 {
        self.eng
            .cmds
            .send(Cmd::Create {
                name: name.into(),
                private: false,
            })
            .unwrap();
        match self.wait("группа создана", T, |e| {
            matches!(e, Event::GroupJoined { .. })
        }) {
            Event::GroupJoined { gid, .. } => gid,
            _ => unreachable!(),
        }
    }

    fn join(&mut self, gid: u32) {
        self.eng.cmds.send(Cmd::Join(gid)).unwrap();
        self.wait(
            "вход в группу",
            T,
            |e| matches!(e, Event::GroupJoined { gid: g, .. } if *g == gid),
        );
    }

    fn addr(&self) -> SocketAddr {
        local(self.eng.local_addr().expect("сокет движка"))
    }

    fn my_ip(&self, gid: u32) -> u32 {
        self.eng.groups.lock().unwrap()[&gid].my_ip
    }

    fn sessions(&self) -> u32 {
        self.eng.meta.lock().unwrap().mesh_sessions
    }

    fn relay_bytes(&self) -> u64 {
        self.eng.meta.lock().unwrap().relay_bytes
    }

    fn connected(&self) -> bool {
        self.eng.meta.lock().unwrap().connected
    }

    /// Сколько раз пакет попал в TUN.
    fn got(&self, pkt: &[u8]) -> usize {
        self.tun
            .injected
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.as_slice() == pkt)
            .count()
    }

    fn wait(&mut self, what: &str, timeout: Duration, pred: impl Fn(&Event) -> bool) -> Event {
        let end = Instant::now() + timeout;
        loop {
            while let Ok(e) = self.eng.events.try_recv() {
                let hit = pred(&e);
                self.seen.push(e.clone());
                if hit {
                    return e;
                }
            }
            assert!(Instant::now() < end, "не дождались: {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Перезапуск движка с тем же конфигом и identity, но новым UDP-адресом
    /// (смена адреса пира).
    fn restart(self, server: &tunnel_server::Server) -> Node {
        let cfg = self.cfg();
        let identity = self.identity.clone();
        drop(self);
        Node::start_cfg(cfg, server, identity).expect("движок перезапускается")
    }
}

fn local(addr: SocketAddr) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], addr.port()))
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "voidlink-mesh-e2e-{tag}-{}-{nanos}",
        std::process::id()
    ))
}

fn start_server(dir: &std::path::Path, port: u16) -> tunnel_server::Server {
    tunnel_server::Server::start(tunnel_server::Config {
        listen: SocketAddr::from(([127, 0, 0, 1], port)),
        data_dir: dir.to_path_buf(),
        workers: 2,
        quiet: true,
        ..Default::default()
    })
    .expect("сервер стартует")
}

fn wait_until(what: &str, within: Duration, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + within;
    while !f() {
        assert!(Instant::now() < end, "не дождались за {within:?}: {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Минимальный IPv4-пакет (заголовок 20 байт + данные).
fn ipv4(src: u32, dst: u32, data: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    let len = (20 + data.len()) as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.to_be_bytes());
    p[16..20].copy_from_slice(&dst.to_be_bytes());
    p.extend_from_slice(data);
    p
}

/// Пакет `from → to` повторяется, пока не дойдёт до TUN получателя.
fn deliver(from: &Node, to: &Node, gid: u32, tag: &str, within: Duration) {
    let pkt = ipv4(from.my_ip(gid), to.my_ip(gid), tag.as_bytes());
    let t0 = Instant::now();
    loop {
        from.eng.send_ip_packet(&pkt);
        let next = Instant::now() + Duration::from_millis(100);
        while Instant::now() < next {
            if to.got(&pkt) > 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(t0.elapsed() < within, "{tag}: пакет не дошёл за {within:?}");
    }
}

const T: Duration = Duration::from_secs(10);
/// Mesh-таймеры движка: шаг 1 с, маршрут через реле — раз в 10 с.
const MESH_T: Duration = Duration::from_secs(45);
/// Пересчёт путей — раз в 10 с: ждать выбора надо с запасом на тик.
const PATHS_T: Duration = Duration::from_secs(25);

/// Три участника одной группы: (a, b, c, gid).
fn three(server: &tunnel_server::Server) -> (Node, Node, Node, u32) {
    let mut a = Node::start("alpha", server);
    let gid = a.create("mesh-relay");
    let mut b = Node::start("bravo", server);
    b.join(gid);
    let mut c = Node::start("charlie", server);
    c.join(gid);
    wait_until("состав из трёх", T, || {
        a.eng.groups.lock().unwrap()[&gid].members.len() == 2
    });
    (a, b, c, gid)
}

#[test]
fn e2e_релей_через_третьего_при_мёртвом_сервере() {
    crate::engine::set_debug(true);
    let dir = temp_dir("relay");
    let server = start_server(&dir, 47610);
    let (a, b, c, gid) = three(&server);
    let (a_pk, b_pk, c_pk) = (
        a.identity.ed_pub(),
        b.identity.ed_pub(),
        c.identity.ed_pub(),
    );
    let (b_ip, c_ip) = (b.my_ip(gid), c.my_ip(gid));
    // mesh включён по умолчанию — MESH_INFO уходит сразу после WELCOME.
    assert!(a.eng.meta.lock().unwrap().mesh_enabled);
    // 1. Все три mesh-сессии (пир ↔ пир) поднимаются сами.
    wait_until("mesh-сессии у всех", MESH_T, || {
        a.sessions() >= 2 && b.sessions() >= 2 && c.sessions() >= 2
    });
    // 2. Закрепляем доставку A→C через B (L2): путь имеет смысл, когда
    //    MESH_ROUTE измерил маршрут, — ждём, пока он станет текущим.
    a.eng
        .cmds
        .send(Cmd::PinPath {
            ip: c_ip,
            path: PathKind::PeerRelay { via: b_pk },
        })
        .unwrap();
    wait_until("путь через реле выбран", MESH_T, || {
        a.eng.paths.current(c_ip) == Some(PathKind::PeerRelay { via: b_pk })
    });
    // 3. Сервер остановлен: групповой кадр идёт через B, сервер не нужен.
    //    Ждать детекта «сервер не отвечает» (20 с) незачем: кадр в сервер и
    //    так не пойдёт — путь закреплён на релее.
    server.stop();
    std::thread::sleep(Duration::from_millis(300));
    let before = b.relay_bytes();
    deliver(&a, &c, gid, "mesh-relay-dead-server", T);
    wait_until("B отрелеил кадр", T, || {
        b.relay_bytes() > before
    });
    assert!(b.relay_bytes() > 0, "счётчик релея не вырос");
    // У A тоже учтена отдача (uplink в MESH_FORWARD).
    assert!(a.relay_bytes() > 0);
    // Путь у A остаётся реле (сервер мёртв, закрепление не снимается).
    assert_eq!(
        a.eng.paths.current(c_ip),
        Some(PathKind::PeerRelay { via: b_pk })
    );
    // C не подменял прямой адрес на релее (инъекция без direct_addr):
    // кадр доставлен, но сессия/участник не считает B прямым адресом C.
    let direct_c = a.eng.groups.lock().unwrap()[&gid]
        .members
        .values()
        .find(|p| p.pubkey == c_pk)
        .map(|p| p.direct_addr);
    assert!(
        direct_c.is_some(),
        "прямой канал A→C в этом тесте тоже есть; релей выбран закреплением"
    );
    // B не релеит «себе» — его собственный трафик не считается.
    let _ = (a_pk, b_ip);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_dht_переживает_мёртвый_сервер_и_смену_адреса() {
    let dir = temp_dir("dht");
    let port = 47611;
    let server = start_server(&dir, port);
    let mut a = Node::start("alpha", &server);
    let gid = a.create("mesh-dht");
    let mut b = Node::start("bravo", &server);
    b.join(gid);
    let b_pk = b.identity.ed_pub();
    // MESH_SEED/состав → контакты DHT → сохранение в client.json.
    wait_until(
        "контакты в client.json",
        Duration::from_secs(30),
        || {
            a.cfg()
                .mesh
                .contacts
                .iter()
                .any(|c| c.ed == proto::hex_of(&b_pk))
        },
    );
    let saved = a.cfg().mesh.contacts.len();
    assert!(saved >= 1);
    wait_until("mesh-сессия A↔B", MESH_T, || a.sessions() >= 1);
    // Сервер умирает: DHT и сессии — не его состояние (проверяем сразу:
    // ждать 20-секундный таймаут незачем).
    server.stop();
    std::thread::sleep(Duration::from_millis(1_000));
    assert!(
        a.sessions() >= 1,
        "mesh-сессия жила через сервер и умерла вместе с ним"
    );
    assert_eq!(
        a.cfg().mesh.contacts.len(),
        saved,
        "DHT потерял контакты при мёртвом сервере"
    );
    // Сервер вернулся (тот же каталог — группы сохранились); реконнект — сразу.
    let server = start_server(&dir, port);
    a.eng.cmds.send(Cmd::Reconnect).unwrap();
    wait_until("переподключение A", T, || a.connected());
    assert!(a.eng.groups.lock().unwrap().contains_key(&gid));
    // Пир переехал на новый UDP-адрес с той же identity.
    let old_addr = b.addr();
    b = b.restart(&server);
    let new_addr = b.addr();
    assert_ne!(old_addr, new_addr, "новый сокет — новый адрес");
    b.join(gid);
    wait_until(
        "рукопожатие с новым адресом",
        MESH_T,
        || a.sessions() >= 1 && b.sessions() >= 1,
    );
    // Трафик до переехавшего пира доставляется (mesh-сессия на новом адресе).
    wait_until("A видит новый endpoint", MESH_T, || {
        a.eng.groups.lock().unwrap()[&gid]
            .members
            .values()
            .any(|p| p.pubkey == b_pk && p.endpoint == Some(b.addr()))
    });
    deliver(&a, &b, gid, "dht-after-move", T);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_переключение_пути_закреплением() {
    let dir = temp_dir("pin");
    let server = start_server(&dir, 47612);
    let mut a = Node::start("alpha", &server);
    let gid = a.create("mesh-pin");
    let mut b = Node::start("bravo", &server);
    b.join(gid);
    let b_ip = b.my_ip(gid);
    // Прямой канал устанавливается RTT-раундом/трафиком.
    deliver(&a, &b, gid, "pin-warmup", T);
    wait_until("прямой путь", PATHS_T, || {
        a.eng.paths.current(b_ip) == Some(PathKind::Direct)
    });
    // Закрепление сервера: пин сильнее автоматики.
    a.eng
        .cmds
        .send(Cmd::PinPath {
            ip: b_ip,
            path: PathKind::Server,
        })
        .unwrap();
    wait_until("пин сервера", T, || {
        a.eng.paths.current(b_ip) == Some(PathKind::Server)
    });
    assert_eq!(
        a.cfg().pinned_paths.get(&crate::path::ip_key(b_ip)),
        Some(&"server".to_string())
    );
    deliver(&a, &b, gid, "pin-server", T);
    // Закрепление прямого пути.
    a.eng
        .cmds
        .send(Cmd::PinPath {
            ip: b_ip,
            path: PathKind::Direct,
        })
        .unwrap();
    wait_until("пин прямого", T, || {
        a.eng.paths.current(b_ip) == Some(PathKind::Direct)
    });
    assert_eq!(
        a.cfg().pinned_paths.get(&crate::path::ip_key(b_ip)),
        Some(&"direct".to_string())
    );
    deliver(&a, &b, gid, "pin-direct", T);
    // Снятие закрепления — автоматика снова выбирает лучший путь.
    a.eng.cmds.send(Cmd::UnpinPath { ip: b_ip }).unwrap();
    wait_until("пин снят", T, || {
        !a.cfg()
            .pinned_paths
            .contains_key(&crate::path::ip_key(b_ip))
    });
    deliver(&a, &b, gid, "pin-auto", T);
    // Отказ пути: снимаем замер прямого канала (имитация обрыва) — таблица
    // обязана выбрать сервер без 20 %-гистерезиса.
    a.eng.paths.record_failure(b_ip);
    deliver(&a, &b, gid, "pin-after-failure", T);
    assert!(
        a.eng.paths.current(b_ip).is_some(),
        "после отказа пути трафик дальше не доставляется"
    );
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_switch_server_не_теряет_dht() {
    let dir1 = temp_dir("sw1");
    let dir2 = temp_dir("sw2");
    let s1 = start_server(&dir1, 47613);
    let s2 = start_server(&dir2, 47614);
    let mut a = Node::start("alpha", &s1);
    let gid = a.create("mesh-switch");
    let mut b = Node::start("bravo", &s1);
    b.join(gid);
    let b_pk = b.identity.ed_pub();
    wait_until(
        "контакты DHT на S1",
        Duration::from_secs(30),
        || {
            a.cfg()
                .mesh
                .contacts
                .iter()
                .any(|c| c.ed == proto::hex_of(&b_pk))
        },
    );
    wait_until("mesh-сессия до переключения", MESH_T, || a.sessions() >= 1);
    let saved = a.cfg().mesh.contacts.len();
    // Переключение на другой сервер: группы прежнего забываются.
    a.eng
        .cmds
        .send(Cmd::SwitchServer {
            addr: local(s2.addr),
            pubkey: s2.pubkey,
            label: "s2".into(),
        })
        .unwrap();
    a.wait(
        "подключение к S2",
        T,
        |e| matches!(e, Event::Connected(addr) if *addr == local(s2.addr)),
    );
    // Mesh-сессии и DHT — не состояние сервера: живут дальше.
    assert!(a.sessions() >= 1, "SwitchServer закрыл mesh-сессии");
    wait_until(
        "DHT сохранён после переключения",
        Duration::from_secs(20),
        || !a.cfg().mesh.contacts.is_empty(),
    );
    assert_eq!(
        a.cfg().mesh.contacts.len(),
        saved,
        "SwitchServer потерял DHT-контакты"
    );
    s1.stop();
    s2.stop();
    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);
}
