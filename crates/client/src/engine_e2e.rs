//! E2E-тесты движка: настоящий сервер (крейт tunnel-server) и настоящие
//! движки на localhost. TUN заменён заглушкой, поэтому права администратора
//! и Wintun не нужны.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tunnel_protocol as proto;
use tunnel_protocol::ctrl;

use crate::engine::{self, Cmd, Engine, Event, TunDev};
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

struct Node {
    eng: Engine,
    tun: Arc<TestTun>,
    /// Все события, полученные за тест (для диагностики).
    seen: Vec<Event>,
}

impl Node {
    fn start(name: &str, server: &tunnel_server::Server) -> Node {
        Node::start_as(name, server, proto::Identity::generate())
    }

    /// Запуск с заданной identity (её pubkey известен заранее).
    fn start_as(name: &str, server: &tunnel_server::Server, identity: proto::Identity) -> Node {
        Node::start_via(name, local(server.addr), server.pubkey, identity)
    }

    /// Запуск через заданный адрес сервера (например, [`LossyProxy`]).
    fn start_via(
        name: &str,
        addr: SocketAddr,
        server_pub: [u8; 32],
        identity: proto::Identity,
    ) -> Node {
        let cfg = Config {
            name: name.into(),
            ..Config::default()
        };
        Node::start_cfg(cfg, addr, server_pub, identity, Arc::new(|_| {}))
            .expect("движок подключается")
    }

    /// Запуск с заданным конфигом и колбэком сохранения.
    fn start_cfg(
        cfg: Config,
        addr: SocketAddr,
        server_pub: [u8; 32],
        identity: proto::Identity,
        save: Arc<dyn Fn(&Config) + Send + Sync>,
    ) -> anyhow::Result<Node> {
        let tun = Arc::new(TestTun::default());
        let eng = engine::start_with_tun(
            Arc::new(Mutex::new(cfg)),
            addr,
            server_pub,
            identity,
            tun.clone(),
            save,
        )?;
        Ok(Node {
            eng,
            tun,
            seen: Vec::new(),
        })
    }

    /// Создаёт группу и ждёт GroupJoined: gid.
    fn create(&mut self, name: &str, private: bool) -> u32 {
        self.eng
            .cmds
            .send(Cmd::Create {
                name: name.into(),
                private,
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

    /// Адрес UDP-сокета движка, как его видят пиры на localhost.
    fn addr(&self) -> SocketAddr {
        local(self.eng.local_addr().unwrap())
    }

    fn epoch(&self, gid: u32) -> u32 {
        self.eng
            .groups
            .lock()
            .unwrap()
            .get(&gid)
            .map(|g| g.epoch)
            .unwrap_or(0)
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

    /// Все участники группы, кроме нас, онлайн и их `n`.
    fn sees_online(&self, gid: u32, n: usize) -> bool {
        let g = self.eng.groups.lock().unwrap();
        g.get(&gid)
            .is_some_and(|gs| gs.members.len() == n && gs.members.values().all(|p| p.online))
    }

    /// Прямой канал с пиром `ip` поднят.
    fn direct_to(&self, gid: u32, ip: u32) -> bool {
        let g = self.eng.groups.lock().unwrap();
        g.get(&gid)
            .and_then(|gs| gs.members.get(&ip))
            .is_some_and(|p| p.direct())
    }

    fn owner(&self, gid: u32) -> Option<[u8; 32]> {
        self.eng.groups.lock().unwrap().get(&gid).map(|g| g.owner)
    }

    /// Было ли событие с позиции `from` журнала `seen`.
    fn saw_since(&mut self, from: usize, pred: impl Fn(&Event) -> bool) -> bool {
        self.drain();
        self.seen[from..].iter().any(pred)
    }

    /// Ждёт событие, подходящее под `pred`.
    fn wait(&mut self, what: &str, timeout: Duration, pred: impl Fn(&Event) -> bool) -> Event {
        let end = Instant::now() + timeout;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            match self
                .eng
                .events
                .recv_timeout(left.min(Duration::from_millis(100)))
            {
                Ok(ev) => {
                    self.seen.push(ev.clone());
                    if pred(&ev) {
                        return ev;
                    }
                }
                Err(_) if Instant::now() >= end => {
                    panic!("не дождались: {what}; события: {:?}", self.seen)
                }
                Err(_) => {}
            }
        }
    }

    fn drain(&mut self) {
        while let Ok(ev) = self.eng.events.try_recv() {
            self.seen.push(ev);
        }
    }

    fn has_group(&self, gid: u32) -> bool {
        self.eng.groups.lock().unwrap().contains_key(&gid)
    }

    fn members(&self, gid: u32) -> usize {
        self.eng
            .groups
            .lock()
            .unwrap()
            .get(&gid)
            .map(|g| g.members.len())
            .unwrap_or(0)
    }

    fn my_ip(&self, gid: u32) -> u32 {
        self.eng.groups.lock().unwrap()[&gid].my_ip
    }

    fn tx_pkts(&self) -> u64 {
        self.eng.stats.tx_pkts.load(Ordering::Relaxed)
    }

    /// Метка федерации группы (uuid из `FED_GROUPS`, T4).
    fn fed_uuid(&self, gid: u32) -> Option<[u8; 16]> {
        self.eng
            .groups
            .lock()
            .unwrap()
            .get(&gid)
            .and_then(|g| g.fed_uuid)
    }

    /// Список доступных федерированных групп движка (`FED_GROUPS`).
    fn fed_list(&self) -> Vec<crate::engine::FedGroupInfo> {
        self.eng.meta.lock().unwrap().fed_groups.clone()
    }

    /// IP участника `pk` в группе `gid` (по состояниям движка).
    fn member_ip(&self, gid: u32, pk: &[u8; 32]) -> Option<u32> {
        self.eng
            .groups
            .lock()
            .unwrap()
            .get(&gid)?
            .members
            .values()
            .find(|p| p.pubkey == *pk)
            .map(|p| p.ip)
    }
}

/// Сервер слушает 0.0.0.0 — клиентам нужен 127.0.0.1 с тем же портом.
fn local(addr: SocketAddr) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], addr.port()))
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!("voidlink-e2e-{tag}-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn start_server(dir: &std::path::Path, port: u16) -> tunnel_server::Server {
    // Тесты окон приглашений создают 20 групп одним владельцем.
    start_server_with(
        dir,
        port,
        tunnel_server::Limits {
            max_owned_groups: 64,
            ..Default::default()
        },
    )
}

fn start_server_with(
    dir: &std::path::Path,
    port: u16,
    limits: tunnel_server::Limits,
) -> tunnel_server::Server {
    tunnel_server::Server::start(tunnel_server::Config {
        listen: SocketAddr::from(([127, 0, 0, 1], port)),
        data_dir: dir.to_path_buf(),
        workers: 4,
        quiet: true,
        limits,
        ..Default::default()
    })
    .expect("сервер стартует")
}

/// Сервер с федерацией (`Config.federate = true`, T4): известные пиры
/// заводятся подсказкой клиента (`SERVER_HINT`), метрики — по `metrics`.
fn start_fed_server(
    dir: &std::path::Path,
    port: u16,
    metrics: Option<SocketAddr>,
) -> tunnel_server::Server {
    tunnel_server::Server::start(tunnel_server::Config {
        listen: SocketAddr::from(([127, 0, 0, 1], port)),
        data_dir: dir.to_path_buf(),
        workers: 4,
        quiet: true,
        federate: true,
        metrics,
        limits: tunnel_server::Limits {
            max_owned_groups: 64,
            ..Default::default()
        },
        ..Default::default()
    })
    .expect("сервер с федерацией стартует")
}

/// `client.json.servers`: адрес (как его видит клиент) и ed25519-ключ —
/// источник кандидатов `SERVER_HINT`.
fn stored_servers(items: &[(SocketAddr, [u8; 32], &str)]) -> Vec<crate::store::StoredServer> {
    items
        .iter()
        .map(|(a, pk, label)| crate::store::StoredServer {
            addr: a.to_string(),
            pubkey: proto::hex_of(pk),
            label: (*label).to_string(),
        })
        .collect()
}

/// Разобранный `server.json` (проверка персистентности федерации).
fn json_file(path: &std::path::Path) -> serde_json::Value {
    let raw = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&raw).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Запись группы федерации в `server.json`: (локальный gid, сервер-источник
/// правды `origin`).
fn fed_group_record(j: &serde_json::Value, uuid_hex: &str) -> Option<(u32, String)> {
    j["federation"]["groups"]
        .as_array()?
        .iter()
        .find(|g| g["uuid"] == uuid_hex)
        .map(|g| {
            (
                g["gid"].as_u64().unwrap_or(0) as u32,
                g["origin"].as_str().unwrap_or_default().to_string(),
            )
        })
}

/// ed25519-ключи закреплённых пиров из `server.json`.
fn fed_peer_eds(j: &serde_json::Value) -> Vec<String> {
    j["federation"]["peers"]
        .as_array()
        .map(|v| {
            v.iter()
                .filter_map(|p| p["ed"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Тело `/metrics` сервера (HTTP-эндпоинт метрик, `--metrics`).
fn metrics_text(addr: SocketAddr) -> String {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).expect("метрики: connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: metrics\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).expect("метрики: read");
    out
}

/// Значение счётчика `name` из тела `/metrics` (0 — строки нет).
fn metric_value(text: &str, name: &str) -> u64 {
    text.lines()
        .find_map(|l| {
            let mut it = l.split_whitespace();
            if it.next() != Some(name) {
                return None;
            }
            it.next()?.parse().ok()
        })
        .unwrap_or(0)
}

/// Ждёт, пока `f` не станет истинным.
fn wait_until(what: &str, within: Duration, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + within;
    while !f() {
        assert!(Instant::now() < end, "не дождались за {within:?}: {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// IP-пакет `from → to` повторяется (как повторяет его приложение), пока
/// не дойдёт до TUN получателя; возвращает, сколько это заняло.
fn deliver(from: &Node, to: &Node, gid: u32, tag: &str, within: Duration) -> Duration {
    deliver_across(from, gid, to, gid, tag, within)
}

/// То же между группами с разными локальными gid (один сервер у каждого
/// клиента — федерация: gid на серверах разные, IP — один на identity).
fn deliver_across(
    from: &Node,
    from_gid: u32,
    to: &Node,
    to_gid: u32,
    tag: &str,
    within: Duration,
) -> Duration {
    let pkt = ipv4(from.my_ip(from_gid), to.my_ip(to_gid), tag.as_bytes());
    let t0 = Instant::now();
    loop {
        from.eng.send_ip_packet(&pkt);
        let next = Instant::now() + Duration::from_millis(100);
        while Instant::now() < next {
            if to.got(&pkt) > 0 {
                return t0.elapsed();
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(t0.elapsed() < within, "{tag}: пакет не дошёл за {within:?}");
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

const T: Duration = Duration::from_secs(10);

impl Node {
    /// Состояние друга в `client.json` движка (issue #24).
    fn friend_state(&self, pk: &[u8; 32]) -> Option<crate::store::FriendState> {
        let hex = proto::hex_of(pk);
        self.eng
            .cfg
            .lock()
            .unwrap()
            .friends
            .iter()
            .find(|f| f.pubkey == hex)
            .map(|f| f.state)
    }

    /// Ник друга в `client.json` (кэш из `FRIEND_LIST`).
    fn friend_nick(&self, pk: &[u8; 32]) -> Option<String> {
        let hex = proto::hex_of(pk);
        self.eng
            .cfg
            .lock()
            .unwrap()
            .friends
            .iter()
            .find(|f| f.pubkey == hex)
            .map(|f| f.nick.clone())
    }

    /// Сколько записей в списке друзей движка.
    fn friends_len(&self) -> usize {
        self.eng.cfg.lock().unwrap().friends.len()
    }
}

/// Правило потерь посредника: (к серверу?, тип фрейма, сколько фреймов
/// каждого типа клиент отправил, включая этот) → потерять.
type DropRule = Box<dyn FnMut(bool, u8, &HashMap<u8, usize>) -> bool + Send>;

/// Придержать сколько фреймов каждого типа, и придержанные.
type Hold = Arc<Mutex<(HashMap<u8, usize>, Vec<Vec<u8>>)>>;
/// Запомненные управляющие фреймы: (к серверу?, датаграмма).
type Tap = Arc<Mutex<Vec<(bool, Vec<u8>)>>>;

/// UDP-посредник между одним клиентом и сервером: теряет фреймы по правилу
/// (тип фрейма в заголовке открыт), считает отправленное клиентом и
/// запоминает управляющие фреймы (для повторов в тестах).
struct LossyProxy {
    addr: SocketAddr,
    server: SocketAddr,
    sock: UdpSocket,
    sent: Arc<Mutex<HashMap<u8, usize>>>,
    /// Управляющие фреймы: (к серверу?, датаграмма).
    tap: Tap,
    /// Задержка: сколько следующих фреймов сервера клиенту каждого типа
    /// придержать, и придержанные (до [`LossyProxy::release`]).
    hold: Hold,
    client: Arc<Mutex<Option<SocketAddr>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LossyProxy {
    fn start(server: SocketAddr, mut drop_rule: DropRule) -> LossyProxy {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let addr = sock.local_addr().unwrap();
        let sent = Arc::new(Mutex::new(HashMap::new()));
        let tap: Tap = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (sent2, tap2, stop2) = (sent.clone(), tap.clone(), stop.clone());
        let hold: Hold = Arc::default();
        let client_at: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
        let (hold2, client2) = (hold.clone(), client_at.clone());
        let rx = sock.try_clone().unwrap();
        let thread = std::thread::spawn(move || {
            let mut buf = vec![0u8; 65_535];
            // Клиент — первый, кто написал посреднику. Остальных (PUNCH пиров
            // на endpoint клиента — адрес посредника) не пересылать: иначе
            // ответы сервера ушли бы пиру.
            let mut client: Option<SocketAddr> = None;
            while !stop2.load(Ordering::Relaxed) {
                let Ok((n, src)) = rx.recv_from(&mut buf) else {
                    continue;
                };
                let to_server = src != server;
                if to_server {
                    if client.is_some_and(|c| c != src) {
                        continue;
                    }
                    client = Some(src);
                    *client2.lock().unwrap() = client;
                }
                let Some(dst) = (if to_server { Some(server) } else { client }) else {
                    continue;
                };
                let typ = proto::split_frame(&buf[..n]).map(|(t, _)| t).unwrap_or(0);
                if !proto::grp::is_group(typ) {
                    let mut tap = tap2.lock().unwrap();
                    if tap.len() < 4096 {
                        tap.push((to_server, buf[..n].to_vec()));
                    }
                }
                if !to_server {
                    let mut h = hold2.lock().unwrap();
                    if let Some(left) = h.0.get_mut(&typ).filter(|left| **left > 0) {
                        *left -= 1;
                        h.1.push(buf[..n].to_vec());
                        continue;
                    }
                }
                let lost = {
                    let mut sent = sent2.lock().unwrap();
                    if to_server {
                        *sent.entry(typ).or_insert(0) += 1;
                    }
                    drop_rule(to_server, typ, &sent)
                };
                if !lost {
                    let _ = rx.send_to(&buf[..n], dst);
                }
            }
        });
        LossyProxy {
            addr,
            server,
            sock,
            sent,
            tap,
            hold,
            client: client_at,
            stop,
            thread: Some(thread),
        }
    }

    /// Сколько фреймов типа `typ` клиент отправил серверу.
    fn sent(&self, typ: u8) -> usize {
        self.sent.lock().unwrap().get(&typ).copied().unwrap_or(0)
    }

    /// Запомненные фреймы клиента типа `typ` (по порядку).
    fn captured(&self, typ: u8) -> Vec<Vec<u8>> {
        self.tap
            .lock()
            .unwrap()
            .iter()
            .filter(|(to_server, d)| {
                *to_server && proto::split_frame(d).is_ok_and(|(t, _)| t == typ)
            })
            .map(|(_, d)| d.clone())
            .collect()
    }

    /// Придержать следующие `n` фреймов сервера клиенту типа `typ`.
    fn hold(&self, typ: u8, n: usize) {
        *self.hold.lock().unwrap().0.entry(typ).or_insert(0) += n;
    }

    /// Сколько фреймов придержано.
    fn held(&self) -> usize {
        self.hold.lock().unwrap().1.len()
    }

    /// Доставить придержанное клиенту (запоздавшие датаграммы).
    fn release(&self) {
        let frames = std::mem::take(&mut self.hold.lock().unwrap().1);
        let client = self.client.lock().unwrap().expect("клиент известен");
        for f in frames {
            self.sock.send_to(&f, client).unwrap();
        }
    }

    /// Датаграмма серверу с адреса клиента (повтор «с того же адреса»).
    fn inject(&self, frame: &[u8]) {
        self.sock.send_to(frame, self.server).unwrap();
    }
}

/// Правило потерь «по бюджету»: следующие `n` фреймов сервера клиенту типа
/// `typ` теряются (`arm`), остальное доходит.
#[derive(Clone, Default)]
struct Budget(Arc<Mutex<HashMap<u8, usize>>>);

impl Budget {
    fn arm(&self, typ: u8, n: usize) {
        *self.0.lock().unwrap().entry(typ).or_insert(0) += n;
    }

    /// Сколько ещё не потеряно из заказанного.
    fn left(&self, typ: u8) -> usize {
        self.0.lock().unwrap().get(&typ).copied().unwrap_or(0)
    }

    fn rule(&self) -> DropRule {
        let b = self.0.clone();
        Box::new(move |to_server, typ, _| {
            if to_server {
                return false;
            }
            let mut b = b.lock().unwrap();
            match b.get_mut(&typ) {
                Some(n) if *n > 0 => {
                    *n -= 1;
                    true
                }
                _ => false,
            }
        })
    }
}

impl Drop for LossyProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[test]
fn e2e_группа_прямой_канал_без_спама_выход_кик_рестарт() {
    let dir = temp_dir("main");
    let server = start_server(&dir, 0);
    let port = server.addr.port();

    let mut a = Node::start("alpha", &server);
    let mut b = Node::start("bravo", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    b.wait("B подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });

    // A создаёт группу, B входит.
    a.eng
        .cmds
        .send(Cmd::Create {
            name: "game".into(),
            private: false,
        })
        .unwrap();
    let gid = match a.wait("A создал группу", T, |e| {
        matches!(e, Event::GroupJoined { .. })
    }) {
        Event::GroupJoined { gid, .. } => gid,
        _ => unreachable!(),
    };
    b.eng.cmds.send(Cmd::Join(gid)).unwrap();
    b.wait(
        "B вошёл",
        T,
        |e| matches!(e, Event::GroupJoined { gid: g, .. } if *g == gid),
    );
    a.wait("A видит B онлайн", T, |e| {
        matches!(e, Event::PeerOnline { .. })
    });
    assert!(
        a.tun.addrs.lock().unwrap().contains(&a.my_ip(gid)),
        "адрес группы назначен"
    );

    // Прямой канал (localhost: PUNCH доходит сразу).
    a.wait("A: прямой канал", T, |e| {
        matches!(e, Event::Direct { .. })
    });
    b.wait("B: прямой канал", T, |e| {
        matches!(e, Event::Direct { .. })
    });

    // Данные A → B доходят до TUN B.
    let pkt = ipv4(a.my_ip(gid), b.my_ip(gid), b"hello");
    a.eng.send_ip_packet(&pkt);
    let end = Instant::now() + T;
    while !b.tun.injected.lock().unwrap().contains(&pkt) {
        assert!(Instant::now() < end, "пакет A→B не дошёл");
        std::thread::sleep(Duration::from_millis(20));
    }

    // Нет спама: в простое пакетов единицы в секунду (раньше PUNCH↔PUNCH
    // отражался бесконечно — тысячи пакетов в секунду).
    let (a0, b0) = (a.tx_pkts(), b.tx_pkts());
    std::thread::sleep(Duration::from_secs(6));
    let rate_a = (a.tx_pkts() - a0) as f64 / 6.0;
    let rate_b = (b.tx_pkts() - b0) as f64 / 6.0;
    assert!(
        rate_a < 5.0 && rate_b < 5.0,
        "спам пакетами: A {rate_a:.1}/с, B {rate_b:.1}/с"
    );
    // RTT меряется.
    let rtt = a.eng.groups.lock().unwrap()[&gid]
        .members
        .values()
        .next()
        .unwrap()
        .rtt_ms;
    assert!(rtt.is_some(), "нет RTT");

    // Выход: группа пропадает и не возвращается.
    b.eng.cmds.send(Cmd::Leave(gid)).unwrap();
    b.wait("B вышел", T, |e| matches!(e, Event::GroupLeft { .. }));
    let end = Instant::now() + T;
    while a.members(gid) != 0 {
        assert!(Instant::now() < end, "A всё ещё видит B в группе");
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_secs(3));
    b.drain();
    assert!(!b.has_group(gid), "группа вернулась к B после выхода");

    // Кик: B снова входит, A исключает.
    b.eng.cmds.send(Cmd::Join(gid)).unwrap();
    b.wait(
        "B вошёл снова",
        T,
        |e| matches!(e, Event::GroupJoined { gid: g, .. } if *g == gid),
    );
    let b_pub = b.eng.my_pub;
    a.eng.cmds.send(Cmd::Kick(gid, b_pub)).unwrap();
    b.wait(
        "B кикнут",
        T,
        |e| matches!(e, Event::Kicked { gid: g, .. } if *g == gid),
    );
    assert!(!b.has_group(gid));

    // Рестарт сервера на том же порту и с теми же данными: клиенты
    // получают RESET на первый же пакет и переподключаются быстро.
    server.stop();
    a.drain();
    let server = start_server(&dir, port);
    let t0 = Instant::now();
    a.wait(
        "A переподключился",
        Duration::from_secs(15),
        |e| matches!(e, Event::Connected(_)),
    );
    assert!(
        t0.elapsed() < Duration::from_secs(12),
        "переподключение заняло {:?}",
        t0.elapsed()
    );
    // Группа восстановилась из автовхода.
    let end = Instant::now() + T;
    while !a.has_group(gid) {
        assert!(
            Instant::now() < end,
            "A не вернулся в группу после рестарта"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(a);
    drop(b);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_приглашение_офлайн_цели_и_отказ() {
    let dir = temp_dir("invite");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    a.eng
        .cmds
        .send(Cmd::Create {
            name: "secret".into(),
            private: true,
        })
        .unwrap();
    let gid = match a.wait("A создал группу", T, |e| {
        matches!(e, Event::GroupJoined { .. })
    }) {
        Event::GroupJoined { gid, .. } => gid,
        _ => unreachable!(),
    };

    // B ещё не запущен: приглашение ждёт на сервере.
    let b_id = proto::Identity::generate();
    let b_pub = b_id.ed_pub();
    a.eng.cmds.send(Cmd::Invite(gid, b_pub)).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    // B подключается — приглашение приходит после HELLO, с pubkey владельца.
    let mut b = Node::start_as("bravo", &server, b_id);
    let a_pub = a.eng.my_pub;
    b.wait("B получил приглашение", T, |e| {
        matches!(e, Event::Invite { gid: g, from_pubkey, from_name, .. }
            if *g == gid && *from_pubkey == a_pub && from_name == "alpha")
    });
    // Список полный — UI может снять всё, чего в нём нет.
    b.wait("B: список приглашений сверен", T, |e| {
        matches!(e, Event::InvitesSynced { gids, from: 0, complete: true } if gids == &vec![gid])
    });

    // Отказ — владелец узнаёт, кто и куда.
    b.eng.cmds.send(Cmd::DeclineInvite(gid)).unwrap();
    a.wait("A: приглашение отклонено", T, |e| {
        matches!(e, Event::InviteDeclined { gid: g, by_pubkey, by_name, group_name }
            if *g == gid && *by_pubkey == b_pub && by_name == "bravo" && group_name == "secret")
    });
    // Отказавшему сервер отвечает свежим списком — уже без этого gid.
    b.wait(
        "B: отказ подтверждён списком",
        T,
        |e| matches!(e, Event::InvitesSynced { gids, from: 0, complete: true } if gids.is_empty()),
    );
    // После отказа в приватную группу не войти.
    b.eng.cmds.send(Cmd::Join(gid)).unwrap();
    b.wait(
        "B: вход без приглашения отклонён",
        T,
        |e| matches!(e, Event::Error(t) if t.contains("приглашение")),
    );
    assert!(!b.has_group(gid));

    drop(a);
    drop(b);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_больше_16_приглашений_движок_дочитывает_окнами() {
    let dir = temp_dir("invite-pages");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let b_id = proto::Identity::generate();
    let b_pub = b_id.ed_pub();
    let mut gids = HashSet::new();
    for i in 0..20 {
        a.eng
            .cmds
            .send(Cmd::Create {
                name: format!("g{i}"),
                private: true,
            })
            .unwrap();
        let gid = match a.wait("A создал группу", T, |e| {
            matches!(e, Event::GroupJoined { .. })
        }) {
            Event::GroupJoined { gid, .. } => gid,
            _ => unreachable!(),
        };
        a.eng.cmds.send(Cmd::Invite(gid, b_pub)).unwrap();
        gids.insert(gid);
    }
    std::thread::sleep(Duration::from_millis(500));

    // После HELLO сервер шлёт первые 16 — движок сам дочитывает остальное
    // (LIST_INVITES), без ответа на приглашения.
    let mut b = Node::start_as("bravo", &server, b_id.clone());
    b.wait(
        "B: последнее окно списка",
        T,
        |e| matches!(e, Event::InvitesSynced { from, complete: true, .. } if *from > 0),
    );
    let got: HashSet<u32> = b
        .seen
        .iter()
        .filter_map(|e| match e {
            Event::Invite { gid, .. } => Some(*gid),
            _ => None,
        })
        .collect();
    assert_eq!(got, gids, "показаны все 20 приглашений");
    drop(b);

    // CLI (`decline`): окно после HELLO не покрывает gid дальше 16-го —
    // окно с самого gid говорит, есть ли приглашение.
    let mut sorted: Vec<u32> = gids.iter().copied().collect();
    sorted.sort();
    let conn = engine::CtrlConn::connect(
        &Config::default(),
        local(server.addr),
        &server.pubkey,
        &b_id,
    )
    .unwrap();
    let first = conn.invite_list().unwrap().expect("окно после HELLO");
    assert_eq!(first.items.len(), 16);
    assert!(!first.complete && !first.covers(sorted[19]) && !first.covers(250));
    let page = conn.invite_page(sorted[19]).unwrap().expect("окно с gid");
    assert!(page.covers(sorted[19]) && page.items.iter().any(|i| i.gid == sorted[19]));
    let none = conn.invite_page(250).unwrap().expect("окно с gid");
    assert!(
        none.covers(250) && none.items.is_empty(),
        "приглашения в 250 нет"
    );

    drop(a);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_потерянные_окна_приглашений_движок_запрашивает_снова() {
    let dir = temp_dir("invite-loss");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let b_id = proto::Identity::generate();
    let b_pub = b_id.ed_pub();
    let mut gids = HashSet::new();
    for i in 0..20 {
        a.eng
            .cmds
            .send(Cmd::Create {
                name: format!("g{i}"),
                private: true,
            })
            .unwrap();
        let gid = match a.wait("A создал группу", T, |e| {
            matches!(e, Event::GroupJoined { .. })
        }) {
            Event::GroupJoined { gid, .. } => gid,
            _ => unreachable!(),
        };
        a.eng.cmds.send(Cmd::Invite(gid, b_pub)).unwrap();
        gids.insert(gid);
    }
    std::thread::sleep(Duration::from_millis(500));

    // Теряется окно после HELLO (все INVITE_LIST, пока движок сам не
    // спросил), затем запрос второй страницы (второй LIST_INVITES): без
    // повторов B не увидел бы ни одного приглашения до реконнекта.
    let proxy = LossyProxy::start(
        local(server.addr),
        Box::new(|to_server, typ, sent| {
            let asked = sent.get(&ctrl::LIST_INVITES).copied().unwrap_or(0);
            if to_server {
                typ == ctrl::LIST_INVITES && asked == 2
            } else {
                typ == ctrl::INVITE_LIST && asked == 0
            }
        }),
    );
    let mut b = Node::start_via("bravo", proxy.addr, server.pubkey, b_id);
    b.wait(
        "B: последнее окно списка",
        Duration::from_secs(25),
        |e| matches!(e, Event::InvitesSynced { from, complete: true, .. } if *from > 0),
    );
    let got: HashSet<u32> = b
        .seen
        .iter()
        .filter_map(|e| match e {
            Event::Invite { gid, .. } => Some(*gid),
            _ => None,
        })
        .collect();
    assert_eq!(got, gids, "показаны все 20 приглашений");
    assert!(
        proxy.sent(ctrl::LIST_INVITES) >= 3,
        "окно и страница перезапрошены"
    );

    drop(a);
    drop(b);
    drop(proxy);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_потерянный_отказ_от_приглашения_повторяется() {
    let dir = temp_dir("decline-loss");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    a.eng
        .cmds
        .send(Cmd::Create {
            name: "secret".into(),
            private: true,
        })
        .unwrap();
    let gid = match a.wait("A создал группу", T, |e| {
        matches!(e, Event::GroupJoined { .. })
    }) {
        Event::GroupJoined { gid, .. } => gid,
        _ => unreachable!(),
    };
    let b_id = proto::Identity::generate();
    let b_pub = b_id.ed_pub();
    a.eng.cmds.send(Cmd::Invite(gid, b_pub)).unwrap();
    std::thread::sleep(Duration::from_millis(300));

    // Первый DECLINE_INVITE теряется.
    let proxy = LossyProxy::start(
        local(server.addr),
        Box::new(|to_server, typ, sent| {
            to_server && typ == ctrl::DECLINE_INVITE && sent[&typ] == 1
        }),
    );
    let mut b = Node::start_via("bravo", proxy.addr, server.pubkey, b_id);
    b.wait(
        "B получил приглашение",
        T,
        |e| matches!(e, Event::Invite { gid: g, .. } if *g == gid),
    );
    b.eng.cmds.send(Cmd::DeclineInvite(gid)).unwrap();
    a.wait("A: приглашение отклонено (повтором)", T, |e| {
        matches!(e, Event::InviteDeclined { gid: g, by_pubkey, .. } if *g == gid && *by_pubkey == b_pub)
    });
    b.wait(
        "B: отказ подтверждён списком",
        T,
        |e| matches!(e, Event::InvitesSynced { gids, complete: true, .. } if !gids.contains(&gid)),
    );
    // Подтверждённый отказ больше не повторяется.
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(
        proxy.sent(ctrl::DECLINE_INVITE),
        2,
        "один потерянный + один повтор"
    );

    drop(a);
    drop(b);
    drop(proxy);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_сервер_не_релеит_чужим_и_шлёт_reset() {
    let dir = temp_dir("relay");
    let server = start_server(&dir, 0);
    let srv = local(server.addr);

    // Посторонний сокет без сессии: групповой фрейм не релеится, в ответ RESET.
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let h = proto::GroupHeader {
        gid: 1,
        src: 0x6442_0102,
        dst: 0x6442_0103,
        epoch: 0,
    };
    let frame = proto::seal_group(&[1; 32], proto::grp::DATA, &h, 0, b"x");
    sock.send_to(&frame, srv).unwrap();
    let mut buf = [0u8; 1500];
    let (n, from) = sock.recv_from(&mut buf).expect("ответ сервера");
    assert_eq!(from, srv);
    let (typ, body) = proto::split_frame(&buf[..n]).unwrap();
    assert_eq!(typ, proto::ctrl::RESET);
    assert!(body.is_empty());

    // Мусор не роняет сервер: после него обычный клиент подключается.
    for len in [0usize, 3, 7, 8, 30, 200] {
        let _ = sock.send_to(&vec![0xAB; len], srv);
    }
    let mut c = Node::start("charlie", &server);
    c.wait("подключение после мусора", T, |e| {
        matches!(e, Event::Connected(_))
    });
    drop(c);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_битый_server_json_не_затирается() {
    let dir = temp_dir("corrupt");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("server.json");
    std::fs::write(&path, b"{ not json").unwrap();
    let r = tunnel_server::Server::start(tunnel_server::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.clone(),
        workers: 1,
        quiet: true,
        ..Default::default()
    });
    assert!(
        r.is_err(),
        "сервер не должен стартовать с битым server.json"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"{ not json",
        "файл не тронут"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_ротация_бан_админ_разбан_и_смена_сервера() {
    let dir = temp_dir("admin");
    let server = start_server(&dir, 0);
    let dir2 = temp_dir("admin-2");
    let server2 = start_server(&dir2, 0);

    let mut a = Node::start("alpha", &server);
    let mut b = Node::start("bravo", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    b.wait("B подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    a.eng
        .cmds
        .send(Cmd::Create {
            name: "lan".into(),
            private: false,
        })
        .unwrap();
    let gid = match a.wait("A создал группу", T, |e| {
        matches!(e, Event::GroupJoined { .. })
    }) {
        Event::GroupJoined { gid, .. } => gid,
        _ => unreachable!(),
    };
    // Вход B ротирует ключ: A получает его дельтой, B — в GROUP_STATE.
    let epoch0 = a.eng.groups.lock().unwrap()[&gid].epoch;
    b.eng.cmds.send(Cmd::Join(gid)).unwrap();
    b.wait(
        "B вошёл",
        T,
        |e| matches!(e, Event::GroupJoined { gid: g, .. } if *g == gid),
    );
    a.wait("A видит B онлайн", T, |e| {
        matches!(e, Event::PeerOnline { .. })
    });
    let end = Instant::now() + T;
    while a.eng.groups.lock().unwrap()[&gid].epoch == epoch0 {
        assert!(Instant::now() < end, "ключ не ротирован после входа");
        std::thread::sleep(Duration::from_millis(20));
    }
    let pkt = ipv4(a.my_ip(gid), b.my_ip(gid), b"after-rotation");
    // Ротации обоих (вход и HELLO3) могли прийти не одновременно — до grace.
    let end = Instant::now() + T;
    loop {
        a.eng.send_ip_packet(&pkt);
        if b.tun.injected.lock().unwrap().contains(&pkt) {
            break;
        }
        assert!(Instant::now() < end, "пакет A→B после ротации не дошёл");
        std::thread::sleep(Duration::from_millis(100));
    }

    // Бан: B получает KICKED с banned, A видит бан в ADMIN_INFO.
    let b_pub = b.eng.my_pub;
    a.eng.cmds.send(Cmd::Ban(gid, b_pub)).unwrap();
    b.wait(
        "B забанен",
        T,
        |e| matches!(e, Event::Kicked { gid: g, banned: true, .. } if *g == gid),
    );
    assert!(!b.has_group(gid));
    a.eng.cmds.send(Cmd::GroupAdmin(gid)).unwrap();
    a.wait("A: бан в списке", T, |e| {
        matches!(e, Event::AdminInfo { gid: g, bans, .. } if *g == gid && bans.iter().any(|(pk, _)| *pk == b_pub))
    });
    a.eng.cmds.send(Cmd::Unban(gid, b_pub)).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    a.eng.cmds.send(Cmd::GroupAdmin(gid)).unwrap();
    a.wait(
        "A: бан снят",
        T,
        |e| matches!(e, Event::AdminInfo { gid: g, bans, .. } if *g == gid && bans.is_empty()),
    );
    b.eng.cmds.send(Cmd::Join(gid)).unwrap();
    b.wait(
        "B вошёл после разбана",
        T,
        |e| matches!(e, Event::GroupJoined { gid: g, .. } if *g == gid),
    );

    // Смена сервера без перезапуска: группы прежнего забыты, рукопожатие с новым.
    let addr2 = local(server2.addr);
    b.eng
        .cmds
        .send(Cmd::SwitchServer {
            addr: addr2,
            pubkey: server2.pubkey,
            label: "two".into(),
        })
        .unwrap();
    b.wait(
        "B забыл группу",
        T,
        |e| matches!(e, Event::GroupLeft { gid: g, .. } if *g == gid),
    );
    b.wait(
        "B переключён",
        T,
        |e| matches!(e, Event::ServerSwitched { addr, .. } if *addr == addr2),
    );
    b.wait(
        "B подключён к новому",
        T,
        |e| matches!(e, Event::Connected(s) if *s == addr2),
    );
    assert!(!b.has_group(gid));
    assert_eq!(b.eng.meta.lock().unwrap().server_label, "two");
    let gid2 = b.create("other", false);
    // Туннель на новом сервере работает: тот же сокет и адаптер.
    let mut e = Node::start("echo", &server2);
    e.wait("E подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    e.join(gid2);
    wait_until("B и E видят друг друга", T, || {
        b.sees_online(gid2, 1) && e.sees_online(gid2, 1)
    });
    deliver(&b, &e, gid2, "switched-be", T);
    deliver(&e, &b, gid2, "switched-eb", T);
    // gid у серверов свои (здесь совпадают): у B только группа нового.
    {
        let g = b.eng.groups.lock().unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!(g[&gid2].name, "other");
    }
    assert_eq!(b.eng.cfg.lock().unwrap().active_server, addr2.to_string());

    drop(a);
    drop(b);
    drop(e);
    server.stop();
    server2.stop();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

/// Три участника; ключи и прямые каналы у всех сошлись.
fn three_in_group(server: &tunnel_server::Server, private: bool) -> (Node, Node, Node, u32) {
    let mut a = Node::start("alpha", server);
    let mut b = Node::start("bravo", server);
    let mut c = Node::start("charlie", server);
    for n in [&mut a, &mut b, &mut c] {
        n.wait("подключён", T, |e| {
            matches!(e, Event::Connected(_))
        });
    }
    let gid = a.create("trio", private);
    b.join(gid);
    c.join(gid);
    wait_until("все видят всех онлайн", T, || {
        a.sees_online(gid, 2) && b.sees_online(gid, 2) && c.sees_online(gid, 2)
    });
    wait_until("эпоха у всех одна", T, || {
        let e = a.epoch(gid);
        b.epoch(gid) == e && c.epoch(gid) == e
    });
    let (ia, ib, ic) = (a.my_ip(gid), b.my_ip(gid), c.my_ip(gid));
    wait_until("прямые каналы попарно", T, || {
        a.direct_to(gid, ib)
            && a.direct_to(gid, ic)
            && b.direct_to(gid, ia)
            && b.direct_to(gid, ic)
            && c.direct_to(gid, ia)
            && c.direct_to(gid, ib)
    });
    (a, b, c, gid)
}

#[test]
fn e2e_три_участника_попарно_подделки_src_и_повторы_отбрасываются() {
    let dir = temp_dir("trio");
    let server = start_server(&dir, 0);
    let srv = local(server.addr);
    let (a, b, c, gid) = three_in_group(&server, false);
    let (ia, ib, ic) = (a.my_ip(gid), b.my_ip(gid), c.my_ip(gid));

    // Попарно во все шесть сторон.
    let nodes = [("a", &a), ("b", &b), ("c", &c)];
    for (nf, from) in nodes {
        for (nt, to) in nodes {
            if nf != nt {
                deliver(from, to, gid, &format!("pair-{nf}-{nt}"), T);
            }
        }
    }

    // B — участник с настоящим ключом — подделывает отправителя C: релей
    // (сервер сверяет src_ip с отправителем) и напрямую (адрес B не из
    // адресов C) — отброшено. Внутренний IPv4-источник ≠ src_ip — тоже.
    // Контроль: честные фреймы B тем же способом доходят, причём повтор того
    // же фрейма (тот же счётчик) — один раз, каким бы путём ни пришёл.
    let frame = |src: u32, inner: u32, tag: &str| {
        b.eng
            .craft_frame(
                gid,
                proto::grp::DATA,
                src,
                ia,
                &ipv4(inner, ia, tag.as_bytes()),
            )
            .unwrap()
    };
    let forged = [
        (frame(ic, ic, "forge-src-relay"), srv),
        (frame(ic, ic, "forge-src-direct"), a.addr()),
        (frame(ib, ic, "forge-inner-relay"), srv),
        (frame(ib, ic, "forge-inner-direct"), a.addr()),
    ];
    let genuine_relay = frame(ib, ib, "genuine-relay");
    let genuine_direct = frame(ib, ib, "genuine-direct");
    for (f, to) in &forged {
        b.eng.send_raw(f, *to);
    }
    b.eng.send_raw(&genuine_relay, srv);
    b.eng.send_raw(&genuine_direct, a.addr());
    let pkt = |inner: u32, tag: &str| ipv4(inner, ia, tag.as_bytes());
    wait_until("честные фреймы B дошли", T, || {
        a.got(&pkt(ib, "genuine-relay")) == 1 && a.got(&pkt(ib, "genuine-direct")) == 1
    });
    // Повторы: тот же фрейм ещё раз тем же путём и другим.
    for _ in 0..3 {
        b.eng.send_raw(&genuine_relay, srv);
        b.eng.send_raw(&genuine_relay, a.addr());
        b.eng.send_raw(&genuine_direct, a.addr());
        b.eng.send_raw(&genuine_direct, srv);
    }
    // Барьер: свежий пакет B → A тем же путём дошёл — повторы до него уже
    // обработаны (или отброшены).
    deliver(&b, &a, gid, "barrier", T);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        a.got(&pkt(ib, "genuine-relay")),
        1,
        "повтор через релей доставлен"
    );
    assert_eq!(
        a.got(&pkt(ib, "genuine-direct")),
        1,
        "повтор напрямую доставлен"
    );
    for (tag, inner) in [
        ("forge-src-relay", ic),
        ("forge-src-direct", ic),
        ("forge-inner-relay", ic),
        ("forge-inner-direct", ic),
    ] {
        assert_eq!(a.got(&pkt(inner, tag)), 0, "подделка {tag} доставлена");
    }
    drop((a, b, c));
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_кикнутый_со_старым_ключом_не_доставляет_и_не_читает() {
    let dir = temp_dir("kick-key");
    let server = start_server(&dir, 0);
    let srv = local(server.addr);
    let (a, mut b, c, gid) = three_in_group(&server, false);
    let (ia, ib, ic) = (a.my_ip(gid), b.my_ip(gid), c.my_ip(gid));

    // Контроль: до кика фреймы B старым (пока текущим) ключом доходят.
    let (old_epoch, old_key, _) = b.eng.group_key(gid).unwrap();
    let mut ctr = 1u64 << 40;
    let mut old_frame = |key: &proto::SymKey, epoch: u32, src: u32, dst: u32, tag: &str| {
        ctr += 1;
        let h = proto::GroupHeader {
            gid,
            src,
            dst,
            epoch,
        };
        proto::seal_group(
            key,
            proto::grp::DATA,
            &h,
            ctr,
            &ipv4(src, dst, tag.as_bytes()),
        )
    };
    let before = old_frame(&old_key, old_epoch, ib, ia, "before-kick");
    b.eng.send_raw(&before, a.addr());
    wait_until("фрейм до кика дошёл", T, || {
        a.got(&ipv4(ib, ia, b"before-kick")) == 1
    });

    let b_pub = b.eng.my_pub;
    a.eng.cmds.send(Cmd::Kick(gid, b_pub)).unwrap();
    b.wait(
        "B кикнут",
        T,
        |e| matches!(e, Event::Kicked { gid: g, banned: false, .. } if *g == gid),
    );
    wait_until(
        "A и C ротировали ключ и убрали B",
        T,
        || {
            a.epoch(gid) != old_epoch
                && c.epoch(gid) == a.epoch(gid)
                && a.members(gid) == 1
                && c.members(gid) == 1
        },
    );
    let new_epoch = a.epoch(gid);

    // Кикнутый со старым ключом: от себя, от имени C и со старым ключом под
    // номером новой эпохи — через релей и напрямую, к A и к C.
    let mut sent = Vec::new();
    for (dst, dst_addr) in [(ia, a.addr()), (ic, c.addr())] {
        for (src, epoch, tag) in [
            (ib, old_epoch, "self-old"),
            (if dst == ia { ic } else { ia }, old_epoch, "spoof-old"),
            (ib, new_epoch, "self-new-epoch"),
        ] {
            for (to, path) in [(srv, "relay"), (dst_addr, "direct")] {
                let tag = format!("{tag}-{path}");
                b.eng
                    .send_raw(&old_frame(&old_key, epoch, src, dst, &tag), to);
                sent.push((src, dst, tag));
            }
        }
    }
    // Барьер: обычный трафик A ↔ C после кика ходит.
    deliver(&a, &c, gid, "after-kick-ac", T);
    deliver(&c, &a, gid, "after-kick-ca", T);
    std::thread::sleep(Duration::from_millis(300));
    for (src, dst, tag) in &sent {
        let to = if *dst == ia { &a } else { &c };
        assert_eq!(
            to.got(&ipv4(*src, *dst, tag.as_bytes())),
            0,
            "доставлено от кикнутого: {tag}"
        );
    }
    // Новый трафик старым ключом не открыть: другая эпоха, другой ключ.
    let fresh = a
        .eng
        .craft_frame(gid, proto::grp::DATA, ia, ic, &ipv4(ia, ic, b"secret"))
        .unwrap();
    let (_, h) = proto::parse_group_header(&fresh).unwrap();
    assert_eq!(h.epoch, new_epoch);
    assert!(
        proto::open_group(&old_key, &fresh).is_err(),
        "новый трафик читается старым ключом"
    );
    let (_, c_key, _) = c.eng.group_key(gid).unwrap();
    assert!(proto::open_group(&c_key, &fresh).is_ok());
    assert!(!b.has_group(gid));
    drop((a, b, c));
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_ротации_ключа_при_потерях_восстанавливаются() {
    let dir = temp_dir("rot-loss");
    let server = start_server(&dir, 0);
    let budget = Budget::default();
    let proxy = LossyProxy::start(local(server.addr), budget.rule());
    let mut a = Node::start("alpha", &server);
    let mut b = Node::start_via(
        "bravo",
        proxy.addr,
        server.pubkey,
        proto::Identity::generate(),
    );
    let mut c = Node::start("charlie", &server);
    for n in [&mut a, &mut b, &mut c] {
        n.wait("подключён", T, |e| {
            matches!(e, Event::Connected(_))
        });
    }
    let gid = a.create("lossy", false);
    // 0. Ответ на JOIN (GROUP_STATE) теряется: группа приходит по списку
    //    групп, где она уже наша (GET_GROUP).
    budget.arm(ctrl::GROUP_STATE, 1);
    b.join(gid);
    assert_eq!(
        budget.left(ctrl::GROUP_STATE),
        0,
        "ответ на JOIN не был потерян"
    );
    wait_until("A и B видят друг друга", T, || {
        a.sees_online(gid, 1) && b.sees_online(gid, 1)
    });
    deliver(&a, &b, gid, "warmup-ab", T);
    deliver(&b, &a, gid, "warmup-ba", T);
    let both_ways = |tag: &str, within: Duration| {
        let t = deliver(&a, &b, gid, &format!("{tag}-ab"), within);
        let t2 = deliver(&b, &a, gid, &format!("{tag}-ba"), within);
        wait_until("эпохи A и B сошлись", within, || {
            a.epoch(gid) == b.epoch(gid)
        });
        t.max(t2)
    };

    // 1. Вход C ротирует ключ, дельта до B теряется: B узнаёт о новой эпохе
    //    по фреймам A и сам делает GET_GROUP.
    std::thread::sleep(Duration::from_millis(300));
    let e0 = a.epoch(gid);
    budget.arm(ctrl::GROUP_UPDATE, 1);
    c.join(gid);
    wait_until("A получил ротацию", T, || a.epoch(gid) != e0);
    let t = both_ways("join-rot", Duration::from_secs(5));
    assert_eq!(
        budget.left(ctrl::GROUP_UPDATE),
        0,
        "дельта не была потеряна"
    );
    eprintln!("ротация входа при потере дельты: восстановление за {t:?}");

    // 2. Выход C — ротация с отзывом: теряются и дельта, и первый ответ на
    //    GET_GROUP. Прошлый ключ у A отозван — B → A молчит до восстановления.
    let e1 = a.epoch(gid);
    budget.arm(ctrl::GROUP_UPDATE, 1);
    budget.arm(ctrl::GROUP_STATE, 1);
    c.eng.cmds.send(Cmd::Leave(gid)).unwrap();
    wait_until(
        "A получил ротацию с отзывом",
        T,
        || a.epoch(gid) != e1 && a.members(gid) == 1,
    );
    let t = both_ways("leave-rot", Duration::from_secs(8));
    assert_eq!(
        budget.left(ctrl::GROUP_STATE),
        0,
        "ответ GET_GROUP не был потерян"
    );
    eprintln!("ротация выхода при потере дельты и состояния: {t:?}");

    // 3. Переподключение A (смена имени — новое рукопожатие) ротирует ключ;
    //    дельта до B теряется.
    let e2 = a.epoch(gid);
    budget.arm(ctrl::GROUP_UPDATE, 1);
    a.eng.cmds.send(Cmd::SetName("alpha-2".into())).unwrap();
    wait_until("A ротировал ключ рукопожатием", T, || a.epoch(gid) != e2);
    both_ways("rehello-a", Duration::from_secs(8));

    // 4. Переподключение B, его WELCOME теряется: повтор HELLO3 той же
    //    попытки получает тот же WELCOME и состояние групп заново.
    let e3 = a.epoch(gid);
    budget.arm(ctrl::WELCOME, 1);
    b.eng.cmds.send(Cmd::SetName("bravo-2".into())).unwrap();
    wait_until("B ротировал ключ рукопожатием", T, || a.epoch(gid) != e3);
    both_ways("rehello-b", Duration::from_secs(8));
    assert_eq!(budget.left(ctrl::WELCOME), 0, "WELCOME не был потерян");
    let b_name_at_a = |a: &Node| {
        let g = a.eng.groups.lock().unwrap();
        g[&gid]
            .members
            .values()
            .next()
            .map(|p| p.name.clone())
            .unwrap_or_default()
    };
    wait_until("A видит новое имя B", T, || {
        b_name_at_a(&a) == "bravo-2"
    });

    // 5. Потерянная дельта без ротации (статус A): ни эпохи, ни следующей
    //    дельты — чинит сверка ревизий по GROUP_LIST (раз в 15 с).
    std::thread::sleep(Duration::from_millis(300));
    budget.arm(ctrl::GROUP_UPDATE, 1);
    a.eng.cmds.send(Cmd::SetStatus("afk".into())).unwrap();
    let status_at_b = |b: &Node| {
        let g = b.eng.groups.lock().unwrap();
        g[&gid]
            .members
            .values()
            .next()
            .map(|p| p.status.clone())
            .unwrap_or_default()
    };
    let t0 = Instant::now();
    wait_until(
        "B видит статус A",
        Duration::from_secs(20),
        || status_at_b(&b) == "afk",
    );
    assert_eq!(
        budget.left(ctrl::GROUP_UPDATE),
        0,
        "дельта статуса не была потеряна"
    );
    eprintln!(
        "потерянная дельта статуса: восстановление за {:?}",
        t0.elapsed()
    );
    both_ways("final", T);
    b.drain();
    assert!(
        !b.seen.iter().any(|e| matches!(e, Event::Disconnected(_))),
        "B терял связь: {:?}",
        b.seen
    );

    drop((a, b, c));
    drop(proxy);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_ротация_ключа_сервера_перезакрепляет_клиента() {
    let dir = temp_dir("srv-rotate");
    let s1 = start_server(&dir, 0);
    let port = s1.addr.port();
    let addr = local(s1.addr);
    let pk1 = s1.pubkey;
    s1.stop();
    let r1 = tunnel_server::rotate_key(&dir).expect("rotate-key");
    let server = start_server(&dir, port);
    assert_eq!(server.pubkey, r1.pubkey);

    // Клиент с неверным ключом сервера не подключается.
    let wrong = proto::Identity::generate().ed_pub();
    let err = Node::start_cfg(
        Config::default(),
        addr,
        wrong,
        proto::Identity::generate(),
        Arc::new(|_| {}),
    )
    .err()
    .expect("чужой ключ сервера принят");
    assert!(
        format!("{err:#}").contains("ключ сервера не совпадает"),
        "{err:#}"
    );

    // Клиент, закрепивший старый ключ: перезакрепление по цепочке.
    let saved: Arc<Mutex<Option<Config>>> = Arc::default();
    let cfg = Config {
        name: "pinned".into(),
        servers: vec![crate::store::StoredServer {
            addr: addr.to_string(),
            pubkey: proto::hex_of(&pk1),
            label: "main".into(),
        }],
        ..Config::default()
    };
    let save = {
        let saved = saved.clone();
        Arc::new(move |c: &Config| *saved.lock().unwrap() = Some(c.clone()))
    };
    let mut n = Node::start_cfg(cfg, addr, pk1, proto::Identity::generate(), save)
        .expect("подключение по цепочке");
    n.wait("перезакреплён", T, |e| {
        matches!(e, Event::ServerKeyRotated { addr: a, new_code } if *a == addr && *new_code == r1.code)
    });
    n.wait("подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let pinned = |saved: &Arc<Mutex<Option<Config>>>| {
        saved
            .lock()
            .unwrap()
            .as_ref()
            .map(|c| c.servers[0].pubkey.clone())
            .unwrap_or_default()
    };
    assert_eq!(
        pinned(&saved),
        proto::hex_of(&r1.pubkey),
        "client.json не перезакреплён"
    );
    assert_eq!(
        n.eng.cfg.lock().unwrap().servers[0].pubkey,
        proto::hex_of(&r1.pubkey)
    );
    let gid = n.create("keep", false);

    // Вторая ротация на ходу: сервер перезапущен с новым ключом, движок
    // получает RESET, переподключается и перезакрепляется ещё раз.
    server.stop();
    let r2 = tunnel_server::rotate_key(&dir).expect("rotate-key");
    let server = start_server(&dir, port);
    n.wait(
        "перезакреплён снова",
        Duration::from_secs(20),
        |e| matches!(e, Event::ServerKeyRotated { new_code, .. } if *new_code == r2.code),
    );
    n.wait("переподключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    assert_eq!(pinned(&saved), proto::hex_of(&r2.pubkey));
    wait_until("группа вернулась", T, || n.has_group(gid));
    drop(n);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_передача_владения_приглашения_в_admin_и_их_срок() {
    let dir = temp_dir("owner");
    let limits = tunnel_server::Limits {
        invite_ttl: Duration::from_secs(3),
        ..Default::default()
    };
    let server = start_server_with(&dir, 0, limits);
    let mut a = Node::start("alpha", &server);
    let mut b = Node::start("bravo", &server);
    let mut d = Node::start("delta", &server);
    for n in [&mut a, &mut b, &mut d] {
        n.wait("подключён", T, |e| {
            matches!(e, Event::Connected(_))
        });
    }
    let gid = a.create("club", true);
    let (a_pub, b_pub, d_pub) = (a.eng.my_pub, b.eng.my_pub, d.eng.my_pub);
    let offline = proto::Identity::generate().ed_pub();

    // Приглашения: B примет, D и офлайн-цель — истекут. Срок доходит до
    // клиента (expires_in) и до владельца (ADMIN_INFO).
    a.eng.cmds.send(Cmd::Invite(gid, b_pub)).unwrap();
    b.wait("B: приглашение со сроком", T, |e| {
        matches!(e, Event::Invite { gid: g, expires_in: 3, from_pubkey, .. } if *g == gid && *from_pubkey == a_pub)
    });
    b.join(gid);
    a.eng.cmds.send(Cmd::Invite(gid, d_pub)).unwrap();
    a.eng.cmds.send(Cmd::Invite(gid, offline)).unwrap();
    d.wait(
        "D: приглашение со сроком",
        T,
        |e| matches!(e, Event::Invite { gid: g, expires_in: 3, .. } if *g == gid),
    );
    let invited = Instant::now();
    a.eng.cmds.send(Cmd::GroupAdmin(gid)).unwrap();
    a.wait("A: висящие приглашения", T, |e| match e {
        Event::AdminInfo {
            gid: g,
            bans,
            invites,
        } if *g == gid => {
            bans.is_empty()
                && invites.len() == 2
                && invites.iter().any(|(pk, name, left)| {
                    *pk == d_pub && name == "delta" && (1..=3).contains(left)
                })
                && invites
                    .iter()
                    .any(|(pk, _, left)| *pk == offline && (1..=3).contains(left))
        }
        _ => false,
    });
    // Истечение: D получает свежий список без gid, владелец — пустой список.
    d.wait(
        "D: приглашение истекло",
        T,
        |e| matches!(e, Event::InvitesSynced { gids, complete: true, .. } if !gids.contains(&gid)),
    );
    assert!(
        invited.elapsed() >= Duration::from_secs(2),
        "приглашение истекло раньше срока"
    );
    a.eng.cmds.send(Cmd::GroupAdmin(gid)).unwrap();
    a.wait("A: приглашений нет", T, |e| {
        matches!(e, Event::AdminInfo { gid: g, invites, .. } if *g == gid && invites.is_empty())
    });
    d.eng.cmds.send(Cmd::Join(gid)).unwrap();
    d.wait(
        "D: вход по истёкшему отклонён",
        T,
        |e| matches!(e, Event::Error(t) if t.contains("приглашение")),
    );
    assert!(!d.has_group(gid));

    // Передача владения участнику: оба видят нового владельца, прежний
    // больше не администрирует.
    a.eng.cmds.send(Cmd::Transfer(gid, b_pub)).unwrap();
    wait_until("владелец сменился у обоих", T, || {
        a.owner(gid) == Some(b_pub) && b.owner(gid) == Some(b_pub)
    });
    a.eng.cmds.send(Cmd::GroupAdmin(gid)).unwrap();
    a.wait(
        "A больше не владелец",
        T,
        |e| matches!(e, Event::Error(t) if t.contains("владелец")),
    );
    b.eng.cmds.send(Cmd::GroupAdmin(gid)).unwrap();
    b.wait(
        "B администрирует",
        T,
        |e| matches!(e, Event::AdminInfo { gid: g, .. } if *g == gid),
    );

    // Новый владелец исключает прежнего (KICKED без бана) и снова приглашает:
    // вход после кика работает.
    b.eng.cmds.send(Cmd::Kick(gid, a_pub)).unwrap();
    a.wait(
        "A кикнут",
        T,
        |e| matches!(e, Event::Kicked { gid: g, banned: false, .. } if *g == gid),
    );
    assert!(!a.has_group(gid));
    b.eng.cmds.send(Cmd::Invite(gid, a_pub)).unwrap();
    a.wait(
        "A приглашён снова",
        T,
        |e| matches!(e, Event::Invite { gid: g, .. } if *g == gid),
    );
    a.join(gid);
    wait_until("A и B снова вместе", T, || {
        a.sees_online(gid, 1) && b.sees_online(gid, 1)
    });
    deliver(&a, &b, gid, "rejoined", T);

    drop((a, b, d));
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_повтор_hello3_не_мешает_живой_сессии() {
    let dir = temp_dir("hello-replay");
    let server = start_server(&dir, 0);
    let srv = local(server.addr);
    let proxy = LossyProxy::start(srv, Box::new(|_, _, _| false));
    let mut a = Node::start("alpha", &server);
    let mut b = Node::start_via(
        "bravo",
        proxy.addr,
        server.pubkey,
        proto::Identity::generate(),
    );
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    b.wait("B подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let gid = a.create("replay", false);
    b.join(gid);
    wait_until("A и B видят друг друга", T, || {
        a.sees_online(gid, 1) && b.sees_online(gid, 1)
    });
    wait_until("эпохи сошлись", T, || {
        a.epoch(gid) == b.epoch(gid)
    });
    deliver(&a, &b, gid, "before", T);
    let epoch = a.epoch(gid);
    b.drain();
    let mark = b.seen.len();

    // Перехваченные HELLO3 B: с cookie (подписан под адрес посредника) и без.
    let hellos = proxy.captured(ctrl::HELLO3);
    let with_cookie = hellos
        .iter()
        .rev()
        .find(|d| {
            proto::split_frame(d).is_ok_and(|(_, body)| {
                proto::Hello3::decode(body).is_ok_and(|h| h.cookie.is_some())
            })
        })
        .expect("HELLO3 с cookie")
        .clone();
    let without = hellos
        .iter()
        .find(|d| {
            proto::split_frame(d).is_ok_and(|(_, body)| {
                proto::Hello3::decode(body).is_ok_and(|h| h.cookie.is_none())
            })
        })
        .expect("HELLO3 без cookie")
        .clone();

    // С другого адреса: только CHALLENGE (cookie привязан к адресу B).
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    for f in [&with_cookie, &without, &with_cookie] {
        sock.send_to(f, srv).unwrap();
    }
    let mut got = Vec::new();
    let end = Instant::now() + Duration::from_millis(800);
    let mut buf = [0u8; 2048];
    while Instant::now() < end {
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            got.push(proto::split_frame(&buf[..n]).map(|(t, _)| t).unwrap_or(0));
        }
    }
    assert!(
        !got.is_empty() && got.iter().all(|t| *t == ctrl::CHALLENGE),
        "ответы на повтор: {got:02x?}"
    );

    // С того же адреса (через посредника): тот же WELCOME, сессия и ключи
    // прежние, ротации нет.
    proxy.inject(&with_cookie);
    proxy.inject(&with_cookie);
    std::thread::sleep(Duration::from_millis(800));
    deliver(&a, &b, gid, "after-ab", T);
    deliver(&b, &a, gid, "after-ba", T);
    assert_eq!(a.epoch(gid), epoch, "повтор HELLO3 ротировал ключ группы");
    assert_eq!(b.epoch(gid), epoch);
    assert!(
        !b.saw_since(mark, |e| matches!(
            e,
            Event::Disconnected(_) | Event::Connected(_)
        )),
        "сессия B пересоздана: {:?}",
        &b.seen[mark..]
    );
    // Управляющий канал B жив: команда — ответ сервера.
    b.eng.cmds.send(Cmd::GroupAdmin(gid)).unwrap();
    b.wait(
        "B: ответ сервера",
        T,
        |e| matches!(e, Event::Error(t) if t.contains("владелец")),
    );
    drop((a, b));
    drop(proxy);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_запоздавший_group_state_не_возвращает_отозванный_ключ() {
    let dir = temp_dir("stale-state");
    let server = start_server(&dir, 0);
    let proxy = LossyProxy::start(local(server.addr), Box::new(|_, _, _| false));
    let proxy_c = LossyProxy::start(local(server.addr), Box::new(|_, _, _| false));
    let mut a = Node::start("alpha", &server);
    let mut b = Node::start_via(
        "bravo",
        proxy.addr,
        server.pubkey,
        proto::Identity::generate(),
    );
    let mut c = Node::start_via(
        "charlie",
        proxy_c.addr,
        server.pubkey,
        proto::Identity::generate(),
    );
    for n in [&mut a, &mut b, &mut c] {
        n.wait("подключён", T, |e| {
            matches!(e, Event::Connected(_))
        });
    }
    let gid = a.create("stale", false);
    b.join(gid);
    c.join(gid);
    wait_until("все видят всех", T, || {
        a.sees_online(gid, 2) && b.sees_online(gid, 2) && c.sees_online(gid, 2)
    });
    wait_until("эпоха у всех одна", T, || {
        let e = a.epoch(gid);
        b.epoch(gid) == e && c.epoch(gid) == e
    });
    std::thread::sleep(Duration::from_millis(300));

    // B и C просят полное состояние (фрейм «новой эпохи» с адреса A —
    // сигнал GET_GROUP принимается только от релея или известного адреса
    // заявленного отправителя), а ответы задерживаются в сети.
    let (epoch, c_key, _) = c.eng.group_key(gid).unwrap();
    let (ia, ib, ic) = (a.my_ip(gid), b.my_ip(gid), c.my_ip(gid));
    for (n, p, ip) in [(&b, &proxy, ib), (&c, &proxy_c, ic)] {
        p.hold(ctrl::GROUP_STATE, 1);
        let h = proto::GroupHeader {
            gid,
            src: ia,
            dst: ip,
            epoch: epoch + 1,
        };
        a.eng.send_raw(
            &proto::seal_group(&[7; 32], proto::grp::DATA, &h, 1, b"x"),
            n.addr(),
        );
        wait_until("ответ GET_GROUP придержан", T, || {
            p.held() == 1
        });
    }

    // Пока ответы в пути, C кикнут: ротация с отзывом, B получает дельту.
    a.eng.cmds.send(Cmd::Kick(gid, c.eng.my_pub)).unwrap();
    c.wait("C кикнут", T, |e| matches!(e, Event::Kicked { .. }));
    wait_until("B получил новый ключ", T, || {
        b.epoch(gid) != epoch && b.epoch(gid) == a.epoch(gid)
    });
    let mark = c.seen.len();

    // Запоздавшее состояние (ключ, который знает C) не откатывает B и не
    // возвращает группу кикнутому C.
    proxy.release();
    proxy_c.release();
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !c.has_group(gid),
        "запоздавшее состояние вернуло группу кикнутому"
    );
    assert!(
        !c.saw_since(mark, |e| matches!(e, Event::GroupJoined { .. })),
        "{:?}",
        &c.seen[mark..]
    );
    let (b_epoch, b_key, _) = b.eng.group_key(gid).unwrap();
    let (a_epoch, a_key, _) = a.eng.group_key(gid).unwrap();
    assert_eq!(
        (b_epoch, b_key),
        (a_epoch, a_key),
        "B откатился к прежнему ключу"
    );
    assert_ne!(b_key, c_key);
    assert_eq!(b.members(gid), 1, "запоздавшее состояние вернуло C");
    deliver(&b, &a, gid, "after-stale", T);
    let frame = b
        .eng
        .craft_frame(gid, proto::grp::DATA, ib, ia, &ipv4(ib, ia, b"secret"))
        .unwrap();
    assert!(
        proto::open_group(&c_key, &frame).is_err(),
        "B шифрует ключом, известным кикнутому"
    );

    drop((a, b, c));
    drop(proxy);
    drop(proxy_c);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Посредник-«подделыватель»: на каждый HELLO3 клиента сначала шлёт ему
/// неаутентифицированные UNSUPPORTED, RESET, WELCOME с битой подписью и
/// WELCOME, подписанный чужим ключом (под наш ed/eph), — и лишь потом
/// пересылает HELLO3 серверу. Остальное — прозрачно.
fn spoofing_proxy(
    server: SocketAddr,
) -> (SocketAddr, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let addr = sock.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let thread = std::thread::spawn(move || {
        let stranger = proto::Identity::generate();
        let mut buf = vec![0u8; 65_535];
        let mut client: Option<SocketAddr> = None;
        while !stop2.load(Ordering::Relaxed) {
            let Ok((n, src)) = sock.recv_from(&mut buf) else {
                continue;
            };
            if src == server {
                if let Some(c) = client {
                    let _ = sock.send_to(&buf[..n], c);
                }
                continue;
            }
            client = Some(src);
            if let Ok((ctrl::HELLO3, body)) = proto::split_frame(&buf[..n])
                && let Ok(h) = proto::Hello3::decode(body)
            {
                let eph = proto::EphemeralKey::generate();
                let forged =
                    proto::Welcome::encode(&stranger, &eph.public(), &[], &h.ed_pub, &h.eph_pub);
                let mut bad_sig = forged.clone();
                *bad_sig.last_mut().unwrap() ^= 0xff;
                let frames = [
                    proto::plain_frame(
                        ctrl::UNSUPPORTED,
                        &proto::handshake::enc_unsupported("подделка"),
                    ),
                    proto::plain_frame(ctrl::RESET, &[]),
                    proto::plain_frame(ctrl::WELCOME, &bad_sig),
                    proto::plain_frame(ctrl::WELCOME, &forged),
                ];
                for f in frames {
                    let _ = sock.send_to(&f, src);
                }
            }
            let _ = sock.send_to(&buf[..n], server);
        }
    });
    (addr, stop, thread)
}

#[test]
fn e2e_открытые_ответы_не_обрывают_подключение() {
    let dir = temp_dir("forged-plain");
    let server = start_server(&dir, 0);
    let (addr, stop, thread) = spoofing_proxy(local(server.addr));

    // CLI (CtrlConn): поддельные UNSUPPORTED/RESET/WELCOME не обрывают
    // рукопожатие — подлинный WELCOME принимается, команда работает.
    let id = proto::Identity::generate();
    let t0 = Instant::now();
    let conn = engine::CtrlConn::connect(&Config::default(), addr, &server.pubkey, &id)
        .expect("CtrlConn подключается сквозь подделки");
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "без ожидания таймаута"
    );
    assert!(conn.rotated.is_none());
    conn.invite_list().expect("ответ сервера после подделок");
    drop(conn);

    // Движок: первое подключение тоже не обрывается и не шлёт Error.
    let mut n = Node::start_via("forged", addr, server.pubkey, proto::Identity::generate());
    n.wait("подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    n.drain();
    assert!(
        !n.seen.iter().any(|e| matches!(e, Event::Error(_))),
        "подделки не дают ошибок: {:?}",
        n.seen
    );
    drop(n);

    stop.store(true, Ordering::Relaxed);
    thread.join().unwrap();
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Кикнутый с отстающей ревизией (дельта не дошла — повод для GET_GROUP):
/// ответ с ревизией новее его своей, но не новее кика, группу не возвращает —
/// граница запоздания берётся из KICKED, а не из своей ревизии.
#[test]
fn e2e_кик_при_отстающей_ревизии_не_возвращает_группу() {
    let dir = temp_dir("stale-lag");
    let server = start_server(&dir, 0);
    let proxy_c = LossyProxy::start(local(server.addr), Box::new(|_, _, _| false));
    let mut a = Node::start("alpha", &server);
    let mut c = Node::start_via(
        "charlie",
        proxy_c.addr,
        server.pubkey,
        proto::Identity::generate(),
    );
    for n in [&mut a, &mut c] {
        n.wait("подключён", T, |e| {
            matches!(e, Event::Connected(_))
        });
    }
    let gid = a.create("lag", false);
    c.join(gid);
    wait_until("видят друг друга", T, || {
        a.sees_online(gid, 1) && c.sees_online(gid, 1)
    });
    std::thread::sleep(Duration::from_millis(300));
    let c_rev = c.eng.groups.lock().unwrap()[&gid].rev;

    // Дельта переименования до C не доходит: его ревизия отстаёт.
    proxy_c.hold(ctrl::GROUP_UPDATE, 1);
    a.eng.cmds.send(Cmd::Rename(gid, "lag2".into())).unwrap();
    wait_until("дельта придержана", T, || {
        proxy_c.held() == 1
    });

    // GET_GROUP от C, ответ (ревизия новее его) задерживается.
    let (epoch, _, _) = c.eng.group_key(gid).unwrap();
    let (ia, ic) = (a.my_ip(gid), c.my_ip(gid));
    proxy_c.hold(ctrl::GROUP_STATE, 1);
    let h = proto::GroupHeader {
        gid,
        src: ia,
        dst: ic,
        epoch: epoch + 1,
    };
    a.eng.send_raw(
        &proto::seal_group(&[7; 32], proto::grp::DATA, &h, 1, b"x"),
        c.addr(),
    );
    wait_until("ответ GET_GROUP придержан", T, || {
        proxy_c.held() == 2
    });
    assert_eq!(
        c.eng.groups.lock().unwrap()[&gid].rev,
        c_rev,
        "ревизия C не должна была сдвинуться"
    );

    a.eng.cmds.send(Cmd::Kick(gid, c.eng.my_pub)).unwrap();
    c.wait("C кикнут", T, |e| matches!(e, Event::Kicked { .. }));
    let mark = c.seen.len();
    proxy_c.release();
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !c.has_group(gid),
        "запоздавшее состояние вернуло группу кикнутому"
    );
    assert!(
        !c.saw_since(mark, |e| matches!(e, Event::GroupJoined { .. })),
        "{:?}",
        &c.seen[mark..]
    );

    drop((a, c));
    drop(proxy_c);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_потерянный_presence_повторяется_до_подтверждения() {
    let dir = temp_dir("presence-loss");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let gid = a.create("game", false);

    // Первые два PRESENCE теряются по дороге к серверу, первый PRESENCE_ACK —
    // по дороге к клиенту.
    let mut acks = 0;
    let proxy = LossyProxy::start(
        local(server.addr),
        Box::new(move |to_server, typ, sent| {
            if to_server {
                return typ == ctrl::PRESENCE && sent[&typ] <= 2;
            }
            if typ == ctrl::PRESENCE_ACK {
                acks += 1;
                return acks == 1;
            }
            false
        }),
    );
    let mut b = Node::start_via(
        "bravo",
        proxy.addr,
        server.pubkey,
        proto::Identity::generate(),
    );
    b.wait("B подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    b.join(gid);
    wait_until("A видит B онлайн", T, || a.sees_online(gid, 1));

    b.eng.cmds.send(Cmd::SetInvisible(true)).unwrap();
    wait_until("A видит невидимку B офлайн", T, || {
        let g = a.eng.groups.lock().unwrap();
        g.get(&gid)
            .is_some_and(|gs| gs.members.len() == 1 && gs.members.values().all(|p| !p.online))
    });
    // Два потерянных + дошедший (его ACK потерян) + подтверждённый; дальше
    // подтверждённое не повторяется.
    wait_until("B получил подтверждение", T, || {
        proxy.sent(ctrl::PRESENCE) >= 4
    });
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(
        proxy.sent(ctrl::PRESENCE),
        4,
        "повторы только до PRESENCE_ACK"
    );

    b.eng.cmds.send(Cmd::SetInvisible(false)).unwrap();
    wait_until("A снова видит B онлайн", T, || {
        a.sees_online(gid, 1)
    });

    drop(a);
    drop(b);
    drop(proxy);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Управляющие фреймы сервера клиенту типа `typ`, прошедшие посредника.
fn from_server(p: &LossyProxy, typ: u8) -> usize {
    p.tap
        .lock()
        .unwrap()
        .iter()
        .filter(|(to_server, d)| !*to_server && proto::split_frame(d).is_ok_and(|(t, _)| t == typ))
        .count()
}

#[test]
fn e2e_переименование_и_передача_дельтой_kind3_удаление_без_сверки_ревизии() {
    let dir = temp_dir("meta-delta");
    let server = start_server(&dir, 0);
    let proxy = LossyProxy::start(local(server.addr), Box::new(|_, _, _| false));
    let mut a = Node::start("alpha", &server);
    let mut b = Node::start_via(
        "bravo",
        proxy.addr,
        server.pubkey,
        proto::Identity::generate(),
    );
    let mut c = Node::start("charlie", &server);
    for n in [&mut a, &mut b, &mut c] {
        n.wait("подключён", T, |e| {
            matches!(e, Event::Connected(_))
        });
    }
    let gid = a.create("old-name", false);
    b.join(gid);
    c.join(gid);
    wait_until("все видят всех", T, || {
        a.sees_online(gid, 2) && b.sees_online(gid, 2) && c.sees_online(gid, 2)
    });
    let rev = |n: &Node| n.eng.groups.lock().unwrap().get(&gid).map(|g| g.rev);
    let name = |n: &Node| {
        n.eng
            .groups
            .lock()
            .unwrap()
            .get(&gid)
            .map(|g| g.name.clone())
    };
    wait_until("ревизия у всех одна", T, || {
        rev(&a) == rev(&b) && rev(&b) == rev(&c)
    });
    std::thread::sleep(Duration::from_millis(300));
    let states0 = from_server(&proxy, ctrl::GROUP_STATE);
    assert!(
        states0 > 0,
        "посредник не видит GROUP_STATE входа — проверка ниже пуста"
    );
    let gets0 = proxy.sent(ctrl::GET_GROUP);
    let rev0 = rev(&b).unwrap();

    // (b) RENAME — дельта kind 3: имя меняется у всех, без полного состояния.
    a.eng
        .cmds
        .send(Cmd::Rename(gid, "new-name".into()))
        .unwrap();
    wait_until("имя сменилось у всех", T, || {
        [&a, &b, &c]
            .iter()
            .all(|n| name(n).as_deref() == Some("new-name"))
    });
    assert_eq!(rev(&b), Some(rev0 + 1), "переименование — одна ревизия");
    assert_eq!(rev(&a), rev(&b));
    assert_eq!(rev(&c), rev(&b));

    // (c) TRANSFER_OWNER — дельта kind 3: новый владелец у всех.
    let c_pub = c.eng.my_pub;
    a.eng.cmds.send(Cmd::Transfer(gid, c_pub)).unwrap();
    wait_until("владелец сменился у всех", T, || {
        [&a, &b, &c].iter().all(|n| n.owner(gid) == Some(c_pub))
    });
    assert_eq!(rev(&b), Some(rev0 + 2), "передача — одна ревизия");
    assert_eq!(
        name(&b).as_deref(),
        Some("new-name"),
        "передача затёрла имя"
    );
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        from_server(&proxy, ctrl::GROUP_STATE),
        states0,
        "B получил GROUP_STATE вместо дельты"
    );
    assert_eq!(
        proxy.sent(ctrl::GET_GROUP),
        gets0,
        "B запрашивал полное состояние"
    );
    // Группа жива после дельт.
    deliver(&b, &c, gid, "after-meta", T);

    // (a) Удаление: GROUP_STATE deleted (rev 0) применяется в обход сверки
    // ревизии — у всех группа исчезает с событием GroupDeleted.
    let marks = [a.seen.len(), b.seen.len(), c.seen.len()];
    c.eng.cmds.send(Cmd::Delete(gid)).unwrap();
    for (n, mark) in [(&mut a, marks[0]), (&mut b, marks[1]), (&mut c, marks[2])] {
        n.wait("группа удалена", T, |e| {
            matches!(e, Event::GroupDeleted { gid: g, name } if *g == gid && name == "new-name")
        });
        assert!(!n.has_group(gid), "группа осталась после удаления");
        assert!(!n.saw_since(
            mark,
            |e| matches!(e, Event::GroupJoined { gid: g, .. } if *g == gid)
        ));
    }
    std::thread::sleep(Duration::from_millis(500));
    for n in [&a, &b, &c] {
        assert!(!n.has_group(gid), "группа вернулась после удаления");
    }

    drop((a, b, c));
    drop(proxy);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// DNS-запрос (A) к встроенному DNS 100.66.0.53:53 от `src`.
fn dns_query(src: u32, id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes()); // A
    q.extend_from_slice(&1u16.to_be_bytes()); // IN
    let mut udp = Vec::new();
    udp.extend_from_slice(&40000u16.to_be_bytes());
    udp.extend_from_slice(&53u16.to_be_bytes());
    udp.extend_from_slice(&((8 + q.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(&q);
    ipv4(src, u32::from(crate::dns::DNS_ADDR), &udp)
}

/// Ответ встроенного DNS с ID `id` среди вброшенных в TUN.
fn dns_answer(n: &Node, id: u16) -> Option<Vec<u8>> {
    let inj = n.tun.injected.lock().unwrap();
    inj.iter()
        .find(|p| {
            p.len() >= 30
                && p[12..16] == crate::dns::DNS_ADDR.octets()
                && p[28..30] == id.to_be_bytes()
        })
        .cloned()
}

/// Минимальный IPv6-пакет (UDP, без контрольной суммы — TUN её не проверяет).
fn ipv6_pkt(src: std::net::Ipv6Addr, dst: std::net::Ipv6Addr, data: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(data.len() as u16).to_be_bytes());
    p[6] = 17;
    p[7] = 64;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p.extend_from_slice(data);
    p
}

#[test]
fn e2e_dns_имена_участников_и_ipv6_оверлей() {
    let dir = temp_dir("dns6");
    let server = start_server(&dir, 0);
    let mut a = Node::start("Alpha", &server);
    let mut b = Node::start("Bravo Two", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    b.wait("B подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let gid = a.create("Game Room", false);
    b.join(gid);
    a.wait("A видит B онлайн", T, |e| {
        matches!(e, Event::PeerOnline { .. })
    });
    let (ia, ib) = (a.my_ip(gid), b.my_ip(gid));

    // DNS: ответ вброшен в TUN самого A, в туннель не уходит.
    for (id, name, want) in [
        (1u16, "bravo-two.vl", Some(ib)),
        (2, "BRAVO-TWO.game-room.vl", Some(ib)),
        (3, "alpha.vl", Some(ia)),
        (4, "bravo-two.other.vl", None),
    ] {
        a.eng.send_ip_packet(&dns_query(ia, id, name));
        let r = dns_answer(&a, id).unwrap_or_else(|| panic!("{name}: нет ответа DNS"));
        assert_eq!(r[16..20], ia.to_be_bytes(), "ответ — запросившему");
        let ancount = u16::from_be_bytes([r[34], r[35]]);
        match want {
            Some(ip) => {
                assert_eq!(ancount, 1, "{name}: одна A-запись");
                assert_eq!(r[r.len() - 4..], ip.to_be_bytes(), "{name}: адрес");
            }
            None => assert_eq!((ancount, r[31] & 0x0f), (0, 3), "{name}: NXDOMAIN"),
        }
    }

    // IPv6 оверлея A → B доходит до TUN B.
    let (a6, b6) = (
        crate::ipv6::v6_of(ia).unwrap(),
        crate::ipv6::v6_of(ib).unwrap(),
    );
    let pkt = ipv6_pkt(a6, b6, b"hello6");
    wait_until("IPv6 A→B", T, || {
        a.eng.send_ip_packet(&pkt);
        std::thread::sleep(Duration::from_millis(50));
        b.got(&pkt) > 0
    });
    // Подделанный IPv6-источник (чужой хост группы) и источник вне
    // префикса отбрасываются у B (раздел 7, п. 6).
    let fake = ipv6_pkt(crate::ipv6::v6_of(ia ^ 0x80).unwrap(), b6, b"spoof6");
    let alien = ipv6_pkt("fe80::1".parse().unwrap(), b6, b"alien6");
    for _ in 0..5 {
        a.eng.send_ip_packet(&fake);
        a.eng.send_ip_packet(&alien);
    }
    let marker = ipv6_pkt(a6, b6, b"marker6");
    wait_until("IPv6 маркер", T, || {
        a.eng.send_ip_packet(&marker);
        std::thread::sleep(Duration::from_millis(50));
        b.got(&marker) > 0
    });
    assert_eq!(
        (b.got(&fake), b.got(&alien)),
        (0, 0),
        "подделки IPv6 не доставлены"
    );
    assert!(
        !b.tun
            .injected
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.len() > 16 && p[12..16] == crate::dns::DNS_ADDR.octets()),
        "DNS-запросы A не уходят пирам"
    );

    drop((a, b));
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Сервер, «видимый» клиенту только по TCP: на порту — TCP-слушатель и
/// UDP-сокет, который всё глотает (сеть режет UDP). Каждое TCP-соединение
/// мостится в свой UDP-сокет к настоящему серверу (рамка `u16 LE` + кадр).
struct TcpOnlyBridge {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    _udp_hole: UdpSocket,
}

impl TcpOnlyBridge {
    fn start(server: SocketAddr) -> TcpOnlyBridge {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let (listener, hole) = loop {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            if let Ok(u) = UdpSocket::bind(l.local_addr().unwrap()) {
                break (l, u);
            }
        };
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let st = stop.clone();
        std::thread::spawn(move || {
            while !st.load(Ordering::Relaxed) {
                let Ok((tcp, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                };
                tcp.set_nonblocking(false).unwrap();
                let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
                udp.set_read_timeout(Some(Duration::from_millis(200)))
                    .unwrap();
                // TCP → сервер.
                let (mut rd, u1, s1) = (tcp.try_clone().unwrap(), udp.clone(), st.clone());
                std::thread::spawn(move || {
                    let mut hdr = [0u8; 2];
                    while !s1.load(Ordering::Relaxed) && rd.read_exact(&mut hdr).is_ok() {
                        let mut f = vec![0u8; u16::from_le_bytes(hdr) as usize];
                        if rd.read_exact(&mut f).is_err() {
                            break;
                        }
                        let _ = u1.send_to(&f, server);
                    }
                });
                // Сервер → TCP.
                let (mut wr, s2) = (tcp, st.clone());
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 65_535];
                    while !s2.load(Ordering::Relaxed) {
                        let Ok((n, src)) = udp.recv_from(&mut buf) else {
                            continue;
                        };
                        if src != server {
                            continue;
                        }
                        let mut out = (n as u16).to_le_bytes().to_vec();
                        out.extend_from_slice(&buf[..n]);
                        if wr.write_all(&out).is_err() {
                            break;
                        }
                    }
                    let _ = wr.shutdown(std::net::Shutdown::Both);
                });
            }
        });
        TcpOnlyBridge {
            addr,
            stop,
            _udp_hole: hole,
        }
    }
}

impl Drop for TcpOnlyBridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[test]
fn e2e_udp_заблокирован_движок_уходит_на_tcp() {
    let dir = temp_dir("tcp-fallback");
    let server = start_server(&dir, 0);
    let bridge = TcpOnlyBridge::start(local(server.addr));

    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    assert_eq!(a.eng.meta.lock().unwrap().transport, engine::Transport::Udp);

    // B видит сервер только по TCP: auto — несколько HELLO3 по UDP, потом TCP.
    let cfg = Config {
        name: "bravo".into(),
        ..Config::default()
    };
    let mut b = Node::start_cfg(
        cfg,
        bridge.addr,
        server.pubkey,
        proto::Identity::generate(),
        Arc::new(|_| {}),
    )
    .expect("B подключается по TCP");
    assert_eq!(b.eng.meta.lock().unwrap().transport, engine::Transport::Tcp);

    let gid = a.create("tcp", false);
    b.join(gid);
    wait_until(
        "оба видят друг друга онлайн",
        T,
        || a.sees_online(gid, 1) && b.sees_online(gid, 1),
    );
    deliver(&a, &b, gid, "a-to-b", T);
    deliver(&b, &a, gid, "b-to-a", T);

    // Режим tcp: сразу по TCP, без попыток по UDP.
    let cfg = Config {
        name: "charlie".into(),
        transport: crate::store::TransportMode::Tcp,
        ..Config::default()
    };
    let t0 = Instant::now();
    let c = Node::start_cfg(
        cfg,
        bridge.addr,
        server.pubkey,
        proto::Identity::generate(),
        Arc::new(|_| {}),
    )
    .expect("C подключается по TCP");
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "режим tcp не ждёт UDP"
    );
    assert_eq!(c.eng.meta.lock().unwrap().transport, engine::Transport::Tcp);

    // CLI-соединение: тот же фолбэк.
    let cli = engine::CtrlConn::connect(
        &Config {
            name: "delta".into(),
            ..Config::default()
        },
        bridge.addr,
        &server.pubkey,
        &proto::Identity::generate(),
    )
    .expect("CtrlConn по TCP");
    assert!(cli.via_tcp());
    cli.send_ctrl(ctrl::CTRL_PING, &[]);
    cli.wait_for(ctrl::CTRL_PONG, T).expect("PONG по TCP");
    drop(b);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Протокол v4: адрес участника один на все группы. Сценарий тестировщика:
/// двое в двух общих группах, трафик идёт через первую; выход из неё не
/// рвёт связь — пакеты на тот же адрес идут через вторую (приватная группа
/// или публичная — для адресов не важно). Раньше у участника в каждой
/// группе был свой адрес `100.66.<gid>.x`, и адрес покинутой группы
/// становился мёртвым.
#[test]
fn e2e_адрес_один_на_все_группы_выход_из_одной_не_рвёт_связь() {
    let dir = temp_dir("peruserip");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    let mut b = Node::start("bravo", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    b.wait("B подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });

    let first = a.create("first", false);
    let second = a.create("second", false);
    b.join(first);
    b.join(second);
    wait_until("A видит B в обеих группах", T, || {
        a.sees_online(first, 1) && a.sees_online(second, 1)
    });
    wait_until("B видит A в обеих группах", T, || {
        b.sees_online(first, 1) && b.sees_online(second, 1)
    });
    let (ip_a, ip_b) = (a.my_ip(first), b.my_ip(first));
    assert_eq!(a.my_ip(second), ip_a, "у A один адрес");
    assert_eq!(b.my_ip(second), ip_b, "у B один адрес");
    assert_ne!(ip_a, ip_b);
    assert_eq!(
        *a.tun.addrs.lock().unwrap(),
        HashSet::from([ip_a]),
        "на адаптере один адрес"
    );

    deliver(&a, &b, first, "A→B до выхода", T);
    deliver(&b, &a, first, "B→A до выхода", T);

    // B выходит из первой: адреса те же, связь — через вторую.
    b.eng.cmds.send(Cmd::Leave(first)).unwrap();
    b.wait(
        "B вышел из первой",
        T,
        |e| matches!(e, Event::GroupLeft { gid, .. } if *gid == first),
    );
    wait_until("A видит выход B", T, || a.members(first) == 0);
    assert_eq!(b.my_ip(second), ip_b);
    deliver(&a, &b, second, "A→B после выхода", T);
    deliver(&b, &a, second, "B→A после выхода", T);

    // Повторный вход — тот же адрес.
    std::thread::sleep(Duration::from_millis(3100));
    b.join(first);
    assert_eq!(b.my_ip(first), ip_b, "адрес закреплён за identity");
    drop(a);
    drop(b);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------- T4b2: федерация клиента (E2E 4) ----------

/// E2E 4: два настоящих сервера в процессе, федерация включена. S1 создаёт
/// группу на A — T4b1 назначает ей uuid и реплицирует B; S2 видит её в
/// `FED_GROUPS` и входит по `JOIN_FED` (B заявляет адрес S2 владельцу, тот
/// добавляет его и присылает новое состояние). Пакет S1→S2 идёт A →
/// `FED_RELAY` → B → TunDev получателя. `server.json` обоих серверов
/// (uuid/gid/peer) переживает рестарт B.
#[test]
fn e2e_федерация_репликация_join_fed_и_релей_до_tun() {
    let dir_a = temp_dir("fed-a");
    let dir_b = temp_dir("fed-b");
    let a = start_fed_server(&dir_a, 0, None);
    let b = start_fed_server(&dir_b, 0, None);
    let (a_pub, b_pub) = (a.pubkey, b.pubkey);
    let (a_addr, b_addr) = (local(a.addr), local(b.addr));
    // client.json.servers — источник SERVER_HINT: клиенты знают оба сервера,
    // и A/B знакомятся без --peer (сервер подсказке не доверяет: SRV_HELLO).
    let servers = stored_servers(&[(a_addr, a_pub, "A"), (b_addr, b_pub, "B")]);
    let save: Arc<dyn Fn(&Config) + Send + Sync> = Arc::new(|_| {});
    let mut s1 = Node::start_cfg(
        Config {
            name: "s1".into(),
            servers,
            ..Config::default()
        },
        a_addr,
        a_pub,
        proto::Identity::generate(),
        save.clone(),
    )
    .expect("S1 подключается");
    let mut s2 = Node::start_cfg(
        Config {
            name: "s2".into(),
            // S2 сам не подсказывает B о A: знакомство серверов — по одной
            // подсказке S1. Взаимные подсказки в один момент дают
            // встречные SRV_HELLO (гонка рукопожатий на сервере, не T4b2).
            ..Config::default()
        },
        b_addr,
        b_pub,
        proto::Identity::generate(),
        save,
    )
    .expect("S2 подключается");
    s1.wait("S1 подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    s2.wait("S2 подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });

    // Своя группа на A: сервер (--federate) даёт ей uuid и реплицирует B.
    let gid1 = s1.create("fed", false);
    let ev = s2.wait(
        "FED_GROUPS на B",
        T,
        |e| matches!(e, Event::FedGroups { groups } if groups.iter().any(|g| g.name == "fed")),
    );
    let fed = match ev {
        Event::FedGroups { groups } => groups.into_iter().find(|g| g.name == "fed").unwrap(),
        _ => unreachable!(),
    };
    assert_ne!(fed.uuid, [0u8; 16], "T4b1: uuid федерации не назначен");
    assert_eq!(fed.owner, s1.eng.my_pub, "владелец группы — S1");
    assert_eq!(fed.members, 1, "в реплике только владелец: {fed:?}");
    let gid2 = fed.gid;
    let uuid_hex = proto::hex_of(&fed.uuid);

    // server.json A: uuid своей группы, локальный gid и origin = сам A.
    wait_until("A записал uuid группы", T, || {
        fed_group_record(&json_file(&dir_a.join("server.json")), &uuid_hex).is_some()
    });
    let ja = json_file(&dir_a.join("server.json"));
    assert_eq!(
        fed_group_record(&ja, &uuid_hex),
        Some((gid1, proto::hex_of(&a_pub))),
        "gid/origin своей группы в server.json A"
    );
    assert!(
        fed_peer_eds(&ja).contains(&proto::hex_of(&b_pub)),
        "A не закрепил B по подсказке: {ja}"
    );

    // S2 входит по uuid: ответ — обычный GROUP_STATE с локальным gid B.
    s2.eng.cmds.send(Cmd::JoinFed { uuid: fed.uuid }).unwrap();
    s2.wait(
        "S2 вошёл в федеративную группу",
        T,
        |e| matches!(e, Event::GroupJoined { gid, name, .. } if *gid == gid2 && name == "fed"),
    );
    assert_eq!(
        s2.fed_uuid(gid2),
        Some(fed.uuid),
        "у группы нет метки федерации"
    );
    assert!(
        s2.fed_list()
            .iter()
            .any(|f| f.uuid == fed.uuid && f.gid == gid2),
        "нет доступной федеративной группы в снимке: {:?}",
        s2.fed_list()
    );
    assert_eq!(s2.members(gid2), 1, "в группе на B только S2");
    let s2_ip = s2.my_ip(gid2);
    assert_ne!(s2_ip, 0, "B не выдал адрес вошедшему");

    // Заявка ушла владельцу (A) и принята: S1 видит S2 с тем же адресом.
    wait_until("S1 видит S2 в группе", T, || {
        s1.members(gid1) == 1 && s1.member_ip(gid1, &s2.eng.my_pub) == Some(s2_ip)
    });
    assert_eq!(s1.fed_uuid(gid1), None, "своя группа S1 — не реплика");

    // Пакет S1→S2: получателя нет на A, кадр уходит FED_RELAY серверу B,
    // оттуда — в TunDev S2. И обратно.
    deliver_across(&s1, gid1, &s2, gid2, "S1→S2 через федерацию", T);
    deliver_across(&s2, gid2, &s1, gid1, "S2→S1 через федерацию", T);

    // server.json B: реплика с uuid, локальным gid B и origin = A.
    wait_until("B записал реплику", T, || {
        fed_group_record(&json_file(&dir_b.join("server.json")), &uuid_hex)
            == Some((gid2, proto::hex_of(&a_pub)))
    });
    let jb = json_file(&dir_b.join("server.json"));
    assert!(
        fed_peer_eds(&jb).contains(&proto::hex_of(&a_pub)),
        "B не закрепил A (TOFU): {jb}"
    );

    // Рестарт B: identity, реплика (uuid/gid) и пин A — в server.json и
    // возвращаются серверу. Новый клиент видит ту же запись сразу.
    let port_b = b.addr.port();
    b.stop();
    let b2 = start_fed_server(&dir_b, port_b, None);
    assert_eq!(b2.pubkey, b_pub, "identity сервера пережила рестарт");
    // Новый клиент B — без старых сессий: список доступных групп приходит из
    // server.json (uuid/gid реплики не пересозданы).
    let mut s3 = Node::start_cfg(
        Config {
            name: "s3".into(),
            ..Config::default()
        },
        local(b2.addr),
        b2.pubkey,
        proto::Identity::generate(),
        Arc::new(|_| {}),
    )
    .expect("S3 подключается");
    let ev = s3.wait(
        "FED_GROUPS после рестарта B",
        T,
        |e| matches!(e, Event::FedGroups { groups } if groups.iter().any(|g| g.uuid == fed.uuid)),
    );
    match ev {
        Event::FedGroups { groups } => {
            let g = groups.iter().find(|g| g.uuid == fed.uuid).unwrap();
            assert_eq!(g.gid, gid2, "локальный gid изменился после рестарта");
            assert_eq!(g.name, "fed");
        }
        _ => unreachable!(),
    }
    let jb2 = json_file(&dir_b.join("server.json"));
    assert_eq!(
        fed_group_record(&jb2, &uuid_hex),
        Some((gid2, proto::hex_of(&a_pub))),
        "uuid/gid/origin реплики не пережили рестарт"
    );
    assert!(
        fed_peer_eds(&jb2).contains(&proto::hex_of(&a_pub)),
        "пин A не пережил рестарт: {jb2}"
    );

    drop(s1);
    drop(s2);
    drop(s3);
    drop(b2);
    a.stop();
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// E2E 4, негатив: ложные кандидаты в `SERVER_HINT` (нерабочий адрес и
/// чужой ed-ключ) сервер отклоняет — метрика
/// `voidlink_fed_hint_rejected_total`, пин не появляется. Подсказка при этом
/// не спамится: одна отправка, дальше пауза 5 минут (в тесте — окно
/// наблюдения).
#[test]
fn e2e_ложные_подсказки_федерации_отклоняются_и_не_спамят() {
    let dir_a = temp_dir("fed-neg-a");
    let dir_b = temp_dir("fed-neg-b");
    let a = start_fed_server(&dir_a, 0, Some("127.0.0.1:0".parse().unwrap()));
    let metrics_addr = a.metrics_addr.expect("метрики включены");
    let b = start_fed_server(&dir_b, 0, None);
    let b_addr = local(b.addr);
    let a_pub = a.pubkey;
    // Посредник считает управляющие фреймы клиента (тип открыт).
    let proxy = LossyProxy::start(local(a.addr), Box::new(|_, _, _| false));
    let bogus = proto::Identity::generate().ed_pub();
    let servers = stored_servers(&[
        // Адрес, который сервер не имеет права принимать (нулевой).
        ("0.0.0.0:5555".parse().unwrap(), [9u8; 32], "ложный адрес"),
        // Живой сервер B, но с чужим ed-ключом: SRV_HELLO_ACK не сойдётся.
        (b_addr, bogus, "ложный ключ"),
    ]);
    let mut s = Node::start_cfg(
        Config {
            name: "neg".into(),
            servers,
            ..Config::default()
        },
        proxy.addr,
        a_pub,
        proto::Identity::generate(),
        Arc::new(|_| {}),
    )
    .expect("клиент подключается");
    s.wait("клиент подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });

    // Подсказка уходит один раз (сразу после WELCOME) и больше не повторяется.
    wait_until("SERVER_HINT отправлен", T, || {
        proxy.sent(ctrl::SERVER_HINT) == 1
    });
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        proxy.sent(ctrl::SERVER_HINT),
        1,
        "SERVER_HINT спамится чаще, чем раз в 5 минут"
    );

    // Оба кандидата отвергнуты: нулевой адрес — сразу, живой с чужим
    // ключом — по ответу SRV_HELLO_ACK. Счётчик отказа растёт, пин не
    // появляется (voidlink_fed_peers = 0).
    wait_until(
        "метрика отклонённых подсказок",
        T,
        || {
            metric_value(
                &metrics_text(metrics_addr),
                "voidlink_fed_hint_rejected_total",
            ) > 0
        },
    );
    let text = metrics_text(metrics_addr);
    assert_eq!(
        metric_value(&text, "voidlink_fed_peers"),
        0,
        "ложный ключ закреплён:\n{text}"
    );

    drop(s);
    drop(proxy);
    b.stop();
    a.stop();
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

// ---------- T4c: встречные SRV_HELLO (тай-брейк федерации) ----------

/// UDP-концентратор федерации для теста гонки: оба сервера видят друг друга
/// по одному адресу посредника (как за NAT). Первые `SRV_HELLO` с каждой
/// стороны придерживаются до [`FedHub::release`] — обе стороны гарантированно
/// получают встречный HELLO уже со своей ожидающей попыткой (настоящая гонка,
/// а не односторонняя подсказка). Всё остальное пересылается сразу.
struct FedHub {
    addr: SocketAddr,
    hellos: Arc<AtomicUsize>,
    held_src: Arc<Mutex<HashSet<SocketAddr>>>,
    release: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FedHub {
    fn start() -> FedHub {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let addr = sock.local_addr().unwrap();
        let hellos = Arc::new(AtomicUsize::new(0));
        let held_src: Arc<Mutex<HashSet<SocketAddr>>> = Arc::default();
        let release = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (h2, hsrc2) = (hellos.clone(), held_src.clone());
        let (rel2, st2) = (release.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            let mut peers: Vec<SocketAddr> = Vec::new();
            let mut held: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
            let mut buf = vec![0u8; 65_535];
            while !st2.load(Ordering::Relaxed) {
                // Отпускание: отложенные HELLO уходят второму участнику.
                if rel2.load(Ordering::Relaxed) && !held.is_empty() {
                    for (src, frame) in held.drain(..) {
                        if let Some(dst) = peers.iter().find(|p| **p != src).copied() {
                            let _ = sock.send_to(&frame, dst);
                        }
                    }
                    hsrc2.lock().unwrap().clear();
                }
                let Ok((n, src)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                if peers.len() < 2 && !peers.contains(&src) {
                    peers.push(src);
                }
                let frame = &buf[..n];
                let typ = proto::split_frame(frame).map(|(t, _)| t).unwrap_or(0);
                if typ == proto::federation::SRV_HELLO {
                    h2.fetch_add(1, Ordering::Relaxed);
                    if !rel2.load(Ordering::Relaxed) {
                        hsrc2.lock().unwrap().insert(src);
                        held.push((src, frame.to_vec()));
                        continue;
                    }
                }
                if let Some(dst) = peers.iter().find(|p| **p != src).copied() {
                    let _ = sock.send_to(frame, dst);
                }
            }
        });
        FedHub {
            addr,
            hellos,
            held_src,
            release,
            stop,
            thread: Some(thread),
        }
    }

    /// Сколько разных серверов уже прислали HELLO (придержанный).
    fn held(&self) -> usize {
        self.held_src.lock().unwrap().len()
    }

    /// Всего `SRV_HELLO`, прошедших через посредника (включая придержанные).
    fn hellos(&self) -> usize {
        self.hellos.load(Ordering::Relaxed)
    }

    fn release(&self) {
        self.release.store(true, Ordering::Relaxed);
    }
}

impl Drop for FedHub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// E2E 4/T4c: у каждого сервера свой клиент, и оба клиента знают **оба**
/// сервера — серверы одновременно получают взаимные `SERVER_HINT` и шлют
/// встречные `SRV_HELLO`. Посредник придерживает оба HELLO, поэтому гонка
/// детерминирована. Тай-брейк T4c (меньший ed — инициатор) обязан свести
/// стороны на одной сессии: группа реплицируется, `JOIN_FED` работает и
/// пакет S1→S2 доходит до TunDev за < 5 с. Повторная подсказка (второй
/// клиент A) не создаёт новых `SRV_HELLO` и не ломает доставку.
#[test]
fn e2e_встречные_подсказки_федерации_не_ломают_репликацию() {
    let dir_a = temp_dir("fed-race-a");
    let dir_b = temp_dir("fed-race-b");
    let a = start_fed_server(&dir_a, 0, Some("127.0.0.1:0".parse().unwrap()));
    let b = start_fed_server(&dir_b, 0, Some("127.0.0.1:0".parse().unwrap()));
    let metrics_a = a.metrics_addr.expect("метрики A включены");
    let metrics_b = b.metrics_addr.expect("метрики B включены");
    let (a_pub, b_pub) = (a.pubkey, b.pubkey);
    let (a_addr, b_addr) = (local(a.addr), local(b.addr));
    // Оба сервера видны клиентам по адресу посредника: HELLO идут через
    // него, и он может придержать их до одновременного получения.
    let hub = FedHub::start();
    let hub_addr = hub.addr;
    let save: Arc<dyn Fn(&Config) + Send + Sync> = Arc::new(|_| {});
    let mut s1 = Node::start_cfg(
        Config {
            name: "s1".into(),
            servers: stored_servers(&[(a_addr, a_pub, "A"), (hub_addr, b_pub, "B")]),
            ..Config::default()
        },
        a_addr,
        a_pub,
        proto::Identity::generate(),
        save.clone(),
    )
    .expect("S1 подключается");
    let mut s2 = Node::start_cfg(
        Config {
            name: "s2".into(),
            servers: stored_servers(&[(b_addr, b_pub, "B"), (hub_addr, a_pub, "A")]),
            ..Config::default()
        },
        b_addr,
        b_pub,
        proto::Identity::generate(),
        save,
    )
    .expect("S2 подключается");
    s1.wait("S1 подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    s2.wait("S2 подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });

    // Оба сервера отправили HELLO и обе попытки придержаны — это гонка.
    wait_until("встречные SRV_HELLO придержаны", T, || hub.held() >= 2);
    hub.release();
    wait_until("федеративная сессия на A", T, || {
        metric_value(&metrics_text(metrics_a), "voidlink_fed_peers") == 1
    });
    wait_until("федеративная сессия на B", T, || {
        metric_value(&metrics_text(metrics_b), "voidlink_fed_peers") == 1
    });

    // Своя группа на A реплицируется B (сессия одна, ключи совпали).
    let gid1 = s1.create("fed-race", false);
    let ev = s2.wait(
        "FED_GROUPS на B",
        T,
        |e| matches!(e, Event::FedGroups { groups } if groups.iter().any(|g| g.name == "fed-race")),
    );
    let fed = match ev {
        Event::FedGroups { groups } => groups.into_iter().find(|g| g.name == "fed-race").unwrap(),
        _ => unreachable!(),
    };
    assert_ne!(fed.uuid, [0u8; 16], "uuid федерации не назначен");
    let gid2 = fed.gid;

    // S2 входит по uuid — ответ обычный GROUP_STATE.
    s2.eng.cmds.send(Cmd::JoinFed { uuid: fed.uuid }).unwrap();
    s2.wait(
        "S2 вошёл в федеративную группу",
        T,
        |e| matches!(e, Event::GroupJoined { gid, name, .. } if *gid == gid2 && name == "fed-race"),
    );
    wait_until("S1 видит S2 в группе", T, || {
        s1.members(gid1) == 1 && s1.member_ip(gid1, &s2.eng.my_pub).is_some()
    });

    // < 5 с — дольше висело бы расхождение ключей (FED_TIMEOUT = 30 с).
    let took = deliver_across(
        &s1,
        gid1,
        &s2,
        gid2,
        "S1→S2 после встречных hint",
        Duration::from_secs(5),
    );
    assert!(
        took < Duration::from_secs(5),
        "пакет S1→S2 дошёл за {took:?} — федерация зависла?"
    );
    deliver_across(
        &s2,
        gid2,
        &s1,
        gid1,
        "S2→S1 после встречных hint",
        Duration::from_secs(5),
    );

    // Повторная подсказка: второй клиент A со списком серверов. Сессия уже
    // установлена, поэтому SRV_HELLO не шлётся и доставка не ломается.
    let hellos_before = hub.hellos();
    let mut s3 = Node::start_cfg(
        Config {
            name: "s3".into(),
            servers: stored_servers(&[(a_addr, a_pub, "A"), (hub_addr, b_pub, "B")]),
            ..Config::default()
        },
        a_addr,
        a_pub,
        proto::Identity::generate(),
        Arc::new(|_| {}),
    )
    .expect("S3 подключается");
    s3.wait("S3 подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    std::thread::sleep(Duration::from_millis(800));
    assert_eq!(
        hub.hellos(),
        hellos_before,
        "повторная подсказка породила новый SRV_HELLO"
    );
    assert_eq!(
        metric_value(&metrics_text(metrics_a), "voidlink_fed_peers"),
        1,
        "пиры A изменились после повторной подсказки"
    );
    deliver_across(
        &s1,
        gid1,
        &s2,
        gid2,
        "S1→S2 после повторной подсказки",
        Duration::from_secs(5),
    );

    drop(s1);
    drop(s2);
    drop(s3);
    drop(hub);
    a.stop();
    b.stop();
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

// ---------- #21: аренда адреса с TTL ----------

#[test]
fn e2e_новая_identity_занимает_адрес_исчезнувшей() {
    // Удалённый профиль пересоздаётся с новым ключом — прежняя identity не
    // вернётся. Её аренда адреса без активности истекает (`--lease-ttl-days`),
    // identity выселяется из групп как по LEAVE, адрес возвращается в пул.
    let dir = temp_dir("lease");
    let limits = tunnel_server::Limits {
        lease_ttl: Duration::from_secs(3),
        // По умолчанию аренды проверяются раз в минуту — в тесте на каждом
        // проходе housekeeping (раз в 2 с).
        lease_gc_every: Duration::from_millis(10),
        // Сессия брошенного клиента — офлайн по таймауту, а не через 30 с.
        session_timeout: Duration::from_secs(1),
        ..Default::default()
    };
    // Метрики — авторитетный счётчик аренд: `server.json` пишется раз в 3 с,
    // и по нему не отличить «аренды не было» от «аренда освобождена».
    let server = tunnel_server::Server::start(tunnel_server::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.clone(),
        workers: 2,
        quiet: true,
        limits: limits.clone(),
        metrics: Some("127.0.0.1:0".parse().unwrap()),
        ..Default::default()
    })
    .expect("сервер стартует");
    let metrics = server.metrics_addr.expect("метрики включены");
    let mut a = Node::start("alpha", &server);
    a.wait("подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let gid = a.create("club", false);
    let a_ip = a.my_ip(gid);
    let a_pub = proto::hex_of(&a.eng.my_pub);
    let mut b = Node::start("bravo", &server);
    b.wait("подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    b.join(gid);
    let b_ip = b.my_ip(gid);
    let b_pub = proto::hex_of(&b.eng.my_pub);
    assert_ne!(a_ip, b_ip, "у каждой identity свой адрес");
    wait_until("обе аренды выданы", T, || {
        metric_value(&metrics_text(metrics), "voidlink_leases") == 2
    });
    drop(b); // профиль удалён: identity больше не появится

    // Освобождение: сессия — офлайн по таймауту, аренда — по TTL, проверка —
    // на проходе housekeeping. Владелец группы аренду не теряет.
    wait_until(
        "аренда исчезнувшей освобождена",
        Duration::from_secs(20),
        || metric_value(&metrics_text(metrics), "voidlink_leases") == 1,
    );
    assert!(
        metric_value(&metrics_text(metrics), "voidlink_leases_expired_total") >= 1,
        "счётчик освобождённых аренд"
    );

    // `server.json`: аренды и «призрачного» участника больше нет, владелец
    // на месте (запись — в пределах SAVE_EVERY).
    let path = dir.join("server.json");
    let state = |p: &std::path::Path| -> serde_json::Value {
        std::fs::read(p)
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or(serde_json::Value::Null)
    };
    wait_until(
        "server.json без исчезнувшей",
        Duration::from_secs(20),
        || {
            let j = state(&path);
            j["user_ips"].get(&b_pub).is_none()
                && j["lease_seen"].get(&b_pub).is_none()
                && j["user_ips"].get(&a_pub).is_some()
        },
    );
    let j = state(&path);
    let members: Vec<String> = j["groups"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|g| g["id"].as_u64() == Some(u64::from(gid)))
        .flat_map(|g| g["members"].as_array().cloned().unwrap_or_default())
        .filter_map(|m| m[0].as_str().map(str::to_string))
        .collect();
    assert!(
        !members.contains(&b_pub),
        "«призрачный» участник выселен: {members:?}"
    );
    assert!(members.contains(&a_pub), "владелец группы на месте");
    assert_eq!(j["user_ips"][&a_pub].as_u64(), Some(u64::from(a_ip)));

    // Перезапуск: указатель выдачи не персистится и начинается с начала
    // пула, поэтому освобождённый адрес достаётся новой identity.
    drop(a);
    server.stop();
    let server = start_server_with(&dir, 0, limits);
    let mut c = Node::start("charlie", &server);
    c.wait("подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    c.join(gid);
    assert_eq!(
        c.my_ip(gid),
        b_ip,
        "адрес исчезнувшей identity достался новой"
    );
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------- issue #19: права кика ----------

/// Не-владелец получает ошибку сервера, а не «успех»: состав и ключ группы
/// не меняются, доставка всем участникам работает.
#[test]
fn не_владелец_кик_получает_error_и_никого_не_выкидывает() {
    let dir = temp_dir("kick-denied");
    let server = start_server(&dir, 0);
    let (a, mut b, c, gid) = three_in_group(&server, false);
    let (epoch, c_pub) = (a.epoch(gid), c.eng.my_pub);
    b.eng.cmds.send(Cmd::Kick(gid, c_pub)).unwrap();
    b.wait(
        "B: отказ сервера",
        T,
        |e| matches!(e, Event::Error(t) if t.contains("владелец")),
    );
    // Никого не выкинуло: C в группе, эпоха и состав прежние.
    assert!(c.has_group(gid), "C выкинут отказом");
    assert_eq!(a.epoch(gid), epoch, "отказ ротировал ключ");
    assert_eq!(a.members(gid), 2, "отказ изменил состав");
    deliver(&a, &c, gid, "after-denied-kick", T);
    drop((a, b, c));
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------- issue #20: удалённые, отключённые и потерянные выходы ----------

/// Вход по gid удалённой группы: «группа не существует», группы нет.
#[test]
fn e2e_вход_по_старому_gid_после_удаления_не_пускает() {
    let dir = temp_dir("old-gid");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let gid = a.create("gone", false);
    a.eng.cmds.send(Cmd::Delete(gid)).unwrap();
    a.wait(
        "группа удалена",
        T,
        |e| matches!(e, Event::GroupDeleted { gid: g, .. } if *g == gid),
    );
    let mut b = Node::start("bravo", &server);
    b.wait("B подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    b.eng.cmds.send(Cmd::Join(gid)).unwrap();
    b.wait(
        "B: «группа не существует»",
        T,
        |e| matches!(e, Event::Error(t) if t.contains("не существует")),
    );
    assert!(!b.has_group(gid), "B вошёл по старому gid");
    drop((a, b));
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Отключение от доставки не выходит из группы: участие, ключ и состав
/// сохраняются, кадры не ходят; attach возвращает доставку.
#[test]
fn e2e_отключиться_и_подключиться_сохраняет_участие() {
    let dir = temp_dir("detach-e2e");
    let server = start_server(&dir, 0);
    let (a, b, _c, gid) = three_in_group(&server, false);
    let (epoch, members) = (a.epoch(gid), a.members(gid));
    b.eng.cmds.send(Cmd::Detach(gid)).unwrap();
    wait_until("B отключён локально", T, || {
        b.eng
            .groups
            .lock()
            .unwrap()
            .get(&gid)
            .is_some_and(|g| g.detached)
    });
    // Сервер подтвердил: своя запись в GROUP_STATE — офлайн.
    wait_until(
        "сервер подтвердил отключение",
        T,
        || {
            b.eng
                .groups
                .lock()
                .unwrap()
                .get(&gid)
                .is_some_and(|g| !g.server_online)
        },
    );
    assert!(b.has_group(gid), "отключение вышло из группы");
    assert_eq!(b.members(gid), 2, "отключение изменило состав");
    assert_eq!(a.epoch(gid), epoch, "отключение ротировало ключ");
    assert_eq!(a.members(gid), members);
    // Пакет в отключённую группу не доставляется (и через сервер, и напрямую).
    let pkt = ipv4(a.my_ip(gid), b.my_ip(gid), b"while-detached");
    for _ in 0..10 {
        a.eng.send_ip_packet(&pkt);
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(b.got(&pkt), 0, "отключённому доставлен пакет");
    // Возврат доставки.
    b.eng.cmds.send(Cmd::Attach(gid)).unwrap();
    wait_until("B подключён обратно", T, || {
        b.eng
            .groups
            .lock()
            .unwrap()
            .get(&gid)
            .is_some_and(|g| !g.detached && g.server_online)
    });
    deliver(&a, &b, gid, "after-attach", T);
    assert_eq!(b.epoch(gid), epoch, "attach ротировал ключ");
    drop((a, b));
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Клиент умер, не получив подтверждения выхода: `pending_leave` в конфиге
/// переживает рестарт, LEAVE повторяется сам, сервер снимает участие.
#[test]
fn e2e_потерянный_leave_повторяется_после_рестарта() {
    let dir = temp_dir("leave-restart");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let b_id = proto::Identity::generate();
    let b_pub = b_id.ed_pub();
    a.eng
        .cmds
        .send(Cmd::Create {
            name: "secret".into(),
            private: true,
        })
        .unwrap();
    let gid = match a.wait("A создал группу", T, |e| {
        matches!(e, Event::GroupJoined { .. })
    }) {
        Event::GroupJoined { gid, .. } => gid,
        _ => unreachable!(),
    };
    a.eng.cmds.send(Cmd::Invite(gid, b_pub)).unwrap();
    std::thread::sleep(Duration::from_millis(300));

    // Первый запуск B: вход по приглашению, затем «падение» без LEAVE.
    let mut b = Node::start_as("bravo", &server, b_id.clone());
    b.wait(
        "B: приглашение",
        T,
        |e| matches!(e, Event::Invite { gid: g, .. } if *g == gid),
    );
    b.join(gid);
    // A видит B участником: сервер принял вход.
    wait_until("A видит B в группе", T, || a.members(gid) == 1);
    drop(b); // процесс умер: LEAVE не ушёл

    // Второй запуск: в конфиге остался неподтверждённый выход.
    let saved = Arc::new(Mutex::new(Vec::new()));
    let sink = saved.clone();
    let cfg = Config {
        name: "bravo".into(),
        pending_leave: vec![gid],
        ..Config::default()
    };
    let mut b = Node::start_cfg(
        cfg,
        local(server.addr),
        server.pubkey,
        b_id,
        Arc::new(move |c: &Config| sink.lock().unwrap().push(c.clone())),
    )
    .unwrap();
    b.wait("B подключён заново", T, |e| {
        matches!(e, Event::Connected(_))
    });
    // LEAVE из pending_leave ушёл сам: сервер снял участие и разослал
    // дельту Removed — A больше B не видит.
    wait_until("LEAVE повторился: A не видит B", T, || {
        a.members(gid) == 0
    });
    wait_until("pending_leave очищен", T, || {
        saved
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.pending_leave.is_empty())
    });
    assert!(!b.has_group(gid), "B вернулся в группу вместо выхода");
    drop((a, b));
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------- друзья (issue #24) ----------

#[test]
fn e2e_заявка_в_друзья_принятие_и_взаимность() {
    let dir = temp_dir("friend-accept");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let mut b = Node::start("bravo", &server);
    b.wait("B подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let (a_pub, b_pub) = (a.eng.my_pub, b.eng.my_pub);

    // A просит дружбы: заявка уходит серверу, а не в свой конфиг.
    a.eng
        .cmds
        .send(Cmd::AddFriend {
            pubkey: b_pub,
            alias: String::new(),
        })
        .unwrap();
    // B видит заявку с ником, а не с кодом.
    b.wait("B получил заявку", T, |e| {
        matches!(e, Event::FriendRequest { pubkey, name, expires_in }
            if *pubkey == a_pub && name == "alpha" && *expires_in > 0)
    });
    // Инициатор — «ждёт ответа», цель — «пришла заявка».
    assert_eq!(
        a.friend_state(&b_pub),
        Some(crate::store::FriendState::PendingOut)
    );
    assert_eq!(
        b.friend_state(&a_pub),
        Some(crate::store::FriendState::PendingIn)
    );

    // Принятие: оба узнают, у обоих дружба. Принявший и так знает (он нажал
    // «принять») — ему событие не нужно, состояние ставится сразу.
    b.eng.cmds.send(Cmd::AcceptFriend(a_pub)).unwrap();
    a.wait("A: заявку приняли", T, |e| {
        matches!(e, Event::FriendAccepted { pubkey, name }
            if *pubkey == b_pub && name == "bravo")
    });
    assert_eq!(
        a.friend_state(&b_pub),
        Some(crate::store::FriendState::Accepted),
        "у инициатора дружба"
    );
    assert_eq!(
        b.friend_state(&a_pub),
        Some(crate::store::FriendState::Accepted),
        "у принявшего тоже — пара одна на двоих"
    );
    // Ник пришёл с сервера (кэш в client.json).
    assert_eq!(a.friend_nick(&b_pub).as_deref(), Some("bravo"));
    assert_eq!(b.friend_nick(&a_pub).as_deref(), Some("alpha"));
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_заявка_офлайн_цели_доставляется_после_hello() {
    let dir = temp_dir("friend-offline");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let a_pub = a.eng.my_pub;

    // B ещё не запущен: заявка ждёт на сервере (взаимность для офлайн-цели —
    // ради этого сервер и хранит заявки).
    let b_id = proto::Identity::generate();
    let b_pub = b_id.ed_pub();
    a.eng
        .cmds
        .send(Cmd::AddFriend {
            pubkey: b_pub,
            alias: String::new(),
        })
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));

    let mut b = Node::start_as("bravo", &server, b_id);
    b.wait("B: заявка пришла после HELLO", T, |e| {
        matches!(e, Event::FriendRequest { pubkey, name, .. }
            if *pubkey == a_pub && name == "alpha")
    });
    // B видит её в списке как входящую, а A — как исходящую.
    assert_eq!(
        b.friend_state(&a_pub),
        Some(crate::store::FriendState::PendingIn)
    );
    assert_eq!(
        a.friend_state(&b_pub),
        Some(crate::store::FriendState::PendingOut)
    );
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_отказ_в_друзья_уведомляет_инициатора() {
    let dir = temp_dir("friend-decline");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let mut b = Node::start("bravo", &server);
    b.wait("B подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let (a_pub, b_pub) = (a.eng.my_pub, b.eng.my_pub);

    a.eng
        .cmds
        .send(Cmd::AddFriend {
            pubkey: b_pub,
            alias: String::new(),
        })
        .unwrap();
    b.wait(
        "B получил заявку",
        T,
        |e| matches!(e, Event::FriendRequest { pubkey, .. } if *pubkey == a_pub),
    );
    b.eng.cmds.send(Cmd::DeclineFriend(a_pub)).unwrap();
    a.wait("A: заявку отклонили", T, |e| {
        matches!(e, Event::FriendDeclined { pubkey, name }
            if *pubkey == b_pub && name == "bravo")
    });
    // У обоих заявки больше нет, дружбы тоже.
    assert_eq!(a.friend_state(&b_pub), None);
    assert_eq!(b.friend_state(&a_pub), None);
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_удаление_друга_снимает_запись_у_обоих() {
    let dir = temp_dir("friend-remove");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let mut b = Node::start("bravo", &server);
    b.wait("B подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let (a_pub, b_pub) = (a.eng.my_pub, b.eng.my_pub);

    // Сначала дружба.
    a.eng
        .cmds
        .send(Cmd::AddFriend {
            pubkey: b_pub,
            alias: String::new(),
        })
        .unwrap();
    b.wait(
        "B получил заявку",
        T,
        |e| matches!(e, Event::FriendRequest { pubkey, .. } if *pubkey == a_pub),
    );
    b.eng.cmds.send(Cmd::AcceptFriend(a_pub)).unwrap();
    a.wait("A: дружба", T, |e| {
        matches!(e, Event::FriendAccepted { .. })
    });

    // Снимает инициатор — у второй стороны запись тоже уходит.
    a.eng.cmds.send(Cmd::RemoveFriend(b_pub)).unwrap();
    b.wait(
        "B: дружбу сняли",
        T,
        |e| matches!(e, Event::FriendRemoved { pubkey } if *pubkey == a_pub),
    );
    assert_eq!(a.friend_state(&b_pub), None);
    assert_eq!(b.friend_state(&a_pub), None);
    assert_eq!(b.friends_len(), 0);
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_заявка_себе_и_повтор_не_создают_дубликата() {
    let dir = temp_dir("friend-self");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let mut b = Node::start("bravo", &server);
    b.wait("B подключён", T, |e| {
        matches!(e, Event::Connected(_))
    });
    let (a_pub, b_pub) = (a.eng.my_pub, b.eng.my_pub);

    // Себе — отказ, записи нет.
    a.eng
        .cmds
        .send(Cmd::AddFriend {
            pubkey: a_pub,
            alias: String::new(),
        })
        .unwrap();
    a.wait(
        "A: себя нельзя",
        T,
        |e| matches!(e, Event::Error(t) if t.contains("себя")),
    );
    assert_eq!(a.friend_state(&a_pub), None);
    assert_eq!(a.friends_len(), 0);

    // Повтор заявки: заявка одна, продлевается срок. У цели второго окна
    // нет — это тот же человек, ответ на прежнее окно уже был бы.
    a.eng
        .cmds
        .send(Cmd::AddFriend {
            pubkey: b_pub,
            alias: String::new(),
        })
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(a.friends_len(), 1, "повтор не плодит записей");
    assert_eq!(
        a.friend_state(&b_pub),
        Some(crate::store::FriendState::PendingOut)
    );
    assert_eq!(a.friend_state(&a_pub), None);
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
}
