//! E2E-тесты движка: настоящий сервер (крейт tunnel-server) и настоящие
//! движки на localhost. TUN заменён заглушкой, поэтому права администратора
//! и Wintun не нужны.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
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
    let pkt = ipv4(from.my_ip(gid), to.my_ip(gid), tag.as_bytes());
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
