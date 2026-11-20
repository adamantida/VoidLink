//! E2E пробы сервера (этап 9, §3.7) на настоящем `tunnel-server`:
//! PROBE_REQ/PROBE_RESP открытым текстом, без сессии; RTT и сверка
//! ed-ключа сервера с закреплённым (`StoredServer.pubkey`).
//!
//! Кроссплатформенно (UDP + loopback): движок — с TUN-заглушкой.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tunnel_client::engine::{self, Cmd, Engine, Event, TunDev};
use tunnel_client::probe::{KeyMatch, ProbeState};
use tunnel_client::store::{Config, StoredServer};
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
    let d = std::env::temp_dir().join(format!("vlp-{tag}-{}-{n}", std::process::id()));
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

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn wait_probe(st: &ProbeState, timeout: Duration) -> Option<tunnel_client::probe::ProbeResult> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(r) = st.poll().into_iter().next() {
            return Some(r);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    st.poll().into_iter().next()
}

/// Проба напрямую (`ProbeState`): свой UDP-сокет, ключ сервера в ответе,
/// сверка с закреплённым — Match / Mismatch / Unknown.
#[test]
fn проба_настоящего_сервера_сверяет_ключ() {
    let d = temp_dir("s");
    let server = start_server(&d);
    let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], server.addr.port()));
    let st = ProbeState::with_timeout(Duration::from_secs(2));

    // Закреплён верный ключ — Match и RTT.
    st.start_probe(addr, Some(server.pubkey), now_ms()).unwrap();
    let r = wait_probe(&st, T).expect("проба завершилась");
    assert_eq!(r.addr, addr);
    assert!(r.available, "{r:?}");
    assert_eq!(r.key, Some(server.pubkey));
    assert_eq!(r.key_match, KeyMatch::Match);
    assert!(r.rtt_ms.is_some(), "RTT измерен");

    // Закреплён чужой ключ — сервер отвечает своим: Mismatch (предупреждение
    // «сервер отвечает чужим ключом»).
    st.start_probe(addr, Some([0xAAu8; 32]), now_ms()).unwrap();
    let r = wait_probe(&st, T).expect("проба завершилась");
    assert!(r.available);
    assert_eq!(r.key, Some(server.pubkey));
    assert_eq!(r.key_match, KeyMatch::Mismatch);
    assert_eq!(r.key_match.as_bool(), Some(false));

    // Без закреплённого ключа want_key=0: ключа в ответе нет, сверки нет.
    st.start_probe(addr, None, now_ms()).unwrap();
    let r = wait_probe(&st, T).expect("проба завершилась");
    assert!(r.available);
    assert_eq!((r.key, r.key_match), (None, KeyMatch::Unknown));

    server.stop();
    let _ = std::fs::remove_dir_all(&d);
}

/// Проба свободного локального порта: две попытки и «недоступен».
#[test]
fn проба_молчащего_порта_недоступна() {
    let sink = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sink.local_addr().unwrap();
    let st = ProbeState::with_timeout(Duration::from_millis(150));
    st.start_probe(addr, None, now_ms()).unwrap();
    let r = wait_probe(&st, T).expect("проба завершилась");
    assert_eq!(r.addr, addr);
    assert!(!r.available);
    assert_eq!(
        (r.rtt_ms, r.key, r.key_match),
        (None, None, KeyMatch::Unknown)
    );
    assert_eq!(st.pending(), 0, "ожидание снято");
}

/// Проба через движок: `Cmd::ProbeServer` не ломает сессию, результат —
/// `Event::ProbeResult` (им же пользуется TUI).
#[test]
fn движок_пробует_сервер_событием() {
    let sdir = temp_dir("s");
    let server = start_server(&sdir);
    let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], server.addr.port()));
    let dir = temp_dir("d");
    let cfg = Config {
        name: "alpha".into(),
        servers: vec![StoredServer {
            addr: addr.to_string(),
            pubkey: proto::hex_of(&server.pubkey),
            label: "дом".into(),
        }],
        ..Config::default()
    };
    let id = proto::Identity::generate();
    let save: Arc<dyn Fn(&Config) + Send + Sync> = Arc::new(|_: &Config| {});
    let eng: Engine = engine::start_with_tun(
        Arc::new(Mutex::new(cfg)),
        addr,
        server.pubkey,
        id,
        Arc::new(NullTun),
        save,
    )
    .expect("движок подключается");

    eng.cmds.send(Cmd::ProbeServer { addr }).unwrap();
    let deadline = Instant::now() + T;
    let mut got = None;
    while Instant::now() < deadline && got.is_none() {
        let left = deadline.saturating_duration_since(Instant::now());
        match eng
            .events
            .recv_timeout(left.min(Duration::from_millis(200)))
        {
            Ok(Event::ProbeResult {
                addr: a,
                success,
                rtt_ms,
                key_match,
            }) => got = Some((a, success, rtt_ms, key_match)),
            Ok(_) => {}
            Err(_) => {}
        }
    }
    let (a, success, rtt, km) = got.expect("событие пробы пришло");
    assert_eq!(a, addr);
    assert!(success, "сервер доступен");
    assert!(rtt.is_some(), "RTT в событии");
    assert_eq!(km, Some(true), "ключ сервера совпал с закреплённым");

    drop(eng);
    server.stop();
    let _ = std::fs::remove_dir_all(&sdir);
    let _ = std::fs::remove_dir_all(&dir);
}
