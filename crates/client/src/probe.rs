//! Проба доступности сервера (§3.7 плана этапа 9).
//!
//! `PROBE_REQ`/`PROBE_RESP` ходят **открытым текстом** и не требуют сессии:
//! пробу можно запускать для любого сервера из списка (в том числе
//! недоступного), не ломая текущую сессию. Сервер отвечает не длиннее
//! запроса и не создаёт сессию.
//!
//! У пробы **свой UDP-сокет и свой поток** ([`ProbeState`]): проба идёт с
//! эфемерного порта, не занимает сокет сессии и работает, даже когда движка
//! нет вовсе (офлайн-TUI). Форматы — `payloads::enc_probe_req/enc_probe_resp`:
//! запрос ровно 64 байта (`nonce(16) | ts_ms(8) | want_key(1) | pad`), ответ
//! 24 или 56 байт (с ed-ключом, если просили).
//!
//! Задание: отправка, ожидание до [`PROBE_TIMEOUT`], один повтор. Нет ответа
//! за две попытки — «недоступен». Результаты складываются в очередь
//! ([`ProbeState::poll`]): движок превращает их в `Event::ProbeResult`,
//! офлайн-движок — тоже (TUI не различает режимы).

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use tunnel_protocol as proto;
use tunnel_protocol::ctrl;
use tunnel_protocol::payloads::{self, PROBE_NONCE_LEN, ProbeReq};

/// Сколько ждать ответа на одну отправку.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// Всего отправок: первая и один повтор ([`PROBE_ATTEMPTS`]).
pub const PROBE_ATTEMPTS: u32 = 2;
/// Такт ожидания внутри попытки: поток проб просыпается и проверяет остановку.
const POLL: Duration = Duration::from_millis(50);
/// Размер приёмного буфера: ответ 24/56 байт, больше не бывает.
const BUF: usize = 512;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Совпадение ключа, который вернул сервер, с закреплённым в конфиге.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyMatch {
    /// Сервер вернул ровно закреплённый ключ.
    Match,
    /// Сервер ответил, но ключ другой: «сервер отвечает чужим ключом».
    Mismatch,
    /// Сверять не с чем: пин не задан, ключ не просили или сервер его не
    /// вернул.
    Unknown,
}

impl KeyMatch {
    /// Из формы события движка (`Event::ProbeResult.key_match`).
    pub fn from_bool(b: Option<bool>) -> KeyMatch {
        match b {
            Some(true) => KeyMatch::Match,
            Some(false) => KeyMatch::Mismatch,
            None => KeyMatch::Unknown,
        }
    }

    /// Форма события движка (`Event::ProbeResult.key_match`).
    pub fn as_bool(self) -> Option<bool> {
        match self {
            KeyMatch::Match => Some(true),
            KeyMatch::Mismatch => Some(false),
            KeyMatch::Unknown => None,
        }
    }

    /// Значок для TUI: ✓ / ✗ / —.
    pub fn glyph(self) -> &'static str {
        match self {
            KeyMatch::Match => "✓",
            KeyMatch::Mismatch => "✗",
            KeyMatch::Unknown => "—",
        }
    }
}

/// Результат пробы: доступен/недоступен, RTT и совпадение ключа сервера с
/// закреплённым.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeResult {
    /// Адрес, который пробовали (результат — по resolved-адресу, не по строке).
    pub addr: SocketAddr,
    /// Сервер ответил (даже если ключ не совпал).
    pub available: bool,
    /// RTT до ответа; `None` — ответа не было.
    pub rtt_ms: Option<u32>,
    /// Ключ, который вернул сервер (если просили и он вернул).
    pub key: Option<[u8; 32]>,
    /// Совпал ли ключ с закреплённым.
    pub key_match: KeyMatch,
}

/// Ожидаемая проба.
#[derive(Debug)]
struct Pending {
    /// Пробуемый адрес: результат относится к нему, даже если датаграмма
    /// пришла с другого порта (NAT).
    addr: SocketAddr,
    started: Instant,
    /// Закреплённый ключ сервера (для сверки); `None` — не закреплён.
    pinned: Option<[u8; 32]>,
}

/// Общее состояние потока проб и вызывающего.
#[derive(Debug, Default)]
struct Inner {
    pending: Mutex<HashMap<[u8; PROBE_NONCE_LEN], Pending>>,
    results: Mutex<VecDeque<ProbeResult>>,
    stop: AtomicBool,
}

impl Inner {
    /// Ответ `PROBE_RESP` от `src` (открытым текстом). `None` — не наша проба,
    /// битый или уже отвеченный ответ. Никогда не паникует: формат с сервера
    /// не доверенный.
    fn on_response(&self, src: SocketAddr, body: &[u8]) -> Option<ProbeResult> {
        let resp = payloads::dec_probe_resp(body).ok()?;
        let p = lock(&self.pending).remove(&resp.nonce)?;
        let rtt_ms = u32::try_from(p.started.elapsed().as_millis()).ok();
        let key_match = match (resp.ed_pub, p.pinned) {
            (Some(k), Some(pin)) => {
                if k == pin {
                    KeyMatch::Match
                } else {
                    KeyMatch::Mismatch
                }
            }
            _ => KeyMatch::Unknown,
        };
        let r = ProbeResult {
            addr: p.addr,
            available: true,
            rtt_ms,
            key: resp.ed_pub,
            key_match,
        };
        lock(&self.results).push_back(r);
        let _ = src;
        Some(r)
    }

    /// Ответа не было за все попытки: снять ожидание и записать «недоступен».
    fn timed_out(&self, nonce: [u8; PROBE_NONCE_LEN]) {
        let Some(p) = lock(&self.pending).remove(&nonce) else {
            return;
        };
        lock(&self.results).push_back(ProbeResult {
            addr: p.addr,
            available: false,
            rtt_ms: None,
            key: None,
            key_match: KeyMatch::Unknown,
        });
    }
}

/// Задание рабочему потоку.
struct Job {
    nonce: [u8; PROBE_NONCE_LEN],
    frame: Vec<u8>,
    addr: SocketAddr,
}

/// Пробы серверов: свой UDP-сокет в отдельном потоке. Держится под `Arc` в
/// `Env` движка или в офлайн-движке TUI.
pub struct ProbeState {
    inner: Arc<Inner>,
    jobs: Mutex<Option<Sender<Job>>>,
    timeout: Duration,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for ProbeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeState")
            .field("pending", &self.pending())
            .finish()
    }
}

impl Default for ProbeState {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeState {
    /// Поток проб с таймаутом [`PROBE_TIMEOUT`].
    pub fn new() -> Self {
        Self::with_timeout(PROBE_TIMEOUT)
    }

    /// Поток проб с явным таймаутом (тесты/встраивание).
    pub fn with_timeout(timeout: Duration) -> Self {
        let inner = Arc::new(Inner::default());
        let (tx, rx) = mpsc::channel::<Job>();
        let w_inner = inner.clone();
        let worker = std::thread::Builder::new()
            .name("probe".into())
            .spawn(move || worker(w_inner, rx, timeout))
            .ok();
        ProbeState {
            inner,
            jobs: Mutex::new(Some(tx)),
            timeout,
            worker: Mutex::new(worker),
        }
    }

    /// Сколько проб ждёт ответа (диагностика/тесты).
    pub fn pending(&self) -> usize {
        lock(&self.inner.pending).len()
    }

    /// Забрать готовые результаты (по порядку завершения).
    pub fn poll(&self) -> Vec<ProbeResult> {
        lock(&self.inner.results).drain(..).collect()
    }

    /// Начать пробу сервера: nonce/ts/want_key, ожидание, отправка в поток.
    /// `pinned` — закреплённый ключ сервера (`StoredServer.pubkey`); при нём
    /// запрос просит ключ в ответе (`want_key = true`).
    pub fn start_probe(
        &self,
        addr: SocketAddr,
        pinned: Option<[u8; 32]>,
        now_ms: u64,
    ) -> Result<()> {
        let nonce: [u8; PROBE_NONCE_LEN] = rand::random();
        let req = ProbeReq {
            nonce,
            ts_ms: now_ms,
            want_key: pinned.is_some(),
        };
        let body = payloads::enc_probe_req(&req);
        debug_assert_eq!(body.len(), payloads::PROBE_REQ_LEN);
        let frame = proto::plain_frame(ctrl::PROBE_REQ, &body);
        // Регистрируем ожидание до отправки: ответ может прийти сразу.
        // Повторный запрос к тому же адресу не ставим: два ожидания дали бы
        // «недоступен» после успешного ответа (запоздавший таймаут).
        {
            let mut pending = lock(&self.inner.pending);
            if pending.values().any(|p| p.addr == addr) {
                bail!("проба {addr} уже идёт");
            }
            pending.insert(
                nonce,
                Pending {
                    addr,
                    started: Instant::now(),
                    pinned,
                },
            );
        }
        let sent = match &*lock(&self.jobs) {
            Some(tx) => tx.send(Job { nonce, frame, addr }).is_ok(),
            None => false,
        };
        if !sent {
            lock(&self.inner.pending).remove(&nonce);
            bail!("поток проб остановлен");
        }
        Ok(())
    }

    /// Ответ `PROBE_RESP` (на основной сокет движка или тестом): `None` — не
    /// наша проба, битый или уже отвеченный ответ.
    pub fn on_response(&self, src: SocketAddr, body: &[u8]) -> Option<ProbeResult> {
        self.inner.on_response(src, body)
    }

    /// Таймаут пробы по nonce (тесты/диагностика).
    pub fn timeout_nonce(&self, nonce: [u8; PROBE_NONCE_LEN]) {
        self.inner.timed_out(nonce);
    }

    /// Таймаут, с которым создан поток (тесты).
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Nonce'ы ожидающих проб (тесты: ответ/таймаут по известному nonce).
    #[cfg(test)]
    pub(crate) fn pending_nonces(&self) -> Vec<[u8; PROBE_NONCE_LEN]> {
        lock(&self.inner.pending).keys().copied().collect()
    }
}

impl Drop for ProbeState {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        // Закрыть очередь заданий: поток выйдет и из `recv`, и по флагу.
        drop(lock(&self.jobs).take());
        let worker = lock(&self.worker).take();
        if let Some(w) = worker {
            let _ = w.join();
        }
    }
}

/// Сокет для пробы `addr`: тот же IP-стек, свободный порт.
fn bind_for(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let any = match addr.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let sock = UdpSocket::bind(any)?;
    sock.set_read_timeout(Some(POLL))?;
    Ok(sock)
}

/// Рабочий поток: по одному заданию, свой сокет, до [`PROBE_ATTEMPTS`]
/// отправок по [`PROBE_TIMEOUT`]. Результат — в очередь [`Inner::results`].
fn worker(inner: Arc<Inner>, jobs: Receiver<Job>, timeout: Duration) {
    let mut buf = [0u8; BUF];
    while !inner.stop.load(Ordering::SeqCst) {
        let job = match jobs.recv_timeout(POLL) {
            Ok(j) => j,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        let sock = match bind_for(job.addr) {
            Ok(s) => s,
            Err(_) => {
                inner.timed_out(job.nonce);
                continue;
            }
        };
        let mut answered = false;
        for _ in 0..PROBE_ATTEMPTS {
            if inner.stop.load(Ordering::SeqCst) {
                return;
            }
            // Ошибка отправки (нет маршрута) — как потеря: повторяем попытку.
            let _ = sock.send_to(&job.frame, job.addr);
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if inner.stop.load(Ordering::SeqCst) {
                    return;
                }
                match sock.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        // Датаграммы с чужого IP — не наш ответ (nonce всё
                        // равно проверится, но чужой трафик не должен съедать
                        // ожидание).
                        if src.ip() != job.addr.ip() {
                            continue;
                        }
                        let Ok((typ, body)) = proto::split_frame(&buf[..n]) else {
                            continue;
                        };
                        if typ != ctrl::PROBE_RESP {
                            continue;
                        }
                        if inner.on_response(src, body).is_some() {
                            answered = true;
                            break;
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    // Сокет сломался — дальше ждать нечего.
                    Err(_) => break,
                }
            }
            if answered {
                break;
            }
        }
        if !answered {
            inner.timed_out(job.nonce);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_protocol::payloads::{PROBE_REQ_LEN, PROBE_RESP_KEY_LEN, PROBE_RESP_LEN, ProbeResp};

    fn addr() -> SocketAddr {
        "203.0.113.9:5555".parse().unwrap()
    }

    fn track(st: &ProbeState, nonce: [u8; PROBE_NONCE_LEN], pinned: Option<[u8; 32]>, ago_ms: u64) {
        let started = Instant::now()
            .checked_sub(Duration::from_millis(ago_ms))
            .unwrap_or_else(Instant::now);
        lock(&st.inner.pending).insert(
            nonce,
            Pending {
                addr: addr(),
                started,
                pinned,
            },
        );
    }

    fn resp(nonce: [u8; PROBE_NONCE_LEN], key: Option<[u8; 32]>) -> Vec<u8> {
        payloads::enc_probe_resp(&ProbeResp {
            nonce,
            ts_ms: 1_700_000_000_000,
            ed_pub: key,
        })
    }

    /// Ждём результат пробы (поток настоящий, сокет — loopback).
    fn wait_result(st: &ProbeState, timeout: Duration) -> Option<ProbeResult> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(r) = st.poll().into_iter().next() {
                return Some(r);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        st.poll().into_iter().next()
    }

    #[test]
    fn ответ_даёт_доступность_и_rtt() {
        let st = ProbeState::new();
        let pin = [5u8; 32];
        track(&st, [1u8; PROBE_NONCE_LEN], Some(pin), 42);
        let r = st
            .on_response(addr(), &resp([1u8; PROBE_NONCE_LEN], Some(pin)))
            .unwrap();
        assert_eq!(r.addr, addr());
        assert!(r.available);
        assert_eq!(r.key, Some(pin));
        assert_eq!(r.key_match, KeyMatch::Match);
        assert!(r.rtt_ms.unwrap() >= 42, "RTT {:?}", r.rtt_ms);
        // Ответ учтён один раз: повтор (и подделка с тем же nonce) — не наша
        // проба.
        assert!(
            st.on_response(addr(), &resp([1u8; PROBE_NONCE_LEN], Some(pin)))
                .is_none()
        );
        assert_eq!(st.pending(), 0);
        assert_eq!(st.poll().len(), 1);
    }

    #[test]
    fn чужой_ключ_и_без_пина() {
        let st = ProbeState::new();
        track(&st, [2u8; PROBE_NONCE_LEN], Some([5u8; 32]), 1);
        let r = st
            .on_response(addr(), &resp([2u8; PROBE_NONCE_LEN], Some([6u8; 32])))
            .unwrap();
        assert_eq!(
            r.key_match,
            KeyMatch::Mismatch,
            "сервер отвечает чужим ключом"
        );
        assert_eq!(r.key_match.as_bool(), Some(false));
        // Без закреплённого ключа сверять не с чем.
        let st = ProbeState::new();
        track(&st, [3u8; PROBE_NONCE_LEN], None, 1);
        let r = st
            .on_response(addr(), &resp([3u8; PROBE_NONCE_LEN], Some([6u8; 32])))
            .unwrap();
        assert_eq!(r.key_match, KeyMatch::Unknown);
        assert_eq!(r.key_match.as_bool(), None);
        // Сервер не вернул ключ (want_key = 0) — rtt есть, сверки нет.
        let st = ProbeState::new();
        track(&st, [4u8; PROBE_NONCE_LEN], Some([5u8; 32]), 1);
        let r = st
            .on_response(addr(), &resp([4u8; PROBE_NONCE_LEN], None))
            .unwrap();
        assert_eq!((r.key, r.key_match), (None, KeyMatch::Unknown));
    }

    #[test]
    fn битый_и_чужой_ответ_не_паникует() {
        let st = ProbeState::new();
        track(&st, [1u8; PROBE_NONCE_LEN], None, 0);
        // Не тот nonce, битая длина, пустой payload, мусор.
        assert!(
            st.on_response(addr(), &resp([9u8; PROBE_NONCE_LEN], None))
                .is_none()
        );
        for b in [
            vec![],
            vec![0u8; 23],
            vec![0u8; 25],
            vec![0u8; 57],
            (0..64).map(|i| i as u8).collect::<Vec<u8>>(),
        ] {
            assert!(st.on_response(addr(), &b).is_none());
        }
        // Ожидание не съедено мусором: настоящий ответ ещё принимается.
        assert!(
            st.on_response(addr(), &resp([1u8; PROBE_NONCE_LEN], None))
                .is_some()
        );
        // Тип кадра: проба — открытым текстом, не ctrl-шифр.
        assert!(ctrl::is_plaintext(ctrl::PROBE_REQ) && ctrl::is_plaintext(ctrl::PROBE_RESP));
    }

    /// Фейковый сервер: отвечает на PROBE_REQ заданным ключом.
    fn fake_server(key: Option<[u8; 32]>) -> (SocketAddr, std::thread::JoinHandle<Vec<u8>>) {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 1024];
            let (n, src) = sock.recv_from(&mut buf).unwrap();
            let body = &buf[..n];
            let (typ, payload) = proto::split_frame(body).unwrap();
            assert_eq!(typ, ctrl::PROBE_REQ);
            let req = payloads::dec_probe_req(payload).unwrap();
            let resp = payloads::enc_probe_resp(&ProbeResp {
                nonce: req.nonce,
                ts_ms: req.ts_ms,
                ed_pub: req.want_key.then_some(key.unwrap_or([0; 32])),
            });
            sock.send_to(&proto::plain_frame(ctrl::PROBE_RESP, &resp), src)
                .unwrap();
            payload.to_vec()
        });
        (addr, h)
    }

    #[test]
    fn проба_через_сокет_и_поток_даёт_ключ_и_rtt() {
        let pin = [7u8; 32];
        let (addr, srv) = fake_server(Some(pin));
        let st = ProbeState::with_timeout(Duration::from_secs(2));
        st.start_probe(addr, Some(pin), 1_700_000_000_000).unwrap();
        let r = wait_result(&st, Duration::from_secs(3)).expect("проба завершилась");
        assert_eq!(r.addr, addr);
        assert!(r.available, "{r:?}");
        assert_eq!(r.key, Some(pin));
        assert_eq!(r.key_match, KeyMatch::Match);
        assert!(r.rtt_ms.is_some());
        // Запрос — ровно 64 байта тела, want_key=1 (был закреплённый ключ).
        let req = srv.join().unwrap();
        assert_eq!(req.len(), PROBE_REQ_LEN);
        assert!(payloads::dec_probe_req(&req).unwrap().want_key);
        assert_eq!(st.pending(), 0);
    }

    #[test]
    fn проба_без_пина_ключ_не_просит_и_чужой_ключ_виден() {
        // Без пина want_key=0: ответ 24 байта, сверки нет.
        let (addr, srv) = fake_server(Some([9; 32]));
        let st = ProbeState::with_timeout(Duration::from_secs(2));
        st.start_probe(addr, None, 1_700_000_000_000).unwrap();
        let r = wait_result(&st, Duration::from_secs(3)).expect("проба завершилась");
        assert!(r.available);
        assert_eq!(r.key, None);
        assert_eq!(r.key_match, KeyMatch::Unknown);
        let req = srv.join().unwrap();
        assert!(!payloads::dec_probe_req(&req).unwrap().want_key);
        assert_eq!(
            payloads::enc_probe_resp(&ProbeResp {
                nonce: [0; PROBE_NONCE_LEN],
                ts_ms: 0,
                ed_pub: None,
            })
            .len(),
            PROBE_RESP_LEN
        );
        assert_eq!(
            payloads::enc_probe_resp(&ProbeResp {
                nonce: [0; PROBE_NONCE_LEN],
                ts_ms: 0,
                ed_pub: Some([0; 32]),
            })
            .len(),
            PROBE_RESP_KEY_LEN
        );
    }

    #[test]
    fn молчащий_сервер_даёт_недоступен_за_две_попытки() {
        // Сокет забинден и не читает: датаграммы уходят в никуда, ответа нет.
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        let st = ProbeState::with_timeout(Duration::from_millis(120));
        assert_eq!(st.timeout(), Duration::from_millis(120));
        let started = Instant::now();
        st.start_probe(sink.local_addr().unwrap(), None, 1_700_000_000_000)
            .unwrap();
        let r = wait_result(&st, Duration::from_secs(3)).expect("проба завершилась");
        assert!(!r.available, "{r:?}");
        assert_eq!(
            (r.rtt_ms, r.key, r.key_match),
            (None, None, KeyMatch::Unknown)
        );
        // Две попытки по 120 мс — не мгновенно и не дольше разумного.
        assert!(
            started.elapsed() >= Duration::from_millis(120),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(st.pending(), 0);
    }

    #[test]
    fn повторная_проба_того_же_адреса_не_дублируется() {
        // Второе ожидание того же адреса дало бы «недоступен» уже после
        // успешного ответа (запоздавший таймаут) — не ставим его.
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sink.local_addr().unwrap();
        let st = ProbeState::with_timeout(Duration::from_millis(120));
        st.start_probe(addr, None, 1_700_000_000_000).unwrap();
        let e = st
            .start_probe(addr, None, 1_700_000_000_000)
            .unwrap_err()
            .to_string();
        assert!(e.contains("уже идёт"), "{e}");
        let r = wait_result(&st, Duration::from_secs(3)).expect("проба завершилась");
        assert!(!r.available);
        assert_eq!(st.pending(), 0);
        // После завершения — снова можно.
        st.start_probe(addr, None, 1_700_000_000_000).unwrap();
        assert_eq!(st.pending(), 1);
    }

    #[test]
    fn поток_останавливается_без_зависаний() {
        let started = Instant::now();
        {
            let st = ProbeState::new();
            assert_eq!(st.pending(), 0);
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }
}
