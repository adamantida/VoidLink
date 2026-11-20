//! Метрики сервера и крошечный HTTP-эндпоинт для них (только std).
//!
//! `Metrics` — набор атомарных счётчиков/датчиков, которые воркеры обновляют
//! без блокировок. `MetricsServer` — один поток, отдающий:
//! - `GET /metrics` — текстовый формат Prometheus (с HELP/TYPE);
//! - `GET /healthz` — `200 ok` или `503 unavailable` по колбэку здоровья;
//! - всё остальное — 404 (не-GET — 405).
//!
//! Запросы обрабатываются по одному: ограничены размер заголовков и время
//! на чтение/запись, поэтому медленный клиент (slowloris) не держит поток
//! дольше таймаута (`READ_DEADLINE` < 1 с — нормальный скрейп приходит одним
//! пакетом). Этого мало против целенаправленной атаки: поэтому эндпоинт
//! рассчитан на локальный/приватный интерфейс — по умолчанию `DEFAULT_ADDR`
//! (127.0.0.1), наружу (0.0.0.0) его не выставлять.
//!
//! Датчики выставляйте из авторитетного количества (`set(&m.sessions,
//! sessions.len())` раз в тик); если всё же нужен инкремент/декремент —
//! `inc`/`dec`, причём `dec` не уходит ниже нуля.

#![allow(dead_code)] // подключается при интеграции

use std::fmt::Write as _;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// Максимальный размер заголовков запроса.
const MAX_REQUEST: usize = 4096;
/// Общий лимит времени на чтение запроса (защита от slowloris).
const READ_DEADLINE: Duration = Duration::from_millis(750);
/// Таймаут записи ответа.
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);
/// Как часто поток проверяет флаг остановки, пока нет подключений.
const ACCEPT_POLL: Duration = Duration::from_millis(50);

/// Адрес эндпоинта по умолчанию: только локальный интерфейс.
pub const DEFAULT_ADDR: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
    std::net::Ipv4Addr::LOCALHOST,
    9100,
));

/// Колбэк проверки здоровья.
pub type HealthFn = Arc<dyn Fn() -> bool + Send + Sync>;

/// Колбэк перед отдачей `/metrics`: выставить датчики из авторитетного состояния.
pub type RefreshFn = Arc<dyn Fn() + Send + Sync>;

/// Реестр метрик. Счётчики только растут, датчики (gauge) выставляются.
#[derive(Default)]
pub struct Metrics {
    // датчики
    pub sessions: AtomicU64,
    pub groups: AtomicU64,
    pub members: AtomicU64,
    pub invites_pending: AtomicU64,
    // счётчики
    pub relayed_frames: AtomicU64,
    pub dropped_frames: AtomicU64,
    pub hello_total: AtomicU64,
    pub challenge_total: AtomicU64,
    pub ctrl_frames: AtomicU64,
    pub bytes_relayed: AtomicU64,
    /// Пробы доступности (`PROBE_REQ`, этап 9).
    pub probes_total: AtomicU64,
    /// Закреплённые (TOFU) серверы-пиры федерации (этап 9, T4a).
    pub fed_peers: AtomicU64,
    /// Отклонённые подсказки/рукопожатия федерации: чужой ключ/адрес/срок
    /// (этап 9, T4a).
    pub fed_hint_rejected: AtomicU64,
}

#[derive(Clone, Copy)]
enum Kind {
    Gauge,
    Counter,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Прибавить к счётчику.
    #[inline]
    pub fn inc(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Ordering::Relaxed);
    }

    /// Уменьшить датчик на 1, не уходя ниже нуля (декремент раньше
    /// парного инкремента в гонке даёт 0, а не ~1.8e19).
    #[inline]
    pub fn dec(g: &AtomicU64) {
        // CAS-цикл вручную: `fetch_update` в новых toolchain помечен устаревшим.
        let mut cur = g.load(Ordering::Relaxed);
        while cur > 0 {
            match g.compare_exchange_weak(cur, cur - 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Выставить датчик.
    #[inline]
    pub fn set(g: &AtomicU64, v: u64) {
        g.store(v, Ordering::Relaxed);
    }

    /// Учесть один релейнутый фрейм размером `bytes`.
    #[inline]
    pub fn relayed(&self, bytes: usize) {
        self.relayed_frames.fetch_add(1, Ordering::Relaxed);
        self.bytes_relayed
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn entries(&self) -> [(&'static str, &'static str, Kind, &AtomicU64); 13] {
        use Kind::*;
        [
            (
                "voidlink_sessions",
                "Активные сессии клиентов",
                Gauge,
                &self.sessions,
            ),
            ("voidlink_groups", "Количество групп", Gauge, &self.groups),
            (
                "voidlink_members",
                "Участники во всех группах",
                Gauge,
                &self.members,
            ),
            (
                "voidlink_invites_pending",
                "Неиспользованные инвайты",
                Gauge,
                &self.invites_pending,
            ),
            (
                "voidlink_relayed_frames_total",
                "Релейнутые фреймы",
                Counter,
                &self.relayed_frames,
            ),
            (
                "voidlink_dropped_frames_total",
                "Отброшенные фреймы",
                Counter,
                &self.dropped_frames,
            ),
            (
                "voidlink_hello_total",
                "Принятые HELLO",
                Counter,
                &self.hello_total,
            ),
            (
                "voidlink_challenge_total",
                "Отправленные CHALLENGE",
                Counter,
                &self.challenge_total,
            ),
            (
                "voidlink_ctrl_frames_total",
                "Управляющие фреймы",
                Counter,
                &self.ctrl_frames,
            ),
            (
                "voidlink_bytes_relayed_total",
                "Байты релея",
                Counter,
                &self.bytes_relayed,
            ),
            (
                "voidlink_probes_total",
                "Пробы доступности (PROBE_REQ)",
                Counter,
                &self.probes_total,
            ),
            (
                "voidlink_fed_peers",
                "Закреплённые серверы-пиры федерации",
                Gauge,
                &self.fed_peers,
            ),
            (
                "voidlink_fed_hint_rejected_total",
                "Отклонённые подсказки/рукопожатия федерации",
                Counter,
                &self.fed_hint_rejected,
            ),
        ]
    }

    /// Текст в формате Prometheus exposition 0.0.4.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(1024);
        for (name, help, kind, v) in self.entries() {
            let t = match kind {
                Kind::Gauge => "gauge",
                Kind::Counter => "counter",
            };
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} {t}");
            let _ = writeln!(out, "{name} {}", v.load(Ordering::Relaxed));
        }
        out
    }
}

/// HTTP-сервер метрик в одном фоновом потоке. Останавливается при `stop()`
/// или drop.
pub struct MetricsServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl MetricsServer {
    /// Слушать `addr` и отдавать метрики. Порт 0 — выбрать свободный
    /// (реальный адрес — `local_addr()`).
    pub fn start(addr: SocketAddr, metrics: Arc<Metrics>, health: HealthFn) -> Result<Self> {
        Self::start_with_refresh(addr, metrics, health, Arc::new(|| {}))
    }

    /// Как `start`, плюс `refresh` перед каждой отдачей `/metrics`.
    pub fn start_with_refresh(
        addr: SocketAddr,
        metrics: Arc<Metrics>,
        health: HealthFn,
        refresh: RefreshFn,
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .with_context(|| format!("метрики: не удалось занять {addr}"))?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let thread = thread::Builder::new()
            .name("metrics-http".into())
            .spawn(move || serve(listener, metrics, health, refresh, stop2))?;
        Ok(Self {
            addr,
            stop,
            thread: Some(thread),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Остановить поток и дождаться его завершения.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for MetricsServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn serve(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    health: HealthFn,
    refresh: RefreshFn,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                // Ошибки отдельного клиента не роняют сервер.
                let _ = handle(stream, &metrics, &health, &refresh);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(_) => thread::sleep(ACCEPT_POLL),
        }
    }
}

/// Прочитать заголовки запроса (до `\r\n\r\n`) с общим дедлайном и лимитом
/// размера. `None` — клиент не уложился или прислал мусор.
fn read_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let deadline = Instant::now() + READ_DEADLINE;
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        if left.is_zero() {
            return None;
        }
        stream.set_read_timeout(Some(left)).ok()?;
        match stream.read(&mut chunk) {
            Ok(0) => return None,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    return Some(buf);
                }
                if buf.len() > MAX_REQUEST {
                    return None;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
}

fn handle(
    mut stream: TcpStream,
    metrics: &Metrics,
    health: &HealthFn,
    refresh: &RefreshFn,
) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let Some(req) = read_request(&mut stream) else {
        // Слишком большой/медленный запрос — закрываем без ответа.
        return Ok(());
    };
    let line = req.split(|&b| b == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let mut parts = line.trim_end().split(' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let path = target.split('?').next().unwrap_or("");

    let (status, ctype, body) = if method != "GET" && method != "HEAD" {
        (
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            "method not allowed\n".to_string(),
        )
    } else {
        match path {
            "/metrics" => {
                refresh();
                (
                    "200 OK",
                    "text/plain; version=0.0.4; charset=utf-8",
                    metrics.render(),
                )
            }
            "/healthz" => {
                if health() {
                    ("200 OK", "text/plain; charset=utf-8", "ok\n".to_string())
                } else {
                    (
                        "503 Service Unavailable",
                        "text/plain; charset=utf-8",
                        "unavailable\n".to_string(),
                    )
                }
            }
            _ => (
                "404 Not Found",
                "text/plain; charset=utf-8",
                "not found\n".to_string(),
            ),
        }
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    if method != "HEAD" {
        stream.write_all(body.as_bytes())?;
    }
    stream.flush()?;
    let _ = stream.shutdown(std::net::Shutdown::Both);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(healthy: bool) -> (MetricsServer, Arc<Metrics>) {
        let m = Metrics::new();
        let flag = Arc::new(AtomicBool::new(healthy));
        let h: HealthFn = Arc::new(move || flag.load(Ordering::Relaxed));
        let s = MetricsServer::start("127.0.0.1:0".parse().unwrap(), m.clone(), h).unwrap();
        (s, m)
    }

    fn get(addr: SocketAddr, req: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn gauge_dec_saturates() {
        let m = Metrics::new();
        Metrics::dec(&m.sessions);
        assert_eq!(m.sessions.load(Ordering::Relaxed), 0);
        Metrics::inc(&m.sessions, 2);
        Metrics::dec(&m.sessions);
        assert_eq!(m.sessions.load(Ordering::Relaxed), 1);
        assert!(DEFAULT_ADDR.ip().is_loopback());
    }

    #[test]
    fn metrics_text_parses() {
        let (s, m) = start(true);
        Metrics::set(&m.sessions, 3);
        m.relayed(100);
        m.relayed(50);
        Metrics::inc(&m.hello_total, 7);
        let resp = get(s.local_addr(), "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains("text/plain; version=0.0.4"));
        let body = resp.split("\r\n\r\n").nth(1).unwrap();
        let mut values = std::collections::HashMap::new();
        let mut types = 0;
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let t = rest.split(' ').nth(1).unwrap();
                assert!(t == "gauge" || t == "counter");
                types += 1;
                continue;
            }
            if line.starts_with("# HELP ") {
                continue;
            }
            let (k, v) = line.split_once(' ').unwrap();
            values.insert(k.to_string(), v.parse::<u64>().unwrap());
        }
        assert_eq!(types, 13);
        assert_eq!(values.len(), 13);
        assert_eq!(values["voidlink_sessions"], 3);
        assert_eq!(values["voidlink_relayed_frames_total"], 2);
        assert_eq!(values["voidlink_bytes_relayed_total"], 150);
        assert_eq!(values["voidlink_hello_total"], 7);
        assert_eq!(values["voidlink_dropped_frames_total"], 0);
        assert_eq!(values["voidlink_probes_total"], 0);
        s.stop();
    }

    #[test]
    fn healthz_ok_and_unavailable() {
        let (s, _) = start(true);
        let r = get(s.local_addr(), "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(r.starts_with("HTTP/1.1 200 OK"), "{r}");
        assert!(r.ends_with("ok\n"));
        let (s2, _) = start(false);
        let r = get(s2.local_addr(), "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(r.starts_with("HTTP/1.1 503"), "{r}");
    }

    #[test]
    fn unknown_path_404_and_post_405() {
        let (s, _) = start(true);
        let r = get(s.local_addr(), "GET /nope HTTP/1.1\r\n\r\n");
        assert!(r.starts_with("HTTP/1.1 404"), "{r}");
        let r = get(s.local_addr(), "POST /metrics HTTP/1.1\r\n\r\n");
        assert!(r.starts_with("HTTP/1.1 405"), "{r}");
    }

    #[test]
    fn oversized_request_dropped() {
        let (s, _) = start(true);
        let big = format!(
            "GET /metrics HTTP/1.1\r\nX: {}\r\n\r\n",
            "a".repeat(MAX_REQUEST * 2)
        );
        let mut c = TcpStream::connect(s.local_addr()).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = c.write_all(big.as_bytes());
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        assert!(!out.starts_with(b"HTTP/1.1 200"));
        // Сервер жив.
        let r = get(s.local_addr(), "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(r.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn slowloris_times_out() {
        let (s, _) = start(true);
        let mut slow = TcpStream::connect(s.local_addr()).unwrap();
        slow.write_all(b"GET /metrics HTTP/1.1\r\n").unwrap();
        let t0 = Instant::now();
        slow.set_read_timeout(Some(READ_DEADLINE + Duration::from_secs(5)))
            .unwrap();
        let mut out = Vec::new();
        // Сервер должен закрыть соединение сам по дедлайну.
        let _ = slow.read_to_end(&mut out);
        let took = t0.elapsed();
        assert!(out.is_empty());
        assert!(
            took >= READ_DEADLINE - Duration::from_millis(200),
            "{took:?}"
        );
        assert!(took < READ_DEADLINE + Duration::from_secs(3), "{took:?}");
        // После этого обычный клиент обслуживается.
        let r = get(s.local_addr(), "GET /healthz HTTP/1.1\r\n\r\n");
        assert!(r.starts_with("HTTP/1.1 200"));
    }
}
