//! TCP-фолбэк канал до сервера для сетей, где режут UDP.
//!
//! По TCP ходят те же датаграммы «TNL2», что и по UDP, в рамке
//! `u16 LE длина` + `кадр` (см. `tunnel_server::tcp`). Поток-читатель
//! разбирает рамки и складывает кадры в mpsc; запись — синхронная, под
//! мьютексом, с таймаутом.
//!
//! Тихий обрыв (NAT забыл соединение, сервер обесточен) ловится таймаутом
//! чтения `READ_TIMEOUT`: если от сервера ничего не приходит столько времени,
//! читатель выходит и `is_alive()` становится `false`. Движок должен пинговать
//! заметно чаще (раз в 5 с), чтобы сервер успевал отвечать.
//!
//! Когда переходить на TCP, решает `should_fallback`: после нескольких
//! неудачных UDP-рукопожатий или если UDP молчит слишком долго.

#![allow(dead_code)] // подключается при интеграции

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Максимальная длина кадра (совпадает с `DEFAULT_MAX_FRAME` сервера).
pub const MAX_FRAME: usize = 4096;
/// Таймаут записи в сокет.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Таймаут чтения: столько тишины от сервера — соединение считается мёртвым.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Сколько неудачных UDP-рукопожатий подряд — и переходим на TCP.
pub const FALLBACK_AFTER_FAILURES: u32 = 3;
/// Если хоть одно рукопожатие не удалось и UDP молчит столько — на TCP.
pub const FALLBACK_AFTER_ELAPSED: Duration = Duration::from_secs(10);

/// Пора ли переходить на TCP: `udp_handshake_failures` — неудачных
/// рукопожатий подряд, `elapsed` — сколько прошло с первой попытки по UDP.
pub fn should_fallback(udp_handshake_failures: u32, elapsed: Duration) -> bool {
    udp_handshake_failures >= FALLBACK_AFTER_FAILURES
        || (udp_handshake_failures >= 1 && elapsed >= FALLBACK_AFTER_ELAPSED)
}

/// Пауза перед попыткой переподключения номер `attempt` (с 0):
/// экспоненциально 0.5 с, 1 с, 2 с, … но не больше 30 с.
pub fn reconnect_delay(attempt: u32) -> Duration {
    let ms = 500u64.saturating_mul(1u64 << attempt.min(6));
    Duration::from_millis(ms.min(30_000))
}

/// Живое TCP-соединение с сервером.
pub struct TcpLink {
    peer: SocketAddr,
    writer: Mutex<TcpStream>,
    alive: Arc<AtomicBool>,
    /// Под мьютексом: `TcpLink` делится между потоками движка (`Arc`).
    rx: Mutex<Receiver<Vec<u8>>>,
    reader: Option<JoinHandle<()>>,
}

impl TcpLink {
    /// Подключиться к `addr` с таймаутом установки соединения.
    pub fn connect(addr: SocketAddr, timeout: Duration) -> io::Result<Self> {
        Self::connect_with_read_timeout(addr, timeout, READ_TIMEOUT)
    }

    /// Как `connect`, но со своим таймаутом тишины от сервера.
    pub fn connect_with_read_timeout(
        addr: SocketAddr,
        timeout: Duration,
        read_timeout: Duration,
    ) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_nodelay(true)?;
        stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        let read_half = stream.try_clone()?;
        read_half.set_read_timeout(Some(read_timeout))?;
        let alive = Arc::new(AtomicBool::new(true));
        let (tx, rx) = mpsc::channel();
        let reader = {
            let alive = alive.clone();
            thread::Builder::new()
                .name("tcp-link-rx".into())
                .spawn(move || {
                    // `tx.clone()`: оригинальный `Sender` живёт до конца
                    // замыкания, поэтому «канал закрыт» виден получателю не
                    // раньше, чем выставлен `alive = false`. Иначе между
                    // `Disconnected` и `is_alive()` остаётся окно гонки.
                    reader_loop(read_half, tx.clone());
                    alive.store(false, Ordering::SeqCst);
                })?
        };
        Ok(TcpLink {
            peer: addr,
            writer: Mutex::new(stream),
            alive,
            rx: Mutex::new(rx),
            reader: Some(reader),
        })
    }

    /// Подключаться до `attempts` раз с паузами `reconnect_delay`.
    pub fn connect_with_retry(
        addr: SocketAddr,
        timeout: Duration,
        attempts: u32,
    ) -> io::Result<Self> {
        let mut last = io::Error::other("нет попыток подключения");
        for i in 0..attempts.max(1) {
            if i > 0 {
                thread::sleep(reconnect_delay(i - 1));
            }
            match Self::connect(addr, timeout) {
                Ok(l) => return Ok(l),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Переподключиться к тому же серверу (старое соединение закрывается).
    /// Непрочитанные кадры старого соединения теряются.
    pub fn reconnect(&mut self, timeout: Duration) -> io::Result<()> {
        let fresh = Self::connect(self.peer, timeout)?;
        *self = fresh; // Drop старого закроет сокет и дождётся читателя
        Ok(())
    }

    /// Адрес сервера.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Соединение живо (читатель не получил EOF/ошибку, запись не падала).
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    /// Отправить кадр. Ошибка записи помечает соединение мёртвым.
    ///
    /// Запись синхронная: при забитом сокете вызов может заблокировать
    /// вызывающий поток (и мьютекс писателя) до `WRITE_TIMEOUT` (5 с).
    pub fn send(&self, frame: &[u8]) -> io::Result<()> {
        if frame.is_empty() || frame.len() > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "недопустимая длина кадра",
            ));
        }
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "соединение закрыто",
            ));
        }
        let mut buf = Vec::with_capacity(2 + frame.len());
        buf.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        buf.extend_from_slice(frame);
        let mut w = self.writer.lock().unwrap();
        if let Err(e) = w.write_all(&buf) {
            self.alive.store(false, Ordering::SeqCst);
            let _ = w.shutdown(Shutdown::Both);
            return Err(e);
        }
        Ok(())
    }

    /// Следующий входящий кадр (ждать не дольше `timeout`).
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Vec<u8>, RecvTimeoutError> {
        self.rx.lock().unwrap().recv_timeout(timeout)
    }

    /// Входящий кадр без ожидания.
    pub fn try_recv(&self) -> Result<Vec<u8>, TryRecvError> {
        self.rx.lock().unwrap().try_recv()
    }

    /// Закрыть соединение.
    pub fn close(&self) {
        self.alive.store(false, Ordering::SeqCst);
        let _ = self.writer.lock().unwrap().shutdown(Shutdown::Both);
    }
}

impl Drop for TcpLink {
    fn drop(&mut self) {
        self.close();
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
    }
}

fn reader_loop(mut s: TcpStream, tx: mpsc::Sender<Vec<u8>>) {
    loop {
        let mut hdr = [0u8; 2];
        if s.read_exact(&mut hdr).is_err() {
            break;
        }
        let len = u16::from_le_bytes(hdr) as usize;
        if len == 0 || len > MAX_FRAME {
            break; // нарушение формата — соединение больше не синхронно
        }
        let mut frame = vec![0u8; len];
        if s.read_exact(&mut frame).is_err() || tx.send(frame).is_err() {
            break;
        }
    }
    let _ = s.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn read_frame(s: &mut TcpStream) -> Vec<u8> {
        let mut hdr = [0u8; 2];
        s.read_exact(&mut hdr).unwrap();
        let mut f = vec![0u8; u16::from_le_bytes(hdr) as usize];
        s.read_exact(&mut f).unwrap();
        f
    }

    fn write_frame(s: &mut TcpStream, f: &[u8]) {
        let mut b = (f.len() as u16).to_le_bytes().to_vec();
        b.extend_from_slice(f);
        s.write_all(&b).unwrap();
    }

    const T: Duration = Duration::from_secs(3);

    #[test]
    fn tcp_link_frames_both_ways() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let link = TcpLink::connect(addr, T).unwrap();
        let (mut srv, _) = l.accept().unwrap();

        link.send(b"TNL2 ping").unwrap();
        link.send(b"second").unwrap();
        assert_eq!(read_frame(&mut srv), b"TNL2 ping");
        assert_eq!(read_frame(&mut srv), b"second");

        // Две рамки одним write.
        let mut both = vec![3, 0];
        both.extend_from_slice(b"abc");
        both.extend_from_slice(&[1, 0, b'z']);
        srv.write_all(&both).unwrap();
        assert_eq!(link.recv_timeout(T).unwrap(), b"abc");
        assert_eq!(link.recv_timeout(T).unwrap(), b"z");
        assert!(link.try_recv().is_err());

        assert!(link.send(b"").is_err());
        assert!(link.send(&[0u8; MAX_FRAME + 1]).is_err());
        assert!(link.is_alive());
    }

    #[test]
    fn tcp_link_detects_close_and_reconnects() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let mut link = TcpLink::connect(addr, T).unwrap();
        let (srv, _) = l.accept().unwrap();
        drop(srv);
        assert_eq!(link.recv_timeout(T), Err(RecvTimeoutError::Disconnected));
        assert!(!link.is_alive());
        assert!(link.send(b"x").is_err());

        link.reconnect(T).unwrap();
        let (mut srv2, _) = l.accept().unwrap();
        assert!(link.is_alive());
        link.send(b"again").unwrap();
        assert_eq!(read_frame(&mut srv2), b"again");
        write_frame(&mut srv2, b"back");
        assert_eq!(link.recv_timeout(T).unwrap(), b"back");
    }

    #[test]
    fn tcp_link_bad_length_closes() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let link = TcpLink::connect(l.local_addr().unwrap(), T).unwrap();
        let (mut srv, _) = l.accept().unwrap();
        srv.write_all(&[0, 0]).unwrap();
        assert_eq!(link.recv_timeout(T), Err(RecvTimeoutError::Disconnected));
        assert!(!link.is_alive());
    }

    #[test]
    fn tcp_link_silent_server_marks_dead() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let link = TcpLink::connect_with_read_timeout(
            l.local_addr().unwrap(),
            T,
            Duration::from_millis(300),
        )
        .unwrap();
        // Сервер держит соединение, но молчит — как при тихом обрыве.
        let (_srv, _) = l.accept().unwrap();
        assert_eq!(link.recv_timeout(T), Err(RecvTimeoutError::Disconnected));
        assert!(!link.is_alive());
    }

    #[test]
    fn tcp_link_connect_refused_and_retry() {
        // Свободный порт: занимаем и сразу отпускаем.
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(TcpLink::connect(addr, Duration::from_millis(500)).is_err());
        assert!(TcpLink::connect_with_retry(addr, Duration::from_millis(200), 2).is_err());
    }

    #[test]
    fn tcp_link_fallback_policy() {
        assert!(!should_fallback(0, Duration::from_secs(60)));
        assert!(!should_fallback(1, Duration::from_secs(2)));
        assert!(!should_fallback(2, Duration::from_secs(9)));
        assert!(should_fallback(3, Duration::ZERO));
        assert!(should_fallback(1, FALLBACK_AFTER_ELAPSED));
        assert_eq!(reconnect_delay(0), Duration::from_millis(500));
        assert_eq!(reconnect_delay(1), Duration::from_secs(1));
        assert_eq!(reconnect_delay(100), Duration::from_secs(30));
    }
}
