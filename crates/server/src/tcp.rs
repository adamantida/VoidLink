//! TCP-фолбэк транспорт для сетей, где режут UDP.
//!
//! По TCP ходят те же самые датаграммы «TNL2», что и по UDP, только каждая
//! обёрнута в рамку: `u16 LE длина` + `кадр`. Нулевая длина или длина больше
//! `max_frame` — нарушение протокола, соединение закрывается.
//!
//! Устройство:
//! - поток accept (неблокирующий слушатель с опросом раз в 50 мс) принимает
//!   соединения и проверяет лимиты (всего / на IP);
//! - на каждое соединение — поток-читатель (разбирает рамки и отдаёт кадры
//!   обработчику `handler(Peer::Tcp(addr), frame)`) и поток-писатель с
//!   ограниченной очередью: `send` не блокируется, при переполнении кадр
//!   отбрасывается (как потерянная UDP-датаграмма);
//! - соединение, не приславшее ни одного ЦЕЛОГО кадра дольше `idle_timeout`,
//!   закрывается (даже если байты капают по одному — защита от slowloris);
//! - при закрытии соединение убирается из реестра, писатель завершается.
//!
//! Адресация: TCP и UDP — РАЗНЫЕ пространства адресов. Один и тот же
//! `ip:port` может одновременно быть UDP-клиентом за NAT и TCP-соединением,
//! поэтому обработчик получает `Peer`, помеченный транспортом. При интеграции
//! сессии сервера нужно ключевать по `Peer` (или держать отдельную карту для
//! TCP), а ответ слать по транспорту из ключа сессии — НЕ маршрутизировать
//! по `is_live(Peer::Tcp(addr))` для адреса, пришедшего из UDP-сокета.
//!
//! Размер кадра: `DEFAULT_MAX_FRAME = 4096` рассчитан на протокол v3, где
//! любой длинный payload сервера режется FRAG на куски по 1100 байт. На v2
//! (без FRAG) крупные payload'ы вроде GROUP_STATE могут превысить лимит, и
//! `send` их молча отбросит — подключать после порта на v3.
//!
//! Незавершённое рукопожатие транспорт не отслеживает: соединение, которое
//! шлёт мусорные кадры, живёт, пока сессионный слой не вызовет `close`.

#![allow(dead_code)] // подключается при интеграции

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Адрес клиента, помеченный транспортом: UDP и TCP не пересекаются.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Peer {
    Udp(SocketAddr),
    Tcp(SocketAddr),
}

impl Peer {
    /// Сетевой адрес без пометки транспорта.
    pub fn addr(&self) -> SocketAddr {
        match *self {
            Peer::Udp(a) | Peer::Tcp(a) => a,
        }
    }

    /// Это TCP-клиент?
    pub fn is_tcp(&self) -> bool {
        matches!(self, Peer::Tcp(_))
    }
}

/// Обработчик входящего кадра: TCP-клиент (`Peer::Tcp`) и сам кадр (без рамки).
pub type FrameHandler = Arc<dyn Fn(Peer, &[u8]) + Send + Sync>;

/// Обработчик закрытия соединения (EOF, простой, ошибка, нарушение формата).
/// Не вызывается для соединений, закрытых через `TcpSender::close` или `stop`.
pub type CloseHandler = Arc<dyn Fn(Peer) + Send + Sync>;

/// Фильтр приёма соединений: `false` — соединение закрывается сразу и в
/// реестр не попадает. Сервер так не даёт TCP-клиенту занять адрес, который
/// уже принадлежит живой UDP-сессии (TCP и UDP — разные пространства адресов,
/// один `ip:port` может быть занят в обоих).
pub type AdmitFilter = Arc<dyn Fn(SocketAddr) -> bool + Send + Sync>;

/// Обработчики и фильтр приёма, общие для всех соединений.
struct Hooks {
    handler: FrameHandler,
    on_close: CloseHandler,
    filter: AdmitFilter,
}

/// Максимальный размер кадра по умолчанию (v3: payload'ы режутся FRAG по 1100 байт).
pub const DEFAULT_MAX_FRAME: usize = 4096;

/// Таймаут записи: «зависший» клиент не держит писателя вечно.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Шаг чтения: так часто читатель проверяет простой между целыми кадрами.
const READ_TICK: Duration = Duration::from_secs(1);
/// Период опроса неблокирующего слушателя (и задержка реакции на stop).
const ACCEPT_POLL: Duration = Duration::from_millis(50);

/// Лимиты TCP-транспорта.
#[derive(Clone, Debug)]
pub struct TcpLimits {
    /// Максимум одновременных соединений.
    pub max_conns: usize,
    /// Максимум одновременных соединений с одного IP.
    pub max_per_ip: usize,
    /// Соединение без ЦЕЛЫХ входящих кадров столько времени закрывается.
    pub idle_timeout: Duration,
    /// Максимальная длина кадра (не больше u16::MAX).
    pub max_frame: usize,
    /// Длина очереди исходящих кадров на соединение.
    pub queue_len: usize,
}

impl Default for TcpLimits {
    fn default() -> Self {
        TcpLimits {
            max_conns: 1024,
            max_per_ip: 8,
            // Клиент пингует раз в 5 с — как SESSION_TIMEOUT у UDP-сессий.
            idle_timeout: Duration::from_secs(30),
            max_frame: DEFAULT_MAX_FRAME,
            queue_len: 256,
        }
    }
}

struct Conn {
    id: u64,
    tx: SyncSender<Vec<u8>>,
    /// Клон сокета — чтобы закрыть соединение снаружи (shutdown будит читателя).
    stream: TcpStream,
}

#[derive(Default)]
struct Registry {
    conns: Mutex<HashMap<SocketAddr, Conn>>,
    next_id: AtomicU64,
}

impl Registry {
    /// Убрать соединение `peer`, только если это всё ещё соединение `id`
    /// (адрес мог уже переиспользоваться новым), и закрыть его сокет.
    /// `true` — запись была этой и убрана.
    fn remove_if(&self, peer: SocketAddr, id: u64) -> bool {
        let mut conns = self.conns.lock().unwrap();
        if conns.get(&peer).is_some_and(|c| c.id == id)
            && let Some(c) = conns.remove(&peer)
        {
            let _ = c.stream.shutdown(Shutdown::Both);
            return true;
        }
        false
    }
}

/// Отправитель кадров по TCP-соединениям; дёшево клонируется.
#[derive(Clone)]
pub struct TcpSender {
    reg: Arc<Registry>,
    max_frame: usize,
}

impl TcpSender {
    /// Поставить кадр в очередь соединения `peer`. Не блокируется:
    /// `false` — это не TCP-клиент, соединения нет, кадр некорректного
    /// размера или очередь полна.
    pub fn send(&self, peer: Peer, frame: &[u8]) -> bool {
        let Peer::Tcp(addr) = peer else { return false };
        if frame.is_empty() || frame.len() > self.max_frame {
            return false;
        }
        let conns = self.reg.conns.lock().unwrap();
        let Some(c) = conns.get(&addr) else {
            return false;
        };
        match c.tx.try_send(frame.to_vec()) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Есть живое TCP-соединение `peer`? Для `Peer::Udp` всегда `false`.
    pub fn is_live(&self, peer: Peer) -> bool {
        match peer {
            Peer::Tcp(addr) => self.reg.conns.lock().unwrap().contains_key(&addr),
            Peer::Udp(_) => false,
        }
    }

    /// Закрыть соединение (например, при kick/ban). `Peer::Udp` игнорируется.
    pub fn close(&self, peer: Peer) {
        let Peer::Tcp(addr) = peer else { return };
        if let Some(c) = self.reg.conns.lock().unwrap().remove(&addr) {
            let _ = c.stream.shutdown(Shutdown::Both);
        }
    }

    /// Число живых соединений.
    pub fn conn_count(&self) -> usize {
        self.reg.conns.lock().unwrap().len()
    }

    fn close_all(&self) {
        let drained: Vec<Conn> = self
            .reg
            .conns
            .lock()
            .unwrap()
            .drain()
            .map(|(_, c)| c)
            .collect();
        for c in drained {
            let _ = c.stream.shutdown(Shutdown::Both);
        }
    }
}

/// Запущенный TCP-транспорт. При `stop()` / drop закрывает слушатель и все соединения.
pub struct TcpTransport {
    local_addr: SocketAddr,
    sender: TcpSender,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl TcpTransport {
    /// Слушать `listen`, отдавать входящие кадры в `handler`.
    pub fn start(listen: SocketAddr, handler: FrameHandler, limits: TcpLimits) -> io::Result<Self> {
        Self::start_filtered(
            listen,
            handler,
            Arc::new(|_| {}),
            Arc::new(|_| true),
            limits,
        )
    }

    /// Как `start`, плюс `on_close` при закрытии соединения клиентом/по простою.
    pub fn start_with_close(
        listen: SocketAddr,
        handler: FrameHandler,
        on_close: CloseHandler,
        limits: TcpLimits,
    ) -> io::Result<Self> {
        Self::start_filtered(listen, handler, on_close, Arc::new(|_| true), limits)
    }

    /// Как `start_with_close`, плюс фильтр приёма `filter`: `false` —
    /// соединение закрывается, не попадая в реестр.
    pub fn start_filtered(
        listen: SocketAddr,
        handler: FrameHandler,
        on_close: CloseHandler,
        filter: AdmitFilter,
        limits: TcpLimits,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(listen)?;
        // Неблокирующий слушатель: stop не зависит от «самоподключения».
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        let mut limits = limits;
        limits.max_frame = limits.max_frame.clamp(1, u16::MAX as usize);
        limits.queue_len = limits.queue_len.max(1);
        let sender = TcpSender {
            reg: Arc::new(Registry::default()),
            max_frame: limits.max_frame,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let accept = {
            let sender = sender.clone();
            let stop = stop.clone();
            thread::Builder::new()
                .name("tcp-accept".into())
                .spawn(move || {
                    accept_loop(listener, sender, handler, on_close, filter, limits, stop)
                })?
        };
        Ok(TcpTransport {
            local_addr,
            sender,
            stop,
            accept: Some(accept),
        })
    }

    /// Фактический адрес слушателя (полезно при порте 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Отправитель для ответов клиентам.
    pub fn sender(&self) -> TcpSender {
        self.sender.clone()
    }

    /// Остановить приём и закрыть все соединения (ждёт не дольше ~`ACCEPT_POLL`).
    pub fn stop(&mut self) {
        if self.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
        self.sender.close_all();
    }
}

impl Drop for TcpTransport {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(
    listener: TcpListener,
    sender: TcpSender,
    handler: FrameHandler,
    on_close: CloseHandler,
    filter: AdmitFilter,
    limits: TcpLimits,
    stop: Arc<AtomicBool>,
) {
    let hooks = Hooks {
        handler,
        on_close,
        filter,
    };
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, peer)) => {
                // На macOS/Windows принятый сокет наследует неблокирующий режим.
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                // Превышение лимитов и ошибки сокета — молча.
                let _ = admit(stream, peer, &sender, &hooks, &limits);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            // Например, EMFILE: не крутим цикл вхолостую.
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
    // Слушатель закрывается здесь, при выходе из потока.
}

/// Проверить лимиты, зарегистрировать соединение и запустить его потоки.
/// Если поток не удалось запустить, запись убирается из реестра.
fn admit(
    stream: TcpStream,
    peer: SocketAddr,
    sender: &TcpSender,
    hooks: &Hooks,
    limits: &TcpLimits,
) -> io::Result<()> {
    // Адрес уже занят другим транспортом (живая UDP-сессия) — соединение не
    // принимаем: иначе кадры той сессии уходили бы в этот TCP-сокет.
    if !(hooks.filter)(peer) {
        let _ = stream.shutdown(Shutdown::Both);
        return Err(io::Error::other("адрес занят другим транспортом"));
    }
    stream.set_nodelay(true)?;
    let tick = READ_TICK
        .min(limits.idle_timeout)
        .max(Duration::from_millis(10));
    stream.set_read_timeout(Some(tick))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let reader_stream = stream.try_clone()?;
    let writer_stream = stream.try_clone()?;
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(limits.queue_len);
    let reg = sender.reg.clone();
    let id = reg.next_id.fetch_add(1, Ordering::Relaxed);
    {
        let mut conns = reg.conns.lock().unwrap();
        let per_ip = conns.keys().filter(|a| a.ip() == peer.ip()).count();
        if conns.len() >= limits.max_conns || per_ip >= limits.max_per_ip {
            let _ = stream.shutdown(Shutdown::Both);
            return Err(io::Error::other("лимит соединений"));
        }
        conns.insert(peer, Conn { id, tx, stream });
    }

    if let Err(e) = thread::Builder::new()
        .name("tcp-writer".into())
        .spawn(move || writer_loop(writer_stream, rx))
    {
        reg.remove_if(peer, id);
        return Err(e);
    }

    let reader_reg = reg.clone();
    let handler = hooks.handler.clone();
    let on_close = hooks.on_close.clone();
    let max_frame = limits.max_frame;
    let idle = limits.idle_timeout;
    let spawned = thread::Builder::new()
        .name("tcp-reader".into())
        .spawn(move || {
            reader_loop(reader_stream, peer, max_frame, idle, &handler);
            // Закрытие: запись реестра сбрасывается вместе с отправителем очереди —
            // писатель выйдет.
            if reader_reg.remove_if(peer, id) {
                on_close(Peer::Tcp(peer));
            }
        });
    if let Err(e) = spawned {
        // Убираем запись: отправитель очереди сброшен, писатель завершится.
        reg.remove_if(peer, id);
        return Err(e);
    }
    Ok(())
}

/// Прочитать ровно `buf.len()` байт. `false` — EOF, ошибка или простой:
/// с последнего целого кадра (`last_frame`) прошло не меньше `idle`.
/// Проверка идёт и посреди кадра, так что медленная «капель» не спасает.
fn read_full(s: &mut TcpStream, buf: &mut [u8], last_frame: Instant, idle: Duration) -> bool {
    let mut off = 0;
    while off < buf.len() {
        match s.read(&mut buf[off..]) {
            Ok(0) => return false,
            Ok(n) => off += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return false,
        }
        if last_frame.elapsed() >= idle {
            return false;
        }
    }
    true
}

/// Читать рамки до ошибки, простоя или нарушения формата.
fn reader_loop(
    mut s: TcpStream,
    peer: SocketAddr,
    max_frame: usize,
    idle: Duration,
    handler: &FrameHandler,
) {
    let mut buf = vec![0u8; max_frame];
    let mut last_frame = Instant::now();
    loop {
        let mut hdr = [0u8; 2];
        if !read_full(&mut s, &mut hdr, last_frame, idle) {
            break; // EOF, простой или ошибка
        }
        let len = u16::from_le_bytes(hdr) as usize;
        if len == 0 || len > max_frame {
            break; // нарушение протокола
        }
        if !read_full(&mut s, &mut buf[..len], last_frame, idle) {
            break;
        }
        last_frame = Instant::now();
        handler(Peer::Tcp(peer), &buf[..len]);
    }
    let _ = s.shutdown(Shutdown::Both);
}

fn writer_loop(mut s: TcpStream, rx: Receiver<Vec<u8>>) {
    let mut out = Vec::with_capacity(2 + DEFAULT_MAX_FRAME);
    while let Ok(frame) = rx.recv() {
        out.clear();
        encode_frame_into(&mut out, &frame);
        if s.write_all(&out).is_err() {
            let _ = s.shutdown(Shutdown::Both);
            break;
        }
    }
}

/// Дописать кадр в рамке в `out`. Паника, если кадр пустой или длиннее u16::MAX
/// (иначе длина обрежется и поток рамок рассинхронизируется).
fn encode_frame_into(out: &mut Vec<u8>, frame: &[u8]) {
    assert!(
        !frame.is_empty() && frame.len() <= u16::MAX as usize,
        "длина кадра TCP должна быть 1..=65535, получено {}",
        frame.len()
    );
    out.extend_from_slice(&(frame.len() as u16).to_le_bytes());
    out.extend_from_slice(frame);
}

/// Обернуть кадр в рамку (для клиентов и тестов).
/// Паника, если кадр пустой или длиннее u16::MAX.
pub fn encode_frame(frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + frame.len());
    encode_frame_into(&mut out, frame);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[test]
    fn фильтр_приёма_закрывает_соединение() {
        use std::sync::atomic::AtomicUsize;
        let hits = Arc::new(AtomicUsize::new(0));
        let h: FrameHandler = {
            let hits = hits.clone();
            Arc::new(move |_p: Peer, _f: &[u8]| {
                hits.fetch_add(1, Ordering::SeqCst);
            })
        };
        let t = TcpTransport::start_filtered(
            loopback(),
            h,
            Arc::new(|_| {}),
            Arc::new(|_| false),
            TcpLimits::default(),
        )
        .unwrap();
        let mut s = TcpStream::connect(t.local_addr()).unwrap();
        let _ = s.write_all(&encode_frame(&[1, 2, 3]));
        assert!(is_closed(&mut s), "соединение не закрыто фильтром");
        assert_eq!(hits.load(Ordering::SeqCst), 0, "кадр дошёл до обработчика");
        assert_eq!(t.sender().conn_count(), 0, "соединение попало в реестр");
    }

    /// Обработчик, складывающий кадры в канал.
    fn collector() -> (FrameHandler, Receiver<(Peer, Vec<u8>)>) {
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let h: FrameHandler = Arc::new(move |a, f: &[u8]| {
            let _ = tx.lock().unwrap().send((a, f.to_vec()));
        });
        (h, rx)
    }

    fn read_frame(s: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut hdr = [0u8; 2];
        s.read_exact(&mut hdr)?;
        let mut body = vec![0u8; u16::from_le_bytes(hdr) as usize];
        s.read_exact(&mut body)?;
        Ok(body)
    }

    /// Сервер закрыл соединение: чтение вернёт EOF или ошибку.
    fn is_closed(s: &mut TcpStream) -> bool {
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut b = [0u8; 1];
        matches!(s.read(&mut b), Ok(0) | Err(_))
    }

    fn wait_until(mut f: impl FnMut() -> bool) -> bool {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(3) {
            if f() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn frames_both_ways() {
        let (h, rx) = collector();
        let t = TcpTransport::start(loopback(), h, TcpLimits::default()).unwrap();
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        c.write_all(&encode_frame(b"TNL2 hello")).unwrap();
        // Две рамки одним write — разбор не должен зависеть от границ TCP.
        let mut two = encode_frame(b"one");
        two.extend(encode_frame(b"two"));
        c.write_all(&two).unwrap();

        let (addr, f) = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(addr, Peer::Tcp(c.local_addr().unwrap()));
        assert_eq!(f, b"TNL2 hello");
        assert_eq!(rx.recv_timeout(Duration::from_secs(3)).unwrap().1, b"one");
        assert_eq!(rx.recv_timeout(Duration::from_secs(3)).unwrap().1, b"two");

        let s = t.sender();
        assert!(s.is_live(addr));
        // Тот же ip:port по UDP — другой клиент, по TCP ему не отвечаем.
        assert!(!s.is_live(Peer::Udp(addr.addr())));
        assert!(!s.send(Peer::Udp(addr.addr()), b"x"));
        assert!(s.send(addr, b"reply"));
        assert!(!s.send(addr, b""), "пустой кадр не отправляется");
        assert!(!s.send(Peer::Tcp("127.0.0.1:1".parse().unwrap()), b"x"));
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        assert_eq!(read_frame(&mut c).unwrap(), b"reply");

        drop(c);
        assert!(
            wait_until(|| !s.is_live(addr)),
            "закрытое соединение убрано из реестра"
        );
    }

    #[test]
    fn close_handler_called_on_eof() {
        let (h, _rx) = collector();
        let (ctx, crx) = mpsc::channel();
        let ctx = Mutex::new(ctx);
        let on_close: CloseHandler = Arc::new(move |p| {
            let _ = ctx.lock().unwrap().send(p);
        });
        let t =
            TcpTransport::start_with_close(loopback(), h, on_close, TcpLimits::default()).unwrap();
        let c = TcpStream::connect(t.local_addr()).unwrap();
        let me = c.local_addr().unwrap();
        assert!(wait_until(|| t.sender().conn_count() == 1));
        drop(c);
        assert_eq!(
            crx.recv_timeout(Duration::from_secs(3)).unwrap(),
            Peer::Tcp(me)
        );
    }

    #[test]
    fn zero_length_closes() {
        let (h, _rx) = collector();
        let t = TcpTransport::start(loopback(), h, TcpLimits::default()).unwrap();
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        c.write_all(&[0, 0]).unwrap();
        assert!(is_closed(&mut c));
        assert!(wait_until(|| t.sender().conn_count() == 0));
    }

    #[test]
    fn oversize_closes() {
        let (h, rx) = collector();
        let limits = TcpLimits {
            max_frame: 100,
            ..TcpLimits::default()
        };
        let t = TcpTransport::start(loopback(), h, limits).unwrap();
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        c.write_all(&101u16.to_le_bytes()).unwrap();
        assert!(is_closed(&mut c));
        assert!(rx.try_recv().is_err());
        assert!(
            !t.sender()
                .send(Peer::Tcp(c.local_addr().unwrap()), &[1u8; 101])
        );
    }

    #[test]
    fn limits_enforced() {
        let (h, _rx) = collector();
        let limits = TcpLimits {
            max_conns: 3,
            max_per_ip: 2,
            ..TcpLimits::default()
        };
        let t = TcpTransport::start(loopback(), h, limits).unwrap();
        let s = t.sender();
        let _a = TcpStream::connect(t.local_addr()).unwrap();
        let _b = TcpStream::connect(t.local_addr()).unwrap();
        assert!(wait_until(|| s.conn_count() == 2));
        // Третье с того же IP — сверх max_per_ip.
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        assert!(is_closed(&mut c));
        assert_eq!(s.conn_count(), 2);
    }

    #[test]
    fn max_conns_enforced() {
        let (h, _rx) = collector();
        let limits = TcpLimits {
            max_conns: 2,
            max_per_ip: 10,
            ..TcpLimits::default()
        };
        let t = TcpTransport::start(loopback(), h, limits).unwrap();
        let s = t.sender();
        let _a = TcpStream::connect(t.local_addr()).unwrap();
        let _b = TcpStream::connect(t.local_addr()).unwrap();
        assert!(wait_until(|| s.conn_count() == 2));
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        assert!(is_closed(&mut c));
        assert_eq!(s.conn_count(), 2);
        // Освободили слот — новое соединение проходит.
        drop(_a);
        assert!(wait_until(|| s.conn_count() == 1));
        let _d = TcpStream::connect(t.local_addr()).unwrap();
        assert!(wait_until(|| s.conn_count() == 2));
    }

    #[test]
    fn idle_timeout_closes() {
        let (h, rx) = collector();
        let limits = TcpLimits {
            // Запас по времени намеренно большой: на macOS SO_RCVTIMEO
            // округляется и планировщик CI дёргает поток с задержкой, из-за
            // чего запись «вовремя» прилетала уже после закрытия (BrokenPipe).
            // Тест про механизм продления, а не про точность таймера.
            idle_timeout: Duration::from_secs(1),
            ..TcpLimits::default()
        };
        let t = TcpTransport::start(loopback(), h, limits).unwrap();
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        // Активность продлевает жизнь соединения.
        for _ in 0..3 {
            thread::sleep(Duration::from_millis(200));
            c.write_all(&encode_frame(b"ping")).unwrap();
        }
        for _ in 0..3 {
            rx.recv_timeout(Duration::from_secs(1)).unwrap();
        }
        assert_eq!(t.sender().conn_count(), 1);
        let started = Instant::now();
        assert!(is_closed(&mut c));
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(wait_until(|| t.sender().conn_count() == 0));
    }

    #[test]
    fn queue_overflow_drops() {
        let (h, rx) = collector();
        let limits = TcpLimits {
            queue_len: 4,
            ..TcpLimits::default()
        };
        let t = TcpTransport::start(loopback(), h, limits).unwrap();
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        c.write_all(&encode_frame(b"hi")).unwrap();
        let (addr, _) = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        // Клиент не читает: буферы сокета заполнятся, затем очередь — и send
        // начнёт возвращать false, не блокируясь.
        let s = t.sender();
        let big = vec![7u8; DEFAULT_MAX_FRAME];
        let started = Instant::now();
        let mut dropped = false;
        for _ in 0..100_000 {
            if !s.send(addr, &big) {
                dropped = true;
                break;
            }
        }
        assert!(dropped, "переполнение очереди должно отбрасывать кадры");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn stop_closes_everything() {
        let (h, _rx) = collector();
        let mut t = TcpTransport::start(loopback(), h, TcpLimits::default()).unwrap();
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        let s = t.sender();
        assert!(wait_until(|| s.conn_count() == 1));
        t.stop();
        assert!(is_closed(&mut c));
        assert_eq!(s.conn_count(), 0);
        assert!(TcpStream::connect_timeout(&t.local_addr(), Duration::from_millis(300)).is_err());
    }

    #[test]
    fn slowloris_closes() {
        let (h, rx) = collector();
        let limits = TcpLimits {
            idle_timeout: Duration::from_millis(400),
            ..TcpLimits::default()
        };
        let t = TcpTransport::start(loopback(), h, limits).unwrap();
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        // Заголовок на 100 байт, затем по байту раз в 100 мс: каждый read
        // успевает до таймаута, но целый кадр так и не приходит.
        c.write_all(&100u16.to_le_bytes()).unwrap();
        let started = Instant::now();
        let closed = loop {
            thread::sleep(Duration::from_millis(100));
            if c.write_all(&[1]).is_err() || started.elapsed() > Duration::from_secs(3) {
                break t.sender().conn_count() == 0;
            }
            if t.sender().conn_count() == 0 {
                break true;
            }
        };
        assert!(closed, "медленная капель не должна держать соединение");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    #[should_panic]
    fn encode_frame_rejects_oversize() {
        let _ = encode_frame(&vec![0u8; u16::MAX as usize + 1]);
    }

    #[test]
    fn encode_frame_max_len() {
        let f = encode_frame(&vec![9u8; u16::MAX as usize]);
        assert_eq!(&f[..2], &u16::MAX.to_le_bytes());
        assert_eq!(f.len(), 2 + u16::MAX as usize);
    }
}
