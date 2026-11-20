//! IPC-сервер демона (PLAN.md 7.2/7.3): `Listener` → поток на соединение.
//!
//! Соединение:
//! - первым должен прийти `Hello`: версия совпала — `Welcome{me}`, иначе
//!   `Reject` и закрытие; любое другое первое сообщение — тоже `Reject`;
//! - `Subscribe` — подписка в хабе: история из кольца (`Event`), снимок на
//!   момент подписки (`Snapshot`), дальше живой поток с `seq`. Пишет его
//!   отдельный поток соединения, так что медленный клиент тормозит только
//!   свою запись: хаб шлёт через `try_send` и при переполнении даёт пропуск;
//! - `Req{id, cmd}` → `Backend::send` → `Ack{id, Ok|Err}`;
//! - `Bye`, разрыв, мусор, фрейм больше лимита, повторный `Hello` —
//!   закрытие только этого соединения; подписка уходит вместе с ним, движок
//!   ничего не замечает;
//! - остановка демона: `Shutdown{reason}` всем (не дольше [`SHUTDOWN_GRACE`]),
//!   затем разрыв всех соединений.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tunnel_ipc::{
    AckResult, ClientMsg, CodecError, Conn, DaemonMsg, Listener, PROTO_VERSION, check_hello,
    read_msg, write_msg,
};

use crate::hub::{Backend, DEFAULT_QUEUE, Hub, HubMsg, Subscription, TICK};
use crate::log::{Level, LogFn};

/// Сколько ждать `Hello` от нового соединения (Unix; у пайпа таймаутов нет).
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Запись, застрявшая дольше этого, — клиент мёртв, соединение рвётся (Unix).
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Сколько ждать доставки `Shutdown` перед разрывом всех соединений.
pub const SHUTDOWN_GRACE: Duration = Duration::from_millis(500);
/// Как часто поток подписки проверяет, не закрыто ли соединение.
const POLL: Duration = Duration::from_millis(100);

/// Версия демона в `Welcome`.
pub const DAEMON_VER: &str = env!("CARGO_PKG_VERSION");

/// Живое соединение (для `Shutdown` и разрыва при остановке).
struct Entry {
    /// Половина только для `shutdown()`.
    ctl: Conn,
    writer: Arc<Mutex<Conn>>,
    thread: Option<JoinHandle<()>>,
}

struct Shared {
    stop: AtomicBool,
    conns: Mutex<HashMap<u64, Entry>>,
    next_id: AtomicU64,
    log: Option<LogFn>,
}

impl Shared {
    fn log(&self, level: Level, msg: &str) {
        if let Some(l) = &self.log {
            l(level, msg);
        }
    }

    fn conns(&self) -> MutexGuard<'_, HashMap<u64, Entry>> {
        self.conns.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Запущенный IPC-сервер. Остановка — [`IpcServer::shutdown`] (drop без
/// неё тоже рвёт соединения, но без `Shutdown`-сообщения).
pub struct IpcServer {
    shared: Arc<Shared>,
    accept: Option<JoinHandle<()>>,
    /// Разбудить `accept` (подключиться к себе).
    wake: Box<dyn Fn() + Send + Sync>,
}

impl IpcServer {
    /// Запустить приём соединений на `listener`. `wake` должен разбудить
    /// заблокированный `accept` (обычно — подключиться к своему же адресу).
    pub fn start<B: Backend + 'static>(
        hub: Arc<Hub<B>>,
        listener: Listener,
        log: Option<LogFn>,
        wake: impl Fn() + Send + Sync + 'static,
    ) -> io::Result<IpcServer> {
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            conns: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            log,
        });
        let sh = shared.clone();
        let accept = std::thread::Builder::new()
            .name("ipc-accept".into())
            .spawn(move || accept_loop(hub, listener, sh))?;
        Ok(IpcServer {
            shared,
            accept: Some(accept),
            wake: Box::new(wake),
        })
    }

    /// Unix: сокет `<data_dir>/daemon.sock`. Каталог данных создаётся (или
    /// закрывается) с правами `0700`, устаревший сокет удаляется. Вызывать
    /// только под замком демона ([`crate::InstanceLock`]).
    #[cfg(unix)]
    pub fn start_unix<B: Backend + 'static>(
        hub: Arc<Hub<B>>,
        data_dir: &std::path::Path,
        log: Option<LogFn>,
    ) -> io::Result<IpcServer> {
        let path = socket_path(data_dir);
        prepare_private_dir(data_dir, log.as_ref())?;
        match tunnel_ipc::transport::cleanup_stale(&path) {
            Ok(true) => {
                if let Some(l) = &log {
                    l(
                        Level::Warn,
                        &format!("удалён устаревший сокет {}", path.display()),
                    );
                }
            }
            Ok(false) => {}
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("сокет {}: {e}", path.display()),
                ));
            }
        }
        let listener = Listener::bind(&path)
            .map_err(|e| io::Error::new(e.kind(), format!("сокет {}: {e}", path.display())))?;
        if let Some(l) = &log {
            l(Level::Info, &format!("IPC: сокет {}", path.display()));
        }
        Self::start(hub, listener, log, move || {
            let _ = tunnel_ipc::connect(&path);
        })
    }

    /// Windows (только служба, PLAN.md 7.2): пайп `name` с SDDL из SID
    /// владельца, записанного при установке.
    #[cfg(windows)]
    pub fn start_pipe<B: Backend + 'static>(
        hub: Arc<Hub<B>>,
        name: &str,
        owner: tunnel_ipc::transport::PipeOwner,
        client_sid: Option<&str>,
        log: Option<LogFn>,
    ) -> io::Result<IpcServer> {
        let listener = Listener::bind_with_owner(name, owner, client_sid)?;
        if let Some(l) = &log {
            l(Level::Info, &format!("IPC: пайп {name}"));
        }
        let name = name.to_string();
        Self::start(hub, listener, log, move || {
            let _ = tunnel_ipc::connect(&name);
        })
    }

    /// Сколько соединений сейчас открыто.
    pub fn clients(&self) -> usize {
        self.shared.conns().len()
    }

    /// `Shutdown{reason}` всем клиентам, разрыв соединений, остановка приёма.
    pub fn shutdown(mut self, reason: &str) {
        self.stop_all(Some(reason));
    }

    fn stop_all(&mut self, reason: Option<&str>) {
        if self.shared.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        // Приём — будим и ждём недолго (если разбудить не вышло, поток
        // останется висеть в accept до конца процесса — это не страшно).
        (self.wake)();
        if let Some(h) = self.accept.take() {
            wait_or_detach(h, Duration::from_secs(1));
        }
        let entries: Vec<Entry> = self.shared.conns().drain().map(|(_, e)| e).collect();
        if let Some(reason) = reason {
            // Пишем из отдельных потоков: застрявший клиент не держит остальных.
            let senders: Vec<_> = entries
                .iter()
                .map(|e| {
                    let w = e.writer.clone();
                    let msg = DaemonMsg::Shutdown {
                        reason: reason.to_string(),
                    };
                    std::thread::spawn(move || {
                        let mut w = w.lock().unwrap_or_else(|e| e.into_inner());
                        let _ = write_msg(&mut *w, &msg);
                    })
                })
                .collect();
            let deadline = Instant::now() + SHUTDOWN_GRACE;
            while Instant::now() < deadline && !senders.iter().all(|s| s.is_finished()) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        for e in &entries {
            let _ = e.ctl.shutdown();
        }
        for mut e in entries {
            if let Some(h) = e.thread.take() {
                wait_or_detach(h, Duration::from_secs(2));
            }
        }
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.stop_all(None);
    }
}

fn wait_or_detach(h: JoinHandle<()>, max: Duration) {
    let t0 = Instant::now();
    while !h.is_finished() && t0.elapsed() < max {
        std::thread::sleep(Duration::from_millis(5));
    }
    if h.is_finished() {
        let _ = h.join();
    }
}

/// Путь сокета демона в каталоге данных.
#[cfg(unix)]
pub fn socket_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join(tunnel_ipc::transport::DEFAULT_SOCKET_FILE)
}

/// Каталог данных: создать с `0700` или закрыть существующий (если он наш) —
/// иначе `Listener::bind` откажет. Чужой каталог не трогаем. Вызывается и
/// в начале [`crate::run_daemon`] — до замка и до записи `client.json`.
#[cfg(unix)]
pub(crate) fn prepare_private_dir(dir: &std::path::Path, log: Option<&LogFn>) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let md = std::fs::metadata(dir)?;
    // SAFETY: geteuid не имеет предусловий.
    let uid = unsafe { libc::geteuid() };
    if md.is_dir() && md.uid() == uid && md.mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        if let Some(l) = log {
            l(
                Level::Warn,
                &format!(
                    "права каталога {} изменены на 0700 (было {:o})",
                    dir.display(),
                    md.mode() & 0o777
                ),
            );
        }
    }
    Ok(())
}

fn accept_loop<B: Backend + 'static>(hub: Arc<Hub<B>>, listener: Listener, sh: Arc<Shared>) {
    let mut errors = 0u32;
    loop {
        let conn = listener.accept();
        if sh.stop.load(Ordering::SeqCst) {
            return;
        }
        let conn = match conn {
            Ok(c) => {
                errors = 0;
                c
            }
            Err(e) => {
                errors += 1;
                if errors <= 3 {
                    sh.log(Level::Warn, &format!("IPC accept: {e}"));
                }
                // Не крутимся вхолостую на постоянной ошибке.
                std::thread::sleep(Duration::from_millis(50 * u64::from(errors.min(20))));
                continue;
            }
        };
        if let Err(e) = spawn_conn(&hub, conn, &sh) {
            sh.log(Level::Warn, &format!("IPC: соединение не принято: {e}"));
        }
    }
}

fn spawn_conn<B: Backend + 'static>(
    hub: &Arc<Hub<B>>,
    conn: Conn,
    sh: &Arc<Shared>,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        conn.set_read_timeout(Some(HELLO_TIMEOUT))?;
        conn.set_write_timeout(Some(WRITE_TIMEOUT))?;
    }
    let id = sh.next_id.fetch_add(1, Ordering::Relaxed);
    let ctl = conn.try_clone()?;
    let writer = Arc::new(Mutex::new(conn.try_clone()?));
    let mut conns = sh.conns();
    let (hub, sh2, w) = (hub.clone(), sh.clone(), writer.clone());
    let thread = std::thread::Builder::new()
        .name(format!("ipc-conn-{id}"))
        .spawn(move || {
            let mut c = Session {
                id,
                hub,
                reader: conn,
                writer: w,
                sh: sh2.clone(),
                closed: Arc::new(AtomicBool::new(false)),
                forwarder: None,
            };
            c.run();
            c.close();
            sh2.conns().remove(&id);
        })?;
    conns.insert(
        id,
        Entry {
            ctl,
            writer,
            thread: Some(thread),
        },
    );
    Ok(())
}

struct Session<B: Backend> {
    id: u64,
    hub: Arc<Hub<B>>,
    reader: Conn,
    writer: Arc<Mutex<Conn>>,
    sh: Arc<Shared>,
    /// Соединение закрывается — поток подписки выходит.
    closed: Arc<AtomicBool>,
    forwarder: Option<JoinHandle<()>>,
}

impl<B: Backend + 'static> Session<B> {
    fn send(&self, m: &DaemonMsg) -> Result<(), CodecError> {
        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        write_msg(&mut *w, m)
    }

    fn run(&mut self) {
        let id = self.id;
        match read_msg::<_, ClientMsg>(&mut self.reader) {
            Ok(ClientMsg::Hello { proto, kind, ver }) => {
                if let Err(rej) = check_hello(proto) {
                    self.sh.log(
                        Level::Warn,
                        &format!(
                            "IPC {id}: {kind:?} {ver}: версия {proto} ≠ {PROTO_VERSION}, отказ"
                        ),
                    );
                    let _ = self.send(&rej);
                    return;
                }
                self.sh
                    .log(Level::Debug, &format!("IPC {id}: {kind:?} {ver} подключён"));
                let welcome = DaemonMsg::Welcome {
                    proto: PROTO_VERSION,
                    daemon_ver: DAEMON_VER.into(),
                    me: self.hub.me(),
                };
                if self.send(&welcome).is_err() {
                    return;
                }
            }
            Ok(other) => {
                self.sh.log(
                    Level::Warn,
                    &format!("IPC {id}: первым пришло не Hello ({other:?}), закрываю"),
                );
                let _ = self.send(&DaemonMsg::Reject {
                    reason: "первым сообщением должен быть Hello".into(),
                });
                return;
            }
            Err(e) => {
                self.sh
                    .log(Level::Debug, &format!("IPC {id}: до Hello: {e}"));
                return;
            }
        }
        #[cfg(unix)]
        if self.reader.set_read_timeout(None).is_err() {
            return;
        }
        loop {
            match read_msg::<_, ClientMsg>(&mut self.reader) {
                Ok(ClientMsg::Req { id: rid, cmd }) => {
                    let result = match self.hub.send(cmd) {
                        Ok(()) => AckResult::Ok,
                        Err(e) => AckResult::Err(e),
                    };
                    if self.send(&DaemonMsg::Ack { id: rid, result }).is_err() {
                        return;
                    }
                }
                Ok(ClientMsg::Subscribe { snapshots_ms }) => {
                    if self.forwarder.is_some() {
                        self.sh.log(
                            Level::Debug,
                            &format!("IPC {id}: повторный Subscribe — игнорирую"),
                        );
                        continue;
                    }
                    let sub = self.hub.subscribe(DEFAULT_QUEUE);
                    let fw = Forwarder {
                        writer: self.writer.clone(),
                        closed: self.closed.clone(),
                        stop_conn: self.reader.try_clone().ok(),
                        snap_every: Duration::from_millis(u64::from(snapshots_ms)),
                    };
                    match std::thread::Builder::new()
                        .name(format!("ipc-sub-{id}"))
                        .spawn(move || fw.run(sub))
                    {
                        Ok(h) => self.forwarder = Some(h),
                        Err(e) => {
                            self.sh
                                .log(Level::Warn, &format!("IPC {id}: поток подписки: {e}"));
                            return;
                        }
                    }
                }
                Ok(ClientMsg::Bye) => {
                    self.sh.log(Level::Debug, &format!("IPC {id}: Bye"));
                    return;
                }
                Ok(ClientMsg::Hello { .. }) => {
                    self.sh
                        .log(Level::Warn, &format!("IPC {id}: повторный Hello, закрываю"));
                    return;
                }
                Err(CodecError::Closed) => {
                    self.sh.log(Level::Debug, &format!("IPC {id}: отключился"));
                    return;
                }
                Err(e) => {
                    if !self.closed.load(Ordering::SeqCst) && !self.sh.stop.load(Ordering::SeqCst) {
                        self.sh
                            .log(Level::Warn, &format!("IPC {id}: {e}, закрываю"));
                    }
                    return;
                }
            }
        }
    }

    /// Закрыть соединение и дождаться потока подписки (её drop — отписка).
    fn close(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        let _ = self.reader.shutdown();
        if let Some(h) = self.forwarder.take() {
            let _ = h.join();
        }
    }
}

/// Поток записи подписки.
struct Forwarder {
    writer: Arc<Mutex<Conn>>,
    closed: Arc<AtomicBool>,
    /// Ошибка записи — разорвать соединение (разбудить поток чтения).
    stop_conn: Option<Conn>,
    /// Минимальный период снимков без пропусков (`snapshots_ms`).
    snap_every: Duration,
}

impl Forwarder {
    fn write(&self, m: &DaemonMsg) -> bool {
        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        write_msg(&mut *w, m).is_ok()
    }

    fn run(self, sub: Subscription) {
        if !self.stream(&sub) {
            self.closed.store(true, Ordering::SeqCst);
            if let Some(c) = &self.stop_conn {
                let _ = c.shutdown();
            }
        }
        // drop(sub): хаб уберёт подписчика на следующей рассылке.
    }

    /// `false` — запись не удалась.
    fn stream(&self, sub: &Subscription) -> bool {
        for (seq, ev) in &sub.history {
            if !self.write(&DaemonMsg::Event {
                seq: *seq,
                ev: (**ev).clone(),
            }) {
                return false;
            }
        }
        // `sent_seq` — последнее событие, известное клиенту (для отсева
        // повторов); `snap_seq` — последнее событие, учтённое в отправленном
        // снимке. Это разные вещи: событие клиент уже видел, а состояние
        // после него — ещё нет.
        let (mut snap_seq, snap) = (sub.snapshot.0, &sub.snapshot.1);
        let mut sent_seq = sub
            .history
            .last()
            .map_or(snap_seq, |(q, _)| snap_seq.max(*q));
        if !self.write(&DaemonMsg::Snapshot {
            seq: snap_seq,
            snap: (**snap).clone(),
        }) {
            return false;
        }
        let mut last_snap = Instant::now();
        while !self.closed.load(Ordering::SeqCst) {
            let msg = match sub.rx.recv_timeout(POLL) {
                Ok(m) => m,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return true,
            };
            let out = match msg {
                HubMsg::Event { seq, ev } => {
                    if seq <= sent_seq {
                        continue; // уже покрыто снимком подписки
                    }
                    sent_seq = seq;
                    DaemonMsg::Event {
                        seq,
                        ev: (*ev).clone(),
                    }
                }
                HubMsg::Snapshot { seq, snap } => {
                    // Снимок с новыми событиями (seq впереди отправленного
                    // снимка) несёт их итог в состоянии — шлём всегда;
                    // периодические без новых событий — не чаще `snapshots_ms`
                    // (с допуском в такт хаба: его период равен нашему).
                    if seq <= snap_seq && last_snap.elapsed() + TICK < self.snap_every {
                        continue;
                    }
                    snap_seq = snap_seq.max(seq);
                    sent_seq = sent_seq.max(seq);
                    last_snap = Instant::now();
                    DaemonMsg::Snapshot {
                        seq,
                        snap: (*snap).clone(),
                    }
                }
            };
            if !self.write(&out) {
                return false;
            }
        }
        true
    }
}
