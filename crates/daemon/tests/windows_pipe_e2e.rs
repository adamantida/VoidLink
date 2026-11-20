//! Демон целиком (замок, лог, хаб, IPC-сервер) поверх настоящего named pipe в
//! режиме `console`: владелец объекта — Administrators, доступ — SID
//! запустившего пользователя (SECURITY.md §13).
//!
//! Служба не нужна, но нужен администратор: `O:BA` без повышения не поставить.
//! Без повышения тест пропускается, а не падает.
#![cfg(windows)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::json;
use tunnel_daemon::{FakeBackend, IpcMode, RunOpts, run_daemon};
use tunnel_ipc::transport::{PipeOwner, current_user_sid, is_elevated};
use tunnel_ipc::{AckResult, ClientError, ClientKind, DaemonMsg, IpcClient};

const T: Duration = Duration::from_secs(5);

/// Замок движка на Windows один на машину (`Global\TunnelEngine`), поэтому
/// тесты этого файла идут по очереди — иначе второй демон не поднимется.
static ENGINE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn engine_guard() -> std::sync::MutexGuard<'static, ()> {
    ENGINE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Уникальное имя пайпа (тесты идут параллельно в одном процессе).
fn pipe_name() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\vl-daemon-test-{}-{n}", std::process::id())
}

/// Свежий каталог данных.
fn data_dir() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("tde-w-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

struct Daemon {
    dir: PathBuf,
    name: String,
    backend: FakeBackend,
    stop: Arc<AtomicBool>,
    th: Option<JoinHandle<Result<(), String>>>,
}

impl Daemon {
    /// `None` — тест не применим (нет прав администратора или замок занят
    /// другим движком: например, у вас запущен `tunnel-daemon console`).
    fn start() -> Option<Daemon> {
        if !is_elevated().unwrap_or(false) {
            eprintln!("пропуск: нужен запуск от администратора (владелец пайпа O:BA)");
            return None;
        }
        let sid = current_user_sid().expect("SID текущего пользователя");
        let dir = data_dir();
        let name = pipe_name();
        let backend = FakeBackend::new();
        let stop = Arc::new(AtomicBool::new(false));
        let opts = RunOpts {
            data_dir: dir.clone(),
            debug: true,
            console_log: false,
            ipc: IpcMode::Pipe {
                name: name.clone(),
                owner_sid: Some(sid),
                owner: PipeOwner::Administrators,
            },
            stop_reason: "тест окончен".into(),
        };
        let (b, s) = (backend.clone(), stop.clone());
        let th = std::thread::spawn(move || run_daemon(&opts, move |_| b, s));
        let mut d = Daemon {
            dir,
            name,
            backend,
            stop,
            th: Some(th),
        };
        // Ждём, пока пайп начнёт принимать.
        let t0 = Instant::now();
        loop {
            if d.th.as_ref().is_some_and(|t| t.is_finished()) {
                let err = d.th.take().unwrap().join().unwrap().unwrap_err();
                let _ = std::fs::remove_dir_all(&d.dir);
                if err.contains("уже запущен") {
                    eprintln!("пропуск: {err}");
                    return None;
                }
                panic!("демон не поднялся: {err}");
            }
            match IpcClient::connect(&d.name, ClientKind::Cli, "probe", T) {
                Ok(c) => {
                    c.bye();
                    return Some(d);
                }
                Err(_) if t0.elapsed() < T => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => panic!("пайп не поднялся: {e}"),
            }
        }
    }

    fn alive(&self) -> bool {
        !self.th.as_ref().unwrap().is_finished()
    }

    fn client(&self) -> IpcClient {
        IpcClient::connect(&self.name, ClientKind::Tui, "test", T).expect("подключение")
    }

    fn stop(mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::SeqCst);
        let r = self.th.take().unwrap().join().unwrap();
        let _ = std::fs::remove_dir_all(&self.dir);
        r
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.th.take() {
            let _ = t.join();
        }
    }
}

/// Ждать сообщение, подходящее под `pred`, не дольше [`T`].
fn wait_for(c: &mut IpcClient, what: &str, mut pred: impl FnMut(&DaemonMsg) -> bool) -> DaemonMsg {
    let deadline = Instant::now() + T;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match c.recv(Some(left)) {
            Ok(m) if pred(&m) => return m,
            Ok(_) => {}
            Err(ClientError::Timeout) => panic!("ждали {what}: таймаут"),
            Err(e) => panic!("ждали {what}: {e}"),
        }
    }
}

#[test]
fn console_пайп_отдаёт_снимок_и_принимает_команды() {
    let _engine = engine_guard();
    let Some(d) = Daemon::start() else {
        return;
    };
    let mut c = d.client();
    c.subscribe(0).unwrap();
    // Хаб присылает снимок сразу после подписки.
    let DaemonMsg::Snapshot { snap, .. } = wait_for(&mut c, "снимок", |m| {
        matches!(m, DaemonMsg::Snapshot { .. })
    }) else {
        unreachable!()
    };
    assert!(snap.is_object(), "снимок не объект: {snap}");
    // Событие бэкенда доезжает подписчику (хаб раздаёт его на такте).
    d.backend.push_event(json!({ "Notice": "тест" }));
    wait_for(
        &mut c,
        "событие Notice",
        |m| matches!(m, DaemonMsg::Event { ev, .. } if ev["Notice"] == json!("тест")),
    );
    // FakeBackend принимает RefreshList и отвечает Ack Ok.
    c.send_req(json!("RefreshList")).unwrap();
    wait_for(&mut c, "Ack", |m| {
        matches!(
            m,
            DaemonMsg::Ack {
                result: AckResult::Ok,
                ..
            }
        )
    });
    assert!(d.alive(), "демон не должен был завершиться");
    d.stop().unwrap();
}

#[test]
fn после_остановки_пайп_исчезает() {
    let _engine = engine_guard();
    let Some(d) = Daemon::start() else {
        return;
    };
    let name = d.name.clone();
    d.stop().unwrap();
    // Демон остановлен — имя пайпа освобождено, подключиться нельзя.
    match IpcClient::connect(&name, ClientKind::Tui, "test", Duration::from_millis(500)) {
        Ok(_) => panic!("пайп остался после остановки демона"),
        Err(ClientError::Connect(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
        }
        Err(e) => panic!("неожиданная ошибка: {e}"),
    }
}
