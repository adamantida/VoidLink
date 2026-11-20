//! IPC между демоном (`tunnel-daemon`) и фронтендами (TUI, трей, CLI) — этап 7.2.
//!
//! - [`proto`] — сообщения `ClientMsg` / `DaemonMsg`. Команды, события, снимки
//!   и `me` — `serde_json::Value`, чтобы крейт не зависел от движка.
//! - [`codec`] — фрейм `u32 LE длина | JSON`, лимит 1 МиБ; битые данные — ошибка,
//!   не паника.
//! - [`transport`] — `Listener::bind(name)` → `accept()` → [`Conn`]; `connect(name)`.
//!   Unix — сокет `0600`, Windows — named pipe с явным SDDL и проверкой, что
//!   сервер пайпа — служба (SYSTEM) или демон от администратора того же
//!   пользователя ([`transport::decide_trust`]).
//! - [`lock`] — single-instance замок движка (демон, embedded TUI, `run`).
//! - [`client`] — блокирующий [`IpcClient`] (Hello, Subscribe, Req с таймаутом)
//!   для TUI, трея и CLI.
// подключается при интеграции
#![allow(dead_code)]

pub mod client;
pub mod codec;
pub mod lock;
pub mod proto;
pub mod transport;

pub use client::{ClientError, IpcClient};
pub use codec::{CodecError, MAX_FRAME, read_msg, write_msg};
pub use lock::{InstanceLock, LockError};
pub use proto::{AckResult, ClientKind, ClientMsg, DaemonMsg, PROTO_VERSION, check_hello};
pub use transport::{Conn, Listener, connect};
