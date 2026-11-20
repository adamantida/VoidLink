//! Транспорт: локальное потоковое соединение без async-рантайма.
//!
//! `Listener::bind(name)` → `accept()` → [`Conn`] (`Read + Write`,
//! `try_clone()` — отдельные половины для потоков чтения и записи);
//! [`connect`]`(name)` — клиент. На Unix `name` — путь сокета, на Windows —
//! имя пайпа ([`DEFAULT_PIPE_NAME`]).

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{Conn, Listener, cleanup_stale, connect};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{
    Conn, Listener, PipeOwner, ServerFacts, Trust, connect, current_user_sid, decide_trust,
    is_elevated, pipe_sddl,
};

/// Имя пайпа демона по умолчанию (Windows).
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\tunnel-daemon";

/// Имя файла сокета в каталоге данных (Unix).
pub const DEFAULT_SOCKET_FILE: &str = "daemon.sock";
