//! Клиент туннеля (протокол v3) как библиотека: движок, хранилище, TUI и
//! вспомогательные модули. CLI (`main.rs`) и другие крейты (daemon, tray)
//! используют их через `tunnel_client::…`.

pub mod api;
pub mod dht;
pub mod dns;
pub mod engine;
#[cfg(test)]
mod engine_e2e;
pub mod federation;
pub mod friends;
pub mod invites;
pub mod ipv6;
/// Mesh-подсистема (L2) — каркас T3.
pub mod mesh;
#[cfg(test)]
mod mesh_e2e;
/// Офлайн-TUI: движка нет — конфиг правится локально, очередь `ui-pending`.
pub mod offline;
pub mod path;
/// Проба сервера (PROBE_REQ/RESP) — каркас T2.
pub mod probe;
pub mod profile;
pub mod remote;
pub mod remote_cli;
pub mod snapshot;
pub mod store;
pub mod tcp_link;
// Wintun — только Windows; на Linux/macOS — tun_linux / tun_macos.
pub mod tui;
#[cfg(windows)]
pub mod tun;
#[cfg(target_os = "linux")]
pub mod tun_linux;
#[cfg(target_os = "macos")]
pub mod tun_macos;
