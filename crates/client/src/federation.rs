//! Федерация серверов на стороне клиента (T4).
//!
//! Кадры 0x40..=0x4F — сервер ↔ сервер: клиенту они не адресованы, но
//! `dispatch` обязан их разбирать безопасно (иначе незнакомый кадр ушёл бы в
//! ctrl-разбор и вызвал `RESET`). Клиентская часть федерации —
//! `FED_GROUPS` (0x95) и `JOIN_FED` (0x19) — реализуется в T4.

use std::net::SocketAddr;

/// Входящий федеративный кадр (0x40..=0x4F). `false` — не обработан (клиент
/// такие кадры молча роняет; серверные — в `crates/server/src/federation.rs`).
pub fn on_frame(_src: SocketAddr, _typ: u8, _body: &[u8]) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn клиент_не_обрабатывает_федеративные_кадры() {
        let src: SocketAddr = "203.0.113.5:5555".parse().unwrap();
        for typ in 0x40u8..=0x4F {
            assert!(!on_frame(src, typ, &[]));
            assert!(!on_frame(src, typ, &[0xAA; 64]));
        }
    }
}