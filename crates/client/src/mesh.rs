//! Mesh-подсистема клиента (L2: релей через участников, §3.2/§3.4).
//!
//! T1 — каркас: [`MeshState`], ветка входящих кадров ([`on_frame`]) и исходящих
//! ([`send_frame`]). Сессии, ключи, RPC (`MESH_PING`, `MESH_FIND_NODE`,
//! `MESH_ROUTE`, `MESH_FORWARD`) и учёт лимитов реле — T3. Форматы кадров и
//! криптография рукопожатия уже в `tunnel_protocol::mesh`.
//!
//! Кадры 0x30..=0x3F пир ↔ пир: `dispatch` отдаёт их сюда **до** проверки
//! «только от сервера» (mesh-пир сервером не является), а молчание/`false`
//! означает «кадр отброшен» — как у старых клиентов (§4.3), без ошибок и
//! `RESET`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

/// Состояние mesh-клиента. T3 добавит сюда сессии (ed → ключи/счётчики),
/// таблицу реле и статистику.
#[derive(Debug, Default)]
pub struct MeshState {
    /// Mesh включён (конфиг `mesh.enabled` / `Cmd::SetMeshEnabled`).
    enabled: AtomicBool,
}

impl MeshState {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }
}

/// Входящий mesh-кадр (0x30..=0x3F). `true` — кадр обработан.
///
/// T3: рукопожатия и RPC. Пока кадры не поддерживаются — `false`, вызывающий
/// молча роняет кадр (совместимость с v4-пирами, §4.3).
pub fn on_frame(_st: &MeshState, _src: SocketAddr, _typ: u8, _body: &[u8]) -> bool {
    false
}

/// Собрать исходящий mesh-кадр (рукопожатие/RPC). `None` — T1: отправлять
/// пока нечего; T3 заполнит.
pub fn send_frame(_st: &MeshState, _to: SocketAddr, _typ: u8, _payload: &[u8]) -> Option<Vec<u8>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_protocol::{ctrl, federation, mesh};

    #[test]
    fn каркас_безопасен_для_любых_кадров() {
        let st = MeshState::new(true);
        assert!(st.enabled());
        st.set_enabled(false);
        assert!(!st.enabled());
        let src: SocketAddr = "203.0.113.5:4000".parse().unwrap();
        // Ни один вход не паникует и не «обрабатывается» до T3.
        for typ in 0x30u8..=0x3F {
            assert!(!on_frame(&st, src, typ, &[]));
            assert!(!on_frame(&st, src, typ, &[0xFF; 200]));
            assert!(send_frame(&st, src, typ, &[1, 2, 3]).is_none());
        }
        // Диапазоны не пересекаются: mesh — не ctrl и не федерация.
        for typ in 0x30u8..=0x3F {
            assert!(mesh::is_mesh(typ));
            assert!(!ctrl::is_plaintext(typ));
            assert!(!federation::is_fed(typ));
        }
    }
}
