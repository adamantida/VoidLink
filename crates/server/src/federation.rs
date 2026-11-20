//! Федерация серверов (сервер ↔ сервер), §3.5 плана этапа 9.
//!
//! T1 — каркас: точки входа для кадров 0x40..=0x4F и для `SERVER_HINT` /
//! `JOIN_FED`, чтобы `lib.rs` уже разбирал их безопасно и T4 не переписывал
//! общий код. Реальные рукопожатия `SRV_HELLO`/`SRV_HELLO_ACK`, TOFU-пиннинг
//! в `server.json`, репликация групп/адресов и `FED_RELAY` — T4.
//!
//! Номера кадров — `tunnel_protocol::federation`; здесь только поведение.
//! Необработанный кадр — молча отбросить: сервер не должен отвечать `RESET`
//! чужому серверу.

use std::net::SocketAddr;

use tunnel_protocol::federation;
use tunnel_protocol::payloads::ServerHint;

use crate::Shared;

/// Входящий федеративный кадр (0x40..=0x4F). `true` — обработан.
///
/// T4: `SRV_HELLO`/`ACK` (подпись + TOFU), `FED_GROUP_PUSH/DELTA`,
/// `FED_ADDR_PUSH/REVOKE`, `FED_RELAY`. Пока — ничего; вызывающий роняет
/// кадр молча (без `RESET` и без лога).
pub(crate) fn on_frame(_sh: &Shared, _src: SocketAddr, typ: u8, _body: &[u8]) -> bool {
    let _ = federation::is_fed(typ); // T4: ветвление по типу
    false
}

/// `SERVER_HINT` от клиента: кандидаты-серверы. Сервер им **не доверяет** —
/// на каждого кандидата T4 пошлёт `SRV_HELLO` и сверит ключ с заявленным.
///
/// T1: формат уже проверен декодером, кандидаты принимаются молча (лог —
/// чтобы пилот T4 видел входящие подсказки).
pub(crate) fn on_hint(sh: &Shared, from: &[u8; 32], hints: &[ServerHint]) {
    if hints.is_empty() {
        return;
    }
    if !sh.quiet {
        sh.log(format!(
            "hint: {} от {} — федерация появится в T4",
            hints.len(),
            crate::short(from)
        ));
    }
}

/// `JOIN_FED` от клиента: вход в федерированную группу по uuid. T4 вернёт
/// обычный `GROUP_STATE`; пока — честная ошибка (клиент T1 его не шлёт).
pub(crate) fn on_join_fed(_sh: &Shared, _from: &[u8; 32], _uuid: &[u8]) -> anyhow::Result<()> {
    anyhow::bail!("вход в федерированную группу ещё не реализован (T4)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn диапазон_федеративных_кадров() {
        assert!(federation::is_fed(federation::SRV_HELLO));
        assert!(federation::is_fed(federation::FED_RELAY));
        assert!(!federation::is_fed(0x3F) && !federation::is_fed(0x50));
    }
}
