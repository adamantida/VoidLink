//! Проба доступности сервера (§3.7 плана этапа 9).
//!
//! `PROBE_REQ`/`PROBE_RESP` ходят **открытым текстом** и не требуют сессии:
//! пробу можно запускать для любого сервера из списка (в том числе
//! недоступного), не ломая текущую сессию. Сервер отвечает не длиннее
//! запроса и не создаёт сессию.
//!
//! T1: разбор ответа и сверка ключа готовы, отправка запроса — T2
//! (`start_probe` пока возвращает ошибку «не реализовано»; никаких `todo!()`
//! в проде). Форматы — `payloads::enc_probe_req/enc_probe_resp`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{Result, bail};
use tunnel_protocol::payloads::{self, PROBE_NONCE_LEN};

/// Результат пробы: доступен/недоступен, RTT и совпадение ключа сервера с
/// закреплённым.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeResult {
    pub addr: SocketAddr,
    pub rtt_ms: Option<u32>,
    /// Ключ, который вернул сервер (если просили и он вернул).
    pub key: Option<[u8; 32]>,
    /// Совпал ли ключ с закреплённым. `None` — сверять не с чем (ключ не
    /// просили, сервер его не вернул или пин отсутствует).
    pub key_match: Option<bool>,
}

/// Ожидаемая проба.
#[derive(Debug)]
struct Pending {
    started: Instant,
    /// Закреплённый ключ сервера (для сверки); `None` — не закреплён.
    pinned: Option<[u8; 32]>,
}

/// Состояние проб: ожидающие ответа nonce'ы. Держится под `Arc` в `Env`.
#[derive(Debug, Default)]
pub struct ProbeState {
    pending: Mutex<HashMap<[u8; PROBE_NONCE_LEN], Pending>>,
}

impl ProbeState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Сколько проб ждёт ответа (диагностика/тесты).
    pub fn pending(&self) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Начать пробу сервера. T2: сгенерировать nonce/ts, запомнить ожидание,
    /// вернуть готовый кадр `PROBE_REQ` (открытым текстом) для отправки.
    ///
    /// Пока — честная ошибка «не реализовано»: движок превращает её в
    /// `Event::ProbeResult { success: false }`, а не роняет поток.
    pub fn start_probe(&self, _addr: SocketAddr, _now_ms: u64) -> Result<Vec<u8>> {
        bail!("проба сервера ещё не реализована (T2)")
    }

    /// Ответ `PROBE_RESP` от `src` (открытым текстом). `None` — не наша проба,
    /// битый или уже отвеченный ответ. Никогда не паникует: формат с сервера
    /// не доверенный.
    pub fn on_response(&self, src: SocketAddr, body: &[u8]) -> Option<ProbeResult> {
        let resp = payloads::dec_probe_resp(body).ok()?;
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let p = pending.remove(&resp.nonce)?;
        let rtt_ms = u32::try_from(p.started.elapsed().as_millis()).ok();
        let key_match = match (resp.ed_pub, p.pinned) {
            (Some(k), Some(pin)) => Some(k == pin),
            _ => None,
        };
        Some(ProbeResult {
            addr: src,
            rtt_ms,
            key: resp.ed_pub,
            key_match,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_protocol::payloads::ProbeResp;
    use tunnel_protocol::ctrl;

    fn addr() -> SocketAddr {
        "203.0.113.9:5555".parse().unwrap()
    }

    fn track(st: &ProbeState, nonce: [u8; PROBE_NONCE_LEN], pinned: Option<[u8; 32]>, ago_ms: u64) {
        let started = Instant::now()
            .checked_sub(std::time::Duration::from_millis(ago_ms))
            .unwrap_or_else(Instant::now);
        st.pending.lock().unwrap().insert(
            nonce,
            Pending {
                started,
                pinned,
            },
        );
    }

    fn resp(nonce: [u8; PROBE_NONCE_LEN], key: Option<[u8; 32]>) -> Vec<u8> {
        payloads::enc_probe_resp(&ProbeResp {
            nonce,
            ts_ms: 1_700_000_000_000,
            ed_pub: key,
        })
    }

    #[test]
    fn ответ_даёт_rtt_и_сверку_ключа() {
        let st = ProbeState::new();
        let pin = [5u8; 32];
        track(&st, [1u8; PROBE_NONCE_LEN], Some(pin), 42);
        let r = st.on_response(addr(), &resp([1u8; PROBE_NONCE_LEN], Some(pin))).unwrap();
        assert_eq!(r.addr, addr());
        assert_eq!(r.key, Some(pin));
        assert_eq!(r.key_match, Some(true));
        assert!(r.rtt_ms.unwrap() >= 42, "RTT {:?}", r.rtt_ms);
        // Ответ учтён один раз: повтор (и подделка с тем же nonce) — не наша
        // проба.
        assert!(st.on_response(addr(), &resp([1u8; PROBE_NONCE_LEN], Some(pin))).is_none());
        assert_eq!(st.pending(), 0);
    }

    #[test]
    fn чужой_ключ_и_без_пина() {
        let st = ProbeState::new();
        track(&st, [2u8; PROBE_NONCE_LEN], Some([5u8; 32]), 1);
        let r = st.on_response(addr(), &resp([2u8; PROBE_NONCE_LEN], Some([6u8; 32]))).unwrap();
        assert_eq!(r.key_match, Some(false), "сервер отвечает чужим ключом");
        // Без закреплённого ключа сверять не с чем.
        let st = ProbeState::new();
        track(&st, [3u8; PROBE_NONCE_LEN], None, 1);
        let r = st.on_response(addr(), &resp([3u8; PROBE_NONCE_LEN], Some([6u8; 32]))).unwrap();
        assert_eq!(r.key_match, None);
        // Сервер не вернул ключ (want_key = 0) — rtt есть, сверки нет.
        let st = ProbeState::new();
        track(&st, [4u8; PROBE_NONCE_LEN], Some([5u8; 32]), 1);
        let r = st.on_response(addr(), &resp([4u8; PROBE_NONCE_LEN], None)).unwrap();
        assert_eq!((r.key, r.key_match), (None, None));
    }

    #[test]
    fn битый_и_чужой_ответ_не_паникует() {
        let st = ProbeState::new();
        track(&st, [1u8; PROBE_NONCE_LEN], None, 0);
        // Не тот nonce, битая длина, пустой payload, мусор.
        assert!(st.on_response(addr(), &resp([9u8; PROBE_NONCE_LEN], None)).is_none());
        for b in [
            vec![],
            vec![0u8; 23],
            vec![0u8; 25],
            vec![0u8; 57],
            (0..64).map(|i| i as u8).collect::<Vec<u8>>(),
        ] {
            assert!(st.on_response(addr(), &b).is_none());
        }
        // Ожидание не съедено мусором: настоящий ответ ещё принимается.
        assert!(st.on_response(addr(), &resp([1u8; PROBE_NONCE_LEN], None)).is_some());
        // start_probe — честная ошибка до T2, не паника.
        let err = st.start_probe(addr(), 0).unwrap_err().to_string();
        assert!(err.contains("T2"), "{err}");
        // Тип кадра: проба — открытым текстом, не ctrl-шифр.
        assert!(ctrl::is_plaintext(ctrl::PROBE_REQ) && ctrl::is_plaintext(ctrl::PROBE_RESP));
    }
}