//! Проба доступности сервера (`PROBE_REQ` → `PROBE_RESP`, §3.7 плана).
//!
//! Проба ходит **открытым текстом** и не требует сессии и рукопожатия: её
//! можно запускать для любого сервера из списка, не ломая текущую сессию.
//! Поэтому здесь нет ни cookie, ни AEAD — только:
//!
//! * строгая длина запроса (ровно 64 байта, [`payloads::PROBE_REQ_LEN`]) и
//!   свежесть `ts_ms` — старый nonce не превращает сервер в усилитель;
//! * лимит по IP (`Shared::allow_ip`) и общий «plain»-бюджет
//!   (`Shared::send_plain`) — как у прочих открытых ответов;
//! * ответ **не длиннее запроса** (24 или 56 байт ≤ 64) и без создания
//!   сессии: пробующий не занимает ни адрес, ни слот сессии;
//! * метрика `voidlink_probes_total`.
//!
//! ed-ключ сервера в ответе только если клиент попросил (`want_key`) — он
//! нужен, чтобы сверить сервер с закреплённым (`StoredServer.pubkey`).

use std::net::SocketAddr;

use tunnel_protocol::ctrl;
use tunnel_protocol::payloads::{self as pl, ProbeResp};

use crate::{Shared, metrics};

/// Допустимый разброс `ts_ms` пробы: ответ на старый nonce — бесплатный
/// усилитель. 2 минуты — с запасом на кривые часы клиента.
pub const PROBE_TS_SKEW_MS: u64 = 120_000;

/// Обработать `PROBE_REQ` от `src`. Битый/просроченный/просрочивший лимит
/// запрос отбрасывается молча (как прочий мусор — без лога и без ERROR).
pub(crate) fn handle_probe_req(sh: &Shared, src: SocketAddr, body: &[u8]) {
    metrics::Metrics::inc(&sh.metrics.probes_total, 1);
    let Ok(req) = pl::dec_probe_req(body) else {
        sh.drop_frame();
        return;
    };
    // Часы: ответ на старый nonce не нужен ни клиенту, ни атакующему.
    if crate::unix_ms().abs_diff(req.ts_ms) > PROBE_TS_SKEW_MS {
        sh.drop_frame();
        return;
    }
    if !sh.allow_ip(src.ip()) {
        sh.drop_frame();
        return;
    }
    let ed = req.want_key.then(|| sh.identity.ed_pub());
    let resp = pl::enc_probe_resp(&ProbeResp {
        nonce: req.nonce,
        ts_ms: req.ts_ms,
        ed_pub: ed,
    });
    // Инвариант правила «ответ не больше запроса»: 24/56 ≤ 64.
    // `send_plain` берёт общий plain-бюджет сервера и уважает `quiet`.
    sh.send_plain(src, ctrl::PROBE_RESP, &resp);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_protocol::payloads::PROBE_REQ_LEN;

    #[test]
    fn ответ_не_длиннее_запроса() {
        // Формат: ответ 24/56, запрос ровно 64 — правило выполняется всегда,
        // при любом want_key.
        let req = pl::ProbeReq {
            nonce: [1u8; pl::PROBE_NONCE_LEN],
            ts_ms: 1_700_000_000_000,
            want_key: true,
        };
        assert_eq!(pl::enc_probe_req(&req).len(), PROBE_REQ_LEN);
        for want_key in [true, false] {
            let resp = pl::enc_probe_resp(&ProbeResp {
                nonce: req.nonce,
                ts_ms: req.ts_ms,
                ed_pub: want_key.then_some([2u8; 32]),
            });
            assert!(resp.len() <= PROBE_REQ_LEN);
            assert_eq!(
                pl::dec_probe_resp(&resp).unwrap().ed_pub.is_some(),
                want_key
            );
        }
        // Время: свежий запрос в окне, старый — нет.
        let now: u64 = 1_700_000_000_000;
        assert!(now.abs_diff(req.ts_ms) <= PROBE_TS_SKEW_MS);
        assert!(now.abs_diff(req.ts_ms + PROBE_TS_SKEW_MS + 1) > PROBE_TS_SKEW_MS);
        // Проба — открытым текстом, не ctrl-шифр.
        assert!(ctrl::is_plaintext(ctrl::PROBE_REQ) && ctrl::is_plaintext(ctrl::PROBE_RESP));
    }
}
