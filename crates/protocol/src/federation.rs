//! Федерация серверов (сервер ↔ сервер), этап 9 (§3.5 плана).
//!
//! Кадры лежат в диапазоне **0x40..=0x4F** — вне mesh (0x30..=0x3F), вне
//! ctrl и вне фреймов группы. Версия протокола не меняется: старые серверы
//! такие кадры не понимают (и не должны — федерация включается флагом).
//!
//! * `SRV_HELLO` / `SRV_HELLO_ACK` — открытым текстом, подпись ed25519
//!   (`domain("voidlink-fed-v1") || ed || x || eph || nonce || ts || flags`).
//!   Якорь — ed25519-ключ сервера: TOFU-пиннинг в `server.json` (`--peer` —
//!   явный пин). `x` — долгоживущий X25519-ключ сервера, он тоже
//!   закрепляется: ответ обязан предъявить тот же ключ, что заявлен.
//! * Ключи федеративной сессии — `X25519(eph_a, eph_b)` →
//!   `derive("voidlink-fed-v1", shared)` и два тега направлений (прямая
//!   секретность на каждой сессии).
//! * `0x42..=0x4F` — кадры федеративной сессии (AEAD того же формата, что
//!   ctrl): репликация групп и адресов, кросс-серверный релей.
//!
//! В T4a — кодеки рукопожатия и ключи сессии; кадры `0x42..=0x4F` остаются
//! T4b (номера зафиксированы здесь). Кодеки не паникуют: любое чтение за
//! концом — ошибка, длины проверяются `ensure!`.

use anyhow::{Result, ensure};

use crate::handshake::EphemeralKey;
use crate::{Identity, Reader, SymKey, derive_key, put_pub, put_u64};

// ---------- типы кадров ----------

/// Рукопожатие федерации (открытым текстом, подписано).
pub const SRV_HELLO: u8 = 0x40;
/// Ответ на рукопожатие + параметры сессии.
pub const SRV_HELLO_ACK: u8 = 0x41;
/// Репликация группы целиком (uuid, имя, владелец, ключ, эпоха, состав).
pub const FED_GROUP_PUSH: u8 = 0x42;
/// Дельта состава/метаданных реплицированной группы.
pub const FED_GROUP_DELTA: u8 = 0x43;
/// Публикация выдачи адреса identity (`FED_ADDR_PUSH`).
pub const FED_ADDR_PUSH: u8 = 0x44;
/// Отзыв/перевыдача адреса (конфликт: побеждает сервер с меньшим id).
pub const FED_ADDR_REVOKE: u8 = 0x45;
/// Кросс-серверный релей группового кадра.
pub const FED_RELAY: u8 = 0x46;

/// Последний номер федеративного диапазона (включительно).
pub const FED_LAST: u8 = 0x4F;

/// Тип относится к федеративным кадрам (сервер ↔ сервер).
pub fn is_fed(typ: u8) -> bool {
    (SRV_HELLO..=FED_LAST).contains(&typ)
}

// ---------- лимиты и теги ----------

/// Длина nonce рукопожатия.
pub const FED_NONCE_LEN: usize = 16;
/// Допустимый разброс `ts_ms`: старые/будущие кадры — отказ (повтор чужого
/// `SRV_HELLO` через сутки не должен приниматься).
pub const FED_TS_SKEW_MS: u64 = 120_000;
/// Длина тела `SRV_HELLO`/`SRV_HELLO_ACK`:
/// `ed(32) | x(32) | eph(32) | nonce(16) | ts_ms(8) | flags/ver(1) | sig(64)`.
pub const SRV_HELLO_LEN: usize = 32 + 32 + 32 + FED_NONCE_LEN + 8 + 1 + 64;

/// Домен подписи рукопожатия и тег KDF (домены направлений — от него).
pub const FED_DOMAIN: &[u8] = b"voidlink-fed-v1";
const KDF_I2R: &[u8] = b"voidlink-fed-v1/i2r";
const KDF_R2I: &[u8] = b"voidlink-fed-v1/r2i";

/// Версия рукопожатия федерации (младшие 4 бита поля `flags/ver`).
/// Версия **протокола** остаётся `v4`; это версия нового рукопожатия.
pub const FED_VER: u8 = 1;
/// Маска версии в поле `flags/ver`.
pub const FED_VER_MASK: u8 = 0x0F;
/// Флаг «готов релеить чужой трафик» (старшие 4 бита `flags/ver`).
pub const FED_FLAG_RELAY: u8 = 0x10;

// ---------- ключи сессии ----------

/// Ключи федеративной сессии по направлениям. `i2r` — инициатор →
/// ответивший, `r2i` — обратно; у каждой стороны `tx`/`rx` выбираются ролью.
#[derive(Clone, PartialEq, Eq)]
pub struct FedKeys {
    pub i2r: SymKey,
    pub r2i: SymKey,
}

impl std::fmt::Debug for FedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FedKeys(..)")
    }
}

impl FedKeys {
    /// `k = derive("voidlink-fed-v1", shared)`,
    /// `i2r = derive("voidlink-fed-v1/i2r", k)`, `r2i = …/r2i`.
    pub fn derive(shared: &[u8; 32]) -> Self {
        let k = derive_key(FED_DOMAIN, shared);
        Self {
            i2r: derive_key(KDF_I2R, &k),
            r2i: derive_key(KDF_R2I, &k),
        }
    }

    /// Ключ отправки этой стороны (`initiator` — мы начали рукопожатие).
    pub fn tx(&self, initiator: bool) -> SymKey {
        if initiator { self.i2r } else { self.r2i }
    }

    /// Ключ приёма этой стороны.
    pub fn rx(&self, initiator: bool) -> SymKey {
        if initiator { self.r2i } else { self.i2r }
    }
}

/// Сессионные ключи федерации по общему секрету эфемерных X25519.
pub fn fed_keys(shared: &[u8; 32]) -> FedKeys {
    FedKeys::derive(shared)
}

// ---------- рукопожатие ----------

/// `SRV_HELLO` / `SRV_HELLO_ACK`:
/// `ed(32) | x(32) | eph(32) | nonce(16) | ts_ms(8, BE) | flags/ver(1) | sig(64)`.
///
/// `sig` — ed25519 над
/// `FED_DOMAIN || ed || x || eph || nonce || ts || flags/ver`.
/// Формат один и тот же у HELLO и ACK: тип кадра различает их снаружи.
#[derive(Clone, PartialEq, Eq)]
pub struct SrvHello {
    /// ed25519-ключ сервера-отправителя (якорь доверия TOFU).
    pub ed: [u8; 32],
    /// Долгоживущий X25519-ключ сервера-отправителя (закрепляется вместе с ed).
    pub x: [u8; 32],
    /// Эфемерный X25519-ключ этой попытки (прямая секретность).
    pub eph: [u8; 32],
    /// Случайная метка попытки (свежесть/защита от повтора).
    pub nonce: [u8; FED_NONCE_LEN],
    /// Время отправки, unix мс.
    pub ts_ms: u64,
    /// Версия (младшие 4 бита) и флаги (старшие) — см. [`FED_VER`],
    /// [`FED_FLAG_RELAY`].
    pub flags: u8,
    pub sig: [u8; 64],
}

impl std::fmt::Debug for SrvHello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrvHello")
            .field("ed", &crate::hex_of(&self.ed))
            .field("x", &crate::hex_of(&self.x))
            .field("eph", &crate::hex_of(&self.eph))
            .field("nonce", &crate::hex_of(&self.nonce))
            .field("ts_ms", &self.ts_ms)
            .field("ver", &self.version())
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

impl SrvHello {
    /// Новое рукопожатие от `me`: ed/x берутся из identity, подпись — её
    /// ключом. `flags` — младшие 4 бита версии заполняются автоматически.
    pub fn new(
        me: &Identity,
        eph: [u8; 32],
        nonce: [u8; FED_NONCE_LEN],
        ts_ms: u64,
        flags: u8,
    ) -> Self {
        let mut h = Self {
            ed: me.ed_pub(),
            x: me.x_pub(),
            eph,
            nonce,
            ts_ms,
            flags: (flags & !FED_VER_MASK) | FED_VER,
            sig: [0u8; 64],
        };
        h.sig = me.sign(&h.signing_payload());
        h
    }

    /// Версия рукопожатия из поля `flags/ver`.
    pub fn version(&self) -> u8 {
        self.flags & FED_VER_MASK
    }

    /// Старшие биты `flags/ver` (возможности отправителя).
    pub fn caps(&self) -> u8 {
        self.flags & !FED_VER_MASK
    }

    /// Что подписывается (и что проверяется).
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(FED_DOMAIN.len() + SRV_HELLO_LEN - 64);
        m.extend_from_slice(FED_DOMAIN);
        put_pub(&mut m, &self.ed);
        put_pub(&mut m, &self.x);
        put_pub(&mut m, &self.eph);
        m.extend_from_slice(&self.nonce);
        put_u64(&mut m, self.ts_ms);
        m.push(self.flags);
        m
    }

    /// Тело кадра (ровно [`SRV_HELLO_LEN`] байт, без хвоста).
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SRV_HELLO_LEN);
        put_pub(&mut v, &self.ed);
        put_pub(&mut v, &self.x);
        put_pub(&mut v, &self.eph);
        v.extend_from_slice(&self.nonce);
        put_u64(&mut v, self.ts_ms);
        v.push(self.flags);
        v.extend_from_slice(&self.sig);
        v
    }

    /// Готовый кадр `SRV_HELLO`/`SRV_HELLO_ACK` (открытым текстом).
    pub fn to_frame(&self, typ: u8) -> Vec<u8> {
        crate::plain_frame(typ, &self.encode())
    }

    /// Разбор тела кадра. Длина строго [`SRV_HELLO_LEN`]: открытая часть
    /// подписана целиком, хвост был бы неподписанным.
    pub fn decode(body: &[u8]) -> Result<Self> {
        ensure!(
            body.len() == SRV_HELLO_LEN,
            "srv hello: длина {} вместо {SRV_HELLO_LEN}",
            body.len()
        );
        let mut r = Reader::new(body);
        Ok(Self {
            ed: r.pub_key()?,
            x: r.pub_key()?,
            eph: r.pub_key()?,
            nonce: r.array()?,
            ts_ms: r.u64()?,
            flags: r.u8()?,
            sig: r.array()?,
        })
    }

    /// Совпадает ли долгоживущий X25519-ключ с ожидаемым (TOFU/`--peer`):
    /// ответ обязан предъявить тот же ключ, что заявлен.
    pub fn verify_x(&self, expected: &[u8; 32]) -> Result<()> {
        ensure!(
            crate::ct_eq(&self.x, expected),
            "srv hello: чужой x-ключ (не тот, что закреплён)"
        );
        Ok(())
    }

    /// Проверка подлинности: поддерживаемая версия, якорь (чей ed ждали),
    /// свежесть и подпись.
    ///
    /// Порядок проверок — от дешёвой к дорогой: версия и чужой ключ
    /// отсекаются до подписи, просроченный кадр — до неё же.
    pub fn verify(&self, expected_ed: &[u8; 32], now_ms: u64) -> Result<()> {
        ensure!(
            self.version() == FED_VER,
            "srv hello: версия рукопожатия {} (поддерживается {FED_VER})",
            self.version()
        );
        ensure!(
            crate::ct_eq(&self.ed, expected_ed),
            "srv hello: чужой ed-ключ (не тот сервер, которого ждали)"
        );
        ensure!(
            now_ms.abs_diff(self.ts_ms) <= FED_TS_SKEW_MS,
            "srv hello: просрочен (ts {} при now {now_ms})",
            self.ts_ms
        );
        Identity::verify(&self.ed, &self.signing_payload(), &self.sig)
            .map_err(|_| anyhow::anyhow!("srv hello: подпись не сходится"))
    }

    /// X25519 нашего эфемерного ключа с `eph` пира. Точка малого порядка
    /// (несогласованный ключ) — ошибка: общий секрет был бы предсказуем.
    pub fn dh(&self, my_eph: &EphemeralKey) -> Result<[u8; 32]> {
        my_eph
            .dh(&self.eph)
            .map_err(|_| anyhow::anyhow!("srv hello: eph пира плохого порядка"))
    }

    /// Подлинность + общий секрет одной проверкой (обычный путь получателя).
    pub fn verify_and_dh(
        &self,
        expected_ed: &[u8; 32],
        now_ms: u64,
        my_eph: &EphemeralKey,
    ) -> Result<[u8; 32]> {
        self.verify(expected_ed, now_ms)?;
        self.dh(my_eph)
    }
}

/// Ответ второй стороны: тот же формат, другое имя для читаемости кода.
pub type SrvHelloAck = SrvHello;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex_of;

    /// Фиксированное «сейчас»: тесты не зависят от часов.
    const NOW: u64 = 1_700_000_000_000;

    fn me() -> Identity {
        Identity::generate()
    }

    fn eph() -> EphemeralKey {
        EphemeralKey::generate()
    }

    fn sample(id: &Identity, e: &EphemeralKey, ts: u64) -> SrvHello {
        SrvHello::new(id, e.public(), [7; FED_NONCE_LEN], ts, 0)
    }

    #[test]
    fn диапазон_федерации_не_пересекается() {
        for t in SRV_HELLO..=FED_LAST {
            assert!(is_fed(t));
            assert!(!crate::mesh::is_mesh(t));
            assert!(!crate::grp::is_group(t));
            assert!(
                !crate::ctrl::is_plaintext(t),
                "федерация не ctrl-плейнтекст"
            );
        }
        assert!(!is_fed(0x3F) && !is_fed(0x50));
        assert!(is_fed(SRV_HELLO) && is_fed(SRV_HELLO_ACK) && is_fed(FED_RELAY));
    }

    #[test]
    fn hello_кодируется_и_разбирается() {
        let id = me();
        let e = eph();
        let h = sample(&id, &e, 1_700_000_000_000);
        let enc = h.encode();
        assert_eq!(enc.len(), SRV_HELLO_LEN);
        assert_eq!(SrvHello::decode(&enc).unwrap(), h);
        // Длина фиксирована: хвост и обрезка — ошибка.
        let mut longer = enc.clone();
        longer.push(0);
        assert!(SrvHello::decode(&longer).is_err());
        for n in 0..enc.len() {
            assert!(SrvHello::decode(&enc[..n]).is_err(), "len {n}");
        }
        let frame = h.to_frame(SRV_HELLO_ACK);
        let (typ, body) = crate::split_frame(&frame).unwrap();
        assert_eq!(typ, SRV_HELLO_ACK);
        assert_eq!(SrvHello::decode(body).unwrap(), h);
    }

    #[test]
    fn версия_и_флаги() {
        let id = me();
        let mut h = sample(&id, &eph(), NOW);
        h.flags = 0x30 | FED_VER;
        assert_eq!(h.version(), FED_VER);
        assert_eq!(h.caps(), 0x30);
        // Версия не поддерживается — отказ до подписи.
        let mut bad = sample(&id, &eph(), NOW);
        bad.flags = (FED_VER + 1) & FED_VER_MASK;
        let now = NOW;
        assert!(
            bad.verify(&bad.ed, now)
                .unwrap_err()
                .to_string()
                .contains("версия")
        );
        // Подпись покрывает байт flags: подмена флагов ломает подпись.
        let mut h = sample(&id, &eph(), now);
        assert!(h.verify(&h.ed, now).is_ok());
        h.flags |= FED_FLAG_RELAY;
        assert!(h.verify(&h.ed, now).is_err());
    }

    #[test]
    fn verify_проверяет_якорь_свежесть_и_подпись() {
        let a = me();
        let b = me();
        let e = eph();
        let now = NOW;
        let h = sample(&a, &e, now);
        assert!(h.verify(&a.ed_pub(), now).is_ok());
        // Чужой ed — отказ.
        assert!(h.verify(&b.ed_pub(), now).is_err());
        // Просрочка в обе стороны.
        assert!(h.verify(&a.ed_pub(), now + FED_TS_SKEW_MS + 1).is_err());
        assert!(h.verify(&a.ed_pub(), now - FED_TS_SKEW_MS - 1).is_err());
        assert!(h.verify(&a.ed_pub(), now + FED_TS_SKEW_MS).is_ok());
        // Подпись не сходится (байт sig).
        let mut bad = h.clone();
        bad.sig[0] ^= 1;
        assert!(bad.verify(&a.ed_pub(), now).is_err());
        // Подпись не покрывает подменённый eph.
        let mut bad = h.clone();
        bad.eph[0] ^= 1;
        assert!(bad.verify(&a.ed_pub(), now).is_err());
    }

    #[test]
    fn verify_x_сверяет_заявленный_ключ() {
        let a = me();
        let h = sample(&a, &eph(), NOW);
        assert!(h.verify_x(&a.x_pub()).is_ok());
        assert!(h.verify_x(&[0; 32]).is_err());
        assert!(h.verify_x(&[9; 32]).is_err());
    }

    #[test]
    fn dh_и_ключи_двух_направлений() {
        let a = me();
        let b = me();
        let ea = eph();
        let eb = eph();
        let now = NOW;
        let ha = sample(&a, &ea, now);
        let hb = sample(&b, &eb, now);
        assert!(ha.verify(&a.ed_pub(), now).is_ok());
        assert!(hb.verify(&b.ed_pub(), now).is_ok());
        let sa = ha.verify_and_dh(&a.ed_pub(), now, &eb).unwrap();
        let sb = hb.verify_and_dh(&b.ed_pub(), now, &ea).unwrap();
        assert_eq!(sa, sb, "общий секрет один и тот же");
        let ka = FedKeys::derive(&sa);
        let kb = FedKeys::derive(&sb);
        assert_eq!(ka, kb);
        // Инициатор a: tx = i2r, rx = r2i; у b — наоборот.
        assert_eq!(ka.tx(true), kb.rx(false));
        assert_eq!(ka.rx(true), kb.tx(false));
        assert_ne!(ka.tx(true).as_slice(), ka.rx(true).as_slice());
    }

    #[test]
    fn ключ_малого_порядка_отвергается() {
        let id = me();
        let e = eph();
        let now = NOW;
        // all-zero X25519-ключ даёт несогласованный общий секрет.
        let mut h = SrvHello::new(&id, [0; 32], [1; FED_NONCE_LEN], now, 0);
        h.sig = id.sign(&h.signing_payload());
        assert!(h.verify(&id.ed_pub(), now).is_ok(), "подпись-то сходится");
        assert!(h.dh(&e).is_err(), "но общий секрет невычислим");
        assert!(h.verify_and_dh(&id.ed_pub(), now, &e).is_err());
        assert!(e.dh(&[0; 32]).is_err());
    }

    #[test]
    fn hello_ack_тот_же_формат() {
        let a = me();
        let h = sample(&a, &eph(), NOW);
        let mut b: SrvHelloAck = h.clone();
        assert_eq!(b.encode(), h.encode());
        b.flags = FED_VER | FED_FLAG_RELAY;
        let frame = b.to_frame(SRV_HELLO_ACK);
        let (typ, body) = crate::split_frame(&frame).unwrap();
        assert_eq!(typ, SRV_HELLO_ACK);
        let back = SrvHelloAck::decode(body).unwrap();
        assert_eq!(back, b);
        assert_eq!(hex_of(&back.ed), hex_of(&a.ed_pub()));
    }

    #[test]
    fn константы_кадров_зафиксированы() {
        assert_eq!(SRV_HELLO, 0x40);
        assert_eq!(SRV_HELLO_ACK, 0x41);
        assert_eq!(FED_GROUP_PUSH, 0x42);
        assert_eq!(FED_GROUP_DELTA, 0x43);
        assert_eq!(FED_ADDR_PUSH, 0x44);
        assert_eq!(FED_ADDR_REVOKE, 0x45);
        assert_eq!(FED_RELAY, 0x46);
        assert_eq!(FED_LAST, 0x4F);
        assert_eq!(SRV_HELLO_LEN, 185);
        assert_eq!(FED_VER, 1);
    }
}
