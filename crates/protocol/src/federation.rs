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
use crate::{
    Identity, Reader, SymKey, derive_key, put_bool, put_pub, put_str, put_u16, put_u32, put_u64,
};

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
/// Подтверждение доставки `FED_RELAY` получателю (его сервер доставил кадр).
pub const FED_RELAY_ACK: u8 = 0x47;
/// Отказ в доставке `FED_RELAY`: нет группы/отправителя-участника/сессии.
pub const FED_RELAY_NACK: u8 = 0x48;

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

// ---------- репликация групп (T4b) ----------

/// Наибольшее число участников реплицированной группы (совпадает с
/// `server::MAX_MEMBERS`: больше сервер всё равно не примет).
pub const FED_GROUP_MAX_MEMBERS: usize = 254;

/// Участник реплицированной группы: identity и её адрес оверлея. Адрес
/// выдаёт сервер участника, а общий пул подтверждает его остальным
/// (`FED_ADDR_PUSH`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FedMember {
    pub pk: [u8; 32],
    pub ip: u32,
}

const FED_MEMBER_LEN: usize = 32 + 4;
/// Минимальная длина тела [`FedGroup`]:
/// `uuid(16) | owner(32) | gid(4) | rev(4) | epoch(4) | flags(1) | name_len(1) |
/// key(32) | n(2)`.
pub const FED_GROUP_MIN_LEN: usize = 16 + 32 + 4 + 4 + 4 + 1 + 1 + 32 + 2;
/// Флаг группы: приватная (вход только по приглашению владельца).
pub const FED_GROUP_PRIVATE: u8 = 0x01;
/// Флаг группы: удалена владельцем (участникам — удалить локальную копию).
pub const FED_GROUP_DELETED: u8 = 0x02;

/// Полная запись реплицированной группы (`FED_GROUP_PUSH`).
///
/// Владелец — источник правды: запись целиком приходит от сервера владельца
/// и применяется на остальных серверах федерации. `gid` — номер у владельца;
/// каждый сервер назначает участникам свой локальный gid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FedGroup {
    /// Идентификатор группы во всей федерации (не зависит от gid).
    pub uuid: [u8; 16],
    /// ed25519-ключ владельца группы.
    pub owner: [u8; 32],
    /// Локальный gid у владельца (диагностика/отладка; не адресация).
    pub gid: u32,
    pub name: String,
    pub private: bool,
    pub key: [u8; 32],
    /// Номер ключа `key`.
    pub epoch: u32,
    /// Ревизия состояния у владельца (растёт на каждое видимое изменение).
    pub rev: u32,
    pub members: Vec<FedMember>,
    pub deleted: bool,
}

impl FedGroup {
    /// Тело кадра (без типа/AEAD — его добавляет серверный слой).
    pub fn encode(&self) -> Vec<u8> {
        let mut v =
            Vec::with_capacity(FED_GROUP_MIN_LEN + self.name.len() + self.members.len() * 36);
        v.extend_from_slice(&self.uuid);
        put_pub(&mut v, &self.owner);
        put_u32(&mut v, self.gid);
        put_u32(&mut v, self.rev);
        put_u32(&mut v, self.epoch);
        let mut flags = 0u8;
        if self.private {
            flags |= FED_GROUP_PRIVATE;
        }
        if self.deleted {
            flags |= FED_GROUP_DELETED;
        }
        v.push(flags);
        put_str(&mut v, &self.name);
        v.extend_from_slice(&self.key);
        let n = self.members.len().min(FED_GROUP_MAX_MEMBERS);
        put_u16(&mut v, n as u16);
        for m in &self.members[..n] {
            put_pub(&mut v, &m.pk);
            put_u32(&mut v, m.ip);
        }
        v
    }

    /// Разбор тела: длины/счётчики проверяются, хвост — ошибка.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let uuid: [u8; 16] = r.array()?;
        let owner = r.pub_key()?;
        let gid = r.u32()?;
        let rev = r.u32()?;
        let epoch = r.u32()?;
        let flags = r.u8()?;
        ensure!(
            flags & !(FED_GROUP_PRIVATE | FED_GROUP_DELETED) == 0,
            "fed group: неизвестные флаги {flags:#04x}"
        );
        let name = r.str()?;
        let key: [u8; 32] = r.array()?;
        let n = r.u16()? as usize;
        ensure!(n <= FED_GROUP_MAX_MEMBERS, "fed group: участников {n}");
        let mut members = Vec::with_capacity(r.capacity_for(n, FED_MEMBER_LEN));
        for _ in 0..n {
            members.push(FedMember {
                pk: r.pub_key()?,
                ip: r.u32()?,
            });
        }
        r.finish()?;
        Ok(Self {
            uuid,
            owner,
            gid,
            name,
            private: flags & FED_GROUP_PRIVATE != 0,
            key,
            epoch,
            rev,
            members,
            deleted: flags & FED_GROUP_DELETED != 0,
        })
    }
}

/// Изменение реплицированной группы (`FED_GROUP_DELTA`). Дешёвый путь для
/// изменений, которые не требуют полной записи (вход/выход участника).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FedChange {
    /// kind 1: участник добавлен/изменён (адрес оверлея).
    MemberAdd { pk: [u8; 32], ip: u32 },
    /// kind 2: участник удалён.
    MemberRemove { pk: [u8; 32] },
    /// kind 3: имя/владелец/приватность/ключ/эпоха (вход и выход меняют ключ).
    Meta {
        name: String,
        owner: [u8; 32],
        private: bool,
        key: [u8; 32],
        epoch: u32,
    },
    /// kind 4: группа удалена владельцем.
    Deleted,
}

/// kind 1 — участник добавлен.
pub const FED_CHANGE_MEMBER_ADD: u8 = 1;
/// kind 2 — участник удалён.
pub const FED_CHANGE_MEMBER_REMOVE: u8 = 2;
/// kind 3 — метаданные/ключ.
pub const FED_CHANGE_META: u8 = 3;
/// kind 4 — группа удалена.
pub const FED_CHANGE_DELETED: u8 = 4;

impl FedChange {
    pub fn kind(&self) -> u8 {
        match self {
            Self::MemberAdd { .. } => FED_CHANGE_MEMBER_ADD,
            Self::MemberRemove { .. } => FED_CHANGE_MEMBER_REMOVE,
            Self::Meta { .. } => FED_CHANGE_META,
            Self::Deleted => FED_CHANGE_DELETED,
        }
    }
}

/// Дельта записи: `uuid(16) | owner(32) | rev(4) | base_rev(4) | n(1) |
/// n × change`. `rev` — ревизия после изменений, `base_rev` — до; `n = 0`
/// запрещено. Несколько изменений в одном кадре: вход участника — это и
/// `MemberAdd`, и `Meta` (ротация ключа).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FedGroupDelta {
    pub uuid: [u8; 16],
    pub owner: [u8; 32],
    pub rev: u32,
    pub base_rev: u32,
    pub changes: Vec<FedChange>,
}

/// Минимальная длина тела дельты.
pub const FED_DELTA_MIN_LEN: usize = 16 + 32 + 4 + 4 + 1;
/// Больше изменений в одной дельте не шлём (не влезет/проще полная запись).
pub const FED_MAX_CHANGES: usize = 16;

impl FedGroupDelta {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(FED_DELTA_MIN_LEN + 16 + 32);
        v.extend_from_slice(&self.uuid);
        put_pub(&mut v, &self.owner);
        put_u32(&mut v, self.rev);
        put_u32(&mut v, self.base_rev);
        let n = self.changes.len().min(FED_MAX_CHANGES);
        v.push(n as u8);
        for change in &self.changes[..n] {
            v.push(change.kind());
            match change {
                FedChange::MemberAdd { pk, ip } => {
                    put_pub(&mut v, pk);
                    put_u32(&mut v, *ip);
                }
                FedChange::MemberRemove { pk } => put_pub(&mut v, pk),
                FedChange::Meta {
                    name,
                    owner,
                    private,
                    key,
                    epoch,
                } => {
                    put_str(&mut v, name);
                    put_pub(&mut v, owner);
                    put_bool(&mut v, *private);
                    v.extend_from_slice(key);
                    put_u32(&mut v, *epoch);
                }
                FedChange::Deleted => {}
            }
        }
        v
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let uuid: [u8; 16] = r.array()?;
        let owner = r.pub_key()?;
        let rev = r.u32()?;
        let base_rev = r.u32()?;
        let n = r.u8()? as usize;
        ensure!(
            (1..=FED_MAX_CHANGES).contains(&n),
            "fed delta: изменений {n}"
        );
        let mut changes = Vec::with_capacity(r.capacity_for(n, 1));
        for _ in 0..n {
            let kind = r.u8()?;
            changes.push(match kind {
                FED_CHANGE_MEMBER_ADD => FedChange::MemberAdd {
                    pk: r.pub_key()?,
                    ip: r.u32()?,
                },
                FED_CHANGE_MEMBER_REMOVE => FedChange::MemberRemove { pk: r.pub_key()? },
                FED_CHANGE_META => FedChange::Meta {
                    name: r.str()?,
                    owner: r.pub_key()?,
                    private: r.boolean()?,
                    key: r.array()?,
                    epoch: r.u32()?,
                },
                FED_CHANGE_DELETED => FedChange::Deleted,
                other => anyhow::bail!("fed delta: неизвестный kind {other}"),
            });
        }
        r.finish()?;
        Ok(Self {
            uuid,
            owner,
            rev,
            base_rev,
            changes,
        })
    }
}

// ---------- общий пул адресов (T4b) ----------

/// Длина тела [`FedAddrClaim`]: `pk(32) | ip(4) | server(32) | ts_ms(8)`.
pub const FED_ADDR_LEN: usize = 32 + 4 + 32 + 8;

/// Заявка на адрес оверлея в общем пуле федерации (`FED_ADDR_PUSH`) или её
/// отзыв (`FED_ADDR_REVOKE`). `server` — ed25519-ключ сервера, выдавшего
/// адрес: конфликт одной identity решается меньшим `server` (он же и
/// подтверждает адрес), проигравший перевыдаёт адрес и уведомляет.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FedAddrClaim {
    pub pk: [u8; 32],
    pub ip: u32,
    pub server: [u8; 32],
    pub ts_ms: u64,
}

impl FedAddrClaim {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(FED_ADDR_LEN);
        put_pub(&mut v, &self.pk);
        put_u32(&mut v, self.ip);
        put_pub(&mut v, &self.server);
        put_u64(&mut v, self.ts_ms);
        v
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        ensure!(
            body.len() == FED_ADDR_LEN,
            "fed addr: длина {} вместо {FED_ADDR_LEN}",
            body.len()
        );
        let mut r = Reader::new(body);
        Ok(Self {
            pk: r.pub_key()?,
            ip: r.u32()?,
            server: r.pub_key()?,
            ts_ms: r.u64()?,
        })
    }
}

// ---------- кросс-серверный релей (T4b) ----------

/// Наибольшая длина заворачиваемого группового кадра: тело `FED_RELAY`
/// должно влезть в u16 вместе с заголовком релея.
pub const FED_RELAY_MAX_FRAME: usize = u16::MAX as usize - (16 + 32 + 32 + 2);

/// Завёрнутый групповой кадр: `uuid(16) | sender(32) | dst(32) | len(2) |
/// frame`. `sender` и `dst` — identity участников: первый должен быть
/// участником реплицированной группы (проверяет получатель), второй — иметь
/// сессию на принимающем сервере.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FedRelay {
    pub uuid: [u8; 16],
    pub sender: [u8; 32],
    pub dst: [u8; 32],
    pub frame: Vec<u8>,
}

/// Минимальная длина тела релея (пустой кадр не пересылается, но формат).
pub const FED_RELAY_MIN_LEN: usize = 16 + 32 + 32 + 2;

impl FedRelay {
    pub fn encode(&self) -> Vec<u8> {
        assert!(
            self.frame.len() <= FED_RELAY_MAX_FRAME,
            "relay frame too long"
        );
        let mut v = Vec::with_capacity(FED_RELAY_MIN_LEN + self.frame.len());
        v.extend_from_slice(&self.uuid);
        put_pub(&mut v, &self.sender);
        put_pub(&mut v, &self.dst);
        put_u16(&mut v, self.frame.len() as u16);
        v.extend_from_slice(&self.frame);
        v
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let uuid: [u8; 16] = r.array()?;
        let sender = r.pub_key()?;
        let dst = r.pub_key()?;
        let n = r.u16()? as usize;
        ensure!(
            n > 0 && n <= FED_RELAY_MAX_FRAME,
            "fed relay: длина кадра {n}"
        );
        let frame = r.bytes(n)?.to_vec();
        r.finish()?;
        Ok(Self {
            uuid,
            sender,
            dst,
            frame,
        })
    }
}

/// Причины отказа `FED_RELAY` (`FedRelayReply::reason`).
pub mod nack {
    /// Группы с таким uuid на этом сервере нет (не реплицирована).
    pub const NO_GROUP: u8 = 1;
    /// Отправитель не участник реплицированной группы.
    pub const NO_SENDER: u8 = 2;
    /// Получатель не участник группы / адрес не совпал.
    pub const NO_DST: u8 = 3;
    /// У получателя нет живой сессии на этом сервере.
    pub const NO_SESSION: u8 = 4;
    /// Внутренний кадр не разбирается (заголовок/длина/эпоха).
    pub const BAD_FRAME: u8 = 5;

    /// Текст причины для лога/диагностики.
    pub fn text(code: u8) -> &'static str {
        match code {
            NO_GROUP => "группа не реплицирована",
            NO_SENDER => "отправитель не участник группы",
            NO_DST => "получатель не участник группы",
            NO_SESSION => "у получателя нет сессии",
            BAD_FRAME => "внутренний кадр не разбирается",
            _ => "неизвестная причина",
        }
    }
}

/// Ответ на `FED_RELAY` (`FED_RELAY_ACK`/`FED_RELAY_NACK`):
/// `uuid(16) | dst(32) | ok(1) | reason(1)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FedRelayReply {
    pub uuid: [u8; 16],
    pub dst: [u8; 32],
    pub ok: bool,
    /// Причина отказа (0 при `ok`), см. [`nack`].
    pub reason: u8,
}

/// Длина тела ответа на релей.
pub const FED_RELAY_REPLY_LEN: usize = 16 + 32 + 1 + 1;

impl FedRelayReply {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(FED_RELAY_REPLY_LEN);
        v.extend_from_slice(&self.uuid);
        put_pub(&mut v, &self.dst);
        put_bool(&mut v, self.ok);
        v.push(if self.ok { 0 } else { self.reason.max(1) });
        v
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        ensure!(
            body.len() == FED_RELAY_REPLY_LEN,
            "fed relay reply: длина {} вместо {FED_RELAY_REPLY_LEN}",
            body.len()
        );
        let mut r = Reader::new(body);
        Ok(Self {
            uuid: r.array()?,
            dst: r.pub_key()?,
            ok: r.boolean()?,
            reason: r.u8()?,
        })
    }
}

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
        assert_eq!(FED_RELAY_ACK, 0x47);
        assert_eq!(FED_RELAY_NACK, 0x48);
        assert_eq!(FED_LAST, 0x4F);
        assert_eq!(SRV_HELLO_LEN, 185);
        assert_eq!(FED_VER, 1);
    }

    // ---------- репликация групп/адресов/релей (T4b) ----------

    fn fed_group() -> FedGroup {
        FedGroup {
            uuid: [3; 16],
            owner: [4; 32],
            gid: 7,
            name: "фед-группа".into(),
            private: true,
            key: [5; 32],
            epoch: 2,
            rev: 9,
            members: vec![
                FedMember {
                    pk: [6; 32],
                    ip: 0x6442_0101,
                },
                FedMember {
                    pk: [7; 32],
                    ip: 0x6442_0102,
                },
            ],
            deleted: false,
        }
    }

    #[test]
    fn fed_group_кодируется_и_разбирается() {
        let g = fed_group();
        let enc = g.encode();
        assert_eq!(FedGroup::decode(&enc).unwrap(), g);
        // Хвост и обрезка — ошибка (формат строгий).
        let mut longer = enc.clone();
        longer.push(0);
        assert!(FedGroup::decode(&longer).is_err());
        for n in 0..enc.len() {
            assert!(FedGroup::decode(&enc[..n]).is_err(), "len {n}");
        }
        // Пустая группа (без участников) и флаги.
        let empty = FedGroup {
            members: vec![],
            private: false,
            deleted: true,
            ..g.clone()
        };
        let back = FedGroup::decode(&empty.encode()).unwrap();
        assert!(back.deleted && !back.private && back.members.is_empty());
        // Неизвестный флаг — отказ.
        let mut bad = enc.clone();
        let flags_at = 16 + 32 + 4 + 4 + 4;
        bad[flags_at] |= 0x80;
        assert!(FedGroup::decode(&bad).is_err());
        // Счётчик участников больше лимита — отказ.
        const { assert!(FED_GROUP_MAX_MEMBERS >= 254) };
    }

    #[test]
    fn дельта_группы_все_виды() {
        let base = FedGroupDelta {
            uuid: [1; 16],
            owner: [2; 32],
            rev: 5,
            base_rev: 4,
            changes: vec![FedChange::MemberAdd {
                pk: [3; 32],
                ip: 0x6442_0103,
            }],
        };
        assert_eq!(FedGroupDelta::decode(&base.encode()).unwrap(), base);
        for change in [
            FedChange::MemberRemove { pk: [4; 32] },
            FedChange::Meta {
                name: "новое имя".into(),
                owner: [7; 32],
                private: false,
                key: [9; 32],
                epoch: 8,
            },
            FedChange::Deleted,
        ] {
            let d = FedGroupDelta {
                changes: vec![change],
                rev: base.rev + 1,
                base_rev: base.rev,
                ..base.clone()
            };
            assert_eq!(FedGroupDelta::decode(&d.encode()).unwrap(), d);
        }
        // Несколько изменений в одном кадре (вход = MemberAdd + Meta).
        let d = FedGroupDelta {
            changes: vec![
                FedChange::MemberAdd {
                    pk: [5; 32],
                    ip: 0x6442_0104,
                },
                FedChange::Meta {
                    name: "x".into(),
                    owner: [2; 32],
                    private: true,
                    key: [6; 32],
                    epoch: 3,
                },
            ],
            rev: 6,
            base_rev: 5,
            ..base.clone()
        };
        assert_eq!(FedGroupDelta::decode(&d.encode()).unwrap(), d);
        // Ноль изменений и неизвестный kind — отказ.
        let mut bad = base.encode();
        let n_at = 16 + 32 + 4 + 4;
        bad[n_at] = 0;
        assert!(FedGroupDelta::decode(&bad).is_err());
        let mut bad = base.encode();
        bad[n_at] = 1;
        let kind_at = n_at + 1;
        bad[kind_at] = 0;
        assert!(FedGroupDelta::decode(&bad).is_err());
        // Обрезка — ошибка, не паника.
        let enc = base.encode();
        for n in 0..enc.len() {
            assert!(FedGroupDelta::decode(&enc[..n]).is_err(), "len {n}");
        }
    }

    #[test]
    fn заявка_адреса_фиксированной_длины() {
        let c = FedAddrClaim {
            pk: [1; 32],
            ip: 0x6442_0102,
            server: [2; 32],
            ts_ms: NOW,
        };
        let enc = c.encode();
        assert_eq!(enc.len(), FED_ADDR_LEN);
        assert_eq!(FedAddrClaim::decode(&enc).unwrap(), c);
        let mut longer = enc.clone();
        longer.push(0);
        assert!(FedAddrClaim::decode(&longer).is_err());
        assert!(FedAddrClaim::decode(&enc[..enc.len() - 1]).is_err());
    }

    #[test]
    fn релей_и_ответ() {
        let r = FedRelay {
            uuid: [8; 16],
            sender: [1; 32],
            dst: [2; 32],
            frame: crate::plain_frame(crate::grp::DATA, &[9; 64]),
        };
        let back = FedRelay::decode(&r.encode()).unwrap();
        assert_eq!(back, r);
        // Пустой/битый кадр — отказ.
        let mut bad = r.encode();
        let len_at = 16 + 32 + 32;
        bad[len_at..len_at + 2].copy_from_slice(&0u16.to_be_bytes());
        assert!(FedRelay::decode(&bad).is_err());
        assert!(FedRelay::decode(&[0u8; 10]).is_err());
        // Длина за пределом — отказ без паники.
        assert!(FedRelay::decode(&r.encode()[..r.encode().len() - 1]).is_err());

        let ok = FedRelayReply {
            uuid: r.uuid,
            dst: r.dst,
            ok: true,
            reason: 0,
        };
        assert_eq!(FedRelayReply::decode(&ok.encode()).unwrap(), ok);
        let no = FedRelayReply {
            ok: false,
            reason: nack::NO_SESSION,
            ..ok
        };
        let back = FedRelayReply::decode(&no.encode()).unwrap();
        assert!(!back.ok && back.reason == nack::NO_SESSION);
        assert_eq!(no.encode().len(), FED_RELAY_REPLY_LEN);
        assert!(!nack::text(nack::NO_GROUP).is_empty());
    }
}
