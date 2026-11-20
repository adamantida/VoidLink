//! Mesh-протокол (пир ↔ пир), этап 9 (§3.2 плана).
//!
//! Кадры лежат в диапазоне **0x30..=0x3F** — вне [`crate::grp::is_group`] и вне
//! ctrl-диапазона, поэтому старые клиенты такие кадры молча роняют: версия
//! протокола не меняется, возможности включаются наличием mesh-секции в
//! `GROUP_STATE` (§4.2).
//!
//! * `MESH_HELLO` / `MESH_HELLO_ACK` — открытым текстом, подпись ed25519
//!   (`domain("voidlink-mesh-v1") || ed || eph_x || nonce || ts || flags`).
//!   Якорь доверия — ed-ключ, уже известный из состава группы
//!   (`MemberInfo.pubkey`): новый канал доверия не вводится.
//! * Ключи mesh-сессии — `X25519(eph_a, eph_b)` → `derive("voidlink-mesh-v1",
//!   shared)` и два тега направлений (прямая секретность на каждой сессии).
//! * `0x32..=0x3F` — RPC внутри mesh-сессии (AEAD того же формата, что ctrl).
//! * `MESH_FORWARD` — релей группового кадра через пира (L2): `inner` —
//!   исходный групповой кадр целиком, реле меняет только открытую обёртку.
//!
//! Кодеки не паникуют: любое чтение за концом — ошибка, счётчики из сети не
//! раздувают аллокацию (`Reader::capacity_for`), все размеры проверяются
//! `ensure!`.

use anyhow::{Result, ensure};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::handshake::EphemeralKey;
use crate::{
    Identity, MAX_GROUP_PAYLOAD, Reader, SymKey, derive_key, put_pub, put_u16, put_u32, put_u64,
    split_frame,
};

// ---------- типы кадров ----------

/// Рукопожатие mesh (открытым текстом, подписано).
pub const MESH_HELLO: u8 = 0x30;
/// Ответ на рукопожатие: тот же формат, что [`MESH_HELLO`].
pub const MESH_HELLO_ACK: u8 = 0x31;

/// Проверка живости контакта и RTT.
pub const MESH_PING: u8 = 0x32;
pub const MESH_PONG: u8 = 0x33;
/// Актуальный endpoint/x-ключ пира (когда сервер недоступен).
pub const MESH_GET_CONTACT: u8 = 0x34;
pub const MESH_CONTACT: u8 = 0x35;
/// DHT-поиск: список контактов, ближайших к целевому `ed_pub`.
pub const MESH_FIND_NODE: u8 = 0x36;
pub const MESH_NODES: u8 = 0x37;
/// Поиск пути к пиру (кто из соседей ближе к цели).
pub const MESH_ROUTE: u8 = 0x38;
pub const MESH_ROUTE_OK: u8 = 0x39;
pub const MESH_ROUTE_FAIL: u8 = 0x3A;
/// Релей группового кадра через пира (L2).
pub const MESH_FORWARD: u8 = 0x3B;
pub const MESH_FORWARD_ACK: u8 = 0x3C;
pub const MESH_FORWARD_NACK: u8 = 0x3D;
/// Вежливое закрытие mesh-сессии.
pub const MESH_BYE: u8 = 0x3E;

/// Диапазон mesh-кадров (проверяется до ctrl-разбора).
pub fn is_mesh(typ: u8) -> bool {
    (MESH_HELLO..=0x3F).contains(&typ)
}

// ---------- лимиты и теги ----------

/// Максимум хопов релея (L2).
pub const MESH_MAX_HOPS: u8 = 3;
/// Максимум записей `visited` в кадре (жёсткий предел разбора: даже мусорный
/// кадр не заставит читать больше).
pub const MESH_MAX_VISITED: usize = 8;
/// Длина nonce рукопожатия (и probe-запроса).
pub const MESH_NONCE_LEN: usize = 16;
/// Допустимый разброс `ts_ms` рукопожатия: старые/будущие кадры — отказ
/// (повтор чужого HELLO через сутки не должен приниматься).
pub const MESH_TS_SKEW_MS: u64 = 120_000;
/// Длина тела `MESH_HELLO`/`MESH_HELLO_ACK`.
pub const MESH_HELLO_LEN: usize = 32 + 32 + MESH_NONCE_LEN + 8 + 1 + 64;
/// Минимальная длина тела `MESH_FORWARD` (без `visited` и `inner`).
pub const MESH_FORWARD_MIN: usize = 32 + 32 + 1 + 1 + 2;

/// Домен подписи рукопожатия и тег KDF (общий: домены направлений — от него).
pub const MESH_DOMAIN: &[u8] = b"voidlink-mesh-v1";
const KDF_I2R: &[u8] = b"voidlink-mesh-v1/i2r";
const KDF_R2I: &[u8] = b"voidlink-mesh-v1/r2i";

/// Возможности пира (`caps` в mesh-секции `GROUP_STATE`, §4.2).
pub mod caps {
    /// Умеет mesh (получать `MESH_HELLO` и RPC).
    pub const MESH: u8 = 1 << 0;
    /// Готов релеить чужой трафик.
    pub const RELAY: u8 = 1 << 1;
    /// Готов принимать релей через пира.
    pub const ACCEPT_RELAY: u8 = 1 << 2;

    /// Бит `need` выставлен в маске.
    pub fn has(mask: u8, need: u8) -> bool {
        mask & need == need
    }
}

// ---------- ключи сессии ----------

/// Ключи mesh-сессии по направлениям. `i2r` — инициатор → ответивший,
/// `r2i` — обратно; у каждой стороны `tx`/`rx` выбираются ролью.
#[derive(Clone, PartialEq, Eq)]
pub struct MeshKeys {
    pub i2r: SymKey,
    pub r2i: SymKey,
}

impl std::fmt::Debug for MeshKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MeshKeys(..)")
    }
}

impl MeshKeys {
    /// `k = derive("voidlink-mesh-v1", shared)`,
    /// `i2r = derive("voidlink-mesh-v1/i2r", k)`, `r2i = …/r2i`.
    pub fn derive(shared: &[u8; 32]) -> Self {
        let k = derive_key(MESH_DOMAIN, shared);
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

/// Сессионные ключи mesh по общему секрету эфемерных X25519.
pub fn mesh_keys(shared: &[u8; 32]) -> MeshKeys {
    MeshKeys::derive(shared)
}

/// XOR-расстояние двух ключей (Kademlia-метрика DHT, §3.3): лексикографический
/// порядок массива — это и есть порядок по расстоянию.
pub fn x25519_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut d = [0u8; 32];
    for i in 0..32 {
        d[i] = a[i] ^ b[i];
    }
    d
}

/// Индекс корзины DHT: старшие 5 бит XOR-расстояния (0 — «свой ключ»).
pub fn distance_bucket(a: &[u8; 32], b: &[u8; 32]) -> u8 {
    x25519_distance(a, b)[0] >> 3
}

// ---------- рукопожатие ----------

/// `MESH_HELLO` / `MESH_HELLO_ACK`:
/// `ed(32) | eph_x(32) | nonce(16) | ts_ms(8, BE) | flags(1) | sig(64)`.
///
/// `sig` — ed25519 над `MESH_DOMAIN || ed || eph_x || nonce || ts || flags`.
/// Формат один и тот же у HELLO и ACK: тип кадра различает их снаружи.
#[derive(Clone, PartialEq, Eq)]
pub struct MeshHello {
    /// ed25519-ключ отправителя (он же якорь доверия из состава группы).
    pub ed: [u8; 32],
    /// Эфемерный X25519-ключ этой попытки (прямая секретность).
    pub eph_x: [u8; 32],
    /// Случайная метка попытки (свежесть/защита от повтора).
    pub nonce: [u8; MESH_NONCE_LEN],
    /// Время отправки, unix мс.
    pub ts_ms: u64,
    /// Флаги (`caps::*` — какие возможности предлагает отправитель).
    pub flags: u8,
    pub sig: [u8; 64],
}

impl std::fmt::Debug for MeshHello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshHello")
            .field("ed", &crate::hex_of(&self.ed))
            .field("eph_x", &crate::hex_of(&self.eph_x))
            .field("nonce", &crate::hex_of(&self.nonce))
            .field("ts_ms", &self.ts_ms)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

impl MeshHello {
    /// Новое рукопожатие от `me`: ed берётся из identity, подпись — его ключом.
    pub fn new(
        me: &Identity,
        eph_x: [u8; 32],
        nonce: [u8; MESH_NONCE_LEN],
        ts_ms: u64,
        flags: u8,
    ) -> Self {
        let mut h = Self {
            ed: me.ed_pub(),
            eph_x,
            nonce,
            ts_ms,
            flags,
            sig: [0u8; 64],
        };
        h.sig = me.sign(&h.signing_payload());
        h
    }

    /// Что подписывается (и что проверяется).
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(MESH_DOMAIN.len() + MESH_HELLO_LEN - 64);
        m.extend_from_slice(MESH_DOMAIN);
        put_pub(&mut m, &self.ed);
        put_pub(&mut m, &self.eph_x);
        m.extend_from_slice(&self.nonce);
        crate::put_u64(&mut m, self.ts_ms);
        m.push(self.flags);
        m
    }

    /// Тело кадра (ровно [`MESH_HELLO_LEN`] байт, без хвоста).
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(MESH_HELLO_LEN);
        put_pub(&mut v, &self.ed);
        put_pub(&mut v, &self.eph_x);
        v.extend_from_slice(&self.nonce);
        crate::put_u64(&mut v, self.ts_ms);
        v.push(self.flags);
        v.extend_from_slice(&self.sig);
        v
    }

    /// Готовый кадр `MESH_HELLO`/`MESH_HELLO_ACK` (открытым текстом).
    pub fn to_frame(&self, typ: u8) -> Vec<u8> {
        crate::plain_frame(typ, &self.encode())
    }

    /// Разбор тела кадра. Длина строго [`MESH_HELLO_LEN`]: открытая часть
    /// подписана целиком, хвост был бы неподписанным.
    pub fn decode(body: &[u8]) -> Result<Self> {
        ensure!(
            body.len() == MESH_HELLO_LEN,
            "mesh hello: длина {} вместо {MESH_HELLO_LEN}",
            body.len()
        );
        let mut r = Reader::new(body);
        Ok(Self {
            ed: r.pub_key()?,
            eph_x: r.pub_key()?,
            nonce: r.array()?,
            ts_ms: r.u64()?,
            flags: r.u8()?,
            sig: r.array()?,
        })
    }

    /// Проверка подлинности: якорь (чей ed ждали), свежесть и подпись.
    ///
    /// Порядок проверок — от дешёвой к дорогой: чужой ключ отсекается до
    /// подписи, просроченный кадр — до неё же.
    pub fn verify_from(&self, expected: &[u8; 32], now_ms: u64) -> Result<()> {
        ensure!(
            crate::ct_eq(&self.ed, expected),
            "mesh hello: чужой ed-ключ (не тот пир, которого ждали)"
        );
        ensure!(
            now_ms.abs_diff(self.ts_ms) <= MESH_TS_SKEW_MS,
            "mesh hello: просрочен (ts {} при now {now_ms})",
            self.ts_ms
        );
        Identity::verify(&self.ed, &self.signing_payload(), &self.sig)
            .map_err(|_| anyhow::anyhow!("mesh hello: подпись не сходится"))
    }

    /// X25519 нашего эфемерного ключа с `eph_x` пира. Точка малого порядка
    /// (несогласованный ключ) — ошибка: общий секрет был бы предсказуем.
    pub fn dh(&self, my_eph: &EphemeralKey) -> Result<[u8; 32]> {
        my_eph
            .dh(&self.eph_x)
            .map_err(|_| anyhow::anyhow!("mesh hello: eph_x пира плохого порядка"))
    }

    /// Подлинность + общий секрет одной проверкой (обычный путь получателя).
    pub fn verify_and_dh(
        &self,
        expected: &[u8; 32],
        now_ms: u64,
        my_eph: &EphemeralKey,
    ) -> Result<[u8; 32]> {
        self.verify_from(expected, now_ms)?;
        self.dh(my_eph)
    }
}

/// Ответ второй стороны: тот же формат, другое имя для читаемости кода.
pub type MeshHelloAck = MeshHello;

// ---------- релей ----------

/// `MESH_FORWARD`: `dst_ed(32) | src_ed(32) | hops(1) | visited_len(1) |
/// visited_len × ed(32) | inner_len(2) | inner`.
///
/// `inner` — исходный групповой кадр целиком (`TNL2 | grp::DATA …`): он
/// зашифрован ключом группы, реле не может подменить содержимое (AAD).
/// `hops` — сколько релеев кадр уже прошёл; каждый релей добавляет себя в
/// `visited` и увеличивает `hops` (поэтому `hops == visited.len()`), а
/// получив `hops == MESH_MAX_HOPS` — не пересылает дальше.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MeshForward {
    /// Кому в итоге (ed25519 получателя).
    pub dst_ed: [u8; 32],
    /// Кто отправил (ed25519 источника; реле не меняет).
    pub src_ed: [u8; 32],
    /// Пройдено хопов (и длина `visited`).
    pub hops: u8,
    /// Через кого уже прошло (возврат назад запрещён).
    pub visited: Vec<[u8; 32]>,
    /// Исходный групповой кадр целиком.
    pub inner: Vec<u8>,
}

impl MeshForward {
    /// Тело кадра. Ошибка — нарушение инвариантов (не паника: размеры
    /// приходят и из сети, и от вызывающего).
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.hops <= MESH_MAX_HOPS,
            "mesh forward: хопов {} > {MESH_MAX_HOPS}",
            self.hops
        );
        ensure!(
            self.visited.len() <= MESH_MAX_VISITED,
            "mesh forward: visited {} > {MESH_MAX_VISITED}",
            self.visited.len()
        );
        ensure!(
            self.hops as usize == self.visited.len(),
            "mesh forward: hops != visited"
        );
        ensure!(
            self.inner.len() <= MAX_GROUP_PAYLOAD,
            "mesh forward: inner {} > {MAX_GROUP_PAYLOAD}",
            self.inner.len()
        );
        ensure!(
            split_frame(&self.inner).is_ok(),
            "mesh forward: inner — не кадр TNL2"
        );
        let inner_len = u16::try_from(self.inner.len()).map_err(|_| {
            anyhow::anyhow!("mesh forward: inner {} не влезает в u16", self.inner.len())
        })?;
        let mut v =
            Vec::with_capacity(MESH_FORWARD_MIN + self.visited.len() * 32 + self.inner.len());
        put_pub(&mut v, &self.dst_ed);
        put_pub(&mut v, &self.src_ed);
        v.push(self.hops);
        v.push(self.visited.len() as u8);
        for ed in &self.visited {
            put_pub(&mut v, ed);
        }
        put_u16(&mut v, inner_len);
        v.extend_from_slice(&self.inner);
        Ok(v)
    }

    /// Готовый кадр `MESH_FORWARD` (открытым текстом; `inner` уже зашифрован).
    pub fn to_frame(&self) -> Result<Vec<u8>> {
        Ok(crate::plain_frame(MESH_FORWARD, &self.encode()?))
    }

    /// Разбор тела кадра со всеми проверками диапазонов.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let dst_ed = r.pub_key()?;
        let src_ed = r.pub_key()?;
        let hops = r.u8()?;
        let vlen = r.u8()? as usize;
        ensure!(
            hops <= MESH_MAX_HOPS,
            "mesh forward: хопов {hops} > {MESH_MAX_HOPS}"
        );
        ensure!(
            vlen <= MESH_MAX_VISITED,
            "mesh forward: visited {vlen} > {MESH_MAX_VISITED}"
        );
        let mut visited = Vec::with_capacity(r.capacity_for(vlen, 32));
        for _ in 0..vlen {
            visited.push(r.pub_key()?);
        }
        ensure!(
            hops as usize == visited.len(),
            "mesh forward: hops {hops} != visited {vlen}"
        );
        ensure!(
            !visited.contains(&dst_ed),
            "mesh forward: получатель в visited"
        );
        ensure!(
            !visited.contains(&src_ed),
            "mesh forward: источник в visited"
        );
        let inner_len = r.u16()? as usize;
        ensure!(
            inner_len <= MAX_GROUP_PAYLOAD,
            "mesh forward: inner {inner_len} > {MAX_GROUP_PAYLOAD}"
        );
        ensure!(
            inner_len == r.remaining(),
            "mesh forward: inner_len {inner_len} != остатка {}",
            r.remaining()
        );
        let inner = r.bytes(inner_len)?.to_vec();
        ensure!(
            split_frame(&inner).is_ok(),
            "mesh forward: inner — не кадр TNL2"
        );
        Ok(Self {
            dst_ed,
            src_ed,
            hops,
            visited,
            inner,
        })
    }
}

/// DH стороны mesh-сессии по её эфемерному секрету (T3: ответ на HELLO).
/// Вынесено сюда, чтобы проверка «плохого порядка» жила рядом с кодеком.
pub fn session_secret(my_secret: [u8; 32], peer_eph: &[u8; 32]) -> Result<[u8; 32]> {
    let shared = StaticSecret::from(my_secret).diffie_hellman(&PublicKey::from(*peer_eph));
    ensure!(
        shared.was_contributory(),
        "mesh: эфемерный ключ пира малого порядка"
    );
    Ok(shared.to_bytes())
}

// ---------- RPC внутри mesh-сессии ----------

/// Коды отказов `MESH_FORWARD_NACK` / `MESH_ROUTE_FAIL` / `MESH_FORWARD`
/// (общие для всех mesh-ответов «почему нет»).
pub mod code {
    /// Отказ без уточнения.
    pub const REJECTED: u8 = 1;
    /// Нет маршрута/сессии до цели.
    pub const NO_ROUTE: u8 = 2;
    /// Исчерпан лимит полосы релея (окно 10 с).
    pub const BUDGET: u8 = 3;
    /// Петля/превышен TTL хопов/цель в `visited`.
    pub const LOOP: u8 = 4;
    /// Кадр не разобрался (размер/формат/не TNL2).
    pub const BAD: u8 = 5;
    /// Внутренний групповой кадр отвергнут получателем (ключ/эпоха/окно).
    pub const DROP: u8 = 6;
}

/// Максимум записей `Node` в одном `MESH_NODES`/`MESH_CONTACT`.
pub const MAX_RPC_NODES: usize = 16;
/// Минимальная длина записи `Node`: ed(32) | x(32) | caps(1) | rtt(2) | len(2).
pub const NODE_MIN: usize = 32 + 32 + 1 + 2 + 2;
/// Тело `MESH_BYE` (пустое).
pub const MESH_BYE_LEN: usize = 0;

/// Контакт mesh-сети в RPC (DHT-ответы, обмен контактами). `rtt_ms`
/// — последний известный RTT до контакта (0 — неизвестен).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// ed25519 — идентификатор узла DHT.
    pub ed: [u8; 32],
    /// x25519 — статический ключ контакта.
    pub x: [u8; 32],
    pub addr: std::net::SocketAddr,
    /// Возможности контакта (`caps::*`).
    pub caps: u8,
    pub rtt_ms: u16,
}

fn put_node(v: &mut Vec<u8>, n: &Node) {
    put_pub(v, &n.ed);
    put_pub(v, &n.x);
    v.push(n.caps);
    put_u16(v, n.rtt_ms);
    crate::put_str(v, &n.addr.to_string());
}

fn read_node(r: &mut Reader) -> Result<Node> {
    let ed = r.pub_key()?;
    let x = r.pub_key()?;
    let caps = r.u8()?;
    let rtt_ms = r.u16()?;
    let addr = r.str()?.parse().map_err(|_| {
        anyhow::anyhow!("mesh rpc: адрес контакта не разбирается")
    })?;
    Ok(Node {
        ed,
        x,
        addr,
        caps,
        rtt_ms,
    })
}

/// RPC внутри mesh-сессии (типы [`MESH_PING`]…[`MESH_BYE`]).
///
/// Тело кадра — `counter(8) | ChaCha20-Poly1305(payload, aad = заголовок)`
/// (тот же формат, что ctrl, [`crate::seal_ctrl`]): тип кадра и есть
/// идентификатор RPC, поэтому тела не пересекаются.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rpc {
    /// Проверка живости: `id u64 | ts_ms u64`.
    Ping { id: u64, ts_ms: u64 },
    /// Ответ: `id u64 | ts_ms u64 | load u8 | caps u8`. `load` — доля
    /// использованной полосы релея 0..=255.
    Pong {
        id: u64,
        ts_ms: u64,
        load: u8,
        caps: u8,
    },
    /// Актуальный контакт цели: `target 32 | found u8 | [Node]`.
    Contact {
        target: [u8; 32],
        node: Option<Node>,
    },
    /// Запрос контакта цели: `target 32`.
    GetContact { target: [u8; 32] },
    /// DHT-поиск: `id u64 | target 32`.
    FindNode { id: u64, target: [u8; 32] },
    /// Ответ DHT: `id u64 | n u8 (≤ 16) | n × Node`.
    Nodes { id: u64, nodes: Vec<Node> },
    /// Поиск пути: `id u64 | target 32`.
    Route { id: u64, target: [u8; 32] },
    /// Путь найден: `id u64 | target 32 | up_ms u32 | down_ms u32 | load u8`.
    RouteOk {
        id: u64,
        target: [u8; 32],
        up_ms: u32,
        down_ms: u32,
        load: u8,
    },
    /// Пути нет: `id u64 | target 32 | code u8`.
    RouteFail {
        id: u64,
        target: [u8; 32],
        code: u8,
    },
    /// Релей принял кадр: `seq u64`.
    ForwardAck { seq: u64 },
    /// Релей отказал: `seq u64 | code u8`.
    ForwardNack { seq: u64, code: u8 },
    /// Вежливое закрытие: пустое тело.
    Bye,
}

impl Rpc {
    /// Тип кадра этого RPC.
    pub fn typ(&self) -> u8 {
        match self {
            Rpc::Ping { .. } => MESH_PING,
            Rpc::Pong { .. } => MESH_PONG,
            Rpc::GetContact { .. } => MESH_GET_CONTACT,
            Rpc::Contact { .. } => MESH_CONTACT,
            Rpc::FindNode { .. } => MESH_FIND_NODE,
            Rpc::Nodes { .. } => MESH_NODES,
            Rpc::Route { .. } => MESH_ROUTE,
            Rpc::RouteOk { .. } => MESH_ROUTE_OK,
            Rpc::RouteFail { .. } => MESH_ROUTE_FAIL,
            Rpc::ForwardAck { .. } => MESH_FORWARD_ACK,
            Rpc::ForwardNack { .. } => MESH_FORWARD_NACK,
            Rpc::Bye => MESH_BYE,
        }
    }

    /// Тело кадра. Список контактов длиннее [`MAX_RPC_NODES`] обрезается
    /// (как в остальных кодеках: размер ответа не растёт из-за вызывающего).
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(80);
        match self {
            Rpc::Ping { id, ts_ms } => {
                put_u64(&mut v, *id);
                put_u64(&mut v, *ts_ms);
            }
            Rpc::Pong {
                id,
                ts_ms,
                load,
                caps,
            } => {
                put_u64(&mut v, *id);
                put_u64(&mut v, *ts_ms);
                v.push(*load);
                v.push(*caps);
            }
            Rpc::GetContact { target } => put_pub(&mut v, target),
            Rpc::Contact { target, node } => {
                put_pub(&mut v, target);
                match node {
                    Some(n) => {
                        v.push(1);
                        put_node(&mut v, n);
                    }
                    None => v.push(0),
                }
            }
            Rpc::FindNode { id, target } => {
                put_u64(&mut v, *id);
                put_pub(&mut v, target);
            }
            Rpc::Nodes { id, nodes } => {
                put_u64(&mut v, *id);
                let n = nodes.len().min(MAX_RPC_NODES);
                v.push(n as u8);
                for node in &nodes[..n] {
                    put_node(&mut v, node);
                }
            }
            Rpc::Route { id, target } => {
                put_u64(&mut v, *id);
                put_pub(&mut v, target);
            }
            Rpc::RouteOk {
                id,
                target,
                up_ms,
                down_ms,
                load,
            } => {
                put_u64(&mut v, *id);
                put_pub(&mut v, target);
                put_u32(&mut v, *up_ms);
                put_u32(&mut v, *down_ms);
                v.push(*load);
            }
            Rpc::RouteFail { id, target, code } => {
                put_u64(&mut v, *id);
                put_pub(&mut v, target);
                v.push(*code);
            }
            Rpc::ForwardAck { seq } => put_u64(&mut v, *seq),
            Rpc::ForwardNack { seq, code } => {
                put_u64(&mut v, *seq);
                v.push(*code);
            }
            Rpc::Bye => {}
        }
        v
    }

    /// Готовый кадр открытым текстом (тело потом шифруется сессией; для
    /// тестов и локальной проверки).
    pub fn to_frame(&self) -> Vec<u8> {
        crate::plain_frame(self.typ(), &self.encode())
    }

    /// Разбор тела по типу кадра. Лишние байты — ошибка: формат фиксирован.
    pub fn decode(typ: u8, body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let rpc = match typ {
            MESH_PING => Rpc::Ping {
                id: r.u64()?,
                ts_ms: r.u64()?,
            },
            MESH_PONG => Rpc::Pong {
                id: r.u64()?,
                ts_ms: r.u64()?,
                load: r.u8()?,
                caps: r.u8()?,
            },
            MESH_GET_CONTACT => Rpc::GetContact {
                target: r.pub_key()?,
            },
            MESH_CONTACT => {
                let target = r.pub_key()?;
                let found = r.u8()?;
                ensure!(found <= 1, "mesh rpc: флаг контакта {found}");
                let node = (found == 1).then(|| read_node(&mut r)).transpose()?;
                Rpc::Contact { target, node }
            }
            MESH_FIND_NODE => Rpc::FindNode {
                id: r.u64()?,
                target: r.pub_key()?,
            },
            MESH_NODES => {
                let id = r.u64()?;
                let n = r.u8()? as usize;
                ensure!(n <= MAX_RPC_NODES, "mesh rpc: контактов {n} > {MAX_RPC_NODES}");
                let mut nodes = Vec::with_capacity(r.capacity_for(n, NODE_MIN));
                for _ in 0..n {
                    nodes.push(read_node(&mut r)?);
                }
                Rpc::Nodes { id, nodes }
            }
            MESH_ROUTE => Rpc::Route {
                id: r.u64()?,
                target: r.pub_key()?,
            },
            MESH_ROUTE_OK => Rpc::RouteOk {
                id: r.u64()?,
                target: r.pub_key()?,
                up_ms: r.u32()?,
                down_ms: r.u32()?,
                load: r.u8()?,
            },
            MESH_ROUTE_FAIL => Rpc::RouteFail {
                id: r.u64()?,
                target: r.pub_key()?,
                code: r.u8()?,
            },
            MESH_FORWARD_ACK => Rpc::ForwardAck { seq: r.u64()? },
            MESH_FORWARD_NACK => Rpc::ForwardNack {
                seq: r.u64()?,
                code: r.u8()?,
            },
            MESH_BYE => Rpc::Bye,
            _ => anyhow::bail!("mesh rpc: тип {typ:#04x} — не RPC"),
        };
        ensure!(r.remaining() == 0, "mesh rpc: хвост {} байт", r.remaining());
        Ok(rpc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HDR_LEN, grp};

    fn eph() -> EphemeralKey {
        EphemeralKey::generate()
    }

    fn hello(me: &Identity, e: &EphemeralKey) -> MeshHello {
        MeshHello::new(
            me,
            e.public(),
            [7u8; MESH_NONCE_LEN],
            1_700_000_000_000,
            caps::MESH,
        )
    }

    #[test]
    fn hello_туда_обратно_и_подпись() {
        let a = Identity::generate();
        let b = Identity::generate();
        let ea = eph();
        let h = hello(&a, &ea);
        let body = h.encode();
        assert_eq!(body.len(), MESH_HELLO_LEN);
        let got = MeshHello::decode(&body).unwrap();
        assert_eq!(got, h);
        // Подпись сходится у того, кто ждал именно этот ed.
        got.verify_from(&a.ed_pub(), 1_700_000_000_000).unwrap();
        // Чужой ed — отказ (якорь доверия из состава группы).
        let err = got.verify_from(&b.ed_pub(), 1_700_000_000_000).unwrap_err();
        assert!(format!("{err:#}").contains("чужой ed"), "{err:#}");
        // Просрочка/будущее — отказ.
        assert!(
            got.verify_from(&a.ed_pub(), 1_700_000_000_000 + MESH_TS_SKEW_MS + 1)
                .is_err()
        );
        assert!(
            got.verify_from(&a.ed_pub(), 1_700_000_000_000 - MESH_TS_SKEW_MS - 1)
                .is_err()
        );
        // Подмена любого подписанного поля — отказ.
        for i in 0..MESH_HELLO_LEN - 64 {
            let mut t = body.clone();
            t[i] ^= 1;
            let ok = MeshHello::decode(&t)
                .and_then(|x| x.verify_from(&a.ed_pub(), 1_700_000_000_000))
                .is_ok();
            assert!(!ok, "байт {i}");
        }
        // Хвост не допускается: неподписанных байт в кадре быть не должно.
        let mut tail = body.clone();
        tail.push(0);
        assert!(MeshHello::decode(&tail).is_err());
        for n in 0..MESH_HELLO_LEN {
            assert!(MeshHello::decode(&body[..n]).is_err(), "обрезка до {n}");
        }
        // Кадр целиком: заголовок + тело.
        let frame = h.to_frame(MESH_HELLO);
        let (typ, b) = split_frame(&frame).unwrap();
        assert_eq!((typ, b.len()), (MESH_HELLO, MESH_HELLO_LEN));
        assert_eq!(frame.len(), HDR_LEN + MESH_HELLO_LEN);
    }

    #[test]
    fn hello_ack_тот_же_формат_и_dh() {
        let a = Identity::generate();
        let b = Identity::generate();
        let (ea, eb) = (eph(), eph());
        let ha: MeshHelloAck = hello(&a, &ea);
        let now = 1_700_000_000_000;
        let hb = MeshHelloAck::new(&b, eb.public(), [9u8; MESH_NONCE_LEN], now, caps::MESH);
        // Обе стороны получают общий секрет и одни и те же направленные ключи.
        let sa = hb.verify_and_dh(&b.ed_pub(), now, &ea).unwrap();
        let sb = ha.verify_and_dh(&a.ed_pub(), now, &eb).unwrap();
        assert_eq!(sa, sb);
        let k = MeshKeys::derive(&sa);
        assert_eq!(k.i2r, MeshKeys::derive(&sb).i2r);
        assert_ne!(k.i2r, k.r2i, "направления разделены");
        assert_eq!(k.tx(true), k.rx(false), "tx инициатора = rx ответившего");
        assert_eq!(k.tx(false), k.rx(true));
        // Ключ сессии не совпадает с ctrl-ключами (свой домен).
        assert_ne!(k.i2r, crate::derive_key(b"tunnel/v3/c2s", &sa));
    }

    #[test]
    fn hello_плохой_порядок_эфемерного_ключа() {
        let a = Identity::generate();
        let ea = eph();
        let mut h = hello(&a, &ea);
        // Нулевой эфемерный ключ — точка малого порядка: DH отвергается.
        h.eph_x = [0u8; 32];
        h.sig = a.sign(&h.signing_payload()); // подпись валидна — подпись тут ни при чём
        let body = h.encode();
        let got = MeshHello::decode(&body).unwrap();
        let err = got.dh(&eph()).unwrap_err();
        assert!(format!("{err:#}").contains("порядка"), "{err:#}");
        assert!(
            got.verify_and_dh(&a.ed_pub(), 1_700_000_000_000, &eph())
                .is_err()
        );
        // session_secret тоже отказывает.
        assert!(session_secret([1u8; 32], &[0u8; 32]).is_err());
    }

    #[test]
    fn forward_туда_обратно_и_мусор() {
        let inner = crate::seal_group(
            &[3u8; 32],
            grp::DATA,
            &crate::GroupHeader {
                gid: 1,
                src: 2,
                dst: 3,
                epoch: 4,
            },
            0,
            b"data",
        );
        let f = MeshForward {
            dst_ed: [1; 32],
            src_ed: [2; 32],
            hops: 1,
            visited: vec![[9; 32]],
            inner: inner.clone(),
        };
        let body = f.encode().unwrap();
        assert_eq!(MeshForward::decode(&body).unwrap(), f);
        // Обрезка — ошибка на любом префиксе.
        for n in 0..body.len() {
            assert!(MeshForward::decode(&body[..n]).is_err(), "обрезка до {n}");
        }
        // Хвост после inner — ошибка (inner_len должен покрыть остаток).
        let mut tail = body.clone();
        tail.push(0);
        assert!(MeshForward::decode(&tail).is_err());
        // Инварианты кодирования.
        let bad = MeshForward {
            hops: 4,
            visited: vec![[9; 32]; 4],
            ..f.clone()
        };
        assert!(bad.encode().is_err(), "хопов > 3");
        let bad = MeshForward {
            hops: 1,
            visited: vec![],
            ..f.clone()
        };
        assert!(bad.encode().is_err(), "hops != visited");
        let bad = MeshForward {
            hops: 0,
            visited: vec![],
            inner: vec![0; 4],
            ..f.clone()
        };
        assert!(bad.encode().is_err(), "inner не кадр");
        let big = MeshForward {
            hops: 0,
            visited: vec![],
            inner: vec![0u8; MAX_GROUP_PAYLOAD + 1],
            ..f.clone()
        };
        assert!(big.encode().is_err());
        // Получатель/источник в visited — петля, отказ уже на разборе.
        let mut looped = body.clone();
        let at = HDR_LEN + 32 + 32 + 2;
        looped[at..at + 32].copy_from_slice(&[1u8; 32]); // visited[0] = dst
        assert!(MeshForward::decode(&looped).is_err());
        // Тип кадра в заголовке — MESH_FORWARD.
        let frame = f.to_frame().unwrap();
        assert_eq!(split_frame(&frame).unwrap().0, MESH_FORWARD);
    }

    #[test]
    fn forward_лимит_visited_из_сети_не_аллоцирует() {
        // Заявленный visited_len больше остатка: ошибка, без паники.
        let mut body = vec![0u8; 32 + 32];
        body.push(0); // hops
        body.push(200); // visited_len
        assert!(MeshForward::decode(&body).is_err());
        // visited_len в пределах лимита, но байт не хватает.
        let mut body = vec![0u8; 32 + 32];
        body.push(8);
        body.push(8);
        assert!(MeshForward::decode(&body).is_err());
    }

    #[test]
    fn расстояние_и_корзины() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert_eq!(x25519_distance(&a, &b), [0u8; 32]);
        assert_eq!(distance_bucket(&a, &b), 0);
        let mut c = [0u8; 32];
        c[0] = 0x80;
        assert_eq!(x25519_distance(&a, &c)[0], 0x80);
        assert_eq!(distance_bucket(&a, &c), 0x10);
        let mut d = [0u8; 32];
        d[0] = 0x07; // 0b0000_0111 → старшие 5 бит = 0
        assert_eq!(distance_bucket(&a, &d), 0);
        let mut e = [0u8; 32];
        e[0] = 0x08; // 0b0000_1000 → 1
        assert_eq!(distance_bucket(&a, &e), 1);
        let mut f = [0u8; 32];
        f[0] = 0xFF; // 0b1111_1111 → 31
        assert_eq!(distance_bucket(&a, &f), 31);
        // XOR симметричен и совпадает побайтово.
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x[5] = 0xAA;
        y[5] = 0x55;
        assert_eq!(x25519_distance(&x, &y), x25519_distance(&y, &x));
        assert_eq!(x25519_distance(&x, &y)[5], 0xFF);
    }

    #[test]
    fn rpc_туда_обратно_и_обрезки() {
        let node = Node {
            ed: [1; 32],
            x: [2; 32],
            addr: "203.0.113.7:4000".parse().unwrap(),
            caps: caps::MESH | caps::RELAY,
            rtt_ms: 42,
        };
        let all = vec![
            Rpc::Ping {
                id: 7,
                ts_ms: 1_700_000_000_000,
            },
            Rpc::Pong {
                id: 7,
                ts_ms: 1_700_000_000_001,
                load: 200,
                caps: 3,
            },
            Rpc::GetContact { target: [3; 32] },
            Rpc::Contact {
                target: [3; 32],
                node: Some(node.clone()),
            },
            Rpc::Contact {
                target: [3; 32],
                node: None,
            },
            Rpc::FindNode {
                id: 9,
                target: [4; 32],
            },
            Rpc::Nodes {
                id: 9,
                nodes: vec![node.clone(), Node { rtt_ms: 0, ..node.clone() }],
            },
            Rpc::Route {
                id: 11,
                target: [5; 32],
            },
            Rpc::RouteOk {
                id: 11,
                target: [5; 32],
                up_ms: 12,
                down_ms: 40,
                load: 7,
            },
            Rpc::RouteFail {
                id: 11,
                target: [5; 32],
                code: code::NO_ROUTE,
            },
            Rpc::ForwardAck { seq: 123 },
            Rpc::ForwardNack {
                seq: 123,
                code: code::BUDGET,
            },
            Rpc::Bye,
        ];
        for rpc in all {
            let body = rpc.encode();
            assert_eq!(
                Rpc::decode(rpc.typ(), &body).unwrap(),
                rpc,
                "{rpc:?}: туда-обратно"
            );
            // Любая обрезка — ошибка, не паника.
            for n in 0..body.len() {
                assert!(Rpc::decode(rpc.typ(), &body[..n]).is_err(), "{rpc:?} обрезка {n}");
            }
            // Хвост — ошибка: формат фиксирован.
            let mut tail = body.clone();
            tail.push(0);
            assert!(Rpc::decode(rpc.typ(), &tail).is_err(), "{rpc:?} хвост");
        }
        // Список контактов сверх лимита обрезается на кодировании.
        let many: Vec<Node> = (0..MAX_RPC_NODES + 5).map(|_| node.clone()).collect();
        let body = Rpc::Nodes { id: 1, nodes: many }.encode();
        match Rpc::decode(MESH_NODES, &body).unwrap() {
            Rpc::Nodes { nodes, .. } => assert_eq!(nodes.len(), MAX_RPC_NODES),
            other => panic!("не Nodes: {other:?}"),
        }
        // Заявленное число контактов больше лимита — ошибка без аллокации.
        let mut bad = vec![0u8; 8];
        bad.push(u8::MAX);
        assert!(Rpc::decode(MESH_NODES, &bad).is_err());
        // Флаг контакта — только 0/1.
        let mut bad = vec![0u8; 32];
        bad.push(2);
        assert!(Rpc::decode(MESH_CONTACT, &bad).is_err());
        // Не-RPC тип — ошибка.
        assert!(Rpc::decode(MESH_FORWARD, &[]).is_err());
        assert!(Rpc::decode(MESH_HELLO, &[]).is_err());
    }

    #[test]
    fn caps_и_диапазоны() {
        use crate::ctrl;
        assert!(caps::has(caps::MESH | caps::RELAY, caps::RELAY));
        assert!(!caps::has(caps::MESH, caps::RELAY));
        assert!(is_mesh(MESH_HELLO) && is_mesh(0x3F));
        assert!(!is_mesh(0x40) && !is_mesh(0x2F) && !is_mesh(ctrl::PRESENCE));
        // Все mesh-типы вне групп и ctrl.
        for t in MESH_HELLO..=0x3F {
            assert!(!grp::is_group(t));
            assert!(!ctrl::is_plaintext(t));
        }
    }
}
