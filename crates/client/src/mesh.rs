//! Mesh-подсистема клиента (L2: релей через участников, §3.2/§3.4).
//!
//! Здесь живёт всё, что не требует доступа к группам/TUN/конфигу: сессии
//! `ed → ключи`, рукопожатия, RPC внутри сессии, ретрансляция MESH_FORWARD и
//! учёт её лимитов. Движок (`engine.rs`) передаёт снимок «кто есть кто»
//! ([`MeshCtx`]) и исполняет результат ([`MeshOut`]) — так у модуля нет
//! циклических зависимостей, а юнит-тесты не поднимают движок.
//!
//! ```text
//! MESH_HELLO/ACK  открытый текст: ed | eph_x | nonce | ts | flags | sig(ed)
//!                 ключи = X25519(eph_a, eph_b) → MeshKeys (i2r/r2i)
//! RPC 0x32..0x3E  seal_ctrl(ключ направления, counter, typ, payload)
//!                 тело = counter LE | ChaCha20-Poly1305; окно повторов своё
//!                 на каждое направление сессии
//! MESH_FORWARD    dst_ed | src_ed | hops | visited[] | inner(групповой кадр)
//!                 обёртка открытая, inner зашифрован ключом группы; seq = blake3(inner)
//! ```
//!
//! Кадры 0x30..=0x3F пир ↔ пир: `dispatch` отдаёт их сюда **до** проверки
//! «только от сервера» (mesh-пир сервером не является), а молчание означает
//! «кадр отброшен» — как у старых клиентов (§4.3), без `RESET`.
//!
//! Безопасность:
//! * якорь доверия — ed-ключ из состава группы (`MemberInfo.pubkey`) или
//!   контакта DHT; чужой ed отвергается до проверки подписи;
//! * `ts` рукопожатия — окно [`mesh::MESH_TS_SKEW_MS`] (повтор чужого HELLO
//!   через сутки не принимается), ACK обязан эхом повторить наш `nonce`
//!   (привязка ответа к попытке);
//! * точка малого порядка в `eph_x` отвергается DH (`session_secret`);
//! * RPC принимается только от сессии на том же адресе: подделать `src_ed`
//!   в открытом MESH_FORWARD без ключа сессии нельзя;
//! * лимиты: ≤ [`MAX_SESSIONS`] сессий, ≤ [`RELAY_PEERS_MAX`] реле-пиров,
//!   бюджет [`RELAY_WINDOW_MS`] на пира, ≤ [`MAX_FORWARD_INNER`] байт
//!   `inner`, ≤ [`mesh::MESH_MAX_HOPS`] хопов, ≤ [`MAX_PENDING_FORWARDS`]
//!   кадров в полёте.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use tunnel_protocol as proto;
use tunnel_protocol::handshake::EphemeralKey;
use tunnel_protocol::mesh::{self, MeshForward, MeshHello, MeshKeys, Rpc, caps, code};
use tunnel_protocol::payloads::MeshSeed;

use crate::dht::{Contact, Dht};

// ---------- лимиты ----------

/// Максимум одновременных mesh-сессий (по числу участников группы).
pub const MAX_SESSIONS: usize = 256;
/// Не чаще одной попытки рукопожатия на пира.
pub const HANDSHAKE_GAP_MS: u64 = 5_000;
/// Сколько ждём ответ на HELLO, прежде чем начать заново.
pub const HANDSHAKE_TTL_MS: u64 = 30_000;
/// Сессия без кадров столько считается мёртвой.
pub const SESSION_IDLE_MS: u64 = 120_000;
/// Период `MESH_INFO` серверу (и повтор сразу после WELCOME — движок).
pub const INFO_EVERY_MS: u64 = 5 * 60 * 1000;
/// Период PING живой сессии.
pub const PING_EVERY_MS: u64 = 30_000;
/// Сколько ждём PONG, прежде чем считать сессию мёртвой.
pub const PING_TIMEOUT_MS: u64 = 10_000;
/// Максимум ожидающих PONG.
pub const MAX_PENDING_PINGS: usize = 64;
/// Максимум реле-пиров (кому/через кого релеим чужой трафик).
pub const RELAY_PEERS_MAX: usize = 8;
/// Окно учёта полосы релея.
pub const RELAY_WINDOW_MS: u64 = 10_000;
/// Сколько байт `inner` влезает в один MESH_FORWARD кадр.
pub const MAX_FORWARD_INNER: usize = proto::MAX_CTRL_PAYLOAD - mesh::MESH_FORWARD_MIN - 8 * 32;
/// Сколько ждём ACK на forward, прежде чем повторить.
pub const FORWARD_GAP_MS: u64 = 1_500;
/// Попыток отправки forward одному реле.
pub const FORWARD_TRIES: u32 = 2;
/// Максимум forward в полёте (копий одного кадра — тоже: каждая копия
/// считается отдельно, issue #25).
pub const MAX_PENDING_FORWARDS: usize = 128;
/// Сколько предыдущих хопов может ждать один и тот же forward (issue #25):
/// дублированный кадр сходится в релее с двух путей, а копия к получателю
/// уходит одна — подтверждение получают все ждущие.
pub const FORWARD_WAITERS_MAX: usize = 4;
/// Сколько помним «кадр уже подтверждён» (issue #25): отказ второй копии
/// после успешной первой не должен снимать путь.
pub const FORWARD_ACKED_TTL_MS: u64 = 10_000;
/// Максимум ожидающих ROUTE/FIND_NODE.
pub const MAX_PENDING_RPC: usize = 64;
/// Сколько `visited` помним (предел разбора — у кодека).
const MAX_VISITED: usize = mesh::MESH_MAX_VISITED;

// ---------- состояние ----------

/// Живая mesh-сессия с пиром.
pub struct MeshSess {
    /// ed25519 пира (якорь доверия).
    pub ed: [u8; 32],
    /// Адрес, на котором сессия установлена (последний приславший кадр).
    pub addr: SocketAddr,
    /// Статический x-ключ пира (для DHT/контактов).
    pub x: [u8; 32],
    /// Наш эфемерный ключ этой сессии (tie-break одновременных рукопожатий).
    my_eph: [u8; 32],
    /// Эфемерный ключ пира (для отсева повторного HELLO).
    pub peer_eph: [u8; 32],
    /// Когда сессия установлена (мс): свежая сессия не заменяется гонкой.
    since_ms: u64,
    keys: MeshKeys,
    initiator: bool,
    tx: u64,
    rx: proto::ReplayWindow,
    pub last_rx_ms: u64,
    pub last_tx_ms: u64,
    /// RTT по PONG/рукопожатию.
    pub rtt_ms: Option<u32>,
    /// Возможности пира из его HELLO.
    pub caps: u8,
    /// PING отправлен, ответа ещё нет: (id, когда).
    ping: Option<(u64, u64)>,
}

impl MeshSess {
    #[allow(clippy::too_many_arguments)]
    fn new(
        ed: [u8; 32],
        addr: SocketAddr,
        x: [u8; 32],
        my_eph: [u8; 32],
        peer_eph: [u8; 32],
        shared: &[u8; 32],
        initiator: bool,
        caps: u8,
        now_ms: u64,
    ) -> Self {
        Self {
            ed,
            addr,
            x,
            my_eph,
            peer_eph,
            since_ms: now_ms,
            keys: mesh::mesh_keys(shared),
            initiator,
            tx: 0,
            rx: proto::ReplayWindow::new(),
            last_rx_ms: now_ms,
            last_tx_ms: now_ms,
            rtt_ms: None,
            caps,
            ping: None,
        }
    }

    /// Зашифровать RPC (тело кадра — `counter LE | ct`, как ctrl).
    fn seal(&mut self, rpc: &Rpc, now_ms: u64) -> Vec<u8> {
        let c = self.tx;
        self.tx = c.checked_add(1).expect("mesh nonce counter exhausted");
        self.last_tx_ms = now_ms;
        proto::seal_ctrl(&self.keys.tx(self.initiator), c, rpc.typ(), &rpc.encode())
    }

    /// Расшифровать RPC. Окно сдвигается только после успешного разбора:
    /// подделка с огромным счётчиком не сдвинет окно.
    fn open(&mut self, typ: u8, body: &[u8]) -> Option<(Rpc, u64)> {
        let key = self.keys.rx(self.initiator);
        let (c, payload) = proto::open_ctrl(&key, typ, body).ok()?;
        if !self.rx.check(c) {
            return None;
        }
        let rpc = Rpc::decode(typ, &payload).ok()?;
        if !self.rx.commit(c) {
            return None;
        }
        Some((rpc, c))
    }
}

impl std::fmt::Debug for MeshSess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshSess")
            .field("ed", &proto::hex_of(&self.ed))
            .field("addr", &self.addr)
            .field("initiator", &self.initiator)
            .field("rtt_ms", &self.rtt_ms)
            .finish_non_exhaustive()
    }
}

/// Ожидание ответа на HELLO.
struct PendingHs {
    eph: EphemeralKey,
    nonce: [u8; mesh::MESH_NONCE_LEN],
    at_ms: u64,
}

/// Ожидание PONG на PING.
struct PendingPing {
    at_ms: u64,
}

/// Отправленный forward, ждущий ACK/NACK.
///
/// Копия адресуется парой `(seq, to)` (issue #25): один кадр может лететь
/// двумя релеями, и две копии — две независимые записи. ACK/NACK снимает
/// только копию от того хопа, который его прислал.
struct PendingForward {
    /// Кому мы его отправили (реле или конечный получатель).
    to: [u8; 32],
    /// Кто просил нас релеить (`None` — мы инициатор).
    prev: Option<[u8; 32]>,
    /// Ещё просившие того же кадра через нас (дублирование сошлось в релее):
    /// получат тот же ACK/NACK, что и `prev`, а копия к получателю — одна.
    also: Vec<[u8; 32]>,
    /// Конечный получатель.
    dst_ed: [u8; 32],
    at_ms: u64,
    tries: u32,
    frame: Vec<u8>,
    addr: SocketAddr,
}

/// Учёт полосы реле-пира в скользящем окне.
#[derive(Clone, Copy)]
struct Budget {
    start_ms: u64,
    bytes: u64,
}

/// Снимок мира для mesh-модуля (движок собирает перед вызовом).
pub struct MeshCtx<'a> {
    /// Наша identity (подпись HELLO, DH).
    pub me: &'a proto::Identity,
    /// Наши возможности (`caps::*`).
    pub my_caps: u8,
    /// Текущее время, unix мс.
    pub now_ms: u64,
    /// Наш UDP-адрес (для ответа на MESH_GET_CONTACT; может быть локальным).
    pub my_addr: Option<SocketAddr>,
    /// Контакты DHT: кого пинговать, куда релеить, у кого просить контакт.
    pub contacts: &'a [Contact],
    /// ed-ключи участников наших групп (кого принимаем и кому релеим).
    pub members: &'a [[u8; 32]],
    /// Релей чужого трафика разрешён.
    pub relay_enabled: bool,
    /// Бюджет релея на пира за окно [`RELAY_WINDOW_MS`], байт.
    pub relay_budget: u64,
    /// Проверка открытого заголовка группового кадра (gid, src, dst, epoch).
    /// Релей не расшифровывает inner: этих полей достаточно, чтобы отсечь
    /// мусор и чужую группу.
    pub check_group: &'a dyn Fn(u32, u32, u32, u32) -> bool,
}

impl MeshCtx<'_> {
    fn member(&self, ed: &[u8; 32]) -> bool {
        self.members.iter().any(|m| m == ed)
    }

    fn contact(&self, ed: &[u8; 32]) -> Option<&Contact> {
        self.contacts.iter().find(|c| &c.ed == ed)
    }
}

/// Что модуль просит сделать движок.
#[derive(Debug, Default)]
pub struct MeshOut {
    /// Готовые датаграммы к отправке.
    pub sends: Vec<(SocketAddr, Vec<u8>)>,
    /// Кадры, адресованные нам: движок проверяет группу (ключ/эпоху/окно) и
    /// зовёт [`MeshState::delivery_result`] — уйдёт ACK или NACK.
    pub deliver: Vec<Relayed>,
    /// События (UI, таблица путей, DHT).
    pub events: Vec<MeshEvent>,
    /// Новые/обновлённые контакты для DHT.
    pub learned: Vec<Contact>,
    /// Ответы на `MESH_FIND_NODE`: (id, контакты) — движок продолжает поиск.
    pub finds: Vec<(u64, Vec<Contact>)>,
    /// Пора отправить `MESH_INFO` серверу.
    pub info_due: bool,
}

impl MeshOut {
    fn send(&mut self, to: SocketAddr, frame: Vec<u8>) {
        self.sends.push((to, frame));
    }
}

/// Кадр релея, дошедший до нас.
#[derive(Debug, Clone)]
pub struct Relayed {
    /// От кого пришла обёртка (реле или источник).
    pub from_ed: [u8; 32],
    /// Идентификатор forward (`blake3(inner)`): уйдёт в ACK/NACK.
    pub seq: u64,
    /// Сколько хопов прошёл.
    pub hops: u8,
    /// Исходный групповой кадр.
    pub inner: Vec<u8>,
}

/// События mesh-модуля.
#[derive(Debug, Clone, PartialEq)]
pub enum MeshEvent {
    /// Сессия установлена/обновлена.
    Up {
        ed: [u8; 32],
        addr: SocketAddr,
        rtt_ms: Option<u32>,
    },
    /// Сессия потеряна.
    Down { ed: [u8; 32], reason: &'static str },
    /// Замер RTT до пира (для PathTable).
    Rtt { ed: [u8; 32], rtt_ms: u32 },
    /// Маршрут через пира измерен (`MESH_ROUTE_OK`).
    RouteMeasured {
        dst_ed: [u8; 32],
        via: [u8; 32],
        up_ms: u32,
        down_ms: u32,
        load: f64,
    },
    /// Маршрут через пира не найден.
    RouteFailed { dst_ed: [u8; 32], via: [u8; 32] },
    /// Релей не принял/не подтвердил кадр: путь до `dst_ed` сломан.
    ForwardFailed { dst_ed: [u8; 32], code: u8 },
    /// Релей подтвердил кадр (для статистики/трейсинга).
    ForwardOk { dst_ed: [u8; 32], via: [u8; 32] },
}

/// Счётчики mesh для снимка состояния.
#[derive(Clone, Copy, Debug, Default)]
pub struct MeshStats {
    /// Байт, отрелеенных этим клиентом (в обе стороны).
    pub relay_bytes: u64,
    /// Живых сессий.
    pub sessions: u32,
    /// Активных реле-пиров (с ненулевым окном).
    pub relay_peers: u32,
    /// Отброшено кадров (подпись/сессия/лимит).
    pub dropped: u64,
    /// Принято forward как получатель.
    pub delivered: u64,
    /// Отправлено forward.
    pub forwarded: u64,
}

/// Состояние mesh-клиента.
pub struct MeshState {
    /// Mesh включён (конфиг `mesh.enabled` / `Cmd::SetMeshEnabled`).
    enabled: AtomicBool,
    sessions: HashMap<[u8; 32], MeshSess>,
    pending_hs: HashMap<[u8; 32], PendingHs>,
    last_hs: HashMap<[u8; 32], u64>,
    pings: HashMap<u64, PendingPing>,
    /// id запроса ROUTE → (цель, когда).
    routes: HashMap<u64, ([u8; 32], u64)>,
    /// Ожидающие ACK/NACK копии forward: `(seq, кому отправлена)` → запись.
    forwards: HashMap<(u64, [u8; 32]), PendingForward>,
    /// Недавно подтверждённые кадры `(seq, когда)`: копия доставлена — отказ
    /// оставшихся копий путь не снимает (issue #25).
    acked: VecDeque<(u64, u64)>,
    /// Бюджет по реле-пирам.
    budgets: HashMap<[u8; 32], Budget>,
    next_id: u64,
    last_info_ms: u64,
    stats: MeshStats,
}

impl std::fmt::Debug for MeshState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshState")
            .field("enabled", &self.enabled())
            .field("sessions", &self.sessions.len())
            .field("forwards", &self.forwards.len())
            .finish_non_exhaustive()
    }
}

impl Default for MeshState {
    fn default() -> Self {
        Self::new(true)
    }
}

impl MeshState {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            sessions: HashMap::new(),
            pending_hs: HashMap::new(),
            last_hs: HashMap::new(),
            pings: HashMap::new(),
            routes: HashMap::new(),
            forwards: HashMap::new(),
            acked: VecDeque::new(),
            budgets: HashMap::new(),
            next_id: 1,
            last_info_ms: 0,
            stats: MeshStats::default(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&mut self, on: bool) {
        if !on {
            // Выключение — рвём сессии: продолжать RPC бессмысленно.
            self.sessions.clear();
            self.pending_hs.clear();
            self.forwards.clear();
            self.acked.clear();
        }
        self.enabled.store(on, Ordering::Relaxed);
    }

    /// Счётчики для снимка.
    pub fn stats(&self) -> MeshStats {
        let now_budget = self.budgets.len() as u32;
        MeshStats {
            sessions: self.sessions.len() as u32,
            relay_peers: now_budget,
            ..self.stats
        }
    }

    /// Живая сессия с пиром.
    pub fn session(&self, ed: &[u8; 32]) -> Option<&MeshSess> {
        self.sessions.get(ed)
    }

    /// RTT до пира, если сессия есть и измерен.
    pub fn rtt_to(&self, ed: &[u8; 32]) -> Option<u32> {
        self.sessions.get(ed).and_then(|s| s.rtt_ms)
    }

    /// Наша текущая загрузка релея 0..=255 (для PONG/ROUTE_OK).
    fn load_byte(&self, budget: u64, now_ms: u64) -> u8 {
        let used: u64 = self
            .budgets
            .values()
            .filter(|b| now_ms.saturating_sub(b.start_ms) < RELAY_WINDOW_MS)
            .map(|b| b.bytes)
            .sum();
        let cap = budget.max(1).saturating_mul(RELAY_PEERS_MAX as u64);
        ((used.min(cap) * 255) / cap) as u8
    }

    /// Списать `n` байт на реле-пира. `Err(code)` — лимит исчерпан.
    fn charge(&mut self, ed: &[u8; 32], n: u64, ctx: &MeshCtx, now_ms: u64) -> Result<(), u8> {
        if !ctx.relay_enabled {
            return Err(code::REJECTED);
        }
        // Окна старых пиров убираем, чтобы «8 пиров» не накапливались навсегда.
        self.budgets
            .retain(|_, b| now_ms.saturating_sub(b.start_ms) < RELAY_WINDOW_MS * 2);
        let b = match self.budgets.get_mut(ed) {
            Some(b) => b,
            None => {
                if self.budgets.len() >= RELAY_PEERS_MAX {
                    return Err(code::BUDGET);
                }
                self.budgets.insert(
                    *ed,
                    Budget {
                        start_ms: now_ms,
                        bytes: 0,
                    },
                );
                self.budgets.get_mut(ed).expect("только что вставили")
            }
        };
        if now_ms.saturating_sub(b.start_ms) >= RELAY_WINDOW_MS {
            b.start_ms = now_ms;
            b.bytes = 0;
        }
        let budget = ctx.relay_budget.max(1);
        if b.bytes.saturating_add(n) > budget {
            return Err(code::BUDGET);
        }
        b.bytes += n;
        self.stats.relay_bytes += n;
        Ok(())
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    // ---------- рукопожатия ----------

    /// Начать рукопожатие с контактом (только `caps::MESH`). `None` — уже
    /// есть сессия, ждём ответа или недавно пробовали (анти-спам).
    pub fn handshake(&mut self, ctx: &MeshCtx, peer: &Contact) -> Option<(SocketAddr, Vec<u8>)> {
        if !self.enabled() || !caps::has(peer.caps, caps::MESH) || !ctx.member(&peer.ed) {
            return None;
        }
        if self.sessions.contains_key(&peer.ed) {
            return None;
        }
        let now = ctx.now_ms;
        if let Some(at) = self.last_hs.get(&peer.ed)
            && now.saturating_sub(*at) < HANDSHAKE_GAP_MS
        {
            return None;
        }
        if self.sessions.len() >= MAX_SESSIONS {
            return None;
        }
        self.last_hs.insert(peer.ed, now);
        let eph = EphemeralKey::generate();
        let nonce = random_nonce();
        let hello = MeshHello::new(ctx.me, eph.public(), nonce, now, ctx.my_caps);
        let frame = hello.to_frame(mesh::MESH_HELLO);
        self.pending_hs.insert(
            peer.ed,
            PendingHs {
                eph,
                nonce,
                at_ms: now,
            },
        );
        Some((peer.addr, frame))
    }

    /// Обработать `MESH_HELLO`: проверить якорь/свежесть/подпись, ответить
    /// ACK и поставить сессию. `None` — кадр отвергнут.
    fn on_hello(
        &mut self,
        ctx: &MeshCtx,
        src: SocketAddr,
        body: &[u8],
    ) -> Option<(SocketAddr, Vec<u8>)> {
        if !self.enabled() {
            return None;
        }
        let hello = MeshHello::decode(body).ok()?;
        // Якорь доверия: ed участника группы/контакта. Чужой ключ — молча.
        if !ctx.member(&hello.ed) {
            self.stats.dropped += 1;
            return None;
        }
        if hello.verify_from(&hello.ed, ctx.now_ms).is_err() {
            self.stats.dropped += 1;
            return None;
        }
        let eph = EphemeralKey::generate();
        let shared = hello.dh(&eph).ok()?;
        // ACK эхом повторяет nonce HELLO: ответ привязан к попытке, а не
        // «случайный» (иначе запоздавший ACK прошлой попытки не отличить).
        let ack = MeshHello::new(ctx.me, eph.public(), hello.nonce, ctx.now_ms, ctx.my_caps);
        let peer_addr = src;
        let x = ctx.contact(&hello.ed).map(|c| c.x).unwrap_or([0u8; 32]);
        let caps = hello.flags;
        self.install(
            hello.ed,
            peer_addr,
            x,
            eph.public(),
            hello.eph_x,
            &shared,
            false,
            caps,
            ctx.now_ms,
        );
        // Повторный HELLO с тем же eph_x — потерянный ACK: отвечаем ещё раз,
        // но только что установленной сессией (ключи уже выведены).
        Some((peer_addr, ack.to_frame(mesh::MESH_HELLO_ACK)))
    }

    /// Обработать `MESH_HELLO_ACK`. `true` — сессия установлена.
    fn on_ack(&mut self, ctx: &MeshCtx, src: SocketAddr, body: &[u8]) -> bool {
        let Some(ack) = MeshHello::decode(body).ok() else {
            return false;
        };
        // Попытка остаётся в ожидании при любой неудаче: просроченный или
        // подделанный ACK не должен съедать наше рукопожатие.
        let Some(pending) = self.pending_hs.get(&ack.ed) else {
            return false;
        };
        // Привязка к нашей попытке: ACK обязан повторить наш nonce.
        if ack.nonce != pending.nonce {
            self.stats.dropped += 1;
            return false;
        }
        if !ctx.member(&ack.ed) || ack.verify_from(&ack.ed, ctx.now_ms).is_err() {
            self.stats.dropped += 1;
            return false;
        }
        let Ok(shared) = ack.dh(&pending.eph) else {
            self.stats.dropped += 1;
            return false;
        };
        let rtt = ctx.now_ms.saturating_sub(pending.at_ms) as u32;
        let my_eph = pending.eph.public();
        self.pending_hs.remove(&ack.ed);
        let x = ctx.contact(&ack.ed).map(|c| c.x).unwrap_or([0u8; 32]);
        let caps = ack.flags;
        self.install(
            ack.ed, src, x, my_eph, ack.eph_x, &shared, true, caps, ctx.now_ms,
        );
        if let Some(s) = self.sessions.get_mut(&ack.ed) {
            s.rtt_ms = Some(rtt);
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn install(
        &mut self,
        ed: [u8; 32],
        addr: SocketAddr,
        x: [u8; 32],
        my_eph: [u8; 32],
        peer_eph: [u8; 32],
        shared: &[u8; 32],
        initiator: bool,
        caps: u8,
        now_ms: u64,
    ) {
        // Одновременное рукопожатие (оба начали): сессии несовместимы.
        // Оставляем одну и ту же с обеих сторон — по лексикографическому
        // максимуму пары «мой eph, eph пира»: сравнение одинаково у обоих.
        if let Some(old) = self.sessions.get(&ed)
            && now_ms.saturating_sub(old.since_ms) < HANDSHAKE_TTL_MS
        {
            let old_pair = pair(old.my_eph, old.peer_eph);
            let new_pair = pair(my_eph, peer_eph);
            if old_pair >= new_pair {
                return;
            }
        }
        self.sessions.insert(
            ed,
            MeshSess::new(
                ed, addr, x, my_eph, peer_eph, shared, initiator, caps, now_ms,
            ),
        );
    }

    // ---------- приём кадров ----------

    /// Входящий mesh-кадр. `MeshOut` содержит всё, что нужно сделать движку.
    pub fn on_frame(&mut self, ctx: &MeshCtx, src: SocketAddr, typ: u8, body: &[u8]) -> MeshOut {
        let mut out = MeshOut::default();
        if !self.enabled() {
            return out;
        }
        match typ {
            mesh::MESH_HELLO => {
                if let Some((to, frame)) = self.on_hello(ctx, src, body) {
                    out.send(to, frame);
                }
            }
            mesh::MESH_HELLO_ACK => {
                self.on_ack(ctx, src, body);
            }
            mesh::MESH_FORWARD => self.on_forward(ctx, src, body, &mut out),
            _ => self.on_rpc(ctx, src, typ, body, &mut out),
        }
        out
    }

    /// RPC внутри сессии: ищем сессию по адресу (адрес — часть аутентичности).
    fn on_rpc(&mut self, ctx: &MeshCtx, src: SocketAddr, typ: u8, body: &[u8], out: &mut MeshOut) {
        let Some(ed) = self
            .sessions
            .iter()
            .find(|(_, s)| s.addr == src)
            .map(|(k, _)| *k)
        else {
            self.stats.dropped += 1;
            return;
        };
        let Some((rpc, _c)) = self.sessions.get_mut(&ed).and_then(|s| s.open(typ, body)) else {
            self.stats.dropped += 1;
            return;
        };
        if let Some(s) = self.sessions.get_mut(&ed) {
            s.last_rx_ms = ctx.now_ms;
        }
        match rpc {
            Rpc::Ping { id, ts_ms } => {
                let load = self.load_byte(ctx.relay_budget, ctx.now_ms);
                let pong = Rpc::Pong {
                    id,
                    ts_ms,
                    load,
                    caps: ctx.my_caps,
                };
                self.send_rpc(out, &ed, &pong, ctx.now_ms);
            }
            Rpc::Pong {
                id,
                ts_ms,
                load: _,
                caps: c,
            } => {
                self.pings.remove(&id);
                let rtt = ctx.now_ms.saturating_sub(ts_ms).min(u32::MAX as u64) as u32;
                if let Some(s) = self.sessions.get_mut(&ed) {
                    s.rtt_ms = Some(rtt);
                    s.ping = None;
                    s.caps = c;
                    s.last_rx_ms = ctx.now_ms;
                }
                out.events.push(MeshEvent::Rtt { ed, rtt_ms: rtt });
                self.learn(ctx, &ed, None, out);
            }
            Rpc::GetContact { target } => {
                let node = if target == ctx.me.ed_pub() {
                    ctx.my_addr.map(|addr| proto::mesh::Node {
                        ed: target,
                        x: ctx.me.x_pub(),
                        addr,
                        caps: ctx.my_caps,
                        rtt_ms: 0,
                    })
                } else {
                    ctx.contact(&target).map(node_of)
                };
                let reply = Rpc::Contact { target, node };
                self.send_rpc(out, &ed, &reply, ctx.now_ms);
            }
            Rpc::Contact { node, .. } => {
                if let Some(n) = node {
                    self.learn_wire(&n, ctx.now_ms, out);
                }
            }
            Rpc::FindNode { id, target } => {
                let nodes: Vec<proto::mesh::Node> = ctx
                    .contacts
                    .iter()
                    .filter(|c| c.ed != target)
                    .take(proto::mesh::MAX_RPC_NODES)
                    .map(node_of)
                    .collect();
                let reply = Rpc::Nodes { id, nodes };
                self.send_rpc(out, &ed, &reply, ctx.now_ms);
            }
            Rpc::Nodes { id, nodes } => {
                let contacts: Vec<Contact> = nodes
                    .iter()
                    .map(|n| Contact {
                        ed: n.ed,
                        x: n.x,
                        addr: n.addr,
                        rtt_ms: u32::from(n.rtt_ms),
                        last_seen_ms: ctx.now_ms,
                        caps: n.caps | caps::MESH,
                    })
                    .collect();
                for c in &contacts {
                    out.learned.push(c.clone());
                }
                out.finds.push((id, contacts));
            }
            Rpc::Route { id, target } => {
                let down = self
                    .sessions
                    .get(&target)
                    .and_then(|s| s.rtt_ms)
                    .or_else(|| ctx.contact(&target).map(|c| c.rtt_ms))
                    .or_else(|| (target == ctx.me.ed_pub()).then_some(0));
                match down {
                    Some(down_ms) => {
                        let reply = Rpc::RouteOk {
                            id,
                            target,
                            up_ms: self.sessions.get(&ed).and_then(|s| s.rtt_ms).unwrap_or(0),
                            down_ms,
                            load: self.load_byte(ctx.relay_budget, ctx.now_ms),
                        };
                        self.send_rpc(out, &ed, &reply, ctx.now_ms);
                    }
                    None => {
                        let reply = Rpc::RouteFail {
                            id,
                            target,
                            code: code::NO_ROUTE,
                        };
                        self.send_rpc(out, &ed, &reply, ctx.now_ms);
                    }
                }
            }
            Rpc::RouteOk {
                id,
                target,
                up_ms,
                down_ms,
                load,
            } => {
                self.routes.remove(&id);
                out.events.push(MeshEvent::RouteMeasured {
                    dst_ed: target,
                    via: ed,
                    up_ms,
                    down_ms,
                    load: f64::from(load) / 255.0,
                });
            }
            Rpc::RouteFail { id, target, .. } => {
                self.routes.remove(&id);
                out.events.push(MeshEvent::RouteFailed {
                    dst_ed: target,
                    via: ed,
                });
            }
            Rpc::ForwardAck { seq } => {
                if let Some(f) = self.forwards.remove(&(seq, ed)) {
                    // Кадр доставлен хотя бы одной копией — путь жив (issue #25).
                    self.mark_acked(seq, ctx.now_ms);
                    match f.prev {
                        // Средний хоп: подтверждаем предыдущему только теперь.
                        Some(prev) => {
                            self.send_rpc(out, &prev, &Rpc::ForwardAck { seq }, ctx.now_ms);
                            for p in &f.also {
                                self.send_rpc(out, p, &Rpc::ForwardAck { seq }, ctx.now_ms);
                            }
                        }
                        None => out.events.push(MeshEvent::ForwardOk {
                            dst_ed: f.dst_ed,
                            via: f.to,
                        }),
                    }
                }
            }
            Rpc::ForwardNack { seq, code: c } => {
                if let Some(f) = self.forwards.remove(&(seq, ed)) {
                    // Копии этого кадра ещё в полёте (дублирование, issue #25):
                    // путь снимаем только когда не осталось ни одной.
                    let in_flight = self.forwards.keys().any(|(s, _)| *s == seq);
                    let mut upstream: Vec<[u8; 32]> = Vec::new();
                    if let Some(prev) = f.prev {
                        upstream.push(prev);
                        upstream.extend(f.also.iter().copied());
                        // Промежуточному хопу тоже сообщаем: он ждёт ACK и без
                        // NACK повторял бы кадр, пока не истечёт таймаут.
                        for p in upstream.iter().filter(|p| **p != f.to) {
                            let reply = Rpc::ForwardNack { seq, code: c };
                            self.send_rpc(out, p, &reply, ctx.now_ms);
                        }
                    }
                    if f.prev.is_none() && !in_flight && !self.acked_recently(seq, ctx.now_ms) {
                        out.events.push(MeshEvent::ForwardFailed {
                            dst_ed: f.dst_ed,
                            code: c,
                        });
                    }
                }
            }
            Rpc::Bye => {
                self.sessions.remove(&ed);
                out.events.push(MeshEvent::Down { ed, reason: "bye" });
            }
        }
    }

    /// Кадр `seq` уже подтверждён кем-то из копий (issue #25): отказ
    /// оставшихся копий не должен снимать путь.
    fn acked_recently(&mut self, seq: u64, now_ms: u64) -> bool {
        while let Some((_, at)) = self.acked.front() {
            if now_ms.saturating_sub(*at) < FORWARD_ACKED_TTL_MS {
                break;
            }
            self.acked.pop_front();
        }
        self.acked.iter().any(|(s, _)| *s == seq)
    }

    fn mark_acked(&mut self, seq: u64, now_ms: u64) {
        if self.acked.len() >= MAX_PENDING_FORWARDS {
            self.acked.pop_front();
        }
        self.acked.push_back((seq, now_ms));
    }

    fn send_rpc(&mut self, out: &mut MeshOut, to: &[u8; 32], rpc: &Rpc, now_ms: u64) {
        let Some(s) = self.sessions.get_mut(to) else {
            return;
        };
        let frame = s.seal(rpc, now_ms);
        let addr = s.addr;
        out.send(addr, frame);
    }

    fn learn(&mut self, ctx: &MeshCtx, ed: &[u8; 32], rtt: Option<u32>, out: &mut MeshOut) {
        let Some(s) = self.sessions.get(ed) else {
            return;
        };
        out.learned.push(Contact {
            ed: *ed,
            x: s.x,
            addr: s.addr,
            rtt_ms: rtt.or(s.rtt_ms).unwrap_or(0),
            last_seen_ms: ctx.now_ms,
            caps: s.caps | caps::MESH,
        });
    }

    fn learn_wire(&mut self, n: &proto::mesh::Node, now_ms: u64, out: &mut MeshOut) {
        out.learned.push(Contact {
            ed: n.ed,
            x: n.x,
            addr: n.addr,
            rtt_ms: u32::from(n.rtt_ms),
            last_seen_ms: now_ms,
            caps: n.caps | caps::MESH,
        });
    }

    // ---------- релей ----------

    /// `MESH_FORWARD`: либо нам, либо мы — реле.
    fn on_forward(&mut self, ctx: &MeshCtx, src: SocketAddr, body: &[u8], out: &mut MeshOut) {
        let Ok(f) = MeshForward::decode(body) else {
            self.stats.dropped += 1;
            return;
        };
        let now = ctx.now_ms;
        let me = ctx.me.ed_pub();
        // Кто прислал на самом деле: сессия на этом адресе. Обёртка
        // открытая, поэтому без сессии подделать отправителя нельзя; `src_ed`
        // в обёртке — исходный источник (реле его не меняет) и обязан быть
        // участником группы.
        let Some(from_ed) = self
            .sessions
            .iter()
            .find(|(_, s)| s.addr == src)
            .map(|(k, _)| *k)
        else {
            self.stats.dropped += 1;
            return;
        };
        if !ctx.member(&f.src_ed) {
            self.stats.dropped += 1;
            return;
        }
        let seq = forward_seq(&f.inner);
        if f.dst_ed == me {
            // Нам: движок расшифрует групповым ключом и ответит ACK/NACK.
            out.deliver.push(Relayed {
                from_ed,
                seq,
                hops: f.hops,
                inner: f.inner,
            });
            return;
        }
        // Мы — реле.
        let refused = self
            .relay_forward(ctx, &f, seq, from_ed, now, out)
            .err()
            .unwrap_or(0);
        if refused != 0 {
            let nack = Rpc::ForwardNack { seq, code: refused };
            self.send_rpc(out, &from_ed, &nack, now);
        }
    }

    /// Проверить и переслать кадр дальше. `Err(code)` — отказ с NACK.
    fn relay_forward(
        &mut self,
        ctx: &MeshCtx,
        f: &MeshForward,
        seq: u64,
        from_ed: [u8; 32],
        now: u64,
        out: &mut MeshOut,
    ) -> Result<(), u8> {
        if !ctx.relay_enabled {
            return Err(code::REJECTED);
        }
        let me = ctx.me.ed_pub();
        if f.hops >= mesh::MESH_MAX_HOPS {
            return Err(code::LOOP);
        }
        if f.visited.len() > MAX_VISITED
            || f.visited.contains(&me)
            || f.visited.contains(&f.dst_ed)
            || f.visited.contains(&f.src_ed)
        {
            return Err(code::LOOP);
        }
        let (_, h) = proto::parse_group_header(&f.inner).map_err(|_| code::BAD)?;
        // Реле не расшифровывает inner, но открытый заголовок обязан быть
        // кадром своей группы: иначе это мусор/чужая группа.
        if !(ctx.check_group)(h.gid, h.src, h.dst, h.epoch) {
            return Err(code::BAD);
        }
        if self.forwards.len() >= MAX_PENDING_FORWARDS {
            return Err(code::REJECTED);
        }
        // Куда дальше: сессия есть — её адрес; иначе контакт DHT.
        let (to_ed, to_addr) = match self.sessions.get(&f.dst_ed) {
            Some(s) => (f.dst_ed, s.addr),
            None => match ctx.contact(&f.dst_ed) {
                Some(c) => (f.dst_ed, c.addr),
                None => return Err(code::NO_ROUTE),
            },
        };
        // Дублированный кадр сошёлся в нас с двух путей (issue #25): копия к
        // получателю уже в полёте — вторую не шлём, но запоминаем, кому ещё
        // должны ACK/NACK, иначе этот хоп повторял бы кадр до таймаута.
        if let Some(p) = self.forwards.get_mut(&(seq, to_ed)) {
            if p.prev != Some(from_ed)
                && p.also.len() < FORWARD_WAITERS_MAX
                && !p.also.contains(&from_ed)
            {
                p.also.push(from_ed);
            }
            return Ok(());
        }
        // Бюджет: и входящий (нам), и исходящий (дальше) — наша полоса.
        self.charge(&from_ed, f.inner.len() as u64, ctx, now)?;
        self.charge(&to_ed, f.inner.len() as u64, ctx, now)?;
        let mut visited = f.visited.clone();
        visited.push(me);
        let hops = f.hops.saturating_add(1);
        let next = MeshForward {
            dst_ed: f.dst_ed,
            src_ed: f.src_ed,
            hops,
            visited,
            inner: f.inner.clone(),
        };
        let frame = next.to_frame().map_err(|_| code::BAD)?;
        self.forwards.insert(
            (seq, to_ed),
            PendingForward {
                to: to_ed,
                prev: Some(from_ed),
                also: Vec::new(),
                dst_ed: f.dst_ed,
                at_ms: now,
                tries: 0,
                frame: frame.clone(),
                addr: to_addr,
            },
        );
        self.stats.forwarded += 1;
        out.send(to_addr, frame);
        Ok(())
    }

    /// Отправить групповой кадр через реле `hop` (L2, инициатор — мы).
    ///
    /// `Err(code)` — реле недоступно/лимит: движок возьмёт следующего
    /// кандидата или сервер.
    pub fn start_forward(
        &mut self,
        ctx: &MeshCtx,
        dst_ed: [u8; 32],
        hop: &Contact,
        inner: &[u8],
    ) -> Result<(SocketAddr, Vec<u8>), u8> {
        if !self.enabled() || !ctx.relay_enabled {
            return Err(code::REJECTED);
        }
        if inner.len() > MAX_FORWARD_INNER {
            return Err(code::BAD);
        }
        if self.forwards.len() >= MAX_PENDING_FORWARDS {
            return Err(code::REJECTED);
        }
        let Some(s) = self.sessions.get(&hop.ed) else {
            return Err(code::NO_ROUTE);
        };
        let addr = s.addr;
        let now = ctx.now_ms;
        self.charge(&hop.ed, inner.len() as u64, ctx, now)?;
        let seq = forward_seq(inner);
        let f = MeshForward {
            dst_ed,
            src_ed: ctx.me.ed_pub(),
            hops: 0,
            visited: Vec::new(),
            inner: inner.to_vec(),
        };
        let frame = f.to_frame().map_err(|_| code::BAD)?;
        self.forwards.insert(
            (seq, hop.ed),
            PendingForward {
                to: hop.ed,
                prev: None,
                also: Vec::new(),
                dst_ed,
                at_ms: now,
                tries: 0,
                frame: frame.clone(),
                addr,
            },
        );
        self.stats.forwarded += 1;
        Ok((addr, frame))
    }

    /// Результат проверки доставленного нам кадра: движок зовёт после
    /// расшифровки. Возвращает готовый ACK/NACK (если есть сессия с отправителем).
    #[must_use]
    pub fn delivery_result(
        &mut self,
        now_ms: u64,
        r: &Relayed,
        ok: bool,
        why: u8,
    ) -> Option<(SocketAddr, Vec<u8>)> {
        if ok {
            self.stats.delivered += 1;
        }
        let rpc = if ok {
            Rpc::ForwardAck { seq: r.seq }
        } else {
            Rpc::ForwardNack {
                seq: r.seq,
                code: why,
            }
        };
        let s = self.sessions.get_mut(&r.from_ed)?;
        let frame = s.seal(&rpc, now_ms);
        let addr = s.addr;
        Some((addr, frame))
    }

    /// Немедленный NACK (кадр не смогли даже начать разбирать) — по сессии.
    pub fn nack(
        &mut self,
        now_ms: u64,
        seq: u64,
        from_ed: &[u8; 32],
        why: u8,
    ) -> Option<(SocketAddr, Vec<u8>)> {
        let s = self.sessions.get_mut(from_ed)?;
        let frame = s.seal(&Rpc::ForwardNack { seq, code: why }, now_ms);
        let addr = s.addr;
        Some((addr, frame))
    }

    // ---------- таймеры ----------

    /// Периодическая работа: рукопожатия, пинги, повторы forward, таймауты.
    pub fn tick(&mut self, ctx: &MeshCtx) -> MeshOut {
        let mut out = MeshOut::default();
        if !self.enabled() {
            return out;
        }
        let now = ctx.now_ms;
        // 1. MESH_INFO — сразу после первого вызова и далее раз в 5 минут.
        if now.saturating_sub(self.last_info_ms) >= INFO_EVERY_MS || self.last_info_ms == 0 {
            self.last_info_ms = now;
            out.info_due = true;
        }
        // 2. Просроченные рукопожатия — забыть, чтобы можно было начать заново.
        self.pending_hs
            .retain(|_, p| now.saturating_sub(p.at_ms) < HANDSHAKE_TTL_MS);
        // 3. Рукопожатия с mesh-контактами: до 4 новых за тик.
        let mut started = 0;
        for c in ctx.contacts {
            if started >= 4 {
                break;
            }
            if let Some((to, frame)) = self.handshake(ctx, c) {
                out.send(to, frame);
                started += 1;
            }
        }
        // Повторить уже начатые (по ответу прошлой попытки) — handshake()
        // выше отправляет первое HELLO; повтор сам сделает следующий тик.
        // 4. Пинги и таймауты сессий; заодно собираем исходящие.
        let now_ms = now;
        let mut dead: Vec<([u8; 32], &'static str)> = Vec::new();
        let mut ping_now: Vec<[u8; 32]> = Vec::new();
        for (ed, s) in self.sessions.iter() {
            if now_ms.saturating_sub(s.last_rx_ms) > SESSION_IDLE_MS {
                dead.push((*ed, "таймаут сессии"));
                continue;
            }
            if let Some((_, at)) = s.ping {
                if now_ms.saturating_sub(at) >= PING_TIMEOUT_MS {
                    dead.push((*ed, "нет PONG"));
                }
            } else if now_ms.saturating_sub(s.last_tx_ms) >= PING_EVERY_MS || s.rtt_ms.is_none() {
                ping_now.push(*ed);
            }
        }
        for ed in ping_now {
            if dead.iter().any(|(d, _)| *d == ed) {
                continue;
            }
            let id = self.next_id();
            let Some(s) = self.sessions.get_mut(&ed) else {
                continue;
            };
            let rpc = Rpc::Ping { id, ts_ms: now_ms };
            let frame = s.seal(&rpc, now_ms);
            let addr = s.addr;
            s.ping = Some((id, now_ms));
            self.pings.insert(id, PendingPing { at_ms: now_ms });
            out.send(addr, frame);
        }
        for (ed, reason) in dead {
            self.sessions.remove(&ed);
            self.forwards
                .retain(|(_, to), f| *to != ed && f.prev != Some(ed) && !f.also.contains(&ed));
            out.events.push(MeshEvent::Down { ed, reason });
        }
        // Просроченные ожидания RPC — не копим.
        self.pings
            .retain(|_, p| now.saturating_sub(p.at_ms) < PING_TIMEOUT_MS * 2);
        self.routes
            .retain(|_, (_, at)| now.saturating_sub(*at) < PING_TIMEOUT_MS * 2);
        // 5. Повторы forward и отказ после FORWARD_TRIES. Копии одного кадра
        //    (дублирование, issue #25) повторяются независимо: у каждой свой
        //    хоп, счётчик попыток и время.
        let mut failed: Vec<(u64, [u8; 32], [u8; 32], u8)> = Vec::new();
        for ((seq, to), f) in self.forwards.iter_mut() {
            if now.saturating_sub(f.at_ms) < FORWARD_GAP_MS {
                continue;
            }
            if f.tries >= FORWARD_TRIES {
                failed.push((*seq, *to, f.dst_ed, code::REJECTED));
                continue;
            }
            f.tries += 1;
            f.at_ms = now;
            out.send(f.addr, f.frame.clone());
        }
        for (seq, to, dst_ed, c) in failed {
            let Some(f) = self.forwards.remove(&(seq, to)) else {
                continue;
            };
            // Ожидание ACK не срослось: сообщаем предыдущим хопам.
            if let Some(prev) = f.prev {
                let nack = Rpc::ForwardNack { seq, code: c };
                self.send_rpc(&mut out, &prev, &nack, now);
                for p in &f.also {
                    self.send_rpc(&mut out, p, &nack, now);
                }
            }
            // Копии того же кадра ещё в полёте — путь снимать рано.
            if self.forwards.keys().any(|(s, _)| *s == seq) {
                continue;
            }
            // Другая копия уже дошла — этот отказ путь не снимает (issue #25).
            if self.acked_recently(seq, now) {
                continue;
            }
            out.events
                .push(MeshEvent::ForwardFailed { dst_ed, code: c });
        }
        out
    }

    /// DHT-поиск: `MESH_FIND_NODE` через сессию `via`.
    pub fn find_node(
        &mut self,
        ctx: &MeshCtx,
        via: &[u8; 32],
        id: u64,
        target: [u8; 32],
    ) -> Option<(SocketAddr, Vec<u8>)> {
        let rpc = Rpc::FindNode { id, target };
        let s = self.sessions.get_mut(via)?;
        let frame = s.seal(&rpc, ctx.now_ms);
        let addr = s.addr;
        Some((addr, frame))
    }

    /// Запрос маршрута через пира (для PathTable): `MESH_ROUTE` сессии `via`.
    pub fn route_probe(
        &mut self,
        ctx: &MeshCtx,
        via: &[u8; 32],
        target_ed: [u8; 32],
        addr: SocketAddr,
    ) -> Option<(SocketAddr, Vec<u8>)> {
        if !self.enabled() {
            return None;
        }
        if self.routes.len() >= MAX_PENDING_RPC {
            return None;
        }
        let id = self.next_id();
        let rpc = Rpc::Route {
            id,
            target: target_ed,
        };
        let s = self.sessions.get_mut(via)?;
        let frame = s.seal(&rpc, ctx.now_ms);
        let to = s.addr;
        self.routes.insert(id, (target_ed, ctx.now_ms));
        // `addr` — запасной вариант: если адрес сессии пустой (не установлен),
        // шлём по известному адресу контакта.
        let _ = addr;
        Some((to, frame))
    }

    /// PING конкретному пиру (например, при смене адреса).
    pub fn ping_peer(&mut self, ctx: &MeshCtx, ed: &[u8; 32]) -> Option<(SocketAddr, Vec<u8>)> {
        let id = self.next_id();
        let rpc = Rpc::Ping {
            id,
            ts_ms: ctx.now_ms,
        };
        let s = self.sessions.get_mut(ed)?;
        let frame = s.seal(&rpc, ctx.now_ms);
        let addr = s.addr;
        s.ping = Some((id, ctx.now_ms));
        self.pings.insert(id, PendingPing { at_ms: ctx.now_ms });
        Some((addr, frame))
    }

    /// Кого из mesh-контактов ещё нет в сессиях (для `handshake`).
    pub fn needs_handshake(&self, ctx: &MeshCtx) -> Vec<Contact> {
        if !self.enabled() {
            return Vec::new();
        }
        ctx.contacts
            .iter()
            .filter(|c| caps::has(c.caps, caps::MESH))
            .filter(|c| !self.sessions.contains_key(&c.ed))
            .filter(|c| {
                self.last_hs
                    .get(&c.ed)
                    .is_none_or(|at| ctx.now_ms.saturating_sub(*at) >= HANDSHAKE_GAP_MS)
            })
            .cloned()
            .collect()
    }

    /// Контакты (ed, x, addr, caps) сессий — для DHT и снимков.
    pub fn session_contacts(&self) -> Vec<Contact> {
        self.sessions
            .values()
            .map(|s| Contact {
                ed: s.ed,
                x: s.x,
                addr: s.addr,
                rtt_ms: s.rtt_ms.unwrap_or(0),
                last_seen_ms: s.last_rx_ms,
                caps: s.caps | caps::MESH,
            })
            .collect()
    }

    /// Закрыть сессию вежливо (BYE) — при выходе из группы/остановке.
    pub fn bye_all(&mut self, ctx: &MeshCtx) -> Vec<(SocketAddr, Vec<u8>)> {
        let now = ctx.now_ms;
        let mut out = Vec::new();
        for s in self.sessions.values_mut() {
            let frame = s.seal(&Rpc::Bye, now);
            out.push((s.addr, frame));
        }
        self.sessions.clear();
        self.pending_hs.clear();
        self.forwards.clear();
        out
    }

    /// DHT-таблица из сессий (движок дополняет её своими контактами).
    pub fn absorb_into(&self, dht: &mut Dht, now_ms: u64) {
        for s in self.sessions.values() {
            let seen = s.last_rx_ms.min(now_ms);
            dht.add_group_peer(s.ed, s.x, s.addr, s.caps | caps::MESH, seen);
        }
    }
}

/// `MESH_SEED` от сервера: убрать свой и нулевой ed (в таблицу они не годятся).
/// Движок отдаёт результат `Dht::bootstrap`.
pub fn note_seeds(seeds: &[MeshSeed], me: &[u8; 32]) -> Vec<MeshSeed> {
    seeds
        .iter()
        .filter(|s| s.ed_pub != *me && s.ed_pub != [0u8; 32])
        .cloned()
        .collect()
}

fn node_of(c: &Contact) -> proto::mesh::Node {
    proto::mesh::Node {
        ed: c.ed,
        x: c.x,
        addr: c.addr,
        caps: c.caps,
        rtt_ms: c.rtt_ms.min(u32::from(u16::MAX)) as u16,
    }
}

/// Идентификатор forward — хэш внутреннего кадра: одинаков при повторах,
/// разный у разных кадров (в т.ч. при релее через несколько хопов).
pub fn forward_seq(inner: &[u8]) -> u64 {
    let h = blake3::hash(inner);
    u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap())
}

/// Упорядоченная пара эфемерных ключей сессии (tie-break рукопожатий).
fn pair(a: [u8; 32], b: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    if a <= b { (a, b) } else { (b, a) }
}

fn random_nonce() -> [u8; mesh::MESH_NONCE_LEN] {
    use rand::Rng;
    let mut n = [0u8; mesh::MESH_NONCE_LEN];
    rand::rng().fill_bytes(&mut n);
    n
}

/// Заглушка типа для `on_ack` (возвращает «отправлять нечего»).
/// Ближайшие к `target` контакты DHT для `MESH_FIND_NODE` (движок).
pub fn find_targets(dht: &Dht, target: &[u8; 32], n: usize) -> Vec<Contact> {
    dht.closest(target, n)
}

/// Самопроверка инвариантов контакта (движок перед вставкой в DHT).
pub fn sane_contact(c: &Contact) -> bool {
    c.ed != [0u8; 32] && caps::has(c.caps, caps::MESH) && c.addr.port() != 0
}

/// Первый доступный relay-кандидат из DHT для `dst_ed` (движок).
pub fn relay_candidates(dht: &Dht, dst_ed: &[u8; 32], n: usize) -> Vec<Contact> {
    dht.relay_candidates(dst_ed, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Peer {
        id: proto::Identity,
        x: [u8; 32],
        addr: SocketAddr,
        st: MeshState,
    }

    fn peer(port: u16) -> Peer {
        let id = proto::Identity::generate();
        Peer {
            x: id.x_pub(),
            addr: format!("127.0.0.1:{port}").parse().unwrap(),
            st: MeshState::new(true),
            id,
        }
    }

    fn contact(p: &Peer) -> Contact {
        Contact {
            ed: p.id.ed_pub(),
            x: p.x,
            addr: p.addr,
            rtt_ms: 0,
            last_seen_ms: 0,
            caps: caps::MESH | caps::RELAY,
        }
    }

    fn ctx<'a>(
        me: &'a proto::Identity,
        contacts: &'a [Contact],
        members: &'a [[u8; 32]],
        now_ms: u64,
    ) -> MeshCtx<'a> {
        MeshCtx {
            me,
            my_caps: caps::MESH | caps::RELAY,
            now_ms,
            my_addr: None,
            contacts,
            members,
            relay_enabled: true,
            relay_budget: 1 << 20,
            check_group: &|_, _, _, _| true,
        }
    }

    /// Расшифровать RPC из готового кадра сессией `from`.
    fn open_from(st: &mut MeshState, from: &[u8; 32], frame: &[u8]) -> Rpc {
        let (typ, body) = proto::split_frame(frame).unwrap();
        st.sessions
            .get_mut(from)
            .expect("сессия с отправителем")
            .open(typ, body)
            .expect("RPC расшифровывается")
            .0
    }

    /// Свести рукопожатие двух сторон: HELLO a→b, ACK b→a.
    fn handshake(a: &mut Peer, b: &mut Peer, now: u64) {
        let ca = [contact(a)];
        let cb = [contact(b)];
        let ma = [b.id.ed_pub()];
        let mb = [a.id.ed_pub()];
        let a_ctx = ctx(&a.id, &ca, &ma, now);
        let b_ctx = ctx(&b.id, &cb, &mb, now);
        // a инициирует.
        let (to, frame) = a.st.handshake(&a_ctx, &contact(b)).expect("handshake");
        assert_eq!(to, b.addr);
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let out = b.st.on_frame(&b_ctx, a.addr, typ, body);
        assert_eq!(out.sends.len(), 1, "ACK");
        let (to2, ack) = &out.sends[0];
        assert_eq!(*to2, a.addr);
        let (typ, body) = proto::split_frame(ack).unwrap();
        assert_eq!(typ, mesh::MESH_HELLO_ACK);
        let out = a.st.on_frame(&a_ctx, b.addr, typ, body);
        assert!(out.sends.is_empty());
        assert!(a.st.session(&b.id.ed_pub()).is_some());
        assert!(b.st.session(&a.id.ed_pub()).is_some());
    }

    #[test]
    fn рукопожатие_и_пинг_понг() {
        let mut a = peer(4001);
        let mut b = peer(4002);
        handshake(&mut a, &mut b, 1_000);
        // RPC: PING от a, PONG от b.
        let ca = [contact(&b)];
        let ma = [b.id.ed_pub()];
        let a_ctx = ctx(&a.id, &ca, &ma, 2_000);
        let (to, frame) = a.st.ping_peer(&a_ctx, &b.id.ed_pub()).expect("ping");
        assert_eq!(to, b.addr);
        let cb = [contact(&a)];
        let mb = [a.id.ed_pub()];
        let b_ctx = ctx(&b.id, &cb, &mb, 2_010);
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let out = b.st.on_frame(&b_ctx, a.addr, typ, body);
        assert_eq!(out.sends.len(), 1, "PONG");
        let (typ, body) = proto::split_frame(&out.sends[0].1).unwrap();
        assert_eq!(typ, mesh::MESH_PONG);
        let a_rx = ctx(&a.id, &ca, &ma, 2_600);
        let out = a.st.on_frame(&a_rx, b.addr, typ, body);
        assert_eq!(
            out.events,
            vec![MeshEvent::Rtt {
                ed: b.id.ed_pub(),
                rtt_ms: 600
            }]
        );
        assert_eq!(a.st.rtt_to(&b.id.ed_pub()), Some(600));
        assert!(!out.learned.is_empty(), "контакт обновился");
        // Повтор того же PONG (replay) — отбрасывается окном.
        let out = a.st.on_frame(&a_ctx, b.addr, typ, body);
        assert!(out.events.is_empty(), "повтор PONG не принят");
    }

    #[test]
    fn одновременное_рукопожатие_даёт_совместимые_сессии() {
        // Оба пира начинают рукопожатие в один тик (типичный случай: mesh
        // поднимается сразу после GROUP_STATE с обеих сторон). Пары
        // эфемерных ключей разные, и без детерминированного выбора сессии
        // стороны остались бы с несовместимыми ключами (PING без PONG).
        let mut a = peer(4020);
        let mut b = peer(4021);
        let ca = [contact(&b)];
        let ma = [b.id.ed_pub()];
        let cb = [contact(&a)];
        let mb = [a.id.ed_pub()];
        let now = 1_000;
        let a_ctx = ctx(&a.id, &ca, &ma, now);
        let b_ctx = ctx(&b.id, &cb, &mb, now);
        let (_, ha) = a.st.handshake(&a_ctx, &contact(&b)).expect("a начал");
        let (_, hb) = b.st.handshake(&b_ctx, &contact(&a)).expect("b начал");
        // Перекрёстный обмен: b получает HELLO_a, a получает HELLO_b.
        let (typ, body) = proto::split_frame(&ha).unwrap();
        let out_b = b.st.on_frame(&b_ctx, a.addr, typ, body);
        assert_eq!(out_b.sends.len(), 1, "b ответил ACK на HELLO_a");
        let (typ, body) = proto::split_frame(&hb).unwrap();
        let out_a = a.st.on_frame(&a_ctx, b.addr, typ, body);
        assert_eq!(out_a.sends.len(), 1, "a ответил ACK на HELLO_b");
        // Теперь каждый получает ACK на свою попытку.
        let (typ, body) = proto::split_frame(&out_b.sends[0].1).unwrap();
        a.st.on_frame(&a_ctx, b.addr, typ, body);
        let (typ, body) = proto::split_frame(&out_a.sends[0].1).unwrap();
        b.st.on_frame(&b_ctx, a.addr, typ, body);
        assert!(a.st.session(&b.id.ed_pub()).is_some());
        assert!(b.st.session(&a.id.ed_pub()).is_some());
        // Ключи совместимы: PING доходит и получает PONG.
        let (to, ping) = a.st.ping_peer(&a_ctx, &b.id.ed_pub()).expect("ping");
        assert_eq!(to, b.addr);
        let (typ, body) = proto::split_frame(&ping).unwrap();
        let out = b.st.on_frame(&b_ctx, a.addr, typ, body);
        assert_eq!(out.sends.len(), 1, "PONG: ключи сессии совпали");
        let (typ, body) = proto::split_frame(&out.sends[0].1).unwrap();
        let out = a.st.on_frame(&a_ctx, b.addr, typ, body);
        assert!(matches!(out.events.first(), Some(MeshEvent::Rtt { .. })));
    }

    #[test]
    fn чужой_ed_и_подпись_отвергаются() {
        let mut a = peer(4001);
        let b = peer(4002);
        let stranger = peer(4003);
        let ca = [contact(&a)];
        let ma = [a.id.ed_pub()];
        let a_ctx = ctx(&a.id, &ca, &ma, 10_000);
        // HELLO от того, кого нет в составе/контактах.
        let eph = EphemeralKey::generate();
        let hello = MeshHello::new(
            &stranger.id,
            eph.public(),
            [1u8; mesh::MESH_NONCE_LEN],
            10_000,
            caps::MESH,
        );
        let frame = hello.to_frame(mesh::MESH_HELLO);
        let (typ, body) = proto::split_frame(&frame).unwrap();
        assert!(
            a.st.on_frame(&a_ctx, stranger.addr, typ, body)
                .sends
                .is_empty()
        );
        assert!(a.st.session(&stranger.id.ed_pub()).is_none());
        // Свой ed, но битая подпись.
        let mut bad = hello;
        bad.ed = a.id.ed_pub();
        bad.sig = [0u8; 64];
        let frame = bad.to_frame(mesh::MESH_HELLO);
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let out = a.st.on_frame(&a_ctx, b.addr, typ, body);
        assert!(out.sends.is_empty());
        assert_eq!(a.st.stats().dropped, 2);
    }

    #[test]
    fn просрочка_и_эхо_nonce_ack() {
        let mut a = peer(4001);
        let mut b = peer(4002);
        let ca = [contact(&b)];
        let cb = [contact(&a)];
        let ma = [b.id.ed_pub()];
        let mb = [a.id.ed_pub()];
        let now = 1_000_000;
        let a_ctx = ctx(&a.id, &ca, &ma, now);
        let b_ctx = ctx(&b.id, &cb, &mb, now);
        let (_, frame) = a.st.handshake(&a_ctx, &contact(&b)).unwrap();
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let out = b.st.on_frame(&b_ctx, a.addr, typ, body);
        let (_, ack) = &out.sends[0];
        // ACK приходит через 3 минуты — просрочен (окно 120 с).
        let late = ctx(&a.id, &ca, &ma, now + mesh::MESH_TS_SKEW_MS + 1);
        let (typ, body) = proto::split_frame(ack).unwrap();
        assert!(a.st.on_frame(&late, b.addr, typ, body).sends.is_empty());
        assert!(a.st.session(&b.id.ed_pub()).is_none());
        // Свежий ACK — принимается.
        let (typ, body) = proto::split_frame(ack).unwrap();
        a.st.on_frame(&a_ctx, b.addr, typ, body);
        assert!(a.st.session(&b.id.ed_pub()).is_some());
        // ACK с чужим nonce (не эхо нашей попытки) — отказ.
        let mut a2 = peer(4005);
        let (_, frame) = a2
            .st
            .handshake(&ctx(&a2.id, &ca, &ma, now), &contact(&b))
            .unwrap();
        let (typ, body) = proto::split_frame(&frame).unwrap();
        b.st.on_frame(&b_ctx, a.addr, typ, body);
        let eph = EphemeralKey::generate();
        let wrong = MeshHello::new(
            &b.id,
            eph.public(),
            [0xAA; mesh::MESH_NONCE_LEN],
            now,
            caps::MESH,
        );
        let fr1 = wrong.to_frame(mesh::MESH_HELLO_ACK);
        let (typ, body) = proto::split_frame(&fr1).unwrap();
        let out = a2
            .st
            .on_frame(&ctx(&a2.id, &ca, &ma, now), b.addr, typ, body);
        assert!(out.sends.is_empty());
        assert!(a2.st.session(&b.id.ed_pub()).is_none());
    }

    #[test]
    fn малый_порядок_эфемерного_ключа() {
        let mut a = peer(4001);
        let b = peer(4002);
        let ca = [contact(&b)];
        let ma = [b.id.ed_pub()];
        let a_ctx = ctx(&a.id, &ca, &ma, 1_000);
        // Шлём HELLO с eph_x = 0 (точка малого порядка) и валидной подписью.
        let mut hello = MeshHello::new(&b.id, [0u8; 32], [2u8; 16], 1_000, caps::MESH);
        hello.sig = b.id.sign(&hello.signing_payload());
        let fr2 = hello.to_frame(mesh::MESH_HELLO);
        let (typ, body) = proto::split_frame(&fr2).unwrap();
        let out = a.st.on_frame(&a_ctx, b.addr, typ, body);
        assert!(out.sends.is_empty(), "ACK не отправляется");
        assert!(a.st.session(&b.id.ed_pub()).is_none());
    }

    #[test]
    fn forward_через_реле_и_ack() {
        let mut a = peer(4001); // источник
        let mut b = peer(4002); // реле
        let mut c = peer(4003); // получатель
        let now = 1_000;
        handshake(&mut a, &mut b, now);
        handshake(&mut b, &mut c, now);
        handshake(&mut a, &mut c, now);
        let inner = proto::seal_group(
            &[3u8; 32],
            proto::grp::DATA,
            &proto::GroupHeader {
                gid: 1,
                src: 2,
                dst: 3,
                epoch: 1,
            },
            0,
            b"payload",
        );
        let cb = [contact(&b), contact(&c)];
        let ma = [b.id.ed_pub(), c.id.ed_pub()];
        let a_ctx = ctx(&a.id, &cb, &ma, now + 10);
        let (to, frame) =
            a.st.start_forward(&a_ctx, c.id.ed_pub(), &contact(&b), &inner)
                .expect("forward");
        assert_eq!(to, b.addr);
        // b принимает: реле — пересылает c, ставит pending.
        let ca = [contact(&a), contact(&c)];
        let mb = [a.id.ed_pub(), c.id.ed_pub()];
        let b_ctx = ctx(&b.id, &ca, &mb, now + 20);
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let out = b.st.on_frame(&b_ctx, a.addr, typ, body);
        assert_eq!(out.sends.len(), 1);
        assert_eq!(out.sends[0].0, c.addr);
        // c получает кадр для себя.
        let ca2 = [contact(&a), contact(&b)];
        let mc = [a.id.ed_pub(), b.id.ed_pub()];
        let c_ctx = ctx(&c.id, &ca2, &mc, now + 30);
        let (typ, body) = proto::split_frame(&out.sends[0].1).unwrap();
        let out = c.st.on_frame(&c_ctx, b.addr, typ, body);
        assert_eq!(out.deliver.len(), 1, "доставка нам");
        let r = out.deliver[0].clone();
        assert_eq!(r.inner, inner);
        assert_eq!(r.hops, 1);
        // c подтверждает — b получает ACK и отвечает a.
        let (to, ack) = c.st.delivery_result(now + 30, &r, true, 0).expect("ack");
        assert_eq!(to, b.addr);
        let (typ, body) = proto::split_frame(&ack).unwrap();
        let out =
            b.st.on_frame(&ctx(&b.id, &ca, &mb, now + 40), c.addr, typ, body);
        assert_eq!(out.sends.len(), 1, "ACK дальше источнику");
        let (typ, body) = proto::split_frame(&out.sends[0].1).unwrap();
        let out = a.st.on_frame(&a_ctx, b.addr, typ, body);
        assert!(matches!(
            out.events.first(),
            Some(MeshEvent::ForwardOk { dst_ed, .. }) if *dst_ed == c.id.ed_pub()
        ));
        assert!(a.st.stats().relay_bytes > 0);
    }

    #[test]
    fn повтор_forward_на_двух_релеях_не_затирает_запись() {
        // Источник шлёт один и тот же кадр двумя релеями (дублирование путей,
        // issue #25): записи о копиях не затирают друг друга, ACK одной копии
        // не снимает вторую, а отказ второй после успешной первой путь не
        // снимает (иначе дублирование само снимало бы здоровый путь).
        let mut a = peer(4001); // источник
        let mut b = peer(4002); // релей 1
        let mut c = peer(4003); // релей 2
        let now = 1_000;
        handshake(&mut a, &mut b, now);
        handshake(&mut a, &mut c, now);
        let inner = proto::seal_group(
            &[3u8; 32],
            proto::grp::DATA,
            &proto::GroupHeader {
                gid: 1,
                src: 2,
                dst: 3,
                epoch: 1,
            },
            0,
            b"dup",
        );
        let seq = forward_seq(&inner);
        let ca = [contact(&b), contact(&c)];
        let ma = [b.id.ed_pub(), c.id.ed_pub()];
        let a_ctx = ctx(&a.id, &ca, &ma, now + 10);
        let (to1, _) =
            a.st.start_forward(&a_ctx, [9u8; 32], &contact(&b), &inner)
                .expect("копия через B");
        let (to2, _) =
            a.st.start_forward(&a_ctx, [9u8; 32], &contact(&c), &inner)
                .expect("копия через C");
        assert_eq!((to1, to2), (b.addr, c.addr));
        assert_eq!(a.st.forwards.len(), 2, "две копии — две записи");
        assert!(a.st.forwards.contains_key(&(seq, b.id.ed_pub())));
        assert!(a.st.forwards.contains_key(&(seq, c.id.ed_pub())));
        // ACK от B снимает только его копию.
        let mut out = MeshOut::default();
        b.st.send_rpc(&mut out, &a.id.ed_pub(), &Rpc::ForwardAck { seq }, now + 20);
        let (typ, body) = proto::split_frame(&out.sends[0].1).unwrap();
        let out =
            a.st.on_frame(&ctx(&a.id, &ca, &ma, now + 20), b.addr, typ, body);
        assert!(matches!(
            out.events.first(),
            Some(MeshEvent::ForwardOk { dst_ed, .. }) if *dst_ed == [9u8; 32]
        ));
        assert_eq!(a.st.forwards.len(), 1, "копия через C осталась");
        assert!(a.st.forwards.contains_key(&(seq, c.id.ed_pub())));
        // NACK от C: кадр уже доставлен копией B — путь не снимаем.
        let mut out = MeshOut::default();
        c.st.send_rpc(
            &mut out,
            &a.id.ed_pub(),
            &Rpc::ForwardNack {
                seq,
                code: code::REJECTED,
            },
            now + 30,
        );
        let (typ, body) = proto::split_frame(&out.sends[0].1).unwrap();
        let out =
            a.st.on_frame(&ctx(&a.id, &ca, &ma, now + 30), c.addr, typ, body);
        assert!(a.st.forwards.is_empty(), "обе копии закрыты");
        assert!(
            out.events.is_empty(),
            "отказ второй копии не снимает доставленный путь"
        );
    }

    #[test]
    fn forward_visited_ttl_и_петля() {
        let mut a = peer(4001); // реле
        let mut b = peer(4002); // источник
        let mut c = peer(4003); // получатель
        let now = 1_000;
        handshake(&mut b, &mut a, now);
        handshake(&mut a, &mut c, now);
        let inner = proto::seal_group(
            &[3u8; 32],
            proto::grp::DATA,
            &proto::GroupHeader {
                gid: 1,
                src: 2,
                dst: 3,
                epoch: 1,
            },
            0,
            b"x",
        );
        let cb = [contact(&a), contact(&c)];
        let mb = [a.id.ed_pub(), b.id.ed_pub(), c.id.ed_pub()];
        let ctx_a = ctx(&a.id, &cb, &mb, now + 10);
        // TTL: hops = 3 — дальше не пересылаем, отвечаем NACK.
        let f = MeshForward {
            dst_ed: c.id.ed_pub(),
            src_ed: b.id.ed_pub(),
            hops: 3,
            visited: vec![[1u8; 32], [2u8; 32], [4u8; 32]],
            inner: inner.clone(),
        };
        let frame = f.to_frame().unwrap();
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let out = a.st.on_frame(&ctx_a, b.addr, typ, body);
        assert!(out.deliver.is_empty());
        assert_eq!(out.sends.len(), 1, "NACK источнику");
        let (typ, _body) = proto::split_frame(&out.sends[0].1).unwrap();
        assert_eq!(typ, mesh::MESH_FORWARD_NACK);
        // Петля: мы уже в visited.
        let mut f2 = f.clone();
        f2.hops = 1;
        f2.visited = vec![a.id.ed_pub()];
        let fr101 = f2.to_frame().unwrap();
        let (typ, body) = proto::split_frame(&fr101).unwrap();
        let out = a.st.on_frame(&ctx_a, b.addr, typ, body);
        assert_eq!(out.sends.len(), 1);
        let (typ, _body) = proto::split_frame(&out.sends[0].1).unwrap();
        assert_eq!(typ, mesh::MESH_FORWARD_NACK);
        // Нет маршрута до цели (цель неизвестна реле) — NACK с NO_ROUTE.
        let unknown = [0x77u8; 32];
        let mut f3 = f.clone();
        f3.dst_ed = unknown;
        f3.hops = 0;
        f3.visited = vec![];
        let fr102 = f3.to_frame().unwrap();
        let (typ, body) = proto::split_frame(&fr102).unwrap();
        let out = a.st.on_frame(&ctx_a, b.addr, typ, body);
        assert_eq!(out.sends.len(), 1);
        assert_eq!(
            open_from(&mut b.st, &a.id.ed_pub(), &out.sends[0].1),
            Rpc::ForwardNack {
                seq: forward_seq(&inner),
                code: code::NO_ROUTE
            }
        );
        // Обёртка от адреса без сессии — отброс (подделать отправителя,
        // не зная ключей mesh-сессии, нельзя).
        let mut f4 = f.clone();
        f4.hops = 0;
        f4.visited = vec![];
        let fr103 = f4.to_frame().unwrap();
        let (typ, body) = proto::split_frame(&fr103).unwrap();
        let stranger: SocketAddr = "127.0.0.1:4099".parse().unwrap();
        let before = a.st.stats().dropped;
        let out = a.st.on_frame(&ctx_a, stranger, typ, body);
        assert!(out.sends.is_empty() && out.deliver.is_empty());
        assert_eq!(a.st.stats().dropped, before + 1);
    }

    #[test]
    fn forward_битый_inner_и_лимит() {
        let mut a = peer(4001);
        let mut b = peer(4002);
        let now = 1_000;
        handshake(&mut a, &mut b, now);
        let ca = [contact(&b)];
        let ma = [b.id.ed_pub()];
        // inner — не кадр TNL2: кодирование forward не пройдёт, а разбор
        // отбросит кадр целиком.
        let f = MeshForward {
            dst_ed: b.id.ed_pub(),
            src_ed: a.id.ed_pub(),
            hops: 0,
            visited: vec![],
            inner: vec![0u8; 10],
        };
        assert!(f.to_frame().is_err());
        // Битый inner в уже готовом кадре — MeshForward::decode откажет.
        let frame = proto::plain_frame(mesh::MESH_FORWARD, &{
            let mut v = Vec::new();
            proto::put_pub(&mut v, &b.id.ed_pub());
            proto::put_pub(&mut v, &a.id.ed_pub());
            v.push(0);
            v.push(0);
            proto::put_u16(&mut v, 4);
            v.extend_from_slice(b"junk");
            v
        });
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let out =
            b.st.on_frame(&ctx(&b.id, &ca, &ma, now + 20), a.addr, typ, body);
        assert!(out.deliver.is_empty());
        assert_eq!(b.st.stats().dropped, 1);
        // Слишком длинный inner — отказ на отправке (код BAD).
        let big = vec![0u8; MAX_FORWARD_INNER + 1];
        assert_eq!(
            b.st.start_forward(
                &ctx(&b.id, &ca, &ma, now),
                a.id.ed_pub(),
                &contact(&a),
                &big
            ),
            Err(code::BAD)
        );
    }

    #[test]
    fn лимит_бюджета_релея() {
        let mut a = peer(4001);
        let mut b = peer(4002);
        let mut c = peer(4003);
        handshake(&mut a, &mut b, 1_000);
        handshake(&mut b, &mut c, 1_000);
        let inner = proto::seal_group(
            &[3u8; 32],
            proto::grp::DATA,
            &proto::GroupHeader {
                gid: 1,
                src: 2,
                dst: 3,
                epoch: 1,
            },
            0,
            &[7u8; 100],
        );
        let cb = [contact(&b), contact(&c)];
        let ma = [b.id.ed_pub(), c.id.ed_pub()];
        let mut a_ctx = ctx(&a.id, &cb, &ma, 2_000);
        a_ctx.relay_budget = inner.len() as u64 / 2; // заведомо мало
        assert_eq!(
            a.st.start_forward(&a_ctx, c.id.ed_pub(), &contact(&b), &inner),
            Err(code::BUDGET)
        );
        // Без разрешения релея — отказ.
        a_ctx.relay_budget = 1 << 30;
        a_ctx.relay_enabled = false;
        assert_eq!(
            a.st.start_forward(&a_ctx, c.id.ed_pub(), &contact(&b), &inner),
            Err(code::REJECTED)
        );
    }

    #[test]
    fn лимит_восьми_реле_пиров() {
        let me = proto::Identity::generate();
        let peer = peer(4010);
        let ca = [contact(&peer)];
        let ma = [peer.id.ed_pub()];
        let c1 = ctx(&me, &ca, &ma, 1_000);
        let mut st = MeshState::new(true);
        // Восемь разных пиров — окна заняты.
        for i in 0..RELAY_PEERS_MAX {
            let ed = [i as u8 + 1; 32];
            st.charge(&ed, 1, &c1, 1_000).expect("окно свободно");
        }
        assert_eq!(st.stats().relay_peers as usize, RELAY_PEERS_MAX);
        // Девятый — отказ BUDGET, лимит не растёт.
        let ninth = [0x99u8; 32];
        assert_eq!(st.charge(&ninth, 1, &c1, 1_000), Err(code::BUDGET));
        assert_eq!(st.stats().relay_peers as usize, RELAY_PEERS_MAX);
        // Через окно старые окна освобождаются — девятый проходит.
        assert!(
            st.charge(&ninth, 1, &c1, 1_000 + RELAY_WINDOW_MS * 2 + 1)
                .is_ok()
        );
        // Релей выключен — отказ на входе.
        let mut off = ctx(&me, &ca, &ma, 1_000);
        off.relay_enabled = false;
        assert_eq!(st.charge(&[0xAA; 32], 1, &off, 1_000), Err(code::REJECTED));
    }

    #[test]
    fn bye_и_таймаут_сессии() {
        let mut a = peer(4001);
        let mut b = peer(4002);
        handshake(&mut a, &mut b, 1_000);
        let ca = [contact(&b)];
        let ma = [b.id.ed_pub()];
        // BYE от b: сессия закрыта.
        let now = 2_000;
        let b_ctx = ctx(&b.id, &ca, &ma, now);
        let (to, frame) = b.st.bye_all(&b_ctx).pop().unwrap();
        assert_eq!(to, a.addr);
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let out = a.st.on_frame(&ctx(&a.id, &ca, &ma, now), b.addr, typ, body);
        assert!(matches!(out.events.first(), Some(MeshEvent::Down { .. })));
        assert!(a.st.session(&b.id.ed_pub()).is_none());
        // Таймаут: сессия без кадров 120 с — удаляется. Новое рукопожатие —
        // не раньше HANDSHAKE_GAP_MS от прошлой попытки.
        handshake(&mut a, &mut b, now + HANDSHAKE_GAP_MS);
        assert!(a.st.session(&b.id.ed_pub()).is_some());
        let late = ctx(
            &a.id,
            &ca,
            &ma,
            now + HANDSHAKE_GAP_MS + SESSION_IDLE_MS + 1,
        );
        let out = a.st.tick(&late);
        assert!(matches!(
            out.events
                .iter()
                .find(|e| matches!(e, MeshEvent::Down { .. })),
            Some(MeshEvent::Down { .. })
        ));
    }

    #[test]
    fn отказ_рукопожатия_не_member_и_без_caps() {
        let mut a = peer(4001);
        let b = peer(4002);
        let ca = [Contact {
            caps: caps::RELAY, // без MESH
            ..contact(&b)
        }];
        let ma = [b.id.ed_pub()];
        let a_ctx = ctx(&a.id, &ca, &ma, 1_000);
        let no_mesh = Contact {
            caps: caps::RELAY,
            ..contact(&b)
        };
        assert!(a.st.handshake(&a_ctx, &no_mesh).is_none(), "без caps::MESH");
        // Нет в составе — тоже нельзя.
        let ca = [contact(&b)];
        let empty: [[u8; 32]; 0] = [];
        let a_ctx = ctx(&a.id, &ca, &empty, 1_000);
        assert!(a.st.handshake(&a_ctx, &contact(&b)).is_none());
        // С MESH и в составе — можно; повтор сразу — нельзя (анти-спам).
        let a_ctx = ctx(&a.id, &ca, &ma, 1_000);
        assert!(a.st.handshake(&a_ctx, &contact(&b)).is_some());
        assert!(a.st.handshake(&a_ctx, &contact(&b)).is_none());
        // Через HANDSHAKE_GAP_MS — снова можно.
        let a_ctx = ctx(&a.id, &ca, &ma, 1_000 + HANDSHAKE_GAP_MS);
        assert!(a.st.handshake(&a_ctx, &contact(&b)).is_some());
    }

    #[test]
    fn find_node_и_route_измерение() {
        let mut a = peer(4001);
        let mut b = peer(4002);
        handshake(&mut a, &mut b, 1_000);
        let target = [0x42u8; 32];
        let contact_c = Contact {
            ed: [0x43u8; 32],
            x: [0x44u8; 32],
            addr: "127.0.0.1:5000".parse().unwrap(),
            rtt_ms: 5,
            last_seen_ms: 0,
            caps: caps::MESH,
        };
        let cb = [contact_c.clone()];
        let ma = [b.id.ed_pub()];
        let b_ctx = ctx(&b.id, &cb, &ma, 2_000);
        // FIND_NODE от a: b отвечает списком ближайших.
        let ca = [contact(&b)];
        let a_ctx = ctx(&a.id, &ca, &ma, 2_000);
        let id = 77;
        let rpc = Rpc::FindNode { id, target };
        // Шлём вручную (как это сделает движок).
        let a_sess = a.st.sessions.get_mut(&b.id.ed_pub()).unwrap();
        let frame = a_sess.seal(&rpc, 2_000);
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let out = b.st.on_frame(&b_ctx, a.addr, typ, body);
        assert_eq!(out.sends.len(), 1);
        let (typ, body) = proto::split_frame(&out.sends[0].1).unwrap();
        let out = a.st.on_frame(&a_ctx, b.addr, typ, body);
        assert_eq!(out.finds.len(), 1);
        assert_eq!(out.finds[0].0, id);
        assert_eq!(out.finds[0].1[0].ed, contact_c.ed);
        // ROUTE: b знает маршрут к contact_c (по контакту).
        let (to, frame) =
            a.st.route_probe(&a_ctx, &b.id.ed_pub(), contact_c.ed, b.addr)
                .expect("route");
        assert_eq!(to, b.addr);
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let out = b.st.on_frame(&b_ctx, a.addr, typ, body);
        let (typ, body) = proto::split_frame(&out.sends[0].1).unwrap();
        let out = a.st.on_frame(&a_ctx, b.addr, typ, body);
        assert!(matches!(
            out.events.first(),
            Some(MeshEvent::RouteMeasured { dst_ed, via, down_ms: 5, .. })
                if *dst_ed == contact_c.ed && *via == b.id.ed_pub()
        ));
        // ROUTE к неизвестной цели — RouteFail.
        let unknown = [0x99u8; 32];
        let (_, frame) =
            a.st.route_probe(&a_ctx, &b.id.ed_pub(), unknown, b.addr)
                .unwrap();
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let out = b.st.on_frame(&b_ctx, a.addr, typ, body);
        assert!(out.sends.len() == 1);
        let (typ, body) = proto::split_frame(&out.sends[0].1).unwrap();
        let out = a.st.on_frame(&a_ctx, b.addr, typ, body);
        assert!(matches!(
            out.events.first(),
            Some(MeshEvent::RouteFailed { dst_ed, .. }) if *dst_ed == unknown
        ));
    }

    #[test]
    fn выключение_рвёт_сессии() {
        let mut a = peer(4001);
        let mut b = peer(4002);
        handshake(&mut a, &mut b, 1_000);
        assert!(a.st.session(&b.id.ed_pub()).is_some());
        a.st.set_enabled(false);
        assert!(a.st.session(&b.id.ed_pub()).is_none());
        assert!(!a.st.enabled());
        // Кадры в выключенном состоянии не обрабатываются.
        let ca = [contact(&b)];
        let ma = [b.id.ed_pub()];
        let out =
            a.st.on_frame(&ctx(&a.id, &ca, &ma, 2_000), b.addr, mesh::MESH_PING, &[]);
        assert!(out.sends.is_empty() && out.deliver.is_empty());
    }

    #[test]
    fn ctx_проверка_группы_блокирует_чужой_inner() {
        // Реле не расшифровывает inner, но открытый заголовок обязан быть
        // кадром своей группы: check_group = false — NACK BAD.
        let mut a = peer(4001); // реле
        let mut b = peer(4002); // источник
        let mut c = peer(4003); // цель
        let now = 1_000;
        handshake(&mut b, &mut a, now);
        handshake(&mut a, &mut c, now);
        let inner = proto::seal_group(
            &[3u8; 32],
            proto::grp::DATA,
            &proto::GroupHeader {
                gid: 9,
                src: 2,
                dst: 3,
                epoch: 1,
            },
            0,
            b"x",
        );
        let ca = [contact(&a), contact(&c)];
        let ma = [a.id.ed_pub(), b.id.ed_pub(), c.id.ed_pub()];
        let mut a_ctx = ctx(&a.id, &ca, &ma, now + 10);
        a_ctx.check_group = &|_, _, _, _| false;
        let f = MeshForward {
            dst_ed: c.id.ed_pub(),
            src_ed: b.id.ed_pub(),
            hops: 0,
            visited: vec![],
            inner: inner.clone(),
        };
        let fr104 = f.to_frame().unwrap();
        let (typ, body) = proto::split_frame(&fr104).unwrap();
        let out = a.st.on_frame(&a_ctx, b.addr, typ, body);
        assert!(out.deliver.is_empty());
        assert_eq!(out.sends.len(), 1, "NACK");
        assert_eq!(
            open_from(&mut b.st, &a.id.ed_pub(), &out.sends[0].1),
            Rpc::ForwardNack {
                seq: forward_seq(&inner),
                code: code::BAD
            }
        );
        // С валидной проверкой — кадр уходит дальше (транспорт реле).
        let a_ctx = ctx(&a.id, &ca, &ma, now + 10);
        let fr105 = f.to_frame().unwrap();
        let (typ, body) = proto::split_frame(&fr105).unwrap();
        let out = a.st.on_frame(&a_ctx, b.addr, typ, body);
        assert_eq!(out.sends.len(), 1);
        assert_eq!(out.sends[0].0, c.addr);
    }
}
