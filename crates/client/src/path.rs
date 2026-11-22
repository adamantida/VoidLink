//! Выбор оптимального пути доставки до участника (§3.6 плана этапа 9).
//!
//! Уровни доставки: `direct` (L0, прямой p2p), `server` (L1, релей сервера),
//! `peer` (L2, релей через участника группы). Путь выбирается **по измеренной
//! стоимости**, а не по фиксированному списку:
//!
//! ```text
//! cost(direct)  = rtt_direct
//! cost(server)  = rtt_server_e2e + 5   (пока e2e нет — плечо до сервера + 5)
//! cost(peer R)  = rtt(us→R) + rtt(R→dst) + 15 + 10 * load(R)
//! ```
//!
//! `rtt_server_e2e` — **честный end-to-end** замер маршрута через сервер
//! ([`PathTable::record_server_path_rtt`], issue #15): PONG на групповой PING,
//! ушедший серверу. Плечо «мы→сервер» (`CTRL_PONG`) — только стоимость до
//! первого e2e-замера и отдельное поле снимка ([`PathTable::server_rtt`]);
//! [`PathTable::current_rtt`] плечо не возвращает никогда.
//!
//! Правила:
//! 1. Пересчёт — [`PathTable::recalc`] (движок зовёт раз в 10 с и при падении
//!    пути).
//! 2. **Гистерезис** (issue #17): новый путь выбирается, только если он
//!    дешевле текущего и относительно (≥ [`HYSTERESIS_PCT`] %), и абсолютно
//!    (≥ `path_hysteresis_ms`), а текущий путь держится не меньше
//!    `path_dwell_ms`. Мёртвый текущий путь переключается сразу, без порогов и
//!    без dwell.
//! 3. **Проверка нового пути** (issue #26): [`VERIFY_MS`] после
//!    автопереключения новый путь сравнивается со старым по RTT, потерям и
//!    джиттеру; если он хуже — откат на старый путь и карантин альтернативы
//!    на [`QUARANTINE_MS`] (`PathChange::Reverted`).
//! 4. **Ручное закрепление** ([`PathTable::set_pin`], `client.json` →
//!    `pinned_paths`) сильнее автоматики и не подчиняется dwell/порогам.
//!    Закреплённый, но недоступный путь даёт `Lost` и откат на автоматику;
//!    закрепление при этом не удаляется, а помечается нерабочим (пока путь не
//!    оживёт).
//!
//! События `PathChanged`/`PathLost` формирует движок: таблица только считает
//! изменения ([`PathChange`]), не зная про UI и каналы.
//!
//! Все времена — миллисекунды от старта движка (`now_ms`), а не `Instant`:
//! так тесты детерминированы, а `Mutex` держится коротко (только арифметика).

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use tunnel_protocol as proto;

use crate::store::{DEFAULT_PATH_DWELL_MS, DEFAULT_PATH_HYSTERESIS_MS, DEFAULT_RTT_INTERVAL_MS};

/// Надбавка за релей сервера (L1): лишний хоп и очередь сервера.
pub const HOP_PENALTY_SERVER_MS: f64 = 5.0;
/// Надбавка за релей через пира (L2): два хопа, NAT, чужой процесс.
pub const HOP_PENALTY_PEER_MS: f64 = 15.0;
/// Надбавка за загрузку реле-пира: `load` 0..1 → 0..10 мс.
pub const LOAD_PENALTY_MS: f64 = 10.0;
/// Насколько новый путь должен быть дешевле текущего (в процентах), чтобы
/// переключиться: 20 % — относительный порог гистерезиса.
pub const HYSTERESIS_PCT: f64 = 20.0;
/// Прямой канал считается живым столько после последнего замера: `direct_addr`
/// старше 12 с — «прямой путь не работает» (§3.4). При интервале проб больше
/// 4 с порог растягивается до `3 × интервал` ([`Policy::direct_fresh_ms`],
/// issue #16): одна-две пропущенные пробы канал не убивают.
pub const DIRECT_FRESH_MS: u64 = 12_000;
/// RTT сервера (плечо) считается актуальным столько (периодический CTRL_PING
/// идёт чаще, но после потери связи замер устаревает).
pub const SERVER_FRESH_MS: u64 = 30_000;
/// Замер маршрута через пира актуален столько.
pub const PEER_FRESH_MS: u64 = 30_000;
/// Сколько последних замеров RTT держать для спарклайна (issue #26).
pub const RTT_HIST_LEN: usize = 60;
/// Окно учёта проб для потерь (issue #26): по последним пробам считаются
/// промилле без ответа. 10 проб при интервале 5 с — около минуты; одна
/// потерянная проба в новом пути даёт 100 ‰ и перекрывает порог отката.
pub const LOSS_WINDOW: usize = 10;
/// Сколько проверять новый путь после автопереключения (issue #26).
pub const VERIFY_MS: u64 = 5_000;
/// Карантин пути, от которого откатились (issue #26): автоматика его не
/// выбирает.
pub const QUARANTINE_MS: u64 = 60_000;

/// Куда (через кого) идёт трафик до участника.
///
/// Сериализуется в снимки состояния и `client.json` (`pinned_paths`):
/// `direct` | `server` | `relay:<hex ed25519>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PathKind {
    /// Прямой канал пир ↔ пир (L0).
    Direct,
    /// Через сервер (L1).
    Server,
    /// Через пира-реле (L2); `via` — ed25519-ключ реле.
    PeerRelay { via: [u8; 32] },
}

impl PathKind {
    /// Строка для `client.json` (`pinned_paths`).
    pub fn to_config(&self) -> String {
        match self {
            PathKind::Direct => "direct".into(),
            PathKind::Server => "server".into(),
            PathKind::PeerRelay { via } => format!("relay:{}", proto::hex_of(via)),
        }
    }

    /// Разбор строки из `client.json`; мусор — `None` (закрепление
    /// игнорируется, конфиг не ломается).
    pub fn parse_config(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("direct") {
            return Some(PathKind::Direct);
        }
        if s.eq_ignore_ascii_case("server") {
            return Some(PathKind::Server);
        }
        let hex = s.strip_prefix("relay:")?;
        let b = proto::hex_to_bytes(hex).ok()?;
        let via: [u8; 32] = b.try_into().ok()?;
        Some(PathKind::PeerRelay { via })
    }

    /// Короткая метка для логов и TUI.
    pub fn label(&self) -> &'static str {
        match self {
            PathKind::Direct => "direct",
            PathKind::Server => "server",
            PathKind::PeerRelay { .. } => "peer",
        }
    }
}

/// Ключ `pinned_paths` (`"100.66.0.2"`) → адрес оверлея.
pub fn parse_ip_key(s: &str) -> Option<u32> {
    match s.trim().parse::<IpAddr>().ok()? {
        IpAddr::V4(a) => Some(u32::from_be_bytes(a.octets())),
        // Оверлей — IPv4; IPv6-ключ в пинах смысла не имеет.
        IpAddr::V6(_) => None,
    }
}

/// Адрес оверлея → ключ `pinned_paths`.
pub fn ip_key(ip: u32) -> String {
    Ipv4Addr::from(ip.to_be_bytes()).to_string()
}

/// Что изменилось при пересчёте (движок превращает это в события).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathChange {
    /// Текущий путь сменился (в т.ч. с «пути не было»).
    Changed {
        ip: u32,
        /// Что было (`None` — пути не было).
        from: Option<PathKind>,
        to: PathKind,
        /// Измеренный RTT выбранного пути (у сервера — только end-to-end,
        /// плечо сюда не попадает; может быть неизвестен).
        rtt_ms: Option<u32>,
    },
    /// Доступных путей не осталось. `from` — что было текущим.
    Lost { ip: u32, from: PathKind },
    /// Автоматика откатила путь назад после проверки нового (issue #26):
    /// `from` — путь, от которого отказались (уходит в карантин), `to` —
    /// восстановленный.
    Reverted {
        ip: u32,
        from: PathKind,
        to: PathKind,
    },
}

/// Метрики текущего пути получателя (issue #26) — то, что уходит в снимок.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathMetrics {
    /// Джиттер: EWMA модуля разности соседних замеров RTT, мс.
    pub jitter_ms: u32,
    /// Потери по последним [`LOSS_WINDOW`] пробам, промилле.
    pub loss_pm: u16,
    /// Последние замеры RTT текущего пути (не больше [`RTT_HIST_LEN`]),
    /// старые первыми.
    pub hist: Vec<u16>,
}

/// Настройки выбора пути из конфига (issue #16/#17): пороги гистерезиса,
/// удержание и интервал проб. Движок обновляет их из `Config`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Policy {
    hysteresis_ms: u32,
    dwell_ms: u64,
    probe_interval_ms: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            hysteresis_ms: DEFAULT_PATH_HYSTERESIS_MS,
            dwell_ms: DEFAULT_PATH_DWELL_MS,
            probe_interval_ms: DEFAULT_RTT_INTERVAL_MS,
        }
    }
}

impl Policy {
    /// Свежесть замера прямого канала: не меньше [`DIRECT_FRESH_MS`] и не
    /// меньше трёх интервалов проб (issue #16) — иначе проба на 5–20 с
    /// «убивала» бы живой канал между замерами.
    fn direct_fresh_ms(&self) -> u64 {
        DIRECT_FRESH_MS.max(self.probe_interval_ms.saturating_mul(3))
    }

    /// Свежесть end-to-end замера через сервер (issue #15): не меньше
    /// [`SERVER_FRESH_MS`] и не меньше двух интервалов проб.
    fn server_e2e_fresh_ms(&self) -> u64 {
        SERVER_FRESH_MS.max(self.probe_interval_ms.saturating_mul(2))
    }
}

/// Окно проб для потерь (issue #26): `true` — ответ (PONG) пришёл.
#[derive(Clone, Debug, Default)]
struct LossWindow {
    probes: VecDeque<bool>,
}

impl LossWindow {
    /// Новая проба без ответа.
    fn sent(&mut self) {
        self.probes.push_back(false);
        while self.probes.len() > LOSS_WINDOW {
            self.probes.pop_front();
        }
    }

    /// Ответ на пробу: отмечается самая старая непрошедшая проба, а не
    /// последняя. PONG может прийти не в порядке отправки (разные группы,
    /// разные пути), и один ответ не должен «закрывать» чужую пробу.
    fn answered(&mut self) {
        if let Some(pos) = self.probes.iter().rposition(|ok| !*ok) {
            self.probes[pos] = true;
        }
    }

    /// Промилле проб без ответа (0 — ни одной, 1000 — ни одна не ответила).
    fn loss_pm(&self) -> u16 {
        if self.probes.is_empty() {
            return 0;
        }
        let lost = self.probes.iter().filter(|ok| !**ok).count();
        (lost * 1000 / self.probes.len()) as u16
    }

    fn clear(&mut self) {
        self.probes.clear();
    }
}

/// Окно проверки нового пути после автопереключения (issue #26): метрики
/// старого пути и момент переключения.
#[derive(Clone, Copy, Debug)]
struct Verify {
    old: PathKind,
    old_cost: f64,
    old_jitter_ms: u32,
    old_loss_pm: u16,
    at: u64,
}

/// Маршрут через пира-реле: кто релеит и что известно о задержке.
#[derive(Clone, Copy, Debug, PartialEq)]
struct PeerRoute {
    via: [u8; 32],
    /// RTT «мы → реле».
    up_ms: u32,
    /// RTT «реле → получатель».
    down_ms: u32,
    /// Загрузка реле 0..1 (доля отданной полосы).
    load: f64,
    at: u64,
}

impl PeerRoute {
    /// `up + down + 15 + 10 * load`.
    fn cost(&self) -> f64 {
        self.up_ms as f64
            + self.down_ms as f64
            + HOP_PENALTY_PEER_MS
            + LOAD_PENALTY_MS * self.load.clamp(0.0, 1.0)
    }

    fn rtt(&self) -> u32 {
        self.up_ms.saturating_add(self.down_ms)
    }
}

/// Один получатель: измерения по путям, метрики и выбранный путь.
#[derive(Clone, Debug, Default)]
struct Target {
    direct_ms: Option<u32>,
    direct_at: u64,
    peer: Option<PeerRoute>,
    /// Честный end-to-end RTT маршрута через сервер (issue #15) и время
    /// замера.
    server_e2e_ms: Option<u32>,
    server_e2e_at: u64,
    /// Текущий путь и его стоимость на момент выбора (для гистерезиса).
    current: Option<PathKind>,
    current_cost: Option<f64>,
    /// Когда выбран текущий путь (для dwell, issue #17).
    current_since: u64,
    /// Закреплённый путь был недоступен (уже сообщили `Lost`); сбрасывается,
    /// когда он снова доступен.
    pin_broken: bool,
    /// Джиттер текущего пути: EWMA |ΔRTT|, мс (issue #26).
    jitter_ms: u32,
    /// Предыдущий замер текущего пути (для джиттера и истории).
    last_rtt_ms: Option<u32>,
    /// Какой путь накопил `hist`/`jitter`: смена пути начинает историю заново.
    hist_kind: Option<PathKind>,
    /// Последние замеры RTT текущего пути (спарклайн, issue #26).
    hist: VecDeque<u16>,
    /// Пробы по получателю: по ним считаются потери (issue #26).
    loss: LossWindow,
    /// Окно проверки нового пути после автопереключения (issue #26).
    verify: Option<Verify>,
    /// Карантин после отката: путь → момент, до которого автоматика его не
    /// выбирает (issue #26).
    blocked: Vec<(PathKind, u64)>,
}

impl Target {
    /// Замер RTT пути: джиттер, история и предыдущий замер — только для
    /// **текущего** пути; замеры других путей историю не трогают. Первый замер
    /// после смены пути начинает историю заново.
    fn note_rtt(&mut self, kind: PathKind, rtt_ms: u32) {
        if self.current != Some(kind) {
            return;
        }
        if self.hist_kind != Some(kind) {
            self.hist_kind = Some(kind);
            self.hist.clear();
            self.jitter_ms = 0;
            self.last_rtt_ms = None;
        }
        if let Some(prev) = self.last_rtt_ms {
            let diff = prev.abs_diff(rtt_ms) as u64;
            // EWMA с α = 1/4: ровный путь даёт джиттер около 0, «пила» — растёт.
            self.jitter_ms = ((self.jitter_ms as u64 * 3 + diff) / 4) as u32;
        }
        self.last_rtt_ms = Some(rtt_ms);
        self.hist.push_back(rtt_ms.min(u16::MAX as u32) as u16);
        while self.hist.len() > RTT_HIST_LEN {
            self.hist.pop_front();
        }
    }

    /// Проба ушла (ответа ещё нет).
    fn note_probe(&mut self) {
        self.loss.sent();
    }

    /// Ответ на последнюю пробу пришёл.
    fn note_answer(&mut self) {
        self.loss.answered();
    }

    fn loss_pm(&self) -> u16 {
        self.loss.loss_pm()
    }

    /// Сменить текущий путь: отметка времени для dwell, метрики — заново.
    fn set_current(&mut self, kind: PathKind, cost: Option<f64>, now_ms: u64) {
        if self.current != Some(kind) {
            self.current = Some(kind);
            self.current_since = now_ms;
            self.hist.clear();
            self.hist_kind = None;
            self.jitter_ms = 0;
            self.last_rtt_ms = None;
            self.loss.clear();
        }
        self.current_cost = cost;
    }

    /// Путь в карантине: автоматика его не выбирает до `until`.
    fn is_blocked(&self, kind: PathKind, now_ms: u64) -> bool {
        self.blocked
            .iter()
            .any(|(k, until)| *k == kind && now_ms < *until)
    }

    /// Отправить путь в карантин (issue #26).
    fn block(&mut self, kind: PathKind, now_ms: u64) {
        let until = now_ms.saturating_add(QUARANTINE_MS);
        match self.blocked.iter_mut().find(|(k, _)| *k == kind) {
            Some((_, t)) => *t = until,
            None => self.blocked.push((kind, until)),
        }
    }

    /// Свежий end-to-end замер через сервер (issue #15).
    fn server_e2e_fresh(&self, now_ms: u64, policy: Policy) -> Option<u32> {
        let ms = self.server_e2e_ms?;
        (now_ms.saturating_sub(self.server_e2e_at) <= policy.server_e2e_fresh_ms()).then_some(ms)
    }

    /// Новый путь после автопереключения хуже старого (issue #26)?
    fn worse_than(&self, cost: f64, v: Verify, policy: Policy) -> bool {
        let rtt_worse =
            cost > v.old_cost * 1.2 && cost - v.old_cost > f64::from(policy.hysteresis_ms);
        let loss_worse = self.loss_pm() > v.old_loss_pm.saturating_add(50);
        let jitter_worse =
            v.old_jitter_ms > 0 && self.jitter_ms > v.old_jitter_ms.saturating_mul(2);
        rtt_worse || loss_worse || jitter_worse
    }
}

#[derive(Debug, Default)]
struct Paths {
    targets: BTreeMap<u32, Target>,
    /// Закрепления: ip → путь (из `client.json`).
    pins: BTreeMap<u32, PathKind>,
    /// Последний измеренный RTT сервера (плечо) и время замера.
    server: Option<(u32, u64)>,
    /// Релей через пиров разрешён (`SetRelayEnabled`).
    relay_enabled: bool,
    /// Пороги выбора пути и интервал проб (issue #16/#17).
    policy: Policy,
    /// Последнее известное таблице время (мс от старта движка): по нему
    /// проверяется свежесть замеров в геттерах, у которых нет `now_ms`.
    now_ms: u64,
}

impl Paths {
    /// Отметить время: свежесть замеров в геттерах считается по нему.
    fn tick(&mut self, now_ms: u64) {
        if now_ms > self.now_ms {
            self.now_ms = now_ms;
        }
    }
}

/// Таблица путей: измерения, выбор с гистерезисом и ручные закрепления.
///
/// Разделяется между потоками движка (`Arc<PathTable>`), внутри — один
/// `Mutex` на короткие операции: захват не держится на время ввода-вывода.
pub struct PathTable {
    inner: Mutex<Paths>,
}

impl std::fmt::Debug for PathTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        f.debug_struct("PathTable")
            .field("targets", &p.targets.len())
            .field("pins", &p.pins.len())
            .field("relay_enabled", &p.relay_enabled)
            .finish()
    }
}

impl PathTable {
    /// Новая таблица с закреплениями из конфига. Мусорные записи (не тот
    /// адрес/путь) пропускаются: конфиг правится руками.
    pub fn new(pins: &BTreeMap<String, String>) -> Self {
        let mut parsed = BTreeMap::new();
        for (k, v) in pins {
            let (Some(ip), Some(kind)) = (parse_ip_key(k), PathKind::parse_config(v)) else {
                continue;
            };
            parsed.insert(ip, kind);
        }
        Self {
            inner: Mutex::new(Paths {
                targets: BTreeMap::new(),
                pins: parsed,
                server: None,
                relay_enabled: true,
                policy: Policy::default(),
                now_ms: 0,
            }),
        }
    }

    /// Таблица без закреплений и измерений (тесты, движок до конфига).
    pub fn empty() -> Self {
        Self::new(&BTreeMap::new())
    }

    /// Пороги выбора пути и интервал проб из конфига (issue #16/#17).
    /// `PathTable` создаётся до чтения конфига, поэтому движок обновляет их
    /// сеттером; повтор с теми же значениями ничего не делает.
    pub fn set_limits(&self, hysteresis_ms: u32, dwell_ms: u64, interval: Duration) {
        let policy = Policy {
            hysteresis_ms,
            dwell_ms,
            probe_interval_ms: interval.as_millis() as u64,
        };
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if p.policy != policy {
            p.policy = policy;
        }
    }

    /// Заменить все закрепления (после правки `client.json`).
    pub fn set_pins(&self, pins: &BTreeMap<String, String>) {
        let mut parsed = BTreeMap::new();
        for (k, v) in pins {
            if let (Some(ip), Some(kind)) = (parse_ip_key(k), PathKind::parse_config(v)) {
                parsed.insert(ip, kind);
            }
        }
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for ip in parsed.keys() {
            p.targets.entry(*ip).or_default().pin_broken = false;
        }
        p.pins = parsed;
    }

    /// Закрепить (`Some`) или открепить (`None`) путь получателя.
    pub fn set_pin(&self, ip: u32, kind: Option<PathKind>) {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Запись получателя заводится и закреплением: иначе пересчёт не знал
        // бы о цели, у которой ещё нет ни одного замера.
        let t = p.targets.entry(ip).or_default();
        t.pin_broken = false;
        match kind {
            Some(k) => {
                p.pins.insert(ip, k);
            }
            None => {
                p.pins.remove(&ip);
            }
        }
    }

    /// Текущее закрепление получателя.
    pub fn pin_of(&self, ip: u32) -> Option<PathKind> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pins
            .get(&ip)
            .copied()
    }

    /// Все закрепления (для записи в конфиг/снимок).
    pub fn pins(&self) -> BTreeMap<u32, PathKind> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pins
            .clone()
    }

    /// Разрешить/запретить релей через пиров (L2).
    pub fn set_relay_enabled(&self, on: bool) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .relay_enabled = on;
    }

    /// Замер прямого канала (из RTT-таймера группы).
    pub fn record_direct_rtt(&self, ip: u32, rtt_ms: u32, now_ms: u64) {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        p.tick(now_ms);
        let t = p.targets.entry(ip).or_default();
        t.direct_ms = Some(rtt_ms);
        t.direct_at = now_ms;
        t.note_rtt(PathKind::Direct, rtt_ms);
    }

    /// Замер RTT сервера — **плечо** «мы → сервер» (CTRL_PONG с меткой).
    /// Это не RTT маршрута до участника: в [`PathTable::current_rtt`] он не
    /// попадает (issue #15).
    pub fn record_server_rtt(&self, rtt_ms: u32, now_ms: u64) {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        p.tick(now_ms);
        p.server = Some((rtt_ms, now_ms));
    }

    /// **Честный end-to-end** замер маршрута через сервер (issue #15): PONG на
    /// групповой PING, ушедший серверу. Именно он — RTT серверного пути и его
    /// стоимость; плечо до сервера его не подменяет.
    pub fn record_server_path_rtt(&self, ip: u32, rtt_ms: u32, now_ms: u64) {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        p.tick(now_ms);
        let t = p.targets.entry(ip).or_default();
        t.server_e2e_ms = Some(rtt_ms);
        t.server_e2e_at = now_ms;
        t.note_rtt(PathKind::Server, rtt_ms);
    }

    /// Проба (групповой PING) ушла получателю — считаем её в потерях
    /// (issue #26), пока не придёт ответ.
    pub fn record_probe_sent(&self, ip: u32) {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        p.targets.entry(ip).or_default().note_probe();
    }

    /// Ответ (PONG) на последнюю пробу получателя (issue #26).
    pub fn record_probe_answered(&self, ip: u32) {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = p.targets.get_mut(&ip) {
            t.note_answer();
        }
    }

    /// Замер маршрута через пира `via`: `up_ms` — мы→реле, `down_ms` —
    /// реле→получатель (из `MESH_ROUTE_OK`), `load` — загрузка реле 0..1.
    pub fn record_peer_rtt(
        &self,
        ip: u32,
        via: [u8; 32],
        up_ms: u32,
        down_ms: u32,
        load: f64,
        now_ms: u64,
    ) {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        p.tick(now_ms);
        let t = p.targets.entry(ip).or_default();
        t.peer = Some(PeerRoute {
            via,
            up_ms,
            down_ms,
            load: load.clamp(0.0, 1.0),
            at: now_ms,
        });
        t.note_rtt(PathKind::PeerRelay { via }, up_ms.saturating_add(down_ms));
    }

    /// Текущий путь сломался (реле отказал, прямой канал пропал): следующий
    /// пересчёт выберет заново без гистерезиса.
    ///
    /// Сами измерения не стираются: они либо протухнут по свежести, либо
    /// заменятся новым замером; текущий путь снимается, чтобы переключение
    /// не требовало 20 %-выигрыша.
    pub fn record_failure(&self, ip: u32) {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(t) = p.targets.get_mut(&ip) else {
            return;
        };
        // Путь, по которому шли, больше не считается живым.
        match t.current {
            Some(PathKind::Direct) => {
                t.direct_ms = None;
                t.direct_at = 0;
            }
            Some(PathKind::PeerRelay { .. }) => t.peer = None,
            Some(PathKind::Server) | None => {}
        }
        t.current = None;
        t.current_cost = None;
        t.verify = None;
    }

    /// Забыть всё про получателя (вышел из группы).
    pub fn clear_target(&self, ip: u32) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .targets
            .remove(&ip);
    }

    /// Завести запись получателя без измерений (участник группы): пересчёт
    /// выберет для него путь по умолчанию — сервер, если связь есть.
    pub fn ensure_target(&self, ip: u32) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .targets
            .entry(ip)
            .or_default();
    }

    /// Выбранный путь получателя.
    pub fn current(&self, ip: u32) -> Option<PathKind> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .targets
            .get(&ip)
            .and_then(|t| t.current)
    }

    /// Измеренный **end-to-end** RTT текущего пути (issue #15).
    ///
    /// Для серверного пути это только свежий замер полного маршрута: плечо
    /// «мы→сервер» здесь не возвращается никогда — иначе UI показывал бы 1 мс
    /// вместо реальных десятков.
    pub fn current_rtt(&self, ip: u32) -> Option<u32> {
        let p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let t = p.targets.get(&ip)?;
        match t.current? {
            PathKind::Direct => t.direct_ms,
            PathKind::Server => t.server_e2e_fresh(p.now_ms, p.policy),
            PathKind::PeerRelay { .. } => t.peer.map(|r| r.rtt()),
        }
    }

    /// Замер RTT сервера — плечо «мы→сервер» (для снимка состояния, issue
    /// #15): отдельно от end-to-end RTT маршрута.
    pub fn server_rtt(&self) -> Option<u32> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .server
            .map(|(r, _)| r)
    }

    /// Метрики текущего пути получателя (issue #26): джиттер, потери и
    /// история замеров. `None` — пути нет.
    pub fn metrics(&self, ip: u32) -> Option<PathMetrics> {
        let p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let t = p.targets.get(&ip)?;
        t.current?;
        Some(PathMetrics {
            jitter_ms: t.jitter_ms,
            loss_pm: t.loss_pm(),
            hist: t.hist.iter().copied().collect(),
        })
    }

    /// Есть ли по получателю хоть одна проба: до неё jitter/loss — не нули,
    /// а «неизвестно» (issue #26).
    pub fn has_probes(&self, ip: u32) -> bool {
        let p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        p.targets
            .get(&ip)
            .is_some_and(|t| !t.loss.probes.is_empty())
    }

    /// Последний end-to-end замер маршрута через сервер до получателя
    /// (issue #15). Плечо до сервера сюда не подставляется.
    pub fn server_path_rtt(&self, ip: u32) -> Option<u32> {
        let p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let t = p.targets.get(&ip)?;
        t.server_e2e_fresh(p.now_ms, p.policy)
    }

    /// Пересчитать пути всех получателей. Возвращает изменения — движок
    /// рассылает их событиями. `server_up` — есть ли связь с сервером.
    pub fn recalc(&self, now_ms: u64, server_up: bool) -> Vec<PathChange> {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        p.tick(now_ms);
        // Закрепления копируются: иначе нельзя одновременно держать
        // `targets.iter_mut()` и `pins.get()` (один и тот же `Paths`).
        let pins = p.pins.clone();
        let ctx = Ctx {
            server: p.server,
            server_up,
            relay: p.relay_enabled,
            policy: p.policy,
            now_ms,
        };
        let mut changes = Vec::new();
        for (ip, t) in p.targets.iter_mut() {
            recalc_target_pinned(*ip, t, pins.get(ip).copied(), ctx, &mut changes);
            // Закрепление переживает падение: «нерабочее» — не «удалённое».
        }
        changes
    }

    /// Пересчёт одного получателя (движок может позвать точечно).
    pub fn recalc_one(&self, ip: u32, now_ms: u64, server_up: bool) -> Vec<PathChange> {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        p.tick(now_ms);
        let ctx = Ctx {
            server: p.server,
            server_up,
            relay: p.relay_enabled,
            policy: p.policy,
            now_ms,
        };
        let pin = p.pins.get(&ip).copied();
        let Some(t) = p.targets.get_mut(&ip) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        recalc_target_pinned(ip, t, pin, ctx, &mut out);
        out
    }

    /// Выбрать путь доставки для `route_packet`: пересчитать получателя
    /// (гистерезис и закрепление — те же, что в [`PathTable::recalc`]) и
    /// вернуть текущий путь. Изменения — вторым элементом: движок рассылает
    /// их событиями. У получателя без записи она заводится (участник группы).
    pub fn choose(
        &self,
        ip: u32,
        now_ms: u64,
        server_up: bool,
    ) -> (Option<PathKind>, Vec<PathChange>) {
        self.ensure_target(ip);
        let changes = self.recalc_one(ip, now_ms, server_up);
        (self.current(ip), changes)
    }

    /// Доступные сейчас пути получателя по возрастанию стоимости (для
    /// отката, когда выбранный путь отказал).
    pub fn fallbacks(&self, ip: u32, now_ms: u64, server_up: bool) -> Vec<PathKind> {
        let p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let ctx = Ctx {
            server: p.server,
            server_up,
            relay: p.relay_enabled,
            policy: p.policy,
            now_ms,
        };
        let Some(t) = p.targets.get(&ip) else {
            return Vec::new();
        };
        let mut v: Vec<(f64, PathKind)> = Vec::new();
        for kind in [
            Some(PathKind::Direct),
            Some(PathKind::Server),
            t.peer.map(|r| PathKind::PeerRelay { via: r.via }),
        ]
        .into_iter()
        .flatten()
        {
            if let Some((cost, _)) = cost_of(t, kind, ctx)
                && cost.is_finite()
            {
                v.push((cost, kind));
            }
        }
        v.sort_by(|a, b| a.0.total_cmp(&b.0));
        v.into_iter().map(|(_, k)| k).collect()
    }
}

/// Неизменяемые входы пересчёта: связь с сервером, режим релея, время.
#[derive(Clone, Copy)]
struct Ctx {
    server: Option<(u32, u64)>,
    server_up: bool,
    relay: bool,
    policy: Policy,
    now_ms: u64,
}

/// Стоимость и RTT пути, если он сейчас доступен.
///
/// RTT (`Some`) — то, что увидит UI: для серверного пути это **только**
/// end-to-end замер (issue #15), плечо до сервера сюда не подставляется.
fn cost_of(t: &Target, kind: PathKind, ctx: Ctx) -> Option<(f64, Option<u32>)> {
    match kind {
        PathKind::Direct => {
            let ms = t.direct_ms?;
            (ctx.now_ms.saturating_sub(t.direct_at) <= ctx.policy.direct_fresh_ms())
                .then_some((ms as f64, Some(ms)))
        }
        PathKind::Server => {
            if !ctx.server_up {
                return None;
            }
            // Честный end-to-end маршрут (issue #15) — он и стоимость, и RTT.
            if let Some(ms) = t.server_e2e_fresh(ctx.now_ms, ctx.policy) {
                return Some((ms as f64 + HOP_PENALTY_SERVER_MS, Some(ms)));
            }
            // До первого e2e-замера стоимость считаем по плечу «мы→сервер»:
            // иначе серверный путь был бы несравним и первый выбор «залипал»
            // бы на прямом. Плечо при этом остаётся плечом — в RTT не идёт.
            match ctx.server {
                Some((rtt, at)) if ctx.now_ms.saturating_sub(at) <= SERVER_FRESH_MS => {
                    Some((rtt as f64 + HOP_PENALTY_SERVER_MS, None))
                }
                // Связь есть, замеров ещё нет: путь доступен, но пока
                // несравним (INFINITY-стоимость).
                _ => Some((f64::INFINITY, None)),
            }
        }
        PathKind::PeerRelay { via } => {
            if !ctx.relay {
                return None;
            }
            let r = t.peer?;
            if r.via != via || ctx.now_ms.saturating_sub(r.at) > PEER_FRESH_MS {
                return None;
            }
            Some((r.cost(), Some(r.rtt())))
        }
    }
}

fn recalc_target_pinned(
    ip: u32,
    t: &mut Target,
    pin: Option<PathKind>,
    ctx: Ctx,
    out: &mut Vec<PathChange>,
) {
    let cost = |t: &Target, kind: PathKind| cost_of(t, kind, ctx);

    // 1. Ручное закрепление сильнее автоматики и не подчиняется dwell.
    if let Some(want) = pin {
        if let Some((c, rtt)) = cost(t, want) {
            t.pin_broken = false;
            t.verify = None;
            if t.current != Some(want) {
                let from = t.current;
                t.set_current(want, Some(c), ctx.now_ms);
                out.push(PathChange::Changed {
                    ip,
                    from,
                    to: want,
                    rtt_ms: rtt,
                });
            } else {
                // Стоимость могла измениться — держим её актуальной для
                // гистерезиса после открепления.
                t.current_cost = Some(c);
            }
            return;
        }
        // Закреплённый путь недоступен: сообщаем один раз и откатываемся на
        // автоматику. Закрепление не удаляется — путь может ожить.
        if !t.pin_broken {
            t.pin_broken = true;
            out.push(PathChange::Lost { ip, from: want });
            // Снимаем текущий путь только при первом падении: дальше уже
            // работает автоматика (с её гистерезисом), и сбрасывать её выбор
            // каждый пересчёт нельзя.
            t.current = None;
            t.current_cost = None;
            t.verify = None;
        }
    }

    // 2. Окно проверки нового пути (issue #26): если после автопереключения
    //    он хуже старого — откат и карантин альтернативы.
    if let Some(v) = t.verify {
        if ctx.now_ms.saturating_sub(v.at) > VERIFY_MS {
            t.verify = None;
        } else if let Some(cur) = t.current
            && cur != v.old
            && let Some((cc, _)) = cost(t, cur)
            && cc.is_finite()
            && t.worse_than(cc, v, ctx.policy)
        {
            t.verify = None;
            t.block(cur, ctx.now_ms);
            t.set_current(v.old, None, ctx.now_ms);
            out.push(PathChange::Reverted {
                ip,
                from: cur,
                to: v.old,
            });
            return;
        }
    }

    // 3. Автоматика: все доступные пути, лучший по стоимости. Пути в
    //    карантине (issue #26) не рассматриваются.
    let mut best: Option<(f64, PathKind, Option<u32>)> = None;
    let candidates = [
        Some(PathKind::Direct),
        Some(PathKind::Server),
        t.peer.map(|r| PathKind::PeerRelay { via: r.via }),
    ];
    for kind in candidates.into_iter().flatten() {
        if t.is_blocked(kind, ctx.now_ms) {
            continue;
        }
        let Some((c, rtt)) = cost(t, kind) else {
            continue;
        };
        // Доступен, но не измерен (сервер без замера): сравнивать не с чем.
        if !c.is_finite() {
            continue;
        }
        if best.as_ref().is_none_or(|(bc, _, _)| c < *bc) {
            best = Some((c, kind, rtt));
        }
    }

    let current = t.current;
    let current_ok = current.and_then(|k| cost(t, k));

    match (current, current_ok) {
        // Текущий путь жив и измерен: меняем только при выигрыше и
        // относительного (20 %), и абсолютного порога, и после dwell
        // (issue #17).
        (Some(cur), Some((cc, _))) if cc.is_finite() => {
            if let Some((bc, bk, brtt)) = best {
                let threshold = cc * (100.0 - HYSTERESIS_PCT) / 100.0;
                let abs_ok = bc <= cc - f64::from(ctx.policy.hysteresis_ms);
                let dwell_ok = ctx.now_ms.saturating_sub(t.current_since) >= ctx.policy.dwell_ms;
                if bk != cur && bc <= threshold && abs_ok && dwell_ok {
                    // Автопереключение: запоминаем метрики старого пути —
                    // через `VERIFY_MS` сравним и, если новый хуже, откатим.
                    t.verify = Some(Verify {
                        old: cur,
                        old_cost: cc,
                        old_jitter_ms: t.jitter_ms,
                        old_loss_pm: t.loss_pm(),
                        at: ctx.now_ms,
                    });
                    t.set_current(bk, Some(bc), ctx.now_ms);
                    out.push(PathChange::Changed {
                        ip,
                        from: Some(cur),
                        to: bk,
                        rtt_ms: brtt,
                    });
                    return;
                }
            }
            t.current_cost = Some(cc);
        }
        // Текущий путь доступен, но ещё не измерен (сервер до первого
        // замера): держим его — сравнение появится после замера.
        (Some(_), Some((cc, _))) => {
            t.current_cost = Some(cc);
        }
        // Текущего живого пути нет: берём лучший без гистерезиса и без dwell —
        // держаться не за что (сломанный путь меняется сразу).
        (cur, _) => {
            if let Some((bc, bk, brtt)) = best {
                t.set_current(bk, Some(bc), ctx.now_ms);
                out.push(PathChange::Changed {
                    ip,
                    from: cur,
                    to: bk,
                    rtt_ms: brtt,
                });
                return;
            }
            // Ничего измеренного: сервер — единственный заведомо рабочий путь.
            if ctx.server_up {
                t.set_current(PathKind::Server, None, ctx.now_ms);
                out.push(PathChange::Changed {
                    ip,
                    from: cur,
                    to: PathKind::Server,
                    rtt_ms: None,
                });
            } else if let Some(from) = cur {
                t.current = None;
                t.current_cost = None;
                t.verify = None;
                out.push(PathChange::Lost { ip, from });
            }
        }
    }
}

/// `SocketAddr` получателя по выбранному пути — то, что нужно `route_packet`.
/// `None` — путь не выбран (или прямого адреса уже нет: `direct_addr`
/// пропал между пересчётом и отправкой).
pub fn send_addr(path: PathKind, direct: Option<SocketAddr>, server: SocketAddr) -> SocketAddr {
    match path {
        PathKind::Direct => direct.unwrap_or(server),
        PathKind::Server => server,
        // Релей L2 транспортируется mesh-сессией (`route_packet` →
        // `try_relay`), а здесь адрес — запасной: сервер доставит, если реле
        // не приняло. Так кадр не теряется.
        PathKind::PeerRelay { .. } => server,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: u32 = 0x6442_0002;
    const OTHER: u32 = 0x6442_0003;
    const VIA: [u8; 32] = [7; 32];

    /// Таблица с порогами из конфига по умолчанию, но без dwell: тесты про
    /// гистерезис не должны ждать 10 с удержания пути. Интервал проб — 5 с
    /// (как в `Config::default`), от него зависит свежесть прямого канала.
    fn table() -> PathTable {
        let t = PathTable::empty();
        t.set_limits(
            crate::store::DEFAULT_PATH_HYSTERESIS_MS,
            0,
            Duration::from_millis(crate::store::DEFAULT_RTT_INTERVAL_MS),
        );
        t
    }

    /// Единственное изменение (паника, если их не одно).
    fn one(changes: Vec<PathChange>) -> PathChange {
        assert_eq!(changes.len(), 1, "ожидалось одно изменение: {changes:?}");
        changes[0]
    }

    #[test]
    fn ответ_закрывает_самую_старую_пробу() {
        // У пира в нескольких общих группах за раунд уходит несколько проб, а
        // PONG приходят в произвольном порядке. Один ответ не должен
        // «закрывать» чужую пробу: иначе здоровая пара показывала бы потери
        // (issue #26).
        let mut w = LossWindow::default();
        w.sent();
        w.sent();
        assert_eq!(w.loss_pm(), 1000);
        w.answered();
        assert_eq!(w.loss_pm(), 500, "ответ закрыл не одну пробу");
        w.answered();
        assert_eq!(w.loss_pm(), 0, "две пробы и два ответа — потерь нет");
        // Лишний ответ (повтор PONG) не портит окно.
        w.answered();
        assert_eq!(w.loss_pm(), 0);
    }

    #[test]
    fn потери_и_джиттер_неизвестны_до_первой_пробы() {
        // Карточка не должна показывать «0 мс · 0 %» без данных (issue #26).
        let t = table();
        t.record_server_rtt(5, 0);
        t.ensure_target(IP);
        t.recalc(0, true);
        assert!(!t.has_probes(IP), "пробы ещё не было");
        t.record_probe_sent(IP);
        assert!(t.has_probes(IP), "проба отмечена");
    }

    #[test]
    fn default_путь_сервер_когда_ничего_не_измерено() {
        let t = table();
        assert_eq!(t.current(IP), None);
        // Без связи с сервером и без измерений — пути нет, событий нет.
        t.ensure_target(IP);
        assert!(t.recalc(0, false).is_empty());
        // Связь есть — сервер (единственный заведомо рабочий).
        let c = one(t.recalc(0, true));
        assert_eq!(
            c,
            PathChange::Changed {
                ip: IP,
                from: None,
                to: PathKind::Server,
                rtt_ms: None
            }
        );
        assert_eq!(t.current(IP), Some(PathKind::Server));
        // Повторный пересчёт ничего не меняет.
        assert!(t.recalc(1, true).is_empty());
    }

    #[test]
    fn прямой_дешевле_сервера_выбирается() {
        let t = table();
        t.record_server_rtt(40, 0);
        t.record_direct_rtt(IP, 10, 0);
        let c = one(t.recalc(100, true));
        assert_eq!(
            c,
            PathChange::Changed {
                ip: IP,
                from: None,
                to: PathKind::Direct,
                rtt_ms: Some(10)
            }
        );
        assert_eq!(t.current_rtt(IP), Some(10));
        assert_eq!(t.server_rtt(), Some(40));
    }

    #[test]
    fn гистерезис_20_процентов() {
        let t = table();
        t.record_server_rtt(50, 0); // стоимость сервера 55
        // End-to-end замер маршрута — он же RTT серверного пути (issue #15).
        t.record_server_path_rtt(IP, 50, 0);
        t.record_direct_rtt(IP, 10, 0);
        one(t.recalc(100, true));
        assert_eq!(t.current(IP), Some(PathKind::Direct));
        // Прямой стал дороже, но меньше чем на 20 % от сервера: 55 vs 60 —
        // порог 60*0.8 = 48, сервер не дешевле → держим прямой.
        t.record_direct_rtt(IP, 60, 1000);
        assert!(t.recalc(2000, true).is_empty(), "дребезг не нужен");
        assert_eq!(t.current(IP), Some(PathKind::Direct));
        // Прямой 100: порог 80, сервер 55 ≤ 80 → переключаемся.
        t.record_direct_rtt(IP, 100, 2000);
        let c = one(t.recalc(3000, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                from: Some(PathKind::Direct),
                to: PathKind::Server,
                rtt_ms: Some(50),
                ..
            }
        ));
        assert_eq!(t.current(IP), Some(PathKind::Server));
        // Обратно: прямой 10 — дешевле сервера на 82 %, переключаемся.
        t.record_direct_rtt(IP, 10, 4000);
        let c = one(t.recalc(5000, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                from: Some(PathKind::Server),
                to: PathKind::Direct,
                ..
            }
        ));
    }

    #[test]
    fn тухлый_прямой_путь_переключает_на_сервер() {
        let t = table();
        t.record_server_rtt(50, 0);
        t.record_direct_rtt(IP, 10, 0);
        one(t.recalc(100, true));
        assert_eq!(t.current(IP), Some(PathKind::Direct));
        // Замер прямой старше трёх интервалов проб (15 с) — путь мёртв, даже
        // без гистерезиса.
        let c = one(t.recalc(16_000, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                from: Some(PathKind::Direct),
                to: PathKind::Server,
                ..
            }
        ));
    }

    #[test]
    fn пин_сильнее_автоматики() {
        let t = table();
        t.record_server_rtt(50, 0);
        t.record_direct_rtt(IP, 10, 0);
        one(t.recalc(100, true));
        assert_eq!(t.current(IP), Some(PathKind::Direct));
        // Закрепляем сервер — он дороже, но автоматика не спорит.
        t.set_pin(IP, Some(PathKind::Server));
        let c = one(t.recalc(200, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                from: Some(PathKind::Direct),
                to: PathKind::Server,
                ..
            }
        ));
        assert!(t.recalc(300, true).is_empty());
        // Сняли пин — автоматика возвращает прямой.
        t.set_pin(IP, None);
        let c = one(t.recalc(400, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                to: PathKind::Direct,
                ..
            }
        ));
    }

    #[test]
    fn мёртвый_пин_даёт_lost_и_откат_но_не_удаляется() {
        let t = table();
        t.record_server_rtt(50, 0);
        t.record_server_path_rtt(IP, 50, 0);
        // Пин на прямой, но прямого замера нет вовсе: Lost + откат на сервер
        // в одном пересчёте.
        t.set_pin(IP, Some(PathKind::Direct));
        let changes = t.recalc(100, true);
        assert_eq!(
            changes,
            vec![
                PathChange::Lost {
                    ip: IP,
                    from: PathKind::Direct
                },
                PathChange::Changed {
                    ip: IP,
                    from: None,
                    to: PathKind::Server,
                    rtt_ms: Some(50)
                },
            ]
        );
        assert!(t.recalc(200, true).is_empty(), "Lost — один раз");
        assert_eq!(t.current(IP), Some(PathKind::Server));
        // Пин остался в таблице (и в конфиге), просто помечен нерабочим.
        assert_eq!(t.pin_of(IP), Some(PathKind::Direct));
        // Прямой ожил — пин снова главный.
        t.record_direct_rtt(IP, 10, 300);
        let c = one(t.recalc(400, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                from: Some(PathKind::Server),
                to: PathKind::Direct,
                rtt_ms: Some(10),
                ..
            }
        ));
    }

    #[test]
    fn пин_на_реле_через_пира() {
        let t = table();
        t.record_server_rtt(50, 0);
        t.record_server_path_rtt(IP, 50, 0);
        t.set_pin(IP, Some(PathKind::PeerRelay { via: VIA }));
        // Маршрута через реле нет — пин мёртв, откат на сервер.
        let changes = t.recalc(100, true);
        assert_eq!(
            changes,
            vec![
                PathChange::Lost {
                    ip: IP,
                    from: PathKind::PeerRelay { via: VIA }
                },
                PathChange::Changed {
                    ip: IP,
                    from: None,
                    to: PathKind::Server,
                    rtt_ms: Some(50)
                },
            ]
        );
        // Появился замер: up 20 + down 20 + 15 = 55, дороже сервера, но пин.
        t.record_peer_rtt(IP, VIA, 20, 20, 0.0, 200);
        let c = one(t.recalc(300, true));
        assert_eq!(
            c,
            PathChange::Changed {
                ip: IP,
                from: Some(PathKind::Server),
                to: PathKind::PeerRelay { via: VIA },
                rtt_ms: Some(40)
            }
        );
    }

    #[test]
    fn релей_пира_и_загрузка() {
        let t = table();
        t.record_server_rtt(40, 0); // 45
        // Реле без загрузки: 20 + 10 + 15 = 45 — поровну с сервером, текущего
        // пути нет: выигрывает тот, кто первый в списке (direct нет).
        t.record_peer_rtt(IP, VIA, 20, 10, 0.0, 0);
        one(t.recalc(100, true));
        assert_eq!(t.current(IP), Some(PathKind::Server));
        // Реле дешевеет на ≥20 %: 10 + 5 + 15 = 30 vs 45 → 30 ≤ 36.
        t.record_peer_rtt(IP, VIA, 10, 5, 0.0, 2000);
        let c = one(t.recalc(2100, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                to: PathKind::PeerRelay { via: VIA },
                rtt_ms: Some(15),
                ..
            }
        ));
        assert_eq!(t.current_rtt(IP), Some(15));
        // Загрузка реле 1.0 добавляет 10 мс: 10+5+15+10 = 40; порог возврата
        // на сервер 30*0.8 = 24 — сервер 45 не дешевле, остаёмся на реле.
        t.record_peer_rtt(IP, VIA, 10, 5, 1.0, 3000);
        assert!(t.recalc(3100, true).is_empty());
        // Выключили релей — пути через пира нет, откат на сервер.
        t.set_relay_enabled(false);
        let c = one(t.recalc(3200, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                from: Some(PathKind::PeerRelay { .. }),
                to: PathKind::Server,
                ..
            }
        ));
    }

    #[test]
    fn record_failure_снимает_текущий_путь_и_переключает_сразу() {
        let t = table();
        t.record_server_rtt(50, 0);
        t.record_direct_rtt(IP, 10, 0);
        one(t.recalc(100, true));
        assert_eq!(t.current(IP), Some(PathKind::Direct));
        // Прямой отказал: текущий путь снят, гистерезиса больше нет.
        t.record_failure(IP);
        assert_eq!(t.current(IP), None);
        let c = one(t.recalc(200, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                from: None,
                to: PathKind::Server,
                ..
            }
        ));
        assert_eq!(t.current(IP), Some(PathKind::Server));
    }

    #[test]
    fn связь_пропала_и_вернулась() {
        let t = table();
        t.record_server_rtt(50, 0);
        t.record_direct_rtt(IP, 10, 0);
        one(t.recalc(100, true));
        // Сервер упал, прямой жив — остаёмся на прямом без событий.
        assert!(t.recalc(200, false).is_empty());
        assert_eq!(t.current(IP), Some(PathKind::Direct));
        // Прямой протух и сервера нет — пути не осталось.
        let c = one(t.recalc(DIRECT_FRESH_MS + 5000, false));
        assert_eq!(
            c,
            PathChange::Lost {
                ip: IP,
                from: PathKind::Direct
            }
        );
        assert_eq!(t.current(IP), None);
        // Связь вернулась — сервер.
        let c = one(t.recalc(DIRECT_FRESH_MS + 6000, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                from: None,
                to: PathKind::Server,
                ..
            }
        ));
    }

    #[test]
    fn несколько_получателей_и_clear_target() {
        let t = table();
        t.record_server_rtt(40, 0);
        t.record_direct_rtt(IP, 10, 0);
        t.record_direct_rtt(OTHER, 90, 0); // 90 > 45 → сервер
        let mut changes = t.recalc(100, true);
        changes.sort_by_key(|c| match c {
            PathChange::Changed { ip, .. }
            | PathChange::Lost { ip, .. }
            | PathChange::Reverted { ip, .. } => *ip,
        });
        assert_eq!(changes.len(), 2);
        assert!(matches!(
            changes[0],
            PathChange::Changed {
                ip: IP,
                to: PathKind::Direct,
                ..
            }
        ));
        assert!(matches!(
            changes[1],
            PathChange::Changed {
                ip: OTHER,
                to: PathKind::Server,
                ..
            }
        ));
        t.clear_target(IP);
        assert_eq!(t.current(IP), None);
        assert_eq!(t.current(OTHER), Some(PathKind::Server));
    }

    #[test]
    fn конфиг_пинов_и_строки() {
        for k in [
            PathKind::Direct,
            PathKind::Server,
            PathKind::PeerRelay { via: VIA },
        ] {
            assert_eq!(PathKind::parse_config(&k.to_config()), Some(k));
        }
        assert_eq!(PathKind::parse_config("DIRECT"), Some(PathKind::Direct));
        assert_eq!(PathKind::parse_config(" server "), Some(PathKind::Server));
        assert_eq!(PathKind::parse_config("relay:zz"), None);
        assert_eq!(PathKind::parse_config("relay:"), None);
        assert_eq!(PathKind::parse_config("relay:0011"), None);
        assert_eq!(PathKind::parse_config("relay"), None);
        assert_eq!(PathKind::parse_config(""), None);
        // Ключ IP: строка конфига ↔ адрес оверлея.
        assert_eq!(parse_ip_key("100.66.0.2"), Some(0x6442_0002));
        assert_eq!(parse_ip_key(" 100.66.0.2 "), Some(0x6442_0002));
        assert_eq!(parse_ip_key("[::1]"), None);
        assert_eq!(parse_ip_key("мусор"), None);
        assert_eq!(ip_key(0x6442_0002), "100.66.0.2");
        // Пины из конфига читаются сразу; мусор пропускается.
        let mut cfg = BTreeMap::new();
        cfg.insert("100.66.0.2".to_string(), "direct".to_string());
        cfg.insert("100.66.0.3".to_string(), "relay:zz".to_string());
        cfg.insert("мусор".to_string(), "server".to_string());
        let t = PathTable::new(&cfg);
        assert_eq!(t.pin_of(IP), Some(PathKind::Direct));
        assert_eq!(t.pin_of(OTHER), None);
        assert_eq!(t.pins().len(), 1);
        // set_pins заменяет набор целиком.
        let mut cfg2 = BTreeMap::new();
        cfg2.insert("100.66.0.3".to_string(), "server".to_string());
        t.set_pins(&cfg2);
        assert_eq!(t.pin_of(IP), None);
        assert_eq!(t.pin_of(OTHER), Some(PathKind::Server));
    }

    #[test]
    fn send_addr_по_пути() {
        let direct: SocketAddr = "203.0.113.1:4000".parse().unwrap();
        let server: SocketAddr = "198.51.100.1:5555".parse().unwrap();
        assert_eq!(send_addr(PathKind::Direct, Some(direct), server), direct);
        // Прямого адреса уже нет — сервер (трафик не теряем).
        assert_eq!(send_addr(PathKind::Direct, None, server), server);
        assert_eq!(send_addr(PathKind::Server, Some(direct), server), server);
        // L2 до T3 идёт сервером: кадр не теряется.
        assert_eq!(
            send_addr(PathKind::PeerRelay { via: VIA }, Some(direct), server),
            server
        );
    }

    #[test]
    fn table_без_паники_из_другого_потока() {
        use std::sync::Arc;
        let t = Arc::new(table());
        let mut hs = Vec::new();
        for i in 0..4u32 {
            let t = t.clone();
            hs.push(std::thread::spawn(move || {
                for j in 0..200u32 {
                    let now = (i * 1000 + j) as u64;
                    t.record_direct_rtt(IP + (j % 3), (j % 90) + 1, now);
                    t.record_server_rtt(j % 80, now);
                    let _ = t.recalc(now, j % 2 == 0);
                    let _ = t.current(IP + (j % 3));
                    let _ = t.current_rtt(IP);
                    if j % 7 == 0 {
                        t.record_failure(IP + (j % 3));
                    }
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
    }

    #[test]
    fn гистерезис_не_переключает_на_разницу_меньше_15_мс() {
        let t = table();
        // Прямой 40, сервер 55 (e2e 50 + 5): текущий — прямой.
        t.record_server_rtt(50, 0);
        t.record_server_path_rtt(IP, 50, 0);
        t.record_direct_rtt(IP, 40, 0);
        one(t.recalc(100, true));
        assert_eq!(t.current(IP), Some(PathKind::Direct));
        // Сервер подешевел до 46 (e2e 41): выигрыш 6 мс < 15 мс — абсолютный
        // порог не пройден, держимся (issue #17).
        t.record_server_path_rtt(IP, 41, 200);
        assert!(t.recalc(300, true).is_empty(), "разница меньше порога");
        assert_eq!(t.current(IP), Some(PathKind::Direct));
        // Сервер 25 (e2e 20): выигрыш ровно 15 мс и 37 % — переключаемся.
        t.record_server_path_rtt(IP, 20, 400);
        let c = one(t.recalc(500, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                from: Some(PathKind::Direct),
                to: PathKind::Server,
                rtt_ms: Some(20),
                ..
            }
        ));
    }

    #[test]
    fn dwell_не_даёт_переключаться_слишком_часто() {
        let t = PathTable::empty();
        // Удержание 10 с (как `path_dwell_ms` по умолчанию), интервал проб 5 с.
        t.set_limits(15, 10_000, Duration::from_secs(5));
        t.record_server_rtt(50, 0);
        t.record_server_path_rtt(IP, 50, 0); // стоимость 55
        t.record_direct_rtt(IP, 30, 0); // дешевле — выбран прямой
        one(t.recalc(100, true));
        assert_eq!(t.current(IP), Some(PathKind::Direct));
        // Сервер стал вдвое дешевле (e2e 10 → 15), но 10 с удержания не прошло.
        t.record_server_path_rtt(IP, 10, 200);
        assert!(t.recalc(5_000, true).is_empty(), "dwell не прошёл");
        assert_eq!(t.current(IP), Some(PathKind::Direct));
        // Прошло 10 с с момента выбора — переключаемся.
        let c = one(t.recalc(10_100, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                from: Some(PathKind::Direct),
                to: PathKind::Server,
                ..
            }
        ));
    }

    #[test]
    fn сломанный_путь_переключается_без_dwell() {
        let t = PathTable::empty();
        // Удержание 60 с — сломанный путь всё равно меняется сразу.
        t.set_limits(15, 60_000, Duration::from_secs(5));
        t.record_server_rtt(50, 0);
        t.record_server_path_rtt(IP, 50, 0);
        t.record_direct_rtt(IP, 10, 0);
        one(t.recalc(100, true));
        assert_eq!(t.current(IP), Some(PathKind::Direct));
        // Прямой отказал: ни порогов, ни dwell (issue #17).
        t.record_failure(IP);
        let c = one(t.recalc(200, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                from: None,
                to: PathKind::Server,
                ..
            }
        ));
        assert_eq!(t.current(IP), Some(PathKind::Server));
    }

    #[test]
    fn серверный_путь_показывает_e2e_а_не_плечо() {
        let t = table();
        // Плечо до сервера — 1 мс (как в issue #14), честный маршрут — 42 мс.
        t.record_server_rtt(1, 0);
        t.record_server_path_rtt(IP, 42, 0);
        let c = one(t.recalc(100, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                to: PathKind::Server,
                rtt_ms: Some(42),
                ..
            }
        ));
        assert_eq!(t.current(IP), Some(PathKind::Server));
        assert_eq!(t.current_rtt(IP), Some(42), "RTT пути — end-to-end");
        // Плечо доступно отдельно — UI покажет, из чего сложился маршрут.
        assert_eq!(t.server_rtt(), Some(1));
    }

    #[test]
    fn плечо_не_подменяет_e2e_при_протухшем_замере() {
        let t = table();
        t.record_server_rtt(1, 0);
        t.record_server_path_rtt(IP, 42, 0);
        one(t.recalc(100, true));
        assert_eq!(t.current_rtt(IP), Some(42));
        // End-to-end замер протух: путь остаётся серверным (связь есть), но
        // RTT неизвестен — плечо 1 мс не подставляется (issue #15).
        t.recalc(SERVER_FRESH_MS + 1, true);
        assert_eq!(t.current(IP), Some(PathKind::Server));
        assert_eq!(t.current_rtt(IP), None, "плечо не подменяет e2e");
        assert_eq!(t.server_rtt(), Some(1), "плечо не потерялось");
    }

    #[test]
    fn jitter_и_loss_считаются_по_пробам() {
        let t = table();
        t.record_server_path_rtt(IP, 40, 0);
        one(t.recalc(100, true));
        // Три пробы: ответ, ответ, без ответа — 1 из 3 = 333 ‰.
        t.record_probe_sent(IP);
        t.record_probe_answered(IP);
        t.record_probe_sent(IP);
        t.record_probe_answered(IP);
        t.record_probe_sent(IP);
        let m = t.metrics(IP).expect("метрики текущего пути");
        assert_eq!(m.loss_pm, 333);
        // Замеры текущего пути: 40 → 60 → 80. Джиттер — EWMA |Δ| с α = 1/4:
        // (0*3+20)/4 = 5, (5*3+20)/4 = 8.
        t.record_server_path_rtt(IP, 40, 200);
        t.record_server_path_rtt(IP, 60, 300);
        t.record_server_path_rtt(IP, 80, 400);
        let m = t.metrics(IP).expect("метрики текущего пути");
        assert_eq!(m.jitter_ms, 8);
        assert_eq!(m.hist, vec![40, 60, 80], "история — старые первыми");
        // Замер другого пути историю текущего не трогает.
        t.record_direct_rtt(IP, 999, 500);
        assert_eq!(t.metrics(IP).unwrap().hist, vec![40, 60, 80]);
    }

    #[test]
    fn авто_откат_при_ухудшении_и_карантин() {
        let t = table();
        t.record_direct_rtt(IP, 30, 0);
        t.record_server_path_rtt(IP, 50, 0); // 55
        one(t.recalc(100, true));
        assert_eq!(t.current(IP), Some(PathKind::Direct));
        // Прямой подорожал до 100, сервер 65 — автопереключение по выгоде:
        // окно проверки запоминает метрики старого пути.
        t.record_direct_rtt(IP, 100, 150);
        t.record_server_path_rtt(IP, 60, 150);
        let c = one(t.recalc(200, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                from: Some(PathKind::Direct),
                to: PathKind::Server,
                ..
            }
        ));
        // В окне проверки новый путь оказался хуже (130 против 100 мс):
        // откат на старый путь и карантин альтернативы на 60 с.
        t.record_server_path_rtt(IP, 125, 300);
        let c = one(t.recalc(1_000, true));
        assert_eq!(
            c,
            PathChange::Reverted {
                ip: IP,
                from: PathKind::Server,
                to: PathKind::Direct
            }
        );
        assert_eq!(t.current(IP), Some(PathKind::Direct));
        // В карантине автоматика сервер не выбирает, даже если он дешевле.
        t.record_server_path_rtt(IP, 5, 1_100); // стоимость 10
        assert!(t.recalc(2_000, true).is_empty(), "карантин не истёк");
        assert_eq!(t.current(IP), Some(PathKind::Direct));
        // Карантин истёк, прямой замер протух — снова сервер.
        let c = one(t.recalc(QUARANTINE_MS + 1_000, true));
        assert!(matches!(
            c,
            PathChange::Changed {
                from: Some(PathKind::Direct),
                to: PathKind::Server,
                ..
            }
        ));
    }
}

#[cfg(test)]
mod choose_tests {
    use super::*;

    const IP: u32 = 0x6442_0002;
    const VIA: [u8; 32] = [7; 32];

    /// Таблица с порогами из конфига по умолчанию и без dwell: тесты про
    /// выбор пути не должны ждать удержание.
    fn table() -> PathTable {
        let t = PathTable::empty();
        t.set_limits(
            crate::store::DEFAULT_PATH_HYSTERESIS_MS,
            0,
            Duration::from_millis(crate::store::DEFAULT_RTT_INTERVAL_MS),
        );
        t
    }

    #[test]
    fn choose_заводит_цель_и_возвращает_путь_сразу() {
        let t = table();
        // Цели ещё нет в таблице: choose заводит её (участник группы).
        let (path, changes) = t.choose(IP, 0, false);
        assert_eq!(path, None, "без связи и измерений пути нет");
        assert!(changes.is_empty());
        // Связь есть, замер сервера есть — сервер (путь по умолчанию).
        t.record_server_rtt(50, 5);
        t.record_server_path_rtt(IP, 50, 5);
        let (path, changes) = t.choose(IP, 10, true);
        assert_eq!(path, Some(PathKind::Server));
        assert_eq!(
            changes,
            vec![PathChange::Changed {
                ip: IP,
                from: None,
                to: PathKind::Server,
                rtt_ms: Some(50)
            }]
        );
        // Прямой дешевле — choose возвращает его без ожидания тика.
        t.record_direct_rtt(IP, 5, 20);
        let (path, changes) = t.choose(IP, 30, true);
        assert_eq!(path, Some(PathKind::Direct));
        assert!(matches!(
            changes.as_slice(),
            [PathChange::Changed {
                from: Some(PathKind::Server),
                to: PathKind::Direct,
                rtt_ms: Some(5),
                ..
            }]
        ));
    }

    #[test]
    fn choose_выбирает_реле_по_стоимости() {
        let t = table();
        t.record_server_rtt(60, 0); // cost 65
        t.record_direct_rtt(IP, 20, 0); // cost 20 — прямой дешевле
        let (path, _) = t.choose(IP, 10, true);
        assert_eq!(path, Some(PathKind::Direct));
        // Реле: 5 + 5 + 15 + 0 = 25 > 20 — гистерезис (20 %: порог 16)
        // не даёт переключиться, хотя реле уже дешевле сервера.
        t.record_peer_rtt(IP, VIA, 5, 5, 0.0, 10);
        let (path, changes) = t.choose(IP, 20, true);
        assert_eq!(path, Some(PathKind::Direct));
        assert!(changes.is_empty(), "дребезг не нужен");
        // Прямой подорожал до 40 — реле (25) дешевле на 37 % → переключение.
        t.record_direct_rtt(IP, 40, 30);
        let (path, changes) = t.choose(IP, 40, true);
        assert_eq!(path, Some(PathKind::PeerRelay { via: VIA }));
        assert!(matches!(
            changes.as_slice(),
            [PathChange::Changed {
                from: Some(PathKind::Direct),
                to: PathKind::PeerRelay { via },
                rtt_ms: Some(10),
                ..
            }] if *via == VIA
        ));
        // Релей запрещён: L2 недоступен, но гистерезиса нет — пересчёт
        // берёт лучший из оставшихся (прямой 40 дешевле сервера 65).
        t.set_relay_enabled(false);
        let (path, changes) = t.choose(IP, 50, true);
        assert_eq!(path, Some(PathKind::Direct));
        assert_eq!(changes.len(), 1);
    }

    #[test]
    fn fallbacks_по_возрастанию_стоимости() {
        let t = table();
        t.record_server_rtt(50, 0);
        t.record_direct_rtt(IP, 10, 0);
        t.record_peer_rtt(IP, VIA, 5, 5, 0.0, 0);
        let v = t.fallbacks(IP, 10, true);
        // Прямой 10, реле 25, сервер 55.
        assert_eq!(
            v,
            vec![
                PathKind::Direct,
                PathKind::PeerRelay { via: VIA },
                PathKind::Server
            ]
        );
        // Без связи сервер недоступен, протухшие замеры не выдумываются.
        let v = t.fallbacks(IP, 100_000, false);
        assert!(v.is_empty(), "все замеры устарели: {v:?}");
        // Неизвестный получатель — пусто.
        assert!(t.fallbacks(0x6442_00FF, 10, true).is_empty());
    }
}
