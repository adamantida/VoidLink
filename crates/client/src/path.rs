//! Выбор оптимального пути доставки до участника (§3.6 плана этапа 9).
//!
//! Уровни доставки: `direct` (L0, прямой p2p), `server` (L1, релей сервера),
//! `peer` (L2, релей через участника группы). Путь выбирается **по измеренной
//! стоимости**, а не по фиксированному списку:
//!
//! ```text
//! cost(direct)  = rtt_direct
//! cost(server)  = rtt_server + 5
//! cost(peer R)  = rtt(us→R) + rtt(R→dst) + 15 + 10 * load(R)
//! ```
//!
//! Правила:
//! 1. Пересчёт — [`PathTable::recalc`] (движок зовёт раз в 10 с и при падении
//!    пути).
//! 2. **Гистерезис 20 %**: новый путь выбирается, только если он дешевле
//!    текущего на ≥ 20 % либо текущий путь мёртв, — иначе «дребезг» между
//!    почти равными путями.
//! 3. **Ручное закрепление** ([`PathTable::set_pin`], `client.json` →
//!    `pinned_paths`) сильнее автоматики. Закреплённый, но недоступный путь
//!    даёт `Lost` и откат на автоматику; закрепление при этом не удаляется, а
//!    помечается нерабочим (пока путь не оживёт).
//!
//! События `PathChanged`/`PathLost` формирует движок: таблица только считает
//! изменения ([`PathChange`]), не зная про UI и каналы.
//!
//! Все времена — миллисекунды от старта движка (`now_ms`), а не `Instant`:
//! так тесты детерминированы, а `Mutex` держится коротко (только арифметика).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;

use tunnel_protocol as proto;

/// Надбавка за релей сервера (L1): лишний хоп и очередь сервера.
pub const HOP_PENALTY_SERVER_MS: f64 = 5.0;
/// Надбавка за релей через пира (L2): два хопа, NAT, чужой процесс.
pub const HOP_PENALTY_PEER_MS: f64 = 15.0;
/// Надбавка за загрузку реле-пира: `load` 0..1 → 0..10 мс.
pub const LOAD_PENALTY_MS: f64 = 10.0;
/// Насколько новый путь должен быть дешевле текущего (в процентах), чтобы
/// переключиться: 20 % — порог гистерезиса.
pub const HYSTERESIS_PCT: f64 = 20.0;
/// Прямой канал считается живым столько после последнего замера: `direct_addr`
/// старше 12 с — «прямой путь не работает» (§3.4).
pub const DIRECT_FRESH_MS: u64 = 12_000;
/// RTT сервера считается актуальным столько (периодический CTRL_PING идёт
/// чаще, но после потери связи замер устаревает).
pub const SERVER_FRESH_MS: u64 = 30_000;
/// Замер маршрута через пира актуален столько.
pub const PEER_FRESH_MS: u64 = 30_000;

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
        /// Измеренный RTT выбранного пути (у сервера/пира может быть неизвестен).
        rtt_ms: Option<u32>,
    },
    /// Доступных путей не осталось. `from` — что было текущим.
    Lost { ip: u32, from: PathKind },
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

/// Один получатель: измерения по путям и выбранный путь.
#[derive(Clone, Debug, Default)]
struct Target {
    direct_ms: Option<u32>,
    direct_at: u64,
    peer: Option<PeerRoute>,
    /// Текущий путь и его стоимость на момент выбора (для гистерезиса).
    current: Option<PathKind>,
    current_cost: Option<f64>,
    /// Закреплённый путь был недоступен (уже сообщили `Lost`); сбрасывается,
    /// когда он снова доступен.
    pin_broken: bool,
}

#[derive(Debug, Default)]
struct Paths {
    targets: BTreeMap<u32, Target>,
    /// Закрепления: ip → путь (из `client.json`).
    pins: BTreeMap<u32, PathKind>,
    /// Последний измеренный RTT сервера и время замера.
    server: Option<(u32, u64)>,
    /// Релей через пиров разрешён (`SetRelayEnabled`).
    relay_enabled: bool,
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
            }),
        }
    }

    /// Таблица без закреплений и измерений (тесты, движок до конфига).
    pub fn empty() -> Self {
        Self::new(&BTreeMap::new())
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
        p.pins = parsed;
    }

    /// Закрепить (`Some`) или открепить (`None`) путь получателя.
    pub fn set_pin(&self, ip: u32, kind: Option<PathKind>) {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match kind {
            Some(k) => {
                p.pins.insert(ip, k);
                // Новое закрепление проверяется сразу на следующем пересчёте.
                if let Some(t) = p.targets.get_mut(&ip) {
                    t.pin_broken = false;
                }
            }
            None => {
                p.pins.remove(&ip);
                if let Some(t) = p.targets.get_mut(&ip) {
                    t.pin_broken = false;
                }
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
        let t = p.targets.entry(ip).or_default();
        t.direct_ms = Some(rtt_ms);
        t.direct_at = now_ms;
    }

    /// Замер RTT сервера (CTRL_PONG с меткой).
    pub fn record_server_rtt(&self, rtt_ms: u32, now_ms: u64) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .server = Some((rtt_ms, now_ms));
    }

    /// Замер маршрута через пира `via`: `up_ms` — мы→реле, `down_ms` —
    /// реле→получатель (из `MESH_ROUTE_OK`), `load` — загрузка реле 0..1.
    pub fn record_peer_rtt(&self, ip: u32, via: [u8; 32], up_ms: u32, down_ms: u32, load: f64, now_ms: u64) {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let t = p.targets.entry(ip).or_default();
        t.peer = Some(PeerRoute {
            via,
            up_ms,
            down_ms,
            load: load.clamp(0.0, 1.0),
            at: now_ms,
        });
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

    /// Измеренный RTT текущего пути.
    pub fn current_rtt(&self, ip: u32) -> Option<u32> {
        let p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let t = p.targets.get(&ip)?;
        match t.current? {
            PathKind::Direct => t.direct_ms,
            PathKind::Server => p.server.map(|(r, _)| r),
            PathKind::PeerRelay { .. } => t.peer.map(|r| r.rtt()),
        }
    }

    /// Замер RTT сервера (для снимка состояния).
    pub fn server_rtt(&self) -> Option<u32> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .server
            .map(|(r, _)| r)
    }

    /// Пересчитать пути всех получателей. Возвращает изменения — движок
    /// рассылает их событиями. `server_up` — есть ли связь с сервером.
    pub fn recalc(&self, now_ms: u64, server_up: bool) -> Vec<PathChange> {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let relay = p.relay_enabled;
        let server = p.server;
        // Закрепления копируются: иначе нельзя одновременно держать
        // `targets.iter_mut()` и `pins.get()` (один и тот же `Paths`).
        let pins = p.pins.clone();
        let mut changes = Vec::new();
        for (ip, t) in p.targets.iter_mut() {
            recalc_target_pinned(
                *ip,
                t,
                pins.get(ip).copied(),
                server,
                server_up,
                relay,
                now_ms,
                &mut changes,
            );
            // Закрепление переживает падение: «нерабочее» — не «удалённое».
        }
        changes
    }

    /// Пересчёт одного получателя (движок может позвать точечно).
    pub fn recalc_one(&self, ip: u32, now_ms: u64, server_up: bool) -> Vec<PathChange> {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let relay = p.relay_enabled;
        let server = p.server;
        let pin = p.pins.get(&ip).copied();
        let Some(t) = p.targets.get_mut(&ip) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        recalc_target_pinned(ip, t, pin, server, server_up, relay, now_ms, &mut out);
        out
    }
}

/// Стоимость и RTT пути, если он сейчас доступен.
fn cost_of(
    t: &Target,
    server: Option<(u32, u64)>,
    server_up: bool,
    relay: bool,
    now_ms: u64,
    kind: PathKind,
) -> Option<(f64, Option<u32>)> {
    match kind {
        PathKind::Direct => {
            let ms = t.direct_ms?;
            (now_ms.saturating_sub(t.direct_at) <= DIRECT_FRESH_MS).then_some((ms as f64, Some(ms)))
        }
        PathKind::Server => {
            if !server_up {
                return None;
            }
            match server {
                // Свежий замер — сравниваем по стоимости.
                Some((rtt, at)) if now_ms.saturating_sub(at) <= SERVER_FRESH_MS => {
                    Some((rtt as f64 + HOP_PENALTY_SERVER_MS, Some(rtt)))
                }
                // Связь есть, RTT ещё не измерили: путь доступен, но пока
                // несравним (None-стоимость).
                _ => Some((f64::INFINITY, None)),
            }
        }
        PathKind::PeerRelay { via } => {
            if !relay {
                return None;
            }
            let r = t.peer?;
            if r.via != via || now_ms.saturating_sub(r.at) > PEER_FRESH_MS {
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
    server: Option<(u32, u64)>,
    server_up: bool,
    relay: bool,
    now_ms: u64,
    out: &mut Vec<PathChange>,
) {
    let cost = |t: &Target, kind: PathKind| cost_of(t, server, server_up, relay, now_ms, kind);

    // 1. Ручное закрепление сильнее автоматики.
    if let Some(want) = pin {
        if let Some((c, rtt)) = cost(t, want) {
            t.pin_broken = false;
            if t.current != Some(want) {
                let from = t.current;
                t.current = Some(want);
                t.current_cost = Some(c);
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
        }
        t.current = None;
        t.current_cost = None;
    }

    // 2. Автоматика: все доступные пути, лучший по стоимости.
    let mut best: Option<(f64, PathKind, Option<u32>)> = None;
    let candidates = [
        Some(PathKind::Direct),
        Some(PathKind::Server),
        t.peer.map(|r| PathKind::PeerRelay { via: r.via }),
    ];
    for kind in candidates.into_iter().flatten() {
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
        // Текущий путь жив и измерен: меняем только при выигрыше ≥ 20 %.
        (Some(cur), Some((cc, _))) if cc.is_finite() => {
            if let Some((bc, bk, brtt)) = best {
                let threshold = cc * (100.0 - HYSTERESIS_PCT) / 100.0;
                if bk != cur && bc <= threshold {
                    t.current = Some(bk);
                    t.current_cost = Some(bc);
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
        // CTRL_PONG): держим его — сравнение появится после замера.
        (Some(_), Some((cc, _))) => {
            t.current_cost = Some(cc);
        }
        // Текущего живого пути нет: берём лучший без гистерезиса — держаться
        // не за что.
        (cur, _) => {
            if let Some((bc, bk, brtt)) = best {
                t.current = Some(bk);
                t.current_cost = Some(bc);
                out.push(PathChange::Changed {
                    ip,
                    from: cur,
                    to: bk,
                    rtt_ms: brtt,
                });
                return;
            }
            // Ничего измеренного: сервер — единственный заведомо рабочий путь.
            if server_up {
                t.current = Some(PathKind::Server);
                t.current_cost = None;
                out.push(PathChange::Changed {
                    ip,
                    from: cur,
                    to: PathKind::Server,
                    rtt_ms: None,
                });
            } else if let Some(from) = cur {
                t.current = None;
                t.current_cost = None;
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
        // Релей L2 в T1 не транспортируется: до реализации mesh (T3) кадр
        // идёт сервером — трафик не теряется.
        PathKind::PeerRelay { .. } => server,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: u32 = 0x6442_0002;
    const OTHER: u32 = 0x6442_0003;
    const VIA: [u8; 32] = [7; 32];

    fn table() -> PathTable {
        PathTable::empty()
    }

    /// Единственное изменение (паника, если их не одно).
    fn one(changes: Vec<PathChange>) -> PathChange {
        assert_eq!(changes.len(), 1, "ожидалось одно изменение: {changes:?}");
        changes[0]
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
        // Замер прямой старше 12 с — путь мёртв, даже без гистерезиса.
        let c = one(t.recalc(DIRECT_FRESH_MS + 1000, true));
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
        assert!(matches!(c, PathChange::Changed { to: PathKind::Direct, .. }));
    }

    #[test]
    fn мёртвый_пин_даёт_lost_и_откат_но_не_удаляется() {
        let t = table();
        t.record_server_rtt(50, 0);
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
            PathChange::Changed { ip, .. } | PathChange::Lost { ip, .. } => *ip,
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
                    t.record_direct_rtt(IP + (j % 3), (j % 90) as u32 + 1, now);
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
}