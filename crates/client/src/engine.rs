//! Движок клиента v3: управляющее соединение с сервером + туннель групп
//! (нормативно — `docs/PROTOCOL.md`).
//!
//! Движок ничего не знает о UI: он публикует состояние (groups/meta/stats)
//! и шлёт события в канал; команды UI → движок идут через канал Cmd.
//!
//! Потоки:
//! - `rx` — блокирующий приём с единственного UDP-сокета. Групповые фреймы
//!   (DATA/PING/PONG/PUNCH/KEEPALIVE) обрабатывает сам, сразу, по правилам
//!   приёма раздела 7; управляющие фреймы сервера передаёт движку. P2P
//!   работает и пока сервер недоступен.
//! - `engine` — рукопожатие и сессия с сервером (сеансовые ключи, окно
//!   повторов, сборка FRAG), команды UI, таймеры (RTT, NAT, CTRL_PING, список
//!   групп, повтор LEAVE, кандидаты). Таймеры идут по часам, а не по паузам в
//!   приёме: под нагрузкой они не «замерзают».
//! - `tun` — пакеты из адаптера → пирам (напрямую или через релей).
//! - `sampler` — раз в секунду скорость трафика для спарклайна.
//!
//! Сокет один на всё время работы: при реконнекте (и смене сервера) шлётся
//! новый HELLO3 с того же адреса, NAT-маппинги и прямые каналы с пирами не
//! рвутся. Ключи групп и счётчики живут только в памяти: после перезапуска
//! HELLO3 участника ротирует ключи всех его групп.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use proto::ctrl;
use proto::handshake;
use proto::payloads;
use tunnel_protocol as proto;

use crate::store::{Config, TransportMode};
use crate::tcp_link::{self, TcpLink};

#[cfg(windows)]
const RING_CAPACITY: u32 = 0x40_0000; // 4 MiB

/// Имя адаптера по умолчанию: Windows — имя wintun-адаптера, Linux — имя
/// TUN-интерфейса, macOS — игнорируется (ядро само выдаёт utunN).
#[cfg(windows)]
pub const DEFAULT_ADAPTER: &str = "TunnelVPN";
#[cfg(target_os = "linux")]
pub const DEFAULT_ADAPTER: &str = "voidlink0";
#[cfg(not(any(windows, target_os = "linux")))]
pub const DEFAULT_ADAPTER: &str = "utun";
/// Шаг цикла движка (верхняя граница задержки таймеров).
const TICK: Duration = Duration::from_millis(100);
/// RTT-зонд онлайн-пирам. Для прямых каналов он же держит NAT-маппинг.
const RTT_EVERY: Duration = Duration::from_secs(2);
/// PUNCH онлайн-пирам без прямого канала.
const PUNCH_EVERY: Duration = Duration::from_secs(5);
/// CTRL_PING серверу (сервер держит сессию 30 с без пакетов).
const PING_EVERY: Duration = Duration::from_secs(5);
const LIST_EVERY: Duration = Duration::from_secs(15);
const SERVER_TIMEOUT: Duration = Duration::from_secs(20);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// Повтор HELLO3 одной попытки, пока нет WELCOME.
const HELLO_RETRY: Duration = Duration::from_secs(1);
/// Первое подключение (синхронное) и CLI ждут WELCOME столько.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Повторное рукопожатие поверх живой сессии (смена имени) бросается через
/// столько: сессия остаётся старой, а если сервер её уже сменил — таймаут
/// сервера переподключит.
const REHELLO_GIVE_UP: Duration = Duration::from_secs(10);
/// HELLO3 с cookie — один на CHALLENGE и не чаще этого: поддельный поток
/// CHALLENGE не превращает клиента в генератор HELLO3.
const COOKIE_GAP: Duration = Duration::from_millis(250);
/// Нет прямых фреймов от пира столько — прямой канал считается потерянным,
/// трафик идёт через релей (пир сменил порт, NAT закрыл маппинг…).
const DIRECT_TIMEOUT: Duration = Duration::from_secs(12);
/// LEAVE повторяется, пока сервер не подтвердит выход списком групп.
const LEAVE_RETRY: Duration = Duration::from_secs(1);
const LEAVE_GIVE_UP: Duration = Duration::from_secs(20);
/// Окно INVITE_LIST, которого ждём (после HELLO3 или запрошенное
/// LIST_INVITES), запрашивается снова, пока не придёт: потерянное окно
/// иначе прятало бы приглашения до переподключения.
const INVITE_SYNC_RETRY: Duration = Duration::from_secs(3);
const INVITE_SYNC_GIVE_UP: Duration = Duration::from_secs(20);
/// DECLINE_INVITE повторяется, пока сервер не подтвердит отказ окном списка.
const DECLINE_RETRY: Duration = Duration::from_secs(1);
const DECLINE_GIVE_UP: Duration = Duration::from_secs(20);
/// GET_GROUP — не чаще раза в секунду на группу (раздел 7).
const GET_GROUP_EVERY: Duration = Duration::from_secs(1);
/// Как часто повторять своё состояние серверу — CANDIDATES (заодно с
/// проверкой, не сменился ли LAN-адрес), STATUS и PRESENCE. Ответа на них
/// нет, а повтор без изменения сервер не считает изменением: потерянная
/// датаграмма чинится не дольше чем за период.
const CAND_EVERY: Duration = Duration::from_secs(60);
/// Пауза между повторами PRESENCE до подтверждения.
const SELF_RETRY: Duration = Duration::from_secs(1);
/// PRESENCE повторяется раз в `SELF_RETRY`, пока сервер не подтвердит его
/// PRESENCE_ACK с тем же значением; дальше — только периодический повтор.
const PRESENCE_GIVE_UP: Duration = Duration::from_secs(20);
const HISTORY_LEN: usize = 60;
const NEW_GROUP_GRACE: Duration = Duration::from_secs(10);
/// Таймаут чтения rx-потока (как часто он проверяет флаг выхода).
const RX_POLL: Duration = Duration::from_millis(250);
/// Шифрованные фреймы, обогнавшие WELCOME (UDP не держит порядок): без
/// ключей сессии их не открыть — разбираются после WELCOME.
const EARLY_MAX: usize = 64;
/// Наборов ключей одной попытки (WELCOME под тот же eph с разными
/// `server_eph`: сервер создал новую сессию на HELLO3 с другого адреса).
const MAX_KEYSETS: usize = 4;
/// Сколько отслуженных ключей групп помнит `KeyLog`.
const KEY_LOG_LEN: usize = 256;
/// Предел паузы сигнала «эпоха новее» после неподтвердившихся сигналов.
const HINT_GAP_MAX: Duration = Duration::from_secs(60);
/// Жёсткий предел сигналов «эпоха новее» на группу за `HINT_WINDOW`
/// (поверх паузы: она сбрасывается каждой подтвердившейся эпохой).
const HINT_MAX_PER_WINDOW: usize = 8;
const HINT_WINDOW: Duration = Duration::from_secs(60);
/// RESET, пришедший раньше этого после подлинного фрейма сервера, —
/// подделка или запоздалый: сервер нашу сессию явно знает.
const RESET_GRACE: Duration = Duration::from_secs(2);
/// Сколько помнится кик из группы (против запоздавших состояний и списков).
const TOMB_TTL: Duration = Duration::from_secs(60);
/// Таймаут установки TCP-соединения с сервером (фолбэк, когда режут UDP).
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

static DEBUG: AtomicBool = AtomicBool::new(false);
pub fn set_debug(on: bool) {
    DEBUG.store(on, Ordering::Relaxed);
}
fn debug() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

// ---------- состояние, открытое для UI ----------

#[derive(Clone)]
pub struct PeerSess {
    pub pubkey: [u8; 32],
    pub name: String,
    pub status: String,
    pub online: bool,
    pub ip: u32,
    /// Адрес пира, каким его видит сервер (MemberInfo.endpoint).
    pub endpoint: Option<SocketAddr>,
    /// LAN-кандидаты пира (CANDIDATES через сервер).
    pub candidates: Vec<SocketAddr>,
    /// Прямой канал: один из `endpoint`/`candidates`, с которого первым
    /// пришёл ответ. Фреймы адрес не переписывают (раздел 7, п. 5).
    pub direct_addr: Option<SocketAddr>,
    pub last_rx: Instant,
    /// Последний фрейм пира, пришедший на `direct_addr`.
    pub last_direct: Option<Instant>,
    pub rtt_ms: Option<u64>,
}

impl PeerSess {
    /// Прямой p2p-канал жив.
    pub fn direct(&self) -> bool {
        self.direct_addr.is_some()
    }

    /// Адрес известен от сервера (endpoint или кандидат).
    pub fn knows(&self, addr: SocketAddr) -> bool {
        self.endpoint == Some(addr) || self.candidates.contains(&addr)
    }

    /// Куда пробивать NAT: endpoint и все кандидаты, без повторов.
    fn punch_addrs(&self) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = self.endpoint.into_iter().collect();
        for c in &self.candidates {
            if !out.contains(c) {
                out.push(*c);
            }
        }
        out
    }
}

/// Окна повторов под одним ключом группы: src_ip → окно (раздел 7, п. 4).
/// Окно принадлежит ключу, а не номеру эпохи: nonce — (src_ip, counter) под
/// ключом, и тот же номер эпохи с другим ключом (откат номеров после падения
/// сервера) окна прежнего ключа не наследует.
type RxWindows = HashMap<u32, proto::ReplayWindow>;

/// Что клиент накопил под ключом группы: следующий счётчик отправки и окна
/// приёма.
#[derive(Default)]
struct KeyState {
    tx: u64,
    rx: RxWindows,
}

/// Отслуженные ключи групп и их [`KeyState`]. Общий для всех групп и их
/// пересозданий: вернуться к такому ключу (запоздавшее состояние, повторный
/// вход без ротации после потерянного LEAVE) — значит продолжить его счётчик
/// (повтор nonce под тем же ключом раскрыл бы трафик) и его окна приёма
/// (иначе записанные раньше фреймы пиров под этим ключом прошли бы снова).
#[derive(Clone, Default)]
struct KeyLog(Arc<Mutex<VecDeque<(proto::SymKey, KeyState)>>>);

impl KeyLog {
    /// Состояние ключа (пустое — ключ новый).
    fn take(&self, key: &proto::SymKey) -> KeyState {
        let mut log = self.0.lock().unwrap();
        match log.iter().position(|(k, _)| k == key) {
            Some(i) => log.remove(i).map(|(_, s)| s).unwrap_or_default(),
            None => KeyState::default(),
        }
    }

    fn put(&self, key: proto::SymKey, st: KeyState) {
        if st.tx == 0 && st.rx.is_empty() {
            return;
        }
        let mut log = self.0.lock().unwrap();
        log.push_back((key, st));
        while log.len() > KEY_LOG_LEN {
            log.pop_front();
        }
    }
}

/// Прошлый ключ группы после ротации без `revoke_prev` (только эпохи
/// `epoch - 1`): принимается до `until`.
struct PrevKey {
    epoch: u32,
    key: proto::SymKey,
    until: Instant,
    st: KeyState,
}

pub struct GroupSess {
    pub name: String,
    pub owner: [u8; 32],
    pub private: bool,
    pub my_ip: u32,
    pub since: Instant,
    /// ip → пир.
    pub members: HashMap<u32, PeerSess>,
    /// Ревизия состояния: сверяется с `base_rev` дельт и с GROUP_LIST.
    pub rev: u32,
    /// Эпоха текущего ключа.
    pub epoch: u32,
    /// Текущий ключ: им шифруется вся отправка.
    key: proto::SymKey,
    /// Счётчик отправки (раздел 7: на (gid, epoch)) и окна приёма под `key`.
    cur: KeyState,
    prev: Option<PrevKey>,
    key_log: KeyLog,
    /// Последний сигнал rx-потока «эпоха новее нашей», на какую эпоху и
    /// пауза до следующего: сигнал, не подтвердившийся ответом на GET_GROUP
    /// (эпоха так и не пришла — подделка), удваивает паузу.
    sync_hint: Option<Instant>,
    hint_epoch: u32,
    hint_gap: Duration,
    /// Моменты последних сигналов (не больше `HINT_MAX_PER_WINDOW` за `HINT_WINDOW`).
    hint_log: VecDeque<Instant>,
    /// Серверная сессия последнего принятого GROUP_STATE (0 — принять
    /// следующий без сверки ревизии): в пределах сессии ревизии сервера
    /// только растут, и запоздавшее состояние с меньшей ревизией — откат
    /// (в т.ч. к ключу, отозванному киком).
    state_sess: u64,
}

impl Drop for GroupSess {
    fn drop(&mut self) {
        self.key_log.put(self.key, std::mem::take(&mut self.cur));
        if let Some(p) = self.prev.take() {
            self.key_log.put(p.key, p.st);
        }
    }
}

impl GroupSess {
    fn new(st: &payloads::GroupState, now: Instant, key_log: KeyLog) -> Self {
        Self {
            name: st.name.clone(),
            owner: st.owner,
            private: st.private,
            my_ip: st.my_ip,
            since: now,
            members: HashMap::new(),
            rev: st.rev,
            epoch: st.epoch,
            key: st.key,
            cur: key_log.take(&st.key),
            prev: None,
            key_log,
            sync_hint: None,
            hint_epoch: 0,
            hint_gap: GET_GROUP_EVERY,
            hint_log: VecDeque::new(),
            state_sess: 0,
        }
    }

    /// Ключ эпохи `epoch`, если он ещё принимается: текущий или прошлый в
    /// пределах grace.
    fn rx_key(&self, epoch: u32, now: Instant) -> Option<proto::SymKey> {
        if epoch == self.epoch {
            return Some(self.key);
        }
        match &self.prev {
            Some(p) if p.epoch == epoch && now < p.until => Some(p.key),
            _ => None,
        }
    }

    /// Окно повторов отправителя `src` под ключом `key` (текущим или
    /// прошлым). `None` — ключ уже сменился (фрейм расшифрован им до смены).
    fn rx_window(&mut self, key: &proto::SymKey, src: u32) -> Option<&mut proto::ReplayWindow> {
        if *key == self.key {
            return Some(self.cur.rx.entry(src).or_default());
        }
        self.prev
            .as_mut()
            .filter(|p| p.key == *key)
            .map(|p| p.st.rx.entry(src).or_default())
    }

    /// Ключ из GROUP_STATE / GROUP_UPDATE. Новый ключ — свои счётчик и окна
    /// (пустые, если ключом ещё не пользовались). Прошлый ключ принимается
    /// ещё `PREV_KEY_GRACE` (участники получают новый не одновременно), но
    /// только если новая эпоха — ровно следующая и без `revoke_prev`: флаг
    /// описывает лишь последнюю ротацию, и при скачке через эпоху (дельта
    /// потерялась, клиент был офлайн) промежуточная могла быть киком — ключ,
    /// который знает исключённый, в grace не остаётся.
    fn set_key(&mut self, epoch: u32, key: proto::SymKey, revoke_prev: bool, now: Instant) {
        if key == self.key {
            // Ключ тот же (повтор состояния, дельта без ротации).
            if revoke_prev || epoch != self.epoch {
                self.retire_prev();
            }
            self.epoch = epoch;
        } else {
            let keep = !revoke_prev && self.epoch.checked_add(1) == Some(epoch);
            let mut old_prev = self.prev.take();
            // Возврат к прошлому ключу или к отслуженному — его счётчик и окна.
            let st = match old_prev.take_if(|p| p.key == key) {
                Some(p) => p.st,
                None => self.key_log.take(&key),
            };
            if let Some(p) = old_prev {
                self.key_log.put(p.key, p.st);
            }
            let old = PrevKey {
                epoch: self.epoch,
                key: std::mem::replace(&mut self.key, key),
                until: now + proto::PREV_KEY_GRACE,
                st: std::mem::replace(&mut self.cur, st),
            };
            self.epoch = epoch;
            if keep {
                self.prev = Some(old);
            } else {
                self.key_log.put(old.key, old.st);
            }
        }
        if self.epoch >= self.hint_epoch {
            self.hint_gap = GET_GROUP_EVERY;
        }
    }

    fn retire_prev(&mut self) {
        if let Some(p) = self.prev.take() {
            self.key_log.put(p.key, p.st);
        }
    }

    /// Фрейм с эпохой, которой у нас нет: сигналить ли GET_GROUP.
    /// Заголовок открыт, расшифровать нечем — значит, только правдоподобно
    /// подлинные: через релей или с адреса заявленного отправителя, известного
    /// от сервера (правило 5 — до расшифровки). Иначе любой, кто знает наш
    /// адрес и gid, заставлял бы нас тянуть GROUP_STATE целиком (а сервер —
    /// слать его). Поверх — пауза с удвоением и предел в минуту.
    fn epoch_hint(
        &mut self,
        h: &proto::GroupHeader,
        src: SocketAddr,
        is_relay: bool,
        now: Instant,
    ) -> bool {
        if h.epoch <= self.epoch {
            return false;
        }
        let from_peer =
            h.src != self.my_ip && self.members.get(&h.src).is_some_and(|p| p.knows(src));
        (is_relay || from_peer) && self.hint_due(h.epoch, now)
    }

    /// Пора ли сигналить «эпоха `epoch` новее нашей» (GET_GROUP).
    fn hint_due(&mut self, epoch: u32, now: Instant) -> bool {
        if self
            .sync_hint
            .is_some_and(|t| now.duration_since(t) < self.hint_gap)
        {
            return false;
        }
        while self
            .hint_log
            .front()
            .is_some_and(|t| now.duration_since(*t) >= HINT_WINDOW)
        {
            self.hint_log.pop_front();
        }
        if self.hint_log.len() >= HINT_MAX_PER_WINDOW {
            return false;
        }
        self.hint_log.push_back(now);
        if self.sync_hint.is_some() && self.hint_epoch > self.epoch {
            self.hint_gap = (self.hint_gap * 2).min(HINT_GAP_MAX);
        }
        self.sync_hint = Some(now);
        self.hint_epoch = epoch;
        true
    }

    /// Заголовок и счётчик следующего фрейма к `dst` (текущий ключ).
    fn next_frame(&mut self, gid: u32, dst: u32) -> (proto::SymKey, proto::GroupHeader, u64) {
        let h = proto::GroupHeader {
            gid,
            src: self.my_ip,
            dst,
            epoch: self.epoch,
        };
        let c = self.cur.tx;
        // Как SendCounter: обёртка повторила бы nonce.
        self.cur.tx = c.checked_add(1).expect("nonce counter exhausted");
        (self.key, h, c)
    }

    /// Участник из MemberInfo. Прямой канал сохраняется, пока его адрес —
    /// среди адресов пира от сервера и пир онлайн. Окна повторов не
    /// трогаются: они принадлежат ключу (сброс открыл бы дорогу повторам, а
    /// память и так ограничена составом группы на ключ).
    fn upsert_member(
        &mut self,
        gid: u32,
        m: &payloads::MemberInfo,
        now: Instant,
        events: &mut Vec<Event>,
    ) {
        let old_ip = self
            .members
            .iter()
            .find(|(_, p)| p.pubkey == m.pubkey)
            .map(|(ip, _)| *ip);
        let prev = old_ip.and_then(|ip| self.members.remove(&ip));
        let prev = prev.as_ref();
        let mut peer = PeerSess {
            pubkey: m.pubkey,
            name: m.name.clone(),
            status: m.status.clone(),
            online: m.online,
            ip: m.ip,
            endpoint: m.endpoint,
            candidates: m.candidates.clone(),
            direct_addr: None,
            last_rx: prev.map(|p| p.last_rx).unwrap_or(now),
            last_direct: None,
            rtt_ms: None,
        };
        if m.online {
            peer.rtt_ms = prev.and_then(|p| p.rtt_ms);
            match prev.and_then(|p| p.direct_addr) {
                Some(a) if peer.knows(a) => {
                    peer.direct_addr = Some(a);
                    peer.last_direct = prev.and_then(|p| p.last_direct);
                }
                // Пир онлайн, но сменил адрес: канал на старом недействителен.
                Some(_) => events.push(Event::DirectLost {
                    gid,
                    ip: m.ip,
                    name: m.name.clone(),
                }),
                None => {}
            }
        }
        if prev.map(|p| p.online) != Some(m.online) {
            if m.online {
                events.push(Event::PeerOnline {
                    gid,
                    ip: m.ip,
                    name: m.name.clone(),
                });
            } else if prev.is_some() {
                events.push(Event::PeerOffline {
                    gid,
                    ip: m.ip,
                    name: m.name.clone(),
                });
            }
        }
        self.members.insert(m.ip, peer);
    }

    fn remove_member(&mut self, pk: &[u8; 32]) {
        let ips: Vec<u32> = self
            .members
            .iter()
            .filter(|(_, p)| p.pubkey == *pk)
            .map(|(ip, _)| *ip)
            .collect();
        for ip in ips {
            self.members.remove(&ip);
        }
    }
}

pub type Groups = Arc<Mutex<HashMap<u32, GroupSess>>>;

/// Глобальные счётчики туннеля (атомарные, читаются UI в любой момент).
pub struct Stats {
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_pkts: AtomicU64,
    pub tx_pkts: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self {
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_pkts: AtomicU64::new(0),
            tx_pkts: AtomicU64::new(0),
        }
    }
}

/// Транспорт до сервера (для UI). P2p с пирами — всегда UDP.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Transport {
    #[default]
    Udp,
    Tcp,
}

/// Метаданные для статус-бара UI.
pub struct Meta {
    pub connected: bool,
    /// Через что сейчас идёт связь с сервером (UDP или TCP-фолбэк).
    pub transport: Transport,
    pub server: SocketAddr,
    pub server_label: String,
    pub group_list: Vec<payloads::GroupSummary>,
    /// Байт/с по последним секундам (для спарклайна).
    pub rx_hist: VecDeque<u64>,
    pub tx_hist: VecDeque<u64>,
    pub started: Instant,
}

impl Meta {
    fn push_hist(&mut self, rx: u64, tx: u64) {
        self.rx_hist.push_back(rx);
        self.tx_hist.push_back(tx);
        while self.rx_hist.len() > HISTORY_LEN {
            self.rx_hist.pop_front();
        }
        while self.tx_hist.len() > HISTORY_LEN {
            self.tx_hist.pop_front();
        }
    }
}

/// События движок → UI. JSON (serde, внешний тег) — форма событий IPC демона.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Event {
    Connected(SocketAddr),
    Disconnected(String),
    GroupJoined {
        gid: u32,
        name: String,
        my_ip: u32,
    },
    GroupLeft {
        gid: u32,
        name: String,
    },
    GroupDeleted {
        gid: u32,
        name: String,
    },
    /// Нас исключили из группы (KICKED); `banned` — с баном.
    Kicked {
        gid: u32,
        name: String,
        banned: bool,
    },
    PeerOnline {
        gid: u32,
        ip: u32,
        name: String,
    },
    PeerOffline {
        gid: u32,
        ip: u32,
        name: String,
    },
    /// Установлен прямой p2p-канал с пиром.
    Direct {
        gid: u32,
        ip: u32,
        name: String,
    },
    /// Прямой канал с онлайн-пиром потерян (таймаут или смена адреса) —
    /// трафик идёт через релей, PUNCH продолжается.
    DirectLost {
        gid: u32,
        ip: u32,
        name: String,
    },
    /// Приглашение в группу (в т.ч. повторная доставка неотвеченного после
    /// HELLO3 — UI должен убирать дубликаты по gid). `expires_in` — секунд
    /// до истечения на момент отправки сервером.
    Invite {
        gid: u32,
        group_name: String,
        from_pubkey: [u8; 32],
        from_name: String,
        expires_in: u32,
    },
    /// Приглашённый отклонил наше приглашение (мы — владелец группы).
    InviteDeclined {
        gid: u32,
        group_name: String,
        by_pubkey: [u8; 32],
        by_name: String,
    },
    /// Приглашение больше недействительно: группу удалили до ответа.
    InviteRevoked {
        gid: u32,
    },
    /// Сервер прислал окно списка неотвеченных приглашений (после HELLO3,
    /// отказа, входа, отзыва BAN/KICK): приглашения с gid ≥ `from`, не больше
    /// 16. Других gid в покрытом окне уже нет — UI снимает их окна.
    /// `complete == false` — хвост не влез: окно достоверно только до
    /// последнего gid в нём, следующее движок дочитывает сам
    /// (LIST_INVITES). Каждое из `gids` перед этим пришло как
    /// [`Event::Invite`].
    InvitesSynced {
        gids: Vec<u32>,
        from: u32,
        complete: bool,
    },
    /// Ответ FRIEND_GROUPS_RESP: группы пира `pubkey` (из самого ответа).
    FriendGroups {
        pubkey: [u8; 32],
        items: Vec<payloads::FriendGroup>,
    },
    /// ADMIN_INFO (владельцу): баны (pk, имя) и неотвеченные приглашения
    /// (pk, имя, секунд до истечения).
    AdminInfo {
        gid: u32,
        bans: Vec<([u8; 32], String)>,
        invites: Vec<([u8; 32], String, u32)>,
    },
    /// Ключ сервера сменён по цепочке ротации от закреплённого: новый ключ
    /// закреплён и сохранён в client.json.
    ServerKeyRotated {
        addr: SocketAddr,
        new_code: String,
    },
    /// Движок переключён на другой сервер (`Cmd::SwitchServer`); группы
    /// прежнего сервера забыты (каждая — `GroupLeft`).
    ServerSwitched {
        addr: SocketAddr,
        label: String,
    },
    Error(String),
    Notice(String),
}

/// Команды UI → движок. JSON (serde, внешний тег) — форма `Req.cmd` IPC демона.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Cmd {
    RefreshList,
    Create {
        name: String,
        private: bool,
    },
    Join(u32),
    Leave(u32),
    Delete(u32),
    Rename(u32, String),
    Invite(u32, [u8; 32]),
    /// Отклонить приглашение в группу.
    DeclineInvite(u32),
    Kick(u32, [u8; 32]),
    Ban(u32, [u8; 32]),
    /// Снять бан (владелец).
    Unban(u32, [u8; 32]),
    /// Запросить баны и приглашения группы (владелец) → `Event::AdminInfo`.
    GroupAdmin(u32),
    /// Передать группу участнику (владелец).
    Transfer(u32, [u8; 32]),
    SetName(String),
    SetStatus(String),
    /// Невидимка: сохраняется в конфиге и шлётся серверу (PRESENCE).
    SetInvisible(bool),
    /// Переключиться на другой сервер без перезапуска (адаптер остаётся).
    SwitchServer {
        addr: SocketAddr,
        pubkey: [u8; 32],
        label: String,
    },
    /// Переключить автовход в группу (локальная настройка).
    ToggleAutojoin(u32),
    FriendGroups([u8; 32]),
    /// Друг в конфиг (PLAN.md 7.1): тот же pubkey — обновить alias.
    AddFriend {
        pubkey: [u8; 32],
        alias: String,
    },
    /// Удалить друга из конфига.
    DelFriend([u8; 32]),
    /// Alias друга (переименование; друга нет — `Event::Error`).
    SetAlias {
        pubkey: [u8; 32],
        alias: String,
    },
    /// Сервер в конфиг (`addr` — `ip:port`); тот же адрес — обновить ключ и
    /// метку.
    AddServer {
        addr: String,
        pubkey: [u8; 32],
        label: String,
    },
    /// Удалить сервер по индексу; текущий сервер движка не удаляется.
    DelServer {
        idx: usize,
    },
    /// Сервер по умолчанию (первый в списке — его берёт следующий запуск).
    SetPrimaryServer {
        idx: usize,
    },
    /// Подсказка «сеть могла смениться» (выход из сна): новое рукопожатие
    /// сразу, без ожидания таймеров и бэкоффа; группы и адаптер — те же.
    Reconnect,
    Quit,
}

/// Приёмник исходящих IP-пакетов (см. [`Engine::ip_sink`]).
pub type IpSink = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// Всё, что нужно UI от движка.
pub struct Engine {
    pub groups: Groups,
    pub meta: Arc<Mutex<Meta>>,
    pub stats: Arc<Stats>,
    pub my_pub: [u8; 32],
    pub my_code: String,
    pub events: mpsc::Receiver<Event>,
    pub cmds: mpsc::Sender<Cmd>,
    pub cfg: Arc<Mutex<Config>>,
    /// Колбэк сохранения конфига (UI может править client.json напрямую).
    save: Arc<dyn Fn(&Config) + Send + Sync>,
    env: Arc<Env>,
}

impl Engine {
    /// Сохраняет конфиг через колбэк движка.
    pub fn save_config(&self, cfg: &Config) -> Result<()> {
        (self.save)(cfg);
        Ok(())
    }

    /// Локальный адрес UDP-сокета движка.
    #[allow(dead_code)]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.env.sock.local_addr().ok()
    }

    /// Отправить IP-пакет в туннель так же, как это делает tun-поток
    /// (для тестов и отладки без адаптера).
    #[allow(dead_code)]
    pub fn send_ip_packet(&self, packet: &[u8]) {
        route_packet(&self.env, packet);
    }

    /// Приёмник исходящих IP-пакетов для своего tun-потока (TUN, который
    /// движок не читает сам: utun/Linux TUN в демоне).
    pub fn ip_sink(&self) -> IpSink {
        let env = self.env.clone();
        Arc::new(move |p: &[u8]| route_packet(&env, p))
    }

    /// Движок остановлен (Drop или `Cmd::Quit`) — tun-потокам пора выйти.
    pub fn quitting(&self) -> bool {
        self.env.quitting()
    }

    /// Эпоха, ключ и свой IP группы (тесты: «старый ключ» исключённого).
    #[cfg(test)]
    pub fn group_key(&self, gid: u32) -> Option<(u32, proto::SymKey, u32)> {
        let g = self.env.groups.lock().unwrap();
        g.get(&gid).map(|gs| (gs.epoch, gs.key, gs.my_ip))
    }

    /// Фрейм группы текущим ключом и следующим счётчиком движка, но с
    /// произвольными src/dst (тесты подделки src_ip).
    #[cfg(test)]
    pub fn craft_frame(
        &self,
        gid: u32,
        typ: u8,
        src: u32,
        dst: u32,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let mut g = self.env.groups.lock().unwrap();
        let gs = g.get_mut(&gid)?;
        let (k, mut h, c) = gs.next_frame(gid, dst);
        h.src = src;
        Some(proto::seal_group(&k, typ, &h, c, payload))
    }

    /// Датаграмма с сокета движка (тесты: подделки «от имени» пира).
    #[cfg(test)]
    pub fn send_raw(&self, frame: &[u8], to: SocketAddr) {
        self.env.send(frame, to);
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Останавливаем потоки rx/engine (tun-поток завершится вместе с
        // сессией адаптера).
        self.env.quit.store(true, Ordering::Relaxed);
        let _ = self.cmds.send(Cmd::Quit);
    }
}

// ---------- устройство туннеля ----------

/// То, что движку нужно от сетевого адаптера. Реальная реализация — Wintun;
/// в тестах — заглушка, которая просто запоминает пакеты.
pub trait TunDev: Send + Sync {
    /// Вбросить IP-пакет «из сети» в систему.
    fn inject(&self, packet: &[u8]) -> Result<()>;
    /// Назначить адаптеру свой адрес оверлея, маска /16 (протокол v4: один
    /// адрес на все группы; другой адрес — после смены сервера — заменяет
    /// прежний). Тот же адрес — ничего не делает.
    fn ensure_address(&self, ip: u32) -> Result<()>;
    /// Назначить адаптеру IPv6 оверлея (`ipv6::v6_of`, префикс /64) для
    /// своего IPv4 `v4`, заменив прежний. По умолчанию — ничего.
    fn ensure_address6(&self, _v4: u32) -> Result<()> {
        Ok(())
    }
    /// Маршрут на встроенный DNS (100.66.0.53) через адаптер (идемпотентно).
    /// По умолчанию — ничего.
    fn ensure_dns_route(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
struct WintunDev {
    adapter: Arc<wintun::Adapter>,
    session: Arc<wintun::Session>,
    /// Назначенный адаптеру адрес оверлея.
    configured: Mutex<Option<u32>>,
    /// IPv4, для которого назначен IPv6 оверлея.
    configured6: Mutex<Option<u32>>,
    /// Маршрут на 100.66.0.53 уже ставили (успешно или нет — не повторяем).
    dns_route: AtomicBool,
}

#[cfg(windows)]
impl WintunDev {
    fn if_index(&self) -> Result<u32> {
        self.adapter.get_adapter_index().context("adapter index")
    }
}

/// Запустить команду ОС, ошибка — с её stderr.
fn run_cmd(mut c: std::process::Command, what: &str) -> Result<()> {
    let out = c.output().with_context(|| what.to_string())?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow::anyhow!("{what}: {}", err.trim()));
    }
    Ok(())
}

#[cfg(windows)]
impl TunDev for WintunDev {
    fn inject(&self, packet: &[u8]) -> Result<()> {
        let len: u16 = packet.len().try_into().context("packet too large")?;
        let mut p = self
            .session
            .allocate_send_packet(len)
            .context("allocate_send_packet")?;
        p.bytes_mut().copy_from_slice(packet);
        self.session.send_packet(p);
        Ok(())
    }

    fn ensure_address(&self, ip: u32) -> Result<()> {
        let mut cfg = self.configured.lock().unwrap();
        crate::tun::ensure_address(&self.adapter, &mut cfg, ip)
    }

    fn ensure_address6(&self, v4: u32) -> Result<()> {
        let mut cur = self.configured6.lock().unwrap();
        if *cur == Some(v4) {
            return Ok(());
        }
        let idx = self.if_index()?;
        let c = crate::ipv6::cmd_add_windows(idx, v4)
            .ok_or_else(|| anyhow::anyhow!("адрес вне 100.66.0.0/16"))?;
        // Прежний адрес (другой сервер) — снять; не вышло — не страшно.
        if let Some(old) = *cur
            && let Some(d) = crate::ipv6::cmd_del_windows(idx, old)
        {
            let _ = run_cmd(d.to_command(), "netsh delete ipv6 address");
        }
        run_cmd(c.to_command(), "netsh add ipv6 address")?;
        *cur = Some(v4);
        Ok(())
    }

    fn ensure_dns_route(&self) -> Result<()> {
        if self.dns_route.swap(true, Ordering::Relaxed) {
            return Ok(());
        }
        let idx = self.if_index()?;
        let mut c = std::process::Command::new("netsh");
        c.args([
            "interface",
            "ipv4",
            "add",
            "route",
            &format!("{}/32", crate::dns::DNS_ADDR),
            &idx.to_string(),
            "store=active",
        ]);
        run_cmd(c, "netsh add dns route")
    }
}

/// Split-DNS ОС для `.vl` → 100.66.0.53 (best effort).
fn configure_os_dns(ifname: &str) -> Result<()> {
    if cfg!(windows) {
        let mut c = std::process::Command::new("powershell");
        c.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &crate::dns::windows_nrpt_add(),
        ]);
        run_cmd(c, "NRPT")
    } else if cfg!(target_os = "macos") {
        std::fs::create_dir_all("/etc/resolver").context("/etc/resolver")?;
        std::fs::write(
            crate::dns::MACOS_RESOLVER_PATH,
            crate::dns::macos_resolver_content(),
        )
        .context(crate::dns::MACOS_RESOLVER_PATH)
    } else {
        for argv in crate::dns::linux_resolvectl_setup(ifname) {
            let mut c = std::process::Command::new(&argv[0]);
            c.args(&argv[1..]);
            run_cmd(c, "resolvectl")?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl TunDev for crate::tun_linux::LinuxTun {
    fn inject(&self, packet: &[u8]) -> Result<()> {
        self.write(packet)
    }

    fn ensure_address(&self, ip: u32) -> Result<()> {
        // `ip addr replace <ip>/16` сам добавляет маршрут на 100.66.0.0/16.
        crate::tun_linux::LinuxTun::ensure_address(self, ip)
    }
}

#[cfg(target_os = "macos")]
impl TunDev for crate::tun_macos::Utun {
    fn inject(&self, packet: &[u8]) -> Result<()> {
        self.write(packet).context("запись в utun")?;
        Ok(())
    }

    fn ensure_address(&self, ip: u32) -> Result<()> {
        // ifconfig inet + route add на 100.66.0.0/16.
        crate::tun_macos::Utun::ensure_address(self, ip)
    }

    fn ensure_dns_route(&self) -> Result<()> {
        // Явный host-маршрут на 100.66.0.53: запросы `.vl` из /etc/resolver
        // идут в utun, даже пока маршрута на 100.66.0.0/16 ещё нет.
        crate::tun_macos::Utun::ensure_dns_route(self)
    }
}

// ---------- общий контекст потоков ----------

struct Env {
    groups: Groups,
    meta: Arc<Mutex<Meta>>,
    stats: Arc<Stats>,
    ev: mpsc::Sender<Event>,
    cfg: Arc<Mutex<Config>>,
    save: Arc<dyn Fn(&Config) + Send + Sync>,
    identity: proto::Identity,
    /// Текущий сервер (меняется `Cmd::SwitchServer`).
    server: Mutex<SocketAddr>,
    /// Единственный UDP-сокет: и сервер, и пиры.
    sock: Arc<UdpSocket>,
    /// TCP-канал до сервера (фолбэк): есть — всё серверу идёт по нему.
    tcp: Mutex<Option<Arc<TcpLink>>>,
    tun: Arc<dyn TunDev>,
    quit: AtomicBool,
    key_log: KeyLog,
}

impl Env {
    fn emit(&self, e: Event) {
        let _ = self.ev.send(e);
    }

    fn quitting(&self) -> bool {
        self.quit.load(Ordering::Relaxed)
    }

    fn server(&self) -> SocketAddr {
        *self.server.lock().unwrap()
    }

    fn tcp_link(&self) -> Option<Arc<TcpLink>> {
        self.tcp.lock().unwrap().clone()
    }

    /// Фрейм серверу — по TCP, если он поднят; пирам — всегда по UDP.
    fn send(&self, frame: &[u8], to: SocketAddr) {
        let ok = match self.tcp_link() {
            Some(t) if to == self.server() => t.send(frame).is_ok(),
            _ => self.sock.send_to(frame, to).is_ok(),
        };
        if ok {
            self.stats.tx_pkts.fetch_add(1, Ordering::Relaxed);
            self.stats
                .tx_bytes
                .fetch_add(frame.len() as u64, Ordering::Relaxed);
        }
    }

    fn autojoin_add(&self, gid: u32) {
        let mut cfg = self.cfg.lock().unwrap();
        if !cfg.autojoin.contains(&gid) {
            cfg.autojoin.push(gid);
            (self.save)(&cfg);
        }
    }

    fn autojoin_remove(&self, gid: u32) {
        let mut cfg = self.cfg.lock().unwrap();
        let before = cfg.autojoin.len();
        cfg.autojoin.retain(|g| *g != gid);
        if cfg.autojoin.len() != before {
            (self.save)(&cfg);
        }
    }

    fn update_cfg(&self, f: impl FnOnce(&mut Config)) {
        let mut cfg = self.cfg.lock().unwrap();
        f(&mut cfg);
        (self.save)(&cfg);
    }
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn bind_addr(server: SocketAddr) -> SocketAddr {
    if server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    }
}

/// Флаги HELLO3 из настроек.
fn hello_flags(cfg: &Config) -> u8 {
    if cfg.invisible {
        handshake::HELLO_FLAG_INVISIBLE
    } else {
        0
    }
}

/// Текст ошибки на UNSUPPORTED.
fn unsupported_msg(body: &[u8]) -> String {
    match handshake::dec_unsupported(body) {
        Ok((ver, text)) if !text.is_empty() => format!(
            "сервер другой версии протокола: v{ver}, клиент v{} ({text})",
            proto::PROTOCOL_VERSION
        ),
        Ok((ver, _)) => format!(
            "сервер другой версии протокола: v{ver}, клиент v{}",
            proto::PROTOCOL_VERSION
        ),
        Err(_) => "сервер другой версии протокола".into(),
    }
}

/// Адрес интерфейса, через который виден сервер: `connect` UDP-сокета
/// только выбирает маршрут, пакетов не шлёт.
fn local_ip_towards(server: SocketAddr) -> Option<IpAddr> {
    let s = UdpSocket::bind(bind_addr(server)).ok()?;
    s.connect(server).ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

/// LAN-кандидаты для CANDIDATES: IP интерфейса к серверу и порт сокета
/// движка (раздел 7). Пусто — `lan_discovery: false` или адрес не узнать.
fn lan_candidates(env: &Env) -> Vec<SocketAddr> {
    if !env.cfg.lock().unwrap().lan_discovery {
        return Vec::new();
    }
    let Ok(port) = env.sock.local_addr().map(|a| a.port()) else {
        return Vec::new();
    };
    local_ip_towards(env.server())
        .map(|ip| vec![SocketAddr::new(ip, port)])
        .unwrap_or_default()
}

// ---------- рукопожатие и сессия (общие для движка и CLI) ----------

/// Одна попытка рукопожатия: эфемерный ключ живёт до WELCOME (повторы
/// HELLO3 — с ним же), cookie — из CHALLENGE.
struct Handshake {
    eph: proto::EphemeralKey,
    started: Instant,
    last_cookie: Option<Instant>,
    saw_challenge: bool,
    /// v2-сервер отвечает на HELLO3 RESET'ом — признак старой версии.
    saw_reset: bool,
    /// Ошибка, которую подсказал неаутентифицированный ответ (UNSUPPORTED,
    /// WELCOME под наш eph, но не от закреплённого ключа): подделать её
    /// может любой, кто видит наш HELLO3, поэтому попытка из-за неё не
    /// обрывается — она лишь объясняет таймаут без подлинного WELCOME.
    advisory: Option<String>,
}

impl Handshake {
    fn new() -> Self {
        Self {
            eph: proto::EphemeralKey::generate(),
            started: Instant::now(),
            last_cookie: None,
            saw_challenge: false,
            saw_reset: false,
            advisory: None,
        }
    }

    fn hello(
        &self,
        id: &proto::Identity,
        name: &str,
        flags: u8,
        cookie: Option<&[u8; 16]>,
    ) -> Vec<u8> {
        let body = proto::Hello3::encode(id, &self.eph.public(), name, flags, cookie);
        proto::plain_frame(ctrl::HELLO3, &body)
    }

    /// CHALLENGE → HELLO3 с cookie (тот же eph). `None` — фрейм не тот или
    /// лимит (один HELLO3 с cookie на CHALLENGE, не чаще `COOKIE_GAP`).
    fn on_challenge(
        &mut self,
        id: &proto::Identity,
        name: &str,
        flags: u8,
        body: &[u8],
        now: Instant,
    ) -> Option<Vec<u8>> {
        let cookie = handshake::dec_challenge(body).ok()?;
        self.saw_challenge = true;
        if self
            .last_cookie
            .is_some_and(|t| now.duration_since(t) < COOKIE_GAP)
        {
            return None;
        }
        self.last_cookie = Some(now);
        Some(self.hello(id, name, flags, Some(&cookie)))
    }

    /// Чем объяснить отсутствие WELCOME.
    fn timeout_msg(&self) -> String {
        if let Some(a) = &self.advisory {
            a.clone()
        } else if self.saw_reset && !self.saw_challenge {
            "сервер старой версии протокола (v2): нужен сервер v3".into()
        } else {
            "нет WELCOME от сервера (адрес/код сервера верны?)".into()
        }
    }
}

/// Принятый WELCOME: ключи сессии и итог сверки ключа сервера.
struct Accepted {
    server_eph: [u8; 32],
    keys: proto::DirKeys,
    pin: proto::PinResolution,
}

/// WELCOME под эфемерный ключ `eph`. `Ok(None)` — не для этой попытки
/// (другой eph, подпись, мусор, ключ малого порядка) — игнорируется молча;
/// `Err` — подпись верна, но ключ сервера не закреплённый и цепочки от
/// закреплённого нет.
fn accept_welcome(
    id: &proto::Identity,
    eph: &proto::EphemeralKey,
    pinned: &[u8; 32],
    body: &[u8],
) -> Result<Option<Accepted>> {
    let Ok(w) = proto::Welcome::decode(body, &id.ed_pub(), &eph.public()) else {
        return Ok(None);
    };
    let pin = proto::resolve_pin(pinned, &w)
        .context("WELCOME: подпись не от закреплённого сервера (неверный код сервера?)")?;
    let Ok(keys) = proto::session_keys(proto::Role::Client, id, eph, &w.server_x, &w.server_eph)
    else {
        return Ok(None);
    };
    Ok(Some(Accepted {
        server_eph: w.server_eph,
        keys,
        pin,
    }))
}

/// Ключи одной серверной сессии: свой счётчик, окно повторов и сборка FRAG
/// (msg_id и счётчики сервера — на сессию).
struct Keyset {
    server_eph: [u8; 32],
    keys: proto::DirKeys,
    tx: proto::SendCounter,
    rx: proto::ReplayWindow,
    reasm: proto::Reassembler,
    /// Последний подлинный фрейм сервера под этими ключами.
    last_rx: Option<Instant>,
}

/// Шифрованная ctrl-сессия с сервером. Обычно набор ключей один; ещё один
/// появляется, если сервер создал под тот же eph новую сессию — HELLO3 с
/// cookie дошёл с другого адреса (NAT сменил порт посреди рукопожатия) — и
/// прислал WELCOME с другим `server_eph` (раздел 2; повтор с того же адреса
/// сервер сессию не пересоздаёт, и его WELCOME — тот же). Отправка —
/// ключами, под которыми сервер последним что-то прислал (живая сессия —
/// та, что отвечает; поздний WELCOME прежней её не перебивает), а пока ни
/// одни не ответили — новейшими.
struct CtrlSession {
    eph: proto::EphemeralKey,
    keysets: Vec<Keyset>,
}

impl CtrlSession {
    fn new(eph: proto::EphemeralKey, acc: Accepted) -> Self {
        let mut s = Self {
            eph,
            keysets: Vec::new(),
        };
        s.add(acc);
        s
    }

    /// Ещё один WELCOME под тот же eph. `false` — уже известный (повтор).
    fn add(&mut self, acc: Accepted) -> bool {
        if self.keysets.iter().any(|k| k.server_eph == acc.server_eph) {
            return false;
        }
        self.keysets.insert(
            0,
            Keyset {
                server_eph: acc.server_eph,
                keys: acc.keys,
                tx: proto::SendCounter::new(),
                rx: proto::ReplayWindow::new(),
                reasm: proto::Reassembler::new(),
                last_rx: None,
            },
        );
        self.keysets.truncate(MAX_KEYSETS);
        true
    }

    /// Набор для отправки: последний ответивший, иначе новейший (первый).
    fn active(&self) -> usize {
        let mut best = 0;
        for (i, k) in self.keysets.iter().enumerate() {
            if k.last_rx > self.keysets[best].last_rx {
                best = i;
            }
        }
        best
    }

    fn seal(&mut self, typ: u8, payload: &[u8]) -> Vec<u8> {
        let i = self.active();
        let k = &mut self.keysets[i];
        proto::seal_ctrl(&k.keys.tx, k.tx.next(), typ, payload)
    }

    /// Расшифровка, окно повторов и сборка FRAG. `None` — фрейм не подлинный
    /// или повтор; `Some(None)` — подлинный кусок FRAG, сообщение ещё не
    /// собрано; `Some(Some((typ, payload)))` — сообщение.
    fn open(&mut self, typ: u8, body: &[u8], now: Instant) -> Option<Option<(u8, Vec<u8>)>> {
        // Дешёвая предпроверка окна до расшифровки; сдвиг — только после.
        let ctr = proto::ctrl_counter(body)?;
        let (i, pt) = self.keysets.iter().enumerate().find_map(|(i, k)| {
            if !k.rx.check(ctr) {
                return None;
            }
            proto::open_ctrl(&k.keys.rx, typ, body)
                .ok()
                .map(|(_, pt)| (i, pt))
        })?;
        if !self.keysets[i].rx.commit(ctr) {
            return None;
        }
        // Сервер живёт на этих ключах — ими и отвечать.
        let k = &mut self.keysets[i];
        k.last_rx = Some(now);
        if typ != ctrl::FRAG {
            return Some(Some((typ, pt)));
        }
        k.reasm.expire(now);
        match k.reasm.push(&pt, now) {
            Ok(msg) => Some(msg),
            Err(e) => {
                if debug() {
                    eprintln!("[engine] FRAG: {e}");
                }
                Some(None)
            }
        }
    }

    fn expire(&mut self, now: Instant) {
        for k in &mut self.keysets {
            k.reasm.expire(now);
        }
    }
}

// ---------- однократное управляющее соединение (CLI-команды) ----------

pub struct CtrlConn {
    pub sock: Arc<UdpSocket>,
    pub server: SocketAddr,
    /// TCP-канал до сервера (UDP не ответил или `transport: tcp`).
    tcp: Option<TcpLink>,
    /// Ключ сервера перезакреплён по цепочке ротации (новый ed25519):
    /// вызывающий сохраняет его в client.json.
    pub rotated: Option<[u8; 32]>,
    identity: proto::Identity,
    pinned: [u8; 32],
    sess: Mutex<CtrlSession>,
    /// Сообщения, обогнавшие WELCOME или прочитанные раньше своего ожидания.
    backlog: Mutex<VecDeque<(u8, Vec<u8>)>>,
    /// Последний подлинный фрейм сервера (против поддельного RESET).
    last_auth: Mutex<Instant>,
}

impl CtrlConn {
    /// Рукопожатие v3: HELLO3 → CHALLENGE → HELLO3 с cookie → WELCOME
    /// (подпись под наш ed/eph, сверка с закреплённым ключом).
    pub fn connect(
        cfg: &Config,
        server: SocketAddr,
        server_pub: &[u8; 32],
        identity: &proto::Identity,
    ) -> Result<Self> {
        let sock = Arc::new(UdpSocket::bind(bind_addr(server)).context("bind udp")?);
        sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
        let flags = hello_flags(cfg);
        let mut hs = Handshake::new();
        let started = Instant::now();
        let deadline = started + CONNECT_TIMEOUT;
        let mut next_hello = Instant::now();
        let mut early: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut buf = vec![0u8; 65_535];
        let mut tcp: Option<TcpLink> = None;
        if cfg.transport == TransportMode::Tcp {
            tcp = Some(
                TcpLink::connect(server, TCP_CONNECT_TIMEOUT)
                    .with_context(|| format!("TCP {server}"))?,
            );
        }
        // HELLO3 по UDP без единого ответа — для фолбэка на TCP.
        let mut udp_hellos = 0u32;
        let acc = loop {
            let now = Instant::now();
            if now > deadline {
                anyhow::bail!("{}", hs.timeout_msg());
            }
            // HELLO3 повторяется: UDP может его потерять.
            if now >= next_hello {
                if tcp.is_none()
                    && cfg.transport == TransportMode::Auto
                    && tcp_link::should_fallback(udp_hellos, now.duration_since(started))
                {
                    match TcpLink::connect(server, TCP_CONNECT_TIMEOUT) {
                        Ok(l) => tcp = Some(l),
                        Err(_) => udp_hellos = 0,
                    }
                }
                ctrl_send(
                    &sock,
                    tcp.as_ref(),
                    &hs.hello(identity, &cfg.name, flags, None),
                    server,
                )?;
                if tcp.is_none() {
                    udp_hellos += 1;
                }
                next_hello = Instant::now() + HELLO_RETRY;
            }
            let Some(frame) = ctrl_recv(&sock, tcp.as_ref(), server, &mut buf) else {
                continue;
            };
            if tcp.is_none() {
                udp_hellos = 0;
            }
            let Ok((typ, body)) = proto::split_frame(&frame) else {
                continue;
            };
            // UNSUPPORTED и WELCOME с чужим ключом не аутентифицированы (их
            // подделает любой, кто видит наш HELLO3): рукопожатие ждёт
            // подлинный WELCOME до таймаута, а они лишь объясняют его.
            match typ {
                ctrl::WELCOME => match accept_welcome(identity, &hs.eph, server_pub, body) {
                    Ok(Some(acc)) => break acc,
                    Ok(None) => {}
                    Err(e) => hs.advisory = Some(format!("{e:#}")),
                },
                ctrl::CHALLENGE => {
                    if let Some(f) = hs.on_challenge(identity, &cfg.name, flags, body, now) {
                        let _ = ctrl_send(&sock, tcp.as_ref(), &f, server);
                    }
                }
                ctrl::UNSUPPORTED => hs.advisory = Some(unsupported_msg(body)),
                ctrl::RESET => hs.saw_reset = true,
                t if proto::grp::is_group(t) || ctrl::is_plaintext(t) => {}
                _ => {
                    if early.len() < EARLY_MAX {
                        early.push((typ, body.to_vec()));
                    }
                }
            }
        };
        let (rotated, pinned) = match acc.pin {
            proto::PinResolution::Rotated { new_ed } => (Some(new_ed), new_ed),
            proto::PinResolution::Same => (None, *server_pub),
        };
        let mut sess = CtrlSession::new(hs.eph, acc);
        let now = Instant::now();
        let backlog: VecDeque<(u8, Vec<u8>)> = early
            .into_iter()
            .filter_map(|(t, b)| sess.open(t, &b, now).flatten())
            .collect();
        Ok(Self {
            sock,
            server,
            tcp,
            rotated,
            identity: identity.clone(),
            pinned,
            sess: Mutex::new(sess),
            backlog: Mutex::new(backlog),
            last_auth: Mutex::new(now),
        })
    }

    /// Окно неотвеченных приглашений, которое сервер шлёт после HELLO3:
    /// (приглашения, список полный). PONG раньше списка — окно потеряно
    /// (UDP) или переставлено: то же окно запрашивается без побочных
    /// эффектов (LIST_INVITES с 0), а не новым рукопожатием (оно ротировало
    /// бы ключи всех групп). `None` — списка нет и после повторов.
    pub fn invite_list(&self) -> Result<Option<payloads::InviteList>> {
        self.send_ctrl(ctrl::CTRL_PING, &[]);
        let (typ, p) = self.wait_any(
            &[ctrl::INVITE_LIST, ctrl::CTRL_PONG],
            Duration::from_secs(5),
        )?;
        if typ == ctrl::INVITE_LIST {
            return Ok(Some(payloads::dec_invite_list(&p)?));
        }
        self.invite_page(0)
    }

    /// Окно неотвеченных приглашений с gid ≥ `from` (LIST_INVITES, без
    /// побочных эффектов). Запоздавшие окна с другим началом (окно после
    /// HELLO3 или прошлый запрос) пропускаются; при потере — повтор.
    /// `None` — ответа нет (потеря пакетов).
    pub fn invite_page(&self, from: u32) -> Result<Option<payloads::InviteList>> {
        for _ in 0..3 {
            self.send_ctrl(ctrl::LIST_INVITES, &payloads::enc_u32(from));
            let deadline = Instant::now() + Duration::from_secs(2);
            while let Some(left) = deadline.checked_duration_since(Instant::now()) {
                match self.wait_for(ctrl::INVITE_LIST, left) {
                    Ok(p) => {
                        let l = payloads::dec_invite_list(&p)?;
                        if l.from == from {
                            return Ok(Some(l));
                        }
                    }
                    Err(e) if e.to_string().starts_with("сервер:") => return Err(e),
                    Err(_) => break,
                }
            }
        }
        Ok(None)
    }

    pub fn send_ctrl(&self, typ: u8, payload: &[u8]) {
        let frame = self.sess.lock().unwrap().seal(typ, payload);
        let _ = ctrl_send(&self.sock, self.tcp.as_ref(), &frame, self.server);
    }

    /// Связь с сервером идёт по TCP.
    #[allow(dead_code)] // для вывода CLI и тестов
    pub fn via_tcp(&self) -> bool {
        self.tcp.is_some()
    }

    /// Ждёт фрейм конкретного типа; ERROR превращает в Err; прочее игнорируется.
    pub fn wait_for(&self, expect: u8, timeout: Duration) -> Result<Vec<u8>> {
        self.wait_any(&[expect], timeout).map(|(_, p)| p)
    }

    /// Ждёт сообщение одного из типов `expect`: (тип, payload). ERROR → Err.
    /// Куски FRAG собираются, повторы отсекаются окном.
    pub fn wait_any(&self, expect: &[u8], timeout: Duration) -> Result<(u8, Vec<u8>)> {
        let pick = |typ: u8, p: Vec<u8>| -> Result<Option<(u8, Vec<u8>)>> {
            if typ == ctrl::ERROR {
                anyhow::bail!("сервер: {}", payloads::dec_error(&p).unwrap_or_default());
            }
            Ok(expect.contains(&typ).then_some((typ, p)))
        };
        loop {
            let next = self.backlog.lock().unwrap().pop_front();
            let Some((typ, p)) = next else { break };
            if let Some(r) = pick(typ, p)? {
                return Ok(r);
            }
        }
        let deadline = Instant::now() + timeout;
        self.sock
            .set_read_timeout(Some(Duration::from_millis(200)))
            .ok();
        let mut buf = vec![0u8; 65_535];
        // RESET открыт и подделывается кем угодно: он считается, только если
        // за `RESET_GRACE` до и после него от сервера не было ничего подлинного.
        let mut reset_at: Option<Instant> = None;
        loop {
            let now = Instant::now();
            if reset_at.is_some_and(|t| now.duration_since(t) >= RESET_GRACE) {
                anyhow::bail!("сервер сбросил сессию — повторите команду");
            }
            if now > deadline {
                anyhow::bail!("таймаут ожидания {expect:02x?} от сервера");
            }
            let Some(frame) = ctrl_recv(&self.sock, self.tcp.as_ref(), self.server, &mut buf)
            else {
                continue;
            };
            let (typ, body) = match proto::split_frame(&frame) {
                Ok(x) => x,
                Err(_) => continue,
            };
            match typ {
                // Ещё один WELCOME под наш eph с другим server_eph: сервер
                // создал новую сессию (HELLO3 дошёл с другого адреса).
                ctrl::WELCOME => {
                    let mut s = self.sess.lock().unwrap();
                    if let Ok(Some(acc)) =
                        accept_welcome(&self.identity, &s.eph, &self.pinned, body)
                    {
                        s.add(acc);
                    }
                    continue;
                }
                ctrl::RESET => {
                    let fresh = now.duration_since(*self.last_auth.lock().unwrap()) < RESET_GRACE;
                    if !fresh && reset_at.is_none() {
                        reset_at = Some(now);
                    }
                    continue;
                }
                t if proto::grp::is_group(t) || ctrl::is_plaintext(t) => continue,
                _ => {}
            }
            let msg = self.sess.lock().unwrap().open(typ, body, now);
            if msg.is_some() {
                *self.last_auth.lock().unwrap() = now;
                reset_at = None;
            }
            if let Some(Some((t, p))) = msg
                && let Some(r) = pick(t, p)?
            {
                return Ok(r);
            }
        }
    }
}

/// Фрейм серверу CLI-соединения: по TCP, если он поднят, иначе по UDP.
fn ctrl_send(
    sock: &UdpSocket,
    tcp: Option<&TcpLink>,
    frame: &[u8],
    server: SocketAddr,
) -> std::io::Result<()> {
    match tcp {
        Some(t) => t.send(frame),
        None => sock.send_to(frame, server).map(|_| ()),
    }
}

/// Следующий фрейм от сервера (ждёт ~200 мс): `None` — ничего или чужой.
fn ctrl_recv(
    sock: &UdpSocket,
    tcp: Option<&TcpLink>,
    server: SocketAddr,
    buf: &mut [u8],
) -> Option<Vec<u8>> {
    match tcp {
        Some(t) => {
            let r = t.recv_timeout(Duration::from_millis(200));
            if matches!(r, Err(mpsc::RecvTimeoutError::Disconnected)) {
                // Канал закрыт: не крутиться вхолостую до таймаута вызывающего.
                thread::sleep(Duration::from_millis(200));
            }
            r.ok()
        }
        None => match sock.recv_from(buf) {
            Ok((n, src)) if src == server => Some(buf[..n].to_vec()),
            _ => None,
        },
    }
}

// ---------- запуск ----------

/// Создаёт TUN-устройство платформы (Windows — Wintun, Linux — /dev/net/tun,
/// macOS — utun), запускает потоки и возвращает дескриптор движка.
/// `adapter_name`: имя wintun-адаптера / Linux-интерфейса; на macOS
/// игнорируется (номер utunN выбирает ядро). `dll` — только Windows.
/// Первое подключение выполняется синхронно (ошибка видна вызывающему).
pub fn start(
    cfg: Arc<Mutex<Config>>,
    server: SocketAddr,
    server_pub: [u8; 32],
    identity: proto::Identity,
    adapter_name: &str,
    dll: Option<String>,
    save: Arc<dyn Fn(&Config) + Send + Sync>,
) -> Result<Engine> {
    let mtu = cfg.lock().unwrap().mtu();
    #[cfg(windows)]
    {
        let wintun = crate::tun::load_wintun_dll(dll.as_deref())?;
        let adapter = crate::tun::create_adapter(&wintun, adapter_name)?;
        crate::tun::set_mtu(&adapter, mtu)?;
        crate::tun::allow_firewall(adapter_name);
        let session = Arc::new(adapter.start_session(RING_CAPACITY)?);
        let dev = Arc::new(WintunDev {
            adapter,
            session: session.clone(),
            configured: Mutex::new(None),
            configured6: Mutex::new(None),
            dns_route: AtomicBool::new(false),
        });
        let dns_on = cfg.lock().unwrap().dns;
        let eng = start_with_tun(cfg, server, server_pub, identity, dev, save)?;
        if dns_on && let Err(e) = configure_os_dns(adapter_name) {
            eng.env
                .emit(Event::Notice(format!("DNS для .vl не настроен: {e}")));
        }
        spawn_tun_reader(session, eng.env.clone());
        Ok(eng)
    }
    #[cfg(target_os = "linux")]
    {
        let _ = dll;
        // Имя по умолчанию Windows-адаптера на Linux не годится (регистр,
        // длина) — берём voidlink0, если задано пусто или виндовое имя.
        let name = if adapter_name.is_empty() || adapter_name == "TunnelVPN" {
            DEFAULT_ADAPTER
        } else {
            adapter_name
        };
        let dev = Arc::new(crate::tun_linux::LinuxTun::open(name, mtu).with_context(|| {
            format!("не удалось создать TUN-интерфейс {name} (запусти от root или дай CAP_NET_ADMIN)")
        })?);
        eprintln!("[tun] interface {} up, mtu {mtu}", dev.name());
        let dns_on = cfg.lock().unwrap().dns;
        let eng = start_with_tun(cfg, server, server_pub, identity, dev.clone(), save)?;
        if dns_on && let Err(e) = configure_os_dns(dev.name()) {
            eng.env
                .emit(Event::Notice(format!("DNS для .vl не настроен: {e}")));
        }
        let fd = std::os::fd::AsRawFd::as_raw_fd(dev.as_ref());
        let rd = dev.clone();
        spawn_unix_tun_reader(fd, move |buf| rd.read(buf).map(Some), eng.env.clone());
        Ok(eng)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (dll, adapter_name);
        let dev = Arc::new(
            crate::tun_macos::Utun::open(mtu)
                .context("не удалось создать utun (запусти через sudo)")?,
        );
        let dns_on = cfg.lock().unwrap().dns;
        let eng = start_with_tun(cfg, server, server_pub, identity, dev.clone(), save)?;
        if dns_on && let Err(e) = configure_os_dns("") {
            eng.env
                .emit(Event::Notice(format!("DNS для .vl не настроен: {e}")));
        }
        let fd = dev.raw_fd();
        let rd = dev.clone();
        spawn_unix_tun_reader(
            fd,
            move |buf| match rd.read(buf) {
                Ok(n) => Ok(Some(n)),
                // Обрезанный пакет или чужое семейство — пропускаем.
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => Ok(None),
                Err(e) => Err(anyhow::Error::from(e).context("чтение из utun")),
            },
            eng.env.clone(),
        );
        Ok(eng)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (
            cfg,
            server,
            server_pub,
            identity,
            adapter_name,
            dll,
            save,
            mtu,
        );
        anyhow::bail!("TUN не поддерживается на этой платформе")
    }
}

/// Метка сервера из конфига.
fn server_label(cfg: &Config, server: SocketAddr) -> String {
    cfg.servers
        .iter()
        .find(|s| s.addr.parse::<SocketAddr>().as_ref() == Ok(&server))
        .map(|s| s.label.clone())
        .unwrap_or_default()
}

/// Запуск движка поверх произвольного TUN-устройства (без чтения из него:
/// исходящие пакеты подаются через [`Engine::send_ip_packet`] или tun-поток).
pub fn start_with_tun(
    cfg: Arc<Mutex<Config>>,
    server: SocketAddr,
    server_pub: [u8; 32],
    identity: proto::Identity,
    tun: Arc<dyn TunDev>,
    save: Arc<dyn Fn(&Config) + Send + Sync>,
) -> Result<Engine> {
    let (ev_tx, ev_rx) = mpsc::channel();
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>();
    let (in_tx, in_rx) = mpsc::channel::<Input>();

    let server_label = {
        let mut c = cfg.lock().unwrap();
        // Автовход — этого сервера (gid у каждого сервера свои).
        if c.activate_server(server) {
            save(&c);
        }
        server_label(&c, server)
    };
    let meta = Arc::new(Mutex::new(Meta {
        connected: false,
        transport: Transport::Udp,
        server,
        server_label,
        group_list: Vec::new(),
        rx_hist: VecDeque::new(),
        tx_hist: VecDeque::new(),
        started: Instant::now(),
    }));

    let sock = Arc::new(UdpSocket::bind(bind_addr(server)).context("bind udp")?);
    sock.set_read_timeout(Some(RX_POLL)).ok();

    let groups: Groups = Arc::new(Mutex::new(HashMap::new()));
    let env = Arc::new(Env {
        groups: groups.clone(),
        meta: meta.clone(),
        stats: Arc::new(Stats::new()),
        ev: ev_tx,
        cfg: cfg.clone(),
        save: save.clone(),
        identity,
        server: Mutex::new(server),
        sock,
        tcp: Mutex::new(None),
        tun,
        quit: AtomicBool::new(false),
        key_log: KeyLog::default(),
    });
    let my_pub = env.identity.ed_pub();
    let my_code = env.identity.friend_code();

    // Приём — отдельный поток с самого начала: он же доставит WELCOME.
    {
        let env = env.clone();
        let in_tx = in_tx.clone();
        thread::Builder::new()
            .name("rx".into())
            .spawn(move || rx_loop(env, in_tx))
            .context("spawn rx thread")?;
    }
    // Команды UI → общий входной канал движка.
    {
        let in_tx = in_tx.clone();
        thread::Builder::new()
            .name("cmd".into())
            .spawn(move || {
                for c in cmd_rx {
                    if in_tx.send(Input::Cmd(c)).is_err() {
                        break;
                    }
                }
            })
            .context("spawn cmd thread")?;
    }
    // Первое подключение — синхронно, чтобы ошибка была видна сразу.
    let mut st = State::new(server_pub);
    st.rx_ctx = Some((env.clone(), in_tx));
    if let Err(e) = first_connect(&env, &in_rx, &mut st) {
        env.quit.store(true, Ordering::Relaxed);
        return Err(e);
    }

    spawn_sampler(env.clone());
    {
        let env = env.clone();
        thread::Builder::new()
            .name("engine".into())
            .spawn(move || engine_loop(env, in_rx, st))
            .context("spawn engine thread")?;
    }

    Ok(Engine {
        groups,
        meta,
        stats: env.stats.clone(),
        my_pub,
        my_code,
        events: ev_rx,
        cmds: cmd_tx,
        cfg,
        save,
        env,
    })
}

// ---------- поток приёма ----------

/// Входы цикла движка.
enum Input {
    Cmd(Cmd),
    /// Не групповой фрейм от сервера (открытые рукопожатия/RESET или шифр).
    /// `via_tcp` — пришёл по TCP-каналу.
    Server {
        typ: u8,
        body: Vec<u8>,
        via_tcp: bool,
    },
    /// Фрейм группы новее известной эпохи: пропущена ротация — GET_GROUP.
    NeedGroup(u32),
}

fn rx_loop(env: Arc<Env>, in_tx: mpsc::Sender<Input>) {
    let mut buf = vec![0u8; 65_535];
    while !env.quitting() {
        let (n, src) = match env.sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                use std::io::ErrorKind::*;
                match e.kind() {
                    // Таймаут чтения — проверить флаг выхода.
                    // ConnectionReset — Windows: ICMP unreachable после
                    // send_to в мёртвый эндпоинт (офлайн-пир, старый порт).
                    // Это не потеря связи — пропускаем.
                    WouldBlock | TimedOut | ConnectionReset | Interrupted => {}
                    _ => {
                        if debug() {
                            env.emit(Event::Error(format!("recv: {e}")));
                        }
                        thread::sleep(Duration::from_millis(50));
                    }
                }
                continue;
            }
        };
        if !dispatch(&env, &in_tx, src, &buf[..n], false) {
            break;
        }
    }
}

/// Разбор входящей датаграммы (UDP или кадра TCP): `false` — движок
/// остановлен.
fn dispatch(
    env: &Env,
    in_tx: &mpsc::Sender<Input>,
    src: SocketAddr,
    datagram: &[u8],
    via_tcp: bool,
) -> bool {
    let Ok((typ, body)) = proto::split_frame(datagram) else {
        return true;
    };
    if proto::grp::is_group(typ) {
        match handle_group_frame(env, src, datagram) {
            Some(gid) => in_tx.send(Input::NeedGroup(gid)).is_ok(),
            None => true,
        }
    } else if src == env.server() {
        in_tx
            .send(Input::Server {
                typ,
                body: body.to_vec(),
                via_tcp,
            })
            .is_ok()
    } else {
        true
    }
}

/// Приём по TCP-каналу: кадры — как датаграммы от сервера. Выходит, когда
/// канал закрыт, заменён другим или движок остановлен.
fn tcp_rx_loop(env: Arc<Env>, link: Arc<TcpLink>, in_tx: mpsc::Sender<Input>) {
    while !env.quitting() {
        let current = env.tcp_link().is_some_and(|t| Arc::ptr_eq(&t, &link));
        if !current {
            return;
        }
        match link.recv_timeout(RX_POLL) {
            Ok(frame) => {
                if !dispatch(&env, &in_tx, env.server(), &frame, true) {
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

// ---------- цикл движка ----------

/// Состояние цикла движка (живёт только в потоке engine).
struct State {
    server_pub: [u8; 32],
    /// Движок и копия входного канала — для потока приёма TCP.
    rx_ctx: Option<(Arc<Env>, mpsc::Sender<Input>)>,
    /// HELLO3 по UDP подряд без единого ответа сервера по UDP.
    udp_hellos: u32,
    /// Первый из них (для `tcp_link::should_fallback`).
    udp_since: Option<Instant>,
    /// Сессия с сервером (есть — подключены).
    sess: Option<CtrlSession>,
    /// Попытка рукопожатия: без сессии — подключение, с сессией — повторное
    /// рукопожатие после смены имени.
    hs: Option<Handshake>,
    /// Последняя ошибка рукопожатия (UNSUPPORTED, чужой ключ): показывается
    /// один раз, первое подключение с ней завершается.
    hs_error: Option<String>,
    /// Шифрованные фреймы, пришедшие раньше WELCOME своей попытки.
    early: Vec<(u8, Vec<u8>)>,
    /// Последний подлинный (расшифрованный) фрейм от сервера.
    last_server_rx: Instant,
    next_hello: Instant,
    backoff: Duration,
    /// Группы, из которых вышли, но сервер ещё не подтвердил: gid → начало.
    leaving: HashMap<u32, Instant>,
    /// Ожидаемое окно приглашений: (from, с какого момента ждём).
    invite_sync: Option<(u32, Instant)>,
    last_invite_req: Instant,
    /// Отклонённые приглашения, отказ ещё не подтверждён: gid → начало.
    declining: HashMap<u32, Instant>,
    last_decline: Instant,
    /// Группы, чьё полное состояние нужно запросить (GET_GROUP).
    want_group: HashSet<u32>,
    /// Номер серверной сессии (растёт на каждую новую): ревизии групп
    /// сравнимы только в пределах одной.
    sess_gen: u64,
    /// Группы, из которых нас исключили (KICKED): gid → ревизия сервера
    /// после кика (из KICKED; не меньше нашей тогда) и время. Запоздавший
    /// GROUP_STATE (или список групп) не новее неё группу не возвращает;
    /// действует в пределах сессии и `TOMB_TTL`.
    tombs: HashMap<u32, (u32, Instant)>,
    /// Новая сессия: автовход ещё не сверен с первым GROUP_LIST.
    autojoin_due: bool,
    last_get: HashMap<u32, Instant>,
    /// Последние отправленные CANDIDATES.
    candidates: Vec<SocketAddr>,
    last_cand: Instant,
    /// Неподтверждённый PRESENCE: значение, первая и последняя отправка.
    /// Повторяется, пока не придёт PRESENCE_ACK с этим значением.
    presence: Option<(bool, Instant, Instant)>,
    last_ping: Instant,
    last_list: Instant,
    last_rtt: Instant,
    last_punch: Instant,
    last_leave: Instant,
}

impl State {
    fn new(server_pub: [u8; 32]) -> Self {
        let now = Instant::now();
        Self {
            server_pub,
            rx_ctx: None,
            udp_hellos: 0,
            udp_since: None,
            sess: None,
            hs: None,
            hs_error: None,
            early: Vec::new(),
            last_server_rx: now,
            next_hello: now,
            backoff: HELLO_RETRY,
            leaving: HashMap::new(),
            invite_sync: None,
            last_invite_req: now,
            declining: HashMap::new(),
            last_decline: now,
            want_group: HashSet::new(),
            sess_gen: 0,
            tombs: HashMap::new(),
            autojoin_due: false,
            last_get: HashMap::new(),
            candidates: Vec::new(),
            last_cand: now,
            presence: None,
            last_ping: now,
            last_list: now,
            last_rtt: now,
            last_punch: now,
            last_leave: now,
        }
    }

    fn connected(&self) -> bool {
        self.sess.is_some()
    }

    /// Новая попытка рукопожатия (новый эфемерный ключ), HELLO3 — сразу.
    fn new_attempt(&mut self) {
        self.hs = Some(Handshake::new());
        self.early.clear();
        self.next_hello = Instant::now();
    }

    /// PRESENCE с ожиданием подтверждения (без связи — только запоминается:
    /// уйдёт флагом HELLO3 и повтором после WELCOME).
    fn send_presence(&mut self, env: &Env, invisible: bool) {
        let now = Instant::now();
        self.presence = Some((invisible, now, now));
        self.send_ctrl(env, ctrl::PRESENCE, &payloads::enc_presence(invisible));
    }

    fn send_ctrl(&mut self, env: &Env, typ: u8, payload: &[u8]) {
        if let Some(s) = self.sess.as_mut() {
            let frame = s.seal(typ, payload);
            env.send(&frame, env.server());
        }
    }

    fn send_hello(&mut self, env: &Env) {
        if self.hs.is_none() {
            return;
        }
        ensure_transport(env, self);
        if env.tcp_link().is_none() {
            self.udp_hellos += 1;
            self.udp_since.get_or_insert_with(Instant::now);
        }
        let Some(hs) = &self.hs else { return };
        let frame = {
            let cfg = env.cfg.lock().unwrap();
            hs.hello(&env.identity, &cfg.name, hello_flags(&cfg), None)
        };
        env.send(&frame, env.server());
    }

    /// Ошибка рукопожатия: событие — только если текст новый (повторы
    /// попыток не спамят).
    fn hs_fail(&mut self, env: &Env, msg: String) {
        if self.hs_error.as_deref() != Some(msg.as_str()) {
            env.emit(Event::Error(msg.clone()));
        }
        self.hs_error = Some(msg);
    }
}

/// Перед HELLO3: выбрать транспорт до сервера. TCP поднимается в режиме
/// `tcp` всегда, в `auto` — когда UDP-рукопожатия остаются без ответа
/// (`tcp_link::should_fallback`). Мёртвый TCP-канал забывается.
fn ensure_transport(env: &Env, st: &mut State) {
    if let Some(t) = env.tcp_link() {
        if t.is_alive() {
            return;
        }
        drop_tcp(env);
    }
    let mode = env.cfg.lock().unwrap().transport;
    let want = match mode {
        TransportMode::Udp => false,
        TransportMode::Tcp => true,
        TransportMode::Auto => {
            let elapsed = st.udp_since.map(|t| t.elapsed()).unwrap_or_default();
            tcp_link::should_fallback(st.udp_hellos, elapsed)
        }
    };
    if !want {
        return;
    }
    let Some((env_arc, in_tx)) = st.rx_ctx.clone() else {
        return;
    };
    let server = env.server();
    match TcpLink::connect(server, TCP_CONNECT_TIMEOUT) {
        Ok(link) => {
            let link = Arc::new(link);
            *env.tcp.lock().unwrap() = Some(link.clone());
            env.meta.lock().unwrap().transport = Transport::Tcp;
            if mode == TransportMode::Auto {
                env.emit(Event::Notice(format!(
                    "UDP до сервера {server} не отвечает — связь через TCP"
                )));
            }
            let _ = thread::Builder::new()
                .name("tcp-rx".into())
                .spawn(move || tcp_rx_loop(env_arc, link, in_tx));
        }
        Err(e) => {
            // Снова несколько попыток по UDP, потом — TCP заново.
            st.udp_hellos = 0;
            st.udp_since = None;
            if debug() || mode == TransportMode::Tcp {
                env.emit(Event::Error(format!("TCP {server}: {e}")));
            }
        }
    }
}

/// Закрыть TCP-канал (обрыв, смена сервера): дальше — UDP.
fn drop_tcp(env: &Env) {
    if let Some(t) = env.tcp.lock().unwrap().take() {
        t.close();
    }
    env.meta.lock().unwrap().transport = Transport::Udp;
}

/// Синхронное первое подключение: HELLO3 с повтором раз в секунду, до 10 с.
fn first_connect(env: &Env, in_rx: &mpsc::Receiver<Input>, st: &mut State) -> Result<()> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut early: Vec<Cmd> = Vec::new();
    st.new_attempt();
    loop {
        if st.connected() {
            // Команды, пришедшие до подключения, — после него.
            for c in early {
                do_cmd(env, st, c);
            }
            return Ok(());
        }
        // Неаутентифицированные ответы (UNSUPPORTED, RESET, чужой WELCOME)
        // попытку не обрывают: подлинный WELCOME ждётся до таймаута, а они
        // лишь объясняют его (`Handshake::advisory`).
        let now = Instant::now();
        if now > deadline {
            let msg = st.hs.as_ref().map(|h| h.timeout_msg()).unwrap_or_default();
            anyhow::bail!(msg);
        }
        // Первое подключение — ровно раз в секунду, без нарастания паузы.
        st.backoff = HELLO_RETRY;
        tick(env, st, now);
        match in_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Input::Server { typ, body, via_tcp }) => {
                if !via_tcp {
                    st.udp_hellos = 0;
                    st.udp_since = None;
                }
                on_server_frame(env, st, typ, &body)
            }
            Ok(Input::Cmd(Cmd::Quit)) => anyhow::bail!("остановлено"),
            Ok(Input::Cmd(c)) => early.push(c),
            Ok(Input::NeedGroup(_)) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => anyhow::bail!("rx-поток остановлен"),
        }
    }
}

fn engine_loop(env: Arc<Env>, in_rx: mpsc::Receiver<Input>, mut st: State) {
    loop {
        match in_rx.recv_timeout(TICK) {
            Ok(Input::Cmd(Cmd::Quit)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                env.quit.store(true, Ordering::Relaxed);
                return;
            }
            Ok(Input::Cmd(c)) => do_cmd(&env, &mut st, c),
            Ok(Input::Server { typ, body, via_tcp }) => {
                if !via_tcp {
                    st.udp_hellos = 0;
                    st.udp_since = None;
                }
                on_server_frame(&env, &mut st, typ, &body)
            }
            Ok(Input::NeedGroup(gid)) => {
                if env.groups.lock().unwrap().contains_key(&gid) {
                    st.want_group.insert(gid);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if env.quitting() {
            return;
        }
        tick(&env, &mut st, Instant::now());
    }
}

/// Сервер принял HELLO3 (новая сессия): приветствие и восстановление
/// состояния. `was` — сессия уже была (повторное рукопожатие).
fn on_connected(env: &Env, st: &mut State, was: bool) {
    let now = Instant::now();
    st.last_server_rx = now;
    st.backoff = HELLO_RETRY;
    st.last_ping = now;
    st.last_list = now;
    // Сервер шлёт окно приглашений сразу за WELCOME — ждём его (см. tick).
    st.invite_sync = Some((0, now));
    st.last_invite_req = now;
    st.last_decline = now;
    if !was {
        env.meta.lock().unwrap().connected = true;
        env.emit(Event::Connected(env.server()));
    }
    restore(env, st);
}

/// Состояние новой серверной сессии: статус, кандидаты, выходы и отказы,
/// список. Ключи (ротированные HELLO3) и состав всех наших групп сервер
/// присылает сам — GROUP_STATE за WELCOME; потерянное чинит сверка ревизий
/// по GROUP_LIST. Автовход — по первому списку (`autojoin_due`).
fn restore(env: &Env, st: &mut State) {
    let cfg = env.cfg.lock().unwrap().clone();
    if !cfg.status.is_empty() {
        st.send_ctrl(env, ctrl::STATUS, &payloads::enc_status(&cfg.status));
    }
    // Неподтверждённая смена невидимки — заново в новую сессию (HELLO3 мог
    // уйти до смены); подтверждённая уже в флагах HELLO3.
    if st.presence.is_some() {
        st.send_presence(env, cfg.invisible);
    }
    st.candidates = lan_candidates(env);
    st.last_cand = Instant::now();
    if !st.candidates.is_empty() {
        let p = payloads::enc_candidates(&st.candidates);
        st.send_ctrl(env, ctrl::CANDIDATES, &p);
    }
    st.autojoin_due = true;
    // Новая сессия: прошлые запросы GET_GROUP не в счёт.
    st.last_get.clear();
    let leaving: Vec<u32> = st.leaving.keys().copied().collect();
    for gid in leaving {
        st.send_ctrl(env, ctrl::LEAVE_GROUP, &payloads::enc_gid(gid));
    }
    let declining: Vec<u32> = st.declining.keys().copied().collect();
    for gid in declining {
        st.send_ctrl(env, ctrl::DECLINE_INVITE, &payloads::enc_gid(gid));
    }
    st.send_ctrl(env, ctrl::LIST_GROUPS, &[]);
}

fn lose_server(env: &Env, st: &mut State, reason: &str) {
    if !st.connected() {
        return;
    }
    st.sess = None;
    st.new_attempt();
    st.backoff = HELLO_RETRY;
    env.meta.lock().unwrap().connected = false;
    env.emit(Event::Disconnected(reason.to_string()));
}

fn on_server_frame(env: &Env, st: &mut State, typ: u8, body: &[u8]) {
    let now = Instant::now();
    match typ {
        ctrl::WELCOME => on_welcome(env, st, body),
        ctrl::CHALLENGE => {
            let Some(hs) = st.hs.as_mut() else { return };
            let frame = {
                let cfg = env.cfg.lock().unwrap();
                hs.on_challenge(&env.identity, &cfg.name, hello_flags(&cfg), body, now)
            };
            if let Some(f) = frame {
                env.send(&f, env.server());
            }
        }
        ctrl::UNSUPPORTED => {
            // Ответ на наш HELLO3 (вне рукопожатия — чужой/поддельный). Не
            // аутентифицирован: лишь подсказка, если подлинного WELCOME так и
            // не будет (см. tick).
            if let Some(hs) = st.hs.as_mut() {
                hs.advisory = Some(unsupported_msg(body));
            }
        }
        ctrl::RESET => {
            if let Some(hs) = st.hs.as_mut() {
                hs.saw_reset = true;
            }
            // RESET открыт и подделывается кем угодно: сразу после подлинного
            // фрейма он не повод рвать сессию (и ротировать ключи групп).
            if now.duration_since(st.last_server_rx) < RESET_GRACE {
                return;
            }
            // Сервер не знает нашу сессию (перезапуск/истекла) — сразу HELLO3.
            lose_server(env, st, "сервер сбросил сессию");
        }
        t if ctrl::is_plaintext(t) => {}
        _ => {
            let opened = st.sess.as_mut().and_then(|s| s.open(typ, body, now));
            match opened {
                Some(msg) => {
                    st.last_server_rx = now;
                    if let Some((t, p)) = msg {
                        on_ctrl(env, st, t, &p);
                    }
                }
                // Возможно, фрейм новой попытки, обогнавший её WELCOME.
                None => {
                    if st.hs.is_some() && st.early.len() < EARLY_MAX {
                        st.early.push((typ, body.to_vec()));
                    }
                }
            }
        }
    }
}

fn on_welcome(env: &Env, st: &mut State, body: &[u8]) {
    if let Some(hs) = st.hs.as_ref() {
        match accept_welcome(&env.identity, &hs.eph, &st.server_pub, body) {
            Ok(Some(acc)) => {
                let hs = st.hs.take().expect("попытка есть");
                establish(env, st, hs.eph, acc);
                return;
            }
            Ok(None) => {}
            // Подпись не от закреплённого ключа: подделать такой WELCOME
            // может любой, кто видит наш HELLO3, — ждём подлинный дальше.
            Err(e) => {
                if let Some(hs) = st.hs.as_mut() {
                    hs.advisory = Some(format!("{e:#}"));
                }
                return;
            }
        }
    }
    // Ещё один WELCOME под eph текущей сессии: сервер пересоздал её на
    // повтор HELLO3 — новые ключи, состояние сессии заново.
    let added = match st.sess.as_mut() {
        Some(s) => match accept_welcome(&env.identity, &s.eph, &st.server_pub, body) {
            Ok(Some(acc)) => s.add(acc),
            _ => false,
        },
        None => false,
    };
    if added {
        on_connected(env, st, true);
    }
}

/// WELCOME принят: ключ сервера (перезакрепление), новая сессия, фреймы,
/// обогнавшие WELCOME.
fn establish(env: &Env, st: &mut State, eph: proto::EphemeralKey, acc: Accepted) {
    if let proto::PinResolution::Rotated { new_ed } = acc.pin {
        st.server_pub = new_ed;
        let addr = env.server();
        env.update_cfg(|c| {
            c.repin_server(addr, &new_ed);
        });
        env.emit(Event::ServerKeyRotated {
            addr,
            new_code: proto::friend_code_of(&new_ed),
        });
    }
    let was = st.connected();
    st.sess = Some(CtrlSession::new(eph, acc));
    // Новая сессия: ревизии прежней (до рестарта сервера) не сравнимы.
    st.sess_gen += 1;
    st.tombs.clear();
    st.hs_error = None;
    on_connected(env, st, was);
    for (typ, body) in std::mem::take(&mut st.early) {
        on_server_frame(env, st, typ, &body);
    }
}

/// Таймеры: идут по часам на каждой итерации цикла.
fn tick(env: &Env, st: &mut State, now: Instant) {
    if env.tcp_link().is_some_and(|t| !t.is_alive()) {
        drop_tcp(env);
        lose_server(env, st, "TCP-соединение с сервером закрыто");
    }
    if st.connected() && now.duration_since(st.last_server_rx) > SERVER_TIMEOUT {
        lose_server(env, st, "сервер не отвечает");
    }
    if !st.connected() {
        if st.hs.is_none() {
            st.new_attempt();
        }
        // Подсказка неаутентифицированного ответа — событием, только когда
        // подлинного WELCOME нет дольше CONNECT_TIMEOUT.
        let advice = st
            .hs
            .as_ref()
            .filter(|hs| now.duration_since(hs.started) > CONNECT_TIMEOUT)
            .and_then(|hs| hs.advisory.clone());
        if let Some(msg) = advice {
            st.hs_fail(env, msg);
        }
        if now >= st.next_hello {
            st.send_hello(env);
            st.next_hello = now + st.backoff;
            st.backoff = (st.backoff * 2).min(RECONNECT_MAX);
        }
    } else if let Some(hs) = &st.hs {
        // Повторное рукопожатие поверх живой сессии (смена имени).
        if now.duration_since(hs.started) > REHELLO_GIVE_UP {
            st.hs = None;
            st.early.clear();
        } else if now >= st.next_hello {
            st.send_hello(env);
            st.next_hello = now + HELLO_RETRY;
        }
    }
    if let Some(s) = st.sess.as_mut() {
        s.expire(now);
    }
    if st.connected() {
        if now.duration_since(st.last_ping) >= PING_EVERY {
            st.last_ping = now;
            st.send_ctrl(env, ctrl::CTRL_PING, &[]);
        }
        if now.duration_since(st.last_list) >= LIST_EVERY {
            st.last_list = now;
            st.send_ctrl(env, ctrl::LIST_GROUPS, &[]);
        }
        if !st.leaving.is_empty() && now.duration_since(st.last_leave) >= LEAVE_RETRY {
            st.last_leave = now;
            st.leaving
                .retain(|_, started| now.duration_since(*started) < LEAVE_GIVE_UP);
            let gids: Vec<u32> = st.leaving.keys().copied().collect();
            for gid in gids {
                st.send_ctrl(env, ctrl::LEAVE_GROUP, &payloads::enc_gid(gid));
            }
        }
        if let Some((from, since)) = st.invite_sync
            && now.duration_since(st.last_invite_req) >= INVITE_SYNC_RETRY
        {
            st.last_invite_req = now;
            if now.duration_since(since) < INVITE_SYNC_GIVE_UP {
                st.send_ctrl(env, ctrl::LIST_INVITES, &payloads::enc_u32(from));
            } else {
                st.invite_sync = None;
            }
        }
        if !st.declining.is_empty() && now.duration_since(st.last_decline) >= DECLINE_RETRY {
            st.last_decline = now;
            st.declining
                .retain(|_, started| now.duration_since(*started) < DECLINE_GIVE_UP);
            let gids: Vec<u32> = st.declining.keys().copied().collect();
            for gid in gids {
                st.send_ctrl(env, ctrl::DECLINE_INVITE, &payloads::enc_gid(gid));
            }
        }
        if !st.want_group.is_empty() {
            let due: Vec<u32> = st
                .want_group
                .iter()
                .filter(|g| {
                    st.last_get
                        .get(g)
                        .is_none_or(|t| now.duration_since(*t) >= GET_GROUP_EVERY)
                })
                .copied()
                .collect();
            for gid in due {
                st.want_group.remove(&gid);
                st.last_get.insert(gid, now);
                st.send_ctrl(env, ctrl::GET_GROUP, &payloads::enc_gid(gid));
            }
        }
        if let Some((on, first, last)) = st.presence
            && now.duration_since(last) >= SELF_RETRY
        {
            if now.duration_since(first) >= PRESENCE_GIVE_UP {
                // Дальше чинит периодический повтор раз в `CAND_EVERY`.
                st.presence = None;
            } else {
                st.presence = Some((on, first, now));
                st.send_ctrl(env, ctrl::PRESENCE, &payloads::enc_presence(on));
            }
        }
        if now.duration_since(st.last_cand) >= CAND_EVERY {
            st.last_cand = now;
            // Повтор без изменения сервер не считает изменением (только ACK).
            let on = env.cfg.lock().unwrap().invisible;
            st.send_ctrl(env, ctrl::PRESENCE, &payloads::enc_presence(on));
            let cands = lan_candidates(env);
            if cands != st.candidates {
                st.candidates = cands;
                let p = payloads::enc_candidates(&st.candidates);
                st.send_ctrl(env, ctrl::CANDIDATES, &p);
            }
        }
    }
    // P2P-таймеры работают и без сервера: прямые каналы живут сами.
    if now.duration_since(st.last_rtt) >= RTT_EVERY {
        st.last_rtt = now;
        rtt_round(env, st.connected(), now);
    }
    if now.duration_since(st.last_punch) >= PUNCH_EVERY {
        st.last_punch = now;
        punch_round(env);
    }
}

fn do_cmd(env: &Env, st: &mut State, cmd: Cmd) {
    // Локальные команды — всегда, независимо от связи с сервером.
    match cmd {
        Cmd::Quit => return,
        Cmd::ToggleAutojoin(gid) => {
            let on = env.cfg.lock().unwrap().autojoin.contains(&gid);
            if on {
                env.autojoin_remove(gid);
            } else {
                env.autojoin_add(gid);
            }
            return;
        }
        Cmd::SetName(name) => {
            env.update_cfg(|c| c.name = name);
            if st.connected() {
                // Имя — в HELLO3: новое рукопожатие поверх живой сессии.
                st.new_attempt();
            }
            return;
        }
        Cmd::SetStatus(text) => {
            let t = text.clone();
            env.update_cfg(|c| c.status = t);
            st.send_ctrl(env, ctrl::STATUS, &payloads::enc_status(&text));
            return;
        }
        Cmd::SetInvisible(on) => {
            env.update_cfg(|c| c.invisible = on);
            // Без связи — уйдёт флагом в следующем HELLO3. Повторяется, пока
            // сервер не подтвердит PRESENCE_ACK.
            st.send_presence(env, on);
            return;
        }
        Cmd::Leave(gid) => {
            // Выход — сразу локально; LEAVE повторяется, пока сервер не
            // подтвердит (иначе потерянный LEAVE или запоздавший
            // GROUP_STATE возвращали группу обратно).
            let name = env
                .groups
                .lock()
                .unwrap()
                .remove(&gid)
                .map(|g| g.name.clone());
            env.autojoin_remove(gid);
            st.want_group.remove(&gid);
            st.leaving.insert(gid, Instant::now());
            st.send_ctrl(env, ctrl::LEAVE_GROUP, &payloads::enc_gid(gid));
            if let Some(name) = name {
                env.emit(Event::GroupLeft { gid, name });
            }
            return;
        }
        Cmd::SwitchServer {
            addr,
            pubkey,
            label,
        } => {
            switch_server(env, st, addr, pubkey, label);
            return;
        }
        Cmd::Reconnect => {
            // Без связи — HELLO3 сразу и бэкофф с начала; со связью —
            // повторное рукопожатие поверх сессии (сервер мог её уже забыть,
            // пока мы спали; не ответит — сессия умрёт по таймауту как обычно).
            st.backoff = HELLO_RETRY;
            st.new_attempt();
            return;
        }
        Cmd::AddFriend { .. }
        | Cmd::DelFriend(_)
        | Cmd::SetAlias { .. }
        | Cmd::AddServer { .. }
        | Cmd::DelServer { .. }
        | Cmd::SetPrimaryServer { .. } => {
            cfg_cmd(env, st, cmd);
            return;
        }
        _ => {}
    }
    if !st.connected() {
        env.emit(Event::Error(
            "нет связи с сервером — команда не отправлена".into(),
        ));
        return;
    }
    match cmd {
        Cmd::RefreshList => st.send_ctrl(env, ctrl::LIST_GROUPS, &[]),
        Cmd::Create { name, private } => st.send_ctrl(
            env,
            ctrl::CREATE_GROUP,
            &payloads::enc_create_group(&name, private),
        ),
        Cmd::Join(gid) => {
            st.leaving.remove(&gid);
            st.declining.remove(&gid);
            st.send_ctrl(env, ctrl::JOIN_GROUP, &payloads::enc_gid(gid))
        }
        Cmd::Delete(gid) => st.send_ctrl(env, ctrl::DELETE_GROUP, &payloads::enc_gid(gid)),
        Cmd::Rename(gid, name) => {
            st.send_ctrl(env, ctrl::RENAME_GROUP, &payloads::enc_rename(gid, &name))
        }
        Cmd::Invite(gid, pk) => {
            st.send_ctrl(env, ctrl::INVITE, &payloads::enc_gid_target(gid, &pk))
        }
        // Повторяется, пока окно списка не подтвердит отказ (см. on_ctrl):
        // потерянный DECLINE оставил бы приглашение на сервере, а владелец
        // не узнал бы об отказе.
        Cmd::DeclineInvite(gid) => {
            let now = Instant::now();
            st.declining.insert(gid, now);
            st.last_decline = now;
            st.send_ctrl(env, ctrl::DECLINE_INVITE, &payloads::enc_gid(gid))
        }
        Cmd::Kick(gid, pk) => st.send_ctrl(env, ctrl::KICK, &payloads::enc_gid_target(gid, &pk)),
        Cmd::Ban(gid, pk) => st.send_ctrl(env, ctrl::BAN, &payloads::enc_gid_target(gid, &pk)),
        Cmd::Unban(gid, pk) => st.send_ctrl(env, ctrl::UNBAN, &payloads::enc_gid_target(gid, &pk)),
        Cmd::GroupAdmin(gid) => st.send_ctrl(env, ctrl::GROUP_ADMIN, &payloads::enc_gid(gid)),
        Cmd::Transfer(gid, pk) => st.send_ctrl(
            env,
            ctrl::TRANSFER_OWNER,
            &payloads::enc_gid_target(gid, &pk),
        ),
        Cmd::FriendGroups(pk) => {
            st.send_ctrl(env, ctrl::FRIEND_GROUPS, &payloads::enc_pubkey(&pk));
        }
        Cmd::Quit
        | Cmd::ToggleAutojoin(_)
        | Cmd::SetName(_)
        | Cmd::SetStatus(_)
        | Cmd::SetInvisible(_)
        | Cmd::SwitchServer { .. }
        | Cmd::Reconnect
        | Cmd::AddFriend { .. }
        | Cmd::DelFriend(_)
        | Cmd::SetAlias { .. }
        | Cmd::AddServer { .. }
        | Cmd::DelServer { .. }
        | Cmd::SetPrimaryServer { .. }
        | Cmd::Leave(_) => {}
    }
}

/// Проверка команды правки конфига до отправки движку (демон отвечает
/// `Ack` Err сразу): `None` — команда допустима при текущем конфиге и
/// сервере `current`.
pub fn check_cfg_cmd(cfg: &Config, current: SocketAddr, cmd: &Cmd) -> Option<String> {
    let same = |a: &str| a.parse::<SocketAddr>().ok() == Some(current);
    match cmd {
        Cmd::SetAlias { pubkey, .. } => {
            let hex = proto::hex_of(pubkey);
            (!cfg.friends.iter().any(|f| f.pubkey == hex)).then(|| "такого друга нет".into())
        }
        Cmd::DelFriend(pubkey) => {
            let hex = proto::hex_of(pubkey);
            (!cfg.friends.iter().any(|f| f.pubkey == hex)).then(|| "такого друга нет".into())
        }
        Cmd::AddServer { addr, .. } => addr
            .parse::<SocketAddr>()
            .is_err()
            .then(|| format!("неверный адрес сервера «{addr}» (нужен ip:port)")),
        Cmd::DelServer { idx } => match cfg.servers.get(*idx) {
            None => Some(format!("нет сервера №{idx}")),
            Some(s) if same(&s.addr) => {
                Some("текущий сервер не удаляется — сначала переключитесь".into())
            }
            Some(_) => None,
        },
        Cmd::SetPrimaryServer { idx } => match cfg.servers.get(*idx) {
            None => Some(format!("нет сервера №{idx}")),
            Some(s) => {
                let bad_addr = s.addr.parse::<SocketAddr>().is_err();
                let bad_key = proto::hex_to_bytes(&s.pubkey)
                    .map(|v| v.len() != 32)
                    .unwrap_or(true);
                (bad_addr || bad_key).then(|| format!("сервер №{idx}: неверный адрес или ключ"))
            }
        },
        _ => None,
    }
}

/// Команды правки конфига (PLAN.md 7.1): правка `env.cfg` + колбэк
/// сохранения; результат — `Notice`, отказ — `Error`.
fn cfg_cmd(env: &Env, st: &mut State, cmd: Cmd) {
    let current = env.server();
    if let Some(e) = check_cfg_cmd(&env.cfg.lock().unwrap(), current, &cmd) {
        env.emit(Event::Error(e));
        return;
    }
    match cmd {
        Cmd::AddFriend { pubkey, alias } => {
            let hex = proto::hex_of(&pubkey);
            let a = alias.clone();
            env.update_cfg(|c| match c.friends.iter_mut().find(|f| f.pubkey == hex) {
                Some(f) => f.alias = a,
                None => c.friends.push(crate::store::StoredFriend {
                    pubkey: hex,
                    alias: a,
                }),
            });
            env.emit(Event::Notice(format!("друг добавлен: {alias}")));
        }
        Cmd::DelFriend(pubkey) => {
            let hex = proto::hex_of(&pubkey);
            env.update_cfg(|c| c.friends.retain(|f| f.pubkey != hex));
            env.emit(Event::Notice("друг удалён".into()));
        }
        Cmd::SetAlias { pubkey, alias } => {
            let hex = proto::hex_of(&pubkey);
            let a = alias.clone();
            env.update_cfg(|c| {
                if let Some(f) = c.friends.iter_mut().find(|f| f.pubkey == hex) {
                    f.alias = a;
                }
            });
            env.emit(Event::Notice(format!("alias: {alias}")));
        }
        Cmd::AddServer {
            addr,
            pubkey,
            label,
        } => {
            let hex = proto::hex_of(&pubkey);
            let sa: SocketAddr = addr.parse().expect("проверено в check_cfg_cmd");
            let l = label.clone();
            env.update_cfg(|c| {
                match c
                    .servers
                    .iter_mut()
                    .find(|s| s.addr.parse::<SocketAddr>().ok() == Some(sa))
                {
                    Some(s) => {
                        s.pubkey = hex;
                        s.label = l;
                    }
                    None => c.servers.push(crate::store::StoredServer {
                        addr: sa.to_string(),
                        pubkey: hex,
                        label: l,
                    }),
                }
            });
            if sa == current {
                env.meta.lock().unwrap().server_label = label.clone();
            }
            env.emit(Event::Notice(format!("сервер добавлен: {sa}")));
        }
        Cmd::DelServer { idx } => {
            let mut gone = String::new();
            env.update_cfg(|c| gone = c.servers.remove(idx).addr);
            env.emit(Event::Notice(format!("сервер удалён: {gone}")));
        }
        Cmd::SetPrimaryServer { idx } => {
            // Первый в списке — сервер по умолчанию; если это не текущий —
            // движок сразу переключается на него (он же станет активным).
            let mut entry = None;
            env.update_cfg(|c| {
                let s = c.servers.remove(idx);
                entry = Some(s.clone());
                c.servers.insert(0, s);
            });
            let s = entry.expect("сервер есть (проверено)");
            let addr: SocketAddr = s.addr.parse().expect("проверено в check_cfg_cmd");
            env.emit(Event::Notice(format!("сервер по умолчанию: {addr}")));
            if addr != current {
                let mut pk = [0u8; 32];
                pk.copy_from_slice(
                    &proto::hex_to_bytes(&s.pubkey).expect("проверено в check_cfg_cmd"),
                );
                switch_server(env, st, addr, pk, s.label);
            }
        }
        _ => {}
    }
}

/// Смена сервера без перезапуска: группы прежнего сервера забываются (их
/// ключи и участники к новому не относятся), сессия и все ожидания —
/// заново, адаптер и сокет — те же.
fn switch_server(env: &Env, st: &mut State, addr: SocketAddr, pubkey: [u8; 32], label: String) {
    let family_ok = env
        .sock
        .local_addr()
        .map(|a| a.is_ipv6() == addr.is_ipv6())
        .unwrap_or(false);
    if !family_ok {
        env.emit(Event::Error(format!(
            "сервер {addr}: другое семейство адресов (IPv4/IPv6) — перезапустите клиент с этим сервером"
        )));
        return;
    }
    let old: Vec<(u32, String)> = env
        .groups
        .lock()
        .unwrap()
        .drain()
        .map(|(gid, g)| (gid, g.name.clone()))
        .collect();
    for (gid, name) in old {
        env.emit(Event::GroupLeft { gid, name });
    }
    st.sess = None;
    st.hs_error = None;
    st.new_attempt();
    st.backoff = HELLO_RETRY;
    st.server_pub = pubkey;
    st.leaving.clear();
    st.declining.clear();
    st.invite_sync = None;
    st.want_group.clear();
    st.tombs.clear();
    st.autojoin_due = false;
    st.last_get.clear();
    st.candidates.clear();
    st.udp_hellos = 0;
    st.udp_since = None;
    drop_tcp(env);
    *env.server.lock().unwrap() = addr;
    {
        let mut cfg = env.cfg.lock().unwrap();
        if cfg.activate_server(addr) {
            (env.save)(&cfg);
        }
    }
    {
        let mut m = env.meta.lock().unwrap();
        m.connected = false;
        m.server = addr;
        m.server_label = label.clone();
        m.group_list.clear();
    }
    env.emit(Event::ServerSwitched { addr, label });
}

impl State {
    /// Ревизия, не новее которой состояние исключённой группы — запоздавшее.
    fn tomb(&self, gid: u32) -> Option<u32> {
        self.tombs
            .get(&gid)
            .filter(|(_, t)| t.elapsed() < TOMB_TTL)
            .map(|(rev, _)| *rev)
    }
}

fn on_ctrl(env: &Env, st: &mut State, typ: u8, payload: &[u8]) {
    match typ {
        ctrl::GROUP_STATE => {
            if let Ok(gs) = payloads::dec_group_state(payload) {
                st.want_group.remove(&gs.gid);
                if st.leaving.contains_key(&gs.gid) && !gs.deleted {
                    // Запоздавшее состояние группы, из которой мы вышли.
                    return;
                }
                apply_group_state(env, st, &gs);
            }
        }
        ctrl::GROUP_UPDATE => apply_group_update(env, st, payload),
        ctrl::GROUP_LIST => {
            if let Ok(items) = payloads::dec_group_list(payload) {
                let mine: HashSet<u32> = items.iter().filter(|g| g.mine).map(|g| g.gid).collect();
                // Сервер подтвердил выход — больше не повторяем LEAVE.
                st.leaving.retain(|gid, _| mine.contains(gid));
                reconcile(env, &mine);
                // Автовход — только в группы, где сервер нас участником не
                // считает: свои он и так присылает после HELLO3, а повторный
                // JOIN участника — лишний GROUP_STATE.
                if std::mem::take(&mut st.autojoin_due) {
                    let auto = env.cfg.lock().unwrap().autojoin.clone();
                    for gid in auto {
                        let live = env.groups.lock().unwrap().contains_key(&gid);
                        if !mine.contains(&gid) && !live && !st.leaving.contains_key(&gid) {
                            st.send_ctrl(env, ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
                        }
                    }
                }
                // Сверка ревизий своих групп: потерянная дельта или кусок
                // FRAG чинится не дольше чем за период списка. Своя группа,
                // которой у нас нет (потерялся GROUP_STATE после JOIN), —
                // тоже GET_GROUP. Ревизия сервера меньше нашей — у нас
                // состояние прежней группы с тем же gid (удаление
                // потерялось): ответ принимается без сверки ревизии.
                // Список не новее кика — запоздавший: группу не возвращает.
                st.tombs.retain(|gid, (rev, _)| {
                    !items
                        .iter()
                        .any(|s| s.gid == *gid && s.mine && s.rev > *rev)
                });
                let stale: Vec<u32> = {
                    let mut g = env.groups.lock().unwrap();
                    items
                        .iter()
                        .filter(|s| {
                            s.mine && !st.leaving.contains_key(&s.gid) && st.tomb(s.gid).is_none()
                        })
                        .filter(|s| match g.get_mut(&s.gid) {
                            None => true,
                            Some(gs) if gs.rev > s.rev => {
                                gs.state_sess = 0;
                                true
                            }
                            Some(gs) => gs.rev != s.rev,
                        })
                        .map(|s| s.gid)
                        .collect()
                };
                st.want_group.extend(stale);
                env.meta.lock().unwrap().group_list = items;
            }
        }
        ctrl::INVITE_RCVD => {
            if let Ok(inv) = payloads::dec_invite(payload) {
                on_invite(env, st, inv);
            }
        }
        ctrl::INVITE_LIST => {
            if let Ok(list) = payloads::dec_invite_list(payload) {
                // Неполное окно — дочитать следующее: сервер шлёт не больше
                // 16 за раз (ответ не должен расти), а показать нужно все.
                // gid растут, так что цепочка конечна.
                let now = Instant::now();
                let next = list.next_from();
                if let Some(next) = next {
                    st.send_ctrl(env, ctrl::LIST_INVITES, &payloads::enc_u32(next));
                }
                // Ждали окно с `want` — это его покрывает: ждём следующее
                // (если есть). Окно не о том (ответ на отказ, вход) ожидание
                // не снимает.
                match st.invite_sync {
                    Some((want, _)) if !list.covers(want) => {}
                    _ => {
                        st.invite_sync = next.map(|n| (n, now));
                        st.last_invite_req = now;
                    }
                }
                // Отказ подтверждён: окно покрывает gid, а приглашения в нём нет.
                st.declining.retain(|gid, _| {
                    !list.covers(*gid) || list.items.iter().any(|i| i.gid == *gid)
                });
                let (from, complete) = (list.from, list.complete);
                let gids: Vec<u32> = list.items.iter().map(|i| i.gid).collect();
                for inv in list.items {
                    // Отказ ещё повторяется — список собран до него.
                    if !st.declining.contains_key(&inv.gid) {
                        on_invite(env, st, inv);
                    }
                }
                env.emit(Event::InvitesSynced {
                    gids,
                    from,
                    complete,
                });
            }
        }
        ctrl::INVITE_DECLINED => {
            if let Ok(d) = payloads::dec_invite_declined(payload) {
                env.emit(Event::InviteDeclined {
                    gid: d.gid,
                    group_name: d.group_name,
                    by_pubkey: d.by_pubkey,
                    by_name: d.by_name,
                });
            }
        }
        ctrl::KICKED => {
            if let Ok(k) = payloads::dec_kicked(payload) {
                let local = env
                    .groups
                    .lock()
                    .unwrap()
                    .remove(&k.gid)
                    .map(|g| (g.name.clone(), g.rev));
                // Граница запоздания — ревизия сервера после кика из KICKED:
                // своя могла отставать (пропущенная дельта — как раз повод
                // для GET_GROUP, ответ на который придёт с ревизией новее
                // нашей, но не новее кика). Ставится и без локальной группы:
                // её мог ещё не принести запоздавший GROUP_STATE после JOIN.
                let tomb = local.as_ref().map_or(k.rev, |(_, rev)| (*rev).max(k.rev));
                st.tombs.insert(k.gid, (tomb, Instant::now()));
                let local = local.map(|(name, _)| name);
                env.autojoin_remove(k.gid);
                st.want_group.remove(&k.gid);
                let name = if k.group_name.is_empty() {
                    local.unwrap_or_default()
                } else {
                    k.group_name
                };
                env.emit(Event::Kicked {
                    gid: k.gid,
                    name,
                    banned: k.banned,
                });
            }
        }
        ctrl::ADMIN_INFO => {
            if let Ok(a) = payloads::dec_admin_info(payload) {
                env.emit(Event::AdminInfo {
                    gid: a.gid,
                    bans: a.bans.into_iter().map(|b| (b.pubkey, b.name)).collect(),
                    invites: a
                        .invites
                        .into_iter()
                        .map(|i| (i.pubkey, i.name, i.expires_in))
                        .collect(),
                });
            }
        }
        ctrl::PRESENCE_ACK => {
            // Подтверждено именно последнее отправленное значение — хватит.
            if let Ok(on) = payloads::dec_presence(payload)
                && st.presence.is_some_and(|(want, ..)| want == on)
            {
                st.presence = None;
            }
        }
        ctrl::ERROR => {
            if let Ok(text) = payloads::dec_error(payload) {
                env.emit(Event::Error(text));
            }
        }
        // О ком ответ — в самом ответе: запросы друг другу не мешают.
        ctrl::FRIEND_GROUPS_RESP => {
            if let Ok(f) = payloads::dec_friend_groups(payload) {
                env.emit(Event::FriendGroups {
                    pubkey: f.target,
                    items: f.groups,
                });
            }
        }
        _ => {}
    }
}

/// Приглашение (одиночное или из INVITE_LIST): событие UI; группа из
/// автовхода — войти сразу.
fn on_invite(env: &Env, st: &mut State, inv: payloads::InviteInfo) {
    let gid = inv.gid;
    env.emit(Event::Invite {
        gid,
        group_name: inv.group_name,
        from_pubkey: inv.from_pubkey,
        from_name: inv.from_name,
        expires_in: inv.expires_in,
    });
    let in_autojoin = env.cfg.lock().unwrap().autojoin.contains(&gid);
    if in_autojoin {
        st.send_ctrl(env, ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
    }
}

/// Локальные группы, которых больше нет на сервере (могли кикнуть/удалить,
/// пока нас не было) — убрать.
fn reconcile(env: &Env, mine: &HashSet<u32>) {
    let now = Instant::now();
    let stale: Vec<(u32, String)> = {
        let mut g = env.groups.lock().unwrap();
        let stale: Vec<(u32, String)> = g
            .iter()
            .filter(|(gid, gs)| {
                !mine.contains(gid) && now.duration_since(gs.since) > NEW_GROUP_GRACE
            })
            .map(|(gid, gs)| (*gid, gs.name.clone()))
            .collect();
        for (gid, _) in &stale {
            g.remove(gid);
        }
        stale
    };
    for (gid, name) in stale {
        env.autojoin_remove(gid);
        env.emit(Event::Notice(format!("группа {name} больше недоступна")));
    }
}

// ---------- состояние групп ----------

/// GROUP_STATE — полное состояние: ревизия, ключ эпохи, состав.
/// Запоздавшее (ревизия меньше принятой в этой же сессии) отбрасывается:
/// иначе задержанный GET_GROUP-ответ вернул бы ключ, отозванный киком, и
/// клиент шифровал бы им снова.
fn apply_group_state(env: &Env, es: &mut State, st: &payloads::GroupState) {
    let my_pub = env.identity.ed_pub();
    if st.deleted {
        let removed = {
            env.groups
                .lock()
                .unwrap()
                .remove(&st.gid)
                .map(|g| g.name.clone())
        };
        match removed {
            Some(name) => {
                env.autojoin_remove(st.gid);
                env.emit(Event::GroupDeleted { gid: st.gid, name });
            }
            // Не наша группа — сервер сообщает приглашённому, что группы нет.
            None => env.emit(Event::InviteRevoked { gid: st.gid }),
        }
        return;
    }
    if es.tomb(st.gid).is_some_and(|rev| st.rev <= rev) {
        return;
    }
    let now = Instant::now();
    let mut events: Vec<Event> = Vec::new();
    let is_new = {
        let mut g = env.groups.lock().unwrap();
        if g.get(&st.gid)
            .is_some_and(|cur| cur.state_sess == es.sess_gen && st.rev < cur.rev)
        {
            return;
        }
        let is_new = !g.contains_key(&st.gid);
        let entry = g
            .entry(st.gid)
            .or_insert_with(|| GroupSess::new(st, now, env.key_log.clone()));
        entry.set_key(st.epoch, st.key, st.revoke_prev, now);
        entry.rev = st.rev;
        entry.state_sess = es.sess_gen;
        entry.name = st.name.clone();
        entry.owner = st.owner;
        entry.private = st.private;
        entry.my_ip = st.my_ip;
        // Участники, которых в состоянии больше нет, — убрать; остальные —
        // обновить, сохранив прямые каналы и RTT.
        let present: HashSet<[u8; 32]> = st.members.iter().map(|m| m.pubkey).collect();
        let gone: Vec<[u8; 32]> = entry
            .members
            .values()
            .filter(|p| !present.contains(&p.pubkey))
            .map(|p| p.pubkey)
            .collect();
        for pk in gone {
            entry.remove_member(&pk);
        }
        for m in &st.members {
            if m.pubkey != my_pub {
                entry.upsert_member(st.gid, m, now, &mut events);
            }
        }
        is_new
    };
    es.tombs.remove(&st.gid);
    if is_new {
        env.emit(Event::GroupJoined {
            gid: st.gid,
            name: st.name.clone(),
            my_ip: st.my_ip,
        });
        env.autojoin_add(st.gid);
    }
    if let Err(e) = env.tun.ensure_address(st.my_ip) {
        env.emit(Event::Error(format!(
            "адрес {} на адаптере: {e}",
            proto::ip_str(st.my_ip)
        )));
    }
    if let Err(e) = env.tun.ensure_address6(st.my_ip) {
        env.emit(Event::Notice(format!(
            "IPv6 группы {} не назначен: {e}",
            st.name
        )));
    }
    if env.cfg.lock().unwrap().dns
        && let Err(e) = env.tun.ensure_dns_route()
    {
        env.emit(Event::Notice(format!(
            "маршрут на DNS {}: {e}",
            crate::dns::DNS_ADDR
        )));
    }
    for ev in events {
        env.emit(ev);
    }
}

/// GROUP_UPDATE — дельта: применяется только к ревизии `base_rev`, иначе
/// (пропущена дельта, неизвестный kind) — GET_GROUP.
fn apply_group_update(env: &Env, st: &mut State, payload: &[u8]) {
    let u = match payloads::dec_group_update(payload) {
        Ok(u) => u,
        Err(_) => {
            if let Some(b) = payload.get(..4) {
                let gid = u32::from_be_bytes(b.try_into().unwrap());
                if env.groups.lock().unwrap().contains_key(&gid) {
                    st.want_group.insert(gid);
                }
            }
            return;
        }
    };
    if st.leaving.contains_key(&u.gid) {
        return;
    }
    let my_pub = env.identity.ed_pub();
    let now = Instant::now();
    let mut events: Vec<Event> = Vec::new();
    {
        let mut g = env.groups.lock().unwrap();
        let Some(gs) = g.get_mut(&u.gid) else { return };
        if gs.rev != u.base_rev {
            // Новее нашей — пропущена дельта; не новее — запоздавший повтор.
            if u.rev > gs.rev {
                st.want_group.insert(u.gid);
            }
            return;
        }
        gs.set_key(u.epoch, u.key, u.revoke_prev, now);
        match &u.delta {
            payloads::GroupDelta::Member(m) => {
                if m.pubkey != my_pub {
                    gs.upsert_member(u.gid, m, now, &mut events);
                }
            }
            payloads::GroupDelta::Removed(pk) => {
                if *pk != my_pub {
                    gs.remove_member(pk);
                }
            }
            payloads::GroupDelta::Meta {
                name,
                owner,
                private,
            } => {
                gs.name = name.clone();
                gs.owner = *owner;
                gs.private = *private;
            }
        }
        gs.rev = u.rev;
    }
    for ev in events {
        env.emit(ev);
    }
}

// ---------- групповые фреймы ----------

/// Приём фрейма группы (раздел 7, правила 1–6). `Some(gid)` — эпоха новее
/// известной: нужен GET_GROUP (сигнал не чаще раза в секунду на группу).
fn handle_group_frame(env: &Env, src: SocketAddr, datagram: &[u8]) -> Option<u32> {
    env.stats.rx_pkts.fetch_add(1, Ordering::Relaxed);
    env.stats
        .rx_bytes
        .fetch_add(datagram.len() as u64, Ordering::Relaxed);
    let (_, h) = proto::parse_group_header(datagram).ok()?;
    let now = Instant::now();
    let is_relay = src == env.server();
    // 1. Группа известна, эпоха — текущая или прошлая в пределах grace.
    let key = {
        let mut g = env.groups.lock().unwrap();
        let gs = g.get_mut(&h.gid)?;
        match gs.rx_key(h.epoch, now) {
            Some(k) => k,
            None => {
                // Сигнал «эпоха новее» — только от правдоподобно подлинных.
                if gs.epoch_hint(&h, src, is_relay, now) {
                    return Some(h.gid);
                }
                return None;
            }
        }
    };
    // 2. Расшифровка (подлинность заголовка — он в AAD).
    let (typ, h, ctr, payload) = proto::open_group(&key, datagram).ok()?;
    // 6. DATA: внутренний источник (IPv4 или IPv6 оверлея) — сам отправитель.
    if typ == proto::grp::DATA && crate::ipv6::source_member(&payload) != Some(h.src) {
        return None;
    }
    let mut became_direct: Option<String> = None;
    let reply = {
        let mut g = env.groups.lock().unwrap();
        let gs = g.get_mut(&h.gid)?;
        // 2. Адресован нам; 3. отправитель — текущий участник, не мы.
        if h.dst != gs.my_ip || h.src == gs.my_ip {
            return None;
        }
        let peer = gs.members.get(&h.src)?;
        // 5. Через релей или с адреса пира, известного от сервера.
        if !is_relay && !peer.knows(src) {
            return None;
        }
        // 4. Окно повторов (того ключа, которым открыт фрейм) — последним:
        //    отвергнутый фрейм счётчик не тратит.
        if !gs.rx_window(&key, h.src)?.commit(ctr) {
            return None;
        }
        let peer = gs.members.get_mut(&h.src)?;
        peer.last_rx = now;
        if !is_relay {
            match peer.direct_addr {
                // Канал поднимается на адресе, откуда первым пришёл ответ.
                None => {
                    peer.direct_addr = Some(src);
                    peer.last_direct = Some(now);
                    became_direct = Some(peer.name.clone());
                }
                Some(a) if a == src => peer.last_direct = Some(now),
                Some(_) => {}
            }
        }
        if typ == proto::grp::PONG
            && let Ok(sent_ms) = payloads::dec_ping(&payload)
        {
            peer.rtt_ms = Some(epoch_ms().saturating_sub(sent_ms));
        }
        match typ {
            proto::grp::PING => Some((proto::grp::PONG, gs.next_frame(h.gid, h.src))),
            // Ответ — KEEPALIVE, не PUNCH: на KEEPALIVE не отвечают, пинг-понга
            // PUNCH↔PUNCH нет. Через релей не отвечаем: PUNCH нужен только для
            // прямого канала.
            proto::grp::PUNCH if !is_relay => {
                Some((proto::grp::KEEPALIVE, gs.next_frame(h.gid, h.src)))
            }
            _ => None,
        }
    };
    if let Some(name) = became_direct {
        env.emit(Event::Direct {
            gid: h.gid,
            ip: h.src,
            name,
        });
    }
    match (typ, reply) {
        (proto::grp::DATA, _) => {
            if let Err(e) = env.tun.inject(&payload)
                && debug()
            {
                env.emit(Event::Error(format!("inject: {e}")));
            }
        }
        (proto::grp::PING, Some((t, (k, rh, c)))) => {
            env.send(&proto::seal_group(&k, t, &rh, c, &payload), src);
        }
        (_, Some((t, (k, rh, c)))) => {
            env.send(&proto::seal_group(&k, t, &rh, c, &[]), src);
        }
        _ => {}
    }
    None
}

/// Через какую группу слать пакет участнику `dst` (протокол v4: адрес один
/// на все группы, и общих с получателем групп может быть несколько). Любая
/// из них доставит — порядок лишь выбирает лучшую: с живым прямым каналом,
/// затем с получателем онлайн, затем меньший gid (стабильный выбор, пока
/// ничего не меняется). `None` — общих групп нет или `dst` — мы сами.
fn pick_group(groups: &HashMap<u32, GroupSess>, dst: u32) -> Option<u32> {
    groups
        .iter()
        .filter(|(_, gs)| gs.my_ip != dst)
        .filter_map(|(gid, gs)| gs.members.get(&dst).map(|p| (*gid, p)))
        .min_by_key(|(gid, p)| (p.direct_addr.is_none(), !p.online, *gid))
        .map(|(gid, _)| gid)
}

/// IP-пакет из адаптера → пиру. Напрямую — только если прямой канал жив;
/// иначе через релей сервера.
fn route_packet(env: &Env, bytes: &[u8]) {
    if bytes.len() > proto::MAX_GROUP_PAYLOAD {
        return;
    }
    // Запрос к встроенному DNS — отвечаем сами, в туннель не шлём.
    if bytes.len() >= 20 && bytes[0] >> 4 == 4 && bytes[16..20] == crate::dns::DNS_ADDR.octets() {
        answer_dns(env, bytes);
        return;
    }
    // IPv4 участника-получателя (для IPv6 — по адресу оверлея).
    let Some(dst) = crate::ipv6::route_target(bytes) else {
        return;
    };
    let (key, h, ctr, target) = {
        let mut g = env.groups.lock().unwrap();
        let Some(gid) = pick_group(&g, dst) else {
            return;
        };
        let gs = g.get_mut(&gid).expect("pick_group вернул свою группу");
        let target = gs
            .members
            .get(&dst)
            .and_then(|p| p.direct_addr)
            .unwrap_or_else(|| env.server());
        let (k, h, c) = gs.next_frame(gid, dst);
        (k, h, c, target)
    };
    let frame = proto::seal_group(&key, proto::grp::DATA, &h, ctr, bytes);
    env.send(&frame, target);
}

/// Ответ встроенного DNS на запрос из адаптера: имена — нормализованные
/// отображаемые имена участников (и свои), `<member>.vl` — по всем группам
/// (меньший gid при совпадении), `<member>.<group>.vl` — в группе.
fn answer_dns(env: &Env, bytes: &[u8]) {
    let (on, my_name) = {
        let c = env.cfg.lock().unwrap();
        (c.dns, crate::dns::normalize_label(&c.name))
    };
    if !on {
        return;
    }
    let reply = {
        let g = env.groups.lock().unwrap();
        crate::dns::handle_packet(bytes, |member, group| {
            let mut best: Option<(u32, u32)> = None;
            for (gid, gs) in g.iter() {
                if group.is_some_and(|n| crate::dns::normalize_label(&gs.name) != n) {
                    continue;
                }
                let ip = if !my_name.is_empty() && my_name == member {
                    Some(gs.my_ip)
                } else {
                    gs.members
                        .values()
                        .filter(|p| crate::dns::normalize_label(&p.name) == member)
                        .map(|p| p.ip)
                        .min()
                };
                if let Some(ip) = ip
                    && best.is_none_or(|(b, _)| *gid < b)
                {
                    best = Some((*gid, ip));
                }
            }
            best.map(|(_, ip)| (Some(ip), crate::ipv6::v6_of(ip).map(|a| a.octets())))
        })
    };
    if let Some(r) = reply
        && let Err(e) = env.tun.inject(&r)
        && debug()
    {
        env.emit(Event::Error(format!("inject dns: {e}")));
    }
}

// ---------- раунды RTT и NAT ----------

/// RTT-зонд онлайн-пирам: прямым — напрямую (это же держит NAT-маппинг),
/// остальным — через релей. Заодно гасит протухшие прямые каналы.
fn rtt_round(env: &Env, connected: bool, now: Instant) {
    let payload = payloads::enc_ping(epoch_ms());
    let mut frames: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
    let mut events: Vec<Event> = Vec::new();
    {
        let server = env.server();
        let mut g = env.groups.lock().unwrap();
        for (gid, gs) in g.iter_mut() {
            let ips: Vec<u32> = gs.members.keys().copied().collect();
            for ip in ips {
                let Some(peer) = gs.members.get_mut(&ip) else {
                    continue;
                };
                if !peer.online {
                    continue;
                }
                if peer.direct_addr.is_some()
                    && peer
                        .last_direct
                        .is_none_or(|t| now.duration_since(t) > DIRECT_TIMEOUT)
                {
                    peer.direct_addr = None;
                    peer.last_direct = None;
                    peer.rtt_ms = None;
                    events.push(Event::DirectLost {
                        gid: *gid,
                        ip,
                        name: peer.name.clone(),
                    });
                }
                let target = match peer.direct_addr {
                    Some(a) => a,
                    None if connected => server,
                    None => continue,
                };
                let (k, h, c) = gs.next_frame(*gid, ip);
                frames.push((
                    proto::seal_group(&k, proto::grp::PING, &h, c, &payload),
                    target,
                ));
            }
        }
    }
    for ev in events {
        env.emit(ev);
    }
    for (f, to) in frames {
        env.send(&f, to);
    }
}

/// PUNCH онлайн-пирам без прямого канала — на endpoint и все кандидаты.
/// Пирам с прямым каналом не шлём ничего: их маппинг держат RTT-зонды.
fn punch_round(env: &Env) {
    let mut frames: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
    {
        let mut g = env.groups.lock().unwrap();
        for (gid, gs) in g.iter_mut() {
            let targets: Vec<(u32, Vec<SocketAddr>)> = gs
                .members
                .iter()
                .filter(|(_, p)| p.online && p.direct_addr.is_none())
                .map(|(ip, p)| (*ip, p.punch_addrs()))
                .collect();
            for (ip, addrs) in targets {
                for a in addrs {
                    let (k, h, c) = gs.next_frame(*gid, ip);
                    frames.push((proto::seal_group(&k, proto::grp::PUNCH, &h, c, &[]), a));
                }
            }
        }
    }
    for (f, to) in frames {
        env.send(&f, to);
    }
}

// ---------- фоновые потоки ----------

#[cfg(windows)]
fn spawn_tun_reader(session: Arc<wintun::Session>, env: Arc<Env>) {
    thread::Builder::new()
        .name("tun".into())
        .spawn(move || {
            while !env.quitting() {
                let pkt = match session.receive_blocking() {
                    Ok(p) => p,
                    Err(_) => break,
                };
                route_packet(&env, pkt.bytes());
            }
        })
        .expect("spawn tun thread");
}

/// Поток чтения TUN на Linux/macOS: poll с таймаутом, чтобы поток (и с ним
/// `Arc` устройства, т.е. fd) завершился вскоре после остановки движка, даже
/// если пакетов нет. `read` возвращает длину пакета, `None` — пакет пропустить.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn spawn_unix_tun_reader<R>(fd: std::os::fd::RawFd, read: R, env: Arc<Env>)
where
    R: Fn(&mut [u8]) -> Result<Option<usize>> + Send + 'static,
{
    thread::Builder::new()
        .name("tun".into())
        .spawn(move || {
            let mut buf = vec![0u8; 65535];
            while !env.quitting() {
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: pfd — валидный указатель на один pollfd.
                let rc = unsafe { libc::poll(&mut pfd, 1, 250) };
                if rc < 0 {
                    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
                if rc == 0 {
                    continue;
                }
                if pfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                    eprintln!("[tun] устройство закрыто или в ошибке");
                    break;
                }
                match read(&mut buf) {
                    Ok(Some(0)) => break,
                    Ok(Some(n)) => route_packet(&env, &buf[..n]),
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("[tun] {e:#}");
                        break;
                    }
                }
            }
        })
        .expect("spawn tun thread");
}

/// Раз в секунду: дельта счётчиков → история для спарклайна.
fn spawn_sampler(env: Arc<Env>) {
    thread::Builder::new()
        .name("sampler".into())
        .spawn(move || {
            let mut prev_rx = 0u64;
            let mut prev_tx = 0u64;
            while !env.quitting() {
                thread::sleep(Duration::from_secs(1));
                let rx = env.stats.rx_bytes.load(Ordering::Relaxed);
                let tx = env.stats.tx_bytes.load(Ordering::Relaxed);
                let d_rx = rx.saturating_sub(prev_rx);
                let d_tx = tx.saturating_sub(prev_tx);
                prev_rx = rx;
                prev_tx = tx;
                env.meta.lock().unwrap().push_hist(d_rx, d_tx);
            }
        })
        .expect("spawn sampler thread");
}

// ---------- CLI-режим (run): движок + печать событий ----------

pub fn run(
    cfg: Arc<Config>,
    server: SocketAddr,
    server_pub: [u8; 32],
    identity: proto::Identity,
    adapter_name: &str,
    dll: Option<String>,
    save: Arc<dyn Fn(&Config) + Send + Sync>,
) -> Result<()> {
    let shared = Arc::new(Mutex::new((*cfg).clone()));
    let eng = start(
        shared,
        server,
        server_pub,
        identity,
        adapter_name,
        dll,
        save,
    )?;
    while let Ok(ev) = eng.events.recv() {
        match ev {
            Event::Connected(s) => eprintln!("[engine] connected to {s}"),
            Event::Disconnected(r) => eprintln!("[engine] {r}; переподключение…"),
            Event::GroupJoined { gid, name, my_ip } => eprintln!(
                "[engine] группа {gid} ({}): мой IP {}",
                name,
                proto::ip_str(my_ip)
            ),
            Event::GroupLeft { gid, name } => eprintln!("[engine] вышли из {gid} ({name})"),
            Event::GroupDeleted { gid, name } => {
                eprintln!("[engine] группа {gid} ({name}) удалена")
            }
            Event::Kicked { gid, name, banned } => eprintln!(
                "[engine] вас {} из группы \"{name}\" (gid {gid})",
                if banned {
                    "забанили и исключили"
                } else {
                    "исключили"
                }
            ),
            Event::PeerOnline { ip, name, .. } => {
                eprintln!("[engine] peer {} ({}) онлайн", proto::ip_str(ip), name)
            }
            Event::PeerOffline { ip, name, .. } => {
                eprintln!("[engine] peer {} ({}) офлайн", proto::ip_str(ip), name)
            }
            Event::Direct { gid, ip, name } => eprintln!(
                "[engine] peer {} ({}), группа {gid}: direct p2p",
                proto::ip_str(ip),
                name
            ),
            Event::DirectLost { gid, ip, name } => eprintln!(
                "[engine] peer {} ({}), группа {gid}: прямой канал потерян, через релей",
                proto::ip_str(ip),
                name
            ),
            // Ответить на месте нельзя: CLI join/decline и TUI — свой HELLO3
            // той же identity, он вытесняет этот сеанс (а реконнект run —
            // их), поэтому — только после остановки run.
            Event::Invite {
                gid,
                group_name,
                from_name,
                expires_in,
                ..
            } => eprintln!(
                "[engine] приглашение: {from_name} приглашает в группу {group_name} (gid {gid}, \
                 истекает через {}); ответить — остановив run: командой join {gid} / decline {gid} или в TUI",
                fmt_secs(expires_in)
            ),
            Event::InviteDeclined {
                gid,
                group_name,
                by_name,
                ..
            } => eprintln!(
                "[engine] {by_name} отклонил приглашение в группу {group_name} (gid {gid})"
            ),
            Event::InviteRevoked { gid } => {
                eprintln!("[engine] приглашение в группу {gid} больше недействительно")
            }
            Event::ServerKeyRotated { addr, new_code } => eprintln!(
                "[engine] ключ сервера {addr} сменён по цепочке ротации, закреплён новый: {new_code}"
            ),
            Event::ServerSwitched { addr, label } => {
                eprintln!("[engine] переключено на сервер {addr} {label}")
            }
            Event::AdminInfo { gid, bans, invites } => eprintln!(
                "[engine] группа {gid}: банов {}, приглашений {}",
                bans.len(),
                invites.len()
            ),
            Event::InvitesSynced { .. } => {}
            Event::FriendGroups { .. } => {}
            Event::Error(e) => eprintln!("[engine] {e}"),
            Event::Notice(n) => eprintln!("[engine] {n}"),
        }
    }
    Ok(())
}

/// Секунды → «3 д 4 ч» / «5 ч 10 мин» / «42 мин» / «15 с».
pub fn fmt_secs(s: u32) -> String {
    let (d, h, m) = (s / 86_400, s / 3600 % 24, s / 60 % 60);
    if d > 0 {
        format!("{d} д {h} ч")
    } else if h > 0 {
        format!("{h} ч {m} мин")
    } else if m > 0 {
        format!("{m} мин")
    } else {
        format!("{s} с")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Сервер для тестов рукопожатия: identity, эфемерный ключ, WELCOME.
    struct Srv {
        id: proto::Identity,
        eph: proto::EphemeralKey,
    }

    impl Srv {
        fn new(id: proto::Identity) -> Self {
            Self {
                id,
                eph: proto::EphemeralKey::generate(),
            }
        }

        fn welcome(
            &self,
            client: &proto::Identity,
            client_eph: &[u8; 32],
            links: &[proto::RotationLink],
        ) -> Vec<u8> {
            proto::Welcome::encode(
                &self.id,
                &self.eph.public(),
                links,
                &client.ed_pub(),
                client_eph,
            )
        }

        fn keys(&self, client: &proto::Identity, client_eph: &[u8; 32]) -> proto::DirKeys {
            proto::session_keys(
                proto::Role::Server,
                &self.id,
                &self.eph,
                &client.x_pub(),
                client_eph,
            )
            .unwrap()
        }
    }

    fn open_frame(sess: &mut CtrlSession, frame: &[u8]) -> Option<Option<(u8, Vec<u8>)>> {
        let (typ, body) = proto::split_frame(frame).unwrap();
        sess.open(typ, body, Instant::now())
    }

    #[test]
    fn рукопожатие_сессия_окно_и_frag() {
        let client = proto::Identity::generate();
        let srv = Srv::new(proto::Identity::generate());
        let hs = Handshake::new();
        let eph = hs.eph.public();

        // WELCOME под чужой eph — молча мимо; под свой, но не от
        // закреплённого ключа — ошибка.
        let other = proto::EphemeralKey::generate();
        let foreign = srv.welcome(&client, &other.public(), &[]);
        assert!(
            accept_welcome(&client, &hs.eph, &srv.id.ed_pub(), &foreign)
                .unwrap()
                .is_none()
        );
        let body = srv.welcome(&client, &eph, &[]);
        let wrong_pin = proto::Identity::generate().ed_pub();
        assert!(accept_welcome(&client, &hs.eph, &wrong_pin, &body).is_err());

        let acc = accept_welcome(&client, &hs.eph, &srv.id.ed_pub(), &body)
            .unwrap()
            .unwrap();
        assert_eq!(acc.pin, proto::PinResolution::Same);
        let sk = srv.keys(&client, &eph);
        let mut sess = CtrlSession::new(hs.eph, acc);

        // Клиент → сервер: c2s, счётчик с 0.
        let f = sess.seal(ctrl::CTRL_PING, &[]);
        let (t, b) = proto::split_frame(&f).unwrap();
        assert_eq!(proto::open_ctrl(&sk.rx, t, b).unwrap(), (0, vec![]));

        // Сервер → клиент: s2c; повтор отсекается окном.
        let pong = proto::seal_ctrl(&sk.tx, 0, ctrl::CTRL_PONG, &[]);
        assert_eq!(
            open_frame(&mut sess, &pong),
            Some(Some((ctrl::CTRL_PONG, vec![])))
        );
        assert_eq!(open_frame(&mut sess, &pong), None, "повтор");
        // Чужой ключ — не подлинный.
        assert_eq!(
            open_frame(
                &mut sess,
                &proto::seal_ctrl(&[9; 32], 5, ctrl::CTRL_PONG, &[])
            ),
            None
        );

        // FRAG: куски в обратном порядке собираются в одно сообщение.
        let big: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let mut msg_id = 0u32;
        let parts = proto::frag::prepare(&mut msg_id, ctrl::GROUP_STATE, &big).unwrap();
        assert!(parts.len() > 1);
        let frames: Vec<Vec<u8>> = parts
            .iter()
            .enumerate()
            .map(|(i, (t, p))| proto::seal_ctrl(&sk.tx, 1 + i as u64, *t, p))
            .collect();
        let mut got = None;
        for (i, f) in frames.iter().enumerate().rev() {
            match open_frame(&mut sess, f) {
                Some(Some(m)) => got = Some(m),
                Some(None) => assert!(i > 0, "последний кусок собирает сообщение"),
                None => panic!("кусок {i} не принят"),
            }
        }
        assert_eq!(got, Some((ctrl::GROUP_STATE, big)));
    }

    #[test]
    fn повторный_welcome_под_тот_же_eph() {
        let client = proto::Identity::generate();
        let id = proto::Identity::generate();
        let s1 = Srv::new(id.clone());
        let s2 = Srv::new(id.clone());
        let hs = Handshake::new();
        let eph = hs.eph.public();
        let acc1 = accept_welcome(
            &client,
            &hs.eph,
            &id.ed_pub(),
            &s1.welcome(&client, &eph, &[]),
        )
        .unwrap()
        .unwrap();
        let mut sess = CtrlSession::new(hs.eph, acc1);
        let w2 = s2.welcome(&client, &eph, &[]);
        let acc2 = accept_welcome(&client, &sess.eph, &id.ed_pub(), &w2)
            .unwrap()
            .unwrap();
        assert!(sess.add(acc2), "новая серверная сессия — новые ключи");
        let again = accept_welcome(&client, &sess.eph, &id.ed_pub(), &w2)
            .unwrap()
            .unwrap();
        assert!(!sess.add(again), "повтор того же WELCOME ничего не меняет");

        // Отправка — новейшими ключами…
        let (k1, k2) = (s1.keys(&client, &eph), s2.keys(&client, &eph));
        let f = sess.seal(ctrl::CTRL_PING, &[]);
        let (t, b) = proto::split_frame(&f).unwrap();
        assert!(proto::open_ctrl(&k2.rx, t, b).is_ok());
        // …пока сервер не ответит прежними: живая сессия — та, что отвечает.
        let m = proto::seal_ctrl(&k1.tx, 0, ctrl::CTRL_PONG, &[]);
        assert!(matches!(open_frame(&mut sess, &m), Some(Some(_))));
        let f = sess.seal(ctrl::CTRL_PING, &[]);
        let (t, b) = proto::split_frame(&f).unwrap();
        assert!(proto::open_ctrl(&k1.rx, t, b).is_ok());
    }

    #[test]
    fn каждый_подписанный_welcome_держится_до_ответа_сервера() {
        // PROTOCOL.md, раздел 2: под один eph — несколько WELCOME (сервер
        // пересоздал сессию на HELLO3 с другого адреса). Клиент держит все
        // наборы; отправка — тем, под которым сервер последним ответил.
        let client = proto::Identity::generate();
        let id = proto::Identity::generate();
        let (s1, s2) = (Srv::new(id.clone()), Srv::new(id.clone()));
        let hs = Handshake::new();
        let eph = hs.eph.public();
        let acc1 = accept_welcome(
            &client,
            &hs.eph,
            &id.ed_pub(),
            &s1.welcome(&client, &eph, &[]),
        )
        .unwrap()
        .unwrap();
        let mut sess = CtrlSession::new(hs.eph, acc1);
        let (k1, k2) = (s1.keys(&client, &eph), s2.keys(&client, &eph));
        // Первая сессия ответила…
        let m = proto::seal_ctrl(&k1.tx, 0, ctrl::CTRL_PONG, &[]);
        assert!(matches!(open_frame(&mut sess, &m), Some(Some(_))));
        // …затем WELCOME второй: набор добавлен, но отправка ещё первым.
        let acc2 = accept_welcome(
            &client,
            &sess.eph,
            &id.ed_pub(),
            &s2.welcome(&client, &eph, &[]),
        )
        .unwrap()
        .unwrap();
        assert!(sess.add(acc2));
        let f = sess.seal(ctrl::CTRL_PING, &[]);
        let (t, b) = proto::split_frame(&f).unwrap();
        assert!(proto::open_ctrl(&k1.rx, t, b).is_ok());
        // Вторая сессия ответила — отправка переходит на её ключи, а фреймы
        // первой по-прежнему открываются.
        std::thread::sleep(Duration::from_millis(2));
        let m = proto::seal_ctrl(&k2.tx, 0, ctrl::GROUP_LIST, &[]);
        assert!(matches!(open_frame(&mut sess, &m), Some(Some(_))));
        let f = sess.seal(ctrl::CTRL_PING, &[]);
        let (t, b) = proto::split_frame(&f).unwrap();
        assert!(proto::open_ctrl(&k2.rx, t, b).is_ok());
        let m = proto::seal_ctrl(&k1.tx, 1, ctrl::CTRL_PONG, &[]);
        assert!(matches!(open_frame(&mut sess, &m), Some(Some(_))));
    }

    #[test]
    fn ротация_ключа_сервера_по_цепочке() {
        let client = proto::Identity::generate();
        let old = proto::Identity::generate();
        let new = proto::Identity::generate();
        let link = proto::handshake::make_link(&old, &new);
        let srv = Srv::new(new.clone());
        let hs = Handshake::new();
        let body = srv.welcome(&client, &hs.eph.public(), &[link]);
        let acc = accept_welcome(&client, &hs.eph, &old.ed_pub(), &body)
            .unwrap()
            .unwrap();
        assert_eq!(
            acc.pin,
            proto::PinResolution::Rotated {
                new_ed: new.ed_pub()
            }
        );
        // Цепочка не от закреплённого — ошибка.
        let stranger = proto::Identity::generate().ed_pub();
        assert!(accept_welcome(&client, &hs.eph, &stranger, &body).is_err());
    }

    #[test]
    fn cookie_один_hello3_на_challenge() {
        let client = proto::Identity::generate();
        let mut hs = Handshake::new();
        let ch = handshake::enc_challenge(&[7; 16]);
        let t0 = Instant::now();
        let f = hs
            .on_challenge(&client, "a", 0, &ch, t0)
            .expect("HELLO3 с cookie");
        let (typ, body) = proto::split_frame(&f).unwrap();
        assert_eq!(typ, ctrl::HELLO3);
        let h = proto::Hello3::decode(body).unwrap();
        h.verify().unwrap();
        assert_eq!((h.cookie, h.eph_pub), (Some([7; 16]), hs.eph.public()));
        // Поток CHALLENGE не превращается в поток HELLO3.
        assert!(
            hs.on_challenge(&client, "a", 0, &ch, t0 + Duration::from_millis(10))
                .is_none()
        );
        assert!(
            hs.on_challenge(&client, "a", 0, &ch, t0 + COOKIE_GAP)
                .is_some()
        );
        assert!(
            hs.on_challenge(&client, "a", 0, b"junk", t0 + COOKIE_GAP * 3)
                .is_none()
        );
        // Без CHALLENGE, но с RESET — похоже на v2-сервер.
        let mut v2 = Handshake::new();
        v2.saw_reset = true;
        assert!(v2.timeout_msg().contains("v2"));
        assert!(!hs.timeout_msg().contains("v2"));
    }

    fn state(gid: u32, epoch: u32, key: u8) -> payloads::GroupState {
        payloads::GroupState {
            gid,
            rev: 1,
            epoch,
            revoke_prev: false,
            name: "g".into(),
            owner: [1; 32],
            private: false,
            key: [key; 32],
            deleted: false,
            my_ip: 0x6442_0102,
            members: Vec::new(),
        }
    }

    #[test]
    fn эпохи_ключа_группы_grace_и_revoke() {
        let now = Instant::now();
        let mut g = GroupSess::new(&state(1, 5, 1), now, KeyLog::default());
        assert_eq!(g.rx_key(5, now), Some([1; 32]));
        assert_eq!(g.next_frame(1, 2).2, 0);
        assert_eq!(g.next_frame(1, 2).2, 1);
        assert!(g.rx_window(&[1; 32], 9).is_some());

        // Ротация без revoke: прошлый ключ ещё принимается, счётчик — с 0.
        g.set_key(6, [2; 32], false, now);
        let (k, h, c) = g.next_frame(1, 2);
        assert_eq!((k, h.epoch, c), ([2; 32], 6, 0));
        assert_eq!(g.rx_key(5, now), Some([1; 32]));
        assert_eq!(
            g.rx_key(5, now + proto::PREV_KEY_GRACE),
            None,
            "grace истёк"
        );
        assert_eq!(g.rx_key(4, now), None);
        // Окно отправителя переехало вместе с прошлым ключом.
        assert!(g.prev.as_ref().is_some_and(|p| p.st.rx.contains_key(&9)));

        // revoke_prev — прошлый забывается сразу.
        g.set_key(7, [3; 32], true, now);
        assert_eq!(g.rx_key(6, now), None);
        assert_eq!(g.rx_key(7, now), Some([3; 32]));
    }

    #[test]
    fn скачок_эпохи_не_сохраняет_прошлый_ключ() {
        let now = Instant::now();
        // Скачок 5 -> 7: промежуточная ротация 6 могла быть KICK с revoke_prev —
        // ключ эпохи 5 не принимается даже без revoke_prev в эпохе 7.
        let mut g = GroupSess::new(&state(1, 5, 1), now, KeyLog::default());
        g.set_key(7, [3; 32], false, now);
        assert!(g.prev.is_none());
        assert_eq!(g.rx_key(5, now), None);
        assert_eq!(g.rx_key(7, now), Some([3; 32]));

        // Ровно +1, но с revoke_prev — тоже без grace.
        let mut g = GroupSess::new(&state(1, 5, 1), now, KeyLog::default());
        g.set_key(6, [2; 32], true, now);
        assert!(g.prev.is_none());
        assert_eq!(g.rx_key(5, now), None);

        // Ровно +1 без revoke_prev — grace сохраняется.
        let mut g = GroupSess::new(&state(1, 5, 1), now, KeyLog::default());
        g.set_key(6, [2; 32], false, now);
        assert_eq!(g.rx_key(5, now), Some([1; 32]));
        // Затем скачок 6 -> 8: прежний prev (5) и текущий (6) не остаются.
        g.set_key(8, [4; 32], false, now);
        assert!(g.prev.is_none());
        assert_eq!(g.rx_key(5, now), None);
        assert_eq!(g.rx_key(6, now), None);
        // Тот же ключ со скачком эпохи — prev тоже забывается.
        let mut g = GroupSess::new(&state(1, 5, 1), now, KeyLog::default());
        g.set_key(6, [2; 32], false, now);
        g.set_key(8, [2; 32], false, now);
        assert!(g.prev.is_none());
    }

    #[test]
    fn группа_для_пакета_выбирается_по_получателю() {
        let t0 = Instant::now();
        let (me, peer, other) = (0x6442_0102, 0x6442_0103, 0x6442_0104);
        let peer_sess = |ip: u32, online: bool, direct: bool| PeerSess {
            pubkey: [ip as u8; 32],
            name: "p".into(),
            status: String::new(),
            online,
            ip,
            endpoint: None,
            candidates: Vec::new(),
            direct_addr: direct.then(|| "10.0.0.2:4000".parse().unwrap()),
            last_rx: t0,
            last_direct: None,
            rtt_ms: None,
        };
        let mut groups: HashMap<u32, GroupSess> = HashMap::new();
        for gid in [3, 5, 9] {
            let gs = GroupSess::new(&state(gid, 1, 1), t0, KeyLog::default());
            groups.insert(gid, gs);
        }
        let put = |groups: &mut HashMap<u32, GroupSess>, gid: u32, p: PeerSess| {
            groups.get_mut(&gid).unwrap().members.insert(p.ip, p);
        };
        // Адрес один на все группы: получатель — в 5 и 9, не в 3.
        put(&mut groups, 5, peer_sess(peer, true, false));
        put(&mut groups, 9, peer_sess(peer, true, false));
        put(&mut groups, 3, peer_sess(other, true, false));
        assert_eq!(pick_group(&groups, peer), Some(5), "меньший gid");
        assert_eq!(pick_group(&groups, other), Some(3));
        assert_eq!(pick_group(&groups, 0x6442_0199), None, "общих групп нет");
        assert_eq!(pick_group(&groups, me), None, "сами себе не шлём");
        // Живой прямой канал важнее gid, онлайн — важнее офлайн.
        put(&mut groups, 9, peer_sess(peer, true, true));
        assert_eq!(pick_group(&groups, peer), Some(9));
        put(&mut groups, 9, peer_sess(peer, false, false));
        assert_eq!(pick_group(&groups, peer), Some(5));
        // Вышли из группы 5 — пакет идёт через 9 (раньше адрес получателя в
        // группе 5 указывал только на неё).
        groups.remove(&5);
        assert_eq!(pick_group(&groups, peer), Some(9));
    }

    #[test]
    fn сигнал_эпохи_только_от_подлинных_и_с_пределом() {
        let t0 = Instant::now();
        let mut g = GroupSess::new(&state(1, 5, 1), t0, KeyLog::default());
        let peer_addr: SocketAddr = "10.0.0.2:4000".parse().unwrap();
        let stranger: SocketAddr = "203.0.113.9:4000".parse().unwrap();
        g.members.insert(
            0x6442_0103,
            PeerSess {
                pubkey: [2; 32],
                name: "p".into(),
                status: String::new(),
                online: true,
                ip: 0x6442_0103,
                endpoint: None,
                candidates: vec![peer_addr],
                direct_addr: None,
                last_rx: t0,
                last_direct: None,
                rtt_ms: None,
            },
        );
        let h = |src, epoch| proto::GroupHeader {
            gid: 1,
            src,
            dst: 0x6442_0102,
            epoch,
        };
        // Посторонний адрес, неизвестный src, сам клиент как src — не повод.
        for i in 0..100 {
            let t = t0 + Duration::from_secs(i);
            assert!(!g.epoch_hint(&h(0x6442_0103, 9), stranger, false, t));
            assert!(!g.epoch_hint(&h(0x6442_0199, 9), peer_addr, false, t));
            assert!(!g.epoch_hint(&h(0x6442_0102, 9), peer_addr, false, t));
        }
        // Эпоха не новее — тоже нет.
        assert!(!g.epoch_hint(&h(0x6442_0103, 5), peer_addr, false, t0));
        // С кандидата участника — да; не чаще паузы.
        assert!(g.epoch_hint(&h(0x6442_0103, 9), peer_addr, false, t0));
        assert!(!g.epoch_hint(
            &h(0x6442_0103, 9),
            peer_addr,
            false,
            t0 + Duration::from_millis(500)
        ));
        // Эпоха так и не пришла: паузы растут (1, 2, 4, … с), не каждую секунду.
        let mut fired = 1;
        for ms in (0..600_000).step_by(100) {
            if g.epoch_hint(
                &h(0x6442_0103, 9),
                "10.9.9.9:1".parse().unwrap(),
                true,
                t0 + Duration::from_millis(ms),
            ) {
                fired += 1;
            }
        }
        assert!(fired <= 16, "сигналов за 10 минут: {fired}");
        // Эпоха подтвердилась — пауза сбрасывается.
        let t1 = t0 + Duration::from_secs(700);
        g.set_key(9, [9; 32], false, t1);
        assert!(g.epoch_hint(&h(0x6442_0103, 10), peer_addr, true, t1));
        g.set_key(10, [10; 32], false, t1);
        assert!(g.epoch_hint(
            &h(0x6442_0103, 11),
            peer_addr,
            true,
            t1 + Duration::from_secs(1)
        ));
    }

    #[test]
    fn сигнал_эпохи_жёсткий_предел_в_минуту() {
        // Даже если каждая эпоха подтверждается (пауза всё время сбрасывается),
        // сигналов за минуту — не больше HINT_MAX_PER_WINDOW.
        let t0 = Instant::now();
        let mut g = GroupSess::new(&state(1, 1, 1), t0, KeyLog::default());
        let relay: SocketAddr = "198.51.100.1:7000".parse().unwrap();
        let mut fired = 0;
        for i in 0..60u32 {
            let t = t0 + Duration::from_secs(i as u64);
            let e = g.epoch + 1;
            if g.epoch_hint(
                &proto::GroupHeader {
                    gid: 1,
                    src: 7,
                    dst: 0x6442_0102,
                    epoch: e,
                },
                relay,
                true,
                t,
            ) {
                fired += 1;
            }
            g.set_key(e, [(e % 250) as u8 + 2; 32], false, t);
        }
        assert_eq!(fired, HINT_MAX_PER_WINDOW);
        // Окно сдвинулось — снова можно.
        let t = t0 + HINT_WINDOW + Duration::from_secs(1);
        let e = g.epoch + 1;
        assert!(g.epoch_hint(
            &proto::GroupHeader {
                gid: 1,
                src: 7,
                dst: 0x6442_0102,
                epoch: e
            },
            relay,
            true,
            t
        ));
    }

    #[test]
    fn возврат_к_ключу_продолжает_счётчик() {
        let now = Instant::now();
        let log = KeyLog::default();
        let mut g = GroupSess::new(&state(1, 5, 1), now, log.clone());
        for _ in 0..3 {
            g.next_frame(1, 2);
        }
        // Запоздавшее состояние вернуло старый ключ — nonce не повторяется.
        g.set_key(6, [2; 32], false, now);
        g.set_key(5, [1; 32], false, now);
        assert_eq!(g.next_frame(1, 2).2, 3);
        // Группа забыта и создана заново с тем же ключом (вход без ротации).
        drop(g);
        let mut g2 = GroupSess::new(&state(1, 5, 1), now, log.clone());
        assert_eq!(g2.next_frame(1, 2).2, 4);
        let mut g3 = GroupSess::new(&state(2, 1, 9), now, log);
        assert_eq!(g3.next_frame(2, 2).2, 0, "новый ключ — с 0");
    }

    #[test]
    fn окна_приёма_привязаны_к_ключу_а_не_к_эпохе() {
        let now = Instant::now();
        let log = KeyLog::default();
        let mut g = GroupSess::new(&state(1, 5, 1), now, log.clone());
        assert!(g.rx_window(&[1; 32], 9).unwrap().commit(100));

        // Сервер упал и выдал ту же эпоху 5 с новым ключом: окна прежнего
        // ключа не наследуются — счётчики пира под новым ключом с нуля.
        g.set_key(5, [2; 32], false, now);
        assert_eq!(g.rx_key(5, now), Some([2; 32]));
        assert!(
            g.rx_window(&[2; 32], 9).unwrap().commit(0),
            "новый ключ — свежее окно"
        );
        assert!(
            g.rx_window(&[1; 32], 9).is_none(),
            "прежний ключ той же эпохи не принимается"
        );

        // Возврат к ранее использованному ключу — его окна возвращаются:
        // записанный фрейм под ним повторно не проходит.
        g.set_key(6, [1; 32], true, now);
        assert!(
            !g.rx_window(&[1; 32], 9).unwrap().commit(100),
            "повтор под старым ключом"
        );
        assert!(g.rx_window(&[1; 32], 9).unwrap().commit(101));

        // И после пересоздания группы (окна в KeyLog).
        drop(g);
        let mut g2 = GroupSess::new(&state(1, 5, 2), now, log);
        assert!(
            !g2.rx_window(&[2; 32], 9).unwrap().commit(0),
            "окно ключа пережило пересоздание"
        );
    }

    #[test]
    fn участник_прямой_канал_только_на_известном_адресе() {
        let now = Instant::now();
        let mut g = GroupSess::new(&state(1, 1, 1), now, KeyLog::default());
        let ep: SocketAddr = "1.2.3.4:5000".parse().unwrap();
        let lan: SocketAddr = "192.168.1.5:5000".parse().unwrap();
        let mut m = payloads::MemberInfo {
            pubkey: [5; 32],
            name: "b".into(),
            ip: 0x6442_0103,
            online: true,
            status: String::new(),
            endpoint: Some(ep),
            candidates: vec![lan, ep],
        };
        let mut ev = Vec::new();
        g.upsert_member(1, &m, now, &mut ev);
        assert!(matches!(ev.as_slice(), [Event::PeerOnline { .. }]));
        let p = &g.members[&m.ip];
        assert!(p.knows(ep) && p.knows(lan) && !p.knows("5.6.7.8:1".parse().unwrap()));
        assert_eq!(p.punch_addrs(), vec![ep, lan]);

        // Канал на LAN-кандидате переживает обновление с тем же адресом…
        g.members.get_mut(&m.ip).unwrap().direct_addr = Some(lan);
        ev.clear();
        g.upsert_member(1, &m, now, &mut ev);
        assert_eq!(g.members[&m.ip].direct_addr, Some(lan));
        assert!(ev.is_empty());
        // …и гаснет, когда сервер этот адрес больше не знает.
        m.candidates.clear();
        g.upsert_member(1, &m, now, &mut ev);
        assert_eq!(g.members[&m.ip].direct_addr, None);
        assert!(matches!(ev.as_slice(), [Event::DirectLost { .. }]));

        // Окна приёма живут с ключом, а не с участником: повтор его
        // фреймов под этим ключом и после выхода отвергается.
        assert!(g.rx_window(&[1; 32], m.ip).is_some());
        g.remove_member(&m.pubkey);
        assert!(g.members.is_empty() && g.cur.rx.contains_key(&m.ip));
    }

    #[test]
    fn формат_длительности() {
        assert_eq!(fmt_secs(15), "15 с");
        assert_eq!(fmt_secs(42 * 60), "42 мин");
        assert_eq!(fmt_secs(5 * 3600 + 600), "5 ч 10 мин");
        assert_eq!(fmt_secs(7 * 86_400), "7 д 0 ч");
    }
}
