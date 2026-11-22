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

use crate::path::{self, PathKind, PathTable};
use crate::store::{Config, TransportMode};
use crate::tcp_link::{self, TcpLink};
use crate::{dht, federation, mesh, probe};

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
/// Пересчёт путей доставки (стоимость/гистерезис, §3.6).
const PATHS_EVERY: Duration = Duration::from_secs(10);
/// Шаг mesh-таймеров (сессии, DHT-пинги, повторы forward).
const MESH_EVERY: Duration = Duration::from_secs(1);
/// `MESH_INFO` серверу: сразу после WELCOME и далее раз в 5 минут (§4.1).
const MESH_INFO_EVERY: Duration = Duration::from_secs(5 * 60);
/// `SERVER_HINT` серверу (T4): сразу после WELCOME и далее не чаще раза в
/// 5 минут. Старый сервер тип не знает и молча роняет — шлём всем.
const SERVER_HINT_EVERY: Duration = Duration::from_secs(5 * 60);
/// Обслуживание DHT (устаревание, сохранение контактов) раз в 10 секунд.
/// Кэш `mesh.contacts` переживает рестарт процесса и мёртвый сервер в уже
/// запущенном клиенте, но сам по себе входа в сеть не даёт: ключи групп,
/// состав и `my_ip` выдаёт сервер. Запись файла — только когда таблица
/// реально изменилась (issue #27).
const DHT_EVERY: Duration = Duration::from_secs(10);
/// Поиск `find_node` для меш-пира не чаще раза в 5 минут. Спрашивать есть кого
/// только при непустой таблице: первый источник контактов — `MESH_SEED` и
/// состав групп от сервера, кэш `mesh.contacts` — лишь подсказка.
const LOOKUP_EVERY: Duration = Duration::from_secs(5 * 60);
/// Сколько кандидатов-реле пробуем на один кадр (L2).
const RELAY_TRIES: usize = 3;
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
    /// Статический x25519-ключ пира из mesh-секции `GROUP_STATE` (§4.2):
    /// `None` — клиент mesh не публиковал/сервер его не знает.
    pub mesh_x: Option<[u8; 32]>,
    /// Возможности mesh (`mesh::caps::*`) из mesh-секции.
    pub mesh_caps: u8,
}

impl PeerSess {
    /// Пир умеет mesh (можно инициировать рукопожатие, §3.2).
    pub fn mesh_capable(&self) -> bool {
        self.mesh_x.is_some() && proto::mesh::caps::has(self.mesh_caps, proto::mesh::caps::MESH)
    }

    /// Готов релеить чужой трафик.
    pub fn can_relay(&self) -> bool {
        self.mesh_capable() && proto::mesh::caps::has(self.mesh_caps, proto::mesh::caps::RELAY)
    }
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

/// Сколько последних seq потока помнит кольцо дедупа (issue #25).
pub const DEDUP_WINDOW: usize = 64;
/// Сколько seq считается повтором, мс: дольше — это уже не дублирование
/// путей, а запоздавший/подделанный кадр (его отсечёт окно повторов).
pub const DEDUP_TTL_MS: u32 = 2_000;
/// Предел числа потоков в кольце (LRU по времени последнего кадра).
pub const DEDUP_FLOWS_MAX: usize = 64;
/// Поток без кадров дольше — выбрасывается из кольца, мс.
pub const DEDUP_FLOW_IDLE_MS: u32 = 10_000;

/// Запись кольца дедупа: сквозной seq кадра (счётчик AEAD группы) и время.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DedupEntry {
    seq: u64,
    at_ms: u32,
}

/// Кольцо дедупа одного потока (`src_ip`) на выходе (issue #25): последние
/// [`DEDUP_WINDOW`] seq, принятых не дольше [`DEDUP_TTL_MS`] назад.
///
/// Живёт в [`KeyState`], поэтому принадлежит ключу: при смене ключа кольцо
/// пустое и счётчики начинаются с нуля — как у окон повторов.
#[derive(Debug)]
struct DedupRing {
    entries: [Option<DedupEntry>; DEDUP_WINDOW],
    /// Куда пишется следующая запись (кольцевой буфер).
    next: usize,
    /// Время последнего принятого кадра потока (для LRU по потокам).
    last_ms: u32,
}

impl Default for DedupRing {
    fn default() -> Self {
        Self {
            entries: [None; DEDUP_WINDOW],
            next: 0,
            last_ms: 0,
        }
    }
}

impl DedupRing {
    /// `seq` уже доставлен этим потоком не дольше [`DEDUP_TTL_MS`] назад.
    fn seen(&self, seq: u64, now_ms: u32) -> bool {
        self.entries
            .iter()
            .flatten()
            .any(|e| e.seq == seq && now_ms.wrapping_sub(e.at_ms) < DEDUP_TTL_MS)
    }

    /// Запомнить доставленный `seq`.
    fn record(&mut self, seq: u64, now_ms: u32) {
        self.entries[self.next] = Some(DedupEntry { seq, at_ms: now_ms });
        self.next = (self.next + 1) % DEDUP_WINDOW;
        self.last_ms = now_ms;
    }
}

/// Кольца дедупа под ключом группы: src_ip → кольцо.
type RxDedup = HashMap<u32, DedupRing>;

/// Что клиент накопил под ключом группы: следующий счётчик отправки, окна
/// приёма и кольца дедупа на выходе.
#[derive(Default)]
struct KeyState {
    tx: u64,
    rx: RxWindows,
    dedup: RxDedup,
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
        if st.tx == 0 && st.rx.is_empty() && st.dedup.is_empty() {
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
    /// uuid группы в федерации (`FED_GROUPS`, T4): `Some` — группа пришла с
    /// другого сервера, в UI у неё метка «федерация». `None` — своя группа
    /// (сервер uuid не сообщает) или сервер без федерации.
    pub fed_uuid: Option<[u8; 16]>,
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
            fed_uuid: None,
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

    /// Кольцо дедупа потока `src` под ключом `key` (текущим или прошлым).
    /// Память ограничена: простаивающие дольше [`DEDUP_FLOW_IDLE_MS`] потоки
    /// выбрасываются, при переполнении — самый старый по последнему кадру
    /// (LRU), так что число потоков не больше [`DEDUP_FLOWS_MAX`].
    fn rx_dedup(&mut self, key: &proto::SymKey, src: u32, now_ms: u32) -> Option<&mut DedupRing> {
        let map = if *key == self.key {
            &mut self.cur.dedup
        } else {
            &mut self.prev.as_mut().filter(|p| p.key == *key)?.st.dedup
        };
        if !map.contains_key(&src) {
            map.retain(|_, r| now_ms.wrapping_sub(r.last_ms) < DEDUP_FLOW_IDLE_MS);
            while map.len() >= DEDUP_FLOWS_MAX {
                let Some(oldest) = map.iter().min_by_key(|(_, r)| r.last_ms).map(|(ip, _)| *ip)
                else {
                    break;
                };
                map.remove(&oldest);
            }
        }
        Some(map.entry(src).or_default())
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
            // Mesh-метаданные придут хвостом GROUP_STATE сразу за участниками;
            // до него сохраняем прежние (адрес/ключ пира не менялся).
            mesh_x: prev.and_then(|p| p.mesh_x),
            mesh_caps: prev.map(|p| p.mesh_caps).unwrap_or(0),
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

    /// Применить mesh-хвост `GROUP_STATE` (§4.2): x-ключ и caps по адресу
    /// оверлея. Отсутствующие в хвосте участники — «не публиковали»
    /// (`None`/0), даже если раньше публиковали: сервер отдаёт хвост только
    /// для тех, кто сейчас онлайн.
    fn apply_mesh_section(&mut self, mesh: &[payloads::MeshEntry]) {
        let mut by_ip: HashMap<u32, ([u8; 32], u8)> =
            mesh.iter().map(|e| (e.ip, (e.x_pub, e.caps))).collect();
        for (ip, p) in self.members.iter_mut() {
            match by_ip.remove(ip) {
                Some((x, caps)) => {
                    p.mesh_x = Some(x);
                    p.mesh_caps = caps;
                }
                None => {
                    p.mesh_x = None;
                    p.mesh_caps = 0;
                }
            }
        }
    }

    /// Mesh-хвост `GROUP_UPDATE`: у записи хвоста `ip == 0` (адрес в дельте
    /// `GroupDelta::Member`), поэтому цель ищется по ключу.
    fn apply_mesh_tail_for(&mut self, pubkey: &[u8; 32], mesh: &[payloads::MeshEntry]) {
        let Some(entry) = mesh.first() else {
            return;
        };
        if let Some(p) = self.members.values_mut().find(|p| p.pubkey == *pubkey) {
            p.mesh_x = Some(entry.x_pub);
            p.mesh_caps = entry.caps;
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
    /// Отправлено дублированных копий сверх первой (issue #25).
    pub dup_sent: AtomicU64,
    /// Отброшено дубликатов на выходе (issue #25): пришёл второй экземпляр
    /// кадра, который уже доставлен.
    pub dup_dropped: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self {
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_pkts: AtomicU64::new(0),
            tx_pkts: AtomicU64::new(0),
            dup_sent: AtomicU64::new(0),
            dup_dropped: AtomicU64::new(0),
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

/// Доступная федерированная группа (`FED_GROUPS`, T4): `uuid` — имя группы
/// в федерации (по нему `JOIN_FED`), `gid` — её локальный номер на этом
/// сервере. `payloads::FedGroup` в `Event`/`Meta` не годится: у него нет
/// serde (форма событий IPC демона — JSON).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FedGroupInfo {
    pub uuid: [u8; 16],
    pub gid: u32,
    pub name: String,
    pub owner: [u8; 32],
    pub members: u16,
}

impl From<&payloads::FedGroup> for FedGroupInfo {
    fn from(g: &payloads::FedGroup) -> Self {
        Self {
            uuid: g.uuid,
            gid: g.gid,
            name: g.name.clone(),
            owner: g.owner,
            members: g.members,
        }
    }
}

impl FedGroupInfo {
    /// Короткий hex uuid — для логов и подсказок UI.
    pub fn uuid_short(&self) -> String {
        proto::hex_of(&self.uuid)[..8].to_string()
    }
}

/// Метаданные для статус-бара UI.
pub struct Meta {
    pub connected: bool,
    /// Через что сейчас идёт связь с сервером (UDP или TCP-фолбэк).
    pub transport: Transport,
    pub server: SocketAddr,
    pub server_label: String,
    pub group_list: Vec<payloads::GroupSummary>,
    /// Доступные федерированные группы (`FED_GROUPS`, T4): по возрастанию
    /// локального gid. Пусто — сервер без федерации или реплик нет.
    pub fed_groups: Vec<FedGroupInfo>,
    /// Байт/с по последним секундам (для спарклайна).
    pub rx_hist: VecDeque<u64>,
    pub tx_hist: VecDeque<u64>,
    pub started: Instant,
    /// RTT до сервера по CTRL_PONG с меткой (этап 9).
    pub server_rtt_ms: Option<u32>,
    /// Mesh включён клиентом.
    pub mesh_enabled: bool,
    /// Байт, отрелеенных этим клиентом через mesh (T3).
    pub relay_bytes: u64,
    /// Живых mesh-сессий (для статус-бара и снимка).
    pub mesh_sessions: u32,
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
    /// Доступные федерированные группы сервера (`FED_GROUPS`, T4) — снимок
    /// списка целиком; пустой список — реплик больше нет. `Cmd::JoinFed`
    /// входит в группу по `uuid`.
    FedGroups {
        groups: Vec<FedGroupInfo>,
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
    /// Результат проверки пинга сервера.
    ServerPingResult {
        addr: SocketAddr,
        rtt_ms: Option<u32>,
        success: bool,
    },
    /// Выбран другой путь доставки до участника (этап 9, §3.6).
    PathChanged {
        ip: u32,
        name: String,
        path: PathKind,
        rtt_ms: Option<u32>,
    },
    /// Доступных путей до участника не осталось: трафик не доставляется.
    PathLost {
        ip: u32,
        name: String,
    },
    /// Результат пробы сервера (`Cmd::ProbeServer`, §3.7). Для недоступного
    /// сервера — `success: false`; `key_match` — сверка с закреплённым ключом.
    ProbeResult {
        addr: SocketAddr,
        success: bool,
        rtt_ms: Option<u32>,
        key_match: Option<bool>,
    },
    /// Счётчик релея через пиров (T3): всего байт и активных реле-пиров.
    RelayStats {
        bytes_total: u64,
        peers: u32,
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
    /// Вход в федерированную группу по uuid (`JOIN_FED`, T4). Ответ —
    /// обычный `GROUP_STATE` (и `FedGroups`); ошибка — `Event::Error`.
    JoinFed {
        uuid: [u8; 16],
    },
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
    /// Проверить пинг до сервера (CTRL_PING/CTRL_PONG).
    PingServer {
        addr: SocketAddr,
    },
    /// Закрепить путь до участника (сильнее автоматики; пишется в конфиг).
    PinPath {
        ip: u32,
        path: PathKind,
    },
    /// Снять закрепление пути.
    UnpinPath {
        ip: u32,
    },
    /// Разрешить/запретить релей чужого трафика через себя (L2).
    SetRelayEnabled(bool),
    /// Включить/выключить mesh-оверлей.
    SetMeshEnabled(bool),
    /// Проба доступности сервера без сессии (PROBE_REQ, §3.7).
    ProbeServer {
        addr: SocketAddr,
    },
    Quit,
}

/// Приёмник исходящих IP-пакетов (см. [`Engine::ip_sink`]).
pub type IpSink = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// Ответы `MESH_NODES` из потока приёма → поток движка: (id поиска, контакты).
type MeshFinds = Arc<Mutex<Vec<(u64, Vec<dht::Contact>)>>>;

/// Всё, что нужно UI от движка.
pub struct Engine {
    pub groups: Groups,
    pub meta: Arc<Mutex<Meta>>,
    pub stats: Arc<Stats>,
    /// Таблица путей доставки (этап 9): путь в снимке состояния и будущий
    /// выбор транспорта (T3).
    pub paths: Arc<PathTable>,
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

    /// Сколько контактов в таблице DHT (тесты: кэш `mesh.contacts` загружен).
    #[cfg(test)]
    pub fn dht_contacts(&self) -> usize {
        self.env.dht.lock().unwrap().len()
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

/// Предел одновременно дублируемых целей (issue #25): больше — это уже
/// дублирование всего трафика, а не «маленького latency-sensitive».
pub const DUP_TARGETS_MAX: usize = 8;
/// Сколько цель считается активной после дублирования, мс.
pub const DUP_TARGET_TTL_MS: u64 = 10_000;
/// Допуск правила «второй путь не хуже 1.5× лучшего», мс: на быстрых путях
/// (localhost, LAN) RTT — доли миллисекунды, и без допуска отношение скачет
/// от шума измерений.
pub const DUP_COST_SLACK_MS: f64 = 5.0;
/// Во сколько раз второй путь может быть дороже лучшего.
pub const DUP_COST_RATIO: f64 = 1.5;
/// Свежесть замера RTT релея для правила выбора, мс (как `PEER_FRESH_MS`).
pub const DUP_RELAY_FRESH_MS: u64 = 30_000;
/// Вес нового замера в EWMA скорости цели.
const DUP_RATE_ALPHA: f64 = 0.2;

/// EWMA скорости цели, кбит/с: по ней решается, дублировать ли поток.
#[derive(Clone, Copy, Default)]
struct RateEwma {
    kbps: f64,
    at_ms: u64,
}

impl RateEwma {
    /// Учесть отправленный пакет и вернуть текущую оценку скорости.
    fn observe(&mut self, bytes: usize, now_ms: u64) -> f64 {
        if self.at_ms != 0 {
            let dt = now_ms.saturating_sub(self.at_ms).max(1) as f64 / 1000.0;
            let inst = bytes as f64 * 8.0 / 1000.0 / dt;
            self.kbps = if self.kbps == 0.0 {
                inst
            } else {
                self.kbps * (1.0 - DUP_RATE_ALPHA) + inst * DUP_RATE_ALPHA
            };
        }
        self.at_ms = now_ms;
        self.kbps
    }
}

/// Состояние дублирования путей (issue #25), которое движок ведёт сам:
/// в `path.rs` только измерения и выбор одного пути, а EWMA скорости цели и
/// замеры релея для правила «второй путь не хуже» нужны здесь.
#[derive(Default)]
struct DupState {
    /// EWMA скорости цели, кбит/с.
    rate: HashMap<u32, RateEwma>,
    /// Когда цель последний раз дублировалась (предел одновременных целей).
    active: HashMap<u32, u64>,
    /// RTT маршрута через пира из `MESH_ROUTE_OK`: (получатель, релей) → (мс, когда).
    relay: HashMap<(u32, [u8; 32]), (f64, u64)>,
}

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
    /// Mesh-подсистема (T3): рукопожатия, RPC, ретрансляция.
    mesh: Arc<Mutex<mesh::MeshState>>,
    /// DHT-таблица контактов (T3).
    dht: Arc<Mutex<dht::Dht>>,
    /// Ответы MESH_NODES из потока приёма → поток движка (там поиски).
    mesh_finds: MeshFinds,
    /// Выбор пути доставки (этап 9): измерения, гистерезис, закрепления.
    paths: Arc<PathTable>,
    /// Пробы серверов (T2).
    probes: Arc<probe::ProbeState>,
    /// Дублирование путей (issue #25): EWMA скорости цели, активные цели и
    /// замеры RTT релея.
    dup: Mutex<DupState>,
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

/// Миллисекунды от старта движка — время для [`PathTable`]. Таблица путей
/// работает на числах (а не `Instant`), чтобы юнит-тесты были
/// детерминированы; захват `meta` короткий и без вложенных блокировок.
fn uptime_ms(env: &Env) -> u64 {
    let started = env.meta.lock().unwrap().started;
    started.elapsed().as_millis() as u64
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

/// Сколько просим у ядра под очередь приёма UDP. Длинное сообщение сервера
/// (GROUP_STATE группы на 253 участника — ~215 КБ, ~175 кусков FRAG) приходит
/// залпом; дефолтных 64 КБ на Windows не хватает, и часть датаграмм ядро
/// выбрасывает — сборка FRAG не завершается никогда. 4 МиБ — с запасом на
/// несколько таких сообщений подряд.
const UDP_RECV_BUF: usize = 4 << 20;

/// Просит у ядра увеличенный буфер приёма UDP. Ошибка не критична: остаётся
/// дефолт, и длинные сообщения могут теряться (см. [`UDP_RECV_BUF`]).
#[cfg(unix)]
fn set_recv_buffer(sock: &UdpSocket, bytes: usize) {
    use std::os::fd::AsRawFd;
    // SAFETY: `sock` жив всё время вызова, `len` — корректный `c_int`,
    // размер переданного значения совпадает с `optlen`.
    unsafe {
        let len = bytes as libc::c_int;
        let _ = libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&raw const len).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Windows-вариант: `SO_RCVBUF` через Winsock (`std` такого сеттера не даёт).
#[cfg(windows)]
fn set_recv_buffer(sock: &UdpSocket, bytes: usize) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{SO_RCVBUF, SOL_SOCKET, setsockopt};
    // SAFETY: `sock` жив всё время вызова, `len` — корректный `i32`,
    // размер переданного значения совпадает с `optlen`.
    unsafe {
        let len = bytes as i32;
        let _ = setsockopt(
            sock.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_RCVBUF,
            (&raw const len).cast(),
            size_of::<i32>() as i32,
        );
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
        set_recv_buffer(&sock, UDP_RECV_BUF);
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

/// Закреплённый ed-ключ сервера `addr` (проба просит его в ответе —
/// `want_key`). `None` — сервера нет в конфиге или ключ не разбирается.
fn pinned_server_key(cfg: &Mutex<Config>, addr: SocketAddr) -> Option<[u8; 32]> {
    let cfg = cfg.lock().unwrap_or_else(|e| e.into_inner());
    cfg.servers
        .iter()
        .find(|s| s.addr.parse::<SocketAddr>().ok() == Some(addr))
        .and_then(|s| proto::hex_to_bytes(&s.pubkey).ok())
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
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

    let (server_label, pinned, mesh_enabled, saved_contacts) = {
        let mut c = cfg.lock().unwrap();
        // Автовход — этого сервера (gid у каждого сервера свои).
        if c.activate_server(server) {
            save(&c);
        }
        (
            server_label(&c, server),
            c.pinned_paths.clone(),
            c.mesh.enabled,
            // Кэш DHT: грузим до первого `MESH_SEED`, чтобы серверные данные
            // перебили сохранённые (issue #27).
            c.mesh.contacts.clone(),
        )
    };
    let meta = Arc::new(Mutex::new(Meta {
        connected: false,
        transport: Transport::Udp,
        server,
        server_label,
        group_list: Vec::new(),
        fed_groups: Vec::new(),
        rx_hist: VecDeque::new(),
        tx_hist: VecDeque::new(),
        started: Instant::now(),
        server_rtt_ms: None,
        mesh_enabled,
        relay_bytes: 0,
        mesh_sessions: 0,
    }));

    let sock = Arc::new(UdpSocket::bind(bind_addr(server)).context("bind udp")?);
    sock.set_read_timeout(Some(RX_POLL)).ok();
    set_recv_buffer(&sock, UDP_RECV_BUF);

    let groups: Groups = Arc::new(Mutex::new(HashMap::new()));
    let paths = Arc::new(PathTable::new(&pinned));
    let my_ed = identity.ed_pub();
    // Таблица DHT стартует с кэша `mesh.contacts` (issue #27): кэш — подсказка,
    // а не замена серверу. Ключи групп, состав и свой `my_ip` по-прежнему
    // приходят только в `WELCOME`/`GROUP_STATE`, поэтому без сервера вход в сеть
    // не поднимется; зато известные адреса пиров не теряются между запусками.
    let mut dht_table = dht::Dht::new(my_ed);
    dht_table.load_at(&saved_contacts, epoch_ms());
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
        mesh: Arc::new(Mutex::new(mesh::MeshState::new(mesh_enabled))),
        dht: Arc::new(Mutex::new(dht_table)),
        mesh_finds: Arc::new(Mutex::new(Vec::new())),
        paths: paths.clone(),
        probes: Arc::new(probe::ProbeState::new()),
        dup: Mutex::new(DupState::default()),
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
        paths,
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
    // Этап 9: диапазоны разбираются до проверки «только от сервера».
    // Mesh-кадры приходят от пиров (они не сервер), проба — от любого
    // сервера из списка (пробуемый сервер не обязан быть текущим), кадры
    // федерации — от чужих серверов (клиенту не адресованы).
    if proto::mesh::is_mesh(typ) {
        handle_mesh_frame(env, src, typ, body);
        return true;
    }
    if typ == ctrl::PROBE_RESP {
        if let Some(r) = env.probes.on_response(src, body) {
            env.emit(Event::ProbeResult {
                addr: r.addr,
                success: r.available,
                rtt_ms: r.rtt_ms,
                key_match: r.key_match.as_bool(),
            });
        }
        return true;
    }
    if proto::federation::is_fed(typ) {
        let _ = federation::on_frame(src, typ, body);
        return true;
    }
    if proto::grp::is_group(typ) {
        match handle_group_frame(env, src, datagram, false) {
            FrameVerdict::NeedGroup(gid) => in_tx.send(Input::NeedGroup(gid)).is_ok(),
            // Повтор уже доставленного кадра — не повод тянуть GROUP_STATE.
            FrameVerdict::Accepted | FrameVerdict::Duplicate | FrameVerdict::Drop => true,
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

/// Ожидаемый ответ CTRL_PONG: метка, время отправки и признак «показать
/// результат событием» (периодический замер RTT идёт молча).
struct PendingPong {
    addr: SocketAddr,
    label: u64,
    at: Instant,
    report: bool,
}

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
    /// Ожидающий ответ CTRL_PONG для измерения RTT (метка в payload).
    pending_ping: Option<PendingPong>,
    /// Последний пересчёт путей доставки (§3.6).
    last_paths: Instant,
    /// Последний шаг mesh-таймеров (сессии, DHT, повторы forward).
    last_mesh: Instant,
    /// Последний `MESH_INFO` серверу.
    last_info: Instant,
    /// `MESH_INFO` нужен сразу (после нового WELCOME).
    info_due: bool,
    /// Последнее обслуживание DHT (устаревание, сохранение контактов).
    last_dht: Instant,
    /// Активные поиски `find_node`: id → поиск.
    lookups: HashMap<u64, dht::Lookup>,
    /// Когда последний раз искали контакт (ed → время).
    last_lookup: HashMap<[u8; 32], Instant>,
    /// Когда последний раз мерили маршрут через реле.
    last_route_probe: Instant,
    /// Номер следующего поиска DHT.
    lookup_seq: u64,
    /// Последний отправленный `SERVER_HINT` (T4): `None` — ещё не слали
    /// этому серверу (сразу после WELCOME, не чаще `SERVER_HINT_EVERY`).
    last_hint: Option<Instant>,
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
            pending_ping: None,
            last_paths: now,
            last_mesh: now,
            last_info: now,
            info_due: false,
            last_dht: now,
            lookups: HashMap::new(),
            last_lookup: HashMap::new(),
            last_route_probe: now,
            lookup_seq: 1,
            last_hint: None,
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
    // MESH_INFO — сразу после WELCOME (§4.1): без него сервер не знает наш
    // x-ключ и не отдаёт нас в MESH_SEED/хвосте GROUP_STATE.
    st.info_due = true;
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
    // Пробы серверов: свой поток складывает результаты в очередь — отдаём их
    // событиями (TUI не различает, откуда пришёл ответ).
    for r in env.probes.poll() {
        env.emit(Event::ProbeResult {
            addr: r.addr,
            success: r.available,
            rtt_ms: r.rtt_ms,
            key_match: r.key_match.as_bool(),
        });
    }
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
            // 8-байтовая метка: сервер вернёт её в CTRL_PONG, и мы узнаем RTT
            // до сервера — стоимость пути L1 (§3.6). Замер молчаливый:
            // событие только на явный `Cmd::PingServer`.
            let label = epoch_ms();
            st.send_ctrl(env, ctrl::CTRL_PING, &label.to_be_bytes());
            if st.pending_ping.is_none() {
                st.pending_ping = Some(PendingPong {
                    addr: env.server(),
                    label,
                    at: now,
                    report: false,
                });
            }
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
    // Пути доставки: пересчёт раз в 10 с и сразу при падении пути (§3.6).
    if now.duration_since(st.last_paths) >= PATHS_EVERY {
        st.last_paths = now;
        paths_round(env, st.connected(), now);
    }
    // Mesh/DHT: сессии, пинги, поиски, измерения маршрутов (§3.2–3.4).
    if now.duration_since(st.last_mesh) >= MESH_EVERY {
        st.last_mesh = now;
        mesh_round(env, st, now, st.connected());
    }
}

/// Пересчёт путей всех участников: события `PathChanged`/`PathLost` (§3.6).
fn paths_round(env: &Env, connected: bool, _now: Instant) {
    // Каждому участнику — запись в таблице: у кого нет ни прямого канала, ни
    // mesh-маршрута, путь по умолчанию — сервер.
    {
        let g = env.groups.lock().unwrap();
        for gs in g.values() {
            for p in gs.members.values() {
                env.paths.ensure_target(p.ip);
            }
        }
    }
    for change in env.paths.recalc(uptime_ms(env), connected) {
        match change {
            path::PathChange::Changed {
                ip,
                from,
                to,
                rtt_ms,
            } => {
                if debug() {
                    eprintln!("[engine] путь {ip}: {from:?} -> {to:?} ({rtt_ms:?} мс)");
                }
                env.emit(Event::PathChanged {
                    ip,
                    name: peer_name(env, ip),
                    path: to,
                    rtt_ms,
                });
            }
            path::PathChange::Lost { ip, from } => {
                if debug() {
                    eprintln!("[engine] путь {ip} потерян (был {from:?})");
                }
                env.emit(Event::PathLost {
                    ip,
                    name: peer_name(env, ip),
                });
            }
        }
    }
}

/// `SERVER_HINT` (T4): кандидаты-серверы для федерации — серверы из
/// `client.json.servers` (addr + ed) и контакты DHT, батч ≤ 8. Шлётся сразу
/// после WELCOME и далее не чаще `SERVER_HINT_EVERY`; старый сервер тип не
/// знает и молча роняет, поэтому шлём всем. Пустой список не шлём (и период
/// не сдвигаем: добавили сервер — подсказка уйдёт на ближайшем шаге).
fn hint_round(env: &Env, st: &mut State, now: Instant) {
    if !st.connected() {
        return;
    }
    if st
        .last_hint
        .is_some_and(|t| now.duration_since(t) < SERVER_HINT_EVERY)
    {
        return;
    }
    let hints = hint_candidates(env);
    if hints.is_empty() {
        return;
    }
    st.last_hint = Some(now);
    if debug() {
        eprintln!("[engine] SERVER_HINT: {} кандидат(ов)", hints.len());
    }
    st.send_ctrl(env, ctrl::SERVER_HINT, &payloads::enc_server_hint(&hints));
}

/// Кандидаты для `SERVER_HINT`: `client.json.servers` и контакты DHT
/// (ed + addr), без текущего сервера, без повторов по адресу и не больше
/// [`payloads::MAX_SERVER_HINT`]. Неразборчивый адрес/ключ — пропуск: сервер
/// такие всё равно отверг бы, а кадр от этого не растёт.
fn hint_candidates(env: &Env) -> Vec<payloads::ServerHint> {
    let me = env.server();
    let mut out: Vec<payloads::ServerHint> = Vec::new();
    let mut seen: HashSet<SocketAddr> = HashSet::new();
    let mut push = |addr: &str, ed: &str| {
        let Ok(addr) = addr.parse::<SocketAddr>() else {
            return;
        };
        let Ok(ed) = proto::hex_to_bytes(ed) else {
            return;
        };
        let Ok(ed_pub) = <[u8; 32]>::try_from(ed) else {
            return;
        };
        if addr == me || out.len() >= payloads::MAX_SERVER_HINT || !seen.insert(addr) {
            return;
        }
        out.push(payloads::ServerHint {
            addr: addr.to_string(),
            ed_pub,
        });
    };
    {
        let cfg = env.cfg.lock().unwrap();
        for s in &cfg.servers {
            push(&s.addr, &s.pubkey);
        }
        for c in &cfg.mesh.contacts {
            push(&c.addr, &c.ed);
        }
    }
    // Живая таблица DHT: адрес контакта мог обновиться (mesh-сессия).
    for c in env.dht.lock().unwrap().to_stored() {
        push(&c.addr, &c.ed);
    }
    out
}

/// Шаг mesh/DHT (раз в секунду): `MESH_INFO`, сессии и рукопожатия, DHT
/// (пинги/устаревание/сохранение), поиски `find_node`, измерения маршрутов
/// через реле, разбор ответов `MESH_NODES`.
fn mesh_round(env: &Env, st: &mut State, now: Instant, connected: bool) {
    let now_ms = epoch_ms();
    // 0. MESH_INFO: после WELCOME и далее раз в 5 минут (§4.1).
    if connected && (st.info_due || now.duration_since(st.last_info) >= MESH_INFO_EVERY) {
        st.info_due = false;
        st.last_info = now;
        let caps = my_mesh_caps(env);
        st.send_ctrl(
            env,
            ctrl::MESH_INFO,
            &payloads::enc_mesh_info(&env.identity.x_pub(), caps),
        );
    }
    // 0b. SERVER_HINT серверу (T4): кандидаты-серверы для федерации.
    hint_round(env, st, now);
    // 1. DHT: устаревание (TTL 15 мин) + сохранение контактов в client.json.
    if now.duration_since(st.last_dht) >= DHT_EVERY {
        st.last_dht = now;
        // Контакты из живых mesh-сессий — тоже источник (сменился адрес).
        let sess = env.mesh.lock().unwrap().session_contacts();
        let saved = {
            let mut d = env.dht.lock().unwrap();
            for c in sess {
                d.insert(c);
            }
            d.expire(now_ms);
            // Прунинг на записи: кэш не больше BUCKETS × K записей и не старше
            // CACHE_MAX_AGE (7 суток) — файл не должен расти и хранить мусор.
            d.to_stored_pruned(now_ms)
        };
        if env.cfg.lock().unwrap().mesh.contacts != saved {
            env.update_cfg(|c| c.mesh.contacts = saved);
        }
    }
    // 2. DHT-пинг ближайших: у кого есть mesh-сессия — MESH_PING, остальные
    //    получат HELLO из mesh-таймера (не чаще `HANDSHAKE_GAP_MS`).
    let due = env.dht.lock().unwrap().ping_due(now_ms);
    if !due.is_empty() {
        let w = mesh_world(env);
        let check = GroupCheck { groups: &w.groups };
        let ctx = mesh::MeshCtx {
            me: &env.identity,
            my_caps: my_mesh_caps(env),
            now_ms,
            my_addr: w.my_addr,
            contacts: &w.contacts,
            members: &w.members,
            relay_enabled: relay_enabled(env),
            relay_budget: relay_budget(env),
            check_group: &|gid, src, dst, epoch| check.accepts(gid, src, dst, epoch),
        };
        let mut pinged: Vec<[u8; 32]> = Vec::new();
        {
            let mut mesh = env.mesh.lock().unwrap();
            for c in &due {
                if mesh.session(&c.ed).is_some()
                    && let Some((to, frame)) = mesh.ping_peer(&ctx, &c.ed)
                {
                    env.send(&frame, to);
                    pinged.push(c.ed);
                }
            }
        }
        if !pinged.is_empty() {
            let mut d = env.dht.lock().unwrap();
            for ed in pinged {
                d.mark_pinged(&ed, now_ms);
            }
        }
    }
    // 3. Состав групп: адрес/ключ участника — контакт DHT. Смена адреса
    //    запускает поиск заново (§3.3: «поиск при смене адреса»).
    let peers = mesh_peers(env);
    {
        let mut d = env.dht.lock().unwrap();
        let mut changed = false;
        for p in &peers {
            if d.set_addr(&p.ed, p.addr, now_ms) {
                changed = true;
            } else {
                d.add_group_peer(p.ed, p.x, p.addr, p.caps | proto::mesh::caps::MESH, now_ms);
            }
        }
        if changed {
            st.last_lookup.clear();
        }
    }
    // 4. find_node: до 2 раундов × α = 3 на пира; не чаще раза в 5 минут или
    //    сразу после смены адреса.
    for p in &peers {
        let due = st
            .last_lookup
            .get(&p.ed)
            .is_none_or(|t| now.duration_since(*t) >= LOOKUP_EVERY);
        if !due || !proto::mesh::caps::has(p.caps, proto::mesh::caps::MESH) {
            continue;
        }
        st.last_lookup.insert(p.ed, now);
        st.lookup_seq = st.lookup_seq.wrapping_add(1).max(1);
        let id = st.lookup_seq;
        let lookup = env.dht.lock().unwrap().start_lookup(id, p.ed);
        st.lookups.insert(id, lookup);
        send_find_round(env, st, id);
    }
    // 5. Ответы MESH_NODES: контакты в DHT и следующий раунд поиска.
    let finds = std::mem::take(&mut *env.mesh_finds.lock().unwrap());
    for (id, nodes) in finds {
        env.dht.lock().unwrap().on_nodes(&nodes);
        if st.lookups.contains_key(&id) {
            send_find_round(env, st, id);
        }
    }
    // 6. Маршруты через реле: раз в `PATHS_EVERY` для каждого получателя —
    //    MESH_ROUTE трём ближайшим реле-кандидатам (PathTable получит стоимость
    //    L2 и сможет выбрать peer-путь).
    if now.duration_since(st.last_route_probe) >= PATHS_EVERY {
        st.last_route_probe = now;
        let w = mesh_world(env);
        let check = GroupCheck { groups: &w.groups };
        let ctx = mesh::MeshCtx {
            me: &env.identity,
            my_caps: my_mesh_caps(env),
            now_ms,
            my_addr: w.my_addr,
            contacts: &w.contacts,
            members: &w.members,
            relay_enabled: relay_enabled(env),
            relay_budget: relay_budget(env),
            check_group: &|gid, src, dst, epoch| check.accepts(gid, src, dst, epoch),
        };
        let targets: Vec<([u8; 32], u32, SocketAddr)> = peers
            .iter()
            .filter_map(|p| ip_of_ed(env, &p.ed).map(|ip| (p.ed, ip, p.addr)))
            .collect();
        for (dst_ed, _ip, _addr) in targets {
            let cands = mesh::relay_candidates(&env.dht.lock().unwrap(), &dst_ed, RELAY_TRIES);
            let mut mesh = env.mesh.lock().unwrap();
            for c in cands {
                if c.ed == dst_ed {
                    continue;
                }
                if mesh.session(&c.ed).is_none() {
                    continue;
                }
                if let Some((to, frame)) = mesh.route_probe(&ctx, &c.ed, dst_ed, c.addr) {
                    env.send(&frame, to);
                }
            }
        }
    }
    // 7. Сессии: рукопожатия, пинги, таймауты, повторы forward.
    let w = mesh_world(env);
    let check = GroupCheck { groups: &w.groups };
    let ctx = mesh::MeshCtx {
        me: &env.identity,
        my_caps: my_mesh_caps(env),
        now_ms,
        my_addr: w.my_addr,
        contacts: &w.contacts,
        members: &w.members,
        relay_enabled: relay_enabled(env),
        relay_budget: relay_budget(env),
        check_group: &|gid, src, dst, epoch| check.accepts(gid, src, dst, epoch),
    };
    let out = {
        let mut mesh = env.mesh.lock().unwrap();
        mesh.tick(&ctx)
    };
    apply_mesh_out(env, out);
    sync_mesh_stats(env);
}

/// Продолжить поиск `find_node`: следующие α контактов к цели.
fn send_find_round(env: &Env, st: &mut State, id: u64) {
    let queries = {
        let d = env.dht.lock().unwrap();
        match st.lookups.get_mut(&id) {
            Some(l) => l.next_queries(&d),
            None => return,
        }
    };
    if queries.is_empty() {
        st.lookups.remove(&id);
        return;
    }
    let target = st.lookups.get(&id).map(|l| l.target).expect("поиск есть");
    let w = mesh_world(env);
    let check = GroupCheck { groups: &w.groups };
    let ctx = mesh::MeshCtx {
        me: &env.identity,
        my_caps: my_mesh_caps(env),
        now_ms: epoch_ms(),
        my_addr: w.my_addr,
        contacts: &w.contacts,
        members: &w.members,
        relay_enabled: relay_enabled(env),
        relay_budget: relay_budget(env),
        check_group: &|gid, src, dst, epoch| check.accepts(gid, src, dst, epoch),
    };
    let mut mesh = env.mesh.lock().unwrap();
    for c in queries {
        if let Some((to, frame)) = mesh.find_node(&ctx, &c.ed, id, target) {
            env.send(&frame, to);
        }
    }
}

/// Mesh-пиры из состава групп: ed, x-ключ, endpoint и caps.
fn mesh_peers(env: &Env) -> Vec<dht::Contact> {
    let g = env.groups.lock().unwrap();
    let now = epoch_ms();
    g.values()
        .flat_map(|gs| gs.members.values())
        .filter_map(|p| {
            let x = p.mesh_x?;
            let addr = p.endpoint?;
            Some(dht::Contact {
                ed: p.pubkey,
                x,
                addr,
                rtt_ms: 0,
                last_seen_ms: now,
                caps: p.mesh_caps | proto::mesh::caps::MESH,
            })
        })
        .collect()
}

/// Имя участника по адресу оверлея (первая группа, где он есть).
fn peer_name(env: &Env, ip: u32) -> String {
    let g = env.groups.lock().unwrap();
    g.values()
        .find_map(|gs| gs.members.get(&ip).map(|p| p.name.clone()))
        .unwrap_or_default()
}

// ---------- mesh: DHT, сессии, релей (этап 9) ----------

/// Возможности mesh для `MESH_INFO`/HELLO: `0` — mesh выключен.
fn my_mesh_caps(env: &Env) -> u8 {
    let cfg = env.cfg.lock().unwrap();
    if !cfg.mesh.enabled {
        return 0;
    }
    let mut c = proto::mesh::caps::MESH;
    if cfg.mesh.relay_enabled {
        c |= proto::mesh::caps::RELAY | proto::mesh::caps::ACCEPT_RELAY;
    }
    // Дедупликация на выходе работает всегда (issue #25): кольцо в KeyState
    // не зависит от того, дублируем ли мы сами. Бит сообщает отправителю,
    // что копии этому пиру можно слать.
    c |= proto::mesh::caps::DUP;
    c
}

/// Релей чужого трафика разрешён (`mesh.relay_enabled`, по умолчанию да).
fn relay_enabled(env: &Env) -> bool {
    env.cfg.lock().unwrap().mesh.relay_enabled
}

/// Бюджет релея на пира за окно [`mesh::RELAY_WINDOW_MS`]: кбит/с → байт.
fn relay_budget(env: &Env) -> u64 {
    let kbps = u64::from(env.cfg.lock().unwrap().mesh.relay_budget_kbps);
    kbps.saturating_mul(125)
        .saturating_mul(mesh::RELAY_WINDOW_MS / 1000)
}

/// Дополнить DHT контактами из состава группы: адрес (`MemberInfo.endpoint`)
/// + x-ключ (mesh-секция). Участники без mesh-метаданных пропускаются.
fn sync_group_contacts(env: &Env, gs: &GroupSess) {
    let now = epoch_ms();
    let mut d = env.dht.lock().unwrap();
    for p in gs.members.values() {
        if let (Some(x), Some(addr)) = (p.mesh_x, p.endpoint) {
            let caps = p.mesh_caps | proto::mesh::caps::MESH;
            d.add_group_peer(p.pubkey, x, addr, caps, now);
        }
    }
}

/// Мини-снимок группы для проверки открытого заголовка inner: реле не
/// расшифровывает кадр, но обязано убедиться, что gid/src/dst/epoch — свои.
struct GroupMini {
    gid: u32,
    epoch: u32,
    ips: Vec<u32>,
}

impl GroupMini {
    /// Кадр принадлежит этой группе: gid совпал, отправитель и получатель —
    /// участники, эпоха текущая или прошлая (grace после ротации).
    fn accepts(&self, gid: u32, src: u32, dst: u32, epoch: u32) -> bool {
        self.gid == gid
            && self.ips.contains(&src)
            && self.ips.contains(&dst)
            && (epoch == self.epoch || epoch + 1 == self.epoch)
    }
}

/// Снимок мира для mesh-модуля. Блокировки берутся и отпускаются до вызова
/// mesh (порядок «группы → DHT → mesh» соблюдается везде).
struct MeshWorld {
    contacts: Vec<dht::Contact>,
    members: Vec<[u8; 32]>,
    groups: Vec<GroupMini>,
    my_addr: Option<SocketAddr>,
}

fn mesh_world(env: &Env) -> MeshWorld {
    let mut members: Vec<[u8; 32]> = Vec::new();
    let mut groups: Vec<GroupMini> = Vec::new();
    let mut group_contacts: Vec<dht::Contact> = Vec::new();
    {
        let g = env.groups.lock().unwrap();
        for (gid, gs) in g.iter() {
            groups.push(GroupMini {
                gid: *gid,
                epoch: gs.epoch,
                ips: gs.members.keys().copied().collect(),
            });
            for p in gs.members.values() {
                members.push(p.pubkey);
                if let (Some(x), Some(addr)) = (p.mesh_x, p.endpoint) {
                    group_contacts.push(dht::Contact {
                        ed: p.pubkey,
                        x,
                        addr,
                        rtt_ms: 0,
                        last_seen_ms: epoch_ms(),
                        caps: p.mesh_caps | proto::mesh::caps::MESH,
                    });
                }
                // Готовность релеить: участник без RELAY всё равно может быть
                // целью L2 (его слушает наш релей), но кандидатом — нет.
                let _ = p.can_relay();
            }
        }
    }
    let mut contacts = env.dht.lock().unwrap().contacts();
    for c in group_contacts {
        if !contacts.iter().any(|x| x.ed == c.ed) {
            contacts.push(c);
        }
    }
    MeshWorld {
        contacts,
        members,
        groups,
        my_addr: env.sock.local_addr().ok(),
    }
}

/// Обработка входящего mesh-кадра: собрать снимок, прогнать через модуль,
/// исполнить результат (отправки, DHT, ACK/NACK, события).
fn handle_mesh_frame(env: &Env, src: SocketAddr, typ: u8, body: &[u8]) {
    let w = mesh_world(env);
    let check = GroupCheck { groups: &w.groups };
    let ctx = mesh::MeshCtx {
        me: &env.identity,
        my_caps: my_mesh_caps(env),
        now_ms: epoch_ms(),
        my_addr: w.my_addr,
        contacts: &w.contacts,
        members: &w.members,
        relay_enabled: relay_enabled(env),
        relay_budget: relay_budget(env),
        check_group: &|gid, src, dst, epoch| check.accepts(gid, src, dst, epoch),
    };
    let out = {
        let mut st = env.mesh.lock().unwrap();
        st.on_frame(&ctx, src, typ, body)
    };
    apply_mesh_out(env, out);
}

/// Итог доставки реле-кадра для ACK/NACK (`MeshState::delivery_result`).
///
/// Повтор уже доставленного кадра — **успех** (issue #25): ACK, а не NACK.
/// Иначе потерянный ACK и дубликат снимали бы здоровый путь через
/// `record_failure` по `ForwardFailed`, а с дублированием это стало бы
/// систематическим.
fn delivery_result_of(v: FrameVerdict) -> (bool, u8) {
    match v {
        FrameVerdict::Accepted | FrameVerdict::Duplicate => (true, proto::mesh::code::REJECTED),
        FrameVerdict::NeedGroup(_) | FrameVerdict::Drop => (false, proto::mesh::code::DROP),
    }
}

/// Проверка открытого заголовка inner (реле не расшифровывает кадр).
struct GroupCheck<'a> {
    groups: &'a [GroupMini],
}

impl GroupCheck<'_> {
    fn accepts(&self, gid: u32, src: u32, dst: u32, epoch: u32) -> bool {
        self.groups.iter().any(|g| g.accepts(gid, src, dst, epoch))
    }
}

/// Исполнить [`mesh::MeshOut`]: отправки, контакты в DHT, доставка кадров
/// (с ACK/NACK), события путей/UI.
fn apply_mesh_out(env: &Env, out: mesh::MeshOut) {
    for (to, frame) in &out.sends {
        env.send(frame, *to);
    }
    if !out.learned.is_empty() {
        let now = epoch_ms();
        let mut d = env.dht.lock().unwrap();
        for c in &out.learned {
            if mesh::sane_contact(c) && c.ed != env.identity.ed_pub() {
                let mut c = c.clone();
                c.last_seen_ms = now;
                d.insert(c);
            }
        }
    }
    if !out.finds.is_empty() {
        // Разбор ответов и следующий раунд — в потоке движка (там состояние
        // поисков): сюда только складываем.
        env.mesh_finds
            .lock()
            .unwrap()
            .extend(out.finds.iter().cloned());
    }
    let now_ms = epoch_ms();
    for r in out.deliver {
        let (ok, why) = delivery_result_of(handle_group_frame(env, env.server(), &r.inner, true));
        let reply = {
            let mut st = env.mesh.lock().unwrap();
            st.delivery_result(now_ms, &r, ok, why)
        };
        if let Some((to, frame)) = reply {
            env.send(&frame, to);
        }
    }
    for e in out.events {
        match e {
            mesh::MeshEvent::Up { ed, addr, rtt_ms } => {
                if debug() {
                    eprintln!(
                        "[mesh] сессия с {} ({addr}): {rtt_ms:?} мс",
                        proto::hex_of(&ed)
                    );
                }
            }
            mesh::MeshEvent::Down { ed, reason } => {
                if debug() {
                    eprintln!("[mesh] сессия {} закрыта: {reason}", proto::hex_of(&ed));
                }
            }
            mesh::MeshEvent::Rtt { .. } => {}
            mesh::MeshEvent::RouteMeasured {
                dst_ed,
                via,
                up_ms,
                down_ms,
                load,
            } => {
                if let Some(ip) = ip_of_ed(env, &dst_ed) {
                    // Одно и то же время (uptime) и в таблицу путей, и в кеш
                    // дублирования: у них общий масштаб свежести.
                    let up = uptime_ms(env);
                    env.paths.record_peer_rtt(ip, via, up_ms, down_ms, load, up);
                    // RTT релея — для правила выбора копий (issue #25):
                    // в path.rs стоимость не отдаётся, а для «второй путь не
                    // хуже 1.5× лучшего» нужен замер end-to-end.
                    let mut d = env.dup.lock().unwrap();
                    d.relay
                        .retain(|_, (_, at)| up.saturating_sub(*at) <= DUP_RELAY_FRESH_MS);
                    d.relay
                        .insert((ip, via), (f64::from(up_ms) + f64::from(down_ms), up));
                }
            }
            mesh::MeshEvent::RouteFailed { .. } => {}
            mesh::MeshEvent::ForwardFailed { dst_ed, code } => {
                if let Some(ip) = ip_of_ed(env, &dst_ed) {
                    env.paths.record_failure(ip);
                    env.emit(Event::PathLost {
                        ip,
                        name: peer_name(env, ip),
                    });
                    let connected = env.meta.lock().unwrap().connected;
                    for change in env.paths.recalc_one(ip, uptime_ms(env), connected) {
                        emit_path_change(env, change);
                    }
                }
                if debug() {
                    eprintln!(
                        "[mesh] релей не доставил кадр {}: код {code}",
                        proto::hex_of(&dst_ed)
                    );
                }
            }
            mesh::MeshEvent::ForwardOk { .. } => {}
        }
    }
    sync_mesh_stats(env);
}

/// Байты релея и число сессий — в снимок состояния (§3.4).
fn sync_mesh_stats(env: &Env) {
    let st = env.mesh.lock().unwrap().stats();
    let changed = {
        let mut m = env.meta.lock().unwrap();
        let changed = m.relay_bytes != st.relay_bytes;
        m.relay_bytes = st.relay_bytes;
        m.mesh_sessions = st.sessions;
        changed
    };
    // Счётчик изменился — событием (UI показывает «реле N КБ» без опроса).
    if changed {
        env.emit(Event::RelayStats {
            bytes_total: st.relay_bytes,
            peers: st.relay_peers,
        });
    }
}

/// Адрес оверлея участника по ed-ключу.
fn ip_of_ed(env: &Env, ed: &[u8; 32]) -> Option<u32> {
    let g = env.groups.lock().unwrap();
    g.values()
        .flat_map(|gs| gs.members.values())
        .find(|p| p.pubkey == *ed)
        .map(|p| p.ip)
}

/// Пересчитать путь одного получателя и разослать изменения событиями
/// (сразу после ручного закрепления/открепления, §3.6).
fn recalc_path_now(env: &Env, ip: u32) {
    let connected = env.meta.lock().unwrap().connected;
    for change in env.paths.recalc_one(ip, uptime_ms(env), connected) {
        emit_path_change(env, change);
    }
}

/// Событие смены пути — из [`path::PathChange`].
fn emit_path_change(env: &Env, change: path::PathChange) {
    match change {
        path::PathChange::Changed {
            ip,
            from,
            to,
            rtt_ms,
        } => {
            if debug() {
                eprintln!("[engine] путь {ip}: {from:?} -> {to:?} ({rtt_ms:?} мс)");
            }
            env.emit(Event::PathChanged {
                ip,
                name: peer_name(env, ip),
                path: to,
                rtt_ms,
            });
        }
        path::PathChange::Lost { ip, from } => {
            if debug() {
                eprintln!("[engine] путь {ip} потерян (был {from:?})");
            }
            env.emit(Event::PathLost {
                ip,
                name: peer_name(env, ip),
            });
        }
    }
}

/// Отправить групповой кадр через реле (L2): до 3 кандидатов по стоимости
/// (`PathTable::choose` дал лучшего, следующий — по DHT).
/// `true` — кадр ушёл релею.
fn try_relay(env: &Env, dst: u32, dst_ed: [u8; 32], inner: &[u8]) -> bool {
    let w = mesh_world(env);
    let mut cands: Vec<dht::Contact> = Vec::new();
    if let Some(via) = env.paths.current(dst).and_then(|k| match k {
        PathKind::PeerRelay { via } => Some(via),
        _ => None,
    }) && let Some(c) = w.contacts.iter().find(|c| c.ed == via)
    {
        cands.push(c.clone());
    }
    for c in mesh::relay_candidates(&env.dht.lock().unwrap(), &dst_ed, RELAY_TRIES) {
        if !cands.iter().any(|x| x.ed == c.ed) && c.ed != dst_ed {
            cands.push(c);
        }
    }
    let check = GroupCheck { groups: &w.groups };
    let ctx = mesh::MeshCtx {
        me: &env.identity,
        my_caps: my_mesh_caps(env),
        now_ms: epoch_ms(),
        my_addr: w.my_addr,
        contacts: &w.contacts,
        members: &w.members,
        relay_enabled: relay_enabled(env),
        relay_budget: relay_budget(env),
        check_group: &|gid, src, dst, epoch| check.accepts(gid, src, dst, epoch),
    };
    for c in cands.iter().take(RELAY_TRIES) {
        let mut st = env.mesh.lock().unwrap();
        match st.start_forward(&ctx, dst_ed, c, inner) {
            Ok((to, frame)) => {
                drop(st);
                env.send(&frame, to);
                return true;
            }
            Err(code) => {
                if debug() {
                    eprintln!(
                        "[mesh] реле {} недоступно: код {code}",
                        proto::hex_of(&c.ed)
                    );
                }
            }
        }
    }
    false
}

/// Отправить копию кадра через конкретного релея (issue #25, второй путь).
/// Кандидаты не перебираются: путь выбран таблицей, и если релея нет —
/// копия просто не уходит (`false`), без снятия пути.
fn try_relay_via(env: &Env, dst_ed: [u8; 32], via: [u8; 32], inner: &[u8]) -> bool {
    let w = mesh_world(env);
    let Some(c) = w.contacts.iter().find(|c| c.ed == via).cloned() else {
        return false;
    };
    let check = GroupCheck { groups: &w.groups };
    let ctx = mesh::MeshCtx {
        me: &env.identity,
        my_caps: my_mesh_caps(env),
        now_ms: epoch_ms(),
        my_addr: w.my_addr,
        contacts: &w.contacts,
        members: &w.members,
        relay_enabled: relay_enabled(env),
        relay_budget: relay_budget(env),
        check_group: &|gid, src, dst, epoch| check.accepts(gid, src, dst, epoch),
    };
    let mut st = env.mesh.lock().unwrap();
    match st.start_forward(&ctx, dst_ed, &c, inner) {
        Ok((to, frame)) => {
            drop(st);
            env.send(&frame, to);
            true
        }
        Err(code) => {
            if debug() {
                eprintln!(
                    "[mesh] копия через реле {} не ушла: код {code}",
                    proto::hex_of(&via)
                );
            }
            false
        }
    }
}

/// Отправить копию кадра по пути `kind` (issue #25). `false` — путь сейчас
/// не отправить (нет прямого адреса, релея, сессии): тихо пропускаем.
fn send_extra(
    env: &Env,
    dst_ed: [u8; 32],
    direct: Option<SocketAddr>,
    frame: &[u8],
    kind: PathKind,
) -> bool {
    match kind {
        PathKind::Direct => match direct {
            Some(a) => {
                env.send(frame, a);
                true
            }
            None => false,
        },
        PathKind::Server => {
            env.send(frame, env.server());
            true
        }
        PathKind::PeerRelay { via } => try_relay_via(env, dst_ed, via, frame),
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
        Cmd::PingServer { addr } => {
            // Метка (8 байт) — сервер вернёт её в CTRL_PONG; по ней отличаем
            // свой ответ от чужого/запоздалого и считаем RTT.
            if let Some(sess) = st.sess.as_mut() {
                let label = epoch_ms();
                st.pending_ping = Some(PendingPong {
                    addr,
                    label,
                    at: Instant::now(),
                    report: true,
                });
                let frame = sess.seal(proto::ctrl::CTRL_PING, &label.to_be_bytes());
                env.send(&frame, addr);
            } else {
                env.emit(Event::ServerPingResult {
                    addr,
                    rtt_ms: None,
                    success: false,
                });
            }
            return;
        }
        Cmd::ProbeServer { addr } => {
            // Проба не требует сессии (PROBE_REQ — открытым текстом, §3.7) и
            // идёт своим сокетом/потоком (`probe::ProbeState`), не мешая
            // сессии. Результат — `Event::ProbeResult` из `tick`.
            if let Err(e) =
                env.probes
                    .start_probe(addr, pinned_server_key(&env.cfg, addr), epoch_ms())
            {
                if debug() {
                    eprintln!("[engine] проба {addr}: {e:#}");
                }
                env.emit(Event::ProbeResult {
                    addr,
                    success: false,
                    rtt_ms: None,
                    key_match: None,
                });
            }
            return;
        }
        Cmd::AddFriend { .. }
        | Cmd::DelFriend(_)
        | Cmd::SetAlias { .. }
        | Cmd::AddServer { .. }
        | Cmd::DelServer { .. }
        | Cmd::SetPrimaryServer { .. }
        | Cmd::PinPath { .. }
        | Cmd::UnpinPath { .. }
        | Cmd::SetRelayEnabled(_)
        | Cmd::SetMeshEnabled(_) => {
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
        // T4: вход в федерированную группу по uuid. Ответ — обычный
        // GROUP_STATE (плюс свежий FED_GROUPS с локальным gid); ошибка —
        // Event::Error от сервера. Метка «федерация» ставится по gid из
        // списка, а если gid уже известен — снимаем прежние выход/tomb.
        Cmd::JoinFed { uuid } => {
            let gid = env
                .meta
                .lock()
                .unwrap()
                .fed_groups
                .iter()
                .find(|f| f.uuid == uuid)
                .map(|f| f.gid);
            if let Some(gid) = gid {
                st.leaving.remove(&gid);
                st.declining.remove(&gid);
                st.tombs.remove(&gid);
            }
            st.send_ctrl(env, ctrl::JOIN_FED, &uuid)
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
        | Cmd::Leave(_)
        | Cmd::PingServer { .. }
        | Cmd::PinPath { .. }
        | Cmd::UnpinPath { .. }
        | Cmd::SetRelayEnabled(_)
        | Cmd::SetMeshEnabled(_)
        | Cmd::ProbeServer { .. } => {}
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
        // Закрепление пути: адрес — оверлей, ключ реле — настоящий ed25519
        // (нулевой ключ заведомо не пир).
        Cmd::PinPath { ip, path } => {
            if !proto::is_overlay_ip(*ip) {
                return Some(format!("{} — не адрес оверлея", proto::ip_str(*ip)));
            }
            match path {
                PathKind::PeerRelay { via } if *via == [0u8; 32] => Some("у реле нет ключа".into()),
                _ => None,
            }
        }
        Cmd::UnpinPath { ip } => (!proto::is_overlay_ip(*ip))
            .then(|| format!("{} — не адрес оверлея", proto::ip_str(*ip))),
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
                    ..Default::default()
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
        Cmd::PinPath { ip, path } => {
            // Закрепление сильнее автоматики (§3.6): конфиг — источник правды
            // (переживает рестарт), таблица путей — рабочая копия.
            env.update_cfg(|c| {
                c.pinned_paths.insert(path::ip_key(ip), path.to_config());
            });
            env.paths.set_pin(ip, Some(path));
            // Пересчёт сразу: закрепление сильнее автоматики и не ждёт
            // десятисекундного тика (пользователь ждёт эффекта от нажатия).
            recalc_path_now(env, ip);
            env.emit(Event::Notice(format!(
                "путь до {} закреплён: {}",
                proto::ip_str(ip),
                path.label()
            )));
        }
        Cmd::UnpinPath { ip } => {
            env.update_cfg(|c| {
                c.pinned_paths.remove(&path::ip_key(ip));
            });
            env.paths.set_pin(ip, None);
            recalc_path_now(env, ip);
            env.emit(Event::Notice(format!(
                "закрепление пути до {} снято",
                proto::ip_str(ip)
            )));
        }
        Cmd::SetRelayEnabled(on) => {
            env.update_cfg(|c| c.mesh.relay_enabled = on);
            env.paths.set_relay_enabled(on);
            // Снятие/включение L2 меняет набор путей — пересчитать сразу.
            let connected = env.meta.lock().unwrap().connected;
            for change in env.paths.recalc(uptime_ms(env), connected) {
                emit_path_change(env, change);
            }
            env.emit(Event::Notice(if on {
                "релей через пиров включён".into()
            } else {
                "релей через пиров выключен".into()
            }));
        }
        Cmd::SetMeshEnabled(on) => {
            env.update_cfg(|c| c.mesh.enabled = on);
            env.mesh.lock().unwrap().set_enabled(on);
            env.meta.lock().unwrap().mesh_enabled = on;
            // Включили — сразу публикуемся (сервер добавит нас в MESH_SEED
            // и mesh-хвост GROUP_STATE); выключили — сервер забудет по TTL.
            st.info_due = true;
            env.emit(Event::Notice(if on {
                "mesh включён".into()
            } else {
                "mesh выключен".into()
            }));
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
    // Федерация: подсказки о серверах старого сервера новому не нужны, ждём
    // нового списка (при первом WELCOME уйдёт сразу).
    st.last_hint = None;
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
        m.fed_groups.clear();
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
        // T4: доступные федерированные группы. Метка «федерация» ставится
        // известным группам по gid; событие — только при изменении списка
        // (сервер шлёт кадр с каждым GROUP_LIST).
        ctrl::FED_GROUPS => on_fed_groups(env, payload),
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
        ctrl::CTRL_PONG => {
            // RTT до сервера: 8-байтовая метка в payload отличает наш ответ
            // от чужого/запоздалого. Пустой payload — старый сервер без метки:
            // «RTT неизвестен», но ответ подлинный. Прочая длина — не метка и
            // не старый ответ: не трогаем ожидание.
            let label: Option<u64> = match payload.len() {
                0 => None,
                8 => {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(payload);
                    Some(u64::from_be_bytes(b))
                }
                _ => return,
            };
            let Some(p) = st.pending_ping.take() else {
                return;
            };
            if label.is_some_and(|l| l != p.label) {
                // Не наша метка: ожидание не съедаем (ответ придёт отдельно).
                st.pending_ping = Some(p);
                return;
            }
            let rtt = p.at.elapsed().as_millis() as u32;
            if label.is_some() {
                env.paths.record_server_rtt(rtt, uptime_ms(env));
                if p.addr == env.server() {
                    env.meta.lock().unwrap().server_rtt_ms = Some(rtt);
                }
            }
            if p.report {
                env.emit(Event::ServerPingResult {
                    addr: p.addr,
                    rtt_ms: label.map(|_| rtt),
                    success: true,
                });
            }
        }
        ctrl::MESH_SEED => {
            // Семя DHT от сервера (§3.3): ближайшие к нам онлайн-сессии.
            // Свой/нулевой ключ отфильтровывает сам bootstrap; дальше
            // рукопожатия начнёт mesh-таймер.
            if let Ok(seeds) = payloads::dec_mesh_seed(payload) {
                let me = env.identity.ed_pub();
                let seeds = mesh::note_seeds(&seeds, &me);
                env.dht.lock().unwrap().bootstrap(&seeds, epoch_ms());
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
/// `FED_GROUPS` (T4): список доступных федерированных групп (реплик с других
/// серверов). Состав списка — по возрастанию локального gid; группам в
/// состоянии ставится uuid (метка «федерация» в UI), а группам, которых в
/// списке больше нет, метка снимается. Событие — только при изменении
/// списка: сервер шлёт кадр с каждым `GROUP_LIST` (раз в 15 с).
fn on_fed_groups(env: &Env, payload: &[u8]) {
    let Ok(items) = payloads::dec_fed_groups(payload) else {
        return;
    };
    let mut groups: Vec<FedGroupInfo> = items.iter().map(FedGroupInfo::from).collect();
    groups.sort_by_key(|g| g.gid);
    let changed = {
        let mut m = env.meta.lock().unwrap();
        if m.fed_groups == groups {
            false
        } else {
            m.fed_groups = groups.clone();
            true
        }
    };
    let uuids: HashMap<u32, [u8; 16]> = groups.iter().map(|g| (g.gid, g.uuid)).collect();
    {
        let mut gs = env.groups.lock().unwrap();
        for (gid, group) in gs.iter_mut() {
            let was = group.fed_uuid;
            group.fed_uuid = uuids.get(gid).copied();
            if debug() && was != group.fed_uuid {
                eprintln!(
                    "[engine] группа {gid}: метка федерации {:?} -> {:?}",
                    was.map(|u| proto::hex_of(&u)),
                    group.fed_uuid.map(|u| proto::hex_of(&u))
                );
            }
        }
    }
    if changed {
        if debug() {
            eprintln!("[engine] федерированных групп: {}", groups.len());
        }
        env.emit(Event::FedGroups { groups });
    }
}

fn apply_group_state(env: &Env, es: &mut State, st: &payloads::GroupState) {
    let my_pub = env.identity.ed_pub();
    if st.deleted {
        // Копию федеративной группы удалил владелец: из списка доступных её
        // убираем сами — пустой FED_GROUPS сервер не шлёт (старые клиенты
        // кадра не знают), иначе мёртвая запись осталась бы в UI.
        let changed = {
            let mut m = env.meta.lock().unwrap();
            let before = m.fed_groups.len();
            m.fed_groups.retain(|f| f.gid != st.gid);
            before != m.fed_groups.len()
        };
        if changed {
            let groups = env.meta.lock().unwrap().fed_groups.clone();
            env.emit(Event::FedGroups { groups });
        }
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
    // uuid из FED_GROUPS — до блокировки групп (порядок блокировок везде
    // state → fed/meta, обратный ему здесь не нужен).
    let fed_uuid = env
        .meta
        .lock()
        .unwrap()
        .fed_groups
        .iter()
        .find(|f| f.gid == st.gid)
        .map(|f| f.uuid);
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
        // Метка «федерация»: gid мог прийти в FED_GROUPS раньше состояния
        // (или это ответ на JOIN_FED — список тоже уже был). Нет в списке —
        // прежняя метка сохраняется до следующего FED_GROUPS.
        if let Some(uuid) = fed_uuid {
            entry.fed_uuid = Some(uuid);
        }
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
        // Хвост mesh-метаданных — после участников: сопоставление по ip.
        entry.apply_mesh_section(&st.mesh);
        // DHT: адреса и x-ключи участников — кандидаты в контакты (§3.3).
        sync_group_contacts(env, entry);
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
                    // Хвост дельты (§4.2): mesh-контакт изменившегося участника.
                    gs.apply_mesh_tail_for(&m.pubkey, &u.mesh);
                    sync_group_contacts(env, gs);
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

/// Итог разбора группового кадра: доставлен, нужен GET_GROUP или отброшен.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameVerdict {
    /// Расшифрован и обработан (инъекция в TUN, ответ на PING и т.п.).
    Accepted,
    /// Эпоха новее известной: нужен GET_GROUP (сигнал не чаще раза в секунду).
    NeedGroup(u32),
    /// Повтор уже доставленного кадра (issue #25): не инжектится, окно
    /// повторов не трогает, но это **не** отказ — отправителю уходит ACK.
    /// Иначе дубликат (в т.ч. при дублировании путей) снимал бы здоровый путь.
    Duplicate,
    /// Отброшен: не своя группа, не нам, не тот отправитель, повтор, мусор.
    Drop,
}

/// Приём фрейма группы (раздел 7, правила 1–6). `relayed` — кадр пришёл
/// через пира-релея (`MESH_FORWARD`): прямой адрес при этом не записывается,
/// PING/PUNCH не отвечаются (L2 — только данные).
fn handle_group_frame(env: &Env, src: SocketAddr, datagram: &[u8], relayed: bool) -> FrameVerdict {
    env.stats.rx_pkts.fetch_add(1, Ordering::Relaxed);
    env.stats
        .rx_bytes
        .fetch_add(datagram.len() as u64, Ordering::Relaxed);
    let Ok((_, h)) = proto::parse_group_header(datagram) else {
        return FrameVerdict::Drop;
    };
    let now = Instant::now();
    // Время для кольца дедупа — до захвата групп (uptime_ms берёт meta).
    let now_ms = uptime_ms(env) as u32;
    let is_relay = relayed || src == env.server();
    // 1. Группа известна, эпоха — текущая или прошлая в пределах grace.
    let key = {
        let mut g = env.groups.lock().unwrap();
        let Some(gs) = g.get_mut(&h.gid) else {
            return FrameVerdict::Drop;
        };
        match gs.rx_key(h.epoch, now) {
            Some(k) => k,
            None => {
                // Сигнал «эпоха новее» — только от правдоподобно подлинных.
                return if gs.epoch_hint(&h, src, is_relay, now) {
                    FrameVerdict::NeedGroup(h.gid)
                } else {
                    FrameVerdict::Drop
                };
            }
        }
    };
    // 2. Расшифровка (подлинность заголовка — он в AAD).
    let Ok((typ, h, ctr, payload)) = proto::open_group(&key, datagram) else {
        return FrameVerdict::Drop;
    };
    // 6. DATA: внутренний источник (IPv4 или IPv6 оверлея) — сам отправитель.
    if typ == proto::grp::DATA && crate::ipv6::source_member(&payload) != Some(h.src) {
        return FrameVerdict::Drop;
    }
    let mut became_direct: Option<String> = None;
    let reply = {
        let mut g = env.groups.lock().unwrap();
        let Some(gs) = g.get_mut(&h.gid) else {
            return FrameVerdict::Drop;
        };
        // 2. Адресован нам; 3. отправитель — текущий участник, не мы.
        if h.dst != gs.my_ip || h.src == gs.my_ip {
            return FrameVerdict::Drop;
        }
        let Some(peer) = gs.members.get(&h.src) else {
            return FrameVerdict::Drop;
        };
        // 5. Через релей или с адреса пира, известного от сервера. Через релея
        // (L2) адрес отправителя произволен — подлинность уже дал ключ группы.
        if !is_relay && !peer.knows(src) {
            return FrameVerdict::Drop;
        }
        // 4. Окно повторов (того ключа, которым открыт фрейм) — последним:
        //    отвергнутый фрейм счётчик не тратит. Перед ним — дедуп на выходе
        //    (issue #25): повтор уже доставленного кадра отличается от
        //    подделки/старика и получает ACK, а не NACK.
        let Some(ring) = gs.rx_dedup(&key, h.src, now_ms) else {
            return FrameVerdict::Drop;
        };
        if ring.seen(ctr, now_ms) {
            // Не инжектим, окно не трогаем, прямой канал не поднимаем: кадр
            // уже доставлен, но пир жив — ответ придёт ACK-ом.
            env.stats.dup_dropped.fetch_add(1, Ordering::Relaxed);
            if let Some(peer) = gs.members.get_mut(&h.src) {
                peer.last_rx = now;
            }
            return FrameVerdict::Duplicate;
        }
        let Some(win) = gs.rx_window(&key, h.src) else {
            return FrameVerdict::Drop;
        };
        if !win.commit(ctr) {
            return FrameVerdict::Drop;
        }
        // Кольцо заполняется только после успешного commit: подделанный кадр
        // (AEAD не сошёлся) и повтор вне окна его не отравляют.
        if let Some(ring) = gs.rx_dedup(&key, h.src, now_ms) {
            ring.record(ctr, now_ms);
        }
        let peer = gs.members.get_mut(&h.src).expect("участник проверен");
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
        // Через релея heartbeat не отвечаем: ответ ушёл бы не туда (dst —
        // исходный отправитель), а прямой канал его и так покрывает.
        if relayed {
            None
        } else {
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
    FrameVerdict::Accepted
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

/// IP-пакет из адаптера → пиру. Путь выбирает [`PathTable::choose`] по
/// измеренной стоимости (§3.6): прямой → релей сервера → релей через пира.
/// Отказ выбранного пути (`record_failure` + `PathLost`) — следующий кандидат:
/// реле пробуются по очереди (до [`RELAY_TRIES`]), затем сервер.
///
/// Дублирование (issue #25): маленький пакет к цели, которая умеет дедуп
/// (`caps::DUP`), уходит по нескольким путям — копии **одной и той же**
/// датаграммы.
///
/// Инвариант: кадр запечатывается **один раз** и может быть отправлен по
/// любому числу путей. Повторная запечатки того же payload под тем же
/// счётчиком запрещена — это повтор nonce; per-flow seq здесь один на все
/// пути, потому что кадр один.
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
    let (key, h, ctr, direct, dst_ed, peer_caps) = {
        let mut g = env.groups.lock().unwrap();
        let Some(gid) = pick_group(&g, dst) else {
            return;
        };
        let gs = g.get_mut(&gid).expect("pick_group вернул свою группу");
        let Some(peer) = gs.members.get(&dst) else {
            return;
        };
        let (direct, dst_ed, caps) = (peer.direct_addr, peer.pubkey, peer.mesh_caps);
        let (k, h, c) = gs.next_frame(gid, dst);
        (k, h, c, direct, dst_ed, caps)
    };
    // Запечатали один раз — все копии ниже отправляют эти же байты.
    let frame = proto::seal_group(&key, proto::grp::DATA, &h, ctr, bytes);
    let connected = env.meta.lock().unwrap().connected;
    let now_ms = uptime_ms(env);
    let (chosen, changes) = env.paths.choose(dst, now_ms, connected);
    for ch in changes {
        emit_path_change(env, ch);
    }
    // Дополнительные пути (issue #25) — до отправки: решение не зависит от
    // того, принял ли кадр выбранный путь. Прямой путь без адреса уже уйдёт
    // сервером, и копия «сервером» была бы второй одинаковой датаграммой.
    let extra = if chosen == Some(PathKind::Direct) && direct.is_none() {
        Vec::new()
    } else {
        dup_extra_paths(env, dst, peer_caps, bytes.len(), chosen, now_ms, connected)
    };
    match chosen {
        Some(PathKind::Direct) => match direct {
            Some(a) => env.send(&frame, a),
            // Адрес прямого канала пропал между пересчётом и отправкой:
            // путь сломан, кадр не теряем — сервер доставит.
            None => {
                env.paths.record_failure(dst);
                env.emit(Event::PathLost {
                    ip: dst,
                    name: peer_name(env, dst),
                });
                env.send(&frame, env.server());
            }
        },
        Some(PathKind::PeerRelay { .. }) => {
            if !try_relay(env, dst, dst_ed, &frame) {
                // Реле не приняло (нет сессии/лимит/неизвестная цель):
                // путь сломан, следующий кандидат — сервер (следующий тик
                // пересчитает и, возможно, выберет другое реле).
                env.paths.record_failure(dst);
                env.emit(Event::PathLost {
                    ip: dst,
                    name: peer_name(env, dst),
                });
                env.send(&frame, env.server());
            }
        }
        // Пути нет (нет связи и измерений) — пробуем сервер: если он мёртв,
        // route_packet всё равно не теряет пакет (отправка в мёртвый адрес
        // ничего не даёт, но и вреда нет).
        Some(PathKind::Server) | None => env.send(&frame, env.server()),
    }
    // Копии по дополнительным путям (issue #25): те же байты кадра, без
    // перезапечатки. Отказ копии не трогает таблицу путей: её состояние
    // поправят обычные измерения, а путь к цели уже выбран.
    for kind in extra {
        if send_extra(env, dst_ed, direct, &frame, kind) {
            env.stats.dup_sent.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Входы правила дублирования (issue #25): так сигнатура не разрастается, а
/// тест задаёт их по отдельности.
struct DupQuery<'a> {
    cfg: &'a crate::store::MeshConfig,
    /// Сколько путей копировать (`Config::duplicate_paths`).
    n_paths: u8,
    peer_caps: u8,
    pinned: bool,
    pkt_len: usize,
    /// EWMA скорости цели, кбит/с.
    rate_kbps: f64,
    chosen: Option<PathKind>,
    /// Доступные пути по возрастанию стоимости (`PathTable::fallbacks`).
    paths: &'a [PathKind],
}

/// Правило выбора путей для дублирования (issue #25) без движка — чистая
/// функция, чтобы её можно было проверить юнит-тестом.
///
/// Копии шлются, только если: дублирование включено, пакет не больше
/// `duplicate_max_pkt`, получатель умеет дедуп (`caps::DUP`), цель не
/// закреплена вручную (pin сильнее автоматики), поток цели не быстрее
/// `duplicate_max_kbps`, доступно ≥ 2 пути и каждый следующий не дороже
/// [`DUP_COST_RATIO`]× лучшего (+ [`DUP_COST_SLACK_MS`]).
///
/// Возвращает пути **сверх** выбранного: не больше `n_paths - 1`.
fn dup_plan(q: &DupQuery, cost_ms: impl Fn(PathKind) -> Option<f64>) -> Vec<PathKind> {
    let cfg = q.cfg;
    if !cfg.duplicate || q.pkt_len > usize::from(cfg.duplicate_max_pkt) {
        return Vec::new();
    }
    // Пир не умеет дедуп — копии для него мусор (и трафик).
    if !proto::mesh::caps::has(q.peer_caps, proto::mesh::caps::DUP) {
        return Vec::new();
    }
    // Ручное закрепление сильнее автоматики: у пина ровно один путь.
    if q.pinned || q.chosen.is_none() || q.paths.len() < 2 {
        return Vec::new();
    }
    // Быстрый поток дублировать нельзя: полоса удвоится на потоке, которому
    // это не нужно (дублирование — для редкого latency-sensitive трафика).
    if q.rate_kbps > f64::from(cfg.duplicate_max_kbps) {
        return Vec::new();
    }
    let best = q
        .paths
        .iter()
        .filter_map(|k| cost_ms(*k))
        .fold(f64::INFINITY, f64::min);
    if !best.is_finite() {
        return Vec::new();
    }
    let limit = usize::from(q.n_paths);
    let mut out = Vec::new();
    for kind in q.paths {
        if Some(*kind) == q.chosen {
            continue;
        }
        if out.len() + 1 >= limit {
            break;
        }
        match cost_ms(*kind) {
            // `fallbacks` отсортирован по стоимости: дальше только дороже.
            Some(c) if c <= best * DUP_COST_RATIO + DUP_COST_SLACK_MS => out.push(*kind),
            _ => break,
        }
    }
    out
}

/// RTT пути до получателя `ip`, мс (issue #25): оценка стоимости для правила
/// «второй путь не хуже 1.5× лучшего». Прямой канал — из PONG, сервер — из
/// CTRL_PONG, релей — из `MESH_ROUTE_OK` (запоминает движок).
fn path_rtt_ms(env: &Env, ip: u32, kind: PathKind, now_ms: u64) -> Option<f64> {
    match kind {
        PathKind::Direct => {
            let g = env.groups.lock().unwrap();
            g.values()
                .find_map(|gs| gs.members.get(&ip).and_then(|p| p.rtt_ms))
                .map(|r| r as f64)
        }
        PathKind::Server => env.paths.server_rtt().map(f64::from),
        PathKind::PeerRelay { via } => {
            let d = env.dup.lock().unwrap();
            d.relay
                .get(&(ip, via))
                .filter(|(_, at)| now_ms.saturating_sub(*at) <= DUP_RELAY_FRESH_MS)
                .map(|(rtt, _)| *rtt)
        }
    }
}

/// Дополнительные пути для копий кадра (issue #25): правила, которым нужно
/// состояние движка, — EWMA скорости цели, предел одновременных целей,
/// закрепление, доступные пути и их RTT.
fn dup_extra_paths(
    env: &Env,
    dst: u32,
    peer_caps: u8,
    pkt_len: usize,
    chosen: Option<PathKind>,
    now_ms: u64,
    connected: bool,
) -> Vec<PathKind> {
    let cfg = env.cfg.lock().unwrap().mesh.clone();
    if !cfg.duplicate {
        return Vec::new();
    }
    // EWMA скорости цели (кбит/с) — с учётом этого пакета.
    let rate_kbps = {
        let mut d = env.dup.lock().unwrap();
        d.rate
            .retain(|_, r| now_ms.saturating_sub(r.at_ms) < DUP_TARGET_TTL_MS * 6);
        d.rate.entry(dst).or_default().observe(pkt_len, now_ms)
    };
    // Предел одновременно дублируемых целей: больше DUP_TARGETS_MAX — это уже
    // дублирование всего трафика, а не маленького latency-sensitive.
    {
        let mut d = env.dup.lock().unwrap();
        d.active
            .retain(|_, at| now_ms.saturating_sub(*at) < DUP_TARGET_TTL_MS);
        if !d.active.contains_key(&dst) && d.active.len() >= DUP_TARGETS_MAX {
            return Vec::new();
        }
    }
    let pinned = env.paths.pin_of(dst).is_some();
    let fb = env.paths.fallbacks(dst, now_ms, connected);
    let n_paths = env.cfg.lock().unwrap().duplicate_paths();
    let q = DupQuery {
        cfg: &cfg,
        n_paths,
        peer_caps,
        pinned,
        pkt_len,
        rate_kbps,
        chosen,
        paths: &fb,
    };
    let extra = dup_plan(&q, |k| path_rtt_ms(env, dst, k, now_ms));
    if !extra.is_empty() {
        env.dup.lock().unwrap().active.insert(dst, now_ms);
    }
    extra
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
    // Замеры прямого канала (RTT из PONG по прямому пути) и падения.
    let mut direct_rtts: Vec<(u32, u32)> = Vec::new();
    let mut failures: Vec<u32> = Vec::new();
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
                    failures.push(ip);
                    events.push(Event::DirectLost {
                        gid: *gid,
                        ip,
                        name: peer.name.clone(),
                    });
                }
                // RTT прямого канала — в таблицу путей (стоимость L0).
                if peer.direct_addr.is_some()
                    && let Some(rtt) = peer.rtt_ms
                {
                    // RTT в протоколе — u64 мс; для таблицы хватает u32.
                    direct_rtts.push((ip, u32::try_from(rtt).unwrap_or(u32::MAX)));
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
    // Таблица путей — свой короткий захват, без блокировки групп.
    let now_ms = uptime_ms(env);
    for (ip, rtt) in direct_rtts {
        env.paths.record_direct_rtt(ip, rtt, now_ms);
    }
    for ev in events {
        env.emit(ev);
    }
    for (f, to) in frames {
        env.send(&f, to);
    }
    if !failures.is_empty() {
        // Прямой канал умер: путь снимается и пересчитывается сразу, не
        // дожидаясь 10-секундного тика (§3.6, «немедленно при падении»).
        for ip in failures {
            env.paths.record_failure(ip);
        }
        paths_round(env, connected, now);
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
            Event::FedGroups { groups } => {
                eprintln!("[engine] доступно федерированных групп: {}", groups.len())
            }
            Event::ServerPingResult { .. } => {}
            // Этап 9: путь доставки, пробы, релей. UI-часть — T2/T3/T5.
            Event::PathChanged { .. } | Event::PathLost { .. } => {}
            Event::ProbeResult { .. } => {}
            Event::RelayStats { .. } => {}
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
            mesh: Vec::new(),
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
            mesh_x: None,
            mesh_caps: 0,
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
                mesh_x: None,
                mesh_caps: 0,
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

    // ---------- этап 9: CTRL_PONG с меткой, пути, проба ----------

    /// Заглушка адаптера: движку для тестов Env адаптер не нужен.
    struct NullTun;

    impl TunDev for NullTun {
        fn inject(&self, _packet: &[u8]) -> Result<()> {
            Ok(())
        }
        fn ensure_address(&self, _ip: u32) -> Result<()> {
            Ok(())
        }
    }

    /// Минимальный `Env` без потоков: мета/группы/сокет/таблица путей.
    fn test_env(server: SocketAddr) -> (Arc<Env>, mpsc::Receiver<Event>) {
        test_env_tun(server, Arc::new(NullTun))
    }

    /// То же, но со своей заглушкой адаптера (счётчик инъекций в тестах дедупа).
    fn test_env_tun(server: SocketAddr, tun: Arc<dyn TunDev>) -> (Arc<Env>, mpsc::Receiver<Event>) {
        let (ev_tx, ev_rx) = mpsc::channel();
        let meta = Arc::new(Mutex::new(Meta {
            connected: true,
            transport: Transport::Udp,
            server,
            server_label: String::new(),
            group_list: Vec::new(),
            fed_groups: Vec::new(),
            rx_hist: VecDeque::new(),
            tx_hist: VecDeque::new(),
            started: Instant::now(),
            server_rtt_ms: None,
            mesh_enabled: true,
            relay_bytes: 0,
            mesh_sessions: 0,
        }));
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let paths = Arc::new(PathTable::new(&std::collections::BTreeMap::new()));
        let env = Arc::new(Env {
            groups: Arc::new(Mutex::new(HashMap::new())),
            meta,
            stats: Arc::new(Stats::new()),
            ev: ev_tx,
            cfg: Arc::new(Mutex::new(Config::default())),
            save: Arc::new(|_| {}),
            identity: proto::Identity::generate(),
            server: Mutex::new(server),
            sock,
            tcp: Mutex::new(None),
            tun,
            quit: AtomicBool::new(false),
            key_log: KeyLog::default(),
            mesh: Arc::new(Mutex::new(mesh::MeshState::new(true))),
            dht: Arc::new(Mutex::new(dht::Dht::new([1u8; 32]))),
            mesh_finds: Arc::new(Mutex::new(Vec::new())),
            paths: paths.clone(),
            probes: Arc::new(probe::ProbeState::new()),
            dup: Mutex::new(DupState::default()),
        });
        (env, ev_rx)
    }

    fn pending(label: u64, report: bool) -> PendingPong {
        PendingPong {
            addr: "203.0.113.9:5555".parse().unwrap(),
            label,
            at: Instant::now() - Duration::from_millis(30),
            report,
        }
    }

    // ---------- issue #25: дедупликация на выходе и дублирование путей ----------

    /// Заглушка адаптера со счётчиком инъекций.
    #[derive(Default)]
    struct CountTun {
        injected: AtomicU64,
    }

    impl TunDev for CountTun {
        fn inject(&self, _packet: &[u8]) -> Result<()> {
            self.injected.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn ensure_address(&self, _ip: u32) -> Result<()> {
            Ok(())
        }
    }

    /// Минимальный IPv4-пакет (заголовок 20 байт + данные).
    fn ipv4(src: u32, dst: u32, data: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        let len = (20 + data.len()) as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src.to_be_bytes());
        p[16..20].copy_from_slice(&dst.to_be_bytes());
        p.extend_from_slice(data);
        p
    }

    /// Группа с одним участником: свой ip, ключ `[2; 32]`, эпоха 1.
    fn test_group(gid: u32, my_ip: u32, peer_ip: u32, peer_addr: SocketAddr) -> GroupSess {
        let mut gs = GroupSess::new(
            &payloads::GroupState {
                gid,
                rev: 1,
                epoch: 1,
                revoke_prev: false,
                name: "g".into(),
                owner: [1; 32],
                private: false,
                key: [2; 32],
                deleted: false,
                my_ip,
                members: Vec::new(),
                mesh: Vec::new(),
            },
            Instant::now(),
            KeyLog::default(),
        );
        gs.members.insert(
            peer_ip,
            PeerSess {
                pubkey: [3; 32],
                name: "bravo".into(),
                status: String::new(),
                online: true,
                ip: peer_ip,
                endpoint: Some(peer_addr),
                candidates: Vec::new(),
                direct_addr: None,
                last_rx: Instant::now(),
                last_direct: None,
                rtt_ms: Some(20),
                mesh_x: None,
                mesh_caps: proto::mesh::caps::MESH | proto::mesh::caps::DUP,
            },
        );
        gs
    }

    /// Кадр группы под ключом `[2; 32]` (тот же, что у `test_group`).
    fn test_frame(gid: u32, src: u32, dst: u32, ctr: u64, payload: &[u8]) -> Vec<u8> {
        proto::seal_group(
            &[2u8; 32],
            proto::grp::DATA,
            &proto::GroupHeader {
                gid,
                src,
                dst,
                epoch: 1,
            },
            ctr,
            payload,
        )
    }

    #[test]
    fn дедуп_повтор_не_инжектится_дважды() {
        let server: SocketAddr = "203.0.113.9:5555".parse().unwrap();
        let tun = Arc::new(CountTun::default());
        let (env, _ev) = test_env_tun(server, tun.clone());
        let peer: SocketAddr = "198.51.100.7:4000".parse().unwrap();
        let (gid, my_ip, peer_ip) = (1, 0x6442_0001, 0x6442_0102);
        env.groups
            .lock()
            .unwrap()
            .insert(gid, test_group(gid, my_ip, peer_ip, peer));
        let pkt = ipv4(peer_ip, my_ip, b"dedup");
        let f = test_frame(gid, peer_ip, my_ip, 5, &pkt);
        assert_eq!(
            handle_group_frame(&env, peer, &f, false),
            FrameVerdict::Accepted
        );
        assert_eq!(tun.injected.load(Ordering::Relaxed), 1);
        // Второй экземпляр того же кадра (копия по другому пути) — Duplicate.
        assert_eq!(
            handle_group_frame(&env, peer, &f, false),
            FrameVerdict::Duplicate
        );
        assert_eq!(
            tun.injected.load(Ordering::Relaxed),
            1,
            "повтор не инжектится"
        );
        assert_eq!(env.stats.dup_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn дедуп_повтор_даёт_ack_а_не_nack() {
        // Главный фикс issue #25: отброшенный повтор — успех для отправителя,
        // иначе NACK снимал бы здоровый путь (record_failure по ForwardFailed).
        let server: SocketAddr = "203.0.113.9:5555".parse().unwrap();
        let tun = Arc::new(CountTun::default());
        let (env, _ev) = test_env_tun(server, tun);
        let peer: SocketAddr = "198.51.100.7:4000".parse().unwrap();
        let (gid, my_ip, peer_ip) = (1, 0x6442_0001, 0x6442_0102);
        env.groups
            .lock()
            .unwrap()
            .insert(gid, test_group(gid, my_ip, peer_ip, peer));
        let pkt = ipv4(peer_ip, my_ip, b"ack");
        let f = test_frame(gid, peer_ip, my_ip, 7, &pkt);
        let first = handle_group_frame(&env, peer, &f, true);
        let repeat = handle_group_frame(&env, peer, &f, true);
        assert_eq!(first, FrameVerdict::Accepted);
        assert_eq!(repeat, FrameVerdict::Duplicate);
        assert!(delivery_result_of(first).0);
        assert_eq!(
            delivery_result_of(repeat),
            (true, proto::mesh::code::REJECTED),
            "дубликат подтверждается (ACK), а не отвергается (NACK)"
        );
    }

    #[test]
    fn дедуп_истекает_по_времени() {
        let mut ring = DedupRing::default();
        ring.record(7, 1_000);
        assert!(ring.seen(7, 1_000), "сразу после приёма — повтор");
        assert!(
            ring.seen(7, 1_000 + DEDUP_TTL_MS - 1),
            "в пределах TTL — ещё повтор"
        );
        assert!(
            !ring.seen(7, 1_000 + DEDUP_TTL_MS),
            "после TTL — уже не дубликат (решает окно повторов)"
        );
        // Кольцо ограничено: старые seq вытесняются новыми.
        for i in 0..DEDUP_WINDOW as u64 {
            ring.record(100 + i, 1_000);
        }
        assert!(!ring.seen(7, 1_000), "seq вытеснен кольцом");
    }

    #[test]
    fn дедуп_не_видит_повтор_после_смены_ключа() {
        let peer: SocketAddr = "198.51.100.7:4000".parse().unwrap();
        let (gid, my_ip, peer_ip) = (1, 0x6442_0001, 0x6442_0102);
        let mut gs = test_group(gid, my_ip, peer_ip, peer);
        let key1 = [2u8; 32];
        gs.rx_dedup(&key1, peer_ip, 1_000).unwrap().record(5, 1_000);
        assert!(gs.rx_dedup(&key1, peer_ip, 1_000).unwrap().seen(5, 1_000));
        // Ротация ключа: кольцо принадлежит ключу и начинается с нуля.
        gs.set_key(2, [9u8; 32], false, Instant::now());
        assert!(
            !gs.rx_dedup(&[9u8; 32], peer_ip, 1_000)
                .unwrap()
                .seen(5, 1_000),
            "новый ключ не наследует кольцо прежнего"
        );
        // Прошлый ключ ещё принимается (grace) — и его кольцо цело.
        assert!(gs.rx_dedup(&key1, peer_ip, 1_000).unwrap().seen(5, 1_000));
    }

    #[test]
    fn дедуп_память_ограничена_числом_потоков() {
        let peer: SocketAddr = "198.51.100.7:4000".parse().unwrap();
        let (gid, my_ip, peer_ip) = (1, 0x6442_0001, 0x6442_0102);
        let mut gs = test_group(gid, my_ip, peer_ip, peer);
        let key = [2u8; 32];
        for i in 0..(DEDUP_FLOWS_MAX as u32 * 3) {
            let src = 0x6442_1000 + i;
            let now = 1_000 + i;
            gs.rx_dedup(&key, src, now)
                .unwrap()
                .record(u64::from(i), now);
        }
        assert_eq!(
            gs.cur.dedup.len(),
            DEDUP_FLOWS_MAX,
            "число потоков в кольце ограничено"
        );
        // Простаивающий поток выбрасывается, даже если место есть.
        let stale = 0x6442_9000;
        gs.rx_dedup(&key, stale, 1_000).unwrap();
        let later = 1_000 + DEDUP_FLOW_IDLE_MS + 1;
        gs.rx_dedup(&key, 0x6442_A000, later).unwrap();
        assert!(
            !gs.cur.dedup.contains_key(&stale),
            "простаивающий поток выброшен"
        );
    }

    #[test]
    fn дедуп_не_трогает_окно_повторов() {
        let server: SocketAddr = "203.0.113.9:5555".parse().unwrap();
        let tun = Arc::new(CountTun::default());
        let (env, _ev) = test_env_tun(server, tun);
        let peer: SocketAddr = "198.51.100.7:4000".parse().unwrap();
        let (gid, my_ip, peer_ip) = (1, 0x6442_0001, 0x6442_0102);
        env.groups
            .lock()
            .unwrap()
            .insert(gid, test_group(gid, my_ip, peer_ip, peer));
        let pkt = ipv4(peer_ip, my_ip, b"window");
        let f = test_frame(gid, peer_ip, my_ip, 5, &pkt);
        assert_eq!(
            handle_group_frame(&env, peer, &f, false),
            FrameVerdict::Accepted
        );
        let (max_before, bits_before) = {
            let g = env.groups.lock().unwrap();
            let w = g[&gid].cur.rx[&peer_ip].clone();
            (w.max(), w.check(4))
        };
        assert_eq!(max_before, Some(5));
        assert_eq!(
            handle_group_frame(&env, peer, &f, false),
            FrameVerdict::Duplicate
        );
        let g = env.groups.lock().unwrap();
        let w = &g[&gid].cur.rx[&peer_ip];
        assert_eq!(w.max(), max_before, "окно не сдвинулось повтором");
        assert_eq!(w.check(4), bits_before, "биты окна не изменились");
    }

    /// Правила дублирования без движка: пути Direct (10 мс) и Server (12 мс).
    fn dup_cfg() -> crate::store::MeshConfig {
        crate::store::MeshConfig {
            duplicate: true,
            ..Default::default()
        }
    }

    fn dup_paths() -> Vec<PathKind> {
        vec![PathKind::Direct, PathKind::Server]
    }

    fn dup_cost(kind: PathKind) -> Option<f64> {
        Some(match kind {
            PathKind::Direct => 10.0,
            PathKind::Server => 12.0,
            PathKind::PeerRelay { .. } => 20.0,
        })
    }

    /// Запрос с выбранным Direct и путями `paths`.
    fn dup_query<'a>(
        cfg: &'a crate::store::MeshConfig,
        caps: u8,
        paths: &'a [PathKind],
    ) -> DupQuery<'a> {
        DupQuery {
            cfg,
            n_paths: 2,
            peer_caps: caps,
            pinned: false,
            pkt_len: 64,
            rate_kbps: 0.0,
            chosen: Some(PathKind::Direct),
            paths,
        }
    }

    #[test]
    fn дублирование_не_включается_без_caps() {
        let cfg = dup_cfg();
        let paths = dup_paths();
        let no_dup = proto::mesh::caps::MESH | proto::mesh::caps::RELAY;
        assert!(
            dup_plan(&dup_query(&cfg, no_dup, &paths), dup_cost).is_empty(),
            "без caps::DUP копии не шлём"
        );
        let with_dup = no_dup | proto::mesh::caps::DUP;
        assert_eq!(
            dup_plan(&dup_query(&cfg, with_dup, &paths), dup_cost),
            vec![PathKind::Server]
        );
        // Выключенное дублирование — пусто даже с битом.
        let off = crate::store::MeshConfig {
            duplicate: false,
            ..cfg.clone()
        };
        assert!(dup_plan(&dup_query(&off, with_dup, &paths), dup_cost).is_empty());
        // Ручное закрепление сильнее автоматики: у пина один путь.
        let pinned = DupQuery {
            pinned: true,
            ..dup_query(&cfg, with_dup, &paths)
        };
        assert!(dup_plan(&pinned, dup_cost).is_empty());
    }

    #[test]
    fn дублирование_только_для_малого_трафика() {
        let cfg = dup_cfg();
        let caps = proto::mesh::caps::MESH | proto::mesh::caps::DUP;
        let paths = dup_paths();
        let q = dup_query(&cfg, caps, &paths);
        // Размер: больше duplicate_max_pkt — не дублируем.
        let big = DupQuery {
            pkt_len: usize::from(cfg.duplicate_max_pkt) + 1,
            ..dup_query(&cfg, caps, &paths)
        };
        assert!(
            dup_plan(&big, dup_cost).is_empty(),
            "большой пакет не дублируется"
        );
        assert_eq!(dup_plan(&q, dup_cost), vec![PathKind::Server]);
        // Скорость: быстрый поток цели — не дублируем.
        let fast = DupQuery {
            rate_kbps: f64::from(cfg.duplicate_max_kbps) + 1.0,
            ..dup_query(&cfg, caps, &paths)
        };
        assert!(
            dup_plan(&fast, dup_cost).is_empty(),
            "быстрый поток не дублируется"
        );
        // Стоимость: второй путь дороже 1.5× лучшего (+ допуск) — не дублируем.
        let far = |kind: PathKind| match kind {
            PathKind::Direct => Some(10.0),
            _ => Some(100.0),
        };
        assert!(dup_plan(&q, far).is_empty(), "дорогой второй путь не берём");
        // Три пути: duplicate_paths = 3 — обе копии, кроме выбранной.
        let three = crate::store::MeshConfig {
            duplicate_paths: 3,
            ..cfg.clone()
        };
        let relay = PathKind::PeerRelay { via: [7u8; 32] };
        let mut paths3 = dup_paths();
        paths3.push(relay);
        assert_eq!(
            dup_plan(
                &DupQuery {
                    n_paths: 3,
                    ..dup_query(&three, caps, &paths3)
                },
                dup_cost
            ),
            vec![PathKind::Server, relay]
        );
        // duplicate_paths = 2 — только один дополнительный путь.
        assert_eq!(
            dup_plan(&dup_query(&cfg, caps, &paths3), dup_cost),
            vec![PathKind::Server]
        );
    }

    #[test]
    fn ctrl_pong_метка_даёт_rtt_и_питает_таблицу_путей() {
        let server: SocketAddr = "203.0.113.9:5555".parse().unwrap();
        let (env, ev) = test_env(server);
        let mut st = State::new([1; 32]);
        // Явный пинг: RTT по совпавшей метке + событие.
        st.pending_ping = Some(pending(42, true));
        on_ctrl(&env, &mut st, ctrl::CTRL_PONG, &42u64.to_be_bytes());
        match ev.try_recv().expect("нет события") {
            Event::ServerPingResult {
                addr,
                rtt_ms: Some(rtt),
                success: true,
            } => {
                assert_eq!(addr, server);
                assert!(rtt >= 30, "RTT {rtt}");
            }
            other => panic!("неожиданное событие: {other:?}"),
        }
        assert!(ev.try_recv().is_err());
        assert!(st.pending_ping.is_none());
        assert!(env.meta.lock().unwrap().server_rtt_ms.is_some());
        assert!(
            env.paths.server_rtt().is_some(),
            "RTT сервера — в таблицу путей"
        );

        // Периодический замер (report = false): RTT записан, события нет.
        st.pending_ping = Some(pending(43, false));
        on_ctrl(&env, &mut st, ctrl::CTRL_PONG, &43u64.to_be_bytes());
        assert!(ev.try_recv().is_err(), "молчаливый замер не шлёт событие");
        assert!(st.pending_ping.is_none());

        // Чужая метка: это не наш ответ — ожидание не съедаем, RTT не врём.
        st.pending_ping = Some(pending(7, true));
        on_ctrl(&env, &mut st, ctrl::CTRL_PONG, &8u64.to_be_bytes());
        assert!(st.pending_ping.is_some());
        assert!(ev.try_recv().is_err());

        // Пустой payload (старый сервер без метки): ответ подлинный, RTT
        // неизвестен — событие есть, замер не пишется.
        let before = env.paths.server_rtt();
        st.pending_ping = Some(pending(7, true));
        on_ctrl(&env, &mut st, ctrl::CTRL_PONG, &[]);
        match ev.try_recv().expect("нет события") {
            Event::ServerPingResult {
                rtt_ms: None,
                success: true,
                ..
            } => {}
            other => panic!("неожиданное событие: {other:?}"),
        }
        assert!(st.pending_ping.is_none());
        assert_eq!(env.paths.server_rtt(), before);

        // Мусорная длина (не 8 и не 0) — не наша метка: ожидание цело.
        st.pending_ping = Some(pending(9, true));
        on_ctrl(&env, &mut st, ctrl::CTRL_PONG, &[1, 2, 3]);
        assert!(st.pending_ping.is_some());
        // Без ожидания PONG ничего не делает (не паникует).
        st.pending_ping = None;
        on_ctrl(&env, &mut st, ctrl::CTRL_PONG, &[]);
        assert!(ev.try_recv().is_err());
    }

    #[test]
    fn paths_round_заводит_участников_и_шлёт_событие_пути() {
        let server: SocketAddr = "203.0.113.9:5555".parse().unwrap();
        let (env, ev) = test_env(server);
        // Участник с прямым каналом и замером RTT.
        let mut g = GroupSess::new(
            &payloads::GroupState {
                gid: 1,
                rev: 1,
                epoch: 1,
                revoke_prev: false,
                name: "g".into(),
                owner: [1; 32],
                private: false,
                key: [2; 32],
                deleted: false,
                my_ip: 0x6442_0001,
                members: Vec::new(),
                mesh: Vec::new(),
            },
            Instant::now(),
            KeyLog::default(),
        );
        let peer_ip = 0x6442_0102;
        g.members.insert(
            peer_ip,
            PeerSess {
                pubkey: [3; 32],
                name: "bravo".into(),
                status: String::new(),
                online: true,
                ip: peer_ip,
                endpoint: None,
                candidates: Vec::new(),
                direct_addr: Some("198.51.100.7:4000".parse().unwrap()),
                last_rx: Instant::now(),
                last_direct: Some(Instant::now()),
                rtt_ms: Some(20),
                mesh_x: None,
                mesh_caps: 0,
            },
        );
        env.groups.lock().unwrap().insert(1, g);
        env.paths.record_server_rtt(50, 0);
        // Прямой замер приходит из RTT-раунда (PONG по прямому каналу).
        env.paths.record_direct_rtt(peer_ip, 20, 0);
        paths_round(&env, true, Instant::now());
        // Сервер подключён и прямой канал дешевле → путь Direct; событие —
        // PathChanged, и в снимке у участника будет путь.
        match ev.try_recv().expect("нет события пути") {
            Event::PathChanged {
                ip,
                name,
                path: PathKind::Direct,
                ..
            } => {
                assert_eq!((ip, name.as_str()), (peer_ip, "bravo"));
            }
            other => panic!("неожиданное событие: {other:?}"),
        }
        assert_eq!(env.paths.current(peer_ip), Some(PathKind::Direct));
        // Второй раунд без изменений — без событий.
        paths_round(&env, true, Instant::now());
        assert!(ev.try_recv().is_err());
    }

    #[test]
    fn проба_сервера_идёт_своим_потоком_и_становится_событием() {
        let server: SocketAddr = "203.0.113.9:5555".parse().unwrap();
        let (env, ev) = test_env(server);
        let mut st = State::new([1; 32]);
        // Проба не требует сессии и не занимает сокет движка: задание уходит
        // в отдельный поток, мгновенного события нет.
        do_cmd(&env, &mut st, Cmd::ProbeServer { addr: server });
        assert_eq!(env.probes.pending(), 1);
        assert!(ev.try_recv().is_err(), "результат не мгновенный");
        // Ответ сервера (сверка по nonce) — `tick` отдаёт его событием.
        let nonce = env.probes.pending_nonces()[0];
        let resp = payloads::enc_probe_resp(&payloads::ProbeResp {
            nonce,
            ts_ms: 0,
            ed_pub: None,
        });
        assert!(env.probes.on_response(server, &resp).is_some());
        tick(&env, &mut st, Instant::now());
        match ev.try_recv().expect("нет события пробы") {
            Event::ProbeResult {
                addr,
                success: true,
                rtt_ms: Some(_),
                key_match: None,
            } => assert_eq!(addr, server),
            other => panic!("неожиданное событие: {other:?}"),
        }
        // Молчание сервера — «недоступен» с тем же адресом.
        do_cmd(&env, &mut st, Cmd::ProbeServer { addr: server });
        let nonce = env.probes.pending_nonces()[0];
        env.probes.timeout_nonce(nonce);
        tick(&env, &mut st, Instant::now());
        match ev.try_recv().expect("нет события пробы") {
            Event::ProbeResult {
                addr,
                success: false,
                rtt_ms: None,
                key_match: None,
            } => assert_eq!(addr, server),
            other => panic!("неожиданное событие: {other:?}"),
        }
        assert_eq!(env.probes.pending(), 0);
    }

    #[test]
    fn команды_путей_пишут_конфиг_и_таблицу() {
        let server: SocketAddr = "203.0.113.9:5555".parse().unwrap();
        let (env, ev) = test_env(server);
        let mut st = State::new([1; 32]);
        let ip = 0x6442_0102;
        do_cmd(
            &env,
            &mut st,
            Cmd::PinPath {
                ip,
                path: PathKind::Server,
            },
        );
        assert_eq!(
            env.cfg.lock().unwrap().pinned_paths.get("100.66.1.2"),
            Some(&"server".to_string())
        );
        assert_eq!(env.paths.pin_of(ip), Some(PathKind::Server));
        do_cmd(&env, &mut st, Cmd::SetRelayEnabled(false));
        assert!(!env.cfg.lock().unwrap().mesh.relay_enabled);
        do_cmd(&env, &mut st, Cmd::SetMeshEnabled(false));
        assert!(!env.cfg.lock().unwrap().mesh.enabled);
        assert!(!env.mesh.lock().unwrap().enabled());
        assert!(!env.meta.lock().unwrap().mesh_enabled);
        do_cmd(&env, &mut st, Cmd::UnpinPath { ip });
        assert!(env.cfg.lock().unwrap().pinned_paths.is_empty());
        assert_eq!(env.paths.pin_of(ip), None);
        // Все команды — локальные: по сети ничего не ушло, но и Notic'ов
        // ровно по одному на команду.
        let mut notices = 0;
        while let Ok(ev) = ev.try_recv() {
            if matches!(ev, Event::Notice(_)) {
                notices += 1;
            }
        }
        assert_eq!(notices, 4);
    }

    /// T4b2: кандидаты `SERVER_HINT` — из `client.json.servers` и DHT-контактов
    /// (ed + addr), без текущего сервера, повторов по адресу и битых строк;
    /// батч не больше `MAX_SERVER_HINT`.
    #[test]
    fn подсказки_серверов_батч_без_повторов_и_своего_сервера() {
        let server: SocketAddr = "127.0.0.1:5555".parse().unwrap();
        let (env, _ev) = test_env(server);
        let hex = |b: u8| proto::hex_of(&[b; 32]);
        let stored = |addr: &str, pk: String| crate::store::StoredServer {
            addr: addr.into(),
            pubkey: pk,
            label: String::new(),
        };
        {
            let mut c = env.cfg.lock().unwrap();
            // Текущий сервер себе же не подсказываем.
            c.servers.push(stored(&server.to_string(), hex(1)));
            c.servers.push(stored("127.0.0.1:5101", hex(2)));
            c.servers.push(stored("127.0.0.1:5102", hex(3)));
            // Повтор адреса с другим ключом — один кандидат (первый).
            c.servers.push(stored("127.0.0.1:5101", hex(4)));
            // Битые строки — пропуск, кадр от них не растёт.
            c.servers.push(stored("не адрес", hex(5)));
            c.servers.push(stored("127.0.0.1:5103", "не hex".into()));
            // DHT-контакты: новый адрес — кандидат, повтор — нет.
            for (ed, addr) in [(6u8, "127.0.0.1:5102"), (7u8, "127.0.0.1:5104")] {
                c.mesh.contacts.push(crate::store::StoredContact {
                    ed: hex(ed),
                    x: String::new(),
                    addr: addr.into(),
                    rtt_ms: 0,
                    seen_s: 0,
                    caps: 0,
                });
            }
        }
        let hints = hint_candidates(&env);
        let addrs: Vec<&str> = hints.iter().map(|h| h.addr.as_str()).collect();
        assert_eq!(
            addrs,
            ["127.0.0.1:5101", "127.0.0.1:5102", "127.0.0.1:5104"],
            "порядок, дедупликация по адресу, пропуск битых"
        );
        assert_eq!(hints[0].ed_pub, [2; 32], "ключ первого кандидата адреса");

        // Батч ограничен MAX_SERVER_HINT (лишние не едут).
        {
            let mut c = env.cfg.lock().unwrap();
            c.servers.clear();
            for i in 0..12u32 {
                c.servers
                    .push(stored(&format!("127.0.0.1:{}", 5200 + i), hex(8)));
            }
        }
        assert_eq!(hint_candidates(&env).len(), payloads::MAX_SERVER_HINT);
    }
}
