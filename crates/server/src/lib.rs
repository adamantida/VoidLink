//! Рандеву-сервер v3 (нормативно — `docs/PROTOCOL.md`): identity, группы,
//! lease IP, приглашения с TTL, kick/ban/unban, передача владения, presence,
//! ротация ключей групп и ключа самого сервера.
//!
//! Рукопожатие HELLO3 → CHALLENGE (cookie) → HELLO3 с cookie → WELCOME.
//! Cookie подтверждает обратный адрес раньше проверки подписи: ответ без
//! cookie меньше запроса, а длинные ответы (GROUP_STATE через FRAG и т. п.)
//! уходят только на адрес, который сам получил CHALLENGE, — сервер больше не
//! усилитель. Сеансовые ключи — static-static + ephemeral-ephemeral X25519
//! (прямая секретность); ctrl-фреймы со счётчиком и окном повторов.
//! Фреймы групп релеятся без расшифровки payload'а — сервер читает только
//! открытый заголовок (gid, src_ip, dst_ip, epoch).
//!
//! Многопоточность: несколько воркеров читают один UDP-сокет параллельно.
//! Состояние — под `RwLock`: релей и частые запросы (PING, LIST, GET_GROUP)
//! берут блокировку на чтение и не мешают друг другу, изменения (JOIN, LEAVE,
//! …) — на запись. Счётчики отправки сессии атомарные, окно повторов — под
//! своим `Mutex`, поэтому и шифрование ответов идёт под блокировкой на
//! чтение. Ответы собираются в «исходящие» и отправляются уже после снятия
//! блокировки.
//!
//! Защита от лишней нагрузки:
//! - релей только от установленной сессии, только участнику той же группы и
//!   только со своим IP группы в заголовке (подмена src_ip отбрасывается);
//! - лимиты ([`Limits`], token bucket): релей и управляющие фреймы на сессию,
//!   HELLO/HELLO3 и открытые ответы (CHALLENGE, UNSUPPORTED, RESET) на IP
//!   (IPv6 — на /64) и общий бюджет открытых ответов на весь сервер, входы
//!   в группу (ротации ключа) на группу;
//! - открытый ответ не длиннее запроса (UNSUPPORTED без текста на короткий
//!   запрос), повтор HELLO3 получает только WELCOME;
//! - приглашения и баны группы ограничены, список групп рассылается всем не
//!   чаще раза в `HOUSEKEEPING_EVERY`, а не на каждую команду;
//! - мусор и чужие фреймы отбрасываются молча, без записи в лог.

pub mod leases;
pub mod metrics;
pub mod persist;
pub mod signals;
pub mod tcp;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use proto::ctrl;
use proto::handshake::{self as hs, Hello3, RotationLink, Welcome};
use proto::payloads::{
    self as pl, AdminInfo, BanEntry, GroupDelta, GroupState, GroupSummary, GroupUpdate, MemberInfo,
    PendingInvite,
};
use rand::Rng;
use tunnel_protocol as proto;

const GID_MIN: u32 = 1;
const GID_MAX: u32 = 254;
/// Участников в группе не больше (адреса — общие на сервер, см. `leases`;
/// предел прежний — из /24 группы протокола v3).
const MAX_MEMBERS: usize = 253;
const HOUSEKEEPING_EVERY: Duration = Duration::from_secs(2);
/// Пауза между LEAVE и повторным JOIN той же identity в ту же группу.
const REJOIN_COOLDOWN: Duration = Duration::from_secs(3);
const SAVE_EVERY: Duration = Duration::from_secs(3);
/// Срочное сохранение (кик, бан, выход, удаление…) — не чаще этого: поток
/// таких команд не превращается в поток записей на диск.
const URGENT_SAVE_GAP: Duration = Duration::from_millis(200);
/// Запас к `epoch` и `rev` при загрузке: состояние пишется раз в
/// `SAVE_EVERY`, и после падения сервера номера, уже выданные клиентам с
/// другим ключом, иначе выдавались бы снова (раздел 5: номера только растут).
const LOAD_MARGIN: u32 = 1 << 16;
/// Лимитер HELLO по IP: шардов и записей в шарде. Переполненный шард
/// сначала выбрасывает восполнившиеся корзины (без потери состояния: новая
/// корзина та же), и только если таких нет — новым адресам отказ.
const IP_SHARDS: usize = 16;
const IP_SHARD_MAX: usize = 4096;
const STATS_EVERY: Duration = Duration::from_secs(300);
/// Как часто воркер проверяет флаг остановки.
const RECV_POLL: Duration = Duration::from_millis(250);
/// Сколько датаграмм подряд одному адресу уходит без паузы.
const SEND_BURST: usize = 8;
/// Пауза между пачками залпа: клиент успевает опустошить буфер приёма.
const SEND_PAUSE: Duration = Duration::from_millis(1);

const NAME_MAX_CHARS: usize = 32;
const STATUS_MAX_CHARS: usize = 100;
const GROUP_NAME_MAX_CHARS: usize = 48;
/// Сколько приглашений максимум в одном INVITE_LIST (~550 байт на запись в
/// худшем случае, ~9 КБ на окно — через FRAG): ответ на один запрос
/// ограничен, остальное клиент дочитывает окнами (LIST_INVITES с gid после
/// последнего).
const INVITES_PER_LIST: usize = 16;
/// Ответ на v2 HELLO и HELLO3 другой версии.
/// Повтор WELCOME на повтор HELLO3 той же попытки — не чаще (клиент
/// повторяет HELLO3 раз в секунду): поток перехваченных HELLO3 с адреса
/// жертвы даёт ей не больше двух WELCOME в секунду.
const WELCOME_RESEND_GAP: Duration = Duration::from_millis(500);
/// Сколько помнится `(ed_pub, eph_pub)` закрытой сессии: дольше срока
/// cookie (текущий и предыдущий bucket — до 60 с) с запасом на часы.
const RETIRED_EPH_TTL: Duration = Duration::from_secs(2 * hs::COOKIE_BUCKET_SECS + 5);
/// Порог, после которого `retired_eph` чистится от истёкших записей.
const RETIRED_EPH_PURGE: usize = 256;

const UNSUPPORTED_TEXT: &str = "сервер VoidLink v4: обновите клиент";

// ---------- конфигурация и запуск ----------

/// Лимиты сервера (раздел 9 спецификации). `Default` — значения по
/// умолчанию из спецификации; `tunnel-server` меняет их флагами.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Релей: фреймов в секунду на сессию (игровой трафик + RTT-зонды) и запас.
    pub relay_rate: f64,
    pub relay_burst: f64,
    /// Управляющие фреймы на сессию.
    pub ctrl_rate: f64,
    pub ctrl_burst: f64,
    /// На IP-адрес (IPv6 — на /64): входящие HELLO / HELLO3 (вместе с
    /// ответом на них — CHALLENGE, UNSUPPORTED, WELCOME) и каждый RESET.
    pub hello_rate: f64,
    pub hello_burst: f64,
    /// На весь сервер: открытые ответы без подтверждённого адреса
    /// (CHALLENGE, UNSUPPORTED, RESET) — поток с подменой адресов не
    /// упирается в лимит одного IP.
    pub plain_rate: f64,
    pub plain_burst: f64,
    /// На группу: входы не-участников (каждый — ротация ключа, а выход после
    /// него — ротация с отзывом): чехарда JOIN/LEAVE не ломает трафик группы.
    pub join_rate: f64,
    pub join_burst: f64,
    /// Сессия без единого пакета столько — офлайн (клиент пингует раз в 5 с).
    pub session_timeout: Duration,
    /// Групп во владении одной identity.
    pub max_owned_groups: usize,
    /// Срок жизни приглашения.
    pub invite_ttl: Duration,
    /// Приглашений и банов на группу: без предела любой владелец раздувал бы
    /// server.json (переписывается раз в 3 с) и списки, которые сервер
    /// обходит постоянно.
    pub max_invites_per_group: usize,
    pub max_bans_per_group: usize,
    /// Живых приглашений на одну цель по всем группам: иначе владельцы
    /// множества групп заваливали бы одну identity окнами приглашений.
    pub max_invites_per_target: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            relay_rate: 4000.0,
            relay_burst: 8000.0,
            ctrl_rate: 50.0,
            ctrl_burst: 100.0,
            hello_rate: 5.0,
            hello_burst: 20.0,
            plain_rate: 2000.0,
            plain_burst: 4000.0,
            join_rate: 1.0,
            join_burst: 10.0,
            session_timeout: Duration::from_secs(30),
            max_owned_groups: 16,
            invite_ttl: Duration::from_secs(7 * 24 * 3600),
            max_invites_per_group: 256,
            max_bans_per_group: 1024,
            max_invites_per_target: 64,
        }
    }
}

pub struct Config {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    /// Число потоков-воркеров (0 — по числу ядер, но не больше 8).
    pub workers: usize,
    /// Не печатать события (для тестов).
    pub quiet: bool,
    pub limits: Limits,
    /// TCP-фолбэк на том же порту, что и UDP (`--tcp` / `--no-tcp`).
    pub tcp: bool,
    /// Адрес HTTP-эндпоинта метрик (`--metrics`); `None` — выключен.
    pub metrics: Option<SocketAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], 5555)),
            data_dir: default_data_dir().into(),
            workers: 0,
            quiet: false,
            limits: Limits::default(),
            tcp: true,
            metrics: None,
        }
    }
}

/// Health: housekeeping не отмечался дольше этого — сервер «завис».
const HEALTH_TICK_MAX: Duration = Duration::from_secs(10);

/// Запущенный сервер. Останавливается через [`Server::stop`] или при drop.
pub struct Server {
    pub addr: SocketAddr,
    /// Friend code сервера (клиент пиннит его ed25519-ключ).
    pub code: String,
    pub pubkey: [u8; 32],
    /// Адрес TCP-фолбэка (тот же порт, что UDP), если он включён и занялся.
    pub tcp_addr: Option<SocketAddr>,
    /// Адрес эндпоинта метрик, если включён.
    pub metrics_addr: Option<SocketAddr>,
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
    tcp: Option<tcp::TcpTransport>,
    metrics_srv: Option<metrics::MetricsServer>,
}

impl Server {
    pub fn start(cfg: Config) -> Result<Server> {
        let store = persist::Store::new(&cfg.data_dir);
        let loaded = load_state(&store)?;
        let fresh = loaded.fresh;
        let sock = UdpSocket::bind(cfg.listen).with_context(|| format!("bind {}", cfg.listen))?;
        sock.set_read_timeout(Some(RECV_POLL)).ok();
        let addr = sock.local_addr()?;
        let code = loaded.identity.friend_code();
        let pubkey = loaded.identity.ed_pub();
        // Цепочка, не ведущая к текущему ключу (server.json правили руками),
        // клиентам со старым пином не поможет — но и не мешает остальным.
        let chain_ok = loaded
            .links
            .last()
            .is_none_or(|l| l.new_ed == pubkey && l.new_x == loaded.identity.x_pub());
        let n_links = loaded.links.len();

        let shared = Arc::new(Shared {
            sock,
            state: RwLock::new(State {
                sessions: HashMap::new(),
                by_pub: HashMap::new(),
                groups: loaded.groups,
                leases: loaded.leases,
                next_gid: loaded.next_gid,
                invite_ttl_ms: duration_ms(cfg.limits.invite_ttl),
                retired_eph: HashMap::new(),
            }),
            identity: loaded.identity,
            links: loaded.links,
            cookies: hs::CookieSecret::generate(),
            limits: cfg.limits,
            started: Instant::now(),
            stop: AtomicBool::new(false),
            dirty: AtomicBool::new(true),
            urgent: (Mutex::new(false), Condvar::new()),
            list_dirty: AtomicBool::new(false),
            per_ip: (0..IP_SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            ip_hash: std::hash::RandomState::new(),
            plain: Mutex::new(Bucket::full()),
            quiet: cfg.quiet,
            store,
            written: Mutex::new(None),
            rotated: Mutex::new(None),
            relayed: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            metrics: metrics::Metrics::new(),
            tcp: OnceLock::new(),
            alive: AtomicUsize::new(0),
            expected_threads: AtomicUsize::new(usize::MAX),
            last_tick: AtomicU64::new(0),
        });
        if !cfg.quiet {
            if fresh {
                eprintln!("[server] новое состояние в {}", cfg.data_dir.display());
            } else {
                let n = shared.state.read().unwrap().groups.len();
                eprintln!(
                    "[server] загружено: {n} групп(ы) из {}",
                    cfg.data_dir.display()
                );
            }
            if n_links > 0 {
                eprintln!("[server] цепочка ротации ключа: {n_links} звен(а/ьев)");
            }
            if !chain_ok {
                eprintln!(
                    "[server] ВНИМАНИЕ: цепочка ротации в server.json не ведёт к текущему ключу"
                );
            }
        }
        // Сразу на диск: иначе новая identity, напечатанная ниже, терялась бы
        // при остановке в первые секунды (до первого периодического
        // сохранения) — и код сервера менялся бы при следующем запуске.
        save_now(&shared);

        let workers = if cfg.workers == 0 {
            thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2)
                .clamp(2, 8)
        } else {
            cfg.workers
        };
        let mut threads = Vec::new();
        shared
            .expected_threads
            .store(workers + 1, Ordering::Relaxed);
        for i in 0..workers {
            let sh = shared.clone();
            sh.alive.fetch_add(1, Ordering::Relaxed);
            threads.push(
                thread::Builder::new()
                    .name(format!("worker-{i}"))
                    .spawn(move || {
                        let _alive = Alive(&sh.alive);
                        worker(sh.clone())
                    })?,
            );
        }
        {
            let sh = shared.clone();
            sh.alive.fetch_add(1, Ordering::Relaxed);
            threads.push(
                thread::Builder::new()
                    .name("housekeeping".into())
                    .spawn(move || {
                        let _alive = Alive(&sh.alive);
                        housekeeping(sh.clone())
                    })?,
            );
        }
        // TCP-фолбэк на том же порту: кадры идут тем же путём, что UDP, а
        // источником сессии считается адрес TCP-соединения.
        let tcp = if cfg.tcp {
            let on_frame: tcp::FrameHandler = {
                let sh = shared.clone();
                Arc::new(move |peer, frame| handle_datagram(&sh, peer.addr(), frame))
            };
            let on_close: tcp::CloseHandler = {
                let sh = shared.clone();
                Arc::new(move |peer| drop_session_at(&sh, peer.addr()))
            };
            match tcp::TcpTransport::start_with_close(
                addr,
                on_frame,
                on_close,
                tcp::TcpLimits::default(),
            ) {
                Ok(t) => {
                    let _ = shared.tcp.set(t.sender());
                    Some(t)
                }
                Err(e) => {
                    eprintln!("[server] TCP {addr}: {e} — работаю только по UDP");
                    None
                }
            }
        } else {
            None
        };
        let tcp_addr = tcp.as_ref().map(|t| t.local_addr());
        let metrics_srv = match cfg.metrics {
            Some(maddr) => {
                let health: metrics::HealthFn = {
                    let sh = shared.clone();
                    Arc::new(move || healthy(&sh))
                };
                let refresh: metrics::RefreshFn = {
                    let sh = shared.clone();
                    Arc::new(move || refresh_gauges(&sh))
                };
                Some(metrics::MetricsServer::start_with_refresh(
                    maddr,
                    shared.metrics.clone(),
                    health,
                    refresh,
                )?)
            }
            None => None,
        };
        let metrics_addr = metrics_srv.as_ref().map(|m| m.local_addr());
        shared.log(format!("listening on {addr}, воркеров: {workers}"));
        if let Some(t) = tcp_addr {
            shared.log(format!("TCP-фолбэк на {t}"));
        }
        if let Some(m) = metrics_addr {
            shared.log(format!("метрики: http://{m}/metrics"));
        }
        shared.log(format!("Server code: {code}"));
        Ok(Server {
            addr,
            code,
            pubkey,
            tcp_addr,
            metrics_addr,
            shared,
            threads,
            tcp,
            metrics_srv,
        })
    }

    /// Останавливает потоки и сохраняет состояние.
    pub fn stop(mut self) {
        self.shutdown();
    }

    /// Блокирует до остановки (Ctrl-C завершает процесс).
    pub fn wait(mut self) {
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }

    fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        self.shared.urgent.1.notify_all();
        if let Some(m) = self.metrics_srv.take() {
            m.stop();
        }
        // TCP — раньше воркеров: читатели соединений тоже вызывают обработку.
        if let Some(mut t) = self.tcp.take() {
            t.stop();
        }
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        save_now(&self.shared);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if !self.threads.is_empty() {
            self.shutdown();
        }
    }
}

/// Итог `tunnel-server rotate-key`.
pub struct RotatedKey {
    /// Friend code нового ключа — его выдавать новым клиентам.
    pub code: String,
    pub pubkey: [u8; 32],
    pub old_code: String,
    /// Звеньев в цепочке после ротации (WELCOME несёт последние ≤ 8).
    pub links: usize,
}

/// Ротация ключа сервера (раздел 8): текущая identity подписывает новую,
/// звено дописывается в `server.json`, дальше сервер работает с новым
/// ключом. Запущенный на том же каталоге сервер новый ключ не затирает, а
/// сохраняет (см. `keep_rotated_key`): он вступает в силу с перезапуском.
pub fn rotate_key(data_dir: &Path) -> Result<RotatedKey> {
    anyhow::ensure!(
        data_dir.join("server.json").exists(),
        "в {} нет server.json — ротировать нечего (сервер ещё не запускался?)",
        data_dir.display()
    );
    let store = persist::Store::new(data_dir);
    // Запущенный сервер пишет файл под той же блокировкой: его сохранение не
    // вклинится между нашим чтением и записью (и не затрёт новый ключ).
    let _lock = store
        .lock()
        .with_context(|| format!("блокировка server.json в {}", data_dir.display()))?;
    let mut p = store.load()?.context("server.json пропал")?;
    for l in &p.rotations {
        parse_link(l)?;
    }
    let old = proto::Identity {
        ed_seed: p.ed_seed,
        x_seed: p.x_seed,
    };
    let new = proto::Identity::generate();
    let link = hs::make_link(&old, &new);
    p.rotations.push(hex(&link.to_bytes()));
    p.ed_seed = new.ed_seed;
    p.x_seed = new.x_seed;
    store
        .save(&p)
        .with_context(|| format!("запись server.json в {}", data_dir.display()))?;
    Ok(RotatedKey {
        code: new.friend_code(),
        pubkey: new.ed_pub(),
        old_code: old.friend_code(),
        links: p.rotations.len(),
    })
}

// ---------- состояние ----------

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(burst: f64) -> Self {
        Self {
            tokens: burst,
            last: Instant::now(),
        }
    }

    /// Полный запас при любом `burst` (он обрезается первым `take`).
    fn full() -> Self {
        Self::new(f64::INFINITY)
    }

    fn take(&mut self, rate: f64, burst: f64) -> bool {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * rate).min(burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Запас уже восполнился до `burst`: такая корзина неотличима от новой,
    /// её можно забыть без ослабления лимита.
    fn refilled(&self, rate: f64, burst: f64, now: Instant) -> bool {
        self.tokens + now.saturating_duration_since(self.last).as_secs_f64() * rate >= burst
    }
}

/// Жетон лимитера HELLO из шарда `m` для ключа `key`. Шард с `cap`
/// записями чистится от восполнившихся корзин; не помогло — отказ новому
/// адресу (поток с подменой адресов не раздувает карту и не вытесняет
/// корзины тех, кто реально исчерпал запас).
fn ip_take(
    m: &mut HashMap<IpAddr, Bucket>,
    key: IpAddr,
    rate: f64,
    burst: f64,
    cap: usize,
) -> bool {
    if let Some(b) = m.get_mut(&key) {
        return b.take(rate, burst);
    }
    if m.len() >= cap {
        let now = Instant::now();
        m.retain(|_, b| !b.refilled(rate, burst, now));
        if m.len() >= cap {
            return false;
        }
    }
    m.entry(key)
        .or_insert_with(|| Bucket::new(burst))
        .take(rate, burst)
}

struct Session {
    ed_pub: [u8; 32],
    /// Эфемерный ключ клиента этой попытки: повтор HELLO3 с ним же с того же
    /// адреса — потерянный WELCOME, а не новое подключение.
    eph_pub: [u8; 32],
    name: String,
    status: String,
    keys: proto::DirKeys,
    /// Готовый WELCOME этой сессии: повтор HELLO3 получает его же.
    welcome: Vec<u8>,
    /// Когда WELCOME уходил последний раз, мс от старта сервера
    /// (`WELCOME_RESEND_GAP`).
    welcome_at: AtomicU64,
    /// Счётчик nonce s2c (с 0, строго растёт; атомарный — шифруют и
    /// воркеры под блокировкой на чтение).
    tx: AtomicU64,
    /// msg_id следующего нарезанного на FRAG сообщения.
    msg_id: AtomicU32,
    /// Окно повторов c2s.
    rx: Mutex<proto::ReplayWindow>,
    /// Остальные видят клиента офлайн, без адресов (HELLO3 flags / PRESENCE).
    invisible: bool,
    /// Адреса клиента в локальной сети (CANDIDATES).
    candidates: Vec<SocketAddr>,
    /// Последний пакет, мс от старта сервера (обновляется под read-lock).
    last_seen: AtomicU64,
    relay: Mutex<Bucket>,
    ctrl: Mutex<Bucket>,
}

struct Member {
    ip: u32,
    name: String,
    status: String,
}

struct Invite {
    /// Когда приглашён (unix мс; переживает рестарт — срок не продлевается).
    created_ms: u64,
    /// Имя приглашённого на момент приглашения (ADMIN_INFO).
    name: String,
}

struct Group {
    id: u32,
    name: String,
    owner: [u8; 32],
    private: bool,
    key: proto::SymKey,
    /// Номер ключа `key`.
    epoch: u32,
    /// Ревизия состояния, видимого участникам.
    rev: u32,
    /// Текущий ключ введён с отзывом прошлого (выход/кик/бан).
    revoke_prev: bool,
    /// lease: ed25519 pubkey → участник (офлайн-участники IP сохраняют).
    members: HashMap<[u8; 32], Member>,
    /// Индекс для релея: ip → pubkey.
    by_ip: HashMap<u32, [u8; 32]>,
    /// Забаненные → последнее известное имя.
    banned: HashMap<[u8; 32], String>,
    invites: HashMap<[u8; 32], Invite>,
    /// Лимит входов не-участников (`Limits::join_rate`), не сохраняется.
    joins: Bucket,
    /// Недавно вышедшие (LEAVE) → когда: повторный вход без приглашения —
    /// не раньше `REJOIN_COOLDOWN`. Не сохраняется.
    left: HashMap<[u8; 32], Instant>,
}

impl Group {
    fn insert_member(&mut self, pk: [u8; 32], m: Member) {
        if let Some(old) = self.members.get(&pk) {
            self.by_ip.remove(&old.ip);
        }
        self.by_ip.insert(m.ip, pk);
        self.members.insert(pk, m);
    }

    fn remove_member(&mut self, pk: &[u8; 32]) -> bool {
        match self.members.remove(pk) {
            Some(m) => {
                self.by_ip.remove(&m.ip);
                true
            }
            None => false,
        }
    }

    fn full(&self) -> bool {
        self.members.len() >= MAX_MEMBERS
    }

    /// Новый случайный ключ, `epoch += 1`. `revoke_prev` — получатели сразу
    /// забывают прошлый ключ (ушедший участник его знает).
    fn rotate(&mut self, revoke_prev: bool) {
        rand::rng().fill_bytes(&mut self.key);
        self.epoch = self.epoch.wrapping_add(1);
        self.revoke_prev = revoke_prev;
    }

    /// `rev += 1` на видимое изменение; возвращает прошлую ревизию (`base_rev`
    /// дельты).
    fn bump(&mut self) -> u32 {
        let base = self.rev;
        self.rev = self.rev.wrapping_add(1);
        base
    }
}

struct State {
    sessions: HashMap<SocketAddr, Session>,
    /// Индекс: identity → адрес её сессии.
    by_pub: HashMap<[u8; 32], SocketAddr>,
    groups: HashMap<u32, Group>,
    /// Адрес оверлея identity — один на все её группы.
    leases: leases::Leases,
    next_gid: u32,
    /// `Limits::invite_ttl` в мс (нужен почти всем спискам приглашений).
    invite_ttl_ms: u64,
    /// `(ed_pub, eph_pub)` закрытых сессий → когда закрыта. HELLO3 с таким
    /// ключом (старая попытка клиента, повторённая в пределах срока cookie)
    /// игнорируется: иначе он пересоздавал бы живую сессию.
    retired_eph: HashMap<([u8; 32], [u8; 32]), Instant>,
}

impl State {
    /// Сессия identity: адрес и сама сессия.
    fn session_of(&self, pk: &[u8; 32]) -> Option<(SocketAddr, &Session)> {
        let addr = *self.by_pub.get(pk)?;
        self.sessions.get(&addr).map(|ses| (addr, ses))
    }

    fn online(&self, pk: &[u8; 32]) -> bool {
        self.by_pub.contains_key(pk)
    }

    fn remove_session(&mut self, addr: &SocketAddr) -> Option<Session> {
        let ses = self.sessions.remove(addr)?;
        if self.by_pub.get(&ses.ed_pub) == Some(addr) {
            self.by_pub.remove(&ses.ed_pub);
        }
        let now = Instant::now();
        if self.retired_eph.len() >= RETIRED_EPH_PURGE {
            self.retired_eph
                .retain(|_, t| now.duration_since(*t) < RETIRED_EPH_TTL);
        }
        self.retired_eph.insert((ses.ed_pub, ses.eph_pub), now);
        Some(ses)
    }

    /// Эфемерный ключ закрытой сессии этой identity, cookie под него ещё
    /// может быть жив.
    fn eph_retired(&self, ed: &[u8; 32], eph: &[u8; 32]) -> bool {
        self.retired_eph
            .get(&(*ed, *eph))
            .is_some_and(|t| t.elapsed() < RETIRED_EPH_TTL)
    }

    fn groups_of(&self, pk: &[u8; 32]) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .groups
            .values()
            .filter(|g| g.members.contains_key(pk))
            .map(|g| g.id)
            .collect();
        v.sort_unstable();
        v
    }

    fn owned_by(&self, pk: &[u8; 32]) -> usize {
        self.groups.values().filter(|g| g.owner == *pk).count()
    }

    /// Адрес оверлея identity: закреплённый или новый (`leases`). Пул
    /// исчерпан — забирается у identity вне групп; `None` — и таких нет.
    fn ip_for(&mut self, pk: [u8; 32]) -> Option<u32> {
        let groups = &self.groups;
        self.leases
            .get_or_alloc(pk, |k| groups.values().any(|g| g.members.contains_key(k)))
    }

    /// Свободный gid: начиная с next_gid по кругу (удалённые gid переиспользуются;
    /// раньше после 254 созданий сервер не мог создать ни одной группы).
    fn alloc_gid(&mut self) -> Option<u32> {
        let span = GID_MAX - GID_MIN + 1;
        let start = self.next_gid.clamp(GID_MIN, GID_MAX);
        for i in 0..span {
            let gid = GID_MIN + (start - GID_MIN + i) % span;
            if !self.groups.contains_key(&gid) {
                self.next_gid = if gid == GID_MAX { GID_MIN } else { gid + 1 };
                return Some(gid);
            }
        }
        None
    }

    fn invite_live(&self, inv: &Invite, now_ms: u64) -> bool {
        now_ms < inv.created_ms.saturating_add(self.invite_ttl_ms)
    }

    /// Секунд до истечения приглашения (вверх: живое не показывается как 0).
    fn expires_in(&self, inv: &Invite, now_ms: u64) -> u32 {
        let left = inv
            .created_ms
            .saturating_add(self.invite_ttl_ms)
            .saturating_sub(now_ms);
        left.div_ceil(1000).min(u32::MAX as u64) as u32
    }
}

struct Shared {
    sock: UdpSocket,
    state: RwLock<State>,
    /// Identity сервера и цепочка ротации — неизменны после старта, поэтому
    /// подпись и DH рукопожатия считаются без блокировки состояния.
    identity: proto::Identity,
    links: Vec<RotationLink>,
    cookies: hs::CookieSecret,
    limits: Limits,
    started: Instant,
    stop: AtomicBool,
    dirty: AtomicBool,
    /// Запрос срочного сохранения (housekeeping ждёт на condvar).
    urgent: (Mutex<bool>, Condvar),
    /// Состав или имена групп изменились: housekeeping разошлёт GROUP_LIST
    /// всем сессиям (одна рассылка на период, а не на каждую команду).
    list_dirty: AtomicBool,
    /// Лимитер HELLO по IP, по шардам (воркеры не толкаются на одном Mutex).
    per_ip: Vec<Mutex<HashMap<IpAddr, Bucket>>>,
    ip_hash: std::hash::RandomState,
    /// Общий бюджет открытых ответов (`Limits::plain_rate`).
    plain: Mutex<Bucket>,
    quiet: bool,
    store: persist::Store,
    /// Отпечаток server.json после нашей последней записи.
    written: Mutex<persist::Stamp>,
    /// Ключ, сменённый `rotate-key` при запущенном сервере: сохраняется
    /// вместо нашего (вступит в силу при перезапуске), а не затирается.
    rotated: Mutex<Option<persist::PKey>>,
    relayed: AtomicU64,
    dropped: AtomicU64,
    /// Счётчики для `/metrics`.
    metrics: Arc<metrics::Metrics>,
    /// Реестр TCP-клиентов (если TCP-фолбэк включён).
    tcp: OnceLock<tcp::TcpSender>,
    /// Живых потоков (воркеры + housekeeping) и сколько их должно быть.
    alive: AtomicUsize,
    expected_threads: AtomicUsize,
    /// `now_ms` последнего прохода housekeeping.
    last_tick: AtomicU64,
}

/// Учёт живого потока: декремент при выходе, в том числе по панике.
struct Alive<'a>(&'a AtomicUsize);

impl Drop for Alive<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// `/healthz`: все потоки живы, housekeeping недавно отмечался.
fn healthy(sh: &Shared) -> bool {
    !sh.stop.load(Ordering::Relaxed)
        && sh.alive.load(Ordering::Relaxed) == sh.expected_threads.load(Ordering::Relaxed)
        && sh
            .now_ms()
            .saturating_sub(sh.last_tick.load(Ordering::Relaxed))
            < duration_ms(HEALTH_TICK_MAX)
}

/// Датчики метрик — из авторитетного состояния.
fn refresh_gauges(sh: &Shared) {
    let now = unix_ms();
    let s = sh.state.read().unwrap();
    let m = &sh.metrics;
    metrics::Metrics::set(&m.sessions, s.sessions.len() as u64);
    metrics::Metrics::set(&m.groups, s.groups.len() as u64);
    metrics::Metrics::set(
        &m.members,
        s.groups.values().map(|g| g.members.len() as u64).sum(),
    );
    let pending = s
        .groups
        .values()
        .flat_map(|g| g.invites.values())
        .filter(|i| s.invite_live(i, now))
        .count();
    metrics::Metrics::set(&m.invites_pending, pending as u64);
}

/// TCP-соединение закрылось: его сессия — офлайн сразу, не по таймауту.
fn drop_session_at(sh: &Shared, addr: SocketAddr) {
    let mut out = Outbox::new();
    {
        let mut s = sh.state.write().unwrap();
        let Some(ses) = s.remove_session(&addr) else {
            return;
        };
        sh.log(format!(
            "offline: {} ({}) — TCP закрыт",
            ses.name,
            short(&ses.ed_pub)
        ));
        if !s.online(&ses.ed_pub) {
            member_changed(&mut s, &ses.ed_pub, &mut out);
        }
    }
    sh.list_dirty.store(true, Ordering::Relaxed);
    sh.dirty.store(true, Ordering::Relaxed);
    sh.flush(out);
}

impl Shared {
    fn log(&self, msg: String) {
        if !self.quiet {
            eprintln!("[server] {msg}");
        }
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn drop_frame(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        metrics::Metrics::inc(&self.metrics.dropped_frames, 1);
    }

    /// Единственный путь датаграммы клиенту: адрес живого TCP-клиента —
    /// через реестр TCP, остальное — UDP.
    fn send_to(&self, frame: &[u8], addr: SocketAddr) {
        if let Some(t) = self.tcp.get() {
            let peer = tcp::Peer::Tcp(addr);
            if t.is_live(peer) {
                if !t.send(peer, frame) {
                    self.drop_frame();
                }
                return;
            }
        }
        let _ = self.sock.send_to(frame, addr);
    }

    /// Жетон лимита HELLO для адреса. IPv6 считается по /64: у одного
    /// абонента их 2^64, и лимит на полный адрес не ограничивал бы ничего.
    /// Шард переполнен (поток с подменой адресов) — новым адресам отказ.
    fn allow_ip(&self, ip: IpAddr) -> bool {
        use std::hash::BuildHasher;
        let (rate, burst) = (self.limits.hello_rate, self.limits.hello_burst);
        let key = ip_key(ip);
        let shard = self.ip_hash.hash_one(key) as usize % IP_SHARDS;
        ip_take(
            &mut self.per_ip[shard].lock().unwrap(),
            key,
            rate,
            burst,
            IP_SHARD_MAX,
        )
    }

    /// Жетон общего бюджета открытых ответов.
    fn allow_plain(&self) -> bool {
        self.plain
            .lock()
            .unwrap()
            .take(self.limits.plain_rate, self.limits.plain_burst)
    }

    /// Попросить housekeeping сохранить состояние сейчас (не дожидаясь
    /// `SAVE_EVERY`): кик, бан, выход и т. п. не должны теряться при падении.
    fn save_soon(&self) {
        *self.urgent.0.lock().unwrap() = true;
        self.urgent.1.notify_one();
    }

    fn flush(&self, out: Outbox) {
        // Залп одному адресу (например, 175 кусков FRAG худшего
        // GROUP_STATE — 192 КБ) клиент не успевает принять: буфер приёма UDP
        // на Windows — 64 КБ, лишние датаграммы ядро отбрасывает, сообщение
        // не собирается никогда. Разбавляем длинные залпы паузой: между
        // пачками клиент успевает опустошить буфер.
        let mut prev: Option<SocketAddr> = None;
        let mut burst = 0usize;
        for (addr, frame) in out {
            if prev != Some(addr) {
                prev = Some(addr);
                burst = 0;
            }
            if burst >= SEND_BURST {
                std::thread::sleep(SEND_PAUSE);
                burst = 0;
            }
            self.send_to(&frame, addr);
            burst += 1;
        }
    }

    /// Открытый фрейм (CHALLENGE, UNSUPPORTED, RESET). Лимит по IP — на
    /// вызывающем: HELLO/HELLO3 уже прошёл его, RESET — через [`send_reset`];
    /// здесь — общий бюджет сервера.
    fn send_plain(&self, addr: SocketAddr, typ: u8, body: &[u8]) {
        if !self.allow_plain() {
            self.drop_frame();
            return;
        }
        self.send_to(&proto::plain_frame(typ, body), addr);
    }
}

/// Исходящие датаграммы, собранные под блокировкой и отправляемые после неё.
type Outbox = Vec<(SocketAddr, Vec<u8>)>;

fn hex(b: &[u8]) -> String {
    proto::hex_of(b)
}

fn short(pk: &[u8; 32]) -> String {
    hex(&pk[..4])
}

fn unhex(s: &str) -> Result<[u8; 32]> {
    let v = proto::hex_to_bytes(s)?;
    anyhow::ensure!(v.len() == 32, "bad hex");
    Ok(v.try_into().unwrap())
}

fn parse_link(s: &str) -> Result<RotationLink> {
    RotationLink::from_bytes(&proto::hex_to_bytes(s).context("звено ротации: hex")?)
        .context("server.json: битое звено ротации")
}

/// Ключ лимитера HELLO: IPv4 (и v4-mapped) — адрес, IPv6 — его /64.
fn ip_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6((u128::from(a) & !((1u128 << 64) - 1)).into()),
        },
    }
}

/// UNSUPPORTED не длиннее запроса `req_len` (раздел 2): текст — только если
/// влезает, иначе пустой; не влезает и пустой — ответа нет.
fn unsupported_body(req_len: usize) -> Option<Vec<u8>> {
    [UNSUPPORTED_TEXT, ""]
        .into_iter()
        .map(hs::enc_unsupported)
        .find(|b| proto::HDR_LEN + b.len() <= req_len)
}

fn ip_str(ip: u32) -> String {
    Ipv4Addr::from(ip).to_string()
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn duration_ms(d: Duration) -> u64 {
    d.as_millis().min(u64::MAX as u128) as u64
}

/// Обрезка до `max` символов, без управляющих символов и пробелов по краям.
fn clean(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(max)
        .collect()
}

/// Кандидат, на который пирам есть смысл слать PUNCH: не нулевой адрес/порт,
/// не multicast/broadcast (иначе участник направил бы PUNCH всей группы в
/// чужую широковещательную рассылку).
fn usable_candidate(a: &SocketAddr) -> bool {
    let ip = a.ip();
    a.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != IpAddr::V4(Ipv4Addr::BROADCAST)
}

// ---------- загрузка/сохранение ----------

struct Loaded {
    /// server.json не было — новая identity.
    fresh: bool,
    identity: proto::Identity,
    links: Vec<RotationLink>,
    next_gid: u32,
    groups: HashMap<u32, Group>,
    leases: leases::Leases,
}

/// Адреса identity из `server.json`: сначала `user_ips` (v4), затем — для
/// identity без него — адрес из её группы с меньшим gid (файл сервера v3,
/// где у участника в каждой группе свой `100.66.<gid>.<host>`; такие
/// адреса не пересекаются между identity, и первый же годится в общий).
fn load_leases(p: &persist::Persisted) -> leases::Leases {
    let mut l = leases::Leases::default();
    for (k, ip) in &p.user_ips {
        if let Ok(pk) = unhex(k) {
            l.assign(pk, *ip);
        }
    }
    let mut groups: Vec<&persist::PGroup> = p.groups.iter().collect();
    groups.sort_unstable_by_key(|g| g.id);
    for g in groups {
        for (k, ip) in &g.members {
            if let Ok(pk) = unhex(k)
                && l.get(&pk).is_none()
            {
                l.assign(pk, *ip);
            }
        }
    }
    l
}

fn load_state(store: &persist::Store) -> Result<Loaded> {
    let Some(p) = store.load()? else {
        return Ok(Loaded {
            fresh: true,
            identity: proto::Identity::generate(),
            links: Vec::new(),
            next_gid: GID_MIN,
            groups: HashMap::new(),
            leases: leases::Leases::default(),
        });
    };
    let links = p
        .rotations
        .iter()
        .map(|l| parse_link(l))
        .collect::<Result<Vec<_>>>()?;
    let now = unix_ms();
    let mut leases = load_leases(&p);
    let mut groups = HashMap::new();
    for g in p.groups {
        let banned = g
            .banned
            .iter()
            .map(|b| Ok((unhex(b)?, g.ban_names.get(b).cloned().unwrap_or_default())))
            .collect::<Result<HashMap<_, _>>>()?;
        // Приглашение без времени (server.json v2) — срок с момента загрузки.
        let invites = g
            .invites
            .iter()
            .map(|b| {
                let inv = Invite {
                    created_ms: g.invite_times.get(b).copied().unwrap_or(now),
                    name: g.invite_names.get(b).cloned().unwrap_or_default(),
                };
                Ok((unhex(b)?, inv))
            })
            .collect::<Result<HashMap<_, _>>>()?;
        let mut group = Group {
            id: g.id,
            name: g.name,
            owner: unhex(&g.owner)?,
            private: g.private,
            key: g.key,
            // С 1: в GroupSummary 0 значит «не своя группа». Запас — номера,
            // выданные после последнего сохранения (падение), не повторятся
            // с другим ключом.
            epoch: g.epoch.max(1).wrapping_add(LOAD_MARGIN),
            rev: g.rev.max(1).wrapping_add(LOAD_MARGIN),
            revoke_prev: g.revoke_prev,
            members: HashMap::new(),
            by_ip: HashMap::new(),
            banned,
            invites,
            joins: Bucket::full(),
            left: HashMap::new(),
        };
        for (k, _) in g.members {
            // Адрес участника — адрес его identity (`load_leases`); не
            // досталось (адрес из файла занят или вне пула) — новый.
            let Ok(pk) = unhex(&k) else { continue };
            let Some(ip) = leases.get_or_alloc(pk, |_| true) else {
                continue;
            };
            group.insert_member(
                pk,
                Member {
                    ip,
                    name: g
                        .member_names
                        .get(&k)
                        .cloned()
                        .unwrap_or_else(|| "…".into()),
                    status: g.member_status.get(&k).cloned().unwrap_or_default(),
                },
            );
        }
        // Старый сервер не снимал приглашение при входе в публичную группу и
        // не отказывал в INVITE участнику: такие записи после кика/выхода
        // всплыли бы окном приглашения (и пустили бы обратно в приватную).
        let Group {
            members,
            banned,
            invites,
            ..
        } = &mut group;
        invites.retain(|pk, _| !members.contains_key(pk) && !banned.contains_key(pk));
        groups.insert(g.id, group);
    }
    Ok(Loaded {
        fresh: false,
        identity: proto::Identity {
            ed_seed: p.ed_seed,
            x_seed: p.x_seed,
        },
        links,
        next_gid: p.next_gid.clamp(GID_MIN, GID_MAX),
        groups,
        leases,
    })
}

fn snapshot(
    sh_identity: &proto::Identity,
    links: &[RotationLink],
    s: &State,
) -> persist::Persisted {
    persist::Persisted {
        ed_seed: sh_identity.ed_seed,
        x_seed: sh_identity.x_seed,
        next_gid: s.next_gid,
        rotations: links.iter().map(|l| hex(&l.to_bytes())).collect(),
        user_ips: s.leases.iter().map(|(k, ip)| (hex(k), ip)).collect(),
        groups: s
            .groups
            .values()
            .map(|g| persist::PGroup {
                id: g.id,
                name: g.name.clone(),
                owner: hex(&g.owner),
                private: g.private,
                key: g.key,
                members: g.members.iter().map(|(k, m)| (hex(k), m.ip)).collect(),
                banned: g.banned.keys().map(|b| hex(b)).collect(),
                invites: g.invites.keys().map(|b| hex(b)).collect(),
                epoch: g.epoch,
                rev: g.rev,
                revoke_prev: g.revoke_prev,
                member_names: g
                    .members
                    .iter()
                    .map(|(k, m)| (hex(k), m.name.clone()))
                    .collect(),
                member_status: g
                    .members
                    .iter()
                    .filter(|(_, m)| !m.status.is_empty())
                    .map(|(k, m)| (hex(k), m.status.clone()))
                    .collect(),
                ban_names: g
                    .banned
                    .iter()
                    .filter(|(_, n)| !n.is_empty())
                    .map(|(k, n)| (hex(k), n.clone()))
                    .collect(),
                invite_times: g
                    .invites
                    .iter()
                    .map(|(k, i)| (hex(k), i.created_ms))
                    .collect(),
                invite_names: g
                    .invites
                    .iter()
                    .filter(|(_, i)| !i.name.is_empty())
                    .map(|(k, i)| (hex(k), i.name.clone()))
                    .collect(),
            })
            .collect(),
    }
}

fn save_now(sh: &Shared) {
    // Вся проверка «не сменил ли rotate-key ключ», запись и отпечаток — под
    // блокировкой файла: rotate-key не вклинится между ними (иначе его
    // запись молча затиралась бы нашей или принималась за нашу).
    let _lock = match sh.store.lock() {
        Ok(l) => Some(l),
        Err(e) => {
            eprintln!("[server] блокировка server.json: {e} — пишу без неё");
            None
        }
    };
    // Файл переписан извне (rotate-key) — переписать и без изменений: иначе
    // в нём осталось бы состояние групп на момент чтения rotate-key.
    if !sh.dirty.swap(false, Ordering::Relaxed) && sh.store.stamp() == *sh.written.lock().unwrap() {
        return;
    }
    let mut snap = snapshot(&sh.identity, &sh.links, &sh.state.read().unwrap());
    keep_rotated_key(sh, &mut snap);
    match sh.store.save(&snap) {
        Ok(()) => *sh.written.lock().unwrap() = sh.store.stamp(),
        Err(e) => {
            sh.dirty.store(true, Ordering::Relaxed);
            eprintln!("[server] save error: {e}");
        }
    }
}

/// `rotate-key` при запущенном сервере: на диске новый ключ, чья цепочка
/// продолжает нашу, — его и сохраняем (иначе ротация молча терялась бы при
/// следующем сохранении). Сервер дорабатывает со старым ключом, новый — с
/// перезапуска. Файл читается, только если изменился после нашей записи.
fn keep_rotated_key(sh: &Shared, snap: &mut persist::Persisted) {
    let apply = |snap: &mut persist::Persisted, k: &persist::PKey| {
        snap.ed_seed = k.ed_seed;
        snap.x_seed = k.x_seed;
        snap.rotations = k.rotations.clone();
    };
    let mut rotated = sh.rotated.lock().unwrap();
    if let Some(k) = rotated.as_ref() {
        apply(snap, k);
    }
    // Сравнение — с уже принятым ключом: повторный rotate-key продолжает его.
    let stamp = sh.store.stamp();
    if stamp.is_some()
        && stamp != *sh.written.lock().unwrap()
        && let Some(k) = sh.store.load_key()
        && k.ed_seed != snap.ed_seed
        && k.rotations.len() > snap.rotations.len()
        && k.rotations.starts_with(&snap.rotations)
    {
        eprintln!(
            "[server] ключ сервера сменён rotate-key: новый ключ вступит в силу после перезапуска"
        );
        apply(snap, &k);
        *rotated = Some(k);
    }
}

// ---------- фоновые задачи ----------

/// Ждёт срочного сохранения не дольше `wait`: `true` — его просили.
fn wait_urgent(sh: &Shared, wait: Duration) -> bool {
    let (flag, cv) = &sh.urgent;
    let mut f = flag.lock().unwrap();
    if !*f && !sh.stop.load(Ordering::Relaxed) {
        f = cv.wait_timeout(f, wait).unwrap().0;
    }
    std::mem::take(&mut *f)
}

fn housekeeping(sh: Arc<Shared>) {
    let mut last_save = Instant::now();
    let mut last_tick = Instant::now();
    let mut last_stats = Instant::now();
    let mut last_relayed = 0u64;
    while !sh.stop.load(Ordering::Relaxed) {
        sh.last_tick.store(sh.now_ms(), Ordering::Relaxed);
        let left = HOUSEKEEPING_EVERY.saturating_sub(last_tick.elapsed());
        if wait_urgent(&sh, left) {
            // Срочное — сразу, но не чаще URGENT_SAVE_GAP.
            thread::sleep(URGENT_SAVE_GAP.saturating_sub(last_save.elapsed()));
            last_save = Instant::now();
            save_now(&sh);
        }
        if sh.stop.load(Ordering::Relaxed) {
            break;
        }
        if last_tick.elapsed() < HOUSEKEEPING_EVERY {
            continue;
        }
        last_tick = Instant::now();
        expire_sessions(&sh);
        expire_invites(&sh);
        refresh_gauges(&sh);
        if sh.list_dirty.swap(false, Ordering::Relaxed) {
            broadcast_group_list(&sh);
        }
        // Лимитер по IP: забыть восполнившиеся корзины (раньше — не
        // сбрасывать запас исчерпавшим его, даже при медленном `hello_rate`).
        let (rate, burst, now) = (sh.limits.hello_rate, sh.limits.hello_burst, Instant::now());
        for shard in &sh.per_ip {
            shard
                .lock()
                .unwrap()
                .retain(|_, b| !b.refilled(rate, burst, now));
        }
        if last_save.elapsed() >= SAVE_EVERY {
            last_save = Instant::now();
            save_now(&sh);
        }
        if last_stats.elapsed() >= STATS_EVERY {
            let secs = last_stats.elapsed().as_secs().max(1);
            last_stats = Instant::now();
            let relayed = sh.relayed.load(Ordering::Relaxed);
            let (ses, grp) = {
                let s = sh.state.read().unwrap();
                (s.sessions.len(), s.groups.len())
            };
            sh.log(format!(
                "сессий {ses}, групп {grp}, релей {} пак/с, отброшено всего {}",
                (relayed - last_relayed) / secs,
                sh.dropped.load(Ordering::Relaxed)
            ));
            last_relayed = relayed;
        }
    }
}

/// Presence: сессии без пакетов дольше `session_timeout` — офлайн, группам
/// дельта kind 1.
fn expire_sessions(sh: &Shared) {
    let timeout = duration_ms(sh.limits.session_timeout);
    let is_dead = |ses: &Session, now: u64| {
        now.saturating_sub(ses.last_seen.load(Ordering::Relaxed)) > timeout
    };
    let dead: Vec<SocketAddr> = {
        let s = sh.state.read().unwrap();
        let now = sh.now_ms();
        s.sessions
            .iter()
            .filter(|(_, x)| is_dead(x, now))
            .map(|(a, _)| *a)
            .collect()
    };
    if dead.is_empty() {
        return;
    }
    let mut out = Outbox::new();
    {
        let mut s = sh.state.write().unwrap();
        let now = sh.now_ms();
        for a in dead {
            // Между проходами мог прийти пакет — перепроверить.
            if !s.sessions.get(&a).is_some_and(|x| is_dead(x, now)) {
                continue;
            }
            if let Some(ses) = s.remove_session(&a) {
                sh.log(format!("offline: {} ({})", ses.name, short(&ses.ed_pub)));
                if !s.online(&ses.ed_pub) {
                    member_changed(&mut s, &ses.ed_pub, &mut out);
                }
            }
        }
    }
    sh.list_dirty.store(true, Ordering::Relaxed);
    sh.dirty.store(true, Ordering::Relaxed);
    sh.flush(out);
}

/// Истёкшие приглашения удаляются; приглашённому онлайн — свежее окно
/// INVITE_LIST, покрывающее gid (клиент закроет окно приглашения).
fn expire_invites(sh: &Shared) {
    let now = unix_ms();
    let any = {
        let s = sh.state.read().unwrap();
        s.groups
            .values()
            .any(|g| g.invites.values().any(|i| !s.invite_live(i, now)))
    };
    if !any {
        return;
    }
    let mut out = Outbox::new();
    {
        let mut s = sh.state.write().unwrap();
        let ttl = s.invite_ttl_ms;
        let mut gone: Vec<([u8; 32], u32)> = Vec::new();
        for g in s.groups.values_mut() {
            g.invites.retain(|pk, i| {
                let live = now < i.created_ms.saturating_add(ttl);
                if !live {
                    gone.push((*pk, g.id));
                }
                live
            });
        }
        for (pk, gid) in gone {
            sh.log(format!("invite expired: {gid} → {}", short(&pk)));
            if let Some((addr, ses)) = s.session_of(&pk) {
                push_invite_list(&s, addr, ses, &mut out, invite_window(&s, &pk, gid));
            }
        }
    }
    sh.dirty.store(true, Ordering::Relaxed);
    sh.flush(out);
}

// ---------- приём ----------

fn worker(sh: Arc<Shared>) {
    let mut buf = vec![0u8; 65_535];
    while !sh.stop.load(Ordering::Relaxed) {
        let (n, src) = match sh.sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                use std::io::ErrorKind::*;
                match e.kind() {
                    // ConnectionReset — Windows: ICMP unreachable после
                    // отправки ушедшему клиенту. Не ошибка сервера.
                    WouldBlock | TimedOut | ConnectionReset | Interrupted => {}
                    _ => {
                        sh.log(format!("recv: {e}"));
                        thread::sleep(Duration::from_millis(10));
                    }
                }
                continue;
            }
        };
        handle_datagram(&sh, src, &buf[..n]);
    }
}

fn handle_datagram(sh: &Shared, src: SocketAddr, datagram: &[u8]) {
    let Ok((typ, body)) = proto::split_frame(datagram) else {
        sh.drop_frame();
        return;
    };
    if proto::grp::is_group(typ) {
        relay_group(sh, src, datagram);
    } else if typ == ctrl::HELLO || typ == ctrl::HELLO3 {
        // Один жетон на HELLO — он же покрывает ответ (CHALLENGE /
        // UNSUPPORTED / WELCOME): ответ без жетона не уходит.
        if !sh.allow_ip(src.ip()) {
            sh.drop_frame();
            return;
        }
        metrics::Metrics::inc(&sh.metrics.hello_total, 1);
        if typ == ctrl::HELLO {
            // v2: тело не разбирается; ответ — не длиннее запроса.
            match unsupported_body(datagram.len()) {
                Some(b) => sh.send_plain(src, ctrl::UNSUPPORTED, &b),
                None => sh.drop_frame(),
            }
        } else {
            handle_hello3(sh, src, body);
        }
    } else if ctrl::is_plaintext(typ) {
        // WELCOME / CHALLENGE / RESET / UNSUPPORTED от клиента — мусор.
        sh.drop_frame();
    } else {
        handle_ctrl_frame(sh, src, typ, body);
    }
}

/// Неизвестный адрес шлёт управляющие/групповые фреймы — скорее всего, сервер
/// перезапустился или сессия истекла. Подсказать клиенту переподключиться.
fn send_reset(sh: &Shared, src: SocketAddr) {
    if sh.allow_ip(src.ip()) {
        sh.send_plain(src, ctrl::RESET, &[]);
    }
}

// ---------- relay ----------

fn relay_group(sh: &Shared, src: SocketAddr, datagram: &[u8]) {
    let Ok((_, h)) = proto::parse_group_header(datagram) else {
        sh.drop_frame();
        return;
    };
    let target = {
        let s = sh.state.read().unwrap();
        let Some(ses) = s.sessions.get(&src) else {
            drop(s);
            sh.drop_frame();
            send_reset(sh, src);
            return;
        };
        ses.last_seen.store(sh.now_ms(), Ordering::Relaxed);
        let Some(g) = s.groups.get(&h.gid) else {
            return;
        };
        // Отправитель — участник группы и пишет от своего IP.
        match g.members.get(&ses.ed_pub) {
            Some(m) if m.ip == h.src => {}
            _ => {
                sh.drop_frame();
                return;
            }
        }
        let Some(dst_pk) = g.by_ip.get(&h.dst) else {
            return;
        };
        let Some(addr) = s.by_pub.get(dst_pk).copied() else {
            return;
        };
        if !ses
            .relay
            .lock()
            .unwrap()
            .take(sh.limits.relay_rate, sh.limits.relay_burst)
        {
            sh.drop_frame();
            return;
        }
        addr
    };
    sh.relayed.fetch_add(1, Ordering::Relaxed);
    sh.metrics.relayed(datagram.len());
    sh.send_to(datagram, target);
}

// ---------- отправка ----------

/// Единственный путь ctrl-фрейма сервер → клиент: шифрование ключом `s2c`
/// со следующим счётчиком сессии; payload длиннее `FRAG_THRESHOLD` режется
/// на куски FRAG (msg_id тратится только на нарезанные).
fn push_ctrl(out: &mut Outbox, addr: SocketAddr, ses: &Session, typ: u8, payload: &[u8]) {
    let mut seal = |t: u8, p: &[u8]| {
        let ctr = ses.tx.fetch_add(1, Ordering::Relaxed);
        out.push((addr, proto::seal_ctrl(&ses.keys.tx, ctr, t, p)));
    };
    if payload.len() <= proto::FRAG_THRESHOLD {
        seal(typ, payload);
        return;
    }
    let msg_id = ses.msg_id.fetch_add(1, Ordering::Relaxed);
    // Больше FRAG_MAX_PAYLOAD сервер не строит (списки обрезаются заранее,
    // худший GROUP_STATE влезает) — такое сообщение просто не уходит.
    debug_assert!(
        payload.len() <= proto::FRAG_MAX_PAYLOAD,
        "{typ:#04x}: {} байт",
        payload.len()
    );
    if let Ok(Some(chunks)) = proto::frag::split_frag(msg_id, typ, payload) {
        for c in chunks {
            seal(ctrl::FRAG, &c);
        }
    }
}

fn push_error(out: &mut Outbox, addr: SocketAddr, ses: &Session, text: &str) {
    push_ctrl(out, addr, ses, ctrl::ERROR, &pl::enc_error(text));
}

// ---------- представление состояния ----------

/// MemberInfo участника `pk` глазами `viewer`: invisible-участник для
/// остальных офлайн, без endpoint и кандидатов (релей для него работает).
fn member_info(s: &State, pk: &[u8; 32], m: &Member, viewer: &[u8; 32]) -> MemberInfo {
    let live = s
        .session_of(pk)
        .filter(|(_, x)| !x.invisible || pk == viewer);
    MemberInfo {
        pubkey: *pk,
        name: m.name.clone(),
        ip: m.ip,
        online: live.is_some(),
        status: m.status.clone(),
        endpoint: live.map(|(a, _)| a),
        candidates: live.map(|(_, x)| x.candidates.clone()).unwrap_or_default(),
    }
}

fn group_state(s: &State, g: &Group, viewer: &[u8; 32]) -> GroupState {
    let mut members: Vec<MemberInfo> = g
        .members
        .iter()
        .map(|(pk, m)| member_info(s, pk, m, viewer))
        .collect();
    members.sort_by_key(|m| m.ip);
    GroupState {
        gid: g.id,
        rev: g.rev,
        epoch: g.epoch,
        revoke_prev: g.revoke_prev,
        name: g.name.clone(),
        owner: g.owner,
        private: g.private,
        key: g.key,
        deleted: false,
        my_ip: g.members.get(viewer).map(|m| m.ip).unwrap_or(0),
        members,
    }
}

/// GROUP_STATE удалённой (или несуществующей) группы: всё, кроме gid, — нули.
fn deleted_state(gid: u32) -> GroupState {
    GroupState {
        gid,
        rev: 0,
        epoch: 0,
        revoke_prev: false,
        name: String::new(),
        owner: [0; 32],
        private: false,
        key: [0; 32],
        deleted: true,
        my_ip: 0,
        members: vec![],
    }
}

fn push_group_state(s: &State, g: &Group, addr: SocketAddr, ses: &Session, out: &mut Outbox) {
    let st = group_state(s, g, &ses.ed_pub);
    push_ctrl(out, addr, ses, ctrl::GROUP_STATE, &pl::enc_group_state(&st));
}

/// Что изменилось в группе — тело дельты GROUP_UPDATE.
enum Change {
    /// kind 1: участник добавлен/изменён.
    Member([u8; 32]),
    /// kind 2: участник удалён.
    Removed([u8; 32]),
    /// kind 3: имя / владелец / приватность.
    Meta,
}

/// Дельта `base_rev → g.rev` (с текущим ключом) всем онлайн-участникам,
/// кроме `skip` (тот получил GROUP_STATE целиком).
fn push_update(
    s: &State,
    g: &Group,
    base_rev: u32,
    change: &Change,
    skip: Option<&[u8; 32]>,
    out: &mut Outbox,
) {
    for pk in g.members.keys() {
        if skip == Some(pk) {
            continue;
        }
        let Some((addr, ses)) = s.session_of(pk) else {
            continue;
        };
        let delta = match change {
            Change::Member(who) => match g.members.get(who) {
                Some(m) => GroupDelta::Member(member_info(s, who, m, pk)),
                None => continue,
            },
            Change::Removed(who) => GroupDelta::Removed(*who),
            Change::Meta => GroupDelta::Meta {
                name: g.name.clone(),
                owner: g.owner,
                private: g.private,
            },
        };
        let u = GroupUpdate {
            gid: g.id,
            rev: g.rev,
            base_rev,
            epoch: g.epoch,
            revoke_prev: g.revoke_prev,
            key: g.key,
            delta,
        };
        push_ctrl(
            out,
            addr,
            ses,
            ctrl::GROUP_UPDATE,
            &pl::enc_group_update(&u),
        );
    }
}

/// Участник `pk` изменился (статус, адреса, онлайн, presence) во всех своих
/// группах: `rev += 1` и дельта kind 1 всем онлайн-участникам, ему самому
/// тоже — иначе его ревизия отстала бы и он сделал бы лишний GET_GROUP.
fn member_changed(s: &mut State, pk: &[u8; 32], out: &mut Outbox) {
    for gid in s.groups_of(pk) {
        let Some(g) = s.groups.get_mut(&gid) else {
            continue;
        };
        let base = g.bump();
        push_update(s, &s.groups[&gid], base, &Change::Member(*pk), None, out);
    }
}

/// Группы по gid и число их участников, видимых онлайн всем (не
/// invisible). Считается один раз на рассылку, а не на каждого получателя.
fn visible_counts(s: &State) -> Vec<(&Group, u32)> {
    let mut v: Vec<(&Group, u32)> = s
        .groups
        .values()
        .map(|g| {
            let n = g
                .members
                .keys()
                .filter(|pk| s.session_of(pk).is_some_and(|(_, x)| !x.invisible))
                .count();
            (g, n as u32)
        })
        .collect();
    v.sort_by_key(|(g, _)| g.id);
    v
}

/// GROUP_LIST глазами `me`: invisible-участник видит себя онлайн.
fn summaries(counts: &[(&Group, u32)], me: &[u8; 32], me_invisible: bool) -> Vec<GroupSummary> {
    counts
        .iter()
        .filter_map(|&(g, visible)| {
            let mine = g.members.contains_key(me);
            if g.private && !mine {
                return None;
            }
            Some(GroupSummary {
                gid: g.id,
                name: g.name.clone(),
                private: g.private,
                mine,
                online: visible + u32::from(mine && me_invisible),
                total: g.members.len() as u32,
                rev: if mine { g.rev } else { 0 },
                epoch: if mine { g.epoch } else { 0 },
            })
        })
        .collect()
}

fn group_summaries_for(s: &State, me: &[u8; 32]) -> Vec<GroupSummary> {
    let me_invisible = s.session_of(me).is_some_and(|(_, x)| x.invisible);
    summaries(&visible_counts(s), me, me_invisible)
}

/// Последнее известное серверу имя identity: из сессии, иначе из любой её
/// группы (имена участников сохраняются в server.json). Пусто — неизвестно.
fn known_name(s: &State, pk: &[u8; 32]) -> String {
    if let Some((_, ses)) = s.session_of(pk) {
        return ses.name.clone();
    }
    s.groups
        .values()
        .filter_map(|g| g.members.get(pk))
        .map(|m| &m.name)
        .find(|n| !n.is_empty() && n.as_str() != "…")
        .cloned()
        .unwrap_or_default()
}

/// Имя владельца группы для INVITE_RCVD (неизвестно — короткий ключ).
fn owner_name(s: &State, g: &Group) -> String {
    match known_name(s, &g.owner) {
        n if n.is_empty() => short(&g.owner),
        n => n,
    }
}

/// Все неотвеченные живые приглашения identity (группы, где она в
/// `invites`, но ещё не участник). Сортировка по gid — стабильный порядок
/// окон у клиента.
fn pending_invites(s: &State, pk: &[u8; 32]) -> Vec<pl::InviteInfo> {
    let now = unix_ms();
    let mut out: Vec<pl::InviteInfo> = s
        .groups
        .values()
        .filter(|g| !g.members.contains_key(pk) && !g.banned.contains_key(pk))
        .filter_map(|g| {
            let inv = g.invites.get(pk).filter(|i| s.invite_live(i, now))?;
            Some(pl::InviteInfo {
                gid: g.id,
                group_name: g.name.clone(),
                from_pubkey: g.owner,
                from_name: owner_name(s, g),
                expires_in: s.expires_in(inv, now),
            })
        })
        .collect();
    out.sort_by_key(|i| i.gid);
    out
}

/// INVITE_LIST identity `ses` — окно неотвеченных приглашений с gid ≥
/// `from`, не больше [`INVITES_PER_LIST`]. Неполное окно помечается
/// `complete == false` (обрезан хвост по gid), клиент дочитывает его
/// LIST_INVITES.
fn push_invite_list(s: &State, addr: SocketAddr, ses: &Session, out: &mut Outbox, from: u32) {
    let mut items: Vec<_> = pending_invites(s, &ses.ed_pub)
        .into_iter()
        .filter(|i| i.gid >= from)
        .collect();
    let complete = items.len() <= INVITES_PER_LIST;
    items.truncate(INVITES_PER_LIST);
    let list = pl::InviteList {
        from,
        items,
        complete,
    };
    push_ctrl(
        out,
        addr,
        ses,
        ctrl::INVITE_LIST,
        &pl::enc_invite_list(&list),
    );
}

/// Начало окна INVITE_LIST, которое покрывает `gid`: с начала, если до него
/// меньше [`INVITES_PER_LIST`] неотвеченных (первое окно — то, что клиент
/// видит после HELLO3), иначе с самого `gid`.
fn invite_window(s: &State, pk: &[u8; 32], gid: u32) -> u32 {
    let below = pending_invites(s, pk)
        .iter()
        .filter(|i| i.gid < gid)
        .count();
    if below < INVITES_PER_LIST { 0 } else { gid }
}

fn push_group_list(s: &State, addr: SocketAddr, ses: &Session, out: &mut Outbox) {
    let items = group_summaries_for(s, &ses.ed_pub);
    push_ctrl(
        out,
        addr,
        ses,
        ctrl::GROUP_LIST,
        &pl::enc_group_list(&items),
    );
}

/// GROUP_LIST всем сессиям — из housekeeping по `list_dirty`, под
/// блокировкой на чтение: команда (JOIN, LEAVE, CREATE…) стоит O(1) рассылок
/// за период, а не по одной на команду, и релей не ждёт её под записью.
fn broadcast_group_list(sh: &Shared) {
    let mut out = Outbox::new();
    {
        let s = sh.state.read().unwrap();
        let counts = visible_counts(&s);
        for (a, ses) in &s.sessions {
            let items = summaries(&counts, &ses.ed_pub, ses.invisible);
            push_ctrl(
                &mut out,
                *a,
                ses,
                ctrl::GROUP_LIST,
                &pl::enc_group_list(&items),
            );
        }
    }
    sh.flush(out);
}

/// ADMIN_INFO: баны и живые приглашения с последними известными именами.
fn admin_info(s: &State, g: &Group) -> AdminInfo {
    let now = unix_ms();
    let pick = |pk: &[u8; 32], stored: &str| match known_name(s, pk) {
        n if n.is_empty() => stored.to_string(),
        n => n,
    };
    let mut bans: Vec<BanEntry> = g
        .banned
        .iter()
        .map(|(pk, n)| BanEntry {
            pubkey: *pk,
            name: pick(pk, n),
        })
        .collect();
    bans.sort_by(|a, b| a.name.cmp(&b.name).then(a.pubkey.cmp(&b.pubkey)));
    let mut live: Vec<(&[u8; 32], &Invite)> = g
        .invites
        .iter()
        .filter(|(_, i)| s.invite_live(i, now))
        .collect();
    live.sort_by(|a, b| a.1.created_ms.cmp(&b.1.created_ms).then(a.0.cmp(b.0)));
    let invites = live
        .into_iter()
        .map(|(pk, i)| PendingInvite {
            pubkey: *pk,
            name: pick(pk, &i.name),
            expires_in: s.expires_in(i, now),
        })
        .collect();
    AdminInfo {
        gid: g.id,
        bans,
        invites,
    }
}

// ---------- HELLO3 ----------

/// HELLO3 (раздел 2): версия → cookie → подпись → сессия. Ответ без
/// верного cookie — только маленький CHALLENGE; неверная подпись, мусор и
/// ключи малого порядка отбрасываются молча.
fn handle_hello3(sh: &Shared, src: SocketAddr, body: &[u8]) {
    match hs::hello_version(body) {
        None => {
            sh.drop_frame();
            return;
        }
        Some(v) if v != proto::PROTOCOL_VERSION => {
            match unsupported_body(proto::HDR_LEN + body.len()) {
                Some(b) => sh.send_plain(src, ctrl::UNSUPPORTED, &b),
                None => sh.drop_frame(),
            }
            return;
        }
        Some(_) => {}
    }
    let Ok(h) = Hello3::decode(body) else {
        sh.drop_frame();
        return;
    };
    // Cookie (один keyed blake3) — раньше подписи: без подтверждённого
    // адреса сервер не тратит на HELLO3 ничего дорогого.
    let now = hs::unix_now();
    let cookie_ok = h
        .cookie
        .as_ref()
        .is_some_and(|c| sh.cookies.verify(src, &h.eph_pub, c, now));
    if !cookie_ok {
        metrics::Metrics::inc(&sh.metrics.challenge_total, 1);
        sh.send_plain(
            src,
            ctrl::CHALLENGE,
            &hs::enc_challenge(&sh.cookies.make(src, &h.eph_pub, now)),
        );
        return;
    }
    if h.verify().is_err() {
        sh.drop_frame();
        return;
    }
    let mut out = Outbox::new();
    // Повтор HELLO3 этой же попытки (WELCOME потерялся или задержался) —
    // тот же WELCOME, сессия и ключи не меняются: и задержанный первый
    // WELCOME, и повтор ведут к одним ключам, а перехваченный HELLO3,
    // повторённый с того же адреса, сессию не сбрасывает. `last_seen` не
    // обновляется: повтор чужими руками не держит ушедшего клиента онлайн.
    {
        let s = sh.state.read().unwrap();
        if let Some(ses) = s.sessions.get(&src)
            && ses.ed_pub == h.ed_pub
            && ses.eph_pub == h.eph_pub
        {
            push_hello_replay(sh, src, ses, &mut out);
            drop(s);
            sh.flush(out);
            return;
        }
        // HELLO3 прошлой попытки (её сессию уже сменила более новая или
        // закрыл таймаут) — молча: cookie под старый eph ещё жив, но
        // пересоздавать сессию и рассылать состояние по нему нельзя.
        if s.eph_retired(&h.ed_pub, &h.eph_pub) {
            drop(s);
            sh.drop_frame();
            return;
        }
    }
    // DH и подпись WELCOME — без блокировки состояния. Эфемерный секрет
    // сервера стирается при выходе из функции (прямая секретность).
    let eph = proto::EphemeralKey::generate();
    let Ok(keys) = proto::session_keys(
        proto::Role::Server,
        &sh.identity,
        &eph,
        &h.x_pub,
        &h.eph_pub,
    ) else {
        sh.drop_frame();
        return;
    };
    let welcome = proto::plain_frame(
        ctrl::WELCOME,
        &Welcome::encode(
            &sh.identity,
            &eph.public(),
            &sh.links,
            &h.ed_pub,
            &h.eph_pub,
        ),
    );
    drop(eph);
    {
        let mut s = sh.state.write().unwrap();
        // Дубль датаграммы, обработанный другим воркером одновременно.
        if let Some(ses) = s.sessions.get(&src)
            && ses.ed_pub == h.ed_pub
            && ses.eph_pub == h.eph_pub
        {
            push_hello_replay(sh, src, ses, &mut out);
        } else if s.eph_retired(&h.ed_pub, &h.eph_pub) {
            sh.drop_frame();
        } else {
            install_session(sh, &mut s, src, &h, keys, welcome, &mut out);
        }
    }
    sh.dirty.store(true, Ordering::Relaxed);
    sh.flush(out);
}

/// Ответ на повтор HELLO3 — только тот же WELCOME. Фреймы, шедшие за
/// первым, клиент либо держит (принятые до WELCOME разбираются после него),
/// либо дочитает сам (GROUP_LIST → GET_GROUP, LIST_INVITES). Повтор всего
/// состояния превращал бы перехваченный HELLO3 (cookie живёт до 60 с) в
/// усилитель: ~200 байт → все GROUP_STATE клиента. И сам WELCOME — не
/// чаще `WELCOME_RESEND_GAP`.
fn push_hello_replay(sh: &Shared, src: SocketAddr, ses: &Session, out: &mut Outbox) {
    let now = sh.now_ms();
    let gap = WELCOME_RESEND_GAP.as_millis() as u64;
    let last = ses.welcome_at.load(Ordering::Relaxed);
    if now.saturating_sub(last) < gap
        || ses
            .welcome_at
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        sh.drop_frame();
        return;
    }
    out.push((src, ses.welcome.clone()));
}

fn install_session(
    sh: &Shared,
    s: &mut State,
    src: SocketAddr,
    h: &Hello3,
    keys: proto::DirKeys,
    welcome: Vec<u8>,
    out: &mut Outbox,
) {
    let ed = h.ed_pub;
    let name = match clean(&h.name, NAME_MAX_CHARS) {
        n if n.is_empty() => "anon".to_string(),
        n => n,
    };
    // Старая сессия этого identity (переподключение, другой адрес или новая
    // попытка) и чужая сессия на этом адресе — убрать.
    let mut status = None;
    if let Some(old_addr) = s.by_pub.get(&ed).copied()
        && let Some(old) = s.remove_session(&old_addr)
    {
        status = Some(old.status);
    }
    if let Some(other) = s.remove_session(&src) {
        if other.ed_pub == ed {
            status = Some(other.status);
        } else if !s.online(&other.ed_pub) {
            sh.log(format!(
                "offline: {} ({}) — адрес занят",
                other.name,
                short(&other.ed_pub)
            ));
            member_changed(s, &other.ed_pub, out);
        }
    }
    // После рестарта сервера статус — из сохранённого участника.
    let status = status.unwrap_or_else(|| {
        s.groups
            .values()
            .filter_map(|g| g.members.get(&ed))
            .map(|m| m.status.clone())
            .find(|st| !st.is_empty())
            .unwrap_or_default()
    });
    s.sessions.insert(
        src,
        Session {
            ed_pub: ed,
            eph_pub: h.eph_pub,
            name: name.clone(),
            status: status.clone(),
            keys,
            welcome: welcome.clone(),
            welcome_at: AtomicU64::new(sh.now_ms()),
            tx: AtomicU64::new(0),
            msg_id: AtomicU32::new(0),
            rx: Mutex::new(proto::ReplayWindow::new()),
            invisible: h.invisible(),
            candidates: Vec::new(),
            last_seen: AtomicU64::new(sh.now_ms()),
            relay: Mutex::new(Bucket::new(sh.limits.relay_burst)),
            ctrl: Mutex::new(Bucket::new(sh.limits.ctrl_burst)),
        },
    );
    s.by_pub.insert(ed, src);
    let inv = if h.invisible() { ", invisible" } else { "" };
    sh.log(format!("online: {name} ({}) @ {src}{inv}", short(&ed)));
    out.push((src, welcome));
    // HELLO участника — ротация ключа всех его групп (клиент ключи не
    // хранит). Ему — GROUP_STATE целиком, остальным — дельта kind 1.
    for gid in s.groups_of(&ed) {
        let g = s.groups.get_mut(&gid).unwrap();
        if let Some(m) = g.members.get_mut(&ed) {
            m.name = name.clone();
            m.status = status.clone();
        }
        g.rotate(false);
        let base = g.bump();
        let g = &s.groups[&gid];
        push_group_state(s, g, src, &s.sessions[&src], out);
        push_update(s, g, base, &Change::Member(ed), Some(&ed), out);
    }
    let ses = &s.sessions[&src];
    push_group_list(s, src, ses, out);
    // Неотвеченные приглашения — заново при каждом HELLO3: по полному
    // списку клиент снимает приглашения, отозванные, пока он был офлайн.
    push_invite_list(s, src, ses, out, 0);
}

// ---------- остальные команды ----------

/// Команды без побочных эффектов — под блокировкой на чтение.
fn is_query(typ: u8) -> bool {
    matches!(
        typ,
        ctrl::CTRL_PING
            | ctrl::LIST_GROUPS
            | ctrl::FRIEND_GROUPS
            | ctrl::LIST_INVITES
            | ctrl::GET_GROUP
            | ctrl::GROUP_ADMIN
    )
}

fn is_mutation(typ: u8) -> bool {
    matches!(
        typ,
        ctrl::STATUS
            | ctrl::CREATE_GROUP
            | ctrl::JOIN_GROUP
            | ctrl::LEAVE_GROUP
            | ctrl::INVITE
            | ctrl::DECLINE_INVITE
            | ctrl::KICK
            | ctrl::BAN
            | ctrl::UNBAN
            | ctrl::TRANSFER_OWNER
            | ctrl::RENAME_GROUP
            | ctrl::DELETE_GROUP
            | ctrl::CANDIDATES
            | ctrl::PRESENCE
    )
}

/// Изменения, которые не должны пропасть при падении сервера в окне
/// `SAVE_EVERY` (кикнутый или забаненный снова в группе, вышедший — снова
/// участник): сохраняются сразу.
fn is_urgent(typ: u8) -> bool {
    matches!(
        typ,
        ctrl::KICK
            | ctrl::BAN
            | ctrl::UNBAN
            | ctrl::LEAVE_GROUP
            | ctrl::DELETE_GROUP
            | ctrl::TRANSFER_OWNER
            | ctrl::CREATE_GROUP
    )
}

fn handle_ctrl_frame(sh: &Shared, src: SocketAddr, typ: u8, body: &[u8]) {
    metrics::Metrics::inc(&sh.metrics.ctrl_frames, 1);
    // Быстрый путь — под блокировкой на чтение: сессия, окно повторов,
    // расшифровка, лимит.
    let (me, payload) = {
        let s = sh.state.read().unwrap();
        let Some(ses) = s.sessions.get(&src) else {
            drop(s);
            sh.drop_frame();
            send_reset(sh, src);
            return;
        };
        // Дешёвая предпроверка до AEAD: явный повтор или слишком старый.
        if !proto::ctrl_counter(body).is_some_and(|c| ses.rx.lock().unwrap().check(c)) {
            sh.drop_frame();
            return;
        }
        let Ok((ctr, payload)) = proto::open_ctrl(&ses.keys.rx, typ, body) else {
            // Сессия на адресе есть, но не та, под чьими ключами шлёт клиент
            // (её пересоздал повтор старого HELLO3 или чужой HELLO3 с этого
            // адреса): RESET — пусть переподключится сразу, а не через
            // таймаут. RESET и так не аутентифицирован, клиент сверяет его со
            // свежестью подлинных фреймов (раздел 3).
            drop(s);
            sh.drop_frame();
            send_reset(sh, src);
            return;
        };
        // Окно сдвигается только после успешной расшифровки: подделка с
        // огромным счётчиком не заставит отвергать честные фреймы.
        if !ses.rx.lock().unwrap().commit(ctr) {
            sh.drop_frame();
            return;
        }
        ses.last_seen.store(sh.now_ms(), Ordering::Relaxed);
        if !ses
            .ctrl
            .lock()
            .unwrap()
            .take(sh.limits.ctrl_rate, sh.limits.ctrl_burst)
        {
            sh.drop_frame();
            return;
        }
        (ses.ed_pub, payload)
    };
    let mut out = Outbox::new();
    // Между блокировками сессию могли заменить — команда идёт от той же
    // identity, иначе молча отбрасывается.
    if is_query(typ) {
        let s = sh.state.read().unwrap();
        if let Some(ses) = s.sessions.get(&src).filter(|x| x.ed_pub == me) {
            let r = handle_query(&s, src, ses, typ, &payload, &mut out);
            report(sh, src, ses, typ, r, &mut out);
        }
    } else if is_mutation(typ) {
        let mut s = sh.state.write().unwrap();
        if s.sessions.get(&src).is_some_and(|x| x.ed_pub == me) {
            let r = handle_mutation(sh, &mut s, src, typ, &payload, &mut out);
            sh.dirty.store(true, Ordering::Relaxed);
            if is_urgent(typ) {
                sh.save_soon();
            }
            if let Some(ses) = s.sessions.get(&src) {
                report(sh, src, ses, typ, r, &mut out);
            }
        }
    }
    sh.flush(out);
}

/// Ошибка команды — клиенту текстом ERROR.
fn report(sh: &Shared, src: SocketAddr, ses: &Session, typ: u8, r: Result<()>, out: &mut Outbox) {
    if let Err(e) = r {
        sh.log(format!("ctrl {typ:#04x} from {src}: {e:#}"));
        push_error(out, src, ses, &format!("{e:#}"));
    }
}

fn handle_query(
    s: &State,
    src: SocketAddr,
    ses: &Session,
    typ: u8,
    payload: &[u8],
    out: &mut Outbox,
) -> Result<()> {
    let me = &ses.ed_pub;
    match typ {
        ctrl::CTRL_PING => push_ctrl(out, src, ses, ctrl::CTRL_PONG, &[]),
        ctrl::LIST_GROUPS => push_group_list(s, src, ses, out),
        ctrl::LIST_INVITES => {
            let from = pl::dec_u32(payload)?;
            push_invite_list(s, src, ses, out, from);
        }
        ctrl::FRIEND_GROUPS => {
            let target = pl::dec_pubkey(payload)?;
            let mut groups = Vec::new();
            for g in s.groups.values() {
                let i_am = g.members.contains_key(me);
                let he_is = g.members.contains_key(&target);
                if !(he_is && (!g.private || i_am)) {
                    continue;
                }
                groups.push(pl::FriendGroup {
                    gid: g.id,
                    name: g.name.clone(),
                    private: g.private,
                    shared: i_am && he_is,
                });
            }
            groups.sort_by_key(|g| g.gid);
            let resp = pl::FriendGroups { target, groups };
            push_ctrl(
                out,
                src,
                ses,
                ctrl::FRIEND_GROUPS_RESP,
                &pl::enc_friend_groups(&resp),
            );
        }
        ctrl::GET_GROUP => {
            // Только запросившему: участнику — состояние, на несуществующую
            // группу — «удалена» (клиент уберёт её), не участнику — ошибка.
            let gid = pl::dec_gid(payload)?;
            match s.groups.get(&gid) {
                Some(g) if g.members.contains_key(me) => push_group_state(s, g, src, ses, out),
                Some(_) => anyhow::bail!("вы не участник группы {gid}"),
                None => push_ctrl(
                    out,
                    src,
                    ses,
                    ctrl::GROUP_STATE,
                    &pl::enc_group_state(&deleted_state(gid)),
                ),
            }
        }
        ctrl::GROUP_ADMIN => {
            let gid = pl::dec_gid(payload)?;
            let g = s.groups.get(&gid).context("группа не найдена")?;
            anyhow::ensure!(g.owner == *me, "может только владелец");
            push_ctrl(
                out,
                src,
                ses,
                ctrl::ADMIN_INFO,
                &pl::enc_admin_info(&admin_info(s, g)),
            );
        }
        _ => {}
    }
    Ok(())
}

fn handle_mutation(
    sh: &Shared,
    s: &mut State,
    src: SocketAddr,
    typ: u8,
    payload: &[u8],
    out: &mut Outbox,
) -> Result<()> {
    let (me, uname, ustatus) = {
        let x = &s.sessions[&src];
        (x.ed_pub, x.name.clone(), x.status.clone())
    };
    match typ {
        ctrl::STATUS => {
            let text = clean(&pl::dec_status(payload)?, STATUS_MAX_CHARS);
            // Тот же статус — не изменение (клиент повторяет его
            // периодически: потерянный STATUS иначе не чинился бы).
            if s.sessions[&src].status == text {
                return Ok(());
            }
            s.sessions.get_mut(&src).unwrap().status = text.clone();
            for g in s.groups.values_mut() {
                if let Some(m) = g.members.get_mut(&me) {
                    m.status = text.clone();
                }
            }
            member_changed(s, &me, out);
        }
        ctrl::CANDIDATES => {
            // n > 4 — фрейм отбрасывается молча (раздел 4).
            let Ok(list) = pl::dec_candidates(payload) else {
                return Ok(());
            };
            let list: Vec<SocketAddr> = list.into_iter().filter(usable_candidate).collect();
            let ses = s.sessions.get_mut(&src).unwrap();
            // Повтор того же списка — не изменение, ревизия не растёт.
            if ses.candidates != list {
                ses.candidates = list;
                member_changed(s, &me, out);
            }
        }
        ctrl::PRESENCE => {
            let invisible = pl::dec_presence(payload)?;
            let ses = s.sessions.get_mut(&src).unwrap();
            if ses.invisible != invisible {
                ses.invisible = invisible;
                sh.log(format!("presence: {uname} invisible={invisible}"));
                member_changed(s, &me, out);
            }
            // Подтверждение — всегда, и на повтор: клиент повторяет PRESENCE,
            // пока не получит его (потерянный PRESENCE оставлял бы видимым).
            push_ctrl(
                out,
                src,
                &s.sessions[&src],
                ctrl::PRESENCE_ACK,
                &pl::enc_presence(invisible),
            );
        }
        ctrl::CREATE_GROUP => {
            let (name, private) = pl::dec_create_group(payload)?;
            let name = clean(&name, GROUP_NAME_MAX_CHARS);
            anyhow::ensure!(!name.is_empty(), "пустое имя группы");
            let owned = s.owned_by(&me);
            let max = sh.limits.max_owned_groups;
            anyhow::ensure!(
                owned < max,
                "лимит групп: во владении уже {owned} (максимум {max})"
            );
            let ip = s.ip_for(me).context("нет свободных адресов на сервере")?;
            let gid = s
                .alloc_gid()
                .context("нет свободных номеров групп (все 254 заняты)")?;
            let mut key = [0u8; 32];
            rand::rng().fill_bytes(&mut key);
            let mut g = Group {
                id: gid,
                name: name.clone(),
                owner: me,
                private,
                key,
                epoch: 1,
                rev: 1,
                revoke_prev: false,
                members: HashMap::new(),
                by_ip: HashMap::new(),
                banned: HashMap::new(),
                invites: HashMap::new(),
                joins: Bucket::full(),
                left: HashMap::new(),
            };
            g.insert_member(
                me,
                Member {
                    ip,
                    name: uname.clone(),
                    status: ustatus,
                },
            );
            s.groups.insert(gid, g);
            sh.log(format!("created group {gid} \"{name}\" by {uname}"));
            push_group_state(s, &s.groups[&gid], src, &s.sessions[&src], out);
            push_group_list(s, src, &s.sessions[&src], out);
            sh.list_dirty.store(true, Ordering::Relaxed);
        }
        ctrl::JOIN_GROUP => {
            let gid = pl::dec_gid(payload)?;
            let now = unix_ms();
            let denied = match s.groups.get(&gid) {
                None => Some("группа не найдена"),
                Some(g) if g.banned.contains_key(&me) => Some("вы забанены в этой группе"),
                Some(g)
                    if g.private
                        && !g.members.contains_key(&me)
                        && g.owner != me
                        && !g.invites.get(&me).is_some_and(|i| s.invite_live(i, now)) =>
                {
                    Some("группа приватная, нужно приглашение")
                }
                _ => None,
            };
            if let Some(e) = denied {
                // Вход отклонён, и приглашения в gid нет: свежее окно со
                // списком — клиент снимет мёртвое приглашение (отозвали,
                // истекло, группу удалили, а наш GROUP_STATE потерялся),
                // иначе «Принять» отказывало бы снова и снова. На «группа
                // заполнена» — нет: приглашение остаётся, а движок по
                // списку снова входил бы в группы автовхода.
                push_invite_list(s, src, &s.sessions[&src], out, invite_window(s, &me, gid));
                anyhow::bail!(e);
            }
            let g = s.groups.get_mut(&gid).unwrap();
            if g.members.contains_key(&me) {
                // Повторный JOIN участника — ничего не меняет, только
                // состояние ему (lease сохраняется).
                push_group_state(s, &s.groups[&gid], src, &s.sessions[&src], out);
                return Ok(());
            }
            anyhow::ensure!(!g.full(), "группа заполнена");
            // Одна identity не крутит LEAVE/JOIN (каждый — ротация) и не
            // выбирает общий лимит входов группы: после выхода — пауза.
            // Вход по приглашению владельца — без паузы.
            if g.owner != me
                && !g.invites.contains_key(&me)
                && g.left
                    .get(&me)
                    .is_some_and(|t| t.elapsed() < REJOIN_COOLDOWN)
            {
                anyhow::bail!("недавно вышли из группы — повторите вход позже");
            }
            // Адрес — тот же, что у identity в остальных группах.
            let ip = s.ip_for(me).context("нет свободных адресов на сервере")?;
            let g = s.groups.get_mut(&gid).unwrap();
            // Каждый вход — ротация, а выход за ним — ротация с отзывом:
            // чехарда JOIN/LEAVE (новые identity бесплатны) ломала бы трафик
            // группы. Владельцу — без лимита.
            anyhow::ensure!(
                g.owner == me || g.joins.take(sh.limits.join_rate, sh.limits.join_burst),
                "слишком много входов в группу — повторите позже"
            );
            // Приглашение тратится только при успешном входе. В публичную
            // группу по приглашению — тоже снять.
            let consumed = g.invites.remove(&me).is_some();
            let gname = g.name.clone();
            g.insert_member(
                me,
                Member {
                    ip,
                    name: uname.clone(),
                    status: ustatus,
                },
            );
            // Вход нового участника — ротация (он не должен читать трафик
            // до входа); прошлый ключ остаётся в grace.
            g.rotate(false);
            let base = g.bump();
            sh.log(format!(
                "join: {uname} → {gid} \"{gname}\" as {}",
                ip_str(ip)
            ));
            let g = &s.groups[&gid];
            push_group_state(s, g, src, &s.sessions[&src], out);
            push_update(s, g, base, &Change::Member(me), Some(&me), out);
            // Вошедшему — сразу (раздел 5), остальным — общей рассылкой.
            push_group_list(s, src, &s.sessions[&src], out);
            sh.list_dirty.store(true, Ordering::Relaxed);
            // Приглашение потрачено — свежий список с начала: подтверждение
            // для клиента, и приглашения сверх обрезанного окна (после
            // HELLO3) показываются по мере ответов.
            if consumed {
                push_invite_list(s, src, &s.sessions[&src], out, 0);
            }
        }
        ctrl::LEAVE_GROUP => {
            let gid = pl::dec_gid(payload)?;
            let base = s.groups.get_mut(&gid).and_then(|g| {
                g.remove_member(&me).then(|| {
                    // Устаревшее приглашение не должно всплыть после выхода.
                    g.invites.remove(&me);
                    // Размер ограничен лимитом входов: каждый выход — после входа.
                    g.left.retain(|_, t| t.elapsed() < REJOIN_COOLDOWN);
                    g.left.insert(me, Instant::now());
                    g.rotate(true);
                    g.bump()
                })
            });
            match base {
                Some(base) => {
                    sh.log(format!("leave: {uname} ← {gid}"));
                    push_update(s, &s.groups[&gid], base, &Change::Removed(me), None, out);
                    // Вышедшему — подтверждение сразу, остальным — рассылкой.
                    push_group_list(s, src, &s.sessions[&src], out);
                    sh.list_dirty.store(true, Ordering::Relaxed);
                }
                // Повторный LEAVE (клиент повторяет до подтверждения) —
                // подтвердить списком только ему.
                None => push_group_list(s, src, &s.sessions[&src], out),
            }
        }
        ctrl::INVITE => {
            let (gid, target) = pl::dec_gid_target(payload)?;
            let tname = known_name(s, &target);
            let ttl_secs = s.invite_ttl_ms.div_ceil(1000).min(u32::MAX as u64) as u32;
            let (max_group, max_target) = (
                sh.limits.max_invites_per_group,
                sh.limits.max_invites_per_target,
            );
            // Живые приглашения цели в других группах (продление своего — не новое).
            let now = unix_ms();
            let target_pending = s
                .groups
                .values()
                .filter(|g| g.id != gid)
                .filter(|g| {
                    g.invites
                        .get(&target)
                        .is_some_and(|i| s.invite_live(i, now))
                })
                .count();
            let g = s.groups.get_mut(&gid).context("группа не найдена")?;
            anyhow::ensure!(g.owner == me, "приглашать может только владелец");
            anyhow::ensure!(!g.banned.contains_key(&target), "цель забанена");
            // Участнику окно приглашения ни к чему (и владельцу самому себе).
            anyhow::ensure!(!g.members.contains_key(&target), "уже участник группы");
            anyhow::ensure!(
                g.invites.contains_key(&target) || g.invites.len() < max_group,
                "лимит приглашений в группе ({max_group}): дождитесь ответов или отзовите (KICK)"
            );
            anyhow::ensure!(
                g.invites.contains_key(&target) || target_pending < max_target,
                "лимит приглашений у цели ({max_target}): у неё слишком много неотвеченных приглашений"
            );
            // Повторное приглашение продлевает срок.
            g.invites.insert(
                target,
                Invite {
                    created_ms: unix_ms(),
                    name: tname,
                },
            );
            let invite = pl::InviteInfo {
                gid,
                group_name: g.name.clone(),
                from_pubkey: me,
                from_name: uname,
                expires_in: ttl_secs,
            };
            sh.log(format!("invite: {gid} → {}", short(&target)));
            if let Some((addr, ses)) = s.session_of(&target) {
                push_ctrl(out, addr, ses, ctrl::INVITE_RCVD, &pl::enc_invite(&invite));
            }
        }
        ctrl::DECLINE_INVITE => {
            let gid = pl::dec_gid(payload)?;
            // Идемпотентно: группы или приглашения уже нет — не ошибка
            // (повтор, ответ с другого устройства, группа удалена).
            if let Some(g) = s.groups.get_mut(&gid)
                && g.invites.remove(&me).is_some()
            {
                let note = pl::InviteDeclined {
                    gid,
                    group_name: g.name.clone(),
                    by_pubkey: me,
                    by_name: uname.clone(),
                };
                let owner = g.owner;
                sh.log(format!("decline: {uname} ✗ {gid} \"{}\"", note.group_name));
                if let Some((addr, ses)) = s.session_of(&owner) {
                    push_ctrl(
                        out,
                        addr,
                        ses,
                        ctrl::INVITE_DECLINED,
                        &pl::enc_invite_declined(&note),
                    );
                }
            }
            // Отказавшемуся — всегда свежее окно, покрывающее gid:
            // подтверждение отказа (CLI `decline`) и приглашения сверх
            // обрезанного окна после HELLO3.
            push_invite_list(s, src, &s.sessions[&src], out, invite_window(s, &me, gid));
        }
        ctrl::KICK | ctrl::BAN => {
            let (gid, target) = pl::dec_gid_target(payload)?;
            let banned = typ == ctrl::BAN;
            let tname = known_name(s, &target);
            let max_bans = sh.limits.max_bans_per_group;
            let g = s.groups.get_mut(&gid).context("группа не найдена")?;
            anyhow::ensure!(g.owner == me, "может только владелец");
            anyhow::ensure!(target != g.owner, "нельзя исключить владельца");
            anyhow::ensure!(
                !banned || g.banned.contains_key(&target) || g.banned.len() < max_bans,
                "лимит банов в группе ({max_bans}): снимите старые (UNBAN) или исключите без бана"
            );
            let kicked = g.remove_member(&target);
            // Приглашение снимают и KICK, и BAN: кикнутому не всплывёт окно
            // старого приглашения, а KICK приглашённого (не участника) —
            // отзыв приглашения.
            let uninvited = g.invites.remove(&target).is_some();
            if banned {
                g.banned.insert(target, tname);
            }
            let gname = g.name.clone();
            // Удалённый участник знает текущий ключ — новый, прошлый отозван.
            let base = kicked.then(|| {
                g.rotate(true);
                g.bump()
            });
            // Ревизия после кика — в KICKED: всё, что не новее, запоздало.
            let rev = g.rev;
            let msg = if banned {
                "забанен в"
            } else {
                "кикнут из"
            };
            sh.log(format!("{msg} {gid}: {}", short(&target)));
            if let Some(base) = base {
                push_update(
                    s,
                    &s.groups[&gid],
                    base,
                    &Change::Removed(target),
                    None,
                    out,
                );
            }
            if kicked && let Some((addr, ses)) = s.session_of(&target) {
                let k = pl::Kicked {
                    gid,
                    group_name: gname,
                    banned,
                    rev,
                };
                push_ctrl(out, addr, ses, ctrl::KICKED, &pl::enc_kicked(&k));
            }
            // Приглашённому онлайн — свежее окно, покрывающее gid: клиент
            // закроет окно отозванного приглашения.
            if uninvited && let Some((addr, ses)) = s.session_of(&target) {
                push_invite_list(s, addr, ses, out, invite_window(s, &target, gid));
            }
            if kicked {
                sh.list_dirty.store(true, Ordering::Relaxed);
            }
        }
        ctrl::UNBAN => {
            let (gid, target) = pl::dec_gid_target(payload)?;
            let g = s.groups.get_mut(&gid).context("группа не найдена")?;
            anyhow::ensure!(g.owner == me, "может только владелец");
            // Идемпотентно; подтверждение — свежий ADMIN_INFO.
            if g.banned.remove(&target).is_some() {
                sh.log(format!("unban {gid}: {}", short(&target)));
            }
            let info = admin_info(s, &s.groups[&gid]);
            push_ctrl(
                out,
                src,
                &s.sessions[&src],
                ctrl::ADMIN_INFO,
                &pl::enc_admin_info(&info),
            );
        }
        ctrl::TRANSFER_OWNER => {
            let (gid, target) = pl::dec_gid_target(payload)?;
            let target_owned = s.owned_by(&target);
            let g = s.groups.get_mut(&gid).context("группа не найдена")?;
            anyhow::ensure!(g.owner == me, "передать группу может только владелец");
            anyhow::ensure!(
                g.members.contains_key(&target),
                "новый владелец должен быть участником группы"
            );
            if target == me {
                return Ok(());
            }
            let max = sh.limits.max_owned_groups;
            anyhow::ensure!(
                target_owned < max,
                "лимит групп у нового владельца (максимум {max})"
            );
            g.owner = target;
            let base = g.bump();
            sh.log(format!("owner {gid}: {} → {}", short(&me), short(&target)));
            push_update(s, &s.groups[&gid], base, &Change::Meta, None, out);
        }
        ctrl::RENAME_GROUP => {
            let (gid, name) = pl::dec_rename(payload)?;
            let name = clean(&name, GROUP_NAME_MAX_CHARS);
            let g = s.groups.get_mut(&gid).context("группа не найдена")?;
            anyhow::ensure!(g.owner == me, "может только владелец");
            anyhow::ensure!(!name.is_empty(), "пустое имя группы");
            g.name = name.clone();
            let base = g.bump();
            sh.log(format!("renamed {gid} → \"{name}\""));
            push_update(s, &s.groups[&gid], base, &Change::Meta, None, out);
            sh.list_dirty.store(true, Ordering::Relaxed);
        }
        ctrl::DELETE_GROUP => {
            let gid = pl::dec_gid(payload)?;
            let g = s.groups.get(&gid).context("группа не найдена")?;
            anyhow::ensure!(g.owner == me, "может только владелец");
            let removed = s.groups.remove(&gid).unwrap();
            sh.log(format!("deleted group {gid}"));
            let frame = pl::enc_group_state(&deleted_state(gid));
            // Приглашённым онлайн — тоже: клиент закроет окно приглашения в
            // удалённую группу.
            let notify: HashSet<&[u8; 32]> = removed
                .members
                .keys()
                .chain(removed.invites.keys())
                .collect();
            for pk in notify {
                if let Some((addr, ses)) = s.session_of(pk) {
                    push_ctrl(out, addr, ses, ctrl::GROUP_STATE, &frame);
                }
            }
            push_group_list(s, src, &s.sessions[&src], out);
            sh.list_dirty.store(true, Ordering::Relaxed);
        }
        _ => {}
    }
    Ok(())
}

/// Путь к данным по умолчанию.
pub fn default_data_dir() -> &'static Path {
    Path::new("tunnel-data")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::payloads;
    use std::cell::{Cell, RefCell};

    fn empty_group(id: u32) -> Group {
        Group {
            id,
            name: String::new(),
            owner: [0; 32],
            private: false,
            key: [0; 32],
            epoch: 1,
            rev: 1,
            revoke_prev: false,
            members: HashMap::new(),
            by_ip: HashMap::new(),
            banned: HashMap::new(),
            invites: HashMap::new(),
            joins: Bucket::full(),
            left: HashMap::new(),
        }
    }

    fn empty_state() -> State {
        State {
            sessions: HashMap::new(),
            by_pub: HashMap::new(),
            groups: HashMap::new(),
            leases: leases::Leases::default(),
            next_gid: GID_MIN,
            invite_ttl_ms: duration_ms(Limits::default().invite_ttl),
            retired_eph: HashMap::new(),
        }
    }

    #[test]
    fn gid_переиспользуется_после_удаления() {
        let mut s = empty_state();
        s.next_gid = GID_MAX;
        // Последний gid, затем по кругу с начала.
        assert_eq!(s.alloc_gid(), Some(GID_MAX));
        assert_eq!(s.alloc_gid(), Some(GID_MIN));
        // Заняты все, кроме 7, — выдаётся 7; заняты все — None.
        for gid in GID_MIN..=GID_MAX {
            if gid != 7 {
                s.groups.insert(gid, empty_group(gid));
            }
        }
        assert_eq!(s.alloc_gid(), Some(7));
        s.groups.insert(7, empty_group(7));
        assert_eq!(s.alloc_gid(), None);
    }

    #[test]
    fn имена_чистятся_и_обрезаются() {
        assert_eq!(clean("  ok\u{0}\n ", 10), "ok");
        assert_eq!(clean(&"я".repeat(50), 5), "яяяяя");
    }

    #[test]
    fn кандидаты_фильтруются() {
        let ok = |s: &str| usable_candidate(&s.parse().unwrap());
        assert!(ok("192.168.1.5:4000") && ok("[fe80::1]:4000"));
        assert!(!ok("0.0.0.0:4000") && !ok("192.168.1.5:0"));
        assert!(!ok("224.0.0.1:4000") && !ok("255.255.255.255:4000") && !ok("[ff02::1]:4000"));
    }

    // ---------- «сырой» клиент v3 ----------

    /// Ждёт открытый фрейм `want` на сокете (прочие пропускаются): (body, датаграмма).
    fn recv_plain(sock: &UdpSocket, want: u8, wait: Duration) -> Option<(Vec<u8>, Vec<u8>)> {
        let end = Instant::now() + wait;
        let mut buf = [0u8; 65_535];
        while Instant::now() < end {
            let Ok((n, _)) = sock.recv_from(&mut buf) else {
                continue;
            };
            let Ok((typ, body)) = proto::split_frame(&buf[..n]) else {
                continue;
            };
            if typ == want {
                return Some((body.to_vec(), buf[..n].to_vec()));
            }
        }
        None
    }

    /// «Сырой» клиент поверх протокола — без движка клиента.
    struct Raw {
        sock: UdpSocket,
        srv: SocketAddr,
        pk: [u8; 32],
        keys: proto::DirKeys,
        tx: Cell<u64>,
        rx: RefCell<proto::ReplayWindow>,
        reasm: RefCell<proto::Reassembler>,
        /// Последний отправленный ctrl-фрейм (тест повтора).
        last_sent: RefCell<Vec<u8>>,
        /// HELLO3 с cookie и WELCOME этого подключения.
        hello: Vec<u8>,
        welcome_frame: Vec<u8>,
        welcome: Welcome,
    }

    impl Raw {
        fn connect(srv: SocketAddr, name: &str) -> Raw {
            Raw::connect_as(srv, name, &proto::Identity::generate())
        }

        /// Подключение заданной identity (для переподключения той же личности).
        fn connect_as(srv: SocketAddr, name: &str, id: &proto::Identity) -> Raw {
            Raw::connect_with(srv, name, id, 0)
        }

        /// Полное рукопожатие: HELLO3 → CHALLENGE → HELLO3 с cookie → WELCOME.
        fn connect_with(srv: SocketAddr, name: &str, id: &proto::Identity, flags: u8) -> Raw {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let eph = proto::EphemeralKey::generate();
            let h1 = proto::plain_frame(
                ctrl::HELLO3,
                &Hello3::encode(id, &eph.public(), name, flags, None),
            );
            sock.send_to(&h1, srv).unwrap();
            let (ch, _) =
                recv_plain(&sock, ctrl::CHALLENGE, Duration::from_secs(5)).expect("нет CHALLENGE");
            let cookie = hs::dec_challenge(&ch).unwrap();
            let hello = proto::plain_frame(
                ctrl::HELLO3,
                &Hello3::encode(id, &eph.public(), name, flags, Some(&cookie)),
            );
            sock.send_to(&hello, srv).unwrap();
            let (body, welcome_frame) =
                recv_plain(&sock, ctrl::WELCOME, Duration::from_secs(5)).expect("нет WELCOME");
            let welcome = Welcome::decode(&body, &id.ed_pub(), &eph.public()).unwrap();
            let keys = proto::session_keys(
                proto::Role::Client,
                id,
                &eph,
                &welcome.server_x,
                &welcome.server_eph,
            )
            .unwrap();
            Raw {
                sock,
                srv,
                pk: id.ed_pub(),
                keys,
                tx: Cell::new(0),
                rx: RefCell::new(proto::ReplayWindow::new()),
                reasm: RefCell::new(proto::Reassembler::new()),
                last_sent: RefCell::new(Vec::new()),
                hello,
                welcome_frame,
                welcome,
            }
        }

        fn send(&self, typ: u8, payload: &[u8]) {
            let ctr = self.tx.get();
            self.tx.set(ctr + 1);
            let f = proto::seal_ctrl(&self.keys.tx, ctr, typ, payload);
            self.sock.send_to(&f, self.srv).unwrap();
            *self.last_sent.borrow_mut() = f;
        }

        /// Следующее ctrl-сообщение (FRAG собирается) до `end`.
        fn next_ctrl(&self, end: Instant) -> Option<(u8, Vec<u8>)> {
            let mut buf = [0u8; 65_535];
            while Instant::now() < end {
                let Ok((n, _)) = self.sock.recv_from(&mut buf) else {
                    continue;
                };
                let Ok((typ, body)) = proto::split_frame(&buf[..n]) else {
                    continue;
                };
                if proto::grp::is_group(typ) || ctrl::is_plaintext(typ) {
                    continue;
                }
                let Ok((ctr, p)) = proto::open_ctrl(&self.keys.rx, typ, body) else {
                    continue;
                };
                assert!(
                    self.rx.borrow_mut().commit(ctr),
                    "сервер повторил счётчик {ctr}"
                );
                if typ != ctrl::FRAG {
                    return Some((typ, p));
                }
                if let Some(done) = self.reasm.borrow_mut().push(&p, Instant::now()).unwrap() {
                    return Some(done);
                }
            }
            None
        }

        /// Следующий управляющий фрейм нужного типа (прочие пропускаются).
        fn expect(&self, want: u8) -> Vec<u8> {
            self.until(want).1
        }

        /// Типы управляющих фреймов, пришедших до фрейма `want`, и его payload.
        fn until(&self, want: u8) -> (Vec<u8>, Vec<u8>) {
            let end = Instant::now() + Duration::from_secs(5);
            let mut seen = Vec::new();
            while let Some((typ, p)) = self.next_ctrl(end) {
                if typ == want {
                    return (seen, p);
                }
                seen.push(typ);
            }
            panic!("не дождались фрейма {want:#04x}; пришли {seen:02x?}");
        }

        /// Всё, что пришло за `wait` (типы).
        fn drain(&self, wait: Duration) -> Vec<u8> {
            let end = Instant::now() + wait;
            let mut seen = Vec::new();
            while let Some((typ, _)) = self.next_ctrl(end) {
                seen.push(typ);
            }
            seen
        }

        /// PING → PONG: всё, что пришло до PONG (порядок фреймов сохраняется).
        fn sync(&self) -> Vec<u8> {
            self.send(ctrl::CTRL_PING, &[]);
            self.until(ctrl::CTRL_PONG).0
        }

        fn update(&self) -> GroupUpdate {
            payloads::dec_group_update(&self.expect(ctrl::GROUP_UPDATE)).unwrap()
        }

        fn state(&self) -> GroupState {
            payloads::dec_group_state(&self.expect(ctrl::GROUP_STATE)).unwrap()
        }

        fn error(&self) -> String {
            payloads::dec_error(&self.expect(ctrl::ERROR)).unwrap()
        }

        fn create(&self, name: &str, private: bool) -> GroupState {
            self.send(
                ctrl::CREATE_GROUP,
                &payloads::enc_create_group(name, private),
            );
            self.state()
        }

        /// Ждёт групповой фрейм; None — ничего не пришло за `wait`.
        fn group_frame(&self, wait: Duration) -> Option<Vec<u8>> {
            let end = Instant::now() + wait;
            let mut buf = [0u8; 65_535];
            while Instant::now() < end {
                let Ok((n, _)) = self.sock.recv_from(&mut buf) else {
                    continue;
                };
                let Ok((typ, _)) = proto::split_frame(&buf[..n]) else {
                    continue;
                };
                if proto::grp::is_group(typ) {
                    return Some(buf[..n].to_vec());
                }
            }
            None
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("voidlink-srv-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Один воркер: команды одного клиента обрабатываются строго по
    /// порядку (PING после мутации — барьер). Многопоточность — в
    /// `релей_под_нагрузкой`.
    fn start_in(dir: &Path, limits: Limits) -> Server {
        start_workers(dir, limits, 1)
    }

    fn start_workers(dir: &Path, limits: Limits, workers: usize) -> Server {
        Server::start(Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: dir.to_path_buf(),
            workers,
            quiet: true,
            limits,
            ..Config::default()
        })
        .unwrap()
    }

    fn test_server_with(tag: &str, limits: Limits) -> (Server, PathBuf) {
        let dir = temp_dir(tag);
        (start_in(&dir, limits), dir)
    }

    fn test_server(tag: &str) -> (Server, PathBuf) {
        test_server_with(tag, Limits::default())
    }

    fn frame_for(st: &GroupState, src: u32, dst: u32, payload: &[u8]) -> Vec<u8> {
        let h = proto::GroupHeader {
            gid: st.gid,
            src,
            dst,
            epoch: st.epoch,
        };
        proto::seal_group(&st.key, proto::grp::DATA, &h, 0, payload)
    }

    #[test]
    fn сервер_релеит_только_своим_и_сохраняет_состояние() {
        let dir = temp_dir("relay");
        let server = start_in(&dir, Limits::default());
        let srv = server.addr;

        let a = Raw::connect(srv, "alpha");
        a.expect(ctrl::GROUP_LIST);
        a.send(ctrl::CTRL_PING, &[]);
        a.expect(ctrl::CTRL_PONG);

        let st = a.create("  game\n", false);
        assert_eq!(st.name, "game", "имя группы очищено");
        assert_eq!((st.rev, st.epoch), (1, 1));
        let (gid, ip_a) = (st.gid, st.my_ip);

        let b = Raw::connect(srv, "bravo");
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        let st_b = b.state();
        let ip_b = st_b.my_ip;
        assert_ne!(ip_a, ip_b);

        // Свой src_ip — релеится.
        let ok = frame_for(&st_b, ip_a, ip_b, b"hi");
        a.sock.send_to(&ok, srv).unwrap();
        let got = b
            .group_frame(Duration::from_secs(3))
            .expect("релей своего фрейма");
        assert_eq!(got, ok);

        // Чужой src_ip (подмена) — отбрасывается.
        let spoof = frame_for(&st_b, ip_b, ip_b, b"spoof");
        a.sock.send_to(&spoof, srv).unwrap();
        assert!(
            b.group_frame(Duration::from_millis(700)).is_none(),
            "подмена src_ip релеится"
        );
        // Фрейм от адреса без сессии — RESET, не релей.
        let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
        stranger
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        stranger.send_to(&ok, srv).unwrap();
        assert!(recv_plain(&stranger, ctrl::RESET, Duration::from_secs(3)).is_some());

        // Выход; повторный LEAVE тоже подтверждается списком.
        b.send(ctrl::LEAVE_GROUP, &payloads::enc_gid(gid));
        b.expect(ctrl::GROUP_LIST);
        b.send(ctrl::LEAVE_GROUP, &payloads::enc_gid(gid));
        b.expect(ctrl::GROUP_LIST);
        a.sock.send_to(&ok, srv).unwrap();
        assert!(
            b.group_frame(Duration::from_millis(700)).is_none(),
            "релей после выхода"
        );

        // Приглашение офлайн-identity — время и имя переживают рестарт.
        let x = proto::Identity::generate().ed_pub();
        a.send(ctrl::INVITE, &payloads::enc_gid_target(gid, &x));
        a.sync();
        let (rev, epoch, created) = {
            let s = server.shared.state.read().unwrap();
            let g = &s.groups[&gid];
            (g.rev, g.epoch, g.invites[&x].created_ms)
        };

        // Сохранение и повторная загрузка: identity, группа, имена на месте.
        let code = server.code.clone();
        server.stop();
        let again = Server::start(Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: dir.clone(),
            workers: 1,
            quiet: true,
            limits: Limits::default(),
            ..Config::default()
        })
        .unwrap();
        assert_eq!(again.code, code, "identity сервера сохранилась");
        {
            let s = again.shared.state.read().unwrap();
            let g = &s.groups[&gid];
            assert_eq!(
                g.members[&a.pk].name, "alpha",
                "имя офлайн-участника, а не «…»"
            );
            // С запасом: номера, выданные после последнего сохранения (если
            // бы сервер упал), не повторяются.
            assert_eq!(
                (g.rev, g.epoch),
                (rev + LOAD_MARGIN, epoch + LOAD_MARGIN),
                "ревизия и эпоха сохранились"
            );
            assert_eq!(
                g.invites[&x].created_ms, created,
                "срок приглашения не продлился"
            );
        }
        again.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hello3_без_cookie_получает_только_маленький_challenge() {
        let (server, dir) = test_server("challenge");
        let id = proto::Identity::generate();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let eph = proto::EphemeralKey::generate();
        let hello = proto::plain_frame(
            ctrl::HELLO3,
            &Hello3::encode(&id, &eph.public(), "alpha", 0, None),
        );
        sock.send_to(&hello, server.addr).unwrap();
        let mut buf = [0u8; 65_535];
        let mut got = Vec::new();
        let end = Instant::now() + Duration::from_millis(800);
        while Instant::now() < end {
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                got.push(buf[..n].to_vec());
            }
        }
        assert_eq!(got.len(), 1, "ровно один ответ");
        let (typ, body) = proto::split_frame(&got[0]).unwrap();
        assert_eq!(typ, ctrl::CHALLENGE);
        hs::dec_challenge(body).unwrap();
        assert!(
            got[0].len() < hello.len(),
            "ответ {} ≥ запроса {}",
            got[0].len(),
            hello.len()
        );
        assert!(
            server.shared.state.read().unwrap().sessions.is_empty(),
            "сессия без cookie"
        );

        // Неверный cookie — тоже только CHALLENGE.
        let bad = proto::plain_frame(
            ctrl::HELLO3,
            &Hello3::encode(&id, &eph.public(), "alpha", 0, Some(&[7; 16])),
        );
        sock.send_to(&bad, server.addr).unwrap();
        assert!(recv_plain(&sock, ctrl::CHALLENGE, Duration::from_secs(3)).is_some());
        assert!(server.shared.state.read().unwrap().sessions.is_empty());

        // Подпись проверяется после cookie: верный cookie, порченая подпись —
        // молча.
        let (ch, _) = {
            sock.send_to(&hello, server.addr).unwrap();
            recv_plain(&sock, ctrl::CHALLENGE, Duration::from_secs(3)).unwrap()
        };
        let cookie = hs::dec_challenge(&ch).unwrap();
        let mut forged = Hello3::encode(&id, &eph.public(), "alpha", 0, Some(&cookie));
        *forged.last_mut().unwrap() ^= 1;
        sock.send_to(&proto::plain_frame(ctrl::HELLO3, &forged), server.addr)
            .unwrap();
        assert!(recv_plain(&sock, ctrl::WELCOME, Duration::from_millis(600)).is_none());
        assert!(server.shared.state.read().unwrap().sessions.is_empty());

        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hello3_с_чужого_адреса_не_создаёт_и_не_перехватывает_сессию() {
        let (server, dir) = test_server("hijack");
        let a = Raw::connect(server.addr, "alpha");
        let a_addr = a.sock.local_addr().unwrap();
        a.sync();

        // Перехваченный HELLO3 с cookie, повторённый с другого адреса:
        // cookie привязан к адресу — только CHALLENGE, сессия на месте.
        let evil = UdpSocket::bind("127.0.0.1:0").unwrap();
        evil.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        evil.send_to(&a.hello, server.addr).unwrap();
        assert!(recv_plain(&evil, ctrl::CHALLENGE, Duration::from_secs(3)).is_some());
        assert!(recv_plain(&evil, ctrl::WELCOME, Duration::from_millis(500)).is_none());
        {
            let s = server.shared.state.read().unwrap();
            assert_eq!(s.sessions.len(), 1);
            assert_eq!(s.by_pub[&a.pk], a_addr, "сессия не перехвачена");
        }
        a.sync();

        // Повтор того же HELLO3 с того же адреса (WELCOME потерялся) — тот
        // же WELCOME, ключи сессии не меняются. И только он: состояние групп
        // заново не шлётся (иначе перехваченный HELLO3 — усилитель), и
        // `last_seen` повтор не обновляет.
        let gid = a.create("g", false).gid;
        a.sync();
        server.shared.state.read().unwrap().sessions[&a_addr]
            .last_seen
            .store(0, Ordering::Relaxed);
        a.sock.send_to(&a.hello, server.addr).unwrap();
        let (_, again) =
            recv_plain(&a.sock, ctrl::WELCOME, Duration::from_secs(3)).expect("повтор WELCOME");
        assert_eq!(again, a.welcome_frame, "повтор — тот же WELCOME");
        assert_eq!(
            server.shared.state.read().unwrap().sessions[&a_addr]
                .last_seen
                .load(Ordering::Relaxed),
            0,
            "повтор HELLO3 держит сессию онлайн"
        );
        let seen = a.sync();
        assert!(seen.is_empty(), "за повтором WELCOME пришло: {seen:02x?}");
        a.send(ctrl::GET_GROUP, &payloads::enc_gid(gid));
        assert_eq!(a.state().gid, gid, "сессия жива");

        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn повтор_старого_hello3_не_пересоздаёт_сессию_и_welcome_ограничен() {
        // Типы всех датаграмм (и открытых) за `wait`.
        fn raw_types(sock: &UdpSocket, wait: Duration) -> Vec<u8> {
            let end = Instant::now() + wait;
            let mut buf = [0u8; 65_535];
            let mut seen = Vec::new();
            while Instant::now() < end {
                if let Ok((n, _)) = sock.recv_from(&mut buf)
                    && let Ok((typ, _)) = proto::split_frame(&buf[..n])
                {
                    seen.push(typ);
                }
            }
            seen
        }
        let (server, dir) = test_server("hello-replay");
        let id = proto::Identity::generate();
        let a1 = Raw::connect_as(server.addr, "alpha", &id);
        a1.sync();
        let gid = a1.create("g", false).gid;
        a1.sync();
        // Новая попытка той же identity (новый eph) сменила сессию.
        let a2 = Raw::connect_as(server.addr, "alpha", &id);
        let a2_addr = a2.sock.local_addr().unwrap();
        a2.sync();
        a1.drain(Duration::from_millis(200));

        // HELLO3 прошлой попытки с её адреса (cookie ещё жив) — тишина:
        // ни WELCOME, ни состояния, сессия новой попытки на месте.
        for _ in 0..3 {
            a1.sock.send_to(&a1.hello, server.addr).unwrap();
        }
        let got = raw_types(&a1.sock, Duration::from_millis(600));
        assert!(got.is_empty(), "ответ на старый HELLO3: {got:02x?}");
        {
            let s = server.shared.state.read().unwrap();
            assert_eq!(s.sessions.len(), 1);
            assert_eq!(
                s.by_pub[&id.ed_pub()],
                a2_addr,
                "старый HELLO3 пересоздал сессию"
            );
        }
        assert!(a2.sync().is_empty(), "живой сессии что-то пришло");
        a2.send(ctrl::GET_GROUP, &payloads::enc_gid(gid));
        assert_eq!(a2.state().gid, gid, "сессия жива");

        // Поток повторов HELLO3 живой попытки — не больше одного WELCOME на
        // `WELCOME_RESEND_GAP`, и ничего кроме него.
        thread::sleep(WELCOME_RESEND_GAP);
        for _ in 0..5 {
            a2.sock.send_to(&a2.hello, server.addr).unwrap();
        }
        let got = raw_types(&a2.sock, Duration::from_millis(300));
        assert_eq!(
            got.iter().filter(|&&t| t == ctrl::WELCOME).count(),
            1,
            "WELCOME: {got:02x?}"
        );
        assert!(
            got.iter().all(|&t| t == ctrl::WELCOME),
            "за WELCOME пришло: {got:02x?}"
        );

        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn повтор_ctrl_фрейма_игнорируется() {
        let (server, dir) = test_server("replay");
        let a = Raw::connect(server.addr, "alpha");
        a.sync();
        a.send(ctrl::CTRL_PING, &[]);
        a.expect(ctrl::CTRL_PONG);
        // Тот же фрейм ещё раз — без ответа.
        let replay = a.last_sent.borrow().clone();
        a.sock.send_to(&replay, server.addr).unwrap();
        assert!(
            !a.drain(Duration::from_millis(600))
                .contains(&ctrl::CTRL_PONG),
            "повтор принят"
        );
        // Подделка с огромным счётчиком не сдвигает окно (сдвиг — только
        // после расшифровки): честный следующий фрейм проходит.
        let mut forged = proto::seal_ctrl(&[9; 32], 1 << 40, ctrl::CTRL_PING, &[]);
        forged[proto::HDR_LEN + 8] ^= 1;
        a.sock.send_to(&forged, server.addr).unwrap();
        a.send(ctrl::CTRL_PING, &[]);
        a.expect(ctrl::CTRL_PONG);
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ключ_лимитера_ipv6_по_64_и_unsupported_не_длиннее_запроса() {
        let k = |s: &str| ip_key(s.parse().unwrap());
        assert_eq!(
            k("2001:db8:1:2:aaaa::1"),
            k("2001:db8:1:2:ffff:ffff:ffff:ffff")
        );
        assert_ne!(k("2001:db8:1:2::1"), k("2001:db8:1:3::1"));
        assert_eq!(k("::ffff:10.0.0.1"), k("10.0.0.1"), "v4-mapped — как IPv4");
        assert_ne!(k("10.0.0.1"), k("10.0.0.2"));
        let full = proto::HDR_LEN + hs::enc_unsupported(UNSUPPORTED_TEXT).len();
        assert_eq!(
            unsupported_body(full).unwrap(),
            hs::enc_unsupported(UNSUPPORTED_TEXT)
        );
        assert_eq!(unsupported_body(full - 1).unwrap(), hs::enc_unsupported(""));
        assert_eq!(
            unsupported_body(proto::HDR_LEN + 2).unwrap(),
            hs::enc_unsupported("")
        );
        assert!(unsupported_body(proto::HDR_LEN + 1).is_none());
    }

    #[test]
    fn нерасшифровываемый_ctrl_при_живой_сессии_получает_reset() {
        let (server, dir) = test_server("aead-reset");
        let a = Raw::connect(server.addr, "alpha");
        a.sync();
        // Фрейм под чужими ключами с адреса живой сессии (сессию пересоздал
        // повтор старого HELLO3): RESET, чтобы клиент переподключился сразу.
        let f = proto::seal_ctrl(&[9; 32], 5, ctrl::CTRL_PING, &[]);
        a.sock.send_to(&f, server.addr).unwrap();
        assert!(recv_plain(&a.sock, ctrl::RESET, Duration::from_secs(3)).is_some());
        // Повтор своего фрейма (окно повторов) — не RESET, просто тишина.
        a.send(ctrl::CTRL_PING, &[]);
        a.expect(ctrl::CTRL_PONG);
        let replay = a.last_sent.borrow().clone();
        a.sock.send_to(&replay, server.addr).unwrap();
        assert!(recv_plain(&a.sock, ctrl::RESET, Duration::from_millis(500)).is_none());
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn лимит_приглашений_на_одну_цель() {
        let limits = Limits {
            max_invites_per_target: 2,
            ctrl_rate: 1e6,
            ctrl_burst: 1e6,
            ..Limits::default()
        };
        let (server, dir) = test_server_with("target-cap", limits);
        let a = Raw::connect(server.addr, "alpha");
        let target = [0x77; 32];
        let gids: Vec<u32> = (0..3)
            .map(|i| a.create(&format!("g{i}"), false).gid)
            .collect();
        for &gid in &gids[..2] {
            a.send(ctrl::INVITE, &payloads::enc_gid_target(gid, &target));
        }
        assert!(!a.sync().contains(&ctrl::ERROR));
        a.send(ctrl::INVITE, &payloads::enc_gid_target(gids[2], &target));
        assert!(a.error().contains("лимит приглашений у цели"));
        // Продление уже висящего — не новое приглашение.
        a.send(ctrl::INVITE, &payloads::enc_gid_target(gids[0], &target));
        assert!(!a.sync().contains(&ctrl::ERROR));
        // Другой цели лимит не мешает.
        a.send(
            ctrl::INVITE,
            &payloads::enc_gid_target(gids[2], &[0x78; 32]),
        );
        assert!(!a.sync().contains(&ctrl::ERROR));
        // Отзыв (KICK) освобождает место.
        a.send(ctrl::KICK, &payloads::enc_gid_target(gids[0], &target));
        a.send(ctrl::INVITE, &payloads::enc_gid_target(gids[2], &target));
        assert!(!a.sync().contains(&ctrl::ERROR));
        assert!(
            server.shared.state.read().unwrap().groups[&gids[2]]
                .invites
                .contains_key(&target)
        );
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn лимиты_приглашений_банов_и_входов_в_группу() {
        const MAX_INVITES_PER_GROUP: usize = 64;
        const MAX_BANS_PER_GROUP: usize = 256;
        let limits = Limits {
            join_rate: 0.001,
            join_burst: 2.0,
            ctrl_rate: 1e6,
            ctrl_burst: 1e6,
            max_invites_per_group: MAX_INVITES_PER_GROUP,
            max_bans_per_group: MAX_BANS_PER_GROUP,
            ..Limits::default()
        };
        let (server, dir) = test_server_with("caps", limits);
        let a = Raw::connect(server.addr, "alpha");
        let gid = a.create("g", false).gid;
        for i in 0..MAX_INVITES_PER_GROUP {
            let mut pk = [0u8; 32];
            pk[..8].copy_from_slice(&(i as u64).to_be_bytes());
            a.send(ctrl::INVITE, &payloads::enc_gid_target(gid, &pk));
        }
        assert!(!a.sync().contains(&ctrl::ERROR));
        a.send(ctrl::INVITE, &payloads::enc_gid_target(gid, &[0xAA; 32]));
        assert!(a.error().contains("лимит приглашений"));
        // Повторное приглашение того же — продление, не новое.
        a.send(ctrl::INVITE, &payloads::enc_gid_target(gid, &[0; 32]));
        assert!(!a.sync().contains(&ctrl::ERROR));
        for i in 0..MAX_BANS_PER_GROUP {
            let mut pk = [0xBB; 32];
            pk[..8].copy_from_slice(&(i as u64).to_be_bytes());
            a.send(ctrl::BAN, &payloads::enc_gid_target(gid, &pk));
            if i % 64 == 63 {
                a.sync();
            }
        }
        assert!(!a.sync().contains(&ctrl::ERROR));
        a.send(ctrl::BAN, &payloads::enc_gid_target(gid, &[0xCC; 32]));
        assert!(a.error().contains("лимит банов"));
        {
            let s = server.shared.state.read().unwrap();
            let g = &s.groups[&gid];
            assert_eq!(
                (g.invites.len(), g.banned.len()),
                (MAX_INVITES_PER_GROUP, MAX_BANS_PER_GROUP)
            );
        }
        // Входы не-участников: запас 2, дальше — отказ без ротации.
        let epoch = server.shared.state.read().unwrap().groups[&gid].epoch;
        let (b, c, d) = (
            Raw::connect(server.addr, "b"),
            Raw::connect(server.addr, "c"),
            Raw::connect(server.addr, "d"),
        );
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        assert_eq!(b.state().epoch, epoch + 1);
        c.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        assert_eq!(c.state().epoch, epoch + 2);
        d.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        assert!(d.error().contains("слишком много входов"));
        assert_eq!(
            server.shared.state.read().unwrap().groups[&gid].epoch,
            epoch + 2,
            "отказ ротировал ключ"
        );
        // Повторный JOIN участника — не вход, лимит не тратит.
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        assert_eq!(b.state().epoch, epoch + 2);
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn чехарда_leave_join_одной_identity_не_крутит_ключ() {
        let limits = Limits {
            ctrl_rate: 1e6,
            ctrl_burst: 1e6,
            ..Limits::default()
        };
        let (server, dir) = test_server_with("churn", limits);
        let a = Raw::connect(server.addr, "alpha");
        let gid = a.create("g", false).gid;
        let b = Raw::connect(server.addr, "bravo");
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        b.state();
        b.send(ctrl::LEAVE_GROUP, &payloads::enc_gid(gid));
        b.sync();
        let epoch = server.shared.state.read().unwrap().groups[&gid].epoch;
        // Сразу назад — отказ без ротации и без траты общего лимита входов.
        let joins = server.shared.state.read().unwrap().groups[&gid]
            .joins
            .tokens;
        for _ in 0..20 {
            b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
            assert!(b.error().contains("недавно вышли"));
        }
        {
            let s = server.shared.state.read().unwrap();
            let g = &s.groups[&gid];
            assert_eq!(g.epoch, epoch, "отказ ротировал ключ");
            assert!(
                g.joins.tokens >= joins,
                "отказ потратил лимит входов группы"
            );
        }
        // Другим identity пауза не мешает.
        let c = Raw::connect(server.addr, "charlie");
        c.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        assert_eq!(c.state().epoch, epoch + 1);
        // По приглашению владельца — без паузы.
        a.send(ctrl::INVITE, &payloads::enc_gid_target(gid, &b.pk));
        a.sync();
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        assert_eq!(b.state().epoch, epoch + 2);
        // После паузы — снова можно.
        b.send(ctrl::LEAVE_GROUP, &payloads::enc_gid(gid));
        b.sync();
        thread::sleep(REJOIN_COOLDOWN + Duration::from_millis(100));
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        assert_eq!(b.state().epoch, epoch + 4);
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn список_групп_рассылается_раз_в_период_а_статус_без_изменения_не_дельта() {
        let (server, dir) = test_server("list-debounce");
        let a = Raw::connect(server.addr, "alpha");
        let b = Raw::connect(server.addr, "bravo");
        let gid = a.create("g", false).gid;
        // Владельцу — сразу; B — общей рассылкой housekeeping.
        a.expect(ctrl::GROUP_LIST);
        b.sync();
        for i in 0..20 {
            a.send(
                ctrl::RENAME_GROUP,
                &payloads::enc_rename(gid, &format!("g{i}")),
            );
        }
        a.sync();
        let lists = b
            .drain(Duration::from_millis(2500))
            .iter()
            .filter(|t| **t == ctrl::GROUP_LIST)
            .count();
        assert!(
            (1..=2).contains(&lists),
            "GROUP_LIST у B: {lists} на 20 команд"
        );

        // Тот же статус — без ревизии и дельты.
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        b.state();
        a.update();
        b.send(ctrl::STATUS, &payloads::enc_status("afk"));
        a.update();
        b.send(ctrl::STATUS, &payloads::enc_status("afk"));
        b.sync();
        assert!(
            !a.sync().contains(&ctrl::GROUP_UPDATE),
            "повтор статуса — дельта"
        );
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn кик_сохраняется_сразу() {
        let (server, dir) = test_server("urgent-save");
        let a = Raw::connect(server.addr, "alpha");
        let gid = a.create("g", false).gid;
        let b = Raw::connect(server.addr, "bravo");
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        b.state();
        let store = persist::Store::new(&dir);
        let on_disk = |pk: &[u8; 32]| {
            store
                .load()
                .unwrap()
                .unwrap()
                .groups
                .iter()
                .any(|g| g.id == gid && g.members.iter().any(|(k, _)| *k == hex(pk)))
        };
        wait_until_srv(Duration::from_secs(5), || on_disk(&b.pk));
        a.send(ctrl::KICK, &payloads::enc_gid_target(gid, &b.pk));
        b.expect(ctrl::KICKED);
        // Не через SAVE_EVERY (3 с), а сразу (≤ URGENT_SAVE_GAP + запас).
        let t0 = Instant::now();
        wait_until_srv(Duration::from_secs(5), || !on_disk(&b.pk));
        assert!(
            t0.elapsed() < Duration::from_millis(1500),
            "кик сохранён за {:?}",
            t0.elapsed()
        );
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Падение сразу после BAN (без сохранения при остановке): с диска не
    /// возвращается ни забаненный участник, ни уже выданный номер эпохи.
    #[test]
    fn бан_и_эпоха_переживают_падение() {
        let (server, dir) = test_server("ban-crash");
        let a = Raw::connect(server.addr, "alpha");
        let gid = a.create("g", false).gid;
        let b = Raw::connect(server.addr, "bravo");
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        b.state();
        let store = persist::Store::new(&dir);
        // «Падение» — загрузка того, что сейчас на диске, без shutdown.
        let crashed = || {
            let c = temp_dir("ban-crash-copy");
            std::fs::create_dir_all(&c).unwrap();
            std::fs::copy(dir.join("server.json"), c.join("server.json")).unwrap();
            let l = load_state(&persist::Store::new(&c)).unwrap();
            let _ = std::fs::remove_dir_all(&c);
            l
        };
        let banned_on_disk = |pk: &[u8; 32]| {
            store
                .load()
                .unwrap()
                .unwrap()
                .groups
                .iter()
                .any(|g| g.id == gid && g.banned.contains(&hex(pk)))
        };
        a.send(ctrl::BAN, &payloads::enc_gid_target(gid, &b.pk));
        b.expect(ctrl::KICKED);
        let t0 = Instant::now();
        wait_until_srv(Duration::from_secs(5), || banned_on_disk(&b.pk));
        assert!(
            t0.elapsed() < Duration::from_millis(1500),
            "бан сохранён за {:?}",
            t0.elapsed()
        );
        let issued = server.shared.state.read().unwrap().groups[&gid].epoch;
        let l = crashed();
        let g = &l.groups[&gid];
        assert!(
            g.banned.contains_key(&b.pk) && !g.members.contains_key(&b.pk),
            "забаненный вернулся"
        );
        assert!(
            g.epoch > issued,
            "эпоха {} повторяет выданную {issued}",
            g.epoch
        );
        // UNBAN — тоже сразу.
        a.send(ctrl::UNBAN, &payloads::enc_gid_target(gid, &b.pk));
        a.expect(ctrl::ADMIN_INFO);
        let t0 = Instant::now();
        wait_until_srv(Duration::from_secs(5), || !banned_on_disk(&b.pk));
        assert!(
            t0.elapsed() < Duration::from_millis(1500),
            "разбан сохранён за {:?}",
            t0.elapsed()
        );
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn wait_until_srv(within: Duration, mut f: impl FnMut() -> bool) {
        let end = Instant::now() + within;
        while !f() {
            assert!(Instant::now() < end, "не дождались за {within:?}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn rotate_key_ждёт_блокировку_записи_сервера() {
        let dir = temp_dir("rotate-lock");
        let server = start_in(&dir, Limits::default());
        save_now(&server.shared);
        // Сервер «пишет» (держит блокировку) — rotate-key ждёт, а не пишет
        // между проверкой ключа и записью сервера.
        let held = server.shared.store.lock().unwrap();
        let d2 = dir.clone();
        let t = thread::spawn(move || rotate_key(&d2).unwrap());
        thread::sleep(Duration::from_millis(300));
        assert!(!t.is_finished(), "rotate-key не ждёт блокировку");
        drop(held);
        let r = t.join().unwrap();
        save_now(&server.shared);
        let k = persist::Store::new(&dir).load_key().unwrap();
        assert_eq!(
            proto::Identity {
                ed_seed: k.ed_seed,
                x_seed: k.x_seed
            }
            .ed_pub(),
            r.pubkey
        );
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hello_v2_и_чужая_версия_получают_unsupported() {
        let (server, dir) = test_server("unsupported");
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        // HELLO v2 настоящего размера (ключи, имя, подпись) — с текстом.
        let v2 = proto::plain_frame(ctrl::HELLO, &[0x55; 140]);
        sock.send_to(&v2, server.addr).unwrap();
        let (body, frame) = recv_plain(&sock, ctrl::UNSUPPORTED, Duration::from_secs(3))
            .expect("UNSUPPORTED на v2");
        let (ver, text) = hs::dec_unsupported(&body).unwrap();
        assert_eq!(ver, proto::PROTOCOL_VERSION);
        assert!(!text.is_empty());
        assert!(frame.len() <= v2.len(), "ответ длиннее запроса");
        // Короткий запрос — UNSUPPORTED без текста (не длиннее запроса),
        // пустой HELLO (7 байт) — без ответа: усиления нет.
        let short = proto::plain_frame(ctrl::HELLO, b"v2 hello body");
        sock.send_to(&short, server.addr).unwrap();
        let (body, frame) = recv_plain(&sock, ctrl::UNSUPPORTED, Duration::from_secs(3))
            .expect("короткий UNSUPPORTED");
        assert_eq!(
            hs::dec_unsupported(&body).unwrap(),
            (proto::PROTOCOL_VERSION, String::new())
        );
        assert!(frame.len() <= short.len());
        sock.send_to(&proto::plain_frame(ctrl::HELLO, b""), server.addr)
            .unwrap();
        assert!(
            recv_plain(&sock, ctrl::UNSUPPORTED, Duration::from_millis(500)).is_none(),
            "ответ на 7 байт"
        );
        // HELLO3 клиента v3 — с текстом; HELLO3 из одного байта версии — без ответа.
        let id = proto::Identity::generate();
        let mut h = Hello3::encode(&id, &[5; 32], "x", 0, None);
        h[0] = 3;
        sock.send_to(&proto::plain_frame(ctrl::HELLO3, &h), server.addr)
            .unwrap();
        let (body, _) = recv_plain(&sock, ctrl::UNSUPPORTED, Duration::from_secs(3)).unwrap();
        assert!(!hs::dec_unsupported(&body).unwrap().1.is_empty());
        sock.send_to(&proto::plain_frame(ctrl::HELLO3, &[3]), server.addr)
            .unwrap();
        assert!(recv_plain(&sock, ctrl::UNSUPPORTED, Duration::from_millis(500)).is_none());
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn карта_лимитера_ip_ограничена_и_не_забывает_исчерпавших() {
        let ip = |i: u32| IpAddr::V4(Ipv4Addr::from(i));
        let mut m = HashMap::new();
        // Медленный лимит: исчерпавшие запас не восполняются за тест.
        let (rate, burst) = (0.001, 2.0);
        for i in 0..8 {
            assert!(ip_take(&mut m, ip(i), rate, burst, 8));
            assert!(ip_take(&mut m, ip(i), rate, burst, 8));
            assert!(!ip_take(&mut m, ip(i), rate, burst, 8));
        }
        // Карта полна исчерпавшими: новому адресу отказ, карта не растёт.
        assert!(!ip_take(&mut m, ip(100), rate, burst, 8));
        assert_eq!(m.len(), 8);
        // Восполнившиеся корзины вытесняются, лимит у исчерпавших остаётся.
        let mut m = HashMap::new();
        let (rate, burst) = (1e9, 2.0);
        for i in 0..8 {
            assert!(ip_take(&mut m, ip(i), rate, burst, 8));
        }
        assert!(
            ip_take(&mut m, ip(100), rate, burst, 8),
            "восполнившиеся — вытеснить"
        );
        assert!(m.len() <= 8);
        // IPv6 из одного /64 — одна запись.
        let mut m = HashMap::new();
        for i in 0..100u128 {
            let a = std::net::Ipv6Addr::from((0x2001_0db8_0001_0002u128 << 64) | i);
            ip_take(&mut m, ip_key(IpAddr::V6(a)), 0.001, 1000.0, 8);
        }
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn лимит_hello_по_ip_покрывает_ответы() {
        let limits = Limits {
            hello_rate: 0.001,
            hello_burst: 3.0,
            ..Limits::default()
        };
        let (server, dir) = test_server_with("hello-limit", limits);
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        for _ in 0..10 {
            sock.send_to(&proto::plain_frame(ctrl::HELLO, &[0; 100]), server.addr)
                .unwrap();
        }
        // ctrl от адреса без сессии — RESET, тоже из того же лимита.
        sock.send_to(
            &proto::seal_ctrl(&[1; 32], 0, ctrl::CTRL_PING, &[]),
            server.addr,
        )
        .unwrap();
        let mut n = 0;
        let mut buf = [0u8; 2048];
        let end = Instant::now() + Duration::from_millis(800);
        while Instant::now() < end {
            if sock.recv_from(&mut buf).is_ok() {
                n += 1;
            }
        }
        assert_eq!(n, 3, "ответов больше запаса лимита");
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn кик_и_бан_ротируют_ключ_с_отзывом_и_присылают_kicked() {
        let (server, dir) = test_server("kick-rotate");
        let srv = server.addr;
        let a = Raw::connect(srv, "alpha");
        let st = a.create("game", false);
        let gid = st.gid;

        let b = Raw::connect(srv, "bravo");
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        let sb = b.state();
        // Вход — ротация без отзыва, rev и epoch +1.
        let u = a.update();
        assert_eq!(
            (u.gid, u.base_rev, u.rev, u.epoch, u.revoke_prev),
            (gid, st.rev, st.rev + 1, st.epoch + 1, false)
        );
        assert_ne!(u.key, st.key);
        assert!(
            matches!(&u.delta, GroupDelta::Member(m) if m.pubkey == b.pk && m.name == "bravo" && m.online)
        );
        assert_eq!((sb.rev, sb.epoch, sb.key), (u.rev, u.epoch, u.key));
        assert_eq!(sb.members.len(), 2);

        let c = Raw::connect(srv, "charlie");
        c.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        let sc = c.state();
        assert_eq!(b.update().rev, sc.rev);
        a.update();

        // KICK: удалённому — KICKED, остальным — kind 2 + ротация с отзывом.
        a.send(ctrl::KICK, &payloads::enc_gid_target(gid, &b.pk));
        let k = payloads::dec_kicked(&b.expect(ctrl::KICKED)).unwrap();
        assert_eq!(
            (k.gid, k.group_name.as_str(), k.banned),
            (gid, "game", false)
        );
        let u = c.update();
        assert_eq!(
            (u.base_rev, u.rev, u.epoch, u.revoke_prev),
            (sc.rev, sc.rev + 1, sc.epoch + 1, true)
        );
        assert_eq!(k.rev, u.rev, "KICKED несёт ревизию после кика");
        assert_ne!(u.key, sc.key);
        assert_eq!(u.delta, GroupDelta::Removed(b.pk));
        assert_eq!(a.update().key, u.key);

        // BAN участника: то же, KICKED с banned, вход закрыт.
        a.send(ctrl::BAN, &payloads::enc_gid_target(gid, &c.pk));
        let k = payloads::dec_kicked(&c.expect(ctrl::KICKED)).unwrap();
        assert!(k.banned);
        let u2 = a.update();
        assert_eq!(
            (u2.rev, u2.epoch, u2.revoke_prev),
            (u.rev + 1, u.epoch + 1, true)
        );
        assert_eq!(u2.delta, GroupDelta::Removed(c.pk));
        c.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        assert!(c.error().contains("забанены"));
        // Кикнутый может войти снова (группа публичная) — снова ротация.
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        assert_eq!(b.state().epoch, u2.epoch + 1);
        // LEAVE — тоже с отзывом.
        b.send(ctrl::LEAVE_GROUP, &payloads::enc_gid(gid));
        a.update(); // вход B
        let u3 = a.update();
        assert!(u3.revoke_prev && u3.delta == GroupDelta::Removed(b.pk));

        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hello_участника_ротирует_ключ_и_шлёт_ему_состояние() {
        let (server, dir) = test_server("hello-rotate");
        let srv = server.addr;
        let a = Raw::connect(srv, "alpha");
        let st = a.create("game", false);
        let b_id = proto::Identity::generate();
        let b = Raw::connect_as(srv, "bravo", &b_id);
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(st.gid));
        let sb = b.state();
        a.update();
        // Переподключение B (новый адрес): ему GROUP_STATE с новым ключом,
        // A — дельта kind 1 с новым endpoint.
        let b2 = Raw::connect_as(srv, "bravo2", &b_id);
        let s2 = b2.state();
        assert_eq!((s2.rev, s2.epoch), (sb.rev + 1, sb.epoch + 1));
        let u = a.update();
        assert_eq!(
            (u.rev, u.epoch, u.key, u.revoke_prev),
            (s2.rev, s2.epoch, s2.key, false)
        );
        match &u.delta {
            GroupDelta::Member(m) => {
                assert_eq!(m.name, "bravo2");
                assert_eq!(m.endpoint, Some(b2.sock.local_addr().unwrap()));
            }
            d => panic!("{d:?}"),
        }
        // Старый адрес B больше не сессия — RESET.
        b.send(ctrl::CTRL_PING, &[]);
        assert!(recv_plain(&b.sock, ctrl::RESET, Duration::from_secs(3)).is_some());
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invisible_кандидаты_и_presence() {
        let (server, dir) = test_server("presence");
        let srv = server.addr;
        let a = Raw::connect(srv, "alpha");
        let st = a.create("game", false);
        let b = Raw::connect_with(
            srv,
            "bravo",
            &proto::Identity::generate(),
            hs::HELLO_FLAG_INVISIBLE,
        );
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(st.gid));
        let sb = b.state();
        // Себе invisible виден онлайн, другим — офлайн без адресов.
        let me = sb.members.iter().find(|m| m.pubkey == b.pk).unwrap();
        assert!(me.online && me.endpoint.is_some());
        let GroupDelta::Member(m) = a.update().delta else {
            panic!()
        };
        assert!(!m.online && m.endpoint.is_none() && m.candidates.is_empty());

        let cand: SocketAddr = "10.0.0.5:4000".parse().unwrap();
        b.send(ctrl::CANDIDATES, &payloads::enc_candidates(&[cand]));
        let GroupDelta::Member(m) = a.update().delta else {
            panic!()
        };
        assert!(m.candidates.is_empty(), "кандидаты invisible видны");
        // Сам B тоже получает дельту — его ревизия не отстаёт.
        let ub = b.update();
        assert_eq!(ub.base_rev, sb.rev);

        // Повтор того же значения — без дельты, но с подтверждением.
        b.send(ctrl::PRESENCE, &payloads::enc_presence(true));
        assert!(payloads::dec_presence(&b.expect(ctrl::PRESENCE_ACK)).unwrap());
        assert!(
            !a.sync().contains(&ctrl::GROUP_UPDATE),
            "повтор PRESENCE — не изменение"
        );
        b.send(ctrl::PRESENCE, &payloads::enc_presence(false));
        assert!(!payloads::dec_presence(&b.expect(ctrl::PRESENCE_ACK)).unwrap());
        let GroupDelta::Member(m) = a.update().delta else {
            panic!()
        };
        assert!(m.online);
        assert_eq!(m.endpoint, Some(b.sock.local_addr().unwrap()));
        assert_eq!(m.candidates, vec![cand]);

        // n > 4 — фрейм отбрасывается молча; тот же список — без дельты.
        let mut five = vec![5u8];
        for i in 0..5 {
            proto::put_str(&mut five, &format!("10.0.0.{i}:1"));
        }
        a.send(ctrl::CANDIDATES, &five);
        let seen = a.sync();
        assert!(
            !seen.contains(&ctrl::ERROR) && !seen.contains(&ctrl::GROUP_UPDATE),
            "{seen:02x?}"
        );
        b.send(ctrl::CANDIDATES, &payloads::enc_candidates(&[cand]));
        b.sync();
        assert!(!a.sync().contains(&ctrl::GROUP_UPDATE));
        // GROUP_LIST: rev/epoch своей группы.
        a.send(ctrl::LIST_GROUPS, &[]);
        let list = payloads::dec_group_list(&a.expect(ctrl::GROUP_LIST)).unwrap();
        let g = list.iter().find(|g| g.gid == st.gid).unwrap();
        let s = server.shared.state.read().unwrap();
        assert_eq!(
            (g.rev, g.epoch, g.online, g.total),
            (s.groups[&st.gid].rev, s.groups[&st.gid].epoch, 2, 2)
        );
        drop(s);
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unban_admin_info_и_передача_владения() {
        let (server, dir) = test_server("admin");
        let srv = server.addr;
        let a = Raw::connect(srv, "alpha");
        let gid = a.create("secret", true).gid;
        let b = Raw::connect(srv, "bravo");
        let c = Raw::connect(srv, "charlie");
        a.send(ctrl::INVITE, &payloads::enc_gid_target(gid, &b.pk));
        let inv = payloads::dec_invite(&b.expect(ctrl::INVITE_RCVD)).unwrap();
        assert!(
            inv.expires_in > 6 * 24 * 3600 && inv.expires_in <= 7 * 24 * 3600,
            "{}",
            inv.expires_in
        );
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        b.state();
        a.send(ctrl::INVITE, &payloads::enc_gid_target(gid, &c.pk));
        c.expect(ctrl::INVITE_RCVD);
        let d = proto::Identity::generate().ed_pub();
        a.send(ctrl::BAN, &payloads::enc_gid_target(gid, &b.pk));
        a.send(ctrl::BAN, &payloads::enc_gid_target(gid, &d));

        a.send(ctrl::GROUP_ADMIN, &payloads::enc_gid(gid));
        let info = payloads::dec_admin_info(&a.expect(ctrl::ADMIN_INFO)).unwrap();
        assert_eq!(info.gid, gid);
        let bans: Vec<_> = info
            .bans
            .iter()
            .map(|x| (x.pubkey, x.name.as_str()))
            .collect();
        assert_eq!(bans, vec![(d, ""), (b.pk, "bravo")]);
        assert_eq!(info.invites.len(), 1);
        assert_eq!(
            (info.invites[0].pubkey, info.invites[0].name.as_str()),
            (c.pk, "charlie")
        );
        assert!(info.invites[0].expires_in > 6 * 24 * 3600);
        // Не владельцу — ошибка.
        c.send(ctrl::GROUP_ADMIN, &payloads::enc_gid(gid));
        assert!(c.error().contains("владелец"));

        // UNBAN — идемпотентно, ответ — свежий ADMIN_INFO.
        a.send(ctrl::UNBAN, &payloads::enc_gid_target(gid, &b.pk));
        let info = payloads::dec_admin_info(&a.expect(ctrl::ADMIN_INFO)).unwrap();
        assert_eq!(
            info.bans.iter().map(|x| x.pubkey).collect::<Vec<_>>(),
            vec![d]
        );
        a.send(ctrl::UNBAN, &payloads::enc_gid_target(gid, &b.pk));
        a.expect(ctrl::ADMIN_INFO);
        // Разбаненный снова входит по приглашению.
        a.send(ctrl::INVITE, &payloads::enc_gid_target(gid, &b.pk));
        b.expect(ctrl::INVITE_RCVD);
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        let sb = b.state();

        // Передача не участнику — ошибка; участнику — kind 3 всем.
        a.send(ctrl::TRANSFER_OWNER, &payloads::enc_gid_target(gid, &c.pk));
        assert!(a.error().contains("участник"));
        b.send(ctrl::TRANSFER_OWNER, &payloads::enc_gid_target(gid, &b.pk));
        assert!(b.error().contains("владелец"));
        a.send(ctrl::TRANSFER_OWNER, &payloads::enc_gid_target(gid, &b.pk));
        let u = b.update();
        assert_eq!(u.base_rev, sb.rev);
        assert_eq!(
            u.delta,
            GroupDelta::Meta {
                name: "secret".into(),
                owner: b.pk,
                private: true
            }
        );
        a.send(ctrl::GROUP_ADMIN, &payloads::enc_gid(gid));
        assert!(a.error().contains("владелец"));
        b.send(ctrl::GROUP_ADMIN, &payloads::enc_gid(gid));
        b.expect(ctrl::ADMIN_INFO);
        // Приглашения теперь от нового владельца.
        c.send(ctrl::LIST_INVITES, &payloads::enc_u32(0));
        let l = payloads::dec_invite_list(&c.expect(ctrl::INVITE_LIST)).unwrap();
        assert_eq!(
            (l.items[0].from_pubkey, l.items[0].from_name.as_str()),
            (b.pk, "bravo")
        );

        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn лимит_групп_во_владении() {
        let limits = Limits {
            max_owned_groups: 2,
            ..Limits::default()
        };
        let (server, dir) = test_server_with("owned", limits);
        let a = Raw::connect(server.addr, "alpha");
        let g1 = a.create("one", false).gid;
        a.create("two", false);
        a.send(
            ctrl::CREATE_GROUP,
            &payloads::enc_create_group("three", false),
        );
        assert!(a.error().contains("лимит групп"));
        // Передача тому, у кого лимит исчерпан, — тоже отказ.
        let b = Raw::connect(server.addr, "bravo");
        b.create("b1", false);
        b.create("b2", false);
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(g1));
        b.state();
        a.send(ctrl::TRANSFER_OWNER, &payloads::enc_gid_target(g1, &b.pk));
        assert!(a.error().contains("лимит групп"));
        // Удалил — можно снова.
        a.send(ctrl::DELETE_GROUP, &payloads::enc_gid(g1));
        a.create("three", false);
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn приглашение_истекает() {
        let limits = Limits {
            invite_ttl: Duration::from_secs(1),
            ..Limits::default()
        };
        let (server, dir) = test_server_with("invite-ttl", limits);
        let srv = server.addr;
        let a = Raw::connect(srv, "alpha");
        let gid = a.create("secret", true).gid;
        let b = Raw::connect(srv, "bravo");
        b.expect(ctrl::INVITE_LIST);
        a.send(ctrl::INVITE, &payloads::enc_gid_target(gid, &b.pk));
        let inv = payloads::dec_invite(&b.expect(ctrl::INVITE_RCVD)).unwrap();
        assert_eq!(inv.expires_in, 1);
        // Housekeeping снимает истёкшее и присылает приглашённому окно без него.
        let l = payloads::dec_invite_list(&b.expect(ctrl::INVITE_LIST)).unwrap();
        assert!(l.covers(gid) && l.items.is_empty(), "{l:?}");
        assert!(
            server.shared.state.read().unwrap().groups[&gid]
                .invites
                .is_empty()
        );
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        assert!(b.error().contains("приглашение"));
        a.send(ctrl::GROUP_ADMIN, &payloads::enc_gid(gid));
        assert!(
            payloads::dec_admin_info(&a.expect(ctrl::ADMIN_INFO))
                .unwrap()
                .invites
                .is_empty()
        );

        // Списки пропускают истёкшее и до housekeeping.
        {
            let mut s = server.shared.state.write().unwrap();
            let inv = Invite {
                created_ms: unix_ms() - 5_000,
                name: String::new(),
            };
            s.groups.get_mut(&gid).unwrap().invites.insert(b.pk, inv);
        }
        b.send(ctrl::LIST_INVITES, &payloads::enc_u32(0));
        assert!(
            payloads::dec_invite_list(&b.expect(ctrl::INVITE_LIST))
                .unwrap()
                .items
                .is_empty()
        );
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Строка ровно 255 байт кириллицей (худший случай `str`).
    fn long_text(tag: char) -> String {
        let mut s = "я".repeat(127);
        s.push(tag);
        assert_eq!(s.len(), 255);
        s
    }

    #[test]
    fn группа_253_участника_с_длинными_полями_приходит_через_frag() {
        let (server, dir) = test_server("frag253");
        let a = Raw::connect(server.addr, "alpha");
        let st = a.create("big", false);
        let gid = st.gid;
        // 252 участника с именем и статусом по 255 байт, онлайн с IPv6
        // endpoint и четырьмя IPv6-кандидатами — пишутся прямо в состояние.
        {
            let mut s = server.shared.state.write().unwrap();
            for i in 0..252u16 {
                let mut pk = [0u8; 32];
                pk[..2].copy_from_slice(&i.to_be_bytes());
                pk[31] = 0xEE;
                let v6 = |j: u16| -> SocketAddr {
                    format!("[2001:db8:ffff:ffff:ffff:ffff:{i:04x}:{j:04x}]:65535")
                        .parse()
                        .unwrap()
                };
                let addr = v6(0xffff);
                let ip = s.ip_for(pk).unwrap();
                let g = s.groups.get_mut(&gid).unwrap();
                g.insert_member(
                    pk,
                    Member {
                        ip,
                        name: long_text('n'),
                        status: long_text('s'),
                    },
                );
                s.sessions.insert(
                    addr,
                    Session {
                        ed_pub: pk,
                        eph_pub: [0; 32],
                        name: long_text('n'),
                        status: long_text('s'),
                        keys: proto::DirKeys {
                            tx: [1; 32],
                            rx: [2; 32],
                        },
                        welcome: Vec::new(),
                        welcome_at: AtomicU64::new(0),
                        tx: AtomicU64::new(0),
                        msg_id: AtomicU32::new(0),
                        rx: Mutex::new(proto::ReplayWindow::new()),
                        invisible: false,
                        candidates: (0..4).map(v6).collect(),
                        last_seen: AtomicU64::new(u64::MAX / 2),
                        relay: Mutex::new(Bucket::new(1.0)),
                        ctrl: Mutex::new(Bucket::new(1.0)),
                    },
                );
                s.by_pub.insert(pk, addr);
            }
            assert_eq!(s.groups[&gid].members.len(), 253);
        }
        a.send(ctrl::GET_GROUP, &payloads::enc_gid(gid));
        let raw = a.expect(ctrl::GROUP_STATE);
        assert!(
            raw.len() > 150 * proto::FRAG_THRESHOLD,
            "{} байт",
            raw.len()
        );
        assert!(raw.len() <= proto::FRAG_MAX_PAYLOAD);
        let expected = {
            let s = server.shared.state.read().unwrap();
            pl::enc_group_state(&group_state(&s, &s.groups[&gid], &a.pk))
        };
        assert_eq!(raw, expected, "GROUP_STATE собран без потерь");
        let got = payloads::dec_group_state(&raw).unwrap();
        assert_eq!(got.members.len(), 253);
        let fake = got.members.iter().find(|m| m.pubkey[31] == 0xEE).unwrap();
        assert_eq!(
            (fake.name.len(), fake.status.len(), fake.candidates.len()),
            (255, 255, 4)
        );
        assert!(fake.endpoint.is_some_and(|e| e.is_ipv6()));
        // Не участнику — ошибка, несуществующая группа — «удалена».
        let b = Raw::connect(server.addr, "bravo");
        b.send(ctrl::GET_GROUP, &payloads::enc_gid(gid));
        assert!(b.error().contains("не участник"));
        b.send(ctrl::GET_GROUP, &payloads::enc_gid(200));
        let d = b.state();
        assert!(d.deleted && d.gid == 200);
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ротация_ключа_сервера_принимается_клиентом() {
        let dir = temp_dir("rotate");
        assert!(
            rotate_key(&dir).is_err(),
            "без server.json ротировать нечего"
        );
        let server = start_in(&dir, Limits::default());
        let a = Raw::connect(server.addr, "alpha");
        let gid = a.create("keep", false).gid;
        assert!(a.welcome.links.is_empty());
        let k0 = server.pubkey;
        server.stop();

        let r1 = rotate_key(&dir).unwrap();
        let r2 = rotate_key(&dir).unwrap();
        assert_eq!(r2.links, 2);
        assert_eq!(r1.old_code, proto::friend_code_of(&k0));
        let server = start_in(&dir, Limits::default());
        assert_eq!(server.pubkey, r2.pubkey);
        assert_eq!(server.code, r2.code);
        assert!(
            server
                .shared
                .state
                .read()
                .unwrap()
                .groups
                .contains_key(&gid),
            "группы на месте"
        );

        let b = Raw::connect(server.addr, "bravo");
        let w = &b.welcome;
        assert_eq!(w.server_ed, r2.pubkey);
        assert_eq!(w.links.len(), 2);
        let rotated = hs::PinResolution::Rotated { new_ed: r2.pubkey };
        assert_eq!(
            proto::resolve_pin(&k0, w).unwrap(),
            rotated,
            "пин самого старого ключа"
        );
        assert_eq!(
            proto::resolve_pin(&r1.pubkey, w).unwrap(),
            rotated,
            "пин промежуточного"
        );
        assert_eq!(
            proto::resolve_pin(&r2.pubkey, w).unwrap(),
            hs::PinResolution::Same
        );
        assert!(proto::resolve_pin(&proto::Identity::generate().ed_pub(), w).is_err());
        b.sync();

        // WELCOME несёт не больше 8 последних звеньев.
        server.stop();
        for _ in 0..8 {
            rotate_key(&dir).unwrap();
        }
        let server = start_in(&dir, Limits::default());
        let c = Raw::connect(server.addr, "charlie");
        assert_eq!(c.welcome.links.len(), hs::MAX_LINKS);
        assert!(
            proto::resolve_pin(&k0, &c.welcome).is_err(),
            "звено старого ключа уже не в WELCOME"
        );
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotate_key_при_запущенном_сервере_не_теряется() {
        let dir = temp_dir("rotate-live");
        let server = start_in(&dir, Limits::default());
        let a = Raw::connect(server.addr, "alpha");
        let before = a.create("before", false).gid;
        save_now(&server.shared);
        rotate_key(&dir).unwrap();
        // Сервер дорабатывает со старым ключом, состояние меняется дальше;
        // периодическое сохранение (то же, что в housekeeping) ключ не
        // затирает, и вторая ротация продолжает первую.
        let after = a.create("after", false).gid;
        a.sync();
        save_now(&server.shared);
        let r = rotate_key(&dir).unwrap();
        save_now(&server.shared);
        let on_disk = persist::Store::new(&dir).load_key().unwrap();
        let disk_id = proto::Identity {
            ed_seed: on_disk.ed_seed,
            x_seed: on_disk.x_seed,
        };
        assert_eq!(disk_id.ed_pub(), r.pubkey, "ротация затёрта сохранением");
        assert_eq!(on_disk.rotations.len(), 2);
        server.stop();
        let server = start_in(&dir, Limits::default());
        assert_eq!(server.pubkey, r.pubkey, "после перезапуска — новый ключ");
        {
            let s = server.shared.state.read().unwrap();
            assert!(
                s.groups.contains_key(&before) && s.groups.contains_key(&after),
                "группы потеряны"
            );
        }
        let b = Raw::connect(server.addr, "bravo");
        assert_eq!(b.welcome.links.len(), 2);
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotate_key_не_затирается_финальным_сохранением_при_остановке() {
        let dir = temp_dir("rotate-stop");
        let server = start_in(&dir, Limits::default());
        let a = Raw::connect(server.addr, "alpha");
        let gid = a.create("g", false).gid;
        save_now(&server.shared);
        let r = rotate_key(&dir).unwrap();
        // После ротации состояние меняется (dirty), затем — остановка: её
        // сохранение должно сохранить и новые группы, и новый ключ.
        let gid2 = a.create("g2", false).gid;
        a.sync();
        server.stop();
        let k = persist::Store::new(&dir).load_key().unwrap();
        assert_eq!(
            proto::Identity {
                ed_seed: k.ed_seed,
                x_seed: k.x_seed
            }
            .ed_pub(),
            r.pubkey,
            "ключ затёрт при остановке"
        );
        assert_eq!(k.rotations.len(), 1);
        let server = start_in(&dir, Limits::default());
        assert_eq!(server.pubkey, r.pubkey);
        {
            let s = server.shared.state.read().unwrap();
            assert!(
                s.groups.contains_key(&gid) && s.groups.contains_key(&gid2),
                "группы потеряны"
            );
        }
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn релей_под_нагрузкой() {
        const N: usize = 20_000;
        /// Фреймов «в полёте» одновременно: окно помещается в буфер приёма
        /// любой ОС, иначе тест измеряет размер буфера, а не релей.
        const WINDOW: u64 = 200;
        /// Бюджет на весь прогон: раннеры разные по скорости, важно лишь,
        /// что релей не встал.
        const BUDGET: Duration = Duration::from_secs(30);
        let limits = Limits {
            relay_rate: 1e7,
            relay_burst: 1e7,
            ..Limits::default()
        };
        let dir = temp_dir("load");
        let server = start_workers(&dir, limits, 4);
        let srv = server.addr;
        let a = Raw::connect(srv, "alpha");
        let st = a.create("load", false);
        let b = Raw::connect(srv, "bravo");
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(st.gid));
        let sb = b.state();
        let ip_a = st.my_ip;
        let frame = frame_for(&sb, ip_a, sb.my_ip, &[0x55; 64]);

        let got = Arc::new(AtomicU64::new(0));
        let rsock = b.sock.try_clone().unwrap();
        let counter = got.clone();
        let done = Arc::new(AtomicBool::new(false));
        let stop = done.clone();
        let reader = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let mut idle = Instant::now();
            // Читатель живёт, пока отправитель не закончил и поток не замолчал:
            // иначе пауза в релее обрывает подсчёт и тест считает потери там,
            // где их нет.
            while !(stop.load(Ordering::Relaxed) && idle.elapsed() > Duration::from_millis(700)) {
                if let Ok((n, _)) = rsock.recv_from(&mut buf)
                    && proto::split_frame(&buf[..n]).is_ok_and(|(t, _)| proto::grp::is_group(t))
                {
                    counter.fetch_add(1, Ordering::Relaxed);
                    idle = Instant::now();
                }
            }
        });
        let t0 = Instant::now();
        // Окно «в полёте» ≤ WINDOW фреймов: проверяется пропускная способность
        // релея, а не размер буферов сокетов. Окно узкое — датаграммы в
        // полёте помещаются в буфер приёма любой ОС (на Windows он 64 КБ),
        // иначе часть фреймов теряется на стороне получателя.
        for i in 0..N {
            while i as u64 > got.load(Ordering::Relaxed) + WINDOW && t0.elapsed() < BUDGET {
                thread::yield_now();
            }
            a.sock.send_to(&frame, srv).unwrap();
        }
        while (got.load(Ordering::Relaxed) as usize) < N && t0.elapsed() < BUDGET {
            thread::yield_now();
        }
        done.store(true, Ordering::Relaxed);
        let elapsed = t0.elapsed();
        reader.join().unwrap();
        let received = got.load(Ordering::Relaxed) as usize;
        let relayed = server.shared.relayed.load(Ordering::Relaxed) as usize;
        assert!(received >= N * 99 / 100, "дошло {received} из {N}");
        assert!(relayed >= received, "relayed {relayed} < {received}");
        // Время — не бенчмарк: скорость задаёт раннер (ubuntu-раннер тянет
        // эти 20 000 датаграмм около 6 с, macOS — вдвое быстрее). Проверяем,
        // что релей не встал, а не что он быстрый.
        assert!(elapsed < BUDGET, "{N} фреймов за {elapsed:?}");
        // Сервер жив.
        a.sync();
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn server_json_v2_загружается() {
        let dir = temp_dir("v2json");
        std::fs::create_dir_all(&dir).unwrap();
        let id = proto::Identity {
            ed_seed: [1; 32],
            x_seed: [2; 32],
        };
        let (owner, member, banned, invited) = ([9u8; 32], [1u8; 32], [2u8; 32], [3u8; 32]);
        let arr = |b: [u8; 32]| serde_json::to_string(&b).unwrap();
        let ip = u32::from(Ipv4Addr::new(100, 66, 5, 2));
        // Ровно так писал server.json сервер v2.
        let json = format!(
            r#"{{"ed_seed":{},"x_seed":{},"next_gid":6,"groups":[{{"id":5,"name":"old","owner":"{}",
            "private":true,"key":{},"members":[["{}",{ip}],["{}",{}]],"banned":["{}"],"invites":["{}","{}"]}}]}}"#,
            arr(id.ed_seed),
            arr(id.x_seed),
            hex(&owner),
            arr([7; 32]),
            hex(&owner),
            hex(&member),
            ip + 1,
            hex(&banned),
            hex(&invited),
            hex(&member),
        );
        std::fs::write(dir.join("server.json"), json).unwrap();
        let store = persist::Store::new(&dir);
        let before = unix_ms();
        let l = load_state(&store).unwrap();
        assert!(l.links.is_empty());
        assert_eq!(l.identity.ed_pub(), id.ed_pub());
        let g = &l.groups[&5];
        assert_eq!(
            (g.epoch, g.rev, g.key, g.private),
            (1 + LOAD_MARGIN, 1 + LOAD_MARGIN, [7; 32], true)
        );
        assert_eq!(g.members[&member].name, "…");
        assert_eq!(g.banned.keys().collect::<Vec<_>>(), vec![&banned]);
        // Приглашение участнику (данные старого сервера) — снято; срок
        // оставшегося — с момента загрузки.
        assert_eq!(g.invites.keys().collect::<Vec<_>>(), vec![&invited]);
        assert!(g.invites[&invited].created_ms >= before);
        // И сервер стартует на таком файле с той же identity.
        let server = start_in(&dir, Limits::default());
        assert_eq!(server.pubkey, id.ed_pub());
        server.stop();
        let l = load_state(&store).unwrap();
        assert_eq!(l.groups[&5].members[&member].name, "…");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn отказ_снимает_приглашение_и_уведомляет_владельца() {
        let (server, dir) = test_server("decline");
        let srv = server.addr;
        let a = Raw::connect(srv, "alpha");
        let gid = a.create("secret", true).gid;

        // Пригласить участника (себя) — ошибка, окна приглашения не будет.
        a.send(ctrl::INVITE, &payloads::enc_gid_target(gid, &a.pk));
        let err = a.error();
        assert!(err.contains("участник"), "{err}");

        let b = Raw::connect(srv, "bravo");
        a.send(ctrl::INVITE, &payloads::enc_gid_target(gid, &b.pk));
        let inv = payloads::dec_invite(&b.expect(ctrl::INVITE_RCVD)).unwrap();
        assert_eq!(
            (inv.gid, inv.from_pubkey, inv.from_name.as_str()),
            (gid, a.pk, "alpha")
        );

        // Отказ: владелец получает уведомление, приглашение снято.
        b.send(ctrl::DECLINE_INVITE, &payloads::enc_gid(gid));
        let d = payloads::dec_invite_declined(&a.expect(ctrl::INVITE_DECLINED)).unwrap();
        assert_eq!(
            (
                d.gid,
                d.group_name.as_str(),
                d.by_pubkey,
                d.by_name.as_str()
            ),
            (gid, "secret", b.pk, "bravo")
        );
        assert!(
            !server.shared.state.read().unwrap().groups[&gid]
                .invites
                .contains_key(&b.pk)
        );

        // Войти в приватную группу после отказа нельзя.
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        let err = b.error();
        assert!(err.contains("приглашение"), "{err}");

        // Повторный отказ и отказ в несуществующую группу — без ошибки и
        // без повторного уведомления владельцу.
        b.send(ctrl::DECLINE_INVITE, &payloads::enc_gid(gid));
        b.send(ctrl::DECLINE_INVITE, &payloads::enc_gid(250));
        let seen = b.sync();
        assert!(
            !seen.contains(&ctrl::ERROR),
            "ошибка на повторный отказ: {seen:02x?}"
        );
        let seen = a.sync();
        assert!(
            !seen.contains(&ctrl::INVITE_DECLINED),
            "повторное уведомление: {seen:02x?}"
        );

        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn приглашение_офлайн_цели_доставляется_после_hello() {
        let (server, dir) = test_server("pending");
        let srv = server.addr;
        let a = Raw::connect(srv, "alpha");
        let gid = a.create("secret", true).gid;

        // B офлайн: приглашение принимается без ошибки и ждёт на сервере.
        let b_id = proto::Identity::generate();
        a.send(ctrl::INVITE, &payloads::enc_gid_target(gid, &b_id.ed_pub()));
        let seen = a.sync();
        assert!(!seen.contains(&ctrl::ERROR), "{seen:02x?}");

        // B подключается — получает приглашение сразу после HELLO3, одним
        // полным списком.
        let b = Raw::connect_as(srv, "bravo", &b_id);
        let payloads::InviteList {
            items: list,
            complete,
            ..
        } = payloads::dec_invite_list(&b.expect(ctrl::INVITE_LIST)).unwrap();
        assert!(complete);
        assert_eq!(list.len(), 1);
        let inv = &list[0];
        assert_eq!((inv.gid, inv.group_name.as_str()), (gid, "secret"));
        assert_eq!((inv.from_pubkey, inv.from_name.as_str()), (a.pk, "alpha"));
        assert!(inv.expires_in > 6 * 24 * 3600);

        // Переподключение (новый адрес) — то же приглашение снова.
        let b = Raw::connect_as(srv, "bravo", &b_id);
        let payloads::InviteList { items: list, .. } =
            payloads::dec_invite_list(&b.expect(ctrl::INVITE_LIST)).unwrap();
        assert_eq!(list.iter().map(|i| i.gid).collect::<Vec<_>>(), vec![gid]);

        // Вход тратит приглашение: после следующего HELLO3 список пуст.
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        assert_eq!(b.state().gid, gid);
        let b = Raw::connect_as(srv, "bravo", &b_id);
        let payloads::InviteList {
            items: list,
            complete,
            ..
        } = payloads::dec_invite_list(&b.expect(ctrl::INVITE_LIST)).unwrap();
        assert!(
            complete && list.is_empty(),
            "приглашение участнику: {list:?}"
        );
        let seen = b.sync();
        assert!(
            !seen.contains(&ctrl::INVITE_RCVD),
            "приглашение участнику: {seen:02x?}"
        );

        // Удаление группы — приглашённые онлайн узнают об этом.
        let gid2 = a.create("other", true).gid;
        let c = Raw::connect(srv, "charlie");
        a.send(ctrl::INVITE, &payloads::enc_gid_target(gid2, &c.pk));
        c.expect(ctrl::INVITE_RCVD);
        a.send(ctrl::DELETE_GROUP, &payloads::enc_gid(gid2));
        let st = c.state();
        assert!(st.deleted && st.gid == gid2);

        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn бан_и_кик_отзывают_приглашение_у_онлайн_цели() {
        let (server, dir) = test_server("revoke");
        let srv = server.addr;
        let a = Raw::connect(srv, "alpha");
        let gid = a.create("secret", true).gid;
        let gid2 = a.create("other", true).gid;

        let c = Raw::connect(srv, "charlie");
        c.expect(ctrl::INVITE_LIST);
        for g in [gid, gid2] {
            a.send(ctrl::INVITE, &payloads::enc_gid_target(g, &c.pk));
            c.expect(ctrl::INVITE_RCVD);
        }
        // BAN приглашённого (не участника): ему — полный список без gid.
        a.send(ctrl::BAN, &payloads::enc_gid_target(gid, &c.pk));
        let payloads::InviteList {
            items: list,
            complete,
            ..
        } = payloads::dec_invite_list(&c.expect(ctrl::INVITE_LIST)).unwrap();
        assert!(complete);
        assert_eq!(list.iter().map(|i| i.gid).collect::<Vec<_>>(), vec![gid2]);
        // Не участнику KICKED не приходит.
        assert!(!c.sync().contains(&ctrl::KICKED));
        // KICK приглашённого — отзыв приглашения, тоже с уведомлением.
        a.send(ctrl::KICK, &payloads::enc_gid_target(gid2, &c.pk));
        let payloads::InviteList {
            items: list,
            complete,
            ..
        } = payloads::dec_invite_list(&c.expect(ctrl::INVITE_LIST)).unwrap();
        assert!(complete && list.is_empty(), "{list:?}");
        assert!(
            !server.shared.state.read().unwrap().groups[&gid2]
                .invites
                .contains_key(&c.pk)
        );

        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Владелец A создаёт `n` приватных групп и приглашает офлайн-identity;
    /// возвращает отсортированные gid.
    fn many_invites(a: &Raw, n: usize, target: &[u8; 32]) -> Vec<u32> {
        let mut gids = Vec::new();
        for i in 0..n {
            gids.push(a.create(&format!("g{i}"), true).gid);
        }
        gids.sort();
        for g in &gids {
            a.send(ctrl::INVITE, &payloads::enc_gid_target(*g, target));
        }
        let seen = a.sync();
        assert!(!seen.contains(&ctrl::ERROR), "{seen:02x?}");
        gids
    }

    /// (from, gid-ы окна, complete) из INVITE_LIST.
    fn window(p: Vec<u8>) -> (u32, Vec<u32>, bool) {
        let l = payloads::dec_invite_list(&p).unwrap();
        (l.from, l.items.iter().map(|i| i.gid).collect(), l.complete)
    }

    /// Сервер, где одна identity может владеть многими группами.
    fn many_groups_server(tag: &str) -> (Server, PathBuf) {
        test_server_with(
            tag,
            Limits {
                max_owned_groups: 64,
                ..Limits::default()
            },
        )
    }

    #[test]
    fn больше_16_приглашений_приходят_окнами_не_больше_16() {
        let (server, dir) = many_groups_server("many");
        let srv = server.addr;
        let a = Raw::connect(srv, "alpha");
        let b_id = proto::Identity::generate();
        let gids = many_invites(&a, 20, &b_id.ed_pub());

        // После HELLO3 — первые 16 по gid, окно неполное.
        let b = Raw::connect_as(srv, "bravo", &b_id);
        assert_eq!(
            window(b.expect(ctrl::INVITE_LIST)),
            (0, gids[..16].to_vec(), false)
        );
        // LIST_INVITES дочитывает следующее окно, ничего не меняя.
        let next = gids[15] + 1;
        b.send(ctrl::LIST_INVITES, &payloads::enc_u32(next));
        assert_eq!(
            window(b.expect(ctrl::INVITE_LIST)),
            (next, gids[16..].to_vec(), true)
        );
        assert!(
            server.shared.state.read().unwrap().groups[&gids[16]]
                .invites
                .contains_key(&b.pk)
        );
        // Отказ — в ответ окно с начала, тоже не больше 16: видно 17-е.
        b.send(ctrl::DECLINE_INVITE, &payloads::enc_gid(gids[0]));
        assert_eq!(
            window(b.expect(ctrl::INVITE_LIST)),
            (0, gids[1..17].to_vec(), false)
        );
        // Вход по приглашению — тоже.
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gids[1]));
        assert_eq!(
            window(b.expect(ctrl::INVITE_LIST)),
            (0, gids[2..18].to_vec(), false)
        );
        // BAN по последнему gid: окно с него самого (первое его не покрыло
        // бы) — отозванное приглашение попадает в сверку клиента.
        a.send(ctrl::BAN, &payloads::enc_gid_target(gids[19], &b.pk));
        assert_eq!(
            window(b.expect(ctrl::INVITE_LIST)),
            (gids[19], vec![], true)
        );
        // Отказ от gid без приглашения дальше первого окна — окно с него:
        // CLI видит, что приглашения не было.
        b.send(ctrl::DECLINE_INVITE, &payloads::enc_gid(gids[19]));
        assert_eq!(
            window(b.expect(ctrl::INVITE_LIST)),
            (gids[19], vec![], true)
        );

        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn вход_после_удаления_группы_показывает_17_е_приглашение() {
        let (server, dir) = many_groups_server("many-del");
        let srv = server.addr;
        let a = Raw::connect(srv, "alpha");
        let b_id = proto::Identity::generate();
        let gids = many_invites(&a, 17, &b_id.ed_pub());

        let b = Raw::connect_as(srv, "bravo", &b_id);
        assert_eq!(
            window(b.expect(ctrl::INVITE_LIST)),
            (0, gids[..16].to_vec(), false)
        );
        // Группу из окна удалили: неотвеченных стало 16, списка не было.
        a.send(ctrl::DELETE_GROUP, &payloads::enc_gid(gids[1]));
        assert!(b.state().deleted);
        // Вход тратит приглашение — список приходит, хотя неотвеченных
        // меньше 16, и в нём 17-е.
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gids[0]));
        assert_eq!(
            window(b.expect(ctrl::INVITE_LIST)),
            (0, gids[2..].to_vec(), true)
        );
        // Повторный JOIN участника приглашений не тратит — списка нет.
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gids[0]));
        let (seen, _) = b.until(ctrl::GROUP_STATE);
        let seen = [seen, b.sync()].concat();
        assert!(!seen.contains(&ctrl::INVITE_LIST), "{seen:02x?}");

        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn отклонённый_вход_присылает_свежий_список() {
        let (server, dir) = test_server("join-denied");
        let srv = server.addr;
        let a = Raw::connect(srv, "alpha");
        let gid = a.create("secret", true).gid;
        let gid2 = a.create("other", true).gid;
        let b = Raw::connect(srv, "bravo");
        b.expect(ctrl::INVITE_LIST);
        for g in [gid, gid2] {
            a.send(ctrl::INVITE, &payloads::enc_gid_target(g, &b.pk));
            b.expect(ctrl::INVITE_RCVD);
        }
        // Приглашение отозвано (KICK), клиент о нём не узнал — «Принять»:
        // ERROR и список без gid, клиент снимет мёртвое приглашение.
        a.send(ctrl::KICK, &payloads::enc_gid_target(gid, &b.pk));
        b.expect(ctrl::INVITE_LIST);
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        let (seen, p) = b.until(ctrl::INVITE_LIST);
        assert!(!seen.contains(&ctrl::GROUP_STATE), "{seen:02x?}");
        assert_eq!(window(p), (0, vec![gid2], true));
        let err = b.error();
        assert!(err.contains("приглашение"), "{err}");
        // Группу удалили (GROUP_STATE мог потеряться) — то же.
        a.send(ctrl::DELETE_GROUP, &payloads::enc_gid(gid2));
        b.expect(ctrl::GROUP_STATE);
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid2));
        assert_eq!(window(b.expect(ctrl::INVITE_LIST)), (0, vec![], true));

        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn устаревшие_приглашения_участников_чистятся_при_загрузке() {
        let dir = temp_dir("legacy");
        let store = persist::Store::new(&dir);
        let (member, banned, invited) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let mut g = empty_group(5);
        g.owner = [9; 32];
        g.insert_member(
            member,
            Member {
                ip: u32::from(Ipv4Addr::new(100, 66, 5, 2)),
                name: "b".into(),
                status: "st".into(),
            },
        );
        g.banned.insert(banned, "zed".into());
        // Так оставлял старый сервер: приглашение участнику и забаненному.
        for pk in [member, banned, invited] {
            g.invites.insert(
                pk,
                Invite {
                    created_ms: 42,
                    name: "who".into(),
                },
            );
        }
        let mut s = empty_state();
        s.groups.insert(5, g);
        s.next_gid = 6;
        let id = proto::Identity::generate();
        store.save(&snapshot(&id, &[], &s)).unwrap();

        let l = load_state(&store).unwrap();
        let g = &l.groups[&5];
        assert_eq!(g.invites.keys().collect::<Vec<_>>(), vec![&invited]);
        assert_eq!(
            (
                g.invites[&invited].created_ms,
                g.invites[&invited].name.as_str()
            ),
            (42, "who")
        );
        assert_eq!(
            (
                g.members[&member].name.as_str(),
                g.members[&member].status.as_str()
            ),
            ("b", "st")
        );
        assert_eq!(g.banned[&banned], "zed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- эксплуатация: метрики и TCP-фолбэк ----------

    fn http_get(addr: SocketAddr, path: &str) -> String {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    fn metric_values(resp: &str) -> HashMap<String, u64> {
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        body.lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once(' '))
            .map(|(k, v)| (k.to_string(), v.parse().unwrap()))
            .collect()
    }

    #[test]
    fn метрики_показывают_живые_счётчики_после_рукопожатия() {
        let dir = temp_dir("metrics");
        let server = Server::start(Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: dir.clone(),
            workers: 1,
            quiet: true,
            metrics: Some("127.0.0.1:0".parse().unwrap()),
            ..Config::default()
        })
        .unwrap();
        let maddr = server.metrics_addr.expect("метрики включены");
        let a = Raw::connect(server.addr, "alpha");
        a.expect(ctrl::GROUP_LIST);
        let st = a.create("game", false);
        let b = Raw::connect(server.addr, "bravo");
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(st.gid));
        let st_b = b.state();
        let x = proto::Identity::generate().ed_pub();
        a.send(ctrl::INVITE, &payloads::enc_gid_target(st.gid, &x));
        a.sync();
        let f = frame_for(&st_b, st.my_ip, st_b.my_ip, b"hi");
        a.sock.send_to(&f, server.addr).unwrap();
        b.group_frame(Duration::from_secs(3)).expect("релей");

        let r = http_get(maddr, "/metrics");
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        let v = metric_values(&r);
        assert_eq!(v["voidlink_sessions"], 2);
        assert_eq!(v["voidlink_groups"], 1);
        assert_eq!(v["voidlink_members"], 2);
        assert_eq!(v["voidlink_invites_pending"], 1);
        assert!(v["voidlink_hello_total"] >= 4, "{v:?}");
        assert!(v["voidlink_challenge_total"] >= 2, "{v:?}");
        assert!(v["voidlink_ctrl_frames_total"] >= 3, "{v:?}");
        assert_eq!(v["voidlink_relayed_frames_total"], 1);
        assert_eq!(v["voidlink_bytes_relayed_total"], f.len() as u64);

        let h = http_get(maddr, "/healthz");
        assert!(h.starts_with("HTTP/1.1 200"), "{h}");
        server.stop();
        assert!(std::net::TcpStream::connect_timeout(&maddr, Duration::from_millis(300)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// UDP ↔ TCP мост для `Raw`: клиент шлёт датаграммы на локальный UDP,
    /// мост пересылает их рамками по TCP-соединению с сервером и обратно.
    struct TcpBridge {
        udp: SocketAddr,
        tcp_local: SocketAddr,
        stream: std::net::TcpStream,
        stop: Arc<AtomicBool>,
    }

    impl TcpBridge {
        fn new(srv: SocketAddr) -> TcpBridge {
            use std::io::{Read, Write};
            let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            udp.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let stream = std::net::TcpStream::connect(srv).unwrap();
            stream.set_nodelay(true).unwrap();
            let tcp_local = stream.local_addr().unwrap();
            let client: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
            let stop = Arc::new(AtomicBool::new(false));
            {
                let (udp, mut w, client, stop) = (
                    udp.try_clone().unwrap(),
                    stream.try_clone().unwrap(),
                    client.clone(),
                    stop.clone(),
                );
                thread::spawn(move || {
                    let mut buf = [0u8; 65_535];
                    while !stop.load(Ordering::Relaxed) {
                        let Ok((n, from)) = udp.recv_from(&mut buf) else {
                            continue;
                        };
                        *client.lock().unwrap() = Some(from);
                        if w.write_all(&tcp::encode_frame(&buf[..n])).is_err() {
                            break;
                        }
                    }
                });
            }
            {
                let (udp, mut r) = (udp.try_clone().unwrap(), stream.try_clone().unwrap());
                thread::spawn(move || {
                    loop {
                        let mut hdr = [0u8; 2];
                        if r.read_exact(&mut hdr).is_err() {
                            break;
                        }
                        let mut body = vec![0u8; u16::from_le_bytes(hdr) as usize];
                        if r.read_exact(&mut body).is_err() {
                            break;
                        }
                        if let Some(to) = *client.lock().unwrap() {
                            let _ = udp.send_to(&body, to);
                        }
                    }
                });
            }
            TcpBridge {
                udp: udp.local_addr().unwrap(),
                tcp_local,
                stream,
                stop,
            }
        }

        fn close(&self) {
            self.stop.store(true, Ordering::Relaxed);
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
        }
    }

    #[test]
    fn tcp_клиент_и_udp_клиент_релеят_друг_другу() {
        let (server, dir) = test_server("tcp");
        let tcp_addr = server.tcp_addr.expect("TCP-фолбэк включён по умолчанию");
        assert_eq!(
            tcp_addr.port(),
            server.addr.port(),
            "TCP на том же порту, что UDP"
        );
        let bridge = TcpBridge::new(tcp_addr);

        // A — по TCP (рукопожатие v3 целиком через TCP), B — по UDP.
        let a = Raw::connect(bridge.udp, "alpha");
        a.expect(ctrl::GROUP_LIST);
        let st = a.create("game", false);
        assert_eq!(
            server
                .shared
                .state
                .read()
                .unwrap()
                .by_pub
                .get(&a.pk)
                .copied(),
            Some(bridge.tcp_local),
            "источник сессии — адрес TCP-соединения"
        );
        let b = Raw::connect(server.addr, "bravo");
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(st.gid));
        let st_b = b.state();

        // TCP → UDP.
        let ab = frame_for(&st_b, st.my_ip, st_b.my_ip, b"over tcp");
        a.sock.send_to(&ab, a.srv).unwrap();
        assert_eq!(
            b.group_frame(Duration::from_secs(3))
                .expect("релей TCP → UDP"),
            ab
        );
        // UDP → TCP: ответ идёт через реестр TCP, а не UDP-сокетом.
        let ba = frame_for(&st_b, st_b.my_ip, st.my_ip, b"over udp");
        b.sock.send_to(&ba, server.addr).unwrap();
        assert_eq!(
            a.group_frame(Duration::from_secs(3))
                .expect("релей UDP → TCP"),
            ba
        );

        // Закрытие TCP — сессия снимается сразу, не по таймауту.
        bridge.close();
        wait_until_srv(Duration::from_secs(3), || {
            !server
                .shared
                .state
                .read()
                .unwrap()
                .by_pub
                .contains_key(&a.pk)
        });
        server.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// GROUP_STATE группы `gid` (прочие GROUP_STATE пропускаются).
    fn state_of(r: &Raw, gid: u32) -> GroupState {
        loop {
            let st = r.state();
            if st.gid == gid {
                return st;
            }
        }
    }

    #[test]
    fn адрес_один_на_identity_во_всех_группах_и_после_выхода() {
        let (server, dir) = test_server("peruserip");
        let a = Raw::connect(server.addr, "alpha");
        let one = a.create("one", false);
        let two = a.create("two", false);
        assert_eq!(one.my_ip, two.my_ip, "у владельца один адрес на группы");
        assert!(leases::valid(one.my_ip));

        let b = Raw::connect(server.addr, "bravo");
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(one.gid));
        let b1 = state_of(&b, one.gid);
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(two.gid));
        let b2 = state_of(&b, two.gid);
        assert_eq!(b1.my_ip, b2.my_ip, "у участника один адрес на группы");
        assert_ne!(b1.my_ip, one.my_ip);
        // Участники видят друг друга под тем же адресом в обеих группах.
        for st in [&b1, &b2] {
            let a_ip = st.members.iter().find(|m| m.pubkey == a.pk).unwrap().ip;
            assert_eq!(a_ip, one.my_ip);
        }

        // Выход из обеих групп и повторный вход — адрес тот же.
        b.send(ctrl::LEAVE_GROUP, &payloads::enc_gid(one.gid));
        b.send(ctrl::LEAVE_GROUP, &payloads::enc_gid(two.gid));
        b.sync();
        thread::sleep(REJOIN_COOLDOWN + Duration::from_millis(100));
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(two.gid));
        assert_eq!(state_of(&b, two.gid).my_ip, b1.my_ip, "адрес закреплён");

        // И переживает перезапуск сервера (server.json).
        server.stop();
        let l = load_state(&persist::Store::new(&dir)).unwrap();
        assert_eq!(l.leases.get(&b.pk), Some(b1.my_ip));
        assert_eq!(l.leases.get(&a.pk), Some(one.my_ip));
        assert_eq!(l.groups[&two.gid].members[&b.pk].ip, b1.my_ip);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn server_json_v3_адреса_групп_сводятся_в_один() {
        let dir = temp_dir("v3ips");
        std::fs::create_dir_all(&dir).unwrap();
        let ip = |c: u8, d: u8| u32::from(Ipv4Addr::new(100, 66, c, d));
        let (x, y) = ([1u8; 32], [2u8; 32]);
        let arr = |b: [u8; 32]| serde_json::to_string(&b).unwrap();
        // Сервер v3: у X в группе 5 — 100.66.5.2, в группе 7 — 100.66.7.3;
        // у Y в группе 7 — 100.66.7.2; поля user_ips нет.
        let group = |id: u32, members: &[([u8; 32], u32)]| {
            let m: Vec<String> = members
                .iter()
                .map(|(k, a)| format!(r#"["{}",{a}]"#, hex(k)))
                .collect();
            format!(
                r#"{{"id":{id},"name":"g{id}","owner":"{}","key":{},"members":[{}]}}"#,
                hex(&x),
                arr([7; 32]),
                m.join(",")
            )
        };
        let json = format!(
            r#"{{"ed_seed":{},"x_seed":{},"next_gid":8,"groups":[{},{}]}}"#,
            arr([1; 32]),
            arr([2; 32]),
            group(7, &[(x, ip(7, 3)), (y, ip(7, 2))]),
            group(5, &[(x, ip(5, 2))]),
        );
        std::fs::write(dir.join("server.json"), json).unwrap();
        let store = persist::Store::new(&dir);
        let l = load_state(&store).unwrap();
        // X — адрес из группы с меньшим gid, во всех группах.
        assert_eq!(l.leases.get(&x), Some(ip(5, 2)));
        assert_eq!(l.leases.get(&y), Some(ip(7, 2)));
        assert_eq!(l.groups[&5].members[&x].ip, ip(5, 2));
        assert_eq!(l.groups[&7].members[&x].ip, ip(5, 2));
        assert_eq!(l.groups[&7].members[&y].ip, ip(7, 2));
        assert_eq!(l.groups[&7].by_ip.get(&ip(5, 2)), Some(&x));
        assert!(!l.groups[&7].by_ip.contains_key(&ip(7, 3)));
        // Сервер стартует на таком файле и пишет user_ips.
        let server = start_in(&dir, Limits::default());
        server.stop();
        let p = store.load().unwrap().unwrap();
        assert_eq!(p.user_ips.get(&hex(&x)), Some(&ip(5, 2)));
        assert_eq!(p.user_ips.get(&hex(&y)), Some(&ip(7, 2)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
