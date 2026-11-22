//! Локальное хранилище клиента: identity, друзья, серверы, настройки.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tunnel_protocol as proto;

/// MTU адаптера по умолчанию: 1500 минус заголовки IP/UDP и фрейма группы
/// с запасом под IPv6 и PPPoE.
pub const DEFAULT_MTU: usize = 1400;
/// Разумные пределы MTU: меньше 576 IPv4 не гарантирует, больше 1500 —
/// внешний пакет почти везде фрагментируется.
pub const MTU_MIN: usize = 576;
pub const MTU_MAX: usize = 1500;

/// Интервал RTT-проб по умолчанию: 5 с — в пределах 5–10 с из issue #16.
pub const DEFAULT_RTT_INTERVAL_MS: u64 = 5_000;
/// Клэмп интервала проб: чаще 2 с — «чаттер», реже 20 с — NAT-маппинг
/// прямого канала успевает протухнуть (сервер держит сессию 30 с).
pub const RTT_INTERVAL_MIN_MS: u64 = 2_000;
pub const RTT_INTERVAL_MAX_MS: u64 = 20_000;
/// Гистерезис выбора пути: абсолютный выигрыш, мс (issue #17).
pub const DEFAULT_PATH_HYSTERESIS_MS: u32 = 15;
pub const PATH_HYSTERESIS_MAX_MS: u32 = 200;
/// Минимальное время удержания выбранного пути, мс (issue #17).
pub const DEFAULT_PATH_DWELL_MS: u64 = 10_000;
pub const PATH_DWELL_MAX_MS: u64 = 120_000;

fn default_true() -> bool {
    true
}

fn default_mtu() -> usize {
    DEFAULT_MTU
}

fn default_rtt_interval() -> u64 {
    DEFAULT_RTT_INTERVAL_MS
}

fn default_path_hysteresis() -> u32 {
    DEFAULT_PATH_HYSTERESIS_MS
}

fn default_path_dwell() -> u64 {
    DEFAULT_PATH_DWELL_MS
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub identity: Option<StoredIdentity>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub servers: Vec<StoredServer>,
    #[serde(default)]
    pub friends: Vec<StoredFriend>,
    /// Группы, к которым подключаемся автоматически при старте `run`.
    #[serde(default)]
    pub autojoin: Vec<u32>,
    /// Тема оформления TUI: dark | light | contrast.
    #[serde(default)]
    pub theme: String,
    /// Сообщать серверу LAN-адрес (CANDIDATES): пиры в одной сети
    /// соединяются напрямую, без NAT.
    #[serde(default = "default_true")]
    pub lan_discovery: bool,
    /// MTU адаптера (см. [`Config::mtu`] — с ограничением пределами).
    #[serde(default = "default_mtu")]
    pub mtu: usize,
    /// Невидимка: другие участники видят нас офлайн (флаг HELLO3, PRESENCE).
    #[serde(default)]
    pub invisible: bool,
    /// Сервер, к которому относится `autojoin` (адрес `ip:port`). Пусто —
    /// старый конфиг: список считается списком первого же сервера.
    #[serde(default)]
    pub active_server: String,
    /// Списки автовхода остальных серверов: gid у каждого сервера свои,
    /// и при смене сервера чужие gid вошли бы в посторонние группы.
    #[serde(default)]
    pub autojoin_by_server: BTreeMap<String, Vec<u32>>,
    /// Встроенный DNS для имён пиров (`<member>.vl`, `<member>.<group>.vl`
    /// на 100.66.0.53) и настройка split-DNS ОС для `.vl`.
    #[serde(default = "default_true")]
    pub dns: bool,
    /// Транспорт до сервера: auto (UDP, при молчании — TCP) | udp | tcp.
    #[serde(default)]
    pub transport: TransportMode,
    /// Имя Wintun-адаптера (экран «Серверы» TUI; пусто — по умолчанию,
    /// флаг `--adapter` важнее). Применяется после перезапуска.
    #[serde(default)]
    pub adapter: String,
    /// Путь к `wintun.dll` (пусто — рядом с exe или из PATH; флаг `--dll`
    /// важнее). Применяется после перезапуска.
    #[serde(default)]
    pub dll: String,
    /// Mesh-оверлей (этап 9): включён ли, релеит ли этот клиент и сколько
    /// трафика отдаёт, сохранённые DHT-контакты.
    #[serde(default)]
    pub mesh: MeshConfig,
    /// Ручное закрепление пути: `"<ip оверлея>" → "direct" | "server" |
    /// "relay:<hex ed25519>"` (§3.6). Сильнее автоматического выбора.
    #[serde(default)]
    pub pinned_paths: BTreeMap<String, String>,
    /// Интервал RTT-проб пирам, мс (issue #16): 2 с давали постоянный обмен
    /// 300–600 Б/с при трёх участниках. Читать через [`Config::rtt_interval`].
    #[serde(default = "default_rtt_interval")]
    pub rtt_interval_ms: u64,
    /// Гистерезис выбора пути: насколько новый путь должен быть дешевле
    /// текущего **в миллисекундах** (issue #17). Читать через
    /// [`Config::path_hysteresis`].
    #[serde(default = "default_path_hysteresis")]
    pub path_hysteresis_ms: u32,
    /// Сколько держать выбранный путь, прежде чем разрешить переключение
    /// (issue #17). Читать через [`Config::path_dwell`].
    #[serde(default = "default_path_dwell")]
    pub path_dwell_ms: u64,
    /// Выходы из групп, которые сервер ещё не подтвердил (issue #20):
    /// повторяются после рестарта, иначе приватная группа пустила бы обратно
    /// без нового приглашения.
    #[serde(default)]
    pub pending_leave: Vec<u32>,
}

/// Настройки mesh-оверлея (`client.json` → `mesh`). Все поля с `serde(default)`:
/// старый конфиг без секции читается как значения по умолчанию.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MeshConfig {
    /// Участвовать в mesh (публиковать MESH_INFO, принимать пиров).
    pub enabled: bool,
    /// Релеить чужой трафик (L2). По умолчанию включено (§3.4).
    pub relay_enabled: bool,
    /// Лимит отдачи реле, кбит/с (16384 ≈ 2 МБ/с).
    pub relay_budget_kbps: u32,
    /// Сохранённые DHT-контакты (переживают рестарт при мёртвом сервере).
    pub contacts: Vec<StoredContact>,
    /// Дублирование маленького latency-sensitive трафика по нескольким путям
    /// сразу (issue #25). По умолчанию выключено: полоса тратится вдвое.
    pub duplicate: bool,
    /// Потолок скорости цели, при которой пакет ещё дублируется, кбит/с.
    pub duplicate_max_kbps: u32,
    /// Потолок размера пакета для дублирования, байт.
    pub duplicate_max_pkt: u16,
    /// Сколько путей копировать (2 или 3): больше — только хуже для полосы.
    pub duplicate_paths: u8,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            relay_enabled: true,
            relay_budget_kbps: DEFAULT_RELAY_KBPS,
            contacts: Vec::new(),
            duplicate: false,
            duplicate_max_kbps: DEFAULT_DUPLICATE_KBPS,
            duplicate_max_pkt: DEFAULT_DUPLICATE_PKT,
            duplicate_paths: DEFAULT_DUPLICATE_PATHS,
        }
    }
}

/// Лимит реле по умолчанию: 2 МБ/с (§3.4).
pub const DEFAULT_RELAY_KBPS: u32 = 16_384;
/// Дублирование (issue #25): потолок скорости цели по умолчанию, кбит/с.
pub const DEFAULT_DUPLICATE_KBPS: u32 = 256;
/// Дублирование: потолок размера пакета по умолчанию, байт.
pub const DEFAULT_DUPLICATE_PKT: u16 = 512;
/// Дублирование: сколько путей копировать по умолчанию.
pub const DEFAULT_DUPLICATE_PATHS: u8 = 2;
/// Дублирование: допустимый диапазон числа путей.
pub const DUPLICATE_PATHS_MIN: u8 = 2;
pub const DUPLICATE_PATHS_MAX: u8 = 3;

/// Состояние друга (issue #24): дружба существует только после принятия
/// заявки, старая односторонняя запись — `Legacy`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FriendState {
    /// Запись из конфига до появления заявок: живёт локально, пока сервер не
    /// подтвердит дружбу (`Accepted`).
    #[default]
    Legacy,
    /// Заявка отправлена, ответа ещё нет.
    PendingOut,
    /// Заявка пришла от второй стороны.
    PendingIn,
    /// Дружба подтверждена взаимно.
    Accepted,
}

/// Сохранённый контакт mesh/DHT (`mesh.contacts`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredContact {
    /// hex ed25519 — идентификатор узла DHT.
    pub ed: String,
    /// hex x25519 — статический ключ контакта.
    #[serde(default)]
    pub x: String,
    /// `ip:port` — последний известный endpoint.
    #[serde(default)]
    pub addr: String,
    /// Последний RTT до контакта, мс.
    #[serde(default)]
    pub rtt_ms: u32,
    /// Когда контакт последний раз отвечал, unix секунды.
    #[serde(default)]
    pub seen_s: u64,
    /// Возможности mesh (`mesh::caps::*`); бит `MESH` подразумевается.
    #[serde(default)]
    pub caps: u8,
}

/// Выбор транспорта до сервера.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportMode {
    /// UDP, а если рукопожатие не отвечает (`tcp_link::should_fallback`) — TCP.
    #[default]
    Auto,
    /// Только UDP.
    Udp,
    /// Только TCP (сервер — по TCP, p2p с пирами — всё равно UDP).
    Tcp,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            identity: None,
            name: String::new(),
            status: String::new(),
            servers: Vec::new(),
            friends: Vec::new(),
            autojoin: Vec::new(),
            theme: String::new(),
            lan_discovery: true,
            mtu: DEFAULT_MTU,
            invisible: false,
            active_server: String::new(),
            autojoin_by_server: BTreeMap::new(),
            dns: true,
            transport: TransportMode::Auto,
            adapter: String::new(),
            dll: String::new(),
            mesh: MeshConfig::default(),
            pinned_paths: BTreeMap::new(),
            rtt_interval_ms: DEFAULT_RTT_INTERVAL_MS,
            path_hysteresis_ms: DEFAULT_PATH_HYSTERESIS_MS,
            path_dwell_ms: DEFAULT_PATH_DWELL_MS,
            pending_leave: Vec::new(),
        }
    }
}

impl Config {
    /// Интервал RTT-проб пирам (issue #16) в разумных пределах: 2 с — уже
    /// «чаттер», 20 с — NAT-маппинг прямого канала успевает протухнуть.
    pub fn rtt_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(
            self.rtt_interval_ms
                .clamp(RTT_INTERVAL_MIN_MS, RTT_INTERVAL_MAX_MS),
        )
    }

    /// Абсолютный гистерезис выбора пути, мс (issue #17).
    pub fn path_hysteresis(&self) -> u32 {
        self.path_hysteresis_ms.min(PATH_HYSTERESIS_MAX_MS)
    }

    /// Время удержания выбранного пути, мс (issue #17).
    pub fn path_dwell(&self) -> u64 {
        self.path_dwell_ms.min(PATH_DWELL_MAX_MS)
    }

    /// Число путей для дублирования (issue #25) в допустимых пределах.
    pub fn duplicate_paths(&self) -> u8 {
        self.mesh
            .duplicate_paths
            .clamp(DUPLICATE_PATHS_MIN, DUPLICATE_PATHS_MAX)
    }

    /// MTU адаптера в разумных пределах (руками вписанный 0 или 9000 не
    /// ломают туннель).
    pub fn mtu(&self) -> usize {
        self.mtu.clamp(MTU_MIN, MTU_MAX)
    }

    /// Делает `addr` текущим сервером: `autojoin` прежнего откладывается,
    /// восстанавливается список нового. `true` — конфиг изменился (сохранить).
    pub fn activate_server(&mut self, addr: SocketAddr) -> bool {
        let key = addr.to_string();
        if self.active_server == key {
            return false;
        }
        let prev = std::mem::replace(&mut self.active_server, key.clone());
        if prev.is_empty() {
            // Старый конфиг без active_server: список — этого сервера.
            return true;
        }
        let old = std::mem::take(&mut self.autojoin);
        if old.is_empty() {
            self.autojoin_by_server.remove(&prev);
        } else {
            self.autojoin_by_server.insert(prev, old);
        }
        self.autojoin = self.autojoin_by_server.remove(&key).unwrap_or_default();
        true
    }

    /// Закреплённый ключ сервера `addr` (после ротации по цепочке).
    /// `true` — запись найдена и изменена.
    pub fn repin_server(&mut self, addr: SocketAddr, pubkey: &[u8; 32]) -> bool {
        let hex = proto::hex_of(pubkey);
        let mut changed = false;
        for s in self.servers.iter_mut() {
            if s.addr.parse::<SocketAddr>().ok() == Some(addr) && s.pubkey != hex {
                s.pubkey = hex.clone();
                changed = true;
            }
        }
        changed
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredIdentity {
    pub ed_seed: String, // hex
    pub x_seed: String,  // hex
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StoredServer {
    pub addr: String,
    /// hex ed25519 pubkey сервера (пиннинг identity).
    pub pubkey: String,
    #[serde(default)]
    pub label: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct StoredFriend {
    pub pubkey: String, // hex
    /// Ручное переопределение имени: перекрывает ник с сервера.
    #[serde(default)]
    pub alias: String,
    /// Ник с сервера (issue #24): кэш имени из `FRIEND_LIST`, чтобы в списке
    /// был ник, а не код.
    #[serde(default)]
    pub nick: String,
    /// Состояние дружбы; отсутствует в старом конфиге — `Legacy`.
    #[serde(default)]
    pub state: FriendState,
}

pub struct Store {
    path: PathBuf,
}

/// Каталог по умолчанию: %APPDATA%\tunnel (Windows), иначе ./tunnel-client-data.
pub fn default_dir() -> PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        return Path::new(&appdata).join("tunnel");
    }
    if let Ok(home) = std::env::var("HOME") {
        return Path::new(&home).join(".tunnel-client");
    }
    PathBuf::from("tunnel-client-data")
}

impl Store {
    pub fn new(dir: &Path) -> Self {
        let _ = std::fs::create_dir_all(dir);
        Self {
            path: dir.join("client.json"),
        }
    }

    pub fn load(&self) -> Result<Config> {
        match std::fs::read(&self.path) {
            Ok(raw) => {
                let mut cfg: Config = serde_json::from_slice(&raw).context("client.json parse")?;
                migrate_friends(&mut cfg);
                Ok(cfg)
            }
            Err(_) => Ok(Config::default()),
        }
    }

    pub fn save(&self, cfg: &Config) -> Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(cfg)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// Миграция списка друзей при загрузке `client.json` (issue #24).
///
/// До появления заявок друг добавлялся локально, а `alias` по умолчанию
/// подставлялся равным friend code. Такой «алиас» — не имя: в панели друзей
/// он занимал всю строку и скрывал ник с сервера. Поэтому алиас, который
/// парсится как friend code этого же pubkey, очищается; отсутствующий
/// `state` serde подставляет как [`FriendState::Legacy`] — запись живёт
/// локально, пока сервер не подтвердит пару.
pub fn migrate_friends(cfg: &mut Config) {
    for f in cfg.friends.iter_mut() {
        let Ok(pk) = crate::friends::parse_pk(&f.pubkey) else {
            continue;
        };
        let alias = f.alias.trim();
        if alias.is_empty() {
            continue;
        }
        if proto::parse_friend_code(alias).ok() == Some(pk) {
            f.alias.clear();
        }
    }
}

/// Инициализация identity: загрузка из конфига или генерация новой.
pub fn ensure_identity(cfg: &mut Config) -> proto::Identity {
    if let Some(si) = &cfg.identity
        && let (Ok(ed), Ok(x)) = (
            proto::hex_to_bytes(&si.ed_seed),
            proto::hex_to_bytes(&si.x_seed),
        )
        && ed.len() == 32
        && x.len() == 32
    {
        let mut edb = [0u8; 32];
        let mut xb = [0u8; 32];
        edb.copy_from_slice(&ed);
        xb.copy_from_slice(&x);
        return proto::Identity {
            ed_seed: edb,
            x_seed: xb,
        };
    }
    let id = proto::Identity::generate();
    cfg.identity = Some(StoredIdentity {
        ed_seed: proto::hex_of(&id.ed_seed),
        x_seed: proto::hex_of(&id.x_seed),
    });
    id
}

/// Токен пира → pubkey: friend code, hex или имя друга (алиас либо ник).
///
/// Имена не уникальны: если под токен подходит несколько друзей, это ошибка
/// со списком кандидатов, а не «первый в списке» — иначе `say`/`friend-groups`
/// уходили бы случайному тёзке.
pub fn resolve_peer(cfg: &Config, token: &str) -> Result<[u8; 32]> {
    if let Ok(pk) = proto::Identity::parse_friend_code(token) {
        return Ok(pk);
    }
    let t = token.trim().to_lowercase();
    if let Ok(v) = proto::hex_to_bytes(&t)
        && v.len() == 32
    {
        return Ok(v.try_into().unwrap());
    }
    // Один друг может подойти и алиасом, и ником — считаем его один раз.
    // Сравниваем с тем именем, которое видно: алиас перекрывает ник, иначе
    // «второй» в списке не находился бы, а скрытый ник — находился.
    let mut hits: Vec<[u8; 32]> = Vec::new();
    for f in &cfg.friends {
        let Ok(pk) = crate::friends::parse_pk(&f.pubkey) else {
            continue;
        };
        let shown = crate::friends::display_name(&f.alias, &f.nick, &pk);
        if shown.to_lowercase() == t && !hits.contains(&pk) {
            hits.push(pk);
        }
    }
    match hits.len() {
        0 => anyhow::bail!(
            "не найден peer по токену {token:?} (ни friend code, ни hex, ни алиас/ник)"
        ),
        1 => Ok(hits[0]),
        _ => {
            let names: Vec<String> = hits
                .iter()
                .map(|pk| {
                    let f = cfg
                        .friends
                        .iter()
                        .find(|f| crate::friends::parse_pk(&f.pubkey).ok() == Some(*pk));
                    let (alias, nick) = f
                        .map(|f| (f.alias.as_str(), f.nick.as_str()))
                        .unwrap_or(("", ""));
                    format!(
                        "{} ({})",
                        crate::friends::display_name(alias, nick, pk),
                        proto::hex_of(&pk[..4])
                    )
                })
                .collect();
            anyhow::bail!(
                "«{token}» — неоднозначно: подходит {} друга — {}; уточните friend code",
                hits.len(),
                names.join(", ")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn старый_конфиг_получает_умолчания() {
        let cfg: Config = serde_json::from_str(r#"{"name":"a","autojoin":[3]}"#).unwrap();
        assert!(cfg.lan_discovery && !cfg.invisible);
        assert_eq!(cfg.mtu(), DEFAULT_MTU);
        // Этап 9: старый client.json без секции mesh и пинов читается.
        assert_eq!(cfg.mesh, MeshConfig::default());
        assert!(
            cfg.mesh.enabled && cfg.mesh.relay_enabled,
            "mesh включается по умолчанию"
        );
        assert_eq!(cfg.mesh.relay_budget_kbps, DEFAULT_RELAY_KBPS);
        assert!(cfg.mesh.contacts.is_empty());
        assert!(cfg.pinned_paths.is_empty());
        // Новые поля пишутся и читаются обратно.
        let mut cfg = Config::default();
        cfg.pinned_paths
            .insert("100.66.0.2".into(), "relay:0011".into());
        cfg.mesh.contacts.push(StoredContact {
            ed: "aa".into(),
            x: "bb".into(),
            addr: "1.2.3.4:5".into(),
            rtt_ms: 42,
            seen_s: 7,
            caps: 0,
        });
        let json = serde_json::to_string(&cfg).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mesh, cfg.mesh);
        assert_eq!(back.pinned_paths, cfg.pinned_paths);
        assert_eq!(back.pinned_paths["100.66.0.2"], "relay:0011");
        let d = Config::default();
        assert!(d.lan_discovery);
        assert_eq!(d.mtu, DEFAULT_MTU);
        let wild = Config {
            mtu: 9000,
            ..Config::default()
        };
        assert_eq!(wild.mtu(), MTU_MAX);
        let zero = Config {
            mtu: 0,
            ..Config::default()
        };
        assert_eq!(zero.mtu(), MTU_MIN);
    }

    #[test]
    fn автовход_у_каждого_сервера_свой() {
        let a: SocketAddr = "1.1.1.1:5555".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:5555".parse().unwrap();
        // Старый конфиг: список принадлежит первому активированному серверу.
        let mut cfg = Config {
            autojoin: vec![1, 2],
            ..Config::default()
        };
        assert!(cfg.activate_server(a));
        assert_eq!(cfg.autojoin, vec![1, 2]);
        assert!(!cfg.activate_server(a));
        assert!(cfg.activate_server(b));
        assert!(cfg.autojoin.is_empty(), "gid сервера A не входят на B");
        cfg.autojoin.push(7);
        assert!(cfg.activate_server(a));
        assert_eq!(cfg.autojoin, vec![1, 2]);
        assert!(cfg.activate_server(b));
        assert_eq!(cfg.autojoin, vec![7]);
    }

    fn friend(pk: [u8; 32], alias: &str, nick: &str, state: FriendState) -> StoredFriend {
        StoredFriend {
            pubkey: proto::hex_of(&pk),
            alias: alias.into(),
            nick: nick.into(),
            state,
        }
    }

    #[test]
    fn старый_друг_без_состояния_читается_как_локальный() {
        // Конфиг до issue #24: ни `state`, ни `nick` в записи нет.
        let pk = [7u8; 32];
        let json = format!(
            r#"{{"name":"a","friends":[{{"pubkey":"{}","alias":"старый"}}]}}"#,
            proto::hex_of(&pk)
        );
        let cfg: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg.friends.len(), 1);
        assert_eq!(cfg.friends[0].state, FriendState::Legacy);
        assert!(cfg.friends[0].nick.is_empty());
        assert_eq!(cfg.friends[0].alias, "старый");
        // Состояние пишется и читается обратно.
        let mut cfg = Config::default();
        cfg.friends
            .push(friend(pk, "имя", "ник", FriendState::Accepted));
        let back: Config = serde_json::from_str(&serde_json::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(back.friends[0].state, FriendState::Accepted);
        assert_eq!(back.friends[0].nick, "ник");
    }

    #[test]
    fn алиас_равный_коду_при_загрузке_очищается() {
        let pk = [9u8; 32];
        let code = proto::friend_code_of(&pk);
        let mut cfg = Config::default();
        cfg.friends.push(friend(pk, &code, "", FriendState::Legacy));
        // Имя, не совпадающее с кодом, и код чужого ключа не трогаем.
        cfg.friends
            .push(friend([8u8; 32], "нормальное имя", "", FriendState::Legacy));
        cfg.friends
            .push(friend([3u8; 32], &code, "", FriendState::Legacy));
        migrate_friends(&mut cfg);
        assert!(
            cfg.friends[0].alias.is_empty(),
            "friend code в алиасе — это код, а не имя"
        );
        assert_eq!(cfg.friends[1].alias, "нормальное имя");
        assert_eq!(
            cfg.friends[2].alias, code,
            "код другого ключа — тоже код, но по контракту чистим только совпадающий"
        );
        // Повторная миграция идемпотентна.
        migrate_friends(&mut cfg);
        assert!(cfg.friends[0].alias.is_empty());
    }

    #[test]
    fn несколько_друзей_с_одним_ником_не_разрешаются_молча() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let mut cfg = Config::default();
        cfg.friends
            .push(friend(a, "", "тёзка", FriendState::Accepted));
        cfg.friends
            .push(friend(b, "", "тёзка", FriendState::Accepted));
        // Один тёзка — разрешается.
        let err = resolve_peer(&cfg, "тёзка").unwrap_err().to_string();
        assert!(err.contains("неоднозначно"), "{err}");
        assert!(err.contains("тёзка"), "в ошибке есть список: {err}");
        assert!(err.contains("2"), "и число кандидатов: {err}");
        // Алиас перекрывает ник и снимает неоднозначность.
        cfg.friends[1].alias = "второй".into();
        assert_eq!(resolve_peer(&cfg, "тёзка").unwrap(), a);
        assert_eq!(resolve_peer(&cfg, "второй").unwrap(), b);
        // Точный ключ разрешается всегда — это не имя.
        assert_eq!(resolve_peer(&cfg, &proto::hex_of(&b)).unwrap(), b);
        assert_eq!(resolve_peer(&cfg, &proto::friend_code_of(&a)).unwrap(), a);
        // Друг, подходящий и алиасом, и ником, считается один раз.
        cfg.friends[0].alias = "тёзка".into();
        cfg.friends[1].alias.clear();
        assert!(
            resolve_peer(&cfg, "тёзка")
                .unwrap_err()
                .to_string()
                .contains('2'),
            "оба тёзки — снова неоднозначно"
        );
    }

    #[test]
    fn перезакрепление_ключа_по_адресу() {
        let a: SocketAddr = "1.1.1.1:5555".parse().unwrap();
        let mut cfg = Config {
            servers: vec![StoredServer {
                addr: a.to_string(),
                pubkey: "00".into(),
                label: String::new(),
            }],
            ..Config::default()
        };
        assert!(cfg.repin_server(a, &[0xab; 32]));
        assert_eq!(cfg.servers[0].pubkey, proto::hex_of(&[0xab; 32]));
        assert!(!cfg.repin_server(a, &[0xab; 32]));
        assert!(!cfg.repin_server("9.9.9.9:1".parse().unwrap(), &[1; 32]));
    }

    #[test]
    fn интервал_проб_из_конфига_с_клэмпом() {
        use std::time::Duration;
        let d = Config::default();
        assert_eq!(d.rtt_interval(), Duration::from_secs(5));
        assert_eq!(d.rtt_interval_ms, DEFAULT_RTT_INTERVAL_MS);
        // Меньше 2 с — «чаттер», больше 20 с — NAT-маппинг прямого канала
        // успевает протухнуть (issue #16).
        for (ms, want) in [
            (0u64, RTT_INTERVAL_MIN_MS),
            (500, RTT_INTERVAL_MIN_MS),
            (2_000, 2_000),
            (5_000, 5_000),
            (20_000, 20_000),
            (60_000, RTT_INTERVAL_MAX_MS),
            (u64::MAX, RTT_INTERVAL_MAX_MS),
        ] {
            let c = Config {
                rtt_interval_ms: ms,
                ..Config::default()
            };
            assert_eq!(
                c.rtt_interval(),
                Duration::from_millis(want),
                "интервал {ms} мс"
            );
        }
        // Старый client.json без ключа — умолчание.
        let c: Config = serde_json::from_str(r#"{"name":"a"}"#).unwrap();
        assert_eq!(c.rtt_interval(), Duration::from_secs(5));
    }

    #[test]
    fn гистерезис_и_dwell_клэмпятся() {
        let d = Config::default();
        assert_eq!(d.path_hysteresis(), DEFAULT_PATH_HYSTERESIS_MS);
        assert_eq!(d.path_dwell(), DEFAULT_PATH_DWELL_MS);
        // Ноль разрешён: «без абсолютного порога» и «без удержания».
        let zero = Config {
            path_hysteresis_ms: 0,
            path_dwell_ms: 0,
            ..Config::default()
        };
        assert_eq!(zero.path_hysteresis(), 0);
        assert_eq!(zero.path_dwell(), 0);
        // Потолки: больше — только дольше держаться за плохой путь.
        let wild = Config {
            path_hysteresis_ms: 10_000,
            path_dwell_ms: u64::MAX,
            ..Config::default()
        };
        assert_eq!(wild.path_hysteresis(), PATH_HYSTERESIS_MAX_MS);
        assert_eq!(wild.path_dwell(), PATH_DWELL_MAX_MS);
        // Старый client.json — умолчания (issue #17).
        let c: Config = serde_json::from_str(r#"{"name":"a"}"#).unwrap();
        assert_eq!(c.path_hysteresis(), DEFAULT_PATH_HYSTERESIS_MS);
        assert_eq!(c.path_dwell(), DEFAULT_PATH_DWELL_MS);
    }
}
