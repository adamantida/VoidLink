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

fn default_true() -> bool {
    true
}

fn default_mtu() -> usize {
    DEFAULT_MTU
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
        }
    }
}

impl Config {
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

#[derive(Serialize, Deserialize, Clone)]
pub struct StoredFriend {
    pub pubkey: String, // hex
    pub alias: String,
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
            Ok(raw) => Ok(serde_json::from_slice(&raw).context("client.json parse")?),
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

/// Токен пира → pubkey: friend code, hex или alias из списка друзей.
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
    if let Some(f) = cfg.friends.iter().find(|f| f.alias.to_lowercase() == t) {
        let v = proto::hex_to_bytes(&f.pubkey)?;
        anyhow::ensure!(v.len() == 32, "bad stored pubkey");
        return Ok(v.try_into().unwrap());
    }
    anyhow::bail!("не найден peer по токену {token:?} (ни friend code, ни hex, ни alias)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn старый_конфиг_получает_умолчания() {
        let cfg: Config = serde_json::from_str(r#"{"name":"a","autojoin":[3]}"#).unwrap();
        assert!(cfg.lan_discovery && !cfg.invisible);
        assert_eq!(cfg.mtu(), DEFAULT_MTU);
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
}
