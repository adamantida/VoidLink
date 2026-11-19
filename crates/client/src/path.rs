//! Optimal path selection for peer-to-peer communication.
//!
//! Implements the path selection algorithm: try direct (hole punch) → DHT relay → server relay.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Node identifier (ed25519 public key).
pub type NodeId = [u8; 32];

/// A relay ticket from DHT relay node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayTicket {
    /// The relay node's address.
    pub relay_addr: SocketAddr,
    /// Estimated latency to relay in ms.
    pub latency_ms: u32,
    /// Ticket expiry timestamp (Unix epoch millis).
    pub expires_at: u64,
    /// The relay node's public key.
    pub relay_pubkey: NodeId,
}

impl RelayTicket {
    /// Check if ticket is still valid.
    pub fn is_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        now < self.expires_at
    }

    /// Estimated RTT via this relay (ticket latency + 10ms overhead).
    pub fn est_rtt_ms(&self) -> u32 {
        self.latency_ms.saturating_add(10)
    }
}

/// Path type for reaching a peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Path {
    /// Direct P2P connection (hole-punched).
    Direct {
        peer_addr: SocketAddr,
        rtt_ms: u32,
    },
    /// Via DHT relay node.
    DhtRelay {
        ticket: RelayTicket,
        relay_addr: SocketAddr,
        est_rtt_ms: u32,
    },
    /// Via central server relay.
    ServerRelay {
        server_addr: SocketAddr,
        est_rtt_ms: u32,
    },
}

impl Path {
    /// Get the target address to send data to.
    pub fn target_addr(&self) -> SocketAddr {
        match self {
            Path::Direct { peer_addr, .. } => *peer_addr,
            Path::DhtRelay { relay_addr, .. } => *relay_addr,
            Path::ServerRelay { server_addr, .. } => *server_addr,
        }
    }

    /// Get the number of relay hops (0 for direct, 1 for relays).
    pub fn relay_hops(&self) -> u8 {
        match self {
            Path::Direct { .. } => 0,
            Path::DhtRelay { .. } | Path::ServerRelay { .. } => 1,
        }
    }

    /// Get estimated RTT in ms.
    pub fn est_rtt_ms(&self) -> u32 {
        match self {
            Path::Direct { rtt_ms, .. } => *rtt_ms,
            Path::DhtRelay { est_rtt_ms, .. } => *est_rtt_ms,
            Path::ServerRelay { est_rtt_ms, .. } => *est_rtt_ms,
        }
    }
}

/// NAT type classification for path scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatType {
    /// No NAT / public IP.
    Open,
    /// Full cone NAT.
    FullCone,
    /// Restricted cone NAT.
    RestrictedCone,
    /// Port-restricted cone NAT.
    PortRestrictedCone,
    /// Symmetric NAT (hardest for P2P).
    Symmetric,
    /// Unknown / not yet classified.
    Unknown,
}

/// Scored path for selection.
#[derive(Debug, Clone)]
pub struct PathScore {
    pub path: Path,
    pub score: f32,           // lower = better
    pub rtt_ms: u32,
    pub relay_hops: u8,
    pub bandwidth_mbps: u32,
    pub nat_type: NatType,
}

impl PathScore {
    /// Create a new PathScore from a Path.
    pub fn new(path: Path, nat_type: NatType, bandwidth_mbps: u32) -> Self {
        let rtt_ms = path.est_rtt_ms();
        let relay_hops = path.relay_hops();
        Self {
            path,
            score: 0.0,
            rtt_ms,
            relay_hops,
            bandwidth_mbps,
            nat_type,
        }
    }
}

/// Key for tracking failures per path.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum PathKey {
    Direct(NodeId),
    DhtRelay(NodeId, SocketAddr), // target, relay_addr
    ServerRelay(NodeId),
}

/// Configuration for path selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathConfig {
    /// Path selection strategy.
    pub strategy: PathStrategy,
    /// Timeout for direct connection attempts (ms).
    pub direct_timeout_ms: u32,
    /// Timeout for relay connection attempts (ms).
    pub relay_timeout_ms: u32,
    /// Maximum failures before circuit breaker opens.
    pub max_failures: u32,
    /// Circuit breaker reset time (seconds).
    pub circuit_breaker_secs: u32,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            strategy: PathStrategy::Auto,
            direct_timeout_ms: 2000,
            relay_timeout_ms: 5000,
            max_failures: 5,
            circuit_breaker_secs: 30,
        }
    }
}

/// Path selection strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PathStrategy {
    /// Auto select best path (default).
    #[default]
    Auto,
    /// Only use direct connections.
    DirectOnly,
    /// Prefer relay over direct.
    PreferRelay,
}

/// Path selector with RTT history, relay tickets cache, and circuit breaker.
pub struct PathSelector {
    // RTT history per peer (direct)
    direct_rtt: Mutex<HashMap<NodeId, Vec<u32>>>,
    // DHT relay tickets cache: target -> ticket
    relay_tickets: Mutex<HashMap<NodeId, RelayTicket>>,
    // Server RTT
    server_rtt: Mutex<Option<u32>>,
    // Circuit breaker: failed attempts per path
    failures: Mutex<HashMap<PathKey, (u32, Instant)>>,
    // Configuration
    config: PathConfig,
}

impl PathSelector {
    /// Create a new PathSelector with default configuration.
    pub fn new() -> Self {
        Self::with_config(PathConfig::default())
    }

    /// Create a new PathSelector with custom configuration.
    pub fn with_config(config: PathConfig) -> Self {
        Self {
            direct_rtt: Mutex::new(HashMap::new()),
            relay_tickets: Mutex::new(HashMap::new()),
            server_rtt: Mutex::new(None),
            failures: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// Get the current configuration.
    pub fn config(&self) -> &PathConfig {
        &self.config
    }

    /// Update the configuration.
    pub fn set_config(&mut self, config: PathConfig) {
        self.config = config;
    }

    /// Main entry: select best path for target peer.
    pub fn select_path(
        &self,
        target: NodeId,
        dht: Option<&dyn DhtNode>,
        server_addr: SocketAddr,
        peer_direct_addr: Option<SocketAddr>,
        _peer_nat_type: NatType,
    ) -> Path {
        // If strategy is DirectOnly, only try direct
        if self.config.strategy == PathStrategy::DirectOnly {
            if let Some(addr) = peer_direct_addr {
                let rtt = self.get_direct_rtt(target).unwrap_or(100);
                return Path::Direct { peer_addr: addr, rtt_ms: rtt };
            }
            // Fall through to server relay if no direct address
        }

        // Strategy PreferRelay: try DHT relay first if available
        if self.config.strategy == PathStrategy::PreferRelay {
            if let Some(ticket) = self.get_valid_dht_ticket(target) {
                if !self.is_circuit_open(&PathKey::DhtRelay(target, ticket.relay_addr)) {
                    return Path::DhtRelay {
                        relay_addr: ticket.relay_addr,
                        est_rtt_ms: ticket.est_rtt_ms(),
                        ticket,
                    };
                }
            }
        }

        // Auto strategy (default): Direct -> DHT Relay -> Server Relay

        // 1. Try direct if we have a direct address and circuit not open
        if let Some(addr) = peer_direct_addr {
            if !self.is_circuit_open(&PathKey::Direct(target)) {
                let rtt = self.get_direct_rtt(target).unwrap_or(100);
                return Path::Direct { peer_addr: addr, rtt_ms: rtt };
            }
        }

        // 2. Try DHT relay if available and circuit not open
        if let Some(dht_node) = dht {
            if let Some(ticket) = dht_node.get_relay_ticket(target) {
                if ticket.is_valid() && !self.is_circuit_open(&PathKey::DhtRelay(target, ticket.relay_addr)) {
                    self.cache_dht_ticket(target, ticket.clone());
                    return Path::DhtRelay {
                        relay_addr: ticket.relay_addr,
                        est_rtt_ms: ticket.est_rtt_ms(),
                        ticket,
                    };
                }
            }
            // Also check cached tickets
            if let Some(ticket) = self.get_valid_dht_ticket(target) {
                if !self.is_circuit_open(&PathKey::DhtRelay(target, ticket.relay_addr)) {
                    return Path::DhtRelay {
                        relay_addr: ticket.relay_addr,
                        est_rtt_ms: ticket.est_rtt_ms(),
                        ticket,
                    };
                }
            }
        } else if let Some(ticket) = self.get_valid_dht_ticket(target) {
            if !self.is_circuit_open(&PathKey::DhtRelay(target, ticket.relay_addr)) {
                return Path::DhtRelay {
                    relay_addr: ticket.relay_addr,
                    est_rtt_ms: ticket.est_rtt_ms(),
                    ticket,
                };
            }
        }

        // 3. Fall back to server relay
        let server_rtt = self.get_server_rtt().unwrap_or(100);
        Path::ServerRelay {
            server_addr,
            est_rtt_ms: server_rtt.saturating_add(20),
        }
    }

    /// Record RTT measurement from PING/PONG.
    pub fn record_rtt(&self, target: NodeId, rtt_ms: u32, path: &Path) {
        match path {
            Path::Direct { .. } => {
                let mut history = self.direct_rtt.lock().unwrap();
                let entry = history.entry(target).or_default();
                entry.push(rtt_ms);
                // Keep last 10 measurements
                if entry.len() > 10 {
                    entry.remove(0);
                }
            }
            Path::DhtRelay { .. } => {
                // Could track relay RTT history here
            }
            Path::ServerRelay { .. } => {
                let mut srtt = self.server_rtt.lock().unwrap();
                *srtt = Some(match *srtt {
                    Some(old) => (old * 3 + rtt_ms) / 4, // EWMA
                    None => rtt_ms,
                });
            }
        }
    }

    /// Record a failure for a path (timeout, relay error).
    pub fn record_failure(&self, path: &Path, target: NodeId) {
        let key = match path {
            Path::Direct { .. } => PathKey::Direct(target),
            Path::DhtRelay { relay_addr, .. } => PathKey::DhtRelay(target, *relay_addr),
            Path::ServerRelay { server_addr: _, .. } => PathKey::ServerRelay(target),
        };

        let mut failures = self.failures.lock().unwrap();
        let (count, last_failure) = failures.entry(key).or_insert((0, Instant::now()));
        *count += 1;
        *last_failure = Instant::now();
    }

    /// Check if circuit breaker is open for a path.
    fn is_circuit_open(&self, key: &PathKey) -> bool {
        let failures = self.failures.lock().unwrap();
        if let Some((count, last_failure)) = failures.get(key) {
            if *count >= self.config.max_failures {
                let elapsed = last_failure.elapsed();
                if elapsed < Duration::from_secs(self.config.circuit_breaker_secs as u64) {
                    return true;
                } else {
                    // Circuit breaker reset - clear the failure count
                    drop(failures);
                    let mut failures = self.failures.lock().unwrap();
                    failures.remove(key);
                }
            }
        }
        false
    }

    /// Get current best path for UI display (without DHT lookup).
    pub fn current_path(&self, target: NodeId, server_addr: SocketAddr) -> Option<Path> {
        // Check if we have a direct RTT
        if let Some(_rtt) = self.get_direct_rtt(target) {
            // We'd need the peer address - for UI just return a placeholder
            // In practice this would be called with more context
            return None;
        }

        // Check cached DHT ticket
        if let Some(ticket) = self.get_valid_dht_ticket(target) {
            return Some(Path::DhtRelay {
                relay_addr: ticket.relay_addr,
                est_rtt_ms: ticket.est_rtt_ms(),
                ticket,
            });
        }

        // Server relay
        let server_rtt = self.get_server_rtt().unwrap_or(100);
        Some(Path::ServerRelay {
            server_addr,
            est_rtt_ms: server_rtt.saturating_add(20),
        })
    }

    /// Get average direct RTT for a peer.
    fn get_direct_rtt(&self, target: NodeId) -> Option<u32> {
        let history = self.direct_rtt.lock().unwrap();
        history.get(&target).and_then(|v| {
            if v.is_empty() {
                None
            } else {
                let sum: u32 = v.iter().sum();
                Some(sum / v.len() as u32)
            }
        })
    }

    /// Get server RTT.
    fn get_server_rtt(&self) -> Option<u32> {
        *self.server_rtt.lock().unwrap()
    }

    /// Get valid cached DHT ticket.
    fn get_valid_dht_ticket(&self, target: NodeId) -> Option<RelayTicket> {
        let tickets = self.relay_tickets.lock().unwrap();
        tickets.get(&target).filter(|t| t.is_valid()).cloned()
    }

    /// Cache a DHT relay ticket.
    fn cache_dht_ticket(&self, target: NodeId, ticket: RelayTicket) {
        let mut tickets = self.relay_tickets.lock().unwrap();
        tickets.insert(target, ticket);
    }

    /// Score a path for selection (lower = better).
    /// score = base_rtt + relay_penalty * hops + failure_penalty * failures - bandwidth_bonus
    pub fn score_path(&self, path: &Path, target: NodeId, nat_type: NatType, bandwidth_mbps: u32) -> f32 {
        let base_rtt = path.est_rtt_ms() as f32;
        let relay_hops = path.relay_hops() as f32;
        let relay_penalty = 50.0; // 50ms per hop penalty
        let bandwidth_bonus = (bandwidth_mbps as f32).min(100.0) * 0.1; // Up to 10ms bonus

        // Failure penalty
        let key = match path {
            Path::Direct { .. } => PathKey::Direct(target),
            Path::DhtRelay { relay_addr, .. } => PathKey::DhtRelay(target, *relay_addr),
            Path::ServerRelay { .. } => PathKey::ServerRelay(target),
        };
        let failures = self.failures.lock().unwrap().get(&key).map(|(c, _)| *c).unwrap_or(0) as f32;
        let failure_penalty = failures * 100.0; // 100ms per failure

        // NAT type penalty
        let nat_penalty = match nat_type {
            NatType::Open => 0.0,
            NatType::FullCone => 10.0,
            NatType::RestrictedCone => 20.0,
            NatType::PortRestrictedCone => 30.0,
            NatType::Symmetric => 50.0,
            NatType::Unknown => 25.0,
        };

        base_rtt + relay_penalty * relay_hops + failure_penalty + nat_penalty - bandwidth_bonus
    }

    /// Clear all cached state for a target (e.g., on peer disconnect).
    pub fn clear_target(&self, target: NodeId) {
        self.direct_rtt.lock().unwrap().remove(&target);
        self.relay_tickets.lock().unwrap().remove(&target);
        self.failures.lock().unwrap().retain(|k, _| match k {
            PathKey::Direct(t) => *t != target,
            PathKey::DhtRelay(t, _) => *t != target,
            PathKey::ServerRelay(t) => *t != target,
        });
    }

    /// Get failure count for a path (for debugging/UI).
    pub fn failure_count(&self, path: &Path, target: NodeId) -> u32 {
        let key = match path {
            Path::Direct { .. } => PathKey::Direct(target),
            Path::DhtRelay { relay_addr, .. } => PathKey::DhtRelay(target, *relay_addr),
            Path::ServerRelay { .. } => PathKey::ServerRelay(target),
        };
        self.failures.lock().unwrap().get(&key).map(|(c, _)| *c).unwrap_or(0)
    }
}

impl Default for PathSelector {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for DHT node operations needed by PathSelector.
pub trait DhtNode: Send + Sync {
    /// Get a relay ticket for the target peer.
    fn get_relay_ticket(&self, target: NodeId) -> Option<RelayTicket>;
    
    /// Get the NAT type for a peer (if known).
    fn get_nat_type(&self, target: NodeId) -> Option<NatType>;
    
    /// Get estimated bandwidth to a peer (Mbps).
    fn get_bandwidth_estimate(&self, target: NodeId) -> Option<u32>;
}

/// Path selection event for telemetry/TUI.
#[derive(Debug, Clone)]
pub struct PathSelectedEvent {
    pub target: NodeId,
    pub path: Path,
    pub score: f32,
    pub previous_path: Option<Path>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    fn make_node_id(byte: u8) -> NodeId {
        [byte; 32]
    }

    #[test]
    fn test_path_selector_new() {
        let selector = PathSelector::new();
        let target = make_node_id(1);
        let server = make_addr(5000);

        // No direct addr, no DHT -> server relay
        let path = selector.select_path(target, None, server, None, NatType::Unknown);
        assert!(matches!(path, Path::ServerRelay { .. }));
    }

    #[test]
    fn test_path_selector_direct_preferred() {
        let selector = PathSelector::new();
        let target = make_node_id(1);
        let server = make_addr(5000);
        let direct_addr = make_addr(4000);

        // Direct address available -> direct
        let path = selector.select_path(target, None, server, Some(direct_addr), NatType::Open);
        assert!(matches!(path, Path::Direct { peer_addr, .. } if peer_addr == direct_addr));
    }

    #[test]
    fn test_path_selector_direct_only_strategy() {
        let mut config = PathConfig::default();
        config.strategy = PathStrategy::DirectOnly;
        let selector = PathSelector::with_config(config);
        let target = make_node_id(1);
        let server = make_addr(5000);

        // No direct addr -> server relay (fallback)
        let path = selector.select_path(target, None, server, None, NatType::Unknown);
        assert!(matches!(path, Path::ServerRelay { .. }));

        // With direct addr -> direct
        let direct_addr = make_addr(4000);
        let path = selector.select_path(target, None, server, Some(direct_addr), NatType::Unknown);
        assert!(matches!(path, Path::Direct { .. }));
    }

    #[test]
    fn test_path_selector_prefer_relay_strategy() {
        let mut config = PathConfig::default();
        config.strategy = PathStrategy::PreferRelay;
        let selector = PathSelector::with_config(config);
        let target = make_node_id(1);
        let server = make_addr(5000);
        let direct_addr = make_addr(4000);

        // No DHT ticket -> direct (since PreferRelay only prefers when available)
        let path = selector.select_path(target, None, server, Some(direct_addr), NatType::Unknown);
        assert!(matches!(path, Path::Direct { .. }));
    }

    #[test]
    fn test_record_rtt_direct() {
        let selector = PathSelector::new();
        let target = make_node_id(1);
        let path = Path::Direct {
            peer_addr: make_addr(4000),
            rtt_ms: 50,
        };

        selector.record_rtt(target, 50, &path);
        selector.record_rtt(target, 60, &path);
        selector.record_rtt(target, 70, &path);

        let rtt = selector.get_direct_rtt(target).unwrap();
        assert_eq!(rtt, 60); // Average of 50, 60, 70
    }

    #[test]
    fn test_circuit_breaker() {
        let mut config = PathConfig::default();
        config.max_failures = 3;
        config.circuit_breaker_secs = 1;
        let selector = PathSelector::with_config(config);
        let target = make_node_id(1);
        let server = make_addr(5000);
        let direct_addr = make_addr(4000);

        // Record 3 failures
        let path = Path::Direct {
            peer_addr: direct_addr,
            rtt_ms: 50,
        };
        selector.record_failure(&path, target);
        selector.record_failure(&path, target);
        selector.record_failure(&path, target);

        // Circuit should be open - should fall back to server relay
        let path = selector.select_path(target, None, server, Some(direct_addr), NatType::Open);
        assert!(matches!(path, Path::ServerRelay { .. }));

        // Wait for circuit breaker to reset
        std::thread::sleep(Duration::from_secs(2));

        // Should try direct again
        let path = selector.select_path(target, None, server, Some(direct_addr), NatType::Open);
        assert!(matches!(path, Path::Direct { .. }));
    }

    #[test]
    fn test_score_path() {
        let selector = PathSelector::new();
        let target = make_node_id(1);

        let direct = Path::Direct {
            peer_addr: make_addr(4000),
            rtt_ms: 30,
        };
        let score = selector.score_path(&direct, target, NatType::Open, 100);
        // base_rtt(30) + relay_penalty(0) + failure_penalty(0) + nat_penalty(0) - bandwidth_bonus(10) = 20
        assert!((score - 20.0).abs() < 1.0);

        let relay = Path::DhtRelay {
            ticket: RelayTicket {
                relay_addr: make_addr(5000),
                latency_ms: 40,
                expires_at: {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    now + 60_000
                },
                relay_pubkey: make_node_id(2),
            },
            relay_addr: make_addr(5000),
            est_rtt_ms: 50,
        };
        let score = selector.score_path(&relay, target, NatType::Open, 100);
        // base_rtt(50) + relay_penalty(50) + failure_penalty(0) + nat_penalty(0) - bandwidth_bonus(10) = 90
        assert!((score - 90.0).abs() < 1.0);

        // With failures
        selector.record_failure(&direct, target);
        selector.record_failure(&direct, target);
        let score = selector.score_path(&direct, target, NatType::Open, 100);
        // base_rtt(30) + relay_penalty(0) + failure_penalty(200) + nat_penalty(0) - bandwidth_bonus(10) = 220
        assert!((score - 220.0).abs() < 1.0);
    }

    #[test]
    fn test_nat_type_penalty() {
        let selector = PathSelector::new();
        let target = make_node_id(1);
        let direct = Path::Direct {
            peer_addr: make_addr(4000),
            rtt_ms: 30,
        };

        let score_open = selector.score_path(&direct, target, NatType::Open, 0);
        let score_symmetric = selector.score_path(&direct, target, NatType::Symmetric, 0);

        // Symmetric should have 50ms more penalty
        assert!((score_symmetric - score_open - 50.0).abs() < 1.0);
    }

    #[test]
    fn test_clear_target() {
        let selector = PathSelector::new();
        let target = make_node_id(1);
        let direct_addr = make_addr(4000);

        selector.record_rtt(target, 50, &Path::Direct { peer_addr: direct_addr, rtt_ms: 50 });
        selector.record_failure(&Path::Direct { peer_addr: direct_addr, rtt_ms: 50 }, target);

        selector.clear_target(target);

        assert!(selector.get_direct_rtt(target).is_none());
        assert_eq!(selector.failure_count(&Path::Direct { peer_addr: direct_addr, rtt_ms: 50 }, target), 0);
    }

    #[test]
    fn test_relay_ticket_expiry() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let ticket = RelayTicket {
            relay_addr: make_addr(5000),
            latency_ms: 40,
            expires_at: now + 10,
            relay_pubkey: make_node_id(2),
        };

        assert!(ticket.is_valid());
        std::thread::sleep(Duration::from_millis(20));
        assert!(!ticket.is_valid());
    }
}