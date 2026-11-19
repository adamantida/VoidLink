//! Kademlia-style DHT для peer discovery и relay routing.
//!
//! Реализует:
//! - XOR distance metric (Kademlia)
//! - K-buckets с K=16, 256 buckets
//! - UDP wire messages (bincode serialized)
//! - Bootstrap, periodic refresh, persistent state
//! - Token-based DoS protection (PING/PONG)
//! - Relay ticket validation (ed25519 signature, expiry, capacity)

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail, ensure};
use bincode;
use blake3;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteArray;

use crate::Identity;

/// Node ID = ed25519 public key (32 bytes)
pub type NodeId = [u8; 32];

/// Kademlia K parameter: max nodes per bucket
pub const K: usize = 16;
/// Number of buckets (256 for 256-bit IDs)
pub const NUM_BUCKETS: usize = 256;
/// Bucket refresh interval
pub const BUCKET_REFRESH_INTERVAL: Duration = Duration::from_secs(3600); // 1 hour
/// Token lifetime for PING/PONG
pub const TOKEN_TTL: Duration = Duration::from_secs(600); // 10 minutes
/// Max pending FIND_NODE requests
pub const MAX_PENDING_LOOKUPS: usize = 32;
/// State file name
pub const STATE_FILE: &str = "dht_state.bin";

/// DHT frame magic bytes
pub const DHT_MAGIC: [u8; 4] = *b"DHT1";
/// DHT frame type byte
pub const DHT_FRAME_TYPE: u8 = 0x17;

/// Result of a FindValue query
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueResult {
    Found(RelayTicket),
    Nodes(Vec<NodeContact>),
}

/// Encode a DHT message into a UDP frame (magic + type + bincode payload)
pub fn encode_dht_frame(msg: &DhtMessage) -> Vec<u8> {
    let payload = bincode::serialize(msg).expect("encode DhtMessage");
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.extend_from_slice(&DHT_MAGIC);
    frame.push(DHT_FRAME_TYPE);
    frame.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    frame.extend_from_slice(&payload);
    frame
}

/// Decode a DHT frame into a message
pub fn decode_dht_frame(bytes: &[u8]) -> Result<DhtMessage> {
    ensure!(bytes.len() >= 7, "DHT frame too short");
    ensure!(bytes[..4] == DHT_MAGIC, "bad DHT magic");
    ensure!(bytes[4] == DHT_FRAME_TYPE, "bad DHT frame type");
    let len = u16::from_le_bytes([bytes[5], bytes[6]]) as usize;
    let payload = &bytes[7..];
    ensure!(payload.len() == len, "DHT frame length mismatch");
    bincode::deserialize(payload).map_err(|e| anyhow!("decode DhtMessage: {}", e))
}

/// Encode a DHT message for UDP sending (alias for encode_dht_frame)
pub fn encode_dht_msg(msg: &DhtMessage) -> Vec<u8> {
    encode_dht_frame(msg)
}

/// Decode a DHT message from UDP payload (alias for decode_dht_frame)
pub fn decode_dht_msg(bytes: &[u8]) -> Result<DhtMessage> {
    decode_dht_frame(bytes)
}

/// Serialize [u8; 64] as bytes
fn serialize_signature<S>(sig: &[u8; 64], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_bytes(sig)
}

/// Deserialize [u8; 64] from bytes
fn deserialize_signature<'de, D>(deserializer: D) -> std::result::Result<[u8; 64], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes = ByteArray::<64>::deserialize(deserializer)?;
    Ok(*bytes)
}

/// Distance metric: XOR distance (Kademlia)
/// Returns a 32-byte array where each byte is a XOR b
pub fn distance(a: &NodeId, b: &NodeId) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Leading zeros in distance (0..=256), used as bucket index
/// bucket = leading_zeros(distance) = floor(log2(1/distance))
pub fn bucket_index(a: &NodeId, b: &NodeId) -> usize {
    let dist = distance(a, b);
    let mut leading = 0;
    for &byte in &dist {
        if byte == 0 {
            leading += 8;
        } else {
            leading += byte.leading_zeros() as usize;
            break;
        }
    }
    leading.min(NUM_BUCKETS - 1)
}

/// Current unix timestamp in seconds
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Relay ticket: signed proof of relay capacity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayTicket {
    pub node_id: NodeId,
    pub capacity_mbps: u32,
    pub expires_at: u64,       // unix timestamp
    #[serde(serialize_with = "serialize_signature", deserialize_with = "deserialize_signature")]
    pub signature: [u8; 64],   // ed25519 signature by node's ed25519 key
}

impl RelayTicket {
    /// Create a new relay ticket signed by the given identity
    pub fn new(id: &Identity, capacity_mbps: u32, expires_at: u64) -> Self {
        let mut ticket = Self {
            node_id: id.ed_pub(),
            capacity_mbps,
            expires_at,
            signature: [0u8; 64],
        };
        ticket.signature = id.sign(&ticket.signing_bytes());
        ticket
    }

    /// Bytes that are signed: node_id || capacity_mbps (BE) || expires_at (BE)
    fn signing_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 4 + 8);
        v.extend_from_slice(&self.node_id);
        v.extend_from_slice(&self.capacity_mbps.to_be_bytes());
        v.extend_from_slice(&self.expires_at.to_be_bytes());
        v
    }

    /// Verify the ticket's signature, expiry, and capacity > 0
    pub fn verify(&self) -> Result<()> {
        // Capacity must be > 0
        ensure!(self.capacity_mbps > 0, "relay ticket: capacity must be > 0");

        // Not expired
        let now = unix_now();
        ensure!(self.expires_at > now, "relay ticket: expired at {}", self.expires_at);

        // Verify signature
        let vk = VerifyingKey::from_bytes(&self.node_id)
            .map_err(|_| anyhow!("relay ticket: invalid node_id"))?;
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&self.signing_bytes(), &sig)
            .map_err(|_| anyhow!("relay ticket: invalid signature"))?;

        Ok(())
    }

    /// Hash of the ticket (used as key for STORE/FIND_VALUE)
    pub fn hash(&self) -> [u8; 32] {
        let encoded = bincode::serialize(self).expect("encode relay ticket");
        let mut h = blake3::Hasher::new();
        h.update(b"tunnel/dht/relay_ticket");
        h.update(&encoded);
        *h.finalize().as_bytes()
    }

    /// Time until expiry in seconds (saturating)
    pub fn ttl(&self) -> u64 {
        self.expires_at.saturating_sub(unix_now())
    }
}

/// Node contact info for DHT routing table
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeContact {
    pub id: NodeId,
    pub addr: SocketAddr,      // UDP endpoint
    pub last_seen: u64,        // unix timestamp (SystemTime doesn't impl Serialize)
    pub relay_capacity: u32,   // max relay bandwidth (Mbps)
    pub relay_ticket: Option<RelayTicket>,
}

impl NodeContact {
    /// Create a new contact without relay ticket
    pub fn new(id: NodeId, addr: SocketAddr, relay_capacity: u32) -> Self {
        Self {
            id,
            addr,
            last_seen: unix_now(),
            relay_capacity,
            relay_ticket: None,
        }
    }

    /// Create a contact with relay ticket
    pub fn with_ticket(id: NodeId, addr: SocketAddr, ticket: RelayTicket) -> Self {
        let capacity = ticket.capacity_mbps;
        Self {
            id,
            addr,
            last_seen: unix_now(),
            relay_capacity: capacity,
            relay_ticket: Some(ticket),
        }
    }

    /// Update last_seen to now
    pub fn touch(&mut self) {
        self.last_seen = unix_now();
    }

    /// Check if contact is stale (not seen for > 1 hour)
    pub fn is_stale(&self, max_age: Duration) -> bool {
        let now = unix_now();
        self.last_seen + max_age.as_secs() < now
    }

    /// Distance from this node to target
    pub fn distance_to(&self, target: &NodeId) -> [u8; 32] {
        distance(&self.id, target)
    }

    /// Bucket index for this node relative to target
    pub fn bucket_index_for(&self, target: &NodeId) -> usize {
        bucket_index(&self.id, target)
    }

    /// Serialize NodeContact to bytes for DHT_BOOTSTRAP payload.
    /// Format: id(32) | addr_type(1) | addr(4 or 16) | port(2) | last_seen(8) | tcp_addr_flag(1) | tcp_addr(optional)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 1 + 18 + 8 + 1 + 18);
        v.extend_from_slice(&self.id);
        match self.addr {
            SocketAddr::V4(v4) => {
                v.push(4);
                v.extend_from_slice(&v4.ip().octets());
                v.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                v.push(6);
                v.extend_from_slice(&v6.ip().octets());
                v.extend_from_slice(&v6.port().to_be_bytes());
            }
        }
        v.extend_from_slice(&self.last_seen.to_be_bytes());
        v.push(0); // tcp_addr not used, but kept for compatibility
        v
    }

    /// Deserialize NodeContact from bytes.
    pub fn from_bytes(mut data: &[u8]) -> Result<Self> {
        ensure!(data.len() >= 33, "NodeContact too short");
        let mut id = [0u8; 32];
        id.copy_from_slice(&data[..32]);
        data = &data[32..];

        ensure!(!data.is_empty(), "missing addr type");
        let addr = match data[0] {
            4 => {
                ensure!(data.len() >= 1 + 4 + 2, "IPv4 addr too short");
                let ip = std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&data[1..5])?);
                let port = u16::from_be_bytes(<[u8; 2]>::try_from(&data[5..7])?);
                data = &data[7..];
                SocketAddr::V4(std::net::SocketAddrV4::new(ip, port))
            }
            6 => {
                ensure!(data.len() >= 1 + 16 + 2, "IPv6 addr too short");
                let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&data[1..17])?);
                let port = u16::from_be_bytes(<[u8; 2]>::try_from(&data[17..19])?);
                data = &data[19..];
                SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0))
            }
            _ => anyhow::bail!("invalid addr type"),
        };

        ensure!(data.len() >= 8, "missing last_seen");
        let last_seen = u64::from_be_bytes(<[u8; 8]>::try_from(&data[..8])?);
        data = &data[8..];

        // tcp_addr flag (0 = none, 1 = present)
        let _tcp_addr = if !data.is_empty() && data[0] == 1 {
            data = &data[1..];
            ensure!(!data.is_empty(), "missing tcp addr type");
            match data[0] {
                4 => {
                    ensure!(data.len() >= 1 + 4 + 2, "TCP IPv4 addr too short");
                    let ip = std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&data[1..5])?);
                    let port = u16::from_be_bytes(<[u8; 2]>::try_from(&data[5..7])?);
                    data = &data[7..];
                    Some(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
                }
                6 => {
                    ensure!(data.len() >= 1 + 16 + 2, "TCP IPv6 addr too short");
                    let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&data[1..17])?);
                    let port = u16::from_be_bytes(<[u8; 2]>::try_from(&data[17..19])?);
                    data = &data[19..];
                    Some(SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0)))
                }
                _ => anyhow::bail!("invalid tcp addr type"),
            }
        } else {
            None
        };
        // _tcp_addr intentionally unused for now (reserved for future TCP DHT connections)

        Ok(Self {
            id,
            addr,
            last_seen,
            relay_capacity: 0,
            relay_ticket: None,
        })
    }
}

/// DHT wire messages (UDP, bincode serialized)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhtMessage {
    Ping { from: NodeContact },
    Pong { from: NodeContact, token: u64 },
    FindNode { target: NodeId, from: NodeContact },
    Nodes { closest: Vec<NodeContact>, token: u64 },
    FindValue { key: [u8; 32], from: NodeContact },  // key = relay ticket hash
    Store { key: [u8; 32], value: RelayTicket, from: NodeContact },
    Value { ticket: RelayTicket, token: u64 },
    RelayTicketRequest { requester: NodeContact },
    RelayTicketResponse { ticket: RelayTicket },
}

impl DhtMessage {
    /// Serialize to bytes
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("encode DhtMessage")
    }

    /// Deserialize from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow!("decode DhtMessage: {}", e))
    }
}

/// Token for DoS protection (PING/PONG)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Token(pub u64);

impl Token {
    /// Generate a new random token
    pub fn generate() -> Self {
        Self(rand::random::<u64>())
    }

    /// Check if token is valid (not expired)
    pub fn is_valid(&self, issued_at: u64) -> bool {
        let now = unix_now();
        issued_at + TOKEN_TTL.as_secs() > now
    }
}

/// A K-bucket holding up to K nodes
#[derive(Debug, Clone)]
struct KBucket {
    nodes: VecDeque<NodeContact>,
}

impl KBucket {
    fn new() -> Self {
        Self {
            nodes: VecDeque::with_capacity(K),
        }
    }

    fn len(&self) -> usize {
        self.nodes.len()
    }

    fn is_full(&self) -> bool {
        self.nodes.len() >= K
    }

    /// Add or update a node in the bucket (MRU at front)
    fn add(&mut self, node: NodeContact) -> bool {
        // Check if already exists
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            // Move to front (MRU)
            let mut n = self.nodes.remove(pos).unwrap();
            n.touch();
            self.nodes.push_front(n);
            return true;
        }

        // If full, evict LRU (back) if it's stale, otherwise reject
        if self.is_full() {
            if let Some(lru) = self.nodes.back() {
                if lru.is_stale(Duration::from_secs(3600)) {
                    self.nodes.pop_back();
                } else {
                    return false; // bucket full, LRU not stale
                }
            }
        }

        self.nodes.push_front(node);
        true
    }

    /// Get closest nodes to target (up to count)
    fn closest(&self, target: &NodeId, count: usize) -> Vec<NodeContact> {
        let mut nodes: Vec<_> = self.nodes.iter().cloned().collect();
        nodes.sort_by_key(|n| n.distance_to(target));
        nodes.into_iter().take(count).collect()
    }

    /// Get all nodes in bucket
    fn all(&self) -> Vec<NodeContact> {
        self.nodes.iter().cloned().collect()
    }

    /// Remove a node by ID
    fn remove(&mut self, id: &NodeId) -> bool {
        if let Some(pos) = self.nodes.iter().position(|n| n.id == *id) {
            self.nodes.remove(pos);
            true
        } else {
            false
        }
    }
}

/// Routing table: 256 K-buckets
#[derive(Debug, Clone)]
pub struct RoutingTable {
    buckets: [KBucket; NUM_BUCKETS],
    self_id: NodeId,
}

impl Default for RoutingTable {
    fn default() -> Self {
        // This won't be used directly, but needed for derive on containing structs
        Self::new([0u8; 32])
    }
}

impl RoutingTable {
    pub fn new(self_id: NodeId) -> Self {
        Self {
            buckets: std::array::from_fn(|_| KBucket::new()),
            self_id,
        }
    }

    /// Add or update a contact
    pub fn add(&mut self, contact: NodeContact) -> bool {
        if contact.id == self.self_id {
            return false; // don't add self
        }
        let idx = contact.bucket_index_for(&self.self_id);
        self.buckets[idx].add(contact)
    }

    /// Find closest nodes to target (up to count, default K)
    pub fn find_closest(&self, target: &NodeId, count: usize) -> Vec<NodeContact> {
        let mut results = Vec::new();
        let target_bucket = bucket_index(&self.self_id, target);

        // Search buckets in order of increasing distance
        let mut order: Vec<usize> = (0..NUM_BUCKETS).collect();
        order.sort_by_key(|&i| {
            // XOR distance between bucket midpoint and target
            // Bucket i covers distances with leading_zeros = i
            // Midpoint is roughly 1 << (255 - i)
            i.abs_diff(target_bucket)
        });

        for idx in order {
            let bucket_nodes = self.buckets[idx].closest(target, count.saturating_sub(results.len()));
            results.extend(bucket_nodes);
            if results.len() >= count {
                break;
            }
        }

        results.truncate(count);
        results
    }

    /// Get all known nodes (for persistence/debugging)
    pub fn all_nodes(&self) -> Vec<NodeContact> {
        self.buckets.iter().flat_map(|b| b.all()).collect()
    }

    /// Count total nodes
    pub fn total_nodes(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    /// Get nodes in a specific bucket (for refresh)
    pub fn bucket_nodes(&self, idx: usize) -> Vec<NodeContact> {
        if idx < NUM_BUCKETS {
            self.buckets[idx].all()
        } else {
            vec![]
        }
    }

    /// Remove a node
    pub fn remove(&mut self, id: &NodeId) -> bool {
        let idx = bucket_index(&self.self_id, id);
        self.buckets[idx].remove(id)
    }

    /// Get a random node ID in bucket range (for FIND_NODE refresh)
    pub fn random_id_in_bucket(&self, bucket_idx: usize) -> NodeId {
        let mut id = self.self_id;
        // Bucket idx covers distances with leading_zeros = idx
        // We need a target that falls in this bucket
        // Distance should have idx leading zeros, then a 1
        if bucket_idx < 256 {
            let byte_idx = bucket_idx / 8;
            let bit_idx = bucket_idx % 8;
            if byte_idx < 32 {
                // Set the first differing bit at position bucket_idx
                // This means distance has idx leading zeros
                id[byte_idx] ^= 1 << (7 - bit_idx);
                // Randomize lower bits
                for i in byte_idx + 1..32 {
                    id[i] = rand::random::<u8>();
                }
            }
        }
        id
    }
}

/// Pending FIND_NODE lookup
#[derive(Debug, Clone)]
struct PendingLookup {
    target: NodeId,
    token: Token,
    queried: Vec<NodeId>,
    results: Vec<NodeContact>,
    started_at: u64,
}

/// Persistent DHT state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtState {
    pub nodes: Vec<NodeContact>,
    pub self_id: NodeId,
    pub saved_at: u64,
}

impl DhtState {
    pub fn new(self_id: NodeId, nodes: Vec<NodeContact>) -> Self {
        Self {
            nodes,
            self_id,
            saved_at: unix_now(),
        }
    }
}

/// DHT Node implementation
pub struct DhtNode {
    routing: RoutingTable,
    pending_lookups: Vec<PendingLookup>,
    tokens: Vec<(Token, u64)>, // (token, issued_at)
    self_contact: NodeContact,
    state_path: std::path::PathBuf,
}

impl DhtNode {
    /// Create a new DHT node with the given identity and UDP address
    pub fn new(identity: &Identity, addr: SocketAddr, state_dir: &Path) -> Self {
        let self_id = identity.ed_pub();
        let self_contact = NodeContact::new(self_id, addr, 0); // capacity 0 = not a relay by default
        let state_path = state_dir.join(STATE_FILE);

        Self {
            routing: RoutingTable::new(self_id),
            pending_lookups: Vec::new(),
            tokens: Vec::new(),
            self_contact,
            state_path,
        }
    }

    /// Set relay capacity and generate ticket
    pub fn set_relay_capacity(&mut self, identity: &Identity, capacity_mbps: u32, expires_at: u64) {
        let ticket = RelayTicket::new(identity, capacity_mbps, expires_at);
        self.self_contact = NodeContact::with_ticket(
            self.self_contact.id,
            self.self_contact.addr,
            ticket,
        );
        self.self_contact.relay_capacity = capacity_mbps;
    }

    /// Get self NodeId
    pub fn node_id(&self) -> NodeId {
        self.self_contact.id
    }

    /// Get self contact info
    pub fn self_contact(&self) -> &NodeContact {
        &self.self_contact
    }

    /// Bootstrap from a list of known peers (signed by server)
    pub fn bootstrap(&mut self, peers: Vec<NodeContact>) {
        for peer in peers {
            self.routing.add(peer);
        }
    }

    /// Handle incoming DHT message, return response if any
    pub fn handle_message(&mut self, msg: DhtMessage, from_addr: SocketAddr) -> Option<DhtMessage> {
        match msg {
            DhtMessage::Ping { from } => {
                // Add sender to routing table
                let mut contact = from;
                contact.addr = from_addr; // use actual source address
                self.routing.add(contact.clone());

                // Generate token and respond with PONG
                let token = Token::generate();
                self.tokens.push((token, unix_now()));
                Some(DhtMessage::Pong {
                    from: self.self_contact.clone(),
                    token: token.0,
                })
            }
            DhtMessage::Pong { from, token } => {
                // Verify token
                if let Some(pos) = self.tokens.iter().position(|(t, _)| t.0 == token) {
                    let (_, issued_at) = self.tokens.remove(pos);
                    if Token(token).is_valid(issued_at) {
                        // Add sender to routing table
                        let mut contact = from;
                        contact.addr = from_addr;
                        self.routing.add(contact);
                    }
                }
                None
            }
            DhtMessage::FindNode { target, from } => {
                // Add sender to routing table
                let mut contact = from;
                contact.addr = from_addr;
                self.routing.add(contact);

                // Find closest nodes
                let closest = self.routing.find_closest(&target, K);
                let token = Token::generate();
                self.tokens.push((token, unix_now()));
                Some(DhtMessage::Nodes {
                    closest,
                    token: token.0,
                })
            }
            DhtMessage::Nodes { closest, token } => {
                // Handle response to our FIND_NODE
                if let Some(pos) = self.pending_lookups.iter().position(|l| l.token.0 == token) {
                    let mut lookup = self.pending_lookups.remove(pos);
                    // Add results to routing table
                    for node in &closest {
                        self.routing.add(node.clone());
                    }
                    lookup.results.extend(closest.clone());
                    if let Some(first) = closest.first() {
                        lookup.queried.push(first.id);
                    }
                    // If we got fewer than K nodes, lookup converged
                    if closest.len() < K {
                        // Lookup complete
                    } else {
                        // Continue lookup with next closest unqueried
                        self.continue_lookup(lookup);
                    }
                }
                None
            }
            DhtMessage::FindValue { key, from } => {
                // Add sender
                let mut contact = from;
                contact.addr = from_addr;
                self.routing.add(contact);

                // Check if we have the value (relay ticket)
                if let Some(ticket) = self.self_contact.relay_ticket.as_ref() {
                    if ticket.hash() == key {
                        let token = Token::generate();
                        self.tokens.push((token, unix_now()));
                        return Some(DhtMessage::Value {
                            ticket: ticket.clone(),
                            token: token.0,
                        });
                    }
                }
                // Otherwise return closest nodes (like FIND_NODE)
                let closest = self.routing.find_closest(&NodeId::from(key), K);
                let token = Token::generate();
                self.tokens.push((token, unix_now()));
                Some(DhtMessage::Nodes {
                    closest,
                    token: token.0,
                })
            }
            DhtMessage::Store { key, value, from } => {
                // Add sender
                let mut contact = from;
                contact.addr = from_addr;
                self.routing.add(contact);

                // Verify ticket before storing
                if value.verify().is_ok() && value.hash() == key {
                    // Store in self if it's our ticket
                    if value.node_id == self.self_contact.id {
                        self.self_contact.relay_ticket = Some(value);
                    }
                    // TODO: In full implementation, store for other nodes too
                }
                None
            }
            DhtMessage::Value { ticket: _, token: _ } => {
                // Handle response to FIND_VALUE
                // Ticket validation happens at caller
                None
            }
            DhtMessage::RelayTicketRequest { requester } => {
                // Add requester
                let mut contact = requester;
                contact.addr = from_addr;
                self.routing.add(contact);

                // Respond with our ticket if we have one
                if let Some(ticket) = self.self_contact.relay_ticket.clone() {
                    Some(DhtMessage::RelayTicketResponse { ticket })
                } else {
                    None
                }
            }
            DhtMessage::RelayTicketResponse { ticket: _ } => {
                // Handle response - caller validates
                None
            }
        }
    }

    /// Initiate FIND_NODE lookup for target
    pub fn find_node(&mut self, target: NodeId) -> Vec<NodeContact> {
        // First check local routing table
        let closest = self.routing.find_closest(&target, K);
        if closest.is_empty() {
            return vec![];
        }

        // Start async lookup
        let token = Token::generate();
        self.tokens.push((token, unix_now()));
        let lookup = PendingLookup {
            target,
            token,
            queried: vec![],
            results: closest.clone(),
            started_at: unix_now(),
        };
        self.pending_lookups.push(lookup);

        // Return immediate local results
        closest
    }

    /// Continue a pending lookup
    fn continue_lookup(&mut self, mut lookup: PendingLookup) {
        // Find next unqueried closest node
        for node in &lookup.results {
            if !lookup.queried.contains(&node.id) {
                lookup.queried.push(node.id);
                self.pending_lookups.push(lookup);
                return;
            }
        }
        // No more nodes to query - lookup converged
    }

    /// Periodic maintenance: refresh buckets, expire tokens/lookups
    pub fn maintain(&mut self) {
        let now = unix_now();

        // Expire old tokens
        self.tokens.retain(|(t, issued)| t.is_valid(*issued));

        // Expire old lookups (> 30 seconds)
        self.pending_lookups.retain(|l| now - l.started_at < 30);

        // Refresh stale buckets (pick random bucket, do FIND_NODE)
        // In a real implementation, this would send UDP packets
        // Here we just mark which buckets need refresh
    }

    /// Get buckets that need refresh (empty or stale)
    pub fn buckets_needing_refresh(&self) -> Vec<usize> {
        (0..NUM_BUCKETS)
            .filter(|&i| self.routing.buckets[i].len() == 0)
            .collect()
    }

    /// Save state to disk
    pub fn save(&self) -> Result<()> {
        let state = DhtState::new(self.self_contact.id, self.routing.all_nodes());
        let encoded = bincode::serialize(&state)?;
        std::fs::write(&self.state_path, encoded)?;
        Ok(())
    }

    /// Load state from disk
    pub fn load(&mut self) -> Result<()> {
        if !self.state_path.exists() {
            return Ok(());
        }
        let data = std::fs::read(&self.state_path)?;
        let state: DhtState = bincode::deserialize(&data)
            .map_err(|e| anyhow!("decode state: {}", e))?;
        if state.self_id != self.self_contact.id {
            bail!("state self_id mismatch");
        }
        for node in state.nodes {
            self.routing.add(node);
        }
        Ok(())
    }

    /// Get all known relay tickets (for relay selection)
    pub fn known_relays(&self) -> Vec<RelayTicket> {
        self.routing
            .all_nodes()
            .into_iter()
            .filter_map(|n| n.relay_ticket)
            .filter(|t| t.verify().is_ok())
            .collect()
    }

    /// Select best relay for a target (closest with sufficient capacity)
    pub fn select_relay(&self, target: &NodeId, min_capacity_mbps: u32) -> Option<NodeContact> {
        self.routing
            .all_nodes()
            .into_iter()
            .filter(|n| n.relay_capacity >= min_capacity_mbps)
            .filter(|n| n.relay_ticket.as_ref().map(|t| t.verify().is_ok()).unwrap_or(false))
            .min_by_key(|n| n.distance_to(target))
    }

    /// Total known nodes
    pub fn node_count(&self) -> usize {
        self.routing.total_nodes()
    }

    /// Get known nodes for persistence (up to limit)
    pub fn known_nodes(&self, limit: usize) -> Vec<NodeContact> {
        let mut nodes = self.routing.all_nodes();
        nodes.truncate(limit);
        nodes
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    fn random_id() -> NodeId {
        let mut id = [0u8; 32];
        rand::rng().fill_bytes(&mut id);
        id
    }

    #[test]
    fn test_distance_metric() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        let d = distance(&a, &b);
        assert_eq!(d, [0u8; 32], "distance to self is zero");

        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[31] = 1;
        let d = distance(&a, &b);
        assert_eq!(d[31], 1, "distance is XOR");
        for i in 0..31 {
            assert_eq!(d[i], 0);
        }

        // Symmetry
        let a = random_id();
        let b = random_id();
        assert_eq!(distance(&a, &b), distance(&b, &a), "distance is symmetric");

        // Triangle inequality doesn't hold for XOR, but identity holds
        assert_eq!(distance(&a, &a), [0u8; 32]);
    }

    #[test]
    fn test_bucket_splitting() {
        let self_id = [0xFFu8; 32]; // All 1s
        let mut table = RoutingTable::new(self_id);

        // Add 20 nodes that all fall in bucket 0 (distance has 0 leading zeros)
        // Using node_id = [0x00u8; 32] gives distance = [0xFFu8; 32] which has 0 leading zeros
        for i in 0..20 {
            let mut id = [0x00u8; 32]; // Distance = 0xFF (leading zeros = 0) -> bucket 0
            id[31] = i as u8;
            let contact = NodeContact::new(id, test_addr(10000 + i as u16), 0);
            let added = table.add(contact);
            if i < K {
                assert!(added, "first {K} should be added");
            } else {
                assert!(!added, "bucket full, should reject");
            }
        }

        assert_eq!(table.buckets[0].len(), K);
        assert_eq!(table.total_nodes(), K);
    }

    #[test]
    fn test_bucket_index_calculation() {
        let a = [0x00u8; 32];
        let b = [0x00u8; 32];
        assert_eq!(bucket_index(&a, &b), 255, "identical IDs -> bucket 255");

        let a = [0x00u8; 32];
        let b = [0x80u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(bucket_index(&a, &b), 0, "MSB differs -> bucket 0");

        let a = [0x00u8; 32];
        let b = [0x01u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(bucket_index(&a, &b), 7, "bit 7 differs -> bucket 7");
    }

    #[test]
    fn test_lookup_convergence() {
        let identity = Identity::generate();
        let mut node = DhtNode::new(&identity, test_addr(10000), std::path::Path::new("."));

        // Add some peers
        for i in 0..10 {
            let mut id = identity.ed_pub();
            id[31] = i as u8;
            let contact = NodeContact::new(id, test_addr(20000 + i as u16), 100);
            node.routing.add(contact);
        }

        let target = random_id();
        let results = node.find_node(target);

        // Should return up to K closest nodes
        assert!(results.len() <= K);

        // Results should be sorted by distance
        for i in 1..results.len() {
            let d1 = distance(&results[i-1].id, &target);
            let d2 = distance(&results[i].id, &target);
            // Compare as big-endian integers
            assert!(d1 <= d2, "results not sorted by distance");
        }
    }

    #[test]
    fn test_relay_ticket_validation() {
        let identity = Identity::generate();
        let now = unix_now();

        // Valid ticket
        let ticket = RelayTicket::new(&identity, 100, now + 3600);
        assert!(ticket.verify().is_ok());
        assert!(ticket.capacity_mbps == 100);
        assert!(ticket.ttl() > 0);

        // Expired ticket
        let expired = RelayTicket::new(&identity, 100, now - 1);
        assert!(expired.verify().is_err());

        // Zero capacity
        let zero_cap = RelayTicket::new(&identity, 0, now + 3600);
        assert!(zero_cap.verify().is_err());

        // Bad signature
        let ticket2 = RelayTicket::new(&identity, 100, now + 3600);
        let mut bad_sig = ticket2.clone();
        bad_sig.signature[0] ^= 1;
        assert!(bad_sig.verify().is_err());

        // Wrong node_id
        let mut wrong_id = ticket2;
        wrong_id.node_id = [1u8; 32];
        assert!(wrong_id.verify().is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let identity = Identity::generate();
        let ticket = RelayTicket::new(&identity, 100, unix_now() + 3600);
        let contact = NodeContact::with_ticket(identity.ed_pub(), test_addr(10000), ticket.clone());

        // Test RelayTicket
        let encoded = bincode::serialize(&ticket).unwrap();
        let decoded: RelayTicket = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, ticket);

        // Test NodeContact
        let encoded = bincode::serialize(&contact).unwrap();
        let decoded: NodeContact = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.id, contact.id);
        assert_eq!(decoded.addr, contact.addr);
        assert_eq!(decoded.relay_capacity, contact.relay_capacity);
        assert_eq!(decoded.relay_ticket, contact.relay_ticket);

        // Test DhtMessage
        let msg = DhtMessage::Ping { from: contact.clone() };
        let encoded = msg.encode();
        let decoded = DhtMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);

        let msg = DhtMessage::FindNode { target: random_id(), from: contact };
        let encoded = msg.encode();
        let decoded = DhtMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);

        let msg = DhtMessage::Nodes { closest: vec![], token: 42 };
        let encoded = msg.encode();
        let decoded = DhtMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_dht_ping_pong() {
        let identity = Identity::generate();
        let mut node = DhtNode::new(&identity, test_addr(10000), std::path::Path::new("."));

        let peer_id = random_id();
        let peer_contact = NodeContact::new(peer_id, test_addr(20000), 0);
        let ping = DhtMessage::Ping { from: peer_contact.clone() };

        // Handle PING -> should respond with PONG
        let response = node.handle_message(ping, test_addr(20000));
        assert!(matches!(response, Some(DhtMessage::Pong { .. })));

        // Peer should be in routing table
        assert_eq!(node.routing.total_nodes(), 1);

        // Handle PONG with valid token
        if let Some(DhtMessage::Pong { from, token }) = response {
            let pong = DhtMessage::Pong { from, token };
            let response2 = node.handle_message(pong, test_addr(20000));
            assert_eq!(response2, None); // No response to PONG
        }
    }

    #[test]
    fn test_dht_find_node() {
        let identity = Identity::generate();
        let mut node = DhtNode::new(&identity, test_addr(10000), std::path::Path::new("."));

        // Add some peers
        for i in 0..5 {
            let mut id = identity.ed_pub();
            id[31] = i as u8;
            let contact = NodeContact::new(id, test_addr(20000 + i as u16), 0);
            node.routing.add(contact);
        }

        let target = random_id();
        let find_node = DhtMessage::FindNode { target, from: node.self_contact().clone() };

        let response = node.handle_message(find_node, test_addr(30000));
        assert!(matches!(response, Some(DhtMessage::Nodes { closest, .. }) if !closest.is_empty()));
    }

    #[test]
    fn test_dht_state_persistence() {
        let identity = Identity::generate();
        let temp_dir = std::env::temp_dir();
        let state_path = temp_dir.join("test_dht_state.bin");

        // Create node and add peers
        {
            let mut node = DhtNode::new(&identity, test_addr(10000), &temp_dir);
            for i in 0..3 {
                let mut id = identity.ed_pub();
                id[31] = i as u8;
                let contact = NodeContact::new(id, test_addr(20000 + i as u16), 100);
                node.routing.add(contact);
            }
            node.save().unwrap();
        }

        // Load into new node
        {
            let mut node = DhtNode::new(&identity, test_addr(10000), &temp_dir);
            node.load().unwrap();
            assert_eq!(node.routing.total_nodes(), 3);
        }

        // Cleanup
        std::fs::remove_file(state_path).ok();
    }

    #[test]
    fn test_relay_ticket_hash() {
        let identity = Identity::generate();
        let ticket = RelayTicket::new(&identity, 100, unix_now() + 3600);
        let _hash = ticket.hash();

        // Same ticket -> same hash
        let ticket2 = RelayTicket::new(&identity, 100, unix_now() + 3600);
        assert_eq!(ticket.hash(), ticket2.hash());

        // Different capacity -> different hash
        let ticket3 = RelayTicket::new(&identity, 200, unix_now() + 3600);
        assert_ne!(ticket.hash(), ticket3.hash());
    }

    #[test]
    fn test_select_relay() {
        let identity = Identity::generate();
        let mut node = DhtNode::new(&identity, test_addr(10000), std::path::Path::new("."));

        let target = random_id();

        // Add relay with high capacity
        let relay_id = random_id();
        let relay_identity = Identity::generate();
        let relay_ticket = RelayTicket::new(&relay_identity, 1000, unix_now() + 3600);
        let relay_contact = NodeContact::with_ticket(relay_id, test_addr(20000), relay_ticket);
        node.routing.add(relay_contact);

        // Add relay with low capacity
        let relay_id2 = random_id();
        let relay_identity2 = Identity::generate();
        let relay_ticket2 = RelayTicket::new(&relay_identity2, 10, unix_now() + 3600);
        let relay_contact2 = NodeContact::with_ticket(relay_id2, test_addr(20001), relay_ticket2);
        node.routing.add(relay_contact2);

        // Select with min 100 Mbps -> should pick first
        let selected = node.select_relay(&target, 100);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().relay_capacity, 1000);

        // Select with min 2000 Mbps -> none
        let selected = node.select_relay(&target, 2000);
        assert!(selected.is_none());
    }
}