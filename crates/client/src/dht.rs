//! DHT client for peer discovery and relay routing.
//!
//! Runs in a dedicated std thread with a blocking UDP socket.
//! Implements Kademlia-style routing with K=16 buckets.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use crossbeam_channel;
use tunnel_protocol as proto;

use proto::dht::{
    bucket_index, decode_dht_frame, distance, encode_dht_frame, DhtMessage,
    NodeContact, NodeId, RelayTicket, ValueResult, K,
};

/// DHT state persisted to disk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistedState {
    /// Known node contacts (for bootstrap on restart).
    peers: Vec<NodeContact>,
    /// Known relay tickets.
    tickets: HashMap<NodeId, RelayTicket>,
    /// Our NodeId.
    our_id: NodeId,
    /// Timestamp of last save.
    saved_at: u64,
}

impl PersistedState {
    fn new(our_id: NodeId) -> Self {
        Self {
            peers: Vec::new(),
            tickets: HashMap::new(),
            our_id,
            saved_at: now_ms(),
        }
    }
}

/// Shared DHT state accessible from both main thread and background thread.
struct DhtShared {
    /// Kademlia buckets: 256 buckets, each holding up to K contacts.
    buckets: [Mutex<Vec<NodeContact>>; 256],
    /// Whether bootstrap has completed.
    bootstrapped: AtomicBool,
    /// Known relay tickets (target NodeId -> ticket).
    known_tickets: Mutex<HashMap<NodeId, RelayTicket>>,
    /// Path to persisted state file.
    state_path: PathBuf,
    /// Shutdown signal.
    shutdown: AtomicBool,
    /// Last persist time.
    last_persist: AtomicU64,
    /// Pending FindValue requests (request_id -> (target, response channel)).
    pending_requests: Mutex<HashMap<u64, (NodeId, crossbeam_channel::Sender<Option<RelayTicket>>)>>,
    /// Request ID counter.
    next_request_id: AtomicU64,
}

/// DHT node running in a background thread.
pub struct DhtNode {
    /// Our NodeId (Ed25519 public key).
    pub our_id: NodeId,
    /// UDP socket for DHT traffic.
    socket: Arc<UdpSocket>,
    /// Shared state.
    shared: Arc<DhtShared>,
    /// Background thread handle.
    thread_handle: Mutex<Option<thread::JoinHandle<()>>>,
}

impl DhtNode {
    /// Create a new DHT node.
    pub fn new(our_id: NodeId, socket: Arc<UdpSocket>, state_path: PathBuf) -> Self {
        // Initialize buckets array
        let buckets: [Mutex<Vec<NodeContact>>; 256] = std::array::from_fn(|_| Mutex::new(Vec::new()));

        let shared = Arc::new(DhtShared {
            buckets,
            bootstrapped: AtomicBool::new(false),
            known_tickets: Mutex::new(HashMap::new()),
            state_path,
            shutdown: AtomicBool::new(false),
            last_persist: AtomicU64::new(0),
            pending_requests: Mutex::new(HashMap::new()),
            next_request_id: AtomicU64::new(1),
        });

        Self {
            our_id,
            socket,
            shared,
            thread_handle: Mutex::new(None),
        }
    }

    /// Start the DHT background thread.
    ///
    /// `bootstrap_peers` - initial peers from server (signed DHT_BOOTSTRAP frame).
    pub fn start(&self, bootstrap_peers: Vec<NodeContact>) {
        // Load persisted state first
        self.load_state();

        // Add bootstrap peers
        for peer in bootstrap_peers {
            self.add_contact(peer);
        }

        let shared = self.shared.clone();
        let socket = self.socket.clone();
        let our_id = self.our_id;

        let handle = thread::Builder::new()
            .name("dht".into())
            .spawn(move || {
                dht_thread_main(socket, our_id, shared)
            })
            .expect("spawn DHT thread");

        *self.thread_handle.lock().unwrap() = Some(handle);
    }

    /// Find a relay ticket for the target peer.
    ///
    /// Returns cached ticket if available and valid, otherwise initiates
    /// a DHT lookup and waits for the result (with timeout).
    pub fn find_relay_ticket(&self, target: NodeId) -> Option<RelayTicket> {
        // Check cache first
        {
            let tickets = self.shared.known_tickets.lock().unwrap();
            if let Some(ticket) = tickets.get(&target) {
                if !ticket.is_expired() {
                    return Some(ticket.clone());
                }
            }
        }

        // Initiate DHT lookup
        let (tx, rx) = crossbeam_channel::bounded(1);
        let request_id = self.shared.next_request_id.fetch_add(1, Ordering::Relaxed);

        {
            let mut pending = self.shared.pending_requests.lock().unwrap();
            pending.insert(request_id, (target, tx));
        }

        // Send FindValue to closest known nodes
        self.send_find_value(target, request_id);

        // Wait for response with timeout
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Some(ticket)) => Some(ticket),
            _ => None,
        }
    }

    /// Get the closest K contacts to a target (for path selection).
    pub fn get_closest_contacts(&self, target: &NodeId, count: usize) -> Vec<NodeContact> {
        let mut candidates = Vec::new();

        // Collect from all buckets
        for bucket in &self.shared.buckets {
            let bucket_contacts = bucket.lock().unwrap();
            candidates.extend(bucket_contacts.iter().cloned());
        }

        // Sort by distance to target
        candidates.sort_by(|a, b| {
            let da = distance(&a.id, target);
            let db = distance(&b.id, target);
            da.cmp(&db)
        });

        candidates.truncate(count);
        candidates
    }

    /// Add a contact to the appropriate bucket.
    pub fn add_contact(&self, contact: NodeContact) {
        if contact.id == self.our_id {
            return; // Don't add ourselves
        }

        let bucket_idx = bucket_index(&self.our_id, &contact.id);
        let mut bucket = self.shared.buckets[bucket_idx].lock().unwrap();

        // Check if already exists
        if let Some(existing) = bucket.iter_mut().find(|c| c.id == contact.id) {
            // Update address and last_seen
            existing.addr = contact.addr;
            existing.tcp_addr = contact.tcp_addr;
            existing.touch();
            return;
        }

        // Add to bucket (evict oldest if full)
        if bucket.len() >= K {
            // Find oldest (by last_seen) and replace
            if let Some(oldest_idx) = bucket
                .iter()
                .enumerate()
                .min_by_key(|(_, c)| c.last_seen)
                .map(|(i, _)| i)
            {
                bucket[oldest_idx] = contact;
            }
        } else {
            bucket.push(contact);
        }
    }

    /// Send FindValue request to closest nodes.
    fn send_find_value(&self, target: NodeId, request_id: u64) {
        let contacts = self.get_closest_contacts(&target, K * 3); // Query more nodes
        if contacts.is_empty() {
            return;
        }

        let from = NodeContact::new(self.our_id, self.socket.local_addr().unwrap());
        let msg = DhtMessage::FindValue {
            from,
            key: target,
            request_id,
        };
        let frame = encode_dht_frame(&msg);

        for contact in contacts {
            let _ = self.socket.send_to(&frame, contact.addr);
        }
    }

    /// Handle incoming DHT message.
    pub fn handle_message(&self, msg: DhtMessage, src: SocketAddr) {
        match msg {
            DhtMessage::Ping { from } => {
                // Respond with Pong
                self.add_contact(from.clone());
                let pong = DhtMessage::Pong {
                    from: NodeContact::new(self.our_id, self.socket.local_addr().unwrap()),
                };
                let frame = encode_dht_frame(&pong);
                let _ = self.socket.send_to(&frame, src);
            }
            DhtMessage::Pong { from } => {
                self.add_contact(from);
            }
            DhtMessage::FindNode { from, target, request_id } => {
                self.add_contact(from.clone());
                // Respond with closest nodes
                let nodes = self.get_closest_contacts(&target, K);
                let resp = DhtMessage::Nodes {
                    from: NodeContact::new(self.our_id, self.socket.local_addr().unwrap()),
                    request_id,
                    nodes,
                };
                let frame = encode_dht_frame(&resp);
                let _ = self.socket.send_to(&frame, src);
            }
            DhtMessage::Nodes { from, request_id, nodes } => {
                self.add_contact(from);
                for node in &nodes {
                    self.add_contact(node.clone());
                }
                // If this was in response to our FindValue, also try those nodes
                self.try_pending_request(request_id, &nodes);
            }
            DhtMessage::FindValue { from, key, request_id } => {
                self.add_contact(from.clone());
                // Check if we have the value
                let tickets = self.shared.known_tickets.lock().unwrap();
                let resp = if let Some(ticket) = tickets.get(&key) {
                    if !ticket.is_expired() {
                        DhtMessage::Value {
                            from: NodeContact::new(self.our_id, self.socket.local_addr().unwrap()),
                            request_id,
                            result: ValueResult::Found(ticket.clone()),
                        }
                    } else {
                        // Expired, return closer nodes
                        let nodes = self.get_closest_contacts(&key, K);
                        DhtMessage::Value {
                            from: NodeContact::new(self.our_id, self.socket.local_addr().unwrap()),
                            request_id,
                            result: ValueResult::Nodes(nodes),
                        }
                    }
                } else {
                    // Don't have it, return closer nodes
                    let nodes = self.get_closest_contacts(&key, K);
                    DhtMessage::Value {
                        from: NodeContact::new(self.our_id, self.socket.local_addr().unwrap()),
                        request_id,
                        result: ValueResult::Nodes(nodes),
                    }
                };
                let frame = encode_dht_frame(&resp);
                let _ = self.socket.send_to(&frame, src);
            }
            DhtMessage::Value { from, request_id, result } => {
                self.add_contact(from);
                match result {
                    ValueResult::Found(ticket) => {
                        // Verify ticket signature
                        if ticket.verify(&ticket.target).is_ok() && !ticket.is_expired() {
                            // Cache it
                            self.shared
                                .known_tickets
                                .lock()
                                .unwrap()
                                .insert(ticket.target, ticket.clone());
                            // Notify waiter
                            self.complete_pending_request(request_id, Some(ticket));
                        }
                    }
                    ValueResult::Nodes(nodes) => {
                        for node in &nodes {
                            self.add_contact(node.clone());
                        }
                        // Try these nodes for pending request
                        self.try_pending_request(request_id, &nodes);
                    }
                }
            }
            DhtMessage::Store { from, key, value, request_id } => {
                self.add_contact(from.clone());
                // Verify and store
                let ok = value.verify(&value.target).is_ok() && !value.is_expired();
                if ok {
                    self.shared.known_tickets.lock().unwrap().insert(key, value);
                }
                let resp = DhtMessage::StoreOk {
                    from: NodeContact::new(self.our_id, self.socket.local_addr().unwrap()),
                    request_id,
                    ok,
                };
                let frame = encode_dht_frame(&resp);
                let _ = self.socket.send_to(&frame, src);
            }
            DhtMessage::StoreOk { .. } => {
                // Store acknowledged, nothing to do
            }
        }
    }

    /// Try to send FindValue to newly discovered nodes for a pending request.
    fn try_pending_request(&self, request_id: u64, nodes: &[NodeContact]) {
        let target = {
            let pending = self.shared.pending_requests.lock().unwrap();
            pending.get(&request_id).map(|(t, _)| *t)
        };
        if let Some(target) = target {
            for node in nodes {
                let from = NodeContact::new(self.our_id, self.socket.local_addr().unwrap());
                let msg = DhtMessage::FindValue {
                    from,
                    key: target,
                    request_id,
                };
                let frame = encode_dht_frame(&msg);
                let _ = self.socket.send_to(&frame, node.addr);
            }
        }
    }

    /// Complete a pending request with a result.
    fn complete_pending_request(&self, request_id: u64, ticket: Option<RelayTicket>) {
        let mut pending = self.shared.pending_requests.lock().unwrap();
        if let Some((_, tx)) = pending.remove(&request_id) {
            let _ = tx.send(ticket);
        }
    }

    /// Persist known peers and tickets to disk.
    fn persist(&self) {
        let mut state = PersistedState::new(self.our_id);

        // Collect all contacts from buckets
        for bucket in &self.shared.buckets {
            let contacts = bucket.lock().unwrap();
            state.peers.extend(contacts.iter().cloned());
        }

        // Collect tickets
        state.tickets = self.shared.known_tickets.lock().unwrap().clone();
        state.saved_at = now_ms();

        // Write atomically
        let tmp_path = self.shared.state_path.with_extension("tmp");
        if let Ok(data) = serde_json::to_vec(&state) {
            let _ = std::fs::write(&tmp_path, data);
            let _ = std::fs::rename(&tmp_path, &self.shared.state_path);
            self.shared.last_persist.store(now_ms(), Ordering::Relaxed);
        }
    }

    /// Load persisted state from disk.
    fn load_state(&self) {
        if let Ok(data) = std::fs::read(&self.shared.state_path) {
            if let Ok(state) = serde_json::from_slice::<PersistedState>(&data) {
                // Verify it's our state
                if state.our_id == self.our_id {
                    // Add peers to buckets
                    for peer in state.peers {
                        self.add_contact(peer);
                    }
                    // Restore tickets (filter expired)
                    let mut tickets = self.shared.known_tickets.lock().unwrap();
                    for (target, ticket) in state.tickets {
                        if !ticket.is_expired() {
                            tickets.insert(target, ticket);
                        }
                    }
                }
            }
        }
    }

    /// Shutdown the DHT node.
    pub fn shutdown(&self) {
        self.shared.shutdown.store(true, Ordering::Relaxed);
        // Persist on shutdown
        self.persist();
        // Wait for thread
        if let Some(handle) = self.thread_handle.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

/// Main DHT thread loop.
fn dht_thread_main(socket: Arc<UdpSocket>, our_id: NodeId, shared: Arc<DhtShared>) {
    // Set socket timeout for periodic wakeups
    socket.set_read_timeout(Some(Duration::from_millis(500))).ok();

    let mut buf = vec![0u8; 65535];
    let mut last_refresh = Instant::now();
    let mut last_persist_check = Instant::now();
    let mut request_id_counter = 1u64;

    // Initial bootstrap if we have peers
    if !shared.bootstrapped.load(Ordering::Relaxed) {
        // Trigger refresh to bootstrap
        last_refresh = Instant::now() - Duration::from_secs(60);
    }

    while !shared.shutdown.load(Ordering::Relaxed) {
        let now = Instant::now();

        // Receive loop
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Ok(msg) = decode_dht_frame(&buf[..n]) {
                    handle_message_inline(
                        &socket,
                        our_id,
                        &shared,
                        msg,
                        src,
                    );
                }
            }
            Err(e) => {
                use std::io::ErrorKind::*;
                match e.kind() {
                    WouldBlock | TimedOut | Interrupted => {}
                    _ => {
                        eprintln!("[dht] recv error: {e}");
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        }

        // Periodic bucket refresh (every 60s)
        if now.duration_since(last_refresh) >= Duration::from_secs(60) {
            refresh_buckets(&socket, our_id, &shared, &mut request_id_counter);
            last_refresh = now;
        }

        // Periodic persist (every 30s or on change)
        if now.duration_since(last_persist_check) >= Duration::from_secs(30) {
            persist_inline(&shared, our_id);
            last_persist_check = now;
        }

        // Clean up expired pending requests
        cleanup_pending_requests(&shared);
    }

    // Final persist on shutdown
    persist_inline(&shared, our_id);
}

/// Inline message handler for the DHT thread.
fn handle_message_inline(
    socket: &UdpSocket,
    our_id: NodeId,
    shared: &Arc<DhtShared>,
    msg: DhtMessage,
    src: SocketAddr,
) {
    match msg {
        DhtMessage::Ping { from } => {
            add_contact_inline(shared, our_id, from.clone());
            let pong = DhtMessage::Pong {
                from: NodeContact::new(our_id, socket.local_addr().unwrap()),
            };
            let frame = encode_dht_frame(&pong);
            let _ = socket.send_to(&frame, src);
        }
        DhtMessage::Pong { from } => {
            add_contact_inline(shared, our_id, from);
        }
        DhtMessage::FindNode { from, target, request_id } => {
            add_contact_inline(shared, our_id, from.clone());
            let nodes = get_closest_contacts_inline(shared, our_id, &target, K);
            let resp = DhtMessage::Nodes {
                from: NodeContact::new(our_id, socket.local_addr().unwrap()),
                request_id,
                nodes,
            };
            let frame = encode_dht_frame(&resp);
            let _ = socket.send_to(&frame, src);
        }
        DhtMessage::Nodes { from, request_id, nodes } => {
            add_contact_inline(shared, our_id, from);
            for node in &nodes {
                add_contact_inline(shared, our_id, node.clone());
            }
            try_pending_request_inline(shared, request_id, &nodes, socket, our_id);
        }
        DhtMessage::FindValue { from, key, request_id } => {
            add_contact_inline(shared, our_id, from.clone());
            let tickets = shared.known_tickets.lock().unwrap();
            let resp = if let Some(ticket) = tickets.get(&key) {
                if !ticket.is_expired() {
                    DhtMessage::Value {
                        from: NodeContact::new(our_id, socket.local_addr().unwrap()),
                        request_id,
                        result: ValueResult::Found(ticket.clone()),
                    }
                } else {
                    let nodes = get_closest_contacts_inline(shared, our_id, &key, K);
                    DhtMessage::Value {
                        from: NodeContact::new(our_id, socket.local_addr().unwrap()),
                        request_id,
                        result: ValueResult::Nodes(nodes),
                    }
                }
            } else {
                let nodes = get_closest_contacts_inline(shared, our_id, &key, K);
                DhtMessage::Value {
                    from: NodeContact::new(our_id, socket.local_addr().unwrap()),
                    request_id,
                    result: ValueResult::Nodes(nodes),
                }
            };
            let frame = encode_dht_frame(&resp);
            let _ = socket.send_to(&frame, src);
        }
        DhtMessage::Value { from, request_id, result } => {
            add_contact_inline(shared, our_id, from);
            match result {
                ValueResult::Found(ticket) => {
                    if ticket.verify(&ticket.target).is_ok() && !ticket.is_expired() {
                        shared.known_tickets.lock().unwrap().insert(ticket.target, ticket.clone());
                        complete_pending_request_inline(shared, request_id, Some(ticket));
                    }
                }
                ValueResult::Nodes(nodes) => {
                    for node in &nodes {
                        add_contact_inline(shared, our_id, node.clone());
                    }
                    try_pending_request_inline(shared, request_id, &nodes, socket, our_id);
                }
            }
        }
        DhtMessage::Store { from, key, value, request_id } => {
            add_contact_inline(shared, our_id, from.clone());
            let ok = value.verify(&value.target).is_ok() && !value.is_expired();
            if ok {
                shared.known_tickets.lock().unwrap().insert(key, value);
            }
            let resp = DhtMessage::StoreOk {
                from: NodeContact::new(our_id, socket.local_addr().unwrap()),
                request_id,
                ok,
            };
            let frame = encode_dht_frame(&resp);
            let _ = socket.send_to(&frame, src);
        }
        DhtMessage::StoreOk { .. } => {}
    }
}

/// Add contact to buckets (inline version).
fn add_contact_inline(shared: &Arc<DhtShared>, our_id: NodeId, contact: NodeContact) {
    if contact.id == our_id {
        return;
    }
    let bucket_idx = bucket_index(&our_id, &contact.id);
    let mut bucket = shared.buckets[bucket_idx].lock().unwrap();
    if let Some(existing) = bucket.iter_mut().find(|c| c.id == contact.id) {
        existing.addr = contact.addr;
        existing.tcp_addr = contact.tcp_addr;
        existing.touch();
        return;
    }
    if bucket.len() >= K {
        if let Some(oldest_idx) = bucket
            .iter()
            .enumerate()
            .min_by_key(|(_, c)| c.last_seen)
            .map(|(i, _)| i)
        {
            bucket[oldest_idx] = contact;
        }
    } else {
        bucket.push(contact);
    }
}

/// Get closest contacts (inline version).
fn get_closest_contacts_inline(
    shared: &Arc<DhtShared>,
    our_id: NodeId,
    target: &NodeId,
    count: usize,
) -> Vec<NodeContact> {
    let mut candidates = Vec::new();
    for bucket in &shared.buckets {
        let contacts = bucket.lock().unwrap();
        candidates.extend(contacts.iter().cloned());
    }
    candidates.sort_by(|a, b| {
        let da = distance(&a.id, target);
        let db = distance(&b.id, target);
        da.cmp(&db)
    });
    candidates.truncate(count);
    candidates
}

/// Try pending request with new nodes (inline version).
fn try_pending_request_inline(
    shared: &Arc<DhtShared>,
    request_id: u64,
    nodes: &[NodeContact],
    socket: &UdpSocket,
    our_id: NodeId,
) {
    let target = {
        let pending = shared.pending_requests.lock().unwrap();
        pending.get(&request_id).map(|(t, _)| *t)
    };
    if let Some(target) = target {
        for node in nodes {
            let from = NodeContact::new(our_id, socket.local_addr().unwrap());
            let msg = DhtMessage::FindValue {
                from,
                key: target,
                request_id,
            };
            let frame = encode_dht_frame(&msg);
            let _ = socket.send_to(&frame, node.addr);
        }
    }
}

/// Complete pending request (inline version).
fn complete_pending_request_inline(
    shared: &Arc<DhtShared>,
    request_id: u64,
    ticket: Option<RelayTicket>,
) {
    let mut pending = shared.pending_requests.lock().unwrap();
    if let Some((_, tx)) = pending.remove(&request_id) {
        let _ = tx.send(ticket);
    }
}

/// Periodic bucket refresh.
fn refresh_buckets(
    socket: &UdpSocket,
    our_id: NodeId,
    shared: &Arc<DhtShared>,
    request_id_counter: &mut u64,
) {
    // If not bootstrapped, try to find nodes close to us (bootstrap)
    if !shared.bootstrapped.load(Ordering::Relaxed) {
        // Generate random target IDs in each bucket range to discover nodes
        for i in 0..256 {
            if i % 16 == 0 {
                // Only sample some buckets to avoid too much traffic
                let mut target = our_id;
                // Set bit at position i to create a target in that bucket
                if i < 256 {
                    let byte_idx = i / 8;
                    let bit_idx = i % 8;
                    target[byte_idx] ^= 1 << (7 - bit_idx);
                }
                let nodes = get_closest_contacts_inline(shared, our_id, &target, K);
                for node in nodes {
                    let from = NodeContact::new(our_id, socket.local_addr().unwrap());
                    let msg = DhtMessage::FindNode {
                        from,
                        target,
                        request_id: *request_id_counter,
                    };
                    let frame = encode_dht_frame(&msg);
                    let _ = socket.send_to(&frame, node.addr);
                }
                *request_id_counter += 1;
            }
        }
        shared.bootstrapped.store(true, Ordering::Relaxed);
    } else {
        // Regular refresh: ping random nodes in each bucket to keep them alive
        for bucket in &shared.buckets {
            let contacts: Vec<NodeContact> = {
                let b = bucket.lock().unwrap();
                b.iter().cloned().collect()
            };
            for contact in contacts {
                if contact.is_stale(Duration::from_secs(300)) {
                    // Ping to verify
                    let from = NodeContact::new(our_id, socket.local_addr().unwrap());
                    let msg = DhtMessage::Ping { from };
                    let frame = encode_dht_frame(&msg);
                    let _ = socket.send_to(&frame, contact.addr);
                }
            }
        }
    }
}

/// Persist state (inline version).
fn persist_inline(shared: &Arc<DhtShared>, our_id: NodeId) {
    let mut state = PersistedState::new(our_id);
    for bucket in &shared.buckets {
        let contacts = bucket.lock().unwrap();
        state.peers.extend(contacts.iter().cloned());
    }
    state.tickets = shared.known_tickets.lock().unwrap().clone();
    state.saved_at = now_ms();

    let tmp_path = shared.state_path.with_extension("tmp");
    if let Ok(data) = serde_json::to_vec(&state) {
        let _ = std::fs::write(&tmp_path, data);
        let _ = std::fs::rename(&tmp_path, &shared.state_path);
        shared.last_persist.store(now_ms(), Ordering::Relaxed);
    }
}

/// Clean up expired pending requests.
fn cleanup_pending_requests(shared: &Arc<DhtShared>) {
    let mut pending = shared.pending_requests.lock().unwrap();
    let tickets = shared.known_tickets.lock().unwrap();
    pending.retain(|_, (target, tx)| {
        // If we have a valid ticket now, complete the request
        if let Some(ticket) = tickets.get(target) {
            if !ticket.is_expired() {
                let _ = tx.send(Some(ticket.clone()));
                return false;
            }
        }
        true
    });
}

/// Current time in milliseconds.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tunnel_protocol::Identity;

    #[test]
    fn dht_node_creation() {
        let id = Identity::generate();
        let our_id = id.ed_pub();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let state_path = PathBuf::from("/tmp/dht_test_state.bin");

        let node = DhtNode::new(our_id, socket, state_path);
        assert_eq!(node.our_id, our_id);
    }

    #[test]
    fn add_contact_and_bucket() {
        let id = Identity::generate();
        let our_id = id.ed_pub();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let state_path = PathBuf::from("/tmp/dht_test_state2.bin");

        let node = DhtNode::new(our_id, socket, state_path);

        let peer_id = [1u8; 32];
        let addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 5555).into();
        let contact = NodeContact::new(peer_id, addr);

        node.add_contact(contact.clone());

        // Verify it's in the right bucket
        let bucket_idx = bucket_index(&our_id, &peer_id);
        let bucket = node.shared.buckets[bucket_idx].lock().unwrap();
        assert_eq!(bucket.len(), 1);
        assert_eq!(bucket[0].id, peer_id);
        assert_eq!(bucket[0].addr, addr);
    }

    #[test]
    fn bucket_eviction() {
        let id = Identity::generate();
        let our_id = id.ed_pub();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let state_path = PathBuf::from("/tmp/dht_test_state3.bin");

        let node = DhtNode::new(our_id, socket, state_path);

        // Fill a bucket beyond K
        let bucket_idx = 0; // Use bucket 0 by crafting IDs with distance 0
        for i in 0..K + 5 {
            let mut peer_id = our_id;
            peer_id[0] = i as u8; // Small distance = bucket 0
            let addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 5555 + i as u16).into();
            let contact = NodeContact::new(peer_id, addr);
            node.add_contact(contact);
        }

        let bucket = node.shared.buckets[bucket_idx].lock().unwrap();
        assert_eq!(bucket.len(), K); // Should not exceed K
    }

    #[test]
    fn find_relay_ticket_not_found() {
        let id = Identity::generate();
        let our_id = id.ed_pub();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let state_path = PathBuf::from("/tmp/dht_test_state4.bin");

        let node = DhtNode::new(our_id, socket, state_path);
        let _handle = node.start(Vec::new());

        let target = [2u8; 32];
        let ticket = node.find_relay_ticket(target);
        assert!(ticket.is_none()); // No peers, no ticket

        node.shutdown();
    }
}