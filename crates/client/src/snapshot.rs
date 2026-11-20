//! Сериализуемый снимок состояния движка (PLAN 7.1): то, что `EngineApi::snapshot`
//! отдаёт фронтенду и что демон шлёт по IPC (7.3).
//!
//! Вместо `Instant` — длительности относительно момента снимка (`*_ago`,
//! `uptime_s`), вместо атомиков — числа. В `CfgView` нет identity: секреты
//! не покидают движок. Конструкторы `from_*` строят снимок из внутренних
//! структур движка (`GroupSess`, `Meta`, `Stats`, `Config`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tunnel_protocol::payloads;

use crate::engine::{GroupSess, Meta, PeerSess, Stats};
use crate::invites::Invite;
use crate::path::{PathKind, PathTable};
use crate::store::Config;

/// Полный снимок.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    /// Группы, в которых состоим, по возрастанию gid.
    pub groups: Vec<GroupSnap>,
    pub meta: MetaSnap,
    pub stats: StatsSnap,
    pub cfg: CfgView,
    /// Неотвеченные приглашения (см. `invites::PendingInvites::list`).
    pub pending_invites: Vec<Invite>,
}

/// Участник группы.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerSnap {
    pub pubkey: [u8; 32],
    pub name: String,
    pub status: String,
    pub online: bool,
    pub ip: u32,
    /// Адрес пира (`ip:port`), если известен.
    pub endpoint: Option<String>,
    pub direct: bool,
    /// Сколько миллисекунд назад от него что-то пришло.
    pub last_rx_ms_ago: u64,
    /// Последний фрейм напрямую (не через релей), мс назад.
    pub last_direct_ms_ago: Option<u64>,
    pub rtt_ms: Option<u64>,
    /// Выбранный путь доставки (этап 9): прямой / сервер / через пира.
    /// `None` — пути ещё нет (не было пересчёта).
    #[serde(default)]
    pub path: Option<PathSnap>,
}

/// Путь доставки в снимке: вид, RTT и (для реле) ключ пира.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathSnap {
    pub kind: PathKind,
    /// Измеренный RTT выбранного пути (у сервера может быть неизвестен).
    #[serde(default)]
    pub rtt_ms: Option<u64>,
}

impl PeerSnap {
    pub fn from_sess(p: &PeerSess, paths: &PathTable, now: Instant) -> Self {
        let path = paths.current(p.ip).map(|kind| PathSnap {
            kind,
            rtt_ms: paths.current_rtt(p.ip).map(u64::from),
        });
        Self {
            pubkey: p.pubkey,
            name: p.name.clone(),
            status: p.status.clone(),
            online: p.online,
            ip: p.ip,
            endpoint: p.endpoint.map(|a| a.to_string()),
            direct: p.direct(),
            last_rx_ms_ago: ms_ago(p.last_rx, now),
            last_direct_ms_ago: p.last_direct.map(|t| ms_ago(t, now)),
            rtt_ms: p.rtt_ms,
            path,
        }
    }
}

/// Группа, в которой состоим. Ключа группы в снимке нет.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSnap {
    pub gid: u32,
    pub name: String,
    pub owner: [u8; 32],
    pub private: bool,
    pub my_ip: u32,
    /// Сколько секунд мы в группе.
    pub joined_s_ago: u64,
    /// Участники по возрастанию IP.
    pub members: Vec<PeerSnap>,
}

impl GroupSnap {
    pub fn from_sess(gid: u32, g: &GroupSess, paths: &PathTable, now: Instant) -> Self {
        let mut members: Vec<PeerSnap> = g
            .members
            .values()
            .map(|p| PeerSnap::from_sess(p, paths, now))
            .collect();
        members.sort_by_key(|p| p.ip);
        Self {
            gid,
            name: g.name.clone(),
            owner: g.owner,
            private: g.private,
            my_ip: g.my_ip,
            joined_s_ago: now.saturating_duration_since(g.since).as_secs(),
            members,
        }
    }

    /// Все группы движка, по возрастанию gid.
    pub fn from_groups(
        groups: &HashMap<u32, GroupSess>,
        paths: &PathTable,
        now: Instant,
    ) -> Vec<Self> {
        let mut v: Vec<Self> = groups
            .iter()
            .map(|(gid, g)| Self::from_sess(*gid, g, paths, now))
            .collect();
        v.sort_by_key(|g| g.gid);
        v
    }
}

/// Строка списка групп сервера (`GROUP_LIST`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSummarySnap {
    pub gid: u32,
    pub name: String,
    pub private: bool,
    pub mine: bool,
    pub online: u32,
    pub total: u32,
}

impl From<&payloads::GroupSummary> for GroupSummarySnap {
    fn from(s: &payloads::GroupSummary) -> Self {
        Self {
            gid: s.gid,
            name: s.name.clone(),
            private: s.private,
            mine: s.mine,
            online: s.online,
            total: s.total,
        }
    }
}

/// Метаданные статус-бара.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MetaSnap {
    pub connected: bool,
    /// Адрес текущего сервера (`ip:port`).
    pub server: String,
    pub server_label: String,
    pub group_list: Vec<GroupSummarySnap>,
    /// Байт/с по последним секундам (для спарклайна), старые — первыми.
    pub rx_hist: Vec<u64>,
    pub tx_hist: Vec<u64>,
    /// Сколько секунд работает движок.
    pub uptime_s: u64,
    /// RTT до сервера по CTRL_PONG с меткой (`None` — ещё не измерен или
    /// старый сервер без метки).
    #[serde(default)]
    pub server_rtt_ms: Option<u32>,
    /// Mesh включён клиентом (`Config.mesh.enabled`).
    #[serde(default)]
    pub mesh_enabled: bool,
    /// Сколько байт этот клиент отрелеил через mesh (T3).
    #[serde(default)]
    pub relay_bytes: u64,
    /// Движка нет: TUI работает офлайн (демон без движка, демона нет).
    /// Правки конфига при этом сохраняются, сетевые команды — отказ.
    #[serde(default)]
    pub offline: bool,
    /// Почему движка нет: причина для шапки/лога (`{"engine": null, "error"}`).
    #[serde(default)]
    pub offline_reason: Option<String>,
    /// Сколько правок TUI ждёт применения на демоне (очередь
    /// `ui-pending.json` офлайн-режима).
    #[serde(default)]
    pub pending_edits: u32,
}

impl MetaSnap {
    pub fn from_meta(m: &Meta, now: Instant) -> Self {
        Self {
            connected: m.connected,
            server: m.server.to_string(),
            server_label: m.server_label.clone(),
            group_list: m.group_list.iter().map(Into::into).collect(),
            rx_hist: m.rx_hist.iter().copied().collect(),
            tx_hist: m.tx_hist.iter().copied().collect(),
            uptime_s: now.saturating_duration_since(m.started).as_secs(),
            server_rtt_ms: m.server_rtt_ms,
            mesh_enabled: m.mesh_enabled,
            relay_bytes: m.relay_bytes,
            ..MetaSnap::default()
        }
    }
}

/// Счётчики трафика.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StatsSnap {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_pkts: u64,
    pub tx_pkts: u64,
}

impl StatsSnap {
    pub fn from_stats(s: &Stats) -> Self {
        Self {
            rx_bytes: s.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: s.tx_bytes.load(Ordering::Relaxed),
            rx_pkts: s.rx_pkts.load(Ordering::Relaxed),
            tx_pkts: s.tx_pkts.load(Ordering::Relaxed),
        }
    }
}

/// Сервер из конфига.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfgServer {
    pub addr: String,
    /// hex ed25519 pubkey сервера.
    pub pubkey: String,
    pub label: String,
}

/// Друг из конфига.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfgFriend {
    /// hex pubkey.
    pub pubkey: String,
    pub alias: String,
}

/// Конфиг без identity: имя, статус, серверы, друзья, автовход.
/// Тема — локальная настройка фронтенда, в снимок не входит.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CfgView {
    pub name: String,
    pub status: String,
    pub servers: Vec<CfgServer>,
    pub friends: Vec<CfgFriend>,
    pub autojoin: Vec<u32>,
    /// Невидимка (`Cmd::SetInvisible`).
    #[serde(default)]
    pub invisible: bool,
    /// Mesh включён (этап 9).
    #[serde(default)]
    pub mesh_enabled: bool,
    /// Релей через пиров разрешён.
    #[serde(default)]
    pub relay_enabled: bool,
    /// Лимит отдачи реле, кбит/с.
    #[serde(default)]
    pub relay_budget_kbps: u32,
    /// Ручные закрепления путей (`"<ip>" → "direct"|"server"|"relay:<hex>"`).
    #[serde(default)]
    pub pinned_paths: std::collections::BTreeMap<String, String>,
}

impl CfgView {
    pub fn from_cfg(c: &Config) -> Self {
        Self {
            name: c.name.clone(),
            status: c.status.clone(),
            servers: c
                .servers
                .iter()
                .map(|s| CfgServer {
                    addr: s.addr.clone(),
                    pubkey: s.pubkey.clone(),
                    label: s.label.clone(),
                })
                .collect(),
            friends: c
                .friends
                .iter()
                .map(|f| CfgFriend {
                    pubkey: f.pubkey.clone(),
                    alias: f.alias.clone(),
                })
                .collect(),
            autojoin: c.autojoin.clone(),
            invisible: c.invisible,
            mesh_enabled: c.mesh.enabled,
            relay_enabled: c.mesh.relay_enabled,
            relay_budget_kbps: c.mesh.relay_budget_kbps,
            pinned_paths: c.pinned_paths.clone(),
        }
    }

    /// Обратно в `Config` (без identity и локальных настроек): чтобы
    /// фронтенд разбирал peer/друга/сервер теми же функциями, что CLI
    /// (`store::resolve_peer` и т.п.).
    pub fn to_config(&self) -> Config {
        Config {
            name: self.name.clone(),
            status: self.status.clone(),
            servers: self
                .servers
                .iter()
                .map(|s| crate::store::StoredServer {
                    addr: s.addr.clone(),
                    pubkey: s.pubkey.clone(),
                    label: s.label.clone(),
                })
                .collect(),
            friends: self
                .friends
                .iter()
                .map(|f| crate::store::StoredFriend {
                    pubkey: f.pubkey.clone(),
                    alias: f.alias.clone(),
                })
                .collect(),
            autojoin: self.autojoin.clone(),
            invisible: self.invisible,
            mesh: crate::store::MeshConfig {
                enabled: self.mesh_enabled,
                relay_enabled: self.relay_enabled,
                relay_budget_kbps: self.relay_budget_kbps,
                ..Default::default()
            },
            pinned_paths: self.pinned_paths.clone(),
            ..Config::default()
        }
    }
}

fn ms_ago(t: Instant, now: Instant) -> u64 {
    now.saturating_duration_since(t).as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{StoredFriend, StoredIdentity, StoredServer};
    use std::time::Duration;

    fn sample() -> Snapshot {
        Snapshot {
            groups: vec![GroupSnap {
                gid: 7,
                name: "игра".into(),
                owner: [9; 32],
                private: true,
                my_ip: 0x0A00_0002,
                joined_s_ago: 42,
                members: vec![PeerSnap {
                    pubkey: [1; 32],
                    name: "bravo".into(),
                    status: "тут".into(),
                    online: true,
                    ip: 0x0A00_0003,
                    endpoint: Some("1.2.3.4:5000".into()),
                    direct: true,
                    last_rx_ms_ago: 120,
                    last_direct_ms_ago: None,
                    rtt_ms: Some(33),
                    path: Some(PathSnap {
                        kind: PathKind::Direct,
                        rtt_ms: Some(33),
                    }),
                }],
            }],
            meta: MetaSnap {
                connected: true,
                server: "5.6.7.8:9000".into(),
                server_label: "дом".into(),
                group_list: vec![GroupSummarySnap {
                    gid: 7,
                    name: "игра".into(),
                    private: true,
                    mine: false,
                    online: 2,
                    total: 3,
                }],
                rx_hist: vec![1, 2, 3],
                tx_hist: vec![4, 5],
                uptime_s: 3600,
                server_rtt_ms: Some(48),
                mesh_enabled: true,
                relay_bytes: 1024,
                ..MetaSnap::default()
            },
            stats: StatsSnap {
                rx_bytes: 10,
                tx_bytes: 20,
                rx_pkts: 1,
                tx_pkts: 2,
            },
            cfg: CfgView {
                name: "alpha".into(),
                status: String::new(),
                servers: vec![CfgServer {
                    addr: "5.6.7.8:9000".into(),
                    pubkey: "ab".repeat(32),
                    label: "дом".into(),
                }],
                friends: vec![CfgFriend {
                    pubkey: "cd".repeat(32),
                    alias: "bravo".into(),
                }],
                autojoin: vec![7],
                invisible: true,
                mesh_enabled: true,
                relay_enabled: false,
                relay_budget_kbps: 4096,
                pinned_paths: std::collections::BTreeMap::from([(
                    "100.66.0.2".to_string(),
                    "server".to_string(),
                )]),
            },
            pending_invites: vec![Invite {
                gid: 11,
                group_name: "чат".into(),
                from_pubkey: [3; 32],
                from_name: "charlie".into(),
                received_ms_ago: 1500,
                expires_in_s: Some(604_800),
            }],
        }
    }

    #[test]
    fn json_туда_и_обратно() {
        let s = sample();
        let json = serde_json::to_string(&s).unwrap();
        let back: Snapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
        let empty = Snapshot::default();
        let back: Snapshot = serde_json::from_str(&serde_json::to_string(&empty).unwrap()).unwrap();
        assert_eq!(back, empty);
    }

    #[test]
    fn cfg_view_без_identity() {
        let cfg = Config {
            identity: Some(StoredIdentity {
                ed_seed: "секрет-ed".into(),
                x_seed: "секрет-x".into(),
            }),
            name: "alpha".into(),
            status: "st".into(),
            servers: vec![StoredServer {
                addr: "a:1".into(),
                pubkey: "pk".into(),
                label: "l".into(),
            }],
            friends: vec![StoredFriend {
                pubkey: "fp".into(),
                alias: "f".into(),
            }],
            autojoin: vec![1, 2],
            theme: "dark".into(),
            ..Config::default()
        };
        let v = CfgView::from_cfg(&cfg);
        assert_eq!(v.name, "alpha");
        assert_eq!(v.servers[0].label, "l");
        assert_eq!(v.friends[0].alias, "f");
        assert_eq!(v.autojoin, vec![1, 2]);
        let json = serde_json::to_string(&v).unwrap();
        assert!(!json.contains("секрет"), "identity утекла в снимок: {json}");
    }

    #[test]
    fn длительности_вместо_instant() {
        let base = Instant::now();
        let now = base + Duration::from_secs(10);
        let peer = PeerSess {
            pubkey: [1; 32],
            name: "b".into(),
            status: String::new(),
            online: true,
            ip: 5,
            endpoint: Some("1.2.3.4:5".parse().unwrap()),
            candidates: Vec::new(),
            direct_addr: None,
            last_rx: base + Duration::from_millis(9_750),
            last_direct: Some(base),
            rtt_ms: None,
            mesh_x: None,
            mesh_caps: 0,
        };
        let paths = PathTable::empty();
        let p = PeerSnap::from_sess(&peer, &paths, now);
        assert_eq!(p.last_rx_ms_ago, 250);
        assert_eq!(p.last_direct_ms_ago, Some(10_000));
        assert_eq!(p.endpoint.as_deref(), Some("1.2.3.4:5"));
        // Момент в будущем (гонка часов) — ноль, а не паника.
        assert_eq!(ms_ago(now + Duration::from_secs(1), now), 0);
    }
}
