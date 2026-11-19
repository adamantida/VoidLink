//! Шов между фронтендом (TUI, CLI) и движком (PLAN.md 7.1).
//!
//! [`EngineApi`] — всё, что TUI знает о движке: снимок, события, команды и
//! `me`. Две реализации:
//! - [`LocalEngine`] — движок в том же процессе (embedded-режим, `run`, демон);
//! - [`crate::remote::IpcEngine`] — тонкий клиент демона по IPC (7.4).
//!
//! Неотвеченные приглашения ведёт [`PendingInvites`] прямо здесь, по событиям
//! движка: тот же код у embedded-режима и у демона (`EngineBackend` — обёртка
//! над `LocalEngine`), поэтому снимки у них совпадают (7.7).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use tunnel_protocol as proto;

use crate::engine::{self, Cmd, Engine, Event, Groups, Meta, Stats};
use crate::invites::{IncomingInvite, InviteOutcome, PendingInvites};
use crate::snapshot::{CfgView, GroupSnap, MetaSnap, Snapshot, StatsSnap};
use crate::store::Config;

/// Кто я: pubkey и friend code (секретов нет).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Me {
    pub my_pub: [u8; 32],
    pub my_code: String,
}

impl Me {
    /// JSON-форма `Welcome.me` демона: `{"my_pub": hex, "my_code": …}`.
    pub fn to_json(&self) -> Value {
        json!({ "my_pub": proto::hex_of(&self.my_pub), "my_code": self.my_code })
    }

    pub fn from_json(v: &Value) -> Option<Me> {
        let hex = v.get("my_pub")?.as_str()?;
        let my_pub: [u8; 32] = proto::hex_to_bytes(hex).ok()?.try_into().ok()?;
        let my_code = v.get("my_code")?.as_str()?.to_string();
        Some(Me { my_pub, my_code })
    }
}

/// Где работает движок (пометка в шапке TUI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineMode {
    /// В этом процессе (нужны права администратора на TUN).
    Embedded,
    /// В демоне; мы — тонкий клиент по IPC.
    Remote,
}

impl EngineMode {
    pub fn label(self) -> &'static str {
        match self {
            EngineMode::Embedded => "embedded",
            EngineMode::Remote => "демон",
        }
    }
}

/// То, чем фронтенд пользуется вместо `&Engine`.
pub trait EngineApi {
    /// Текущее состояние (кадр не ждёт движок/пайп).
    fn snapshot(&self) -> Arc<Snapshot>;
    /// Накопившиеся события, без блокировки.
    fn poll_events(&self) -> Vec<Event>;
    /// Команда движку. `Err` — отклонена сразу (неверный индекс сервера,
    /// демон недоступен…); результат выполнения приходит событием.
    fn send(&self, cmd: Cmd) -> Result<()>;
    fn me(&self) -> &Me;
    fn mode(&self) -> EngineMode;
    /// Связь с движком потеряна (демон недоступен) — только у IPC.
    fn unavailable(&self) -> bool {
        false
    }
    /// История событий до подключения (кольцо демона) — один раз, для лога
    /// без тостов и окон. У embedded-движка истории нет.
    fn take_history(&self) -> Vec<Event> {
        Vec::new()
    }
    /// Тема — локальная настройка фронтенда, не команда движку.
    fn save_theme(&self, theme: &str) -> Result<()>;
    /// Адаптер и dll embedded-движка (применятся после перезапуска).
    fn save_adapter(&self, name: &str, dll: &str) -> Result<()>;
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Движок в этом процессе. `Sync`: TUI зовёт его из одного потока, демон — из
/// хаба и IPC-потоков.
pub struct LocalEngine {
    groups: Groups,
    meta: Arc<Mutex<Meta>>,
    stats: Arc<Stats>,
    cfg: Arc<Mutex<Config>>,
    me: Me,
    cmds: Mutex<Sender<Cmd>>,
    /// Приёмник событий движка (`Receiver` не `Sync`).
    events: Mutex<Receiver<Event>>,
    invites: Mutex<PendingInvites>,
    changed: AtomicBool,
    /// Сам движок: Drop останавливает его потоки. Поля выше — его клоны.
    engine: Mutex<Engine>,
}

impl LocalEngine {
    /// Обернуть запущенный движок.
    pub fn new(mut eng: Engine) -> Self {
        // Поля из Engine не вынуть (у него есть Drop) — подменяем приёмник
        // событий пустым и забираем настоящий себе.
        let (_dummy_tx, dummy_rx) = std::sync::mpsc::channel();
        let events = std::mem::replace(&mut eng.events, dummy_rx);
        LocalEngine {
            groups: eng.groups.clone(),
            meta: eng.meta.clone(),
            stats: eng.stats.clone(),
            cfg: eng.cfg.clone(),
            me: Me {
                my_pub: eng.my_pub,
                my_code: eng.my_code.clone(),
            },
            cmds: Mutex::new(eng.cmds.clone()),
            events: Mutex::new(events),
            invites: Mutex::new(PendingInvites::new()),
            changed: AtomicBool::new(true),
            engine: Mutex::new(eng),
        }
    }

    /// Снимок по значению (то же, что [`EngineApi::snapshot`]).
    pub fn snapshot_now(&self) -> Snapshot {
        let now = Instant::now();
        let groups = GroupSnap::from_groups(&lock(&self.groups), now);
        let meta = MetaSnap::from_meta(&lock(&self.meta), now);
        let cfg = CfgView::from_cfg(&lock(&self.cfg));
        Snapshot {
            groups,
            meta,
            stats: StatsSnap::from_stats(&self.stats),
            cfg,
            pending_invites: lock(&self.invites).list(now),
        }
    }

    /// Состояние изменилось с прошлого вызова (флаг сбрасывается) — хаб
    /// демона рассылает снимок сразу.
    pub fn changed(&self) -> bool {
        self.changed.swap(false, Ordering::Relaxed)
    }

    /// Сам движок (тесты, `local_addr`, `send_ip_packet`).
    pub fn engine(&self) -> MutexGuard<'_, Engine> {
        lock(&self.engine)
    }

    /// Событие → список приглашений; `false` — событие подавить (запоздавшее
    /// приглашение, которое мы только что отклонили).
    fn track(inv: &mut PendingInvites, ev: &Event, now: Instant) -> bool {
        match ev {
            Event::Invite {
                gid,
                group_name,
                from_pubkey,
                from_name,
                expires_in,
            } => {
                let i = IncomingInvite {
                    gid: *gid,
                    group_name: group_name.clone(),
                    from_pubkey: *from_pubkey,
                    from_name: from_name.clone(),
                    expires_in: Some(*expires_in),
                };
                return inv.on_invite(i, now) != InviteOutcome::Declined;
            }
            Event::InvitesSynced {
                gids,
                from,
                complete,
            } => {
                inv.on_synced(gids, *from, *complete, now);
            }
            Event::GroupJoined { gid, .. } => {
                inv.on_group_joined(*gid, now);
            }
            Event::GroupDeleted { gid, .. } => {
                inv.on_group_deleted(*gid, now);
            }
            Event::InviteRevoked { gid } => {
                inv.on_revoked(*gid, now);
            }
            _ => {}
        }
        true
    }

    fn edit_cfg(&self, f: impl FnOnce(&mut Config)) -> Result<()> {
        let cfg = {
            let mut c = lock(&self.cfg);
            f(&mut c);
            c.clone()
        };
        self.engine().save_config(&cfg)
    }
}

impl EngineApi for LocalEngine {
    fn snapshot(&self) -> Arc<Snapshot> {
        Arc::new(self.snapshot_now())
    }

    fn poll_events(&self) -> Vec<Event> {
        let mut evs = Vec::new();
        {
            let rx = lock(&self.events);
            while let Ok(e) = rx.try_recv() {
                evs.push(e);
            }
        }
        let now = Instant::now();
        let mut inv = lock(&self.invites);
        let expired = !inv.tick(now).is_empty();
        evs.retain(|e| Self::track(&mut inv, e, now));
        drop(inv);
        if expired || !evs.is_empty() {
            self.changed.store(true, Ordering::Relaxed);
        }
        evs
    }

    fn send(&self, cmd: Cmd) -> Result<()> {
        let current: SocketAddr = lock(&self.meta).server;
        if let Some(e) = engine::check_cfg_cmd(&lock(&self.cfg), current, &cmd) {
            return Err(anyhow!(e));
        }
        if let Cmd::DeclineInvite(gid) = cmd {
            lock(&self.invites).on_decline(gid, Instant::now());
        }
        lock(&self.cmds)
            .send(cmd)
            .map_err(|_| anyhow!("движок остановлен"))?;
        self.changed.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn me(&self) -> &Me {
        &self.me
    }

    fn mode(&self) -> EngineMode {
        EngineMode::Embedded
    }

    fn save_theme(&self, theme: &str) -> Result<()> {
        self.edit_cfg(|c| c.theme = theme.to_string())
    }

    fn save_adapter(&self, name: &str, dll: &str) -> Result<()> {
        self.edit_cfg(|c| {
            c.adapter = name.to_string();
            c.dll = dll.to_string();
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn me_json_туда_и_обратно() {
        let me = Me {
            my_pub: [5; 32],
            my_code: "TUN-X".into(),
        };
        assert_eq!(Me::from_json(&me.to_json()), Some(me));
        assert_eq!(Me::from_json(&Value::Null), None);
        assert_eq!(
            Me::from_json(&json!({"my_pub": "zz", "my_code": "x"})),
            None
        );
    }
}
