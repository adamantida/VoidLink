//! Однострочные команды CLI через демон (PLAN.md 7.4).
//!
//! Свой ctrl-сеанс (`CtrlConn`) шлёт HELLO с той же identity и вытесняет
//! сессию работающего движка. Поэтому:
//! - демон доступен → команда уходит ему по IPC (`Req` → `Ack`, затем ждём
//!   нужное событие с таймаутом), конфиг правит сам демон командами из 7.1;
//! - замок движка занят, а демона нет (embedded TUI или `run`) → отказ;
//! - иначе — как раньше, короткий ctrl-сеанс (решает `main.rs`).
//!
//! Вывод — в `out`, тем же текстом, что у прямых команд.

use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use tunnel_ipc::{AckResult, ClientKind, DaemonMsg, InstanceLock, IpcClient};
use tunnel_protocol as proto;

use crate::api::Me;
use crate::engine::{self, Cmd, Event};
use crate::remote::{Endpoint, HANDSHAKE_TIMEOUT, subscribe};
use crate::snapshot::Snapshot;
use crate::store::{self, Config};

/// Ответ на команду, о которой сервер сообщает только ошибкой.
pub const QUIET_WAIT: Duration = Duration::from_secs(3);
/// Ответ сервера, который мы ждём явно (вход, создание, списки).
pub const REPLY_WAIT: Duration = Duration::from_secs(10);

/// Текст отказа, когда движок работает без демона.
pub const LOCKED_MSG: &str = "движок уже запущен без демона (embedded TUI или `run`): закройте TUI / остановите run \
или установите службу — свой HELLO этой команды вытеснил бы его сеанс";

/// Куда идёт команда CLI.
pub enum Route {
    /// Демон доступен — через него.
    Daemon(Box<IpcClient>),
    /// Замок занят, демона нет — отказ ([`LOCKED_MSG`]).
    Locked,
    /// Движка нет — короткий ctrl-сеанс, как раньше.
    Direct,
}

/// Демон для каталога данных `dir` (Unix — `<dir>/daemon.sock`). Демон есть,
/// но не пускает (права, чужой пайп, версия) — ошибка, без фолбэка.
pub fn route(dir: &Path) -> Result<Route> {
    route_to(&Endpoint::for_data_dir(dir), dir)
}

pub fn route_to(ep: &Endpoint, dir: &Path) -> Result<Route> {
    match ep.connect(ClientKind::Cli, HANDSHAKE_TIMEOUT) {
        Ok(Some(c)) => Ok(Route::Daemon(Box::new(c))),
        Ok(None) if InstanceLock::is_held(dir) => Ok(Route::Locked),
        Ok(None) => Ok(Route::Direct),
        Err(e) => bail!("{e} ({})", ep.describe()),
    }
}

/// Команды, которые идут через демона, если он есть (остальные — локальные:
/// `help`; `export-identity` — локальная, но сверяется с identity демона
/// ([`export_guard`]); `tui` решает сам).
pub fn is_engine_cmd(cmd: &str) -> bool {
    matches!(
        cmd,
        "id" | "set-name"
            | "set-status"
            | "add-server"
            | "servers"
            | "del-server"
            | "groups"
            | "create"
            | "join"
            | "leave"
            | "invites"
            | "decline"
            | "invite"
            | "kick"
            | "ban"
            | "unban"
            | "bans"
            | "transfer"
            | "rename"
            | "delete"
            | "friend-groups"
            | "add-friend"
            | "del-friend"
            | "friends"
            | "alias"
            | "import-identity"
            | "set-transport"
            | "set-mtu"
            | "dns"
            | "invisible"
            | "run"
    )
}

/// `export-identity` при работающем демоне: выгружается identity этого
/// каталога данных, а туннель держит демон — со своей identity (на Windows
/// служба хранит её в `%ProgramData%\tunnel`, не в профиле пользователя).
/// Совпадают — можно; нет (или демон не назвал свою) — отказ с объяснением,
/// как `id` через демона показывает identity демона.
pub fn export_guard(daemon: Option<&Me>, local_pub: Option<[u8; 32]>, dir: &Path) -> Result<()> {
    let Some(d) = daemon else {
        bail!(
            "export-identity: демон работает, но не сообщил свою identity — остановите демон и повторите"
        );
    };
    if local_pub == Some(d.my_pub) {
        return Ok(());
    }
    let local = local_pub
        .map(|p| proto::friend_code_of(&p))
        .unwrap_or_else(|| "нет".into());
    bail!(
        "export-identity: туннель держит демон с identity {} (её показывает `id`), а эта команда \
выгрузила бы другую — локальную identity каталога {} ({local}). Identity демона лежит в его каталоге \
данных (Windows: %ProgramData%\\tunnel, только администраторы): выгрузите её оттуда от \
администратора — tunnel-client --dir <каталог данных демона> export-identity <файл>",
        d.my_code,
        dir.display()
    )
}

/// Только чтение локального конфига — работает и при занятом замке.
pub fn is_readonly(cmd: &str) -> bool {
    matches!(cmd, "id" | "servers" | "friends")
}

/// Сеанс CLI у демона: подписка (история кольца отброшена) и свежий снимок.
struct Session<'a> {
    c: &'a mut IpcClient,
    snap: Snapshot,
}

impl Session<'_> {
    fn cfg(&self) -> Config {
        self.snap.cfg.to_config()
    }

    /// `Req` → `Ack`; отказ демона — ошибка с его текстом.
    fn req(&mut self, cmd: Cmd) -> Result<()> {
        let v = serde_json::to_value(&cmd)?;
        match self
            .c
            .request(v, HANDSHAKE_TIMEOUT)
            .map_err(|e| anyhow!("{e}"))?
        {
            AckResult::Ok => Ok(()),
            AckResult::Err(e) => bail!("{e}"),
        }
    }

    /// Ждёт событие, для которого `f` вернёт `Some`. `Event::Error` (если `f`
    /// его не разобрал) — ошибка. `None` — таймаут.
    fn wait<T>(
        &mut self,
        timeout: Duration,
        mut f: impl FnMut(&Event) -> Option<Result<T>>,
    ) -> Result<Option<T>> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            match self.c.recv(Some(left)) {
                Ok(DaemonMsg::Event { ev, .. }) => {
                    let Ok(ev) = serde_json::from_value::<Event>(ev) else {
                        continue;
                    };
                    if let Some(r) = f(&ev) {
                        return r.map(Some);
                    }
                    if let Event::Error(e) = ev {
                        bail!("{e}");
                    }
                }
                Ok(DaemonMsg::Snapshot { snap, .. }) => {
                    if let Ok(s) = serde_json::from_value(snap) {
                        self.snap = s;
                    }
                }
                Ok(DaemonMsg::Shutdown { reason }) => bail!("демон завершается: {reason}"),
                Ok(_) => {}
                Err(tunnel_ipc::ClientError::Timeout) => return Ok(None),
                Err(e) => bail!("{e}"),
            }
        }
    }

    /// Ждёт событие или таймаут (ошибка сервера — `Err`, тишина — `Ok`).
    fn wait_quiet(&mut self, timeout: Duration, f: impl FnMut(&Event) -> bool) -> Result<()> {
        let mut f = f;
        self.wait(timeout, |e| f(e).then_some(Ok(()))).map(|_| ())
    }

    /// Ждёт снимок, в котором правка конфига уже применена (иначе следующая
    /// команда CLI увидела бы старый конфиг). Ошибка движка — `Err`.
    fn until(&mut self, what: &str, mut f: impl FnMut(&Snapshot) -> bool) -> Result<()> {
        let deadline = Instant::now() + REPLY_WAIT;
        while !f(&self.snap) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                bail!("демон не подтвердил: {what}");
            }
            match self.c.recv(Some(left)) {
                Ok(DaemonMsg::Snapshot { snap, .. }) => {
                    if let Ok(s) = serde_json::from_value(snap) {
                        self.snap = s;
                    }
                }
                Ok(DaemonMsg::Event { ev, .. }) => {
                    if let Ok(Event::Error(e)) = serde_json::from_value::<Event>(ev) {
                        bail!("{e}");
                    }
                }
                Ok(DaemonMsg::Shutdown { reason }) => bail!("демон завершается: {reason}"),
                Ok(_) | Err(tunnel_ipc::ClientError::Timeout) => {}
                Err(e) => bail!("{e}"),
            }
        }
        Ok(())
    }

    /// Снимки, пришедшие за `dur` (последний — в `self.snap`).
    fn settle(&mut self, dur: Duration) -> Result<()> {
        self.wait(dur, |_| None::<Result<()>>).map(|_| ())
    }
}

fn gid_arg(v: Option<&String>) -> Result<u32> {
    let v = v.context("нужен gid")?;
    v.parse::<u32>().context("gid должен быть числом")
}

fn server_idx(cfg: &Config, tok: &str) -> Option<usize> {
    if let Some(i) = cfg
        .servers
        .iter()
        .position(|s| s.addr == tok || (!s.label.is_empty() && s.label == tok))
    {
        return Some(i);
    }
    tok.parse::<usize>().ok().filter(|n| *n < cfg.servers.len())
}

fn friend_name(cfg: &Config, pk: &[u8; 32], fallback: &str) -> String {
    cfg.friends
        .iter()
        .find(|f| f.pubkey == proto::hex_of(pk))
        .map(|f| f.alias.clone())
        .unwrap_or_else(|| fallback.to_string())
}

/// Выполнить команду CLI `cmd` через демона. Неизвестная/не поддержанная
/// через демона команда — ошибка с объяснением.
pub fn run(c: &mut IpcClient, cmd: &str, rest: &[String], out: &mut dyn Write) -> Result<()> {
    let me = Me::from_json(c.me());
    let (snap, _history, _editable) = subscribe(c, HANDSHAKE_TIMEOUT).map_err(|e| anyhow!(e))?;
    let mut s = Session { c, snap };
    match cmd {
        "id" => {
            let me = me.context("демон не сообщил identity")?;
            writeln!(out, "friend code: {} (identity демона)", me.my_code)?;
            writeln!(out, "ed25519 pub: {}", proto::hex_of(&me.my_pub))?;
            let cfg = &s.snap.cfg;
            writeln!(
                out,
                "name:        {}",
                if cfg.name.is_empty() {
                    "(не задано)"
                } else {
                    &cfg.name
                }
            )?;
            writeln!(
                out,
                "status:      {}",
                if cfg.status.is_empty() {
                    "(не задано)"
                } else {
                    &cfg.status
                }
            )?;
        }
        "set-name" => {
            let name = rest.join(" ");
            if name.trim().is_empty() {
                bail!("usage: set-name <имя>");
            }
            s.req(Cmd::SetName(name.clone()))?;
            s.until("имя", |x| x.cfg.name == name)?;
            writeln!(out, "имя установлено: {name}")?;
        }
        "set-status" => {
            let text = rest.join(" ");
            s.req(Cmd::SetStatus(text.clone()))?;
            s.until("статус", |x| x.cfg.status == text)?;
            writeln!(out, "статус установлен: {text:?}")?;
        }
        "invisible" => {
            let on = match rest.first().map(|s| s.as_str()) {
                Some("on") => true,
                Some("off") => false,
                _ => bail!("usage: invisible on|off"),
            };
            s.req(Cmd::SetInvisible(on))?;
            s.until("невидимка", |x| x.cfg.invisible == on)?;
            writeln!(
                out,
                "невидимка {}",
                if on {
                    "включена"
                } else {
                    "выключена"
                }
            )?;
        }
        "add-server" => {
            let usage = "usage: add-server <addr> <code> [label]";
            let addr = rest.first().context(usage)?;
            let code = rest.get(1).context(usage)?;
            addr.parse::<SocketAddr>()
                .context("addr должен быть ip:port")?;
            let pubkey = proto::Identity::parse_friend_code(code)?;
            let label = rest.get(2).cloned().unwrap_or_default();
            if s.snap.cfg.servers.iter().any(|x| x.addr == *addr) {
                bail!("сервер {addr} уже добавлен");
            }
            s.req(Cmd::AddServer {
                addr: addr.clone(),
                pubkey,
                label,
            })?;
            s.until("сервер в конфиге", |x| {
                x.cfg.servers.iter().any(|v| v.addr == *addr)
            })?;
            writeln!(out, "сервер {addr} добавлен (pubkey закреплён)")?;
        }
        "servers" => {
            if s.snap.cfg.servers.is_empty() {
                writeln!(
                    out,
                    "(нет серверов; добавь: add-server <addr> <code> [label])"
                )?;
            }
            for (n, x) in s.snap.cfg.servers.iter().enumerate() {
                writeln!(
                    out,
                    "{}: {} {} [{}]",
                    n,
                    x.addr,
                    if x.label.is_empty() { "-" } else { &x.label },
                    x.pubkey
                )?;
            }
        }
        "del-server" => {
            let tok = rest.first().context("usage: del-server <N|addr|label>")?;
            let idx =
                server_idx(&s.cfg(), tok).with_context(|| format!("сервер {tok:?} не найден"))?;
            let gone = s.snap.cfg.servers[idx].addr.clone();
            s.req(Cmd::DelServer { idx })?;
            s.until("сервер удалён", |x| {
                !x.cfg.servers.iter().any(|v| v.addr == gone)
            })?;
            writeln!(out, "удалено")?;
        }
        "groups" => {
            s.req(Cmd::RefreshList)?;
            // Список приходит в снимке (демон шлёт его раз в секунду).
            s.settle(Duration::from_millis(1500))?;
            let items = &s.snap.meta.group_list;
            if items.is_empty() {
                writeln!(out, "(групп нет; создай: create <имя>)")?;
            }
            for g in items {
                writeln!(
                    out,
                    "{:>4}  {:<20} {} online {}/{} {}",
                    g.gid,
                    g.name,
                    if g.private { "[private]" } else { "[public] " },
                    g.online,
                    g.total,
                    if g.mine { "(состою)" } else { "" }
                )?;
            }
        }
        "create" => {
            let private = rest.iter().any(|a| a == "--private");
            let name: String = rest
                .iter()
                .filter(|a| *a != "--private")
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");
            if name.trim().is_empty() {
                bail!("usage: create <имя> [--private]");
            }
            let known: Vec<u32> = s.snap.groups.iter().map(|g| g.gid).collect();
            s.req(Cmd::Create { name, private })?;
            let (gid, name, ip) = s
                .wait(REPLY_WAIT, |e| match e {
                    Event::GroupJoined { gid, name, my_ip } if !known.contains(gid) => {
                        Some(Ok((*gid, name.clone(), *my_ip)))
                    }
                    _ => None,
                })?
                .context("сервер не ответил — группа могла не создаться")?;
            writeln!(
                out,
                "группа {gid} \"{name}\" создана, мой IP {} (autojoin — у демона)",
                proto::ip_str(ip)
            )?;
        }
        "join" => {
            let gid = gid_arg(rest.first())?;
            s.req(Cmd::Join(gid))?;
            let (name, ip) = s
                .wait(REPLY_WAIT, |e| match e {
                    Event::GroupJoined {
                        gid: g,
                        name,
                        my_ip,
                    } if *g == gid => Some(Ok((name.clone(), *my_ip))),
                    Event::GroupDeleted { gid: g, .. } if *g == gid => {
                        Some(Err(anyhow!("группа {gid} удалена")))
                    }
                    _ => None,
                })?
                .or_else(|| {
                    s.snap
                        .groups
                        .iter()
                        .find(|g| g.gid == gid)
                        .map(|g| (g.name.clone(), g.my_ip))
                })
                .context("сервер не ответил — повторите")?;
            writeln!(
                out,
                "вошёл в {gid} \"{name}\", мой IP {} (autojoin — у демона)",
                proto::ip_str(ip)
            )?;
        }
        "leave" => {
            let gid = gid_arg(rest.first())?;
            s.req(Cmd::Leave(gid))?;
            s.wait_quiet(
                QUIET_WAIT,
                |e| matches!(e, Event::GroupLeft { gid: g, .. } if *g == gid),
            )?;
            writeln!(out, "вышел из {gid} (autojoin снят)")?;
        }
        "delete" => {
            let gid = gid_arg(rest.first())?;
            s.req(Cmd::Delete(gid))?;
            s.wait_quiet(
                QUIET_WAIT,
                |e| matches!(e, Event::GroupDeleted { gid: g, .. } if *g == gid),
            )?;
            writeln!(out, "группа {gid} удалена")?;
        }
        "rename" => {
            let gid = gid_arg(rest.first())?;
            let name = rest[1.min(rest.len())..].join(" ");
            if name.trim().is_empty() {
                bail!("usage: rename <gid> <имя>");
            }
            s.req(Cmd::Rename(gid, name))?;
            s.wait_quiet(QUIET_WAIT, |_| false)?;
            writeln!(out, "переименовано")?;
        }
        "invite" | "kick" | "ban" | "unban" | "transfer" => {
            let gid = gid_arg(rest.first())?;
            let peer = rest
                .get(1)
                .with_context(|| format!("usage: {cmd} <gid> <peer (code|hex|alias)>"))?;
            let pk = store::resolve_peer(&s.cfg(), peer)?;
            let c = match cmd {
                "invite" => Cmd::Invite(gid, pk),
                "kick" => Cmd::Kick(gid, pk),
                "ban" => Cmd::Ban(gid, pk),
                "unban" => Cmd::Unban(gid, pk),
                _ => Cmd::Transfer(gid, pk),
            };
            s.req(c)?;
            s.wait_quiet(QUIET_WAIT, |_| false)?;
            writeln!(out, "{cmd}: ок")?;
        }
        "invites" => {
            let cfg = s.cfg();
            if s.snap.pending_invites.is_empty() {
                writeln!(out, "(приглашений нет)")?;
            } else {
                for i in &s.snap.pending_invites {
                    let from = friend_name(&cfg, &i.from_pubkey, &i.from_name);
                    let exp = i
                        .expires_in_s
                        .map(|x| engine::fmt_secs(x.min(u64::from(u32::MAX)) as u32));
                    writeln!(
                        out,
                        "{:>4}  {:<20} от {from} (истекает через {})",
                        i.gid,
                        i.group_name,
                        exp.as_deref().unwrap_or("—")
                    )?;
                }
                writeln!(out, "принять: join <gid> · отклонить: decline <gid>")?;
            }
        }
        "decline" => {
            let gid = gid_arg(rest.first())?;
            if !s.snap.pending_invites.iter().any(|i| i.gid == gid) {
                bail!("нет приглашения в группу {gid}");
            }
            // Повтор DECLINE до подтверждения сервером — забота движка демона.
            s.req(Cmd::DeclineInvite(gid))?;
            writeln!(out, "приглашение в {gid} отклонено")?;
        }
        "friend-groups" => {
            let peer = rest.first().context("usage: friend-groups <peer>")?;
            let pk = store::resolve_peer(&s.cfg(), peer)?;
            s.req(Cmd::FriendGroups(pk))?;
            let items = s
                .wait(REPLY_WAIT, |e| match e {
                    Event::FriendGroups { pubkey, items } if *pubkey == pk => {
                        Some(Ok(items.clone()))
                    }
                    _ => None,
                })?
                .context("сервер не ответил — повторите")?;
            if items.is_empty() {
                writeln!(out, "(у друга нет видимых групп)")?;
            }
            for g in items {
                writeln!(
                    out,
                    "{:>4}  {:<20} {} {}",
                    g.gid,
                    g.name,
                    if g.private { "[private]" } else { "[public] " },
                    if g.shared { "(общая)" } else { "" }
                )?;
            }
        }
        "bans" => {
            let gid = gid_arg(rest.first())?;
            s.req(Cmd::GroupAdmin(gid))?;
            let (bans, invites) = s
                .wait(REPLY_WAIT, |e| match e {
                    Event::AdminInfo {
                        gid: g,
                        bans,
                        invites,
                    } if *g == gid => Some(Ok((bans.clone(), invites.clone()))),
                    _ => None,
                })?
                .context("сервер не ответил — повторите")?;
            let cfg = s.cfg();
            let who = |pk: &[u8; 32], name: &str| {
                let shown = friend_name(
                    &cfg,
                    pk,
                    if name.is_empty() {
                        "(без имени)"
                    } else {
                        name
                    },
                );
                format!("{shown:<20} {}", proto::friend_code_of(pk))
            };
            writeln!(out, "баны группы {gid}:")?;
            if bans.is_empty() {
                writeln!(out, "  (нет)")?;
            }
            for (pk, name) in &bans {
                writeln!(out, "  {}", who(pk, name))?;
            }
            writeln!(out, "неотвеченные приглашения:")?;
            if invites.is_empty() {
                writeln!(out, "  (нет)")?;
            }
            for (pk, name, exp) in &invites {
                writeln!(
                    out,
                    "  {}  истекает через {}",
                    who(pk, name),
                    engine::fmt_secs(*exp)
                )?;
            }
            writeln!(
                out,
                "снять бан: unban {gid} <peer> · отозвать приглашение: kick {gid} <peer>"
            )?;
        }
        "add-friend" => {
            let code = rest.first().context("usage: add-friend <code> [alias]")?;
            let pubkey = proto::Identity::parse_friend_code(code)?;
            let alias = rest.get(1).cloned().unwrap_or_else(|| code.clone());
            if s.snap
                .cfg
                .friends
                .iter()
                .any(|f| f.pubkey == proto::hex_of(&pubkey))
            {
                bail!("друг уже добавлен");
            }
            s.req(Cmd::AddFriend {
                pubkey,
                alias: alias.clone(),
            })?;
            let hex = proto::hex_of(&pubkey);
            s.until("друг в конфиге", |x| {
                x.cfg.friends.iter().any(|f| f.pubkey == hex)
            })?;
            writeln!(out, "друг добавлен: {alias} ({})", proto::hex_of(&pubkey))?;
        }
        "del-friend" => {
            let alias = rest.first().context("usage: del-friend <alias>")?;
            let pks: Vec<[u8; 32]> = s
                .snap
                .cfg
                .friends
                .iter()
                .filter(|f| &f.alias == alias)
                .filter_map(|f| proto::hex_to_bytes(&f.pubkey).ok()?.try_into().ok())
                .collect();
            if pks.is_empty() {
                bail!("друг {alias:?} не найден");
            }
            for pk in &pks {
                s.req(Cmd::DelFriend(*pk))?;
            }
            let hexes: Vec<String> = pks.iter().map(|pk| proto::hex_of(pk)).collect();
            s.until("друг удалён", |x| {
                !x.cfg.friends.iter().any(|f| hexes.contains(&f.pubkey))
            })?;
            writeln!(out, "удалён")?;
        }
        "alias" => {
            let usage = "usage: alias <friend (alias|code|hex)> <новое имя>";
            let peer = rest.first().context(usage)?;
            let name = rest[1.min(rest.len())..].join(" ");
            if name.trim().is_empty() {
                bail!("{usage}");
            }
            let cfg = s.cfg();
            let pk = store::resolve_peer(&cfg, peer)?;
            let hex = proto::hex_of(&pk);
            if cfg
                .friends
                .iter()
                .any(|f| f.alias == name && f.pubkey != hex)
            {
                bail!("имя {name:?} уже занято другим другом");
            }
            if !cfg.friends.iter().any(|f| f.pubkey == hex) {
                bail!("друг {peer:?} не найден");
            }
            s.req(Cmd::SetAlias {
                pubkey: pk,
                alias: name.clone(),
            })?;
            s.until("алиас", |x| {
                x.cfg
                    .friends
                    .iter()
                    .any(|f| f.pubkey == hex && f.alias == name)
            })?;
            writeln!(out, "друг переименован: {name}")?;
        }
        "friends" => {
            if s.snap.cfg.friends.is_empty() {
                writeln!(out, "(нет друзей; добавь: add-friend <code> [alias])")?;
            }
            for f in &s.snap.cfg.friends {
                writeln!(out, "{:<16} {}", f.alias, f.pubkey)?;
            }
        }
        "run" => bail!(
            "туннель уже поднят демоном — второй движок с той же identity выбил бы его с сервера"
        ),
        "set-transport" | "set-mtu" | "dns" | "import-identity" => bail!(
            "{cmd}: при работающем демоне недоступно — это настройка движка демона, IPC-команды для неё нет \
(остановите демон и повторите)"
        ),
        other => bail!("неизвестная команда: {other:?}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `export-identity` при демоне: та же identity — можно; другая (служба
    /// Windows со своей identity в ProgramData) или нет локальной — отказ,
    /// в тексте — friend code демона.
    #[test]
    fn export_guard_checks_daemon_identity() {
        let dir = Path::new("/tmp/profile");
        let a = proto::Identity::generate();
        let b = proto::Identity::generate();
        let me = Me {
            my_pub: a.ed_pub(),
            my_code: a.friend_code(),
        };
        export_guard(Some(&me), Some(a.ed_pub()), dir).unwrap();
        let e = export_guard(Some(&me), Some(b.ed_pub()), dir)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains(&a.friend_code()) && e.contains(&b.friend_code()),
            "{e}"
        );
        assert!(export_guard(Some(&me), None, dir).is_err());
        assert!(export_guard(None, Some(a.ed_pub()), dir).is_err());
        assert!(!is_engine_cmd("export-identity"));
    }
}
