//! Клиент туннеля (протокол v3): CLI-диспетчер.
//!
//! Глобальные флаги: `--dir <путь>` (каталог конфига), `--profile <имя>`
//! (каталог `<dir>/profiles/<имя>`), `--debug`,
//! `--server <N|addr|label>` (по умолчанию — последний использованный).
//! Для `run` дополнительно: `--adapter <имя>`, `--dll <путь>`.
//!
//! Подкоманды:
//!   id                          — friend code и ключи identity
//!   set-name <имя>              — имя профиля (видят другие)
//!   set-status <текст>          — статус-текст
//!   add-server <addr> <code> [label] — добавить сервер (addr ip:port, code — friend code сервера)
//!   servers                     — список серверов
//!   del-server <N|addr|label>   — удалить сервер
//!   groups                      — список групп на сервере
//!   create <имя> [--private]    — создать группу (владелец = мы)
//!   join <gid>                  — войти в группу
//!   leave <gid>                 — выйти
//!   invites                     — неотвеченные приглашения
//!   decline <gid>               — отклонить приглашение
//!   invite <gid> <peer>         — пригласить (владелец)
//!   kick <gid> <peer>           — исключить (владелец)
//!   ban <gid> <peer>            — забанить (владелец)
//!   unban <gid> <peer>          — снять бан (владелец)
//!   bans <gid>                  — баны и неотвеченные приглашения (владелец)
//!   transfer <gid> <peer>       — передать группу участнику (владелец)
//!   rename <gid> <имя>          — переименовать (владелец)
//!   delete <gid>                — удалить группу (владелец)
//!   friend-groups <peer>        — группы друга
//!   add-friend <code> [alias]   — добавить друга локально
//!   del-friend <alias>          — удалить друга
//!   friends                     — список друзей
//!   alias <friend> <имя>        — переименовать друга локально
//!   export-identity <файл> [--passphrase <p>|--passphrase-stdin] [--force]
//!                               — выгрузить identity (перенос на другую машину)
//!   import-identity <файл> [--passphrase <p>|--passphrase-stdin] [--force]
//!                               — загрузить identity (--force — заменить текущую)
//!   set-transport auto|udp|tcp  — транспорт до сервера
//!   set-mtu <N>                 — MTU адаптера
//!   dns on|off                  — встроенный DNS для имён пиров (*.vl)
//!   invisible on|off            — невидимка (другие видят нас офлайн)
//!   run                         — поднять туннель (autojoin-группы)
//!   tui [--embedded|--remote]   — интерфейс: при работающем демоне — тонкий
//!                                 клиент (без прав админа), иначе свой движок
//!
//! Если в конфиге нет имени или серверов, `tui` сначала показывает
//! экран первичной настройки (tui::setup): имя, сервер, адаптер, dll.
//!
//! Демон (PLAN.md 7.4): если он доступен, сетевые команды и правки конфига
//! идут ему по IPC (`remote_cli`) — свой ctrl-сеанс вытеснил бы его сессию.
//! Движок запущен без демона (embedded TUI или `run` держат замок) — такие
//! команды отказывают.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use proto::ctrl;
use proto::payloads;
use tunnel_protocol as proto;

use tunnel_client::remote::{Endpoint, IpcEngine, UiPrefs};
use tunnel_client::remote_cli::{self, Route};
use tunnel_client::{engine, profile, store, tui};
use tunnel_ipc::{InstanceLock, LockError};

use store::{Config, StoredFriend, StoredServer};

/// Режим TUI, заданный флагом.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UiMode {
    Embedded,
    Remote,
}

/// Глобальные флаги CLI (в любом месте командной строки).
#[derive(Debug, PartialEq)]
struct Globals {
    dir: Option<std::path::PathBuf>,
    profile: Option<String>,
    adapter: String,
    /// `--adapter` задан явно (иначе берётся из конфига).
    adapter_set: bool,
    dll: Option<String>,
    server_sel: Option<String>,
    debug: bool,
    /// `--embedded` / `--remote` для `tui` (по умолчанию — по наличию демона).
    ui_mode: Option<UiMode>,
    /// Подкоманда и её аргументы.
    args: Vec<String>,
}

impl Globals {
    /// Каталог данных: `--dir` (или каталог по умолчанию), а с `--profile` —
    /// его подкаталог `profiles/<имя>`.
    fn data_dir(&self) -> Result<std::path::PathBuf> {
        let base = self.dir.clone().unwrap_or_else(store::default_dir);
        match &self.profile {
            None => Ok(base),
            Some(name) => profile::profile_dir_in(&base, name),
        }
    }
}

fn parse_globals(mut args: Vec<String>) -> Result<Globals> {
    let mut g = Globals {
        dir: None,
        profile: None,
        adapter: engine::DEFAULT_ADAPTER.to_string(),
        adapter_set: false,
        dll: None,
        server_sel: None,
        debug: false,
        ui_mode: None,
        args: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--dir" {
            g.dir = Some(args.get(i + 1).context("--dir требует значение")?.into());
            args.drain(i..=i + 1);
        } else if a == "--profile" {
            let name = args
                .get(i + 1)
                .context("--profile требует значение")?
                .clone();
            profile::validate_profile_name(&name)?;
            g.profile = Some(name);
            args.drain(i..=i + 1);
        } else if a == "--adapter" {
            g.adapter = args
                .get(i + 1)
                .context("--adapter требует значение")?
                .clone();
            g.adapter_set = true;
            args.drain(i..=i + 1);
        } else if a == "--dll" {
            if !cfg!(windows) {
                bail!("--dll нужен только на Windows (wintun.dll)");
            }
            g.dll = Some(args.get(i + 1).context("--dll требует значение")?.clone());
            args.drain(i..=i + 1);
        } else if a == "--server" {
            g.server_sel = Some(
                args.get(i + 1)
                    .context("--server требует значение")?
                    .clone(),
            );
            args.drain(i..=i + 1);
        } else if a == "--debug" {
            g.debug = true;
            args.remove(i);
        } else if a == "--embedded" || a == "--remote" {
            let m = if a == "--embedded" {
                UiMode::Embedded
            } else {
                UiMode::Remote
            };
            if g.ui_mode.is_some_and(|x| x != m) {
                bail!("--embedded и --remote взаимоисключающие");
            }
            g.ui_mode = Some(m);
            args.remove(i);
        } else {
            i += 1;
        }
    }
    g.args = args;
    Ok(g)
}

/// Аргументы export-/import-identity: файл, парольная фраза, `--force`.
#[derive(Debug, PartialEq)]
struct IdentityArgs {
    file: std::path::PathBuf,
    passphrase: Option<String>,
    passphrase_stdin: bool,
    force: bool,
}

fn parse_identity_args(cmd: &str, rest: &[String]) -> Result<IdentityArgs> {
    let usage = || format!("usage: {cmd} <файл> [--passphrase <p>|--passphrase-stdin] [--force]");
    let mut file = None;
    let mut passphrase = None;
    let mut passphrase_stdin = false;
    let mut force = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--passphrase" => {
                passphrase = Some(rest.get(i + 1).with_context(usage)?.clone());
                i += 2;
                continue;
            }
            "--passphrase-stdin" => passphrase_stdin = true,
            "--force" => force = true,
            f if f.starts_with("--") => bail!("неизвестный флаг {f:?}; {}", usage()),
            f => {
                if file.is_some() {
                    bail!("лишний аргумент {f:?}; {}", usage());
                }
                file = Some(std::path::PathBuf::from(f));
            }
        }
        i += 1;
    }
    if passphrase.is_some() && passphrase_stdin {
        bail!("--passphrase и --passphrase-stdin взаимоисключающие");
    }
    if matches!(&passphrase, Some(p) if p.is_empty()) {
        bail!("пустая парольная фраза");
    }
    Ok(IdentityArgs {
        file: file.with_context(usage)?,
        passphrase,
        passphrase_stdin,
        force,
    })
}

impl IdentityArgs {
    /// Парольная фраза: из флага или первой строки stdin.
    fn passphrase(&self) -> Result<Option<String>> {
        if !self.passphrase_stdin {
            return Ok(self.passphrase.clone());
        }
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("чтение парольной фразы из stdin")?;
        let p = line.trim_end_matches(['\r', '\n']).to_string();
        anyhow::ensure!(!p.is_empty(), "пустая парольная фраза");
        Ok(Some(p))
    }
}

/// `on|off` → bool.
fn parse_on_off(v: Option<&String>, usage: &str) -> Result<bool> {
    match v.map(|s| s.as_str()) {
        Some("on") => Ok(true),
        Some("off") => Ok(false),
        _ => bail!("{usage}"),
    }
}

fn parse_mtu(v: Option<&String>) -> Result<usize> {
    let n: usize = v
        .context("usage: set-mtu <N>")?
        .parse()
        .context("MTU должен быть числом")?;
    anyhow::ensure!(
        (store::MTU_MIN..=store::MTU_MAX).contains(&n),
        "MTU должен быть в пределах {}..={}",
        store::MTU_MIN,
        store::MTU_MAX
    );
    Ok(n)
}

fn parse_transport(v: Option<&String>) -> Result<store::TransportMode> {
    let t = v
        .context("usage: set-transport auto|udp|tcp")?
        .to_ascii_lowercase();
    let t: store::TransportMode = serde_json::from_value(serde_json::Value::String(t))
        .map_err(|_| anyhow::anyhow!("usage: set-transport auto|udp|tcp"))?;
    Ok(t)
}

/// Импорт identity в конфиг `store` (до автосоздания новой identity).
fn import_identity_cmd(store: &store::Store, a: &IdentityArgs) -> Result<()> {
    let pass = a.passphrase()?;
    let id = profile::import_from_file(&a.file, pass.as_deref())?;
    let mut cfg = store.load().context("чтение конфига")?;
    if profile::apply_identity(&mut cfg, &id, a.force)? {
        store.save(&cfg).context("запись конфига")?;
        println!("identity импортирована: {}", id.friend_code());
    } else {
        println!("identity уже такая: {}", id.friend_code());
    }
    Ok(())
}

/// Экспорт identity в файл (без `--force` существующий файл не затирается).
fn export_identity_cmd(id: &proto::Identity, a: &IdentityArgs) -> Result<()> {
    if a.file.exists() && !a.force {
        bail!("файл {} уже есть; повторите с --force", a.file.display());
    }
    let pass = a.passphrase()?;
    profile::export_to_file(&a.file, id, pass.as_deref())?;
    println!(
        "identity {} выгружена в {}{}",
        id.friend_code(),
        a.file.display(),
        if pass.is_some() {
            " (зашифрована)"
        } else {
            " (НЕ зашифрована — храните файл в секрете)"
        }
    );
    Ok(())
}

fn main() -> Result<()> {
    let g = parse_globals(std::env::args().skip(1).collect())?;
    let dir = g.data_dir()?;
    let mut adapter = g.adapter.clone();
    let mut dll = g.dll.clone();
    let server_sel = g.server_sel.clone();
    let ui_mode = g.ui_mode;
    let args = g.args;
    engine::set_debug(g.debug);

    // Демон или чужой движок — до любых правок client.json (PLAN.md 7.4).
    let cmd0 = args.first().cloned().unwrap_or_else(|| "tui".into());
    // export-identity локальная, но при работающем демоне выгрузила бы не ту
    // identity, что держит туннель (служба Windows — своя, в ProgramData).
    if cmd0 == "export-identity"
        && let Route::Daemon(c) = remote_cli::route(&dir)?
    {
        let local = store::Store::new(&dir)
            .load()
            .ok()
            .filter(|c| c.identity.is_some())
            .map(|mut c| store::ensure_identity(&mut c).ed_pub());
        let me = tunnel_client::api::Me::from_json(c.me());
        remote_cli::export_guard(me.as_ref(), local, &dir)?;
    }
    if remote_cli::is_engine_cmd(&cmd0) {
        match remote_cli::route(&dir)? {
            Route::Daemon(mut c) => {
                let mut out = std::io::stdout();
                return remote_cli::run(&mut c, &cmd0, &args[1..], &mut out);
            }
            Route::Locked if !remote_cli::is_readonly(&cmd0) => bail!("{}", remote_cli::LOCKED_MSG),
            Route::Locked | Route::Direct => {}
        }
    }

    let store = store::Store::new(&dir);

    // Импорт — до автосоздания identity: иначе в свежем профиле сначала
    // появилась бы случайная identity и импорт требовал бы --force.
    if args.first().map(|s| s.as_str()) == Some("import-identity") {
        return import_identity_cmd(&store, &parse_identity_args("import-identity", &args[1..])?);
    }

    let mut cfg: Config = store.load().context("чтение конфига")?;
    // Адаптер и dll из конфига (экран «Серверы» в TUI), если не заданы флагами.
    if !g.adapter_set && !cfg.adapter.is_empty() {
        adapter = cfg.adapter.clone();
    }
    if dll.is_none() && !cfg.dll.is_empty() {
        dll = Some(cfg.dll.clone());
    }

    let save = |c: &Config| -> Result<()> { store.save(c).context("запись конфига") };

    // Identity: создаётся один раз и сразу сохраняется, чтобы все команды
    // (и `run`) использовали одну и ту же личность.
    if cfg.identity.is_none() {
        let id = store::ensure_identity(&mut cfg);
        save(&cfg)?;
        println!("создана новая identity: {}", id.friend_code());
    }

    let cmd = args.first().cloned().unwrap_or_else(|| "tui".into());
    let rest: Vec<String> = args[1.min(args.len())..].to_vec();
    let rest: &[String] = &rest;

    let identity = store::ensure_identity(&mut cfg);

    match cmd.as_str() {
        "help" | "-h" | "--help" => usage(),
        "id" => {
            let id = store::ensure_identity(&mut cfg);
            save(&cfg)?;
            println!("friend code: {}", id.friend_code());
            println!("ed25519 pub: {}", proto::hex_of(&id.ed_pub()));
            println!("x25519 pub:  {}", proto::hex_of(&id.x_pub()));
            println!(
                "name:        {}",
                if cfg.name.is_empty() {
                    "(не задано)"
                } else {
                    &cfg.name
                }
            );
            println!(
                "status:      {}",
                if cfg.status.is_empty() {
                    "(не задано)"
                } else {
                    &cfg.status
                }
            );
        }
        "set-name" => {
            let name = rest.join(" ");
            bail_if_empty(&name, "usage: set-name <имя>");
            cfg.name = name;
            save(&cfg)?;
            println!("имя установлено: {}", cfg.name);
        }
        "set-status" => {
            let text = rest.join(" ");
            cfg.status = text;
            save(&cfg)?;
            println!("статус установлен: {:?}", cfg.status);
        }
        "add-server" => {
            let addr = rest
                .first()
                .context("usage: add-server <addr> <code> [label]")?;
            let code = rest
                .get(1)
                .context("usage: add-server <addr> <code> [label]")?;
            addr.parse::<SocketAddr>()
                .context("addr должен быть ip:port")?;
            let pub_hex = proto::hex_of(&proto::Identity::parse_friend_code(code)?);
            let label = rest.get(2).cloned().unwrap_or_default();
            if cfg.servers.iter().any(|s| s.addr == *addr) {
                bail!("сервер {addr} уже добавлен");
            }
            cfg.servers.push(StoredServer {
                addr: addr.clone(),
                pubkey: pub_hex,
                label,
            });
            save(&cfg)?;
            println!("сервер {addr} добавлен (pubkey закреплён)");
        }
        "servers" => {
            if cfg.servers.is_empty() {
                println!("(нет серверов; добавь: add-server <addr> <code> [label])");
            }
            for (n, s) in cfg.servers.iter().enumerate() {
                println!(
                    "{}: {} {} [{}]",
                    n,
                    s.addr,
                    if s.label.is_empty() { "-" } else { &s.label },
                    s.pubkey
                );
            }
        }
        "del-server" => {
            let tok = rest.first().context("usage: del-server <N|addr|label>")?;
            // Раньше числовой токен сравнивался сам с собой и
            // `del-server 1` удалял все серверы.
            let idx =
                find_server(&cfg, tok).with_context(|| format!("сервер {tok:?} не найден"))?;
            cfg.servers.remove(idx);
            save(&cfg)?;
            println!("удалено");
        }
        "groups" => with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
            let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
            conn.send_ctrl(ctrl::LIST_GROUPS, &[]);
            let p = conn.wait_for(ctrl::GROUP_LIST, std::time::Duration::from_secs(10))?;
            let items = payloads::dec_group_list(&p)?;
            if items.is_empty() {
                println!("(групп нет; создай: create <имя>)");
            }
            for g in items {
                println!(
                    "{:>4}  {:<20} {} online {}/{} {}",
                    g.gid,
                    g.name,
                    if g.private { "[private]" } else { "[public] " },
                    g.online,
                    g.total,
                    if g.mine { "(состою)" } else { "" }
                );
            }
            Ok(())
        })?,
        "create" => {
            let private = rest.iter().any(|a| a == "--private");
            let name: String = rest
                .iter()
                .filter(|a| *a != "--private")
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");
            bail_if_empty(&name, "usage: create <имя> [--private]");
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                // После HELLO3 сервер шлёт GROUP_STATE каждой нашей группы:
                // созданная — та, которой нет среди своих в списке.
                conn.send_ctrl(ctrl::LIST_GROUPS, &[]);
                let p = conn.wait_for(ctrl::GROUP_LIST, std::time::Duration::from_secs(10))?;
                let known: std::collections::HashSet<u32> = payloads::dec_group_list(&p)?
                    .iter()
                    .filter(|g| g.mine)
                    .map(|g| g.gid)
                    .collect();
                conn.send_ctrl(
                    ctrl::CREATE_GROUP,
                    &payloads::enc_create_group(&name, private),
                );
                let st = loop {
                    let p = conn.wait_for(ctrl::GROUP_STATE, std::time::Duration::from_secs(10))?;
                    let st = payloads::dec_group_state(&p)?;
                    if !st.deleted && !known.contains(&st.gid) {
                        break st;
                    }
                };
                println!(
                    "группа {} \"{}\" создана, мой IP {}",
                    st.gid,
                    st.name,
                    proto::ip_str(st.my_ip)
                );
                if autojoin_add(&store, server, st.gid)? {
                    println!("добавлена в autojoin");
                }
                Ok(())
            })?;
        }
        "join" => {
            let gid = parse_gid(rest.first())?;
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
                // Своё состояние — по gid (GROUP_STATE шлётся и на GET_GROUP).
                let st = loop {
                    let p = conn.wait_for(ctrl::GROUP_STATE, std::time::Duration::from_secs(10))?;
                    let st = payloads::dec_group_state(&p)?;
                    if st.gid == gid {
                        break st;
                    }
                };
                if st.deleted {
                    bail!("группа {gid} удалена");
                }
                println!(
                    "вошёл в {} \"{}\", мой IP {}",
                    st.gid,
                    st.name,
                    proto::ip_str(st.my_ip)
                );
                if autojoin_add(&store, server, gid)? {
                    println!("добавлена в autojoin");
                }
                Ok(())
            })?;
        }
        "invites" => with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
            // Сервер шлёт первое окно (до 16) неотвеченных приглашений сразу
            // после HELLO3 (потерянное запрашивается LIST_INVITES с 0),
            // остальные дочитываются окнами LIST_INVITES.
            let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
            let Some(mut list) = conn.invite_list()? else {
                bail!("список приглашений не получен (потеря пакетов) — повторите");
            };
            let mut items = Vec::new();
            let complete = loop {
                let next = list.next_from();
                items.append(&mut list.items);
                match next {
                    Some(from) => match conn.invite_page(from)? {
                        Some(page) => list = page,
                        None => break false,
                    },
                    None => break list.complete,
                }
            };
            for inv in &items {
                let from = cfg2
                    .friends
                    .iter()
                    .find(|f| f.pubkey == proto::hex_of(&inv.from_pubkey))
                    .map(|f| f.alias.clone())
                    .unwrap_or_else(|| inv.from_name.clone());
                println!(
                    "{:>4}  {:<20} от {from} (истекает через {})",
                    inv.gid,
                    inv.group_name,
                    engine::fmt_secs(inv.expires_in)
                );
            }
            if items.is_empty() {
                println!("(приглашений нет)");
            } else {
                if !complete {
                    println!(
                        "… показаны не все (остальные не получены — потеря пакетов), повторите"
                    );
                }
                println!("принять: join <gid> · отклонить: decline <gid>");
            }
            Ok(())
        })?,
        "decline" => {
            let gid = parse_gid(rest.first())?;
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                // Без списка не проверить, есть ли приглашение («отклонено»
                // было бы неправдой: DECLINE идемпотентен).
                let Some(mut list) = conn.invite_list()? else {
                    bail!("список приглашений не получен (потеря пакетов) — отказ не отправлен");
                };
                // Окно после HELLO — первые 16 по gid; gid дальше него —
                // окно с самого gid (иначе отказ от несуществующего
                // приглашения «прошёл» бы: DECLINE идемпотентен).
                if !list.covers(gid) {
                    list = conn.invite_page(gid)?.context(
                        "список приглашений не получен (потеря пакетов) — отказ не отправлен",
                    )?;
                }
                if !list.items.iter().any(|i| i.gid == gid) {
                    bail!("нет приглашения в группу {gid}");
                }
                // Сервер отвечает на DECLINE_INVITE свежим окном, покрывающим
                // gid, — это и подтверждение: gid в нём нет. DECLINE
                // идемпотентен, при потере (или запоздавшем старом списке) —
                // повтор.
                for _ in 0..3 {
                    conn.send_ctrl(ctrl::DECLINE_INVITE, &payloads::enc_gid(gid));
                    match conn.wait_for(ctrl::INVITE_LIST, std::time::Duration::from_secs(3)) {
                        Ok(p) => {
                            let l = payloads::dec_invite_list(&p)?;
                            if l.covers(gid) && !l.items.iter().any(|i| i.gid == gid) {
                                println!("приглашение в {gid} отклонено");
                                return Ok(());
                            }
                        }
                        Err(e) if e.to_string().starts_with("сервер:") => return Err(e),
                        Err(_) => {}
                    }
                }
                bail!("сервер не подтвердил отказ — повторите")
            })?;
        }
        "leave" => {
            let gid = parse_gid(rest.first())?;
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::LEAVE_GROUP, &payloads::enc_gid(gid));
                conn.wait_for(ctrl::CTRL_PING, std::time::Duration::from_secs(3))
                    .ok(); // ждём ERROR
                autojoin_remove(&store, server, gid)?;
                println!("вышел из {gid} (autojoin снят)");
                Ok(())
            })?;
        }
        "invite" | "kick" | "ban" | "unban" | "transfer" => {
            let gid = parse_gid(rest.first())?;
            let peer = rest
                .get(1)
                .context(format!("usage: {cmd} <gid> <peer (code|hex|alias)>"))?;
            let target = store::resolve_peer(&cfg, peer)?;
            let typ = match cmd.as_str() {
                "invite" => ctrl::INVITE,
                "kick" => ctrl::KICK,
                "ban" => ctrl::BAN,
                "unban" => ctrl::UNBAN,
                _ => ctrl::TRANSFER_OWNER,
            };
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(typ, &payloads::enc_gid_target(gid, &target));
                let r = conn.wait_for(ctrl::CTRL_PING, std::time::Duration::from_secs(3));
                if let Err(e) = r
                    && e.to_string().contains("сервер:")
                {
                    bail!("{e}");
                }
                println!("{}: ок", cmd);
                Ok(())
            })?;
        }
        "rename" => {
            let gid = parse_gid(rest.first())?;
            let name = rest[1.min(rest.len())..].join(" ");
            bail_if_empty(&name, "usage: rename <gid> <имя>");
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::RENAME_GROUP, &payloads::enc_rename(gid, &name));
                let r = conn.wait_for(ctrl::CTRL_PING, std::time::Duration::from_secs(3));
                if let Err(e) = r
                    && e.to_string().contains("сервер:")
                {
                    bail!("{e}");
                }
                println!("переименовано");
                Ok(())
            })?;
        }
        "delete" => {
            let gid = parse_gid(rest.first())?;
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::DELETE_GROUP, &payloads::enc_gid(gid));
                let r = conn.wait_for(ctrl::CTRL_PING, std::time::Duration::from_secs(3));
                if let Err(e) = r
                    && e.to_string().contains("сервер:")
                {
                    bail!("{e}");
                }
                autojoin_remove(&store, server, gid)?;
                println!("группа {gid} удалена");
                Ok(())
            })?;
        }
        "friend-groups" => {
            let peer = rest.first().context("usage: friend-groups <peer>")?;
            let target = store::resolve_peer(&cfg, peer)?;
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::FRIEND_GROUPS, &payloads::enc_pubkey(&target));
                // Ответ — о ком спрошено (target в ответе).
                let items = loop {
                    let p = conn
                        .wait_for(ctrl::FRIEND_GROUPS_RESP, std::time::Duration::from_secs(10))?;
                    let f = payloads::dec_friend_groups(&p)?;
                    if f.target == target {
                        break f.groups;
                    }
                };
                if items.is_empty() {
                    println!("(у друга нет видимых групп)");
                }
                for g in items {
                    println!(
                        "{:>4}  {:<20} {} {}",
                        g.gid,
                        g.name,
                        if g.private { "[private]" } else { "[public] " },
                        if g.shared { "(общая)" } else { "" }
                    );
                }
                Ok(())
            })?;
        }
        "bans" => {
            let gid = parse_gid(rest.first())?;
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::GROUP_ADMIN, &payloads::enc_gid(gid));
                let info = loop {
                    let p = conn.wait_for(ctrl::ADMIN_INFO, std::time::Duration::from_secs(10))?;
                    let a = payloads::dec_admin_info(&p)?;
                    if a.gid == gid {
                        break a;
                    }
                };
                let who = |pk: &[u8; 32], name: &str| {
                    let alias = cfg2
                        .friends
                        .iter()
                        .find(|f| f.pubkey == proto::hex_of(pk))
                        .map(|f| f.alias.clone());
                    let shown = alias.unwrap_or_else(|| {
                        if name.is_empty() {
                            "(без имени)".into()
                        } else {
                            name.to_string()
                        }
                    });
                    format!("{shown:<20} {}", proto::friend_code_of(pk))
                };
                println!("баны группы {gid}:");
                if info.bans.is_empty() {
                    println!("  (нет)");
                }
                for b in &info.bans {
                    println!("  {}", who(&b.pubkey, &b.name));
                }
                println!("неотвеченные приглашения:");
                if info.invites.is_empty() {
                    println!("  (нет)");
                }
                for i in &info.invites {
                    println!(
                        "  {}  истекает через {}",
                        who(&i.pubkey, &i.name),
                        engine::fmt_secs(i.expires_in)
                    );
                }
                println!("снять бан: unban {gid} <peer> · отозвать приглашение: kick {gid} <peer>");
                Ok(())
            })?;
        }
        "invisible" => {
            let on = parse_on_off(rest.first(), "usage: invisible on|off")?;
            cfg.invisible = on;
            save(&cfg)?;
            // Флаг уходит в HELLO3: на сервере он живёт, пока жива сессия.
            println!(
                "невидимка {}: применится при следующем подключении (tui/run)",
                if on {
                    "включена"
                } else {
                    "выключена"
                }
            );
        }
        "add-friend" => {
            let code = rest.first().context("usage: add-friend <code> [alias]")?;
            let pk = proto::Identity::parse_friend_code(code)?;
            let alias = rest.get(1).cloned().unwrap_or_else(|| code.clone());
            if cfg.friends.iter().any(|f| f.pubkey == proto::hex_of(&pk)) {
                bail!("друг уже добавлен");
            }
            cfg.friends.push(StoredFriend {
                pubkey: proto::hex_of(&pk),
                alias: alias.clone(),
            });
            save(&cfg)?;
            println!("друг добавлен: {} ({})", alias.clone(), proto::hex_of(&pk));
        }
        "del-friend" => {
            let alias = rest.first().context("usage: del-friend <alias>")?;
            let before = cfg.friends.len();
            cfg.friends.retain(|f| &f.alias != alias);
            if cfg.friends.len() == before {
                bail!("друг {alias:?} не найден");
            }
            save(&cfg)?;
            println!("удалён");
        }
        "alias" => {
            let usage = "usage: alias <friend (alias|code|hex)> <новое имя>";
            let peer = rest.first().context(usage)?;
            let name = rest[1.min(rest.len())..].join(" ");
            bail_if_empty(&name, usage);
            let pk = proto::hex_of(&store::resolve_peer(&cfg, peer)?);
            if cfg
                .friends
                .iter()
                .any(|f| f.alias == name && f.pubkey != pk)
            {
                bail!("имя {name:?} уже занято другим другом");
            }
            let f = cfg
                .friends
                .iter_mut()
                .find(|f| f.pubkey == pk)
                .with_context(|| format!("друг {peer:?} не найден"))?;
            f.alias = name.clone();
            save(&cfg)?;
            println!("друг переименован: {name}");
        }
        "export-identity" => {
            let a = parse_identity_args("export-identity", rest)?;
            export_identity_cmd(&identity, &a)?;
        }
        "set-transport" => {
            cfg.transport = parse_transport(rest.first())?;
            save(&cfg)?;
            println!(
                "транспорт: {} (применится при следующем подключении)",
                format!("{:?}", cfg.transport).to_lowercase()
            );
        }
        "set-mtu" => {
            cfg.mtu = parse_mtu(rest.first())?;
            save(&cfg)?;
            println!("MTU: {} (применится при следующем подключении)", cfg.mtu);
        }
        "dns" => {
            cfg.dns = parse_on_off(rest.first(), "usage: dns on|off")?;
            save(&cfg)?;
            println!(
                "DNS для имён пиров {}: применится при следующем подключении",
                if cfg.dns {
                    "включён"
                } else {
                    "выключен"
                }
            );
        }
        "friends" => {
            if cfg.friends.is_empty() {
                println!("(нет друзей; добавь: add-friend <code> [alias])");
            }
            for f in &cfg.friends {
                println!("{:<16} {}", f.alias, f.pubkey);
            }
        }
        "run" | "tui" | "ui" => {
            let tui_mode = cmd != "run";
            if !tui_mode && ui_mode.is_some() {
                bail!("--embedded / --remote — только для tui");
            }
            // tui: демон есть → тонкий клиент; Hello не прошёл → ошибка без
            // фолбэка (два движка с одной identity выбивают друг друга).
            if tui_mode && ui_mode != Some(UiMode::Embedded) {
                let ep = Endpoint::for_data_dir(&dir);
                let live = ep.open().with_context(|| {
                    format!("демон ({}) есть, но подключиться нельзя", ep.describe())
                })?;
                match live {
                    Some(_probe) => return run_remote_tui(&ep, &dir, &cfg),
                    None if ui_mode == Some(UiMode::Remote) => {
                        bail!(
                            "демон не запущен ({}); без --remote tui поднимет свой движок",
                            ep.describe()
                        )
                    }
                    None => {}
                }
            }
            // Свой движок: замок single-instance (демон / другой TUI / run).
            let _lock = match InstanceLock::acquire(&dir) {
                Ok(l) => l,
                Err(LockError::Busy) => bail!(
                    "движок уже запущен (embedded TUI, run или демон без IPC) — второй с той же identity \
выбил бы его с сервера; закройте его или подключайтесь к демону"
                ),
                Err(e) => bail!("{e}"),
            };
            // Первичная настройка: если конфиг не заполнен (нет имени или
            // серверов) и флаги не заданы — спрашиваем прямо в TUI, до старта
            // движка. Консольному `run` достаточно CLI-подсказки.
            if tui_mode && (cfg.name.is_empty() || cfg.servers.is_empty()) {
                // Свой движок: адаптер и dll — наши, спрашиваем и запоминаем.
                if !tui::setup::run(
                    &mut cfg,
                    &mut adapter,
                    &mut dll,
                    true,
                    &identity.friend_code(),
                )? {
                    bail!(
                        "настройка не завершена; запусти ещё раз или задай параметры командами CLI"
                    );
                }
                // Адаптер и dll — в конфиг: иначе введённое при первом старте
                // терялось и следующий запуск спрашивал бы заново.
                cfg.adapter = adapter.clone();
                cfg.dll = dll.clone().unwrap_or_default();
                save(&cfg)?;
            }
            if cfg.name.is_empty() {
                bail!(
                    "задай имя: set-name <имя> (или запусти `tunnel-client tui` — настройка там)"
                );
            }
            let (server, pub_key) = pick_server(&cfg, server_sel.as_deref())?;
            save(&cfg)?;
            let cfg = Arc::new(cfg);
            let store = Arc::new(store::Store::new(&dir));
            if !tui_mode {
                // Автовход, ротация ключа сервера, невидимка — в client.json.
                let save_store = store.clone();
                let save = Arc::new(move |c: &Config| {
                    let _ = save_store.save(c);
                });
                engine::run(cfg, server, pub_key, identity.clone(), &adapter, dll, save)?;
            } else {
                tui::run(cfg, server, pub_key, identity.clone(), &adapter, dll, store)?;
            }
        }
        other => {
            eprintln!("неизвестная команда: {other:?}");
            usage();
            std::process::exit(2);
        }
    }
    Ok(())
}

/// `tui` тонким клиентом демона. Первичная настройка — командами демону.
fn run_remote_tui(ep: &Endpoint, dir: &std::path::Path, local: &Config) -> Result<()> {
    use tunnel_client::api::EngineApi;
    let eng = IpcEngine::connect(ep, Some(dir.to_path_buf()))?;
    let snap = eng.snapshot();
    if snap.cfg.name.is_empty() || snap.cfg.servers.is_empty() {
        let mut c = snap.cfg.to_config();
        // Адаптер и dll в тонком режиме задаёт демон (служба): спрашивать их
        // здесь нельзя — поле было бы обязательным, а применять его некуда,
        // и первичную настройку нельзя было бы завершить.
        let (mut adapter, mut dll) = (String::new(), None);
        if !tui::setup::run(&mut c, &mut adapter, &mut dll, false, &eng.me().my_code)? {
            bail!("настройка не завершена; запусти ещё раз или задай параметры командами CLI");
        }
        if c.name != snap.cfg.name {
            eng.send(engine::Cmd::SetName(c.name.clone()))?;
        }
        for s in c
            .servers
            .iter()
            .filter(|s| !snap.cfg.servers.iter().any(|x| x.addr == s.addr))
        {
            let pubkey: [u8; 32] = proto::hex_to_bytes(&s.pubkey)
                .ok()
                .and_then(|v| v.try_into().ok())
                .with_context(|| format!("неверный ключ сервера {}", s.addr))?;
            eng.send(engine::Cmd::AddServer {
                addr: s.addr.clone(),
                pubkey,
                label: s.label.clone(),
            })?;
        }
        // Команды уходят демону без ответа: ждём, пока он их применит, —
        // иначе настройка молча пропала бы (имя/сервер не сохранены).
        let want: Vec<String> = c.servers.iter().map(|s| s.addr.clone()).collect();
        wait_daemon_cfg(&eng, &c.name, &want, std::time::Duration::from_secs(10))?;
    }
    // Тема — локальная: ui.json (client.json при демоне — его).
    let mut ui = local.clone();
    let prefs = UiPrefs::load(dir);
    if !prefs.theme.is_empty() {
        ui.theme = prefs.theme;
    }
    tui::run_remote(eng, &ui)
}

/// Ждёт, пока демон применит правки конфига: снимок с нужным именем и
/// серверами. Если демон не подтвердил — его ошибка (или «не сохранил»).
fn wait_daemon_cfg(
    eng: &IpcEngine,
    want_name: &str,
    want_servers: &[String],
    timeout: std::time::Duration,
) -> Result<()> {
    use tunnel_client::api::EngineApi;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let s = eng.snapshot();
        let name_ok = s.cfg.name == want_name;
        let srv_ok = want_servers
            .iter()
            .all(|a| s.cfg.servers.iter().any(|x| x.addr == *a));
        if name_ok && srv_ok {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            // Причину отказа демона забираем из событий (ошибка пришла
            // событием, а не в ответе на команду).
            let mut why = String::new();
            for ev in eng.poll_events() {
                if let engine::Event::Error(e) = ev {
                    why = e;
                }
            }
            if !why.is_empty() {
                bail!("демон: {why}");
            }
            bail!(
                "демон не сохранил настройку (имя «{want_name}») — задай параметры командами CLI \
                 (set-name, add-server)"
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Подсказка по флагам `run` для текущей ОС.
fn run_flags_help() -> &'static str {
    if cfg!(windows) {
        "--adapter <имя wintun-адаптера> --dll <путь к wintun.dll>; нужен запуск от администратора"
    } else if cfg!(target_os = "linux") {
        "--adapter <имя интерфейса, по умолчанию voidlink0>; нужен root или CAP_NET_ADMIN"
    } else {
        "адаптер — utunN, выбирается автоматически; нужен запуск через sudo"
    }
}

fn usage() {
    println!(
        r#"tunnel-client (протокол v3) — Hamachi-подобный VPN
global: --dir <path> --profile <имя> --debug --server <N|addr|label> (по умолчанию — последний использованный)
  id                          friend code и identity
  set-name <имя>              имя профиля
  set-status <текст>          статус
  add-server <addr> <code> [label]
  servers | del-server <N|addr|label>
  groups                      список групп
  create <имя> [--private]    создать группу
  join <gid> | leave <gid> | delete <gid>
  invites | decline <gid>     приглашения: список / отклонить
  invite <gid> <peer> | kick <gid> <peer> | ban <gid> <peer>
  unban <gid> <peer>          снять бан
  bans <gid>                  баны и неотвеченные приглашения (владелец)
  transfer <gid> <peer>       передать группу участнику
  rename <gid> <имя>
  friend-groups <peer>
  add-friend <code> [alias] | del-friend <alias> | friends
  alias <friend> <имя>        переименовать друга локально
  export-identity <файл> [--passphrase <p>|--passphrase-stdin] [--force]
  import-identity <файл> [--passphrase <p>|--passphrase-stdin] [--force]
  set-transport auto|udp|tcp  транспорт до сервера
  set-mtu <N>                 MTU адаптера (576..1500)
  dns on|off                  встроенный DNS для имён пиров (*.vl)
  invisible on|off            невидимка: другие видят вас офлайн
  run                         поднять туннель (global: --adapter --dll --server <N>, см. ниже)
  tui [--embedded|--remote]   то же, но с графическим интерфейсом (ratatui);
                              при работающем демоне — тонкий клиент без прав админа
peer = friend code (TUN-…) | hex | alias

Если при запуске tui имя или сервер не заданы — сначала открывается
экран первичной настройки (Enter — применить, Esc — отмена).
При работающем демоне команды уходят ему (IPC), а не своим сеансом."#
    );
    println!("run/tui: {}", run_flags_help());
}

fn bail_if_empty(s: &str, msg: &str) {
    if s.trim().is_empty() {
        eprintln!("{msg}");
        std::process::exit(2);
    }
}

fn parse_gid(v: Option<&String>) -> Result<u32> {
    let v = v.context("нужен gid")?;
    v.parse::<u32>().context("gid должен быть числом")
}

/// Индекс сервера по токену: номер из `servers` (с 0), адрес или метка.
fn find_server(cfg: &Config, tok: &str) -> Option<usize> {
    if let Some(i) = cfg
        .servers
        .iter()
        .position(|s| s.addr == tok || (!s.label.is_empty() && s.label == tok))
    {
        return Some(i);
    }
    tok.parse::<usize>().ok().filter(|n| *n < cfg.servers.len())
}

/// Выбор сервера: --server <N|addr|label>, иначе последний использованный
/// (`active_server`, его же автовход), иначе первый в списке.
fn pick_server(cfg: &Config, sel: Option<&str>) -> Result<(SocketAddr, [u8; 32])> {
    let active = cfg.servers.iter().find(|s| {
        s.addr
            .parse::<SocketAddr>()
            .is_ok_and(|a| a.to_string() == cfg.active_server)
    });
    let entry = match sel {
        // Раньше `--server N` всегда выбирал первый сервер.
        Some(tok) => {
            &cfg.servers
                [find_server(cfg, tok).with_context(|| format!("сервер {tok:?} не найден"))?]
        }
        None => active
            .or(cfg.servers.first())
            .context("нет серверов; добавь: add-server <addr> <code>")?,
    };
    let addr: SocketAddr = entry.addr.parse().context("bad server addr")?;
    let pkv = proto::hex_to_bytes(&entry.pubkey).context("bad server pubkey")?;
    anyhow::ensure!(pkv.len() == 32, "bad server pubkey");
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pkv);
    Ok((addr, pk))
}

/// Правка client.json по свежей копии с диска: CLI-команда не затирает
/// то, что успела записать раньше (ротация ключа сервера, автовход).
fn persist<T>(store: &store::Store, f: impl FnOnce(&mut Config) -> T) -> Result<T> {
    let mut c = store.load().context("чтение конфига")?;
    let r = f(&mut c);
    store.save(&c).context("запись конфига")?;
    Ok(r)
}

/// Одноразовое соединение с сервером. Ключ, перезакреплённый по цепочке
/// ротации (WELCOME), сразу сохраняется.
fn connect(
    store: &store::Store,
    cfg: &Config,
    server: SocketAddr,
    pub_key: &[u8; 32],
    identity: &proto::Identity,
) -> Result<engine::CtrlConn> {
    let conn = engine::CtrlConn::connect(cfg, server, pub_key, identity)?;
    if let Some(new_ed) = conn.rotated {
        persist(store, |c| c.repin_server(server, &new_ed))?;
        eprintln!(
            "ключ сервера {server} сменён по цепочке ротации; закреплён новый: {}",
            proto::friend_code_of(&new_ed)
        );
    }
    Ok(conn)
}

/// Автовход в `gid` сервера `server`. `true` — добавлен.
fn autojoin_add(store: &store::Store, server: SocketAddr, gid: u32) -> Result<bool> {
    persist(store, |c| {
        c.activate_server(server);
        let add = !c.autojoin.contains(&gid);
        if add {
            c.autojoin.push(gid);
        }
        add
    })
}

fn autojoin_remove(store: &store::Store, server: SocketAddr, gid: u32) -> Result<()> {
    persist(store, |c| {
        c.activate_server(server);
        c.autojoin.retain(|g| *g != gid);
    })
}

/// Выполняет замыкание с выбранным сервером.
fn with_server<T>(
    cfg: &Config,
    sel: Option<&str>,
    f: impl FnOnce(SocketAddr, [u8; 32], &Config) -> Result<T>,
) -> Result<T> {
    let (server, pub_key) = pick_server(cfg, sel)?;
    f(server, pub_key, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srv(addr: &str, label: &str) -> StoredServer {
        StoredServer {
            addr: addr.into(),
            pubkey: String::new(),
            label: label.into(),
        }
    }

    #[test]
    fn сервер_по_номеру_адресу_метке() {
        let cfg = Config {
            servers: vec![
                srv("1.1.1.1:5555", "home"),
                srv("2.2.2.2:5555", ""),
                srv("3.3.3.3:5555", "work"),
            ],
            ..Config::default()
        };
        assert_eq!(
            find_server(&cfg, "1"),
            Some(1),
            "номер — индекс, а не «всегда первый»"
        );
        assert_eq!(find_server(&cfg, "2"), Some(2));
        assert_eq!(find_server(&cfg, "3"), None);
        assert_eq!(find_server(&cfg, "3.3.3.3:5555"), Some(2));
        assert_eq!(find_server(&cfg, "home"), Some(0));
        assert_eq!(
            find_server(&cfg, ""),
            None,
            "пустая метка не совпадает с сервером без метки"
        );
    }

    fn sv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "vl-cli-{tag}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn глобальные_флаги_в_любом_месте() {
        let g = parse_globals(sv(&[
            "--debug",
            "join",
            "--server",
            "home",
            "5",
            "--profile",
            "work",
            "--dir",
            "/x",
        ]))
        .unwrap();
        assert!(g.debug);
        assert_eq!(g.server_sel.as_deref(), Some("home"));
        assert_eq!(g.profile.as_deref(), Some("work"));
        assert_eq!(g.args, sv(&["join", "5"]));
        assert_eq!(g.adapter, engine::DEFAULT_ADAPTER);
        assert_eq!(
            g.data_dir().unwrap(),
            std::path::Path::new("/x").join("profiles").join("work")
        );

        let g = parse_globals(sv(&["--dir", "/x", "id"])).unwrap();
        assert_eq!(g.data_dir().unwrap(), std::path::PathBuf::from("/x"));
        assert!(
            parse_globals(sv(&["--profile", "../evil"])).is_err(),
            "имя профиля проверяется"
        );
        assert!(parse_globals(sv(&["id", "--profile"])).is_err());
        assert!(parse_globals(sv(&["--dir"])).is_err());
    }

    #[test]
    fn аргументы_identity() {
        let a = parse_identity_args(
            "export-identity",
            &sv(&["f.json", "--passphrase", "p w", "--force"]),
        )
        .unwrap();
        assert_eq!(
            a,
            IdentityArgs {
                file: "f.json".into(),
                passphrase: Some("p w".into()),
                passphrase_stdin: false,
                force: true
            }
        );
        let a =
            parse_identity_args("import-identity", &sv(&["--passphrase-stdin", "f.json"])).unwrap();
        assert!(a.passphrase_stdin && a.passphrase.is_none() && !a.force);
        assert!(parse_identity_args("x", &sv(&[])).is_err(), "нужен файл");
        assert!(parse_identity_args("x", &sv(&["a", "b"])).is_err());
        assert!(parse_identity_args("x", &sv(&["a", "--passphrase"])).is_err());
        assert!(parse_identity_args("x", &sv(&["a", "--passphrase", ""])).is_err());
        assert!(
            parse_identity_args("x", &sv(&["a", "--passphrase", "p", "--passphrase-stdin"]))
                .is_err()
        );
        assert!(parse_identity_args("x", &sv(&["a", "--bogus"])).is_err());
    }

    #[test]
    fn настройки_mtu_transport_on_off() {
        assert_eq!(parse_mtu(Some(&"1280".into())).unwrap(), 1280);
        assert!(parse_mtu(Some(&"100".into())).is_err());
        assert!(parse_mtu(Some(&"9000".into())).is_err());
        assert!(parse_mtu(Some(&"abc".into())).is_err());
        assert!(parse_mtu(None).is_err());
        assert_eq!(
            parse_transport(Some(&"TCP".into())).unwrap(),
            store::TransportMode::Tcp
        );
        assert_eq!(
            parse_transport(Some(&"auto".into())).unwrap(),
            store::TransportMode::Auto
        );
        assert!(parse_transport(Some(&"quic".into())).is_err());
        assert!(parse_on_off(Some(&"on".into()), "u").unwrap());
        assert!(!parse_on_off(Some(&"off".into()), "u").unwrap());
        assert!(parse_on_off(Some(&"yes".into()), "u").is_err());
        let cfg: Config = serde_json::from_str("{}").unwrap();
        assert_eq!(
            cfg.transport,
            store::TransportMode::Auto,
            "старый конфиг — транспорт auto"
        );
        assert!(cfg.dns, "старый конфиг — встроенный DNS включён");
    }

    #[test]
    fn экспорт_и_импорт_в_профиль() {
        let base = tmp_dir("prof");
        let src = store::Store::new(&base);
        let mut cfg = Config::default();
        let id = store::ensure_identity(&mut cfg);
        src.save(&cfg).unwrap();

        let file = base.join("id.json");
        let a = IdentityArgs {
            file: file.clone(),
            passphrase: None,
            passphrase_stdin: false,
            force: false,
        };
        export_identity_cmd(&id, &a).unwrap();
        assert!(
            export_identity_cmd(&id, &a).is_err(),
            "существующий файл без --force не затирается"
        );
        export_identity_cmd(&id, &IdentityArgs { force: true, ..a }).unwrap();

        // Свежий профиль: импорт без --force (identity ещё нет).
        let g = parse_globals(sv(&[
            "--dir",
            base.to_str().unwrap(),
            "--profile",
            "laptop",
        ]))
        .unwrap();
        let dst = store::Store::new(&g.data_dir().unwrap());
        let imp = IdentityArgs {
            file: file.clone(),
            passphrase: None,
            passphrase_stdin: false,
            force: false,
        };
        import_identity_cmd(&dst, &imp).unwrap();
        let got = store::ensure_identity(&mut dst.load().unwrap());
        assert_eq!(got.friend_code(), id.friend_code());
        // Повторный импорт той же identity — no-op.
        import_identity_cmd(&dst, &imp).unwrap();

        // Другая identity поверх — только с --force.
        let other = proto::Identity::generate();
        let file2 = base.join("other.json");
        profile::export_to_file(&file2, &other, None).unwrap();
        let imp2 = IdentityArgs {
            file: file2,
            passphrase: None,
            passphrase_stdin: false,
            force: false,
        };
        assert!(import_identity_cmd(&dst, &imp2).is_err());
        import_identity_cmd(
            &dst,
            &IdentityArgs {
                force: true,
                ..imp2
            },
        )
        .unwrap();
        let got = store::ensure_identity(&mut dst.load().unwrap());
        assert_eq!(got.friend_code(), other.friend_code());
        assert_eq!(
            profile::list_profiles(&base).unwrap(),
            vec!["laptop".to_string()]
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
