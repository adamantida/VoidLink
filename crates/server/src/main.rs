//! tunnel-server: точка входа. Логика — в библиотеке крейта (`lib.rs`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};

const USAGE: &str = "\
Использование:
  tunnel-server [адрес=0.0.0.0:5555] [флаги]
  tunnel-server rotate-key [--data <dir>]

Флаги:
  --data <dir>              каталог состояния (server.json), по умолчанию tunnel-data
  --workers N               потоков-воркеров (0 — по числу ядер, до 8)
  -q, --quiet               не печатать события
  --relay-rate R            релей: фреймов/с на сессию (4000)
  --relay-burst B           релей: запас фреймов (8000)
  --ctrl-rate R             управляющих фреймов/с на сессию (50)
  --ctrl-burst B            запас управляющих фреймов (100)
  --hello-rate R            HELLO и открытых ответов в секунду на IP (5)
  --hello-burst B           запас HELLO на IP (20)
  --plain-rate R            открытых ответов без cookie в секунду на весь сервер (2000)
  --plain-burst B           их запас (4000)
  --join-rate R             входов в группу в секунду на группу (1)
  --join-burst B            их запас (10)
  --session-timeout <сек>   сессия без пакетов столько — офлайн (30)
  --max-owned-groups N      групп во владении одной identity (16)
  --invite-ttl-days N       срок жизни приглашения, дней (7)
  --max-invites-per-group N приглашений на группу (256)
  --max-bans-per-group N    банов на группу (1024)
  --max-invites-per-target N живых приглашений одной identity по всем группам (64)
  --tcp / --no-tcp          TCP-фолбэк на том же порту, что UDP (включён)
  --metrics <addr>          HTTP-метрики: /metrics (Prometheus) и /healthz,
                            например 127.0.0.1:9100 (по умолчанию выключены)

SIGTERM/SIGINT (Windows: Ctrl+C, закрытие консоли) — корректная остановка:
воркеры останавливаются, состояние сохраняется, код выхода 0. Повторный
сигнал во время остановки — немедленный выход с кодом 1.

rotate-key: сменить ключ сервера. Старый ключ подписывает новый, звено
дописывается в server.json; клиенты со старым кодом перезакрепляются сами,
новым выдаётся напечатанный код. Новый ключ действует с (пере)запуска
сервера: запущенный на том же каталоге сервер его не затирает.";

fn value<T: FromStr>(args: &[String], i: usize, flag: &str) -> Result<T> {
    args.get(i + 1)
        .with_context(|| format!("{flag}: нужно значение"))?
        .parse()
        .map_err(|_| anyhow::anyhow!("{flag}: неверное значение {:?}", args[i + 1]))
}

fn rotate_key(args: &[String]) -> Result<()> {
    let mut data_dir: PathBuf = tunnel_server::default_data_dir().into();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                eprintln!("{USAGE}");
                return Ok(());
            }
            "--data" => {
                data_dir = value::<String>(args, i, "--data")?.into();
                i += 1;
            }
            other => anyhow::bail!("rotate-key: неизвестный аргумент {other:?}"),
        }
        i += 1;
    }
    let r = tunnel_server::rotate_key(&data_dir)?;
    println!("Ключ сервера сменён (звеньев в цепочке: {}).", r.links);
    println!("Старый код: {}", r.old_code);
    println!("Новый код:  {}", r.code);
    println!("Pubkey:     {}", tunnel_protocol::hex_of(&r.pubkey));
    println!("Если сервер запущен — новый ключ вступит в силу после его перезапуска.");
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("rotate-key") {
        return rotate_key(&args[1..]);
    }
    let mut cfg = tunnel_server::Config::default();
    let mut listen = "0.0.0.0:5555".to_string();
    let l = &mut cfg.limits;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-h" | "--help" => {
                eprintln!("{USAGE}");
                return Ok(());
            }
            "--data" => cfg.data_dir = value::<String>(&args, i, a)?.into(),
            "--workers" => cfg.workers = value(&args, i, a)?,
            "--relay-rate" => l.relay_rate = value(&args, i, a)?,
            "--relay-burst" => l.relay_burst = value(&args, i, a)?,
            "--ctrl-rate" => l.ctrl_rate = value(&args, i, a)?,
            "--ctrl-burst" => l.ctrl_burst = value(&args, i, a)?,
            "--hello-rate" => l.hello_rate = value(&args, i, a)?,
            "--hello-burst" => l.hello_burst = value(&args, i, a)?,
            "--plain-rate" => l.plain_rate = value(&args, i, a)?,
            "--plain-burst" => l.plain_burst = value(&args, i, a)?,
            "--join-rate" => l.join_rate = value(&args, i, a)?,
            "--join-burst" => l.join_burst = value(&args, i, a)?,
            "--session-timeout" => l.session_timeout = Duration::from_secs(value(&args, i, a)?),
            "--max-owned-groups" => l.max_owned_groups = value(&args, i, a)?,
            "--max-invites-per-group" => l.max_invites_per_group = value(&args, i, a)?,
            "--max-bans-per-group" => l.max_bans_per_group = value(&args, i, a)?,
            "--max-invites-per-target" => l.max_invites_per_target = value(&args, i, a)?,
            "--metrics" => {
                let m: String = value(&args, i, a)?;
                cfg.metrics = Some(
                    m.parse::<SocketAddr>()
                        .context("--metrics: неверный адрес")?,
                );
            }
            "--tcp" | "--no-tcp" => {
                cfg.tcp = a == "--tcp";
                i += 1;
                continue;
            }
            "--invite-ttl-days" => {
                let days: u64 = value(&args, i, a)?;
                l.invite_ttl = Duration::from_secs(days.saturating_mul(24 * 3600));
            }
            "-q" | "--quiet" => {
                cfg.quiet = true;
                i += 1;
                continue;
            }
            other if other.starts_with('-') => {
                anyhow::bail!("неизвестный флаг {other:?} (см. --help)")
            }
            other => {
                listen = other.to_string();
                i += 1;
                continue;
            }
        }
        // Флаг со значением.
        i += 2;
    }
    for (name, v) in [
        ("--relay-rate", l.relay_rate),
        ("--ctrl-rate", l.ctrl_rate),
        ("--hello-rate", l.hello_rate),
        ("--plain-rate", l.plain_rate),
        ("--join-rate", l.join_rate),
    ] {
        anyhow::ensure!(v.is_finite() && v > 0.0, "{name}: нужно число > 0");
    }
    for (name, v) in [
        ("--relay-burst", l.relay_burst),
        ("--ctrl-burst", l.ctrl_burst),
        ("--hello-burst", l.hello_burst),
        ("--plain-burst", l.plain_burst),
        ("--join-burst", l.join_burst),
    ] {
        anyhow::ensure!(v.is_finite() && v >= 1.0, "{name}: нужно число ≥ 1");
    }
    anyhow::ensure!(
        !l.session_timeout.is_zero(),
        "--session-timeout: нужно ≥ 1 с"
    );
    anyhow::ensure!(!l.invite_ttl.is_zero(), "--invite-ttl-days: нужно ≥ 1");
    cfg.listen = listen.parse::<SocketAddr>().context("bad listen addr")?;
    // Обработчики — до старта: сигнал в первые миллисекунды тоже корректно
    // останавливает сервер.
    let shutdown = tunnel_server::signals::Shutdown::install()?;
    let quiet = cfg.quiet;
    let server = tunnel_server::Server::start(cfg)?;
    shutdown.wait();
    if !quiet {
        eprintln!("[server] сигнал остановки: сохраняю состояние и выхожу");
    }
    // Останавливает воркеры, TCP и метрики, затем финальный save_now.
    server.stop();
    Ok(())
}
