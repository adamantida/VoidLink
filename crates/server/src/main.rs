//! tunnel-server: точка входа. Логика — в библиотеке крейта (`lib.rs`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};

/// Верхняя граница `--lease-ttl-days` (10 лет): защита от опечатки, а не
/// содержательный предел — `0` законно выключает освобождение.
const LEASE_TTL_DAYS_MAX: u64 = 3650;

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
  --lease-ttl-days N        аренда адреса оверлея без активности, дней (30);
                            0 — не освобождать адреса никогда
  --max-invites-per-group N приглашений на группу (256)
  --max-bans-per-group N    банов на группу (1024)
  --max-invites-per-target N живых приглашений одной identity по всем группам (64)
  --tcp / --no-tcp          TCP-фолбэк на том же порту, что UDP (включён)
  --metrics <addr>          HTTP-метрики: /metrics (Prometheus) и /healthz,
                            например 127.0.0.1:9100 (по умолчанию выключены)
  --federate                федерация серверов (этап 9): SRV_HELLO/ACK,
                            TOFU-пиннинг ключей пиров, репликация групп и
                            адресов, межсерверный релей, SERVER_HINT
  --peer <addr>             явный пин сервера-пира (можно повторять)
  --fed-pool <addr>         сервер общего пула адресов федерации (можно
                            повторять): обмен заявками адресов identity

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
    if args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("{USAGE}");
        return Ok(());
    }
    let cfg = parse_args(&args)?;
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

/// Разбор аргументов запуска сервера (всё, кроме `rotate-key` и `--help`).
fn parse_args(args: &[String]) -> Result<tunnel_server::Config> {
    let mut cfg = tunnel_server::Config::default();
    let mut listen = "0.0.0.0:5555".to_string();
    let l = &mut cfg.limits;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--data" => cfg.data_dir = value::<String>(args, i, a)?.into(),
            "--workers" => cfg.workers = value(args, i, a)?,
            "--relay-rate" => l.relay_rate = value(args, i, a)?,
            "--relay-burst" => l.relay_burst = value(args, i, a)?,
            "--ctrl-rate" => l.ctrl_rate = value(args, i, a)?,
            "--ctrl-burst" => l.ctrl_burst = value(args, i, a)?,
            "--hello-rate" => l.hello_rate = value(args, i, a)?,
            "--hello-burst" => l.hello_burst = value(args, i, a)?,
            "--plain-rate" => l.plain_rate = value(args, i, a)?,
            "--plain-burst" => l.plain_burst = value(args, i, a)?,
            "--join-rate" => l.join_rate = value(args, i, a)?,
            "--join-burst" => l.join_burst = value(args, i, a)?,
            "--session-timeout" => l.session_timeout = Duration::from_secs(value(args, i, a)?),
            "--max-owned-groups" => l.max_owned_groups = value(args, i, a)?,
            "--max-invites-per-group" => l.max_invites_per_group = value(args, i, a)?,
            "--max-bans-per-group" => l.max_bans_per_group = value(args, i, a)?,
            "--max-invites-per-target" => l.max_invites_per_target = value(args, i, a)?,
            "--metrics" => {
                let m: String = value(args, i, a)?;
                cfg.metrics = Some(
                    m.parse::<SocketAddr>()
                        .context("--metrics: неверный адрес")?,
                );
            }
            // Федерация серверов (этап 9, T4a).
            "--federate" => {
                cfg.federate = true;
                i += 1;
                continue;
            }
            "--peer" => {
                let s: String = value(args, i, a)?;
                cfg.peers.push(s.parse().context("--peer: неверный адрес")?);
            }
            "--fed-pool" => {
                let s: String = value(args, i, a)?;
                cfg.fed_pool
                    .push(s.parse().context("--fed-pool: неверный адрес")?);
            }
            "--tcp" | "--no-tcp" => {
                cfg.tcp = a == "--tcp";
                i += 1;
                continue;
            }
            "--invite-ttl-days" => {
                let days: u64 = value(args, i, a)?;
                l.invite_ttl = Duration::from_secs(days.saturating_mul(24 * 3600));
            }
            // Аренда адреса оверлея (issue #21): без активности столько дней
            // адрес возвращается в пул. 0 — освобождение выключено.
            "--lease-ttl-days" => {
                let days: u64 = value(args, i, a)?;
                l.lease_ttl = Duration::from_secs(days.saturating_mul(24 * 3600));
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
    // 0 — законное «не освобождать никогда»; верхняя граница — от опечатки
    // (лишний ноль превратил бы срок в тысячи лет, то есть в то же 0).
    anyhow::ensure!(
        l.lease_ttl.as_secs() <= LEASE_TTL_DAYS_MAX * 24 * 3600,
        "--lease-ttl-days: не больше {LEASE_TTL_DAYS_MAX} дней (0 — не освобождать)"
    );
    cfg.listen = listen.parse::<SocketAddr>().context("bad listen addr")?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<tunnel_server::Config> {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse_args(&args)
    }

    #[test]
    fn федерация_по_умолчанию_выключена() {
        let c = parse(&[]).unwrap();
        assert!(!c.federate);
        assert!(c.peers.is_empty() && c.fed_pool.is_empty());
        // Явный пин сам по себе федерацию не включает — нужен --federate.
        let c = parse(&["--peer", "192.0.2.1:5555"]).unwrap();
        assert!(!c.federate);
        assert_eq!(c.peers.len(), 1);
    }

    #[test]
    fn федеративные_флаги_разбираются() {
        let c = parse(&[
            "--federate",
            "--peer",
            "203.0.113.5:5555",
            "--peer",
            "[2001:db8::1]:7000",
            "--fed-pool",
            "198.51.100.9:443",
        ])
        .unwrap();
        assert!(c.federate);
        assert_eq!(c.peers.len(), 2, "флаг повторяемый");
        assert_eq!(c.peers[0], "203.0.113.5:5555".parse().unwrap());
        assert_eq!(c.peers[1].port(), 7000);
        assert_eq!(c.fed_pool.len(), 1);
        // Флаги не мешают остальным.
        let c = parse(&["--federate", "--quiet", "--workers", "2"]).unwrap();
        assert!(c.federate && c.quiet && c.workers == 2);
    }

    #[test]
    fn федеративные_флаги_с_опечаткой_ошибка() {
        assert!(parse(&["--peer", "не адрес"]).is_err());
        assert!(parse(&["--peer"]).is_err(), "нужно значение");
        assert!(parse(&["--fed-pool", "0.0.0.0"]).is_err());
        assert!(parse(&["--federate=да"]).is_err(), "неизвестный флаг");
        assert!(USAGE.contains("--federate") && USAGE.contains("--peer"));
    }

    #[test]
    fn lease_ttl_дней_разбирается() {
        let days = |n: u64| Duration::from_secs(n * 24 * 3600);
        // По умолчанию — 30 дней, как в `Limits::default`.
        assert_eq!(parse(&[]).unwrap().limits.lease_ttl, days(30));
        assert_eq!(
            parse(&["--lease-ttl-days", "7"]).unwrap().limits.lease_ttl,
            days(7)
        );
        // 0 — освобождение выключено (аренда не истекает никогда).
        assert_eq!(
            parse(&["--lease-ttl-days", "0"]).unwrap().limits.lease_ttl,
            Duration::ZERO
        );
        // Мусор, отрицательное и значение без числа отвергаются.
        assert!(parse(&["--lease-ttl-days", "abc"]).is_err());
        assert!(parse(&["--lease-ttl-days", "-1"]).is_err());
        assert!(parse(&["--lease-ttl-days"]).is_err(), "нужно значение");
        // Верхняя граница — от опечатки (лишний ноль), но не от 0.
        assert!(parse(&["--lease-ttl-days", "3650"]).is_ok());
        assert!(parse(&["--lease-ttl-days", "3651"]).is_err());
        assert!(parse(&["--lease-ttl-days", "999999999"]).is_err());
        assert!(USAGE.contains("--lease-ttl-days"));
        // Флаг не мешает остальным и не задевает срок приглашений.
        let c = parse(&["--lease-ttl-days", "3", "--invite-ttl-days", "5"]).unwrap();
        assert_eq!(c.limits.lease_ttl, days(3));
        assert_eq!(c.limits.invite_ttl, days(5));
    }
}
