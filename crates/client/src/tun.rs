//! Управление Wintun-адаптером: загрузка dll, создание, адреса, файрвол.

use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result};

pub fn load_wintun_dll(explicit: Option<&str>) -> Result<wintun::Wintun> {
    // SAFETY: загрузка подписанного драйвера wintun.
    if let Some(p) = explicit {
        return unsafe { wintun::load_from_path(p) }.context(format!("cannot load {p}"));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let p = dir.join("wintun.dll");
        if p.exists() {
            return unsafe { wintun::load_from_path(&p) }
                .context(format!("cannot load {}", p.display()));
        }
    }
    unsafe { wintun::load_from_path("wintun.dll") }
        .context("wintun.dll not found (положи рядом с exe или укажи --dll)")
}

/// Создаёт (или открывает существующий) адаптер.
pub fn create_adapter(wintun: &wintun::Wintun, name: &str) -> Result<Arc<wintun::Adapter>> {
    match wintun::Adapter::create(wintun, name, "Tunnel", None) {
        Ok(a) => {
            eprintln!("[tun] adapter {name} created");
            Ok(a)
        }
        Err(_) => {
            let a = wintun::Adapter::open(wintun, name)
                .context("не удалось создать/открыть wintun-адаптер (запуск от администратора?)")?;
            eprintln!("[tun] adapter {name} reused");
            Ok(a)
        }
    }
}

/// Назначает адаптеру адрес оверлея с маской /16 (протокол v4: один адрес
/// на все группы). `netsh set address` заменяет все IPv4-адреса адаптера —
/// заодно снимает адреса прошлого запуска и прошлого сервера. `current` —
/// уже назначенный адрес (тот же — ничего не делаем).
pub fn ensure_address(adapter: &wintun::Adapter, current: &mut Option<u32>, ip: u32) -> Result<()> {
    if *current == Some(ip) {
        return Ok(());
    }
    let addr: Ipv4Addr = ip.into();
    let mask = Ipv4Addr::from(tunnel_protocol::OVERLAY_MASK);
    adapter
        .set_network_addresses_tuple(addr.into(), mask.into(), None)
        .context("set adapter address")?;
    *current = Some(ip);
    Ok(())
}

pub fn set_mtu(adapter: &wintun::Adapter, mtu: usize) -> Result<()> {
    adapter.set_mtu(mtu).context("set mtu")
}

/// Разово разрешает входящий трафик на интерфейсе (best effort).
pub fn allow_firewall(adapter_name: &str) {
    let rule = format!("name=\"{adapter_name} Allow\"");
    let _ = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", &rule])
        .output();
    let _ = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &rule,
            "dir=in",
            "action=allow",
            &format!("interface={adapter_name}"),
        ])
        .output();
}
