//! Управление Wintun-адаптером: загрузка dll, создание, адреса, файрвол.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result};

pub fn load_wintun_dll(explicit: Option<&str>) -> Result<wintun::Wintun> {
    // SAFETY: загрузка подписанного драйвера wintun.
    if let Some(p) = explicit {
        return unsafe { wintun::load_from_path(p) }.context(format!("cannot load {p}"));
    }
    // Только рядом с exe: поиск по CWD/PATH в процессе с правами
    // администратора (`run` требует их) позволял бы обычному пользователю
    // подложить DLL в текущий каталог и получить код от администратора.
    // Служба грузит DLL так же — см. `winsvc::service_wintun_dll`.
    let p = default_dll_path()?;
    unsafe { wintun::load_from_path(&p) }.context(format!("cannot load {}", p.display()))
}

/// Путь к `wintun.dll` по умолчанию: только рядом с exe. Поиска по CWD/PATH
/// нет — в процессе с правами администратора это был бы DLL-хайджекинг.
fn default_dll_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("не удалось определить путь к exe")?;
    dll_next_to(&exe)
}

/// Ядро `default_dll_path` без обращения к окружению (тестируется отдельно).
fn dll_next_to(exe: &Path) -> Result<PathBuf> {
    let dir = exe.parent().context("у exe нет родительского каталога")?;
    let p = dir.join("wintun.dll");
    if !p.exists() {
        anyhow::bail!(
            "wintun.dll не найден рядом с {}; положи DLL в каталог установки или укажи --dll",
            exe.display()
        );
    }
    Ok(p)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dll_берётся_только_рядом_с_exe() {
        let dir = std::env::temp_dir().join(format!("vl-dll-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("tunnel-client.exe");
        let err = dll_next_to(&exe).unwrap_err().to_string();
        assert!(err.contains("рядом"), "нет подсказки про каталог: {err}");
        // Подложенная «рядом» DLL принимается: это каталог установки.
        std::fs::write(dir.join("wintun.dll"), b"not a real dll").unwrap();
        assert_eq!(dll_next_to(&exe).unwrap(), dir.join("wintun.dll"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
