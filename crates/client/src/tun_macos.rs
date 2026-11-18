//! utun-устройство macOS: системный control-сокет `com.apple.net.utun_control`.
//!
//! Каждый пакет в utun предваряется 4-байтным заголовком семейства адресов
//! (AF_INET / AF_INET6, big-endian). Наружу API выглядит как обычный TUN:
//! `open(mtu)`, `read`, `write`, `ensure_address(ip)`, `name()` — заголовок
//! добавляется/снимается внутри.
//!
//! Адреса групп: `ifconfig utunN inet <ip> <ip> netmask 255.255.255.0 [alias]`
//! плюс маршрут `route -n add -net 100.66.<gid>.0/24 -interface utunN`.
//! Повторный вызов для того же IP ничего не делает.
//!
//! Встроенный DNS (`100.66.0.53`, вне /24 групп) — отдельный маршрут
//! `route -n add -host 100.66.0.53 -interface utunN` ([`Utun::ensure_dns_route`]).

// подключается при интеграции
#![allow(dead_code)]

use std::collections::HashSet;
use std::ffi::CStr;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};

/// Имя ядерного контрола utun.
const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
/// Размер заголовка семейства адресов перед каждым пакетом.
const AF_HEADER_LEN: usize = 4;
/// Максимальный размер пакета, который читаем за раз (с запасом над MTU).
const MAX_PACKET: usize = 65535;

/// Открытое utun-устройство. Потокобезопасно: `read`/`write` можно звать
/// из разных потоков через `Arc<Utun>`.
pub struct Utun {
    fd: OwnedFd,
    name: String,
    /// Назначенный адрес оверлея (host order; один: протокол v4).
    v4: Mutex<Option<u32>>,
    /// Уже назначенные IPv6-адреса.
    v6: Mutex<HashSet<Ipv6Addr>>,
    /// Маршрут на встроенный DNS уже стоит.
    dns_route: AtomicBool,
}

impl Utun {
    /// Создаёт новый utun (ядро само выбирает свободный номер) и ставит MTU.
    /// Требует root.
    pub fn open(mtu: usize) -> Result<Self> {
        let fd = open_utun_fd().context("создание utun (запуск от root?)")?;
        let name = read_ifname(fd.as_raw_fd()).context("чтение имени utun")?;
        let dev = Utun {
            fd,
            name,
            v4: Mutex::new(None),
            v6: Mutex::new(HashSet::new()),
            dns_route: AtomicBool::new(false),
        };
        dev.set_mtu(mtu)?;
        run(&ifconfig_up_args(&dev.name)).context("ifconfig up")?;
        eprintln!("[tun] utun {} создан, mtu {mtu}", dev.name);
        Ok(dev)
    }

    /// Имя интерфейса, например `utun5`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Сырой дескриптор (для poll/select при интеграции).
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Ставит MTU через ifconfig.
    pub fn set_mtu(&self, mtu: usize) -> Result<()> {
        run(&mtu_args(&self.name, mtu)).context("ifconfig mtu")
    }

    /// Читает один IP-пакет (без 4-байтного заголовка) в `buf`.
    /// Блокирующий вызов. Возвращает длину пакета. Если пакет не влез в `buf`
    /// (MSG_TRUNC), возвращает `InvalidData` — обрезанный пакет дальше не идёт;
    /// буфер размером MTU (или `MAX_PACKET`) этого не допускает.
    /// Пакет с семейством, отличным от AF_INET/AF_INET6, тоже даёт `InvalidData`.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut hdr = [0u8; AF_HEADER_LEN];
        let mut iov = [
            libc::iovec {
                iov_base: hdr.as_mut_ptr().cast(),
                iov_len: AF_HEADER_LEN,
            },
            libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len().min(MAX_PACKET),
            },
        ];
        loop {
            // SAFETY: msghdr — POD, нули валидны; iov указывают на живые буферы нужной длины.
            let mut msg: libc::msghdr = unsafe { mem::zeroed() };
            msg.msg_iov = iov.as_mut_ptr();
            msg.msg_iovlen = iov.len() as _;
            // SAFETY: msg корректно заполнен, буферы живы на время вызова.
            let n = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut msg, 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if msg.msg_flags & libc::MSG_TRUNC != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "utun: пакет больше буфера, обрезан",
                ));
            }
            let n = n as usize;
            if n < AF_HEADER_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "utun: короткий пакет",
                ));
            }
            if !is_ip_family(af_from_header(hdr)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "utun: неизвестное семейство адресов",
                ));
            }
            return Ok(n - AF_HEADER_LEN);
        }
    }

    /// Пишет один IP-пакет; заголовок семейства выбирается по версии IP.
    pub fn write(&self, packet: &[u8]) -> io::Result<usize> {
        let Some(hdr) = af_header_for(packet) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "utun: не IPv4/IPv6 пакет",
            ));
        };
        let iov = [
            libc::iovec {
                iov_base: hdr.as_ptr() as *mut _,
                iov_len: AF_HEADER_LEN,
            },
            libc::iovec {
                iov_base: packet.as_ptr() as *mut _,
                iov_len: packet.len(),
            },
        ];
        loop {
            // SAFETY: iov указывают на живые буферы нужной длины, ядро их только читает.
            let n = unsafe { libc::writev(self.fd.as_raw_fd(), iov.as_ptr(), 2) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            return Ok((n as usize).saturating_sub(AF_HEADER_LEN));
        }
    }

    /// Назначает адрес оверлея (host order) и маршрут на 100.66.0.0/16.
    /// `ifconfig inet` без `alias` заменяет прежний адрес (прошлый сервер).
    /// Идемпотентно: повторный вызов с тем же IP ничего не делает.
    pub fn ensure_address(&self, ip: u32) -> Result<()> {
        let mut used = self.v4.lock().unwrap();
        if *used == Some(ip) {
            return Ok(());
        }
        run(&ifconfig_inet_args(&self.name, ip)).context("ifconfig inet")?;
        if let Err(e) = run(&route_add_args(&self.name)) {
            // Маршрут уже есть (например, после перезапуска) — это нормально.
            if !route_exists_error(&e.to_string()) {
                return Err(e).context("route add");
            }
        }
        *used = Some(ip);
        eprintln!("[tun] {} = {}", self.name, Ipv4Addr::from(ip));
        Ok(())
    }

    /// Маршрут на встроенный DNS (`100.66.0.53`) через этот utun:
    /// `/etc/resolver/vl` шлёт туда запросы `.vl`, а /24 групп его не
    /// покрывают. Идемпотентно (уже стоит — «File exists» не ошибка); после
    /// неудачи следующий вызов пробует снова.
    pub fn ensure_dns_route(&self) -> Result<()> {
        if self.dns_route.load(Ordering::Relaxed) {
            return Ok(());
        }
        if let Err(e) = run(&dns_route_args(&self.name))
            && !route_exists_error(&e.to_string())
        {
            return Err(e).context("route add DNS");
        }
        self.dns_route.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Назначает IPv6-адрес (опционально, для будущих групп v6).
    pub fn ensure_address_v6(&self, ip: Ipv6Addr, prefix: u8) -> Result<()> {
        let mut used = self.v6.lock().unwrap();
        if used.contains(&ip) {
            return Ok(());
        }
        run(&ifconfig_inet6_args(&self.name, ip, prefix)).context("ifconfig inet6")?;
        used.insert(ip);
        Ok(())
    }
}

// ---------- системные вызовы ----------

fn open_utun_fd() -> io::Result<OwnedFd> {
    // SAFETY: обычный socket(2); результат проверяется.
    let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw — только что созданный валидный дескриптор.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // Не наследовать дескриптор в дочерние ifconfig/route: ставим сразу после
    // socket() (SOCK_CLOEXEC на macOS нет), чтобы сузить окно гонки с fork/exec.
    // SAFETY: fcntl на валидном fd.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: ctl_info — POD, нули — валидное значение.
    let mut info: libc::ctl_info = unsafe { mem::zeroed() };
    for (dst, src) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME.bytes()) {
        *dst = src as libc::c_char;
    }
    // SAFETY: CTLIOCGINFO заполняет ctl_info по указателю.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: sockaddr_ctl — POD.
    let mut addr: libc::sockaddr_ctl = unsafe { mem::zeroed() };
    addr.sc_len = mem::size_of::<libc::sockaddr_ctl>() as u8;
    addr.sc_family = libc::AF_SYSTEM as u8;
    addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0; // 0 = ядро выбирает первый свободный utunN
    // SAFETY: адрес и длина соответствуют sockaddr_ctl.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_ctl).cast(),
            mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn read_ifname(fd: RawFd) -> io::Result<String> {
    let mut buf = [0u8; libc::IFNAMSIZ];
    let mut len = buf.len() as libc::socklen_t;
    // SAFETY: буфер и длина корректны.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    parse_ifname(&buf[..(len as usize).min(buf.len())])
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "utun: пустое имя интерфейса"))
}

fn run(args: &[String]) -> Result<()> {
    let (cmd, rest) = args.split_first().context("пустая команда")?;
    let out = Command::new(cmd)
        .args(rest)
        .output()
        .with_context(|| format!("запуск {cmd}"))?;
    if !out.status.success() {
        bail!(
            "{} завершился с ошибкой: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim(),
            String::from_utf8_lossy(&out.stdout).trim()
        );
    }
    Ok(())
}

// ---------- чистые функции (тестируются) ----------

/// Заголовок семейства для исходящего пакета по версии IP (старший полубайт).
fn af_header_for(packet: &[u8]) -> Option<[u8; AF_HEADER_LEN]> {
    let af = match packet.first()? >> 4 {
        4 => libc::AF_INET,
        6 => libc::AF_INET6,
        _ => return None,
    };
    Some((af as u32).to_be_bytes())
}

/// Семейство из заголовка входящего пакета.
fn af_from_header(hdr: [u8; AF_HEADER_LEN]) -> i32 {
    u32::from_be_bytes(hdr) as i32
}

/// Поддерживаемое семейство адресов (IPv4/IPv6).
fn is_ip_family(af: i32) -> bool {
    af == libc::AF_INET || af == libc::AF_INET6
}

/// Имя интерфейса из C-строки, возвращённой UTUN_OPT_IFNAME.
fn parse_ifname(raw: &[u8]) -> Option<String> {
    let s = match CStr::from_bytes_until_nul(raw) {
        Ok(c) => c.to_string_lossy().into_owned(),
        Err(_) => String::from_utf8_lossy(raw).into_owned(),
    };
    (!s.is_empty()).then_some(s)
}

fn s(x: impl Into<String>) -> String {
    x.into()
}

fn ifconfig_up_args(ifname: &str) -> Vec<String> {
    vec![s("ifconfig"), s(ifname), s("up")]
}

fn mtu_args(ifname: &str, mtu: usize) -> Vec<String> {
    vec![s("ifconfig"), s(ifname), s("mtu"), mtu.to_string()]
}

/// `ifconfig utunN inet <ip> <ip> netmask 255.255.0.0`.
fn ifconfig_inet_args(ifname: &str, ip: u32) -> Vec<String> {
    let a = Ipv4Addr::from(ip).to_string();
    vec![
        s("ifconfig"),
        s(ifname),
        s("inet"),
        a.clone(),
        a,
        s("netmask"),
        Ipv4Addr::from(tunnel_protocol::OVERLAY_MASK).to_string(),
    ]
}

/// `route -n add -net 100.66.0.0/16 -interface utunN`.
fn route_add_args(ifname: &str) -> Vec<String> {
    vec![
        s("route"),
        s("-n"),
        s("add"),
        s("-net"),
        format!(
            "{}/{}",
            Ipv4Addr::from(tunnel_protocol::OVERLAY_NET),
            tunnel_protocol::OVERLAY_PREFIX_LEN
        ),
        s("-interface"),
        s(ifname),
    ]
}

/// `route -n add -host 100.66.0.53 -interface utunN`.
fn dns_route_args(ifname: &str) -> Vec<String> {
    vec![
        s("route"),
        s("-n"),
        s("add"),
        s("-host"),
        crate::dns::DNS_ADDR.to_string(),
        s("-interface"),
        s(ifname),
    ]
}

fn ifconfig_inet6_args(ifname: &str, ip: Ipv6Addr, prefix: u8) -> Vec<String> {
    vec![
        s("ifconfig"),
        s(ifname),
        s("inet6"),
        ip.to_string(),
        s("prefixlen"),
        prefix.to_string(),
        s("alias"),
    ]
}

/// `route add` для уже существующего маршрута пишет «File exists».
fn route_exists_error(msg: &str) -> bool {
    msg.contains("File exists") || msg.contains("already in table")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn af_header_by_version() {
        let v4 = [0x45u8, 0, 0, 20];
        let v6 = [0x60u8, 0, 0, 0];
        assert_eq!(af_header_for(&v4), Some([0, 0, 0, 2]));
        assert_eq!(af_header_for(&v6), Some([0, 0, 0, 30]));
        assert_eq!(af_header_for(&[0x10]), None);
        assert_eq!(af_header_for(&[]), None);
        assert_eq!(af_from_header(af_header_for(&v4).unwrap()), libc::AF_INET);
        assert_eq!(af_from_header(af_header_for(&v6).unwrap()), libc::AF_INET6);
        assert!(is_ip_family(af_from_header(af_header_for(&v4).unwrap())));
        assert!(!is_ip_family(af_from_header([0, 0, 0, 0])));
    }

    #[test]
    fn ifname_parsing() {
        assert_eq!(parse_ifname(b"utun7\0\0\0").as_deref(), Some("utun7"));
        assert_eq!(parse_ifname(b"utun12").as_deref(), Some("utun12"));
        assert_eq!(parse_ifname(b"\0\0"), None);
    }

    #[test]
    fn command_args() {
        let a = ip(100, 66, 3, 17);
        assert_eq!(
            ifconfig_inet_args("utun4", a).join(" "),
            "ifconfig utun4 inet 100.66.3.17 100.66.3.17 netmask 255.255.0.0"
        );
        assert_eq!(
            route_add_args("utun4").join(" "),
            "route -n add -net 100.66.0.0/16 -interface utun4"
        );
        assert_eq!(mtu_args("utun4", 1280).join(" "), "ifconfig utun4 mtu 1280");
        assert_eq!(
            dns_route_args("utun4").join(" "),
            "route -n add -host 100.66.0.53 -interface utun4"
        );
        assert_eq!(
            ifconfig_inet6_args("utun4", "fd00::1".parse().unwrap(), 64).join(" "),
            "ifconfig utun4 inet6 fd00::1 prefixlen 64 alias"
        );
    }

    #[test]
    fn route_exists_detection() {
        assert!(route_exists_error(
            "route: writing to routing socket: File exists"
        ));
        assert!(!route_exists_error("route: bad address"));
    }

    /// Реальное устройство: `sudo cargo test -p tunnel-client tun_macos -- --ignored`.
    #[test]
    #[ignore]
    fn open_real_utun() {
        let dev = Utun::open(1280).expect("open utun");
        assert!(dev.name().starts_with("utun"));
        let a = ip(100, 66, 250, 9);
        dev.ensure_address(a).expect("addr");
        dev.ensure_address(a).expect("addr повторно");
        dev.ensure_address(ip(100, 66, 251, 9))
            .expect("второй адрес");
    }
}
