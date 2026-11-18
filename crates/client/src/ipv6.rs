//! IPv6-оверлей поверх IPv4-адресации участников.
//!
//! ULA-префикс `fd66:766c:696e::/48`. Участник с IPv4 `100.66.<a>.<b>` (один
//! адрес на все группы, протокол v4) получает IPv6 `fd66:766c:696e::<a>:<b>`
//! из подсети `fd66:766c:696e::/64`; на адаптере — один такой адрес с
//! префиксом /64. Обратное отображение работает только внутри этой подсети
//! и только для адресов вида `::<a>:<b>` с `a, b <= 255`.
// подключается при интеграции
#![allow(dead_code)]

use std::net::Ipv6Addr;

/// Первые 48 бит ULA-префикса: fd66:766c:696e.
pub const PREFIX: [u16; 3] = [0xfd66, 0x766c, 0x696e];
/// Длина префикса адреса оверлея на адаптере.
pub const PREFIX_LEN: u8 = 64;
/// IPv4-сеть участников: 100.66.0.0/16.
const V4_NET: u32 = 0x6442_0000;
const V4_MASK: u32 = 0xFFFF_0000;

const IPV4_HDR_MIN: usize = 20;
const IPV6_HDR: usize = 40;

/// Семейство IP-пакета по старшему полубайту первого байта.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

/// Семейство пакета; `None` — пусто или не IP.
pub fn family(packet: &[u8]) -> Option<Family> {
    match packet.first()? >> 4 {
        4 => Some(Family::V4),
        6 => Some(Family::V6),
        _ => None,
    }
}

/// IPv4 участника (u32 в порядке big-endian, как в протоколе) → IPv6
/// оверлея. `None`, если адрес не из 100.66.0.0/16.
pub fn v6_of(v4: u32) -> Option<Ipv6Addr> {
    if v4 & V4_MASK != V4_NET {
        return None;
    }
    let a = ((v4 >> 8) & 0xFF) as u16;
    let b = (v4 & 0xFF) as u16;
    Some(Ipv6Addr::new(
        PREFIX[0], PREFIX[1], PREFIX[2], 0, 0, 0, a, b,
    ))
}

/// IPv6 оверлея → IPv4 участника. Только внутри `fd66:766c:696e::/64`,
/// интерфейсный идентификатор строго `::<a>:<b>` с `a, b <= 255`.
pub fn v4_of(v6: Ipv6Addr) -> Option<u32> {
    let s = v6.segments();
    if s[..3] != PREFIX || s[3..6] != [0, 0, 0] {
        return None;
    }
    let (a, b) = (s[6], s[7]);
    if a > 0xFF || b > 0xFF {
        return None;
    }
    Some(V4_NET | (u32::from(a) << 8) | u32::from(b))
}

/// Принадлежит ли адрес нашему /48.
pub fn in_prefix(v6: Ipv6Addr) -> bool {
    v6.segments()[..3] == PREFIX
}

/// Подсеть адресов оверлея: `fd66:766c:696e::` (/64).
pub fn overlay_prefix() -> Ipv6Addr {
    Ipv6Addr::new(PREFIX[0], PREFIX[1], PREFIX[2], 0, 0, 0, 0, 0)
}

/// Проверка заголовка IPv6: версия 6, полный фиксированный заголовок и
/// payload length не больше фактического размера пакета.
fn check_v6(packet: &[u8]) -> Option<()> {
    if packet.len() < IPV6_HDR || packet[0] >> 4 != 6 {
        return None;
    }
    let payload = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    // payload length = 0 — jumbogram (hop-by-hop), в оверлее не бывает.
    if payload == 0 || IPV6_HDR + payload > packet.len() {
        return None;
    }
    Some(())
}

fn addr_at(packet: &[u8], off: usize) -> Ipv6Addr {
    let b: [u8; 16] = packet[off..off + 16].try_into().unwrap();
    Ipv6Addr::from(b)
}

/// Адрес источника IPv6-пакета (с валидацией заголовка).
pub fn ipv6_src(packet: &[u8]) -> Option<Ipv6Addr> {
    check_v6(packet)?;
    Some(addr_at(packet, 8))
}

/// Адрес назначения IPv6-пакета (с валидацией заголовка).
pub fn ipv6_dst(packet: &[u8]) -> Option<Ipv6Addr> {
    check_v6(packet)?;
    Some(addr_at(packet, 24))
}

/// Проверка заголовка IPv4: версия, IHL и total length.
fn check_v4(packet: &[u8]) -> Option<()> {
    if packet.len() < IPV4_HDR_MIN || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0F) * 4;
    let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if ihl < IPV4_HDR_MIN || total < ihl || total > packet.len() {
        return None;
    }
    Some(())
}

/// Адрес из сети участников 100.66.0.0/16.
fn is_member_v4(ip: u32) -> bool {
    ip & V4_MASK == V4_NET
}

fn v4_at(packet: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(packet[off..off + 4].try_into().unwrap())
}

/// Куда маршрутизировать пакет из адаптера: IPv4 участника-получателя.
/// Оба семейства фильтруются одинаково: IPv4 — только 100.66.0.0/16,
/// IPv6 — только адреса нашего префикса (мультикаст, broadcast, link-local
/// и чужие адреса отбрасываются).
pub fn route_target(packet: &[u8]) -> Option<u32> {
    match family(packet)? {
        Family::V4 => {
            check_v4(packet)?;
            Some(v4_at(packet, 16)).filter(|ip| is_member_v4(*ip))
        }
        Family::V6 => v4_of(ipv6_dst(packet)?),
    }
}

/// Отправитель пакета как IPv4 участника — для анти-спуфинга на приёме
/// (src должен совпадать с адресом пира).
pub fn source_member(packet: &[u8]) -> Option<u32> {
    match family(packet)? {
        Family::V4 => {
            check_v4(packet)?;
            Some(v4_at(packet, 12)).filter(|ip| is_member_v4(*ip))
        }
        Family::V6 => v4_of(ipv6_src(packet)?),
    }
}

/// Команда ОС: программа и аргументы.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: &'static str,
    pub args: Vec<String>,
}

impl Cmd {
    pub fn to_command(&self) -> std::process::Command {
        let mut c = std::process::Command::new(self.program);
        c.args(&self.args);
        c
    }
}

fn strs(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// Имя Unix-интерфейса пригодно для передачи аргументом: непустое, не
/// начинается с `-` (иначе будет прочитано как опция), только
/// `[A-Za-z0-9._-]`, не длиннее 15 байт (IFNAMSIZ - 1 в Linux).
fn valid_ifname(ifname: &str) -> bool {
    !ifname.is_empty()
        && ifname.len() <= 15
        && !ifname.starts_with('-')
        && ifname
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Windows: `netsh interface ipv6 add address <idx> <a>/64 store=active`.
/// Интерфейс задаётся индексом (wintun: GetAdapterLuid →
/// ConvertInterfaceLuidToIndex), а не именем — имя с пробелом Rust
/// закавычит целиком вместе с `interface=`, и netsh его не разберёт.
pub fn cmd_add_windows(if_index: u32, v4: u32) -> Option<Cmd> {
    let a = v6_of(v4)?;
    let mut args = strs(&["interface", "ipv6", "add", "address"]);
    args.push(if_index.to_string());
    args.push(format!("{a}/{PREFIX_LEN}"));
    args.push("store=active".into());
    Some(Cmd {
        program: "netsh",
        args,
    })
}

/// Windows: снять прежний адрес (смена сервера)
/// (`netsh interface ipv6 delete address <idx> <a>`).
pub fn cmd_del_windows(if_index: u32, v4: u32) -> Option<Cmd> {
    let a = v6_of(v4)?;
    let mut args = strs(&["interface", "ipv6", "delete", "address"]);
    args.push(if_index.to_string());
    args.push(a.to_string());
    Some(Cmd {
        program: "netsh",
        args,
    })
}

/// Linux: `ip -6 addr add <a>/64 dev <if> nodad` — без DAD адрес сразу
/// рабочий, а не «tentative» ещё 1–2 с.
pub fn cmd_add_linux(ifname: &str, v4: u32) -> Option<Cmd> {
    let mut c = linux("add", ifname, v4)?;
    c.args.push("nodad".into());
    Some(c)
}

/// Linux: `ip -6 addr del <a>/64 dev <if>`.
pub fn cmd_del_linux(ifname: &str, v4: u32) -> Option<Cmd> {
    linux("del", ifname, v4)
}

fn linux(op: &str, ifname: &str, v4: u32) -> Option<Cmd> {
    if !valid_ifname(ifname) {
        return None;
    }
    let a = v6_of(v4)?;
    let mut args = strs(&["-6", "addr", op]);
    args.push(format!("{a}/{PREFIX_LEN}"));
    args.push("dev".into());
    args.push(ifname.into());
    Some(Cmd {
        program: "ip",
        args,
    })
}

/// macOS: `ifconfig <if> inet6 <a> prefixlen 64 alias`.
pub fn cmd_add_macos(ifname: &str, v4: u32) -> Option<Cmd> {
    if !valid_ifname(ifname) {
        return None;
    }
    let a = v6_of(v4)?;
    let mut args = vec![ifname.to_string(), "inet6".into(), a.to_string()];
    args.extend(strs(&["prefixlen", "64", "alias"]));
    Some(Cmd {
        program: "ifconfig",
        args,
    })
}

/// macOS: `ifconfig <if> inet6 <a> -alias`.
pub fn cmd_del_macos(ifname: &str, v4: u32) -> Option<Cmd> {
    if !valid_ifname(ifname) {
        return None;
    }
    let a = v6_of(v4)?;
    let args = vec![
        ifname.to_string(),
        "inet6".into(),
        a.to_string(),
        "-alias".into(),
    ];
    Some(Cmd {
        program: "ifconfig",
        args,
    })
}

/// Адаптер оверлея: имя (Linux/macOS) и индекс интерфейса (Windows).
#[derive(Debug, Clone, Copy)]
pub struct Iface<'a> {
    pub name: &'a str,
    pub index: u32,
}

/// Команда добавления адреса для текущей ОС.
pub fn cmd_add(iface: Iface<'_>, v4: u32) -> Option<Cmd> {
    if cfg!(windows) {
        cmd_add_windows(iface.index, v4)
    } else if cfg!(target_os = "macos") {
        cmd_add_macos(iface.name, v4)
    } else {
        cmd_add_linux(iface.name, v4)
    }
}

/// Команда удаления адреса для текущей ОС.
pub fn cmd_del(iface: Iface<'_>, v4: u32) -> Option<Cmd> {
    if cfg!(windows) {
        cmd_del_windows(iface.index, v4)
    } else if cfg!(target_os = "macos") {
        cmd_del_macos(iface.name, v4)
    } else {
        cmd_del_linux(iface.name, v4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from(Ipv4Addr::new(a, b, c, d))
    }

    fn v4_packet(src: u32, dst: u32) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[12..16].copy_from_slice(&src.to_be_bytes());
        p[16..20].copy_from_slice(&dst.to_be_bytes());
        p
    }

    fn v6_packet(src: Ipv6Addr, dst: Ipv6Addr, payload: usize) -> Vec<u8> {
        let mut p = vec![0u8; IPV6_HDR + payload];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
        p[6] = 17;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p
    }

    fn p6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn отображение_туда_и_обратно() {
        let v4 = ip4(100, 66, 7, 42);
        let v6 = v6_of(v4).unwrap();
        assert_eq!(v6.to_string(), "fd66:766c:696e::7:2a");
        assert_eq!(v4_of(v6), Some(v4));
        for a in [0u8, 1, 255] {
            for b in [0u8, 1, 128, 254, 255] {
                let ip = ip4(100, 66, a, b);
                assert_eq!(v4_of(v6_of(ip).unwrap()), Some(ip));
            }
        }
        assert_eq!(overlay_prefix().to_string(), "fd66:766c:696e::");
    }

    #[test]
    fn чужие_адреса_отвергаются() {
        assert_eq!(v6_of(ip4(10, 0, 0, 1)), None);
        assert_eq!(v6_of(ip4(100, 67, 1, 1)), None);
        assert_eq!(v4_of(p6("fd66:766c:696f:1::1")), None);
        assert_eq!(v4_of(p6("fe80::1")), None);
        assert_eq!(v4_of(p6("fd66:766c:696e::100:1")), None); // a > 255
        assert_eq!(v4_of(p6("fd66:766c:696e::1:100")), None); // b > 255
        assert_eq!(v4_of(p6("fd66:766c:696e:1::1:1")), None); // не наша /64
        assert_eq!(v4_of(p6("fd66:766c:696e:0:1::1:1")), None);
        assert_eq!(v4_of(p6("fd66:766c:696e:7::2a")), None, "схема v3");
        assert!(in_prefix(p6("fd66:766c:696e:ffff::1")));
        assert!(!in_prefix(p6("ff02::1")));
    }

    #[test]
    fn семейство_и_разбор() {
        assert_eq!(family(&[]), None);
        assert_eq!(family(&[0x45]), Some(Family::V4));
        assert_eq!(family(&[0x60]), Some(Family::V6));
        assert_eq!(family(&[0x00]), None);

        let s = v6_of(ip4(100, 66, 3, 1)).unwrap();
        let d = v6_of(ip4(100, 66, 3, 2)).unwrap();
        let pk = v6_packet(s, d, 8);
        assert_eq!(ipv6_src(&pk), Some(s));
        assert_eq!(ipv6_dst(&pk), Some(d));
        // обрезанный пакет
        assert_eq!(ipv6_dst(&pk[..39]), None);
        assert_eq!(ipv6_dst(&pk[..45]), None);
        // payload length = 0
        let mut z = pk.clone();
        z[4] = 0;
        z[5] = 0;
        assert_eq!(ipv6_dst(&z), None);
        // не IPv6
        let mut w = pk.clone();
        w[0] = 0x45;
        assert_eq!(ipv6_src(&w), None);
    }

    #[test]
    fn маршрут_для_обоих_семейств() {
        let me = ip4(100, 66, 3, 1);
        let peer = ip4(100, 66, 3, 2);
        assert_eq!(route_target(&v4_packet(me, peer)), Some(peer));
        assert_eq!(source_member(&v4_packet(me, peer)), Some(me));
        let mut bad = v4_packet(me, peer);
        bad[0] = 0x44; // IHL < 5
        assert_eq!(route_target(&bad), None);
        let mut long = v4_packet(me, peer);
        long[2..4].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(route_target(&long), None);

        let pk = v6_packet(v6_of(me).unwrap(), v6_of(peer).unwrap(), 8);
        assert_eq!(route_target(&pk), Some(peer));
        assert_eq!(source_member(&pk), Some(me));
        let mc = v6_packet(v6_of(me).unwrap(), p6("ff02::1"), 8);
        assert_eq!(route_target(&mc), None);
        assert_eq!(route_target(&[0x10, 0, 0]), None);
    }

    #[test]
    fn чужие_ipv4_не_маршрутизируются() {
        let me = ip4(100, 66, 3, 1);
        for dst in [
            ip4(10, 0, 0, 1),
            ip4(224, 0, 0, 1),
            ip4(255, 255, 255, 255),
            ip4(8, 8, 8, 8),
        ] {
            assert_eq!(route_target(&v4_packet(me, dst)), None);
            assert_eq!(source_member(&v4_packet(dst, me)), None);
        }
    }

    #[test]
    fn команды_адаптера() {
        let v4 = ip4(100, 66, 5, 9);
        let w = cmd_add_windows(17, v4).unwrap();
        assert_eq!(w.program, "netsh");
        assert_eq!(
            w.args,
            [
                "interface",
                "ipv6",
                "add",
                "address",
                "17",
                "fd66:766c:696e::5:9/64",
                "store=active"
            ]
        );
        let wd = cmd_del_windows(17, v4).unwrap();
        assert_eq!(
            wd.args,
            [
                "interface",
                "ipv6",
                "delete",
                "address",
                "17",
                "fd66:766c:696e::5:9"
            ]
        );
        let l = cmd_add_linux("vl0", v4).unwrap();
        assert_eq!(l.program, "ip");
        assert_eq!(
            l.args,
            [
                "-6",
                "addr",
                "add",
                "fd66:766c:696e::5:9/64",
                "dev",
                "vl0",
                "nodad"
            ]
        );
        assert_eq!(cmd_del_linux("vl0", v4).unwrap().args[2], "del");
        let m = cmd_add_macos("utun7", v4).unwrap();
        assert_eq!(m.program, "ifconfig");
        assert_eq!(
            m.args,
            [
                "utun7",
                "inet6",
                "fd66:766c:696e::5:9",
                "prefixlen",
                "64",
                "alias"
            ]
        );
        assert_eq!(cmd_del_macos("utun7", v4).unwrap().args[3], "-alias");
        let ok = Iface {
            name: "vl0",
            index: 17,
        };
        assert!(cmd_add(ok, ip4(10, 0, 0, 1)).is_none());
        assert!(cmd_add(ok, v4).is_some() && cmd_del(ok, v4).is_some());
    }

    #[test]
    fn плохие_имена_интерфейса() {
        let v4 = ip4(100, 66, 5, 9);
        for bad in ["", "-down", "a b", "x;y", "abcdefghijklmnop"] {
            assert!(cmd_add_linux(bad, v4).is_none(), "{bad}");
            assert!(cmd_del_linux(bad, v4).is_none(), "{bad}");
            assert!(cmd_add_macos(bad, v4).is_none(), "{bad}");
            assert!(cmd_del_macos(bad, v4).is_none(), "{bad}");
        }
        assert!(cmd_add_linux("voidlink.0_a-b", v4).is_some());
    }
}
