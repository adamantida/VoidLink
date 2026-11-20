//! Адреса оверлея за identity (протокол v4): у каждой identity на сервере
//! один адрес из `100.66.0.0/16`, общий для всех её групп. Адрес выдаётся
//! при первом входе (или создании группы) и сохраняется в `server.json`:
//! после выхода из всех групп и повторного входа он тот же.
//!
//! Пул — `100.66.1.1`…`100.66.255.254` без `.0` и `.255` в последнем октете
//! (64 770 адресов): `100.66.0.0/24` — служебная (`100.66.0.53` — встроенный
//! DNS клиента). Пул кончился — адрес забирается у identity, которая сейчас
//! ни в одной группе (новые identity бесплатны, и без этого их поток занял
//! бы весь пул навсегда).

use std::collections::HashMap;

use tunnel_protocol as proto;

/// Третий октет: с 1 (`100.66.0.0/24` служебная).
const NET_MIN: u32 = 1;
const NET_MAX: u32 = 255;
/// Последний октет: без `.0` и `.255`.
const HOST_MIN: u32 = 1;
const HOST_MAX: u32 = 254;

/// Адрес из пула выдачи.
pub fn valid(ip: u32) -> bool {
    let net = (ip >> 8) & 0xFF;
    let host = ip & 0xFF;
    proto::is_overlay_ip(ip)
        && (NET_MIN..=NET_MAX).contains(&net)
        && (HOST_MIN..=HOST_MAX).contains(&host)
}

/// Адресов в пуле: 255 × 254.
const POOL_SIZE: u32 = (NET_MAX - NET_MIN + 1) * (HOST_MAX - HOST_MIN + 1);

/// Адрес пула по номеру `0..POOL_SIZE`.
fn pool_ip(i: u32) -> u32 {
    let per_net = HOST_MAX - HOST_MIN + 1;
    proto::OVERLAY_NET | ((NET_MIN + i / per_net) << 8) | (HOST_MIN + i % per_net)
}

#[cfg(test)]
fn pool() -> impl Iterator<Item = u32> {
    (0..POOL_SIZE).map(pool_ip)
}

/// identity ↔ адрес, взаимно однозначно.
#[derive(Default)]
pub struct Leases {
    by_pub: HashMap<[u8; 32], u32>,
    by_ip: HashMap<u32, [u8; 32]>,
    /// Адреса, закреплённые общим пулом федерации за identity других
    /// серверов (`FED_ADDR_PUSH`): локальному пулу они не выдаются. Пока
    /// федерации нет, множество пусто и выдача не меняется.
    reserved: std::collections::HashSet<u32>,
    /// Номер адреса пула, с которого искать свободный: выдача подряд не
    /// перебирает каждый раз уже выданные с начала пула.
    next: u32,
}

impl Leases {
    pub fn get(&self, pk: &[u8; 32]) -> Option<u32> {
        self.by_pub.get(pk).copied()
    }

    /// Чья это identity по адресу (для конфликта федерации: адрес занят
    /// локальным участником).
    pub fn owner_of(&self, ip: u32) -> Option<[u8; 32]> {
        self.by_ip.get(&ip).copied()
    }

    /// Зарезервировать адрес чужой identity (федеративный пул): локально он
    /// не выдаётся. Уже занятый своим адресом — не резервируется.
    pub fn reserve(&mut self, ip: u32) {
        if !self.by_ip.contains_key(&ip) {
            self.reserved.insert(ip);
        }
    }

    /// Снять резерв (identity ушла из пула/адрес перевыдан).
    pub fn unreserve(&mut self, ip: u32) {
        self.reserved.remove(&ip);
    }

    /// Адрес зарезервирован за чужой identity.
    pub fn is_reserved(&self, ip: u32) -> bool {
        self.reserved.contains(&ip)
    }

    /// Забрать адрес у identity (конфликт федерации): адрес снова свободен.
    pub fn revoke(&mut self, pk: &[u8; 32]) -> Option<u32> {
        let ip = self.by_pub.remove(pk)?;
        self.by_ip.remove(&ip);
        Some(ip)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_pub.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 32], u32)> {
        self.by_pub.iter().map(|(k, ip)| (k, *ip))
    }

    /// Закрепить `ip` за `pk` (загрузка `server.json`). Отказ — адрес вне
    /// пула или занят, либо у `pk` уже есть адрес.
    pub fn assign(&mut self, pk: [u8; 32], ip: u32) -> bool {
        if !valid(ip)
            || self.by_ip.contains_key(&ip)
            || self.by_pub.contains_key(&pk)
            || self.reserved.contains(&ip)
        {
            return false;
        }
        self.by_pub.insert(pk, ip);
        self.by_ip.insert(ip, pk);
        true
    }

    /// Адрес `pk`: закреплённый или новый. Пул кончился — забирается адрес
    /// identity, для которой `in_use` ложно (не состоит ни в одной группе).
    /// `None` — свободных и освобождаемых адресов нет.
    pub fn get_or_alloc(
        &mut self,
        pk: [u8; 32],
        in_use: impl Fn(&[u8; 32]) -> bool,
    ) -> Option<u32> {
        if let Some(ip) = self.get(&pk) {
            return Some(ip);
        }
        let free = (0..POOL_SIZE)
            .map(|i| (self.next + i) % POOL_SIZE)
            .find(|&i| {
                let ip = pool_ip(i);
                !self.by_ip.contains_key(&ip) && !self.reserved.contains(&ip)
            });
        let ip = match free {
            Some(i) => {
                self.next = (i + 1) % POOL_SIZE;
                pool_ip(i)
            }
            None => {
                let (old, ip) = self
                    .by_pub
                    .iter()
                    .find(|(k, ip)| **k != pk && !self.reserved.contains(*ip) && !in_use(k))
                    .map(|(k, ip)| (*k, *ip))?;
                self.by_pub.remove(&old);
                self.by_ip.remove(&ip);
                ip
            }
        };
        self.by_pub.insert(pk, ip);
        self.by_ip.insert(ip, pk);
        Some(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(c: u8, d: u8) -> u32 {
        u32::from(std::net::Ipv4Addr::new(100, 66, c, d))
    }

    fn pk(n: u32) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&n.to_be_bytes());
        k
    }

    #[test]
    fn pool_bounds() {
        assert!(valid(ip(1, 1)) && valid(ip(255, 254)) && valid(ip(3, 17)));
        assert!(!valid(ip(0, 53)), "служебная /24 (DNS)");
        assert!(!valid(ip(1, 0)) && !valid(ip(1, 255)));
        assert!(!valid(u32::from(std::net::Ipv4Addr::new(100, 67, 1, 1))));
        assert_eq!(pool().count(), 255 * 254);
        assert!(pool().all(valid));
        assert_eq!(
            pool().collect::<std::collections::HashSet<_>>().len(),
            255 * 254
        );
        assert_eq!(
            (pool_ip(0), pool_ip(253), pool_ip(254)),
            (ip(1, 1), ip(1, 254), ip(2, 1))
        );
        assert_eq!(pool_ip(POOL_SIZE - 1), ip(255, 254));
    }

    #[test]
    fn same_address_until_reclaimed() {
        let mut l = Leases::default();
        let a = l.get_or_alloc(pk(1), |_| true).unwrap();
        let b = l.get_or_alloc(pk(2), |_| true).unwrap();
        assert_eq!((a, b), (ip(1, 1), ip(1, 2)));
        assert_eq!(l.get_or_alloc(pk(1), |_| true), Some(a), "закреплён");
        assert_eq!(l.len(), 2);
    }

    #[test]
    fn assign_rejects_conflicts() {
        let mut l = Leases::default();
        assert!(l.assign(pk(1), ip(3, 17)));
        assert!(!l.assign(pk(2), ip(3, 17)), "адрес занят");
        assert!(!l.assign(pk(1), ip(3, 18)), "у identity уже есть адрес");
        assert!(!l.assign(pk(3), ip(0, 53)), "вне пула");
        // Занятый загрузкой адрес новым не выдаётся.
        assert_eq!(l.get_or_alloc(pk(4), |_| true), Some(ip(1, 1)));
        assert!(l.assign(pk(5), ip(1, 2)));
        assert_eq!(l.get_or_alloc(pk(6), |_| true), Some(ip(1, 3)));
    }

    #[test]
    fn exhausted_pool_reclaims_only_idle() {
        let mut l = Leases::default();
        let n = pool().count() as u32;
        for i in 0..n {
            assert!(l.get_or_alloc(pk(i), |_| true).is_some());
        }
        // Все в группах — нового адреса нет.
        assert_eq!(l.get_or_alloc(pk(n), |_| true), None);
        assert!(l.get(&pk(n)).is_none());
        // Одна identity вне групп — её адрес переходит новой.
        let idle = pk(7);
        let freed = l.get(&idle).unwrap();
        assert_eq!(l.get_or_alloc(pk(n), |k| *k != idle), Some(freed));
        assert!(l.get(&idle).is_none());
        assert_eq!(l.len(), n as usize);
    }

    // ---------- общий пул федерации (T4b1) ----------

    #[test]
    fn зарезервированный_адрес_не_выдаётся() {
        let mut l = Leases::default();
        // Первый свободный адрес занят заявкой чужой identity.
        l.reserve(ip(1, 1));
        assert!(l.is_reserved(ip(1, 1)));
        assert_eq!(l.get_or_alloc(pk(1), |_| true), Some(ip(1, 2)));
        assert!(!l.assign(pk(2), ip(1, 1)), "зарезервированный не выдаётся");
        // Снятый резерв снова доступен.
        l.unreserve(ip(1, 1));
        assert!(!l.is_reserved(ip(1, 1)));
        assert!(l.assign(pk(2), ip(1, 1)));
        // Адрес своей identity не резервируется (он и так в пуле).
        l.reserve(ip(1, 2));
        assert!(!l.is_reserved(ip(1, 2)), "свой адрес не резерв");
        assert_eq!(l.owner_of(ip(1, 2)), Some(pk(1)));
    }

    #[test]
    fn revoke_освобождает_адрес_для_перевыдачи() {
        let mut l = Leases::default();
        let a = l.get_or_alloc(pk(1), |_| true).unwrap();
        assert_eq!(l.revoke(&pk(1)), Some(a));
        assert!(l.get(&pk(1)).is_none());
        assert_eq!(l.revoke(&pk(1)), None, "повторный отзыв — None");
        // Освобождённый адрес снова свободен: закрепляется без конфликта.
        assert!(l.assign(pk(2), a));
        assert_eq!(l.owner_of(a), Some(pk(2)));
    }

    #[test]
    fn резерв_не_забирается_при_исчерпании_пула() {
        let mut l = Leases::default();
        let n = pool().count() as u32;
        for i in 0..n {
            l.get_or_alloc(pk(i), |_| true).unwrap();
        }
        // Один адрес уходит в заявку чужой identity — новой выдаче он не
        // достанется, даже если identity освободит его (все «idle»).
        let held = l.get(&pk(0)).unwrap();
        l.revoke(&pk(0));
        l.reserve(held);
        assert_eq!(l.get_or_alloc(pk(n), |_| true), None);
    }
}
