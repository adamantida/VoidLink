//! DHT-оверлей клиента (§3.3 плана этапа 9).
//!
//! Идентификатор узла — ed25519-ключ клиента, расстояние — XOR (Kademlia:
//! 32 корзины × 8 контактов, индекс — старшие 5 бит расстояния,
//! `tunnel_protocol::mesh::distance_bucket`). Бутстрап: `MESH_SEED` от
//! сервера, кэш контактов из состава групп (`MemberInfo.endpoint` + mesh-секция
//! `GROUP_STATE`), сохранённая таблица (`client.json` → `mesh.contacts`).
//!
//! Здесь только таблица и её арифметика: поиск (`find_node`, α = 3 раунда по
//! 2) отдаёт движку список контактов, которые надо спросить, а сами кадры
//! шлёт `mesh.rs`. Время — миллисекунды (`now_ms`), чтобы тесты были
//! детерминированы.
//!
//! Контакт устаревает за [`TTL_MS`] (15 мин) без ответа; ближайшие к нам
//! [`PING_COUNT`] контактов движок пингует раз в [`PING_EVERY_MS`] (5 мин).
//! Таблица переживает рестарт: [`Dht::to_stored`] / [`Dht::load`].

use std::net::SocketAddr;

use tunnel_protocol::mesh;
use tunnel_protocol::payloads::MeshSeed;

use crate::store::StoredContact;

/// hex-ключ (32 байта) из конфига; мусор — `None`.
fn hex_pub(s: &str) -> Option<[u8; 32]> {
    let v = tunnel_protocol::hex_to_bytes(s).ok()?;
    v.try_into().ok()
}

/// Корзин DHT: старшие 5 бит XOR-расстояния (0..=31).
pub const BUCKETS: usize = 32;
/// Контактов в корзине (Kademlia).
pub const K: usize = 8;
/// Контакт без ответа столько — забывается (15 мин).
pub const TTL_MS: u64 = 15 * 60 * 1000;
/// Период пинга ближайших контактов (5 мин).
pub const PING_EVERY_MS: u64 = 5 * 60 * 1000;
/// Сколько ближайших к нам контактов пингуется.
pub const PING_COUNT: usize = 8;
/// Параллелизм поиска (α в Kademlia).
pub const ALPHA: usize = 3;
/// Раундов поиска: 2 (каждый — до α запросов).
pub const MAX_ROUNDS: u8 = 2;
/// Предел одновременных поисков (от запросов из сети).
pub const MAX_LOOKUPS: usize = 32;

/// Контакт DHT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    /// ed25519 — идентификатор узла.
    pub ed: [u8; 32],
    /// x25519 — статический ключ (mesh-секция `GROUP_STATE`/`MESH_SEED`).
    pub x: [u8; 32],
    /// Последний известный endpoint.
    pub addr: SocketAddr,
    /// Последний измеренный RTT, мс (0 — не измеряли).
    pub rtt_ms: u32,
    /// Когда контакт последний раз подавал признаки жизни, мс.
    pub last_seen_ms: u64,
    /// Возможности (`mesh::caps::*`).
    pub caps: u8,
}

impl Contact {
    /// Контакт годен к использованию в `now_ms`.
    pub fn fresh(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_seen_ms) <= TTL_MS
    }

    /// Готов релеить чужой трафик.
    pub fn can_relay(&self) -> bool {
        mesh::caps::has(self.caps, mesh::caps::RELAY)
    }
}

/// Раунд поиска `find_node`: кого уже спросили и что нашли.
#[derive(Clone, Debug)]
pub struct Lookup {
    /// Идентификатор запроса (эхо в `MESH_FIND_NODE`/`MESH_NODES`).
    pub id: u64,
    /// Кого ищем.
    pub target: [u8; 32],
    /// Сделано раундов.
    pub round: u8,
    /// Кого уже спросили.
    asked: Vec<[u8; 32]>,
}

impl Lookup {
    /// Следующие α контактов, которых ещё не спрашивали. Пусто — раунды
    /// кончились или спрашивать некого.
    pub fn next_queries(&mut self, dht: &Dht) -> Vec<Contact> {
        if self.round >= MAX_ROUNDS {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(ALPHA);
        for c in dht.closest(&self.target, ALPHA * 3) {
            if out.len() >= ALPHA {
                break;
            }
            if !self.asked.contains(&c.ed) {
                self.asked.push(c.ed);
                out.push(c);
            }
        }
        if !out.is_empty() {
            self.round += 1;
        }
        out
    }
}

/// Таблица маршрутизации DHT.
#[derive(Clone, Debug)]
pub struct Dht {
    /// Наш ed-ключ (идентификатор в оверлее).
    me: [u8; 32],
    /// Корзины по старшим 5 битам XOR-расстояния до нас.
    buckets: Vec<Vec<Contact>>,
    /// Когда последний раз пинговали контакт (не чаще [`PING_EVERY_MS`]).
    pinged: Vec<([u8; 32], u64)>,
}

impl Dht {
    pub fn new(me: [u8; 32]) -> Self {
        Self {
            me,
            buckets: vec![Vec::new(); BUCKETS],
            pinged: Vec::new(),
        }
    }

    /// Наш идентификатор.
    pub fn me(&self) -> [u8; 32] {
        self.me
    }

    /// Контактов в таблице.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Наполнить таблицу контактами (MESH_SEED, кэш групп, сохранённая
    /// таблица). Чужие для нас ключи (мы сами, нулевой ed) отбрасываются.
    pub fn bootstrap(&mut self, seeds: &[MeshSeed], now_ms: u64) -> usize {
        let mut added = 0;
        for s in seeds {
            if self.insert(Contact {
                ed: s.ed_pub,
                x: s.x_pub,
                addr: s.addr,
                rtt_ms: 0,
                last_seen_ms: now_ms,
                // MESH_SEED не несёт caps: сервер отдаёт только умеющих mesh.
                caps: mesh::caps::MESH,
            }) {
                added += 1;
            }
        }
        added
    }

    /// Загрузить сохранённые контакты (`client.json` → `mesh.contacts`).
    /// Бит `MESH` ставится всегда (контакт попал в таблицу только через mesh),
    /// `RELAY` — из сохранённого `caps`.
    pub fn load(&mut self, saved: &[StoredContact]) -> usize {
        let mut added = 0;
        for c in saved {
            let (Some(ed), Some(x)) = (hex_pub(&c.ed), hex_pub(&c.x)) else {
                continue;
            };
            let Ok(addr) = c.addr.parse::<SocketAddr>() else {
                continue;
            };
            if self.insert(Contact {
                ed,
                x,
                addr,
                rtt_ms: c.rtt_ms,
                // Время — из сохранённого, но не «из будущего»: часы могли
                // сдвинуться; свежесть всё равно проверит `expire`.
                last_seen_ms: c.seen_s.saturating_mul(1000),
                caps: c.caps | mesh::caps::MESH,
            }) {
                added += 1;
            }
        }
        added
    }

    /// Сохраняемая копия таблицы (по возрастанию ed — стабильный `client.json`).
    pub fn to_stored(&self) -> Vec<StoredContact> {
        let mut out: Vec<StoredContact> = self
            .contacts()
            .into_iter()
            .map(|c| StoredContact {
                ed: tunnel_protocol::hex_of(&c.ed),
                x: tunnel_protocol::hex_of(&c.x),
                addr: c.addr.to_string(),
                rtt_ms: c.rtt_ms,
                seen_s: c.last_seen_ms / 1000,
                caps: c.caps,
            })
            .collect();
        out.sort_by(|a, b| a.ed.cmp(&b.ed));
        out
    }

    /// Вставить/обновить контакт. `false` — контакт отвергнут (некуда или
    /// корзина полна живых и чужих не вытесняем).
    pub fn insert(&mut self, mut c: Contact) -> bool {
        if c.ed == self.me || c.ed == [0u8; 32] {
            return false;
        }
        let b = mesh::distance_bucket(&self.me, &c.ed) as usize;
        let bucket = &mut self.buckets[b.min(BUCKETS - 1)];
        if let Some(old) = bucket.iter_mut().find(|x| x.ed == c.ed) {
            // Время последней жизни — только вперёд: запоздавший ответ не
            // «омолаживает» и не «старит» уже известный контакт.
            c.last_seen_ms = c.last_seen_ms.max(old.last_seen_ms);
            if c.rtt_ms == 0 {
                c.rtt_ms = old.rtt_ms;
            }
            *old = c;
            return true;
        }
        if bucket.len() < K {
            bucket.push(c);
            return true;
        }
        // Корзина полна: вытесняем только заведомо более старый контакт
        // (иначе долгоживущие узлы Kademlia не трогает).
        let Some((idx, oldest)) = bucket
            .iter()
            .enumerate()
            .min_by_key(|(_, x)| x.last_seen_ms)
        else {
            return false;
        };
        if c.last_seen_ms > oldest.last_seen_ms.saturating_add(TTL_MS / 2) {
            bucket[idx] = c;
            return true;
        }
        false
    }

    /// Обновить контакт (ответил) — вставить или отметить.
    pub fn mark_seen(&mut self, ed: &[u8; 32], rtt_ms: u32, now_ms: u64) -> bool {
        match self.get_mut(ed) {
            Some(c) => {
                c.last_seen_ms = c.last_seen_ms.max(now_ms);
                if rtt_ms > 0 {
                    c.rtt_ms = rtt_ms;
                }
                true
            }
            None => false,
        }
    }

    /// Узнали новый адрес контакта (пир сменил endpoint). `true` — адрес
    /// действительно другой: движок запустит поиск заново.
    pub fn set_addr(&mut self, ed: &[u8; 32], addr: SocketAddr, now_ms: u64) -> bool {
        match self.get_mut(ed) {
            Some(c) => {
                // Тот же адрес — это не «новость»: не обновляем last_seen,
                // иначе сохранение client.json дёргалось бы каждую секунду.
                if c.addr == addr {
                    return false;
                }
                c.addr = addr;
                c.last_seen_ms = now_ms;
                // Байты на старый адрес больше не считаются живыми: контакт
                // заново проверится пингом.
                self.pinged.retain(|(e, _)| e != ed);
                true
            }
            None => false,
        }
    }

    /// Учесть `MeshSeed`/`MeshEntry`: контакт без адреса невозможен, поэтому
    /// `MeshEntry` (ip/x/caps, без адреса) сюда не попадает — движок берёт
    /// адрес из `MemberInfo.endpoint`.
    pub fn add_group_peer(
        &mut self,
        ed: [u8; 32],
        x: [u8; 32],
        addr: SocketAddr,
        caps: u8,
        now_ms: u64,
    ) -> bool {
        self.insert(Contact {
            ed,
            x,
            addr,
            rtt_ms: 0,
            last_seen_ms: now_ms,
            caps,
        })
    }

    /// Контакт по ключу.
    pub fn get(&self, ed: &[u8; 32]) -> Option<&Contact> {
        let b = mesh::distance_bucket(&self.me, ed) as usize;
        self.buckets
            .get(b.min(BUCKETS - 1))?
            .iter()
            .find(|c| &c.ed == ed)
    }

    fn get_mut(&mut self, ed: &[u8; 32]) -> Option<&mut Contact> {
        let b = mesh::distance_bucket(&self.me, ed) as usize;
        self.buckets
            .get_mut(b.min(BUCKETS - 1))?
            .iter_mut()
            .find(|c| &c.ed == ed)
    }

    /// Все контакты (порядок не важен).
    pub fn contacts(&self) -> Vec<Contact> {
        self.buckets.iter().flatten().cloned().collect()
    }

    /// До `n` контактов, ближайших к `target` по XOR (Kademlia). Годные
    /// (не устаревшие) — первыми, затем по расстоянию: устаревший контакт
    /// ещё можно попробовать, но только когда живых не хватает.
    pub fn closest_with(&self, target: &[u8; 32], n: usize, now_ms: u64) -> Vec<Contact> {
        let mut v = self.contacts();
        v.sort_by(|a, b| {
            let (fa, fb) = (a.fresh(now_ms), b.fresh(now_ms));
            (!fa)
                .cmp(&!fb)
                .then_with(|| {
                    mesh::x25519_distance(target, &a.ed).cmp(&mesh::x25519_distance(target, &b.ed))
                })
                .then_with(|| a.ed.cmp(&b.ed))
        });
        v.truncate(n);
        v
    }

    /// То же без фильтра времени (поиск/тесты).
    pub fn closest(&self, target: &[u8; 32], n: usize) -> Vec<Contact> {
        self.closest_with(target, n, u64::MAX / 2)
    }

    /// До `n` контактов, ближайших к нам (пинг-раунд).
    pub fn closest_to_me(&self, n: usize) -> Vec<Contact> {
        self.closest(&self.me, n)
    }

    /// Кого пингуем сейчас: до [`PING_COUNT`] ближайших к нам, кого не
    /// пинговали [`PING_EVERY_MS`].
    pub fn ping_due(&self, now_ms: u64) -> Vec<Contact> {
        let due: Vec<Contact> = self
            .closest_to_me(PING_COUNT)
            .into_iter()
            .filter(|c| {
                self.pinged
                    .iter()
                    .find(|(e, _)| e == &c.ed)
                    .is_none_or(|(_, at)| now_ms.saturating_sub(*at) >= PING_EVERY_MS)
            })
            .collect();
        due
    }

    /// Отметить, что пинг контакта отправлен (чтобы не спамить).
    pub fn mark_pinged(&mut self, ed: &[u8; 32], now_ms: u64) {
        match self.pinged.iter_mut().find(|(e, _)| e == ed) {
            Some((_, at)) => *at = now_ms,
            None => self.pinged.push((*ed, now_ms)),
        }
        // Список пингов не растёт бесконечно: помним только живые контакты.
        if self.pinged.len() > K * BUCKETS {
            let live: Vec<[u8; 32]> = self.contacts().iter().map(|c| c.ed).collect();
            let pinged = &mut self.pinged;
            pinged.retain(|(e, _)| live.contains(e));
        }
    }

    /// Выкинуть контакты, не подававшие признаков жизни [`TTL_MS`].
    /// Возвращает число удалённых.
    pub fn expire(&mut self, now_ms: u64) -> usize {
        let mut gone = 0;
        for b in &mut self.buckets {
            let before = b.len();
            b.retain(|c| c.fresh(now_ms));
            gone += before - b.len();
        }
        if gone > 0 {
            let live: Vec<[u8; 32]> = self.contacts().iter().map(|c| c.ed).collect();
            let pinged = &mut self.pinged;
            pinged.retain(|(e, _)| live.contains(e));
        }
        gone
    }

    /// Начать поиск `target`. `round == 0`, запросы — [`Lookup::next_queries`].
    pub fn start_lookup(&self, id: u64, target: [u8; 32]) -> Lookup {
        Lookup {
            id,
            target,
            round: 0,
            asked: Vec::new(),
        }
    }

    /// Ответ `MESH_NODES`: добавить контакты. Возвращает число новых.
    pub fn on_nodes(&mut self, nodes: &[Contact]) -> usize {
        let before = self.len();
        for c in nodes {
            self.insert(c.clone());
        }
        self.len().saturating_sub(before)
    }

    /// Кандидаты в реле для цели: до `n` ближайших к `target` контактов,
    /// готовых релеить (`RELAY`) и не сама цель.
    pub fn relay_candidates(&self, target: &[u8; 32], n: usize) -> Vec<Contact> {
        self.closest(target, BUCKETS * K)
            .into_iter()
            .filter(|c| c.can_relay() && c.ed != *target)
            .take(n)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(first: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = first;
        k
    }

    fn contact(ed: [u8; 32], addr: &str, caps: u8) -> Contact {
        Contact {
            ed,
            x: [9u8; 32],
            addr: addr.parse().unwrap(),
            rtt_ms: 5,
            last_seen_ms: 0,
            caps,
        }
    }

    #[test]
    fn корзины_и_расстояние() {
        let me = key(0);
        let mut d = Dht::new(me);
        // Старшие 5 бит расстояния = индекс корзины: ed[0] = 0x08 → 1.
        assert!(d.insert(contact(key(0x08), "203.0.113.1:1", mesh::caps::MESH)));
        assert!(d.insert(contact(key(0xFF), "203.0.113.2:1", mesh::caps::MESH)));
        assert_eq!(d.len(), 2);
        // Свой ключ и нулевой — не контакты.
        assert!(!d.insert(contact(me, "203.0.113.3:1", 0)));
        assert!(!d.insert(contact(key(0), "203.0.113.3:1", 0)));
        assert_eq!(d.len(), 2);
        // Дубль обновляет, а не добавляет.
        let mut c = contact(key(0x08), "203.0.113.10:1", mesh::caps::MESH);
        c.rtt_ms = 9;
        assert!(d.insert(c));
        assert_eq!(d.len(), 2);
        assert_eq!(d.get(&key(0x08)).unwrap().rtt_ms, 9);
        assert_eq!(
            d.get(&key(0x08)).unwrap().addr,
            "203.0.113.10:1".parse().unwrap()
        );
    }

    #[test]
    fn близость_по_xor() {
        let me = key(0);
        let mut d = Dht::new(me);
        for k in [0x10u8, 0x01, 0x80, 0x02] {
            d.insert(contact(key(k), "203.0.113.1:1", 0));
        }
        // Цель 0x01: ближе всех ed=0x01 (расстояние 0), затем 0x02, 0x10, 0x80.
        let close: Vec<u8> = d.closest(&key(0x01), 4).iter().map(|c| c.ed[0]).collect();
        assert_eq!(close, vec![0x01, 0x02, 0x10, 0x80]);
        // Ограничение n.
        assert_eq!(d.closest(&key(0x01), 2)[0].ed[0], 0x01);
        assert_eq!(d.closest(&key(0x01), 2).len(), 2);
    }

    #[test]
    fn пять_узлов_и_поиск_двумя_раундами() {
        let me = key(0);
        let mut d = Dht::new(me);
        let mut seeds = Vec::new();
        for i in 1..=5u8 {
            let mut ed = [0u8; 32];
            ed[0] = i << 4; // корзины 0/2/4.. — разные
            ed[31] = i;
            seeds.push(MeshSeed {
                ed_pub: ed,
                x_pub: [i; 32],
                addr: format!("203.0.113.{i}:4000").parse().unwrap(),
            });
        }
        assert_eq!(d.bootstrap(&seeds, 0), 5);
        assert_eq!(d.len(), 5);
        // Поиск: α = 3 в первом раунде, второй раунд — кого ещё не спрашивали.
        let target = key(0xAA);
        let mut l = d.start_lookup(1, target);
        let first = l.next_queries(&d);
        assert_eq!(first.len(), ALPHA);
        assert_eq!(l.round, 1);
        let second = l.next_queries(&d);
        assert_eq!(second.len(), 2, "осталось двое");
        assert_eq!(l.round, 2);
        assert!(l.next_queries(&d).is_empty(), "раунды кончились");
        // Спрошенные не повторяются.
        let mut asked: Vec<[u8; 32]> = first.iter().chain(second.iter()).map(|c| c.ed).collect();
        asked.sort();
        asked.dedup();
        assert_eq!(asked.len(), 5);
        // Ответ Nodes пополняет таблицу: новый узел находится.
        let new = contact(key(0x7F), "203.0.113.99:4000", mesh::caps::MESH);
        let new_ed = new.ed;
        assert_eq!(d.on_nodes(&[new]), 1);
        assert!(d.get(&new_ed).is_some());
    }

    #[test]
    fn устаревание_и_ttl_пинга() {
        let me = key(0);
        let mut d = Dht::new(me);
        d.insert(contact(key(0x10), "203.0.113.1:1", mesh::caps::MESH));
        d.insert(contact(key(0x20), "203.0.113.2:1", mesh::caps::MESH));
        assert_eq!(d.len(), 2);
        // Оба живы.
        assert_eq!(d.expire(TTL_MS), 0);
        // Через TTL+1 оба забыты.
        assert_eq!(d.expire(TTL_MS + 1), 2);
        assert!(d.is_empty());
        // Свежий контакт пингуется сразу, после отметки — только через 5 мин.
        let mut d = Dht::new(me);
        d.insert(contact(key(0x30), "203.0.113.3:1", mesh::caps::MESH));
        assert_eq!(d.ping_due(0).len(), 1, "свежий контакт ещё не пингован");
        d.mark_pinged(&key(0x30), 0);
        assert!(d.ping_due(1).is_empty());
        assert_eq!(d.ping_due(PING_EVERY_MS).len(), 1);
        // Пинг-список не течёт: после expire остаётся только живое.
        d.expire(TTL_MS + 1);
        assert!(d.ping_due(TTL_MS + 2).is_empty());
    }

    #[test]
    fn персистенция_туда_обратно() {
        let me = key(0);
        let mut d = Dht::new(me);
        let mut c = contact(
            key(0x40),
            "203.0.113.4:4000",
            mesh::caps::MESH | mesh::caps::RELAY,
        );
        c.rtt_ms = 33;
        c.last_seen_ms = 1_700_000_000_000;
        d.insert(c.clone());
        let saved = d.to_stored();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].rtt_ms, 33);
        assert_eq!(saved[0].seen_s, 1_700_000_000);
        assert!(mesh::caps::has(saved[0].caps, mesh::caps::RELAY));
        // Загрузка в новую таблицу.
        let mut d2 = Dht::new(me);
        assert_eq!(d2.load(&saved), 1);
        let got = d2.get(&c.ed).unwrap();
        assert_eq!(got.addr, c.addr);
        assert_eq!(got.rtt_ms, 33);
        assert_eq!(got.last_seen_ms, 1_700_000_000_000);
        assert!(got.can_relay());
        // Мусор в сохранённом не ломает загрузку.
        let junk = vec![
            StoredContact {
                ed: "не hex".into(),
                x: String::new(),
                addr: String::new(),
                rtt_ms: 0,
                seen_s: 0,
                caps: 0,
            },
            StoredContact {
                ed: tunnel_protocol::hex_of(&key(0x44)),
                x: tunnel_protocol::hex_of(&[1u8; 32]),
                addr: "не адрес".into(),
                rtt_ms: 0,
                seen_s: 0,
                caps: 0,
            },
        ];
        assert_eq!(d2.load(&junk), 0);
    }

    #[test]
    fn кандидаты_реле_и_смена_адреса() {
        let me = key(0);
        let mut d = Dht::new(me);
        let target = key(0x80);
        // Ближе всех к цели — без RELAY, дальше — с RELAY.
        d.insert(contact(key(0x81), "203.0.113.1:1", mesh::caps::MESH));
        d.insert(contact(
            key(0x90),
            "203.0.113.2:1",
            mesh::caps::MESH | mesh::caps::RELAY,
        ));
        d.insert(contact(
            key(0xA0),
            "203.0.113.3:1",
            mesh::caps::MESH | mesh::caps::RELAY,
        ));
        let cand = d.relay_candidates(&target, 3);
        assert_eq!(cand.len(), 2, "без RELAY не кандидат");
        assert_eq!(cand[0].ed[0], 0x90, "сначала ближайший реле");
        // Смена адреса: true только при реальном изменении.
        let ed = key(0x90);
        assert!(!d.set_addr(&ed, "203.0.113.2:1".parse().unwrap(), 10));
        assert!(d.set_addr(&ed, "198.51.100.7:1".parse().unwrap(), 10));
        assert_eq!(d.get(&ed).unwrap().addr, "198.51.100.7:1".parse().unwrap());
        // Неизвестный контакт — false (таблица не растёт от смены адреса).
        assert!(!d.set_addr(&key(0xEE), "198.51.100.9:1".parse().unwrap(), 10));
        // mark_seen по неизвестному — false, по известному — обновление.
        assert!(!d.mark_seen(&key(0xEE), 1, 10));
        assert!(d.mark_seen(&ed, 12, 20));
        assert_eq!(d.get(&ed).unwrap().rtt_ms, 12);
        assert_eq!(d.get(&ed).unwrap().last_seen_ms, 20);
    }

    #[test]
    fn корзина_не_растёт_свыше_k() {
        let me = key(0);
        let mut d = Dht::new(me);
        // Все в корзине 0 (старшие 5 бит = 0): ed[0] = 0x00..0x07.
        for i in 0..=K as u8 + 3 {
            d.insert(contact(key(i & 0x07), "203.0.113.1:1", mesh::caps::MESH));
        }
        assert!(d.len() <= K, "корзина ограничена K: {}", d.len());
    }
}
