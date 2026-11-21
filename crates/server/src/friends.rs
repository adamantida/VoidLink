//! Друзья: заявки и принятые пары (issue #24).
//!
//! Чистая модель без потоков и часов: `now_ms` и лимиты передаются
//! параметрами, поэтому правила проверяются юнит-тестами без сервера и без
//! ожидания TTL.
//!
//! **Почему сервер хранит пары.** Раньше дружба была локальной правкой
//! `client.json`, и вторая сторона о ней не знала. Взаимность для офлайн-цели
//! иначе недостижима: заявка должна ждать в сервере, пока адресат не
//! подключится, а принятая пара — переживать рестарт обоих. Сервер знает
//! только пары pubkey и время: ников, групп и адресов оверлея здесь нет
//! (см. `docs/FAQ.md`).
//!
//! Инварианты:
//!
//! * пара всегда упорядочена (`min`, `max`) — дружба одно множество, а не два
//!   направления, поэтому «снял один» снимает у обоих;
//! * заявка и дружба по одной паре одновременно не живут: `accept` удаляет
//!   заявку, встречная заявка принимается сразу;
//! * заявка живёт `friend_req_ttl`, повтор продлевает срок, а не плодит
//!   дубликат;
//! * `remove` снимает и дружбу, и (если была) заявку по этой паре.

use anyhow::{Result, ensure};
use std::collections::BTreeMap;
use tunnel_protocol::payloads::{FriendInfo, friend_state};

use crate::persist::{PFriendEdge, PFriendReq, PFriends};

/// Сколько записей отдаётся в одном окне `FRIEND_LIST`: ответ ограничен по
/// размеру (u8-счётчик и FRAG не нужны), хвост клиент дочитывает
/// `LIST_FRIENDS` с `from` = последний ключ окна.
pub const FRIENDS_PER_LIST: usize = 16;

/// Упорядоченная пара: ключ дружбы и заявки.
fn pair(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    if a <= b { (*a, *b) } else { (*b, *a) }
}

/// Принятая дружба (`a < b`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge {
    pub a: [u8; 32],
    pub b: [u8; 32],
    /// unix мс принятия: `FRIEND_LIST::since_ms` и порядок в списке.
    pub since_ms: u64,
}

impl Edge {
    /// Вторая сторона пары для `me` (`None` — `me` в паре нет).
    pub fn other(&self, me: &[u8; 32]) -> Option<[u8; 32]> {
        if self.a == *me {
            Some(self.b)
        } else if self.b == *me {
            Some(self.a)
        } else {
            None
        }
    }
}

/// Неотвеченная заявка.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub from: [u8; 32],
    pub to: [u8; 32],
    /// unix мс: от него считается `friend_req_ttl`.
    pub created_ms: u64,
    /// Имя отправителя на момент заявки (показывается цели).
    pub from_name: String,
}

/// Что вышло из [`Friends::request`] — от этого зависит, кому и что слать.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestOutcome {
    /// Новая заявка: цель надо уведомить `FRIEND_REQ_RCVD`.
    Created(Request),
    /// Повтор своей заявки: срок продлён, цель получает окно заново (если
    /// она онлайн — окно могло быть закрыто, а заявка ещё жива).
    Extended(Request),
    /// Встречная заявка была — сразу дружба, обе стороны получают
    /// `FRIEND_REQ_ACCEPTED`.
    Accepted(Edge),
    /// Уже друзья: идемпотентно, отправителю — свежий список.
    AlreadyFriends,
}

/// Заявки и принятые пары.
#[derive(Debug, Clone, Default)]
pub struct Friends {
    /// `(min, max)` → заявка (направление внутри).
    requests: BTreeMap<([u8; 32], [u8; 32]), Request>,
    /// `(min, max)` → дружба.
    edges: BTreeMap<([u8; 32], [u8; 32]), Edge>,
}

impl Friends {
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty() && self.edges.is_empty()
    }

    /// Друзья ли `a` и `b` (в любом порядке).
    pub fn is_friend(&self, a: &[u8; 32], b: &[u8; 32]) -> bool {
        self.edges.contains_key(&pair(a, b))
    }

    pub fn edge(&self, a: &[u8; 32], b: &[u8; 32]) -> Option<Edge> {
        self.edges.get(&pair(a, b)).copied()
    }

    /// Сколько у identity принятых дружб (`Limits::max_friends`).
    pub fn friend_count(&self, pk: &[u8; 32]) -> usize {
        self.edges
            .values()
            .filter(|e| e.other(pk).is_some())
            .count()
    }

    /// Живых заявок, адресованных `pk` (`Limits::max_friend_reqs_per_target`).
    pub fn incoming_count(&self, pk: &[u8; 32]) -> usize {
        self.requests.values().filter(|r| r.to == *pk).count()
    }

    /// Заявка по паре (в любом направлении).
    pub fn request_between(&self, a: &[u8; 32], b: &[u8; 32]) -> Option<&Request> {
        self.requests.get(&pair(a, b))
    }

    /// Заявка `from` → `to` именно в этом направлении.
    pub fn request_from(&self, from: &[u8; 32], to: &[u8; 32]) -> Option<&Request> {
        self.requests
            .get(&pair(from, to))
            .filter(|r| r.from == *from)
    }

    /// Заявка в друзья: создать, продлить или (при встречной) сразу принять.
    ///
    /// `max_per_target` — сколько живых заявок может быть адресовано цели:
    /// без предела популярную identity заваливали бы окнами заявок.
    /// `max_friends` — предел друзей на identity (нужен и здесь: встречная
    /// заявка принимается сразу).
    pub fn request(
        &mut self,
        from: [u8; 32],
        to: [u8; 32],
        from_name: String,
        now_ms: u64,
        max_per_target: usize,
        max_friends: usize,
    ) -> Result<RequestOutcome> {
        ensure!(from != to, "нельзя добавить себя в друзья");
        if self.is_friend(&from, &to) {
            return Ok(RequestOutcome::AlreadyFriends);
        }
        // Между ними уже есть заявка: своя — продлить, встречная — принять.
        if let Some(existing) = self.requests.get(&pair(&from, &to)).cloned() {
            if existing.from == to {
                let edge = self.accept(&to, &from, now_ms, max_friends)?;
                return Ok(RequestOutcome::Accepted(edge));
            }
            let req = self
                .requests
                .get_mut(&pair(&from, &to))
                .expect("заявка только что была");
            req.created_ms = now_ms;
            req.from_name = from_name;
            return Ok(RequestOutcome::Extended(req.clone()));
        }
        ensure!(
            self.incoming_count(&to) < max_per_target,
            "лимит заявок в друзья у цели ({max_per_target}): она слишком популярна"
        );
        let req = Request {
            from,
            to,
            created_ms: now_ms,
            from_name,
        };
        self.requests.insert(pair(&from, &to), req.clone());
        Ok(RequestOutcome::Created(req))
    }

    /// Принять заявку `from` → `to` (принимает `to`). Уже друзья — та же пара
    /// обратно (идемпотентно, повтор FRIEND_ACCEPT не ошибка).
    pub fn accept(
        &mut self,
        from: &[u8; 32],
        to: &[u8; 32],
        now_ms: u64,
        max_friends: usize,
    ) -> Result<Edge> {
        ensure!(from != to, "нельзя принять себя в друзья");
        if let Some(e) = self.edge(from, to) {
            return Ok(e);
        }
        ensure!(
            self.request_from(from, to).is_some(),
            "заявки от этой identity нет"
        );
        ensure!(
            self.friend_count(from) < max_friends && self.friend_count(to) < max_friends,
            "лимит друзей ({max_friends})"
        );
        self.requests.remove(&pair(from, to));
        let (a, b) = pair(from, to);
        let edge = Edge {
            a,
            b,
            since_ms: now_ms,
        };
        self.edges.insert((a, b), edge);
        Ok(edge)
    }

    /// Отклонить заявку `from` → `to`. `Some` — заявка была (второй стороне
    /// надо сказать `FRIEND_REQ_DECLINED`); `None` — уже нет (идемпотентно).
    pub fn decline(&mut self, from: &[u8; 32], to: &[u8; 32]) -> Option<Request> {
        let req = self.requests.get(&pair(from, to))?;
        // Отклонить можно только адресованную себе: `to` — тот, кто отклоняет.
        if req.to != *to {
            return None;
        }
        self.requests.remove(&pair(from, to))
    }

    /// Снять дружбу (с любой стороны). `Some` — пара была; вторую сторону
    /// надо уведомить `FRIEND_REMOVED`. Заявка по этой паре тоже снимается.
    pub fn remove(&mut self, a: &[u8; 32], b: &[u8; 32]) -> Option<Edge> {
        self.requests.remove(&pair(a, b));
        self.edges.remove(&pair(a, b))
    }

    /// Истёкшие заявки удаляются; возвращаются те, о ком надо сказать цели
    /// (её окно заявок изменилось).
    pub fn expire(&mut self, now_ms: u64, ttl_ms: u64) -> Vec<Request> {
        let mut gone = Vec::new();
        self.requests.retain(|_, r| {
            let live = now_ms < r.created_ms.saturating_add(ttl_ms);
            if !live {
                gone.push(r.clone());
            }
            live
        });
        gone.sort_by_key(|r| r.created_ms);
        gone
    }

    /// Есть ли просроченные заявки: дешёвая проверка под чтением, чтобы не
    /// брать блокировку состояния на запись каждый тик housekeeping.
    pub fn has_expired(&self, now_ms: u64, ttl_ms: u64) -> bool {
        self.requests
            .values()
            .any(|r| now_ms >= r.created_ms.saturating_add(ttl_ms))
    }

    /// Все связи `me` по возрастанию pubkey (без имён: их подставляет сервер,
    /// у модели нет доступа к именам групп и сессий).
    pub fn links(&self, me: &[u8; 32]) -> Vec<FriendInfo> {
        let mut v: Vec<FriendInfo> = Vec::new();
        for r in self.requests.values() {
            if r.from == *me {
                v.push(FriendInfo {
                    pk: r.to,
                    name: String::new(),
                    state: friend_state::PENDING_OUT,
                    since_ms: r.created_ms,
                });
            } else if r.to == *me {
                v.push(FriendInfo {
                    pk: r.from,
                    name: String::new(),
                    state: friend_state::PENDING_IN,
                    since_ms: r.created_ms,
                });
            }
        }
        for e in self.edges.values() {
            if let Some(other) = e.other(me) {
                v.push(FriendInfo {
                    pk: other,
                    name: String::new(),
                    state: friend_state::ACCEPTED,
                    since_ms: e.since_ms,
                });
            }
        }
        v.sort_by_key(|i| i.pk);
        v
    }

    /// Окно `FRIEND_LIST` для `me`: связи с pubkey ≥ `from`, не больше
    /// [`FRIENDS_PER_LIST`]. `complete` — после окна у `me` больше ничего нет.
    pub fn window(&self, me: &[u8; 32], from: &[u8; 32]) -> (Vec<FriendInfo>, bool) {
        let mut all = self.links(me);
        all.retain(|i| i.pk >= *from);
        let complete = all.len() <= FRIENDS_PER_LIST;
        all.truncate(FRIENDS_PER_LIST);
        (all, complete)
    }

    /// Секция `friends` для server.json.
    pub fn persisted(&self) -> PFriends {
        PFriends {
            requests: self
                .requests
                .values()
                .map(|r| PFriendReq {
                    from: r.from,
                    to: r.to,
                    created_ms: r.created_ms,
                    from_name: r.from_name.clone(),
                })
                .collect(),
            edges: self
                .edges
                .values()
                .map(|e| PFriendEdge {
                    a: e.a,
                    b: e.b,
                    since_ms: e.since_ms,
                })
                .collect(),
        }
    }

    /// Восстановление из server.json. Битые записи пропускаются, а не роняют
    /// сервер: без этого один испорченный pubkey не давал бы подняться.
    pub fn load(p: &PFriends) -> Friends {
        let mut f = Friends::default();
        for r in &p.requests {
            if r.from == r.to || r.from == [0u8; 32] || r.to == [0u8; 32] {
                continue;
            }
            f.requests.insert(
                pair(&r.from, &r.to),
                Request {
                    from: r.from,
                    to: r.to,
                    created_ms: r.created_ms,
                    from_name: r.from_name.clone(),
                },
            );
        }
        for e in &p.edges {
            if e.a == e.b || e.a == [0u8; 32] || e.b == [0u8; 32] {
                continue;
            }
            let (a, b) = pair(&e.a, &e.b);
            f.edges.insert(
                (a, b),
                Edge {
                    a,
                    b,
                    since_ms: e.since_ms,
                },
            );
        }
        // Заявка по паре, которая уже дружба, — мусор от старой записи:
        // иначе клиент показал бы и дружбу, и «ждёт ответа».
        f.requests.retain(|k, _| !f.edges.contains_key(k));
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: u64 = 7 * 24 * 3600 * 1000;
    const MAX_PER_TARGET: usize = 4;
    /// С запасом: в тесте окна нужно больше друзей, чем влезает в окно.
    const MAX_FRIENDS: usize = 32;

    fn pk(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn req(f: &mut Friends, from: u8, to: u8, now: u64) -> RequestOutcome {
        f.request(
            pk(from),
            pk(to),
            format!("u{from}"),
            now,
            MAX_PER_TARGET,
            MAX_FRIENDS,
        )
        .unwrap()
    }

    fn accepted(f: &mut Friends, a: u8, b: u8, now: u64) -> Edge {
        req(f, a, b, now);
        f.accept(&pk(a), &pk(b), now, MAX_FRIENDS).unwrap()
    }

    /// Состояние связи `me` с `other` в окне списка.
    fn state(f: &Friends, me: u8, other: u8) -> Option<u8> {
        f.window(&pk(me), &[0; 32])
            .0
            .into_iter()
            .find(|i| i.pk == pk(other))
            .map(|i| i.state)
    }

    #[test]
    fn примирение_пар_упорядочено() {
        // Пара (2,1) и (1,2) — одна и та же дружба.
        let mut f = Friends::default();
        accepted(&mut f, 2, 1, 100);
        assert!(f.is_friend(&pk(1), &pk(2)));
        assert!(f.is_friend(&pk(2), &pk(1)));
        assert_eq!(f.friend_count(&pk(1)), 1);
        assert_eq!(f.friend_count(&pk(2)), 1);
        assert_eq!(f.edge(&pk(1), &pk(2)).unwrap().a, pk(1));
    }

    #[test]
    fn приятие_создаёт_обоюдную_запись() {
        let mut f = Friends::default();
        assert_eq!(
            req(&mut f, 1, 2, 100),
            RequestOutcome::Created(Request {
                from: pk(1),
                to: pk(2),
                created_ms: 100,
                from_name: "u1".into(),
            })
        );
        // До принятия: у инициатора «ждёт ответа», у цели «пришла заявка».
        assert_eq!(state(&f, 1, 2), Some(friend_state::PENDING_OUT));
        assert_eq!(state(&f, 2, 1), Some(friend_state::PENDING_IN));
        let e = f.accept(&pk(1), &pk(2), 200, MAX_FRIENDS).unwrap();
        assert_eq!(e.since_ms, 200);
        // После принятия у обоих — дружба, заявки больше нет.
        assert_eq!(state(&f, 1, 2), Some(friend_state::ACCEPTED));
        assert_eq!(state(&f, 2, 1), Some(friend_state::ACCEPTED));
        assert!(f.request_between(&pk(1), &pk(2)).is_none());
        assert_eq!(
            f.window(&pk(1), &[0; 32]).0[0].since_ms,
            200,
            "время принятия, а не заявки"
        );
        // Повтор FRIEND_ACCEPT идемпотентен.
        assert_eq!(f.accept(&pk(1), &pk(2), 300, MAX_FRIENDS).unwrap(), e);
    }

    #[test]
    fn заявка_себе_и_уже_друзьям_отказ() {
        let mut f = Friends::default();
        // Себе — ошибка, а не молчаливая запись.
        let e = f.request(pk(1), pk(1), "я".into(), 10, MAX_PER_TARGET, MAX_FRIENDS);
        assert!(e.is_err(), "заявка себе должна быть отказом");
        assert!(f.is_empty());
        // Уже друзья — идемпотентно (без второй заявки и без ошибки).
        accepted(&mut f, 1, 2, 100);
        assert_eq!(req(&mut f, 1, 2, 200), RequestOutcome::AlreadyFriends);
        assert_eq!(req(&mut f, 2, 1, 200), RequestOutcome::AlreadyFriends);
        assert!(f.request_between(&pk(1), &pk(2)).is_none());
        assert_eq!(f.friend_count(&pk(1)), 1);
        // Принять заявку, которой нет, — ошибка (а не дружба из воздуха).
        assert!(f.accept(&pk(1), &pk(3), 300, MAX_FRIENDS).is_err());
    }

    #[test]
    fn лимит_заявок_на_одну_цель() {
        let mut f = Friends::default();
        for from in 1..=MAX_PER_TARGET as u8 {
            assert!(matches!(
                req(&mut f, from, 9, 100),
                RequestOutcome::Created(_)
            ));
        }
        // Сверх лимита — отказ, и заявка не создаётся.
        let e = f.request(
            pk(99),
            pk(9),
            "u99".into(),
            100,
            MAX_PER_TARGET,
            MAX_FRIENDS,
        );
        assert!(e.is_err(), "лимит заявок у цели должен соблюдаться");
        assert_eq!(f.incoming_count(&pk(9)), MAX_PER_TARGET);
        // Заявка в другую цель проходит: лимит считается на цель.
        assert!(matches!(
            req(&mut f, 99, 10, 100),
            RequestOutcome::Created(_)
        ));
        // Своя повторная заявка лимит не тратит и продлевает срок.
        assert_eq!(
            req(&mut f, 1, 9, 500),
            RequestOutcome::Extended(Request {
                from: pk(1),
                to: pk(9),
                created_ms: 500,
                from_name: "u1".into(),
            })
        );
        assert_eq!(f.incoming_count(&pk(9)), MAX_PER_TARGET);
    }

    #[test]
    fn встречные_заявки_дают_дружбу() {
        let mut f = Friends::default();
        req(&mut f, 1, 2, 100);
        // 2 отвечает заявкой вместо ACCEPT — сервер принимает сам.
        match req(&mut f, 2, 1, 200) {
            RequestOutcome::Accepted(e) => {
                assert_eq!((e.a, e.b, e.since_ms), (pk(1), pk(2), 200));
            }
            other => panic!("ожидали автопринятие, получили {other:?}"),
        }
        assert!(f.is_friend(&pk(1), &pk(2)));
        assert!(f.request_between(&pk(1), &pk(2)).is_none());
    }

    #[test]
    fn отказ_снимает_заявку() {
        let mut f = Friends::default();
        req(&mut f, 1, 2, 100);
        // Отклонить может только адресат: заявка 1→2, а `decline(2, 1)` — это
        // «1 отклоняет заявку 2→1», которой нет.
        assert!(f.decline(&pk(2), &pk(1)).is_none());
        assert!(f.request_between(&pk(1), &pk(2)).is_some());
        let gone = f.decline(&pk(1), &pk(2));
        assert_eq!(gone.map(|r| r.from), Some(pk(1)));
        assert!(f.request_between(&pk(1), &pk(2)).is_none());
        assert!(f.decline(&pk(1), &pk(2)).is_none(), "идемпотентно");
        assert_eq!(state(&f, 1, 2), None);
    }

    #[test]
    fn удаление_друга_снимает_запись_у_обоих() {
        let mut f = Friends::default();
        accepted(&mut f, 1, 2, 100);
        accepted(&mut f, 1, 3, 100);
        // Снимает вторая сторона — запись уходит у обоих.
        assert!(f.remove(&pk(2), &pk(1)).is_some());
        assert!(!f.is_friend(&pk(1), &pk(2)));
        assert_eq!(state(&f, 1, 2), None);
        assert_eq!(state(&f, 2, 1), None);
        assert!(f.is_friend(&pk(1), &pk(3)), "чужая пара не задета");
        // Повтор REMOVE — не ошибка (идемпотентно).
        assert!(f.remove(&pk(1), &pk(2)).is_none());
        // Снятие снимает и живую заявку по этой паре.
        req(&mut f, 4, 1, 100);
        assert!(f.remove(&pk(1), &pk(4)).is_none());
        assert!(f.request_between(&pk(4), &pk(1)).is_none());
    }

    #[test]
    fn заявка_в_друзья_истекает() {
        let mut f = Friends::default();
        req(&mut f, 1, 2, 1_000);
        req(&mut f, 3, 2, TTL);
        // Раньше срока — обе живы.
        assert!(f.expire(1_000 + TTL - 1, TTL).is_empty());
        assert_eq!(f.incoming_count(&pk(2)), 2);
        // Вторая истекла, первая — ещё нет.
        let gone = f.expire(1_000 + TTL, TTL);
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].from, pk(1));
        assert_eq!(f.incoming_count(&pk(2)), 1);
        // Обе истекли — окно цели пусто, у инициатора тоже.
        assert_eq!(f.expire(TTL * 3, TTL).len(), 1);
        assert!(f.is_empty());
        assert_eq!(state(&f, 1, 2), None);
    }

    #[test]
    fn окно_списка_друзей_идёт_по_возрастанию_ключа() {
        let mut f = Friends::default();
        for other in [30u8, 10, 20] {
            accepted(&mut f, 1, other, 100);
        }
        req(&mut f, 1, 40, 100);
        req(&mut f, 50, 1, 100);
        let (items, complete) = f.window(&pk(1), &[0; 32]);
        assert!(complete);
        let pks: Vec<u8> = items.iter().map(|i| i.pk[0]).collect();
        assert_eq!(pks, vec![10, 20, 30, 40, 50]);
        // Окно с середины: только ключи ≥ from.
        let (items, complete) = f.window(&pk(1), &pk(30));
        assert!(complete);
        assert_eq!(
            items.iter().map(|i| i.pk[0]).collect::<Vec<_>>(),
            vec![30, 40, 50]
        );
        // Чужого в списке нет.
        assert!(!items.iter().any(|i| i.pk == pk(99)));
    }

    #[test]
    fn полное_окно_режется_и_помечается_неполным() {
        let mut f = Friends::default();
        let n = FRIENDS_PER_LIST + 3;
        for i in 2..=n as u8 {
            accepted(&mut f, 1, i, 100);
        }
        let (items, complete) = f.window(&pk(1), &[0; 32]);
        assert_eq!(items.len(), FRIENDS_PER_LIST);
        assert!(!complete, "обрезанное окно не полное");
        // Дочитывание с последнего ключа окна покрывает остаток.
        let last = items.last().unwrap().pk;
        let (tail, complete) = f.window(&pk(1), &last);
        assert!(complete);
        assert_eq!(
            tail.len(),
            n - 1 - FRIENDS_PER_LIST + 1,
            "последний ключ окна повторяется первым"
        );
        assert_eq!(tail[0].pk, last);
    }

    #[test]
    fn дружбы_и_заявки_переживают_сериализацию() {
        let mut f = Friends::default();
        accepted(&mut f, 1, 2, 100);
        req(&mut f, 3, 4, 200);
        let p = f.persisted();
        assert_eq!(p.edges.len(), 1);
        assert_eq!(p.requests.len(), 1);
        let back = Friends::load(&p);
        assert!(back.is_friend(&pk(1), &pk(2)));
        assert_eq!(
            back.request_between(&pk(3), &pk(4))
                .map(|r| r.from_name.clone()),
            Some("u3".into())
        );
        assert_eq!(back.persisted(), p);
    }

    #[test]
    fn битые_записи_при_загрузке_пропускаются() {
        // Нулевой ключ, пара из себя и заявка по уже принятой паре — мусор.
        let p = PFriends {
            requests: vec![
                PFriendReq {
                    from: [0; 32],
                    to: pk(2),
                    created_ms: 1,
                    from_name: String::new(),
                },
                PFriendReq {
                    from: pk(5),
                    to: pk(5),
                    created_ms: 1,
                    from_name: String::new(),
                },
                PFriendReq {
                    from: pk(1),
                    to: pk(2),
                    created_ms: 1,
                    from_name: "старая".into(),
                },
            ],
            edges: vec![
                PFriendEdge {
                    a: pk(2),
                    b: pk(1),
                    since_ms: 7,
                },
                PFriendEdge {
                    a: pk(9),
                    b: pk(9),
                    since_ms: 7,
                },
            ],
        };
        let f = Friends::load(&p);
        assert!(f.is_friend(&pk(1), &pk(2)));
        assert_eq!(f.friend_count(&pk(9)), 0);
        assert!(
            f.request_between(&pk(1), &pk(2)).is_none(),
            "заявка по принятой паре не восстанавливается"
        );
        assert_eq!(f.incoming_count(&pk(2)), 0);
    }
}
