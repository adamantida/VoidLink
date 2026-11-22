//! Друзья на стороне движка (issue #24).
//!
//! Чистая модель без потоков и часов: `now` передаётся параметром, поэтому
//! `LocalEngine` и демон ведут один и тот же список, а тесты не ждут реальных
//! секунд. Образец — [`crate::invites`]: те же правила сверки и памяти отказа.
//!
//! Что здесь есть и чего нет:
//!
//! * дружба — только принятая заявка (`FriendState::Accepted`); запись из
//!   конфига до появления заявок — `Legacy`, она живёт локально, пока сервер
//!   не пришлёт пару, и показывается как «локально, не подтверждён»;
//! * сервер — источник правды по состояниям: полный `FRIEND_LIST` снимает
//!   устаревшие заявки и апгрейдит `Legacy` до `Accepted`;
//! * [`FRIEND_SYNC_GRACE`] — сверка не снимает запись, пришедшую только что
//!   (список мог быть собран раньше);
//! * [`FRIEND_DECLINE_MEMORY`] — отклонённая заявка 5 с не возвращается
//!   запоздавшим списком;
//! * алиас (`alias`) — локальное переименование, модель его не трогает: он
//!   живёт в `client.json`, а показывается по правилу
//!   [`display_name`] — алиас → ник → короткий код.

use std::time::{Duration, Instant};

use tunnel_protocol as proto;
use tunnel_protocol::payloads::{FriendInfo, friend_state};

use crate::store::{Config, FriendState, StoredFriend};

/// Память отказа: отклонённая заявка не возвращается запоздавшим списком,
/// собранным сервером до нашего `FRIEND_DECLINE`.
pub const FRIEND_DECLINE_MEMORY: Duration = Duration::from_secs(5);
/// Сверка со списком сервера не снимает запись, пришедшую меньше 2 с назад.
pub const FRIEND_SYNC_GRACE: Duration = Duration::from_secs(2);

/// Короткий код identity для показа, когда ни алиаса, ни ника нет: первые
/// 4 байта hex (как в карточках админа) — 8 символов вместо 52.
pub fn short_code(pk: &[u8; 32]) -> String {
    proto::hex_of(&pk[..4]) + "…"
}

/// Как показывать друга: алиас (ручное имя) → ник с сервера → короткий код.
pub fn display_name(alias: &str, nick: &str, pk: &[u8; 32]) -> String {
    let a = alias.trim();
    if !a.is_empty() {
        return a.to_string();
    }
    let n = nick.trim();
    if !n.is_empty() {
        return n.to_string();
    }
    short_code(pk)
}

/// Друг или заявка в модели.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Friend {
    pub pk: [u8; 32],
    /// Ник с сервера (последний известный; пусто — не приходил).
    pub nick: String,
    pub state: FriendState,
    /// unix мс сервера: когда заявка отправлена/пришла или дружба принята.
    pub since_ms: u64,
}

#[derive(Debug, Clone)]
struct Entry {
    f: Friend,
    /// Когда запись появилась у нас (для [`FRIEND_SYNC_GRACE`]).
    received_at: Instant,
    /// Когда заявка истекает на сервере (`None` — бессрочно/неизвестно).
    expires_at: Option<Instant>,
}

/// Что вышло из [`Friends::on_request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestOutcome {
    /// Новая входящая заявка — фронтенду показать окно.
    New,
    /// Повтор заявки — данные обновлены, второе окно не нужно.
    Updated,
    /// Встречная: мы уже просили — теперь дружба.
    Accepted,
    /// Недавно отклонили — запоздавший список, игнор.
    Declined,
}

/// Друзья и заявки сессии.
#[derive(Debug, Clone, Default)]
pub struct Friends {
    entries: Vec<Entry>,
    /// Только что отклонённые (pk, когда).
    declined: Vec<([u8; 32], Instant)>,
}

impl Friends {
    pub fn new() -> Self {
        Self::default()
    }

    /// Список из конфига: прошлая сессия оставила состояния в `client.json`.
    /// `Legacy` сохраняется как есть — сервер подтвердит или нет.
    pub fn from_cfg(cfg: &Config, now: Instant) -> Friends {
        let mut f = Friends::default();
        for s in &cfg.friends {
            let Ok(pk) = parse_pk(&s.pubkey) else {
                continue;
            };
            f.entries.push(Entry {
                f: Friend {
                    pk,
                    nick: s.nick.clone(),
                    state: s.state,
                    since_ms: 0,
                },
                received_at: now,
                expires_at: None,
            });
        }
        f.sort();
        f
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn contains(&self, pk: &[u8; 32]) -> bool {
        self.entries.iter().any(|e| &e.f.pk == pk)
    }

    pub fn get(&self, pk: &[u8; 32]) -> Option<&Friend> {
        self.entries.iter().find(|e| &e.f.pk == pk).map(|e| &e.f)
    }

    /// Состояние связи с `pk` (`None` — записи нет).
    pub fn state_of(&self, pk: &[u8; 32]) -> Option<FriendState> {
        self.get(pk).map(|f| f.state)
    }

    /// Уже друзья (не заявка).
    pub fn is_friend(&self, pk: &[u8; 32]) -> bool {
        self.state_of(pk) == Some(FriendState::Accepted)
    }

    /// Список для показа, по возрастанию ключа (фронтенд сортирует сам).
    pub fn list(&self) -> Vec<Friend> {
        self.entries.iter().map(|e| e.f.clone()).collect()
    }

    /// Входящие заявки — для окна «принять/отклонить».
    pub fn incoming(&self) -> Vec<Friend> {
        self.entries
            .iter()
            .filter(|e| e.f.state == FriendState::PendingIn)
            .map(|e| e.f.clone())
            .collect()
    }

    fn sort(&mut self) {
        self.entries.sort_by_key(|e| e.f.pk);
    }

    /// Отклонено меньше [`FRIEND_DECLINE_MEMORY`] назад.
    pub fn recently_declined(&self, pk: &[u8; 32], now: Instant) -> bool {
        self.declined
            .iter()
            .any(|(p, t)| p == pk && now.saturating_duration_since(*t) < FRIEND_DECLINE_MEMORY)
    }

    /// Записать состояние связи (создать или обновить), не теряя ник, если
    /// новый пустой: сервер мог ещё не знать имени.
    fn set(&mut self, pk: [u8; 32], nick: String, state: FriendState, since_ms: u64, now: Instant) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.f.pk == pk) {
            if !nick.is_empty() {
                e.f.nick = nick;
            }
            e.f.state = state;
            if since_ms != 0 {
                e.f.since_ms = since_ms;
            }
            // Заявка снова живая — срок сбрасывается по данным сервера.
            if state != FriendState::PendingIn && state != FriendState::PendingOut {
                e.expires_at = None;
            }
            return;
        }
        self.entries.push(Entry {
            f: Friend {
                pk,
                nick,
                state,
                since_ms,
            },
            received_at: now,
            expires_at: None,
        });
        self.sort();
    }

    /// Пришла заявка (`FRIEND_REQ_RCVD` или элемент списка).
    pub fn on_request(
        &mut self,
        from: [u8; 32],
        nick: String,
        expires_in: Option<u32>,
        now: Instant,
    ) -> RequestOutcome {
        if self.recently_declined(&from, now) {
            return RequestOutcome::Declined;
        }
        // Встречная заявка: мы уже просили этого человека — сервер считает
        // пару принятой, модель делает то же (даже если кадр потерялся).
        if self.state_of(&from) == Some(FriendState::PendingOut) {
            self.set(from, nick, FriendState::Accepted, 0, now);
            return RequestOutcome::Accepted;
        }
        let expires_at = expires_in.map(|s| now + Duration::from_secs(u64::from(s)));
        match self.entries.iter_mut().find(|e| e.f.pk == from) {
            Some(e) => {
                if !nick.is_empty() {
                    e.f.nick = nick;
                }
                // Уже друзья — запоздавшая заявка состояние не понижает.
                if e.f.state != FriendState::Accepted {
                    e.f.state = FriendState::PendingIn;
                    // Повтор заявки продлевает срок.
                    if expires_at.is_some() {
                        e.expires_at = expires_at;
                    }
                }
                RequestOutcome::Updated
            }
            None => {
                self.entries.push(Entry {
                    f: Friend {
                        pk: from,
                        nick,
                        state: FriendState::PendingIn,
                        since_ms: 0,
                    },
                    received_at: now,
                    expires_at,
                });
                self.sort();
                RequestOutcome::New
            }
        }
    }

    /// Отправили заявку (`Cmd::AddFriend`): сразу «ждёт ответа», не дожидаясь
    /// списка от сервера. Уже друзья — ничего не меняем.
    pub fn request_sent(&mut self, pk: [u8; 32], now: Instant) {
        match self.state_of(&pk) {
            Some(FriendState::Accepted) => {}
            Some(FriendState::PendingOut) => {}
            _ => self.set(pk, String::new(), FriendState::PendingOut, 0, now),
        }
    }

    /// Заявку приняли: `by` — вторая сторона. Дружба обоюдная, поэтому
    /// запись одна и состояние `Accepted` — с какой бы стороны её ни приняли.
    pub fn on_accepted(&mut self, by: [u8; 32], nick: String, now: Instant) -> Friend {
        self.set(by, nick, FriendState::Accepted, 0, now);
        if let Some(e) = self.entries.iter_mut().find(|e| e.f.pk == by) {
            e.expires_at = None;
        }
        self.get(&by).cloned().expect("только что записали")
    }

    /// Заявку отклонили: снять «ждёт ответа» и запомнить отказ на
    /// [`FRIEND_DECLINE_MEMORY`], чтобы запоздавший список её не вернул.
    pub fn on_declined(&mut self, by: [u8; 32], now: Instant) -> Option<Friend> {
        self.declined
            .retain(|(p, t)| *p != by && now.saturating_duration_since(*t) < FRIEND_DECLINE_MEMORY);
        self.declined.push((by, now));
        let pos = self.entries.iter().position(|e| {
            e.f.pk == by && matches!(e.f.state, FriendState::PendingOut | FriendState::PendingIn)
        })?;
        Some(self.entries.remove(pos).f)
    }

    /// Отказ отправлен нами (`Cmd::DeclineFriend`): убрать сразу, не дожидаясь
    /// списка от сервера, и запомнить на [`FRIEND_DECLINE_MEMORY`].
    pub fn on_decline_sent(&mut self, pk: [u8; 32], now: Instant) -> Option<Friend> {
        self.on_declined(pk, now)
    }

    /// Дружбу сняли (вторая сторона — `FRIEND_REMOVED`, или мы сами):
    /// `Some` — запись была.
    pub fn on_removed(&mut self, pk: &[u8; 32]) -> Option<Friend> {
        let pos = self.entries.iter().position(|e| &e.f.pk == pk)?;
        Some(self.entries.remove(pos).f)
    }

    /// Полное окно списка с сервера (`FRIEND_LIST`). Всё, чего в покрытом окне
    /// нет, снимается (кроме `Legacy`: это наша локальная запись, сервер про
    /// неё и не должен знать). Возвращает снятые записи.
    pub fn on_synced(
        &mut self,
        items: &[FriendInfo],
        from: &[u8; 32],
        complete: bool,
        now: Instant,
    ) -> Vec<Friend> {
        // Последний ключ окна: дальше `complete` решает, покрыто ли всё.
        let upto = if complete {
            None
        } else {
            Some(items.iter().map(|i| i.pk).max().unwrap_or(*from))
        };
        let mut removed = Vec::new();
        self.entries.retain(|e| {
            if e.f.state == FriendState::Legacy {
                return true;
            }
            let in_window = e.f.pk >= *from && upto.is_none_or(|u| e.f.pk <= u);
            let gone = in_window
                && !items.iter().any(|i| i.pk == e.f.pk)
                && now.saturating_duration_since(e.received_at) >= FRIEND_SYNC_GRACE;
            if gone {
                removed.push(e.f.clone());
            }
            !gone
        });
        // Состояния и ники — по серверу. `Legacy` апгрейдится до `Accepted`,
        // когда сервер прислал пару: локальная запись стала настоящей.
        for i in items {
            if !friend_state::known(i.state) {
                continue;
            }
            let state = match i.state {
                friend_state::ACCEPTED => FriendState::Accepted,
                friend_state::PENDING_IN => FriendState::PendingIn,
                _ => FriendState::PendingOut,
            };
            self.set(i.pk, i.name.clone(), state, i.since_ms, now);
        }
        removed
    }

    /// Раз в тик: снять истёкшие заявки (их же сервер удаляет в housekeeping)
    /// и забыть старые отказы. Возвращает истёкшие.
    pub fn tick(&mut self, now: Instant) -> Vec<Friend> {
        self.declined
            .retain(|(_, t)| now.saturating_duration_since(*t) < FRIEND_DECLINE_MEMORY);
        let mut expired = Vec::new();
        self.entries.retain(|e| {
            let gone = e.expires_at.is_some_and(|t| now >= t)
                && matches!(e.f.state, FriendState::PendingIn | FriendState::PendingOut);
            if gone {
                expired.push(e.f.clone());
            }
            !gone
        });
        expired.sort_by_key(|f| f.pk);
        expired
    }

    /// Записать состояния в конфиг (`client.json`), сохранив алиасы: алиас —
    /// локальное имя, модель его не знает и не переписывает. Записи, которых
    /// в модели нет, из конфига уходят.
    pub fn apply(&self, cfg: &mut Config) {
        let mut out = Vec::with_capacity(self.entries.len());
        for e in &self.entries {
            let hex = proto::hex_of(&e.f.pk);
            let alias = cfg
                .friends
                .iter()
                .find(|f| f.pubkey == hex)
                .map(|f| f.alias.clone())
                .unwrap_or_default();
            out.push(StoredFriend {
                pubkey: hex,
                alias,
                nick: e.f.nick.clone(),
                state: e.f.state,
            });
        }
        cfg.friends = out;
    }
}

/// hex pubkey из `client.json` → ключ.
pub fn parse_pk(hex: &str) -> anyhow::Result<[u8; 32]> {
    let v = proto::hex_to_bytes(hex)?;
    anyhow::ensure!(v.len() == 32, "bad stored pubkey");
    Ok(v.try_into().expect("длина проверена"))
}

/// Элемент списка `payloads::FriendList` → состояние модели (`None` —
/// состояние неизвестно, запись показывать нельзя).
pub fn info_state(i: &FriendInfo) -> Option<FriendState> {
    match i.state {
        friend_state::ACCEPTED => Some(FriendState::Accepted),
        friend_state::PENDING_IN => Some(FriendState::PendingIn),
        friend_state::PENDING_OUT => Some(FriendState::PendingOut),
        _ => None,
    }
}

/// Состояние из `FRIEND_LIST` для подсказки/маркера в панели друзей.
pub fn state_marker(state: FriendState) -> &'static str {
    match state {
        FriendState::Legacy => "локально",
        FriendState::PendingOut => "заявка отправлена",
        FriendState::PendingIn => "заявка пришла",
        FriendState::Accepted => "друг",
    }
}

/// Короткая подпись состояния для узкой колонки панели.
pub fn state_badge(state: FriendState) -> &'static str {
    match state {
        FriendState::Legacy => "лок.",
        FriendState::PendingOut => "→",
        FriendState::PendingIn => "←",
        FriendState::Accepted => "✓",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: u32 = 600;

    fn pk(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn t0() -> Instant {
        Instant::now()
    }

    /// Момент «давно пришедшей» записи: сверка такие не щадит.
    fn aged(t: Instant) -> Instant {
        t + FRIEND_SYNC_GRACE * 2
    }

    fn info(b: u8, state: u8, name: &str) -> FriendInfo {
        FriendInfo {
            pk: pk(b),
            name: name.into(),
            state,
            since_ms: 100,
        }
    }

    #[test]
    fn заявка_добавляется_повтор_обновляет_без_дубликата() {
        let t = t0();
        let mut f = Friends::new();
        assert_eq!(
            f.on_request(pk(2), "bravo".into(), Some(TTL), t),
            RequestOutcome::New
        );
        assert_eq!(
            f.on_request(pk(1), "alpha".into(), Some(TTL), t),
            RequestOutcome::New
        );
        // Повтор заявки: без дубликата, ник обновлён, срок продлён.
        let later = t + Duration::from_secs(60);
        assert_eq!(
            f.on_request(pk(1), "alpha2".into(), Some(TTL), later),
            RequestOutcome::Updated
        );
        assert_eq!(f.len(), 2);
        let a = f.get(&pk(1)).unwrap();
        assert_eq!(a.nick, "alpha2");
        assert_eq!(a.state, FriendState::PendingIn);
        // Список — по возрастанию ключа.
        assert_eq!(
            f.list().iter().map(|x| x.pk[0]).collect::<Vec<_>>(),
            vec![1, 2]
        );
        // Истёкшая заявка снимается тиком.
        let gone = f.tick(later + Duration::from_secs(TTL as u64 + 1));
        assert_eq!(gone.len(), 2);
        assert!(f.is_empty());
    }

    #[test]
    fn принятие_делает_дружбу_обоюдной() {
        let t = t0();
        let mut f = Friends::new();
        f.request_sent(pk(2), t);
        assert_eq!(f.state_of(&pk(2)), Some(FriendState::PendingOut));
        // Пришло «приняли» — у нас дружба, заявки больше нет.
        let fr = f.on_accepted(pk(2), "bravo".into(), t);
        assert_eq!(fr.state, FriendState::Accepted);
        assert!(f.is_friend(&pk(2)));
        assert_eq!(f.incoming().len(), 0);
        // Вторая сторона видит то же самое: пара одна на двоих.
        let mut g = Friends::new();
        g.on_request(pk(1), "alpha".into(), Some(TTL), t);
        g.on_accepted(pk(1), "alpha".into(), t);
        assert!(g.is_friend(&pk(1)));
        // Повторное принятие не плодит записей.
        g.on_accepted(pk(1), "alpha".into(), t);
        assert_eq!(g.len(), 1);
    }

    #[test]
    fn отказ_снимает_заявку_и_помнится_5_секунд() {
        let t = t0();
        let mut f = Friends::new();
        f.on_request(pk(3), "charlie".into(), Some(TTL), t);
        // Отказ на нашей стороне: заявка уходит сразу.
        assert!(f.on_decline_sent(pk(3), t).is_some());
        assert!(!f.contains(&pk(3)));
        // Запоздавший список, собранный до отказа, её не возвращает.
        assert_eq!(
            f.on_request(
                pk(3),
                "charlie".into(),
                Some(TTL),
                t + Duration::from_secs(1)
            ),
            RequestOutcome::Declined
        );
        assert!(!f.contains(&pk(3)));
        // Через 5 с память отказа истекает — новая заявка проходит.
        let after = t + FRIEND_DECLINE_MEMORY + Duration::from_millis(1);
        assert_eq!(
            f.on_request(pk(3), "charlie".into(), Some(TTL), after),
            RequestOutcome::New
        );
        // «Отклонили нам» — снимает нашу исходящую.
        let mut g = Friends::new();
        g.request_sent(pk(4), t);
        assert_eq!(g.on_declined(pk(4), t).map(|x| x.pk), Some(pk(4)));
        assert!(!g.contains(&pk(4)));
        // Отклонение дружбы заявку не снимает (это не заявка).
        let mut h = Friends::new();
        h.on_accepted(pk(5), "echo".into(), t);
        assert!(h.on_declined(pk(5), t).is_none());
        assert!(h.is_friend(&pk(5)));
    }

    #[test]
    fn список_с_сервера_снимает_устаревшие_заявки() {
        let t = t0();
        let mut f = Friends::new();
        f.on_request(pk(1), "a".into(), Some(TTL), t);
        f.on_request(pk(2), "b".into(), Some(TTL), t);
        f.request_sent(pk(3), t);
        let now = aged(t);
        // Пока были офлайн, 1 отклонили, 2 приняли, 3 сняли.
        let items = vec![info(2, friend_state::ACCEPTED, "b")];
        let gone = f.on_synced(&items, &[0; 32], true, now);
        assert_eq!(gone.iter().map(|x| x.pk[0]).collect::<Vec<_>>(), vec![1, 3]);
        assert_eq!(f.state_of(&pk(2)), Some(FriendState::Accepted));
        assert_eq!(f.len(), 1);
        // Повторная сверка ничего не снимает и ничего не дублирует.
        assert!(f.on_synced(&items, &[0; 32], true, now).is_empty());
        assert_eq!(f.len(), 1);
        // Запись, пришедшая только что, сверка не трогает (список мог быть
        // собран раньше).
        f.on_request(pk(9), "i".into(), Some(TTL), now);
        assert!(f.on_synced(&items, &[0; 32], true, now).is_empty());
        assert!(f.contains(&pk(9)));
        // Неполное окно снимает только до последнего ключа в нём.
        let now2 = now + FRIEND_SYNC_GRACE * 2;
        f.request_sent(pk(40), now2);
        let gone = f.on_synced(
            &[info(9, friend_state::PENDING_IN, "i")],
            &[0; 32],
            false,
            now2,
        );
        assert_eq!(
            gone.iter().map(|x| x.pk[0]).collect::<Vec<_>>(),
            vec![2],
            "ключи за последним в окне не покрыты"
        );
        assert!(f.contains(&pk(40)), "за окном — не снято");
    }

    #[test]
    fn встречные_заявки_становятся_дружбой() {
        let t = t0();
        let mut f = Friends::new();
        f.request_sent(pk(7), t);
        // Он отвечает не «принять», а своей заявкой — сервер считает пару
        // принятой, модель обязана прийти к тому же.
        assert_eq!(
            f.on_request(pk(7), "seven".into(), Some(TTL), t),
            RequestOutcome::Accepted
        );
        assert!(f.is_friend(&pk(7)));
        assert_eq!(f.incoming().len(), 0, "окна заявки быть не должно");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn ник_фолбэк_алиас_перекрывает_и_код_последний() {
        let p = pk(0xAB);
        // Алиас важнее ника.
        assert_eq!(display_name("мой", "серверный", &p), "мой");
        // Нет алиаса — ник с сервера.
        assert_eq!(display_name("", "серверный", &p), "серверный");
        assert_eq!(display_name("   ", " серверный ", &p), "серверный");
        // Ничего нет — короткий код, а не 52 символа friend code.
        let code = display_name("", "", &p);
        assert_eq!(code, short_code(&p));
        assert!(code.len() < 20, "код в списке короткий: {code}");
        assert!(code.starts_with("abababab"), "{code}");
    }

    #[test]
    fn локальная_запись_без_серверной_помечается_локальной() {
        let t = t0();
        let mut cfg = Config::default();
        cfg.friends.push(StoredFriend {
            pubkey: proto::hex_of(&pk(8)),
            alias: "старый друг".into(),
            nick: String::new(),
            state: FriendState::Legacy,
        });
        let mut f = Friends::from_cfg(&cfg, t);
        assert_eq!(f.state_of(&pk(8)), Some(FriendState::Legacy));
        // Сервер про неё не знает — сверка её не снимает.
        let now = t + FRIEND_SYNC_GRACE * 2;
        assert!(f.on_synced(&[], &[0; 32], true, now).is_empty());
        assert_eq!(f.state_of(&pk(8)), Some(FriendState::Legacy));
        assert_eq!(state_badge(FriendState::Legacy), "лок.");
        // Сервер прислал пару — запись стала настоящей.
        let items = vec![info(8, friend_state::ACCEPTED, "nick8")];
        f.on_synced(&items, &[0; 32], true, now);
        assert!(f.is_friend(&pk(8)));
        // Алиас при записи в конфиг не потерян, ник обновлён.
        f.apply(&mut cfg);
        assert_eq!(cfg.friends.len(), 1);
        assert_eq!(cfg.friends[0].alias, "старый друг");
        assert_eq!(cfg.friends[0].nick, "nick8");
        assert_eq!(cfg.friends[0].state, FriendState::Accepted);
    }

    #[test]
    fn удаление_и_применение_к_конфигу() {
        let t = t0();
        let mut cfg = Config::default();
        let mut f = Friends::new();
        f.on_accepted(pk(1), "a".into(), t);
        f.on_request(pk(2), "b".into(), Some(TTL), t);
        f.apply(&mut cfg);
        assert_eq!(cfg.friends.len(), 2);
        // Снятие: запись уходит и из модели, и из конфига.
        assert_eq!(f.on_removed(&pk(1)).map(|x| x.nick), Some("a".into()));
        assert!(f.on_removed(&pk(1)).is_none(), "повтор — не ошибка");
        f.apply(&mut cfg);
        assert_eq!(cfg.friends.len(), 1);
        assert_eq!(cfg.friends[0].pubkey, proto::hex_of(&pk(2)));
        // Модель, загруженная из конфига, эквивалентна.
        let back = Friends::from_cfg(&cfg, t);
        assert_eq!(back.list(), f.list());
    }
}
