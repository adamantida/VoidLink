//! Федерация серверов (сервер ↔ сервер), §3.5 плана этапа 9.
//!
//! T4a — ядро: рукопожатие `SRV_HELLO`/`SRV_HELLO_ACK`, федеративная сессия
//! (AEAD того же формата, что ctrl), TOFU-пиннинг ключей в `server.json`,
//! недоверенные подсказки `SERVER_HINT`. T4b1 — серверная репликация и релей:
//! записи групп владельца (`FED_GROUP_PUSH`/`FED_GROUP_DELTA`), общий пул
//! адресов identity (`FED_ADDR_PUSH`/`FED_ADDR_REVOKE`) и кросс-серверный
//! релей групповых кадров (`FED_RELAY` + `ACK`/`NACK`). Клиентская часть
//! (`FED_GROUPS`/`JOIN_FED` на клиенте) — T4b2.
//!
//! ## Как устроено
//!
//! * Таблица пиров — TOFU: `Pin { addr, ed, x, added_at }`. Сервер, которого
//!   ещё не знают, закрепляется при первом успешном рукопожатии; при
//!   расхождении ed/x/addr — отказ, метрика `voidlink_fed_hint_rejected_total`
//!   и тревога в лог.
//! * `SERVER_HINT` от клиента — только повод послать `SRV_HELLO`; заявленный
//!   в подсказке ключ обязан совпасть с ключом ответа, иначе отказ.
//! * Транспорт — основной UDP-сокет сервера: своего порта федерация не
//!   заводит. [`Shared::send_to`](crate::Shared) же отдаёт кадр в реестр TCP,
//!   если адрес — живое TCP-соединение (тот же TCP-фолбэк, что у клиентов).
//! * `--peer` и `--fed-pool` — кандидаты рукопожатия (`--fed-pool` ещё и
//!   серверы общего пула адресов).
//! * Кадры `0x42..=0x48` — только внутри установленной сессии, AEAD по её
//!   ключам; сам федеративный диапазон открытым текстом не ходит.
//! * Таймаут рукопожатия и простоя сессии — 30 с; `SRV_HELLO` переотправляется
//!   раз в `HELLO_RESEND`, пока не пришёл `ACK`.
//! * Встречные `SRV_HELLO` (оба сервера одновременно узнали друг о друге)
//!   разрешаются детерминированно: инициатор — меньший ed25519-ключ. Меньший
//!   игнорирует входящий `HELLO` (ACK придёт на его собственный), больший
//!   отменяет свою попытку и принимает входящий. Запоздалый `HELLO` не
//!   перезаписывает уже установленную initiator-сессию, а `ACK` без ожидающей
//!   попытки игнорируется (не ошибка) — T4c.
//! * Все действия собираются под блокировкой таблицы ([`Action`]) и
//!   применяются после неё: отправка, метрики, лог, сохранение на диск,
//!   репликация в состояние (уже без блокировки федерации — порядок
//!   `state → fed`).
//!
//! ## Репликация (T4b1)
//!
//! * Владелец группы — источник правды. Изменение его группы уходит пирам
//!   полной записью (новая группа, откат/скачок ревизии, удаление) или
//!   дельтой (вход/выход/имя/владение/ключ). Каждый сервер назначает
//!   участникам свой локальный gid; uuid — общий на федерацию и переживает
//!   рестарт (`federation.groups`).
//! * Реплицированные группы видны локальным клиентам (список
//!   `GROUP_LIST`/`FED_GROUPS`, `GET_GROUP`, `JOIN_FED` → `GROUP_STATE`), но
//!   не публикуются обратно: у каждой записи ровно один источник правды.
//!   Первая полная запись и фиксирует его (`origin`); записи и дельты от
//!   другого сервера по тому же uuid отвергаются.
//! * При входе клиента в чужую (реплицированную) группу сервер шлёт
//!   владельцу дельту-заявку; владелец сам добавляет участника, ротирует
//!   ключ и рассылает изменение — источник правды остаётся у него.
//! * Общий пул адресов: сервер заявляет адреса своих identity
//!   (`FED_ADDR_PUSH`), пиры резервируют их локально. Конфликт (одна
//!   identity с разными адресами или один адрес у разных identity) решает
//!   меньший ed25519-ключ сервера: он и остаётся; проигравший перевыдаёт
//!   адрес и уведомляет пиров.
//! * `FED_RELAY`: если получатель группового кадра не на этом сервере, а
//!   группа федерирована, кадр заворачивается серверу, заявившему адрес
//!   получателя. Тот проверяет, что отправитель и получатель — участники
//!   реплицированной группы, у получателя есть сессия, эпоха ключа и
//!   src/dst кадра совпадают, и пересобирает кадр под свой локальный gid
//!   (ключ группы у него есть). Ответ — `FED_RELAY_ACK`/`NACK`.
//! * Дельты применяются по возрастанию ревизии; потерянную дельту чинит
//!   полная запись при следующей установке сессии с пиром (полная
//!   синхронизация всех своих групп и адресов) — отдельного «догони меня»
//!   кадра в T4b1 нет.
//!
//! ## Ограничения T4b1
//!
//! * Передача владения группой реплицируется как изменение метаданных, но
//!   источник правды остаётся на прежнем сервере (переезд владения — T4b2+).
//! * `revoke_prev` и баны/приглашения не реплицируются: участникам хватает
//!   состава и ключа.
//! * Клиентская часть (экраны, автовход, e2e) — T4b2.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use proto::federation::{
    self, FedAddrClaim, FedChange, FedGroup, FedGroupDelta, FedKeys, FedMember, FedRelay,
    FedRelayReply, SrvHello, nack,
};
use proto::handshake::EphemeralKey;
use proto::payloads::ServerHint;
use proto::replay::ReplayWindow;
use proto::{Identity, SendCounter};
use rand::Rng;
use tunnel_protocol as proto;

use crate::Shared;
use crate::metrics::Metrics;
use crate::persist;

/// Таймаут рукопожатия и простоя федеративной сессии.
pub(crate) const FED_TIMEOUT: Duration = Duration::from_secs(30);
/// Переотправка `SRV_HELLO`, пока не пришёл `ACK`.
pub(crate) const HELLO_RESEND: Duration = Duration::from_secs(2);
const FED_TIMEOUT_MS: u64 = FED_TIMEOUT.as_millis() as u64;
const HELLO_RESEND_MS: u64 = HELLO_RESEND.as_millis() as u64;
/// Больше пиров сервер не закрепляет: таблица не растёт без границ.
pub(crate) const MAX_PEERS: usize = 64;
/// Одновременных попыток рукопожатия (подсказки приходят от клиентов).
const MAX_PENDING: usize = 32;

/// Действие, собранное под блокировкой таблицы и применяемое после неё.
#[derive(Debug)]
enum Action {
    /// Отправить кадр через основной UDP-сокет сервера (или TCP-фолбэк).
    Send(SocketAddr, Vec<u8>),
    /// Отказ: метрика `voidlink_fed_hint_rejected_total` + тревога в лог.
    Reject(String),
    /// Пир закреплён (TOFU) — таблицу надо сохранить на диск.
    Pinned(String),
    /// Обычное событие в лог.
    Info(String),
    /// Применить реплицированную запись группы к состоянию сервера
    /// (создать/обновить локальную копию с локальным gid). `from` — сервер,
    /// от которого пришла запись (источник правды для этого uuid).
    ReplGroup { rec: FedGroup, from: [u8; 32] },
    /// Применить дельту к реплицированной группе `uuid` от `from`.
    ReplDelta {
        delta: FedGroupDelta,
        from: [u8; 32],
    },
    /// Удалить локальную копию реплицированной группы (владелец удалил).
    ReplDelete([u8; 16]),
    /// Заявка адреса в общем пуле: если локальная identity проиграла
    /// конфликт — перевыдать ей адрес и уведомить пиров.
    AddrLost { pk: [u8; 32], ip: u32 },
    /// Зарезервировать адрес удалённой identity в локальном пуле (занят
    /// чужим участником федерации).
    AddrReserve { pk: [u8; 32], ip: u32, on: bool },
    /// Доставить релейнутый кадр локальному клиенту и ответить пиру.
    Relay { from: [u8; 32], rel: FedRelay },
    /// Пир просит добавить своего клиента в нашу группу (`JOIN_FED` на его
    /// стороне): владелец решает, принимать ли.
    JoinRequest {
        uuid: [u8; 16],
        from: [u8; 32],
        changes: Vec<FedChange>,
    },
    /// Пир установил сессию: нужна полная синхронизация (собирается в
    /// housekeeping — под блокировкой состояния её брать нельзя).
    SessionUp,
}

/// Заявка на адрес в общем пуле федерации.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Claim {
    pub ip: u32,
    /// ed25519-ключ сервера, выдавшего адрес (меньший побеждает в конфликте).
    pub server: [u8; 32],
    /// unix мс последнего подтверждения.
    pub ts_ms: u64,
}

/// Снимок локальной (нашей, авторитетной) группы для публикации пирам.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GroupSnap {
    pub uuid: [u8; 16],
    /// Наш локальный gid (у пиров он свой).
    pub gid: u32,
    pub name: String,
    pub owner: [u8; 32],
    pub private: bool,
    pub key: [u8; 32],
    pub epoch: u32,
    pub rev: u32,
    /// Забаненные не реплицируются: записи хватит участникам.
    pub members: Vec<([u8; 32], u32)>,
}

impl GroupSnap {
    /// Полная запись для `FED_GROUP_PUSH`.
    fn record(&self) -> FedGroup {
        FedGroup {
            uuid: self.uuid,
            owner: self.owner,
            gid: self.gid,
            name: self.name.clone(),
            private: self.private,
            key: self.key,
            epoch: self.epoch,
            rev: self.rev,
            members: self
                .members
                .iter()
                .map(|(pk, ip)| FedMember { pk: *pk, ip: *ip })
                .collect(),
            deleted: false,
        }
    }

    /// Изменения относительно прошлой публикации. `None` — дельта не
    /// выражается (ревизия откатилась, изменений слишком много): шлём полную
    /// запись.
    fn changes(&self, old: &FedGroup) -> Option<Vec<FedChange>> {
        let mut out = Vec::new();
        if self.name != old.name
            || self.private != old.private
            || self.owner != old.owner
            || self.key != old.key
            || self.epoch != old.epoch
        {
            out.push(FedChange::Meta {
                name: self.name.clone(),
                owner: self.owner,
                private: self.private,
                key: self.key,
                epoch: self.epoch,
            });
        }
        let old_members: BTreeMap<[u8; 32], u32> =
            old.members.iter().map(|m| (m.pk, m.ip)).collect();
        for (pk, ip) in &self.members {
            if old_members.get(pk) != Some(ip) {
                out.push(FedChange::MemberAdd { pk: *pk, ip: *ip });
            }
        }
        for pk in old_members.keys() {
            if !self.members.iter().any(|(k, _)| k == pk) {
                out.push(FedChange::MemberRemove { pk: *pk });
            }
        }
        if out.len() > federation::FED_MAX_CHANGES {
            return None;
        }
        Some(out)
    }
}

/// Закреплённый (TOFU) пир: `server.json → federation.peers[]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pin {
    pub addr: SocketAddr,
    pub ed: [u8; 32],
    pub x: [u8; 32],
    /// unix мс закрепления.
    pub added_at: u64,
}

/// Исходящая попытка рукопожатия (ждём `SRV_HELLO_ACK` с этого адреса).
struct Pending {
    /// Чей ed ждём: из `SERVER_HINT`, `--peer`/пина. `None` — `--peer` без
    /// ключа (TOFU по первому ответу).
    expected_ed: Option<[u8; 32]>,
    /// Закреплённый x: ответ обязан предъявить тот же.
    expected_x: Option<[u8; 32]>,
    eph: EphemeralKey,
    /// Готовый `SRV_HELLO` — переотправляется как есть (тот же eph/nonce).
    frame: Vec<u8>,
    sent_ms: u64,
    tries: u32,
}

/// Установленная федеративная сессия.
struct Session {
    peer: [u8; 32],
    addr: SocketAddr,
    keys: FedKeys,
    initiator: bool,
    tx: SendCounter,
    rx: ReplayWindow,
    last_rx_ms: u64,
    /// Готовый `ACK` на повтор того же `HELLO`: подпись HELLO и кадр ответа.
    /// Повтор (потерянный ACK) получает тот же ответ, а не новую сессию.
    reply: Option<([u8; 64], Vec<u8>)>,
}

/// Адрес явного пина (`--peer`): ключа ещё нет, TOFU по первому ответу.
#[derive(Clone, Copy)]
struct Target {
    addr: SocketAddr,
}

/// Таблица федерации: пиры, попытки рукопожатия, сессии, репликация.
pub(crate) struct Fed {
    /// Федерация включается флагом `--federate`: без него кадры 0x40..=0x4F
    /// не разбираются вовсе (старый сервер их молча роняет).
    enabled: bool,
    /// Наш ed25519-ключ: разрешает конфликт адресов (меньший id побеждает).
    id: [u8; 32],
    /// ed → закреплённый пир.
    pins: BTreeMap<[u8; 32], Pin>,
    /// адрес → ed: адрес пира закреплён за ключом.
    addrs: HashMap<SocketAddr, [u8; 32]>,
    /// `--peer`: адреса явного пина.
    targets: Vec<Target>,
    /// Обратный индекс установленных сессий для приёма кадров 0x42..=0x4F.
    sessions: HashMap<[u8; 32], Session>,
    sess_addrs: HashMap<SocketAddr, [u8; 32]>,
    pending: HashMap<SocketAddr, Pending>,
    /// `--fed-pool`: серверы, участвующие в общем пуле адресов. Пусто —
    /// в пуле участвуют все пиры.
    pool: Vec<SocketAddr>,
    /// uuid → сервер-источник правды для реплицированной группы (запись
    /// группы на этом сервере — копия). Наши группы сюда не входят.
    origin: BTreeMap<[u8; 16], [u8; 32]>,
    /// identity → заявка на адрес в общем пуле.
    claims: BTreeMap<[u8; 32], Claim>,
    /// uuid → последняя опубликованная нами полная запись (для дельт).
    mine: BTreeMap<[u8; 16], FedGroup>,
    /// Адреса, уже разосланные пирам: повторно не шлём, пока не изменились.
    announced: HashMap<[u8; 32], u32>,
    /// Пиры, которым уже отправлена полная синхронизация (группы + адреса)
    /// в текущей сессии: повторяется при переустановке сессии.
    synced: HashSet<[u8; 32]>,
    /// uuid → счётчик ре-шифрования релейных кадров (nonce под местный gid).
    relay_seq: HashMap<[u8; 16], u64>,
    /// Пир установил сессию: housekeeping сделает полную синхронизацию
    /// (под блокировкой состояния её собирать нельзя — `on_hint` держит её).
    sync_pending: bool,
}

impl Fed {
    /// Конструктор для тестов: без своего id и без восстановленного
    /// состояния федерации.
    #[cfg(test)]
    pub(crate) fn new(
        enabled: bool,
        pins: Vec<Pin>,
        peers: &[SocketAddr],
        pool: &[SocketAddr],
    ) -> Self {
        Self::new_with(enabled, [0u8; 32], pins, peers, pool, &[], &[])
    }

    /// Полный конструктор: `id` — наш ed-ключ, `groups`/`claims` — то, что
    /// пережило рестарт (`server.json → federation.groups/addr_claims`).
    pub(crate) fn new_with(
        enabled: bool,
        id: [u8; 32],
        pins: Vec<Pin>,
        peers: &[SocketAddr],
        pool: &[SocketAddr],
        groups: &[persist::PFedGroup],
        claims: &[persist::PAddrClaim],
    ) -> Self {
        let mut f = Self {
            enabled,
            id,
            pins: BTreeMap::new(),
            addrs: HashMap::new(),
            targets: peers.iter().map(|a| Target { addr: *a }).collect(),
            sessions: HashMap::new(),
            sess_addrs: HashMap::new(),
            pending: HashMap::new(),
            pool: pool.to_vec(),
            origin: BTreeMap::new(),
            claims: BTreeMap::new(),
            mine: BTreeMap::new(),
            announced: HashMap::new(),
            synced: HashSet::new(),
            relay_seq: HashMap::new(),
            sync_pending: false,
        };
        for p in pins.into_iter().take(MAX_PEERS) {
            f.insert_pin(p);
        }
        for g in groups {
            let (Ok(uuid), Ok(origin)) = (crate::unhex16(&g.uuid), crate::unhex(&g.origin)) else {
                continue;
            };
            // Записи своей группы в `origin` нет: она авторитетна здесь.
            if origin != id {
                f.origin.insert(uuid, origin);
            }
        }
        for c in claims {
            let (Ok(pk), Ok(server)) = (crate::unhex(&c.pk), crate::unhex(&c.server)) else {
                continue;
            };
            if server == id {
                continue; // свои адреса — в leases, не в чужом пуле
            }
            f.claims.insert(
                pk,
                Claim {
                    ip: c.ip,
                    server,
                    ts_ms: c.ts_ms,
                },
            );
        }
        f
    }

    /// Зарезервировать адрес под ключ (`false` — адрес уже за другим ed).
    fn insert_pin(&mut self, p: Pin) -> bool {
        if let Some(ed) = self.addrs.get(&p.addr)
            && ed != &p.ed
        {
            return false;
        }
        if let Some(old) = self.pins.get(&p.ed)
            && old.addr != p.addr
        {
            self.addrs.remove(&old.addr);
        }
        self.addrs.insert(p.addr, p.ed);
        self.pins.insert(p.ed, p);
        true
    }

    /// Начать рукопожатие с `addr`. `None` — уже идёт попытка или есть
    /// сессия: подсказки от разных клиентов не превращаются в шторм HELLO.
    fn begin(
        &mut self,
        me: &Identity,
        addr: SocketAddr,
        expected_ed: Option<[u8; 32]>,
        expected_x: Option<[u8; 32]>,
        now_unix: u64,
        now_ms: u64,
    ) -> Option<Action> {
        if self
            .sessions
            .values()
            .any(|s| s.addr == addr && now_ms.saturating_sub(s.last_rx_ms) < FED_TIMEOUT_MS)
        {
            return None;
        }
        if let Some(p) = self.pending.get(&addr)
            && now_ms.saturating_sub(p.sent_ms) < FED_TIMEOUT_MS
        {
            return None;
        }
        if self.pending.len() >= MAX_PENDING {
            return Some(Action::Reject(
                "очередь рукопожатий федерации переполнена".into(),
            ));
        }
        let eph = EphemeralKey::generate();
        let mut nonce = [0u8; federation::FED_NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let hello = SrvHello::new(me, eph.public(), nonce, now_unix, 0);
        let frame = hello.to_frame(federation::SRV_HELLO);
        self.pending.insert(
            addr,
            Pending {
                expected_ed,
                expected_x,
                eph,
                frame: frame.clone(),
                sent_ms: now_ms,
                tries: 1,
            },
        );
        Some(Action::Send(addr, frame))
    }

    /// Подсказка клиента: на каждого кандидата — `SRV_HELLO`. Кандидату не
    /// доверяем: заявленный ключ сверяется с ключом ответа в [`Self::on_ack`].
    fn hint(
        &mut self,
        me: &Identity,
        from: &[u8; 32],
        hints: &[ServerHint],
        now_unix: u64,
        now_ms: u64,
    ) -> Vec<Action> {
        let mut out = vec![Action::Info(format!(
            "hint: {} кандидат(ов) от {} — не доверяем, проверяем SRV_HELLO",
            hints.len(),
            crate::short(from)
        ))];
        for h in hints {
            let Ok(addr) = h.addr.parse::<SocketAddr>() else {
                out.push(Action::Reject(format!(
                    "подсказка {:?}: адрес не разбирается",
                    h.addr
                )));
                continue;
            };
            if !crate::usable_candidate(&addr) {
                out.push(Action::Reject(format!(
                    "подсказка {addr}: адрес не годится (нулевой/групповой)"
                )));
                continue;
            }
            if let Some(pin) = self.pins.get(&h.ed_pub)
                && pin.addr != addr
            {
                out.push(Action::Reject(format!(
                    "подсказка {addr}: ключ {} закреплён за адресом {}",
                    crate::short(&h.ed_pub),
                    pin.addr
                )));
                continue;
            }
            if let Some(ed) = self.addrs.get(&addr)
                && ed != &h.ed_pub
            {
                out.push(Action::Reject(format!(
                    "подсказка {addr}: адрес закреплён за другим ключом {}",
                    crate::short(ed)
                )));
                continue;
            }
            let expected_x = self.pins.get(&h.ed_pub).map(|p| p.x);
            if let Some(a) = self.begin(me, addr, Some(h.ed_pub), expected_x, now_unix, now_ms) {
                out.push(a);
            }
        }
        out
    }

    /// Наша ожидающая попытка к тому же пиру. Адрес мог не совпасть с
    /// адресом подсказки (NAT/прокси): сверяем ещё и заявленный ed.
    fn collision(&self, src: SocketAddr, ed: &[u8; 32]) -> Option<SocketAddr> {
        if self.pending.contains_key(&src) {
            return Some(src);
        }
        self.pending
            .iter()
            .find(|(_, p)| p.expected_ed.as_ref().is_some_and(|e| proto::ct_eq(e, ed)))
            .map(|(a, _)| *a)
    }

    /// Свежая сессия, где инициатор — мы. Запоздалый `SRV_HELLO` от пира не
    /// должен её перезаписывать: у пира уже нет ожидающей попытки (он ответил
    /// ACK'ом), ACK на его новый HELLO уйдёт в пустоту и ключи разойдутся.
    fn initiator_session(&self, ed: &[u8; 32], now_ms: u64) -> bool {
        self.sessions
            .get(ed)
            .is_some_and(|s| s.initiator && now_ms.saturating_sub(s.last_rx_ms) < FED_TIMEOUT_MS)
    }

    /// Входящий `SRV_HELLO`: проверка подписи/свежести, TOFU-закрепление,
    /// ответ `SRV_HELLO_ACK`. `Err` — кадр не разбирается (молча роняем);
    /// `Ok` — разобран, действия (в т. ч. отказ) применяются вызывающим.
    fn on_hello(
        &mut self,
        me: &Identity,
        src: SocketAddr,
        body: &[u8],
        now_unix: u64,
        now_ms: u64,
    ) -> Result<Vec<Action>> {
        let hello = SrvHello::decode(body)?;
        if !self.enabled {
            return Ok(Vec::new());
        }
        // Закреплённый адрес под другим ключом — отказ до проверки подписи.
        if let Some(ed) = self.addrs.get(&src)
            && ed != &hello.ed
        {
            return Ok(vec![Action::Reject(format!(
                "SRV_HELLO с {src}: на закреплённом адресе другой ключ {}",
                crate::short(&hello.ed)
            ))]);
        }
        // Версия/якорь/свежесть/подпись. Неизвестного пира проверяем по
        // заявленному ключу (TOFU): подпись доказывает владение им.
        let expected = self.pins.get(&hello.ed).map(|p| p.ed).unwrap_or(hello.ed);
        if let Err(e) = hello.verify(&expected, now_unix) {
            return Ok(vec![Action::Reject(format!("SRV_HELLO с {src}: {e}"))]);
        }
        if let Some(pin) = self.pins.get(&hello.ed) {
            if let Err(e) = hello.verify_x(&pin.x) {
                return Ok(vec![Action::Reject(format!("SRV_HELLO с {src}: {e}"))]);
            }
            if pin.addr != src {
                return Ok(vec![Action::Reject(format!(
                    "SRV_HELLO с {src}: адрес не совпал с закреплённым {}",
                    pin.addr
                ))]);
            }
        }
        // Повтор того же HELLO (потерянный ACK) — тот же ответ, без новой
        // сессии: эфемерные ключи и ACK не пересоздаются.
        if let Some(s) = self.sessions.get(&hello.ed)
            && let Some((sig, ack)) = &s.reply
            && sig == &hello.sig
        {
            return Ok(vec![Action::Send(src, ack.clone())]);
        }
        // Встречные `SRV_HELLO`: оба сервера получили подсказку друг о друге
        // и одновременно начали рукопожатие. Тай-брейк детерминированный —
        // инициатор меньший ed25519-ключ. Меньший не отвечает на входящий
        // HELLO (ACK придёт на его собственный), больший отменяет свою
        // попытку и принимает входящий: обе стороны приходят к паре
        // (эфемерный меньшего, эфемерный большего).
        let mut out = Vec::new();
        if self.id < hello.ed {
            if self.collision(src, &hello.ed).is_some() {
                return Ok(vec![Action::Info(format!(
                    "SRV_HELLO с {src}: встречное рукопожатие — наш ed меньше, остаёмся инициатором"
                ))]);
            }
            if self.initiator_session(&hello.ed, now_ms) {
                return Ok(vec![Action::Info(format!(
                    "SRV_HELLO с {src}: сессия уже установлена (мы — инициатор), HELLO игнорируем"
                ))]);
            }
        } else if let Some(pend) = self.collision(src, &hello.ed) {
            self.pending.remove(&pend);
            out.push(Action::Info(format!(
                "SRV_HELLO с {src}: встречное рукопожатие — ed пира меньше, уступаем инициативу"
            )));
        }
        let my_eph = EphemeralKey::generate();
        let shared = match hello.dh(&my_eph) {
            Ok(k) => k,
            Err(e) => {
                out.push(Action::Reject(format!("SRV_HELLO с {src}: {e}")));
                return Ok(out);
            }
        };
        if !self.pins.contains_key(&hello.ed) {
            if self.pins.len() >= MAX_PEERS {
                return Ok(vec![Action::Reject(format!(
                    "SRV_HELLO с {src}: таблица пиров заполнена ({MAX_PEERS})"
                ))]);
            }
            let pin = Pin {
                addr: src,
                ed: hello.ed,
                x: hello.x,
                added_at: now_unix,
            };
            if !self.insert_pin(pin) {
                return Ok(vec![Action::Reject(format!(
                    "SRV_HELLO с {src}: адрес уже закреплён за другим ключом"
                ))]);
            }
            out.push(Action::Pinned(format!(
                "TOFU: закреплён сервер {} по адресу {src}",
                crate::short(&hello.ed)
            )));
        }
        let mut nonce = [0u8; federation::FED_NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let ack = SrvHello::new(me, my_eph.public(), nonce, now_unix, 0);
        let ack_frame = ack.to_frame(federation::SRV_HELLO_ACK);
        self.install(Session {
            peer: hello.ed,
            addr: src,
            keys: FedKeys::derive(&shared),
            initiator: false,
            tx: SendCounter::new(),
            rx: ReplayWindow::new(),
            last_rx_ms: now_ms,
            reply: Some((hello.sig, ack_frame.clone())),
        });
        out.push(Action::Send(src, ack_frame));
        out.push(Action::SessionUp);
        Ok(out)
    }

    /// Входящий `SRV_HELLO_ACK`: сверка с заявленным/закреплённым ключом,
    /// TOFU-закрепление и установка сессии (мы — инициатор).
    fn on_ack(
        &mut self,
        src: SocketAddr,
        body: &[u8],
        now_unix: u64,
        now_ms: u64,
    ) -> Result<Vec<Action>> {
        let ack = SrvHello::decode(body)?;
        if !self.enabled {
            return Ok(Vec::new());
        }
        // Ответ ждём только оттуда, куда уходил HELLO. ACK без ожидающей
        // попытки — не ошибка: это запоздалый/лишний ответ (например, на
        // HELLO, чью попытку уже отменил тай-брейк встречного рукопожатия
        // или забрал таймаут). Просто игнорируем, ничего не меняя.
        {
            let Some(p) = self.pending.get(&src) else {
                return Ok(vec![Action::Info(format!(
                    "SRV_HELLO_ACK с {src}: ожидающей попытки нет — игнорируем"
                ))]);
            };
            // Ключ ответа обязан совпасть с заявленным (подсказка/пин).
            if let Some(ed) = p.expected_ed
                && !proto::ct_eq(&ack.ed, &ed)
            {
                return Ok(vec![Action::Reject(format!(
                    "SRV_HELLO_ACK с {src}: ключ ответа {} не совпал с заявленным {}",
                    crate::short(&ack.ed),
                    crate::short(&ed)
                ))]);
            }
            if let Some(x) = p.expected_x
                && !proto::ct_eq(&ack.x, &x)
            {
                return Ok(vec![Action::Reject(format!(
                    "SRV_HELLO_ACK с {src}: x-ключ {} не совпал с закреплённым",
                    crate::short(&ack.x)
                ))]);
            }
        }
        if let Err(e) = ack.verify(&ack.ed, now_unix) {
            return Ok(vec![Action::Reject(format!("SRV_HELLO_ACK с {src}: {e}"))]);
        }
        if let Some(pin) = self.pins.get(&ack.ed) {
            if let Err(e) = ack.verify_x(&pin.x) {
                return Ok(vec![Action::Reject(format!("SRV_HELLO_ACK с {src}: {e}"))]);
            }
            if pin.addr != src {
                return Ok(vec![Action::Reject(format!(
                    "SRV_HELLO_ACK с {src}: адрес не совпал с закреплённым {}",
                    pin.addr
                ))]);
            }
        }
        if let Some(ed) = self.addrs.get(&src)
            && ed != &ack.ed
        {
            return Ok(vec![Action::Reject(format!(
                "SRV_HELLO_ACK с {src}: адрес закреплён за другим ключом {}",
                crate::short(ed)
            ))]);
        }
        let Some(p) = self.pending.remove(&src) else {
            return Ok(Vec::new());
        };
        let shared = match ack.dh(&p.eph) {
            Ok(k) => k,
            Err(e) => return Ok(vec![Action::Reject(format!("SRV_HELLO_ACK с {src}: {e}"))]),
        };
        let mut out = Vec::new();
        if !self.pins.contains_key(&ack.ed) {
            if self.pins.len() >= MAX_PEERS {
                return Ok(vec![Action::Reject(format!(
                    "SRV_HELLO_ACK с {src}: таблица пиров заполнена ({MAX_PEERS})"
                ))]);
            }
            let pin = Pin {
                addr: src,
                ed: ack.ed,
                x: ack.x,
                added_at: now_unix,
            };
            if !self.insert_pin(pin) {
                return Ok(vec![Action::Reject(format!(
                    "SRV_HELLO_ACK с {src}: адрес уже закреплён за другим ключом"
                ))]);
            }
            out.push(Action::Pinned(format!(
                "TOFU: закреплён сервер {} по адресу {src}",
                crate::short(&ack.ed)
            )));
        }
        self.install(Session {
            peer: ack.ed,
            addr: src,
            keys: FedKeys::derive(&shared),
            initiator: true,
            tx: SendCounter::new(),
            rx: ReplayWindow::new(),
            last_rx_ms: now_ms,
            reply: None,
        });
        out.push(Action::SessionUp);
        Ok(out)
    }

    fn install(&mut self, s: Session) {
        if let Some(old) = self.sessions.get(&s.peer)
            && old.addr != s.addr
        {
            self.sess_addrs.remove(&old.addr);
        }
        // Новая сессия (в т.ч. переустановленная) — синхронизация заново.
        self.synced.remove(&s.peer);
        self.sess_addrs.insert(s.addr, s.peer);
        self.sessions.insert(s.peer, s);
    }

    /// Периодический проход: переотправка `SRV_HELLO`, таймауты попыток и
    /// сессий.
    fn tick(&mut self, now_ms: u64) -> Vec<Action> {
        let mut out = Vec::new();
        let mut dead: Vec<(SocketAddr, u32)> = Vec::new();
        let mut resend: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        for (addr, p) in self.pending.iter_mut() {
            let age = now_ms.saturating_sub(p.sent_ms);
            if age >= FED_TIMEOUT_MS {
                dead.push((*addr, p.tries));
            } else if age >= HELLO_RESEND_MS {
                p.sent_ms = now_ms;
                p.tries += 1;
                resend.push((*addr, p.frame.clone()));
            }
        }
        for (addr, tries) in dead {
            self.pending.remove(&addr);
            out.push(Action::Info(format!(
                "рукопожатие с {addr} не удалось за {} с ({tries} попыток)",
                FED_TIMEOUT.as_secs()
            )));
        }
        for (addr, frame) in resend {
            out.push(Action::Send(addr, frame));
        }
        // Сессия без кадров дольше таймаута закрывается. Репликация и релей
        // шлют кадры 0x42..=0x48 и продлевают её; keepalive не нужен.
        let expired: Vec<[u8; 32]> = self
            .sessions
            .iter()
            .filter(|(_, s)| now_ms.saturating_sub(s.last_rx_ms) >= FED_TIMEOUT_MS)
            .map(|(ed, _)| *ed)
            .collect();
        for ed in expired {
            if let Some(s) = self.sessions.remove(&ed) {
                self.sess_addrs.remove(&s.addr);
                out.push(Action::Info(format!(
                    "сессия с {} ({}) истекла",
                    crate::short(&ed),
                    s.addr
                )));
            }
        }
        out
    }

    /// Старт: рукопожатие со всеми закреплёнными пирами и `--peer`-адресами.
    fn bootstrap(&mut self, me: &Identity, now_unix: u64, now_ms: u64) -> Vec<Action> {
        if !self.enabled {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let pins: Vec<Pin> = self.pins.values().cloned().collect();
        for pin in pins {
            if !seen.insert(pin.addr) {
                continue;
            }
            if let Some(a) = self.begin(me, pin.addr, Some(pin.ed), Some(pin.x), now_unix, now_ms) {
                out.push(a);
            }
        }
        for t in self.targets.clone() {
            if !seen.insert(t.addr) {
                continue;
            }
            if !crate::usable_candidate(&t.addr) {
                out.push(Action::Info(format!(
                    "--peer {}: адрес не годится (нулевой/групповой)",
                    t.addr
                )));
                continue;
            }
            if let Some(a) = self.begin(me, t.addr, None, None, now_unix, now_ms) {
                out.push(a);
            }
        }
        // `--fed-pool`: серверы общего пула адресов — тоже кандидаты в пиры
        // (ключ закрепляется TOFU, как у `--peer`).
        for a in self.pool.clone() {
            if !seen.insert(a) || !crate::usable_candidate(&a) {
                continue;
            }
            if let Some(x) = self.begin(me, a, None, None, now_unix, now_ms) {
                out.push(x);
            }
        }
        out
    }

    // ---------- репликация групп и адресов ----------

    /// Зашифровать тело кадра для каждого пира (кроме `skip`) и положить в
    /// очередь отправки.
    fn broadcast(
        &mut self,
        typ: u8,
        body: &[u8],
        out: &mut crate::Outbox,
        skip: Option<&[u8; 32]>,
    ) {
        let peers: Vec<([u8; 32], SocketAddr)> = self
            .sess_addrs
            .iter()
            .map(|(a, ed)| (*ed, *a))
            .filter(|(ed, _)| skip != Some(ed))
            .collect();
        for (ed, _) in peers {
            if let Some(sess) = self.sessions.get_mut(&ed) {
                let addr = sess.addr;
                let frame = seal(sess, typ, body);
                out.push((addr, frame));
            }
        }
    }

    /// Зашифровать кадр одному пиру и положить в очередь отправки.
    fn send_to_peer(&mut self, peer: &[u8; 32], typ: u8, body: &[u8], out: &mut crate::Outbox) {
        if let Some(sess) = self.sessions.get_mut(peer) {
            let addr = sess.addr;
            let frame = seal(sess, typ, body);
            out.push((addr, frame));
        }
    }

    /// Опубликовать изменение группы владельца: полная запись (`PUSH`) или
    /// дельта (`DELTA`) относительно прошлой публикации. Ничего не изменилось
    /// — кадров нет.
    fn publish(&mut self, snap: &GroupSnap, out: &mut crate::Outbox) {
        if !self.enabled {
            return;
        }
        let rec = snap.record();
        let (typ, body) = match self.mine.get(&snap.uuid) {
            // Ещё не публиковали (или сервер перезапустился) — полная запись.
            None => (federation::FED_GROUP_PUSH, rec.encode()),
            Some(old) if *old == rec => return,
            Some(old) if old.rev < rec.rev => match snap.changes(old) {
                Some(changes) if !changes.is_empty() => {
                    let d = FedGroupDelta {
                        uuid: snap.uuid,
                        owner: snap.owner,
                        rev: rec.rev,
                        base_rev: old.rev,
                        changes,
                    };
                    (federation::FED_GROUP_DELTA, d.encode())
                }
                // Ревизия выросла, а видимых изменений нет (статус/адреса
                // сессий не реплицируются) — дельту не шлём.
                Some(_) => {
                    self.mine.insert(snap.uuid, rec);
                    return;
                }
                None => (federation::FED_GROUP_PUSH, rec.encode()),
            },
            // Ревизия откатилась/прыгнула — только полная запись.
            Some(_) => (federation::FED_GROUP_PUSH, rec.encode()),
        };
        self.mine.insert(snap.uuid, rec);
        self.broadcast(typ, &body, out, None);
    }

    /// Опубликовать удаление группы владельца.
    fn publish_deleted(&mut self, snap: &GroupSnap, out: &mut crate::Outbox) {
        if !self.enabled {
            return;
        }
        let mut rec = self
            .mine
            .get(&snap.uuid)
            .cloned()
            .unwrap_or_else(|| snap.record());
        rec.deleted = true;
        rec.rev = snap.rev.wrapping_add(1);
        rec.members.clear();
        self.mine.remove(&snap.uuid);
        self.broadcast(federation::FED_GROUP_PUSH, &rec.encode(), out, None);
    }

    /// Полная синхронизация с пирами, которым в этой сессии ещё ничего не
    /// отправляли: все наши группы и заявки на адреса.
    fn sync(&mut self, snaps: &[GroupSnap], claims: &[FedAddrClaim], out: &mut crate::Outbox) {
        if !self.enabled {
            return;
        }
        let unsynced: Vec<[u8; 32]> = self
            .sess_addrs
            .values()
            .filter(|ed| !self.synced.contains(*ed))
            .copied()
            .collect();
        if unsynced.is_empty() {
            return;
        }
        let mut bodies: Vec<(u8, Vec<u8>)> = Vec::with_capacity(snaps.len() + claims.len());
        for snap in snaps {
            let rec = snap.record();
            bodies.push((federation::FED_GROUP_PUSH, rec.encode()));
            self.mine.insert(snap.uuid, rec);
        }
        for c in claims {
            bodies.push((federation::FED_ADDR_PUSH, c.encode()));
            self.announced.insert(c.pk, c.ip);
        }
        for ed in unsynced {
            if let Some(sess) = self.sessions.get_mut(&ed) {
                let addr = sess.addr;
                for (typ, body) in &bodies {
                    let frame = seal(sess, *typ, body);
                    out.push((addr, frame));
                }
                self.synced.insert(ed);
            }
        }
    }

    /// Есть ли пиры, которым не отправляли полную синхронизацию (чтобы не
    /// собирать снимки групп зря каждый проход).
    fn has_unsynced(&self) -> bool {
        self.sess_addrs.values().any(|ed| !self.synced.contains(ed))
    }

    /// Разослать заявки на адреса, которых пиры ещё не видели (общий пул).
    fn publish_claims(&mut self, claims: &[FedAddrClaim], out: &mut crate::Outbox) {
        for c in claims {
            if self.announced.get(&c.pk) == Some(&c.ip) {
                continue;
            }
            self.announced.insert(c.pk, c.ip);
            let body = c.encode();
            self.broadcast(federation::FED_ADDR_PUSH, &body, out, None);
        }
    }

    /// Обернуть групповой кадр для сервера, на котором живёт получатель
    /// (`FED_RELAY`). `true` — кадр ушёл (получатель заявлен другим сервером
    /// и сессия с ним есть).
    ///
    /// Вызывается из `relay_group` под блокировкой состояния (порядок
    /// `state → fed`).
    fn wrap_relay(
        &mut self,
        uuid: &[u8; 16],
        sender: &[u8; 32],
        dst: &[u8; 32],
        frame: &[u8],
        out: &mut crate::Outbox,
    ) -> bool {
        if !self.enabled || frame.len() > federation::FED_RELAY_MAX_FRAME {
            return false;
        }
        let Some(claim) = self.claims.get(dst).copied() else {
            return false;
        };
        // Адрес заявлен нами — получатель должен быть здесь; иначе кадр
        // отбрасывается (заявка устарела).
        if claim.server == self.id || !self.sessions.contains_key(&claim.server) {
            return false;
        }
        let rel = FedRelay {
            uuid: *uuid,
            sender: *sender,
            dst: *dst,
            frame: frame.to_vec(),
        };
        let body = rel.encode();
        let peer = claim.server;
        self.send_to_peer(&peer, federation::FED_RELAY, &body, out);
        true
    }

    /// Входящая полная запись группы. Принимается только от закреплённого
    /// сервера, и только от того, кто уже владеет этим uuid (первый PUSH и
    /// фиксирует источник правды — конфликтующих записей не бывает).
    fn on_group_push(&mut self, from: [u8; 32], body: &[u8]) -> Result<Vec<Action>> {
        let rec = FedGroup::decode(body)?;
        if !self.enabled {
            return Ok(Vec::new());
        }
        if !self.pins.contains_key(&from) {
            anyhow::bail!("FED_GROUP_PUSH от незакреплённого сервера");
        }
        if self.mine.contains_key(&rec.uuid) {
            return Ok(vec![Action::Reject(format!(
                "FED_GROUP_PUSH: uuid {} — наша группа, источник правды здесь",
                crate::hex(&rec.uuid)
            ))]);
        }
        match self.origin.get(&rec.uuid) {
            Some(origin) if *origin != from => {
                return Ok(vec![Action::Reject(format!(
                    "FED_GROUP_PUSH: uuid {} уже реплицирован от {}",
                    crate::hex(&rec.uuid),
                    crate::short(origin)
                ))]);
            }
            Some(_) => {}
            None => {
                if self.origin.len() >= MAX_FED_GROUPS {
                    return Ok(vec![Action::Reject(
                        "FED_GROUP_PUSH: таблица реплицированных групп заполнена".into(),
                    )]);
                }
                self.origin.insert(rec.uuid, from);
            }
        }
        if rec.deleted {
            return Ok(vec![Action::ReplDelete(rec.uuid)]);
        }
        Ok(vec![Action::ReplGroup { rec, from }])
    }

    /// Входящая дельта. Дельта по нашей собственной группе — заявка на вход
    /// (её принимает владелец), по реплицированной — изменение от источника.
    fn on_group_delta(&mut self, from: [u8; 32], body: &[u8]) -> Result<Vec<Action>> {
        let delta = FedGroupDelta::decode(body)?;
        if !self.enabled {
            return Ok(Vec::new());
        }
        if !self.pins.contains_key(&from) {
            anyhow::bail!("FED_GROUP_DELTA от незакреплённого сервера");
        }
        if self.mine.contains_key(&delta.uuid) {
            return Ok(vec![Action::JoinRequest {
                uuid: delta.uuid,
                from,
                changes: delta.changes,
            }]);
        }
        match self.origin.get(&delta.uuid) {
            Some(origin) if *origin == from => Ok(vec![Action::ReplDelta { delta, from }]),
            Some(origin) => Ok(vec![Action::Reject(format!(
                "FED_GROUP_DELTA: uuid {} реплицирован от {}",
                crate::hex(&delta.uuid),
                crate::short(origin)
            ))]),
            // Полной записи ещё не было: дельта по группе, которую здесь
            // считают своей, — заявка на вход (её решает владелец), по
            // остальным — событие в лог.
            None => Ok(vec![Action::JoinRequest {
                uuid: delta.uuid,
                from,
                changes: delta.changes,
            }]),
        }
    }

    /// Входящая заявка адреса (`FED_ADDR_PUSH`/`FED_ADDR_REVOKE`).
    ///
    /// Конфликт одной identity (разные адреса) и одного адреса (разные
    /// identity) решает меньший server id: он и остаётся. Проигравший
    /// перевыдаёт адрес (`Action::AddrLost`) и уведомляет пиров.
    fn on_addr(
        &mut self,
        from: [u8; 32],
        typ: u8,
        body: &[u8],
        local: &[([u8; 32], u32)],
        now_unix: u64,
        out: &mut crate::Outbox,
    ) -> Result<Vec<Action>> {
        let c = FedAddrClaim::decode(body)?;
        if !self.enabled {
            return Ok(Vec::new());
        }
        if !self.pins.contains_key(&from) {
            anyhow::bail!("FED_ADDR от незакреплённого сервера");
        }
        if c.server != from {
            anyhow::bail!("FED_ADDR: заявка от имени чужого сервера");
        }
        if !crate::leases::valid(c.ip) {
            return Ok(vec![Action::Reject(format!(
                "FED_ADDR: адрес {} вне пула",
                crate::ip_str(c.ip)
            ))]);
        }
        if typ == federation::FED_ADDR_REVOKE {
            // Отзыв принимается только у той же заявки (pk/ip/сервер).
            let ours = self
                .claims
                .get(&c.pk)
                .is_some_and(|cur| cur.ip == c.ip && cur.server == c.server);
            if ours {
                self.claims.remove(&c.pk);
                return Ok(vec![Action::AddrReserve {
                    pk: c.pk,
                    ip: c.ip,
                    on: false,
                }]);
            }
            return Ok(Vec::new());
        }
        let local_ip = |pk: &[u8; 32]| local.iter().find(|(k, _)| k == pk).map(|(_, ip)| *ip);
        let local_owner = |ip: u32| local.iter().find(|(_, x)| *x == ip).map(|(k, _)| *k);
        let mut acts = Vec::new();
        // Наша identity с этим адресом уже владеет им — подтверждение.
        if local_ip(&c.pk) == Some(c.ip) {
            return Ok(acts);
        }
        // Конфликт с адресом нашей identity: меньший server id побеждает.
        let contested = local_ip(&c.pk).filter(|ip| *ip != c.ip);
        let (loser_pk, loser_ip) = match (contested, local_owner(c.ip)) {
            (Some(ip), _) => (Some(c.pk), ip),
            (None, Some(owner)) if owner != c.pk => (Some(owner), c.ip),
            _ => (None, 0),
        };
        if let Some(pk) = loser_pk {
            if self.id < c.server {
                // Мы победили: свою заявку повторяем пиру, чужую не принимаем.
                let mine = FedAddrClaim {
                    pk,
                    ip: loser_ip,
                    server: self.id,
                    ts_ms: now_unix,
                };
                let body = mine.encode();
                if let Some(sess) = self.sessions.get_mut(&from) {
                    let addr = sess.addr;
                    let frame = seal(sess, federation::FED_ADDR_PUSH, &body);
                    out.push((addr, frame));
                }
                return Ok(acts);
            }
            acts.push(Action::AddrLost { pk, ip: loser_ip });
        }
        // Адрес занят другой заявкой в пуле — побеждает меньший server id.
        let holder = self
            .claims
            .iter()
            .find(|(pk, cur)| cur.ip == c.ip && **pk != c.pk)
            .map(|(pk, cur)| (*pk, *cur));
        if let Some((other, cur)) = holder {
            if c.server < cur.server {
                self.claims.remove(&other);
                acts.push(Action::AddrReserve {
                    pk: other,
                    ip: c.ip,
                    on: false,
                });
            } else {
                // Проиграли: пир узнает нашу заявку из общего обмена.
                return Ok(acts);
            }
        }
        match self.claims.get(&c.pk).copied() {
            Some(cur) if cur.ip == c.ip => {
                if c.server <= cur.server {
                    self.claims.insert(
                        c.pk,
                        Claim {
                            ip: c.ip,
                            server: c.server,
                            ts_ms: c.ts_ms,
                        },
                    );
                }
            }
            // Сервер-владелец адреса перевыдал его (равный id) или выиграл
            // конфликт (меньший) — принимаем новый адрес.
            Some(cur) if c.server <= cur.server => {
                self.claims.insert(
                    c.pk,
                    Claim {
                        ip: c.ip,
                        server: c.server,
                        ts_ms: c.ts_ms,
                    },
                );
                acts.push(Action::AddrReserve {
                    pk: c.pk,
                    ip: cur.ip,
                    on: false,
                });
            }
            Some(_) => return Ok(acts),
            None => {
                self.claims.insert(
                    c.pk,
                    Claim {
                        ip: c.ip,
                        server: c.server,
                        ts_ms: c.ts_ms,
                    },
                );
                acts.push(Action::AddrReserve {
                    pk: c.pk,
                    ip: c.ip,
                    on: true,
                });
            }
        }
        // Дальше заявка расходится по остальным пирам (общий пул).
        self.broadcast(federation::FED_ADDR_PUSH, &c.encode(), out, Some(&from));
        Ok(acts)
    }

    /// Входящий `FED_RELAY` — дальше его проверяет локальный слой (ему нужны
    /// группы и сессии получателя).
    fn on_relay(&mut self, from: [u8; 32], body: &[u8]) -> Result<Vec<Action>> {
        let rel = FedRelay::decode(body)?;
        if !self.enabled {
            return Ok(Vec::new());
        }
        if !self.pins.contains_key(&from) {
            anyhow::bail!("FED_RELAY от незакреплённого сервера");
        }
        Ok(vec![Action::Relay { from, rel }])
    }

    /// Входящий ответ на релей: отказ — повод для лога, доставка уже учтена
    /// метрикой на доставившем сервере.
    fn on_reply(&mut self, from: [u8; 32], typ: u8, body: &[u8]) -> Result<Vec<Action>> {
        let reply = FedRelayReply::decode(body)?;
        if !self.enabled {
            return Ok(Vec::new());
        }
        if !self.pins.contains_key(&from) {
            anyhow::bail!("FED_RELAY ответ от незакреплённого сервера");
        }
        Ok(if reply.ok || typ == federation::FED_RELAY_ACK {
            Vec::new()
        } else {
            vec![Action::Info(format!(
                "релей для {} отклонён {}: {}",
                crate::short(&reply.dst),
                crate::short(&from),
                nack::text(reply.reason)
            ))]
        })
    }
}

/// Сколько реплицированных групп сервер держит максимум (иначе таблица
/// растёт без границ на чужом потоке).
pub(crate) const MAX_FED_GROUPS: usize = 512;

/// Применить собранные действия: отправка, метрики, лог, сохранение.
///
/// Действия с состоянием (`Repl*`, `Addr*`, `Relay`) приходят только из
/// [`on_session_frame`]/[`tick`], где блокировка состояния не удерживается:
/// `apply` берёт её сам. `on_hint` вызывает `apply` под записью состояния, но
/// его действия инертны (отправка/лог/пин) — так порядок блокировок
/// `state → fed` не нарушается.
fn apply(sh: &Shared, actions: Vec<Action>) {
    for a in actions {
        match a {
            Action::Send(addr, frame) => sh.send_to(&frame, addr),
            Action::Reject(why) => {
                Metrics::inc(&sh.metrics.fed_hint_rejected, 1);
                sh.log(format!("federation: ОТКАЗ — {why}"));
            }
            Action::Pinned(msg) => {
                sh.log(format!("federation: {msg}"));
                sh.dirty.store(true, Ordering::Relaxed);
                sh.save_soon();
            }
            Action::Info(msg) => sh.log(format!("federation: {msg}")),
            Action::ReplGroup { rec, from } => crate::fed_apply_group(sh, &rec, &from),
            Action::ReplDelta { delta, from } => crate::fed_apply_delta(sh, &delta, &from),
            Action::ReplDelete(uuid) => crate::fed_delete_repl(sh, &uuid),
            Action::AddrLost { pk, ip } => crate::fed_reissue_addr(sh, &pk, ip),
            Action::AddrReserve { pk, ip, on } => crate::fed_reserve_addr(sh, &pk, ip, on),
            Action::Relay { from, rel } => crate::fed_deliver_relay(sh, &from, &rel),
            Action::JoinRequest {
                uuid,
                from,
                changes,
            } => crate::fed_accept_join(sh, &uuid, &from, &changes),
            Action::SessionUp => {
                // Полная синхронизация — в housekeeping (там нет блокировок
                // состояния, которые держит путь подсказки).
                sh.fed.lock().unwrap().sync_pending = true;
            }
        }
    }
}

/// Входящий федеративный кадр (0x40..=0x4F). `true` — обработан.
pub(crate) fn on_frame(sh: &Shared, src: SocketAddr, typ: u8, body: &[u8]) -> bool {
    match typ {
        federation::SRV_HELLO | federation::SRV_HELLO_ACK => on_handshake_frame(sh, src, typ, body),
        federation::FED_GROUP_PUSH
        | federation::FED_GROUP_DELTA
        | federation::FED_ADDR_PUSH
        | federation::FED_ADDR_REVOKE
        | federation::FED_RELAY
        | federation::FED_RELAY_ACK
        | federation::FED_RELAY_NACK => on_session_frame(sh, src, typ, body),
        // 0x49..=0x4F зарезервированы — молча роняем, без RESET чужому
        // серверу.
        _ => false,
    }
}

/// Рукопожатие федерации: открытым текстом, бюджет открытых ответов.
fn on_handshake_frame(sh: &Shared, src: SocketAddr, typ: u8, body: &[u8]) -> bool {
    if !sh.fed.lock().unwrap().enabled {
        return false;
    }
    // Общий бюджет открытых ответов: рукопожатие не должно превращаться в
    // усилитель/нагрузку на подпись.
    if !sh.allow_plain() {
        return false;
    }
    let now_ms = sh.now_ms();
    let now_unix = crate::unix_ms();
    let actions = {
        let mut fed = sh.fed.lock().unwrap();
        let r = if typ == federation::SRV_HELLO {
            fed.on_hello(&sh.identity, src, body, now_unix, now_ms)
        } else {
            fed.on_ack(src, body, now_unix, now_ms)
        };
        match r {
            Ok(a) => a,
            // Не разбирается (мусор/не наш кадр) — молча роняем.
            Err(_) => return false,
        }
    };
    apply(sh, actions);
    true
}

/// Кадр федеративной сессии (`0x42..=0x4F`): AEAD под ключами сессии.
fn on_session_frame(sh: &Shared, src: SocketAddr, typ: u8, body: &[u8]) -> bool {
    let now_ms = sh.now_ms();
    let now_unix = crate::unix_ms();
    // Снимок локальных адресов нужен заявкам (конфликт адресов), но брать
    // блокировку состояния под блокировкой федерации нельзя.
    let local: Vec<([u8; 32], u32)> = if typ == federation::FED_ADDR_PUSH {
        let s = sh.state.read().unwrap();
        s.leases.iter().map(|(k, ip)| (*k, ip)).collect()
    } else {
        Vec::new()
    };
    let mut out = crate::Outbox::new();
    let actions = {
        let mut fed = sh.fed.lock().unwrap();
        if !fed.enabled {
            return false;
        }
        let Some(peer) = fed.sess_addrs.get(&src).copied() else {
            return false;
        };
        let Some(pt) = ({
            let Some(sess) = fed.sessions.get_mut(&peer) else {
                return false;
            };
            let pt = open(sess, typ, body);
            if pt.is_some() {
                sess.last_rx_ms = now_ms;
            }
            pt
        }) else {
            // Подделка/повтор/не та сессия — молча роняем.
            return false;
        };
        let r = match typ {
            federation::FED_GROUP_PUSH => fed.on_group_push(peer, &pt),
            federation::FED_GROUP_DELTA => fed.on_group_delta(peer, &pt),
            federation::FED_ADDR_PUSH | federation::FED_ADDR_REVOKE => {
                fed.on_addr(peer, typ, &pt, &local, now_unix, &mut out)
            }
            federation::FED_RELAY => fed.on_relay(peer, &pt),
            federation::FED_RELAY_ACK | federation::FED_RELAY_NACK => fed.on_reply(peer, typ, &pt),
            _ => Ok(Vec::new()),
        };
        match r {
            Ok(a) => a,
            Err(e) => {
                sh.log(format!("federation: {typ:#04x} от {src}: {e}"));
                return false;
            }
        }
    };
    sh.flush(out);
    apply(sh, actions);
    true
}

/// `SERVER_HINT` от клиента: кандидаты-серверы. Сервер им **не доверяет** —
/// на каждого кандидата уходит `SRV_HELLO`, ключ проверяется по ответу.
pub(crate) fn on_hint(sh: &Shared, from: &[u8; 32], hints: &[ServerHint]) {
    if hints.is_empty() {
        return;
    }
    let actions = {
        let mut fed = sh.fed.lock().unwrap();
        if !fed.enabled {
            sh.log(format!(
                "hint: {} от {} — федерация выключена (--federate)",
                hints.len(),
                crate::short(from)
            ));
            return;
        }
        fed.hint(&sh.identity, from, hints, crate::unix_ms(), sh.now_ms())
    };
    apply(sh, actions);
}

/// Старт федерации: рукопожатие с закреплёнными пирами, `--peer`, пулом.
pub(crate) fn bootstrap(sh: &Shared) {
    let actions = {
        let mut fed = sh.fed.lock().unwrap();
        fed.bootstrap(&sh.identity, crate::unix_ms(), sh.now_ms())
    };
    apply(sh, actions);
}

/// Периодический проход федерации (из housekeeping).
pub(crate) fn tick(sh: &Shared) {
    let actions = {
        let mut fed = sh.fed.lock().unwrap();
        fed.tick(sh.now_ms())
    };
    apply(sh, actions);
    reconcile(sh);
}

/// Полная синхронизация с пирами, установившими сессию: все наши группы и
/// заявки на адреса. Собирается без блокировки федерации и без неё же
/// отправляется — вызывать без блокировки состояния.
pub(crate) fn reconcile(sh: &Shared) {
    let needs = {
        let mut fed = sh.fed.lock().unwrap();
        let needs = fed.sync_pending || fed.has_unsynced();
        fed.sync_pending = false;
        needs
    };
    if !needs {
        return;
    }
    let (snaps, claims) = {
        let s = sh.state.read().unwrap();
        (
            crate::fed_snaps(&s),
            crate::fed_claims(&s, &sh.identity.ed_pub()),
        )
    };
    let mut out = crate::Outbox::new();
    {
        let mut fed = sh.fed.lock().unwrap();
        if !fed.enabled {
            return;
        }
        fed.sync(&snaps, &claims, &mut out);
    }
    sh.flush(out);
}

/// Опубликовать изменение группы владельца всем пирам. Вызывается под
/// блокировкой состояния (порядок `state → fed`).
pub(crate) fn publish_group(sh: &Shared, snap: &GroupSnap, out: &mut crate::Outbox) {
    let mut fed = sh.fed.lock().unwrap();
    if !fed.enabled {
        return;
    }
    fed.publish(snap, out);
}

/// Опубликовать удаление группы владельца пирам.
pub(crate) fn publish_deleted(sh: &Shared, snap: &GroupSnap, out: &mut crate::Outbox) {
    let mut fed = sh.fed.lock().unwrap();
    if !fed.enabled {
        return;
    }
    fed.publish_deleted(snap, out);
}

/// Опубликовать заявку на адрес identity (наш адрес в общем пуле) и
/// разослать её пирам. Вызывается без блокировки состояния.
pub(crate) fn publish_claim(sh: &Shared, pk: [u8; 32], ip: u32) {
    let c = FedAddrClaim {
        pk,
        ip,
        server: sh.identity.ed_pub(),
        ts_ms: crate::unix_ms(),
    };
    let mut out = crate::Outbox::new();
    {
        let mut fed = sh.fed.lock().unwrap();
        if !fed.enabled {
            return;
        }
        fed.announced.insert(pk, ip);
        fed.broadcast(federation::FED_ADDR_PUSH, &c.encode(), &mut out, None);
    }
    sh.flush(out);
}

/// Разослать заявки на адреса (общий пул), не дублируя уже отправленные.
/// Вызывается под блокировкой состояния (порядок `state → fed`).
pub(crate) fn publish_claims(sh: &Shared, claims: &[FedAddrClaim], out: &mut crate::Outbox) {
    let mut fed = sh.fed.lock().unwrap();
    if !fed.enabled {
        return;
    }
    fed.publish_claims(claims, out);
}

/// Включена ли федерация (`--federate`).
pub(crate) fn enabled(sh: &Shared) -> bool {
    sh.fed.lock().unwrap().enabled
}

/// Отправить владельцу заявку на вход в реплицированную группу (его клиент
/// войдёт по `JOIN_FED`). Нет сессии с владельцем — заявка не уходит.
pub(crate) fn request_join(
    sh: &Shared,
    uuid: &[u8; 16],
    owner: &[u8; 32],
    pk: [u8; 32],
    ip: u32,
    rev: u32,
    out: &mut crate::Outbox,
) {
    let d = FedGroupDelta {
        uuid: *uuid,
        owner: *owner,
        rev: rev.wrapping_add(1),
        base_rev: rev,
        changes: vec![FedChange::MemberAdd { pk, ip }],
    };
    let mut fed = sh.fed.lock().unwrap();
    if !fed.enabled {
        return;
    }
    if let Some(origin) = fed.origin.get(uuid).copied() {
        let body = d.encode();
        fed.send_to_peer(&origin, federation::FED_GROUP_DELTA, &body, out);
    }
}

/// Обернуть групповой кадр для сервера, на котором живёт получатель
/// (`FED_RELAY`). `None` — адрес получателя не заявлен другим сервером или
/// сессии с ним нет: кадр отбрасывается.
///
/// Вызывается из `relay_group` под блокировкой состояния (порядок
/// `state → fed`); отправка — после её освобождения.
pub(crate) fn relay_for_peer(
    sh: &Shared,
    uuid: &[u8; 16],
    sender: &[u8; 32],
    dst: &[u8; 32],
    frame: &[u8],
) -> Option<(SocketAddr, Vec<u8>)> {
    let mut out = crate::Outbox::new();
    {
        let mut fed = sh.fed.lock().unwrap();
        fed.wrap_relay(uuid, sender, dst, frame, &mut out);
    }
    out.into_iter().next()
}

/// Ответ пиру на `FED_RELAY` (`ACK`/`NACK`).
pub(crate) fn reply_relay(sh: &Shared, peer: &[u8; 32], reply: &FedRelayReply) {
    let typ = if reply.ok {
        federation::FED_RELAY_ACK
    } else {
        federation::FED_RELAY_NACK
    };
    let body = reply.encode();
    let mut out = crate::Outbox::new();
    {
        let mut fed = sh.fed.lock().unwrap();
        if !fed.enabled {
            return;
        }
        fed.send_to_peer(peer, typ, &body, &mut out);
    }
    sh.flush(out);
}

/// Счётчик для ре-шифрования релейного кадра под локальный gid: старшие 32
/// бита случайны на процесс (два сервера не столкнутся одним nonce), младшие
/// растут на каждый релей.
pub(crate) fn relay_counter(sh: &Shared, uuid: &[u8; 16]) -> u64 {
    let mut fed = sh.fed.lock().unwrap();
    let e = fed
        .relay_seq
        .entry(*uuid)
        .or_insert_with(|| (rand::random::<u32>() as u64) << 32);
    *e = e.wrapping_add(1);
    *e
}

/// Пиры для `server.json → federation.peers`.
pub(crate) fn persisted_peers(sh: &Shared) -> Vec<persist::PPeer> {
    sh.fed
        .lock()
        .unwrap()
        .pins
        .values()
        .map(|p| persist::PPeer {
            addr: p.addr.to_string(),
            ed: crate::hex(&p.ed),
            x: crate::hex(&p.x),
            added_at: p.added_at,
        })
        .collect()
}

/// Заявки на адреса удалённых identity (`server.json →
/// federation.addr_claims`).
pub(crate) fn persisted_claims(sh: &Shared) -> Vec<persist::PAddrClaim> {
    sh.fed
        .lock()
        .unwrap()
        .claims
        .iter()
        .map(|(pk, c)| persist::PAddrClaim {
            pk: crate::hex(pk),
            ip: c.ip,
            server: crate::hex(&c.server),
            ts_ms: c.ts_ms,
        })
        .collect()
}

/// Закреплённые пиров столько (датчик `voidlink_fed_peers`).
pub(crate) fn pin_count(sh: &Shared) -> usize {
    sh.fed.lock().unwrap().pins.len()
}

/// Датчик `voidlink_fed_groups`: сколько реплицированных (чужих) групп
/// сервер знает.
pub(crate) fn repl_count(sh: &Shared) -> usize {
    sh.fed.lock().unwrap().origin.len()
}

/// Датчик `voidlink_fed_addr_claims`: заявок на адреса в общем пуле.
pub(crate) fn claim_count(sh: &Shared) -> usize {
    sh.fed.lock().unwrap().claims.len()
}

/// Закреплён ли пир с ключом `ed` (тесты федерации).
#[cfg(test)]
pub(crate) fn has_pin(sh: &Shared, ed: &[u8; 32]) -> bool {
    sh.fed.lock().unwrap().pins.contains_key(ed)
}

/// Заявленный адрес identity в общем пуле (тесты федерации).
#[cfg(test)]
pub(crate) fn claim_of(sh: &Shared, pk: &[u8; 32]) -> Option<u32> {
    sh.fed.lock().unwrap().claims.get(pk).map(|c| c.ip)
}

/// Тесты: записать заявку адреса в таблицу (как пришедшую от пира).
#[cfg(test)]
pub(crate) fn test_claim(sh: &Shared, pk: [u8; 32], ip: u32, server: [u8; 32]) {
    sh.fed.lock().unwrap().claims.insert(
        pk,
        Claim {
            ip,
            server,
            ts_ms: 1,
        },
    );
}

/// Разбор `federation.peers` из `server.json`. Битая запись — пропуск с
/// тревогой в лог: остальное состояние сервера важнее одной строки.
pub(crate) fn load_pins(peers: &[persist::PPeer]) -> Vec<Pin> {
    let mut out = Vec::with_capacity(peers.len());
    for p in peers {
        let (Ok(addr), Ok(ed), Ok(x)) = (
            p.addr.parse::<SocketAddr>(),
            crate::unhex(&p.ed),
            crate::unhex(&p.x),
        ) else {
            eprintln!(
                "[server] ВНИМАНИЕ: federation.peers: пропущена битая запись {:?} (ed {:?})",
                p.addr, p.ed
            );
            continue;
        };
        if out.iter().any(|q: &Pin| q.ed == ed) {
            continue;
        }
        out.push(Pin {
            addr,
            ed,
            x,
            added_at: p.added_at,
        });
        if out.len() >= MAX_PEERS {
            eprintln!(
                "[server] ВНИМАНИЕ: federation.peers: больше {MAX_PEERS} пиров — лишние пропущены"
            );
            break;
        }
    }
    out
}

/// AEAD-кадр федеративной сессии: формат ctrl (`counter LE || ct`, nonce =
/// 0⁴ || counter, AAD — заголовок TNL2). Так ходят кадры 0x42..=0x4F.
fn seal(s: &mut Session, typ: u8, payload: &[u8]) -> Vec<u8> {
    assert!(federation::is_fed(typ), "не федеративный кадр");
    proto::seal_ctrl(&s.keys.tx(s.initiator), s.tx.next(), typ, payload)
}

/// Разбор AEAD-кадра сессии: предпроверка окна, расшифровка, `commit` окна
/// только после успеха (подделка с огромным счётчиком окно не сдвигает).
fn open(s: &mut Session, typ: u8, body: &[u8]) -> Option<Vec<u8>> {
    let counter = proto::ctrl_counter(body)?;
    if !s.rx.check(counter) {
        return None;
    }
    let (c, pt) = proto::open_ctrl(&s.keys.rx(s.initiator), typ, body).ok()?;
    if !s.rx.commit(c) {
        return None;
    }
    Some(pt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    const NOW_MS: u64 = 1_000_000;
    const NOW_UNIX: u64 = 1_700_000_000_000;

    fn fed(enabled: bool) -> Fed {
        Fed::new(enabled, Vec::new(), &[], &[])
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn sends(actions: Vec<Action>) -> Vec<(SocketAddr, Vec<u8>)> {
        actions
            .into_iter()
            .filter_map(|a| match a {
                Action::Send(to, f) => Some((to, f)),
                _ => None,
            })
            .collect()
    }

    fn rejects(actions: Vec<Action>) -> Vec<String> {
        actions
            .into_iter()
            .filter_map(|a| match a {
                Action::Reject(why) => Some(why),
                _ => None,
            })
            .collect()
    }

    fn hello_for(id: &Identity, ts: u64) -> Vec<u8> {
        let eph = EphemeralKey::generate();
        let mut nonce = [0u8; federation::FED_NONCE_LEN];
        nonce[0] = 1;
        SrvHello::new(id, eph.public(), nonce, ts, 0).encode()
    }

    fn ack_of(frame: &[u8]) -> Vec<u8> {
        let (typ, body) = proto::split_frame(frame).unwrap();
        assert_eq!(typ, federation::SRV_HELLO_ACK);
        body.to_vec()
    }

    /// Пара identity с детерминированным порядком: у `a` ed меньше, значит
    /// по тай-брейку встречных `SRV_HELLO` инициатор — именно `a`.
    fn pair_small_big() -> (Identity, Identity) {
        loop {
            let a = Identity::generate();
            let b = Identity::generate();
            if a.ed_pub() < b.ed_pub() {
                return (a, b);
            }
        }
    }

    // ---------- чистое ядро (без сокетов) ----------

    #[test]
    fn рукопожатие_и_aead_в_обе_стороны() {
        let a = Identity::generate();
        let b = Identity::generate();
        let (aa, ba) = (addr(10_001), addr(10_002));
        let mut fa = Fed::new(true, Vec::new(), &[ba], &[]);
        let mut fb = fed(true);
        // a → b: --peer без ключа (TOFU по первому ответу).
        let hello = sends(fa.bootstrap(&a, NOW_UNIX, NOW_MS));
        assert_eq!(hello.len(), 1);
        assert_eq!(hello[0].0, ba);
        let (typ, body) = proto::split_frame(&hello[0].1).unwrap();
        assert_eq!(typ, federation::SRV_HELLO);
        // b принимает и отвечает ACK, закрепляя a.
        let ack = sends(fb.on_hello(&b, aa, body, NOW_UNIX, NOW_MS).unwrap());
        assert_eq!(ack.len(), 1);
        assert_eq!(ack[0].0, aa);
        // a проверяет ACK и закрепляет b.
        let acts = fa.on_ack(ba, &ack_of(&ack[0].1), NOW_UNIX, NOW_MS).unwrap();
        assert!(rejects(acts).is_empty());
        assert_eq!(fa.pins.len(), 1);
        assert_eq!(fb.pins.len(), 1);
        assert_eq!(fa.pins[&b.ed_pub()].addr, ba);
        assert_eq!(fa.pins[&b.ed_pub()].x, b.x_pub());
        assert_eq!(fa.pins[&b.ed_pub()].added_at, NOW_UNIX);
        assert_eq!(fb.pins[&a.ed_pub()].addr, aa);
        assert!(fa.sessions[&b.ed_pub()].initiator);
        assert!(!fb.sessions[&a.ed_pub()].initiator);

        // AEAD: a → b.
        let frame = {
            let s = fa.sessions.get_mut(&b.ed_pub()).unwrap();
            seal(s, federation::FED_RELAY, b"cross-server")
        };
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let pt = {
            let s = fb.sessions.get_mut(&a.ed_pub()).unwrap();
            open(s, typ, body)
        };
        assert_eq!(pt.as_deref(), Some(&b"cross-server"[..]));
        // Повтор того же кадра — окно повторов отвергает.
        let again = {
            let s = fb.sessions.get_mut(&a.ed_pub()).unwrap();
            open(s, typ, body)
        };
        assert!(again.is_none(), "повтор кадра не принимается");

        // AEAD: b → a (своё окно и свой счётчик).
        let frame = {
            let s = fb.sessions.get_mut(&a.ed_pub()).unwrap();
            seal(s, federation::FED_GROUP_PUSH, b"push")
        };
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let pt = {
            let s = fa.sessions.get_mut(&b.ed_pub()).unwrap();
            open(s, typ, body)
        };
        assert_eq!(pt.as_deref(), Some(&b"push"[..]));
    }

    #[test]
    fn повтор_hello_получает_тот_же_ack() {
        let a = Identity::generate();
        let b = Identity::generate();
        let (aa, ba) = (addr(11_001), addr(11_002));
        let mut fa = Fed::new(true, Vec::new(), &[ba], &[]);
        let mut fb = fed(true);
        let hello = sends(fa.bootstrap(&a, NOW_UNIX, NOW_MS));
        let (_, body) = proto::split_frame(&hello[0].1).unwrap();
        let ack1 = sends(fb.on_hello(&b, aa, body, NOW_UNIX, NOW_MS).unwrap());
        let ack2 = sends(fb.on_hello(&b, aa, body, NOW_UNIX, NOW_MS).unwrap());
        assert_eq!(ack1[0].1, ack2[0].1, "повтор HELLO — тот же ACK");
        assert_eq!(fb.sessions.len(), 1, "новая сессия не создаётся");
    }

    /// T4c: встречные `SRV_HELLO` (оба сервера одновременно получили
    /// подсказку друг о друге) сходятся на одной сессии по тай-брейку
    /// «меньший ed — инициатор», сразу и с одинаковыми ключами, без
    /// 30-секундного ожидания таймаута.
    #[test]
    fn встречные_hello_сходятся_на_одной_сессии() {
        let (a, b) = pair_small_big();
        let (aa, ba) = (addr(21_001), addr(21_002));
        let mut fa = Fed::new_with(true, a.ed_pub(), Vec::new(), &[], &[], &[], &[]);
        let mut fb = Fed::new_with(true, b.ed_pub(), Vec::new(), &[], &[], &[], &[]);
        // Оба одновременно получают SERVER_HINT друг о друге и шлют HELLO.
        let hint_a = [ServerHint {
            addr: ba.to_string(),
            ed_pub: b.ed_pub(),
        }];
        let hint_b = [ServerHint {
            addr: aa.to_string(),
            ed_pub: a.ed_pub(),
        }];
        let ha = sends(fa.hint(&a, &[1; 32], &hint_a, NOW_UNIX, NOW_MS));
        let hb = sends(fb.hint(&b, &[2; 32], &hint_b, NOW_UNIX, NOW_MS));
        assert_eq!(
            (ha.len(), hb.len()),
            (1, 1),
            "по одному HELLO с каждой стороны"
        );
        assert_eq!(ha[0].0, ba);
        assert_eq!(hb[0].0, aa);
        let (_, body_a) = proto::split_frame(&ha[0].1).unwrap();
        let (_, body_b) = proto::split_frame(&hb[0].1).unwrap();
        assert_eq!(fa.pending.len(), 1);
        assert_eq!(fb.pending.len(), 1);

        // Меньший (a) игнорирует встречный HELLO: попытка жива, ACK не шлётся.
        let acts = fa.on_hello(&a, ba, body_b, NOW_UNIX, NOW_MS).unwrap();
        assert!(
            acts.iter().all(|x| matches!(x, Action::Info(_))),
            "меньший не должен отвечать ACK: {acts:?}"
        );
        assert!(fa.sessions.is_empty());
        assert!(fa.pending.contains_key(&ba), "попытка меньшего отменена");

        // Больший (b) уступает инициативу: отменяет свою попытку, принимает
        // входящий HELLO и отвечает ACK.
        let acts = fb.on_hello(&b, aa, body_a, NOW_UNIX, NOW_MS).unwrap();
        let ack = sends(acts);
        assert_eq!(ack.len(), 1);
        assert_eq!(ack[0].0, aa);
        assert!(fb.pending.is_empty(), "pending большего не отменён");
        assert_eq!(fb.sessions.len(), 1);
        assert!(!fb.sessions[&a.ed_pub()].initiator);

        // ACK завершает рукопожатие у меньшего — сразу, без таймаута.
        let acts = fa.on_ack(ba, &ack_of(&ack[0].1), NOW_UNIX, NOW_MS).unwrap();
        assert!(
            !acts.iter().any(|x| matches!(x, Action::Reject(_))),
            "{acts:?}"
        );
        assert!(fa.pending.is_empty());
        assert_eq!(fa.sessions.len(), 1);
        assert!(fa.sessions[&b.ed_pub()].initiator);

        // Переотправок HELLO больше нет: обе попытки закрыты.
        assert!(sends(fa.tick(NOW_MS + HELLO_RESEND_MS)).is_empty());
        assert!(sends(fb.tick(NOW_MS + HELLO_RESEND_MS)).is_empty());

        // Ключи совпали — AEAD в обе стороны.
        let frame = seal(
            fa.sessions.get_mut(&b.ed_pub()).unwrap(),
            federation::FED_RELAY,
            b"a->b",
        );
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let pt = open(fb.sessions.get_mut(&a.ed_pub()).unwrap(), typ, body);
        assert_eq!(pt.as_deref(), Some(&b"a->b"[..]), "a→b не расшифровался");
        let frame = seal(
            fb.sessions.get_mut(&a.ed_pub()).unwrap(),
            federation::FED_GROUP_PUSH,
            b"b->a",
        );
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let pt = open(fa.sessions.get_mut(&b.ed_pub()).unwrap(), typ, body);
        assert_eq!(pt.as_deref(), Some(&b"b->a"[..]), "b→a не расшифровался");
    }

    /// T4c: запоздалый `SRV_HELLO` не перезаписывает уже установленную
    /// initiator-сессию, а `SRV_HELLO_ACK` без ожидающей попытки — не ошибка
    /// и ничего не меняет.
    #[test]
    fn запоздалый_hello_не_перезаписывает_initiator_сессию() {
        let (a, b) = pair_small_big();
        let (aa, ba) = (addr(22_001), addr(22_002));
        let mut fa = Fed::new_with(true, a.ed_pub(), Vec::new(), &[], &[], &[], &[]);
        let mut fb = Fed::new_with(true, b.ed_pub(), Vec::new(), &[], &[], &[], &[]);
        // Сводим пару тем же встречным рукопожатием (T4c).
        let hint_a = [ServerHint {
            addr: ba.to_string(),
            ed_pub: b.ed_pub(),
        }];
        let hint_b = [ServerHint {
            addr: aa.to_string(),
            ed_pub: a.ed_pub(),
        }];
        let ha = sends(fa.hint(&a, &[1; 32], &hint_a, NOW_UNIX, NOW_MS));
        let hb = sends(fb.hint(&b, &[2; 32], &hint_b, NOW_UNIX, NOW_MS));
        let (_, body_a) = proto::split_frame(&ha[0].1).unwrap();
        let (_, body_b) = proto::split_frame(&hb[0].1).unwrap();
        fa.on_hello(&a, ba, body_b, NOW_UNIX, NOW_MS).unwrap();
        let ack = sends(fb.on_hello(&b, aa, body_a, NOW_UNIX, NOW_MS).unwrap());
        fa.on_ack(ba, &ack_of(&ack[0].1), NOW_UNIX, NOW_MS).unwrap();
        assert!(fa.sessions[&b.ed_pub()].initiator);
        let keys_before = fa.sessions[&b.ed_pub()].keys.clone();

        // Запоздалый HELLO большего (новая попытка, новый эфемерный ключ):
        // initiator-сессию меньшего он перезаписать не должен.
        let late = hello_for(&b, NOW_UNIX);
        let acts = fa.on_hello(&a, ba, &late, NOW_UNIX, NOW_MS + 1).unwrap();
        assert!(
            acts.iter().all(|x| matches!(x, Action::Info(_))),
            "на запоздалый HELLO не шлём ACK: {acts:?}"
        );
        assert_eq!(fa.sessions.len(), 1);
        assert!(fa.sessions[&b.ed_pub()].initiator, "сессия перезаписана");
        assert_eq!(
            fa.sessions[&b.ed_pub()].keys,
            keys_before,
            "ключи сессии изменились"
        );
        assert!(fa.pending.is_empty());

        // Установленная сессия по-прежнему работает в обе стороны.
        let frame = seal(
            fa.sessions.get_mut(&b.ed_pub()).unwrap(),
            federation::FED_RELAY,
            b"still",
        );
        let (typ, body) = proto::split_frame(&frame).unwrap();
        let pt = open(fb.sessions.get_mut(&a.ed_pub()).unwrap(), typ, body);
        assert_eq!(pt.as_deref(), Some(&b"still"[..]));

        // ACK без ожидающей попытки — не ошибка и не меняет сессию.
        let keys_b = fb.sessions[&a.ed_pub()].keys.clone();
        let acts = fb
            .on_ack(aa, &hello_for(&a, NOW_UNIX), NOW_UNIX, NOW_MS + 2)
            .unwrap();
        assert!(
            !acts.iter().any(|x| matches!(x, Action::Reject(_))),
            "ACK без pending не должен быть отказом: {acts:?}"
        );
        assert!(!acts.iter().any(|x| matches!(x, Action::Send(..))));
        assert_eq!(fb.sessions.len(), 1);
        assert!(!fb.sessions[&a.ed_pub()].initiator);
        assert_eq!(fb.sessions[&a.ed_pub()].keys, keys_b);
    }

    #[test]
    fn hello_просрочка_и_подпись_отвергаются() {
        let a = Identity::generate();
        let b = Identity::generate();
        let mut fb = fed(true);
        // Свежий HELLO принимается (TOFU).
        let ok = fb.on_hello(&b, addr(12_001), &hello_for(&a, NOW_UNIX), NOW_UNIX, NOW_MS);
        assert!(rejects(ok.unwrap()).is_empty());
        assert_eq!(fb.pins.len(), 1);
        // Просроченный — отказ.
        let old = hello_for(&a, NOW_UNIX - federation::FED_TS_SKEW_MS - 1);
        let acts = fb
            .on_hello(&b, addr(12_002), &old, NOW_UNIX, NOW_MS)
            .unwrap();
        let rej = rejects(acts);
        assert_eq!(rej.len(), 1);
        assert!(rej[0].contains("просрочен"), "{rej:?}");
        // Битая подпись — отказ.
        let mut body = hello_for(&a, NOW_UNIX);
        let n = body.len();
        body[n - 1] ^= 1;
        let acts = fb
            .on_hello(&b, addr(12_003), &body, NOW_UNIX, NOW_MS)
            .unwrap();
        let rej = rejects(acts);
        assert_eq!(rej.len(), 1);
        assert!(rej[0].contains("подпись"), "{rej:?}");
        // Кадр не той длины — не разбирается вовсе (Err, молчаливый дроп).
        assert!(
            fb.on_hello(&b, addr(12_004), &body[..n - 1], NOW_UNIX, NOW_MS)
                .is_err()
        );
    }

    #[test]
    fn tofu_чужой_ключ_на_закреплённом_адресе() {
        let a = Identity::generate();
        let b = Identity::generate();
        let c = Identity::generate();
        let pin = Pin {
            addr: addr(13_002),
            ed: b.ed_pub(),
            x: b.x_pub(),
            added_at: 1,
        };
        let mut fb = Fed::new(true, vec![pin], &[], &[]);
        let acts = fb
            .on_hello(&a, addr(13_002), &hello_for(&c, NOW_UNIX), NOW_UNIX, NOW_MS)
            .unwrap();
        let rej = rejects(acts);
        assert_eq!(rej.len(), 1);
        assert!(rej[0].contains("другой ключ"), "{rej:?}");
        assert_eq!(fb.pins[&b.ed_pub()].ed, b.ed_pub(), "пин не перезаписан");
        assert!(fb.sessions.is_empty());
    }

    #[test]
    fn tofu_расхождение_x_отказ() {
        let a = Identity::generate();
        let b = Identity::generate();
        let (aa, ba) = (addr(14_001), addr(14_002));
        let pin = Pin {
            addr: ba,
            ed: b.ed_pub(),
            x: [9; 32],
            added_at: 1,
        };
        let mut fa = Fed::new(true, vec![pin], &[], &[]);
        let mut fb = fed(true);
        let hello = sends(fa.bootstrap(&a, NOW_UNIX, NOW_MS));
        let (_, body) = proto::split_frame(&hello[0].1).unwrap();
        let ack = sends(fb.on_hello(&b, aa, body, NOW_UNIX, NOW_MS).unwrap());
        let rej = rejects(fa.on_ack(ba, &ack_of(&ack[0].1), NOW_UNIX, NOW_MS).unwrap());
        assert_eq!(rej.len(), 1);
        assert!(rej[0].contains("x-ключ"), "{rej:?}");
        assert_eq!(fa.pins[&b.ed_pub()].x, [9; 32], "x не перезаписан");
        assert!(fa.sessions.is_empty());
    }

    #[test]
    fn hint_с_ложным_ключом_отвергается() {
        let a = Identity::generate();
        let b = Identity::generate();
        let (_, ba) = (addr(15_001), addr(15_002));
        let mut fa = fed(true);
        let mut fb = fed(true);
        let bogus = Identity::generate().ed_pub();
        let hints = [ServerHint {
            addr: ba.to_string(),
            ed_pub: bogus,
        }];
        let acts = fa.hint(&a, &[7; 32], &hints, NOW_UNIX, NOW_MS);
        let hello = sends(acts);
        assert_eq!(hello.len(), 1, "на подсказку уходит SRV_HELLO");
        let (_, body) = proto::split_frame(&hello[0].1).unwrap();
        let ack = sends(
            fb.on_hello(&b, addr(15_001), body, NOW_UNIX, NOW_MS)
                .unwrap(),
        );
        let acts = fa.on_ack(ba, &ack_of(&ack[0].1), NOW_UNIX, NOW_MS).unwrap();
        let rej = rejects(acts);
        assert_eq!(rej.len(), 1);
        assert!(rej[0].contains("не совпал с заявленным"), "{rej:?}");
        assert!(fa.pins.is_empty(), "ложный ключ не закрепляется");
        assert!(fa.sessions.is_empty(), "сессия не ставится");
        // Вторая подсказка с тем же (ложным) ed и другим адресом — тоже отказ.
        let other = [ServerHint {
            addr: addr(15_003).to_string(),
            ed_pub: bogus,
        }];
        let rej = rejects(fa.hint(&a, &[7; 32], &other, NOW_UNIX, NOW_MS));
        assert!(
            rej.is_empty(),
            "пока ключ не закреплён, другой адрес — не отказ"
        );
    }

    #[test]
    fn подсказка_с_плохим_адресом_отказ() {
        let a = Identity::generate();
        let mut fa = fed(true);
        let hints = [
            ServerHint {
                addr: "не адрес".into(),
                ed_pub: [1; 32],
            },
            ServerHint {
                addr: "0.0.0.0:5555".into(),
                ed_pub: [2; 32],
            },
        ];
        let rej = rejects(fa.hint(&a, &[0; 32], &hints, NOW_UNIX, NOW_MS));
        assert_eq!(rej.len(), 2, "{rej:?}");
        assert!(rej[0].contains("не разбирается"));
        assert!(rej[1].contains("не годится"));
        assert!(fa.pending.is_empty());
    }

    #[test]
    fn закреплённый_пин_на_другом_адресе_отказ() {
        let a = Identity::generate();
        let other = Identity::generate();
        let pin = Pin {
            addr: addr(16_002),
            ed: other.ed_pub(),
            x: other.x_pub(),
            added_at: 1,
        };
        let mut fa = Fed::new(true, vec![pin], &[], &[]);
        let hints = [ServerHint {
            addr: addr(16_009).to_string(),
            ed_pub: other.ed_pub(),
        }];
        let rej = rejects(fa.hint(&a, &[0; 32], &hints, NOW_UNIX, NOW_MS));
        assert_eq!(rej.len(), 1);
        assert!(rej[0].contains("закреплён за адресом"), "{rej:?}");
        assert!(fa.pending.is_empty());
    }

    #[test]
    fn переотправка_и_таймаут_рукопожатия() {
        let a = Identity::generate();
        let ba = addr(17_002);
        let mut fa = Fed::new(true, Vec::new(), &[ba], &[]);
        assert_eq!(sends(fa.bootstrap(&a, NOW_UNIX, 0)).len(), 1);
        // До HELLO_RESEND — тишина.
        assert!(fa.tick(HELLO_RESEND_MS - 1).is_empty());
        // Пора — тот же кадр (тот же eph/nonce) уходит снова.
        let resent = sends(fa.tick(HELLO_RESEND_MS));
        assert_eq!(resent.len(), 1);
        assert_eq!(resent[0].0, ba);
        // Таймаут: попытка снимается, в лог — событие.
        let acts = fa.tick(HELLO_RESEND_MS + FED_TIMEOUT_MS);
        assert!(fa.pending.is_empty(), "{acts:?}");
        assert!(sends(acts).is_empty());
    }

    #[test]
    fn сессия_истекает_и_касание_продлевает() {
        let a = Identity::generate();
        let b = Identity::generate();
        let aa = addr(18_001);
        let mut fb = fed(true);
        fb.on_hello(&b, aa, &hello_for(&a, NOW_UNIX), NOW_UNIX, NOW_MS)
            .unwrap();
        assert_eq!(fb.sessions.len(), 1);
        // Кадр от пира (репликация/релей) обновляет last_rx_ms; пока
        // проверяем таймаут.
        assert!(fb.tick(NOW_MS + FED_TIMEOUT_MS - 1).is_empty());
        assert_eq!(fb.sessions.len(), 1);
        let acts = fb.tick(NOW_MS + FED_TIMEOUT_MS);
        assert!(fb.sessions.is_empty(), "{acts:?}");
        assert!(fb.sess_addrs.is_empty());
    }

    #[test]
    fn выключенная_федерация_не_отвечает() {
        let a = Identity::generate();
        let b = Identity::generate();
        let mut fb = fed(false);
        let acts = fb
            .on_hello(&b, addr(19_001), &hello_for(&a, NOW_UNIX), NOW_UNIX, NOW_MS)
            .unwrap();
        assert!(acts.is_empty(), "выключено — молчим");
        assert!(fb.pins.is_empty());
        assert!(fb.sessions.is_empty());
        assert!(sends(fb.bootstrap(&a, NOW_UNIX, NOW_MS)).is_empty());
    }

    #[test]
    fn закреплённый_пир_переживает_сериализацию() {
        let a = Identity::generate();
        let b = Identity::generate();
        let pin = Pin {
            addr: addr(20_002),
            ed: b.ed_pub(),
            x: b.x_pub(),
            added_at: 42,
        };
        let peers = [persist::PPeer {
            addr: pin.addr.to_string(),
            ed: crate::hex(&pin.ed),
            x: crate::hex(&pin.x),
            added_at: pin.added_at,
        }];
        let back = load_pins(&peers);
        assert_eq!(back, vec![pin]);
        // Битая запись пропускается, целая — остаётся.
        let mixed = [
            persist::PPeer {
                addr: "мусор".into(),
                ed: crate::hex(&a.ed_pub()),
                x: crate::hex(&a.x_pub()),
                added_at: 1,
            },
            peers[0].clone(),
        ];
        let back = load_pins(&mixed);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].ed, b.ed_pub());
    }

    // ---------- с реальными серверами ----------

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("voidlink-fed-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn start(dir: &Path, federate: bool) -> crate::Server {
        crate::Server::start(Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: dir.to_path_buf(),
            workers: 1,
            quiet: true,
            federate,
            ..Config::default()
        })
        .unwrap()
    }

    fn wait_until(what: &str, timeout: Duration, mut f: impl FnMut() -> bool) {
        let end = Instant::now() + timeout;
        while Instant::now() < end {
            if f() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("не дождались: {what}");
    }

    #[test]
    fn hint_рукопожатие_пин_и_рестарт() {
        let da = temp_dir("hint-a");
        let db = temp_dir("hint-b");
        let a = start(&da, true);
        let b = start(&db, true);
        let hint = ServerHint {
            addr: b.addr.to_string(),
            ed_pub: b.pubkey,
        };
        crate::federation::on_hint(&a.shared, &[7; 32], &[hint]);
        // a закрепил b (ключ ответа сошёлся с заявленным).
        wait_until("пин b на a", Duration::from_secs(5), || {
            a.shared.fed.lock().unwrap().pins.contains_key(&b.pubkey)
        });
        // b закрепил a на входящем SRV_HELLO (TOFU).
        wait_until("пин a на b", Duration::from_secs(5), || {
            b.shared.fed.lock().unwrap().pins.contains_key(&a.pubkey)
        });
        let pin = a.shared.fed.lock().unwrap().pins[&b.pubkey].clone();
        assert_eq!(pin.addr, b.addr);
        assert_eq!(pin.x, b.shared.identity.x_pub());
        assert!(pin.added_at > 0);
        // Датчик voidlink_fed_peers — из авторитетной таблицы.
        crate::refresh_gauges(&a.shared);
        let text = a.shared.metrics.render();
        assert!(
            text.contains("voidlink_fed_peers 1"),
            "нет датчика пиров:\n{text}"
        );
        // Пин переживает рестарт: он в server.json.
        a.stop();
        let raw = std::fs::read_to_string(da.join("server.json")).unwrap();
        assert!(raw.contains("\"federation\""), "{raw}");
        let a2 = start(&da, true);
        let pins = a2.shared.fed.lock().unwrap().pins.clone();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[&b.pubkey], pin);
    }

    #[test]
    fn hint_с_ложным_ключом_метрика_и_отказ() {
        let da = temp_dir("wrong-a");
        let db = temp_dir("wrong-b");
        let a = start(&da, true);
        let b = start(&db, true);
        let bogus = Identity::generate().ed_pub();
        let before = a.shared.metrics.fed_hint_rejected.load(Ordering::Relaxed);
        crate::federation::on_hint(
            &a.shared,
            &[7; 32],
            &[ServerHint {
                addr: b.addr.to_string(),
                ed_pub: bogus,
            }],
        );
        wait_until(
            "метрика отказа федерации",
            Duration::from_secs(5),
            || a.shared.metrics.fed_hint_rejected.load(Ordering::Relaxed) > before,
        );
        assert!(
            a.shared.fed.lock().unwrap().pins.is_empty(),
            "ложный ключ не закреплён"
        );
        assert!(
            !a.shared
                .fed
                .lock()
                .unwrap()
                .sessions
                .contains_key(&b.pubkey)
        );
    }

    #[test]
    fn без_флага_сервер_молчит() {
        let da = temp_dir("off-a");
        let db = temp_dir("off-b");
        let a = start(&da, false);
        let b = start(&db, true);
        crate::federation::on_hint(
            &b.shared,
            &[7; 32],
            &[ServerHint {
                addr: a.addr.to_string(),
                ed_pub: a.pubkey,
            }],
        );
        // a выключен: HELLO не разбирается, ACK не приходит, пина нет.
        std::thread::sleep(Duration::from_millis(400));
        assert!(b.shared.fed.lock().unwrap().pins.is_empty());
        assert!(a.shared.fed.lock().unwrap().pins.is_empty());
    }

    // ---------- репликация групп/адресов и релей (T4b1) ----------

    /// Пара серверов с установленной федеративной сессией (a — инициатор).
    fn pair() -> (Identity, Identity, Fed, Fed) {
        let a = Identity::generate();
        let b = Identity::generate();
        let (aa, ba) = (addr(30_001), addr(30_002));
        let mut fa = Fed::new_with(true, a.ed_pub(), Vec::new(), &[ba], &[], &[], &[]);
        let mut fb = Fed::new_with(true, b.ed_pub(), Vec::new(), &[aa], &[], &[], &[]);
        let hello = sends(fa.bootstrap(&a, NOW_UNIX, NOW_MS));
        let (_, body) = proto::split_frame(&hello[0].1).unwrap();
        let ack = sends(fb.on_hello(&b, aa, body, NOW_UNIX, NOW_MS).unwrap());
        let acts = fa.on_ack(ba, &ack_of(&ack[0].1), NOW_UNIX, NOW_MS).unwrap();
        assert!(rejects(acts).is_empty());
        assert!(fa.sessions.contains_key(&b.ed_pub()));
        assert!(fb.sessions.contains_key(&a.ed_pub()));
        (a, b, fa, fb)
    }

    /// Расшифровать исходящий кадр принимающей стороной: (тип, тело).
    fn open_from(fed: &mut Fed, peer: &[u8; 32], frame: &[u8]) -> (u8, Vec<u8>) {
        let (typ, body) = proto::split_frame(frame).unwrap();
        let sess = fed.sessions.get_mut(peer).expect("нет сессии пира");
        let pt = open(sess, typ, body).expect("кадр не расшифровался");
        (typ, pt)
    }

    /// Снимок группы владельца для публикации.
    fn snap_of(uuid: [u8; 16], owner: [u8; 32], rev: u32) -> GroupSnap {
        GroupSnap {
            uuid,
            gid: 3,
            name: "фед".into(),
            owner,
            private: false,
            key: [rev as u8; 32],
            epoch: rev,
            rev,
            members: vec![(owner, 0x6442_0101)],
        }
    }

    #[test]
    fn репликация_группы_push_и_delta() {
        let (a, b, mut fa, mut fb) = pair();
        let uuid = [7u8; 16];
        let owner = [9u8; 32];
        let snap = snap_of(uuid, owner, 1);
        // Первая публикация — полная запись, одному пиру — один кадр.
        let mut out = Vec::new();
        fa.publish(&snap, &mut out);
        assert_eq!(out.len(), 1);
        let (typ, body) = open_from(&mut fb, &a.ed_pub(), &out[0].1);
        assert_eq!(typ, federation::FED_GROUP_PUSH);
        // Тело кадра — ровно запись группы.
        let decoded = proto::federation::FedGroup::decode(&body).unwrap();
        assert_eq!((decoded.uuid, decoded.owner), (uuid, owner));
        let acts = fb.on_group_push(a.ed_pub(), &body).unwrap();
        match acts.as_slice() {
            [Action::ReplGroup { rec, from }] => {
                assert_eq!(rec.uuid, uuid);
                assert_eq!(rec.owner, owner);
                assert_eq!(rec.gid, 3, "gid владельца информативен");
                assert_eq!(*from, a.ed_pub());
                assert_eq!(rec.members.len(), 1);
            }
            other => panic!("{other:?}"),
        }
        // Запись от незакреплённого сервера — не принимается.
        assert!(fb.on_group_push([0xAB; 32], &body).is_err());

        // Вход участника: MemberAdd + Meta (ротация ключа) — дельта.
        let newcomer = [8u8; 32];
        let mut snap2 = snap.clone();
        snap2.rev = 2;
        snap2.epoch = 2;
        snap2.key = [0x22; 32];
        snap2.members.push((newcomer, 0x6442_0102));
        let mut out = Vec::new();
        fa.publish(&snap2, &mut out);
        assert_eq!(out.len(), 1);
        let (typ, body) = open_from(&mut fb, &a.ed_pub(), &out[0].1);
        assert_eq!(typ, federation::FED_GROUP_DELTA);
        let d = proto::federation::FedGroupDelta::decode(&body).unwrap();
        assert_eq!((d.rev, d.base_rev), (2, 1));
        assert!(
            d.changes
                .iter()
                .any(|c| matches!(c, FedChange::MemberAdd { pk, .. } if *pk == newcomer)),
            "нет MemberAdd: {:?}",
            d.changes
        );
        assert!(
            d.changes
                .iter()
                .any(|c| matches!(c, FedChange::Meta { epoch: 2, .. })),
            "нет ротации ключа: {:?}",
            d.changes
        );
        let acts = fb.on_group_delta(a.ed_pub(), &body).unwrap();
        match acts.as_slice() {
            [Action::ReplDelta { delta, from }] => {
                assert_eq!(delta.rev, 2);
                assert_eq!(*from, a.ed_pub());
            }
            other => panic!("{other:?}"),
        }
        // Повторная публикация того же состояния — тишина.
        let mut out = Vec::new();
        fa.publish(&snap2, &mut out);
        assert!(out.is_empty());

        // Дельта по неизвестной группе — заявка на вход для локального слоя
        // (группа не наша — он её отбросит).
        let unknown = proto::federation::FedGroupDelta {
            uuid: [0x55; 16],
            owner,
            rev: 1,
            base_rev: 0,
            changes: vec![FedChange::MemberAdd {
                pk: [1; 32],
                ip: 0x6442_0103,
            }],
        };
        let acts = fb.on_group_delta(a.ed_pub(), &unknown.encode()).unwrap();
        assert!(
            matches!(acts.as_slice(), [Action::JoinRequest { uuid: u, .. }] if *u == [0x55; 16]),
            "{acts:?}"
        );

        // Дельта по нашей группе — заявка на вход, её решает владелец.
        let join = proto::federation::FedGroupDelta {
            uuid,
            owner,
            rev: 9,
            base_rev: 8,
            changes: vec![FedChange::MemberAdd {
                pk: [3; 32],
                ip: 0x6442_0104,
            }],
        };
        let acts = fa.on_group_delta(b.ed_pub(), &join.encode()).unwrap();
        assert!(
            matches!(acts.as_slice(), [Action::JoinRequest { uuid: u, .. }] if *u == uuid),
            "{acts:?}"
        );

        // Удаление владельцем — полная запись с флагом deleted.
        let mut out = Vec::new();
        fa.publish_deleted(&snap2, &mut out);
        let (typ, body) = open_from(&mut fb, &a.ed_pub(), &out[0].1);
        assert_eq!(typ, federation::FED_GROUP_PUSH);
        let rec = proto::federation::FedGroup::decode(&body).unwrap();
        assert!(rec.deleted && rec.members.is_empty());
        let acts = fb.on_group_push(a.ed_pub(), &body).unwrap();
        assert!(matches!(acts.as_slice(), [Action::ReplDelete(u)] if *u == uuid));
    }

    #[test]
    fn конфликт_адресов_решает_меньший_id() {
        let (a, b, fa, fb) = pair();
        // Наша identity владеет адресом ip1; пир заявляет ей другой адрес.
        let local_pk = [9u8; 32];
        let ip1 = 0x6442_0101;
        let ip2 = 0x6442_0202;
        let local = [(local_pk, ip1)];
        // a.id < b.id: если a меньше, a побеждает; иначе побеждает b.
        let (mut small, mut big, small_id, big_id, _small_is_a) = if a.ed_pub() < b.ed_pub() {
            (fa, fb, a.ed_pub(), b.ed_pub(), true)
        } else {
            (fb, fa, b.ed_pub(), a.ed_pub(), false)
        };
        // Заявку шлёт «больший» (пир), получает «меньший».
        let claim = FedAddrClaim {
            pk: local_pk,
            ip: ip2,
            server: big_id,
            ts_ms: NOW_UNIX,
        };
        let mut out = Vec::new();
        let acts = small
            .on_addr(
                big_id,
                federation::FED_ADDR_PUSH,
                &claim.encode(),
                &local,
                NOW_UNIX,
                &mut out,
            )
            .unwrap();
        // Меньший id не отдаёт свой адрес: потерь нет, пиру уходит наша заявка.
        assert!(
            !acts.iter().any(|x| matches!(x, Action::AddrLost { .. })),
            "{acts:?}"
        );
        assert!(!out.is_empty(), "своя заявка должна уйти пиру");
        let (typ, body) = open_from(&mut big, &small_id, &out[0].1);
        assert_eq!(typ, federation::FED_ADDR_PUSH);
        let ours = FedAddrClaim::decode(&body).unwrap();
        assert_eq!((ours.pk, ours.ip), (local_pk, ip1));
        assert_eq!(ours.server, small_id);
        assert!(small.claims.is_empty(), "чужой адрес не принят");

        // Обратный случай: заявку шлёт меньший, получает больший — локальная
        // identity теряет адрес и перевыдаёт его.
        let claim = FedAddrClaim {
            pk: local_pk,
            ip: ip2,
            server: small_id,
            ts_ms: NOW_UNIX,
        };
        let mut out = Vec::new();
        let acts = big
            .on_addr(
                small_id,
                federation::FED_ADDR_PUSH,
                &claim.encode(),
                &local,
                NOW_UNIX,
                &mut out,
            )
            .unwrap();
        match acts.as_slice() {
            [
                Action::AddrLost { pk, ip },
                Action::AddrReserve { on: true, .. },
            ] => {
                assert_eq!((*pk, *ip), (local_pk, ip1));
            }
            other => panic!("{other:?}"),
        }
        // Адрес меньшего записан, наш — освобождён.
        let cur = big.claims.get(&local_pk).copied().unwrap();
        assert_eq!((cur.ip, cur.server), (ip2, small_id));

        // Адрес занят другой локальной identity: побеждает меньший server id.
        let other_pk = [10u8; 32];
        let claim = FedAddrClaim {
            pk: other_pk,
            ip: ip1,
            server: big_id,
            ts_ms: NOW_UNIX,
        };
        let mut out = Vec::new();
        let acts = small
            .on_addr(
                big_id,
                federation::FED_ADDR_PUSH,
                &claim.encode(),
                &local,
                NOW_UNIX,
                &mut out,
            )
            .unwrap();
        assert!(
            !acts.iter().any(|x| matches!(x, Action::AddrLost { .. })),
            "меньший id не отдаёт адрес своего участника: {acts:?}"
        );
    }

    #[test]
    fn заявка_адреса_принимается_и_резервируется() {
        let (_a, b, mut fa, _fb) = pair();
        let remote_pk = [10u8; 32];
        let ip = 0x6442_0303;
        let c = FedAddrClaim {
            pk: remote_pk,
            ip,
            server: b.ed_pub(),
            ts_ms: NOW_UNIX,
        };
        // Адрес за другой identity, локальных конфликтов нет.
        let mut out = Vec::new();
        let acts = fa
            .on_addr(
                b.ed_pub(),
                federation::FED_ADDR_PUSH,
                &c.encode(),
                &[],
                NOW_UNIX,
                &mut out,
            )
            .unwrap();
        assert!(
            acts.iter()
                .any(|x| matches!(x, Action::AddrReserve { pk, ip: i, on: true } if *pk == remote_pk && *i == ip)),
            "{acts:?}"
        );
        assert_eq!(fa.claims[&remote_pk].ip, ip);
        // Заявка от имени чужого сервера не принимается.
        let mut bogus = c;
        bogus.server = [0xEE; 32];
        assert!(
            fa.on_addr(
                b.ed_pub(),
                federation::FED_ADDR_PUSH,
                &bogus.encode(),
                &[],
                NOW_UNIX,
                &mut out
            )
            .is_err()
        );
        // Отзыв снимает заявку и резерв.
        let acts = fa
            .on_addr(
                b.ed_pub(),
                federation::FED_ADDR_REVOKE,
                &c.encode(),
                &[],
                NOW_UNIX,
                &mut out,
            )
            .unwrap();
        assert!(
            acts.iter()
                .any(|x| matches!(x, Action::AddrReserve { on: false, .. })),
            "{acts:?}"
        );
        assert!(fa.claims.is_empty());
    }

    #[test]
    fn релей_заворачивается_и_проверяется() {
        let (a, b, mut fa, mut fb) = pair();
        let uuid = [0x42; 16];
        let sender = [1u8; 32];
        let dst = [2u8; 32];
        let frame = proto::plain_frame(proto::grp::DATA, &[0u8; 64]);
        // Получатель не заявлен — релей некуда.
        let mut out = Vec::new();
        assert!(!fa.wrap_relay(&uuid, &sender, &dst, &frame, &mut out));
        // Пир заявляет адрес получателя — кадр уходит ему.
        let claim = FedAddrClaim {
            pk: dst,
            ip: 0x6442_0404,
            server: b.ed_pub(),
            ts_ms: NOW_UNIX,
        };
        let acts = fa
            .on_addr(
                b.ed_pub(),
                federation::FED_ADDR_PUSH,
                &claim.encode(),
                &[],
                NOW_UNIX,
                &mut out,
            )
            .unwrap();
        assert!(
            acts.iter()
                .any(|x| matches!(x, Action::AddrReserve { on: true, .. })),
            "{acts:?}"
        );
        let mut out = Vec::new();
        assert!(fa.wrap_relay(&uuid, &sender, &dst, &frame, &mut out));
        assert_eq!(out.len(), 1);
        let (typ, body) = open_from(&mut fb, &a.ed_pub(), &out[0].1);
        assert_eq!(typ, federation::FED_RELAY);
        let rel = FedRelay::decode(&body).unwrap();
        assert_eq!((rel.uuid, rel.sender, rel.dst), (uuid, sender, dst));
        assert_eq!(rel.frame, frame);

        // Кадр больше предела релея не заворачивается (не паникует).
        let huge = vec![0u8; federation::FED_RELAY_MAX_FRAME + 1];
        let mut out = Vec::new();
        assert!(!fa.wrap_relay(&uuid, &sender, &dst, &huge, &mut out));

        // Входящий релей от закреплённого пира — действие для локального слоя.
        let acts = fb.on_relay(a.ed_pub(), &body).unwrap();
        assert!(
            matches!(acts.as_slice(), [Action::Relay { rel, .. }] if rel.dst == dst),
            "{acts:?}"
        );
        // От незакреплённого сервера — отказ.
        assert!(fb.on_relay([0xCD; 32], &body).is_err());
        // Ответ на релей: NACK попадает в лог, ошибок разбора нет.
        let no = FedRelayReply {
            uuid,
            dst,
            ok: false,
            reason: proto::federation::nack::NO_SESSION,
        };
        let acts = fb
            .on_reply(a.ed_pub(), federation::FED_RELAY_NACK, &no.encode())
            .unwrap();
        assert!(matches!(acts.as_slice(), [Action::Info(_)]), "{acts:?}");
    }
}
