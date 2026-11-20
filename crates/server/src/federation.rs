//! Федерация серверов (сервер ↔ сервер), §3.5 плана этапа 9.
//!
//! T4a — ядро: рукопожатие `SRV_HELLO`/`SRV_HELLO_ACK`, федеративная сессия
//! (AEAD того же формата, что ctrl), TOFU-пиннинг ключей в `server.json`,
//! недоверенные подсказки `SERVER_HINT`. Репликация групп/адресов,
//! `FED_RELAY` и клиентская часть — T4b (кадры `0x42..=0x4F` зафиксированы в
//! [`tunnel_protocol::federation`], здесь они пока молча роняются).
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
//! * Таймаут рукопожатия и простоя сессии — 30 с; `SRV_HELLO` переотправляется
//!   раз в `HELLO_RESEND`, пока не пришёл `ACK`.
//! * Все действия собираются под блокировкой таблицы ([`Action`]) и
//!   применяются после неё: отправка, метрики, лог, сохранение на диск.
//!
//! Необработанный кадр — молча отбросить: сервер не должен отвечать `RESET`
//! чужому серверу. Кодеки живут в `tunnel_protocol::federation`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use proto::federation::{self, FedKeys, SrvHello};
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

/// Таблица федерации: пиры, попытки рукопожатия, сессии.
pub(crate) struct Fed {
    /// Федерация включается флагом `--federate`: без него кадры 0x40..=0x4F
    /// не разбираются вовсе (старый сервер их молча роняет).
    enabled: bool,
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
    /// Задел T4b: пул адресов федерации (`--fed-pool`), без репликации.
    #[allow(dead_code)]
    pool: Vec<SocketAddr>,
}

impl Fed {
    pub(crate) fn new(
        enabled: bool,
        pins: Vec<Pin>,
        peers: &[SocketAddr],
        pool: &[SocketAddr],
    ) -> Self {
        let mut f = Self {
            enabled,
            pins: BTreeMap::new(),
            addrs: HashMap::new(),
            targets: peers.iter().map(|a| Target { addr: *a }).collect(),
            sessions: HashMap::new(),
            sess_addrs: HashMap::new(),
            pending: HashMap::new(),
            pool: pool.to_vec(),
        };
        for p in pins.into_iter().take(MAX_PEERS) {
            f.insert_pin(p);
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
        let my_eph = EphemeralKey::generate();
        let shared = match hello.dh(&my_eph) {
            Ok(k) => k,
            Err(e) => return Ok(vec![Action::Reject(format!("SRV_HELLO с {src}: {e}"))]),
        };
        let mut out = Vec::new();
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
        // Ответ ждём только оттуда, куда уходил HELLO.
        {
            let Some(p) = self.pending.get(&src) else {
                return Err(anyhow::anyhow!("SRV_HELLO_ACK без нашей попытки"));
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
            return Err(anyhow::anyhow!("SRV_HELLO_ACK без нашей попытки"));
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
        Ok(out)
    }

    fn install(&mut self, s: Session) {
        if let Some(old) = self.sessions.get(&s.peer)
            && old.addr != s.addr
        {
            self.sess_addrs.remove(&old.addr);
        }
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
        // Сессия без кадров дольше таймаута закрывается. T4b добавит
        // keepalive/кадры репликации, которые её продлевают.
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
        out
    }
}

/// Применить собранные действия: отправка, метрики, лог, сохранение.
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
        }
    }
}

/// Входящий федеративный кадр (0x40..=0x4F). `true` — обработан.
pub(crate) fn on_frame(sh: &Shared, src: SocketAddr, typ: u8, body: &[u8]) -> bool {
    if typ != federation::SRV_HELLO && typ != federation::SRV_HELLO_ACK {
        // 0x42..=0x4F — кадры сессии (T4b); сейчас молча роняются.
        return false;
    }
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

/// `JOIN_FED` от клиента: вход в федерированную группу по uuid. T4b вернёт
/// обычный `GROUP_STATE`; пока — честная ошибка (клиент его пока не шлёт).
pub(crate) fn on_join_fed(_sh: &Shared, _from: &[u8; 32], _uuid: &[u8]) -> anyhow::Result<()> {
    anyhow::bail!("вход в федерированную группу ещё не реализован (T4b)")
}

/// Старт федерации: рукопожатие с закреплёнными пирами и `--peer`.
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
}

/// Пиры для `server.json → federation.peers`.
pub(crate) fn persisted(sh: &Shared) -> persist::PFederation {
    persist::PFederation {
        peers: sh
            .fed
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
            .collect(),
    }
}

/// Закреплённые пиров столько (датчик `voidlink_fed_peers`).
pub(crate) fn pin_count(sh: &Shared) -> usize {
    sh.fed.lock().unwrap().pins.len()
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
/// 0⁴ || counter, AAD — заголовок TNL2). T4b шлёт так 0x42..=0x4F.
#[allow(dead_code)] // T4b: кадры репликации/релея
fn seal(s: &mut Session, typ: u8, payload: &[u8]) -> Vec<u8> {
    assert!(federation::is_fed(typ), "не федеративный кадр");
    proto::seal_ctrl(&s.keys.tx(s.initiator), s.tx.next(), typ, payload)
}

/// Разбор AEAD-кадра сессии: предпроверка окна, расшифровка, `commit` окна
/// только после успеха (подделка с огромным счётчиком окно не сдвигает).
#[allow(dead_code)] // T4b: кадры репликации/релея
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
        // Кадр от пира (T4b) обновит last_rx_ms; пока проверяем таймаут.
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
}
