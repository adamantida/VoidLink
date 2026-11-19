//! Состояние TUI: фокус, списки, попапы, тосты, лог, обработка клавиш.

use std::cell::{Cell, RefCell};
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Result, anyhow};
use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::{Position, Rect};
use tunnel_protocol as proto;

use crate::api::{EngineApi, EngineMode};
use crate::engine::{Cmd, Event};
use crate::snapshot::Snapshot;
use crate::store::{self, Config, StoredFriend, StoredServer};
use crate::tui::admin::{self, AdminAction, AdminView, BanEntry, InviteEntry, MemberEntry};
use crate::tui::badges::Transport;
use crate::tui::servers::{ServerEntry, ServersAction, ServersView};
use crate::tui::theme::ThemeKind;
use crate::tui::{clipboard, keymap};

pub const TOAST_TTL: Duration = Duration::from_secs(5);
/// Окно приглашения первые мгновения не принимает «Принять»/«Отклонить»:
/// оно появляется само, и Enter или клик, адресованные основному экрану,
/// не должны случайно ответить за пользователя. Esc («Позже») — сразу.
pub const INVITE_GUARD: Duration = Duration::from_millis(400);
/// Сверка со списком сервера не снимает приглашение, пришедшее только что:
/// список мог быть собран раньше него (другой поток сервера, перестановка
/// UDP) — свежее приглашение было бы снято как «недействительное».
pub const INVITE_SYNC_GRACE: Duration = Duration::from_secs(2);
/// Отклонённое приглашение какое-то время не показывается снова: список,
/// собранный сервером до нашего DECLINE (ответ на прошлый отказ, медленная
/// связь или перестановка UDP), принёс бы его обратно свежим окном — а
/// сверка из-за [`INVITE_SYNC_GRACE`] его бы не сняла.
pub const INVITE_DECLINE_MEMORY: Duration = Duration::from_secs(5);
pub const LOG_MAX: usize = 400;

// ---------------------------------------------------------------- фокус

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Focus {
    Groups,
    Friends,
    Peers,
    Log,
}

impl Focus {
    pub fn next(self) -> Self {
        match self {
            Focus::Groups => Focus::Friends,
            Focus::Friends => Focus::Peers,
            Focus::Peers => Focus::Log,
            Focus::Log => Focus::Groups,
        }
    }
    pub fn prev(self) -> Self {
        match self {
            Focus::Groups => Focus::Log,
            Focus::Friends => Focus::Groups,
            Focus::Peers => Focus::Friends,
            Focus::Log => Focus::Peers,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Focus::Groups => "группы",
            Focus::Friends => "друзья",
            Focus::Peers => "участники",
            Focus::Log => "лог",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sort {
    Name,
    Online,
    Rtt,
}

impl Sort {
    pub fn next(self) -> Self {
        match self {
            Sort::Name => Sort::Online,
            Sort::Online => Sort::Rtt,
            Sort::Rtt => Sort::Name,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Sort::Name => "имя",
            Sort::Online => "онлайн",
            Sort::Rtt => "RTT",
        }
    }
}

// ---------------------------------------------------------------- модели

#[derive(Clone)]
pub struct PeerView {
    pub pubkey: [u8; 32],
    pub name: String,
    pub ip: u32,
    pub online: bool,
    pub direct: bool,
    pub rtt_ms: Option<u64>,
    pub status: String,
}

#[derive(Clone)]
pub struct GroupView {
    pub gid: u32,
    pub name: String,
    pub private: bool,
    pub mine: bool,
    pub online: u32,
    pub total: u32,
    pub my_ip: Option<u32>,
    pub owner_is_me: bool,
    pub peers: Vec<PeerView>,
}

#[derive(Clone)]
pub struct FriendView {
    pub alias: String,
    pub pubkey: [u8; 32],
    pub online: bool,
    pub shared_groups: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MsgKind {
    Info,
    Ok,
    Warn,
    Error,
}

pub struct Toast {
    pub text: String,
    pub kind: MsgKind,
    pub at: Instant,
}

pub struct LogLine {
    pub text: String,
    pub kind: MsgKind,
    /// Настенное время записи — для локальной метки в логе.
    pub wall: SystemTime,
}

// ---------------------------------------------------------------- попапы

pub enum InputAction {
    CreateGroup,
    RenameGroup(u32),
    AddFriend,
    SetName,
    SetStatus,
    InviteCode(u32),
    /// Новый алиас друга (pubkey).
    FriendAlias([u8; 32]),
    /// Командная строка «:».
    Command,
}

pub struct InputPopup {
    pub title: String,
    pub hint: String,
    pub value: String,
    pub action: InputAction,
    /// Для создания группы: флаг «приватная».
    pub private: bool,
}

pub enum ConfirmAction {
    DeleteGroup(u32),
    LeaveGroup(u32),
    DeleteFriend(String),
}

pub struct ConfirmPopup {
    pub title: String,
    pub message: String,
    pub action: ConfirmAction,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PickMode {
    Invite,
    Kick,
    Ban,
}

#[derive(Clone)]
pub struct PeerChoice {
    pub pubkey: [u8; 32],
    pub label: String,
    pub sub: String,
    pub online: bool,
}

pub struct PeerPickPopup {
    pub gid: u32,
    pub title: String,
    pub mode: PickMode,
    pub items: Vec<PeerChoice>,
    pub sel: usize,
}

pub struct FriendCardPopup {
    pub alias: String,
    pub pubkey: [u8; 32],
    pub groups: Vec<proto::payloads::FriendGroup>,
    pub loading: bool,
}

pub struct ListItem {
    pub label: String,
    pub checked: bool,
    pub value: String,
}

pub enum ListAction {
    ToggleAutojoin,
}

pub struct ListPickPopup {
    pub title: String,
    pub items: Vec<ListItem>,
    pub sel: usize,
    pub action: ListAction,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SettingRow {
    Name,
    Status,
    Server,
    Autojoin,
    Theme,
    Invisible,
}

pub const SETTING_ROWS: [SettingRow; 6] = [
    SettingRow::Name,
    SettingRow::Status,
    SettingRow::Server,
    SettingRow::Autojoin,
    SettingRow::Theme,
    SettingRow::Invisible,
];

pub struct SettingsPopup {
    pub sel: usize,
}

/// Входящее приглашение в группу (окно «Принять / Отклонить / Позже»).
#[derive(Clone, Debug)]
pub struct InvitePopup {
    pub gid: u32,
    pub group_name: String,
    pub from_name: String,
    pub from_pubkey: [u8; 32],
    pub received_at: Instant,
    /// Когда приглашение истекает на сервере (None — неизвестно).
    pub expires_at: Option<Instant>,
    /// Когда окно показано (None — ещё в очереди); см. [`INVITE_GUARD`].
    pub shown_at: Option<Instant>,
}

/// Ответ на приглашение.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InviteAnswer {
    Accept,
    Decline,
    /// Закрыть без ответа: приглашение остаётся на сервере, вернуться — «o».
    Later,
}

pub enum Popup {
    Help,
    Input(InputPopup),
    Confirm(ConfirmPopup),
    PeerPick(PeerPickPopup),
    FriendCard(FriendCardPopup),
    ListPick(ListPickPopup),
    Settings(SettingsPopup),
    Profile,
    Invite(InvitePopup),
    /// Управление своей группой: баны, приглашения, передача владения.
    Admin(AdminView),
    /// Экран «Серверы»: переключение, добавление/удаление, адаптер.
    Servers(ServersView),
}

// ---------------------------------------------------------------- мышь

/// Кнопки панели действий под шапкой: подпись и клавиша, которую «нажимает»
/// клик (дальше работает та же логика, что и с клавиатуры).
pub const TOOLBAR: [(&str, KeyCode, KeyModifiers); 11] = [
    ("F1 справка", KeyCode::F(1), KeyModifiers::NONE),
    ("F2 создать", KeyCode::F(2), KeyModifiers::NONE),
    ("j войти", KeyCode::Char('j'), KeyModifiers::NONE),
    ("x выйти", KeyCode::Char('x'), KeyModifiers::NONE),
    ("i пригласить", KeyCode::Char('i'), KeyModifiers::NONE),
    ("k исключить", KeyCode::Char('k'), KeyModifiers::NONE),
    ("a друг", KeyCode::Char('a'), KeyModifiers::NONE),
    ("p профиль", KeyCode::Char('p'), KeyModifiers::NONE),
    ("F3 настройки", KeyCode::F(3), KeyModifiers::NONE),
    (": команда", KeyCode::Char(':'), KeyModifiers::NONE),
    ("^C выход", KeyCode::Char('c'), KeyModifiers::CONTROL),
];

/// Где что нарисовано в последнем кадре — чтобы понять, куда попал клик.
/// Заполняется в `ui::draw` (там `&App`, поэтому `Cell`/`RefCell`).
#[derive(Default)]
pub struct Hits {
    /// Кнопки панели действий.
    pub toolbar: RefCell<Vec<(Rect, KeyEvent)>>,
    /// Рамка панели и смещение прокрутки её списка.
    pub groups: Cell<(Rect, usize)>,
    pub friends: Cell<(Rect, usize)>,
    pub peers: Cell<(Rect, usize)>,
    pub log: Cell<Rect>,
    /// Вкладки фокуса в статус-баре: клик = перейти в панель.
    pub tabs: RefCell<Vec<(Rect, Focus)>>,
    /// Верхний попап: рамка, смещение списка, кнопки.
    pub popup: Cell<Rect>,
    pub popup_off: Cell<usize>,
    pub popup_buttons: RefCell<Vec<(Rect, KeyEvent)>>,
    /// Тосты — поверх всего, в том числе кнопок попапа: клик по ним мимо.
    pub toasts: Cell<Rect>,
}

/// Куда попал клик.
#[derive(Debug, PartialEq, Eq)]
pub enum Hit {
    Nothing,
    /// Кнопка (панель действий или попап) — эквивалент клавиши.
    Key(KeyEvent),
    /// Строка списка панели: индекс в `visible_*`.
    Item(Focus, usize),
    /// Панель, но мимо строк.
    Panel(Focus),
    /// Строка списка в попапе.
    PopupItem(usize),
    PopupInside,
    PopupOutside,
}

fn inside(r: Rect, x: u16, y: u16) -> bool {
    r.contains(Position::new(x, y))
}

/// Номер строки списка внутри рамки (рамка — 1 клетка, `skip` — строки
/// заголовка таблицы) с учётом прокрутки `off`.
fn row_in(r: Rect, off: usize, skip: u16, x: u16, y: u16) -> Option<usize> {
    if r.width < 3 || r.height < 3 + skip {
        return None;
    }
    let top = r.y + 1 + skip;
    if x <= r.x || x + 1 >= r.right() || y < top || y + 1 >= r.bottom() {
        return None;
    }
    Some(off + (y - top) as usize)
}

/// Шаг по списку длины `len`: по кругу (стрелки) или с упором в края
/// (колесо, Home/End).
fn step(cur: usize, len: usize, delta: i32, wrap: bool) -> usize {
    if len == 0 {
        return 0;
    }
    let next = cur as i32 + delta;
    if wrap {
        next.rem_euclid(len as i32) as usize
    } else {
        next.clamp(0, len as i32 - 1) as usize
    }
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// Окно приглашения появилось только что (см. [`INVITE_GUARD`]).
fn invite_guarded(inv: &InvitePopup) -> bool {
    inv.shown_at.is_some_and(|t| t.elapsed() < INVITE_GUARD)
}

// ---------------------------------------------------------------- приложение

pub struct App {
    pub focus: Focus,
    pub sel_group: Option<u32>,
    pub sel_friend: Option<[u8; 32]>,
    pub sel_peer: Option<[u8; 32]>,
    pub filter: String,
    /// Режим фильтрации (ввод идёт в строку фильтра).
    pub filtering: bool,
    pub sort: Sort,
    pub stack: Vec<Popup>,
    pub toasts: Vec<Toast>,
    pub log: Vec<LogLine>,
    pub groups: Vec<GroupView>,
    pub friends: Vec<FriendView>,
    pub peers: Vec<PeerView>,
    /// История скорости трафика (байт/с) для спарклайна.
    pub rx_hist: Vec<u64>,
    pub tx_hist: Vec<u64>,
    /// Момент старта TUI (для «время в сети»).
    pub started: Instant,
    pub my_pub: [u8; 32],
    pub my_code: String,
    pub my_name: String,
    pub my_status: String,
    pub servers: Vec<StoredServer>,
    pub autojoin: Vec<u32>,
    pub theme_kind: ThemeKind,
    /// Состояние соединения с сервером.
    pub connected: bool,
    pub server_addr: String,
    pub server_label: String,
    /// Накопленные счётчики трафика.
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_pkts: u64,
    pub tx_pkts: u64,
    pub status_msg: String,
    pub log_scroll: usize,
    pub quit: bool,
    /// Геометрия последнего кадра для мыши.
    pub hits: Hits,
    /// Приглашения, ждущие показа (окно — по одному, когда стек попапов пуст).
    pub invites: VecDeque<InvitePopup>,
    /// Отложенные («Позже») приглашения: показать снова — «o» или `:invites`.
    pub later_invites: Vec<InvitePopup>,
    /// Только что отклонённые (gid, когда) — см. [`INVITE_DECLINE_MEMORY`].
    pub declined: Vec<(u32, Instant)>,
    /// Сервер, к которому относятся приглашения и окна с gid (последний
    /// `Connected`/`ServerSwitched`): gid — номер группы на конкретном
    /// сервере, на другом сервере тот же gid — чужая группа.
    pub invites_server: Option<std::net::SocketAddr>,
    /// Адаптер и dll, с которыми запущен клиент (экран «Серверы»).
    pub adapter_name: String,
    pub dll_path: String,
    /// Невидимка (из конфига).
    pub invisible: bool,
    /// Транспорт до сервера (пока движок знает только UDP).
    pub transport: Transport,
    /// Где работает движок (пометка в шапке); `None` — ещё не синхронизировались.
    pub mode: Option<EngineMode>,
    /// Тонкий клиент потерял демона («демон недоступен»).
    pub daemon_down: bool,
    /// Разбираем историю событий демона: только лог, без тостов и окон.
    replaying: bool,
    /// Неотвеченные приглашения из снимка уже разложены по окнам (после
    /// подключения к демону — один раз; потеря связи сбрасывает).
    invites_seeded: bool,
}

impl App {
    pub fn new(my_pub: [u8; 32], my_code: &str, cfg: &Config) -> Self {
        let theme_kind = ThemeKind::from_key(&cfg.theme).unwrap_or(ThemeKind::Dark);
        Self {
            focus: Focus::Groups,
            sel_group: None,
            sel_friend: None,
            sel_peer: None,
            filter: String::new(),
            filtering: false,
            sort: Sort::Name,
            stack: Vec::new(),
            toasts: Vec::new(),
            log: Vec::new(),
            groups: Vec::new(),
            friends: Vec::new(),
            peers: Vec::new(),
            rx_hist: Vec::new(),
            tx_hist: Vec::new(),
            started: Instant::now(),
            my_pub,
            my_code: my_code.to_string(),
            my_name: cfg.name.clone(),
            my_status: cfg.status.clone(),
            servers: cfg.servers.clone(),
            autojoin: cfg.autojoin.clone(),
            theme_kind,
            connected: false,
            server_addr: String::new(),
            server_label: String::new(),
            rx_bytes: 0,
            tx_bytes: 0,
            rx_pkts: 0,
            tx_pkts: 0,
            status_msg: String::new(),
            log_scroll: 0,
            quit: false,
            hits: Hits::default(),
            invites: VecDeque::new(),
            later_invites: Vec::new(),
            declined: Vec::new(),
            invites_server: None,
            adapter_name: cfg.adapter.clone(),
            dll_path: cfg.dll.clone(),
            invisible: cfg.invisible,
            transport: Transport::Udp,
            mode: None,
            daemon_down: false,
            replaying: false,
            invites_seeded: false,
        }
    }

    // ---------- синхронизация с движком ----------

    /// Забирает свежее состояние движка, события, чистит тосты.
    pub fn sync(&mut self, eng: &dyn EngineApi) {
        self.mode = Some(eng.mode());
        let history = eng.take_history();
        let events = eng.poll_events();
        // Снимок — после событий: он не старше них (у embedded — «сейчас»).
        let snap = eng.snapshot();
        if !history.is_empty() {
            self.replaying = true;
            self.apply_events(history, &snap);
            self.replaying = false;
        }
        self.apply_events(events, &snap);
        self.daemon_down = eng.unavailable();
        if self.daemon_down {
            self.invites_seeded = false;
        } else if !self.invites_seeded {
            self.invites_seeded = true;
            self.seed_invites(&snap);
        }
        self.pump_invites();
        self.sync_snapshot(&snap);
    }

    /// Неотвеченные приглашения из снимка (демон знал о них до нашего
    /// подключения) — в очередь окон, как пришедшие событием.
    fn seed_invites(&mut self, snap: &Snapshot) {
        let now = Instant::now();
        for i in &snap.pending_invites {
            if self.has_invite(i.gid) {
                continue;
            }
            let skip =
                snap.groups.iter().any(|g| g.gid == i.gid) || snap.cfg.autojoin.contains(&i.gid);
            let inv = InvitePopup {
                gid: i.gid,
                group_name: i.group_name.clone(),
                from_name: i.from_name.clone(),
                from_pubkey: i.from_pubkey,
                received_at: now
                    .checked_sub(Duration::from_millis(i.received_ms_ago))
                    .unwrap_or(now),
                expires_at: i
                    .expires_in_s
                    .filter(|s| *s > 0)
                    .map(|s| now + Duration::from_secs(s)),
                shown_at: None,
            };
            self.on_invite(inv, skip);
        }
    }

    /// Состояние из снимка (группы, друзья, профиль, статус-бар) без событий.
    pub fn sync_snapshot(&mut self, snap: &Snapshot) {
        let meta = &snap.meta;
        self.rx_hist = meta.rx_hist.clone();
        self.tx_hist = meta.tx_hist.clone();
        self.connected = meta.connected;
        self.server_addr = meta.server.clone();
        self.server_label = meta.server_label.clone();
        // В снимке — целые секунды работы: момент старта переставляем, только
        // если он ушёл больше чем на секунду (иначе часы «в сети» дрожат).
        let now = Instant::now();
        let started = now
            .checked_sub(Duration::from_secs(meta.uptime_s))
            .unwrap_or(now);
        let drift = if started > self.started {
            started - self.started
        } else {
            self.started - started
        };
        if drift > Duration::from_millis(1500) {
            self.started = started;
        }
        self.rx_bytes = snap.stats.rx_bytes;
        self.tx_bytes = snap.stats.tx_bytes;
        self.rx_pkts = snap.stats.rx_pkts;
        self.tx_pkts = snap.stats.tx_pkts;

        let mut groups: Vec<GroupView> = Vec::new();
        for gs in &snap.groups {
            let mut peers: Vec<PeerView> = gs
                .members
                .iter()
                .map(|p| PeerView {
                    pubkey: p.pubkey,
                    name: p.name.clone(),
                    ip: p.ip,
                    online: p.online,
                    direct: p.direct,
                    rtt_ms: p.rtt_ms,
                    status: p.status.clone(),
                })
                .collect();
            peers.sort_by(|a, b| a.name.cmp(&b.name));
            let online = peers.iter().filter(|p| p.online).count() as u32 + 1;
            groups.push(GroupView {
                gid: gs.gid,
                name: gs.name.clone(),
                private: gs.private,
                mine: true,
                online,
                total: peers.len() as u32 + 1,
                my_ip: Some(gs.my_ip),
                owner_is_me: gs.owner == self.my_pub,
                peers,
            });
        }
        for s in meta.group_list.iter() {
            if !groups.iter().any(|g| g.gid == s.gid) {
                groups.push(GroupView {
                    gid: s.gid,
                    name: s.name.clone(),
                    private: s.private,
                    mine: s.mine,
                    online: s.online,
                    total: s.total,
                    my_ip: None,
                    owner_is_me: false,
                    peers: Vec::new(),
                });
            }
        }
        groups.sort_by(|a, b| {
            b.mine
                .cmp(&a.mine)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a.gid.cmp(&b.gid))
        });
        self.groups = groups;

        {
            // «В сети» — только если друг онлайн хотя бы в одной общей группе:
            // офлайн-участник держит lease и остаётся в списке участников.
            let known: HashSet<[u8; 32]> = snap
                .groups
                .iter()
                .flat_map(|g| g.members.iter().filter(|p| p.online).map(|p| p.pubkey))
                .collect();
            let cfg = &snap.cfg;
            let mut friends: Vec<FriendView> = Vec::new();
            for f in cfg.friends.iter() {
                let pk = hex32(&f.pubkey).unwrap_or([0; 32]);
                let shared = snap
                    .groups
                    .iter()
                    .filter(|g| g.members.iter().any(|p| p.pubkey == pk))
                    .count();
                friends.push(FriendView {
                    alias: f.alias.clone(),
                    pubkey: pk,
                    online: known.contains(&pk),
                    shared_groups: shared,
                });
            }
            friends.sort_by_key(|a| a.alias.to_lowercase());
            self.friends = friends;
            self.my_name = cfg.name.clone();
            self.my_status = cfg.status.clone();
            self.servers = cfg
                .servers
                .iter()
                .map(|s| StoredServer {
                    addr: s.addr.clone(),
                    pubkey: s.pubkey.clone(),
                    label: s.label.clone(),
                })
                .collect();
            self.autojoin = cfg.autojoin.clone();
            // Тема — локальная настройка фронтенда, в снимке её нет.
            self.invisible = cfg.invisible;
        }

        // Выбор группы: держим актуальный gid, иначе — первая своя.
        let group_gone = match self.sel_group {
            Some(g) => self.groups.iter().all(|x| x.gid != g),
            None => true,
        };
        if group_gone {
            self.sel_group = self
                .groups
                .iter()
                .find(|g| g.mine)
                .or_else(|| self.groups.first())
                .map(|g| g.gid);
        }
        // Выбор друга.
        let friend_gone = match self.sel_friend {
            Some(f) => self.friends.iter().all(|x| x.pubkey != f),
            None => true,
        };
        if friend_gone {
            self.sel_friend = self.friends.first().map(|f| f.pubkey);
        }

        // Участники выбранной группы + сортировка.
        self.peers = match self
            .sel_group
            .and_then(|g| self.groups.iter().find(|x| x.gid == g))
        {
            Some(g) => {
                let mut peers = g.peers.clone();
                match self.sort {
                    Sort::Name => peers.sort_by(|a, b| a.name.cmp(&b.name)),
                    Sort::Online => peers
                        .sort_by(|a, b| b.online.cmp(&a.online).then_with(|| a.name.cmp(&b.name))),
                    Sort::Rtt => peers.sort_by(|a, b| {
                        let ra = a.rtt_ms.unwrap_or(u64::MAX);
                        let rb = b.rtt_ms.unwrap_or(u64::MAX);
                        ra.cmp(&rb).then_with(|| a.name.cmp(&b.name))
                    }),
                }
                peers
            }
            None => Vec::new(),
        };
        let peer_gone = match self.sel_peer {
            Some(p) => self.peers.iter().all(|x| x.pubkey != p),
            None => true,
        };
        if peer_gone {
            self.sel_peer = self.peers.first().map(|p| p.pubkey);
        }

        self.expire_toasts();
    }

    /// События движка → лог, тосты, окна. `snap` — состояние не старше
    /// событий (уже в группе / автовход — окна приглашения не нужно).
    pub fn apply_events(&mut self, events: Vec<Event>, snap: &Snapshot) {
        use crate::engine::Event as E;
        let in_group = |gid: u32| snap.groups.iter().any(|g| g.gid == gid);
        for ev in events {
            match ev {
                E::Connected(s) => {
                    self.on_server(s);
                    self.log(MsgKind::Ok, format!("подключено к {s}"));
                }
                E::Disconnected(r) => {
                    self.log(MsgKind::Error, format!("{r}; переподключение…"));
                    self.toast(MsgKind::Error, r);
                }
                E::GroupJoined { gid, name, my_ip } => {
                    // Вошли (по приглашению или иначе) — окно больше не нужно.
                    self.drop_invite(gid);
                    let msg = format!(
                        "вошли в группу {gid} «{name}» (мой IP {})",
                        proto::ip_str(my_ip)
                    );
                    self.log(MsgKind::Ok, msg.clone());
                    self.toast(MsgKind::Ok, msg);
                }
                E::GroupLeft { gid, name } => {
                    let msg = format!("вышли из группы {gid} «{name}»");
                    self.log(MsgKind::Info, msg.clone());
                    self.toast(MsgKind::Info, msg);
                }
                E::GroupDeleted { gid, name } => {
                    self.drop_invite(gid);
                    let msg = format!("группа {gid} «{name}» удалена");
                    self.log(MsgKind::Warn, msg.clone());
                    self.toast(MsgKind::Warn, msg);
                }
                E::Kicked { gid, name, banned } => {
                    self.drop_invite(gid);
                    let msg = if banned {
                        format!("вас забанили в группе {gid} «{name}»")
                    } else {
                        format!("вас исключили из группы {gid} «{name}»")
                    };
                    self.log(MsgKind::Error, msg.clone());
                    self.toast(MsgKind::Error, msg);
                }
                E::DirectLost { gid, ip, name } => {
                    let msg = format!(
                        "прямой канал с {name} ({}) в {gid} потерян — через релей",
                        proto::ip_str(ip)
                    );
                    self.log(MsgKind::Warn, msg.clone());
                    self.toast(MsgKind::Warn, msg);
                }
                E::ServerKeyRotated { addr, new_code } => {
                    let msg = format!("ключ сервера {addr} сменён по цепочке ротации: {new_code}");
                    self.log(MsgKind::Warn, msg.clone());
                    self.toast(MsgKind::Warn, msg);
                }
                E::ServerSwitched { addr, label } => {
                    self.on_server(addr);
                    let msg = if label.is_empty() {
                        format!("переключено на сервер {addr}")
                    } else {
                        format!("переключено на сервер {label} ({addr})")
                    };
                    self.log(MsgKind::Info, msg.clone());
                    self.toast(MsgKind::Info, msg);
                    self.server_addr = addr.to_string();
                    self.on_server_switched(addr);
                }
                // Открыт экран администрирования этой группы — заполняем его,
                // иначе сводка в журнал.
                E::AdminInfo { gid, bans, invites } if self.admin_open(gid) => {
                    self.on_admin_info(gid, bans, invites);
                }
                E::AdminInfo { gid, bans, invites } => {
                    let names = |v: Vec<String>| {
                        if v.is_empty() {
                            "—".to_string()
                        } else {
                            v.join(", ")
                        }
                    };
                    let bans = names(bans.into_iter().map(|(_, n)| n).collect());
                    let invites = names(
                        invites
                            .into_iter()
                            .map(|(_, n, exp)| format!("{n} ({})", crate::engine::fmt_secs(exp)))
                            .collect(),
                    );
                    self.log(
                        MsgKind::Info,
                        format!("группа {gid}: баны: {bans}; приглашения: {invites}"),
                    );
                }
                E::PeerOnline { gid, ip, name } => {
                    self.log(
                        MsgKind::Ok,
                        format!("{name} ({}) онлайн в {gid}", proto::ip_str(ip)),
                    );
                }
                E::PeerOffline { gid, ip, name } => {
                    self.log(
                        MsgKind::Info,
                        format!("{name} ({}) офлайн в {gid}", proto::ip_str(ip)),
                    );
                }
                E::Direct { gid, ip, name } => {
                    let msg = format!("прямой канал с {name} ({}) в {gid}", proto::ip_str(ip));
                    self.log(MsgKind::Ok, msg.clone());
                    self.toast(MsgKind::Ok, msg);
                }
                E::Invite {
                    gid,
                    group_name,
                    from_pubkey,
                    from_name,
                    expires_in,
                } => {
                    // Уже в группе или в автовходе (движок войдёт сам) — окно
                    // не показываем: сервер повторяет приглашения после HELLO.
                    // История демона — только в лог.
                    let skip = self.replaying || in_group(gid) || snap.cfg.autojoin.contains(&gid);
                    let inv = InvitePopup {
                        gid,
                        group_name,
                        from_name,
                        from_pubkey,
                        received_at: Instant::now(),
                        expires_at: (expires_in > 0)
                            .then(|| Instant::now() + Duration::from_secs(expires_in as u64)),
                        shown_at: None,
                    };
                    self.on_invite(inv, skip);
                }
                E::InviteDeclined {
                    gid,
                    group_name,
                    by_pubkey,
                    by_name,
                } => {
                    let who = self.friend_alias(&by_pubkey).unwrap_or(by_name);
                    let msg = format!("{who} отклонил приглашение в «{group_name}» ({gid})");
                    self.log(MsgKind::Warn, msg.clone());
                    self.toast(MsgKind::Warn, msg);
                }
                E::InviteRevoked { gid } => {
                    if self.has_invite(gid) {
                        self.drop_invite(gid);
                        let msg = format!("приглашение в группу {gid} отменено: группа удалена");
                        self.log(MsgKind::Info, msg.clone());
                        self.toast(MsgKind::Info, msg);
                    }
                }
                // Неполное окно движок дочитывает сам (LIST_INVITES).
                E::InvitesSynced {
                    gids,
                    from,
                    complete,
                } => {
                    for (gid, name) in self.sync_invites(&gids, from, complete) {
                        // Вошли сами (JOIN тратит приглашение) — не тостить.
                        if in_group(gid) {
                            continue;
                        }
                        let msg = format!("приглашение в «{name}» ({gid}) больше недействительно");
                        self.log(MsgKind::Info, msg.clone());
                        self.toast(MsgKind::Info, msg);
                    }
                }
                // Ответ на чужой запрос из истории — карточку не открываем.
                E::FriendGroups { .. } if self.replaying => {}
                E::FriendGroups { pubkey, items } => self.on_friend_groups(pubkey, items),
                E::ServerPingResult { addr, rtt_ms, success } => {
                    // Update server ping in servers screen if visible
                    if let Some(Popup::Servers(s)) = self.stack.last_mut() {
                        s.update_ping(addr, rtt_ms);
                    }
                    if success {
                        if let Some(rtt) = rtt_ms {
                            self.toast(MsgKind::Ok, format!("пинг {}: {} мс", addr, rtt));
                        } else {
                            self.toast(MsgKind::Ok, format!("пинг {}: OK", addr));
                        }
                    } else {
                        self.toast(MsgKind::Error, format!("пинг {}: таймаут", addr));
                    }
                }
                E::Error(e) => {
                    self.log(MsgKind::Error, e.clone());
                    self.toast(MsgKind::Error, e);
                }
                E::Notice(n) => {
                    self.log(MsgKind::Info, n);
                }
            }
        }
    }

    /// Ответ сервера на FRIEND_GROUPS: заполнить открытую карточку друга
    /// (или открыть новую).
    pub fn on_friend_groups(&mut self, pubkey: [u8; 32], items: Vec<proto::payloads::FriendGroup>) {
        let alias = self
            .friends
            .iter()
            .find(|f| f.pubkey == pubkey)
            .map(|f| f.alias.clone())
            .unwrap_or_else(|| proto::hex_of(&pubkey));
        let mut updated = false;
        if let Some(Popup::FriendCard(card)) = self.stack.last_mut()
            && card.pubkey == pubkey
        {
            card.groups = items.clone();
            card.loading = false;
            updated = true;
        }
        // Запоздавший ответ (карточку уже закрыли) поверх окна приглашения не
        // кладём: после закрытия карточки окно вернулось бы без защиты от
        // случайного нажатия.
        let over_invite = matches!(self.stack.last(), Some(Popup::Invite(_)));
        if !updated && !over_invite {
            self.stack.push(Popup::FriendCard(FriendCardPopup {
                alias,
                pubkey,
                groups: items,
                loading: false,
            }));
        }
    }

    // ---------- приглашения ----------

    /// Алиас друга по pubkey.
    pub fn friend_alias(&self, pk: &[u8; 32]) -> Option<String> {
        self.friends
            .iter()
            .find(|f| f.pubkey == *pk)
            .map(|f| f.alias.clone())
    }

    /// Кто пригласил: алиас друга, иначе имя, которое прислал сервер.
    pub fn invite_from_label(&self, inv: &InvitePopup) -> String {
        match self.friend_alias(&inv.from_pubkey) {
            Some(alias) if alias != inv.from_name && !inv.from_name.is_empty() => {
                format!("{alias} ({})", inv.from_name)
            }
            Some(alias) => alias,
            None => inv.from_name.clone(),
        }
    }

    /// Есть ли приглашение в `gid` — на экране, в очереди или отложенное.
    pub fn has_invite(&self, gid: u32) -> bool {
        self.invites.iter().any(|i| i.gid == gid)
            || self.later_invites.iter().any(|i| i.gid == gid)
            || self
                .stack
                .iter()
                .any(|p| matches!(p, Popup::Invite(i) if i.gid == gid))
    }

    /// Пришло приглашение. `skip` — уже в группе / автовход: только лог.
    /// Повтор того же gid (сервер шлёт неотвеченные после каждого HELLO)
    /// обновляет данные, но второго окна не открывает; отложенное остаётся
    /// отложенным.
    pub fn on_invite(&mut self, inv: InvitePopup, skip: bool) {
        if self.recently_declined(inv.gid) {
            // Запоздавший список, собранный до нашего отказа.
            return;
        }
        let from = self.invite_from_label(&inv);
        let msg = format!("приглашение в «{}» ({}) от {from}", inv.group_name, inv.gid);
        if skip {
            self.log(MsgKind::Info, msg);
            return;
        }
        let gid = inv.gid;
        let update = |x: &mut InvitePopup| {
            x.group_name = inv.group_name.clone();
            x.from_name = inv.from_name.clone();
            x.from_pubkey = inv.from_pubkey;
        };
        let mut known = false;
        for p in self.stack.iter_mut() {
            if let Popup::Invite(x) = p
                && x.gid == gid
            {
                update(x);
                known = true;
            }
        }
        for x in self.invites.iter_mut().chain(self.later_invites.iter_mut()) {
            if x.gid == gid {
                update(x);
                known = true;
            }
        }
        if known {
            return;
        }
        self.log(MsgKind::Warn, msg.clone());
        self.toast(MsgKind::Warn, msg);
        self.invites.push_back(inv);
        self.pump_invites();
    }

    /// Текущий сервер — `addr`. Если это другой сервер, всё, что
    /// привязано к gid старого (приглашения на экране, в очереди и
    /// отложенные, недавние отказы, окна выбора участника / подтверждения
    /// выхода и удаления, ввод для переименования / кода приглашения),
    /// сбрасывается: принять такое приглашение значило бы JOIN в тот же gid
    /// на новом сервере — чужую группу.
    pub fn on_server(&mut self, addr: std::net::SocketAddr) {
        let prev = self.invites_server.replace(addr);
        if prev.is_none() || prev == Some(addr) {
            return;
        }
        self.invites.clear();
        self.later_invites.clear();
        self.declined.clear();
        self.stack.retain(|p| {
            !matches!(
                p,
                Popup::Invite(_)
                    | Popup::PeerPick(_)
                    | Popup::FriendCard(_)
                    | Popup::Confirm(ConfirmPopup {
                        action: ConfirmAction::DeleteGroup(_) | ConfirmAction::LeaveGroup(_),
                        ..
                    })
                    | Popup::Input(InputPopup {
                        action: InputAction::RenameGroup(_) | InputAction::InviteCode(_),
                        ..
                    })
            )
        });
        self.pump_invites();
    }

    /// Отказ отправлен — запомнить gid (см. [`INVITE_DECLINE_MEMORY`]).
    pub fn note_declined(&mut self, gid: u32) {
        self.declined
            .retain(|(g, t)| *g != gid && t.elapsed() < INVITE_DECLINE_MEMORY);
        self.declined.push((gid, Instant::now()));
    }

    fn recently_declined(&self, gid: u32) -> bool {
        self.declined
            .iter()
            .any(|(g, t)| *g == gid && t.elapsed() < INVITE_DECLINE_MEMORY)
    }

    /// Убрать приглашение в `gid` отовсюду (вошли в группу, группа удалена).
    pub fn drop_invite(&mut self, gid: u32) {
        self.invites.retain(|i| i.gid != gid);
        self.later_invites.retain(|i| i.gid != gid);
        self.stack
            .retain(|p| !matches!(p, Popup::Invite(i) if i.gid == gid));
        self.pump_invites();
    }

    /// Сервер прислал окно списка неотвеченных приглашений (gid ≥ `from`):
    /// всё, чего в нём нет (группу удалили, приглашение отозвали или на него
    /// ответили с другого клиента, пока мы были офлайн; вход отклонён), снять.
    /// Окно достоверно от `from`; неполное (`complete == false`, обрезан
    /// хвост) — только до последнего gid в нём. Пришедшие за
    /// [`INVITE_SYNC_GRACE`] до сверки не трогаются. Возвращает снятые (gid,
    /// имя группы).
    pub fn sync_invites(&mut self, gids: &[u32], from: u32, complete: bool) -> Vec<(u32, String)> {
        let upto = if complete {
            u32::MAX
        } else {
            gids.iter().copied().max().unwrap_or(0)
        };
        let mut stale: Vec<(u32, String)> = Vec::new();
        let held = self
            .stack
            .iter()
            .filter_map(|p| match p {
                Popup::Invite(i) => Some(i),
                _ => None,
            })
            .chain(self.invites.iter())
            .chain(self.later_invites.iter());
        for i in held {
            if (from..=upto).contains(&i.gid)
                && !gids.contains(&i.gid)
                && i.received_at.elapsed() >= INVITE_SYNC_GRACE
                && !stale.iter().any(|(g, _)| *g == i.gid)
            {
                stale.push((i.gid, i.group_name.clone()));
            }
        }
        for (gid, _) in &stale {
            self.drop_invite(*gid);
        }
        stale
    }

    /// Показать следующее приглашение, если стек попапов пуст.
    ///
    /// Поверх другого окна приглашение не кладём: пользователь мог как раз
    /// набирать имя группы или friend code, и его «y»/«n»/Enter ушли бы в
    /// окно приглашения — приняли или отклонили бы его вслепую. Поэтому оно
    /// ждёт в очереди (тост и строка лога видны сразу), а окна показываются
    /// по одному, а не стопкой. То же — пока открыта строка поиска «/»:
    /// это ввод текста без попапа.
    pub fn pump_invites(&mut self) {
        if !self.stack.is_empty() || self.filtering {
            return;
        }
        if let Some(mut inv) = self.invites.pop_front() {
            inv.shown_at = Some(Instant::now());
            self.stack.push(Popup::Invite(inv));
        }
    }

    /// Вернуть отложенные приглашения в очередь показа («o», `:invites`).
    pub fn reopen_invites(&mut self) {
        if self.later_invites.is_empty() && self.invites.is_empty() {
            self.toast(MsgKind::Info, "нет неотвеченных приглашений".into());
            return;
        }
        for inv in self.later_invites.drain(..).rev() {
            self.invites.push_front(inv);
        }
        self.pump_invites();
    }

    /// Клавиша в окне приглашения. Возвращает команду движку (если есть).
    /// Enter / y — принять, n — отклонить, Esc / l — позже (русская
    /// раскладка: т — отклонить, д — позже). «н» на месте «y» не принимает:
    /// по-русски она читается как «нет» ([Д/н]), а принять — самое
    /// весомое действие (вход в VPN группы, IP виден участникам); на неё —
    /// только подсказка. Прочие клавиши окно не закрывают.
    pub fn invite_key(&mut self, inv: InvitePopup, key: KeyEvent) -> Option<Cmd> {
        // Ctrl-C и прочие сочетания с Ctrl закрывают окно как «Позже» — ни
        // одно сочетание не принимает и не отклоняет приглашение.
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            if key.code == KeyCode::Char('c') {
                // Ctrl-C откладывает и всю очередь: иначе следующее окно
                // всплывало бы сразу, и для выхода пришлось бы жать Ctrl-C
                // по разу на каждое приглашение.
                let queued: Vec<InvitePopup> = self.invites.drain(..).collect();
                let cmd = self.answer_invite(inv, InviteAnswer::Later);
                self.later_invites.extend(queued);
                return cmd;
            }
            return self.answer_invite(inv, InviteAnswer::Later);
        }
        let ans = match key.code {
            KeyCode::Enter | KeyCode::Char('y' | 'Y') => InviteAnswer::Accept,
            KeyCode::Char('n' | 'N' | 'т' | 'Т') => InviteAnswer::Decline,
            KeyCode::Esc | KeyCode::Char('l' | 'L' | 'д' | 'Д') => InviteAnswer::Later,
            KeyCode::Char('н' | 'Н') => {
                self.status_msg =
                    "«н» не отвечает: принять — Enter/y, отклонить — n (т), позже — Esc".into();
                self.stack.push(Popup::Invite(inv));
                return None;
            }
            _ => {
                self.stack.push(Popup::Invite(inv));
                return None;
            }
        };
        self.answer_invite(inv, ans)
    }

    /// Ответ на приглашение (окно уже снято со стека).
    pub fn answer_invite(&mut self, inv: InvitePopup, ans: InviteAnswer) -> Option<Cmd> {
        if ans != InviteAnswer::Later && invite_guarded(&inv) {
            // Окно только что появилось — нажатие было не ему.
            self.stack.push(Popup::Invite(inv));
            return None;
        }
        let (gid, name) = (inv.gid, inv.group_name.clone());
        let cmd = match ans {
            InviteAnswer::Later => {
                self.later_invites.push(inv);
                self.status_msg = "приглашение отложено — «o», чтобы ответить".into();
                None
            }
            _ if !self.connected => {
                // Команда не дойдёт до сервера — не терять приглашение.
                self.later_invites.push(inv);
                self.toast(
                    MsgKind::Error,
                    "нет связи с сервером — ответ не отправлен, приглашение отложено".into(),
                );
                None
            }
            InviteAnswer::Accept => {
                // Снимется по GroupJoined. JOIN может не пройти: «группа
                // заполнена» — сервер приглашение сохраняет, к нему можно
                // вернуться через «o»; группы нет или приглашение отозвано —
                // сервер вместе с ошибкой шлёт свежий список, сверка снимет.
                self.later_invites.push(inv);
                self.toast(MsgKind::Info, format!("входим в группу {gid} «{name}»"));
                Some(Cmd::Join(gid))
            }
            InviteAnswer::Decline => {
                self.note_declined(gid);
                let msg = format!("приглашение в «{name}» ({gid}) отклонено");
                self.log(MsgKind::Info, msg.clone());
                self.toast(MsgKind::Info, msg);
                Some(Cmd::DeclineInvite(gid))
            }
        };
        self.pump_invites();
        cmd
    }

    pub fn expire_toasts(&mut self) {
        let now = Instant::now();
        self.toasts.retain(|t| now.duration_since(t.at) < TOAST_TTL);
    }

    pub fn toast(&mut self, kind: MsgKind, text: String) {
        if self.replaying {
            return;
        }
        self.toasts.push(Toast {
            text,
            kind,
            at: Instant::now(),
        });
        if self.toasts.len() > 5 {
            self.toasts.remove(0);
        }
    }

    pub fn log(&mut self, kind: MsgKind, text: String) {
        self.log.push(LogLine {
            text,
            kind,
            wall: SystemTime::now(),
        });
        if self.log.len() > LOG_MAX {
            self.log.remove(0);
        }
    }

    // ---------- выборки ----------

    pub fn visible_groups(&self) -> Vec<&GroupView> {
        let f = self.filter.to_lowercase();
        self.groups
            .iter()
            .filter(|g| {
                f.is_empty() || g.name.to_lowercase().contains(&f) || g.gid.to_string() == f
            })
            .collect()
    }

    pub fn visible_friends(&self) -> Vec<&FriendView> {
        let f = self.filter.to_lowercase();
        self.friends
            .iter()
            .filter(|x| f.is_empty() || x.alias.to_lowercase().contains(&f))
            .collect()
    }

    pub fn visible_peers(&self) -> Vec<&PeerView> {
        let f = self.filter.to_lowercase();
        self.peers
            .iter()
            .filter(|p| f.is_empty() || p.name.to_lowercase().contains(&f))
            .collect()
    }

    pub fn selected_group(&self) -> Option<&GroupView> {
        self.sel_group
            .and_then(|g| self.groups.iter().find(|x| x.gid == g))
    }

    pub fn selected_friend(&self) -> Option<&FriendView> {
        self.sel_friend
            .and_then(|f| self.friends.iter().find(|x| x.pubkey == f))
    }

    pub fn selected_peer(&self) -> Option<&PeerView> {
        self.sel_peer
            .and_then(|p| self.peers.iter().find(|x| x.pubkey == p))
    }

    // ---------- клавиши ----------

    pub fn handle_key(&mut self, key: KeyEvent, eng: &dyn EngineApi) {
        // Хоткеи работают и в русской раскладке; в полях ввода — как есть.
        let key = if self.text_input_active() {
            key
        } else {
            latin_key(key)
        };
        if !self.stack.is_empty() {
            self.handle_popup_key(key, eng);
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            self.send(eng, Cmd::Quit);
            return;
        }
        if self.filtering {
            self.handle_filter_key(key);
            return;
        }
        match key.code {
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::BackTab => self.focus = self.focus.prev(),
            KeyCode::F(1) => self.stack.push(Popup::Help),
            KeyCode::F(2) => self.open_create_group(),
            KeyCode::F(3) | KeyCode::F(10) => {
                self.stack.push(Popup::Settings(SettingsPopup { sel: 0 }))
            }
            KeyCode::F(4) => self.open_servers(),
            KeyCode::F(6) => self.open_rename(),
            KeyCode::F(8) => self.open_delete_group(),
            KeyCode::Char('?') => self.stack.push(Popup::Help),
            KeyCode::Char(':') => self.open_command(),
            KeyCode::Char('/') => {
                self.filtering = true;
            }
            KeyCode::Esc => {
                self.filter.clear();
                self.filtering = false;
                self.log_scroll = 0;
            }
            KeyCode::Up => self.move_sel(-1),
            KeyCode::Down => self.move_sel(1),
            KeyCode::PageUp => self.log_scroll = (self.log_scroll + 5).min(self.log.len()),
            KeyCode::PageDown => self.log_scroll = self.log_scroll.saturating_sub(5),
            KeyCode::Home => self.move_sel(-1000),
            KeyCode::End => self.move_sel(1000),
            KeyCode::Enter => self.activate(eng),
            KeyCode::Char('i') => self.open_pick(PickMode::Invite),
            KeyCode::Char('k') => self.open_pick(PickMode::Kick),
            KeyCode::Char('b') => self.open_pick(PickMode::Ban),
            KeyCode::Char('j') => self.join_selected(eng),
            KeyCode::Char('x') => self.open_leave_group(),
            KeyCode::Char('a') => self.open_add_friend(),
            KeyCode::Char('d') => self.open_del_friend(),
            KeyCode::Char('c') => self.copy_context(),
            KeyCode::Char('p') => self.stack.push(Popup::Profile),
            KeyCode::Char('o') => self.reopen_invites(),
            KeyCode::Char('m') => {
                if let Some(cmd) = self.open_admin() {
                    self.send(eng, cmd);
                }
            }
            KeyCode::Char('s') => {
                self.sort = self.sort.next();
                self.status_msg = format!("сортировка: {}", self.sort.label());
            }
            KeyCode::Char('r') if self.focus == Focus::Friends => self.open_friend_alias(),
            KeyCode::Char('r') => {
                self.send(eng, Cmd::RefreshList);
                self.status_msg = "обновляем список групп".into();
            }
            KeyCode::Char(c) if !c.is_control() => {
                // Буквы вне режима фильтра — неизвестные команды.
                self.status_msg = format!("«{c}» — неизвестная команда; F1 — справка, / — поиск");
            }
            _ => {}
        }
    }

    /// Ввод идёт в текстовое поле (поиск или окно ввода) — раскладку не трогаем.
    pub fn text_input_active(&self) -> bool {
        match self.stack.last() {
            Some(Popup::Input(_)) => true,
            Some(_) => false,
            None => self.filtering,
        }
    }

    /// Число неотвеченных приглашений: в очереди, отложенные и открытое окно.
    pub fn pending_invites(&self) -> usize {
        let shown = self
            .stack
            .iter()
            .filter(|p| matches!(p, Popup::Invite(_)))
            .count();
        self.invites.len() + self.later_invites.len() + shown
    }

    /// Копирует в буфер обмена (OSC 52 через SSH) и сообщает результат тостом.
    fn copy_toast(&mut self, text: &str, ok: String) {
        match copy_to_clipboard(text) {
            Ok(()) => self.toast(MsgKind::Ok, ok),
            Err(e) => self.toast(MsgKind::Error, e),
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.filter.clear();
                self.filtering = false;
            }
            KeyCode::Enter => self.filtering = false,
            KeyCode::Backspace => {
                self.filter.pop();
                if self.filter.is_empty() {
                    self.filtering = false;
                }
            }
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::BackTab => self.focus = self.focus.prev(),
            KeyCode::Up => self.move_sel(-1),
            KeyCode::Down => self.move_sel(1),
            KeyCode::Char(c) if !c.is_control() => self.filter.push(c),
            _ => {}
        }
    }

    fn move_sel(&mut self, delta: i32) {
        // Стрелки ходят по кругу, Home/End (±1000) упираются в края.
        // Раньше ±1000 тоже шло по кругу, и Home попадал не на первую строку.
        self.move_sel_by(delta, delta.abs() == 1);
    }

    fn move_sel_by(&mut self, delta: i32, wrap: bool) {
        match self.focus {
            Focus::Groups => {
                let list = self.visible_groups();
                if list.is_empty() {
                    return;
                }
                let cur = list.iter().position(|g| Some(g.gid) == self.sel_group);
                let next = step(cur.unwrap_or(0), list.len(), delta, wrap);
                self.sel_group = Some(list[next].gid);
            }
            Focus::Friends => {
                let list = self.visible_friends();
                if list.is_empty() {
                    return;
                }
                let cur = list.iter().position(|f| Some(f.pubkey) == self.sel_friend);
                let next = step(cur.unwrap_or(0), list.len(), delta, wrap);
                self.sel_friend = Some(list[next].pubkey);
            }
            Focus::Peers => {
                let list = self.visible_peers();
                if list.is_empty() {
                    return;
                }
                let cur = list.iter().position(|p| Some(p.pubkey) == self.sel_peer);
                let next = step(cur.unwrap_or(0), list.len(), delta, wrap);
                self.sel_peer = Some(list[next].pubkey);
            }
            Focus::Log => {
                let max = self.log.len();
                if delta < 0 {
                    self.log_scroll = (self.log_scroll + (-delta) as usize).min(max);
                } else {
                    self.log_scroll = self.log_scroll.saturating_sub(delta as usize);
                }
            }
        }
    }

    // ---------- мышь ----------

    pub fn handle_mouse(&mut self, m: MouseEvent, eng: &dyn EngineApi) {
        // Экраны со своей геометрией (admin, servers) разбирают мышь сами;
        // тост поверх них по-прежнему закрывает то, что под ним.
        if matches!(self.stack.last(), Some(Popup::Admin(_) | Popup::Servers(_)))
            && !inside(self.hits.toasts.get(), m.column, m.row)
        {
            self.screen_mouse(m, eng);
            return;
        }
        match m.kind {
            MouseEventKind::Down(MouseButton::Left) => self.click(m.column, m.row, eng),
            MouseEventKind::ScrollUp => self.wheel(m.column, m.row, -1),
            MouseEventKind::ScrollDown => self.wheel(m.column, m.row, 1),
            _ => {}
        }
    }

    /// Что находится в клетке (x, y) последнего кадра.
    pub fn hit(&self, x: u16, y: u16) -> Hit {
        let h = &self.hits;
        // Тост закрывает то, что под ним (например, «Отклонить» в окне
        // приглашения): невидимая кнопка не должна нажиматься.
        if inside(h.toasts.get(), x, y) {
            return Hit::Nothing;
        }
        if let Some(top) = self.stack.last() {
            for (r, k) in h.popup_buttons.borrow().iter() {
                if inside(*r, x, y) {
                    return Hit::Key(*k);
                }
            }
            let rect = h.popup.get();
            if !inside(rect, x, y) {
                return Hit::PopupOutside;
            }
            let len = match top {
                Popup::PeerPick(p) => p.items.len(),
                Popup::ListPick(p) => p.items.len(),
                Popup::Settings(_) => SETTING_ROWS.len(),
                _ => 0,
            };
            return match row_in(rect, h.popup_off.get(), 0, x, y) {
                Some(i) if i < len => Hit::PopupItem(i),
                _ => Hit::PopupInside,
            };
        }
        for (r, k) in h.toolbar.borrow().iter() {
            if inside(*r, x, y) {
                return Hit::Key(*k);
            }
        }
        for (r, f) in h.tabs.borrow().iter() {
            if inside(*r, x, y) {
                return Hit::Panel(*f);
            }
        }
        let (r, off) = h.groups.get();
        if inside(r, x, y) {
            return match row_in(r, off, 0, x, y) {
                Some(i) if i < self.visible_groups().len() => Hit::Item(Focus::Groups, i),
                _ => Hit::Panel(Focus::Groups),
            };
        }
        let (r, off) = h.friends.get();
        if inside(r, x, y) {
            return match row_in(r, off, 0, x, y) {
                Some(i) if i < self.visible_friends().len() => Hit::Item(Focus::Friends, i),
                _ => Hit::Panel(Focus::Friends),
            };
        }
        let (r, off) = h.peers.get();
        if inside(r, x, y) {
            // Под заголовком таблицы; строка 0 — «я» (если группа выбрана).
            return match row_in(r, off, 1, x, y) {
                Some(i)
                    if self.selected_group().is_some()
                        && i >= 1
                        && i - 1 < self.visible_peers().len() =>
                {
                    Hit::Item(Focus::Peers, i - 1)
                }
                _ => Hit::Panel(Focus::Peers),
            };
        }
        if inside(h.log.get(), x, y) {
            return Hit::Panel(Focus::Log);
        }
        Hit::Nothing
    }

    fn click(&mut self, x: u16, y: u16, eng: &dyn EngineApi) {
        match self.hit(x, y) {
            Hit::Nothing => {}
            Hit::Key(k) => {
                // Кнопка панели действий не должна уйти в строку поиска.
                if self.stack.is_empty() {
                    self.filtering = false;
                }
                self.handle_key(k, eng);
            }
            Hit::PopupOutside => {
                // Мимо окна приглашения — «Позже» (никогда не «Отклонить»), а
                // в первые мгновения после появления окна — ничего: клик
                // предназначался основному экрану.
                if let Some(Popup::Invite(inv)) = self.stack.last()
                    && invite_guarded(inv)
                {
                    return;
                }
                self.handle_key(key(KeyCode::Esc), eng)
            }
            Hit::PopupItem(i) => {
                if self.click_popup_item(i) {
                    self.handle_key(key(KeyCode::Enter), eng);
                }
            }
            Hit::PopupInside => {
                // Строка «приватная группа» в создании группы — переключатель.
                let r = self.hits.popup.get();
                if let Some(Popup::Input(inp)) = self.stack.last()
                    && matches!(inp.action, InputAction::CreateGroup)
                    && y == r.y + 2
                {
                    self.handle_key(key(KeyCode::Tab), eng);
                }
            }
            Hit::Panel(f) => self.focus = f,
            Hit::Item(f, i) => {
                if self.select_item(f, i) {
                    self.activate(eng);
                }
            }
        }
    }

    /// Выбирает строку `i` в попапе-списке. true — пора применить (Enter).
    /// Участник для приглашения/кика/бана применяется только повторным
    /// кликом по уже выбранной строке; настройки и галочки — сразу.
    pub fn click_popup_item(&mut self, i: usize) -> bool {
        match self.stack.last_mut() {
            Some(Popup::PeerPick(p)) => {
                let again = p.sel == i;
                p.sel = i;
                again
            }
            Some(Popup::ListPick(p)) => {
                p.sel = i;
                true
            }
            Some(Popup::Settings(s)) => {
                s.sel = i;
                true
            }
            _ => false,
        }
    }

    /// Фокус на панель и выбор строки `i`. true — строка уже была выбрана
    /// в этой же панели (второй клик = Enter).
    pub fn select_item(&mut self, focus: Focus, i: usize) -> bool {
        let was_focused = self.focus == focus;
        self.focus = focus;
        let already = match focus {
            Focus::Groups => {
                let id = self.visible_groups().get(i).map(|g| g.gid);
                let already = id.is_some() && id == self.sel_group;
                if id.is_some() {
                    self.sel_group = id;
                }
                already
            }
            Focus::Friends => {
                let id = self.visible_friends().get(i).map(|f| f.pubkey);
                let already = id.is_some() && id == self.sel_friend;
                if id.is_some() {
                    self.sel_friend = id;
                }
                already
            }
            Focus::Peers => {
                let id = self.visible_peers().get(i).map(|p| p.pubkey);
                let already = id.is_some() && id == self.sel_peer;
                if id.is_some() {
                    self.sel_peer = id;
                }
                already
            }
            Focus::Log => false,
        };
        was_focused && already
    }

    /// Колесо: прокрутка списка под курсором (без хода по кругу).
    pub fn wheel(&mut self, x: u16, y: u16, delta: i32) {
        if !self.stack.is_empty() {
            if !inside(self.hits.popup.get(), x, y) {
                return;
            }
            match self.stack.last_mut() {
                Some(Popup::PeerPick(p)) => p.sel = step(p.sel, p.items.len(), delta, false),
                Some(Popup::ListPick(p)) => p.sel = step(p.sel, p.items.len(), delta, false),
                Some(Popup::Settings(s)) => s.sel = step(s.sel, SETTING_ROWS.len(), delta, false),
                _ => {}
            }
            return;
        }
        let focus = match self.hit(x, y) {
            Hit::Item(f, _) | Hit::Panel(f) => f,
            _ => return,
        };
        self.focus = focus;
        let delta = if focus == Focus::Log {
            delta * 3
        } else {
            delta
        };
        self.move_sel_by(delta, false);
    }

    fn activate(&mut self, eng: &dyn EngineApi) {
        match self.focus {
            Focus::Friends => {
                if let Some(f) = self.selected_friend() {
                    let pk = f.pubkey;
                    let alias = f.alias.clone();
                    self.stack.push(Popup::FriendCard(FriendCardPopup {
                        alias,
                        pubkey: pk,
                        groups: Vec::new(),
                        loading: true,
                    }));
                    self.send(eng, Cmd::FriendGroups(pk));
                }
            }
            Focus::Groups => {
                if let Some(g) = self.selected_group()
                    && !g.mine
                {
                    let gid = g.gid;
                    self.send(eng, Cmd::Join(gid));
                    self.toast(MsgKind::Info, format!("входим в группу {gid}"));
                }
            }
            Focus::Peers | Focus::Log => {}
        }
    }

    // ---------- попапы ----------

    fn handle_popup_key(&mut self, key: KeyEvent, eng: &dyn EngineApi) {
        match self.stack.last() {
            Some(Popup::Admin(_)) => {
                for cmd in self.admin_key(key) {
                    self.send(eng, cmd);
                }
                self.pump_invites();
                return;
            }
            Some(Popup::Servers(_)) => {
                self.servers_input(eng, |v| v.handle_key(key));
                self.pump_invites();
                return;
            }
            _ => {}
        }
        let popup = match self.stack.pop() {
            Some(p) => p,
            None => return,
        };
        match popup {
            Popup::Help => {
                if !matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::F(1)) {
                    self.stack.push(Popup::Help);
                }
            }
            Popup::Input(inp) => self.input_key(inp, key, eng),
            Popup::Confirm(c) => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    self.confirm_action(c.action, eng)
                }
                _ => {}
            },
            Popup::PeerPick(mut p) => match key.code {
                KeyCode::Up => {
                    if !p.items.is_empty() {
                        p.sel = (p.sel + p.items.len() - 1) % p.items.len();
                    }
                    self.stack.push(Popup::PeerPick(p));
                }
                KeyCode::Down => {
                    if !p.items.is_empty() {
                        p.sel = (p.sel + 1) % p.items.len();
                    }
                    self.stack.push(Popup::PeerPick(p));
                }
                KeyCode::Enter => {
                    if let Some(item) = p.items.get(p.sel).cloned() {
                        if item.pubkey == [0; 32] {
                            // Ручной ввод friend code.
                            self.stack.push(Popup::Input(InputPopup {
                                title: format!("Пригласить в группу {}", p.gid),
                                hint: "friend code (TUN-…) · Enter — отправить".into(),
                                value: String::new(),
                                action: InputAction::InviteCode(p.gid),
                                private: false,
                            }));
                            return;
                        }
                        match p.mode {
                            PickMode::Invite => {
                                self.send(eng, Cmd::Invite(p.gid, item.pubkey));
                                self.toast(
                                    MsgKind::Ok,
                                    format!("приглашение отправлено: {}", item.label),
                                );
                            }
                            PickMode::Kick => {
                                self.send(eng, Cmd::Kick(p.gid, item.pubkey));
                                self.toast(MsgKind::Warn, format!("исключён: {}", item.label));
                            }
                            PickMode::Ban => {
                                self.send(eng, Cmd::Ban(p.gid, item.pubkey));
                                self.toast(MsgKind::Warn, format!("забанен: {}", item.label));
                            }
                        }
                    }
                }
                _ => {}
            },
            Popup::FriendCard(card) => {
                if let KeyCode::Char('c') = key.code {
                    self.copy_toast(
                        &proto::friend_code_of(&card.pubkey),
                        "friend code друга скопирован".into(),
                    );
                    self.stack.push(Popup::FriendCard(card));
                }
            }
            Popup::ListPick(mut p) => match key.code {
                KeyCode::Up => {
                    if !p.items.is_empty() {
                        p.sel = (p.sel + p.items.len() - 1) % p.items.len();
                    }
                    self.stack.push(Popup::ListPick(p));
                }
                KeyCode::Down => {
                    if !p.items.is_empty() {
                        p.sel = (p.sel + 1) % p.items.len();
                    }
                    self.stack.push(Popup::ListPick(p));
                }
                KeyCode::Enter => {
                    match p.action {
                        ListAction::ToggleAutojoin => {
                            // gid берём из выбранной строки: в действии лежит
                            // заглушка 0, из-за которой переключалась «группа 0».
                            let gid = p.items.get(p.sel).and_then(|i| i.value.parse::<u32>().ok());
                            if let Some(gid) = gid {
                                self.send(eng, Cmd::ToggleAutojoin(gid));
                                if let Some(item) = p.items.get_mut(p.sel) {
                                    item.checked = !item.checked;
                                }
                                // Список остаётся открытым: можно отметить несколько групп.
                                self.stack.push(Popup::ListPick(p));
                            }
                        }
                    }
                }
                _ => {}
            },
            Popup::Settings(mut s) => match key.code {
                KeyCode::Up => {
                    s.sel = (s.sel + SETTING_ROWS.len() - 1) % SETTING_ROWS.len();
                    self.stack.push(Popup::Settings(s));
                }
                KeyCode::Down => {
                    s.sel = (s.sel + 1) % SETTING_ROWS.len();
                    self.stack.push(Popup::Settings(s));
                }
                KeyCode::Enter => {
                    let row = SETTING_ROWS[s.sel];
                    self.stack.push(Popup::Settings(s));
                    self.open_setting(row, eng);
                }
                _ => {}
            },
            Popup::Profile => {
                if let KeyCode::Char('c') = key.code {
                    let code = self.my_code.clone();
                    self.copy_toast(&code, "friend code скопирован".into());
                    self.stack.push(Popup::Profile);
                }
            }
            Popup::Invite(inv) => {
                if let Some(cmd) = self.invite_key(inv, key) {
                    self.send(eng, cmd);
                }
            }
            // Разобраны выше.
            p @ (Popup::Admin(_) | Popup::Servers(_)) => self.stack.push(p),
        }
        // Закрыли окно — следующее приглашение из очереди.
        self.pump_invites();
    }

    fn input_key(&mut self, mut inp: InputPopup, key: KeyEvent, eng: &dyn EngineApi) {
        match key.code {
            KeyCode::Esc => {}
            KeyCode::Tab => {
                if matches!(inp.action, InputAction::CreateGroup) {
                    inp.private = !inp.private;
                }
                self.stack.push(Popup::Input(inp));
            }
            KeyCode::Backspace => {
                inp.value.pop();
                self.stack.push(Popup::Input(inp));
            }
            KeyCode::Char(c) if !c.is_control() => {
                inp.value.push(c);
                self.stack.push(Popup::Input(inp));
            }
            KeyCode::Enter => {
                let value = inp.value.trim().to_string();
                let action = inp.action;
                let private = inp.private;
                self.submit_input(action, value, private, eng);
            }
            _ => self.stack.push(Popup::Input(inp)),
        }
    }

    fn submit_input(
        &mut self,
        action: InputAction,
        value: String,
        private: bool,
        eng: &dyn EngineApi,
    ) {
        match action {
            InputAction::CreateGroup => {
                if value.is_empty() {
                    self.toast(MsgKind::Error, "пустое имя группы".into());
                    return;
                }
                self.send(
                    eng,
                    Cmd::Create {
                        name: value,
                        private,
                    },
                );
            }
            InputAction::RenameGroup(gid) => {
                if value.is_empty() {
                    return;
                }
                self.send(eng, Cmd::Rename(gid, value));
            }
            InputAction::SetName => {
                self.send(eng, Cmd::SetName(value.clone()));
                self.my_name = value;
            }
            InputAction::SetStatus => {
                self.send(eng, Cmd::SetStatus(value.clone()));
                self.my_status = value;
            }
            InputAction::AddFriend => {
                let mut it = value.splitn(2, char::is_whitespace);
                let code = it.next().unwrap_or("").trim().to_string();
                let alias = it
                    .next()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| code.clone());
                match proto::Identity::parse_friend_code(&code) {
                    Ok(pk) => {
                        if self.friends.iter().any(|f| f.pubkey == pk) {
                            self.toast(MsgKind::Warn, "друг уже есть".into());
                            return;
                        }
                        if self.add_friend(eng, pk, &alias) {
                            self.toast(MsgKind::Ok, format!("друг добавлен: {alias}"));
                        }
                    }
                    Err(e) => {
                        self.toast(MsgKind::Error, format!("неверный friend code: {e}"));
                    }
                }
            }
            InputAction::InviteCode(gid) => match proto::Identity::parse_friend_code(&value) {
                Ok(pk) => {
                    self.send(eng, Cmd::Invite(gid, pk));
                    self.toast(MsgKind::Ok, "приглашение отправлено".into());
                }
                Err(e) => self.toast(MsgKind::Error, format!("неверный friend code: {e}")),
            },
            InputAction::FriendAlias(pk) => match self.rename_friend(eng, pk, &value) {
                Ok(()) => self.toast(MsgKind::Ok, format!("друг переименован: {value}")),
                Err(e) => self.toast(MsgKind::Error, e.to_string()),
            },
            InputAction::Command => {
                if let Err(e) = self.run_command(&value, eng) {
                    self.toast(MsgKind::Error, e.to_string());
                }
            }
        }
    }

    fn confirm_action(&mut self, action: ConfirmAction, eng: &dyn EngineApi) {
        match action {
            ConfirmAction::DeleteGroup(gid) => {
                self.send(eng, Cmd::Delete(gid));
                self.toast(MsgKind::Warn, format!("группа {gid} удаляется"));
            }
            ConfirmAction::LeaveGroup(gid) => {
                self.send(eng, Cmd::Leave(gid));
                self.toast(MsgKind::Info, format!("выходим из {gid}"));
            }
            ConfirmAction::DeleteFriend(alias) => match self.del_friend(eng, &alias) {
                Ok(true) => self.toast(MsgKind::Ok, format!("друг {alias} удалён")),
                Ok(false) => {}
                Err(_) => self.toast(MsgKind::Warn, format!("друг {alias} не найден")),
            },
        }
    }

    // ---------- открытие попапов ----------

    fn open_create_group(&mut self) {
        self.stack.push(Popup::Input(InputPopup {
            title: "Новая группа".into(),
            hint: "имя группы · Tab — приватная · Enter — создать".into(),
            value: String::new(),
            action: InputAction::CreateGroup,
            private: false,
        }));
    }

    fn open_rename(&mut self) {
        match self.selected_group() {
            Some(g) => {
                let gid = g.gid;
                let name = g.name.clone();
                self.stack.push(Popup::Input(InputPopup {
                    title: format!("Переименовать группу {gid}"),
                    hint: "новое имя · Enter — применить".into(),
                    value: name,
                    action: InputAction::RenameGroup(gid),
                    private: false,
                }));
            }
            None => self.toast(MsgKind::Warn, "не выбрана группа".into()),
        }
    }

    fn open_delete_group(&mut self) {
        match self.selected_group() {
            Some(g) if g.owner_is_me => {
                let gid = g.gid;
                let name = g.name.clone();
                self.stack.push(Popup::Confirm(ConfirmPopup {
                    title: "Удалить группу?".into(),
                    message: format!("группа {gid} «{name}» будет удалена у всех участников"),
                    action: ConfirmAction::DeleteGroup(gid),
                }));
            }
            Some(_) => self.toast(MsgKind::Warn, "удалить может только владелец".into()),
            None => self.toast(MsgKind::Warn, "не выбрана группа".into()),
        }
    }

    fn open_leave_group(&mut self) {
        match self.selected_group() {
            Some(g) if g.mine => {
                let gid = g.gid;
                let name = g.name.clone();
                self.stack.push(Popup::Confirm(ConfirmPopup {
                    title: "Покинуть группу?".into(),
                    message: format!("выйти из группы {gid} «{name}»"),
                    action: ConfirmAction::LeaveGroup(gid),
                }));
            }
            Some(_) => self.toast(MsgKind::Warn, "вы не состоите в группе".into()),
            None => self.toast(MsgKind::Warn, "не выбрана группа".into()),
        }
    }

    fn open_add_friend(&mut self) {
        self.stack.push(Popup::Input(InputPopup {
            title: "Добавить друга".into(),
            hint: "friend code (TUN-…) [алиас] · Enter — добавить".into(),
            value: String::new(),
            action: InputAction::AddFriend,
            private: false,
        }));
    }

    fn open_del_friend(&mut self) {
        match self.selected_friend() {
            Some(f) => {
                let alias = f.alias.clone();
                self.stack.push(Popup::Confirm(ConfirmPopup {
                    title: "Удалить друга?".into(),
                    message: format!("друг «{alias}» будет удалён из локального списка"),
                    action: ConfirmAction::DeleteFriend(alias),
                }));
            }
            None => self.toast(MsgKind::Warn, "не выбран друг".into()),
        }
    }

    fn open_pick(&mut self, mode: PickMode) {
        let gid = match self.selected_group() {
            Some(g) => g.gid,
            None => {
                self.toast(MsgKind::Warn, "не выбрана группа".into());
                return;
            }
        };
        let mut items: Vec<PeerChoice> = Vec::new();
        match mode {
            PickMode::Invite => {
                for f in self.friends.iter() {
                    items.push(PeerChoice {
                        pubkey: f.pubkey,
                        label: f.alias.clone(),
                        sub: "друг".into(),
                        online: f.online,
                    });
                }
                if let Some(g) = self.groups.iter().find(|g| g.gid == gid) {
                    for p in g.peers.iter() {
                        items.push(PeerChoice {
                            pubkey: p.pubkey,
                            label: p.name.clone(),
                            sub: proto::ip_str(p.ip),
                            online: p.online,
                        });
                    }
                }
                let mut seen = HashSet::new();
                items.retain(|i| seen.insert(i.pubkey));
                // Ручной ввод friend code (для тех, кто ещё не в друзьях).
                items.push(PeerChoice {
                    pubkey: [0; 32],
                    label: "ввести friend code вручную…".into(),
                    sub: "TUN-…".into(),
                    online: false,
                });
            }
            PickMode::Kick | PickMode::Ban => {
                if let Some(g) = self.groups.iter().find(|g| g.gid == gid) {
                    for p in g.peers.iter() {
                        items.push(PeerChoice {
                            pubkey: p.pubkey,
                            label: p.name.clone(),
                            sub: proto::ip_str(p.ip),
                            online: p.online,
                        });
                    }
                }
            }
        }
        if items.is_empty() {
            self.toast(MsgKind::Warn, "некого выбирать".into());
            return;
        }
        let title = match mode {
            PickMode::Invite => format!("Пригласить в группу {gid}"),
            PickMode::Kick => format!("Исключить из группы {gid}"),
            PickMode::Ban => format!("Забанить в группе {gid}"),
        };
        self.stack.push(Popup::PeerPick(PeerPickPopup {
            gid,
            title,
            mode,
            items,
            sel: 0,
        }));
    }

    fn open_setting(&mut self, row: SettingRow, eng: &dyn EngineApi) {
        match row {
            SettingRow::Name => self.stack.push(Popup::Input(InputPopup {
                title: "Имя профиля".into(),
                hint: "как вас видят другие · Enter — сохранить".into(),
                value: self.my_name.clone(),
                action: InputAction::SetName,
                private: false,
            })),
            SettingRow::Status => self.stack.push(Popup::Input(InputPopup {
                title: "Статус".into(),
                hint: "короткий текст · Enter — сохранить".into(),
                value: self.my_status.clone(),
                action: InputAction::SetStatus,
                private: false,
            })),
            SettingRow::Server => self.open_servers(),
            SettingRow::Autojoin => {
                let items: Vec<ListItem> = self
                    .groups
                    .iter()
                    .filter(|g| g.mine)
                    .map(|g| ListItem {
                        label: format!("{} «{}»", g.gid, g.name),
                        checked: self.autojoin.contains(&g.gid),
                        value: g.gid.to_string(),
                    })
                    .collect();
                if items.is_empty() {
                    self.toast(MsgKind::Warn, "нет групп".into());
                    return;
                }
                self.stack.push(Popup::ListPick(ListPickPopup {
                    title: "Автовход (Enter — переключить)".into(),
                    items,
                    sel: 0,
                    action: ListAction::ToggleAutojoin,
                }));
            }
            SettingRow::Invisible => {
                let on = !self.invisible;
                self.invisible = on;
                self.send(eng, Cmd::SetInvisible(on));
                self.toast(MsgKind::Ok, invisible_msg(on));
            }
            SettingRow::Theme => {
                let kind = self.theme_kind.next();
                self.theme_kind = kind;
                self.status_msg = format!("тема: {}", kind.label());
                self.toast(MsgKind::Ok, format!("тема: {}", kind.label()));
                // Тема — локальная настройка (embedded — client.json,
                // тонкий клиент — ui.json), не команда движку.
                if let Err(e) = eng.save_theme(kind.as_str()) {
                    self.toast(MsgKind::Error, format!("не сохранить тему: {e}"));
                }
            }
        }
    }

    /// «r» в списке друзей: окно нового алиаса выбранного друга.
    fn open_friend_alias(&mut self) {
        match self.selected_friend() {
            Some(f) => {
                let (pk, alias) = (f.pubkey, f.alias.clone());
                self.stack.push(Popup::Input(InputPopup {
                    title: format!("Переименовать друга «{alias}»"),
                    hint: "новый алиас · Enter — сохранить".into(),
                    value: alias,
                    action: InputAction::FriendAlias(pk),
                    private: false,
                }));
            }
            None => self.toast(MsgKind::Warn, "не выбран друг".into()),
        }
    }

    /// Друг по алиасу, friend code или hex.
    fn resolve_friend(&self, token: &str) -> Result<[u8; 32]> {
        resolve_friend_in(&self.cfg_view(), token)
    }

    /// Новый алиас друга: проверка по текущему списку, `Cmd::SetAlias`
    /// движку; в своём списке — сразу (снимок догонит).
    fn rename_friend(&mut self, eng: &dyn EngineApi, pk: [u8; 32], name: &str) -> Result<()> {
        let mut cfg = self.cfg_view();
        rename_friend_in(&mut cfg, &pk, name)?;
        let alias = name.trim().to_string();
        eng.send(Cmd::SetAlias {
            pubkey: pk,
            alias: alias.clone(),
        })?;
        if let Some(f) = self.friends.iter_mut().find(|f| f.pubkey == pk) {
            f.alias = alias;
        }
        Ok(())
    }

    /// Друг в конфиг движка (`Cmd::AddFriend`); в своём списке — сразу.
    /// Отказ — тост, `false`.
    fn add_friend(&mut self, eng: &dyn EngineApi, pk: [u8; 32], alias: &str) -> bool {
        if !self.send(
            eng,
            Cmd::AddFriend {
                pubkey: pk,
                alias: alias.to_string(),
            },
        ) {
            return false;
        }
        if !self.friends.iter().any(|f| f.pubkey == pk) {
            self.friends.push(FriendView {
                alias: alias.to_string(),
                pubkey: pk,
                online: false,
                shared_groups: 0,
            });
        }
        true
    }

    /// Удалить друзей с алиасом `alias` (`Cmd::DelFriend`). `Err` — такого
    /// нет; `Ok(false)` — движок отказал (тост уже показан).
    fn del_friend(&mut self, eng: &dyn EngineApi, alias: &str) -> Result<bool> {
        let pks: Vec<[u8; 32]> = self
            .friends
            .iter()
            .filter(|f| f.alias == alias)
            .map(|f| f.pubkey)
            .collect();
        if pks.is_empty() {
            return Err(anyhow!("друг не найден"));
        }
        for pk in pks {
            if !self.send(eng, Cmd::DelFriend(pk)) {
                return Ok(false);
            }
            self.friends.retain(|f| f.pubkey != pk);
        }
        Ok(true)
    }

    /// Команда движку; отказ (неверная правка конфига, демон недоступен) —
    /// тост и строка лога. `true` — команда принята.
    fn send(&mut self, eng: &dyn EngineApi, cmd: Cmd) -> bool {
        match eng.send(cmd) {
            Ok(()) => true,
            Err(e) => {
                self.log(MsgKind::Error, e.to_string());
                self.toast(MsgKind::Error, e.to_string());
                false
            }
        }
    }

    /// Конфиг, как его видит фронтенд (снимок + свои ещё не подтверждённые
    /// правки): для разбора peer / друга / сервера.
    pub fn cfg_view(&self) -> Config {
        Config {
            name: self.my_name.clone(),
            status: self.my_status.clone(),
            servers: self.servers.clone(),
            friends: self
                .friends
                .iter()
                .map(|f| StoredFriend {
                    pubkey: proto::hex_of(&f.pubkey),
                    alias: f.alias.clone(),
                })
                .collect(),
            autojoin: self.autojoin.clone(),
            theme: self.theme_kind.as_str().to_string(),
            invisible: self.invisible,
            adapter: self.adapter_name.clone(),
            dll: self.dll_path.clone(),
            ..Config::default()
        }
    }

    fn open_command(&mut self) {
        self.stack.push(Popup::Input(InputPopup {
            title: "Команда".into(),
            hint: ":join 1 · :create имя · :help — список команд".into(),
            value: String::new(),
            action: InputAction::Command,
            private: false,
        }));
    }

    fn join_selected(&mut self, eng: &dyn EngineApi) {
        match self.selected_group() {
            Some(g) if !g.mine => {
                let gid = g.gid;
                self.send(eng, Cmd::Join(gid));
                self.toast(MsgKind::Info, format!("входим в группу {gid}"));
            }
            Some(_) => self.toast(MsgKind::Info, "уже в группе".into()),
            None => self.toast(MsgKind::Warn, "не выбрана группа".into()),
        }
    }

    fn copy_context(&mut self) {
        match self.focus {
            Focus::Peers => match self.selected_peer() {
                Some(p) => {
                    let ip = proto::ip_str(p.ip);
                    self.copy_toast(&ip, format!("IP скопирован: {ip}"));
                }
                None => self.toast(MsgKind::Warn, "не выбран участник".into()),
            },
            Focus::Groups => match self.selected_group() {
                Some(g) => {
                    let txt = match g.my_ip {
                        Some(ip) => proto::ip_str(ip),
                        None => g.gid.to_string(),
                    };
                    self.copy_toast(&txt, format!("скопировано: {txt}"));
                }
                None => self.toast(MsgKind::Warn, "не выбрана группа".into()),
            },
            Focus::Friends => match self.selected_friend() {
                Some(f) => {
                    let (hex, alias) = (proto::hex_of(&f.pubkey), f.alias.clone());
                    self.copy_toast(&hex, format!("pubkey скопирован: {alias}"));
                }
                None => self.toast(MsgKind::Warn, "не выбран друг".into()),
            },
            Focus::Log => {}
        }
    }

    // ---------- управление группой ----------

    /// Открыт ли экран управления группой `gid`.
    pub fn admin_open(&self, gid: u32) -> bool {
        self.stack
            .iter()
            .any(|p| matches!(p, Popup::Admin(v) if v.gid == gid))
    }

    /// «m» на выбранной группе: экран управления (только своя группа).
    /// Возвращает запрос данных для движка.
    pub fn open_admin(&mut self) -> Option<Cmd> {
        let Some(gid) = self.sel_group else {
            self.toast(MsgKind::Warn, "не выбрана группа".into());
            return None;
        };
        match self.open_admin_for(gid) {
            Ok(cmd) => Some(cmd),
            Err(e) => {
                self.toast(MsgKind::Warn, e.to_string());
                None
            }
        }
    }

    /// Открывает экран управления группой `gid` → `Cmd::GroupAdmin(gid)`.
    pub fn open_admin_for(&mut self, gid: u32) -> Result<Cmd> {
        let g = self
            .groups
            .iter()
            .find(|g| g.gid == gid)
            .ok_or_else(|| anyhow!("группа {gid} не найдена"))?;
        if !g.owner_is_me {
            return Err(anyhow!("управлять группой может только владелец"));
        }
        let mut v = AdminView::new(gid, g.name.clone());
        v.members = admin_members(g);
        self.stack.push(Popup::Admin(v));
        Ok(Cmd::GroupAdmin(gid))
    }

    /// Ответ ADMIN_INFO: заполнить открытый экран группы `gid`.
    pub fn on_admin_info(
        &mut self,
        gid: u32,
        bans: Vec<([u8; 32], String)>,
        invites: Vec<([u8; 32], String, u32)>,
    ) {
        let members = self.groups.iter().find(|g| g.gid == gid).map(admin_members);
        let bans: Vec<BanEntry> = bans
            .into_iter()
            .map(|(pk, name)| BanEntry { pk, name })
            .collect();
        let invites: Vec<InviteEntry> = invites
            .into_iter()
            .map(|(pk, name, exp)| InviteEntry {
                pk,
                name,
                expires_in_secs: exp as u64,
            })
            .collect();
        for p in self.stack.iter_mut() {
            if let Popup::Admin(v) = p
                && v.gid == gid
            {
                let members = members.clone().unwrap_or_else(|| v.members.clone());
                v.set_data(bans.clone(), invites.clone(), members);
            }
        }
    }

    /// Клавиша в экране управления (он сверху стека): команды движку.
    pub fn admin_key(&mut self, key: KeyEvent) -> Vec<Cmd> {
        let act = match self.stack.last_mut() {
            Some(Popup::Admin(v)) => admin::handle_key(v, key),
            _ => return Vec::new(),
        };
        self.admin_apply(act)
    }

    /// Действие экрана управления → команды движку. После UNBAN / KICK
    /// данные запрашиваются заново; после передачи владения экран закрыт:
    /// управлять группой мы больше не можем.
    pub fn admin_apply(&mut self, act: Option<AdminAction>) -> Vec<Cmd> {
        let name = |a: &App, pk: &[u8; 32]| match a.stack.last() {
            Some(Popup::Admin(v)) => v
                .bans
                .iter()
                .find(|e| &e.pk == pk)
                .map(|e| e.name.clone())
                .or_else(|| {
                    v.invites
                        .iter()
                        .find(|e| &e.pk == pk)
                        .map(|e| e.name.clone())
                })
                .or_else(|| {
                    v.members
                        .iter()
                        .find(|e| &e.pk == pk)
                        .map(|e| e.name.clone())
                })
                .unwrap_or_else(|| proto::hex_of(&pk[..4])),
            _ => proto::hex_of(&pk[..4]),
        };
        match act {
            None => Vec::new(),
            Some(AdminAction::Close) => {
                self.stack.pop();
                Vec::new()
            }
            Some(AdminAction::Refresh(gid)) => vec![Cmd::GroupAdmin(gid)],
            Some(AdminAction::Unban(gid, pk)) => {
                let n = name(self, &pk);
                self.toast(MsgKind::Ok, format!("бан снят: {n}"));
                vec![Cmd::Unban(gid, pk), Cmd::GroupAdmin(gid)]
            }
            Some(AdminAction::RevokeInvite(gid, pk)) => {
                let n = name(self, &pk);
                self.toast(MsgKind::Ok, format!("приглашение отозвано: {n}"));
                vec![Cmd::Kick(gid, pk), Cmd::GroupAdmin(gid)]
            }
            Some(AdminAction::Transfer(gid, pk)) => {
                let n = name(self, &pk);
                self.stack.pop();
                self.toast(MsgKind::Warn, format!("группа {gid} передаётся: {n}"));
                vec![Cmd::Transfer(gid, pk)]
            }
        }
    }

    // ---------- серверы ----------

    /// Индекс текущего сервера в `cfg.servers` (по адресу из движка).
    fn current_server(&self, cfg: &Config) -> usize {
        cfg.servers
            .iter()
            .position(|s| {
                s.addr == self.server_addr
                    || resolve_addr(&s.addr).is_some_and(|a| a.to_string() == self.server_addr)
            })
            .unwrap_or(0)
    }

    /// Экран «Серверы» (F4, `:servers`, настройки).
    pub fn open_servers(&mut self) {
        let cfg = self.cfg_view();
        self.open_servers_with(&cfg);
    }

    pub fn open_servers_with(&mut self, cfg: &Config) {
        let v = ServersView::new(
            server_entries(cfg),
            self.current_server(cfg),
            &self.adapter_name,
            &self.dll_path,
        );
        self.stack.push(Popup::Servers(v));
    }

    /// Ввод в экран «Серверы» (клавиша или мышь — `f`): действие
    /// применяется к копии конфига (экран сразу показывает итог), а движку
    /// уходят команды (`AddServer`, `DelServer`); адаптер и dll — локальная
    /// настройка embedded-движка.
    fn servers_input(
        &mut self,
        eng: &dyn EngineApi,
        f: impl FnOnce(&mut ServersView) -> Option<ServersAction>,
    ) {
        let act = match self.stack.last_mut() {
            Some(Popup::Servers(v)) => f(v),
            _ => return,
        };
        let Some(act) = act else { return };
        let mut cfg = self.cfg_view();
        // Что сказать движку, если действие применится (`save`).
        enum Then {
            Cmd(Cmd),
            Adapter(String, String),
            Nothing,
        }
        let then = match &act {
            ServersAction::Add {
                addr,
                pubkey,
                label,
            } => Then::Cmd(Cmd::AddServer {
                addr: addr.clone(),
                pubkey: *pubkey,
                label: label.clone(),
            }),
            ServersAction::Delete(i) => Then::Cmd(Cmd::DelServer { idx: *i }),
            ServersAction::SetAdapter { name, dll } => Then::Adapter(name.clone(), dll.clone()),
            ServersAction::Close | ServersAction::Switch(_) | ServersAction::Ping(_) => Then::Nothing,
        };
        let (cmd, save) = self.servers_apply(act, &mut cfg);
        if save {
            match then {
                Then::Cmd(c) => {
                    self.send(eng, c);
                }
                Then::Adapter(name, dll) => {
                    if let Err(e) = eng.save_adapter(&name, &dll) {
                        self.toast(MsgKind::Error, format!("не сохранить адаптер: {e}"));
                    }
                }
                Then::Nothing => {}
            }
        }
        if let Some(cmd) = cmd {
            self.send(eng, cmd);
        }
    }

    /// Действие экрана «Серверы» над конфигом. Возвращает команду движку и
    /// признак «конфиг изменён — сохранить».
    pub fn servers_apply(&mut self, act: ServersAction, cfg: &mut Config) -> (Option<Cmd>, bool) {
        match act {
            ServersAction::Close => {
                self.stack.pop();
                (None, false)
            }
            ServersAction::Switch(i) => {
                let Some(s) = cfg.servers.get(i) else {
                    return (None, false);
                };
                let Some(addr) = resolve_addr(&s.addr) else {
                    self.toast(MsgKind::Error, format!("адрес {} не разрешается", s.addr));
                    return (None, false);
                };
                let Some(pubkey) = hex32(&s.pubkey) else {
                    self.toast(MsgKind::Error, format!("неверный ключ сервера {}", s.addr));
                    return (None, false);
                };
                let label = s.label.clone();
                if let Some(Popup::Servers(v)) = self.stack.last_mut() {
                    v.notice = Some(format!("переключаемся на {addr}…"));
                }
                (
                    Some(Cmd::SwitchServer {
                        addr,
                        pubkey,
                        label,
                    }),
                    false,
                )
            }
            ServersAction::Add {
                addr,
                pubkey,
                label,
            } => {
                cfg.servers.push(StoredServer {
                    addr: addr.clone(),
                    pubkey: proto::hex_of(&pubkey),
                    label,
                });
                self.servers = cfg.servers.clone();
                let cur = self.current_server(cfg);
                if let Some(Popup::Servers(v)) = self.stack.last_mut() {
                    v.set_servers(server_entries(cfg), cur);
                    v.sel = v.servers.len().saturating_sub(1);
                    v.notice = Some(format!("сервер {addr} добавлен"));
                }
                (None, true)
            }
            ServersAction::Delete(i) => {
                let cur = self.current_server(cfg);
                if i >= cfg.servers.len() || i == cur {
                    return (None, false);
                }
                let gone = cfg.servers.remove(i);
                self.servers = cfg.servers.clone();
                let cur = self.current_server(cfg);
                if let Some(Popup::Servers(v)) = self.stack.last_mut() {
                    v.set_servers(server_entries(cfg), cur);
                    v.notice = Some(format!("сервер {} удалён", gone.addr));
                }
                (None, true)
            }
            ServersAction::SetAdapter { name, dll } => {
                cfg.adapter = name.clone();
                cfg.dll = dll.clone();
                if let Some(Popup::Servers(v)) = self.stack.last_mut() {
                    v.adapter_name = name;
                    v.dll_path = dll;
                    v.notice =
                        Some("адаптер и dll сохранены — применится после перезапуска".into());
                }
                self.toast(
                    MsgKind::Ok,
                    "адаптер сохранён — применится после перезапуска".into(),
                );
                (None, true)
            }
            ServersAction::Ping(i) => {
                if let Some(s) = cfg.servers.get(i) {
                    let Some(addr) = resolve_addr(&s.addr) else {
                        self.toast(MsgKind::Error, format!("адрес {} не разрешается", s.addr));
                        return (None, false);
                    };
                    (
                        Some(Cmd::PingServer { addr }),
                        false,
                    )
                } else {
                    (None, false)
                }
            }
        }
    }

    /// Движок переключён на `addr`: отметить текущий в открытом экране.
    pub fn on_server_switched(&mut self, addr: std::net::SocketAddr) {
        for p in self.stack.iter_mut() {
            if let Popup::Servers(v) = p
                && let Some(i) = v
                    .servers
                    .iter()
                    .position(|s| s.addr == addr.to_string() || resolve_addr(&s.addr) == Some(addr))
            {
                v.current = i;
                v.sel = i;
                v.notice = Some(format!("текущий сервер: {addr}"));
            }
        }
    }

    /// Мышь в экранах admin / servers (они сверху стека).
    fn screen_mouse(&mut self, m: MouseEvent, eng: &dyn EngineApi) {
        match self.stack.last_mut() {
            Some(Popup::Admin(v)) => {
                let act = admin::handle_mouse(v, m);
                for cmd in self.admin_apply(act) {
                    self.send(eng, cmd);
                }
            }
            Some(Popup::Servers(_)) => {
                self.servers_input(eng, |v| v.handle_mouse(m.kind, m.column, m.row));
            }
            _ => return,
        }
        self.pump_invites();
    }

    // ---------- командная строка ----------

    /// Выполняет команду из строки «:».
    pub fn run_command(&mut self, line: &str, eng: &dyn EngineApi) -> Result<()> {
        match parse_command(line)? {
            Command::Help => self.stack.push(Popup::Help),
            Command::Join(gid) => {
                self.send(eng, Cmd::Join(gid));
            }
            Command::Decline(gid) => {
                if !self.connected {
                    return Err(anyhow!("нет связи с сервером — отказ не отправлен"));
                }
                self.send(eng, Cmd::DeclineInvite(gid));
                self.note_declined(gid);
                self.drop_invite(gid);
            }
            Command::Invites => self.reopen_invites(),
            Command::Leave(gid) => {
                self.send(eng, Cmd::Leave(gid));
            }
            Command::Create { name, private } => {
                self.send(eng, Cmd::Create { name, private });
            }
            Command::Rename(gid, name) => {
                self.send(eng, Cmd::Rename(gid, name));
            }
            Command::Delete(gid) => {
                self.send(eng, Cmd::Delete(gid));
            }
            Command::Invite(gid, peer) => {
                let pk = self.resolve_peer(&peer)?;
                self.send(eng, Cmd::Invite(gid, pk));
            }
            Command::Kick(gid, peer) => {
                let pk = self.resolve_peer(&peer)?;
                self.send(eng, Cmd::Kick(gid, pk));
            }
            Command::Ban(gid, peer) => {
                let pk = self.resolve_peer(&peer)?;
                self.send(eng, Cmd::Ban(gid, pk));
            }
            Command::Unban(gid, peer) => {
                let pk = self.resolve_peer(&peer)?;
                self.send(eng, Cmd::Unban(gid, pk));
            }
            Command::Transfer(gid, peer) => {
                let pk = self.resolve_peer(&peer)?;
                self.send(eng, Cmd::Transfer(gid, pk));
            }
            Command::Admin(gid) => {
                let gid = gid
                    .or(self.sel_group)
                    .ok_or_else(|| anyhow!("не выбрана группа"))?;
                let cmd = self.open_admin_for(gid)?;
                self.send(eng, cmd);
            }
            Command::Servers => self.open_servers(),
            Command::Invisible(on) => {
                self.send(eng, Cmd::SetInvisible(on));
                self.invisible = on;
                self.toast(MsgKind::Ok, invisible_msg(on));
            }
            Command::Server(tok) => {
                let cfg = self.cfg_view();
                let s = cfg
                    .servers
                    .iter()
                    .find(|s| s.addr == tok || (!s.label.is_empty() && s.label == tok))
                    .or_else(|| tok.parse::<usize>().ok().and_then(|n| cfg.servers.get(n)))
                    .ok_or_else(|| anyhow!("сервер {tok:?} не найден"))?;
                let addr: std::net::SocketAddr = s
                    .addr
                    .parse()
                    .map_err(|_| anyhow!("неверный адрес сервера {}", s.addr))?;
                let pubkey = hex32(&s.pubkey).ok_or_else(|| anyhow!("неверный ключ сервера"))?;
                self.send(
                    eng,
                    Cmd::SwitchServer {
                        addr,
                        pubkey,
                        label: s.label.clone(),
                    },
                );
            }
            Command::AddFriend { code, alias } => {
                let pk = proto::Identity::parse_friend_code(&code)?;
                if self.friends.iter().any(|f| f.pubkey == pk) {
                    return Err(anyhow!("друг уже добавлен"));
                }
                self.add_friend(eng, pk, &alias);
            }
            Command::DelFriend(alias) => {
                self.del_friend(eng, &alias)?;
            }
            Command::SetName(name) => {
                self.send(eng, Cmd::SetName(name));
            }
            Command::SetStatus(text) => {
                self.send(eng, Cmd::SetStatus(text));
            }
            Command::Sort(sort) => {
                self.sort = sort;
            }
            Command::Copy(what) => {
                let txt = match what.as_str() {
                    "code" => self.my_code.clone(),
                    "ip" => self
                        .selected_group()
                        .and_then(|g| g.my_ip)
                        .map(proto::ip_str)
                        .unwrap_or_default(),
                    _ => return Err(anyhow!("copy ip|code")),
                };
                if txt.is_empty() {
                    return Err(anyhow!("нечего копировать"));
                }
                copy_to_clipboard(&txt).map_err(|e| anyhow!(e))?;
                self.toast(MsgKind::Ok, format!("скопировано: {txt}"));
            }
            Command::Alias { friend, name } => {
                let pk = self.resolve_friend(&friend)?;
                self.rename_friend(eng, pk, &name)?;
                self.toast(MsgKind::Ok, format!("друг переименован: {name}"));
            }
            Command::Quit => {
                self.quit = true;
                self.send(eng, Cmd::Quit);
            }
        }
        Ok(())
    }

    /// Friend code / hex / alias → pubkey.
    fn resolve_peer(&self, token: &str) -> Result<[u8; 32]> {
        store::resolve_peer(&self.cfg_view(), token)
    }
}

/// Команда командной строки (разбирается независимо от движка).
#[derive(Debug, PartialEq)]
pub enum Command {
    Help,
    Join(u32),
    /// Отклонить приглашение.
    Decline(u32),
    /// Показать отложенные приглашения.
    Invites,
    Leave(u32),
    Create {
        name: String,
        private: bool,
    },
    Rename(u32, String),
    Delete(u32),
    Invite(u32, String),
    Kick(u32, String),
    Ban(u32, String),
    Unban(u32, String),
    Transfer(u32, String),
    /// Экран управления группой (владелец): gid или выбранная группа.
    Admin(Option<u32>),
    /// Экран «Серверы».
    Servers,
    Invisible(bool),
    /// Переключиться на сервер из списка: номер, адрес или метка.
    Server(String),
    AddFriend {
        code: String,
        alias: String,
    },
    DelFriend(String),
    SetName(String),
    SetStatus(String),
    Sort(Sort),
    Copy(String),
    /// Новый алиас друга: `:alias <друг> <имя>`.
    Alias {
        friend: String,
        name: String,
    },
    Quit,
}

/// Разбирает строку командной строки (без ведущего «:»).
pub fn parse_command(line: &str) -> Result<Command> {
    let mut it = line.split_whitespace();
    let cmd = it.next().unwrap_or("").to_lowercase();
    let rest: Vec<&str> = it.collect();
    let gid_of = |i: usize| -> Result<u32> {
        rest.get(i)
            .ok_or_else(|| anyhow!("нужен gid"))?
            .parse::<u32>()
            .map_err(|_| anyhow!("gid должен быть числом"))
    };
    Ok(match cmd.as_str() {
        "" => Command::Help,
        "help" | "?" => Command::Help,
        "join" => Command::Join(gid_of(0)?),
        "decline" => Command::Decline(gid_of(0)?),
        "invites" => Command::Invites,
        "leave" => Command::Leave(gid_of(0)?),
        "create" => {
            let private = rest.contains(&"--private");
            let name = rest
                .iter()
                .filter(|a| **a != "--private")
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");
            if name.is_empty() {
                return Err(anyhow!("нужно имя группы"));
            }
            Command::Create { name, private }
        }
        "rename" => {
            let gid = gid_of(0)?;
            let name = rest[1.min(rest.len())..].join(" ");
            if name.is_empty() {
                return Err(anyhow!("нужно новое имя"));
            }
            Command::Rename(gid, name)
        }
        "delete" => Command::Delete(gid_of(0)?),
        "invite" => Command::Invite(
            gid_of(0)?,
            rest.get(1)
                .ok_or_else(|| anyhow!("нужен peer (friend code | hex | alias)"))?
                .to_string(),
        ),
        "kick" => Command::Kick(
            gid_of(0)?,
            rest.get(1)
                .ok_or_else(|| anyhow!("нужен peer (friend code | hex | alias)"))?
                .to_string(),
        ),
        "ban" => Command::Ban(
            gid_of(0)?,
            rest.get(1)
                .ok_or_else(|| anyhow!("нужен peer (friend code | hex | alias)"))?
                .to_string(),
        ),
        "unban" => Command::Unban(
            gid_of(0)?,
            rest.get(1)
                .ok_or_else(|| anyhow!("нужен peer (friend code | hex | alias)"))?
                .to_string(),
        ),
        "transfer" => Command::Transfer(
            gid_of(0)?,
            rest.get(1)
                .ok_or_else(|| anyhow!("нужен peer (friend code | hex | alias)"))?
                .to_string(),
        ),
        "admin" | "bans" => Command::Admin(if rest.is_empty() {
            None
        } else {
            Some(gid_of(0)?)
        }),
        "servers" => Command::Servers,
        "invisible" => {
            Command::Invisible(match rest.first().map(|s| s.to_lowercase()).as_deref() {
                Some("on") => true,
                Some("off") => false,
                _ => return Err(anyhow!("invisible on|off")),
            })
        }
        "server" => Command::Server(
            rest.first()
                .ok_or_else(|| anyhow!("нужен сервер: номер, адрес или метка"))?
                .to_string(),
        ),
        "friend" => {
            let code = rest
                .first()
                .ok_or_else(|| anyhow!("нужен friend code"))?
                .to_string();
            let alias = rest
                .get(1)
                .map(|s| s.to_string())
                .unwrap_or_else(|| code.clone());
            Command::AddFriend { code, alias }
        }
        "delfriend" => Command::DelFriend(
            rest.first()
                .ok_or_else(|| anyhow!("нужен alias друга"))?
                .to_string(),
        ),
        "name" => {
            let name = rest.join(" ");
            if name.is_empty() {
                return Err(anyhow!("нужно имя"));
            }
            Command::SetName(name)
        }
        "status" => Command::SetStatus(rest.join(" ")),
        "sort" => {
            let mode = rest.first().copied().unwrap_or("name").to_lowercase();
            Command::Sort(match mode.as_str() {
                "online" => Sort::Online,
                "rtt" => Sort::Rtt,
                _ => Sort::Name,
            })
        }
        "copy" => Command::Copy(rest.first().copied().unwrap_or("ip").to_lowercase()),
        "alias" => {
            let friend = rest
                .first()
                .ok_or_else(|| anyhow!("alias <друг> <новое имя>"))?
                .to_string();
            let name = rest[1.min(rest.len())..].join(" ");
            if name.is_empty() {
                return Err(anyhow!("нужно новое имя друга"));
            }
            Command::Alias { friend, name }
        }
        "quit" | "q" => Command::Quit,
        other => return Err(anyhow!("неизвестная команда: {other}")),
    })
}

// ---------------------------------------------------------------- утилиты

pub fn hex32(s: &str) -> Option<[u8; 32]> {
    let v = proto::hex_to_bytes(s).ok()?;
    if v.len() != 32 {
        return None;
    }
    Some(v.try_into().unwrap())
}

/// Участники группы — кандидаты на передачу владения.
fn admin_members(g: &GroupView) -> Vec<MemberEntry> {
    g.peers
        .iter()
        .map(|p| MemberEntry {
            pk: p.pubkey,
            name: p.name.clone(),
            ip: std::net::Ipv4Addr::from(p.ip),
        })
        .collect()
}

/// Серверы конфига для экрана «Серверы».
fn server_entries(cfg: &Config) -> Vec<ServerEntry> {
    cfg.servers
        .iter()
        .map(|s| ServerEntry {
            label: s.label.clone(),
            addr: s.addr.clone(),
            pubkey: hex32(&s.pubkey).unwrap_or([0; 32]),
            ping_ms: None,
        })
        .collect()
}

/// `ip:port` или `host:port` → адрес (первый из разрешённых).
fn resolve_addr(addr: &str) -> Option<std::net::SocketAddr> {
    if let Ok(a) = addr.parse() {
        return Some(a);
    }
    use std::net::ToSocketAddrs;
    addr.to_socket_addrs().ok()?.next()
}

/// Копирование в системный буфер обмена (через SSH — OSC 52 первым).
pub fn copy_to_clipboard(text: &str) -> std::result::Result<(), String> {
    clipboard::copy(text).map(|_| ())
}

/// Символьная клавиша в русской раскладке → та же клавиша в латинице.
pub fn latin_key(mut key: KeyEvent) -> KeyEvent {
    if let KeyCode::Char(c) = key.code {
        key.code = KeyCode::Char(keymap::latin(c));
    }
    key
}

fn invisible_msg(on: bool) -> String {
    format!(
        "невидимка {}",
        if on {
            "включена"
        } else {
            "выключена"
        }
    )
}

/// Друг по алиасу, friend code или hex (только из списка друзей).
pub fn resolve_friend_in(cfg: &Config, token: &str) -> Result<[u8; 32]> {
    if let Some(f) = cfg.friends.iter().find(|f| f.alias == token) {
        return hex32(&f.pubkey).ok_or_else(|| anyhow!("неверный pubkey друга {token}"));
    }
    let pk = store::resolve_peer(cfg, token)?;
    let hex = proto::hex_of(&pk);
    if cfg.friends.iter().any(|f| f.pubkey == hex) {
        Ok(pk)
    } else {
        Err(anyhow!("друг {token:?} не найден"))
    }
}

/// Меняет алиас друга в конфиге. Алиас не пустой и не занят другим другом.
pub fn rename_friend_in(cfg: &mut Config, pk: &[u8; 32], name: &str) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err(anyhow!("пустой алиас"));
    }
    let hex = proto::hex_of(pk);
    if cfg
        .friends
        .iter()
        .any(|f| f.alias == name && f.pubkey != hex)
    {
        return Err(anyhow!("алиас «{name}» уже занят"));
    }
    let f = cfg
        .friends
        .iter_mut()
        .find(|f| f.pubkey == hex)
        .ok_or_else(|| anyhow!("друг не найден"))?;
    f.alias = name.to_string();
    Ok(())
}

// ---------------------------------------------------------------- тесты

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        let cfg = Config {
            name: "alpha".into(),
            status: "тест".into(),
            ..Config::default()
        };
        App::new([7; 32], "TUN-TEST-CODE", &cfg)
    }

    #[test]
    fn парс_команд_базовые() {
        assert_eq!(parse_command("help").unwrap(), Command::Help);
        assert_eq!(parse_command("join 3").unwrap(), Command::Join(3));
        assert_eq!(parse_command("leave 4").unwrap(), Command::Leave(4));
        assert_eq!(
            parse_command("create gamers").unwrap(),
            Command::Create {
                name: "gamers".into(),
                private: false
            }
        );
        assert_eq!(
            parse_command("create secret --private").unwrap(),
            Command::Create {
                name: "secret".into(),
                private: true
            }
        );
        assert_eq!(
            parse_command("rename 2 my net").unwrap(),
            Command::Rename(2, "my net".into())
        );
        assert_eq!(parse_command("quit").unwrap(), Command::Quit);
        assert_eq!(parse_command("sort rtt").unwrap(), Command::Sort(Sort::Rtt));
        assert_eq!(
            parse_command("copy code").unwrap(),
            Command::Copy("code".into())
        );
    }

    #[test]
    fn парс_команд_ошибки() {
        assert!(parse_command("join").is_err());
        assert!(parse_command("join x").is_err());
        assert!(parse_command("create").is_err());
        assert!(parse_command("бла").is_err());
    }

    #[test]
    fn фильтр_групп_и_друзей() {
        let mut a = app();
        a.groups = vec![
            GroupView {
                gid: 1,
                name: "gamers".into(),
                private: false,
                mine: true,
                online: 2,
                total: 3,
                my_ip: Some(0x6442_0002),
                owner_is_me: true,
                peers: vec![],
            },
            GroupView {
                gid: 2,
                name: "work".into(),
                private: true,
                mine: false,
                online: 0,
                total: 1,
                my_ip: None,
                owner_is_me: false,
                peers: vec![],
            },
        ];
        a.friends = vec![FriendView {
            alias: "bravo".into(),
            pubkey: [1; 32],
            online: true,
            shared_groups: 1,
        }];
        a.filter = "game".into();
        assert_eq!(a.visible_groups().len(), 1);
        assert_eq!(a.visible_groups()[0].gid, 1);
        assert_eq!(a.visible_friends().len(), 0);
        a.filter = "bra".into();
        assert_eq!(a.visible_groups().len(), 0);
        assert_eq!(a.visible_friends().len(), 1);
    }

    #[test]
    fn сортировка_переключается_по_кругу() {
        assert_eq!(Sort::Name.next(), Sort::Online);
        assert_eq!(Sort::Online.next(), Sort::Rtt);
        assert_eq!(Sort::Rtt.next(), Sort::Name);
    }

    #[test]
    fn шаг_по_списку() {
        // Стрелки — по кругу.
        assert_eq!(step(0, 3, -1, true), 2);
        assert_eq!(step(2, 3, 1, true), 0);
        // Home/End и колесо — упор в края (раньше Home на 7 строках давал 1).
        assert_eq!(step(0, 7, -1000, false), 0);
        assert_eq!(step(3, 7, 1000, false), 6);
        assert_eq!(step(0, 0, 1, false), 0);
    }

    // ---------- приглашения ----------

    fn inv(gid: u32) -> InvitePopup {
        InvitePopup {
            gid,
            group_name: format!("g{gid}"),
            from_name: "bravo-srv".into(),
            from_pubkey: [2; 32],
            // Пришло давно: сверка со списком сервера его не щадит.
            received_at: Instant::now()
                .checked_sub(INVITE_SYNC_GRACE * 2)
                .unwrap_or_else(Instant::now),
            expires_at: None,
            shown_at: None,
        }
    }

    /// Онлайн-приложение с выключенной защитой от случайного нажатия.
    fn online() -> App {
        let mut a = app();
        a.connected = true;
        a
    }

    fn shown_gid(a: &App) -> Option<u32> {
        match a.stack.last() {
            Some(Popup::Invite(i)) => Some(i.gid),
            _ => None,
        }
    }

    /// Нажатие в окне приглашения — как `handle_popup_key`, без движка.
    /// Защита первых мгновений снимается (её проверяет отдельный тест).
    fn press(a: &mut App, code: KeyCode) -> Option<Cmd> {
        let Some(Popup::Invite(mut i)) = a.stack.pop() else {
            panic!("нет окна приглашения");
        };
        i.shown_at = None;
        let cmd = a.invite_key(i, key(code));
        a.pump_invites();
        cmd
    }

    #[test]
    fn приглашение_открывает_окно_принять_шлёт_join() {
        let mut a = online();
        a.on_invite(inv(5), false);
        assert_eq!(shown_gid(&a), Some(5));
        assert!(
            a.toasts.iter().any(|t| t.text.contains("g5")),
            "тост остаётся"
        );
        assert!(
            a.log.iter().any(|l| l.text.contains("g5")),
            "строка лога остаётся"
        );
        // Посторонняя клавиша окно не закрывает и ничего не шлёт.
        assert!(press(&mut a, KeyCode::Char('z')).is_none());
        assert_eq!(shown_gid(&a), Some(5));
        assert!(matches!(press(&mut a, KeyCode::Enter), Some(Cmd::Join(5))));
        assert!(a.stack.is_empty());
        // До GroupJoined приглашение хранится: JOIN может не пройти
        // («группа заполнена»), к нему можно вернуться через «o».
        assert!(a.has_invite(5));
        a.reopen_invites();
        assert_eq!(shown_gid(&a), Some(5));
        a.drop_invite(5); // GroupJoined
        assert!(a.stack.is_empty() && !a.has_invite(5));

        a.on_invite(inv(6), false);
        assert!(matches!(
            press(&mut a, KeyCode::Char('y')),
            Some(Cmd::Join(6))
        ));
        // Русская раскладка: «н» на месте «y», но читается как «нет» —
        // не принимает (и не отклоняет), окно остаётся, видна подсказка.
        a.on_invite(inv(7), false);
        assert!(press(&mut a, KeyCode::Char('н')).is_none());
        assert!(press(&mut a, KeyCode::Char('Н')).is_none());
        assert_eq!(shown_gid(&a), Some(7));
        assert!(a.status_msg.contains("Enter/y"));
        assert!(matches!(press(&mut a, KeyCode::Enter), Some(Cmd::Join(7))));
    }

    #[test]
    fn смена_сервера_сбрасывает_приглашения_старого() {
        let a1: std::net::SocketAddr = "10.0.0.1:5599".parse().unwrap();
        let a2: std::net::SocketAddr = "10.0.0.2:5599".parse().unwrap();
        let mut a = online();
        a.on_server(a1);
        a.on_invite(inv(1), false);
        a.on_invite(inv(2), false);
        a.on_invite(inv(3), false);
        assert!(press(&mut a, KeyCode::Esc).is_none()); // 1 — «позже»
        assert!(matches!(
            press(&mut a, KeyCode::Char('n')),
            Some(Cmd::DeclineInvite(2))
        ));
        assert_eq!(shown_gid(&a), Some(3));
        a.stack.push(Popup::Confirm(ConfirmPopup {
            title: String::new(),
            message: String::new(),
            action: ConfirmAction::LeaveGroup(9),
        }));
        a.stack.push(Popup::Help);
        // Переподключение к тому же серверу ничего не трогает.
        a.on_server(a1);
        assert!(a.has_invite(1) && a.has_invite(3) && a.stack.len() == 3);
        // Другой сервер: ни окна, ни очереди, ни «позже», ни окон с gid.
        a.on_server(a2);
        assert!(!a.has_invite(1) && !a.has_invite(3));
        assert!(a.invites.is_empty() && a.later_invites.is_empty() && a.declined.is_empty());
        assert!(
            matches!(a.stack.as_slice(), [Popup::Help]),
            "окна без gid остаются"
        );
        a.reopen_invites();
        assert!(
            shown_gid(&a).is_none(),
            "«o» не вернёт приглашение старого сервера"
        );
        // Отказ на старом сервере не глушит приглашение с тем же gid на новом.
        a.stack.clear();
        a.on_invite(inv(2), false);
        assert_eq!(shown_gid(&a), Some(2));
    }

    #[test]
    fn приглашение_отклонить_шлёт_decline() {
        let mut a = online();
        a.on_invite(inv(3), false);
        assert!(matches!(
            press(&mut a, KeyCode::Char('n')),
            Some(Cmd::DeclineInvite(3))
        ));
        assert!(a.stack.is_empty() && !a.has_invite(3));
        a.on_invite(inv(4), false);
        assert!(matches!(
            press(&mut a, KeyCode::Char('т')),
            Some(Cmd::DeclineInvite(4))
        ));
    }

    #[test]
    fn приглашение_esc_откладывает_ничего_не_шлёт() {
        let mut a = online();
        a.on_invite(inv(8), false);
        assert!(press(&mut a, KeyCode::Esc).is_none());
        assert!(a.stack.is_empty());
        assert_eq!(a.later_invites.len(), 1, "приглашение не потеряно");
        // Повторная доставка (после HELLO) отложенное не открывает.
        a.on_invite(inv(8), false);
        assert!(a.stack.is_empty());
        assert_eq!(a.later_invites.len(), 1);
        // «o» — вернуться к отложенным.
        a.reopen_invites();
        assert_eq!(shown_gid(&a), Some(8));
        assert!(a.later_invites.is_empty());
        assert!(matches!(press(&mut a, KeyCode::Enter), Some(Cmd::Join(8))));
    }

    #[test]
    fn приглашения_в_очереди_по_одному_без_дубликатов() {
        let mut a = online();
        a.on_invite(inv(1), false);
        a.on_invite(inv(2), false);
        a.on_invite(inv(1), false);
        a.on_invite(inv(2), false);
        assert_eq!(a.stack.len(), 1, "окна не складываются стопкой");
        assert_eq!(shown_gid(&a), Some(1));
        assert_eq!(a.invites.len(), 1);
        // Дубликат обновляет данные, но не добавляет окно.
        let mut renamed = inv(2);
        renamed.group_name = "новое имя".into();
        a.on_invite(renamed, false);
        assert_eq!(a.invites.len(), 1);
        assert_eq!(a.invites[0].group_name, "новое имя");
        // Ответ на первое — сразу показывается второе.
        assert!(matches!(
            press(&mut a, KeyCode::Char('n')),
            Some(Cmd::DeclineInvite(1))
        ));
        assert_eq!(shown_gid(&a), Some(2));
        assert!(matches!(press(&mut a, KeyCode::Enter), Some(Cmd::Join(2))));
        assert!(a.stack.is_empty() && a.invites.is_empty());
    }

    #[test]
    fn приглашение_не_перекрывает_открытое_окно() {
        let mut a = online();
        a.open_create_group();
        a.on_invite(inv(9), false);
        assert!(
            matches!(a.stack.last(), Some(Popup::Input(_))),
            "ввод пользователя не тронут"
        );
        assert_eq!(a.stack.len(), 1);
        assert_eq!(a.invites.len(), 1);
        // Окно ввода закрыли — приглашение показывается.
        a.stack.pop();
        a.pump_invites();
        assert_eq!(shown_gid(&a), Some(9));
    }

    #[test]
    fn приглашение_не_всплывает_в_строке_поиска() {
        let mut a = online();
        a.filtering = true;
        a.on_invite(inv(9), false);
        assert!(
            a.stack.is_empty(),
            "буквы фильтра ушли бы в окно приглашения"
        );
        assert_eq!(a.invites.len(), 1);
        a.pump_invites();
        assert!(a.stack.is_empty());
        // Поиск закрыт — приглашение показывается.
        a.filtering = false;
        a.pump_invites();
        assert_eq!(shown_gid(&a), Some(9));
    }

    #[test]
    fn ctrl_c_откладывает_всю_очередь_приглашений() {
        let mut a = online();
        for g in [1, 2, 3] {
            a.on_invite(inv(g), false);
        }
        let Some(Popup::Invite(i)) = a.stack.pop() else {
            panic!()
        };
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(a.invite_key(i, ctrl_c).is_none());
        a.pump_invites();
        assert!(
            a.stack.is_empty(),
            "следующий Ctrl-C должен выйти, а не открыть окно"
        );
        assert!(a.invites.is_empty());
        let later: Vec<u32> = a.later_invites.iter().map(|i| i.gid).collect();
        assert_eq!(later, vec![1, 2, 3], "ничего не потеряно, порядок тот же");
    }

    #[test]
    fn полный_список_с_сервера_снимает_устаревшие_приглашения() {
        let mut a = online();
        for g in [1, 2, 3] {
            a.on_invite(inv(g), false);
        }
        let _ = press(&mut a, KeyCode::Esc); // 1 отложено, на экране 2, в очереди 3
        // Пока были офлайн, группу 1 удалили, а 2 отозвали.
        let gone = a.sync_invites(&[3], 0, true);
        assert_eq!(gone, vec![(2, "g2".to_string()), (1, "g1".to_string())]);
        assert_eq!(shown_gid(&a), Some(3));
        assert!(!a.has_invite(1) && !a.has_invite(2) && a.later_invites.is_empty());
        assert!(a.sync_invites(&[3], 0, true).is_empty());
    }

    #[test]
    fn неполный_список_снимает_устаревшие_только_до_последнего_gid() {
        let mut a = online();
        for g in [1, 2, 3, 20, 30] {
            a.on_invite(inv(g), false);
        }
        // Сервер обрезал список после gid 3 (больше 16 приглашений): 2
        // отозвано, а про 20 и 30 список ничего не говорит.
        let gone = a.sync_invites(&[1, 3], 0, false);
        assert_eq!(gone, vec![(2, "g2".to_string())]);
        assert!(a.has_invite(1) && a.has_invite(3) && a.has_invite(20) && a.has_invite(30));
        // Пустой неполный список ничего не снимает.
        assert!(a.sync_invites(&[], 0, false).is_empty());
        // Полный — снимает и хвост.
        let gone = a.sync_invites(&[1, 3, 30], 0, true);
        assert_eq!(gone, vec![(20, "g20".to_string())]);
    }

    #[test]
    fn окно_списка_снимает_устаревшие_только_в_своих_границах() {
        let mut a = online();
        for g in [1, 2, 17, 18, 25, 40] {
            a.on_invite(inv(g), false);
        }
        // Следующее окно (gid ≥ 17, неполное, до 25): 18 отозвано, а про 1,
        // 2 и 40 окно ничего не говорит.
        let gone = a.sync_invites(&[17, 25], 17, false);
        assert_eq!(gone, vec![(18, "g18".to_string())]);
        assert!(a.has_invite(1) && a.has_invite(2) && a.has_invite(40));
        // Полное окно с 17 снимает хвост, но не начало.
        let gone = a.sync_invites(&[17, 25], 17, true);
        assert_eq!(gone, vec![(40, "g40".to_string())]);
        assert!(a.has_invite(1) && a.has_invite(2));
    }

    #[test]
    fn запоздавший_список_не_возвращает_отклонённое_приглашение() {
        let mut a = online();
        a.on_invite(inv(1), false);
        a.on_invite(inv(2), false);
        // Отклонили 1, затем 2 (защиту от промаха press() снимает).
        assert!(matches!(
            press(&mut a, KeyCode::Char('n')),
            Some(Cmd::DeclineInvite(1))
        ));
        assert!(matches!(
            press(&mut a, KeyCode::Char('n')),
            Some(Cmd::DeclineInvite(2))
        ));
        assert!(!a.has_invite(2));
        // Ответ на отказ от 1 пришёл поздно — собран до отказа от 2: [2].
        let mut stale = inv(2);
        stale.received_at = Instant::now();
        a.on_invite(stale, false);
        assert!(
            !a.has_invite(2) && a.stack.is_empty(),
            "отклонённое снова на экране"
        );
        assert!(a.sync_invites(&[2], 0, true).is_empty());
        // То же для `:decline`-пути — через note_declined.
        a.on_invite(inv(3), false);
        a.note_declined(3);
        a.drop_invite(3);
        a.on_invite(inv(3), false);
        assert!(!a.has_invite(3));
        // Спустя INVITE_DECLINE_MEMORY повторное приглашение снова видно.
        for d in a.declined.iter_mut() {
            d.1 = Instant::now()
                .checked_sub(INVITE_DECLINE_MEMORY * 2)
                .unwrap_or_else(Instant::now);
        }
        a.on_invite(inv(2), false);
        assert!(a.has_invite(2));
    }

    #[test]
    fn список_после_отклонённого_входа_снимает_принятое_приглашение() {
        let mut a = online();
        a.on_invite(inv(7), false);
        assert!(matches!(press(&mut a, KeyCode::Enter), Some(Cmd::Join(7))));
        assert!(a.has_invite(7), "держится до GroupJoined");
        // JOIN отклонён (приглашение отозвано) — сервер прислал список без 7.
        let gone = a.sync_invites(&[], 0, true);
        assert_eq!(gone, vec![(7, "g7".to_string())]);
        assert!(!a.has_invite(7) && a.later_invites.is_empty());
    }

    #[test]
    fn сверка_не_снимает_только_что_пришедшее_приглашение() {
        let mut a = online();
        a.on_invite(inv(1), false);
        let mut fresh = inv(2);
        fresh.received_at = Instant::now();
        a.on_invite(fresh, false);
        // Список собран сервером до приглашения 2 и пришёл после него.
        let gone = a.sync_invites(&[], 0, true);
        assert_eq!(gone, vec![(1, "g1".to_string())]);
        assert!(
            a.has_invite(2),
            "свежее приглашение не снято устаревшим списком"
        );
    }

    #[test]
    fn запоздавшая_карточка_друга_не_ложится_на_приглашение() {
        let mut a = online();
        a.on_invite(inv(4), false);
        a.on_friend_groups([7; 32], vec![]);
        assert_eq!(a.stack.len(), 1);
        assert_eq!(shown_gid(&a), Some(4));
        // Без окна приглашения ответ открывает карточку, как раньше.
        a.stack.clear();
        a.on_friend_groups([7; 32], vec![]);
        assert!(matches!(a.stack.last(), Some(Popup::FriendCard(_))));
    }

    #[test]
    fn приглашение_защита_от_случайного_нажатия() {
        let mut a = online();
        a.on_invite(inv(4), false);
        // Окно только что появилось: Enter и «n» не отвечают.
        let Some(Popup::Invite(i)) = a.stack.pop() else {
            panic!()
        };
        assert!(i.shown_at.is_some());
        assert!(a.invite_key(i, key(KeyCode::Enter)).is_none());
        assert_eq!(shown_gid(&a), Some(4));
        let Some(Popup::Invite(i)) = a.stack.pop() else {
            panic!()
        };
        assert!(a.invite_key(i, key(KeyCode::Char('n'))).is_none());
        assert_eq!(shown_gid(&a), Some(4));
        // Esc («Позже») — сразу; приглашение не отклонено.
        let Some(Popup::Invite(i)) = a.stack.pop() else {
            panic!()
        };
        assert!(a.invite_key(i, key(KeyCode::Esc)).is_none());
        assert!(a.stack.is_empty());
        assert!(a.has_invite(4));
        // Ctrl-«n» / Ctrl-C — тоже только «Позже».
        a.reopen_invites();
        let Some(Popup::Invite(mut i)) = a.stack.pop() else {
            panic!()
        };
        i.shown_at = None;
        let ctrl_n = KeyEvent::new(KeyCode::Char('n'), KeyModifiers::CONTROL);
        assert!(a.invite_key(i, ctrl_n).is_none());
        assert!(a.stack.is_empty() && a.has_invite(4));
    }

    #[test]
    fn приглашение_снимается_при_входе_и_удалении() {
        let mut a = online();
        a.on_invite(inv(1), false);
        a.on_invite(inv(2), false);
        a.on_invite(inv(3), false);
        let _ = press(&mut a, KeyCode::Esc); // 1 отложено, на экране 2
        assert_eq!(shown_gid(&a), Some(2));
        a.drop_invite(2); // вошли в 2 другим путём — окно закрыто, следующее
        assert_eq!(shown_gid(&a), Some(3));
        a.drop_invite(1); // отложенное тоже убирается
        a.drop_invite(3);
        assert!(a.stack.is_empty() && a.invites.is_empty() && a.later_invites.is_empty());
    }

    #[test]
    fn приглашение_без_связи_и_уже_в_группе() {
        let mut a = app(); // не подключено
        a.on_invite(inv(5), false);
        assert!(
            press(&mut a, KeyCode::Enter).is_none(),
            "без связи команда не уйдёт"
        );
        assert!(a.has_invite(5), "приглашение отложено, не потеряно");
        // Уже участник / автовход — окна нет, только лог.
        let mut a = online();
        a.on_invite(inv(6), true);
        assert!(a.stack.is_empty() && !a.has_invite(6));
        assert!(a.log.iter().any(|l| l.text.contains("g6")));
    }

    #[test]
    fn приглашение_от_друга_показывает_алиас() {
        let mut a = online();
        assert_eq!(a.invite_from_label(&inv(1)), "bravo-srv");
        a.friends = vec![FriendView {
            alias: "Боря".into(),
            pubkey: [2; 32],
            online: true,
            shared_groups: 0,
        }];
        assert_eq!(a.invite_from_label(&inv(1)), "Боря (bravo-srv)");
    }

    #[test]
    fn парс_команд_приглашений() {
        assert_eq!(parse_command("decline 4").unwrap(), Command::Decline(4));
        assert_eq!(parse_command("invites").unwrap(), Command::Invites);
        assert!(parse_command("decline").is_err());
    }

    // ---------- экраны «Управление группой» и «Серверы» ----------

    fn owner_app() -> App {
        let mut a = app();
        a.groups = vec![
            GroupView {
                gid: 1,
                name: "gamers".into(),
                private: false,
                mine: true,
                online: 2,
                total: 2,
                my_ip: Some(0x6442_0102),
                owner_is_me: true,
                peers: vec![PeerView {
                    pubkey: [2; 32],
                    name: "bravo".into(),
                    ip: 0x6442_0103,
                    online: true,
                    direct: false,
                    rtt_ms: None,
                    status: String::new(),
                }],
            },
            GroupView {
                gid: 2,
                name: "чужая".into(),
                private: false,
                mine: true,
                online: 1,
                total: 2,
                my_ip: Some(0x6442_0202),
                owner_is_me: false,
                peers: vec![],
            },
        ];
        a.sel_group = Some(1);
        a
    }

    fn admin_view(a: &App) -> &AdminView {
        match a.stack.last() {
            Some(Popup::Admin(v)) => v,
            _ => panic!("экран управления не открыт"),
        }
    }

    #[test]
    fn управление_группой_открыть_получить_снять_бан_отозвать_передать() {
        let mut a = owner_app();
        assert!(matches!(a.open_admin(), Some(Cmd::GroupAdmin(1))));
        assert_eq!(
            admin_view(&a).members.len(),
            1,
            "кандидаты на передачу — участники группы"
        );
        assert!(a.admin_open(1));

        a.on_admin_info(
            1,
            vec![([3; 32], "charlie".into())],
            vec![([4; 32], "delta".into(), 3600)],
        );
        let v = admin_view(&a);
        assert_eq!(v.bans.len(), 1);
        assert_eq!(v.invites[0].expires_in_secs, 3600);

        // Разбанить → UNBAN и повторный запрос данных.
        let cmds = a.admin_key(key(KeyCode::Enter));
        assert!(
            matches!(cmds[..], [Cmd::Unban(1, pk), Cmd::GroupAdmin(1)] if pk == [3; 32]),
            "{cmds:?}"
        );
        // Отозвать приглашение → KICK приглашённого и обновление.
        assert!(a.admin_key(key(KeyCode::Char('2'))).is_empty());
        let cmds = a.admin_key(key(KeyCode::Enter));
        assert!(
            matches!(cmds[..], [Cmd::Kick(1, pk), Cmd::GroupAdmin(1)] if pk == [4; 32]),
            "{cmds:?}"
        );
        // r — обновить.
        assert!(matches!(
            a.admin_key(key(KeyCode::Char('r')))[..],
            [Cmd::GroupAdmin(1)]
        ));
        // Передача — только после явного «y».
        assert!(a.admin_key(key(KeyCode::Char('3'))).is_empty());
        assert!(
            a.admin_key(key(KeyCode::Enter)).is_empty(),
            "Enter лишь открывает подтверждение"
        );
        assert!(admin_view(&a).confirm.is_some());
        assert!(
            a.admin_key(key(KeyCode::Enter)).is_empty(),
            "повторный Enter не передаёт"
        );
        let cmds = a.admin_key(key(KeyCode::Char('y')));
        assert!(
            matches!(cmds[..], [Cmd::Transfer(1, pk)] if pk == [2; 32]),
            "{cmds:?}"
        );
        assert!(a.stack.is_empty(), "после передачи экран закрыт");
    }

    #[test]
    fn управление_группой_только_владельцу_и_esc_закрывает() {
        let mut a = owner_app();
        a.sel_group = Some(2);
        assert!(a.open_admin().is_none());
        assert!(a.stack.is_empty());
        assert!(a.toasts.iter().any(|t| t.text.contains("владелец")));
        assert!(a.open_admin_for(7).is_err());

        a.sel_group = Some(1);
        a.open_admin().unwrap();
        // Ответ по другой группе экран не трогает.
        a.on_admin_info(2, vec![([3; 32], "x".into())], vec![]);
        assert!(admin_view(&a).bans.is_empty());
        assert!(a.admin_key(key(KeyCode::Esc)).is_empty());
        assert!(a.stack.is_empty());
    }

    #[test]
    fn парс_команд_экранов() {
        assert_eq!(parse_command("admin").unwrap(), Command::Admin(None));
        assert_eq!(parse_command("admin 5").unwrap(), Command::Admin(Some(5)));
        assert_eq!(parse_command("bans 6").unwrap(), Command::Admin(Some(6)));
        assert!(parse_command("admin x").is_err());
        assert_eq!(parse_command("servers").unwrap(), Command::Servers);
    }

    fn servers_cfg() -> Config {
        Config {
            servers: vec![
                StoredServer {
                    addr: "127.0.0.1:5599".into(),
                    pubkey: proto::hex_of(&[1; 32]),
                    label: "дом".into(),
                },
                StoredServer {
                    addr: "127.0.0.2:5600".into(),
                    pubkey: proto::hex_of(&[2; 32]),
                    label: String::new(),
                },
            ],
            ..Config::default()
        }
    }

    /// Клавиша в экране «Серверы» и применение действия к конфигу.
    fn srv_key(a: &mut App, cfg: &mut Config, code: KeyCode) -> (Option<Cmd>, bool) {
        let act = match a.stack.last_mut() {
            Some(Popup::Servers(v)) => v.handle_key(key(code)),
            _ => panic!("экран серверов не открыт"),
        };
        match act {
            Some(act) => a.servers_apply(act, cfg),
            None => (None, false),
        }
    }

    fn srv_type(a: &mut App, cfg: &mut Config, text: &str) {
        for c in text.chars() {
            srv_key(a, cfg, KeyCode::Char(c));
        }
    }

    fn servers_view(a: &App) -> &ServersView {
        match a.stack.last() {
            Some(Popup::Servers(v)) => v,
            _ => panic!("экран серверов не открыт"),
        }
    }

    #[test]
    fn серверы_переключение_без_перезапуска() {
        let mut a = app();
        let mut cfg = servers_cfg();
        a.server_addr = "127.0.0.1:5599".into();
        a.open_servers_with(&cfg);
        assert_eq!(servers_view(&a).current, 0);
        srv_key(&mut a, &mut cfg, KeyCode::Down);
        let (cmd, save) = srv_key(&mut a, &mut cfg, KeyCode::Enter);
        match cmd {
            Some(Cmd::SwitchServer { addr, pubkey, .. }) => {
                assert_eq!(addr.to_string(), "127.0.0.2:5600");
                assert_eq!(pubkey, [2; 32]);
            }
            other => panic!("{other:?}"),
        }
        assert!(!save);
        // Движок сообщил о переключении — текущий отмечен.
        a.on_server_switched("127.0.0.2:5600".parse().unwrap());
        assert_eq!(servers_view(&a).current, 1);
        assert!(matches!(
            srv_key(&mut a, &mut cfg, KeyCode::Esc),
            (None, false)
        ));
        assert!(a.stack.is_empty());
    }

    #[test]
    fn серверы_добавить_удалить_адаптер_сохраняются_в_конфиг() {
        let mut a = app();
        let mut cfg = servers_cfg();
        a.server_addr = "127.0.0.1:5599".into();
        a.adapter_name = "TunnelVPN".into();
        a.open_servers_with(&cfg);

        // Добавить.
        srv_key(&mut a, &mut cfg, KeyCode::Char('a'));
        srv_type(&mut a, &mut cfg, "10.0.0.1:7000");
        srv_key(&mut a, &mut cfg, KeyCode::Tab);
        srv_type(&mut a, &mut cfg, &proto::friend_code_of(&[9; 32]));
        srv_key(&mut a, &mut cfg, KeyCode::Tab);
        srv_type(&mut a, &mut cfg, "работа");
        let (cmd, save) = srv_key(&mut a, &mut cfg, KeyCode::Enter);
        assert!(cmd.is_none() && save);
        assert_eq!(cfg.servers.len(), 3);
        assert_eq!(cfg.servers[2].addr, "10.0.0.1:7000");
        assert_eq!(cfg.servers[2].pubkey, proto::hex_of(&[9; 32]));
        assert_eq!(cfg.servers[2].label, "работа");
        assert_eq!(servers_view(&a).servers.len(), 3);

        // Удалить (с подтверждением); текущий удалить нельзя.
        srv_key(&mut a, &mut cfg, KeyCode::Home);
        assert!(matches!(
            srv_key(&mut a, &mut cfg, KeyCode::Char('d')),
            (None, false)
        ));
        assert_eq!(cfg.servers.len(), 3);
        srv_key(&mut a, &mut cfg, KeyCode::Down);
        srv_key(&mut a, &mut cfg, KeyCode::Char('d'));
        let (_, save) = srv_key(&mut a, &mut cfg, KeyCode::Char('y'));
        assert!(save);
        assert_eq!(cfg.servers.len(), 2);
        assert!(cfg.servers.iter().all(|s| s.addr != "127.0.0.2:5600"));
        assert_eq!(servers_view(&a).current, 0);

        // Адаптер и dll — в конфиг, с пометкой о перезапуске.
        srv_key(&mut a, &mut cfg, KeyCode::Char('e'));
        for _ in 0.."TunnelVPN".len() {
            srv_key(&mut a, &mut cfg, KeyCode::Backspace);
        }
        srv_type(&mut a, &mut cfg, "Game");
        srv_key(&mut a, &mut cfg, KeyCode::Tab);
        srv_type(&mut a, &mut cfg, "C:\\w.dll");
        let (cmd, save) = srv_key(&mut a, &mut cfg, KeyCode::Enter);
        assert!(cmd.is_none() && save);
        assert_eq!(cfg.adapter, "Game");
        assert_eq!(cfg.dll, "C:\\w.dll");
        assert!(
            servers_view(&a)
                .notice
                .as_deref()
                .unwrap_or("")
                .contains("после перезапуска")
        );
    }

    // ---------- раскладка, алиасы, невидимка ----------

    struct NullTun;
    impl crate::engine::TunDev for NullTun {
        fn inject(&self, _: &[u8]) -> Result<()> {
            Ok(())
        }
        fn ensure_address(&self, _: u32) -> Result<()> {
            Ok(())
        }
    }

    /// Движок на локальном сервере, без адаптера. Сервер держим, пока жив движок.
    fn test_engine(cfg: Config) -> (crate::api::LocalEngine, tunnel_server::Server) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("voidlink-tui-{}-{nanos}", std::process::id()));
        let server = tunnel_server::Server::start(tunnel_server::Config {
            listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            data_dir: dir,
            workers: 1,
            quiet: true,
            ..Default::default()
        })
        .unwrap();
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], server.addr.port()));
        let eng = crate::engine::start_with_tun(
            std::sync::Arc::new(std::sync::Mutex::new(cfg)),
            addr,
            server.pubkey,
            proto::Identity::generate(),
            std::sync::Arc::new(NullTun),
            std::sync::Arc::new(|_: &Config| {}),
        )
        .unwrap();
        (crate::api::LocalEngine::new(eng), server)
    }

    /// Ждёт, пока движок применит команду (поток движка — асинхронно).
    fn eventually(what: &str, mut f: impl FnMut() -> bool) {
        let t0 = Instant::now();
        while !f() {
            assert!(
                t0.elapsed() < Duration::from_secs(5),
                "не дождались: {what}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn friend_cfg() -> Config {
        Config {
            friends: vec![
                StoredFriend {
                    pubkey: proto::hex_of(&[2; 32]),
                    alias: "bob".into(),
                },
                StoredFriend {
                    pubkey: proto::hex_of(&[3; 32]),
                    alias: "eve".into(),
                },
            ],
            ..Config::default()
        }
    }

    fn ch(c: char) -> KeyEvent {
        key(KeyCode::Char(c))
    }

    #[test]
    fn русская_раскладка_нормализуется_кроме_полей_ввода() {
        let mut a = app();
        assert_eq!(latin_key(ch('й')).code, KeyCode::Char('q'));
        assert_eq!(latin_key(ch('Щ')).code, KeyCode::Char('O'));
        assert_eq!(latin_key(ch('o')).code, KeyCode::Char('o'));
        let ctrl = KeyEvent::new(KeyCode::Char('с'), KeyModifiers::CONTROL);
        assert_eq!(
            latin_key(ctrl),
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
        );
        assert!(!a.text_input_active());
        a.filtering = true;
        assert!(a.text_input_active(), "строка поиска — текст");
        a.filtering = false;
        a.open_command();
        assert!(a.text_input_active(), "окно ввода — текст");
        a.stack.clear();
        a.stack.push(Popup::Help);
        assert!(!a.text_input_active());
    }

    #[test]
    fn хоткеи_в_русской_раскладке_через_handle_key() {
        let (eng, _srv) = test_engine(friend_cfg());
        let mut a = app();
        // «з» = «p» — профиль.
        a.handle_key(ch('з'), &eng);
        assert!(matches!(a.stack.last(), Some(Popup::Profile)));
        a.handle_key(key(KeyCode::Esc), &eng);
        assert!(a.stack.is_empty());
        // «Ж» = «:» — командная строка; в ней кириллица остаётся кириллицей.
        a.handle_key(ch('Ж'), &eng);
        a.handle_key(ch('ы'), &eng);
        match a.stack.last() {
            Some(Popup::Input(i)) => assert_eq!(i.value, "ы"),
            _ => panic!("нет командной строки"),
        }
        a.stack.clear();
        // Поиск: «/» и затем кириллица в фильтр как есть.
        a.handle_key(ch('/'), &eng);
        a.handle_key(ch('б'), &eng);
        assert_eq!(a.filter, "б");
        a.handle_key(key(KeyCode::Esc), &eng);
        // «ы» = «s» — сортировка.
        let before = a.sort;
        a.handle_key(ch('ы'), &eng);
        assert_ne!(a.sort, before);
        // Ctrl+С (кириллица) — выход.
        a.handle_key(
            KeyEvent::new(KeyCode::Char('с'), KeyModifiers::CONTROL),
            &eng,
        );
        assert!(a.quit);
    }

    #[test]
    fn переименование_друга_клавишей_r_и_командой() {
        let (eng, _srv) = test_engine(friend_cfg());
        let mut a = app();
        // Друзья — из снимка движка (friend_cfg: bob и eve).
        a.sync(&eng);
        assert_eq!(a.friends.len(), 2);
        a.sel_friend = Some([2; 32]);
        a.focus = Focus::Friends;
        // «к» = «r» в списке друзей — окно алиаса с текущим именем.
        a.handle_key(ch('к'), &eng);
        match a.stack.last() {
            Some(Popup::Input(i)) => {
                assert!(matches!(i.action, InputAction::FriendAlias(pk) if pk == [2; 32]));
                assert_eq!(i.value, "bob");
            }
            _ => panic!("нет окна алиаса"),
        }
        for _ in 0..3 {
            a.handle_key(key(KeyCode::Backspace), &eng);
        }
        for c in "Боря".chars() {
            a.handle_key(ch(c), &eng);
        }
        a.handle_key(key(KeyCode::Enter), &eng);
        assert!(a.stack.is_empty());
        let alias = |eng: &dyn EngineApi, pk: [u8; 32]| {
            let hex = proto::hex_of(&pk);
            eng.snapshot()
                .cfg
                .friends
                .iter()
                .find(|f| f.pubkey == hex)
                .unwrap()
                .alias
                .clone()
        };
        eventually("алиас Боря в конфиге движка", || {
            alias(&eng, [2; 32]) == "Боря"
        });
        assert_eq!(
            a.friends
                .iter()
                .find(|f| f.pubkey == [2; 32])
                .unwrap()
                .alias,
            "Боря"
        );
        // :alias по алиасу; занятый алиас и неизвестный друг — ошибки.
        a.run_command("alias eve Ева Ивановна", &eng).unwrap();
        eventually("алиас Ева в конфиге движка", || {
            alias(&eng, [3; 32]) == "Ева Ивановна"
        });
        assert!(a.run_command("alias Боря Ева Ивановна", &eng).is_err());
        assert!(a.run_command("alias nobody x", &eng).is_err());
        // Вне списка друзей «r» — обновление списка групп.
        a.focus = Focus::Groups;
        a.handle_key(ch('r'), &eng);
        assert!(a.stack.is_empty() && a.status_msg.contains("обновляем"));
    }

    #[test]
    fn парс_алиаса_и_правка_конфига() {
        assert_eq!(
            parse_command("alias bob Боря Петров").unwrap(),
            Command::Alias {
                friend: "bob".into(),
                name: "Боря Петров".into()
            }
        );
        assert!(parse_command("alias bob").is_err());
        assert!(parse_command("alias").is_err());
        let mut cfg = friend_cfg();
        rename_friend_in(&mut cfg, &[2; 32], "  b2 ").unwrap();
        assert_eq!(cfg.friends[0].alias, "b2");
        assert!(rename_friend_in(&mut cfg, &[2; 32], " ").is_err());
        assert!(rename_friend_in(&mut cfg, &[2; 32], "eve").is_err());
        assert!(rename_friend_in(&mut cfg, &[4; 32], "x").is_err());
        assert_eq!(resolve_friend_in(&cfg, "eve").unwrap(), [3; 32]);
        assert_eq!(
            resolve_friend_in(&cfg, &proto::hex_of(&[2; 32])).unwrap(),
            [2; 32]
        );
    }

    #[test]
    fn невидимка_из_настроек_и_командой() {
        let (eng, _srv) = test_engine(Config::default());
        let mut a = app();
        assert!(!a.invisible);
        a.handle_key(key(KeyCode::F(3)), &eng);
        let row = SETTING_ROWS
            .iter()
            .position(|r| *r == SettingRow::Invisible)
            .unwrap();
        for _ in 0..row {
            a.handle_key(key(KeyCode::Down), &eng);
        }
        a.handle_key(key(KeyCode::Enter), &eng);
        assert!(a.invisible);
        assert!(
            a.toasts
                .iter()
                .any(|t| t.text.contains("невидимка включена"))
        );
        assert!(
            matches!(a.stack.last(), Some(Popup::Settings(_))),
            "настройки остаются открытыми"
        );
        a.stack.clear();
        a.run_command("invisible off", &eng).unwrap();
        assert!(!a.invisible);
    }

    #[test]
    fn счётчик_приглашений_для_бейджа() {
        let mut a = online();
        assert_eq!(a.pending_invites(), 0);
        a.on_invite(inv(1), false);
        a.on_invite(inv(2), false);
        assert_eq!(a.pending_invites(), 2, "одно в окне, одно в очереди");
        press(&mut a, KeyCode::Esc);
        press(&mut a, KeyCode::Esc);
        assert_eq!(a.pending_invites(), 2, "отложенные тоже считаются");
        // Клик по бейджу = «o»: снова открывает отложенные.
        a.reopen_invites();
        assert!(shown_gid(&a).is_some());
    }
}
