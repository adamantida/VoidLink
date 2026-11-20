//! Экран «Серверы»: список серверов профиля, переключение текущего,
//! добавление/удаление и правка адаптера Wintun / пути к `wintun.dll`.
//!
//! Модуль самодостаточный: состояние — простые данные ([`ServersView`]),
//! обработчики клавиш и мыши чистые и возвращают [`ServersAction`] —
//! что именно сделать (переключиться, сохранить конфиг и т. п.), решает
//! вызывающий. Отрисовка запоминает прямоугольники для мыши в
//! [`ServersHits`] (как `app.hits` в основном UI).
//!
//! Клавиши списка: `↑↓`/`Home`/`End` — выбор, `Enter` — переключиться,
//! `a` — добавить, `d` — удалить (кроме текущего, с подтверждением),
//! `e` — адаптер и dll, `Esc`/`q` — закрыть.

// подключается при интеграции
#![allow(dead_code)]

use std::cell::RefCell;
use std::net::SocketAddr;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEventKind};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::prelude::*;
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
    Table, TableState,
};
use tunnel_protocol as proto;

use super::app::resolve_addr;
use super::theme::Theme;
use crate::probe::KeyMatch;

/// Максимальная длина однострочного поля ввода.
const MAX_INPUT: usize = 120;

/// Итог пробы сервера (PROBE_REQ/RESP) для колонок «доступен», «RTT», «ключ».
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeLine {
    pub available: bool,
    pub rtt_ms: Option<u32>,
    /// Совпал ли ключ сервера с закреплённым (✓/✗/—).
    pub key_match: KeyMatch,
}

/// Сервер в списке.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerEntry {
    pub label: String,
    pub addr: String,
    pub pubkey: [u8; 32],
    /// Последний измеренный пинг (мс, CTRL_PING).
    pub ping_ms: Option<u32>,
    /// Последняя проба; `None` — ещё не проверяли.
    pub probe: Option<ProbeLine>,
    /// Проба идёт прямо сейчас («проверяется…»).
    pub probing: bool,
}

/// Форма добавления сервера. `focus`: 0 — адрес, 1 — код, 2 — подпись.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddForm {
    pub addr: String,
    pub code: String,
    pub label: String,
    pub focus: usize,
    pub error: Option<String>,
}

/// Форма адаптера. `focus`: 0 — имя адаптера, 1 — путь к dll.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdapterForm {
    pub name: String,
    pub dll: String,
    pub focus: usize,
    pub error: Option<String>,
}

/// Режим экрана.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    List,
    Add(AddForm),
    EditAdapter(AdapterForm),
    ConfirmDelete(usize),
}

/// Что должен сделать вызывающий.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServersAction {
    /// Переключиться на сервер с этим индексом.
    Switch(usize),
    /// Добавить сервер (адрес проверен синтаксически, ключ — из кода).
    Add {
        addr: String,
        pubkey: [u8; 32],
        label: String,
    },
    /// Удалить сервер (никогда не текущий).
    Delete(usize),
    /// Проверить доступность сервера (PROBE_REQ, §3.7).
    Probe(usize),
    /// Новое имя адаптера и путь к dll (пусто — по умолчанию).
    SetAdapter { name: String, dll: String },
    /// Закрыть экран.
    Close,
}

/// Куда кликать: заполняется при отрисовке.
#[derive(Clone, Debug, Default)]
pub struct ServersHits {
    /// Окно списка.
    pub popup: Rect,
    /// Строки таблицы (без заголовка).
    pub rows: Rect,
    /// Смещение прокрутки таблицы.
    pub offset: usize,
    /// Окно формы / подтверждения поверх списка (пусто в режиме списка).
    pub dialog: Rect,
    /// Поля формы: прямоугольник и номер поля.
    pub fields: Vec<(Rect, usize)>,
    /// Кнопки активного окна: клик = нажатие клавиши.
    pub buttons: Vec<(Rect, KeyEvent)>,
}

/// Состояние экрана «Серверы».
#[derive(Clone, Debug)]
pub struct ServersView {
    pub servers: Vec<ServerEntry>,
    /// Индекс текущего (подключённого) сервера.
    pub current: usize,
    /// Выделенная строка.
    pub sel: usize,
    pub adapter_name: String,
    pub dll_path: String,
    pub mode: Mode,
    /// Подсказка/предупреждение под списком.
    pub notice: Option<String>,
    pub hits: RefCell<ServersHits>,
}

impl ServersView {
    pub fn new(
        servers: Vec<ServerEntry>,
        current: usize,
        adapter_name: &str,
        dll_path: &str,
    ) -> Self {
        let current = current.min(servers.len().saturating_sub(1));
        ServersView {
            servers,
            current,
            sel: current,
            adapter_name: adapter_name.to_string(),
            dll_path: dll_path.to_string(),
            mode: Mode::List,
            notice: None,
            hits: RefCell::new(ServersHits::default()),
        }
    }

    /// Обновляет список (после того как вызывающий применил действие).
    pub fn set_servers(&mut self, servers: Vec<ServerEntry>, current: usize) {
        self.servers = servers;
        let last = self.servers.len().saturating_sub(1);
        self.current = current.min(last);
        self.sel = self.sel.min(last);
    }

    /// Обновляет пинг для сервера по resolved-адресу.
    pub fn update_ping(&mut self, addr: SocketAddr, ping_ms: Option<u32>) {
        for s in &mut self.servers {
            if resolve_addr(&s.addr) == Some(addr) {
                s.ping_ms = ping_ms;
                break;
            }
        }
    }

    /// Результат пробы: строка ищется по resolved-адресу (hostname после
    /// resolve), а не по строке адреса.
    pub fn update_probe(&mut self, addr: SocketAddr, line: ProbeLine) {
        for s in &mut self.servers {
            if resolve_addr(&s.addr) == Some(addr) {
                s.probe = Some(line);
                s.probing = false;
            }
        }
    }

    /// Отметить, что проба сервера идёт («проверяется…»).
    pub fn set_probing(&mut self, addr: SocketAddr) {
        for s in &mut self.servers {
            if resolve_addr(&s.addr) == Some(addr) {
                s.probing = true;
            }
        }
    }

    /// Идёт ли уже проба этого адреса (по resolved-адресу).
    pub fn is_probing(&self, addr: SocketAddr) -> bool {
        self.servers
            .iter()
            .any(|s| s.probing && resolve_addr(&s.addr) == Some(addr))
    }

    /// Адрес выбранного сервера (для явной пробы `p`).
    pub fn selected_addr(&self) -> Option<SocketAddr> {
        self.servers
            .get(self.sel)
            .and_then(|s| resolve_addr(&s.addr))
    }

    // ------------------------------------------------------------ клавиши

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<ServersAction> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Some(ServersAction::Close);
        }
        match std::mem::replace(&mut self.mode, Mode::List) {
            Mode::List => self.key_list(key),
            Mode::ConfirmDelete(i) => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Char('д') | KeyCode::Enter => {
                    if i < self.servers.len() && i != self.current {
                        self.notice = None;
                        Some(ServersAction::Delete(i))
                    } else {
                        None
                    }
                }
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Char('q') => None,
                _ => {
                    self.mode = Mode::ConfirmDelete(i);
                    None
                }
            },
            Mode::Add(mut form) => {
                let act = self.key_add(&mut form, key);
                if act.is_none() && key.code != KeyCode::Esc {
                    self.mode = Mode::Add(form);
                }
                act
            }
            Mode::EditAdapter(mut form) => {
                let act = key_adapter(&mut form, key);
                if act.is_none() && key.code != KeyCode::Esc {
                    self.mode = Mode::EditAdapter(form);
                }
                act
            }
        }
    }

    fn key_list(&mut self, key: KeyEvent) -> Option<ServersAction> {
        let n = self.servers.len();
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return Some(ServersAction::Close),
            KeyCode::Up | KeyCode::Char('k') => self.sel = self.sel.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                if self.sel + 1 < n {
                    self.sel += 1;
                }
            }
            KeyCode::Home => self.sel = 0,
            KeyCode::End => self.sel = n.saturating_sub(1),
            KeyCode::PageUp => self.sel = self.sel.saturating_sub(10),
            KeyCode::PageDown => self.sel = (self.sel + 10).min(n.saturating_sub(1)),
            KeyCode::Enter => {
                if self.sel < n && self.sel != self.current {
                    self.notice = None;
                    return Some(ServersAction::Switch(self.sel));
                }
                if self.sel == self.current && n > 0 {
                    self.notice = Some("этот сервер уже текущий".into());
                }
            }
            KeyCode::Char('a') | KeyCode::Insert => {
                self.notice = None;
                self.mode = Mode::Add(AddForm::default());
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                if self.sel >= n {
                    return None;
                }
                if self.sel == self.current {
                    self.notice =
                        Some("текущий сервер удалить нельзя — сначала переключись".into());
                } else {
                    self.notice = None;
                    self.mode = Mode::ConfirmDelete(self.sel);
                }
            }
            KeyCode::Char('e') => {
                self.notice = None;
                self.mode = Mode::EditAdapter(AdapterForm {
                    name: self.adapter_name.clone(),
                    dll: self.dll_path.clone(),
                    focus: 0,
                    error: None,
                });
            }
            KeyCode::Char('p') if self.sel < n => {
                self.notice = None;
                return Some(ServersAction::Probe(self.sel));
            }
            _ => {}
        }
        None
    }

    fn key_add(&self, form: &mut AddForm, key: KeyEvent) -> Option<ServersAction> {
        match key.code {
            KeyCode::Esc => None,
            KeyCode::Tab | KeyCode::Down => {
                form.focus = (form.focus + 1) % 3;
                None
            }
            KeyCode::BackTab | KeyCode::Up => {
                form.focus = (form.focus + 2) % 3;
                None
            }
            KeyCode::Backspace => {
                field_add(form).pop();
                form.error = None;
                None
            }
            KeyCode::Char(c) if is_text_input(&key, c) => {
                push_char(field_add(form), c);
                form.error = None;
                None
            }
            KeyCode::Enter => match self.validate_add(form) {
                Ok(act) => Some(act),
                Err(e) => {
                    form.error = Some(e);
                    None
                }
            },
            _ => None,
        }
    }

    /// Проверка формы добавления.
    pub fn validate_add(&self, form: &AddForm) -> Result<ServersAction, String> {
        let addr = form.addr.trim();
        if addr.is_empty() {
            return Err("адрес сервера не задан".into());
        }
        if !valid_addr(addr) {
            return Err(format!("адрес {addr:?} — не ip:port и не host:port"));
        }
        if self
            .servers
            .iter()
            .any(|s| s.addr.eq_ignore_ascii_case(addr))
        {
            return Err(format!("сервер {addr} уже в списке"));
        }
        let code = form.code.trim();
        if code.is_empty() {
            return Err("код сервера не задан".into());
        }
        let pubkey = proto::parse_friend_code(code)
            .map_err(|_| "код сервера — не friend code вида TUN-…".to_string())?;
        if self.servers.iter().any(|s| s.pubkey == pubkey) {
            return Err("сервер с этим кодом уже в списке".into());
        }
        Ok(ServersAction::Add {
            addr: addr.to_string(),
            pubkey,
            label: form.label.trim().to_string(),
        })
    }

    // ------------------------------------------------------------ мышь

    /// Мышь: клик по кнопке = её клавиша, клик по строке — выбор,
    /// повторный клик по выбранной — переключение, колесо — прокрутка,
    /// клик мимо окна — закрыть (или отменить форму).
    pub fn handle_mouse(&mut self, kind: MouseEventKind, x: u16, y: u16) -> Option<ServersAction> {
        let hits = self.hits.borrow().clone();
        let inside = |r: Rect| r.contains(Position::new(x, y));
        match kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some((_, key)) = hits.buttons.iter().find(|(r, _)| inside(*r)) {
                    return self.handle_key(*key);
                }
                if !matches!(self.mode, Mode::List) {
                    if let Some((_, idx)) = hits.fields.iter().find(|(r, _)| inside(*r)) {
                        match &mut self.mode {
                            Mode::Add(f) => f.focus = *idx,
                            Mode::EditAdapter(f) => f.focus = *idx,
                            _ => {}
                        }
                        return None;
                    }
                    if !inside(hits.dialog) {
                        self.mode = Mode::List;
                    }
                    return None;
                }
                if inside(hits.rows) {
                    let i = hits.offset + (y - hits.rows.y) as usize;
                    if i < self.servers.len() {
                        if i == self.sel {
                            return self
                                .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
                        }
                        self.sel = i;
                    }
                    return None;
                }
                if !inside(hits.popup) {
                    return Some(ServersAction::Close);
                }
                None
            }
            MouseEventKind::ScrollUp if matches!(self.mode, Mode::List) => {
                self.sel = self.sel.saturating_sub(1);
                None
            }
            MouseEventKind::ScrollDown if matches!(self.mode, Mode::List) => {
                if self.sel + 1 < self.servers.len() {
                    self.sel += 1;
                }
                None
            }
            _ => None,
        }
    }

    // ------------------------------------------------------------ отрисовка

    pub fn draw(&self, f: &mut Frame, th: &Theme, area: Rect) {
        let mut hits = ServersHits::default();
        self.draw_list(f, th, area, &mut hits);
        match &self.mode {
            Mode::List => {}
            Mode::Add(form) => {
                hits.buttons.clear();
                let fields = [
                    ("адрес", form.addr.as_str(), "ip:port или host:port"),
                    ("код", form.code.as_str(), "friend code сервера (TUN-…)"),
                    ("подпись", form.label.as_str(), "необязательно"),
                ];
                draw_form(
                    f,
                    th,
                    area,
                    " Добавить сервер ",
                    &fields,
                    form.focus,
                    &form.error,
                    &mut hits,
                );
            }
            Mode::EditAdapter(form) => {
                hits.buttons.clear();
                let fields = [
                    ("адаптер", form.name.as_str(), "имя Wintun-адаптера"),
                    (
                        "wintun.dll",
                        form.dll.as_str(),
                        "пусто — рядом с exe или из PATH",
                    ),
                ];
                draw_form(
                    f,
                    th,
                    area,
                    " Адаптер ",
                    &fields,
                    form.focus,
                    &form.error,
                    &mut hits,
                );
            }
            Mode::ConfirmDelete(i) => {
                hits.buttons.clear();
                let name = self.servers.get(*i).map(display_name).unwrap_or_default();
                draw_confirm(f, th, area, &name, &mut hits);
            }
        }
        *self.hits.borrow_mut() = hits;
    }

    fn draw_list(&self, f: &mut Frame, th: &Theme, area: Rect, hits: &mut ServersHits) {
        let h = (self.servers.len() as u16 + 8).clamp(10, 24);
        let rect = centered(area, 78, h);
        hits.popup = rect;
        f.render_widget(Clear, rect);
        let focused = matches!(self.mode, Mode::List);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(if focused {
                th.accent
            } else {
                th.unfocused_border
            })
            .title(Span::styled(" Серверы ", th.title))
            .title_bottom(Line::from(Span::styled(
                " Enter — переключить · клик мимо — закрыть ",
                th.dim,
            )));
        let inner = block.inner(rect);
        f.render_widget(block, rect);
        if inner.height < 2 || inner.width < 4 {
            return;
        }
        let [table_area, info_area, notice_area, btn_area] = Layout::vertical([
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(inner);

        if self.servers.is_empty() {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "серверов нет — a: добавить",
                    th.dim,
                ))),
                table_area,
            );
        } else {
            let rows: Vec<Row> = self
                .servers
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let cur = i == self.current;
                    let mark = if cur {
                        Span::styled("●", th.ok)
                    } else {
                        Span::styled(" ", th.dim)
                    };
                    let key = proto::hex_of(&s.pubkey);
                    // Проба: доступен / RTT / ключ (✓ совпал, ✗ чужой, — нет
                    // сверки). Пока идёт — «проверяется…».
                    let (avail, avail_style) = if s.probing {
                        ("проверяется…", th.warn)
                    } else {
                        match s.probe {
                            Some(p) if p.available => ("✓", th.ok),
                            Some(_) => ("✗", th.error),
                            None => ("—", th.dim),
                        }
                    };
                    let rtt_src = s.probe.and_then(|p| p.rtt_ms).or(s.ping_ms);
                    let rtt = rtt_src.map_or("—".to_string(), |v| format!("{v} мс"));
                    let rtt_style = match rtt_src {
                        Some(v) if v < 50 => th.ok,
                        Some(v) if v < 150 => th.warn,
                        Some(_) => th.error,
                        None => th.dim,
                    };
                    let (key_mark, key_style) = match s.probe.map(|p| p.key_match) {
                        Some(KeyMatch::Match) => ("✓", th.ok),
                        Some(KeyMatch::Mismatch) => ("✗", th.error),
                        Some(KeyMatch::Unknown) | None => ("—", th.dim),
                    };
                    Row::new(vec![
                        Cell::from(mark),
                        Cell::from(Span::styled(
                            if s.label.is_empty() {
                                "—".to_string()
                            } else {
                                s.label.clone()
                            },
                            if cur { th.ok } else { th.base },
                        )),
                        Cell::from(Span::styled(s.addr.clone(), th.base)),
                        Cell::from(Span::styled(avail, avail_style)),
                        Cell::from(Span::styled(rtt, rtt_style)),
                        Cell::from(Span::styled(key_mark, key_style)),
                        Cell::from(Span::styled(format!("{}…", &key[..12]), th.dim)),
                    ])
                })
                .collect();
            let table = Table::new(
                rows,
                [
                    Constraint::Length(1),
                    Constraint::Fill(1),
                    Constraint::Fill(2),
                    Constraint::Length(13),
                    Constraint::Length(7),
                    Constraint::Length(5),
                    Constraint::Length(13),
                ],
            )
            .header(
                Row::new(vec!["", "имя", "адрес", "доступен", "RTT", "ключ", "pubkey"])
                    .style(th.dim),
            )
            .row_highlight_style(th.selected)
            .highlight_symbol("▌");
            let mut state = TableState::default();
            state.select(Some(self.sel));
            let table_rect = Rect {
                width: table_area.width.saturating_sub(1),
                ..table_area
            };
            f.render_stateful_widget(table, table_rect, &mut state);
            hits.offset = state.offset();
            hits.rows = Rect {
                y: table_rect.y + 1,
                height: table_rect.height.saturating_sub(1),
                ..table_rect
            };
            let visible = hits.rows.height as usize;
            if self.servers.len() > visible {
                let mut sb = ScrollbarState::new(self.servers.len()).position(self.sel);
                f.render_stateful_widget(
                    Scrollbar::new(ScrollbarOrientation::VerticalRight).style(th.dim),
                    table_area,
                    &mut sb,
                );
            }
        }

        let dll = if self.dll_path.is_empty() {
            "по умолчанию"
        } else {
            self.dll_path.as_str()
        };
        let mut info = vec![
            Span::styled("адаптер ", th.dim),
            Span::styled(self.adapter_name.clone(), th.base),
            Span::styled(" · dll ", th.dim),
            Span::styled(dll.to_string(), th.base),
        ];
        // Проба выбранного сервера: «проверяется…» или итог.
        if let Some(s) = self.servers.get(self.sel) {
            if s.probing {
                info.push(Span::styled(" · проверяется…", th.warn));
            } else if let Some(p) = s.probe {
                let (text, style) = match (p.available, p.key_match) {
                    (false, _) => (" · недоступен", th.error),
                    (true, KeyMatch::Match) => (" · ключ ✓", th.ok),
                    (true, KeyMatch::Mismatch) => (" · чужой ключ ✗", th.error),
                    (true, KeyMatch::Unknown) => (" · доступен", th.ok),
                };
                info.push(Span::styled(text, style));
            }
        }
        f.render_widget(Paragraph::new(Line::from(info)), info_area);
        if let Some(n) = &self.notice {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(format!("! {n}"), th.warn))),
                notice_area,
            );
        }
        draw_buttons(
            f,
            &mut hits.buttons,
            btn_area,
            &[
                ("Переключить (Enter)", th.ok, key(KeyCode::Enter)),
                ("Добавить (a)", th.accent, key(KeyCode::Char('a'))),
                ("Удалить (d)", th.warn, key(KeyCode::Char('d'))),
                ("Адаптер (e)", th.accent, key(KeyCode::Char('e'))),
                ("Закрыть (Esc)", th.dim, key(KeyCode::Esc)),
            ],
        );
    }
}

fn key_adapter(form: &mut AdapterForm, key: KeyEvent) -> Option<ServersAction> {
    match key.code {
        KeyCode::Esc => None,
        KeyCode::Tab | KeyCode::Down | KeyCode::BackTab | KeyCode::Up => {
            form.focus = 1 - form.focus.min(1);
            None
        }
        KeyCode::Backspace => {
            if form.focus == 0 {
                form.name.pop()
            } else {
                form.dll.pop()
            };
            form.error = None;
            None
        }
        KeyCode::Char(c) if is_text_input(&key, c) => {
            push_char(
                if form.focus == 0 {
                    &mut form.name
                } else {
                    &mut form.dll
                },
                c,
            );
            form.error = None;
            None
        }
        KeyCode::Enter => {
            let name = form.name.trim();
            if name.is_empty() {
                form.error = Some("имя адаптера не задано".into());
                return None;
            }
            Some(ServersAction::SetAdapter {
                name: name.to_string(),
                dll: form.dll.trim().to_string(),
            })
        }
        _ => None,
    }
}

fn field_add(form: &mut AddForm) -> &mut String {
    match form.focus {
        0 => &mut form.addr,
        1 => &mut form.code,
        _ => &mut form.label,
    }
}

/// Печатный символ без Ctrl/Alt: Ctrl+V, Alt+x и т.п. не вставляют букву в поле.
/// Ctrl+Alt вместе — это AltGr на Windows, его пропускаем как обычный ввод.
fn is_text_input(key: &KeyEvent, c: char) -> bool {
    let m = key.modifiers & (KeyModifiers::CONTROL | KeyModifiers::ALT);
    !c.is_control() && (m.is_empty() || m == KeyModifiers::CONTROL | KeyModifiers::ALT)
}

fn push_char(s: &mut String, c: char) {
    if s.chars().count() < MAX_INPUT {
        s.push(c);
    }
}

/// Адрес: `SocketAddr` (`1.2.3.4:5`, `[::1]:5`) или синтаксически верный
/// `host:port` — имя резолвится позже, при подключении.
pub fn valid_addr(addr: &str) -> bool {
    if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
        return sa.port() != 0;
    }
    let Some((host, port)) = addr.rsplit_once(':') else {
        return false;
    };
    let port_ok = port.parse::<u16>().is_ok_and(|p| p != 0);
    // Все метки из цифр — это кривой IPv4 (`999.1.1.1`), а не имя хоста.
    let bad_ipv4 = host
        .split('.')
        .all(|l| l.chars().all(|c| c.is_ascii_digit()));
    let host_ok = !host.is_empty()
        && !bad_ipv4
        && host.len() <= 253
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    port_ok && host_ok
}

fn display_name(s: &ServerEntry) -> String {
    if s.label.is_empty() {
        s.addr.clone()
    } else {
        format!("{} ({})", s.label, s.addr)
    }
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + area.width.saturating_sub(w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    }
}

/// Строка кнопок-«чипов» (как в ui.rs); не влезшие не рисуются.
fn draw_buttons(
    f: &mut Frame,
    hits: &mut Vec<(Rect, KeyEvent)>,
    row: Rect,
    items: &[(&str, Style, KeyEvent)],
) {
    if row.width == 0 || row.height == 0 {
        return;
    }
    let mut spans = Vec::new();
    let mut x = row.x;
    for (label, style, key) in items {
        let chip = Span::styled(format!(" {label} "), style.add_modifier(Modifier::REVERSED));
        let w = chip.width() as u16;
        if x + w > row.right() {
            break;
        }
        hits.push((Rect::new(x, row.y, w, 1), *key));
        spans.push(chip);
        spans.push(Span::raw(" "));
        x += w + 1;
    }
    f.render_widget(Paragraph::new(Line::from(spans)), Rect { height: 1, ..row });
}

/// Форма из однострочных полей поверх списка.
#[allow(clippy::too_many_arguments)]
fn draw_form(
    f: &mut Frame,
    th: &Theme,
    area: Rect,
    title: &str,
    fields: &[(&str, &str, &str)],
    focus: usize,
    error: &Option<String>,
    hits: &mut ServersHits,
) {
    // поля + подсказка + ошибка + кнопки + рамка
    let rect = centered(area, 70, fields.len() as u16 + 5);
    hits.dialog = rect;
    f.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(th.focused_border)
        .title(Span::styled(title.to_string(), th.title));
    let inner = block.inner(rect);
    f.render_widget(block, rect);
    let mut y = inner.y;
    for (i, (label, value, _)) in fields.iter().enumerate() {
        if y >= inner.bottom() {
            break;
        }
        let sel = i == focus;
        let shown = if sel {
            format!("{value}▌")
        } else if value.is_empty() {
            "·".to_string()
        } else {
            value.to_string()
        };
        let row = Rect::new(inner.x, y, inner.width, 1);
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("{label:<12}"), th.dim),
                Span::styled(shown, if sel { th.focused_border } else { th.base }),
            ])),
            row,
        );
        hits.fields.push((row, i));
        y += 1;
    }
    let line = match error {
        Some(e) => Line::from(Span::styled(format!("✗ {e}"), th.error)),
        None => Line::from(Span::styled(
            format!("  {}", fields.get(focus).map(|f| f.2).unwrap_or_default()),
            th.dim,
        )),
    };
    if y < inner.bottom() {
        f.render_widget(Paragraph::new(line), Rect::new(inner.x, y, inner.width, 1));
        y += 1;
    }
    if y + 1 < inner.bottom() {
        y += 1;
    }
    if y < inner.bottom() {
        draw_buttons(
            f,
            &mut hits.buttons,
            Rect::new(inner.x, y, inner.width, 1),
            &[
                ("Сохранить (Enter)", th.ok, key(KeyCode::Enter)),
                ("Следующее поле (Tab)", th.accent, key(KeyCode::Tab)),
                ("Отмена (Esc)", th.dim, key(KeyCode::Esc)),
            ],
        );
    }
}

fn draw_confirm(f: &mut Frame, th: &Theme, area: Rect, name: &str, hits: &mut ServersHits) {
    let rect = centered(area, 60, 6);
    hits.dialog = rect;
    f.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(th.warn)
        .title(Span::styled(" Удалить сервер? ", th.warn));
    let inner = block.inner(rect);
    f.render_widget(block, rect);
    if inner.height == 0 {
        return;
    }
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("сервер ", th.dim),
            Span::styled(name.to_string(), th.base),
            Span::styled(" будет удалён из профиля", th.dim),
        ])),
        Rect { height: 1, ..inner },
    );
    if inner.height >= 3 {
        draw_buttons(
            f,
            &mut hits.buttons,
            Rect::new(inner.x, inner.y + 2, inner.width, 1),
            &[
                ("Да (y)", th.warn, key(KeyCode::Char('y'))),
                ("Отмена (Esc)", th.dim, key(KeyCode::Esc)),
            ],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::theme::ThemeKind;
    use ratatui::backend::TestBackend;

    const THEMES: [ThemeKind; 5] = ThemeKind::ALL;

    fn k(code: KeyCode) -> KeyEvent {
        key(code)
    }

    fn view(n: usize) -> ServersView {
        let servers = (0..n)
            .map(|i| ServerEntry {
                label: if i == 1 {
                    String::new()
                } else {
                    format!("srv{i}")
                },
                addr: format!("10.0.0.{}:5555", i + 1),
                pubkey: [i as u8; 32],
                ping_ms: None,
                probe: None,
                probing: false,
            })
            .collect();
        ServersView::new(servers, 0, "TunnelVPN", "")
    }

    fn render(v: &ServersView, kind: ThemeKind, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        let th = Theme::of(kind);
        term.draw(|f| v.draw(f, &th, f.area())).unwrap();
        let buf = term.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..h {
            for x in 0..w {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn type_str(v: &mut ServersView, s: &str) {
        for c in s.chars() {
            assert_eq!(v.handle_key(k(KeyCode::Char(c))), None);
        }
    }

    fn find(text: &str, needle: &str) -> (u16, u16) {
        for (y, line) in text.lines().enumerate() {
            if let Some(b) = line.find(needle) {
                return (line[..b].chars().count() as u16, y as u16);
            }
        }
        panic!("нет {needle:?} на экране:\n{text}");
    }

    #[test]
    fn список_рисуется_во_всех_темах_и_узко() {
        for kind in THEMES {
            let v = view(3);
            let text = render(&v, kind, 100, 30);
            assert!(text.contains("Серверы"), "{text}");
            assert!(text.contains("10.0.0.2:5555"));
            assert!(text.contains("srv0"));
            assert!(text.contains("●"), "текущий не отмечен:\n{text}");
            assert!(text.contains("TunnelVPN"));
            assert!(text.contains("по умолчанию"));
            assert!(text.contains("0000000000"), "нет ключа:\n{text}");
            for (w, h) in [(30, 8), (20, 4), (5, 3), (1, 1)] {
                let _ = render(&v, kind, w, h);
            }
        }
    }

    #[test]
    fn режимы_рисуются_во_всех_темах() {
        for kind in THEMES {
            let mut v = view(3);
            v.handle_key(k(KeyCode::Char('a')));
            let text = render(&v, kind, 100, 30);
            assert!(text.contains("Добавить сервер"));
            assert!(text.contains("ip:port или host:port"));
            let _ = render(&v, kind, 24, 6);

            v.mode = Mode::List;
            v.handle_key(k(KeyCode::Char('e')));
            let text = render(&v, kind, 100, 30);
            assert!(text.contains("Адаптер"));
            assert!(text.contains("wintun.dll"));
            let _ = render(&v, kind, 24, 6);

            v.mode = Mode::ConfirmDelete(2);
            let text = render(&v, kind, 100, 30);
            assert!(text.contains("Удалить сервер?"));
            assert!(text.contains("srv2 (10.0.0.3:5555)"));
            let _ = render(&v, kind, 24, 5);
        }
    }

    #[test]
    fn пустой_список_и_длинный_со_скроллбаром() {
        let v = ServersView::new(vec![], 0, "A", "C:\\wintun.dll");
        let text = render(&v, ThemeKind::Dark, 100, 30);
        assert!(text.contains("серверов нет"));
        assert!(text.contains("C:\\wintun.dll"));

        let mut v = view(40);
        v.sel = 39;
        let text = render(&v, ThemeKind::Dark, 100, 30);
        assert!(
            text.contains("10.0.0.40:5555"),
            "выделенная строка не видна:\n{text}"
        );
        assert!(
            text.contains('█') || text.contains('║'),
            "нет скроллбара:\n{text}"
        );
    }

    #[test]
    fn навигация_и_переключение() {
        let mut v = view(3);
        assert_eq!(v.handle_key(k(KeyCode::Enter)), None);
        assert!(v.notice.is_some(), "текущий — подсказка");
        v.handle_key(k(KeyCode::Down));
        v.handle_key(k(KeyCode::Down));
        v.handle_key(k(KeyCode::Down));
        assert_eq!(v.sel, 2);
        assert_eq!(
            v.handle_key(k(KeyCode::Enter)),
            Some(ServersAction::Switch(2))
        );
        v.handle_key(k(KeyCode::Home));
        assert_eq!(v.sel, 0);
        v.handle_key(k(KeyCode::End));
        assert_eq!(v.sel, 2);
        assert_eq!(v.handle_key(k(KeyCode::Esc)), Some(ServersAction::Close));
    }

    #[test]
    fn удаление_только_не_текущего_с_подтверждением() {
        let mut v = view(3);
        assert_eq!(v.handle_key(k(KeyCode::Char('d'))), None);
        assert_eq!(v.mode, Mode::List);
        assert!(v.notice.as_deref().unwrap().contains("нельзя"));

        v.sel = 1;
        v.handle_key(k(KeyCode::Char('d')));
        assert_eq!(v.mode, Mode::ConfirmDelete(1));
        assert_eq!(v.handle_key(k(KeyCode::Char('x'))), None);
        assert_eq!(v.mode, Mode::ConfirmDelete(1));
        assert_eq!(v.handle_key(k(KeyCode::Esc)), None);
        assert_eq!(v.mode, Mode::List);

        v.handle_key(k(KeyCode::Char('d')));
        assert_eq!(
            v.handle_key(k(KeyCode::Char('y'))),
            Some(ServersAction::Delete(1))
        );
        assert_eq!(v.mode, Mode::List);

        v.set_servers(v.servers[..2].to_vec(), 0);
        assert_eq!(v.servers.len(), 2);
    }

    #[test]
    fn добавление_с_валидацией() {
        let id = proto::Identity::generate();
        let code = id.friend_code();
        let mut v = view(2);
        v.handle_key(k(KeyCode::Char('a')));
        assert!(matches!(v.mode, Mode::Add(_)));

        // пустой адрес
        assert_eq!(v.handle_key(k(KeyCode::Enter)), None);
        let Mode::Add(f) = &v.mode else { panic!() };
        assert!(f.error.as_deref().unwrap().contains("адрес"));

        type_str(&mut v, "нет-адреса");
        v.handle_key(k(KeyCode::Enter));
        let Mode::Add(f) = &v.mode else { panic!() };
        assert!(f.error.as_deref().unwrap().contains("host:port"));
        for _ in 0.."нет-адреса".chars().count() {
            v.handle_key(k(KeyCode::Backspace));
        }

        // дубликат
        type_str(&mut v, "10.0.0.1:5555");
        v.handle_key(k(KeyCode::Tab));
        type_str(&mut v, &code);
        v.handle_key(k(KeyCode::Enter));
        let Mode::Add(f) = &v.mode else { panic!() };
        assert!(f.error.as_deref().unwrap().contains("уже"), "{:?}", f.error);

        // правильный host:port
        v.mode = Mode::Add(AddForm {
            addr: "vpn.example.org:5555".into(),
            code: "TUN-мусор".into(),
            ..Default::default()
        });
        v.handle_key(k(KeyCode::Enter));
        let Mode::Add(f) = &v.mode else { panic!() };
        assert!(f.error.as_deref().unwrap().contains("friend code"));

        v.mode = Mode::Add(AddForm {
            addr: " vpn.example.org:5555 ".into(),
            code: code.clone(),
            focus: 2,
            ..Default::default()
        });
        type_str(&mut v, "дом");
        assert_eq!(
            v.handle_key(k(KeyCode::Enter)),
            Some(ServersAction::Add {
                addr: "vpn.example.org:5555".into(),
                pubkey: id.ed_pub(),
                label: "дом".into(),
            })
        );
        assert_eq!(v.mode, Mode::List);

        // тот же ключ под другим адресом — дубликат
        v.servers.push(ServerEntry {
            label: String::new(),
            addr: "vpn.example.org:5555".into(),
            pubkey: id.ed_pub(),
            ping_ms: None,
            probe: None,
            probing: false,
        });
        v.mode = Mode::Add(AddForm {
            addr: "other.example.org:1".into(),
            code: code.clone(),
            ..Default::default()
        });
        v.handle_key(k(KeyCode::Enter));
        let Mode::Add(f) = &v.mode else { panic!() };
        assert!(
            f.error.as_deref().unwrap().contains("кодом"),
            "{:?}",
            f.error
        );

        // Ctrl/Alt + буква не печатают, AltGr (Ctrl+Alt) и Shift — печатают
        v.mode = Mode::Add(AddForm::default());
        v.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::CONTROL));
        v.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::ALT));
        v.handle_key(KeyEvent::new(
            KeyCode::Char('@'),
            KeyModifiers::CONTROL | KeyModifiers::ALT,
        ));
        v.handle_key(KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT));
        let Mode::Add(f) = &v.mode else { panic!() };
        assert_eq!(f.addr, "@A");

        v.mode = Mode::List;
        v.handle_key(k(KeyCode::Char('a')));
        assert_eq!(v.handle_key(k(KeyCode::Esc)), None);
        assert_eq!(v.mode, Mode::List);
    }

    #[test]
    fn адреса() {
        for ok in [
            "1.2.3.4:5555",
            "[::1]:5555",
            "localhost:1",
            "a-b.example.com:65535",
            "10.0.0.1x:5",
        ] {
            assert!(valid_addr(ok), "{ok}");
        }
        for bad in [
            "",
            "1.2.3.4",
            "host:0",
            "host:70000",
            ":5555",
            "-a.com:1",
            "a..b:1",
            "::1:5555",
            "хост:1",
            "1.2.3.4:0",
            "[::1]:0",
            "999.1.1.1:5",
            "1.2.3:5",
        ] {
            assert!(!valid_addr(bad), "{bad}");
        }
    }

    #[test]
    fn правка_адаптера() {
        let mut v = view(1);
        v.dll_path = "old.dll".into();
        v.handle_key(k(KeyCode::Char('e')));
        for _ in 0.."TunnelVPN".len() {
            v.handle_key(k(KeyCode::Backspace));
        }
        assert_eq!(v.handle_key(k(KeyCode::Enter)), None);
        let Mode::EditAdapter(f) = &v.mode else {
            panic!()
        };
        assert!(f.error.is_some());
        type_str(&mut v, "Tun2");
        v.handle_key(k(KeyCode::Tab));
        type_str(&mut v, "x");
        assert_eq!(
            v.handle_key(k(KeyCode::Enter)),
            Some(ServersAction::SetAdapter {
                name: "Tun2".into(),
                dll: "old.dllx".into()
            })
        );
    }

    #[test]
    fn мышь_строки_кнопки_и_мимо() {
        let mut v = view(3);
        let text = render(&v, ThemeKind::Dark, 100, 30);
        let click = MouseEventKind::Down(MouseButton::Left);

        // клик по строке выбирает, повторный — переключает
        let (x, y) = find(&text, "10.0.0.3:5555");
        assert_eq!(v.handle_mouse(click, x, y), None);
        assert_eq!(v.sel, 2);
        assert_eq!(v.handle_mouse(click, x, y), Some(ServersAction::Switch(2)));

        // колесо
        v.handle_mouse(MouseEventKind::ScrollUp, x, y);
        assert_eq!(v.sel, 1);
        v.handle_mouse(MouseEventKind::ScrollDown, x, y);
        v.handle_mouse(MouseEventKind::ScrollDown, x, y);
        assert_eq!(v.sel, 2);

        // кнопка «Добавить»
        let (x, y) = find(&text, "Добавить (a)");
        assert_eq!(v.handle_mouse(click, x, y), None);
        assert!(matches!(v.mode, Mode::Add(_)));

        // в форме: клик по полю «подпись» — фокус
        let text = render(&v, ThemeKind::Dark, 100, 30);
        let (x, y) = find(&text, "подпись");
        v.handle_mouse(click, x, y);
        let Mode::Add(f) = &v.mode else { panic!() };
        assert_eq!(f.focus, 2);
        // кнопка «Отмена»
        let (x, y) = find(&text, "Отмена (Esc)");
        assert_eq!(v.handle_mouse(click, x, y), None);
        assert_eq!(v.mode, Mode::List);

        // подтверждение удаления кнопкой
        v.sel = 1;
        v.handle_key(k(KeyCode::Char('d')));
        let text = render(&v, ThemeKind::Dark, 100, 30);
        let (x, y) = find(&text, "Да (y)");
        assert_eq!(v.handle_mouse(click, x, y), Some(ServersAction::Delete(1)));

        // форма: клик мимо — отмена формы; список: клик мимо — закрыть
        v.handle_key(k(KeyCode::Char('e')));
        render(&v, ThemeKind::Dark, 100, 30);
        assert_eq!(v.handle_mouse(click, 0, 0), None);
        assert_eq!(v.mode, Mode::List);
        render(&v, ThemeKind::Dark, 100, 30);
        assert_eq!(v.handle_mouse(click, 0, 0), Some(ServersAction::Close));
    }
}
