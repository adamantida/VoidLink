//! Отрисовка TUI: шапка, списки, таблица участников, лог, трафик, статус-бар,
//! попапы.
//!
//! Геометрия для мыши (`App::hits`) пишется здесь же каждый кадр. Списки
//! рисуются так, что их строки начинаются сразу под верхней рамкой панели
//! (у таблицы участников — под строкой заголовка): на это опирается
//! `App::hit`. Полосы прокрутки рисуются поверх правой рамки и строк не
//! сдвигают.

use std::cell::RefCell;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, LineGauge, List, ListItem, ListState, Paragraph, Row,
    Scrollbar, ScrollbarOrientation, ScrollbarState, Sparkline, Table, TableState, Tabs, Wrap,
};

use tunnel_protocol as proto;

use crate::path::PathKind;
use crate::snapshot::PathSnap;
use crate::tui::app::{
    App, ConfirmPopup, Focus, FriendCardPopup, InputPopup, InvitePopup, ListPickPopup, MsgKind,
    PathPinPopup, PeerCardPopup, PeerPickPopup, PeerView, Popup, SETTING_ROWS, SettingsPopup,
    TOOLBAR,
};
use crate::tui::badges::{self, BadgeState, ConnState};
use crate::tui::clock;
use crate::tui::identicon::Identicon;
use crate::tui::theme::{Btn, Theme};

/// Ёмкость группы: адреса 100.66.<gid>.2 … .254.
const GROUP_CAP: u32 = 253;
/// Панель трафика рядом с логом — только если по ширине влезает и то и другое.
const TRAFFIC_W: u16 = 32;
const TRAFFIC_MIN_TOTAL: u16 = 72;

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let th = Theme::of(app.theme_kind);

    // Геометрия для мыши собирается заново каждый кадр.
    app.hits.toolbar.borrow_mut().clear();
    app.hits.popup_buttons.borrow_mut().clear();
    app.hits.tabs.borrow_mut().clear();
    app.hits.popup.set(Rect::default());
    app.hits.popup_off.set(0);
    app.hits.groups.set((Rect::default(), 0));
    app.hits.friends.set((Rect::default(), 0));
    app.hits.peers.set((Rect::default(), 0));
    app.hits.log.set(Rect::default());
    app.hits.toasts.set(Rect::default());

    // Фон всего кадра — цветом темы: светлая тема не зависит от фона терминала.
    f.render_widget(Block::default().style(th.frame()), area);

    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Min(8),
        Constraint::Length(8),
        Constraint::Length(1),
    ])
    .split(area);

    draw_header(f, app, &th, chunks[0]);
    draw_toolbar(f, app, &th, chunks[1]);
    draw_body(f, app, &th, chunks[2]);
    let traffic_panel = chunks[3].width >= TRAFFIC_MIN_TOTAL;
    if traffic_panel {
        let cols = Layout::horizontal([Constraint::Min(30), Constraint::Length(TRAFFIC_W)])
            .split(chunks[3]);
        draw_log(f, app, &th, cols[0], false);
        draw_traffic(f, app, &th, cols[1]);
    } else {
        // Узко: вместо панели трафика — текущая скорость в заголовке лога.
        draw_log(f, app, &th, chunks[3], true);
    }
    draw_status(f, app, &th, chunks[4]);

    if let Some(popup) = app.stack.last() {
        draw_popup(f, app, &th, popup, area);
    }
    draw_toasts(f, app, &th, area);
}

// ---------------------------------------------------------------- общие детали

/// Панель со скруглённой рамкой: заголовок с иконкой и счётчиком-«пилюлей»,
/// подсказка снизу справа.
fn panel_block(
    th: &Theme,
    icon: &str,
    title: String,
    badge: Option<String>,
    focused: bool,
    bottom: Option<String>,
) -> Block<'static> {
    let mut spans = vec![Span::styled(
        format!(" {icon} {title} "),
        if focused {
            th.title
        } else {
            th.dim.add_modifier(Modifier::BOLD)
        },
    )];
    if let Some(badge) = badge {
        spans.push(Span::styled(
            format!(" {badge} "),
            if focused {
                th.pill(th.c.accent)
            } else {
                th.chip()
            },
        ));
        spans.push(Span::raw(" "));
    }
    let mut b = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if focused {
            th.focused_border
        } else {
            th.unfocused_border
        })
        .style(th.surface())
        .title(Line::from(spans));
    if let Some(bottom) = bottom {
        b = b.title_bottom(Line::from(Span::styled(format!(" {bottom} "), th.dim)).right_aligned());
    }
    b
}

/// Рамка попапа: скруглённая, с фоном панели.
fn popup_block(th: &Theme, title: Line<'static>, border: Style) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border)
        .style(th.surface())
        .title(title)
}

fn popup_title(th: &Theme, icon: &str, text: &str) -> Line<'static> {
    Line::from(Span::styled(format!(" {icon} {text} "), th.title))
}

/// Вертикальная полоса прокрутки поверх правой рамки, строки `rows` панели
/// `area`. Рисуется, только если список не влезает.
fn scrollbar(
    f: &mut Frame,
    th: &Theme,
    area: Rect,
    rows: Rect,
    total: usize,
    offset: usize,
    focused: bool,
) {
    let visible = rows.height as usize;
    if area.width < 2 || visible == 0 || total <= visible {
        return;
    }
    let track = Rect {
        x: area.right() - 1,
        y: rows.y,
        width: 1,
        height: rows.height,
    };
    let mut state = ScrollbarState::new(total - visible + 1)
        .position(offset.min(total - visible))
        .viewport_content_length(visible);
    let sb = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None)
        .track_symbol(Some("│"))
        .thumb_symbol("█")
        .track_style(if focused {
            th.focused_border
        } else {
            th.scroll_track()
        })
        .thumb_style(if focused {
            th.accent
        } else {
            th.scroll_thumb()
        });
    f.render_stateful_widget(sb, track, &mut state);
}

/// Строки внутри рамки (без рамки).
fn inner(area: Rect) -> Rect {
    Rect {
        x: area.x.saturating_add(1),
        y: area.y.saturating_add(1),
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    }
}

// ---------------------------------------------------------------- шапка

fn draw_header(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(th.focused_border)
        .style(th.header())
        .title(Line::from({
            let mut t = vec![
                Span::styled(" ◆ ", th.accent),
                Span::styled("Tunnel ", th.title),
            ];
            // Где движок: embedded (в этом процессе) или демон (PLAN.md 7.4).
            if let Some(m) = app.mode {
                t.push(Span::styled(format!("· {} ", m.label()), th.dim));
            }
            t
        }));
    let body = block.inner(area);
    f.render_widget(block, area);
    if body.is_empty() {
        return;
    }

    let (pill_text, pill_style) = match app.conn {
        ConnState::Online => (" ● в сети ", th.pill(th.c.success)),
        ConnState::Reconnecting => (" ○ сервер недоступен ", th.pill(th.c.danger)),
        ConnState::DaemonDown => (" ⚠ демон недоступен ", th.pill(th.c.danger)),
        ConnState::NoServer => (" ○ нет сервера ", th.pill(th.c.warn)),
    };
    let pill_w = Span::raw(pill_text).width() as u16;
    let cols = Layout::horizontal([Constraint::Min(1), Constraint::Length(pill_w + 1)]).split(body);

    let server = if app.server_addr.is_empty() {
        "—".to_string()
    } else {
        app.server_addr.clone()
    };
    let name = if app.my_name.is_empty() {
        "(без имени)".to_string()
    } else {
        app.my_name.clone()
    };
    let mut spans = vec![Span::styled(
        format!(" {name} "),
        th.base.add_modifier(Modifier::BOLD),
    )];
    if !app.my_status.is_empty() {
        spans.push(Span::styled(format!("· {} ", app.my_status), th.dim));
    }
    if !app.server_label.is_empty() {
        spans.push(Span::styled(format!("· {} ", app.server_label), th.dim));
    }
    spans.push(Span::styled("· сервер ", th.dim));
    spans.push(Span::styled(server, th.accent));
    if !app.status_msg.is_empty() {
        spans.push(Span::styled(format!(" · {}", app.status_msg), th.warn));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), cols[0]);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(pill_text, pill_style))).right_aligned(),
        cols[1],
    );
}

// ---------------------------------------------------------------- панель действий

/// Ширина кнопки в клетках: чип — « подпись » (пробелы вокруг), выделение
/// клавиши `keycap` меняет только стиль, не ширину.
fn chip_width(label: &str) -> u16 {
    Span::raw(label).width() as u16 + 2
}

/// Ширина ряда кнопок с зазорами `gap` между ними.
fn buttons_width(items: &[(&str, Btn, KeyEvent)], gap: u16) -> u16 {
    let n = items.len() as u16;
    items.iter().map(|(l, _, _)| chip_width(l)).sum::<u16>() + gap * n.saturating_sub(1)
}

/// Необязательная кнопка «путь до участника» (Shift+P): в [`TOOLBAR`] её нет,
/// потому что на 80 колонках ряд не влезает и без неё (issue #22).
const PATH_BTN: (&str, KeyCode, KeyModifiers) = ("P путь", KeyCode::Char('P'), KeyModifiers::NONE);

/// Кнопки панели действий: постоянные подписи плюс «P путь» сразу за
/// «p профиль», если весь ряд помещается в `width`. Иначе кнопку не добавляем:
/// `draw_buttons` молча выбрасывает не влезшие, и вместе с ней пропали бы
/// «F3 настройки» и «: команда».
fn toolbar_items(width: u16) -> Vec<(&'static str, Btn, KeyEvent)> {
    let mut items: Vec<(&'static str, Btn, KeyEvent)> = TOOLBAR
        .iter()
        .map(|(label, code, mods)| (*label, Btn::Normal, KeyEvent::new(*code, *mods)))
        .collect();
    let Some(at) = TOOLBAR
        .iter()
        .position(|(_, code, _)| *code == KeyCode::Char('p'))
        .map(|i| i + 1)
    else {
        return items;
    };
    let mut probe = items.clone();
    probe.insert(
        at,
        (
            PATH_BTN.0,
            Btn::Normal,
            KeyEvent::new(PATH_BTN.1, PATH_BTN.2),
        ),
    );
    if buttons_width(&probe, 1) <= width {
        items = probe;
    }
    items
}

/// Кнопки-клавиши под шапкой: клик по ним = нажатие клавиши.
fn draw_toolbar(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let row = Rect {
        x: area.x + 1,
        width: area.width.saturating_sub(1),
        ..area
    };
    let items = toolbar_items(row.width);
    draw_buttons(f, th, &app.hits.toolbar, row, &items, 1, true);
}

/// Строка кнопок: рисует их и запоминает в `hits`, куда кликать. Кнопки,
/// которые не влезли по ширине, не рисуются. `keycap` — выделить первое
/// слово подписи (клавишу), как в панели действий.
fn draw_buttons(
    f: &mut Frame,
    th: &Theme,
    hits: &RefCell<Vec<(Rect, KeyEvent)>>,
    row: Rect,
    items: &[(&str, Btn, KeyEvent)],
    gap: u16,
    keycap: bool,
) {
    if row.width == 0 || row.height == 0 {
        return;
    }
    let mut hits = hits.borrow_mut();
    let mut spans = Vec::new();
    let mut x = row.x;
    for (label, kind, key) in items {
        let style = th.button(*kind);
        let chip: Vec<Span> = match label.split_once(' ') {
            Some((cap, rest)) if keycap => vec![
                Span::styled(
                    format!(" {cap}"),
                    style.fg(th.c.accent).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(" {rest} "), style),
            ],
            _ => vec![Span::styled(format!(" {label} "), style)],
        };
        let w = chip_width(label);
        if x + w > row.right() {
            break;
        }
        hits.push((Rect::new(x, row.y, w, 1), *key));
        spans.extend(chip);
        spans.push(Span::raw(" ".repeat(gap as usize)));
        x += w + gap;
    }
    f.render_widget(Paragraph::new(Line::from(spans)), Rect { height: 1, ..row });
}

/// Строка внутри рамки попапа (`n` — номер строки от верхней границы).
fn inner_row(rect: Rect, n: u16) -> Rect {
    let y = rect.y + 1 + n;
    if rect.width < 3 || y + 1 >= rect.bottom() {
        return Rect::default();
    }
    Rect::new(rect.x + 1, y, rect.width - 2, 1)
}

/// Строка кнопок с отступом от рамки.
fn button_row(rect: Rect, n: u16) -> Rect {
    let r = inner_row(rect, n);
    if r.width < 2 {
        return r;
    }
    Rect {
        x: r.x + 1,
        width: r.width - 1,
        ..r
    }
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

// ---------------------------------------------------------------- тело

fn draw_body(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let cols = Layout::horizontal([Constraint::Percentage(32), Constraint::Min(40)]).split(area);
    let left =
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).split(cols[0]);

    draw_groups(f, app, th, left[0]);
    draw_friends(f, app, th, left[1]);
    draw_peers(f, app, th, cols[1]);
}

fn list_title(name: &str, filter: &str) -> String {
    if filter.is_empty() {
        name.to_string()
    } else {
        format!("{name} /{filter}")
    }
}

fn draw_groups(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let list = app.visible_groups();
    let focused = app.focus == Focus::Groups;
    let block = panel_block(
        th,
        "≡",
        list_title("Группы", &app.filter),
        Some(list.len().to_string()),
        focused,
        None,
    );

    let items: Vec<ListItem> = list
        .iter()
        .map(|g| {
            // Доступная федерированная группа (`FED_GROUPS`, T4): метка и
            // отдельный значок, вход — по uuid (JOIN_FED).
            let fed = app.fed_group(g.gid).is_some();
            let (mark, mark_style) = if g.mine {
                ("●", th.ok)
            } else {
                ("○", th.dim)
            };
            let mut spans = vec![Span::styled(format!("{mark} "), mark_style)];
            if fed {
                spans.push(Span::styled("⇄ ", th.accent));
            }
            spans.push(Span::styled(
                g.name.clone(),
                if g.mine { th.base } else { th.dim },
            ));
            if g.private {
                spans.push(Span::styled(" [priv]", th.warn));
            }
            if fed {
                spans.push(Span::styled("  [федерация]", th.accent));
            } else if g.mine {
                spans.push(Span::styled(format!("  {}/{}", g.online, g.total), th.dim));
            } else if g.private {
                spans.push(Span::styled("  (по приглашению)", th.dim));
            } else {
                spans.push(Span::styled("  (публичная)", th.dim));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let mut state = ListState::default();
    if let Some(sel) = app
        .sel_group
        .and_then(|g| list.iter().position(|x| x.gid == g))
    {
        state.select(Some(sel));
    }
    let total = items.len();
    let widget = List::new(items)
        .block(block)
        .highlight_style(th.selection(focused))
        .highlight_symbol("▌ ");
    f.render_stateful_widget(widget, area, &mut state);
    scrollbar(f, th, area, inner(area), total, state.offset(), focused);
    app.hits.groups.set((area, state.offset()));
}

fn draw_friends(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let list = app.visible_friends();
    let focused = app.focus == Focus::Friends;
    let online = list.iter().filter(|x| x.online).count();
    let block = panel_block(
        th,
        "◇",
        list_title("Друзья", &app.filter),
        Some(format!("{online}/{}", list.len())),
        focused,
        None,
    );

    let items: Vec<ListItem> = list
        .iter()
        .map(|fr| {
            let (mark, style) = if fr.online {
                ("●", th.ok)
            } else {
                ("○", th.dim)
            };
            let mut spans = vec![Span::styled(format!("{mark} "), style)];
            spans.push(Span::styled(
                fr.display(),
                if fr.online { th.base } else { th.dim },
            ));
            // Маркер состояния (issue #24): заявка отправлена/пришла,
            // локальная запись. Обычная дружба маркера не имеет — это норма.
            if let Some(badge) = fr.badge() {
                spans.push(Span::styled(format!("  {badge}"), th.warn));
            }
            if fr.shared_groups > 0 {
                spans.push(Span::styled(
                    format!("  {} общих", fr.shared_groups),
                    th.dim,
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let mut state = ListState::default();
    if let Some(sel) = app
        .sel_friend
        .and_then(|f| list.iter().position(|x| x.pubkey == f))
    {
        state.select(Some(sel));
    }
    let total = items.len();
    let widget = List::new(items)
        .block(block)
        .highlight_style(th.selection(focused))
        .highlight_symbol("▌ ");
    f.render_stateful_widget(widget, area, &mut state);
    scrollbar(f, th, area, inner(area), total, state.offset(), focused);
    app.hits.friends.set((area, state.offset()));
}

fn draw_peers(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let g = app.selected_group();
    let focused = app.focus == Focus::Peers;
    let title = match g {
        Some(g) => {
            let kind = if g.private {
                "приватная"
            } else {
                "публичная"
            };
            let mine = g
                .my_ip
                .map(|ip| format!(" · мой IP {}", proto::ip_str(ip)))
                .unwrap_or_default();
            format!("Группа {} «{}» ({}){mine}", g.gid, g.name, kind)
        }
        None => "Группа".to_string(),
    };
    let bottom = Some(format!("сортировка: {} · s — сменить", app.sort.label()));
    let block = panel_block(th, "◆", title, None, focused, bottom);
    let body = block.inner(area);
    f.render_widget(block, area);

    // Нижняя строка панели — шкала заполненности группы (если есть место).
    let gauge = g.is_some() && body.height >= 4;
    let table_area = if gauge {
        Rect {
            height: body.height - 1,
            ..body
        }
    } else {
        body
    };

    // Колонка «путь» (этап 9). На узком терминале её нет вовсе — таблица
    // остаётся читаемой; на среднем — короткие метки без RTT и хопов.
    let path_w: u16 = if table_area.width >= 92 {
        // «⇄ через <6 hex> 33 мс (2 хопа)» — 29 клеток.
        32
    } else if table_area.width >= 76 {
        24
    } else if table_area.width >= 64 {
        16
    } else {
        0
    };
    let mut head = vec![
        Cell::from("имя"),
        Cell::from("IP"),
        Cell::from("связь"),
        Cell::from("RTT"),
    ];
    if path_w > 0 {
        head.push(Cell::from("путь"));
    }
    head.push(Cell::from("статус"));
    let header = Row::new(head).style(th.header().fg(th.c.text_muted).add_modifier(Modifier::BOLD));

    let mut rows: Vec<Row> = Vec::new();

    // Строка «я».
    if let Some(g) = g {
        let mut cells = vec![
            Cell::from(Span::styled(
                format!("{} (я)", app.my_name),
                Style::default()
                    .fg(th.c.accent_alt)
                    .add_modifier(Modifier::BOLD),
            )),
            Cell::from(Span::styled(
                g.my_ip.map(proto::ip_str).unwrap_or_default(),
                th.accent,
            )),
            Cell::from(Span::styled("—", th.dim)),
            Cell::from(Span::styled("—", th.dim)),
        ];
        if path_w > 0 {
            // До себя пути нет: путь — маршрут доставки до участника.
            cells.push(Cell::from(Span::styled("—", th.dim)));
        }
        cells.push(Cell::from(Span::styled(app.my_status.clone(), th.dim)));
        rows.push(Row::new(cells));
    }

    let peers = app.visible_peers();
    for p in peers.iter() {
        let link = if !p.online {
            ("○ офлайн", th.offline)
        } else if p.direct {
            ("◆ direct", th.direct)
        } else {
            ("◇ relay", th.relay)
        };
        // RTT офлайн-участника не показываем (issue #18): замер остался с
        // прошлой сессии, и «48 мс» у строки «офлайн» — выдумка.
        let rtt_ms = p.rtt_ms.filter(|_| p.online);
        let rtt = match rtt_ms {
            Some(v) => format!("{v} мс"),
            None => "—".to_string(),
        };
        let rtt_style = match rtt_ms {
            Some(v) if v < 50 => th.ok,
            Some(v) if v < 150 => th.warn,
            Some(_) => th.error,
            None => th.dim,
        };
        let mut cells = vec![
            Cell::from(p.name.clone()),
            Cell::from(proto::ip_str(p.ip)),
            Cell::from(Span::styled(link.0, link.1)),
            Cell::from(Span::styled(rtt, rtt_style)),
        ];
        if path_w > 0 {
            let (text, style) = path_cell(app, th, p, path_w < 30);
            cells.push(Cell::from(Span::styled(text, style)));
        }
        cells.push(Cell::from(Span::styled(p.status.clone(), th.dim)));
        rows.push(Row::new(cells).style(if p.online { th.base } else { th.offline }));
    }

    if rows.len() <= 1 {
        rows.push(Row::new(vec![Cell::from(Span::styled(
            "(пока никого нет)",
            th.dim,
        ))]));
    }

    let mut widths = vec![
        Constraint::Min(10),
        Constraint::Length(14),
        Constraint::Length(9),
        Constraint::Length(7),
    ];
    if path_w > 0 {
        widths.push(Constraint::Length(path_w));
    }
    widths.push(Constraint::Fill(1));
    let total = rows.len();
    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(th.selection(focused))
        .highlight_symbol("▌ ");

    let mut state = TableState::default();
    // Индексы в таблице: 0 — строка «я», дальше — участники.
    if let Some(sel) = app
        .sel_peer
        .and_then(|p| peers.iter().position(|x| x.pubkey == p))
    {
        state.select(Some(sel + 1));
    }
    f.render_stateful_widget(table, table_area, &mut state);
    let rows_area = Rect {
        y: table_area.y.saturating_add(1),
        height: table_area.height.saturating_sub(1),
        ..table_area
    };
    scrollbar(f, th, area, rows_area, total, state.offset(), focused);
    // Для мыши — рамка «как будто» вокруг одной таблицы: строка шкалы
    // играет роль нижней рамки и в строки не попадает.
    let hit_rect = Rect {
        height: (table_area.height + 2).min(area.height),
        ..area
    };
    app.hits.peers.set((hit_rect, state.offset()));

    if let (true, Some(g)) = (gauge, g) {
        let row = Rect {
            x: body.x + 1,
            y: body.bottom() - 1,
            width: body.width.saturating_sub(2),
            height: 1,
        };
        let ratio = (g.total as f64 / GROUP_CAP as f64).clamp(0.0, 1.0);
        let label = Line::from(vec![
            Span::styled("занято ", th.dim),
            Span::styled(
                format!("{}/{GROUP_CAP}", g.total),
                th.base.add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" · онлайн {}", g.online), th.dim),
        ]);
        let lg = LineGauge::default()
            .ratio(ratio)
            .label(label)
            .filled_symbol("━")
            .unfilled_symbol("─")
            .filled_style(th.gauge_filled())
            .unfilled_style(th.gauge_unfilled());
        f.render_widget(lg, row);
    }
}

// ---------------------------------------------------------------- путь

/// Хопов у L2-реле всегда два: мы → реле → участник. Движок пока не считает
/// длину маршрута в хопах, для промежуточного реле она постоянна.
const RELAY_HOPS: u32 = 2;

/// Текст метки пути (этап 9): `◆ прямой 12 мс`, `◇ сервер 48 мс, плечо 1 мс`,
/// `⇄ через <реле> 33 мс (2 хопа)`; `—` — пути нет или участник офлайн.
/// `short` — узкая колонка: без RTT, хопов и плеча, чтобы метка влезла.
fn path_text(app: &App, p: &PeerView, short: bool) -> String {
    // Офлайн-участник пути не имеет (issue #18): в кэше мог остаться путь с
    // прошлого пересчёта, но показывать его — значит врать.
    if !p.online {
        return "—".to_string();
    }
    let Some(snap) = &p.path else {
        return "—".to_string();
    };
    match &snap.kind {
        PathKind::Direct => match (short, snap.rtt_ms) {
            (false, Some(ms)) => format!("◆ прямой {ms} мс"),
            _ => "◆ прямой".to_string(),
        },
        // Полный RTT и плечо «мы → сервер» отдельно: видно, из чего сложилась
        // цифра (issue #15/#18).
        PathKind::Server => match (short, snap.rtt_ms, snap.leg_ms) {
            (false, Some(ms), Some(leg)) => format!("◇ сервер {ms} мс, плечо {leg} мс"),
            (false, Some(ms), None) => format!("◇ сервер {ms} мс"),
            (false, None, Some(leg)) => format!("◇ сервер, плечо {leg} мс"),
            _ => "◇ сервер".to_string(),
        },
        PathKind::PeerRelay { via } => {
            let relay = app.peer_name_or_short(via);
            if short {
                format!("⇄ {relay}")
            } else {
                let rtt = match snap.rtt_ms {
                    Some(ms) => format!(" {ms} мс"),
                    None => String::new(),
                };
                format!("⇄ через {relay}{rtt} ({RELAY_HOPS} хопа)")
            }
        }
    }
}

/// Колонка «путь» таблицы участников: текст и стиль под вид пути.
fn path_cell(app: &App, th: &Theme, p: &PeerView, short: bool) -> (String, Style) {
    // Офлайн — всегда «—» и приглушённый стиль: путь из кэша мог остаться с
    // прошлого пересчёта (issue #18).
    if !p.online {
        return ("—".to_string(), th.offline);
    }
    let style = match p.path.as_ref().map(|s| &s.kind) {
        Some(PathKind::Direct) => th.direct,
        Some(PathKind::Server) => th.accent,
        Some(PathKind::PeerRelay { .. }) => th.relay,
        None => th.dim,
    };
    (path_text(app, p, short), style)
}

// ---------------------------------------------------------------- лог

fn draw_log(f: &mut Frame, app: &App, th: &Theme, area: Rect, rates: bool) {
    let focused = app.focus == Focus::Log;
    let mut block = panel_block(
        th,
        "»",
        "Лог".to_string(),
        None,
        focused,
        Some("PgUp/PgDn или колесо — прокрутка".to_string()),
    );
    if rates {
        let rx_rate = app.rx_hist.last().copied().unwrap_or(0);
        let tx_rate = app.tx_hist.last().copied().unwrap_or(0);
        block = block.title_top(
            Line::from(vec![
                Span::styled(format!(" ↓{}/с", kb(rx_rate)), th.chart_rx()),
                Span::styled(format!(" ↑{}/с ", kb(tx_rate)), th.chart_tx()),
            ])
            .right_aligned(),
        );
    }
    let inner_height = area.height.saturating_sub(2) as usize;
    let total = app.log.len();
    let end = total.saturating_sub(app.log_scroll);
    let start = end.saturating_sub(inner_height);

    let lines: Vec<Line> = app.log[start..end]
        .iter()
        .map(|l| {
            let (mark, style) = match l.kind {
                MsgKind::Info => ("·", th.dim),
                MsgKind::Ok => ("✓", th.ok),
                MsgKind::Warn => ("!", th.warn),
                MsgKind::Error => ("✗", th.error),
            };
            Line::from(vec![
                Span::styled(format!("{} ", clock::format_local(l.wall)), th.dim),
                Span::styled(format!("{mark} "), style.add_modifier(Modifier::BOLD)),
                Span::styled(
                    l.text.clone(),
                    if l.kind == MsgKind::Info {
                        th.base
                    } else {
                        style
                    },
                ),
            ])
        })
        .collect();

    f.render_widget(Paragraph::new(lines).block(block), area);
    scrollbar(f, th, area, inner(area), total, start, focused);
    app.hits.log.set(area);
}

// ---------------------------------------------------------------- трафик

/// Последние `n` значений истории (график показывает самые свежие секунды).
fn tail(v: &[u64], n: usize) -> &[u64] {
    &v[v.len().saturating_sub(n)..]
}

fn draw_traffic(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    // Ширина графика = число последних секунд истории на экране.
    let n = area.width.saturating_sub(2) as usize;
    let rx = tail(&app.rx_hist, n);
    let tx = tail(&app.tx_hist, n);
    // Общий масштаб: высоты столбиков приёма и передачи сравнимы.
    let peak = rx.iter().chain(tx).copied().max().unwrap_or(0);
    let max = peak.max(1024);
    let block = panel_block(
        th,
        "↕",
        "Трафик".to_string(),
        None,
        false,
        Some(format!("пакеты {}/{}", app.rx_pkts, app.tx_pkts)),
    )
    .title_top(Line::from(Span::styled(format!(" пик {}/с ", kb(peak)), th.dim)).right_aligned());
    let body = block.inner(area);
    f.render_widget(block, area);
    if body.is_empty() {
        return;
    }
    let rx_rate = app.rx_hist.last().copied().unwrap_or(0);
    let tx_rate = app.tx_hist.last().copied().unwrap_or(0);

    let label = |arrow: &str, name: &str, rate: u64, style: Style| {
        Line::from(vec![
            Span::styled(format!("{arrow} "), style.add_modifier(Modifier::BOLD)),
            Span::styled(format!("{name} "), th.dim),
            Span::styled(
                format!("{}/с", kb(rate)),
                style.add_modifier(Modifier::BOLD),
            ),
        ])
    };
    let rx_label = label("↓", "приём", rx_rate, th.chart_rx());
    let tx_label = label("↑", "передача", tx_rate, th.chart_tx());

    if body.height < 4 {
        let lines = vec![rx_label, tx_label];
        f.render_widget(Paragraph::new(lines), body);
        return;
    }
    let spark_h = (body.height - 2) / 2;
    let parts = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(spark_h),
        Constraint::Length(1),
        Constraint::Min(1),
    ])
    .split(body);
    f.render_widget(Paragraph::new(rx_label), parts[0]);
    f.render_widget(
        Sparkline::default().data(rx).max(max).style(th.chart_rx()),
        parts[1],
    );
    f.render_widget(Paragraph::new(tx_label), parts[2]);
    f.render_widget(
        Sparkline::default().data(tx).max(max).style(th.chart_tx()),
        parts[3],
    );
}

// ---------------------------------------------------------------- статус

/// Вкладки фокуса в порядке Tab.
const TABS: [Focus; 4] = [Focus::Groups, Focus::Friends, Focus::Peers, Focus::Log];

/// «группы» → «Группы».
fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

fn draw_status(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    f.render_widget(Block::default().style(th.header()), area);
    if area.is_empty() {
        return;
    }

    // Вкладки фокуса: подсвечена текущая панель, клик — перейти в неё.
    let titles: Vec<String> = TABS
        .iter()
        .map(|f| format!(" {} ", capitalize(f.label())))
        .collect();
    let tabs_w: u16 = titles
        .iter()
        .map(|t| Span::raw(t.as_str()).width() as u16)
        .sum::<u16>()
        + TABS.len() as u16
        - 1;
    let tabs_area = Rect {
        width: tabs_w.min(area.width),
        ..area
    };
    let sel = TABS.iter().position(|f| *f == app.focus);
    let tabs = Tabs::new(titles.iter().map(|t| Line::from(t.as_str())))
        .select(sel)
        .style(th.tab_inactive())
        .highlight_style(th.tab_active())
        .divider(Span::styled("│", th.unfocused_border))
        .padding("", "");
    f.render_widget(tabs, tabs_area);
    {
        let mut hits = app.hits.tabs.borrow_mut();
        let mut x = tabs_area.x;
        for (t, focus) in titles.iter().zip(TABS.iter()) {
            let w = Span::raw(t.as_str()).width() as u16;
            if x + w > tabs_area.right() {
                break;
            }
            hits.push((Rect::new(x, area.y, w, 1), *focus));
            x += w + 1;
        }
    }

    let my_ip = app
        .selected_group()
        .and_then(|g| g.my_ip)
        .map(proto::ip_str)
        .unwrap_or_else(|| "—".into());
    let (direct, relay) = app.peers.iter().fold((0usize, 0usize), |(d, r), p| {
        if !p.online {
            (d, r)
        } else if p.direct {
            (d + 1, r)
        } else {
            (d, r + 1)
        }
    });

    let mut spans = vec![
        Span::raw("  "),
        Span::styled(" IP ", th.chip()),
        Span::styled(format!(" {my_ip} "), th.pill(th.c.accent)),
        Span::styled(
            format!("  ≡ {}", app.groups.iter().filter(|g| g.mine).count()),
            th.accent,
        ),
        Span::styled(" групп", th.dim),
    ];
    // Mesh (этап 9): релей и живые сессии. Нулевой релей показываем как
    // «реле 0» — счётчик не исчезает и не прыгает при первом байте.
    if app.mesh_enabled {
        spans.push(Span::styled("  реле ", th.dim));
        spans.push(Span::styled(relay_bytes_text(app.relay_bytes), th.relay));
        if app.mesh_sessions > 0 {
            spans.push(Span::styled("  mesh ", th.dim));
            spans.push(Span::styled(sessions_text(app.mesh_sessions), th.base));
        }
    }
    if app.filtering || !app.filter.is_empty() {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!(" /{} ", app.filter),
            th.pill(th.c.warn),
        ));
    }
    let rest = Rect {
        x: tabs_area.right(),
        width: area.width - tabs_area.width,
        ..area
    };
    let left = Line::from(spans);
    let left_w = (left.width() as u16).min(rest.width);
    f.render_widget(Paragraph::new(left), rest);

    // Бейджи справа: соединение, приглашения (клик — «o»), невидимка,
    // транспорт, прямые/релейные пиры.
    let state = BadgeState {
        pending_invites: app.pending_invites(),
        conn: app.conn,
        invisible: app.invisible,
        transport: app.transport,
        direct,
        relay,
        pending_edits: app.pending_edits,
    };
    let badges_area = Rect {
        x: rest.x + left_w + 1,
        width: rest.width.saturating_sub(left_w + 1),
        ..rest
    };
    f.render_widget(Clear, badges_area);
    f.render_widget(Block::default().style(th.header()), badges_area);
    let hits = badges::render_badges(f, badges_area, &state, th);
    app.hits.toolbar.borrow_mut().extend(hits);
}

/// Сколько осталось до истечения: «6 д», «5 ч», «12 мин».
fn left_until(t: std::time::Instant) -> String {
    let s = t
        .saturating_duration_since(std::time::Instant::now())
        .as_secs();
    if s == 0 {
        "истекло".into()
    } else if s >= 86_400 {
        format!("истекает через {} д", s / 86_400)
    } else if s >= 3600 {
        format!("истекает через {} ч", s / 3600)
    } else if s >= 60 {
        format!("истекает через {} мин", s / 60)
    } else {
        "истекает меньше чем через минуту".into()
    }
}

// ---------------------------------------------------------------- тосты

fn draw_toasts(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    if app.toasts.is_empty() {
        return;
    }
    let w = 52.min(area.width.saturating_sub(4));
    let max_h = area.height.saturating_sub(2);
    if w < 3 || max_h < 3 {
        return;
    }
    // Высота — по строкам после переноса (длинный тост занимает несколько);
    // не влезают — уходят старые, новый виден всегда.
    let heights: Vec<u16> = app
        .toasts
        .iter()
        .map(|t| {
            wrapped_lines(
                &format!("{} {}", toast_mark(t.kind), t.text),
                (w - 2) as usize,
            ) as u16
        })
        .collect();
    let mut skip = 0;
    let mut total: u16 = heights.iter().sum();
    while total + 2 > max_h && skip + 1 < heights.len() {
        total -= heights[skip];
        skip += 1;
    }
    let h = (total + 2).min(max_h);
    let x = area.x + area.width.saturating_sub(w + 1);
    let y = area.y + area.height.saturating_sub(h + 2);
    let rect = Rect {
        x,
        y,
        width: w,
        height: h,
    };
    app.hits.toasts.set(rect);
    f.render_widget(Clear, rect);
    let border = match app
        .toasts
        .iter()
        .map(|t| t.kind)
        .max_by_key(|k| severity(*k))
    {
        Some(MsgKind::Error) => th.error,
        Some(MsgKind::Warn) => th.warn,
        Some(MsgKind::Ok) => th.ok,
        _ => th.accent,
    };
    let block = popup_block(th, Line::default(), border);
    let lines: Vec<Line> = app
        .toasts
        .iter()
        .skip(skip)
        .map(|t| {
            let mark = toast_mark(t.kind);
            let style = match t.kind {
                MsgKind::Info => th.accent,
                MsgKind::Ok => th.ok,
                MsgKind::Warn => th.warn,
                MsgKind::Error => th.error,
            };
            Line::from(vec![
                Span::styled(format!("{mark} "), style.add_modifier(Modifier::BOLD)),
                Span::styled(
                    t.text.clone(),
                    if t.kind == MsgKind::Info {
                        th.base
                    } else {
                        style
                    },
                ),
            ])
        })
        .collect();
    let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    f.render_widget(p, rect);
}

fn toast_mark(k: MsgKind) -> &'static str {
    match k {
        MsgKind::Info => "•",
        MsgKind::Ok => "✓",
        MsgKind::Warn => "!",
        MsgKind::Error => "✗",
    }
}

fn severity(k: MsgKind) -> u8 {
    match k {
        MsgKind::Info => 0,
        MsgKind::Ok => 1,
        MsgKind::Warn => 2,
        MsgKind::Error => 3,
    }
}

// ---------------------------------------------------------------- попапы

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}

/// Место под попап: запомнить для мыши и очистить.
fn open_popup(f: &mut Frame, app: &App, rect: Rect) {
    app.hits.popup.set(rect);
    f.render_widget(Clear, rect);
}

fn draw_popup(f: &mut Frame, app: &App, th: &Theme, popup: &Popup, area: Rect) {
    match popup {
        Popup::Help => {
            let lines = help_lines(th);
            let rect = centered(area, 74, lines.len() as u16 + 2);
            open_popup(f, app, rect);
            let block = popup_block(th, popup_title(th, "?", "Справка (F1)"), th.focused_border)
                .title_bottom(Line::from(Span::styled(
                    " Esc или клик мимо окна — закрыть ",
                    th.dim,
                )))
                .padding(ratatui::widgets::Padding::horizontal(1));
            f.render_widget(Paragraph::new(lines).block(block), rect);
        }
        Popup::Input(inp) => {
            let rect = centered(area, 70, 7);
            open_popup(f, app, rect);
            draw_input(f, app, th, inp, rect);
        }
        Popup::Confirm(c) => {
            // Высота — под текст: строки сообщения + отступ + кнопки + рамка.
            // Строки считаются для той же ширины, что получит окно (узкий
            // терминал), иначе кнопки уезжали за рамку.
            let w = 60.min(area.width);
            let lines = confirm_lines(&c.message, w);
            let rect = centered(area, w, lines + 5);
            open_popup(f, app, rect);
            draw_confirm(f, app, th, c, rect, lines);
        }
        Popup::PeerPick(p) => {
            let h = (p.items.len() as u16 + 4).clamp(8, 20);
            let rect = centered(area, 60, h);
            open_popup(f, app, rect);
            app.hits.popup_off.set(draw_peer_pick(f, th, p, rect));
        }
        Popup::FriendCard(c) => {
            // 5 строк identicon + 6 служебных + группы + кнопки + рамка.
            // Ширина — под friend code целиком (62 символа): обрезанный рамкой
            // код при копировании давал «неверную длину».
            let h = (c.groups.len().max(1) as u16 + 15).min(27);
            let rect = centered(area, 68, h);
            open_popup(f, app, rect);
            draw_friend_card(f, app, th, c, rect);
        }
        Popup::PeerCard(c) => {
            // Высота — по содержимому: строки данных плюс спарклайн RTT, если
            // движок прислал историю (issue #18).
            let body = peer_card_body(app, th, c);
            let rect = centered(area, 62, body.height());
            open_popup(f, app, rect);
            draw_peer_card(f, app, th, c, body, rect);
        }
        Popup::PathPin(p) => {
            // Высота — по содержимому: метрики и спарклайн добавляют строки.
            let body = path_pin_body(app, th, p);
            let rect = centered(area, 52, body.height());
            open_popup(f, app, rect);
            draw_path_pin(f, th, p, body, rect);
        }
        Popup::ListPick(p) => {
            let h = (p.items.len() as u16 + 4).clamp(8, 20);
            let rect = centered(area, 56, h);
            open_popup(f, app, rect);
            app.hits.popup_off.set(draw_list_pick(f, th, p, rect));
        }
        Popup::Settings(s) => {
            let rect = centered(area, 60, 12);
            open_popup(f, app, rect);
            app.hits.popup_off.set(draw_settings(f, app, th, s, rect));
        }
        Popup::Profile => {
            // 5 строк identicon + 9 строк данных + кнопки + рамка.
            let rect = centered(area, 68, 18);
            open_popup(f, app, rect);
            draw_profile(f, app, th, rect);
        }
        Popup::Invite(inv) => {
            let rect = centered(area, 70, 8);
            open_popup(f, app, rect);
            draw_invite(f, app, th, inv, rect);
        }
        Popup::FriendReq(req) => {
            let rect = centered(area, 66, 8);
            open_popup(f, app, rect);
            draw_friend_req(f, app, th, req, rect);
        }
        // Свои рамка и геометрия для мыши — в самих модулях.
        Popup::Admin(v) => crate::tui::admin::draw(f, th, v, area),
        Popup::Servers(v) => v.draw(f, th, area),
    }
}

fn draw_input(f: &mut Frame, app: &App, th: &Theme, inp: &InputPopup, area: Rect) {
    let block = popup_block(th, popup_title(th, "✎", &inp.title), th.focused_border)
        .title_bottom(Line::from(Span::styled(format!(" {} ", inp.hint), th.dim)));
    f.render_widget(block, area);

    let mut value = inp.value.clone();
    if matches!(inp.action, crate::tui::app::InputAction::Command) {
        value = format!(":{value}");
    }
    // Поле ввода — строка 0 на фоне шапки.
    let field = Line::from(vec![
        Span::raw(" "),
        Span::styled(value, th.base),
        Span::styled("▏", th.accent.add_modifier(Modifier::SLOW_BLINK)),
    ]);
    f.render_widget(Paragraph::new(field).style(th.header()), inner_row(area, 0));
    // Строка 1 — переключатель приватности (клик по ней = Tab, см. App::click).
    if matches!(inp.action, crate::tui::app::InputAction::CreateGroup) {
        let (mark, style) = if inp.private {
            ("[x]", th.ok)
        } else {
            ("[ ]", th.dim)
        };
        let line = Line::from(vec![
            Span::styled(format!(" {mark} "), style.add_modifier(Modifier::BOLD)),
            Span::styled(
                format!(
                    "приватная группа: {}",
                    if inp.private { "да" } else { "нет" }
                ),
                th.base,
            ),
            Span::styled("  (Tab или клик — переключить)", th.dim),
        ]);
        f.render_widget(Paragraph::new(line), inner_row(area, 1));
    }
    draw_buttons(
        f,
        th,
        &app.hits.popup_buttons,
        button_row(area, 3),
        &[
            ("OK (Enter)", Btn::Primary, key(KeyCode::Enter)),
            ("Отмена (Esc)", Btn::Normal, key(KeyCode::Esc)),
        ],
        2,
        false,
    );
}

fn draw_confirm(f: &mut Frame, app: &App, th: &Theme, c: &ConfirmPopup, area: Rect, lines: u16) {
    let block = popup_block(
        th,
        Line::from(Span::styled(
            format!(" ▲ {} ", c.title),
            th.warn.add_modifier(Modifier::BOLD),
        )),
        th.warn,
    );
    f.render_widget(block, area);
    let msg = Rect {
        x: area.x + 2,
        y: area.y + 1,
        width: area.width.saturating_sub(4),
        height: lines.min(area.height.saturating_sub(2)),
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(c.message.clone(), th.base)))
            .wrap(Wrap { trim: true }),
        msg,
    );
    let buttons_at = lines + 1;
    draw_buttons(
        f,
        th,
        &app.hits.popup_buttons,
        button_row(area, buttons_at),
        &[
            ("Да (y)", Btn::Danger, key(KeyCode::Char('y'))),
            ("Отмена (Esc)", Btn::Normal, key(KeyCode::Esc)),
        ],
        2,
        false,
    );
}

/// Сколько строк займёт сообщение подтверждения в окне ширины `w` (1…6).
/// Перенос по словам — как у `Wrap { trim: true }`: слово, не влезающее в
/// остаток строки, уходит на следующую, а длиннее строки — режется. Оценка
/// «символы / ширина» занижала число строк, и конец сообщения обрезался.
fn confirm_lines(msg: &str, w: u16) -> u16 {
    wrapped_lines(msg, w.saturating_sub(4).max(1) as usize).clamp(1, 6) as u16
}

/// Сколько строк займёт `msg` при переносе по словам в ширину `width`
/// (как `Wrap { trim: true }`).
fn wrapped_lines(msg: &str, width: usize) -> usize {
    let width = width.max(1);
    let mut lines = 1usize;
    let mut cur = 0usize; // ширина текущей строки
    for word in msg.split_whitespace() {
        let ww = Span::raw(word).width();
        if cur > 0 && cur + 1 + ww <= width {
            cur += 1 + ww;
            continue;
        }
        if cur > 0 {
            lines += 1;
        }
        // Слово с начала строки; длиннее строки — режется на части.
        lines += ww.saturating_sub(1) / width;
        cur = match ww % width {
            0 if ww > 0 => width,
            r => r,
        };
    }
    lines
}

/// Список в попапе со скруглённой рамкой и полосой прокрутки. Возвращает
/// смещение прокрутки (для мыши).
fn draw_popup_list(
    f: &mut Frame,
    th: &Theme,
    block: Block<'static>,
    items: Vec<ListItem>,
    sel: usize,
    area: Rect,
) -> usize {
    let total = items.len();
    let mut state = ListState::default();
    state.select(Some(sel));
    let list = List::new(items)
        .block(block)
        .highlight_style(th.selected)
        .highlight_symbol("▌ ");
    f.render_stateful_widget(list, area, &mut state);
    scrollbar(f, th, area, inner(area), total, state.offset(), true);
    state.offset()
}

fn draw_peer_pick(f: &mut Frame, th: &Theme, p: &PeerPickPopup, area: Rect) -> usize {
    let block = popup_block(th, popup_title(th, "◆", &p.title), th.focused_border).title_bottom(
        Line::from(Span::styled(
            " клик — выбор, ещё клик/Enter — применить · Esc — отмена ",
            th.dim,
        )),
    );
    let items: Vec<ListItem> = p
        .items
        .iter()
        .map(|i| {
            let (mark, style) = if i.online {
                ("●", th.ok)
            } else {
                ("○", th.dim)
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{mark} "), style),
                Span::styled(i.label.clone(), th.base),
                Span::styled(format!("  {}", i.sub), th.dim),
            ]))
        })
        .collect();
    draw_popup_list(f, th, block, items, p.sel, area)
}

/// Строки identicon (5×5) по pubkey.
fn identicon_lines(pubkey: &[u8; 32]) -> Vec<Line<'static>> {
    let id = Identicon::from_pubkey(pubkey);
    (0..5)
        .map(|r| {
            let spans: Vec<Span> = id
                .row_line(r)
                .into_iter()
                .map(|(s, fg, bg)| Span::styled(s, Style::default().fg(fg).bg(bg)))
                .collect();
            Line::from(spans)
        })
        .collect()
}

fn draw_friend_card(f: &mut Frame, app: &App, th: &Theme, c: &FriendCardPopup, area: Rect) {
    let mut lines = identicon_lines(&c.pubkey);
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("имя: ", th.dim),
        Span::styled(c.alias.clone(), th.base.add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(vec![Span::styled("friend code:", th.dim)]));
    lines.push(Line::from(Span::styled(
        proto::friend_code_of(&c.pubkey),
        th.accent,
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("группы друга:", th.title)));
    if c.loading {
        lines.push(Line::from(Span::styled("загрузка…", th.dim)));
    } else if c.groups.is_empty() {
        lines.push(Line::from(Span::styled("(нет видимых групп)", th.dim)));
    } else {
        for g in c.groups.iter() {
            lines.push(Line::from(vec![
                Span::styled(format!("{} ", g.gid), th.accent),
                Span::styled(g.name.clone(), th.base),
                Span::styled(
                    format!(
                        " {}",
                        if g.private {
                            "[приватная]"
                        } else {
                            "[публичная]"
                        }
                    ),
                    th.dim,
                ),
                Span::styled(if g.shared { "  (общая)" } else { "" }, th.ok),
            ]));
        }
    }
    lines.push(Line::from(""));
    let buttons_at = lines.len() as u16;

    let block = popup_block(
        th,
        popup_title(th, "◇", &format!("Друг: {}", c.alias)),
        th.focused_border,
    );
    f.render_widget(Paragraph::new(lines).block(block), area);
    draw_buttons(
        f,
        th,
        &app.hits.popup_buttons,
        inner_row(area, buttons_at),
        &[
            ("Копировать код (c)", Btn::Primary, key(KeyCode::Char('c'))),
            ("Закрыть (Esc)", Btn::Normal, key(KeyCode::Esc)),
        ],
        2,
        false,
    );
}

/// Строка закрепления пути из конфига: «сервер» / «прямой» /
/// «через <реле>» или «авто» (закрепления нет).
fn pin_text(app: &App, ip: u32) -> String {
    let Some(raw) = app.pinned_paths.get(&crate::path::ip_key(ip)) else {
        return "авто".to_string();
    };
    match PathKind::parse_config(raw) {
        Some(PathKind::Direct) => "прямой".to_string(),
        Some(PathKind::Server) => "сервер".to_string(),
        Some(PathKind::PeerRelay { via }) => format!("через {}", app.peer_name_or_short(&via)),
        // Испорченная строка конфига равносильна «авто» (см. parse_config).
        None => "авто".to_string(),
    }
}

/// Потери в промилле → проценты: 0 → «0 %», 12 → «1.2 %», 1000 → «100 %».
fn loss_text(loss_pm: u16) -> String {
    if loss_pm.is_multiple_of(10) {
        format!("{} %", loss_pm / 10)
    } else {
        format!("{}.{} %", loss_pm / 10, loss_pm % 10)
    }
}

/// Строка метрик канала (issue #26): джиттер и потери. Пусто у старого
/// демона, который этих полей не присылает, — тогда строки нет вовсе.
fn path_metrics(th: &Theme, snap: &PathSnap) -> Option<Line<'static>> {
    let mut parts = Vec::new();
    if let Some(jitter) = snap.jitter_ms {
        parts.push(format!("джиттер {jitter} мс"));
    }
    if let Some(loss) = snap.loss_pm {
        parts.push(format!("потери {}", loss_text(loss)));
    }
    if parts.is_empty() {
        return None;
    }
    Some(Line::from(vec![
        Span::styled("канал: ", th.dim),
        Span::styled(parts.join(" · "), th.base),
    ]))
}

/// Содержимое попапа: строки текста и история RTT для спарклайна. Высота окна
/// считается по ним: метрик у старого демона нет, и окно не растёт зря.
struct PopupBody {
    lines: Vec<Line<'static>>,
    /// История RTT — рисуется поверх пустой строки-заглушки `hist_row`.
    hist: Vec<u16>,
    /// Строка под спарклайн (сразу после метрик пути).
    hist_row: u16,
}

impl PopupBody {
    /// Строк в окне: текст (вместе со строкой спарклайна) + кнопки + рамка.
    fn height(&self) -> u16 {
        self.lines.len() as u16 + 3
    }

    /// Номер строки с кнопками — сразу под текстом.
    fn buttons_row(&self) -> u16 {
        self.lines.len() as u16
    }
}

/// Спарклайн истории RTT в одну строку окна (приём тот же, что у графика
/// трафика: `Sparkline` с потолком по максимуму). Пустая история — ничего.
fn draw_rtt_hist(f: &mut Frame, th: &Theme, row: Rect, hist: &[u16]) {
    if hist.is_empty() || row.width < 12 || row.height == 0 {
        return;
    }
    let cols = Layout::horizontal([Constraint::Length(6), Constraint::Min(1)]).split(row);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(" rtt: ", th.dim))),
        cols[0],
    );
    // Потолок — максимум истории: относительные высоты читаются лучше, чем
    // по абсолютной шкале. Хвост — самые свежие замеры.
    let max = hist.iter().copied().max().unwrap_or(1).max(1);
    let w = cols[1].width as usize;
    let data = &hist[hist.len().saturating_sub(w)..];
    f.render_widget(
        Sparkline::default()
            .data(data.iter().copied().map(u64::from))
            .max(u64::from(max))
            .style(th.accent),
        cols[1],
    );
}

/// Строки карточки участника (Enter в таблице участников): путь доставки,
/// метрики канала, закрепление, для L2 — имя реле (этап 9, issue #18/#26).
fn peer_card_body(app: &App, th: &Theme, c: &PeerCardPopup) -> PopupBody {
    let peer = app.peers.iter().find(|p| p.pubkey == c.pubkey);
    let mut lines = identicon_lines(&c.pubkey);
    let mut hist = Vec::new();
    let mut hist_at = None;
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("имя: ", th.dim),
        Span::styled(
            app.peer_name_or_short(&c.pubkey),
            th.base.add_modifier(Modifier::BOLD),
        ),
    ]));
    if let Some(p) = peer {
        lines.push(Line::from(vec![
            Span::styled("IP: ", th.dim),
            Span::styled(proto::ip_str(p.ip), th.accent),
        ]));
        lines.push(Line::from(vec![
            Span::styled("статус: ", th.dim),
            Span::styled(p.status.clone(), th.base),
            Span::styled(
                if p.online {
                    "  (в сети)"
                } else {
                    "  (офлайн)"
                },
                if p.online { th.ok } else { th.offline },
            ),
        ]));
        // Связь и RTT — только у живого участника: у офлайна замер остался
        // с прошлой сессии (issue #18).
        lines.push(Line::from(vec![
            Span::styled("связь: ", th.dim),
            Span::styled(
                if !p.online {
                    "—"
                } else if p.direct {
                    "прямой канал"
                } else {
                    "через релей"
                },
                if p.online { th.base } else { th.offline },
            ),
            Span::styled(
                match p.rtt_ms.filter(|_| p.online) {
                    Some(ms) => format!("  {ms} мс"),
                    None => String::new(),
                },
                th.dim,
            ),
        ]));
        // Путь доставки — главное в карточке (этап 9).
        let (text, style) = path_cell(app, th, p, false);
        lines.push(Line::from(vec![
            Span::styled("путь: ", th.dim),
            Span::styled(text, style),
        ]));
        // Метрики и спарклайн — только для живого пути: у офлайна их нет, а у
        // старого демона их нет в снимке (обратная совместимость).
        if p.online
            && let Some(snap) = p.path.as_ref()
        {
            if let Some(line) = path_metrics(th, snap) {
                lines.push(line);
            }
            if !snap.hist.is_empty() {
                hist_at = Some(lines.len() as u16);
                lines.push(Line::from(""));
                hist.clone_from(&snap.hist);
            }
        }
        // Закрепление: из конфига в снимке (переживает рестарт движка).
        lines.push(Line::from(vec![
            Span::styled("закреплено: ", th.dim),
            Span::styled(
                pin_text(app, p.ip),
                if app.pinned_paths.contains_key(&crate::path::ip_key(p.ip)) {
                    th.ok
                } else {
                    th.dim
                },
            ),
        ]));
        if let Some(PathKind::PeerRelay { via }) = p.path.as_ref().map(|s| s.kind) {
            lines.push(Line::from(vec![
                Span::styled("реле: ", th.dim),
                Span::styled(app.peer_name_or_short(&via), th.relay),
            ]));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "участник больше не в группе",
            th.dim,
        )));
    }
    lines.push(Line::from(""));
    PopupBody {
        lines,
        hist,
        hist_row: hist_at.unwrap_or(0),
    }
}

/// Карточка участника: текст, спарклайн RTT и кнопки.
fn draw_peer_card(
    f: &mut Frame,
    app: &App,
    th: &Theme,
    c: &PeerCardPopup,
    body: PopupBody,
    area: Rect,
) {
    let buttons_at = body.buttons_row();
    let hist_at = body.hist_row;
    let hist = body.hist;
    let block = popup_block(
        th,
        popup_title(
            th,
            "◆",
            &format!("Участник: {}", app.peer_name_or_short(&c.pubkey)),
        ),
        th.focused_border,
    );
    f.render_widget(Paragraph::new(body.lines).block(block), area);
    draw_rtt_hist(f, th, inner_row(area, hist_at), &hist);
    draw_buttons(
        f,
        th,
        &app.hits.popup_buttons,
        inner_row(area, buttons_at),
        &[
            ("Путь (P)", Btn::Primary, key(KeyCode::Char('P'))),
            ("Закрыть (Esc)", Btn::Normal, key(KeyCode::Esc)),
        ],
        2,
        false,
    );
}

/// Строки окна пути до участника: текущий путь, метрики канала и варианты
/// закрепления (`0 авто`, `1 прямой`, `2 сервер`, `3 реле`).
fn path_pin_body(app: &App, th: &Theme, p: &PathPinPopup) -> PopupBody {
    let key_ip = crate::path::ip_key(p.ip);
    let current = app
        .pinned_paths
        .get(&key_ip)
        .and_then(|raw| PathKind::parse_config(raw));
    let peer = app.peers.iter().find(|x| x.pubkey == p.pubkey);
    let mut hist = Vec::new();
    let mut lines = vec![
        Line::from(vec![
            Span::styled("до: ", th.dim),
            Span::styled(
                format!("{} · {}", p.name, proto::ip_str(p.ip)),
                th.base.add_modifier(Modifier::BOLD),
            ),
        ]),
        // Что движок выбрал сам — чтобы решение было осознанным.
        match peer {
            Some(peer) => {
                let (text, style) = path_cell(app, th, peer, false);
                Line::from(vec![
                    Span::styled("сейчас: ", th.dim),
                    Span::styled(text, style),
                ])
            }
            None => Line::from(Span::styled("сейчас: —", th.dim)),
        },
    ];
    // Метрики и спарклайн живого пути (issue #18/#26): у офлайна и у старого
    // демона их нет — тогда строк не добавляем.
    let mut hist_at = None;
    if let Some(peer) = peer
        && peer.online
        && let Some(snap) = peer.path.as_ref()
    {
        if let Some(line) = path_metrics(th, snap) {
            lines.push(line);
        }
        if !snap.hist.is_empty() {
            hist_at = Some(lines.len() as u16);
            lines.push(Line::from(""));
            hist.clone_from(&snap.hist);
        }
    }
    lines.push(Line::from(""));
    let opt = |k: char, text: String, on: bool, enabled: bool| {
        let (mark, style) = if !enabled {
            ("—", th.dim)
        } else if on {
            ("●", th.ok)
        } else {
            ("○", th.base)
        };
        Line::from(vec![
            Span::styled(
                format!(" {k} "),
                if enabled {
                    th.accent.add_modifier(Modifier::BOLD)
                } else {
                    th.dim
                },
            ),
            Span::styled(format!("{mark} "), style),
            Span::styled(text, if on && enabled { th.ok } else { style }),
        ])
    };
    lines.push(opt(
        '0',
        "авто (выбирает движок)".into(),
        current.is_none(),
        true,
    ));
    lines.push(opt(
        '1',
        "прямой".into(),
        matches!(current, Some(PathKind::Direct)),
        true,
    ));
    lines.push(opt(
        '2',
        "сервер".into(),
        matches!(current, Some(PathKind::Server)),
        true,
    ));
    let relay_label = match p.relay {
        Some(via) => format!("реле: {}", app.peer_name_or_short(&via)),
        None => "реле: нет".into(),
    };
    let relay_on = matches!(current, Some(PathKind::PeerRelay { .. }));
    lines.push(opt('3', relay_label, relay_on, p.relay.is_some()));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "0–3 — закрепить · Esc — закрыть",
        th.dim,
    )));
    PopupBody {
        lines,
        hist,
        hist_row: hist_at.unwrap_or(0),
    }
}

/// Окно выбора пути до участника (этап 9): `0 авто`, `1 прямой`,
/// `2 сервер`, `3 реле`. Текущее закрепление помечено «●», недоступное
/// (нет известного реле) — «—».
fn draw_path_pin(f: &mut Frame, th: &Theme, p: &PathPinPopup, body: PopupBody, area: Rect) {
    let hist_at = body.hist_row;
    let hist = body.hist;
    let block = popup_block(
        th,
        popup_title(th, "⇄", &format!("Путь до {}", p.name)),
        th.focused_border,
    );
    f.render_widget(Paragraph::new(body.lines).block(block), area);
    draw_rtt_hist(f, th, inner_row(area, hist_at), &hist);
}

fn draw_list_pick(f: &mut Frame, th: &Theme, p: &ListPickPopup, area: Rect) -> usize {
    let block = popup_block(th, popup_title(th, "≡", &p.title), th.focused_border).title_bottom(
        Line::from(Span::styled(
            " Enter или клик — выбрать · Esc — закрыть ",
            th.dim,
        )),
    );
    let items: Vec<ListItem> = p
        .items
        .iter()
        .map(|i| {
            let (mark, style) = if i.checked {
                ("[x]", th.ok.add_modifier(Modifier::BOLD))
            } else {
                ("[ ]", th.dim)
            };
            let mut spans = vec![
                Span::styled(format!("{mark} "), style),
                Span::styled(i.label.clone(), th.base),
            ];
            if !i.value.is_empty() {
                spans.push(Span::styled(format!("  {}", i.value), th.dim));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    draw_popup_list(f, th, block, items, p.sel, area)
}

fn draw_settings(f: &mut Frame, app: &App, th: &Theme, s: &SettingsPopup, area: Rect) -> usize {
    let rows: Vec<(String, String)> = vec![
        (
            "имя".to_string(),
            if app.my_name.is_empty() {
                "(не задано)".into()
            } else {
                app.my_name.clone()
            },
        ),
        (
            "статус".to_string(),
            if app.my_status.is_empty() {
                "(не задан)".into()
            } else {
                app.my_status.clone()
            },
        ),
        (
            "сервер".to_string(),
            app.servers
                .first()
                .map(|s| s.addr.clone())
                .unwrap_or_else(|| "(нет)".into()),
        ),
        (
            "автовход".to_string(),
            if app.autojoin.is_empty() {
                "(нет)".into()
            } else {
                app.autojoin
                    .iter()
                    .map(|g| g.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        ),
        ("тема".to_string(), app.theme_kind.label().to_string()),
        (
            "невидимка".to_string(),
            if app.invisible { "вкл" } else { "выкл" }.to_string(),
        ),
    ];

    let items: Vec<ListItem> = SETTING_ROWS
        .iter()
        .zip(rows.iter())
        .map(|(_, (label, value))| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{label:<12}"), th.dim),
                Span::styled(value.clone(), th.base),
            ]))
        })
        .collect();

    let block = popup_block(th, popup_title(th, "◎", "Настройки"), th.focused_border).title_bottom(
        Line::from(Span::styled(
            " Enter или клик — изменить · Esc — закрыть ",
            th.dim,
        )),
    );
    draw_popup_list(f, th, block, items, s.sel, area)
}

fn draw_profile(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let mut lines = identicon_lines(&app.my_pub);
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("имя:     ", th.dim),
        Span::styled(app.my_name.clone(), th.base.add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("статус:  ", th.dim),
        Span::styled(app.my_status.clone(), th.base),
    ]));
    lines.push(Line::from(vec![Span::styled("friend code:", th.dim)]));
    // Код — отдельной строкой целиком, чтобы его можно было выделить мышью.
    lines.push(Line::from(Span::styled(app.my_code.clone(), th.accent)));
    lines.push(Line::from(vec![
        Span::styled("группы:  ", th.dim),
        Span::styled(
            format!("{}", app.groups.iter().filter(|g| g.mine).count()),
            th.base,
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("друзья:  ", th.dim),
        Span::styled(app.friends.len().to_string(), th.base),
    ]));
    lines.push(Line::from(vec![
        Span::styled("в сети:  ", th.dim),
        Span::styled(uptime(app.started), th.base),
    ]));
    lines.push(Line::from(vec![
        Span::styled("трафик:  ", th.dim),
        Span::styled(format!("↓ {}", kb(app.rx_bytes)), th.chart_rx()),
        Span::styled(format!("  ↑ {}", kb(app.tx_bytes)), th.chart_tx()),
        Span::styled(
            format!("  (пакетов {}/{})", app.rx_pkts, app.tx_pkts),
            th.dim,
        ),
    ]));
    lines.push(Line::from(""));
    let buttons_at = lines.len() as u16;

    let block = popup_block(th, popup_title(th, "☻", "Профиль"), th.focused_border);
    f.render_widget(Paragraph::new(lines).block(block), area);
    draw_buttons(
        f,
        th,
        &app.hits.popup_buttons,
        inner_row(area, buttons_at),
        &[
            (
                "Копировать friend code (c)",
                Btn::Primary,
                key(KeyCode::Char('c')),
            ),
            ("Закрыть (Esc)", Btn::Normal, key(KeyCode::Esc)),
        ],
        2,
        false,
    );
}

/// Окно входящего приглашения: кто, куда, три кнопки.
fn draw_invite(f: &mut Frame, app: &App, th: &Theme, inv: &InvitePopup, area: Rect) {
    let queued = app.invites.len() + app.later_invites.len();
    let mut title = vec![Span::styled(" ★ Приглашение в группу ", th.title)];
    if queued > 0 {
        title.push(Span::styled(format!(" ещё {queued} "), th.pill(th.c.warn)));
        title.push(Span::raw(" "));
    }
    let lines = vec![
        Line::from(vec![
            Span::styled("от:      ", th.dim),
            Span::styled(
                app.invite_from_label(inv),
                th.base.add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("группа:  ", th.dim),
            Span::styled(
                format!("«{}»", inv.group_name),
                th.accent.add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("  gid {}", inv.gid), th.dim),
        ]),
        Line::from(vec![
            Span::styled("пришло:  ", th.dim),
            Span::styled(ago(inv.received_at), th.dim),
            Span::styled(
                inv.expires_at
                    .map(|t| format!(" · {}", left_until(t)))
                    .unwrap_or_default(),
                th.warn,
            ),
        ]),
        Line::from(""),
    ];
    let buttons_at = lines.len() as u16;
    let block = popup_block(
        th,
        Line::from(title),
        Style::default()
            .fg(th.c.accent_alt)
            .add_modifier(Modifier::BOLD),
    )
    .title_bottom(Line::from(Span::styled(
        " Enter/y — принять · n — отклонить · Esc — позже (o — вернуться) ",
        th.dim,
    )))
    .padding(ratatui::widgets::Padding::horizontal(1));
    f.render_widget(Paragraph::new(lines).block(block), area);
    draw_buttons(
        f,
        th,
        &app.hits.popup_buttons,
        button_row(area, buttons_at),
        &[
            ("Принять (Enter)", Btn::Primary, key(KeyCode::Enter)),
            ("Отклонить (n)", Btn::Danger, key(KeyCode::Char('n'))),
            ("Позже (Esc)", Btn::Normal, key(KeyCode::Esc)),
        ],
        2,
        false,
    );
}

/// Окно входящей заявки в друзья (issue #24): кто и сколько ждать ответа.
/// Ника и алиас берём из своего списка — в кадре сервера ник мог быть пустым.
fn draw_friend_req(
    f: &mut Frame,
    app: &App,
    th: &Theme,
    req: &crate::tui::app::FriendReqPopup,
    area: Rect,
) {
    let title = vec![Span::styled(" ☆ Заявка в друзья ", th.title)];
    let who = app
        .friends
        .iter()
        .find(|x| x.pubkey == req.pubkey)
        .map(|x| x.display())
        .unwrap_or_else(|| req.name.clone());
    let lines = vec![
        Line::from(vec![
            Span::styled("от:      ", th.dim),
            Span::styled(who, th.base.add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("ключ:    ", th.dim),
            Span::styled(crate::friends::short_code(&req.pubkey), th.dim),
        ]),
        Line::from(vec![
            Span::styled("пришло:  ", th.dim),
            Span::styled(ago(req.received_at), th.dim),
            Span::styled(
                req.expires_at
                    .map(|t| format!(" · {}", left_until(t)))
                    .unwrap_or_default(),
                th.warn,
            ),
        ]),
        Line::from(""),
    ];
    let buttons_at = lines.len() as u16;
    let block = popup_block(
        th,
        Line::from(title),
        Style::default()
            .fg(th.c.accent_alt)
            .add_modifier(Modifier::BOLD),
    )
    .title_bottom(Line::from(Span::styled(
        " Enter/y — принять · n — отклонить · Esc — закрыть (заявка останется) ",
        th.dim,
    )))
    .padding(ratatui::widgets::Padding::horizontal(1));
    f.render_widget(Paragraph::new(lines).block(block), area);
    draw_buttons(
        f,
        th,
        &app.hits.popup_buttons,
        button_row(area, buttons_at),
        &[
            ("Принять (Enter)", Btn::Primary, key(KeyCode::Enter)),
            ("Отклонить (n)", Btn::Danger, key(KeyCode::Char('n'))),
            ("Позже (Esc)", Btn::Normal, key(KeyCode::Esc)),
        ],
        2,
        false,
    );
}

// ---------------------------------------------------------------- справка
fn help_lines(th: &Theme) -> Vec<Line<'static>> {
    let kv = |k: &str, v: &str| {
        Line::from(vec![
            Span::styled(format!("{k:<16}"), th.accent.add_modifier(Modifier::BOLD)),
            Span::styled(v.to_string(), th.base),
        ])
    };
    let head = |t: &str| Line::from(Span::styled(format!("▸ {t}"), th.title));
    vec![
        head("Навигация"),
        kv(
            "Tab / Shift-Tab",
            "смена фокуса (группы → друзья → участники → лог)",
        ),
        kv("↑ ↓", "перемещение по списку"),
        kv("Enter", "войти в группу / карточка друга или участника"),
        kv("/", "поиск по спискам (Esc — сбросить, Enter — принять)"),
        kv("s", "сменить сортировку (имя / онлайн / RTT)"),
        kv("r", "обновить список групп"),
        Line::from(""),
        head("Группы"),
        kv("F2", "создать группу (Tab — приватная)"),
        kv("F6", "переименовать группу"),
        kv("F8", "удалить группу (только владелец)"),
        kv("j", "войти в публичную группу"),
        kv(
            "⇄ · :joinfed",
            "федеративная группа: метка «федерация», вход по uuid/gid",
        ),
        kv("x", "покинуть группу"),
        kv(
            "d",
            "отключиться от доставки / подключиться (участие сохраняется)",
        ),
        kv("i", "пригласить друга в группу"),
        kv("k / b", "исключить / забанить участника"),
        kv(
            "m · :admin",
            "управление своей группой: баны, приглашения, владелец",
        ),
        kv("o", "неотвеченные приглашения (отложенные «Позже»)"),
        kv(
            "  в окне",
            "Enter/y — принять · n — отклонить · Esc — позже",
        ),
        Line::from(""),
        head("Друзья и профиль"),
        kv("a", "добавить друга по friend code"),
        kv("d (в друзьях)", "удалить друга (с подтверждением)"),
        kv("r (в друзьях)", "переименовать друга (:alias друг имя)"),
        kv("c", "скопировать IP / pubkey / friend code"),
        kv("p", "карточка профиля"),
        // 1:1 замена прежней строки «p (участники)»: высота справки не растёт
        // (на 40-строчном терминале она уже упирается в предел), issue #22.
        kv(
            "P · :path",
            "путь до участника: 0 авто · 1 прямой · 2 сервер · 3 реле",
        ),
        kv("F3", "настройки (имя, сервер, автовход, тема, невидимка)"),
        kv(
            "F4 · :servers",
            "серверы: переключить, добавить, удалить, адаптер",
        ),
        Line::from(""),
        head("Прочее"),
        kv(":", "командная строка (:help — список)"),
        kv("раскладка", "хоткеи работают и в русской раскладке"),
        kv("PgUp / PgDn", "прокрутка лога"),
        kv("Ctrl-C", "выход (или :quit)"),
        Line::from(""),
        head("Мышь"),
        kv("клик", "фокус и выбор строки; второй клик — как Enter"),
        kv("колесо", "прокрутка списка или лога под курсором"),
        kv("кнопки", "панель под шапкой и кнопки в окнах = клавиши"),
        kv("вкладки", "внизу слева: клик — перейти в панель"),
        kv("мимо окна", "закрыть окно (как Esc)"),
        kv("Shift+мышь", "выделить текст средствами терминала"),
    ]
}

// ---------------------------------------------------------------- время

/// Байты → человекочитаемый вид.
fn kb(v: u64) -> String {
    if v >= 1024 * 1024 {
        format!("{:.1} МБ", v as f64 / (1024.0 * 1024.0))
    } else if v >= 1024 {
        format!("{:.1} КБ", v as f64 / 1024.0)
    } else {
        format!("{v} Б")
    }
}

/// Байты релея: ноль — коротко «0», иначе как обычные байты.
fn relay_bytes_text(v: u64) -> String {
    if v == 0 { "0".to_string() } else { kb(v) }
}

/// «1 сессия» / «2 сессии» / «5 сессий».
fn sessions_text(n: u32) -> String {
    let tail = n % 100;
    let word = if (11..=14).contains(&tail) {
        "сессий"
    } else {
        match n % 10 {
            1 => "сессия",
            2..=4 => "сессии",
            _ => "сессий",
        }
    };
    format!("{n} {word}")
}

/// Время в формате ч:м:с (аптайм).
fn uptime(t: std::time::Instant) -> String {
    let secs = t.elapsed().as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// «только что» / «N с назад» / «N мин назад».
fn ago(t: std::time::Instant) -> String {
    match t.elapsed().as_secs() {
        0..=4 => "только что".into(),
        s @ 5..=59 => format!("{s} с назад"),
        s => format!("{} мин назад", s / 60),
    }
}

// ---------------------------------------------------------------- тесты

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::PathSnap;
    use crate::store::Config;
    use crate::tui::app::{App, FriendView, GroupView, PeerView};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn demo_app() -> App {
        let mut app = App::new([9; 32], "TUN-TEST-CODE-TEST-CODE", &Config::default());
        app.my_name = "alpha".into();
        app.my_status = "в сети".into();
        app.connected = true;
        app.conn = ConnState::Online;
        app.server_addr = "127.0.0.1:5599".into();
        app.groups = vec![
            GroupView {
                gid: 1,
                name: "gamers".into(),
                private: false,
                mine: true,
                online: 2,
                total: 2,
                my_ip: Some(0x6442_0102),
                owner_is_me: true,
                detached: false,
                peers: vec![PeerView {
                    pubkey: [2; 32],
                    name: "bravo".into(),
                    ip: 0x6442_0103,
                    online: true,
                    direct: true,
                    rtt_ms: Some(7),
                    status: "ok".into(),
                    path: Some(PathSnap::new(PathKind::Direct, Some(7))),
                }],
            },
            GroupView {
                gid: 2,
                name: "secret".into(),
                private: true,
                mine: false,
                online: 1,
                total: 1,
                my_ip: None,
                owner_is_me: false,
                detached: false,
                peers: vec![],
            },
        ];
        app.peers = vec![PeerView {
            pubkey: [2; 32],
            name: "bravo".into(),
            ip: 0x6442_0103,
            online: true,
            direct: true,
            rtt_ms: Some(7),
            status: "ok".into(),
            path: Some(PathSnap::new(PathKind::Direct, Some(7))),
        }];
        app.friends = vec![FriendView {
            alias: "bravo".into(),
            nick: String::new(),
            state: crate::store::FriendState::Accepted,
            pubkey: [2; 32],
            online: true,
            shared_groups: 1,
        }];
        app.sel_group = Some(1);
        app
    }

    fn render(app: &App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, app)).unwrap();
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

    /// Первая строка экрана, в которой есть `text` (для проверок колонок).
    fn text_row(screen: &[Vec<char>], text: &str) -> String {
        screen
            .iter()
            .map(|r| r.iter().collect::<String>())
            .find(|r| r.contains(text))
            .unwrap_or_else(|| panic!("нет строки с «{text}»"))
    }

    #[test]
    fn основной_экран_содержит_ключевое() {
        let text = render(&demo_app(), 140, 40);
        assert!(text.contains("Группы"), "нет блока групп:\n{text}");
        assert!(text.contains("gamers"), "нет группы gamers");
        assert!(text.contains("Друзья"), "нет блока друзей");
        assert!(text.contains("bravo"), "нет друга bravo");
        assert!(text.contains("direct"), "нет метки direct");
        assert!(text.contains("7 мс"), "нет RTT");
        assert!(text.contains("100.66.1.2"), "нет своего IP");
        assert!(text.contains("● в сети"), "нет статуса соединения");
    }

    #[test]
    fn колонка_путь_и_карточка_участника() {
        // Демо-снимок: у bravo выбран прямой путь — колонка «путь» на месте.
        let mut app = demo_app();
        app.toasts.clear();
        let text = render(&app, 140, 40);
        assert!(
            text.contains("◆ прямой 7 мс"),
            "нет колонки «путь»:\n{text}"
        );

        // Все виды пути (без пути, прямой, сервер, реле) на широком экране.
        let mut busy = busy_app();
        busy.toasts.clear();
        let text = render(&busy, 140, 40);
        assert!(
            text.contains("◇ сервер 48 мс"),
            "нет метки сервера:\n{text}"
        );
        assert!(text.contains("⇄ через"), "нет метки реле:\n{text}");
        assert!(text.contains("(2 хопа)"), "нет числа хопов:\n{text}");
        // Узкий терминал колонку не рисует вовсе — и не паникует.
        let _ = render(&busy, 60, 24);

        // Статус-бар: релей и число mesh-сессий при включённом mesh.
        let mut mesh = demo_app();
        mesh.toasts.clear();
        mesh.mesh_enabled = true;
        mesh.relay_bytes = 12_595;
        mesh.mesh_sessions = 2;
        let text = render(&mesh, 140, 40);
        assert!(text.contains("реле 12.3 КБ"), "нет счётчика релея:\n{text}");
        assert!(
            text.contains("mesh 2 сессии"),
            "нет счётчика mesh-сессий:\n{text}"
        );
        // Ноль релея показывается как «реле 0» — счётчик не скачет.
        mesh.relay_bytes = 0;
        mesh.mesh_sessions = 0;
        let text = render(&mesh, 140, 40);
        assert!(text.contains("реле 0"), "нет нулевого релея:\n{text}");
        assert!(!text.contains("mesh 0"), "нулевые сессии не показываем");

        // Карточка участника: путь и закрепление.
        let mut app = demo_app();
        app.toasts.clear();
        app.stack
            .push(Popup::PeerCard(PeerCardPopup { pubkey: [2; 32] }));
        let text = render(&app, 140, 40);
        assert!(text.contains("Участник: bravo"), "нет карточки:\n{text}");
        assert!(
            text.contains("закреплено: авто"),
            "нет строки закрепления:\n{text}"
        );

        // Окно выбора пути: варианты, отметка текущего и имя реле.
        app.stack.clear();
        app.stack.push(Popup::PathPin(PathPinPopup {
            pubkey: [2; 32],
            name: "bravo".into(),
            ip: 0x6442_0103,
            relay: Some([3; 32]),
        }));
        let text = render(&app, 140, 40);
        assert!(text.contains("Путь до bravo"), "нет окна пути:\n{text}");
        assert!(text.contains("0 ● авто"), "«авто» не отмечено:\n{text}");
        assert!(
            text.contains("3 ○ реле: 030303"),
            "нет варианта реле:\n{text}"
        );
        // Нет реле — вариант «3» показан недоступным.
        app.stack.clear();
        app.stack.push(Popup::PathPin(PathPinPopup {
            pubkey: [2; 32],
            name: "bravo".into(),
            ip: 0x6442_0103,
            relay: None,
        }));
        let text = render(&app, 140, 40);
        assert!(
            text.contains("3 — реле: нет"),
            "нет недоступного реле:\n{text}"
        );
    }

    #[test]
    fn метрики_и_спарклайн_пути_когда_движок_их_прислал() {
        let mut app = demo_app();
        app.toasts.clear();
        // Новые поля контракта (issue #15/#26): полный RTT, плечо, джиттер,
        // потери и история замеров.
        let mut snap = PathSnap::new(PathKind::Server, Some(48));
        snap.leg_ms = Some(1);
        snap.jitter_ms = Some(3);
        snap.loss_pm = Some(12);
        snap.hist = vec![10, 20, 30, 40];
        app.peers[0].path = Some(snap.clone());
        app.groups[0].peers[0].path = Some(snap);

        // Колонка «путь»: полный RTT и плечо «мы → сервер» (issue #18).
        let s = frame(&app, 140, 40);
        let row = text_row(&s, "100.66.1.3");
        assert!(row.contains("◇ сервер 48 мс, плечо 1 мс"), "{row}");

        // Карточка участника: метрики канала и спарклайн RTT.
        app.stack
            .push(Popup::PeerCard(PeerCardPopup { pubkey: [2; 32] }));
        let text = render(&app, 140, 40);
        assert!(
            text.contains("канал: джиттер 3 мс · потери 1.2 %"),
            "нет метрик канала:\n{text}"
        );
        assert!(text.contains("rtt:"), "нет спарклайна RTT:\n{text}");
        // Узкий экран: спарклайн не рисуется, паники нет.
        let _ = render(&app, 40, 12);

        // Окно пути: те же метрики.
        app.stack.clear();
        app.stack.push(Popup::PathPin(PathPinPopup {
            pubkey: [2; 32],
            name: "bravo".into(),
            ip: 0x6442_0103,
            relay: None,
        }));
        let text = render(&app, 140, 40);
        assert!(text.contains("Путь до bravo"), "нет окна пути:\n{text}");
        assert!(
            text.contains("канал: джиттер 3 мс · потери 1.2 %"),
            "нет метрик в окне пути:\n{text}"
        );
        assert!(text.contains("rtt:"), "нет спарклайна в окне пути:\n{text}");

        // Старый демон: полей нет — ни строк метрик, ни спарклайна.
        let mut old = demo_app();
        old.toasts.clear();
        old.peers[0].path = Some(PathSnap::new(PathKind::Server, Some(48)));
        old.groups[0].peers[0].path = Some(PathSnap::new(PathKind::Server, Some(48)));
        old.stack
            .push(Popup::PeerCard(PeerCardPopup { pubkey: [2; 32] }));
        let text = render(&old, 140, 40);
        assert!(!text.contains("канал:"), "метрики без данных:\n{text}");
        assert!(!text.contains("rtt:"), "спарклайн без истории:\n{text}");
    }

    #[test]
    fn офлайн_участник_без_пути_и_rtt() {
        // Снимок мог сохранить путь и замер RTT с прошлой сессии: у строки
        // «офлайн» их быть не должно (issue #18).
        let mut app = demo_app();
        app.toasts.clear();
        let mut peer = app.peers[0].clone();
        peer.online = false;
        peer.rtt_ms = Some(48);
        peer.path = Some(PathSnap::new(PathKind::Server, Some(48)));
        app.peers = vec![peer.clone()];
        app.groups[0].peers = vec![peer];

        let s = frame(&app, 140, 40);
        let row = text_row(&s, "100.66.1.3");
        assert!(row.contains('—'), "нет «—» вместо пути и RTT: {row}");
        assert!(!row.contains("мс"), "у офлайна остался RTT: {row}");
        assert!(!row.contains("сервер"), "у офлайна остался путь: {row}");

        // Карточка участника: связь «—», пути нет, метрик и спарклайна нет.
        app.stack
            .push(Popup::PeerCard(PeerCardPopup { pubkey: [2; 32] }));
        let text = render(&app, 140, 40);
        assert!(text.contains("связь: —"), "нет «связь: —»:\n{text}");
        assert!(text.contains("путь: —"), "нет «путь: —»:\n{text}");
        assert!(!text.contains("канал:"), "метрики офлайн-пути:\n{text}");
        assert!(!text.contains("rtt:"), "спарклайн офлайн-пути:\n{text}");
    }

    #[test]
    fn колонка_путь_следует_за_событиями_и_снимком() {
        // Три кадра: путь из снимка → событие сменило путь → участник офлайн.
        let mut app = demo_app();
        app.toasts.clear();
        let s = frame(&app, 140, 40);
        let row = text_row(&s, "100.66.1.3");
        assert!(row.contains("◆ прямой 7 мс"), "кадр 1: {row}");

        app.apply_events(
            vec![crate::engine::Event::PathChanged {
                ip: 0x6442_0103,
                name: "bravo".into(),
                path: PathKind::Server,
                rtt_ms: Some(48),
            }],
            &crate::snapshot::Snapshot::default(),
        );
        let s = frame(&app, 140, 40);
        let row = text_row(&s, "100.66.1.3");
        assert!(row.contains("◇ сервер 48 мс"), "кадр 2: {row}");
        assert!(
            !row.contains("прямой"),
            "кадр 2: старый путь остался: {row}"
        );

        // Снимок вслед за событием: участник ушёл в офлайн, кэш пути снят.
        app.apply_events(
            vec![crate::engine::Event::PeerOffline {
                gid: 1,
                ip: 0x6442_0103,
                name: "bravo".into(),
            }],
            &crate::snapshot::Snapshot::default(),
        );
        assert!(app.peers[0].path.is_none(), "кэш пути пережил офлайн");
        for peer in app.peers.iter_mut().chain(app.groups[0].peers.iter_mut()) {
            peer.online = false;
        }
        let s = frame(&app, 140, 40);
        let row = text_row(&s, "100.66.1.3");
        assert!(row.contains('—'), "кадр 3: нет «—»: {row}");
        assert!(!row.contains("мс"), "кадр 3: остался RTT: {row}");
        assert!(!row.contains("сервер"), "кадр 3: остался путь: {row}");
    }

    // «P» в имени — клавиша Shift+P (issue #22), а не нарушение snake_case.
    #[allow(non_snake_case)]
    #[test]
    fn справка_знает_про_p_и_P() {
        let th = Theme::of(crate::tui::theme::ThemeKind::Dark);
        let lines = help_lines(&th);
        let texts: Vec<String> = lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.to_string()).collect())
            .collect();
        // «p» — профиль, «P» (и `:path`) — путь до участника (issue #22).
        assert!(
            texts
                .iter()
                .any(|l| l.starts_with("p ") && l.contains("карточка профиля")),
            "нет строки «p» — профиль: {texts:?}"
        );
        assert!(
            texts
                .iter()
                .any(|l| l.starts_with("P ") && l.contains("путь до участника")),
            "нет строки «P» — путь: {texts:?}"
        );
        assert!(
            texts.iter().all(|l| !l.contains("p (участники)")),
            "осталась старая строка «p (участники)»"
        );
        // Строки заменены 1:1: справка уже упирается в 40-строчный терминал,
        // и новые клавиши не должны её удлинять.
        assert_eq!(lines.len(), 44, "высота справки изменилась");
    }

    #[test]
    fn кнопка_путь_появляется_только_когда_влезает() {
        // На 80 колонках ряд не влезает целиком и без «P путь»: кнопку не
        // добавляем, иначе draw_buttons выбросил бы «F3 настройки» и
        // «: команда» (issue #22).
        let app = demo_app();
        let s = frame(&app, 80, 24);
        let keys: Vec<KeyCode> = app
            .hits
            .toolbar
            .borrow()
            .iter()
            .map(|(_, k)| k.code)
            .collect();
        assert!(
            !keys.contains(&KeyCode::Char('P')),
            "«P путь» на 80 колонках: {keys:?}"
        );
        // Ни одна постоянная кнопка не потеряна: видимое — префикс TOOLBAR.
        let base: Vec<KeyCode> = TOOLBAR.iter().map(|(_, c, _)| *c).collect();
        assert_eq!(keys, base[..keys.len()].to_vec(), "кнопки панели потеряны");
        let text: String = s.iter().map(|r| r.iter().collect::<String>()).collect();
        assert!(!text.contains("P путь"), "подпись на 80 колонках");

        // Широкий терминал: кнопка есть, подпись постоянная, клик = Shift+P.
        let _ = frame(&app, 200, 40);
        let hits = app.hits.toolbar.borrow().clone();
        assert!(
            hits.iter().any(|(_, k)| k.code == KeyCode::Char('P')),
            "нет кнопки «P путь» на широком экране"
        );
        let text = render(&app, 200, 40);
        assert!(text.contains("P путь"), "нет подписи «P путь»");
        assert!(text.contains("p профиль"), "нет подписи «p профиль»");
        assert!(!text.contains("p путь"), "динамическая подмена подписи");
    }

    #[test]
    fn попапы_отрисовываются() {
        let mut app = demo_app();
        app.stack.push(Popup::Help);
        let text = render(&app, 140, 40);
        assert!(text.contains("Справка"), "нет оверлея справки");
        assert!(text.contains("Создать группу") || text.contains("создать группу"));

        let mut app = demo_app();
        app.stack.push(Popup::Profile);
        let text = render(&app, 140, 40);
        assert!(text.contains("Профиль"));
        assert!(text.contains("TUN-TEST-CODE"));

        let mut app = demo_app();
        app.stack
            .push(Popup::Settings(crate::tui::app::SettingsPopup { sel: 0 }));
        let text = render(&app, 140, 40);
        assert!(text.contains("Настройки"));
    }

    #[test]
    fn подтверждение_показывает_всё_сообщение_и_кнопки() {
        // Длинное имя одним словом: перенос по словам даёт 3 строки, а
        // оценка «символы / ширина» — 2 (хвост сообщения обрезался).
        let name = "x".repeat(48);
        let message = format!("группа 12 «{name}» будет удалена у всех участников");
        assert_eq!(confirm_lines(&message, 60), 3);
        assert_eq!(confirm_lines("Точно?", 60), 1);
        assert_eq!(
            confirm_lines(&"y".repeat(112), 60),
            2,
            "слово ровно в две строки"
        );
        for w in [140u16, 30] {
            let mut app = demo_app();
            app.stack.push(Popup::Confirm(ConfirmPopup {
                title: "Удалить группу".into(),
                message: message.clone(),
                action: ConfirmAction::DeleteGroup(12),
            }));
            let text = render(&app, w, 40);
            assert!(
                text.contains("участников"),
                "конец сообщения обрезан (ширина {w}):\n{text}"
            );
            assert!(text.contains("Да (y)"), "нет кнопок (ширина {w}):\n{text}");
            assert_eq!(
                app.hits.popup_buttons.borrow().len(),
                2,
                "кнопки не кликабельны ({w})"
            );
        }
    }

    #[test]
    fn узкий_экран_не_паникует() {
        for (w, h) in [(40u16, 12u16), (80, 24), (200, 60)] {
            let _ = render(&demo_app(), w, h);
        }
    }

    /// Служебный тест: печатает отрисованный экран (запуск с --nocapture).
    #[test]
    fn печать_экрана() {
        let text = render(&demo_app(), 140, 36);
        println!("{text}");
        println!("{}", render(&busy_app(), 80, 24));
    }

    // ---------- мышь ----------

    use crate::tui::app::{ConfirmAction, Hit};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    /// Рисует кадр (это заполняет `app.hits`) и возвращает экран построчно,
    /// по одному символу на клетку.
    fn frame(app: &App, w: u16, h: u16) -> Vec<Vec<char>> {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().chars().next().unwrap_or(' '))
                    .collect()
            })
            .collect()
    }

    /// Координаты первого вхождения `text` правее `min_x`.
    fn find(screen: &[Vec<char>], text: &str, min_x: usize) -> (u16, u16) {
        let pat: Vec<char> = text.chars().collect();
        for (y, row) in screen.iter().enumerate() {
            for x in min_x..row.len().saturating_sub(pat.len() - 1) {
                if row[x..x + pat.len()] == pat[..] {
                    return (x as u16, y as u16);
                }
            }
        }
        panic!("на экране нет «{text}»");
    }

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn мышь_попадание_в_панели_и_кнопки() {
        let app = demo_app();
        // 150 колонок: панель действий выросла на кнопку «d отключ.», и на
        // 140 последняя кнопка перестала влезать (не влезшие не рисуются).
        let s = frame(&app, 150, 40);

        let (x, y) = find(&s, "secret", 0);
        assert_eq!(app.hit(x, y), Hit::Item(Focus::Groups, 1));
        let (x, y) = find(&s, "● gamers", 0);
        assert_eq!(app.hit(x, y), Hit::Item(Focus::Groups, 0));

        // «bravo» есть и в друзьях (слева), и в таблице участников (справа).
        let (x, y) = find(&s, "● bravo", 0);
        assert_eq!(app.hit(x, y), Hit::Item(Focus::Friends, 0));
        let (x, y) = find(&s, "bravo", 40);
        assert_eq!(app.hit(x, y), Hit::Item(Focus::Peers, 0));
        // Строка «я» и заголовок таблицы — мимо участников.
        let (x, y) = find(&s, "alpha (я)", 40);
        assert_eq!(app.hit(x, y), Hit::Panel(Focus::Peers));

        let (x, y) = find(&s, "F3 настройки", 0);
        assert_eq!(app.hit(x, y), Hit::Key(k(KeyCode::F(3))));
        let (x, y) = find(&s, "^C выход", 0);
        assert_eq!(
            app.hit(x + 1, y),
            Hit::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL))
        );

        let (x, y) = find(&s, "Лог", 0);
        assert_eq!(app.hit(x, y + 1), Hit::Panel(Focus::Log));
        // Шапка — не кликабельна.
        assert_eq!(app.hit(1, 1), Hit::Nothing);
    }

    #[test]
    fn мышь_клик_выбирает_второй_применяет() {
        let mut app = demo_app();
        let _ = frame(&app, 140, 40);
        // Фокус на группах, выбрана группа 1: клик по группе 2 только выбирает.
        assert!(!app.select_item(Focus::Groups, 1));
        assert_eq!(app.sel_group, Some(2));
        // Повторный клик по той же строке — «Enter».
        assert!(app.select_item(Focus::Groups, 1));
        // Клик в другой панели сначала переводит фокус.
        assert!(!app.select_item(Focus::Friends, 0));
        assert_eq!(app.focus, Focus::Friends);
        assert!(app.select_item(Focus::Friends, 0));
    }

    #[test]
    fn мышь_колесо_без_хода_по_кругу() {
        let mut app = demo_app();
        let s = frame(&app, 140, 40);
        let (x, y) = find(&s, "● gamers", 0);
        app.wheel(x, y, -1);
        assert_eq!(app.sel_group, Some(1), "вверх с первой строки — стоим");
        app.wheel(x, y, 1);
        assert_eq!(app.sel_group, Some(2));
        app.wheel(x, y, 1);
        assert_eq!(app.sel_group, Some(2), "вниз с последней — стоим");
    }

    #[test]
    fn мышь_попапы() {
        let mut app = demo_app();
        app.stack.push(Popup::Confirm(ConfirmPopup {
            title: "Удалить группу".into(),
            message: "Точно?".into(),
            action: ConfirmAction::DeleteGroup(1),
        }));
        let s = frame(&app, 140, 40);
        let (x, y) = find(&s, "Да (y)", 0);
        assert_eq!(app.hit(x, y), Hit::Key(k(KeyCode::Char('y'))));
        let (x, y) = find(&s, "Отмена (Esc)", 0);
        assert_eq!(app.hit(x, y), Hit::Key(k(KeyCode::Esc)));
        let (x, y) = find(&s, "Точно?", 0);
        assert_eq!(app.hit(x, y), Hit::PopupInside);
        assert_eq!(app.hit(0, 0), Hit::PopupOutside);

        let mut app = demo_app();
        app.stack.push(Popup::Settings(SettingsPopup { sel: 0 }));
        let s = frame(&app, 140, 40);
        let (x, y) = find(&s, "тема", 0);
        assert_eq!(app.hit(x, y), Hit::PopupItem(4));
        // Клик по строке настроек применяется сразу.
        assert!(app.click_popup_item(4));
        match app.stack.last() {
            Some(Popup::Settings(s)) => assert_eq!(s.sel, 4),
            _ => panic!("нет попапа настроек"),
        }

        let mut app = demo_app();
        app.stack.push(Popup::Profile);
        let s = frame(&app, 140, 40);
        let (x, y) = find(&s, "Копировать friend code", 0);
        assert_eq!(app.hit(x, y), Hit::Key(k(KeyCode::Char('c'))));
    }

    #[test]
    fn окно_приглашения_кнопки_и_мышь() {
        let mut app = demo_app();
        app.stack.push(Popup::Invite(crate::tui::app::InvitePopup {
            gid: 2,
            group_name: "secret".into(),
            from_name: "bravo-srv".into(),
            from_pubkey: [2; 32],
            received_at: std::time::Instant::now(),
            expires_at: None,
            shown_at: None,
        }));
        let s = frame(&app, 140, 40);
        let text: String = s
            .iter()
            .map(|r| r.iter().collect::<String>() + "\n")
            .collect();
        assert!(text.contains("Приглашение в группу"), "{text}");
        assert!(text.contains("bravo (bravo-srv)"), "алиас друга: {text}");
        assert!(text.contains("«secret»") && text.contains("gid 2"));
        let (x, y) = find(&s, "Принять (Enter)", 0);
        assert_eq!(app.hit(x, y), Hit::Key(k(KeyCode::Enter)));
        let (x, y) = find(&s, "Отклонить (n)", 0);
        assert_eq!(app.hit(x, y), Hit::Key(k(KeyCode::Char('n'))));
        let (x, y) = find(&s, "Позже (Esc)", 0);
        assert_eq!(app.hit(x, y), Hit::Key(k(KeyCode::Esc)));
        let (x, y) = find(&s, "от:", 0);
        assert_eq!(app.hit(x, y), Hit::PopupInside);
        assert_eq!(app.hit(0, 0), Hit::PopupOutside);
        // Справка упоминает клавиши ответа.
        let mut app = demo_app();
        app.stack.push(Popup::Help);
        let text = render(&app, 140, 60);
        assert!(text.contains("неотвеченные приглашения"), "{text}");
    }

    #[test]
    fn длинный_тост_переносится_и_новый_виден() {
        let mut app = demo_app();
        app.toasts.clear();
        app.toast(
            MsgKind::Error,
            "нет связи с сервером — ответ не отправлен, приглашение отложено".into(),
        );
        app.toast(MsgKind::Info, "последний тост".into());
        let text = render(&app, 80, 24);
        assert!(
            text.contains("приглашение отложено"),
            "конец тоста обрезан: {text}"
        );
        assert!(
            text.contains("последний тост"),
            "новый тост вытеснен: {text}"
        );
        assert_eq!(
            wrapped_lines(
                "✗ нет связи с сервером — ответ не отправлен, приглашение отложено",
                50
            ),
            2
        );
    }

    #[test]
    fn клик_по_тосту_не_жмёт_кнопку_окна_под_ним() {
        let mut app = demo_app();
        app.stack.push(Popup::Invite(InvitePopup {
            gid: 2,
            group_name: "secret".into(),
            from_name: "bravo-srv".into(),
            from_pubkey: [2; 32],
            received_at: std::time::Instant::now(),
            expires_at: None,
            shown_at: None,
        }));
        app.toasts.clear();
        for i in 0..5 {
            app.toast(MsgKind::Info, format!("тост {i}"));
        }
        // 80x20: тосты ложатся на ряд кнопок окна приглашения.
        let _ = frame(&app, 80, 20);
        let t = app.hits.toasts.get();
        let covered = app
            .hits
            .popup_buttons
            .borrow()
            .iter()
            .map(|(r, _)| r.intersection(t))
            .find(|r| r.area() > 0)
            .expect("тост закрывает кнопку окна");
        assert_eq!(app.hit(covered.x, covered.y), Hit::Nothing);
        // Без тостов кнопка снова нажимается.
        app.toasts.clear();
        let _ = frame(&app, 80, 20);
        assert!(matches!(app.hit(covered.x, covered.y), Hit::Key(_)));
    }

    // ---------- виджеты и темы ----------

    use crate::tui::app::{
        InputAction, ListAction, ListPickPopup, PeerChoice, PeerPickPopup, PickMode,
    };
    use crate::tui::theme::{Palette, ThemeKind};
    use ratatui::style::Color;

    /// Все виды попапов (для дымовых тестов отрисовки).
    fn all_popups() -> Vec<(&'static str, Popup, bool)> {
        let choice = |i: u8| PeerChoice {
            pubkey: [i; 32],
            label: format!("peer-{i}"),
            sub: "100.66.1.9".into(),
            online: i.is_multiple_of(2),
        };
        vec![
            ("справка", Popup::Help, false),
            (
                "создание группы",
                Popup::Input(InputPopup {
                    title: "Новая группа".into(),
                    hint: "Enter — создать".into(),
                    value: "lan".into(),
                    action: InputAction::CreateGroup,
                    private: true,
                }),
                true,
            ),
            (
                "командная строка",
                Popup::Input(InputPopup {
                    title: "Команда".into(),
                    hint: ":help".into(),
                    value: "invites".into(),
                    action: InputAction::Command,
                    private: false,
                }),
                true,
            ),
            (
                "подтверждение",
                Popup::Confirm(ConfirmPopup {
                    title: "Удалить группу".into(),
                    message: "Точно удалить «gamers»? Это нельзя отменить.".into(),
                    action: ConfirmAction::DeleteGroup(1),
                }),
                true,
            ),
            (
                "выбор участника",
                Popup::PeerPick(PeerPickPopup {
                    gid: 1,
                    title: "Пригласить".into(),
                    mode: PickMode::Invite,
                    items: (0..30).map(choice).collect(),
                    sel: 25,
                }),
                false,
            ),
            (
                "карточка друга",
                Popup::FriendCard(FriendCardPopup {
                    alias: "bravo".into(),
                    pubkey: [2; 32],
                    groups: vec![],
                    loading: true,
                }),
                true,
            ),
            (
                "карточка участника",
                Popup::PeerCard(PeerCardPopup { pubkey: [2; 32] }),
                true,
            ),
            (
                "выбор пути",
                Popup::PathPin(PathPinPopup {
                    pubkey: [2; 32],
                    name: "bravo".into(),
                    ip: 0x6442_0103,
                    relay: Some([3; 32]),
                }),
                false,
            ),
            (
                "выбор пути без реле",
                Popup::PathPin(PathPinPopup {
                    pubkey: [2; 32],
                    name: "bravo".into(),
                    ip: 0x6442_0103,
                    relay: None,
                }),
                false,
            ),
            (
                "список",
                Popup::ListPick(ListPickPopup {
                    title: "Автовход".into(),
                    items: (0..3)
                        .map(|i| crate::tui::app::ListItem {
                            label: format!("группа {i}"),
                            checked: i == 1,
                            value: String::new(),
                        })
                        .collect(),
                    sel: 0,
                    action: ListAction::ToggleAutojoin,
                }),
                false,
            ),
            (
                "настройки",
                Popup::Settings(SettingsPopup { sel: 4 }),
                false,
            ),
            ("профиль", Popup::Profile, true),
            (
                "приглашение",
                Popup::Invite(crate::tui::app::InvitePopup {
                    gid: 2,
                    group_name: "secret".into(),
                    from_name: "bravo-srv".into(),
                    from_pubkey: [2; 32],
                    received_at: std::time::Instant::now(),
                    expires_at: Some(
                        std::time::Instant::now() + std::time::Duration::from_secs(6 * 86_400 + 60),
                    ),
                    shown_at: None,
                }),
                true,
            ),
        ]
    }

    /// Приложение с длинными списками, логом, трафиком и тостами.
    fn busy_app() -> App {
        let mut app = demo_app();
        for i in 0..30u32 {
            app.groups.push(GroupView {
                gid: 10 + i,
                name: format!("g{i:02}"),
                private: i.is_multiple_of(3),
                mine: i.is_multiple_of(2),
                online: i,
                total: i + 1,
                my_ip: None,
                owner_is_me: false,
                detached: false,
                peers: vec![],
            });
        }
        let peers: Vec<PeerView> = (0..40u8)
            .map(|i| PeerView {
                pubkey: [100 + i; 32],
                name: format!("p{i:02}"),
                ip: 0x6442_0110 + i as u32,
                online: !i.is_multiple_of(4),
                direct: i.is_multiple_of(2),
                rtt_ms: if i.is_multiple_of(5) {
                    None
                } else {
                    Some(i as u64 * 7)
                },
                status: "ok".into(),
                // Все виды пути: без пути, прямой, сервер и через реле
                // (ключ реле в списке участников отсутствует — имя по hex).
                path: match i % 4 {
                    0 => None,
                    1 => Some(PathSnap::new(PathKind::Direct, Some(i as u64 * 7))),
                    2 => Some(PathSnap::new(PathKind::Server, Some(48))),
                    _ => Some(PathSnap::new(
                        PathKind::PeerRelay { via: [200 + i; 32] },
                        Some(33),
                    )),
                },
            })
            .collect();
        app.groups[0].peers = peers.clone();
        app.groups[0].total = 41;
        app.peers = peers;
        for i in 0..20u8 {
            app.friends.push(FriendView {
                alias: format!("f{i:02}"),
                nick: String::new(),
                state: crate::store::FriendState::Accepted,
                pubkey: [200 + i; 32],
                online: i.is_multiple_of(2),
                shared_groups: 0,
            });
        }
        for i in 0..100 {
            let kind = [MsgKind::Info, MsgKind::Ok, MsgKind::Warn, MsgKind::Error][i % 4];
            app.log(kind, format!("событие {i}"));
        }
        app.toasts.clear();
        app.toast(MsgKind::Warn, "тост".into());
        app.rx_hist = (0..60).map(|i| i * 500).collect();
        app.tx_hist = (0..60).map(|i| (60 - i) * 300).collect();
        app
    }

    #[test]
    fn все_темы_и_попапы_рисуются_на_любом_размере() {
        for kind in ThemeKind::ALL {
            for (w, h) in [(120u16, 40u16), (80, 24), (40, 12), (20, 5), (1, 1)] {
                let mut app = busy_app();
                app.theme_kind = kind;
                let _ = frame(&app, w, h);
                if w >= 80 {
                    let (r, _) = app.hits.groups.get();
                    assert!(r.width > 0 && r.height > 0, "{kind:?} {w}x{h}: нет групп");
                    assert!(
                        app.hits.peers.get().0.height > 0,
                        "{kind:?}: нет участников"
                    );
                    assert!(app.hits.log.get().height > 0, "{kind:?}: нет лога");
                    assert_eq!(app.hits.tabs.borrow().len(), 4, "{kind:?}: вкладки");
                    assert!(!app.hits.toolbar.borrow().is_empty());
                }
                for (name, popup, has_buttons) in all_popups() {
                    let mut app = busy_app();
                    app.theme_kind = kind;
                    app.stack.push(popup);
                    let _ = frame(&app, w, h);
                    if w >= 80 {
                        let r = app.hits.popup.get();
                        assert!(r.width > 0 && r.height > 0, "{kind:?} {w}x{h}: {name}");
                        assert_eq!(
                            !app.hits.popup_buttons.borrow().is_empty(),
                            has_buttons,
                            "{kind:?} {w}x{h}: кнопки «{name}»"
                        );
                        // Кнопки — внутри окна.
                        for (b, _) in app.hits.popup_buttons.borrow().iter() {
                            assert!(r.contains(b.as_position()), "{name}: кнопка вне окна");
                            assert!(b.right() < r.right(), "{name}: кнопка на рамке");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn фон_кадра_красится_темой() {
        for kind in ThemeKind::ALL {
            let mut app = demo_app();
            app.theme_kind = kind;
            let mut term = Terminal::new(TestBackend::new(140, 40)).unwrap();
            term.draw(|f| draw(f, &app)).unwrap();
            let buf = term.backend().buffer();
            let c = Palette::of(kind);
            // Правый край панели действий — «голый» фон кадра.
            assert_eq!(buf[(139u16, 3u16)].bg, c.bg, "{kind:?}: фон кадра");
            // Внутри панели групп — фон панели.
            let (r, _) = app.hits.groups.get();
            assert_eq!(
                buf[(r.right() - 3, r.bottom() - 2)].bg,
                c.surface,
                "{kind:?}"
            );
            // Ни одной клетки с цветом терминала по умолчанию.
            for y in 0..40u16 {
                for x in 0..140u16 {
                    assert_ne!(buf[(x, y)].bg, Color::Reset, "{kind:?}: ({x},{y}) без фона");
                }
            }
        }
    }

    #[test]
    fn вкладки_фокуса_кликабельны() {
        let mut app = demo_app();
        let s = frame(&app, 140, 40);
        let (x, y) = find(&s, "Участники", 0);
        assert_eq!(y, 39, "вкладки — в статус-баре:\n{}", render(&app, 140, 40));
        assert_eq!(app.hit(x, y), Hit::Panel(Focus::Peers));
        let (x, y) = find_row(&s, " Лог ", 39);
        assert_eq!(app.hit(x + 1, y), Hit::Panel(Focus::Log));
        // Подсвечена текущая вкладка.
        app.focus = Focus::Friends;
        let mut term = Terminal::new(TestBackend::new(140, 40)).unwrap();
        term.draw(|f| draw(f, &app)).unwrap();
        let buf = term.backend().buffer();
        let c = Palette::of(app.theme_kind);
        let (fx, fy) = find(&s, "Друзья", 0);
        let (fx, fy) = if fy == 39 {
            (fx, fy)
        } else {
            find_row(&s, "Друзья", 39)
        };
        assert_eq!(buf[(fx, fy)].bg, c.tab_active_bg, "активная вкладка");
        let (gx, gy) = find_row(&s, "Группы", 39);
        assert_ne!(buf[(gx, gy)].bg, c.tab_active_bg, "неактивная вкладка");
    }

    /// Координаты `text` в строке `y`.
    fn find_row(screen: &[Vec<char>], text: &str, y: usize) -> (u16, u16) {
        let pat: Vec<char> = text.chars().collect();
        let row = &screen[y];
        for x in 0..row.len().saturating_sub(pat.len() - 1) {
            if row[x..x + pat.len()] == pat[..] {
                return (x as u16, y as u16);
            }
        }
        panic!("в строке {y} нет «{text}»");
    }

    #[test]
    fn прокрутка_списков_согласована_с_мышью() {
        let mut app = busy_app();
        // Выбрана последняя группа — список прокручен.
        app.sel_group = Some(39);
        app.focus = Focus::Peers;
        app.sel_peer = Some([139; 32]);
        let s = frame(&app, 80, 24);
        assert!(app.hits.groups.get().1 > 0, "список групп не прокручен");
        let (x, y) = find(&s, "○ g29", 0);
        assert_eq!(app.hit(x, y), Hit::Item(Focus::Groups, 31));
        // Полоса прокрутки — на правой рамке панели групп, ползунок внизу.
        let (r, _) = app.hits.groups.get();
        let col: String = (r.y + 1..r.bottom() - 1)
            .map(|y| s[y as usize][(r.right() - 1) as usize])
            .collect();
        assert!(col.contains('█'), "нет ползунка: {col:?}");
        assert!(col.ends_with('█'), "ползунок не внизу: {col:?}");

        // Таблица участников прокручена к p39; клик по строке — тот участник.
        assert!(app.hits.peers.get().1 > 0, "таблица не прокручена");
        let (x, y) = find(&s, "p39", 24);
        assert_eq!(app.hit(x, y), Hit::Item(Focus::Peers, 39));
        // Строка шкалы заполненности — в панели, но не участник.
        let (x, y) = find(&s, "занято 30/253", 0);
        assert_eq!(app.hit(x, y), Hit::Panel(Focus::Peers));
        assert_eq!(app.hit(x, y - 1), Hit::Item(Focus::Peers, 39));
    }

    #[test]
    fn лог_прокручивается_с_полосой() {
        let mut app = busy_app();
        app.toasts.clear();
        app.log_scroll = 50;
        let s = frame(&app, 120, 40);
        let text: String = s
            .iter()
            .map(|r| r.iter().collect::<String>() + "\n")
            .collect();
        assert!(text.contains("событие 49"), "{text}");
        assert!(!text.contains("событие 99"));
        let r = app.hits.log.get();
        let col: String = (r.y + 1..r.bottom() - 1)
            .map(|y| s[y as usize][(r.right() - 1) as usize])
            .collect();
        assert!(col.contains('█'), "нет ползунка лога: {col:?}");
    }

    #[test]
    fn трафик_и_статус() {
        let mut app = busy_app();
        app.toasts.clear();
        let text = render(&app, 120, 40);
        assert!(text.contains("Трафик") && text.contains("приём") && text.contains("передача"));
        assert!(text.contains("пик"), "{text}");
        // Узко: панели трафика нет, скорость — в заголовке лога.
        let text = render(&app, 70, 24);
        assert!(!text.contains("Трафик"));
        let log_top = text.lines().find(|l| l.contains("Лог")).unwrap();
        assert!(
            log_top.contains("↓28.8 КБ/с") && log_top.contains('↑'),
            "{text}"
        );
    }

    #[test]
    fn выбранная_строка_читаема_во_всех_темах() {
        for kind in ThemeKind::ALL {
            let mut app = demo_app();
            app.theme_kind = kind;
            let mut term = Terminal::new(TestBackend::new(140, 40)).unwrap();
            term.draw(|f| draw(f, &app)).unwrap();
            let s = frame(&app, 140, 40);
            let buf = term.backend().buffer();
            let c = Palette::of(kind);
            let (x, y) = find(&s, "● gamers", 0);
            assert_eq!(buf[(x, y)].bg, c.sel_bg, "{kind:?}");
            assert_eq!(buf[(x, y)].fg, c.sel_fg, "{kind:?}");
        }
    }

    // ---------- экраны «Управление группой» и «Серверы» ----------

    mod screens {
        use super::demo_app;
        use crate::engine::Cmd;
        use crate::store::{Config, StoredServer};
        use crate::tui::app::{App, Popup};
        use crate::tui::{admin, ui::draw};
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        use ratatui::crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
        use tunnel_protocol as proto;

        fn frame(app: &App, w: u16, h: u16) -> Vec<Vec<char>> {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| draw(f, app)).unwrap();
            let buf = term.backend().buffer().clone();
            (0..h)
                .map(|y| {
                    (0..w)
                        .map(|x| buf[(x, y)].symbol().chars().next().unwrap_or(' '))
                        .collect()
                })
                .collect()
        }

        fn find(screen: &[Vec<char>], text: &str) -> (u16, u16) {
            let pat: Vec<char> = text.chars().collect();
            for (y, row) in screen.iter().enumerate() {
                for x in 0..row.len().saturating_sub(pat.len() - 1) {
                    if row[x..x + pat.len()] == pat[..] {
                        return (x as u16, y as u16);
                    }
                }
            }
            panic!("на экране нет «{text}»");
        }

        fn text(screen: &[Vec<char>]) -> String {
            screen
                .iter()
                .map(|r| r.iter().collect::<String>() + "\n")
                .collect()
        }

        fn click(x: u16, y: u16) -> MouseEvent {
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: x,
                row: y,
                modifiers: KeyModifiers::NONE,
            }
        }

        /// Клик по экрану управления (как `App::handle_mouse` для него).
        fn admin_click(app: &mut App, x: u16, y: u16) -> Vec<Cmd> {
            let act = match app.stack.last_mut() {
                Some(Popup::Admin(v)) => admin::handle_mouse(v, click(x, y)),
                _ => panic!("экран управления не открыт"),
            };
            app.admin_apply(act)
        }

        #[test]
        fn управление_группой_рисуется_и_кликается() {
            let mut app = demo_app();
            assert!(matches!(app.open_admin(), Some(Cmd::GroupAdmin(1))));
            app.on_admin_info(
                1,
                vec![([3; 32], "charlie".into())],
                vec![([4; 32], "delta".into(), 7200)],
            );
            let s = frame(&app, 140, 40);
            let t = text(&s);
            assert!(
                t.contains("Управление группой «gamers»") && t.contains("charlie"),
                "{t}"
            );

            // Клик по кнопке «Разбанить» = Enter на выбранной строке.
            let (x, y) = find(&s, "Разбанить (Enter)");
            let cmds = admin_click(&mut app, x + 1, y);
            assert!(
                matches!(cmds[..], [Cmd::Unban(1, pk), Cmd::GroupAdmin(1)] if pk == [3; 32]),
                "{cmds:?}"
            );

            // Вкладка «Приглашения» кликом, затем «Отозвать».
            let (x, y) = find(&s, "Приглашения");
            assert!(admin_click(&mut app, x + 1, y).is_empty());
            let s = frame(&app, 140, 40);
            assert!(text(&s).contains("delta"));
            let (x, y) = find(&s, "Отозвать приглашение (Enter)");
            let cmds = admin_click(&mut app, x + 1, y);
            assert!(
                matches!(cmds[..], [Cmd::Kick(1, pk), Cmd::GroupAdmin(1)] if pk == [4; 32]),
                "{cmds:?}"
            );

            // Клик мимо окна — закрыть.
            assert!(admin_click(&mut app, 0, 0).is_empty());
            assert!(app.stack.is_empty());
        }

        #[test]
        fn серверы_рисуются_и_переключаются_кликом() {
            let mut app = demo_app();
            let mut cfg = Config {
                servers: vec![
                    StoredServer {
                        addr: "127.0.0.1:5599".into(),
                        pubkey: proto::hex_of(&[1; 32]),
                        label: "дом".into(),
                    },
                    StoredServer {
                        addr: "127.0.0.9:5601".into(),
                        pubkey: proto::hex_of(&[2; 32]),
                        label: "офис".into(),
                    },
                ],
                ..Config::default()
            };
            app.open_servers_with(&cfg);
            let s = frame(&app, 140, 40);
            let t = text(&s);
            assert!(
                t.contains("127.0.0.1:5599") && t.contains("127.0.0.9:5601"),
                "{t}"
            );

            // Первый клик по строке выбирает, второй — переключает.
            let (x, y) = find(&s, "127.0.0.9:5601");
            let mut act = None;
            for _ in 0..2 {
                act = match app.stack.last_mut() {
                    Some(Popup::Servers(v)) => {
                        v.handle_mouse(MouseEventKind::Down(MouseButton::Left), x, y)
                    }
                    _ => panic!("экран серверов не открыт"),
                };
            }
            let (cmd, save) = app.servers_apply(act.expect("переключение"), &mut cfg);
            assert!(!save);
            assert!(
                matches!(cmd, Some(Cmd::SwitchServer { addr, .. }) if addr.to_string() == "127.0.0.9:5601")
            );
        }

        #[test]
        fn справка_знает_про_новые_экраны() {
            let mut app = demo_app();
            app.stack.push(Popup::Help);
            let t = text(&frame(&app, 140, 50));
            assert!(t.contains(":admin") && t.contains(":servers"), "{t}");
        }
    }

    #[test]
    fn статус_бар_бейджи_и_клик_по_приглашениям() {
        let mut app = demo_app();
        app.toasts.clear();
        app.connected = true;
        app.invisible = true;
        app.later_invites.push(InvitePopup {
            gid: 9,
            group_name: "x".into(),
            from_name: "y".into(),
            from_pubkey: [5; 32],
            received_at: std::time::Instant::now(),
            expires_at: None,
            shown_at: None,
        });
        let s = frame(&app, 200, 40);
        let last: String = s[39].iter().collect();
        assert!(last.contains("● в сети"), "{last}");
        assert!(last.contains("✦ 1"), "{last}");
        assert!(last.contains("невидимка"), "{last}");
        assert!(last.contains("UDP"), "{last}");
        assert!(
            last.contains("◆ 1 прямых") && last.contains("◇ 0 через релей"),
            "{last}"
        );
        // Клик по бейджу приглашений — клавиша «o».
        let (x, y) = find(&s, "✦ 1", 0);
        assert_eq!(app.hit(x, y), Hit::Key(k(KeyCode::Char('o'))));
        // Без связи — «сервер недоступен», без приглашений бейджа нет.
        app.connected = false;
        app.conn = ConnState::Reconnecting;
        app.later_invites.clear();
        let s = frame(&app, 200, 40);
        let last: String = s[39].iter().collect();
        assert!(
            last.contains("○ сервер недоступен") && !last.contains('✦'),
            "{last}"
        );
        // Узко — не паникует.
        let _ = frame(&app, 40, 20);
    }

    #[test]
    fn пилюли_офлайна_и_ожидающих_правок() {
        // Демон недоступен + отложенные правки (офлайн-очередь).
        let mut app = demo_app();
        app.conn = ConnState::DaemonDown;
        app.pending_edits = 2;
        let s = frame(&app, 200, 40);
        let header: String = s[1].iter().collect();
        assert!(header.contains("⚠ демон недоступен"), "{header}");
        let last: String = s[39].iter().collect();
        assert!(last.contains("ожидает применения (2)"), "{last}");
        // Без серверов — «нет сервера», правок нет — нет бейджа.
        app.conn = ConnState::NoServer;
        app.pending_edits = 0;
        app.servers.clear();
        let s = frame(&app, 200, 40);
        let header: String = s[1].iter().collect();
        assert!(header.contains("○ нет сервера"), "{header}");
        let last: String = s[39].iter().collect();
        assert!(!last.contains("ожидает применения"), "{last}");
    }

    #[test]
    fn окно_приглашения_показывает_срок() {
        let mut app = demo_app();
        app.toasts.clear();
        app.stack.push(Popup::Invite(InvitePopup {
            gid: 2,
            group_name: "secret".into(),
            from_name: "bravo-srv".into(),
            from_pubkey: [2; 32],
            received_at: std::time::Instant::now(),
            expires_at: Some(
                std::time::Instant::now() + std::time::Duration::from_secs(6 * 86_400 + 600),
            ),
            shown_at: None,
        }));
        let text = render(&app, 120, 40);
        assert!(text.contains("истекает через 6 д"), "{text}");
    }

    #[test]
    fn лог_с_локальным_временем_и_невидимка_в_настройках() {
        let mut app = demo_app();
        app.toasts.clear();
        app.log.clear();
        app.log(MsgKind::Info, "запись".into());
        let want = clock::format_local(app.log[0].wall);
        let text = render(&app, 120, 40);
        assert!(text.contains(&format!("{want} · запись")), "{text}");
        app.stack.push(Popup::Settings(SettingsPopup { sel: 0 }));
        app.invisible = true;
        let text = render(&app, 120, 40);
        assert!(text.contains("невидимка") && text.contains("вкл"), "{text}");
    }
}
