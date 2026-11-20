//! Маленькие бейджи строки статуса: приглашения, соединение, невидимка,
//! транспорт и счётчик прямых/релейных пиров.
//!
//! Модуль ничего не знает про `App`: integration-слой собирает [`BadgeState`]
//! из состояния движка/демона и вызывает [`render_badges`] (или
//! [`fit_badges`], если нужны только спаны). Кликабельные бейджи возвращают
//! хит-зоны в формате `ui.rs` — `(Rect, KeyEvent)`: клик эквивалентен нажатию
//! клавиши.

// подключается при интеграции
#![allow(dead_code)]

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::theme::Theme;

/// Клавиша, открывающая список приглашений.
pub const INVITES_KEY: char = 'o';

/// Состояние соединения с сервером (или демоном) — пилюля в шапке и
/// статус-баре.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ConnState {
    /// Движок есть, сервер отвечает.
    Online,
    /// Движок есть, сервер не отвечает (переподключение).
    #[default]
    Reconnecting,
    /// Демон недоступен: IPC потерян или TUI работает офлайн (движка нет).
    DaemonDown,
    /// В конфиге нет серверов — подключаться некуда.
    NoServer,
}

/// Транспорт до сервера.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Transport {
    #[default]
    Udp,
    Tcp,
}

/// Всё, что нужно для отрисовки бейджей.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct BadgeState {
    pub pending_invites: usize,
    pub conn: ConnState,
    pub invisible: bool,
    pub transport: Transport,
    /// Онлайн-пиры с прямым P2P-каналом.
    pub direct: usize,
    /// Онлайн-пиры через релей.
    pub relay: usize,
    /// Сколько правок TUI ждёт применения демоном (офлайн-очередь).
    pub pending_edits: usize,
}

/// Вид бейджа. Порядок вариантов = порядок слева направо.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BadgeKind {
    Conn,
    Pending,
    Invites,
    Invisible,
    Transport,
    Peers,
}

impl BadgeKind {
    /// Приоритет: меньше — важнее; при нехватке ширины первыми
    /// выбрасываются бейджи с наибольшим значением.
    pub fn priority(self) -> u8 {
        match self {
            BadgeKind::Conn => 0,
            BadgeKind::Pending => 1,
            BadgeKind::Invites => 2,
            BadgeKind::Invisible => 3,
            BadgeKind::Peers => 4,
            BadgeKind::Transport => 5,
        }
    }

    /// Клавиша, которую эмулирует клик по бейджу.
    pub fn click_key(self) -> Option<KeyEvent> {
        match self {
            BadgeKind::Invites => Some(KeyEvent::new(
                KeyCode::Char(INVITES_KEY),
                KeyModifiers::NONE,
            )),
            _ => None,
        }
    }
}

/// Один бейдж: вид + его спаны.
#[derive(Clone, Debug)]
pub struct Badge {
    pub kind: BadgeKind,
    pub spans: Vec<Span<'static>>,
}

impl Badge {
    pub fn width(&self) -> usize {
        self.spans.iter().map(Span::width).sum()
    }
}

/// Разделитель между бейджами.
const SEP: &str = " ";

/// Собирает все видимые бейджи (без учёта ширины) в порядке слева направо.
pub fn badges(state: &BadgeState, th: &Theme) -> Vec<Badge> {
    let mut out = Vec::with_capacity(6);

    let (glyph, text, style) = match state.conn {
        ConnState::Online => ("●", "в сети", th.ok),
        ConnState::Reconnecting => ("○", "сервер недоступен", th.warn),
        ConnState::DaemonDown => ("⚠", "демон недоступен", th.error),
        ConnState::NoServer => ("○", "нет сервера", th.error),
    };
    out.push(Badge {
        kind: BadgeKind::Conn,
        spans: vec![Span::styled(
            format!(" {glyph} {text} "),
            style.add_modifier(Modifier::REVERSED | Modifier::BOLD),
        )],
    });

    // Офлайн-правки: показываем, что они ещё не на демоне (⏳).
    if state.pending_edits > 0 {
        let n = if state.pending_edits > 1 {
            format!(" ({})", state.pending_edits)
        } else {
            String::new()
        };
        out.push(Badge {
            kind: BadgeKind::Pending,
            spans: vec![Span::styled(
                format!("⏳ ожидает применения{n}"),
                th.warn.add_modifier(Modifier::BOLD),
            )],
        });
    }

    if state.pending_invites > 0 {
        out.push(Badge {
            kind: BadgeKind::Invites,
            spans: vec![
                // '✦' (U+2726): без emoji-представления, во всех терминалах — 1 ячейка
                // ('✉' в Windows Terminal/iTerm рисуется шириной 2 и сдвигает зону клика).
                Span::styled(
                    format!("✦ {}", state.pending_invites),
                    th.accent.add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(" [{INVITES_KEY}]"), th.dim),
            ],
        });
    }

    if state.invisible {
        out.push(Badge {
            kind: BadgeKind::Invisible,
            spans: vec![Span::styled("◌ невидимка", th.warn)],
        });
    }

    let (label, style) = match state.transport {
        Transport::Udp => ("UDP", th.dim),
        Transport::Tcp => ("TCP", th.warn),
    };
    out.push(Badge {
        kind: BadgeKind::Transport,
        spans: vec![Span::styled(label, style)],
    });

    out.push(Badge {
        kind: BadgeKind::Peers,
        spans: vec![
            Span::styled(format!("◆ {} прямых", state.direct), th.direct),
            Span::styled(" / ", th.dim),
            Span::styled(format!("◇ {} через релей", state.relay), th.relay),
        ],
    });

    out
}

/// Все бейджи одной строкой спанов (без учёта ширины).
pub fn status_badges(state: &BadgeState, th: &Theme) -> Vec<Span<'static>> {
    join(&badges(state, th))
}

/// Склеивает бейджи через разделитель.
fn join(list: &[Badge]) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (i, b) in list.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(SEP));
        }
        spans.extend(b.spans.iter().cloned());
    }
    spans
}

fn total_width(list: &[Badge]) -> usize {
    let seps = list.len().saturating_sub(1) * SEP.len();
    list.iter().map(Badge::width).sum::<usize>() + seps
}

/// Результат подгонки по ширине.
#[derive(Clone, Debug, Default)]
pub struct BadgeLine {
    pub spans: Vec<Span<'static>>,
    /// Вошедшие бейджи в порядке отрисовки.
    pub kinds: Vec<BadgeKind>,
    /// Кликабельные зоны: (смещение x от начала строки, ширина, клавиша).
    pub hits: Vec<(u16, u16, KeyEvent)>,
    pub width: u16,
}

/// Оставляет столько бейджей, сколько влезает в `max_width` ячеек,
/// выбрасывая сначала наименее важные. Порядок оставшихся не меняется.
pub fn fit_badges(state: &BadgeState, th: &Theme, max_width: u16) -> BadgeLine {
    let mut list = badges(state, th);
    while !list.is_empty() && total_width(&list) > max_width as usize {
        let worst = list
            .iter()
            .enumerate()
            .max_by_key(|(_, b)| b.kind.priority())
            .map(|(i, _)| i)
            .unwrap();
        list.remove(worst);
    }

    let mut hits = Vec::new();
    let mut x = 0usize;
    for (i, b) in list.iter().enumerate() {
        if i > 0 {
            x += SEP.len();
        }
        let w = b.width();
        if let Some(k) = b.kind.click_key() {
            hits.push((x as u16, w as u16, k));
        }
        x += w;
    }

    BadgeLine {
        spans: join(&list),
        kinds: list.iter().map(|b| b.kind).collect(),
        hits,
        width: x as u16,
    }
}

/// Рисует бейджи в первой строке `area`, прижимая их к правому краю, и
/// возвращает хит-зоны кликабельных бейджей (формат `App::hits` из `ui.rs`).
pub fn render_badges(
    f: &mut Frame,
    area: Rect,
    state: &BadgeState,
    th: &Theme,
) -> Vec<(Rect, KeyEvent)> {
    if area.width == 0 || area.height == 0 {
        return Vec::new();
    }
    let line = fit_badges(state, th, area.width);
    let x0 = area.x + area.width - line.width;
    let row = Rect::new(x0, area.y, line.width, 1);
    f.render_widget(Paragraph::new(Line::from(line.spans)), row);
    line.hits
        .into_iter()
        .map(|(dx, w, k)| (Rect::new(x0 + dx, area.y, w, 1), k))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::theme::ThemeKind;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn full() -> BadgeState {
        BadgeState {
            pending_invites: 3,
            conn: ConnState::Online,
            invisible: true,
            transport: Transport::Tcp,
            direct: 2,
            relay: 1,
            pending_edits: 0,
        }
    }

    fn render(state: &BadgeState, kind: ThemeKind, w: u16) -> (String, Vec<(Rect, KeyEvent)>) {
        let th = Theme::of(kind);
        let mut term = Terminal::new(TestBackend::new(w, 1)).unwrap();
        let mut hits = Vec::new();
        term.draw(|f| hits = render_badges(f, f.area(), state, &th))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let text: String = (0..w).map(|x| buf[(x, 0)].symbol().to_string()).collect();
        (text, hits)
    }

    #[test]
    fn все_бейджи_на_широком_экране() {
        for kind in ThemeKind::ALL {
            let (text, hits) = render(&full(), kind, 120);
            assert!(text.contains("в сети"), "{text}");
            assert!(text.contains("✦ 3"), "{text}");
            assert!(text.contains("[o]"), "{text}");
            assert!(text.contains("◌ невидимка"), "{text}");
            assert!(text.contains("TCP"), "{text}");
            assert!(text.contains("◆ 2 прямых / ◇ 1 через релей"), "{text}");
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].1.code, KeyCode::Char('o'));
        }
    }

    #[test]
    fn узкий_экран_теряет_маловажное() {
        for kind in ThemeKind::ALL {
            for w in [40u16, 80, 120] {
                let th = Theme::of(kind);
                let line = fit_badges(&full(), &th, w);
                assert!(line.width <= w, "ширина {} > {w}", line.width);
                // Соединение и приглашения остаются всегда при ширине ≥ 40.
                assert_eq!(line.kinds[0], BadgeKind::Conn);
                assert!(line.kinds.contains(&BadgeKind::Invites), "w={w}");
                let (text, hits) = render(&full(), kind, w);
                assert!(text.contains("в сети"), "w={w}: {text}");
                assert!(text.contains("✦ 3"), "w={w}: {text}");
                assert_eq!(hits.len(), 1);
            }
            let line = fit_badges(&full(), &Theme::of(kind), 40);
            assert!(!line.kinds.contains(&BadgeKind::Transport));
            assert!(!line.kinds.contains(&BadgeKind::Peers));
        }
    }

    #[test]
    fn приоритет_выброса() {
        let th = Theme::of(ThemeKind::Dark);
        let all = total_width(&badges(&full(), &th)) as u16;
        // Минус одна ячейка — уходит транспорт, но не счётчик.
        let line = fit_badges(&full(), &th, all - 1);
        assert!(!line.kinds.contains(&BadgeKind::Transport));
        assert!(line.kinds.contains(&BadgeKind::Peers));
        // Совсем узко — ничего не влезает, но и не паникует.
        assert!(fit_badges(&full(), &th, 0).kinds.is_empty());
        let (text, hits) = render(&full(), ThemeKind::Dark, 5);
        assert!(hits.is_empty());
        assert_eq!(text.trim(), "");
    }

    #[test]
    fn приглашения_скрыты_при_нуле() {
        let st = BadgeState {
            pending_invites: 0,
            ..full()
        };
        let (text, hits) = render(&st, ThemeKind::Dark, 120);
        assert!(!text.contains('✦'), "{text}");
        assert!(hits.is_empty());
    }

    #[test]
    fn хит_зона_попадает_в_бейдж() {
        let (text, hits) = render(&full(), ThemeKind::Light, 80);
        let r = hits[0].0;
        let cells: Vec<String> = text.chars().map(String::from).collect();
        let got: String = cells[r.x as usize..(r.x + r.width) as usize].concat();
        assert_eq!(got, "✦ 3 [o]");
    }

    #[test]
    fn состояния_соединения_и_транспорт() {
        let th = Theme::of(ThemeKind::Contrast);
        for (conn, want) in [
            (ConnState::Online, "в сети"),
            (ConnState::Reconnecting, "сервер недоступен"),
            (ConnState::DaemonDown, "демон недоступен"),
            (ConnState::NoServer, "нет сервера"),
        ] {
            let st = BadgeState {
                conn,
                ..Default::default()
            };
            let text: String = status_badges(&st, &th)
                .iter()
                .map(|s| s.content.to_string())
                .collect();
            assert!(text.contains(want), "{text}");
            assert!(text.contains("UDP"), "{text}");
            assert!(!text.contains("невидимка"));
        }
    }

    #[test]
    fn офлайн_правки_ждут_применения() {
        let th = Theme::of(ThemeKind::Dark);
        let st = BadgeState {
            pending_edits: 2,
            ..Default::default()
        };
        let text: String = status_badges(&st, &th)
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        assert!(text.contains("⏳ ожидает применения (2)"), "{text}");
        // Одна правка — без числа; нет правок — нет бейджа.
        let st = BadgeState {
            pending_edits: 1,
            ..Default::default()
        };
        let text: String = status_badges(&st, &th)
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        assert!(text.contains("⏳ ожидает применения") && !text.contains("(1)"), "{text}");
        let text: String = status_badges(&BadgeState::default(), &th)
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        assert!(!text.contains("ожидает применения"), "{text}");
    }

    #[test]
    fn глиф_приглашений_одна_ячейка() {
        assert_eq!(Span::raw("✦").width(), 1);
    }
}
