//! TUI-режим клиента (ratatui + crossterm).
//!
//! Движок ничего не знает про UI: TUI видит его через [`EngineApi`] —
//! снимок состояния, события и команды. Два режима (PLAN.md 7.4):
//! [`run`] — embedded, движок в этом процессе ([`LocalEngine`], нужны права
//! на TUN); [`run_remote`] — тонкий клиент демона ([`IpcEngine`]).

pub mod admin;
pub mod app;
pub mod badges;
pub mod clipboard;
pub mod clock;
pub mod identicon;
pub mod keymap;
pub mod servers;
pub mod setup;
pub mod theme;
pub mod ui;

use std::io::Stdout;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind, MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::prelude::*;

use crate::api::{EngineApi, LocalEngine};
use crate::engine::{self, Cmd};
use crate::remote::IpcEngine;
use crate::store::{Config, Store};

use app::App;

/// Запускает TUI: поднимает движок и рисует интерфейс до выхода.
pub fn run(
    cfg: Arc<Config>,
    server: std::net::SocketAddr,
    server_pub: [u8; 32],
    identity: tunnel_protocol::Identity,
    adapter_name: &str,
    dll: Option<String>,
    store: Arc<Store>,
) -> Result<()> {
    let dll_path = dll.clone().unwrap_or_default();
    // Смещение локального времени — до запуска потоков движка.
    clock::init();
    let shared = Arc::new(Mutex::new((*cfg).clone()));
    let save_store = store.clone();
    let save = move |c: &Config| {
        let _ = save_store.save(c);
    };
    let eng = engine::start(
        shared,
        server,
        server_pub,
        identity,
        adapter_name,
        dll,
        Arc::new(save),
    )?;

    let cfg_snapshot = eng.cfg.lock().unwrap().clone();
    let eng = LocalEngine::new(eng);

    let mut term = setup_terminal(true)?;
    let mut app = App::new(eng.me().my_pub, &eng.me().my_code, &cfg_snapshot);
    // Экран «Серверы» показывает то, с чем клиент запущен на самом деле.
    app.adapter_name = adapter_name.to_string();
    app.dll_path = dll_path;
    let res = event_loop(&mut term, &mut app, &eng);
    let restore = restore_terminal(&mut term, true);
    // Останавливаем движок (потоки туннеля) в любом случае.
    let _ = eng.send(Cmd::Quit);
    restore?;
    res
}

/// Тонкий клиент: движок в демоне, TUI только рисует и шлёт команды
/// (права администратора не нужны). `ui` — локальные настройки (тема).
/// Закрытие TUI туннель не трогает.
pub fn run_remote(eng: IpcEngine, ui: &Config) -> Result<()> {
    clock::init();
    let mut term = setup_terminal(true)?;
    let mut app = App::new(eng.me().my_pub, &eng.me().my_code, ui);
    // Адаптер и dll — у демона, TUI их не знает.
    app.adapter_name = String::new();
    app.dll_path = String::new();
    let res = event_loop(&mut term, &mut app, &eng);
    restore_terminal(&mut term, true)?;
    res
}

/// `mouse` — захват мыши (клики, колесо; выделение текста терминалом — с
/// Shift). Экрану первичной настройки мышь не нужна: без захвата поток
/// событий движения не вызывает лишних перерисовок.
pub(crate) fn setup_terminal(mouse: bool) -> Result<Terminal<CrosstermBackend<Stdout>>> {
    install_panic_hook();
    let mut out = std::io::stdout();
    // Захват мыши — до raw-режима: crossterm запоминает текущий режим
    // консоли и восстанавливает его при `DisableMouseCapture`. Иначе в
    // «исходном» режиме остался бы raw, и после выхода из TUI консоль была
    // бы без эха.
    if mouse {
        execute!(out, EnableMouseCapture)?;
    }
    enable_raw_mode()?;
    execute!(out, EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(out))?)
}

/// При панике вернуть терминал в нормальный режим до печати сообщения —
/// иначе консоль остаётся в raw-режиме, на альтернативном экране и с
/// захватом мыши, а текст паники не виден.
fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = disable_raw_mode();
            // По отдельности: DisableMouseCapture без EnableMouseCapture на
            // Windows падает — и LeaveAlternateScreen тогда бы не выполнился.
            let _ = execute!(std::io::stdout(), DisableMouseCapture);
            let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
            prev(info);
        }));
    });
}

/// Восстановление консоли. `mouse` — был ли включён захват мыши: снимать
/// надо только то, что включали. На Windows `DisableMouseCapture` без
/// предшествующего `EnableMouseCapture` падает с «Initial console modes not
/// set» (crossterm не знает исходного режима мыши) — а экран первичной
/// настройки мышь не включает.
pub(crate) fn restore_terminal(
    term: &mut Terminal<CrosstermBackend<Stdout>>,
    mouse: bool,
) -> Result<()> {
    // Сначала захват мыши: crossterm восстанавливает запомненный режим
    // консоли целиком — вместе с эхом и вводом строки.
    if mouse {
        execute!(term.backend_mut(), DisableMouseCapture)?;
    }
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    Ok(())
}

fn event_loop(
    term: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    eng: &dyn EngineApi,
) -> Result<()> {
    let tick = Duration::from_millis(120);
    loop {
        app.sync(eng);
        term.draw(|f| ui::draw(f, app))?;
        if app.quit {
            return Ok(());
        }
        if event::poll(tick)? {
            // Движения мыши приходят пачками — пропускаем их без перерисовки.
            // После любого значимого события кадр перерисовывается: клик
            // проверяется по геометрии последнего кадра (`App::hits`).
            let mut n = 0;
            loop {
                let mut significant = true;
                match event::read()? {
                    Event::Key(key) if key.kind != KeyEventKind::Release => {
                        app.handle_key(key, eng);
                    }
                    Event::Mouse(m) => {
                        significant =
                            !matches!(m.kind, MouseEventKind::Moved | MouseEventKind::Drag(_));
                        app.handle_mouse(m, eng);
                    }
                    _ => {}
                }
                n += 1;
                if significant || n >= 64 || !event::poll(Duration::ZERO)? {
                    break;
                }
            }
        }
    }
}
