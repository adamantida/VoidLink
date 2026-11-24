//! Копирование текста в буфер обмена.
//!
//! Два пути: escape-последовательность OSC 52 (работает через SSH — копирует
//! в буфер того терминала, где сидит пользователь) и системные утилиты
//! (`clip.exe`, `pbcopy`, `wl-copy`, `xclip`, `xsel`). В SSH-сессии сначала
//! пробуем OSC 52, локально — сначала системный буфер, OSC 52 — запасной.
#![allow(dead_code)] // подключается при интеграции

use std::io::{IsTerminal, Write};
use std::process::{Command, Stdio};

/// Каким способом текст попал в буфер.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Escape-последовательность OSC 52 в терминал.
    Osc52,
    /// Windows `clip.exe`.
    WinClip,
    /// macOS `pbcopy`.
    PbCopy,
    /// Wayland `wl-copy`.
    WlCopy,
    /// X11 `xclip`.
    Xclip,
    /// X11 `xsel`.
    Xsel,
}

impl Method {
    /// Короткое имя для статус-строки.
    pub fn label(self) -> &'static str {
        match self {
            Method::Osc52 => "OSC 52",
            Method::WinClip => "clip.exe",
            Method::PbCopy => "pbcopy",
            Method::WlCopy => "wl-copy",
            Method::Xclip => "xclip",
            Method::Xsel => "xsel",
        }
    }
}

/// Целевая ОС для выбора утилит.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    Mac,
    Other,
}

impl Os {
    fn current() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::Mac
        } else {
            Os::Other
        }
    }
}

/// Снимок окружения, от которого зависит выбор способа.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Env {
    pub ssh: bool,
    pub tmux: bool,
    pub screen: bool,
    pub wayland: bool,
    pub x11: bool,
}

impl Env {
    /// Читает переменные окружения процесса.
    pub fn from_process() -> Env {
        let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
        Env {
            ssh: set("SSH_TTY") || set("SSH_CONNECTION") || set("SSH_CLIENT"),
            tmux: set("TMUX"),
            screen: set("STY"),
            wayland: set("WAYLAND_DISPLAY"),
            x11: set("DISPLAY"),
        }
    }
}

/// Порядок попыток для данного окружения.
pub fn plan(os: Os, env: &Env) -> Vec<Method> {
    let mut local = Vec::new();
    match os {
        Os::Windows => local.push(Method::WinClip),
        Os::Mac => local.push(Method::PbCopy),
        Os::Other => {
            if env.wayland {
                local.push(Method::WlCopy);
            }
            if env.x11 {
                local.extend([Method::Xclip, Method::Xsel]);
            }
        }
    }
    if env.ssh {
        // Через SSH системный буфер — это буфер удалённой машины: он почти
        // бесполезен, поэтому OSC 52 первым.
        let mut v = vec![Method::Osc52];
        v.extend(local);
        v
    } else {
        local.push(Method::Osc52);
        local
    }
}

/// Копирует текст: перебирает способы по [`plan`], возвращает сработавший.
pub fn copy(text: &str) -> Result<Method, String> {
    let env = Env::from_process();
    let mut errors = Vec::new();
    for m in plan(Os::current(), &env) {
        match try_method(m, text, &env) {
            Ok(()) => return Ok(m),
            Err(e) => errors.push(format!("{}: {e}", m.label())),
        }
    }
    Err(format!("не удалось скопировать ({})", errors.join("; ")))
}

/// Предел длины base64-полезной нагрузки OSC 52 (длиннее терминалы отбрасывают).
const OSC52_MAX_B64: usize = 100_000;

fn try_method(m: Method, text: &str, env: &Env) -> Result<(), String> {
    match m {
        Method::Osc52 => {
            // Без терминала последовательность никуда не дойдёт — пробуем следующий способ.
            if !std::io::stdout().is_terminal() {
                return Err("stdout не терминал".into());
            }
            // xterm и tmux молча отбрасывают слишком длинные OSC 52.
            if text.len().div_ceil(3) * 4 > OSC52_MAX_B64 {
                return Err("слишком длинный текст для OSC 52".into());
            }
            let seq = osc52_wrapped(text, env);
            let mut out = std::io::stdout().lock();
            out.write_all(seq.as_bytes())
                .and_then(|_| out.flush())
                .map_err(|e| e.to_string())
        }
        Method::WinClip => {
            // clip.exe понимает UTF-16LE с BOM независимо от кодовой страницы.
            let mut data = vec![0xFF, 0xFE];
            data.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
            pipe(&system32("clip.exe"), &[], &data)
        }
        Method::PbCopy => pipe("pbcopy", &[], text.as_bytes()),
        Method::WlCopy => pipe("wl-copy", &[], text.as_bytes()),
        Method::Xclip => pipe("xclip", &["-selection", "clipboard"], text.as_bytes()),
        Method::Xsel => pipe("xsel", &["--clipboard", "--input"], text.as_bytes()),
    }
}

/// Полный путь к системной утилите Windows.
///
/// `Command::new("clip.exe")` ищет по CWD и `PATH`, а TUI умеет работать
/// повышенным (embedded-режим): подложенный в рабочий каталог `clip.exe` дал бы
/// код от администратора (аудит 2026-11, FRNT-4). Так же поступает `winsvc`
/// с `powershell.exe`.
#[cfg(windows)]
fn system32(name: &str) -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    format!("{root}\\System32\\{name}")
}

#[cfg(not(windows))]
fn system32(name: &str) -> String {
    name.to_string()
}

/// Запускает утилиту, пишет данные в stdin и ждёт успешного завершения.
fn pipe(cmd: &str, args: &[&str], data: &[u8]) -> Result<(), String> {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let written = child
        .stdin
        .take()
        .ok_or_else(|| "нет stdin".to_string())
        .and_then(|mut s| s.write_all(data).map_err(|e| e.to_string()));
    let status = child.wait().map_err(|e| e.to_string())?;
    written?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("код выхода {status}"))
    }
}

/// OSC 52 «положить в буфер `c`», завершённая BEL.
pub fn osc52(text: &str) -> String {
    format!("\x1b]52;c;{}\x07", base64(text.as_bytes()))
}

/// OSC 52 с обёрткой для мультиплексора: tmux/screen иначе съедают
/// последовательность.
pub fn osc52_wrapped(text: &str, env: &Env) -> String {
    let seq = osc52(text);
    if env.tmux {
        wrap_tmux(&seq)
    } else if env.screen {
        wrap_screen(&seq)
    } else {
        seq
    }
}

/// tmux passthrough: `ESC P tmux; <seq с удвоенными ESC> ESC \`.
/// В tmux ≥ 3.3 нужно `set -g allow-passthrough on`.
pub fn wrap_tmux(seq: &str) -> String {
    format!("\x1bPtmux;{}\x1b\\", seq.replace('\x1b', "\x1b\x1b"))
}

/// GNU screen ограничивает строку DCS, поэтому режем на куски по 768 байт,
/// каждый в своей `ESC P … ESC \`.
pub fn wrap_screen(seq: &str) -> String {
    const CHUNK: usize = 768;
    let bytes = seq.as_bytes(); // OSC 52 — чистый ASCII, резать можно где угодно
    let mut out = String::with_capacity(bytes.len() + bytes.len() / CHUNK * 4 + 4);
    for chunk in bytes.chunks(CHUNK) {
        out.push_str("\x1bP");
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push_str("\x1b\\");
    }
    out
}

/// Стандартный base64 (RFC 4648) с паддингом.
pub fn base64(data: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(ABC[(n >> 18) as usize & 63] as char);
        out.push(ABC[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            ABC[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            ABC[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc_vectors() {
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (i, o) in cases {
            assert_eq!(base64(i.as_bytes()), o);
        }
        assert_eq!(base64("привет".as_bytes()), "0L/RgNC40LLQtdGC");
        assert_eq!(base64(&[0xFF, 0xFE, 0xFD]), "//79");
    }

    #[test]
    fn osc52_plain() {
        assert_eq!(osc52("hi"), "\x1b]52;c;aGk=\x07");
        assert_eq!(osc52_wrapped("hi", &Env::default()), osc52("hi"));
    }

    #[test]
    fn osc52_tmux() {
        let env = Env {
            tmux: true,
            screen: true,
            ..Env::default()
        };
        assert_eq!(
            osc52_wrapped("hi", &env),
            "\x1bPtmux;\x1b\x1b]52;c;aGk=\x07\x1b\\"
        );
    }

    #[test]
    fn osc52_screen_chunks() {
        let env = Env {
            screen: true,
            ..Env::default()
        };
        assert_eq!(osc52_wrapped("hi", &env), "\x1bP\x1b]52;c;aGk=\x07\x1b\\");
        let long = "x".repeat(1000);
        let seq = osc52(&long);
        let wrapped = wrap_screen(&seq);
        let parts: Vec<&str> = wrapped.split("\x1b\\").filter(|p| !p.is_empty()).collect();
        assert_eq!(parts.len(), seq.len().div_ceil(768));
        let joined: String = parts
            .iter()
            .map(|p| p.strip_prefix("\x1bP").unwrap())
            .collect();
        assert_eq!(joined, seq);
    }

    #[test]
    fn plan_local() {
        let e = Env::default();
        assert_eq!(plan(Os::Windows, &e), [Method::WinClip, Method::Osc52]);
        assert_eq!(plan(Os::Mac, &e), [Method::PbCopy, Method::Osc52]);
        assert_eq!(plan(Os::Other, &e), [Method::Osc52]);
        let e = Env {
            wayland: true,
            x11: true,
            ..Env::default()
        };
        assert_eq!(
            plan(Os::Other, &e),
            [Method::WlCopy, Method::Xclip, Method::Xsel, Method::Osc52]
        );
    }

    #[test]
    fn plan_ssh_osc_first() {
        let e = Env {
            ssh: true,
            x11: true,
            ..Env::default()
        };
        assert_eq!(
            plan(Os::Other, &e),
            [Method::Osc52, Method::Xclip, Method::Xsel]
        );
        let e = Env {
            ssh: true,
            ..Env::default()
        };
        assert_eq!(plan(Os::Windows, &e), [Method::Osc52, Method::WinClip]);
        assert_eq!(plan(Os::Mac, &e)[0], Method::Osc52);
    }
}
