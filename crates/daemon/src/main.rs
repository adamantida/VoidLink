use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tunnel_daemon::Level;
use tunnel_daemon::cli::{self, Mode};
use tunnel_daemon::engine_backend::{DaemonBackend, DaemonEngine, TunOpts, WintunDll, real_start};
use tunnel_daemon::service;

fn main() -> ExitCode {
    let mode = match cli::parse(std::env::args().skip(1)) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ошибка: {e}\n\n{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };
    let dir = |d: Option<std::path::PathBuf>| d.unwrap_or_else(tunnel_daemon::default_data_dir);
    let res = match mode {
        Mode::Help => {
            print!("{}", cli::USAGE);
            Ok(())
        }
        Mode::Console {
            debug,
            fake,
            seed_config,
            data_dir,
        } => {
            // Остановка — Ctrl+C / SIGTERM: флаг, хаб выходит штатно.
            let stop = Arc::new(AtomicBool::new(false));
            service::install_ctrl_handler(stop.clone());
            let dir = dir(data_dir);
            // Windows: движок с правами администратора доверяет каталогу
            // данных — он должен быть закрыт, как у службы (и до переноса
            // пользовательского конфига в него).
            if !fake && let Err(e) = service::secure_console_data_dir(&dir) {
                eprintln!("ошибка: {e}");
                return ExitCode::FAILURE;
            }
            if seed_config {
                match service::seed_user_config(&dir) {
                    Ok(Some(src)) => eprintln!(
                        "конфиг перенесён: {} → {}",
                        src.display(),
                        dir.join("client.json").display()
                    ),
                    Ok(None) => eprintln!(
                        "переносить нечего: у демона уже есть client.json или нет пользовательского"
                    ),
                    Err(e) => {
                        eprintln!("ошибка: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            if fake {
                service::run_console(&dir, debug, |_log| tunnel_daemon::FakeBackend::new(), stop)
            } else {
                // Настоящий движок по client.json каталога данных (нужны права
                // администратора на TUN). Нет серверов — «нет сервера» до
                // AddServer; ошибка запуска при заданном сервере — останов и
                // выход с ней (как раньше).
                tunnel_client::engine::set_debug(debug);
                let failed = Arc::new(std::sync::Mutex::new(None::<String>));
                let (f, s, d) = (failed.clone(), stop.clone(), dir.clone());
                let r = service::run_console(
                    &dir,
                    debug,
                    move |log| {
                        let fail = |e: String| {
                            *f.lock().unwrap_or_else(|p| p.into_inner()) = Some(e);
                            s.store(true, std::sync::atomic::Ordering::SeqCst);
                        };
                        // wintun.dll — только рядом с exe (dll из client.json
                        // не используется: конфиг правится по IPC).
                        let tun = TunOpts {
                            wintun: WintunDll::beside_current_exe(),
                        };
                        match DaemonEngine::open(&d, log.clone(), real_start(tun), None) {
                            Ok(e) => {
                                if !e.has_server() {
                                    log(Level::Warn, tunnel_daemon::NO_SERVERS_HINT);
                                } else if let Err(err) = e.start_now() {
                                    fail(err);
                                }
                                DaemonBackend::Ready(Box::new(e))
                            }
                            Err(e) => {
                                log(Level::Error, &e);
                                fail(e.clone());
                                DaemonBackend::Failed(e)
                            }
                        }
                    },
                    stop,
                );
                match failed.lock().unwrap_or_else(|p| p.into_inner()).take() {
                    Some(e) => Err(e),
                    None => r,
                }
            }
        }
        // Данные службы — %ProgramData%\tunnel (или --data-dir): движок по
        // client.json (wintun.dll — только рядом с exe, адаптер из конфига,
        // выход из сна — переподключение); без серверов — ждёт AddServer.
        Mode::Service { data_dir } => {
            service::run_service(data_dir.as_deref(), DaemonBackend::service)
        }
        Mode::Install => service::install(),
        Mode::Uninstall { purge } => service::uninstall(purge, || Ok(())),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ошибка: {e}");
            ExitCode::FAILURE
        }
    }
}
