//! Разбор командной строки `tunnel-daemon`.

use std::path::PathBuf;

pub const USAGE: &str = "\
tunnel-daemon — служба туннеля (владелец движка)

использование:
  tunnel-daemon console [--debug] [--fake] [--data-dir <каталог>]
                        [--seed-config]
      запуск в консоли (от администратора: движок поднимает TUN по
      <каталог>/client.json), лог и в консоль, и в файл;
      на Unix фронтенды подключаются к <каталог>/daemon.sock,
      на Windows — к пайпу \\\\.\\pipe\\tunnel-daemon (только от администратора);
      --fake — бэкенд в памяти без движка (разработка фронтендов; пайп на
      Windows поднимается только от администратора, как и у обычного console);
      --seed-config — перенести client.json из %APPDATA%\\tunnel (identity,
      серверы) в каталог данных демона, если конфига там ещё нет
  tunnel-daemon service [--data-dir <каталог>]
      точка входа службы (запускает SCM, руками не вызывать)
  tunnel-daemon install
      установить и запустить службу
  tunnel-daemon uninstall [--purge]
      удалить службу; --purge — ещё и данные (identity, конфиг, логи)
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Console {
        debug: bool,
        fake: bool,
        /// Перенести пользовательский `client.json` в каталог данных демона.
        seed_config: bool,
        data_dir: Option<PathBuf>,
    },
    Service {
        data_dir: Option<PathBuf>,
    },
    Install,
    Uninstall {
        purge: bool,
    },
    Help,
}

/// Аргументы без имени программы.
pub fn parse<I, S>(args: I) -> Result<Mode, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut it = args.into_iter().map(Into::into);
    let Some(cmd) = it.next() else {
        return Ok(Mode::Help);
    };
    let rest: Vec<String> = it.collect();
    let mut debug = false;
    let mut fake = false;
    let mut seed_config = false;
    let mut purge = false;
    let mut data_dir = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--debug" if cmd == "console" => debug = true,
            "--fake" if cmd == "console" => fake = true,
            "--seed-config" if cmd == "console" => seed_config = true,
            "--purge" if cmd == "uninstall" => purge = true,
            "--data-dir" if cmd == "console" || cmd == "service" => {
                i += 1;
                let v = rest.get(i).ok_or("--data-dir: нужен путь")?;
                data_dir = Some(PathBuf::from(v));
            }
            a => return Err(format!("{cmd}: неизвестный аргумент «{a}»")),
        }
        i += 1;
    }
    Ok(match cmd.as_str() {
        "console" => Mode::Console {
            debug,
            fake,
            seed_config,
            data_dir,
        },
        "service" => Mode::Service { data_dir },
        "install" => Mode::Install,
        "uninstall" => Mode::Uninstall { purge },
        "help" | "-h" | "--help" => Mode::Help,
        c => return Err(format!("неизвестная команда «{c}»")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes() {
        assert_eq!(parse(Vec::<String>::new()), Ok(Mode::Help));
        assert_eq!(
            parse(["console"]),
            Ok(Mode::Console {
                debug: false,
                fake: false,
                seed_config: false,
                data_dir: None
            })
        );
        assert_eq!(
            parse(["console", "--debug", "--data-dir", "/x"]),
            Ok(Mode::Console {
                debug: true,
                fake: false,
                seed_config: false,
                data_dir: Some("/x".into())
            })
        );
        assert_eq!(
            parse(["console", "--fake"]),
            Ok(Mode::Console {
                debug: false,
                fake: true,
                seed_config: false,
                data_dir: None
            })
        );
        assert_eq!(
            parse(["console", "--seed-config"]),
            Ok(Mode::Console {
                debug: false,
                fake: false,
                seed_config: true,
                data_dir: None
            })
        );
        assert!(parse(["service", "--fake"]).is_err());
        assert!(parse(["service", "--seed-config"]).is_err());
        assert_eq!(parse(["service"]), Ok(Mode::Service { data_dir: None }));
        assert_eq!(parse(["install"]), Ok(Mode::Install));
        assert_eq!(parse(["uninstall"]), Ok(Mode::Uninstall { purge: false }));
        assert_eq!(
            parse(["uninstall", "--purge"]),
            Ok(Mode::Uninstall { purge: true })
        );
        assert!(parse(["install", "--purge"]).is_err());
        assert!(parse(["console", "--data-dir"]).is_err());
        assert!(parse(["frobnicate"]).is_err());
    }
}
