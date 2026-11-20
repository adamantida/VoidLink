//! Служба Windows для `tunnel-daemon` (этап 7.3/7.6 PLAN.md):
//!
//! - [`run_as_service`] — вход из SCM: Stop/Shutdown и выход из сна
//!   (POWEREVENT resume) приходят телу службы через канал [`ServiceEvent`];
//! - [`install`] — служба `TunnelDaemon` (LocalSystem, автозапуск, рестарт
//!   5/10/30 с), `%ProgramData%\tunnel` с ACL, импорт `client.json`
//!   пользователя, `owner.sid` для SDDL пайпа, `Run`-ключ трея, ярлык с AUMID;
//! - [`uninstall`] — обратное (конфиг — только с `purge`);
//! - [`service_wintun_dll`] — `wintun.dll` только рядом с exe и только из
//!   каталога, куда пишет лишь администратор (`verify_install_dir`; та же
//!   проверка — при `install`).
//!
//! Настоящий код — под `cfg(windows)`; на остальных ОС функции службы
//! возвращают ошибку, а чистая часть (пути, SDDL, скрипты) работает везде.

mod common;
pub use common::*;

#[cfg(windows)]
mod acl;
#[cfg(windows)]
mod install;
#[cfg(windows)]
mod service;
#[cfg(windows)]
pub use acl::{check_path, secure_data_dir, verify_install_dir};
#[cfg(windows)]
pub use install::{import_user_config, install, uninstall};
#[cfg(windows)]
pub use service::run_as_service;

#[cfg(not(windows))]
mod stub {
    use std::sync::mpsc::Receiver;

    use anyhow::{Result, bail};

    use crate::{InstallOptions, InstallReport, ServiceEvent, UninstallOptions};

    const NO_SCM: &str =
        "служба Windows недоступна на этой ОС (используйте `tunnel-daemon console`)";

    /// Заглушка: SCM есть только в Windows.
    pub fn run_as_service<F>(_name: &str, _body: F) -> Result<()>
    where
        F: FnOnce(Receiver<ServiceEvent>) -> Result<()> + Send + 'static,
    {
        bail!(NO_SCM)
    }

    /// Заглушка: установка службы есть только в Windows.
    pub fn install(_opts: &InstallOptions) -> Result<InstallReport> {
        bail!(NO_SCM)
    }

    /// Заглушка: удаление службы есть только в Windows.
    pub fn uninstall<F>(_opts: &UninstallOptions, _remove_adapter: F) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        bail!(NO_SCM)
    }
}
#[cfg(not(windows))]
pub use stub::{install, run_as_service, uninstall};

#[cfg(all(test, not(windows)))]
mod stub_tests {
    use super::*;

    #[test]
    fn stubs_fail() {
        assert!(run_as_service(SERVICE_NAME, |_| Ok(())).is_err());
        let o = InstallOptions::for_layout(std::path::Path::new("/pf"), None);
        assert!(install(&o).is_err());
        assert!(uninstall(&UninstallOptions::standard(false, None), || Ok(())).is_err());
    }
}
