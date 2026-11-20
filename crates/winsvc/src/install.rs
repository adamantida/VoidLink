//! Установка и удаление службы (запуск от администратора).

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, ProgressInvokeNever, SDDL_REVISION_1, SE_FILE_OBJECT,
    TREE_SEC_INFO_RESET, TreeSetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    GetTokenInformation, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_USERS, REG_SZ, RegDeleteKeyValueW, RegSetKeyValueW,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};

use crate::common::*;

const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_SERVICE_EXISTS: i32 = 1073;

fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

fn win_err(code: i32) -> impl Fn(&windows_service::Error) -> bool {
    move |e| matches!(e, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(code))
}

/// Устанавливает (или обновляет) службу и всё окружение. Порядок: проверка
/// каталога установки ([`crate::acl::verify_install_dir`]) → каталог
/// данных (владелец и ACL) → импорт конфига → SID владельца → служба → Run →
/// ярлык → старт. Ошибки Run-ключа, ярлыка и старта некритичны: служба уже
/// установлена, они попадают в [`InstallReport::warnings`].
pub fn install(opts: &InstallOptions) -> Result<InstallReport> {
    if !opts.daemon_exe.is_absolute() {
        bail!(
            "путь службы должен быть абсолютным: {}",
            opts.daemon_exe.display()
        );
    }
    // Служба (SYSTEM) грузит exe и wintun.dll из этого каталога: писать туда
    // может только администратор, иначе отказ.
    crate::acl::verify_install_dir(&opts.daemon_exe)?;
    let dir = data_dir();
    prepare_data_dir(&dir)?;

    // только после смены владельца/ACL: подложенный заранее файл к этому
    // моменту удалён вместе с чужим каталогом
    let config_imported = import_user_config(&dir, opts.user_appdata.as_deref())?.is_some();
    let owner_sid = match &opts.owner_sid {
        Some(sid) => {
            validate_sid(sid)?;
            sid.clone()
        }
        None => interactive_user_sid()?,
    };
    write_secure(&owner_sid_path(&dir), format!("{owner_sid}\n").as_bytes())?;

    let service_updated = install_service(opts)?;

    let mut warnings = Vec::new();
    if let Some(tray) = &opts.tray_exe
        && let Err(e) = set_run_value(Some(&owner_sid), &run_value(tray))
    {
        warnings.push(format!("Run-ключ трея: {e:#}"));
    }
    if let Some(sc) = &opts.shortcut
        && let Err(e) = create_shortcut(sc)
    {
        warnings.push(format!("ярлык {}: {e:#}", sc.lnk.display()));
    }
    if opts.start
        && let Err(e) = start_service(&opts.service_name)
    {
        warnings.push(format!("запуск службы: {e:#}"));
    }
    Ok(InstallReport {
        data_dir: dir,
        config_imported,
        owner_sid,
        service_updated,
        warnings,
    })
}

/// Каталог данных, которому можно доверять. Существующий каталог
/// пересоздаётся, если это ссылка, его владелец не SYSTEM/Administrators
/// или в нём нет `owner.sid` прошлой установки (его мог заранее создать
/// обычный пользователь — `%ProgramData%` это разрешает — и подложить
/// туда `client.json`). Затем владелец BA и защищённый DACL ставятся на
/// каталог и сбрасываются на всех детей.
fn prepare_data_dir(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            let trusted = !meta.file_type().is_symlink()
                && meta.is_dir()
                && owner_sid_path(dir).is_file()
                && is_trusted_owner(dir)?;
            if !trusted {
                let rm = if meta.file_type().is_symlink() || !meta.is_dir() {
                    // ссылку/файл удаляем сами по себе, не заходя внутрь
                    std::fs::remove_dir(dir).or_else(|_| std::fs::remove_file(dir))
                } else {
                    std::fs::remove_dir_all(dir)
                };
                rm.with_context(|| format!("удаление чужого {}", dir.display()))?;
                create_fresh_dir(dir)?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_fresh_dir(dir)?,
        Err(e) => return Err(e).with_context(|| format!("{}", dir.display())),
    }
    set_dir_acl(dir, DATA_DIR_SDDL).with_context(|| format!("ACL на {}", dir.display()))?;
    if !is_trusted_owner(dir)? {
        bail!("не удалось сменить владельца {}", dir.display());
    }
    Ok(())
}

/// `create_dir` (не `_all`): если каталог успели создать между удалением и
/// созданием — это ошибка, а не молчаливое использование чужого каталога.
pub(crate) fn create_fresh_dir(dir: &Path) -> Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("создание {}", parent.display()))?;
    }
    std::fs::create_dir(dir).with_context(|| format!("создание {}", dir.display()))
}

/// Удаляет службу: стоп → `remove_adapter` (Wintun-адаптер) → удаление из
/// SCM → Run-ключ → ярлык → (с `purge`) `%ProgramData%\tunnel`. Шаги не
/// прерываются ошибкой предыдущих; все ошибки — одной в конце.
pub fn uninstall<F>(opts: &UninstallOptions, remove_adapter: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let mut errors = Vec::new();
    match stop_and_delete(&opts.service_name, remove_adapter) {
        Ok(errs) => errors.extend(errs),
        Err(e) => errors.push(format!("служба: {e:#}")),
    }
    // SID из owner.sid — до purge; без него — HKCU установщика
    let owner = read_owner_sid(&data_dir()).ok();
    if opts.remove_run_key
        && let Err(e) = delete_run_value(owner.as_deref())
    {
        errors.push(format!("Run-ключ: {e:#}"));
    }
    if let Some(lnk) = &opts.shortcut_lnk {
        match std::fs::remove_file(lnk) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => errors.push(format!("ярлык {}: {e}", lnk.display())),
        }
    }
    if opts.purge {
        let dir = data_dir();
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => errors.push(format!("{}: {e}", dir.display())),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(errors.join("; ")))
    }
}

fn install_service(opts: &InstallOptions) -> Result<bool> {
    let mgr = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("OpenSCManager (нужны права администратора)")?;
    let info = ServiceInfo {
        name: OsString::from(&opts.service_name),
        display_name: OsString::from(&opts.display_name),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: opts.daemon_exe.clone(),
        launch_arguments: opts.service_args.iter().map(OsString::from).collect(),
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_STATUS | ServiceAccess::START;
    let (svc, updated) = match mgr.create_service(&info, access) {
        Ok(s) => (s, false),
        Err(e) if win_err(ERROR_SERVICE_EXISTS)(&e) => {
            let s = mgr
                .open_service(&opts.service_name, access)
                .context("OpenService")?;
            s.change_config(&info).context("ChangeServiceConfig")?;
            (s, true)
        }
        Err(e) => return Err(e).context("CreateService"),
    };
    svc.set_description(&opts.description)
        .context("описание службы")?;
    let actions = RECOVERY_DELAYS
        .iter()
        .map(|&delay| ServiceAction {
            action_type: ServiceActionType::Restart,
            delay,
        })
        .collect();
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(RECOVERY_RESET),
        reboot_msg: None,
        command: None,
        actions: Some(actions),
    })
    .context("политика восстановления")?;
    // рестарт и при выходе с ненулевым кодом, а не только при падении процесса
    svc.set_failure_actions_on_non_crash_failures(true)
        .context("восстановление при ошибке выхода")?;
    Ok(updated)
}

fn start_service(name: &str) -> Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("OpenSCManager")?;
    let svc = mgr
        .open_service(name, ServiceAccess::START | ServiceAccess::QUERY_STATUS)
        .context("OpenService")?;
    if svc.query_status()?.current_state == ServiceState::Stopped {
        svc.start::<&OsStr>(&[]).context("StartService")?;
    }
    Ok(())
}

/// Стоп и удаление службы; ошибки адаптера — во втором векторе.
fn stop_and_delete<F>(name: &str, remove_adapter: F) -> Result<Vec<String>>
where
    F: FnOnce() -> Result<()>,
{
    let mut errs = Vec::new();
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("OpenSCManager (нужны права администратора)")?;
    let svc = match mgr.open_service(
        name,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(s) => Some(s),
        Err(e) if win_err(ERROR_SERVICE_DOES_NOT_EXIST)(&e) => None,
        Err(e) => return Err(e).context("OpenService"),
    };
    // ошибки опроса статуса не прерывают шаг: адаптер и DeleteService ниже
    let stopped = |svc: &windows_service::service::Service| -> std::result::Result<bool, String> {
        svc.query_status()
            .map(|st| st.current_state == ServiceState::Stopped)
            .map_err(|e| format!("QueryServiceStatus: {e}"))
    };
    if let Some(svc) = &svc {
        match stopped(svc) {
            Ok(true) => {}
            first => {
                if let Err(e) = first {
                    errs.push(e);
                }
                let _ = svc.stop();
                let deadline = Instant::now() + Duration::from_secs(20);
                loop {
                    match stopped(svc) {
                        Ok(true) => break,
                        Ok(false) => {}
                        Err(e) => {
                            // временная ошибка — пробуем дальше до дедлайна
                            if Instant::now() > deadline {
                                errs.push(e);
                                break;
                            }
                        }
                    }
                    if Instant::now() > deadline {
                        errs.push("служба не остановилась за 20 с".to_string());
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        }
    }
    // адаптер — после остановки службы (она держит его открытым)
    if let Err(e) = remove_adapter() {
        errs.push(format!("адаптер: {e:#}"));
    }
    if let Some(svc) = svc
        && let Err(e) = svc.delete()
    {
        errs.push(format!("DeleteService: {e}"));
    }
    Ok(errs)
}

/// Импорт `%APPDATA%\tunnel\client.json` пользователя (из
/// [`InstallOptions::user_appdata`] или окружения), если у службы конфига
/// ещё нет. Возвращает путь источника, если импорт был.
///
/// Используется и `install`, и `tunnel-daemon console --seed-config`: перенос
/// identity/серверов в каталог данных демона — единственный способ сохранить
/// свой friend code при переходе на демон.
pub fn import_user_config(dir: &Path, appdata: Option<&Path>) -> Result<Option<PathBuf>> {
    let dst = service_config_path(dir);
    if dst.exists() {
        return Ok(None);
    }
    let appdata = match appdata {
        Some(a) => a.to_path_buf(),
        None => match std::env::var_os("APPDATA") {
            Some(a) => PathBuf::from(a),
            None => return Ok(None),
        },
    };
    let src = user_config_path(&appdata);
    let data = match std::fs::read(&src) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("чтение {}", src.display())),
    };
    write_secure(&dst, &data)?;
    Ok(Some(src))
}

/// Запись файла в каталог данных: создаётся заново (не копируется), чтобы
/// он унаследовал ACL каталога, а не исходника из профиля.
fn write_secure(path: &PathBuf, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data).with_context(|| format!("запись {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("запись {}", path.display()))
}

/// Ставит владельца и защищённый DACL из SDDL на каталог и сбрасывает их
/// на всех детей (`TREE_SEC_INFO_RESET`: явные ACE детей заменяются
/// унаследованными).
pub(crate) fn set_dir_acl(dir: &Path, sddl: &str) -> Result<()> {
    let sddl_w = wide(sddl);
    let path_w = wide(dir);
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: указатели валидны на время вызовов; sd освобождается LocalFree.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(std::io::Error::last_os_error()).context("разбор SDDL");
        }
        let res = (|| {
            let mut present = 0;
            let mut defaulted = 0;
            let mut dacl: *mut ACL = std::ptr::null_mut();
            if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0
                || present == 0
            {
                bail!("в SDDL нет DACL");
            }
            let mut owner: PSID = std::ptr::null_mut();
            if GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted) == 0 || owner.is_null() {
                bail!("в SDDL нет владельца");
            }
            let rc = TreeSetNamedSecurityInfoW(
                path_w.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                owner,
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
                TREE_SEC_INFO_RESET,
                None,
                ProgressInvokeNever,
                std::ptr::null(),
            );
            if rc != ERROR_SUCCESS {
                return Err(std::io::Error::from_raw_os_error(rc as i32))
                    .context("TreeSetNamedSecurityInfo");
            }
            Ok(())
        })();
        LocalFree(sd as HLOCAL);
        res
    }
}

/// Владелец каталога — SYSTEM или Administrators.
fn is_trusted_owner(dir: &Path) -> Result<bool> {
    let path_w = wide(dir);
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: owner указывает внутрь sd, sd освобождается LocalFree.
    unsafe {
        let rc = GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        );
        if rc != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(rc as i32))
                .with_context(|| format!("владелец {}", dir.display()));
        }
        let res = sid_to_string(owner);
        LocalFree(sd as HLOCAL);
        Ok(TRUSTED_OWNER_SIDS.contains(&res?.as_str()))
    }
}

/// SID → строка `S-1-…`.
///
/// # Safety
/// `sid` — валидный SID.
pub(crate) unsafe fn sid_to_string(sid: PSID) -> Result<String> {
    let mut s: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: по контракту функции; s освобождается LocalFree.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut s) == 0 {
            return Err(std::io::Error::last_os_error()).context("ConvertSidToStringSid");
        }
        let n = (0..).take_while(|&i| *s.add(i) != 0).count();
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
        LocalFree(s as HLOCAL);
        Ok(out)
    }
}

/// SID пользователя рабочего стола: владелец процесса оболочки
/// (`GetShellWindow` → explorer.exe). Токен самого установщика не годится:
/// при over-the-shoulder UAC (обычный пользователь вводит пароль админа)
/// это SID админа. Без оболочки — SID токена установщика.
fn interactive_user_sid() -> Result<String> {
    // SAFETY: хэндлы процесса закрываются; HWND только читается.
    unsafe {
        let hwnd = GetShellWindow();
        if !hwnd.is_null() {
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, &mut pid);
            if pid != 0 {
                let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                if !proc.is_null() {
                    let sid = token_user_sid(proc);
                    CloseHandle(proc);
                    if let Ok(sid) = sid {
                        return Ok(sid);
                    }
                }
            }
        }
        token_user_sid(GetCurrentProcess())
    }
}

/// Строковый SID пользователя токена процесса.
///
/// # Safety
/// `process` — валидный хэндл процесса с правом запроса информации.
unsafe fn token_user_sid(process: HANDLE) -> Result<String> {
    // SAFETY: буфер достаточного размера, хэндл токена закрывается.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
            return Err(std::io::Error::last_os_error()).context("OpenProcessToken");
        }
        let mut len = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        // u64 — выравнивание под TOKEN_USER
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
        let err = std::io::Error::last_os_error();
        CloseHandle(token);
        if ok == 0 {
            return Err(err).context("GetTokenInformation(TokenUser)");
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid = sid_to_string(user.User.Sid)?;
        validate_sid(&sid)?;
        Ok(sid)
    }
}

/// Куст реестра пользователя: `HKEY_USERS\<sid>` (при установке с чужими
/// учётными данными HKCU — куст админа), без SID — HKCU.
fn user_run_key(sid: Option<&str>) -> (HKEY, Vec<u16>) {
    match sid {
        Some(sid) => (HKEY_USERS, wide(format!("{sid}\\{RUN_KEY}"))),
        None => (HKEY_CURRENT_USER, wide(RUN_KEY)),
    }
}

fn set_run_value(sid: Option<&str>, value: &str) -> Result<()> {
    let (root, key) = user_run_key(sid);
    let name = wide(RUN_VALUE);
    let data = wide(value);
    // SAFETY: буферы с нулём на конце живут до конца вызова.
    let rc = unsafe {
        RegSetKeyValueW(
            root,
            key.as_ptr(),
            name.as_ptr(),
            REG_SZ,
            data.as_ptr().cast(),
            (data.len() * 2) as u32,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(rc as i32)).context("RegSetKeyValue");
    }
    Ok(())
}

fn delete_run_value(sid: Option<&str>) -> Result<()> {
    let (root, key) = user_run_key(sid);
    let name = wide(RUN_VALUE);
    // SAFETY: буферы с нулём на конце живут до конца вызова.
    let rc = unsafe { RegDeleteKeyValueW(root, key.as_ptr(), name.as_ptr()) };
    if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
        return Err(std::io::Error::from_raw_os_error(rc as i32)).context("RegDeleteKeyValue");
    }
    Ok(())
}

fn create_shortcut(spec: &ShortcutSpec) -> Result<()> {
    let out = Command::new(powershell_exe()?)
        .args(powershell_args(&shortcut_script(spec)))
        .output()
        .context("запуск powershell.exe")?;
    if !out.status.success() {
        bail!(
            "powershell: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Абсолютный путь к `powershell.exe` из системного каталога: поиск по
/// PATH из повышенного процесса мог бы найти подложенный exe.
fn powershell_exe() -> Result<PathBuf> {
    let mut buf = [0u16; 512];
    // SAFETY: буфер и его длина корректны.
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return Err(std::io::Error::last_os_error()).context("GetSystemDirectory");
    }
    let sys = PathBuf::from(OsString::from_wide(&buf[..n]));
    Ok(sys.join(r"WindowsPowerShell\v1.0\powershell.exe"))
}
