//! Пайп-транспорт на Windows в режиме `console` (владелец объекта — `O:BA`)
//! и проверка доверия клиента (SECURITY.md §13).
//!
//! Требуется повышенный процесс: `O:BA` без администратора поставить нельзя
//! (в UAC-фильтрованном токене группа Administrators — deny-only, и
//! `CreateNamedPipeW` отказывает по владельцу). Без повышения тесты
//! пропускаются с сообщением, а не падают.
#![cfg(windows)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

use serde_json::json;
use tunnel_ipc::transport::{current_user_sid, is_elevated};
use tunnel_ipc::{
    AckResult, ClientKind, ClientMsg, DaemonMsg, Listener, PROTO_VERSION, check_hello, connect,
    read_msg, write_msg,
};

/// Уникальное имя пайпа: тесты идут параллельно в одном процессе.
fn pipe_name() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\vl-ipc-test-{}-{n}", std::process::id())
}

/// SID текущего пользователя, если процесс повышен; иначе — пропуск теста.
fn elevated_sid(test: &str) -> Option<String> {
    if is_elevated().unwrap_or(false) {
        return Some(current_user_sid().expect("SID текущего пользователя"));
    }
    eprintln!("пропуск {test}: нужен запуск от администратора (владелец пайпа O:BA)");
    None
}

#[test]
fn console_pipe_hello_req_ack_roundtrip() {
    let Some(sid) = elevated_sid("console_pipe_hello_req_ack_roundtrip") else {
        return;
    };
    let name = pipe_name();
    let l = Listener::bind_console(&name, &sid).unwrap();

    let srv = thread::spawn(move || {
        let mut c = l.accept().unwrap();
        let mut w = c.try_clone().unwrap();
        let ClientMsg::Hello { proto, kind, .. } = read_msg(&mut c).unwrap() else {
            panic!("ждали Hello");
        };
        assert_eq!(kind, ClientKind::Tui);
        check_hello(proto).unwrap();
        write_msg(
            &mut w,
            &DaemonMsg::Welcome {
                proto: PROTO_VERSION,
                daemon_ver: "test".into(),
                me: json!({"my_code": "ABC"}),
            },
        )
        .unwrap();
        let ClientMsg::Req { id, cmd } = read_msg(&mut c).unwrap() else {
            panic!("ждали Req");
        };
        assert_eq!(cmd["ping"], json!(1));
        write_msg(
            &mut w,
            &DaemonMsg::Ack {
                id,
                result: AckResult::Ok,
            },
        )
        .unwrap();
    });

    // Клиент проверяет доверие: сервер — повышенный процесс этого же
    // пользователя (владелец объекта BA).
    let mut c = connect(&name).unwrap();
    write_msg(&mut c, &ClientMsg::hello(ClientKind::Tui, "test")).unwrap();
    let DaemonMsg::Welcome { me, .. } = read_msg(&mut c).unwrap() else {
        panic!("ждали Welcome");
    };
    assert_eq!(me["my_code"], json!("ABC"));
    write_msg(
        &mut c,
        &ClientMsg::Req {
            id: 7,
            cmd: json!({"ping": 1}),
        },
    )
    .unwrap();
    let DaemonMsg::Ack { id, result } = read_msg(&mut c).unwrap() else {
        panic!("ждали Ack");
    };
    assert_eq!(id, 7);
    assert_eq!(result, AckResult::Ok);
    srv.join().unwrap();
}

#[test]
fn занятое_имя_пайпа_не_переиспользуется() {
    let Some(sid) = elevated_sid("занятое_имя_пайпа_не_переиспользуется")
    else {
        return;
    };
    let name = pipe_name();
    let _l = Listener::bind_console(&name, &sid).unwrap();
    // FILE_FLAG_FIRST_PIPE_INSTANCE: второй сервер с тем же именем падает, а
    // не присоединяется к чужому пайпу (защита от захвата имени).
    assert!(Listener::bind_console(&name, &sid).is_err());
}

#[test]
fn нет_пайпа_это_not_found() {
    let err = match connect(pipe_name()) {
        Ok(_) => panic!("подключились к несуществующему пайпу"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
}
