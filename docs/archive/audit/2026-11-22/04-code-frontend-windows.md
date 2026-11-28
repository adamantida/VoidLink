# Аудит фронтендов и Windows-части VoidLink (TUI, демон, IPC, служба, трей, CLI)

**Базис:** коммит `c0689fc` (ветка dev, = origin/master), дерево `C:\Users\SumalyFly\RustroverProjects\VoidLink`.
**Дата:** 2026-11-22. **Аудитор:** независимый (поток W4), задача `task-4`.
**Префикс находок:** FRNT.

## 1. Область, метод, что НЕ проверялось

**Область (7 частей по заданию).**

1. `crates/ipc` — фрейминг (`codec`), сообщения (`proto`), транспорт Unix/Windows (`transport/unix.rs`, `transport/windows.rs`, named pipe), клиент (`client.rs`), замок single-instance (`lock.rs`).
2. `crates/daemon` — `hub.rs` (seq/кольцо/снимки/backpressure), `server.rs` (приём, `Hello`, подписка, `Shutdown`), `engine_backend.rs` (валидация команд), `service.rs` (режимы, SCM, пайп), `log.rs`, `cli.rs`, `main.rs`.
3. `crates/client/src/tui` — `app.rs`, `ui.rs`, `admin.rs`, `servers.rs`, `setup.rs`, `badges.rs`, `clipboard.rs`, `mod.rs` (жизненный цикл терминала).
4. `crates/winsvc` — `common.rs` (пути/SDDL/проверка DACL), `install.rs` (установка/удаление), `acl.rs`, `service.rs`.
5. `crates/tray` — `model.rs`, `remote.rs`, `win.rs`.
6. CLI — `crates/client/src/main.rs`, `crates/client/src/remote_cli.rs`, `crates/daemon/src/cli.rs`; клиентский шов `crates/client/src/{api,remote,profile,offline}.rs` в части, которую использует IPC/демон.
7. `infrastructure/windows/install.ps1`, `uninstall.ps1`.
8. Сквозные проверки соответствия `docs/IPC.md`, `docs/DAEMON.md` (разделы «Пайп и доступ», «Windows-служба», «Уведомления», «Single-instance»), `docs/SECURITY.md` §12–§15.

**Метод.** Чтение исходников инструментами read/grep/glob; CodeGraph для навигации по символам (`projectPath` задан явно). Каждая ссылка `файл:строка` открыта и проверена в этом дереве; для S1/S2 приведена дословная цитата. Сверка «обещание в документе ↔ код» — построчно по разделам IPC.md/DAEMON.md. Сборки/тесты/clippy **не запускались** (по условиям задания: гейты гоняет ведущий).

**Что НЕ проверялось (осознанно вне области).**
- Криптография, рукопожатие, кадры протокола, mesh/DHT/федерация — другие потоки.
- Движок (`client/src/engine*.rs`, `mesh*.rs`, `path.rs`, `probe.rs`, `dns.rs`, `tun*.rs`) — только в объёме, необходимом для оценки валидации команд демоном (`check_cfg_cmd`) и снимков.
- `crates/server` — не мой поток.
- Динамический анализ: служба не устанавливалась, пайп под SYSTEM не поднимался, TUI/трей не запускались. Все выводы — статические. Специфика Windows-API (порядок поиска `ShellExecute`/`CreateProcess`) отмечена как precondition, а не как доказанный факт.
- Полный построчный разбор `tui/app.rs` (6 147 строк) и `tui/ui.rs` (3 647) не делался: применены grep по опасным конструкциям (`unwrap`/`expect`/`panic`/`[`-`индексация/`lock()`) и выборочное чтение 6 фрагментов. Это ограничение охвата, а не утверждение «там чисто».

## 2. Покрытие

| Модуль/файл | Строк | Что проверено | Глубина |
|---|---|---|---|
| `ipc/src/codec.rs` | 182 | лимит кадра до выделения памяти, частичные чтения, `BadLength`/`TooLarge`/`Truncated`, отсутствие паник | полностью |
| `ipc/src/proto.rs` | 147 | версия IPC, формы сообщений, `check_hello` | полностью |
| `ipc/src/client.rs` | 272 | handshake с таймаутом, поток чтения + очередь, `request`/pending, `Drop` | полностью |
| `ipc/src/transport/windows.rs` | 785 | SDDL пайпа, `PIPE_CLIENT_ACCESS`, `FIRST_PIPE_INSTANCE`, `REJECT_REMOTE_CLIENTS`, overlapped I/O, `decide_trust`, `shutdown` | полностью |
| `ipc/src/transport/unix.rs` | 171 | 0600/0700, `check_private_dir`, `cleanup_stale`, удаление своего сокета по dev/ino | полностью |
| `ipc/src/lock.rs` | 582 | `flock` + `O_NOFOLLOW` + nlink, права каталога, мьютекс `Global\TunnelEngine`, проверка владельца | полностью |
| `daemon/src/hub.rs` | 515 | seq, кольцо 500, `try_send`-backpressure, «пропуск → снимок», кэш снимка | полностью |
| `daemon/src/server.rs` | 566 | приём, `Hello`-таймаут (Unix), подписка, форвардер, `Shutdown`, жизненный цикл соединения | полностью |
| `daemon/src/service.rs` | 778 | режимы, `IpcMode`, пайп службы/console, `service_body`, установка/удаление | полностью (тесты — выборочно) |
| `daemon/src/engine_backend.rs` | 839 | `Backend::send` (разбор `Cmd`, запрет `Quit`), снимок/события, `DaemonBackend::Failed` | частично (1–120, 490–662) |
| `daemon/src/{log,cli,main,lock,fake}.rs` | 900 | ротация лога, разбор аргументов, коды возврата, отсутствие секретов в логе | полностью (`fake.rs` — просмотр) |
| `winsvc/src/common.rs` | 808 | пути, `DATA_DIR_SDDL`, `check_admin_only`, `WRITE_MASK`/`REPLACE_MASK`, `wintun_dll_beside`, `ps_quote` | полностью |
| `winsvc/src/install.rs` | 579 | порядок install, `prepare_data_dir`, `write_secure`, `TreeSetNamedSecurityInfo`, failure actions, uninstall/purge | полностью |
| `winsvc/src/acl.rs` | 140 | разбор ACE, `verify_install_dir` (exe+dll+предки), `secure_data_dir` | полностью |
| `winsvc/src/service.rs` | 136 | SCM, StopPending, коды выхода, POWEREVENT resume | полностью |
| `tray/src/win.rs` | 306 | цикл сообщений, меню, toast, `copy` (arboard), `open_tui`, `stop_service` | полностью |
| `tray/src/remote.rs` | 1087 | транспорт, `base_seq`, `on_down`, `session`/`run_loop`, `Notifier` | частично (60–180, 330–563; тесты — выборочно) |
| `tray/src/model.rs` | 928 | меню по состоянию, tooltip 127 UTF-16, `Notifier::observe`, иконки | частично (176–350, 405–535) |
| `client/src/tui/mod.rs` | 197 | raw/alt-screen/mouse, panic hook, порядок restore | полностью |
| `client/src/tui/clipboard.rs` | 345 | OSC 52, tmux/screen, системные утилиты, запуск процессов | полностью |
| `client/src/tui/badges.rs` | 439 | `ConnState`/`Pending`/`Invites`, приоритеты, hit-зоны | частично (1–175) |
| `client/src/tui/setup.rs` | 686 | `validate`→`apply` (два `expect`), восстановление консоли, `own_adapter` | частично (150–220, 240–360) |
| `client/src/tui/app.rs` | 6147 | `sync`/`sync_snapshot`, приглашения, `parse_command`, индикаторы; grep по `unwrap/expect/panic` | точечно (626–825, 1200–1430, 3940–4000 + grep) |
| `client/src/tui/ui.rs` | 3647 | блокировки в рендере (0), вывод `my_code`/`my_pub`, индексация | grep + фрагменты |
| `client/src/{api,remote,remote_cli,profile}.rs` | 2253 | `LocalEngine::send`/`check_cfg_cmd`, `IpcEngine` (seq, reconnect), `route`/`is_readonly`, 0600 при экспорте | полностью/частично (remote 1–590) |
| `client/src/main.rs` | 1667 | разбор флагов, `Route`, коды возврата, что печатается (ключи/коды), `--passphrase` | частично (1200–1345 + grep по всему файлу) |
| `infrastructure/windows/*.ps1` | 228 | ACL через icacls, порядок copy→ACL, UAC-перезапуск, purge | полностью |
| `docs/IPC.md`, `docs/DAEMON.md`, `docs/SECURITY.md` §12–15 | 1713 | сверка обещаний: seq/снимки/таймауты, пайп, служба, уведомления, остаточные риски | целевые разделы |

**Итого в области:** ≈31 700 строк (крейты ipc/daemon/winsvc/tray ≈9 900, TUI+клиент ≈19 800, инфраструктура 228, документы 1 713). Прочитано в глубину ≈17 000 строк.

## 3. Находки

### S2

#### FRNT-1 · TUI (тонкий клиент) · S2 · уверенность высокая

**Evidence.** `crates/client/src/remote.rs:358-370`:

```rust
                if let Ok(Some(mut c)) = ep.connect(ClientKind::Tui, HANDSHAKE_TIMEOUT) {
                    if Me::from_json(c.me()).as_ref() != Some(&me) {
                        sh.push(Event::Error(
                            "демон работает с другой identity — перезапустите TUI".into(),
                        ));
                    }
                    if let Ok((snap, _seen, editable)) = subscribe(&mut c, HANDSHAKE_TIMEOUT) {
                        *lock(&sh.snap) = Arc::new(snap);
                        sh.editable.store(editable, Ordering::SeqCst);
                        sh.down.store(false, Ordering::SeqCst);
                        sh.push(Event::Notice("связь с демоном восстановлена".into()));
                        conn = Some(c);
                    }
                }
```

Identity фронтенда фиксируется один раз в `App::new` и больше не обновляется — `crates/client/src/tui/app.rs:585` (`my_code: my_code.to_string(),`), `crates/client/src/tui/app.rs:499` (`pub my_code: String,`), `crates/client/src/tui/app.rs:584-585`; в шапке рисуется `crates/client/src/tui/ui.rs:1984` (`lines.push(Line::from(Span::styled(app.my_code.clone(), th.accent)));`). `sync_snapshot` (`app.rs:691-822`) обновляет `my_name`/`my_status`, но не `my_pub`/`my_code`.

**Сценарий.** TUI работает против демона с identity A (шапка показывает friend code A, `App::my_pub = A`). Демон перезапускают с другим каталогом данных / другой identity B (на Windows — типичный случай: `tunnel-daemon uninstall --purge` + `install` при живом TUI, либо служба поднялась после сбоя с новым `client.json`). Через `RECONNECT_EVERY` (1 с) `worker` подключается к B, кладёт в лог строку «перезапустите TUI» и **продолжает работу**: снимок B подменяет состояние, команды уходят в B.

**Влияние.** Ложное состояние интерфейса сразу в трёх местах:
- шапка и `copy code` (`app.rs:3743`, `Command::Copy("code")`) отдают friend code **A**, пока туннель держит **B** — новый друг добавит A и его заявка не дойдёт никуда (движка A нет);
- `owner_is_me` считается как `gs.owner == self.my_pub` (`app.rs:747`), то есть для групп B, где владелец — B, интерфейс считает, что владелец **не я** → у своих групп пропадают действия владельца (`admin`, `kick`/`ban`/`transfer`, удаление/переименование);
- сообщение «перезапустите TUI» обещает действие, которого код не требует и не выполняет: пользователь видит ошибку и продолжает работать в неверной сессии.

**Как проверить.** 1) Запустить `tunnel-daemon console --data-dir d1` (identity A), открыть `tunnel-client tui` (тонкий режим). 2) Остановить демон, запустить `tunnel-daemon console --data-dir d2` (identity B, другой `client.json`). 3) Через 1–2 с: в логе TUI — «демон работает с другой identity», в шапке — код A, в списке групп — группы B, у групп B нет метки владельца. Юнит-тест: поддельный демон на Unix-сокете с другим `me` (каркас уже есть — `remote.rs:548+`, `FakeDaemon`).

**Рекомендация.** При несовпадении identity не подменять снимок и не продолжать сессию: либо (а) обновлять `my_pub`/`my_code` из `Welcome.me` при каждом (пере)подключении (сбрасывать `owner_is_me`/`declined`/`invites` через `on_server`-подобный сброс), либо (б) закрывать соединение, показывать модальное окно «демон сменил identity — перезапустите TUI» и переходить в офлайн-режим, но не работать с чужим состоянием. Минимум — не логировать «перезапустите», если код всё равно продолжает.

### S3

#### FRNT-2 · TUI (тонкий клиент) · S3 · уверенность высокая

**Evidence.** `crates/client/src/remote.rs:397-403`:

```rust
        if !lost {
            match c.recv(Some(POLL)) {
                Ok(DaemonMsg::Event { ev, .. }) => {
                    if let Ok(e) = serde_json::from_value::<Event>(ev) {
                        sh.push(e);
                    }
                }
                Ok(DaemonMsg::Snapshot { snap, .. }) => {
```

`seq` события не читается вообще (`DaemonMsg::Event { ev, .. }` — поле отброшено), `DaemonMsg::Snapshot { snap, .. }` — тоже. Документ требует обратного — `docs/IPC.md:289-296`:

```text
3. Событие с `seq <= last_seq` — повтор, его игнорировать.
4. Событие с `seq == last_seq + 1` — применить и обновить `last_seq`.
5. Событие с `seq > last_seq + 1` — **пропуск**. Клиент отмечает, что состояние может быть неполным, и до ближайшего `snapshot` события не применяет ...
6. `snapshot` с `seq = S` — заменить состояние, `last_seq = max(last_seq, S)`, сбросить признак пропуска.
```

Для сравнения: трей реализует хотя бы часть правила (`crates/tray/src/remote.rs:360-362, 405-411` — `base_seq`), TUI — ничего.

**Сценарий.** Очередь подписчика в хабе переполняется (`DEFAULT_QUEUE = 256`, `hub.rs:35`), хаб документированно выбрасывает события этому клиенту (`hub.rs:295-312`, `deliver` → `need_snapshot = true`, события не шлются). TUI получает событие с `seq`, разрывным относительно предыдущего, и **применяет** его (`app.rs:880+ apply_events` меняет `peers`/`paths`/`relay_bytes`, показывает тосты и строки лога). Признака «состояние неполно» интерфейс не выставляет.

**Влияние.** До ближайшего снимка (≤1 с) интерфейс показывает частично неверное состояние (пути пиров, счётчик релея, лента/тосты с пропущенными и/или «внеочередными» событиями), и пользователь не узнаёт, что часть ленты потеряна. Полная подмена состояния снимком ограничивает ущерб одной секундой, поэтому S3, а не S2. Дополнительно — расхождение с `IPC.md` §«Правила клиента»: клиент, написанный по документу, и штатный TUI ведут себя по-разному.

**Как проверить.** Юнит-тест на `worker`/подписку: поддельный демон шлёт `Event{seq:1}`, `Event{seq:5}` (пропуск) — сейчас оба попадут в `poll_events`; ожидаемое поведение — второй не применяется, выставлен флаг пропуска. На живом демоне: `tunnel-daemon console --fake`, подписчик, который не читает (тест `slow_subscriber_does_not_block_others`, `hub.rs:373`), затем быстрый читатель.

**Рекомендация.** Добавить в `Shared`/`IpcEngine` `last_seq` и `gap`: обновлять на `Snapshot`, отбрасывать `seq <= last_seq`, при `seq > last_seq + 1` — не применять событие к состоянию (только в ленту, помечая «пропуск») до следующего снимка. Отразить в `docs/TUI.md` (раздел про ленту).

#### FRNT-3 · демон (hub/server) · S3 · уверенность высокая

**Evidence.** `crates/daemon/src/hub.rs:161-188`:

```rust
        let pre = {
            let g = self.lock();
            g.snap.is_none().then_some(g.seq)
        };
        let fresh = pre.map(|seq| (seq, Arc::new(self.backend.snapshot())));
        let mut g = self.lock();
        let snap = match (&g.snap, fresh) {
            (Some(s), _) => s.clone(),
            (None, Some(s)) => {
                g.snap = Some(s.clone());
                s
            }
            ...
        Subscription {
            id,
            history: g.ring.iter().cloned().collect(),
            snapshot: snap,
            rx,
        }
```

и `crates/daemon/src/server.rs:514-524`:

```rust
        let (mut snap_seq, snap) = (sub.snapshot.0, &sub.snapshot.1);
        let mut sent_seq = sub
            .history
            .last()
            .map_or(snap_seq, |(q, _)| snap_seq.max(*q));
        if !self.write(&DaemonMsg::Snapshot {
            seq: snap_seq,
            snap: (**snap).clone(),
        }) {
```

**Механизм.** Кэш `g.snap` обновляется в `pump_at` только при `need = changed || due || stale || snap.is_none()` (`hub.rs:233-241`). Если в такте пришли события, но `changed()` ложно и период `SNAPSHOT_EVERY` не истёк, кэш остаётся со старым `seq`, а кольцо (`g.ring`) уже содержит события с бо́льшими `seq`. Новый подписчик получает **историю новее снимка**: `sub.snapshot.0 < sub.history.last().0`, а `Forwarder` шлёт снимок ровно с `seq = sub.snapshot.0`. Флаг `stale` (`hub.rs:238-239`) спасает только существующих подписчиков с `need_snapshot`, но не `subscribe`.

**Влияние.** Нарушено обещание `docs/IPC.md:258-261` («снимок на момент подписки») и `IPC.md:285` («`seq` снимка — номер последнего события, которое уже учтено в состоянии снимка»): клиент, соблюдающий правила 2 и 6 (`IPC.md:292-296`), после истории с `seq = H` получает снимок с `seq = S < H`, ставит `last_seq = H` и **не применяет** историю к состоянию — состояние остаётся на момент S, то есть до ~1 с устаревшим, а события S+1..H уже «погашены» как история. Штатный TUI маскирует это тем, что проигрывает историю в состояние (`app.rs:632-636`), но это же противоречит правилу 2 документа. Ущерб ограничен одним тактом — S3.

**Как проверить.** Юнит-тест в `hub.rs`: `pump_at(t0)` (снимок), затем `backend.push(1)` без `changed`/`due`, `pump_at(t0+10ms)`, затем `subscribe(...)` → `assert!(sub.snapshot.0 >= sub.history.last().unwrap().0)` сейчас упадёт. Живой сценарий: `--fake` + подписчик, приходящий между тактами.

**Рекомендация.** В `subscribe` либо всегда строить свежий снимок (цена — один `backend.snapshot()` на подключение), либо возвращать `snapshot.0 = max(cache_seq, ring.last().0)` **только** если содержимое кэша действительно покрывает эти события (проще первое). Альтернатива: в `Forwarder::stream` не отправлять историю, если `snap_seq < last_history_seq`, а сразу запросить свежий снимок.

#### FRNT-4 · TUI (копирование в буфер) · S3 · уверенность высокая

**Evidence.** `crates/client/src/tui/clipboard.rs:147-152`:

```rust
        Method::WinClip => {
            // clip.exe понимает UTF-16LE с BOM независимо от кодовой страницы.
            let mut data = vec![0xFF, 0xFE];
            data.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
            pipe("clip.exe", &[], &data)
        }
```

и `clipboard.rs:161-174`:

```rust
fn pipe(cmd: &str, args: &[&str], data: &[u8]) -> Result<(), String> {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .stdin(Stdio::piped())
```

**Сценарий (precondition — важна).** Embedded-TUI (`tunnel-client tui --embedded`) и `run` требуют прав администратора (TUN). `Command::new("clip.exe")` на Windows разрешает имя по стандартному порядку: каталог приложения → **текущий каталог** → System32 → PATH. Если администратор запускает TUI из каталога, куда может писать другой локальный пользователь (или из распакованного архива/загрузок), подложенный `clip.exe` выполнится с правами администратора при первом копировании (IP пира, свой IP, код — `app.rs` `Command::Copy`). То же для `pbcopy`/`wl-copy`/`xclip`/`xsel` в embedded-режиме на Unix (там — с правами root/CAP_NET_ADMIN).

**Влияние.** Локальное повышение привилегий до администратора/root из непривилегированного пользователя при условии, что администратор запускает elevated-клиент из чужого каталога и копирует текст. Требует и социальной составляющей, поэтому S3, а не S1.

**Как проверить.** На Windows: положить безобидный `clip.exe` (например, `cmd /c echo pwned > %TEMP%\x`) в каталог, из которого запускается elevated TUI, нажать «копировать IP» — файл появится. Проверять только на тестовой машине.

**Рекомендация.** Брать полный путь (`%SystemRoot%\System32\clip.exe` через `GetSystemDirectoryW`, как уже сделано для `powershell.exe` в `winsvc/src/install.rs:570-579`) либо не запускать внешние утилиты из elevated-режима вовсе (в embedded-TUI оставить только OSC 52 и `arboard`, как в трее — `tray/src/win.rs:257-261`). Дополнить `docs/SECURITY.md` §15 (сейчас риск не отражён; `docs/TUI.md:560` просто перечисляет утилиты).

### S4

#### FRNT-5 · трей · S4 · уверенность высокая (дрейф документа)

**Evidence.** `crates/tray/src/remote.rs:455-456`:

```rust
        // TODO(7.4): открыт ли TUI — демон пока не сообщает о своих клиентах.
        st.tui_open = false;
```

против `docs/DAEMON.md:249-251`:

```text
- `WhenTuiClosed` (по умолчанию) — молчим, пока открыт TUI: там приглашение и
  так видно в окне;
- `Always` — уведомления всегда.
```

**Влияние.** Режим по умолчанию фактически равен `Always`: toast-ы приходят и при открытом TUI. Функциональной ошибки нет, но заявленное поведение в коде отсутствует; `should_show` (`model.rs:508-513`) и тесты выглядят корректно, поэтому дефект легко не заметить при чтении.

**Как проверить.** Открыть TUI и трей, попросить приглашение — toast появится при `WhenTuiClosed`. Либо юнит-тест `Notifier::observe` с `tui_open: true` — он проходит, потому что поле никто не заполняет.

**Рекомендация.** Либо реализовать (демон уже знает своих клиентов: `IpcServer::clients()`, `server.rs:166-168`, `ClientKind::Tui` в `Hello` — можно отдавать в снимке `meta.tui_open`), либо убрать `WhenTuiClosed` из документа и кода как нереализованный режим.

#### FRNT-6 · winsvc (публичный API) · S4 · уверенность высокая

**Evidence.** `crates/winsvc/src/common.rs:253-258`:

```rust
pub fn pipe_sddl(owner_sid: &str) -> Result<String> {
    validate_sid(owner_sid)?;
    Ok(format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{owner_sid})"
    ))
}
```

Против правила, зафиксированного в `crates/ipc/src/transport/windows.rs:73-77`:

```rust
/// Права пользователя на пайп: `FILE_GENERIC_READ | FILE_GENERIC_WRITE`
/// (`0x120089 | 0x120116`) без `FILE_CREATE_PIPE_INSTANCE` (`0x4`).
...
const PIPE_CLIENT_ACCESS: u32 = 0x0012_019b;
```

`GRGW` = `FILE_GENERIC_READ|FILE_GENERIC_WRITE` = `0x120089|0x120116` = `0x12019f`, то есть **с** битом `0x4`, который для пайпа означает `FILE_CREATE_PIPE_INSTANCE`.

**Влияние.** Сейчас функция — мёртвый код (единственные ссылки: собственный тест `common.rs:612-618`; пайп строит `ipc::transport::windows::pipe_sddl`). Но `winsvc` реэкспортирует её наружу (`winsvc/src/lib.rs:16-17`, `pub use common::*`), а по смыслу имени её естественно взять для пайпа — тогда пользователь-владелец получит право поднимать свои экземпляры серверной стороны пайпа (именно то, что §13 SECURITY.md называет исключённым). Это «заряженное ружьё» и противоречие внутри дерева.

**Как проверить.** `grep -rn "pipe_sddl" crates` — использование только в тесте. Сравнить маски: `0x12019f & 0x4 == 4`.

**Рекомендация.** Удалить `winsvc::common::pipe_sddl` (пайп целиком принадлежит `tunnel-ipc`) либо заменить маску на `0x12019b` и добавить в тест `assert_eq!(mask & 0x4, 0)` — как в `ipc/src/transport/windows.rs:689`.

#### FRNT-7 · демон/ipc на Windows · S4 · уверенность высокая (механизм) / средняя (эксплуатируемость)

**Evidence.** `crates/daemon/src/server.rs:33-36` и `302-307`:

```rust
/// Сколько ждать `Hello` от нового соединения (Unix; у пайпа таймаутов нет).
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Запись, застрявшая дольше этого, — клиент мёртв, соединение рвётся (Unix).
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
```

```rust
    #[cfg(unix)]
    {
        conn.set_read_timeout(Some(HELLO_TIMEOUT))?;
        conn.set_write_timeout(Some(WRITE_TIMEOUT))?;
    }
```

Плюс отсутствие ограничения числа соединений (`PIPE_UNLIMITED_INSTANCES`, `ipc/src/transport/windows.rs:280`; `Shared::conns` — `HashMap` без лимита, `server.rs:55`) и отсутствие валидации `snapshots_ms` (`server.rs:413-427`: `snap_every: Duration::from_millis(u64::from(snapshots_ms))` без нижней границы).

**Сценарий.** Локальный пользователь, которому выдан доступ к пайпу (SID из `owner.sid`), открывает N соединений и не отправляет `Hello` — каждое даёт поток `ipc-conn-N` и живой экземпляр пайпа с буферами 64 КиБ×2 в пуле ядра; освобождаются они только по закрытию клиентского хэндла. Аналогично клиент, который не читает, блокирует запись навсегда (таймаута записи на пайпе нет). `Subscribe{snapshots_ms: 0}` заставляет `Forwarder` отдавать снимок на каждом такте хаба (20 Гц вместо 1 Гц).

**Влияние.** Отказ в обслуживании демона/машины силами того же пользователя, который и так может остановить свою службу; через границу привилегий (обычный пользователь → SYSTEM-служба) — только исчерпание разделяемого пула. Отсутствие таймаутов на пайпе задокументировано (`docs/IPC.md:116`), поэтому это не «скрытый» дефект, но последствия (неограниченный рост потоков/экземпляров) в документах не описаны.

**Как проверить.** На Windows: `for i in 1..2000 { open pipe; don't send }` — смотреть `(Get-Process tunnel-daemon).Threads.Count` и потребление пула. `Subscribe{snapshots_ms:0}` — счётчик `Snapshot` за секунду.

**Рекомендация.** (1) Клампить `snapshots_ms` снизу (например, ≥250 мс) в `server.rs`; (2) ограничить число одновременных соединений (семафор/счётчик в `Shared`) и ввести «теневой» таймаут `Hello` для пайпа (поток-сторож с `CancelIoEx` через `Conn::shutdown`); (3) при отказе от ограничений — описать риск в `SECURITY.md` §15.

#### FRNT-8 · TUI (жизненный цикл терминала) · S4 · уверенность средняя

**Evidence.** `crates/client/src/tui/mod.rs:107-120`:

```rust
pub(crate) fn setup_terminal(mouse: bool) -> Result<Terminal<CrosstermBackend<Stdout>>> {
    install_panic_hook();
    let mut out = std::io::stdout();
    if mouse {
        execute!(out, EnableMouseCapture)?;
    }
    enable_raw_mode()?;
    execute!(out, EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(out))?)
```

**Влияние.** Если `EnterAlternateScreen` (или `Terminal::new`) вернёт ошибку, функция выходит по `?` **после** `enable_raw_mode()` и `EnableMouseCapture`, не вызывая `restore_terminal`: консоль остаётся в raw-режиме с захватом мыши. Паника этот путь не покрывает (panic hook срабатывает только на панику). Вероятность мала (ошибка записи в stdout сразу после успешного raw-режима), поэтому S4.

**Как проверить.** Подменить stdout на объект, падающий на записи `\x1b[?1049h` (юнит-тест с поддельным backend'ом), либо `chcp`/`conhost`-сбой на реальной консоли. Достаточно теста на «restore вызывается при любой ошибке после enable_raw_mode».

**Рекомендация.** Обернуть шаги в RAII-страж (`struct TermGuard` с `Drop` → `disable_raw_mode`/`LeaveAlternateScreen`/`DisableMouseCapture`), как это уже неявно делает panic hook; либо вызывать `restore_terminal` при ошибке в `setup_terminal`.

#### FRNT-9 · CLI · S4 · уверенность высокая

**Evidence.** `crates/client/src/main.rs:1279`:

```rust
        r#"tunnel-client (протокол v3) — Hamachi-подобный VPN
```

При `crates/protocol/src/lib.rs:64`: `pub const PROTOCOL_VERSION: u8 = 4;`. Тот же устаревший «v3» — в `docs/DAEMON.md:94` и `docs/CLIENT.md:850` (это уже область аудита документации, передаю как замечание).

**Влияние.** Пользователь, читающий `--help`, считает, что клиент говорит по v3, и делает неверные выводы о совместимости с серверами (v4 несовместим с v3 — `docs/CHANGELOG.md:116`).

**Рекомендация.** Печатать версию из константы: `format!("tunnel-client (протокол v{}) ...", tunnel_protocol::PROTOCOL_VERSION)`.

#### FRNT-10 · трей · S4 · уверенность высокая

**Evidence.** `crates/tray/src/remote.rs:497-509`:

```rust
fn run_loop(t: &dyn Transport, sh: &Shared, cmds: &Receiver<(Action, Value)>, retry: Duration) {
    while !sh.stop.load(Ordering::Relaxed) {
        let _ = session(t, sh, cmds);
        sh.on_down();
```

**Влияние.** `session()` возвращает `Err(OpenError::Down(e))` с текстом причины, включая security-значимый «сервер пайпа — не служба и не повышенный демон этого пользователя: возможна подмена демона» (`ipc/src/transport/windows.rs:361-367`) и «нет прав». Строка отбрасывается (`let _ =`), в состояние попадает только `on_down()` → «служба недоступна». Пользователь не может отличить «службы нет» от «пайп подменён»/«нет доступа» — падает диагностируемость ровно того сценария, ради которого сделана `decide_trust`. (Отказ версии — `Rejected` — обрабатывается отдельно и виден: `remote.rs:465-468`.)

**Рекомендация.** Передавать текст ошибки в состояние (один раз на эпизод, как `on_reject`): `sh.on_error(format!("IPC: {e}"))` в `run_loop`.

#### FRNT-11 · CLI · S4 · уверенность высокая

**Evidence.** `crates/client/src/main.rs:202-205`:

```rust
            "--passphrase" => {
                i += 1;
                passphrase = Some(rest.get(i).with_context(usage)?.clone());
            }
```

**Влияние.** Парольная фраза, защищающая экспорт identity, попадает в командную строку процесса — её видит `ps`/чтение `/proc/<pid>/cmdline` любой локальный пользователь на Linux (на Windows — любой процесс того же пользователя и администратор). Безопасная альтернатива `--passphrase-stdin` есть и рекомендована в `docs/CLIENT.md:167`, но риск «фраза в argv» не отражён ни в `SECURITY.md` §12, ни в §15 (там есть только §15 п.12 «офлайн-перебор» и п.13 «экспорт без пароля»).

**Рекомендация.** Оставить `--passphrase` для совместимости, но добавить предупреждение в `stderr` при его использовании («фраза видна в списке процессов; используйте --passphrase-stdin») и строку в `SECURITY.md` §15.

## 4. Проверено — находок нет

Ниже — то, что проверялось целенаправленно и выдержало проверку (чтобы был виден охват, а не только дефекты).

**Фрейминг и кодек (`ipc/src/codec.rs`).** Длина проверяется **до** выделения памяти (`read_frame`, 81-98); `MAX_FRAME = 1 << 20`; тело ровно 1 МиБ допустимо (тест 159-167); `0` → `BadLength`; обрыв посреди кадра → `Truncated`; `Interrupted` не считается ошибкой; `write_msg` пишет заголовок и тело одной записью и отказывает на oversize, ничего не записав (тест 169-181). Паник нет, все ошибки — значения.

**Права named pipe (`ipc/src/transport/windows.rs`).** `FILE_FLAG_FIRST_PIPE_INSTANCE` на первом экземпляре (270-273) — сервер не присоединяется к чужому пайпу; `PIPE_REJECT_REMOTE_CLIENTS` (279); SDDL с `O:SY`/`O:BA` и `D:P` (без наследования) (209-221); маска клиента `0x12019b` **без** `FILE_CREATE_PIPE_INSTANCE` (73-77, тест 689-690); `valid_sid` (169-175) отсекает инъекцию в SDDL (проверено: `s[1..]` безопасно из-за `starts_with("S-1-")`); экземпляр для следующего клиента создаётся до ожидания, поэтому имя не освобождается (294-311); `ConnectNamedPipe`/`ERROR_PIPE_CONNECTED` обработан (317-322); `SECURITY_IDENTIFICATION` у клиента (346); `decide_trust` — порядок «сначала токен, потом владелец» (411-419) и таблица тестов (701-774) закрывают и неповышенного своего (739), и чужого (749), и подделку владельца при читаемом токене; при недоступном токене требуется владелец SYSTEM/BA (753-773) — то есть админ, у которого и так есть контроль. `overlapped` использует отдельный event на клон и `SeqCst`-флаг перед `CancelIoEx` (106-132); `read`/`write` после `shutdown` дают EOF/`BrokenPipe`, а не зависание (601-664). `SecDesc` освобождается через `LocalFree` (161-165), утечек хэндлов в `server_facts`/`pipe_owner` не найдено (449-562).

**Unix-сокет (`transport/unix.rs`).** Каталог обязан быть своим и `mode & 0o077 == 0` до `bind` (73-92); файл `0600` (33); `Drop` удаляет сокет только при совпадении `(dev, ino)` (57-65); `cleanup_stale` не трогает не-сокет и живой сокет (98-122).

**Single-instance (`ipc/src/lock.rs`).** Unix: `O_NOFOLLOW`, `nlink == 1`, каталог `0700` (с исправлением своих прав), `try_lock` с повторами против ложного «занято» (140-185); `is_held` берёт общий замок на миг (117-129) — тест `probe_does_not_block_acquire` (471-499) это фиксирует. Windows: мьютекс `Global\TunnelEngine`, DACL с `READ_CONTROL|SYNCHRONIZE` для `AU`, чтобы проверка работала без админа (311); посторонний объект (чужой владелец, другой тип, `ACCESS_DENIED`) не блокирует запуск (219-236) — тест `foreign_object_ignored` (566-581); `null`-хэндл корректно обрабатывается в `Drop` (441-448). Захват имени одним и тем же пользователем даёт лишь self-DoS, что и записано в `SECURITY.md` §14.

**Хаб (`daemon/src/hub.rs`).** `seq` строго монотонный с 1 (215-221); кольцо `RING_CAP = 500` (217-220); `try_send` — медленный подписчик не блокирует ни движок, ни других (тест 372-399); при переполнении события не шлются, досылается снимок с `seq` такта (295-312, тест 401-427); снимок строится **вне** мьютекса хаба (252); `unreachable!` в `subscribe` (173) действительно недостижим: `g.snap` только заполняется и никогда не очищается (проверено все три ветки `match`); `drop` подписки удаляет её на следующем такте (тест 501-514).

**Сервер демона (`daemon/src/server.rs`).** Первым обязан быть `Hello` (359-397); версия проверяется `check_hello`; повторный `Hello` и повторный `Subscribe` — закрытие/игнор (413-448); любая ошибка кодека закрывает только это соединение; гонки «поток соединения завершился раньше `conns.insert`» нет — мьютекс `conns` берётся **до** `spawn` (311-336), поэтому `remove(&id)` не может опередить `insert`; `stop_all` шлёт `Shutdown` из отдельных потоков с `SHUTDOWN_GRACE = 500 мс`, затем рвёт соединения (185-214).

**Валидация команд на стороне демона.** `Backend::send` разбирает `cmd` в `Cmd` (ошибка → `Ack{Err}`), запрещает `Quit` (`engine_backend.rs:80-86`, `478`), правки конфига проходят `check_cfg_cmd` (`api.rs:248-261`); `DaemonBackend::Failed` отвечает `Err` на любую команду (`644-649`); в лог команды и ключи не пишутся (grep по `log(.*cmd|key|seed|pass` — пусто).

**Служба Windows (`winsvc`).** Порядок установки: `verify_install_dir` (каталог, exe, dll, предки по `REPLACE_MASK`) → `prepare_data_dir` → импорт конфига → `owner.sid` → служба (56-80). `prepare_data_dir` пересоздаёт каталог, если это ссылка/не каталог/нет `owner.sid`/владелец не SYSTEM|BA (113-139); `create_fresh_dir` использует `create_dir` (не `_all`), чтобы не принять чужой каталог (143-149); `write_secure` пишет новый файл (наследует ACL каталога) + rename (351-355); `TreeSetNamedSecurityInfoW` с `PROTECTED_DACL` и `TREE_SEC_INFO_RESET` (388-402); `check_admin_only` fail-closed: NULL DACL — отказ, `UnknownAllow` — отказ, любой allow с маской записи не от доверенного SID — отказ (362-393, тест 671-723); `wintun.dll` только рядом с exe, путь обязан быть абсолютным (287-314); служба проверяет каталог при старте через `service_wintun_dll` → `verify_install_dir` (`312`); failure actions 5/10/30 с + `set_failure_actions_on_non_crash_failures` (224-240); `LocalSystem` (`account_name: None`, 207); `powershell.exe` берётся из `GetSystemDirectoryW`, не из PATH (570-579); `ps_quote` экранирует `'` и U+2018..U+201B (410-421); `--purge` удаляет только данные, конфиг без `--purge` сохраняется (177-184).

**Терминал TUI.** Panic hook снимает raw/alt-screen/mouse до печати сообщения (125-138); `restore_terminal` вызывается и при ошибке `event_loop` (76-81, 99-101); порядок «мышь → raw → alt» и обратный соблюдён из-за особенности crossterm на Windows (107-120, 145-158); в `ui.rs` нет ни одного `lock()` — рендер не блокируется на мьютексах (grep: 0 совпадений); все `unwrap/expect/panic` в `tui/*` — внутри `#[cfg(test)]` либо доказанно защищены (`setup.rs:188,197` вызывает `apply` только после `validate` в том же такте — `setup.rs:276-291`, `310-315`; `app.rs:3981` — `try_into` после проверки длины); секретов на экране нет: рисуются только `my_pub`, friend code (публичный) и identicon; приватные сиды в TUI не попадают.

**Трей.** Меню соответствует `DAEMON.md:221-230`: группы и приглашения активны только при `online`, «Остановить туннель» — только при живом демоне (`model.rs:192-276`); tooltip обрезается до 127 UTF-16 с учётом суррогатных пар (`model.rs:278-312`); `Notifier` не растёт (множество `seen_invites` пересобирается из снимка, `model.rs:461-475`), «нет связи» — один раз за эпизод (486-497); буфер обмена — `arboard`, без внешних процессов (`win.rs:257-261`); `map_snapshot` устойчив к мусору и `null` (тесты `remote.rs:658-680`); `Link::recv` корректно превращает таймаут в `Ok(None)` (`remote.rs:77-83`), поэтому `POLL = 50 мс` не рвёт сессию; один поток связи с реконнектом, утечки потока нет (497-510).

**CLI.** `Route`/`is_readonly` не дают открыть свой ctrl-сеанс при живом движке без демона (`remote_cli.rs:48-59`, `main.rs:346`); коды возврата: 2 — ошибка разбора/неизвестная команда (2, 939, 1326-1331), 1 — ошибка выполнения (`main.rs:113-119`); печатаются только публичные ключи (`ed25519 pub`, `x25519 pub`, friend code — `main.rs:389-392`); экспорт identity пишется `0600` и через временный файл (`profile.rs:318-358`), при ошибке tmp удаляется.

**Инфраструктура.** `install.ps1`: UAC-перезапуск с нормализованным `$Source` (37-49), проверка наличия всех файлов до копирования (62-66), остановка службы/трея перед заменой (68-77), копирование в `%ProgramFiles%\Tunnel` (79-82), затем явный DACL `/inheritance:r` + `SYSTEM/BA F`, `Users RX`, сброс наследования на детях и `/setowner BA` (96-103) — порядок «сначала копия, потом ACL» безопасен, потому что каталог Program Files недоступен на запись обычному пользователю; регистрация службы идёт уже из защищённого каталога (105-114). `uninstall.ps1`: остановка, `tunnel-daemon uninstall`, страховочный `sc delete`, удаление Run-ключа и каталога с повторами, `--purge` — только по флагу (37-93).

**Документы.** `docs/IPC.md` в части фрейминга, лимитов (`MAX_FRAME`, `HELLO_TIMEOUT`, `WRITE_TIMEOUT`, `SHUTDOWN_GRACE`, `RING_CAP`, `DEFAULT_QUEUE`, `SNAPSHOT_EVERY`, `TICK`, `CLIENT_QUEUE`, `PIPE_BUF`, `BUSY_RETRIES`) совпадает с константами кода; SDDL в `IPC.md:93-94`, `DAEMON.md:368-372` и `SECURITY.md:370-371` совпадает с `pipe_sddl`; `SECURITY.md` §13-14 соответствует `decide_trust`/`verify_install_dir`; 20 остаточных рисков §15 не переоценивались как находки — из них в моей области пересекаются №4 (сиды на диске), №12-13 (экспорт) и §14 (фолбэк `wintun.dll` по имени в CLI/TUI, уже заявленный).

## 5. Гипотезы и вопросы к владельцу

**Г1. `%ProgramData%\tunnel` не проверяется при старте службы.** `service::run_service` (`daemon/src/service.rs:417-441`) читает `owner.sid` и поднимает пайп, но ACL каталога данных не проверяет; `secure_data_dir` вызывается только в режиме `console` (`main.rs:37`) и при `install` (`winsvc/src/install.rs:66`). `install.ps1` при обновлении **не** вызывает `tunnel-daemon install`, если служба уже есть (`install.ps1:106-114`), то есть после первой установки ACL каталога данных больше никем не перепроверяется. Если ACL когда-либо ослаблен (восстановление из бэкапа, ручной `icacls`, миграция с другой машины), служба молча прочитает подложенный `client.json`/`identity`. Предусловие — действие администратора, поэтому это гипотеза, а не находка. Вопрос: нужна ли проверка `secure_data_dir` при старте службы (по аналогии с `verify_install_dir`)?

**Г2. `snapshots_ms`/`ver`/`kind` от клиента не валидируются.** См. FRNT-7. Вопрос: считать ли клиента доверенным полностью (он и так может остановить свою службу) или всё же клампить параметры подписки?

**Г3. `Forwarder` делит мьютекс записи с `Session::send`.** На Windows без таймаута записи зависший клиент держит мьютекс бесконечно, и `Ack` для этого соединения не уходит (`server.rs:352-355`, `485-488`). Проверяемо только на живой службе с «залипшим» читателем; последствия ограничены одним соединением. Вопрос: нужен ли на пайпе сторож записи (см. FRNT-7)?

**Г4. `later_invites` в TUI без верхней границы** (`app.rs:1348`, `1475`): очередь отложенных окон приглашений не ограничена; число уникальных `gid` ограничено сервером (лимиты групп/приглашений), поэтому рост возможен лишь при массовых приглашениях от участника с полномочиями. Гипотеза: при 1000+ приглашений память TUI растёт без предела. Вопрос: нужен ли `INVITES_MAX`?

**Г5. Порядок поиска `ShellExecuteW("sc.exe")` в трее** (`tray/src/win.rs:286-305`): «Остановить туннель» запускает `sc.exe` по голому имени с `runas`. Если ShellExecute ищет исполняемый файл в текущем каталоге трея (поведение зависит от версии/флагов), подложенный `sc.exe` выполнится после подтверждения UAC. Тот же класс — `wt.exe`/`conhost.exe`/`tunnel-client.exe` в `open_tui` (`win.rs:264-283`). Проверить на живой Windows; надёжное исправление — полные пути. Вопрос: подтвердить/опровергнуть порядок поиска на целевой ОС.

**Г6. Согласованность семантики снимка для нештатного клиента.** FRNT-3 показывает, что «снимок на момент подписки» может быть старее истории. Вопрос владельцу протокола: считается ли допустимым, что клиент, соблюдающий `IPC.md` §«Правила клиента», на первом кадре получает состояние на ~1 с в прошлом? Если да — правило 6 в `IPC.md` стоит уточнить («снимок может быть старее последних событий истории; состояние дополнительно проигрывать историей нельзя — ждите следующего снимка»).

**Г7. Требуется прогон на Linux (запрос ведущему).** Всё, что связано с `flock`/`O_NOFOLLOW`/`0600` и с Unix-таймаутами (`HELLO_TIMEOUT`/`WRITE_TIMEOUT`), проверено статически на Windows-хосте. Прошу на Linux-хосте прогнать: `cargo test -p tunnel-ipc` (тесты `lock_file_links_refused`, `lock_dir_made_private`, `probe_does_not_block_acquire`) и e2e демона из `docs/TESTING.md` (раздел про IPC) — это подтвердит поведение замка и сокета на реальной ФС.

## 6. Итог

Транспорт и границы доверия в этой области сделаны заметно аккуратнее среднего по проекту. Кодек не паникует и проверяет длину до выделения памяти; named pipe собран с `FIRST_PIPE_INSTANCE`, `REJECT_REMOTE_CLIENTS`, явным SDDL без наследования и с маской клиента **без** права создавать экземпляры; клиент проверяет личность сервера пайпа по токену процесса, а при недоступном токене — по владельцу объекта, и порядок этих проверок не даёт обойти правило подделкой владельца. Замок single-instance на обеих платформах закрывает и симлинк, и жёсткую ссылку, и захват имени посторонним; установщик службы проверяет DACL каталога установки, exe, DLL и всех предков, пересоздаёт недоверенный каталог данных и ставит защищённый DACL; `wintun.dll` берётся только рядом с exe. TUI корректно возвращает терминал при панике и не держит блокировок в рендере, паники вне тестов отсутствуют, приватные ключи на экран и в лог не попадают. Находок S1 в области нет: ни одного способа получить код от SYSTEM/root через пайп, DLL, конфиг или IPC статическим анализом не найдено.

Главный дефект — **FRNT-1 (S2)**: при переподключении к демону с другой identity TUI пишет «перезапустите TUI» и продолжает работать, оставив в шапке и в `copy code` прежний friend code, а `owner_is_me` считая по прежнему ключу — то есть у своих групп пропадают действия владельца. Это ровно тот класс «ложного состояния интерфейса», который в этой области опаснее всего: пользователь действует по неверной картине, а сообщение об ошибке обещает поведение, которого код не выполняет.

Второй слой — расхождение кода с `docs/IPC.md` в семантике `seq`/`снимков`: TUI вообще не отслеживает `seq` (FRNT-2), а хаб отдаёт новому подписчику снимок, который может быть старее собственной истории (FRNT-3). Ущерб ограничен одним тактом хаба (≤1 с) и маскируется тем, что TUI проигрывает историю в состояние, — но клиент, написанный по документу, получит устаревшее состояние, а признак «состояние неполно» не выставляется ни в одном фронтенде.

Остальное — гигиена с одним практическим исключением: **FRNT-4** (запуск `clip.exe` по голому имени из elevated-TUI) — реальный, хотя и узкий, путь повышения привилегий при запуске embedded-клиента из чужого каталога; лечится полным путём из `System32`, как уже сделано для `powershell.exe`. Остальные S4 (мёртвая `winsvc::pipe_sddl` с неверной маской `GRGW`, отсутствие таймаутов и лимита соединений на пайпе, потеря текста ошибки подключения в трее, нереализованный `WhenTuiClosed`, «протокол v3» в `--help`, пароль в argv) стоит закрыть пакетом: они дешёвы в правке и убирают будущие ловушки.
