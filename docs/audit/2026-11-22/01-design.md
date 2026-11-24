# Аудит дизайна VoidLink (W1)

- **Базис:** коммит `c0689fc` (ветка `dev`, совпадает с `origin/master`), дерево `C:\Users\SumalyFly\RustroverProjects\VoidLink`.
- **Аудитор:** design-auditor (W1), независимо от остальных потоков.
- **Префикс находок:** `DES`.
- **Все ссылки `файл:строка` — по указанному коммиту** (проверены чтением файла, не по памяти).

---

## 1. Область, метод, что НЕ проверялось

### 1.1. Область

Восемь тем задания: слоистость и граф зависимостей; модель потоков и блокировок; владение
состоянием и контракт снапшотов IPC; структурное качество (god-objects, дублирование, стратегия
ошибок, тестируемость); проектирование отказов; эволюция протокола; документация как проектное
решение; проектирование интерфейсов (CLI/TUI/IPC/упаковка Windows).

### 1.2. Метод

1. Нормативные утверждения брались **из документов** (`docs/ARCHITECTURE.md` §1–§10,
   `docs/IPC.md` §«Номера seq, пропуски и снимки», `docs/SECURITY.md` §15/§17,
   `docs/STAGE9_VERIFICATION.md`, `docs/NETWORKING.md`, `docs/TUI.md`, `docs/INSTALL.md`,
   `README.md`) и проверялись **против кода** точечным чтением (read) и grep по конкретным
   символам/константам.
2. Проверка порядка блокировок — вручную по каждому месту, где под одним локом берётся второй
   (`state`/`fed`/`per-session`/`Groups`/`Paths`/`Config`), включая пути, которые
   документация называет явно (`on_hint`, `save_now`, `relay_group`, `paths_round`,
   `snapshot_now`).
3. Счёт тестов — `grep '#\[test\]'` по дереву как прокси; **`cargo test --list` не запускался**
   (запрет на cargo в этом аудите), поэтому число 752 — оценка сверху, а не результат гейта.
4. CodeGraph MCP использовался как вспомогательный поиск; все цитаты в отчёте — из файлов,
   открытых read/grep (не из ответов графа).

### 1.3. Что НЕ проверялось

- **Не запускались** `cargo build/test/clippy/fmt`, `cargo deny/audit`, e2e, NAT-лаборатория.
  Все выводы о поведении — статические.
- **Не проверялась криптография** (AEAD, KDF, подписи, cookie) — это поток безопасности; здесь
  только то, как крипто-примитивы встроены в дизайн (порядок вызовов под локами, повторные
  запечатки, ротация).
- **Не проверялись** `crates/server/src/metrics.rs`, `tcp.rs`, `signals.rs` построчно
  (только их роль в модели потоков), `crates/tray/*` (кроме модели снимка), `crates/winsvc/*`
  (кроме точки стыка с демоном), `infrastructure/linux`, `netns`.
- **Не проверялась** живая Windows-служба, пайп, Wintun, MSI — только код и документация.
- **Не проверялась** корректность самих тестов (что они проверяют то, что заявлено) — только их
  расположение и границы.
- Отчёты других аудиторов в `docs/audit/2026-11-22/` **не читались** (независимость).

---

## 2. Покрытие

| Модуль / файл | Строк | Что проверено | Глубина |
|---|---:|---|---|
| `docs/ARCHITECTURE.md` | 816 | §1–§10 целиком против кода: граф, потоки, локи, владение, §7 таблицы, §8 IPC, §9 решения, §10 ограничения | построчно |
| `crates/server/src/lib.rs` | 8 407 | `Server::start/shutdown`, `Shared`+док-комментарий о порядке локов, `save_now`/`keep_rotated_key`/`housekeeping`/`wait_urgent`, `worker`/`handle_datagram`/`relay_group`/`flush`, `handle_ctrl_frame` (голова), `handle_mutation` (границы + 3 arm'а), `broadcast_group_list`, `healthy`/`refresh_gauges`, `Alive`, константы | выборочно-глубоко |
| `crates/server/src/federation.rs` | 2 869 | `apply`, `on_frame`, `on_handshake_frame`, `on_session_frame`, `on_hint`, `reconcile`, `publish_*`, `Fed::hint`; вложения локов `fed`/`state` | выборочно-глубоко |
| `crates/client/src/engine.rs` | 7 865 | модель потоков (спавн, отсутствие JoinHandle, `Drop`), `Env`, `update_cfg`/`autojoin_*`/`sync_friends_cfg`, `route_packet`, `paths_round`, `handle_group_frame` (inject), константы, `start_with_tun` | выборочно-глубоко |
| `crates/client/src/offline.rs` | 1 253 | очередь `ui-pending.json`, `adopt`/`flush`/`send`/`is_cfg_cmd`/`apply_cfg_cmd`, сброс очереди | глубоко (ключевой путь) |
| `crates/client/src/remote.rs` | 873 | `subscribe`, поток `ipc-engine`, обработка `Event`/`Snapshot`, реконнект; **отсутствие** учёта `seq` | глубоко |
| `crates/client/src/api.rs`, `snapshot.rs`, `store.rs`, `path.rs` | 717+750+1 840+~400 | `snapshot_now` (порядок локов), `from_sess`, `MetaSnap`, `Store::save`, poison-политика `PathTable` | выборочно |
| `crates/client/src/main.rs`, `remote_cli.rs` | 1 667+808 | диспетчер CLI, `usage()`, ветки друзей, `route`/`LOCKED_MSG`/`is_engine_cmd` | выборочно |
| `crates/client/src/tui/app.rs`, `ui.rs`, `badges.rs` | 6 147+3 647 | вывод `ConnState`, `draw_status`, бейджи mesh/реле, «правдивость» IP | выборочно |
| `crates/daemon/src/hub.rs` | 515 | целиком: seq, кольцо, снимок, переполнение, `subscribe` | построчно |
| `crates/daemon/src/server.rs`, `engine_backend.rs`, `service.rs` | 778+839+778 | `accept_loop`/`spawn_conn` (лимиты), `offline_cmd`, `poll_events`+`ResumeSignal`, `Shutdown` | выборочно-глубоко |
| `crates/ipc/src/proto.rs`, `codec.rs`, `transport/windows.rs` | 145+180+785 | `check_hello`, `MAX_FRAME`, SDDL/`decide_trust`/проверка сервера пайпа | выборочно |
| `crates/protocol/src/payloads.rs`, `handshake.rs`, `frag.rs`, `federation.rs`, `lib.rs` | 2 249+892+~280+1 088+1 031 | `PROTOCOL_VERSION`, exact-match в HELLO3/CHALLENGE/WELCOME, mesh-хвост `'MSH1'` (magic + `dec_mesh_section`), `FRAG_THRESHOLD/MAX_PAYLOAD/MAX_COUNT`, `FED_VER` | выборочно |
| `docs/IPC.md` | 592 | §«Рукопожатие и подписка», §«Номера seq, пропуски и снимки», §«Формы команд» | построчно (ключевые §) |
| `docs/SECURITY.md` | 614 | §13 (пайп), §15 (20 рисков), §17 (статус) | ключевые § |
| `docs/STAGE9_VERIFICATION.md`, `docs/PLAN.md`, `docs/CLIENT.md`, `docs/DAEMON.md`, `docs/TESTING.md`, `docs/TUI.md`, `docs/NETWORKING.md`, `docs/INSTALL.md`, `README.md` | ~4 100 | числа, статусы, якоря строк, обещания против кода | выборочно по числам |
| `crates/*/Cargo.toml`, `crates/client/build.rs`, `infrastructure/windows/install.ps1`, `vendor/` | — | фактический граф зависимостей, dev-deps, копирование `wintun.dll`, упаковка | полностью |

Оценка объёма: **~3 400 строк кода и ~2 300 строк документации прочитано адресно** (не подряд);
счётчики `#[test]`, `lock().unwrap()`, константы — по всему дереву через grep.

**Расхождение с вводными данными (важно).** Во вводных указано «`vendor/wintun/` пуст».
В дереве `c0689fc` это **не так**: `vendor/wintun/wintun.dll` — 427 552 байта, отслеживается
git (blob `aee04e7…`, `git cat-file -s` = 427552), `crates/client/build.rs:7-17` копирует его
в `target/<profile>/wintun.dll`, `infrastructure/windows/install.ps1:29` кладёт его в
`%ProgramFiles%\Tunnel`, откуда служба его и грузит (`crates/client/src/tun.rs:9-25` —
`current_exe().parent()/wintun.dll`). Упаковочного дефекта по этой линии нет (см. §4).

---

## 3. Находки

### S2

---

#### DES-01 · Состояние/офлайн-очередь · **S2** · уверенность: высокая (механизм), средняя (как часто попадает в «не ту» запись)

**Evidence.**

`crates/client/src/offline.rs:418-436` — в очередь офлайн-правок попадают **позиционные**
команды:

```rust
fn is_cfg_cmd(cmd: &Cmd) -> bool {
    matches!(
        cmd,
        Cmd::SetName(_)
            | Cmd::SetStatus(_)
            ...
            | Cmd::AddServer { .. }
            | Cmd::DelServer { .. }
            | Cmd::SetPrimaryServer { .. }
            | Cmd::SwitchServer { .. }
```

`crates/client/src/offline.rs:341-342` — и они формулируются как индекс:

```rust
            Cmd::DelServer { idx } => format!("сервер №{idx} удалён"),
            Cmd::SetPrimaryServer { idx } => format!("сервер по умолчанию: №{idx}"),
```

Очередь переживает перезапуск (`offline.rs:43 PENDING_FILE = "ui-pending.json"`,
`offline.rs:90 save_pending`) и при появлении демона выливается **в чужой конфиг**
(`offline.rs:298-316`: сброс только если `CfgView::from_cfg(&local) == snap.cfg`, иначе
`self.flush(eng.as_ref())`). Демон применяет её к **своему** списку серверов:

```rust
// crates/daemon/src/engine_backend.rs:455-456
            Cmd::DelServer { idx } => format!("сервер №{idx} удалён"),
            Cmd::SetPrimaryServer { idx } => format!("сервер по умолчанию: №{idx}"),
// :487-492
        let saved = {
            let mut c = lock(&this.cfg);
            apply_cfg_cmd(&mut c, cmd);
            c.clone()
        };
```

а `apply_cfg_cmd` трактует `idx` как позицию в **текущем** списке
(`crates/client/src/offline.rs:486-498`: `Cmd::DelServer { idx } => if idx < c.servers.len()
{ c.servers.remove(idx); }`, `SetPrimaryServer { idx } => ... c.servers.insert(0, s)`).

**Сценарий.** Windows-умолчание: у службы свой конфиг `%ProgramData%\tunnel\client.json`,
у TUI — `%APPDATA%` (`docs/ARCHITECTURE.md:737-739`), т.е. списки серверов расходятся
**штатно**. 1) Демона нет (не установлен / остановлен), TUI работает офлайн; пользователь
удаляет сервер №0 и делает «по умолчанию» сервер №1 — правки применяются локально и уходят в
`ui-pending.json` как `DelServer{idx:0}`, `SetPrimaryServer{idx:1}`. 2) Демон поднимается; его
список серверов другой (порядок/длина другие — например, после `migrate_servers` из прошлого
сеанса). 3) `flush` отправляет `DelServer{0}`/`SetPrimaryServer{1}` демону, и они бьют по
**другим** записям: удаляется не тот сервер, основным становится не тот.

**Влияние.** Демон (а значит и весь трафик, и identity) может подняться против сервера, который
пользователь не выбирал, либо потерять нужную запись. Ошибка «тихая»: и TUI, и демон показывают
успех (`Event::Notice("сервер №0 удалён")`), `SwitchServer` проверяет `known` по адресу
(`engine_backend.rs:457-466`), а `DelServer`/`SetPrimaryServer` — нет. Восстановимо вручную
через `servers`/`add-server`, но требует, чтобы пользователь заметил.

**Как проверить.** Юнит-тест: конфиг A = `[S1, S2]`, конфиг B = `[S2, S1]`; очередь
`[DelServer{0}]`; применить к B — удалится `S2` вместо `S1`. Вручную: офлайн-TUI удаляет
сервер, затем поднимается `tunnel-daemon console` с другим `--dir` и своим списком.

**Рекомендация.** В очереди хранить не индекс, а **идентификатор записи** (адрес + pubkey) и
применять по нему; при отсутствии записи — пропускать команду с заметкой в лог, а не бить по
индексу. Как минимум — добавить в `DelServer`/`SetPrimaryServer` проверку «запись по этому
индексу совпадает с ожидаемой» (адрес в команде).

---

#### DES-02 · Модель потоков/наблюдаемость · **S2** · уверенность: высокая

**Evidence.** Движок клиента не хранит `JoinHandle` своих потоков и не проверяет их живость:

```rust
// crates/client/src/engine.rs:2382-2389
    // Приём — отдельный поток с самого начала: он же доставит WELCOME.
    {
        let env = env.clone();
        let in_tx = in_tx.clone();
        thread::Builder::new()
            .name("rx".into())
            .spawn(move || rx_loop(env, in_tx))
            .context("spawn rx thread")?;
    }
```

```rust
// crates/client/src/engine.rs:1218-1225
impl Drop for Engine {
    fn drop(&mut self) {
        // Останавливаем потоки rx/engine (tun-поток завершится вместе с
        // сессией адаптера).
        self.env.quit.store(true, Ordering::Relaxed);
        let _ = self.cmds.send(Cmd::Quit);
    }
}
```

`Engine` (`engine.rs:1131-1146`) содержит только каналы и состояние — ни одного
`JoinHandle`/`AtomicBool` «поток жив». Возвращённые `spawn`-хендлы (rx:2386, cmd:2394,
engine:2426) отбрасываются.

Индикатор связи при этом берётся из состояния, которое обновляет **только сам движок**:
`snapshot.rs:300-315` (`connected: m.connected`), `tui/app.rs:650-658`
(`self.connected => ConnState::Online`).

Для контраста сервер такую проверку имеет: `crates/server/src/lib.rs:1026-1043` —
`Alive` (декремент в `Drop`, в том числе при панике) + `healthy()`, отдаваемый в
`/healthz`.

**Сценарий.** Любая паника в потоке `rx`/`engine` (а в этих файлах 146 `lock().unwrap()` и
десятки индексаций — см. DES-07) завершает поток. Процесс жив, TUI продолжает получать
снимки (их строит `LocalEngine` из `Groups`/`Meta`), `meta.connected` остаётся `true`,
пилюля показывает «● в сети», RTT/счётчики замирают. Команды пользователя уходят в канал, где
их никто не читает, — молча.

**Влияние.** Ложное состояние интерфейса, ведущее к неверной эксплуатации: пользователь считает
туннель работающим, а трафик не идёт; при этом «переподключить» нечем (поток мёртв). Для
embedded-TUI и для демона одинаково (демон в этом случае тоже не узнает, что движка нет:
`EngineBackend` держит `LocalEngine` и не проверяет потоки).

**Как проверить.** Тест: паникующий `TunDev::inject` (в `engine_e2e` уже есть `TestTun`) →
проверить, что через 2 с `snapshot().meta.connected` не станет `false` и событие об аварии не
придёт.

**Рекомендация.** Хранить `JoinHandle` потоков `rx`/`engine` и в `snapshot`/`Event`
отдавать признак «движок мёртв» (`JoinHandle::is_finished()`), как `healthy()` у сервера;
переводить `ConnState` в `DaemonDown`/офлайн и писать причину в лог.

---

### S3

---

#### DES-03 · Документация/статусы · **S3** · уверенность: высокая

**Evidence.** `docs/SECURITY.md:446` (риск №9) и `docs/SECURITY.md:494` (§17) объявляют
объединение рассылок списка групп **неподтверждённым**:

```
| 9 | Churn членства и рассылка списков групп создают нагрузку в пределах лимитов | ... | Лимит входов на группу, кулдаун повторного входа 3 с; объединение рассылок списка групп — ⏳ |
...
| Объединение рассылок списка групп | ⏳ | не подтверждено в коде |
```

Код: объединение **есть** и работает через `list_dirty`:

```rust
// crates/server/src/lib.rs:1781-1783 (housekeeping)
        if sh.list_dirty.swap(false, Ordering::Relaxed) {
            broadcast_group_list(&sh);
        }
// crates/server/src/lib.rs:3330-3351
/// GROUP_LIST всем сессиям — из housekeeping по `list_dirty`, под
/// блокировкой на чтение: команда (JOIN, LEAVE, CREATE…) стоит O(1) рассылок
/// за период, а не по одной на команду, и релей не ждёт её под записью.
fn broadcast_group_list(sh: &Shared) {
```

Других отправителей `ctrl::GROUP_LIST` вне тестов нет (`lib.rs:3322` — хелпер
`push_group_list` для одной сессии, `lib.rs:3344` — внутри `broadcast_group_list`;
остальные вхождения — в `#[cfg(test)] mod tests`, начиная с `lib.rs:4950`).
`docs/ARCHITECTURE.md:778` при этом ставит тот же пункт в плюс: «Список групп рассылается
раз в 2 с по флагу | Одна команда не разносит N кадров по всем сессиям | Задержка обновления
списка до 2 с».

**Сценарий.** Аудитор/оператор читает `SECURITY.md` §15/§17 как источник истины о контролах и
считает, что защиты от churn-рассылки нет; при этом `ARCHITECTURE.md` утверждает обратное.

**Влияние.** Два нормативных документа противоречат друг другу в оценке **существующего**
контроля; §17 вводит в заблуждение при подготовке к эксплуатации (можно начать «оптимизировать»
уже сделанное) и обесценивает статус-таблицу целиком: если ⏳ стоит на сделанном, то ✅ больше
ничего не доказывает.

**Как проверить.** `grep -n 'GROUP_LIST' crates/server/src/lib.rs` — единственный не-тестовый
отправитель — `broadcast_group_list`; тест `lib.rs:5481` уже проверяет объединение
(`filter(|t| **t == ctrl::GROUP_LIST)`).

**Рекомендация.** Перевести §15 №9 и §17 в ✅ с указанием `list_dirty`/`broadcast_group_list`;
в §17 добавить правило «статус ⏳ обязан иметь ссылку на файл:строку, где контроля нет» — иначе
таблица дрейфует (см. DES-04).

---

#### DES-04 · Документация/верификация · **S3** · уверенность: высокая

**Evidence.** `docs/STAGE9_VERIFICATION.md` — акт приёмки этапа 9, ссылается на строки кода как
на доказательства. Якоря **устарели** относительно `c0689fc`:

| Документ утверждает | Фактически в дереве | Δ |
|---|---|---|
| `server/lib.rs` `handle_datagram:1726` (`STAGE9_VERIFICATION.md:85`) | `fn handle_datagram` — `lib.rs:2079` | +353 |
| `server/lib.rs` `handle_mutation:3415` (`:85`) | `fn handle_mutation` — `lib.rs:3866` | +451 |
| «вызов из `relay_group` — `server/lib.rs:1832`» (`:146`) | `relay_group` — `lib.rs:2138`, вызов `federation::relay_for_peer` — `lib.rs:2188-2190` | +356 |

Счёт тестов расходится в трёх местах: `docs/STAGE9_VERIFICATION.md:43,50,56-62` — **565**
(с таблицей по крейтам: protocol 84, server 103, client 316, ipc 9, daemon 18, winsvc 15, tray 20);
`README.md:14,260` и `docs/TESTING.md:26` — **695**; `grep '#\[test\]'` по дереву — **752**
(protocol 89, server 136, client 417, ipc 30, daemon 43, winsvc 16, tray 21).

**Сценарий.** Рецензент приёмки идёт по якорям `STAGE9_VERIFICATION.md`, попадает в посторонний
код и делает вывод «доказательство не найдено» (или, наоборот, «всё на месте», не заметив
подмены). Числа 565/695/752 не сходятся между собой, и ни одно не воспроизводится из документа
командой без запуска cargo.

**Влияние.** Акт приёмки нефальсифицируем: его доказательства нельзя проверить, не переоткрывая
всё заново. Это ровно тот «дрейф спеки, ведущий к неверной эксплуатации», из-за которого
статус «PASS» перестаёт что-либо значить для следующих этапов.

**Как проверить.** `grep -n 'fn handle_datagram\|fn handle_mutation\|fn relay_group'
crates/server/src/lib.rs` (2079/3866/2138) и `grep -c '#\[test\]'` по крейтам.

**Рекомендация.** В `STAGE9_VERIFICATION.md` заменить абсолютные номера строк на **имена
символов** (`handle_mutation`, `relay_group`), а числа тестов брать из артефакта гейта (лог
`cargo test --list`), а не вписывать руками; в `docs/TESTING.md` зафиксировать одну процедуру
счёта и одну цифру, которую обновляют README-бейдж, STAGE9 и `voidlink-docs`.

---

#### DES-05 · Структурное качество · **S3** · уверенность: высокая

**Evidence.** Одна функция обрабатывает **все** мутирующие ctrl-команды сервера:
`crates/server/src/lib.rs:3866-4580` — 715 строк, 22 `match`-arm'а (STATUS, CANDIDATES,
PRESENCE, MESH_INFO, SERVER_HINT, JOIN_FED, CREATE_GROUP, JOIN_GROUP, LEAVE_GROUP, GROUP_ATTACH,
INVITE, DECLINE_INVITE, FRIEND_REQ, FRIEND_ACCEPT, FRIEND_DECLINE, FRIEND_REMOVE, KICK|BAN,
UNBAN, TRANSFER_OWNER, RENAME_GROUP, DELETE_GROUP):

```rust
// crates/server/src/lib.rs:3866-3878
fn handle_mutation(
    sh: &Shared,
    s: &mut State,
    src: SocketAddr,
    typ: u8,
    payload: &[u8],
    out: &mut Outbox,
) -> Result<()> {
    let (me, uname, ustatus) = {
        let x = &s.sessions[&src];
        (x.ed_pub, x.name.clone(), x.status.clone())
    };
    match typ {
```

Arm'ы — от 15 до 90 строк (`JOIN_GROUP` 4021-4132 = 112 строк, `KICK|BAN` 4421-4487,
`CREATE_GROUP` 3963-4020). Рядом — столь же крупные `handle_query` (96 строк) и
`on_ctrl`/`do_cmd` в клиенте (366/348 строк, `client/src/engine.rs`).

**Сценарий.** Новая команда или правка одной команды требует редактирования функции, которую
никто не читает целиком; тест одной команды невозможен без сборки `Shared`+`State`+`Outbox`
(в тестах это ~30 строк подготовки, `lib.rs:4613 empty_state`), поэтому покрытие растёт
медленнее кода (ср. DES-04: у `server` 136 `#[test]` на 8 407 строк).

**Влияние.** Риск регрессии в чужих командах при правке одной; невозможность точечного
ревью (диффы на 700-строчную функцию); отсутствие границы «команда = функция» мешает и
трассировке «команда → тест» (что и видно в DES-04).

**Как проверить.** `awk`-обмер длин функций (мой прогон: `handle_mutation` 713 строк —
единственная функция >200 строк в `server/lib.rs`); `git log -L` по функции покажет частоту
правок в неё.

**Рекомендация.** Разнести arm'ы в `fn cmd_join_group(...)`/`cmd_create_group(...)` в
`crates/server/src/mutations/` (модуль уже есть у `federation.rs`/`friends.rs`), оставив в
`handle_mutation` только диспетчеризацию (`match typ { JOIN_GROUP => cmd_join(...), ... }`).
Сигнатура `(sh, s, src, me, payload, out) -> Result<()>` уже готова к такому разрезу.

---

#### DES-06 · Блокировки/ввод-вывод · **S3** · уверенность: высокая

**Evidence.** Запись `client.json` на диск выполняется **под** `Mutex<Config>` на потоке
движка:

```rust
// crates/client/src/engine.rs:1529-1533
    fn update_cfg(&self, f: impl FnOnce(&mut Config)) {
        let mut cfg = self.cfg.lock().unwrap();
        f(&mut cfg);
        (self.save)(&cfg);
    }
// crates/client/src/engine.rs:2744-2745
        cfg.friends = next.friends;
        (env.save)(&cfg);
```

`save` — это `Store::save`, то есть `fs::write` + `fs::rename`
(`crates/client/src/store.rs:396-401`):

```rust
    pub fn save(&self, cfg: &Config) -> Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(cfg)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
```

Тот же `Mutex<Config>` берут: сборщик снимка (`api.rs:150 CfgView::from_cfg(&lock(&self.cfg))`)
— то есть TUI/хаб ждут этот лок каждый кадр/тик; и путь рукопожатия
(`engine.rs:2291-2298 pinned_server_key`).

Для контраста: демон в том же сценарии делает правильно — клонирует под локом и пишет вне его
(`crates/daemon/src/engine_backend.rs:487-492`).

**Сценарий.** Windows-антивирус/индексатор задерживает `fs::write`/`rename` на 1–3 с (типовая
задержка на `client.json` при активном сканере). В это время: поток `engine` не тикает (не
шлёт `CTRL_PING` раз в 5 с, не обрабатывает команды, не переподключается), а embedded-TUI не
может построить снимок (`CfgView::from_cfg` ждёт тот же лок) — интерфейс замирает.

**Влияние.** Замирание UI и таймеров движка на время дискового вызова; при задержке >20 с
(`SERVER_TIMEOUT`) сервер успевает истечь сессию — туннель падает «сам». Нарушено собственное
правило проекта «ответы и I/O — после снятия блокировки» (`ARCHITECTURE.md:610-620`), которое
для сетевой отправки соблюдается, а для диска — нет.

**Как проверить.** Тест с `save`-колбэком, который спит 2 с: измерить, за сколько тиков движок
перестаёт слать `CTRL_PING`; в embedded-TUI — за сколько кадров обновляется снимок.

**Рекомендация.** Как в демоне: под локом только клонировать `Config`, писать после
`drop(guard)`; в идеале — отдельный поток записи с коалесингом (dirty-флаг + 200–500 мс), чтобы
частые `FRIEND_LIST` не писали файл на каждое изменение.

---

#### DES-07 · Модель блокировок/отравление · **S3** · уверенность: высокая

**Evidence.** Политика обработки отравленных (`poisoned`) локов в проекте **двух видов** и
выбрана по файлу, а не по правилу. Клиент местами восстанавливается:

```rust
// crates/client/src/path.rs:451
        let p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
// crates/client/src/api.rs:97-99
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
```

Сервер — нигде: `crates/server/src/lib.rs` содержит 92 `lock()/read()/write().unwrap()`
(в т.ч. `save_now`: `lib.rs:1682` `*sh.written.lock().unwrap()`, `lib.rs:1691`
`sh.state.read().unwrap()`), клиентский `engine.rs` — 146.

**Сценарий.** Одна паника в любом воркере, держащем `RwLock<State>` на запись (а под ним
исполняется `handle_mutation` с индексациями вида `s.sessions[&src]`, `lib.rs:3875`),
отравляет лок. После этого **каждый** последующий `state.read().unwrap()` паникует: воркеры
умирают один за другим, `housekeeping` тоже (он читает состояние в `save_now`/
`refresh_gauges`), сервер перестаёт отвечать, но процесс остаётся жив и слушает сокет.

**Влияние.** Одна паника превращается в полный отказ сервера (каскад), вместо локализации
одного кадра. При этом `/healthz` (если включён) покажет «нездоров», но ничего не
перезапустит (см. DES-02 про отсутствие супервизии) — оператор видит живой процесс и мёртвый
сервис.

**Как проверить.** Тест: `std::panic::catch_unwind` вокруг `state.write()` с паникой, затем
`state.read()` — увидеть панику во втором вызове; сравнить с `PathTable` (там
`into_inner`).

**Рекомендация.** Выбрать одно правило и применить везде: либо хелпер
`fn state(&self) -> MutexGuard<'_, State>` с `unwrap_or_else(|e| e.into_inner())` (состояние
сервера консистентно на уровне отдельных структур — отравление там не несёт смысла), либо
осознанная политика «паника = останов процесса» с `std::process::abort` и рестартом службой.
Смешение двух политик — худший вариант: неясно, что произойдёт.

---

#### DES-08 · Интерфейс CLI/документация · **S3** · уверенность: высокая

**Evidence.** Пользовательский `--help` и доки говорят «протокол v3», код — v4:

```rust
// crates/client/src/main.rs:1277-1280
fn usage() {
    println!(
        r#"tunnel-client (протокол v3) — Hamachi-подобный VPN
```

`crates/protocol/src/lib.rs:64`: `pub const PROTOCOL_VERSION: u8 = 4;`.
Те же «v3» — в `crates/client/src/lib.rs:1` («Клиент туннеля (протокол v3) как библиотека»),
`crates/client/src/main.rs:1`, `docs/CLIENT.md:850` («PROTOCOL.md: протокол v3, которым клиент
и сервер обмениваются»), `docs/DAEMON.md:94` («движок … протокол v3»).

**Сценарий.** Пользователь сверяет версию клиента с версией сервера по `--help`/докам,
видит v3 и делает неверный вывод о совместимости (v3-клиенты сервер отвергает:
`handshake.rs:287 ensure!(version == PROTOCOL_VERSION, ...)`).

**Влияние.** Ложная информация о протоколе в первой строке `--help` — самой читаемой строке
инструмента; расхождение с `PROTOCOL.md`/`GLOSSARY.md` (v4) создаёт впечатление, что часть
документации описывает другой продукт.

**Как проверить.** `grep -rn 'протокол v3' crates/ docs/*.md` — 5 вхождений, все против
`PROTOCOL_VERSION = 4`.

**Рекомендация.** Убрать номер из `usage()` (или подставлять `PROTOCOL_VERSION` через
`format!`), поправить 4 оставшихся места; в `voidlink-docs` добавить проверку «версия
протокола в тексте = `PROTOCOL_VERSION`».

---

#### DES-09 · Интерфейс CLI · **S3** · уверенность: высокая

**Evidence.** Ошибка сетевых команд друзей предлагает заведомо неработающий выход:

```rust
// crates/client/src/main.rs:811-826
        "add-friend" => {
            ...
            let _code = rest.first().context("usage: add-friend <code> [alias]")?;
            bail!(
                "заявка в друзья отправляется через сервер — нужен запущенный движок \
                 (tunnel-client run или демон TunnelDaemon); без связи она не дойдёт"
            );
        }
        // Ответ на входящую заявку — тоже сетевой кадр.
        "accept-friend" | "decline-friend" | "remove-friend" => bail!(
            "команда {cmd:?} отправляется через сервер — нужен запущенный движок \
             (tunnel-client run или демон TunnelDaemon)"
        ),
```

Но `tunnel-client run` не обслуживает CLI-команды: он держит замок single-instance, и
следующий вызов упирается в `LOCKED_MSG` (`crates/client/src/remote_cli.rs:33-34`,
`main.rs:340-348`):

```rust
pub const LOCKED_MSG: &str = "движок уже запущен без демона (embedded TUI или `run`): закройте TUI / остановите run \
или установите службу — свой HELLO этой команды вытеснил бы его сеанс";
```

**Сценарий.** Пользователь без службы читает совет «нужен `tunnel-client run`», запускает
`run`, повторяет команду — получает `LOCKED_MSG` «остановите run». Цикл без выхода; работает
только установка демона, о которой сообщение говорит вскользь.

**Влияние.** Пользователь выполняет предписанное действие и получает отказ с противоположным
советом — «интерфейс врёт» в самом чувствительном месте (первый запуск, друзья).

**Как проверить.** `tunnel-client run` в одном терминале, `tunnel-client add-friend <code>` в
другом (нужен адаптер/админ — либо прочитать ветки `main.rs:340-348` + `remote_cli.rs:33`).

**Рекомендация.** Текст: «…нужен **демон** (`tunnel-daemon install` / `tunnel-daemon console`);
`run` эти команды не обслуживает». Заодно `usage()` (`main.rs:1296-1299`) должен помечать
команды друзей как «только через демон».

---

#### DES-10 · IPC/устойчивость · **S3** · уверенность: высокая

**Evidence.** IPC-сервер демона принимает **неограниченное** число соединений, на каждое —
поток и (после `subscribe`) очередь в 256 сообщений:

```rust
// crates/daemon/src/server.rs:270-296
fn accept_loop<B: Backend + 'static>(hub: Arc<Hub<B>>, listener: Listener, sh: Arc<Shared>) {
    let mut errors = 0u32;
    loop {
        let conn = listener.accept();
        ...
        if let Err(e) = spawn_conn(&hub, conn, &sh) {
            sh.log(Level::Warn, &format!("IPC: соединение не принято: {e}"));
        }
    }
}
```

`crates/daemon/src/hub.rs:35` `pub const DEFAULT_QUEUE: usize = 256;`, подписка создаёт
`mpsc::sync_channel(queue.max(1))` и `Sub` в векторе (`hub.rs:156-189`). Счётчика/лимита
соединений нет ни в `server.rs`, ни в `hub.rs` (`pub fn subscribers()` — только чтение).

**Сценарий.** Локальный пользователь машины (пайп выдаёт доступ по SID владельца —
`docs/SECURITY.md:396-398`: «любой процесс этого пользователя может говорить с демоном»)
открывает N соединений и на каждом шлёт `hello`+`subscribe`. На каждое: поток (`ipc-conn-{id}`)
+ 256-слотовый канал + запись в `conns`; каждое получает поток событий/снимков.

**Влияние.** Истощение памяти привилегированной службы `LocalSystem` → падение туннеля у всех
пользователей машины (и, при автозапуске, повторение). Предусловие: локальный доступ к машине
(не сеть), поэтому это не RCE, но отказ в обслуживании службы. В §15 это не отражено.

**Как проверить.** Скрипт: 500 подключений к пайпу с `hello`+`subscribe`, замерить RSS
`tunnel-daemon`.

**Рекомендация.** Жёсткий лимит одновременных соединений (например, 16) и подписчиков (8) с
`reject`/закрытием сверх лимита; счётчик в лог и в `/healthz`-аналог демона.

---

### S4

---

#### DES-11 · Документация · **S4** · уверенность: высокая

**Evidence.** `docs/ARCHITECTURE.md:805-807` в «Ограничениях»:

```
- **Сон и пробуждение.** Служба должна делать немедленный HELLO после
  выхода из сна (`POWEREVENT`); для этого в демоне есть `ResumeSignal`, но
  подключение к движку службы зависит от подключения движка к `service`.
```

Код: связка **есть** — `crates/daemon/src/service.rs:406` (`ServiceEvent::Resume =>
resume.raise()`), `crates/daemon/src/engine_backend.rs:529-536` (`ResumeSignal::take` →
`b.send(Cmd::Reconnect)`), `crates/winsvc/src/service.rs:98-101` (POWEREVENT →
`ServiceEvent::Resume`). Тест есть: `service.rs:601-634` («resume не дошёл» — проверка
таймаута).

**Сценарий/влияние.** Оператор читает «не подключено» и считает, что после сна туннель
восстанавливается только по 20-секундному таймауту, хотя реконнект немедленный; ограничение
числится в списке открытых вопросов, который иначе пуст.

**Как проверить.** `grep -n 'ResumeSignal\|Cmd::Reconnect' crates/daemon/src/*.rs`.

**Рекомендация.** Перенести пункт из «Ограничений» в §8 (реализовано) со ссылкой на
`engine_backend.rs:529`.

---

#### DES-12 · Архитектура/документация · **S4** · уверенность: высокая

**Evidence.** `docs/ARCHITECTURE.md:86-92` — граф зависимостей, в котором у клиента только
`protocol` (и dev-dep `server`):

```
    server --> protocol
    client -. dev-dependency, e2e .-> server
    client --> protocol
    daemon --> ipc
    daemon --> client
```

Фактически `crates/client/Cargo.toml:18`: `tunnel-ipc = { path = "../ipc" }` — обычная
(не dev) зависимость; клиент использует её в `remote.rs`/`remote_cli.rs`.

**Сценарий/влияние.** Граф занижает связность: изменение `tunnel-ipc` пересобирает и клиент, и
демон, и трей; читатель §2 делает вывод, что IPC-контракт касается только демона/трея.

**Как проверить.** `grep -n tunnel- crates/*/Cargo.toml`.

**Рекомендация.** Добавить `client --> ipc` в mermaid и в текст §2 («клиент носит IPC-клиент для
тонкого режима»).

---

#### DES-13 · IPC/документация · **S4** · уверенность: высокая

**Evidence.** `docs/ARCHITECTURE.md:701`: «`Welcome{proto, daemon_ver, me}` или `Reject` —
Ответ на Hello; **при несовпадении мажорной версии** — закрытие». В коде понятия «мажорная
версия» нет — сравнивается весь `u32` на равенство:

```rust
// crates/ipc/src/proto.rs:78-89
pub fn check_hello(proto: u32) -> Result<(), DaemonMsg> {
    if proto == PROTO_VERSION {
        Ok(())
    } else {
        Err(DaemonMsg::Reject {
            reason: format!(
                "несовместимая версия IPC: клиент {proto}, демон {PROTO_VERSION} — обновите tunnel-client / демон"
            ),
        })
    }
}
```

**Сценарий/влияние.** Добавление поля в IPC-сообщение без смены `PROTO_VERSION` безопасно
(serde игнорирует лишние поля — `docs/IPC.md:247`), но **любое** изменение числа рвёт связь
целиком; читатель §8 ожидает совместимость в пределах мажорной версии и может поставить
несовместимый TUI к демону, рассчитывая на деградацию.

**Как проверить.** `grep -n 'PROTO_VERSION' crates/ipc/src/proto.rs`.

**Рекомендация.** Либо ввести major/minor (`proto >> 16`), либо исправить формулировку §8:
«точное совпадение `PROTO_VERSION`; добавление полей совместимо, изменение — нет».

---

#### DES-14 · Эволюция протокола/дублирование констант · **S4** · уверенность: высокая

**Evidence.** Один инвариант «время жизни mesh-контакта» живёт в четырёх константах трёх
модулей и нигде не проверяется на согласованность:

```rust
// crates/server/src/lib.rs:2271
const MESH_TTL_MS: u64 = 15 * 60 * 1000;
// crates/client/src/dht.rs:45
pub const TTL_MS: u64 = 15 * 60 * 1000;
// crates/client/src/mesh.rs:59
pub const INFO_EVERY_MS: u64 = 5 * 60 * 1000;
// crates/client/src/engine.rs:68
const MESH_INFO_EVERY: Duration = Duration::from_secs(5 * 60);
```

Плюс два независимых определения одного интервала в одном крейте (`mesh::INFO_EVERY_MS` и
`engine::MESH_INFO_EVERY`) — оба используются (`mesh.rs:1150`, `engine.rs:3492`).

**Сценарий/влияние.** Если `MESH_TTL_MS` уменьшат ниже периода `MESH_INFO`, публикации начнут
истекать между обновлениями: сервер молча перестанет раздавать контакт в `MESH_SEED`, mesh
деградирует без ошибок и логов; тест этого не заметит, потому что связь «TTL > период» нигде не
зафиксирована. `docs/ARCHITECTURE.md:350` дублирует значение словами («5 мин»).

**Как проверить.** `grep -rn 'MESH_TTL\|INFO_EVERY' crates/ docs/`; теста-инварианта нет.

**Рекомендация.** Перенести обе константы в `tunnel-protocol` (mesh-раздел) и добавить
`debug_assert!(MESH_TTL_MS > 3 * INFO_EVERY_MS)` + юнит-тест; в клиенте оставить одну
константу вместо двух.

---

#### DES-15 · Проектирование отказов/backpressure · **S4** · уверенность: высокая

**Evidence.** Ошибка инжекта пакета в адаптер не считается и почти не видна:

```rust
// crates/client/src/engine.rs:5689-5694
        (proto::grp::DATA, _) => {
            if let Err(e) = env.tun.inject(&payload)
                && debug()
            {
                env.emit(Event::Error(format!("inject: {e}")));
            }
        }
```

На Windows `inject` — `allocate_send_packet` (`engine.rs:1281-1289`), который отказывает, когда
кольцо Wintun заполнено. Ни счётчика дропов, ни повтора, ни метрики; сообщение — только при
`--debug`.

**Сценарий/влияние.** При всплеске входящего трафика (или медленном приложении-получателе)
пакеты теряются, и ни UI, ни `stats` этого не показывают: «потери» видны только как провал
скорости. Диагностика «почему ping теряется» упирается в отсутствие счётчика.

**Как проверить.** Тест: `TestTun`, возвращающий `Err` на `inject`, — проверить, что
`stats`/снимок не меняются и событие не приходит без `debug`.

**Рекомендация.** `stats.inject_dropped: AtomicU64`, поле в `StatsSnap` и в карточке
диагностики; первое событие в лог без `debug`.

---

#### DES-16 · Модель блокировок/документация · **S4** · уверенность: высокая

**Evidence.** Для сервера порядок захвата локов задокументирован явно
(`crates/server/src/lib.rs:1017-1021`: «Порядок блокировок: `state` → `fed` … `fed` никогда не
удерживается при взятии `state`»), а для клиента `docs/ARCHITECTURE.md:591-609` перечисляет
состояния и их защиту, но **не задаёт порядок**. Порядок существует только в комментарии кода:

```rust
// crates/client/src/engine.rs:5317
    // uuid из FED_GROUPS — до блокировки групп (порядок блокировок везде
```

Фактический порядок, который я проверил: `Groups` → `Paths` (`paths_round`,
`engine.rs:3363-3374`: под `groups.lock()` вызывается `env.paths.ensure_target`;
`snapshot_now` → `GroupSnap::from_groups` → `PeerSnap::from_sess` → `paths.current`), `state` →
`session-mutex` (`lib.rs:3700-3734`), `state` → `fed` (`federation.rs:1523-1547`).

**Сценарий/влияние.** Новый код (например, «прочитать `Paths`, потом `Groups`») не нарушит
ни одного записанного правила — правила нет; инверсия даст дедлок, который воспроизводится раз в
сутки под нагрузкой. У сервера такой риск закрыт комментарием-контрактом, у клиента — нет.

**Как проверить.** `grep -n 'порядок блокировок' crates/ docs/` — 4 упоминания, все в
комментариях кода; в `docs/ARCHITECTURE.md` — ноль.

**Рекомендация.** Добавить в §7 подраздел «Порядок захвата (клиент): `Groups` → `Paths`,
`Groups` → `Meta`, `Config` — только листом» и `debug`-ассерт/комментарий в местах, где
берутся два лока.

---

#### DES-17 · IPC-контракт · **S4** · уверенность: высокая

**Evidence.** `docs/IPC.md:289-296` требует от клиента вести `last_seq` и детектировать
пропуски (правила 3–6). Единственный первопартийный потребитель — `IpcEngine` — `seq`
игнорирует полностью:

```rust
// crates/client/src/remote.rs:398-410
            match c.recv(Some(POLL)) {
                Ok(DaemonMsg::Event { ev, .. }) => {
                    if let Ok(e) = serde_json::from_value::<Event>(ev) {
                        sh.push(e);
                    }
                }
                Ok(DaemonMsg::Snapshot { snap, .. }) => {
                    let editable = snapshot_editable(&snap);
                    if let Ok(s) = parse_snapshot(snap) {
                        *lock(&sh.snap) = Arc::new(s);
```

(`seq` связан в `..`.) `docs/IPC.md:592` это фактически признаёт («для правил seq `IpcClient`
ничего не делает: их нужно реализовать в интерфейсе»), но правила 3–6 остаются нереализованными
и в `IpcEngine`.

**Сценарий/влияние.** При переполнении очереди подписчика TUI теряет события без пометки: лента
событий (единственное, что строится из `Event`) показывает дырку как обычную
последовательность, а правило 5 («не применять события до снимка») не соблюдается. Состояние
экрана при этом корректно (оно из снимков раз в секунду), поэтому влияние ограничено лентой/логом
и диагностикой — но контракт и реализация расходятся.

**Как проверить.** Тест: подписка с очередью 2, 10 событий — проверить, что `IpcEngine`
сообщает о пропуске (сейчас — нет).

**Рекомендация.** Либо реализовать `last_seq`/`gap` в `IpcEngine` (10 строк) и показывать
«⏳ состояние могло устареть» в бейджах, либо понизить правила 3–6 в `IPC.md` до
«рекомендация для сторонних фронтендов» и убрать слово «минимально корректный клиент».

---

#### DES-18 · Интерфейс CLI · **S4** · уверенность: высокая

**Evidence.** `del-friend` ищет друга только по `alias`, тогда как `alias`/`invite`/`kick`
используют общий резолвер (`store::resolve_peer`: alias | friend code | hex):

```rust
// crates/client/src/main.rs:827-833
        "del-friend" => {
            let alias = rest.first().context("usage: del-friend <alias>")?;
            let before = cfg.friends.len();
            cfg.friends.retain(|f| &f.alias != alias);
            if cfg.friends.len() == before {
                bail!("друг {alias:?} не найден");
            }
```

`usage()` при этом обещает `del-friend <имя>` (`main.rs:1300`), а `docs/CLIENT.md:307` —
`del-friend <имя>`.

**Сценарий/влияние.** Пользователь, привыкший, что `peer` везде = code|hex|alias
(`main.rs:1315`), делает `del-friend TUN-XXXX` и получает «не найден», хотя друг есть (у него
пустой alias). Ложное «не найден» — мелкая, но повторяющаяся эргономическая ошибка.

**Как проверить.** Друг с пустым alias → `del-friend <code>` → «не найден».

**Рекомендация.** Использовать `store::resolve_peer` и удалять по pubkey (как `alias`/`invite`).

---

## 4. Проверено — находок нет

Ниже — проверки, которые **могли** дать находку и не дали; перечислены, чтобы был виден охват.

1. **Граф зависимостей без циклов и без протечки серверных типов в клиент.** `tunnel-server`
   не зависит ни от чего, кроме `protocol`; `client` зависит от `server` **только** как
   dev-dependency (`crates/client/Cargo.toml:38`) и только в `#[cfg(test)]`-модулях
   (`crates/client/src/lib.rs:9-10,17-18`: `#[cfg(test)] mod engine_e2e;`, `#[cfg(test)]
   mesh_e2e;`); в не-тестовом коде клиента `tunnel_server` не встречается. `tunnel-ipc` —
   лист (только serde), поэтому `client → ipc` и `daemon → client` цикла не дают. Единственный
   дефект этой линии — документация (DES-12).
2. **Порядок `state` → `fed` не нарушен, инверсий нет.** `federation::on_session_frame`
   снимает снимок состояния **до** `fed` с явным комментарием (`federation.rs:1427-1434`),
   `reconcile` берёт `state`, отпускает, потом `fed` (`:1533-1547`), `on_hint` под
   `state.write()` (вызов из `handle_mutation`, `lib.rs:3953-3957`) порождает только
   `Info`/`Reject`/`Send` (`federation.rs:480-532`), а `apply` для них не берёт
   `state` (`federation.rs:1343-1375`) — дедлока по этому пути нет. Проверял прицельно,
   потому что это был главный кандидат в S1.
3. **«Отправка после снятия лока» соблюдается на горячих путях.** `relay_group` собирает
   адрес под `state.read()` и отправляет после блока (`lib.rs:2144-2200`); `flush` вызывается
   вне блокировки (`lib.rs:3766`); `route_packet` держит `Groups` только на выбор ключа и
   отправляет после (`engine.rs:5751-5763`); `paths_round` копит `PathChange` и шлёт события
   после лока (`engine.rs:3375-3415`); `snapshot_now` берёт локи последовательно, без
   вложений (`api.rs:146-158`).
4. **`Groups` → `Paths` — единственный порядок.** Обратного (`Paths` → `Groups`) нет: методы
   `PathTable` не знают про `Groups`, а все вызовы из-под `groups.lock()`
   (`engine.rs:3364-3373`, `snapshot.rs:100-130`) идут в эту сторону.
5. **Контракт снимков хаба соответствует `docs/IPC.md`.** `seq` с 1, без повторов
   (`hub.rs:214-221`); кольцо 500 (`hub.rs:31,217-220`); снимок раз в секунду и по изменению
   (`hub.rs:233-241`); переполнение → `need_snapshot`, события не шлются, снимок досылается
   (`hub.rs:295-312`); снимок строится вне мьютекса хаба (`hub.rs:250-252`); `seq` снимка —
   последний учтённый (`hub.rs:211-241,256`). Кэш снимка может быть старее истории при
   подписке — но правило «состояние берётся из снимка» (`IPC.md:291-292`) это допускает.
6. **Форвард-совместимость JSON-слоёв.** Ни в `ipc`, ни в `tray`, ни в `snapshot` нет
   `deny_unknown_fields` (`grep` по `crates/` — 0), лишние поля игнорируются, как обещает
   `docs/IPC.md:247`; `Snapshot` и `Cmd` — один и тот же тип из `tunnel-client`, поэтому
   дрейфа «демон/клиент» в снимке нет по построению.
7. **Расширение `GROUP_STATE`/`GROUP_UPDATE` mesh-хвостом спроектировано как data-extension, а
   не как смена версии** — `payloads.rs:129-155`: хвост начинается с `MESH_MAGIC`, при чужом
   magic возвращается пустой вектор («чужое будущее расширение — mesh-метаданных нет»), т.е.
   старый клиент и старый сервер совместимы без `PROTOCOL_VERSION`. `PROTOCOL_VERSION = 4`
   (`protocol/src/lib.rs:64`) и exact-match в HELLO3/CHALLENGE/WELCOME
   (`handshake.rs:287,337,464`) — согласовано с §9 «новые возможности не меняют версию».
   `FED_VER = 1` с маской (`protocol/src/federation.rs:79-81,269`) — то же решение для
   федерации.
8. **`save_now` и трёхсекундный цикл соответствуют описанию.** `SAVE_EVERY = 3 с`
   (`lib.rs:71,1793-1796`), срочные сохранения через `Condvar` + `URGENT_SAVE_GAP = 200 мс`
   (`lib.rs:78,1153-1155,1736-1759`), `LOAD_MARGIN = 1<<16` (`lib.rs:82`), блокировка файла
   и проверка смены ключа (`lib.rs:1673-1700,1706-1731`) — совпадает с §4/§9 и с
   `SECURITY.md` §15 №7/№8.
9. **`handle_mutation` не оставляет частичных мутаций на ошибке** там, где я смотрел:
   в `JOIN_GROUP` (`lib.rs:4021-4132`) и `CREATE_GROUP` (`3963-4020`) все `?`/`ensure!`
   стоят **до** первой записи в `State`. Это дисциплина, а не гарантия типа (см. §5, гипотеза
   H-2), но дефекта в проверенных arm'ах нет.
10. **Отсутствие супервизии на сервере частично компенсировано**: `Alive` (декремент в `Drop`,
    в т.ч. при панике) + `healthy()` (`alive == expected_threads`, свежесть `last_tick`,
    `lib.rs:1026-1043`) → `/healthz`; перезапуска нет, но сигнал есть. У клиента аналога нет —
    это и есть DES-02.
11. **Упаковка Windows: `vendor/wintun` не пуст.** `wintun.dll` (427 552 байта, git blob
    `aee04e7`) копируется `build.rs` рядом с exe, `install.ps1:29` кладёт его в
    `%ProgramFiles%\Tunnel`, служба грузит его из `current_exe().parent()`
    (`tun.rs:9-25`) — путь согласован с `docs/INSTALL.md:94-98`. MSI в дереве отсутствует, но
    `PLAN.md:551,818,825` честно помечает его ⏳ — дрейфа нет.
12. **IPC-пайп: проверки на стороне клиента есть** (`ipc/transport/windows.rs:8-16`,
    `332,387-430`: `GetNamedPipeServerProcessId` + сверка SYSTEM/повышенный процесс того же
    пользователя, `PIPE_REJECT_REMOTE_CLIENTS`, `FIRST_PIPE_INSTANCE`) — совпадает с
    `ARCHITECTURE.md:727-734` и `SECURITY.md` §13. Лимит кадра 1 МиБ — `codec.rs:10`.
13. **Офлайн-очередь не теряет правки при перезапуске TUI** (атомарная запись
    `tmp+rename`, `offline.rs:90-100`, `TUI.md:419-429`) — кроме проблемы адресации из DES-01.

---

## 5. Гипотезы и вопросы к владельцу

Гипотезы — то, что **не подтверждено** кодом или требует прогона. В находки не включено.

- **H-1. `Save`-`запись` под локом на Windows может быть заметно дороже, чем в Linux-тестах.**
  Все e2e-тесты гоняются на `TestTun` и `Arc<dyn Fn(&Config)>`-заглушке (`engine_e2e.rs:63`,
  `Arc::new(|_| {})`), поэтому DES-06 в тестах не воспроизводится в принципе. Нужен прогон на
  Windows с реальным `client.json` и включённым антивирусом — это запрос к ведущему (Linux-хост).
- **H-2. Атомарность мутаций держится на дисциплине, а не на типах.** В проверенных arm'ах
  (`JOIN_GROUP`, `CREATE_GROUP`) порядок правильный, но `handle_mutation` получает
  `&mut State` и `?:` любая новая команда, записавшая в состояние до проверки, оставит
  половину изменений — `report` (`lib.rs:3769-3775`) отправит клиенту ERROR, а `dirty`
  выставится (`lib.rs:3754`) и половина уйдёт на диск. Вопрос: нужен ли `debug`-ассерт
  «мутация после первого `?` запрещена» или ревью-правило.
- **H-3. `IpcEngine` при переподключении теряет снимок без пометки.** `remote.rs:364-369`:
  после реконнекта снимок заменяется целиком, `editable` обновляется, но признака «состояние
  могло устареть» (аналог `pending`) в снимке нет. Проверяемо тестом, влияние — секундное
  расхождение UI. Требует решения владельца: считать ли это нормой.
- **H-4. Число тестов 752 (grep) vs 695 (README/TESTING) vs 565 (STAGE9) — какое верно?**
  Мой счёт — прокси (`#[test]` по файлам), гейт не запускался. Вопрос: есть ли CI-артефакт с
  `cargo test --list`, на который можно ссылаться вместо ручных чисел (это же лечение DES-04).
- **H-5. `FRAG_MAX_PAYLOAD` = 281 600 байт (`frag.rs:15-19`) и «худший GROUP_STATE влезает»
  проверены тестами (`payloads.rs:1747,2217`), а «худший GROUP_LIST» — нет.** В release
  `push_ctrl` при превышении молча не отправляет сообщение (`lib.rs:2224-2233`: только
  `debug_assert!`, затем `if let Ok(Some(chunks))`). Считаю маловероятным (для 281 КБ нужны
  сотни групп с длинными именами), поэтому это гипотеза, а не находка. Вопрос: есть ли тест
  «GROUP_LIST худшего размера»?
- **H-6. `SYSTEM`-служба и `console` делят один пайп**; при остановленной службе
  `console` от администратора поднимает свой (`ARCHITECTURE.md:733-734`). Не проверял, что
  происходит с уже подключёнными фронтендами при такой смене владельца пайпа — по коду это
  выглядит как «TUI переподключится раз в 1 с» (`remote.rs:357`), но живой проверки нет.

Вопросы к владельцу (влияют на оценку находок):
1. `DelServer{idx}`/`SetPrimaryServer{idx}` в офлайн-очереди — сознательное упрощение
   (DES-01) или недосмотр? Если упрощение, нужно отразить в §9 `ARCHITECTURE.md`.
2. Клиент намеренно не имеет супервизии потоков (DES-02), или это ожидает реализации вместе с
   `POWEREVENT`/`service`?
3. Допустимо ли считать `SECURITY.md` §17 машиночитаемой таблицей (со ссылками
   файл:строка) — тогда дрейф ловится скриптом, а не аудитом (DES-03/DES-04).

---

## 6. Итог

**Состояние области.** Дизайн VoidLink заметно зрелее, чем можно ожидать от проекта такого
размера: границы крейтов выдержаны (серверные типы не протекают в клиент, e2e-связка живёт
только под `#[cfg(test)]`), правило «собираем под локом — отправляем после» соблюдается на всех
горячих путях, порядок `state` → `fed` задокументирован и **не нарушен** (главный кандидат в
S1 не подтвердился), контракт снимков хаба точно соответствует `docs/IPC.md` по `seq`, кольцу,
переполнению и моменту сборки снимка, а расширение протокола сделано data-extension'ом с magic,
а не сменой версии. Это инженерно сильные решения, и они держатся в коде, а не только в тексте.
Слабые места — не в крипто- и не в сетевой части, а в **наблюдаемости и в адресации состояния
между процессами**: у клиента нет способа узнать, что его собственный движок мёртв (DES-02), а
офлайн-очередь адресует правки позицией в чужом списке (DES-01). Это два S2, и оба — про то, что
интерфейс может говорить «всё хорошо», когда это не так.

**Главные риски.** Первый — «тихая смерть туннеля»: паника в потоке `rx`/`engine` (а
предпосылки для паники в этих файлах есть: 146 `lock().unwrap()` и индексации `State`) не
наблюдается никем, пилюля остаётся зелёной, команды уходят в мёртвый канал. Второй — «не тот
сервер»: офлайн-правки, отложенные на часы, применяются к конфигу демона по индексам, а
расхождение `%APPDATA%`/`%ProgramData%` на Windows — штатное. Третий, более мягкий, но
системный: документация перестала быть проверяемой — акт приёмки этапа 9 ссылается на строки,
сдвинутые на 350–450, три источника дают три разных числа тестов, `SECURITY.md` держит ⏳ на
реализованном контроле, а `--help` сообщает «протокол v3» при `PROTOCOL_VERSION = 4`. Пока
дрейф идёт «в безопасную сторону» (сделанное помечено как несделанное), это гигиена; но тот же
механизм уже один раз сработал в обратную сторону — и именно поэтому §17 перестаёт быть
доказательством.

**Что чинить в первую очередь.** (1) `last_seq`-подобный признак живости движка в снимке —
10–20 строк, снимает целый класс «ложного состояния»; (2) адресация офлайн-команд по
адрес+pubkey вместо индекса — правка на полдня, снимает «не тот сервер»; (3) одно правило
poison-политики (DES-07) — иначе каскадный отказ сервера остаётся вероятностным, но реальным;
(4) привести `STAGE9_VERIFICATION.md`/`SECURITY.md` §17/`README` к одному машиночитаемому
источнику чисел и имён символов вместо номеров строк.

**Ограничение этого отчёта.** Всё изложенное — статический анализ `c0689fc`; cargo-гейты,
e2e, живая Windows-служба и NAT-лаборатория не запускались (запрет в задании), поэтому
утверждения о поведении под нагрузкой (H-1, H-3, H-5) остаются гипотезами, а не находками.
