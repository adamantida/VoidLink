> **История (2026-11-28).** Документ не актуален и оставлен для истории: он описывает состояние на момент своего этапа, а не текущее. Актуальное — [README](../../README.md), [SERVER](../SERVER.md), [CLIENT](../CLIENT.md), [PROTOCOL](../PROTOCOL.md), [DEVELOPMENT](../DEVELOPMENT.md).

# Этап 9 — отчёт приёмки (T7)

Независимая проверка этапа 9: гейты качества, матрица пяти пунктов бэклога,
консистентность документации, безопасность/качество, остаточные риски.
Production-код не менялся; в ветке — только этот отчёт.

> **Переавторизация (T9).** Хэши коммитов в отчёте — до переписывания истории:
> содержимое коммитов не менялось, изменены только автор и коммиттер (все
> коммиты этапа — на профиле GitHub
> `SumalyFly <43584533+adamantida@users.noreply.github.com>`).

> **Исторический документ.** Это отчёт приёмки этапа 9 на коммите `bcbf457`
> (2026-11-20). Хэши коммитов, счёт тестов и ссылки `file:line` — снимок на дату
> приёмки; текущее состояние сверяйте с кодом и с `docs/PLAN.md`,
> `docs/TESTING.md`, `docs/CHANGELOG.md`. **Актуальный счёт тестов — 712 на
> Windows и 751 на Linux** (см. §1 [TESTING.md](../DEVELOPMENT.md) и раздел
> Unreleased в [CHANGELOG.md](../CHANGELOG.md)); число `565` ниже — значение на момент приёмки, а не
> текущее. Документ не переписывается: правки в него вносятся только как
> пометки.

| Параметр | Значение |
|---|---|
| Ветка / worktree | `stage9/90-verify`, `VoidLink-wt/90-verify` |
| База | `dev` = `bcbf457` (Merge T6; все T0–T6, T4c смержены) |
| HEAD проверки | `bcbf45781aebac80f70b8997ed55a6c04db4bb53`, рабочее дерево чисто |
| ОС / тулчейн | Windows 11 Pro build 26300; rustc 1.100.0 (0ef1bc386), cargo 1.100.0 |
| Дата | 2026-11-20 |

## 0. Итог

| Часть | Вердикт |
|---|---|
| Гейты (`fmt`, `clippy`, `test`) | **PASS** |
| Матрица пяти пунктов бэклога | **PASS** (код, тесты и e2e на месте; цепочки подтверждены codegraph) |
| Безопасность/качество | **PASS** — фаззинг федеративных кодеков добавлен T8b (Q1 закрыт, см. §5, §9) |
| Документация | **PASS после T8** — расхождения из §4 закрыты (T8a), фаззинг Q1 добавлен (T8b); см. §9 |
| **Итог этапа** | **PASS** — код, приёмка и документация; остаточные риски — ручной NAT/TUN |

Блокеров в production-коде нет. Все «блокеры» ниже — это несинхронизированные
документы (T8) и два необязательных улучшения качества.

---

## 1. Гейты

Выполнено в worktree, команды — как в CI (`.github/workflows/ci.yml`).

| # | Команда | Результат | Детали |
|---|---|---|---|
| 1 | `cargo fmt --all -- --check` | **PASS**, exit 0 | без вывода |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings` | **PASS**, exit 0 | `Finished dev profile … in 43.24s`, предупреждений нет |
| 3 | `cargo test --workspace -- --test-threads=1` | **PASS**, exit 0 | 565 тестов на Windows, 0 failed, 0 ignored — снимок `bcbf457`; актуально 712/751 (см. §1.1) |
| 4 | `cargo deny check` | **не выполнен**: `error: no such command: deny` (не установлен) | CI-джоба `deny` (`EmbarkStudios/cargo-deny-action@v2`, `deny.toml` не менялся с базы) |
| 5 | `cargo audit` | **не выполнен**: `error: no such command: audit` (не установлен) | CI-джоба `audit` (`rustsec/audit-check@v2`) |

### 1.1. Счёт тестов (бейдж)

```
cargo test --workspace -- --list | grep -c ": test$"   → 565
```

> Снимок на `bcbf457`. Актуальный счёт после приёмки — **712** на Windows и
> **751** на Linux (см. баннер и §1 [TESTING.md](../DEVELOPMENT.md)); разница — тесты,
> добавленные после этапа 9. Таблица ниже историческая и в сумме даёт 565.

| Крейт | Тестов (Windows, `--all-targets --list`) |
|---|---|
| `tunnel-protocol` | 84 |
| `tunnel-server` | 103 |
| `tunnel-client` | 316 |
| `tunnel-ipc` | 9 |
| `tunnel-daemon` | 18 |
| `tunnel-winsvc` | 15 |
| `tunnel-tray` | 20 |
| **Итого** | **565** |

Doc-тестов — 0. Ожидание «565» подтверждено. Полный прогон с
`--test-threads=1` завершился exit 0 (cargo прекращает прогон при первом
падении, поэтому exit 0 = все бинарники зелёные).

На Windows не компилируются unix-only файлы: `crates/ipc/tests/unix_socket.rs`
(8 тестов), `crates/daemon/tests/ipc_e2e.rs` (13), `crates/daemon/tests/offline_e2e.rs`
(2), `crates/client/tests/offline_ipc_e2e.rs` (2), `crates/server/tests/sigterm.rs`
(1) — минимум **26** тестов, которые на Linux/macOS добавятся к 565. Это
важно для T8: docs/TESTING.md §1 сейчас утверждает «+13 unix-only».

---

## 2. Матрица пяти пунктов бэклога

Цепочки подтверждены `codegraph explore` / `codegraph node` по индексу
worktree (индекс собран локально в `.codegraph/`, gitignored; 91 файл,
4 781 узел). Для каждого пункта — код, trail, юнит-тесты, e2e.

| Пункт | Код | Codegraph-цепочка | Тесты/e2e |
|---|---|---|---|
| L2 mesh-релей | `protocol/mesh.rs:34–56,166,244,265,313,371`; `client/mesh.rs:428,508,624,871,918,993` | `engine::dispatch:2215` → `handle_mesh_frame:3411` → `Mesh::on_frame:624` → `on_forward:871` → `relay_forward:918` → `charge:428` | `client/mesh.rs:1439,1618,1680,1759,1806,1842`; `protocol/mesh.rs:746,834,902`; e2e 1 `mesh_e2e.rs:269` |
| L3 федерация | `protocol/federation.rs:35–54,79–83,137,307,617`; `server/federation.rs:415,480,558,679,1073,1113,1151,1298,1640`; `server/lib.rs:2400,2456,2591`; `client/engine.rs:2992,3818,4212,4435` | сервер: `handle_datagram:1726` → `federation::on_frame:1378` → `on_handshake_frame:1395` → `on_hello:558`/`on_ack:679`; `on_session_frame:1424` → `on_group_push:1073`/`on_relay:1298`; клиент: `handle_mutation:3415 (join_fed на :3510)` → `join_fed:2591` → `request_join:1608` | `server/federation.rs:1884,1944,1963,2114,2148,2170,2193,2524,2640,2804`; `protocol/federation.rs:750,765,810,937,1053`; e2e 4 `engine_e2e.rs:2753`, негатив `:2932`, встречные hint `:3109` |
| Офлайн-TUI | `client/offline.rs:43,78,90,256,320,524,591`; `daemon/engine_backend.rs:224,438,453,552`; `tui/badges.rs:407` | `ResilientEngine:524` ← `connect_offline_with_reason(remote.rs:239)`; `DaemonEngine:254` `State::Waiting:224` ← `open:310`/`fail:430`; `Cmd::SwitchServer` — `send:552` → `offline_cmd:438` | `offline.rs:821,845,869,880,900,911,1008,1091,1119`; `engine_backend.rs:691`; e2e 6 — `daemon/tests/offline_e2e.rs:158,216`, `client/tests/offline_ipc_e2e.rs:230,294` (**unix-only**) |
| Проба сервера | `protocol/payloads.rs:339,343,345,349,358,385,393,406`; `server/probe.rs:27,38,47`; `client/probe.rs:33,35,47,129,232,321` | `handle_datagram:1726` → `probe::handle_probe_req(server/probe.rs:47)` → `dec_probe_req(payloads.rs:366)` → `enc_probe_resp:393`; клиент: `do_cmd(engine.rs:3752)`/`probe_local(offline.rs:182)` → `start_probe(probe.rs:232)` → `on_response:277` → `KeyMatch:47/129` | `probe.rs:432,455,485,536,555,587,611,632`; `payloads.rs:1727+`; e2e 5 `probe_e2e.rs:72,108,126` |
| Выбор пути | `client/path.rs:35–52,59,149,190,401,421,442,455,530`; `engine.rs:3575,3608,4823`; `tui/ui.rs:557,703,732` | `route_packet:4823` → `choose(path.rs:442)` → `recalc_one:421`; `route_packet:4871` → `try_relay:3608` → `start_forward(mesh.rs:993)`; `path_cell(ui.rs:732)` ← `draw_peers:614`/`draw_peer_card:1529` | `path.rs:685,708,727,765,784,815,856,892,930,952,1103,1138,1172`; `tui/ui.rs:2127`; `tui/app.rs:4929,4961,4977,5007,5039`; e2e 3 `mesh_e2e.rs:421`, пин/откат `:547` |

### 2.1. L2 mesh-релей

* Рукопожатие: `MESH_HELLO`/`ACK` — `crates/protocol/src/mesh.rs:34,36`;
  ровно 153 байта (`MESH_HELLO_LEN = 32+32+16+8+1+64`, `:76`), подпись
  проверяется `MeshHello::verify_from` (`:265`), DH — `dh` (`:281`), допуск
  времени 120 с (`MESH_TS_SKEW_MS`, `:74`).
* Релей: `MESH_FORWARD` (`:52`), `MESH_FORWARD_ACK`/`NACK` (`:53,54`), тело
  `MeshForward` (`:313`), сборка `to_frame` (`:371`), разбор `decode` (`:376`);
  `MESH_MAX_HOPS = 3` (`:66`), `MESH_MAX_VISITED = 8` (`:69`).
* Клиент: приём — `Mesh::on_frame` (`client/mesh.rs:624`), пересылка —
  `on_forward:871` → `relay_forward:918` (проверки `relay_enabled`, хопов,
  `visited`, чужого `inner`, числа кадров в полёте); отправитель —
  `start_forward:993`.
* Бюджет: `charge:428` — окно 10 с (`RELAY_WINDOW_MS:69`), ≤ 8 реле-пиров
  (`RELAY_PEERS_MAX:67`), девятый получает `BUDGET` (`:438–440`);
  `relay_budget` (`engine.rs:3318`) = `kbps × 125 × 10`; для 16384 кбит/с →
  20 480 000 байт за окно — совпадает с PROTOCOL §10.3.
* Тесты: рукопожатие/пинг `client/mesh.rs:1439`, повтор/одновременность
  `:1474`, чужой ключ `:1516`, просрочка `:1552`, малый порядок `:1601`;
  forward+ack `:1618`, visited/TTL/петля `:1680`, битый inner/лимит `:1759`,
  бюджет `:1806`, восемь реле-пиров `:1842`. Протокол: `forward_туда_обратно`
  (`protocol/mesh.rs:834`), лимиты из сети без аллокаций (`:902`).
* e2e 1: `e2e_релей_через_третьего_при_мёртвом_сервере`
  (`client/mesh_e2e.rs:269`) — настоящий сервер (остановлен внутри теста),
  три движка, `TunDev`-заглушка, `MESH_FORWARD` A→C через B.

### 2.2. L3 федерация

* Форматы: `SRV_HELLO 0x40`, `SRV_HELLO_ACK 0x41`, `FED_GROUP_PUSH 0x42`,
  `FED_GROUP_DELTA 0x43`, `FED_ADDR_PUSH 0x44`, `FED_ADDR_REVOKE 0x45`,
  `FED_RELAY 0x46`, `FED_RELAY_ACK 0x47`, `FED_RELAY_NACK 0x48`,
  `FED_LAST 0x4F` (`protocol/federation.rs:35–54`); версия/флаг
  `FED_VER`/`FED_FLAG_RELAY` (`:79–83`); кодек `SrvHello` (`:137`),
  `SrvHelloAck` (`:307`), `FedRelay` (`:617`), причины NACK (`:666–674`).
* Сервер: входящий кадр — `federation::on_frame:1378` (диспетчер
  `server/lib.rs:1763`, после `PROBE_REQ`/HELLO, до ctrl);
  `on_handshake_frame:1395` → `on_hello:558` (подпись, свежесть, TOFU-пин
  `insert_pin:415`) и `on_ack:679`; `on_session_frame:1424` (AEAD-сессия,
  окно повторов) → `on_group_push:1073`, `on_group_delta:1113`,
  `on_addr:1151`, `on_relay:1298`, `on_reply:1311`.
* TOFU и подсказки: `hint:480` (недоверенный `SERVER_HINT`, ключ проверяется
  подписью), `on_hint:1482`; тесты `tofu_чужой_ключ_на_закреплённом_адресе`
  (`:2148`), `tofu_расхождение_x_отказ` (`:2170`), `hint_с_ложным_ключом_отвергается`
  (`:2193`), `закреплённый_пин_на_другом_адресе_отказ` (`:2252`),
  `выключенная_федерация_не_отвечает` (`:2309`), `закреплённый_пир_переживает_сериализацию`
  (`:2323`).
* Встречные hint (T4c): детерминированный тай-брейк — меньший ed25519
  инициатор, больший отменяет свою попытку (описание —
  `server/federation.rs:35–59`; реализация — `on_hello:558`, тест
  `встречные_hello_сходятся_на_одной_сессии:1963`; e2e
  `e2e_встречные_подсказки_федерации_не_ломают_репликацию:3109`).
* Репликация: `publish:926`, `sync:980`, `on_group_push:1073`,
  `on_group_delta:1113`; тест `репликация_группы_push_и_delta:2524`,
  конфликт адресов `:2640`, заявка адреса `:2742`.
* Релей L3: `wrap_relay:1039`, `relay_for_peer:1640`, `reply_relay:1656`,
  `fed_deliver_relay(server/lib.rs:2400)`, `fed_deliver_reply:2456`;
  вызов из `relay_group` — `server/lib.rs:1832`; тест
  `релей_заворачивается_и_проверяется:2804` и сквозной
  `federation_relay_от_клиента_до_получателя_на_другом_сервере`
  (`server/lib.rs:6884`).
* `JOIN_FED`: `join_fed(server/lib.rs:2591)` — находит реплику по uuid,
  заводит участника, ротирует ключ у владельца или шлёт `request_join`
  (`server/federation.rs:1608`) владельцу; клиент — `Cmd::JoinFed`
  (`client/engine.rs:843`), отправка `:3818`, приём `FED_GROUPS` —
  `on_ctrl:4144` (FED_GROUPS на `:4212`) → `on_fed_groups:4435`; метка «федерация» в TUI —
  `client/tui/ui.rs:404–422`, команда `:joinfed` — `tui/app.rs:3346,3383`.
* e2e 4: `e2e_федерация_репликация_join_fed_и_релей_до_tun`
  (`engine_e2e.rs:2753`) — два настоящих сервера, `SERVER_HINT`, TOFU,
  репликация, `JOIN_FED`, `FED_RELAY` до `TunDev`, рестарт `server.json`.
  Негатив: `e2e_ложные_подсказки_федерации_отклоняются_и_не_спамят`
  (`:2932`) — ложный адрес/ключ, метрика `voidlink_fed_hint_rejected_total`,
  отсутствие спама. Встречные hint: `:3109` (T4c).

### 2.3. Офлайн-TUI

* Офлайн-движок: `ResilientEngine` (`client/offline.rs:524`) — создаётся
  `connect_offline(dir, cfg, identity)` / вариант с причиной
  (`client/remote.rs:228,239`); правки применяются локально
  (`apply_local:320`), копятся в `ui-pending.json`
  (`PENDING_FILE:43`, `load_pending:78`, `save_pending:90`), уходят демону
  `flush:256`; `pending_edits:591`; проба без движка — `probe_local:180`.
* TUI всегда открывается: `tui` — демон → тонкий клиент, иначе офлайн;
  `tui --offline` демона не ищет (`client/main.rs:944,1090`); бейджи
  `⏳ ожидает применения (N)` — `tui/badges.rs:407`, `tui/ui.rs:3105`;
  пилюли `⚠ демон недоступен` / `○ нет сервера`.
* Демон без движка: `State::Waiting` (`daemon/engine_backend.rs:224`) с
  видимой причиной; `Cmd::SwitchServer` в Waiting применяется сразу и будит
  движок — `send:552` → `offline_cmd:438` (`engine_backend.rs:453,481`);
  тест `switch_server_в_waiting_переключает_и_будит_движок:691`,
  `failed_демон_отдаёт_причину:790`; `offline_e2e.rs:216`
  (`tui_добавляет_сервер_демону_в_состоянии_нет_сервера`).
* e2e 6 (**unix-only**, `#![cfg(unix)]`): `offline_e2e.rs:158`
  (офлайн-правки уходят демону после старта) и `:216`;
  `offline_ipc_e2e.rs:230` (очередь уходит и очищается), `:294`
  (причина «демон без движка» видна TUI). На Windows не выполняются —
  кроссплатформенная логика очереди покрыта `offline.rs:1091,1119`.
* Юнит-тесты офлайна: `офлайн_правка_применяется_и_не_теряется:821`,
  `очередь_переживает_перезапуск_tui:845`, `сетевая_команда_офлайн_отклоняется:869`,
  `тема_и_адаптер_сохраняются_офлайн:880`, `битый_файл_очереди_не_роняет_tui:900`,
  `проба_работает_без_движка:911`, `состояние_офлайн_сети_по_пилюлям:1008`.

### 2.4. Проба сервера

* Кодек: `PROBE_REQ_LEN = 64`, `PROBE_RESP_LEN = 24`, `PROBE_RESP_KEY_LEN = 56`
  (`protocol/payloads.rs:339,343,345`), `ProbeReq:349`, `enc_probe_req:358`,
  `ProbeResp:385`, `enc_probe_resp:393`, `dec_probe_resp:406`.
* Сервер: `probe::handle_probe_req` (`server/probe.rs:47`) — ровно 64 байта,
  свежесть `PROBE_TS_SKEW_MS = 120_000` (`:27,38`), ответ 24/56 и **не
  длиннее запроса** (`:78`), без сессии; диспетчер — `server/lib.rs:1733`
  (до HELLO); метрика `voidlink_probes_total`.
* Клиент: свой UDP-сокет/поток — `start_probe` (`client/probe.rs:232`),
  таймаут 3 с и 2 попытки (`:33,35`), ожидание результата `wait_result:420`,
  дедуп повторной пробы (`:611`); `PROBE_RESP` принимается от любого сервера
  в `dispatch` (`engine.rs:2233–2243`), не только от текущего.
* Ключ: `KeyMatch` (`probe.rs:47`), вычисление `:129–137` — `Match`/
  `Mismatch`/`Unknown` (нет пина или ключ не просили), форма события
  `:57–72`; тесты `ответ_даёт_доступность_и_rtt:432`,
  `чужой_ключ_и_без_пина:455`, `битый_и_чужой_ответ_не_паникует:485`,
  `проба_через_сокет_и_поток_даёт_ключ_и_rtt:536`,
  `молчащий_сервер_даёт_недоступен_за_две_попытки:587`.
* TUI: колонки «доступен / RTT / ключ» — `tui/servers.rs:567,993,1010`;
  автопроба — `tui/app.rs:4781`; чужой ключ — предупреждение, не запрет
  (`tui/app.rs:4835,4858`).
* e2e 5: `probe_e2e.rs:72` (настоящий сервер, `Match`), `:108` (молчащий
  порт), `:126` (движок отдаёт пробу событием).

### 2.5. Выбор пути

* Модель: `HOP_PENALTY_SERVER_MS = 5`, `HOP_PENALTY_PEER_MS = 15`,
  `LOAD_PENALTY_MS = 10`, `HYSTERESIS_PCT = 20`, свежесть
  `DIRECT_FRESH_MS = 12_000`, `SERVER_FRESH_MS = PEER_FRESH_MS = 30_000`
  (`client/path.rs:35–52`); `PeerRoute::cost` (`:149`) = `up+down+15+10·load`;
  `PathKind` — `Direct`/`Server`/`PeerRelay` (`:59`).
* Таблица: `PathTable` (`:190`), `recalc:401`, `recalc_one:421`,
  `choose:442`, `fallbacks:455`, `recalc_target_pinned:530`; гистерезис —
  новый путь должен быть дешевле на ≥20 % (`:600`); пин сильнее автоматики,
  недоступный пин даёт **один** `PathLost` и откат, но не удаляется
  (`:564`); `PathLost` также при отсутствии путей (`:647`).
* Исполнение: `route_packet` (`engine.rs:4823`) → `choose` (`:4852`);
  `Direct` — прямой адрес, `PeerRelay` — `try_relay:3608` →
  `start_forward(mesh.rs:993)`, `Server`/`None` — сервер; неудача —
  `emit_path_change:3575` + откат на сервер. L3 в `PathKind` нет.
* TUI: колонка «путь» — заголовок `tui/ui.rs:557`, `path_text:703`,
  `path_cell:732`, карточка участника `:1529`; окно `p`/закрепление —
  `tui/app.rs:2023,2052,2061`; тест `колонка_путь_и_карточка_участника`
  (`tui/ui.rs:2127`), окно/пин — `tui/app.rs:4929,4961,4977,5007`,
  событие пути — `:5039`.
* Юнит-тесты: `default_путь_сервер…:685`, `прямой_дешевле:708`,
  `гистерезис_20_процентов:727`, `тухлый_прямой:765`, `пин_сильнее_автоматики:784`,
  `мёртвый_пин_даёт_lost_и_откат_но_не_удаляется:815`, `пин_на_реле:856`,
  `релей_пира_и_загрузка:892`, `record_failure…:930`, `связь_пропала_и_вернулась:952`,
  `fallbacks_по_возрастанию_стоимости:1172`.
* e2e 3: `e2e_переключение_пути_закреплением` (`mesh_e2e.rs:421`) —
  `PinPath`/`UnpinPath`, `direct`/`server`/`peer`, `PathChanged`/`PathLost`
  без дублей, пин переживает рестарт; плюс `e2e_путь_сервер_пир_пин_блокирует_и_откатывает`
  (`:547`). e2e 2/7 — `:333`, `:487`, `:669`.

---

## 3. Соответствие кода нормативным константам

Выборочно сверено с PROTOCOL §10–§13 (всё совпало):

| Норматив | Код |
|---|---|
| `MESH_HELLO` = 153 байта, skew 120 с | `protocol/mesh.rs:76,74` |
| `MAX_FORWARD_INNER` = 65 187 (63,7 КиБ) | `client/mesh.rs:71` = `65511−68−256` |
| хопов ≤ 3, `visited` ≤ 8, кадров в полёте ≤ 128, повтор 1,5 с | `protocol/mesh.rs:66,69`; `client/mesh.rs:77,73` |
| бюджет: 16 384 кбит/с → 20 480 000 байт / 10 с / пира, ≤ 8 пиров | `client/mesh.rs:67,69,428`; `engine.rs:3318` |
| проба: запрос 64, ответ 24/56, skew 120 с, 3 с × 2 попытки | `payloads.rs:339,343,345`; `server/probe.rs:27`; `client/probe.rs:33,35` |
| стоимость и свежесть путей (5/15/10 мс, 20 %, 12/30 с) | `client/path.rs:35–52` |
| DHT 32×8, α=3, 2 раунда, ≤ 32 поисков, TTL 15 мин | `client/dht.rs:32,34,42,44,46` |
| `PROTOCOL_VERSION = 4` | `protocol/lib.rs:64` |
| `is_plaintext` — только `PROBE_REQ/RESP` из новых | `protocol/lib.rs:176–181` |

---

## 4. Документация: найденные расхождения (правит T8)

Ничего из этого T7 не правил. Формат: **файл:строка — что не так → что должно быть**.

### 4.1. `docs/PROTOCOL.md` — главный блокер T8

1. **36–40** — «федерация (T4) — черновик, кадры `0x40..=0x4F` пока только
   безопасно отбрасываются» → федерация реализована (T4a/T4b1/T4b2/T4c),
   e2e 4 зелёный.
2. **884–898 (§12)** — таблица кадров помечает `0x40..=0x47` как «⏳ T4»,
   а `0x47–0x4F` как «резерв» → фактически: `0x47 = FED_RELAY_ACK`,
   `0x48 = FED_RELAY_NACK`, `0x4F = FED_LAST` (граница диапазона); все
   кадры реализованы и покрыты тестами.
3. **900–906** — «T1 фиксирует номера… Сейчас (T4 — черновик) работают
   только безопасные точки входа: … `JOIN_FED` отвечает `ERROR`» → работают
   `SRV_HELLO`/`ACK` с AEAD-сессией, TOFU-пиннинг, репликация
   групп/адресов, `FED_RELAY`, `JOIN_FED` (`server/lib.rs:2591`).
4. **913–921** — «`JOIN_FED`… до T4 сервер отвечает `ERROR`», «`FED_GROUPS`…
   (T4)» → `JOIN_FED` реализован, `FED_GROUPS` обрабатывается клиентом
   (`client/engine.rs:4212` → `on_fed_groups:4435`).
5. **937** — строка деградации «федерация… T4 — черновик… `JOIN_FED` → `ERROR`»
   → переписать под реализованное поведение (федерация выключена по
   умолчанию, `JOIN_FED` без `--federate` даёт понятную ошибку).
6. **960–965** — «федерация (T4) пока черновик… `L3` не реализован, поэтому
   `PathKind::PeerRelay` — верхний уровень доставки» → серверный L3-релей
   (`FED_RELAY` → `fed_deliver_relay`) реализован и e2e-проверен; в
   клиентской `PathTable` уровней по-прежнему L0–L2 (это надо сказать явно,
   а не «L3 не реализован»).
7. **§12** — нет описания тел `0x42..0x48`, флагов `FED_VER`/
   `FED_FLAG_RELAY` (`protocol/federation.rs:79–83`) и кодов NACK
   (`:666–674`), нет описания тай-брейка встречных `SRV_HELLO` (T4c;
   сейчас только в doc-комментарии `server/federation.rs:35–59` и тесте
   `:1963`).
8. **§13** — лимиты федерации (сессии/репликация/релей) не перечислены;
   таблица деградации не упоминает `--federate`.

### 4.2. `docs/PLAN.md` — §9

9. **977** — заголовок «T1/T2/T3 ✅, T4 ⏳, T5 в работе» → T2/T3/T4/T4c/T6
   сделаны; T5-доки — этот отчёт, закрывает T8.
10. **1005** — «`cargo test --workspace` — 517» → **565** на Windows.
11. **1044–1057 (§9.4/§9.5)** — «Федерация — ⏳ T4 (черновик)», список
    «осталось», «e2e 4 не утверждается до готовности T4», «L3 — ⏳ T4» →
    переписать в «сделано (T4a/T4b1/T4b2/T4c)»; e2e 4 утверждён; L3 —
    серверный релей готов, в `PathTable` L3 не выбирается.
12. **1069–1076 (§9.6)** — «docs — ✅ черновик, финальный проход ⏳»,
    «e2e-сценарии — ⏳ T2–T4» → e2e 1–7 готовы (см. TESTING §10), docs
    синхронизирует T8.
13. **1084–1086 (§9.7)** — «Бюджет релея `relay_budget_kbps` пока только
    хранится» → бюджет списывается и режет полосу (`client/mesh.rs:428`,
    `engine.rs:3318`); «L3 в модели стоимости не описан» — верно, оставить.
14. **1142–1144** — «Этап 9 (⏳): … (T2), (T3), (T4), (T5)» → обновить статусы.

### 4.3. `docs/TESTING.md`

15. **26, 46** — «517 на Windows (+13 unix-only)» → 565; фактических
    unix-only файлов минимум 26 тестов (см. §1.1). Либо пересчитать по CI
    на Linux/macOS.
16. **197–200 (§2.8 статус)** — «Федерация (T4) проверяется только на уровне
    форматов — ⏳» → есть полные тесты федерации и e2e 4.
17. **333 (критерий релиза 5), 340–341** — «e2e 4 (федерация) не
    утверждается до T4» → e2e 4 существует и зелёный.
18. **351 (таблица §10.1, строка 4)** — «Где —», статус «⏳ T4 (не
    утверждать)» → `crates/client/src/engine_e2e.rs`,
    `e2e_федерация_репликация_join_fed_и_релей_до_tun:2753` (+ негатив
    `:2932`, встречные hint `:3109`), статус ✅.
19. **§2.7** — список фаззинга включает только `FED_GROUPS`; федеративные
    кодеки `SrvHello`/`SrvHelloAck`/`FedGroupDelta`/`FedAddrClaim`/
    `FedRelay`/`FedRelayReply` в фазз-харнесс не добавлены (см. §5.2).
20. **§2.8** — нет проверок федерации (handshake/TOFU/репликация/релей)
    как отдельного пункта матрицы; после T4 их стоит добавить.

### 4.4. `README.md`

21. **14** — бейдж `тесты-456` → **565**. **260** — «**456 автотестов**» → 565.
22. **275** — «**В работе:** этап 9 — mesh/DHT… (T3), федерация (T4), проба
    с клиента и офлайн-режим TUI (T2)» → всё перечисленное сделано; в
    «Готово»/«В работе» оставить только реально открытое (MSI, Windows-ручки
    и т.п.). Бейдж протокола `v4+` (12) — корректен.

### 4.5. `docs/SERVER.md`

23. **147, 178–183** — «федерация — T4… Новых флагов пока нет… метрики
    появятся вместе с T4» → реализовано; нужны флаги `--federate`,
    `--peer <addr>` (повторяемый), `--fed-pool <addr>` (повторяемый)
    (`crates/server/src/main.rs:38–43,145–158`), описание TOFU/репликации/
    релея.
24. **133–142** — список метрик не содержит пяти федеративных:
    `voidlink_fed_peers`, `voidlink_fed_hint_rejected_total`,
    `voidlink_fed_groups`, `voidlink_fed_addr_claims`,
    `voidlink_fed_relayed_total` (`crates/server/src/metrics.rs:193–219`).

### 4.6. `docs/SECURITY.md`

25. **479** — строка «Федерация… ⏳ T4 (черновик)» → ✅, с уточнением
    TOFU-риска первого знакомства.
26. **547–566 (§18.3)** — «Сейчас это **черновик**: … `JOIN_FED` → `ERROR`»,
    «до T4 сервер отвечает `ERROR`» → переписать под реализацию
    (TOFU-пин, репликация ключей, `FED_RELAY`; риск первого знакомства
    остаётся).

### 4.7. `docs/TUI.md`, `docs/CLIENT.md`

27. **TUI.md:205–228** — в таблице команд нет `:joinfed <uuid-hex|gid>`
    (`client/tui/app.rs:3346,3383`) и метки `[федерация]` в списке групп
    (`client/tui/ui.rs:404–422,1921`).
28. **CLIENT.md** (раздел про `client.json`, 572–632) — mesh и `pinned_paths`
    описаны, но клиентская федерация нет: автоматический `SERVER_HINT` раз
    в 5 мин (`client/engine.rs:69–71,2992,3076`), `FED_GROUPS` в снимке
    (`client/api.rs:151`), `:joinfed`. CLI-команд `probe`/`pin`/`unpin`
    действительно нет — это утверждение верно.

### 4.8. Прочие документы (вне обязательного списка, но тоже разъехались)

29. **NETWORKING.md:103,287** — «L3… не реализовано» → серверный L3-релей
    готов; `PathTable` его не выбирает — сформулировать точно.
30. **ARCHITECTURE.md:42,264,471,757** — те же «федерация — черновик»,
    «`JOIN_FED` → `ERROR`», «L3 не реализован».
31. **CHANGELOG.md:278** — «456 тестов»; **:383** — «PROTOCOL.md —
    спецификация протокола v3» → v4+.
32. Мелочь в коде (не docs, не блокер): комментарий
    `crates/client/src/federation.rs:5–7` говорит, что клиентская часть
    «реализуется в T4», хотя она реализована в `engine.rs`.

---

## 5. Безопасность и качество

### 5.1. `unwrap()`/`panic!` на разборе сети

Проверены (вне `#[cfg(test)]`): `protocol/{mesh,federation,payloads}`,
`client/{mesh,dht,probe}`, `server/{federation,probe}`.

| Файл | Найдено вне тестов | Оценка |
|---|---|---|
| `protocol/mesh.rs` | 0 | — |
| `protocol/federation.rs` | 0 | — |
| `protocol/payloads.rs` | 1 (`dec_ping:1054`) | `unwrap` после `ensure!(p.len()==8)` — доказано infallible; код старше этапа 9 |
| `client/mesh.rs` | 3 | счётчик nonce `:148` (`checked_add` → panic только при 2⁶⁴ кадрах); `:448` (`expect` сразу после вставки в map — инвариант); `:1321` (`[..8].try_into` — infallible) |
| `client/dht.rs`, `client/probe.rs`, `server/probe.rs` | 0 | — |
| `server/federation.rs` | 23 `lock()/read().unwrap()` | это мьютексы/состояние, не разбор сети; паника чужого потока под локом отравит его. Паттерн общесерверный, риск низкий |

Новых `panic!`/`unreachable!` в декодерах нет; все длины и счётчики
проверяются `ensure!` до аллокаций (`Reader::capacity_for`), строгие длины
`MESH_HELLO`/`PROBE_REQ`/`PROBE_RESP` соблюдены.

### 5.2. Фаззинг

В `crates/protocol/src/fuzz_tests.rs:56–110` добавлены новые декодеры:
`dec_mesh_info`, `dec_server_hint`, `dec_probe_req`, `dec_probe_resp`,
`dec_mesh_seed`, `dec_fed_groups`, `dec_mesh_section`, `MeshHello::decode` +
`verify_from`/`dh`/`signing_payload`, `MeshForward::decode`, все типы
`mesh::Rpc` (0x32..=0x3E и «чужой»), `read_member`, `parse_group_header`,
`open_group`.

**Пробел:** федеративные сетевые кодеки `SrvHello`, `SrvHelloAck`,
`FedGroupDelta`, `FedAddrClaim`, `FedRelay`, `FedRelayReply` в фазз-харнесс
не включены (только `FedGroup` через `dec_fed_groups`). Для строгого
выполнения «новые декодеры в фаззинге» — добавить в `feed_all` (это тестовый
код, не production). Не блокер приёмки, но зафиксировать.

### 5.3. Зависимости и протокол

* Новых зависимостей **нет**: `git diff b9f108f..HEAD -- Cargo.toml Cargo.lock`
  пуст; в `crates/{client,server}/Cargo.toml` только включены фичи
  `Win32_Networking_WinSock` у уже существующего `windows-sys`.
* `PROTOCOL_VERSION = 4` (`protocol/lib.rs:64`) — версия не менялась,
  расширения включаются данными (PROTOCOL §13).
* `deny.toml` не менялся; CI-workflow не менялся с базы, джобы
  `deny`/`audit` на месте (`.github/workflows/ci.yml`). Локально проверены
  Windows-гейты; Linux/macOS (включая unix-only тесты) прогоняет CI.
* `git status` до создания отчёта был чист; `HEAD = bcbf457`; единственное
  изменение ветки — этот файл (коммит `Stage 9 verification report`),
  после коммита дерево снова чисто.

---

## 6. Остаточные риски

1. **Реальный NAT не проверен.** Ручной чек-лист TESTING §10.2 (`cone`,
   `symmetric`, `samenat`, `hairpin`, выключение реле-пира, бюджет, офлайн-TUI
   на чистой Windows) в этом окружении не выполнялся — нужен Linux с root
   для `nat-lab.sh`. Код L0–L2 покрыт e2e на loopback, но не реальным NAT.
2. **e2e 6 — unix-only.** На Windows не запускались `offline_e2e.rs` и
   `offline_ipc_e2e.rs`; всего в unix-only файлах (`ipc_e2e`, `offline_e2e`,
   `offline_ipc_e2e`, `unix_socket`, `sigterm`) минимум 26 тестов. Логика
   очереди/правок покрыта кроссплатформенными юнит-тестами `offline.rs`,
   но полный путь «демон + TUI» на Windows проверит CI на Linux/macOS или
   ручной чек-лист 7.2.
3. **Документация отстаёт от кода** — весь §4; закрывает T8. До T8 этап 9
   нельзя считать полностью закрытым, хотя код принят.
4. **Фаззинг федеративных кодеков** — см. §5.2; фаззинг в CI не входит,
   гоняется отдельно (`cargo fuzz`, ≥1 ч на разборщик — критерий релиза 4).
5. **`cargo deny`/`cargo audit` локально не проверены** (не установлены);
   лицензии/advisories проверит CI-джоба. Новых крейтов нет, поэтому риск
   низкий.
6. **TOFU первого знакомства** — известный и задокументированный риск
   федерации (MITM при первом `SRV_HELLO`), не дефект.
7. **L3 в клиентской модели стоимости отсутствует** — серверный межсерверный
   релей работает, но `PathKind` не содержит L3; при выборе пути клиент
   остаётся на L0–L2. Документация должна это формулировать явно.
8. **Timing-чувствительные e2e** — mesh-тесты используют таймауты 5–10 с;
   прогон T7 — ещё один зелёный (T6 заявлял 3 зелёных). Один прогон не
   доказывает отсутствие флака, но подтверждает стабильность.

---

## 7. Блокеры/задачи для T8 (file:line)

Приоритет — сначала код-нормативные документы, затем README/эксплуатация.

| # | Файл:строка | Что сделать |
|---|---|---|
| B1 | `docs/PROTOCOL.md:36–40, 884–906, 913–921, 937, 960–965` | Переписать §12 под реализованную федерацию: диапазон `0x40..=0x4F`, `0x47/0x48`, тела `0x42..0x48`, `FED_VER`/`FED_FLAG_RELAY`, коды NACK, TOFU, репликация, `FED_RELAY`, `JOIN_FED`, тай-брейк встречных `SRV_HELLO` (T4c), статус L3 (серверный релей — да, `PathTable` — L0–L2). |
| B2 | `docs/PLAN.md:977, 1005, 1044–1057, 1069–1076, 1084–1086, 1142–1144` | Статусы T1–T6/T4c, 565 тестов, бюджет релея «работает», L3-формулировка. |
| B3 | `docs/TESTING.md:26, 46, 197–200, 333, 340–341, 351` | 565 тестов, unix-only пересчитать (≥26), e2e 4 — ✅ с файлом/именем, §2.8 — федерация не «только форматы»; при желании — п. 14 о федерации и фаззинге. |
| B4 | `README.md:14, 260, 275` | Бейдж/число тестов 565; актуализировать «Готово/В работе». |
| B5 | `docs/SERVER.md:147, 178–183`; `:133–142` | Флаги `--federate/--peer/--fed-pool`, TOFU/репликация/релей; 5 метрик `voidlink_fed_*` (`metrics.rs:193–219`). |
| B6 | `docs/SECURITY.md:479, 547–566` | Федерация ✅, описать TOFU/репликацию/релей и остаточный риск первого знакомства. |
| B7 | `docs/TUI.md:205–228`; `docs/CLIENT.md` (572–632) | `:joinfed`, метка `[федерация]`; клиентская федерация (`SERVER_HINT` авто, `FED_GROUPS`, `:joinfed`). |
| B8 | `docs/NETWORKING.md:103,287`; `docs/ARCHITECTURE.md:42,264,471,757`; `docs/CHANGELOG.md:278,383` | Синхронизировать статусы L3/федерации, 565 тестов, ссылку «протокол v4+». |
| Q1 (не блокер) | `crates/protocol/src/fuzz_tests.rs:56–110` | Добавить федеративные кодеки в `feed_all`, если требование «новые декодеры в фаззинге» строгое. |
| Q2 (косметика) | `crates/client/src/federation.rs:5–7` | Устаревший комментарий «реализуется в T4». |

---

## 8. Как воспроизвести

```bash
cd VoidLink-wt/90-verify                     # branch stage9/90-verify, HEAD bcbf457
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1   # exit 0, 565 тестов на Windows (снимок bcbf457)
cargo test --workspace -- --list | grep -c ": test$"   # 565 (снимок bcbf457)
cargo deny check || echo "cargo-deny не установлен"
cargo audit      || echo "cargo-audit не установлен"
git status --porcelain                       # пусто (кроме этого отчёта)
```

Codegraph (локальный индекс worktree, gitignored):

```bash
codegraph explore "MeshForward relay_forward MeshHello charge"
codegraph node "relay_forward"     # Calls → charge/parse_group_header…, Called by ← on_forward
codegraph node "on_hello"          # две реализации: client/mesh.rs:508 и server/federation.rs:558
codegraph node "join_fed"          # Called by ← handle_mutation
codegraph node "choose"            # Called by ← route_packet
codegraph node "start_probe"       # Called by ← do_cmd / probe_local
```
---

## 9. Закрытие T8 (после отчёта)

| Пункт | Статус | Где |
|---|---|---|
| B1–B8 (документация) | **исправлено** T8a | `f52c533`, merge `01bd7af`: PROTOCOL §12 под T4c, PLAN/TESTING/README/SERVER/SECURITY/TUI/CLIENT/NETWORKING/ARCHITECTURE/CHANGELOG/GLOSSARY синхронизированы с кодом |
| Q1 (фаззинг федеративных декодеров) | **исправлено** T8b | `ea5596c`, merge `6290424`: `SRV_HELLO/ACK`, `FED_GROUP_PUSH/DELTA`, `FED_ADDR_PUSH/REVOKE`, `FED_RELAY/ACK/NACK` в `fuzz_tests.rs` |
| Гейты на финальном `dev` | **PASS** | `01bd7af`: `fmt` 0, `clippy -D warnings` 0, `cargo test --workspace -- --test-threads=1` — 565 passed, 0 failed |
| Счёт тестов | 565 на Windows — снимок на приёмку | на дату отчёта совпадал в README, TESTING, PLAN, CHANGELOG; **актуально 712 (Windows) / 751 (Linux)** |

Финальное состояние: `dev` = `c39d8d6` (после `01bd7af` — только правка вердикта в этом отчёте);
код, приёмка и документация — **PASS**.
