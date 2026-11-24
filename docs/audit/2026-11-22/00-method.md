# Аудит VoidLink — метод, базис и гейты

Дата: 2026-11-24. Базис: коммит `c0689fc` (ветка `dev` = `origin/master`).
Заказ: полный независимый аудит четырёх областей — дизайн, код, безопасность,
бизнес-логика.

## 1. Объём

| Что | Размер |
|---|---|
| Крейты | 7: `protocol`, `server`, `client`, `ipc`, `daemon`, `winsvc`, `tray` |
| Rust-исходники | 94 файла, 79 418 строк |
| Документация | 20 документов в `docs/`, 11 237 строк |
| Инфраструктура | 13 файлов (systemd, install-скрипты, nat-lab, CI) |
| Вне объёма | история git до базиса, внешние сервисы, реальные ключи и конфиги пользователей |

Крупнейшие модули (риск концентрации сложности):
`server/src/lib.rs` 8 407 · `client/src/engine.rs` 7 865 · `tui/app.rs` 6 147 ·
`engine_e2e.rs` 3 839 · `tui/ui.rs` 3 647 · `server/federation.rs` 2 869.

## 2. Метод

Аудит выполнен шестью независимыми потоками (разные агенты, разные контексты,
обмен находками запрещён до синтеза):

| Поток | Отчёт | Префикс находок |
|---|---|---|
| W1 дизайн | [01-design.md](01-design.md) | `DES` |
| W2 код: protocol + server | [02-code-core.md](02-code-core.md) | `CORE` |
| W3 код: engine/mesh/net | [03-code-client.md](03-code-client.md) | `CLNT` |
| W4 код: TUI/daemon/IPC/Windows | [04-code-frontend-windows.md](04-code-frontend-windows.md) | `FRNT` |
| W5 безопасность | [05-security.md](05-security.md) | `SEC` |
| W6 бизнес-логика | [06-business-logic.md](06-business-logic.md) | `BIZ` |

Правила, общие для всех потоков:

1. **Доказательность.** Каждая находка — `файл:строка` базиса + дословный фрагмент,
   сценарий, влияние, способ проверки, рекомендация.
2. **«Решение ≠ дефект».** 20 принятых рисков `docs/SECURITY.md §15` не считаются
   находками. Находка — это либо отсутствие заявленного контроля в коде, либо
   неограниченный/незадокументированный риск.
3. **Предусловия атакующего** указываются явно; локальный доступ или права
   администратора понижают severity.
4. **Adversarial verification.** Каждая находка `S1/S2` перепроверяется ведущим
   или вторым агентом по коду; неподтверждённые понижаются либо уходят в раздел
   «гипотезы». Результаты сверки — в [06-summary.md](06-summary.md).
5. **Отрицательный результат фиксируется**: в каждом отчёте есть раздел
   «проверено — находок нет», иначе охват недоказуем.

## 3. Шкала severity

| Уровень | Определение |
|---|---|
| `S1` | Блокер: утечка ключей или трафика, повышение привилегий/RCE, потеря данных, нарушение сетевого инварианта (например, участник вне группы получает трафик) |
| `S2` | Серьёзно: отказ в обслуживании, узкий обход авторизации, ложное состояние интерфейса, дрейф нормативного документа, ведущий к неверной эксплуатации |
| `S3` | Ограниченное/локальное: некорректность в редком сценарии, утечка метаданных в лог, деградация без потери безопасности |
| `S4` | Гигиена: стиль, дублирование, мёртвый код, неточность комментария |

## 4. Среда и инструменты

| Параметр | Значение |
|---|---|
| Хост аудита | Windows 11 (SyFlyOS 10.0.26300), GNU bash + busybox, права администратора |
| Toolchain | cargo 1.100.0, rustc 1.100.0 (2026-11-05 / 2026-11-09) |
| Linux-хост | `mix21@192.168.1.89` (serveros, Linux 6.17.0-41), репозиторий `~/VoidLink` на том же коммите `c0689fc`, дерево чистое |
| Дополнительно | `cargo-deny` 0.22.0, `cargo-audit` 0.23.0 (локально); на Linux-хосте отсутствуют rustfmt/clippy-компоненты |
| Навигация по коду | CodeGraph (индекс 92 файла / 4 870 узлов; MCP-сервер по умолчанию отвечает по другому проекту, поэтому `projectPath` передаётся явно) |

## 5. Гейты

Полные логи: [evidence/gates.log](evidence/gates.log) (Windows),
[evidence/gates-linux.log](evidence/gates-linux.log) (Linux).

| Гейт | Windows | Linux |
|---|---|---|
| `cargo fmt --all -- --check` | PASS | не запускался: `cargo-fmt` не установлен в toolchain |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS (0 предупреждений) | не запускался: `cargo-clippy` не установлен |
| `cargo test --workspace -- --test-threads=1` | см. §5.1 | см. §5.1 |
| `cargo test --workspace -- --list \| grep -c ": test$"` | см. §5.1 | см. §5.1 |
| `cargo deny check` | см. §5.1 | см. §5.1 |
| `cargo audit` | см. §5.1 | см. §5.1 |

### 5.1. Результаты прогонов

**Windows** (полный лог — [evidence/gates.log](evidence/gates.log)):

| Гейт | Код возврата | Примечание |
|---|---|---|
| `fmt --check` | 0 | PASS |
| `clippy -D warnings` | 0 | PASS, 0 предупреждений |
| `test --workspace -- --test-threads=1` | 0 | все наборы зелёные |
| `--list \| grep -c ": test$"` | — | **695** — совпадает с бейджем README |
| `cargo deny check` | 0 | PASS |
| `cargo audit` | 0 | PASS, 2 «allowed warnings» |

**Linux** (`mix21@192.168.1.89`, Linux 6.17.0-41, тот же коммит `c0689fc`,
логи [gates-linux.log](evidence/gates-linux.log), [linux-rerun.log](evidence/linux-rerun.log),
[linux-unix-suites.log](evidence/linux-unix-suites.log)):

| Гейт | Результат |
|---|---|
| `fmt --check` | exit 0 (после `rustup component add rustfmt` — в исходном toolchain компонента не было) |
| `clippy -D warnings` | exit 0 (после `rustup component add clippy`) |
| `test --workspace -- --test-threads=1` | **exit 101**: 2 падения в `tunnel-server --lib` |
| `--list \| grep -c ": test$"` | **733** (на 38 больше Windows: unix-only файлы) |
| `test -p tunnel-protocol` | 89 passed |
| `test -p tunnel-ipc` | 8 passed (включая `flock`, `O_NOFOLLOW`, `0600`) |
| `test -p tunnel-daemon` | exit 0 (unix-сокет, e2e движка и фронтенда) |
| `test -p tunnel-client` | exit 0, включая `offline_ipc_e2e` и `probe_e2e` |
| `cargo deny`, `cargo audit` | не установлены на хосте |

### 5.3. Разбор двух Linux-падений

1. `tests::группа_253_участника_с_длинными_полями_приходит_через_frag` — **детерминированно**
   (4 из 4 прогонов, включая дефолтный параллелизм). Причина установлена экспериментом
   ([evidence/linux-rmem-experiment.log](evidence/linux-rmem-experiment.log)): тест-обвязка
   `Raw` ставит `SO_RCVBUF` только на Windows (`crates/server/src/lib.rs:4693-4713`),
   а `GROUP_STATE` на 253 участника — ~205 КБ payload / 180 FRAG-кадров
   (`crates/server/src/lib.rs:4685`). При `net.core.rmem_default = 212992` залп не влезает.
   Поднятие `rmem_max` (потолка) не помогает, а поднятие `rmem_default` — тест проходит
   за 0.72 с. Вердикт: **дефект теста**, не продукта (движок просит 4 МиБ на обеих ОС).
   Значения sysctl возвращены к исходным.
2. `tests::релей_под_нагрузкой` — **флейк**: 2 падения из 5 прогонов (в падении исчерпан
   весь бюджет 30 с), успешные — 1.27–1.30 с. Тест использует busy-wait `yield_now()`
   и жёсткий бюджет в функциональном наборе.

На Windows оба теста зелёные; полный набор Windows — 695 passed, 0 failed.

**Исправлено 2026-11-24** (коммит `0e24973`): тестовая обвязка поднимает
`SO_RCVBUF` и на Unix, релей ждёт подтверждений через `sleep`. После правок Linux
даёт `fmt` 0, `clippy` 0, `test` 0 и **741** тест; Windows — 702. Лог:
[evidence/gates-linux-after-fixes.log](evidence/gates-linux-after-fixes.log).

### 5.2. Счёт тестов и бейдж

В README заявлено 695 автотестов, в `docs/CHANGELOG.md`, `docs/PLAN.md`,
`docs/STAGE9_VERIFICATION.md` — 565, ещё в одном месте — 456. Статический подсчёт
атрибутов `#[test]`/`#[tokio::test]` даёт 752, из них 31 — в файлах под
`#![cfg(unix)]`. Авторитетное значение — вывод `--list` (см. §5.1); расхождение
с бейджем фиксируется в сводке как дефект документации.

## 6. Ограничения

| Ограничение | Причина | Как компенсировано |
|---|---|---|
| Реальный NAT (`nat-lab.sh`) | нужен Linux + root + TUN, на хосте аудита недоступно | статический разбор кода L0–L2 и e2e на loopback |
| Linux clippy/rustfmt | в toolchain Linux-хоста нет компонентов rustup | Windows-гейты + CI-паритет (8 джоб) |
| `cargo-fuzz` | не установлен | существующий `fuzz_tests.rs` + разбор декодеров вручную |
| Живой TUI-смоук | требует реального TTY | статический разбор + e2e движка |
| Установка службы/Wintun/MSI | меняет состояние машины | статический разбор + `--fake`-режим |
| Windows-служба под SYSTEM | требует установки службы | разбор `winsvc`, ACL-кода и `install.ps1` |

## 7. Карта артефактов

```
docs/audit/2026-11-22/
  00-method.md            этот файл
  01-design.md            W1
  02-code-core.md         W2
  03-code-client.md       W3
  04-code-frontend-windows.md  W4
  05-security.md          W5
  06-summary.md           сводка и бэклог
  evidence/               логи гейтов, выдержки
```
