# Гейты и флейки: сырые доказательства

Собрано ведущим во время аудита. Все прогоны — на коммите `c0689fc`.

## 1. Локальные гейты (Windows 11, cargo 1.100.0)

| Гейт | Результат |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | exit 0, 0 предупреждений |
| `cargo test --workspace -- --test-threads=1` | exit 0 |
| `cargo test --workspace -- --list \| grep -c ": test$"` | **695** (бейдж README совпадает) |
| `cargo deny check` | exit 0 |
| `cargo audit` | exit 0, 2 «allowed warnings» |

Полный лог: [gates.log](gates.log).

## 2. Гейты на Linux-хосте (serveros, Linux 6.17.0-41, тот же коммит)

| Гейт | Результат |
|---|---|
| `cargo fmt --all -- --check` | exit 0 (после установки компонента rustfmt) |
| `cargo clippy --workspace --all-targets -- -D warnings` | см. [linux-rerun.log](linux-rerun.log) |
| `cargo test --workspace -- --test-threads=1` | **FAILED**: 2 падения в `tunnel-server --lib` |
| `cargo test --workspace -- --list \| grep -c ": test$"` | **733** (на 38 больше, чем на Windows: unix-only файлы) |
| `cargo deny check`, `cargo audit` | не установлены на хосте |

Логи: [gates-linux.log](gates-linux.log), [linux-rerun.log](linux-rerun.log).

### 2.1. Детерминированное падение: `группа_253_участника_с_длинными_полями_приходит_через_frag`

`crates/server/src/lib.rs:6189`; паника в хелпере `until()` — `crates/server/src/lib.rs:4841`:

```
panicked at crates/server/src/lib.rs:4841:13:
не дождались фрейма 0x82; пришли [83, 83]
```

- 4 прогона из 4 (3 изолированных + 1 в полном наборе) — падение;
- в том числе при дефолтном параллелизме (как в CI);
- на Windows тот же коммит — тест зелёный;
- тест добавлен в `2ce8ada` (2026-11-17), то есть CI его гоняет давно.

Что делает тест: подкладывает в состояние сервера 252 участника с `name`/`status` по
255 байт и 4 IPv6-кандидатами (итого 253 участника), затем `GET_GROUP` и ожидает
`GROUP_STATE` размером > `150 × FRAG_THRESHOLD` (165 000 байт) при
`FRAG_MAX_PAYLOAD = 1100 × 256 = 281 600`. Вместо `GROUP_STATE` приходят два
`GROUP_LIST` и наступает таймаут 5 с.

Гипотеза для проверки (передана W2): на Linux ~150–165 FRAG-датаграмм упираются в
дефолтные буферы UDP (`net.core.rmem_default = net.core.wmem_default = 212992`),
часть теряется, а ретрансмиссии/подтверждения доставки у `GROUP_STATE` нет —
сборка не завершается. Требуется вердикт: дефект кода / хрупкий тест / окружение.

### 2.2. Флейк: `релей_под_нагрузкой`

`crates/server/src/lib.rs:6435`. 2 падения из 5 прогонов:

- `20000 фреймов за 30.000001866s` — исчерпан весь бюджет `BUDGET = 30 s` (счётчик
  принятых фреймов встал);
- остальные прогоны — 1.27 с и 1.30 с.

Первый прогон в наборе падал, последующие проходили; при этом один из прогонов шёл
параллельно с установкой rustup-компонентов (влияние нагрузки не исключено).

## 3. CI на GitHub (`gh run view`, репозиторий `adamantida/VoidLink`)

| Run | Ветка/событие | Итог | Что упало |
|---|---|---|---|
| 45032149950 | `master`, push (merge PR #29, коммит `c0689fc`) | success | — |
| 45032081657 | `dev`, pull_request #29 «695 тестов, CI зелёный» | **failure** | `test · macos` |
| 45030764769 | `release/issues-14-27`, PR | success | — |
| 45030227724 / 45029752232 / 45028743559 | `release/issues-14-27`, PR | failure ×3 | — |

macOS-падение (job `137237667465`):

```
test очередь_уходит_демону_и_очищается ... FAILED
panicked at crates/client/tests/offline_ipc_e2e.rs:276:5
test result: FAILED. 1 passed; 1 failed
error: test failed, to rerun pass `-p tunnel-client --test offline_ipc_e2e`
```

Тот же тест зелёный в push-прогоне на `master` — то есть это флейк, а не
постоянный дефект.

### 3.1. Дополнительно найдено при проверке стабильности (Windows, 3 прогона)

`cargo test -p tunnel-client --lib engine_e2e` — 3/3 зелёные (35 тестов, ~155 с).
`cargo test -p tunnel-client --lib mesh_e2e` — **2/3**: в третьем прогоне упал
`mesh_e2e::e2e_потерянный_ack_не_снимает_путь` (10 passed, 1 failed, 202 с).
Лог: [flake-3x.log](flake-3x.log).

## 4. Вывод для сводки

1. Бейдж «695 тестов» на Windows **достоверен** (совпадает с `--list`), но
   документы расходятся: `docs/CHANGELOG.md`, `docs/PLAN.md`,
   `docs/STAGE9_VERIFICATION.md` называют 565, ещё один документ — 456.
2. «CI зелёный на трёх ОС» — верно только для конкретного push-прогона
   `c0689fc`; на том же коде есть красный PR-прогон (macOS), а на Linux 6.17
   воспроизводится детерминированное падение теста, которого нет в CI-прогоне
   на ubuntu-latest. Зелёный CI не является переносимым доказательством.
3. Минимум три нестабильных/платформозависимых теста: `группа_253_…`,
   `релей_под_нагрузкой`, `очередь_уходит_демону_и_очищается`.
