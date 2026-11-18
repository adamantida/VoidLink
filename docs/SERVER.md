# Сервер VoidLink (`tunnel-server`)

Сервер — точка встречи и релей: хранит группы, адреса пользователей, инвайты, раздаёт
endpoint-ы для hole punching и пересылает трафик, пока прямого канала нет.
Работает на Linux (собирается и на macOS/Windows — для отладки). Наружу нужен
один UDP-порт (по умолчанию 5555).

## Сборка под Linux

На самом сервере (или любой Linux-машине той же архитектуры):

```
cargo build --release -p tunnel-server
# → target/release/tunnel-server
```

С macOS/Windows — кросс-сборка статического бинарника (не зависит от glibc
на VPS):

```
rustup target add x86_64-unknown-linux-musl
cargo install cargo-zigbuild        # или cross
cargo zigbuild --release -p tunnel-server --target x86_64-unknown-linux-musl
# → target/x86_64-unknown-linux-musl/release/tunnel-server
```

## Установка (systemd)

```
sudo infrastructure/linux/install-server.sh [путь/к/tunnel-server] [--listen 0.0.0.0:5555]
```

Скрипт:

- создаёт системного пользователя `tunnel` (без shell и home);
- кладёт бинарник в `/opt/tunnel/tunnel-server`, юнит —
  `/etc/systemd/system/tunnel-server.service`;
- создаёт `/etc/default/tunnel-server` (адрес `TUNNEL_LISTEN` и доп. флаги
  `TUNNEL_ARGS`), если его ещё нет;
- включает и запускает службу, печатает **Server code** (`TUN-…`) — его
  вписывают клиенты (`add-server <ip:порт> <TUN-код>`);
- повторный запуск — обновление: стоп → замена бинарника → старт,
  `server.json` не трогается.

Состояние — `/var/lib/tunnel/server.json` (`StateDirectory=tunnel`, права
0700). Юнит ужесточён: `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateTmp`, `PrivateDevices`, пустой набор capabilities,
фильтр системных вызовов. Писать сервер может только в `/var/lib/tunnel`.

Файрвол: открыть только UDP-порт сервера, например `ufw allow 5555/udp`.

Полезное:

```
systemctl status tunnel-server
journalctl -u tunnel-server -f             # события и сводка раз в 5 минут
sudoedit /etc/default/tunnel-server && sudo systemctl restart tunnel-server
```

## Флаги

```
tunnel-server [адрес=0.0.0.0:5555] [флаги]
tunnel-server rotate-key [--data <dir>]
```

Позиционный аргумент — адрес прослушивания (UDP и TCP на одном порту).
Неизвестный флаг — ошибка запуска (`неизвестный флаг … (см. --help)`), и
служба под systemd уходит в цикл перезапусков: не добавляйте в `TUNNEL_ARGS`
ничего, чего нет в таблицах ниже.

| флаг | по умолчанию | смысл |
|---|---|---|
| `--data <dir>` | `tunnel-data` | каталог состояния (`server.json`); в юните — `/var/lib/tunnel` |
| `--workers N` | 0 = по ядрам, до 8 | потоков-воркеров на UDP-сокете |
| `-q`, `--quiet` | — | полная тишина: не печатаются ни события, ни сводка раз в 5 минут, ни строка `Server code: TUN-…` |
| `--tcp` / `--no-tcp` | включён | TCP-фолбэк на том же порту, что UDP (см. «TCP-фолбэк») |
| `--metrics <адрес>` | выключено | HTTP-эндпоинт метрик `/metrics` и `/healthz` (см. «Метрики»); слушать только на `127.0.0.1` |

Лимиты (значения по умолчанию — `Limits::default()` в `crates/server/src/lib.rs`):

| флаг | по умолчанию | смысл |
|---|---|---|
| `--relay-rate R` / `--relay-burst B` | 4000 / 8000 | релей: фреймов/с на сессию и запас |
| `--ctrl-rate R` / `--ctrl-burst B` | 50 / 100 | управляющие фреймы на сессию |
| `--hello-rate R` / `--hello-burst B` | 5 / 20 | HELLO/HELLO3, RESET и открытые ответы на них — в секунду на IP (IPv6 — на /64) |
| `--plain-rate R` / `--plain-burst B` | 2000 / 4000 | открытые ответы без подтверждённого адреса (CHALLENGE, UNSUPPORTED, RESET) — на весь сервер |
| `--join-rate R` / `--join-burst B` | 1 / 10 | входы не-участников в группу — в секунду на группу |
| `--session-timeout <сек>` | 30 | сессия без пакетов столько — офлайн |
| `--max-owned-groups N` | 16 | групп во владении одной identity |
| `--invite-ttl-days N` | 7 | срок жизни приглашения, дней |
| `--max-invites-per-group N` | 256 | приглашений на группу |
| `--max-bans-per-group N` | 1024 | банов на группу |
| `--max-invites-per-target N` | 64 | живых приглашений одной identity по всем группам |

Параметры `*-rate` должны быть числами > 0, `*-burst` — ≥ 1, таймаут и срок
приглашения — ≥ 1. Подробнее о лимитах — раздел 9 [PROTOCOL.md](PROTOCOL.md).

Про `-q`: Server code в журнале при нём не появится, и `install-server.sh`
его не покажет. Чтобы узнать код, один раз запустите сервер без `-q`
(уберите флаг из `TUNNEL_ARGS`, `systemctl restart tunnel-server`,
`journalctl -u tunnel-server | grep TUN-`), затем верните флаг.

Флаги в службе задаются через `TUNNEL_ARGS` в `/etc/default/tunnel-server`:

```
TUNNEL_LISTEN=0.0.0.0:5555
TUNNEL_ARGS=--workers 4
```

## Ротация ключа сервера

Сервер должен быть остановлен (запущенный на том же каталоге сервер новый
ключ не затирает, но вступит он в силу только после перезапуска):

```
sudo systemctl stop tunnel-server
sudo -u tunnel /opt/tunnel/tunnel-server rotate-key --data /var/lib/tunnel
sudo systemctl start tunnel-server
```

`rotate-key [--data <dir>]` печатает число звеньев цепочки, старый и новый
Server code и pubkey. Старый ключ подписывает новый, звено дописывается в
`server.json` (`rotations`). Клиенты, закрепившие любой из последних 8 ключей
цепочки, перезакрепляются сами; новым клиентам раздаётся напечатанный новый
код. Перед ротацией сделайте резервную копию (ниже). Раздел 8
[PROTOCOL.md](PROTOCOL.md).

## Метрики

`--metrics 127.0.0.1:9100` поднимает крошечный HTTP-сервер (один поток):

- `GET /metrics` — формат Prometheus: датчики `voidlink_sessions`,
  `voidlink_groups`, `voidlink_members`, `voidlink_invites_pending`
  (снимаются с состояния при каждом запросе) и счётчики
  `voidlink_relayed_frames_total`, `voidlink_bytes_relayed_total`,
  `voidlink_dropped_frames_total`, `voidlink_hello_total`,
  `voidlink_challenge_total`, `voidlink_ctrl_frames_total`;
- `GET /healthz` — `200 ok`, если живы все воркеры и housekeeping
  отмечался за последние 10 с, иначе `503 unavailable`.

Эндпоинт без авторизации — наружу (`0.0.0.0`) его не выставлять.

## TCP-фолбэк

По умолчанию сервер слушает и TCP на том же адресе и порту, что UDP (для
сетей, где режут UDP). По TCP ходят те же кадры протокола в рамке
`u16 LE длина` + кадр; сессия TCP-клиента ключуется адресом соединения,
ответы и релей ему идут по тому же соединению. Закрытие соединения сразу
снимает сессию (офлайн без ожидания `--session-timeout`). Лимиты: 1024
соединения, 8 с одного IP, простой без целого кадра 30 с — закрытие.
Порт TCP занят — сервер пишет предупреждение и работает только по UDP.
`--no-tcp` выключает фолбэк. Файрвол: `ufw allow 5555/tcp`.

## Остановка

`systemctl stop` шлёт `SIGTERM` (`SIGINT`/Ctrl+C — так же; на Windows —
Ctrl+C, Ctrl+Break и закрытие консоли): сервер останавливает воркеры, TCP и
метрики, делает финальное сохранение `server.json` и выходит с кодом 0.
Повторный сигнал во время остановки — немедленный выход с кодом 1. Запись
файла атомарная (tmp + rename) — наполовину записанным он не бывает.
Клиенты после рестарта сервера получают `RESET` и переподключаются за секунды.

`Restart=on-failure`: упавший сервер поднимается через 2 с. Если
`server.json` повреждён, сервер **не стартует** (а не создаёт новую identity,
из-за которой все клиенты потеряли бы сервер) — восстановите файл из копии.

## Резервная копия `server.json`

В `server.json` — identity сервера (приватный ключ; от него зависит Server
code), группы, `user_ips` (постоянный оверлейный адрес каждой identity, один
на все её группы), бан-листы, инвайты, цепочка ротаций. Потеря файла =
новый Server code и пустой сервер: всем клиентам придётся перенастраиваться.

Адреса пользователей (`user_ips`, hex pubkey → IP) сохраняются в `server.json`
и переживают рестарт и выход из всех групп. `server.json` от v3 (без
`user_ips`) загружается автоматически: адрес identity берётся из группы с
наименьшим gid. Подробнее об адресации — в [NETWORKING.md](NETWORKING.md).

Копия «на горячую» безопасна (файл заменяется атомарно, читается целиком):

```
sudo install -m 0600 /var/lib/tunnel/server.json ~/server.json.$(date +%F)
```

Периодически, например cron/systemd-timer раз в сутки:

```
0 4 * * * root install -m 0600 /var/lib/tunnel/server.json /root/backup/server.json.$(date +\%F)
```

Восстановление:

```
sudo systemctl stop tunnel-server
sudo install -o tunnel -g tunnel -m 0600 server.json.YYYY-MM-DD /var/lib/tunnel/server.json
sudo systemctl start tunnel-server
```

Перенос на другой VPS — то же самое: новый сервер с этим `server.json`
сохраняет Server code; клиентам достаточно сменить адрес
(`del-server` + `add-server` с прежним кодом).
