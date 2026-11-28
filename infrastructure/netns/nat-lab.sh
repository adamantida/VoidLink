#!/usr/bin/env bash
# nat-lab.sh — лаборатория NAT на сетевых пространствах имён Linux (ip netns +
# veth + nftables) для проверки пробития NAT, релея и фолбэков VoidLink.
#
# Запуск: Linux, root (или CAP_NET_ADMIN), iproute2, nftables, ping, ss.
# Подходит для CI-раннера (ubuntu) или одноразовой ВМ. См. docs/DEVELOPMENT.md.
#
#   sudo ./nat-lab.sh run <сценарий>     поднять сеть, сервер, клиентов, проверить, снести
#   sudo ./nat-lab.sh up <сценарий>      только сеть
#   sudo ./nat-lab.sh start              сервер + два клиента (сеть уже поднята)
#   sudo ./nat-lab.sh check              ping по оверлею + direct/relay по счётчику сервера
#   sudo ./nat-lab.sh exec <ns> <cmd…>   команда внутри пространства (srv|wan|nat1|nat2|c1|c2)
#   sudo ./nat-lab.sh down               убить процессы, удалить пространства
#   ./nat-lab.sh list                    список сценариев
#
# Сценарии (EXPECT — ожидаемый путь трафика c1↔c2):
#   cone          c1, c2 за разными port-restricted cone NAT (порт сохраняется)  → direct
#   symmetric     оба за symmetric NAT (случайный порт на каждое назначение)     → relay
#   mixed         c1 за cone, c2 за symmetric                                     → relay
#   samenat       c1, c2 за одним NAT, hairpin выключен (только LAN-кандидаты)   → direct
#   samenat-nolan то же, lan_discovery: false у обоих (ни LAN, ни hairpin)        → relay
#   hairpin       c1, c2 за одним NAT, hairpin включён                            → direct
#   hairpin-nolan то же, lan_discovery: false — работает только hairpin-путь      → direct
#   udpblock      у c1 UDP наружу заблокирован                                    → tcp (фолбэк)
#
# Коды возврата check/run: 0 PASS, 1 FAIL, 2 нет TUN на этой ОС,
#   3 XFAIL (udpblock до TCP-фолбэка: ping не прошёл, но движок c1 жив и
#   сообщил о недоступности сервера — ожидаемое поведение).
#
# Топология (адреса фиксированы):
#
#   vl-srv 203.0.113.10 ──┐
#                         ├── br0 (vl-wan, «интернет» 203.0.113.0/24)
#   vl-nat1 203.0.113.21 ─┤                 vl-nat2 203.0.113.22
#     lan 10.1.0.1/24     │                   lan 10.2.0.1/24
#     ├─ vl-c1 10.1.0.11  └───────────────────  └─ vl-c2 10.2.0.12
#     └─ vl-c2 10.1.0.12   (samenat*/hairpin*: c2 в LAN nat1, nat2 не создаётся)
#
# Замечание о «full cone»: conntrack Linux фильтрует входящее по полному
# кортежу (адрес+порт удалённой стороны), поэтому «cone» здесь —
# port-restricted cone с сохранением порта (endpoint-independent mapping).
# Для пробития NAT этого достаточно и это самый частый домашний NAT.
#
# Переменные окружения:
#   SERVER_BIN   путь к tunnel-server        (по умолчанию: target/release/tunnel-server)
#   CLIENT_BIN   путь к tunnel-client        (по умолчанию: target/release/tunnel-client)
#   CLIENT_RUN   подкоманда движка клиента   (по умолчанию: run)
#   ADAPTER      имя TUN-интерфейса клиента  (по умолчанию: vl0)
#   WORK         каталог данных и логов      (по умолчанию: /tmp/vl-nat-lab)
#   PINGS        число ping в check          (по умолчанию: 20)
#   SETTLE       секунд на пробитие до check (по умолчанию: 8)
#   STOP_WAIT    секунд на штатную остановку по SIGTERM в down (по умолчанию: 3)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
SERVER_BIN="${SERVER_BIN:-$REPO/target/release/tunnel-server}"
CLIENT_BIN="${CLIENT_BIN:-$REPO/target/release/tunnel-client}"
CLIENT_RUN="${CLIENT_RUN:-run}"
ADAPTER="${ADAPTER:-vl0}"
WORK="${WORK:-/tmp/vl-nat-lab}"
PINGS="${PINGS:-20}"
SETTLE="${SETTLE:-8}"
STOP_WAIT="${STOP_WAIT:-3}"

SRV_IP=203.0.113.10
SRV_PORT=5555
NAT1_WAN=203.0.113.21
NAT2_WAN=203.0.113.22
ALL_NS=(vl-c1 vl-c2 vl-nat1 vl-nat2 vl-srv vl-wan)

log() { printf '\033[1;34m[nat-lab]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[nat-lab] ОШИБКА:\033[0m %s\n' "$*" >&2; exit 1; }
nsx() { local ns="$1"; shift; ip netns exec "$ns" "$@"; }

need_root() {
    [[ $(id -u) -eq 0 ]] || die "нужен root (ip netns / nft)"
    local t
    for t in ip nft ping ss; do
        command -v "$t" >/dev/null || die "не найдено: $t"
    done
}

scenario_expect() {
    case "$1" in
        cone | samenat | hairpin | hairpin-nolan) echo direct ;;
        symmetric | mixed | samenat-nolan) echo relay ;;
        udpblock) echo tcp ;;
        *) die "неизвестный сценарий: $1 (см. ./nat-lab.sh list)" ;;
    esac
}

# --- сеть -------------------------------------------------------------------

mk_ns() {
    ip netns add "$1"
    nsx "$1" ip link set lo up
}

# veth: $1 ns_a, $2 if_a, $3 ns_b, $4 if_b
mk_veth() {
    ip link add "$2" netns "$1" type veth peer name "$4" netns "$3"
    nsx "$1" ip link set "$2" up
    nsx "$3" ip link set "$4" up
}

# nftables NAT-роутера: $1 ns, $2 LAN-подсеть, $3 WAN-адрес, $4 режим (cone|symmetric)
nat_rules() {
    local ns="$1" lan="$2" wan="$3" mode="$4" masq="masquerade"
    [[ $mode == symmetric ]] && masq="masquerade fully-random"
    nsx "$ns" nft -f - <<EOF
table ip vlnat {
    chain pre {
        type nat hook prerouting priority dstnat; policy accept;
    }
    chain post {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "wan" ip saddr $lan $masq
        # hairpin: развёрнутый обратно в LAN пакет уходит с WAN-адреса роутера
        oifname "lan" ip saddr $lan ip daddr $lan ct status dnat snat ip to $wan
    }
    chain fwd {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname "lan" accept
    }
}
EOF
}

# NAT-роутер: $1 номер (1|2), $2 режим
mk_nat() {
    local n="$1" mode="$2" ns="vl-nat$1" wan
    wan=$([[ $n == 1 ]] && echo "$NAT1_WAN" || echo "$NAT2_WAN")
    mk_ns "$ns"
    nsx "$ns" sysctl -qw net.ipv4.ip_forward=1
    mk_veth vl-wan "wan-nat$n" "$ns" wan
    nsx vl-wan ip link set "wan-nat$n" master br0
    nsx "$ns" ip addr add "$wan/24" dev wan
    nsx "$ns" ip link add lan type bridge
    nsx "$ns" ip addr add "10.$n.0.1/24" dev lan
    nsx "$ns" ip link set lan up
    nat_rules "$ns" "10.$n.0.0/24" "$wan" "$mode"
    echo "$mode" >"$WORK/nat$n.mode"
}

# клиент: $1 имя (c1|c2), $2 номер NAT, $3 адрес в LAN
mk_client() {
    local c="$1" n="$2" addr="$3" ns="vl-$1"
    mk_ns "$ns"
    mk_veth "vl-nat$n" "lan-$c" "$ns" eth0
    nsx "vl-nat$n" ip link set "lan-$c" master lan
    nsx "$ns" ip addr add "$addr/24" dev eth0
    nsx "$ns" ip route add default via "10.$n.0.1"
    echo "$n" >"$WORK/$c.nat"
}

cmd_up() {
    local sc="${1:-}"
    [[ -n $sc ]] || die "usage: up <сценарий>"
    scenario_expect "$sc" >/dev/null
    need_root
    cmd_down quiet
    # прогоны независимы: старые идентичности клиентов, группы сервера и логи
    # прошлого сценария удаляются (иначе add-server падает «сервер уже добавлен»)
    [[ -n $WORK && $WORK != / ]] || die "WORK пуст или равен /"
    rm -rf "${WORK:?}/c1" "${WORK:?}/c2" "${WORK:?}/srv"
    rm -f "$WORK"/*.log "$WORK"/*.group "$WORK"/*.mode "$WORK"/*.nat "$WORK"/*.pid \
        "$WORK/gid" "$WORK/scenario"
    mkdir -p "$WORK"
    echo "$sc" >"$WORK/scenario"

    mk_ns vl-wan
    nsx vl-wan ip link add br0 type bridge
    nsx vl-wan ip link set br0 up

    mk_ns vl-srv
    mk_veth vl-wan wan-srv vl-srv eth0
    nsx vl-wan ip link set wan-srv master br0
    nsx vl-srv ip addr add "$SRV_IP/24" dev eth0
    # счётчик датаграмм на порт сервера: по приросту видно, шёл ли ping через релей
    nsx vl-srv nft -f - <<EOF
table inet vlmon {
    counter relay_in {}
    chain in {
        type filter hook input priority filter; policy accept;
        udp dport $SRV_PORT ip saddr != $SRV_IP counter name relay_in
    }
}
EOF

    case "$sc" in
        cone)
            mk_nat 1 cone
            mk_nat 2 cone
            mk_client c1 1 10.1.0.11
            mk_client c2 2 10.2.0.12
            ;;
        symmetric)
            mk_nat 1 symmetric
            mk_nat 2 symmetric
            mk_client c1 1 10.1.0.11
            mk_client c2 2 10.2.0.12
            ;;
        mixed)
            mk_nat 1 cone
            mk_nat 2 symmetric
            mk_client c1 1 10.1.0.11
            mk_client c2 2 10.2.0.12
            ;;
        samenat | samenat-nolan | hairpin | hairpin-nolan)
            mk_nat 1 cone
            mk_client c1 1 10.1.0.11
            mk_client c2 1 10.1.0.12
            ;;
        udpblock)
            mk_nat 1 cone
            mk_nat 2 cone
            mk_client c1 1 10.1.0.11
            mk_client c2 2 10.2.0.12
            ;;
    esac
    nsx vl-c1 ping -c1 -W2 "$SRV_IP" >/dev/null || die "c1 не видит сервер (ICMP)"
    nsx vl-c2 ping -c1 -W2 "$SRV_IP" >/dev/null || die "c2 не видит сервер (ICMP)"
    log "сеть поднята: сценарий $sc, ожидается $(scenario_expect "$sc")"
}

# --- процессы ----------------------------------------------------------------

bg() { # $1 ns, $2 лог, $3… команда; pid → $WORK/<ns>.pid
    local ns="$1" out="$2"
    shift 2
    ip netns exec "$ns" "$@" >"$out" 2>&1 &
    echo $! >"$WORK/$ns.pid"
}

client() { # $1 имя, $2… аргументы tunnel-client
    local c="$1"
    shift
    nsx "vl-$c" "$CLIENT_BIN" --dir "$WORK/$c" "$@"
}

overlay_ip() { # из вывода create/join: «… мой IP 10.x.y.z»
    grep -oE 'мой IP [0-9.]+' "$1" | awk '{print $3}' | tail -n1
}

# Порты потока клиент → сервер по conntrack nat1: «<локальный> <публичный>».
# Публичный берётся из conntrack (dport ответа), а не равным локальному:
# masquerade может переназначить порт (коллизия c1/c2, старая запись).
# $1 LAN-адрес клиента.
nat_ports() {
    local addr="$1" line sp dp
    if command -v conntrack >/dev/null; then
        line=$(nsx vl-nat1 conntrack -L -p udp --orig-src "$addr" --orig-dst "$SRV_IP" \
            --dport "$SRV_PORT" 2>/dev/null | head -n1)
    else
        line=$(nsx vl-nat1 cat /proc/net/nf_conntrack 2>/dev/null |
            grep -F "src=$addr dst=$SRV_IP" | grep -F "dport=$SRV_PORT " | head -n1)
    fi
    # две группы sport/dport: оригинал (локальный sport) и ответ (публичный dport)
    sp=$(grep -oE 'sport=[0-9]+' <<<"$line" | head -n1 | cut -d= -f2)
    dp=$(grep -oE 'dport=[0-9]+' <<<"$line" | tail -n1 | cut -d= -f2)
    [[ -n $sp && -n $dp ]] && echo "$sp $dp"
}

# lan_discovery: false в client.json клиента (поле v3, см. PROTOCOL.md)
disable_lan() {
    local f="$WORK/$1/client.json"
    [[ -f $f ]] || die "нет $f"
    python3 - "$f" <<'PY'
import json, os, sys
p = sys.argv[1]
with open(p) as fh:
    cfg = json.load(fh)
cfg["lan_discovery"] = False
with open(p + ".tmp", "w") as fh:
    json.dump(cfg, fh, indent=2)
os.replace(p + ".tmp", p)
PY
}

cmd_start() {
    need_root
    [[ -f $WORK/scenario ]] || die "сначала: up <сценарий>"
    [[ -x $SERVER_BIN ]] || die "нет $SERVER_BIN (cargo build --release -p tunnel-server или SERVER_BIN=…)"
    [[ -x $CLIENT_BIN ]] || die "нет $CLIENT_BIN (CLIENT_BIN=…)"
    local sc code gid _
    sc=$(cat "$WORK/scenario")

    log "старт tunnel-server в vl-srv"
    bg vl-srv "$WORK/server.log" "$SERVER_BIN" "0.0.0.0:$SRV_PORT" --data "$WORK/srv"
    for _ in $(seq 1 50); do
        code=$(grep -oE 'TUN-[A-Za-z0-9-]+' "$WORK/server.log" | head -n1 || true)
        [[ -n $code ]] && break
        sleep 0.1
    done
    [[ -n ${code:-} ]] || die "сервер не напечатал Server code (см. $WORK/server.log)"
    log "server code: $code"

    for c in c1 c2; do
        client "$c" set-name "lab-$c" >/dev/null
        client "$c" add-server "$SRV_IP:$SRV_PORT" "$code" lab >/dev/null
    done
    client c1 create "nat-lab-$sc" | tee "$WORK/c1.group" >&2
    gid=$(grep -oE 'группа [0-9]+' "$WORK/c1.group" | awk '{print $2}')
    [[ -n $gid ]] || die "не удалось создать группу"
    client c2 join "$gid" | tee "$WORK/c2.group" >&2
    echo "$gid" >"$WORK/gid"

    if [[ $sc == *-nolan ]]; then
        disable_lan c1
        disable_lan c2
        log "lan_discovery: false у c1 и c2"
    fi

    if [[ $sc == udpblock ]]; then
        # группа уже настроена по UDP; дальше UDP c1 наружу режется целиком,
        # включая уже установленные потоки (правило встаёт первым в цепочке)
        nsx vl-nat1 nft insert rule ip vlnat fwd iifname lan oifname wan ip saddr 10.1.0.11 meta l4proto udp drop
        log "UDP от c1 наружу заблокирован"
    fi

    for c in c1 c2; do
        log "старт движка $c"
        # shellcheck disable=SC2086 # CLIENT_RUN может содержать несколько слов
        bg "vl-$c" "$WORK/$c.log" "$CLIENT_BIN" --dir "$WORK/$c" --adapter "$ADAPTER" --debug $CLIENT_RUN
    done
    sleep 2

    if [[ $sc == hairpin* ]]; then
        local m1 m2 l1 g1 l2 g2
        m1=$(nat_ports 10.1.0.11 || true)
        m2=$(nat_ports 10.1.0.12 || true)
        [[ -n $m1 && -n $m2 ]] || die "нет записи conntrack клиент → сервер в vl-nat1 (нужен conntrack или /proc/net/nf_conntrack)"
        read -r l1 g1 <<<"$m1"
        read -r l2 g2 <<<"$m2"
        # отражение публичного endpoint (WAN:публичный порт) на LAN-адрес и
        # локальный порт клиента
        nsx vl-nat1 nft add rule ip vlnat pre iifname lan ip daddr "$NAT1_WAN" udp dport "$g1" dnat ip to "10.1.0.11:$l1"
        nsx vl-nat1 nft add rule ip vlnat pre iifname lan ip daddr "$NAT1_WAN" udp dport "$g2" dnat ip to "10.1.0.12:$l2"
        log "hairpin включён: $NAT1_WAN:$g1 → 10.1.0.11:$l1, $NAT1_WAN:$g2 → 10.1.0.12:$l2"
    fi
}

cmd_check() {
    need_root
    local sc expect ip2 before after delta path rc=0
    sc=$(cat "$WORK/scenario")
    expect=$(scenario_expect "$sc")
    ip2=$(overlay_ip "$WORK/c2.group")
    [[ -n $ip2 ]] || die "нет оверлейного IP c2"
    log "ждём пробития ${SETTLE}s…"
    sleep "$SETTLE"

    if ! nsx vl-c1 ip link show "$ADAPTER" >/dev/null 2>&1; then
        log "в vl-c1 нет интерфейса $ADAPTER — TUN на этой ОС не поднят; хвост логов:"
        tail -n 20 "$WORK/c1.log" "$WORK/c2.log" >&2 || true
        return 2
    fi

    before=$(counter_val)
    if nsx vl-c1 ping -c "$PINGS" -i 0.2 -W 2 "$ip2" >"$WORK/ping.log" 2>&1; then
        log "ping c1 → c2 ($ip2): ок"
    else
        log "ping c1 → c2 ($ip2): потери/нет ответа"
        rc=1
    fi
    tail -n 2 "$WORK/ping.log" >&2
    after=$(counter_val)
    delta=$((after - before))
    # через релей каждая пара echo/reply даёт ≥2 датаграммы на сервер; фон (keepalive) мал
    if ((delta >= PINGS)); then path=relay; else path=direct; fi
    [[ $expect == tcp ]] && path="tcp?(udp-счётчик $delta)"
    log "датаграмм на сервер за ping: $delta → путь: $path, ожидалось: $expect"
    if [[ $expect != tcp && $path != "$expect" ]]; then rc=1; fi
    if [[ $expect == tcp ]] && ((rc != 0)); then
        # до TCP-фолбэка: ожидается «сервер недоступен» без падения движка
        if c1_alive && grep -qiE 'недоступен|unreachable|timed? ?out|таймаут' "$WORK/c1.log"; then
            log "СЦЕНАРИЙ $sc: XFAIL — TCP-фолбэка нет, движок c1 жив и сообщил о недоступности"
            return 3
        fi
        log "движок c1 упал или не сообщил о недоступности сервера"
    fi
    if ((rc == 0)); then
        log "СЦЕНАРИЙ $sc: PASS"
    else
        log "СЦЕНАРИЙ $sc: FAIL (логи: $WORK)"
    fi
    return "$rc"
}

c1_alive() {
    [[ -f $WORK/vl-c1.pid ]] && kill -0 "$(cat "$WORK/vl-c1.pid")" 2>/dev/null
}

counter_val() {
    nsx vl-srv nft list counter inet vlmon relay_in | grep -oE 'packets [0-9]+' | awk '{print $2}'
}

cmd_down() {
    local ns pid alive _ pids=() names=()
    for ns in "${ALL_NS[@]}"; do
        if [[ -f $WORK/$ns.pid ]]; then
            pid=$(cat "$WORK/$ns.pid")
            # SIGTERM: заодно проверяется корректная остановка сервера/движка
            if kill -TERM "$pid" 2>/dev/null; then
                pids+=("$pid")
                names+=("$ns")
            fi
            rm -f "$WORK/$ns.pid"
        fi
    done
    # даём процессам STOP_WAIT секунд завершиться штатно, только потом KILL
    for _ in $(seq 1 $((STOP_WAIT * 10))); do
        alive=0
        for ns in "${ALL_NS[@]}"; do
            [[ -n $(ip netns pids "$ns" 2>/dev/null) ]] && alive=1
        done
        ((alive)) || break
        sleep 0.1
    done
    if [[ ${1:-} != quiet ]]; then
        local i
        for i in "${!pids[@]}"; do
            if kill -0 "${pids[$i]}" 2>/dev/null; then
                log "${names[$i]}: не остановился по SIGTERM за ${STOP_WAIT}s — KILL"
            else
                log "${names[$i]}: остановлен по SIGTERM"
            fi
        done
        if [[ -d $WORK/srv ]]; then
            if [[ -n $(find "$WORK/srv" -name 'server.json' 2>/dev/null) ]]; then
                log "server.json сохранён"
            else
                log "server.json не найден в $WORK/srv"
            fi
        fi
    fi
    for ns in "${ALL_NS[@]}"; do
        if ip netns pids "$ns" >/dev/null 2>&1; then
            ip netns pids "$ns" 2>/dev/null | xargs -r kill -KILL 2>/dev/null || true
            ip netns del "$ns" 2>/dev/null || true
        fi
    done
    [[ ${1:-} == quiet ]] || log "лаборатория снесена (логи остались в $WORK)"
}

cmd_run() {
    local sc="${1:-}" rc=0
    cmd_up "$sc"
    trap 'cmd_down' EXIT
    cmd_start
    cmd_check || rc=$?
    return "$rc"
}

cmd_exec() {
    local ns="${1:-}"
    shift || true
    [[ -n $ns ]] || die "usage: exec <srv|wan|nat1|nat2|c1|c2> <cmd…>"
    nsx "vl-$ns" "$@"
}

case "${1:-help}" in
    up) cmd_up "${2:-}" ;;
    start) cmd_start ;;
    check) cmd_check ;;
    down) need_root && cmd_down ;;
    run) cmd_run "${2:-}" ;;
    exec)
        shift
        cmd_exec "$@"
        ;;
    list) printf '%s\n' cone symmetric mixed samenat samenat-nolan hairpin hairpin-nolan udpblock ;;
    *) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
