//! Кодеки payload'ов управляющих сообщений (клиент ↔ сервер), разделы 4–6
//! спецификации. Рукопожатие — в [`crate::handshake`], FRAG — в [`crate::frag`].
//!
//! Декодеры не паникуют, отвергают обрезку и не выделяют память по счётчику
//! из сети больше, чем может поместиться в остаток payload'а. Хвост после
//! известных полей допускается (расширение без смены версии).

use std::net::SocketAddr;

use crate::{
    FRAG_MAX_PAYLOAD, Reader, put_bool, put_pub, put_str, put_u16, put_u32, put_u64, str_wire_len,
};
use anyhow::{Result, bail, ensure};

/// Наибольшее число адресов-кандидатов (CANDIDATES, MemberInfo).
pub const MAX_CANDIDATES: usize = 4;

fn put_addr_opt(buf: &mut Vec<u8>, a: Option<&SocketAddr>) {
    match a {
        Some(a) => put_str(buf, &a.to_string()),
        None => put_str(buf, ""),
    }
}

fn put_candidates(buf: &mut Vec<u8>, c: &[SocketAddr]) {
    let c = &c[..c.len().min(MAX_CANDIDATES)];
    buf.push(c.len() as u8);
    for a in c {
        put_str(buf, &a.to_string());
    }
}

/// `n u8 (≤ 4) | n × str "ip:port"`; неразборчивые адреса выбрасываются.
fn read_candidates(r: &mut Reader) -> Result<Vec<SocketAddr>> {
    let n = r.u8()? as usize;
    ensure!(n <= MAX_CANDIDATES, "кандидатов {n} > {MAX_CANDIDATES}");
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if let Ok(a) = r.str()?.parse() {
            out.push(a);
        }
    }
    Ok(out)
}

// ---------- MemberInfo ----------

/// Участник группы (в GROUP_STATE / GROUP_UPDATE kind 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInfo {
    pub pubkey: [u8; 32],
    pub name: String,
    pub ip: u32,
    pub online: bool,
    pub status: String,
    /// Публичный UDP-endpoint (только онлайн и не invisible); неразборчивый
    /// на проводе — `None`.
    pub endpoint: Option<SocketAddr>,
    /// Адреса в локальной сети пира (≤ 4), для PUNCH.
    pub candidates: Vec<SocketAddr>,
}

/// Минимальный размер MemberInfo на проводе.
const MEMBER_MIN: usize = 32 + 1 + 4 + 1 + 1 + 1 + 1;

pub fn put_member(buf: &mut Vec<u8>, m: &MemberInfo) {
    put_pub(buf, &m.pubkey);
    put_str(buf, &m.name);
    put_u32(buf, m.ip);
    put_bool(buf, m.online);
    put_str(buf, &m.status);
    put_addr_opt(buf, m.endpoint.as_ref());
    put_candidates(buf, &m.candidates);
}

pub fn read_member(r: &mut Reader) -> Result<MemberInfo> {
    Ok(MemberInfo {
        pubkey: r.pub_key()?,
        name: r.str()?,
        ip: r.u32()?,
        online: r.boolean()?,
        status: r.str()?,
        endpoint: r.str()?.parse().ok(),
        candidates: read_candidates(r)?,
    })
}

// ---------- mesh-метаданные в GROUP_STATE / GROUP_UPDATE (§4.2) ----------

/// Магия mesh-хвоста `GROUP_STATE`: `'MSH1'` в big-endian (`0x4D534831`).
pub const MESH_MAGIC: u32 = 0x4D53_4831;
/// Минимальный размер `MeshEntry` на проводе.
pub const MESH_ENTRY_MIN: usize = 4 + 32 + 1;
/// Больше записей, чем влезает в u8-счётчик, не кодируется.
pub const MAX_MESH_ENTRIES: usize = 255;

/// Mesh-метаданные участника группы: статический x25519-ключ (идентификатор
/// контакта DHT) и маска возможностей.
///
/// В `GROUP_STATE` записи идут по возрастанию `ip`; сопоставление — по `ip`
/// (не по индексу), поэтому порядок массива не важен.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshEntry {
    /// Адрес оверлея участника — ключ сопоставления с [`MemberInfo`].
    pub ip: u32,
    /// Статический x25519-ключ (для DHT-контактов; в рукопожатии mesh не
    /// участвует — там эфемерные ключи).
    pub x_pub: [u8; 32],
    /// `mesh::caps::*`.
    pub caps: u8,
}

pub fn put_mesh_entry(buf: &mut Vec<u8>, e: &MeshEntry) {
    put_u32(buf, e.ip);
    put_pub(buf, &e.x_pub);
    buf.push(e.caps);
}

pub fn read_mesh_entry(r: &mut Reader) -> Result<MeshEntry> {
    Ok(MeshEntry {
        ip: r.u32()?,
        x_pub: r.pub_key()?,
        caps: r.u8()?,
    })
}

/// Хвост `GROUP_STATE`: `MESH_MAGIC | n u8 | n × MeshEntry`. Пустой список не
/// кодируется вовсе — старые серверы хвоста не шлют и не должны платить.
pub fn enc_mesh_section(buf: &mut Vec<u8>, mesh: &[MeshEntry]) {
    let n = mesh.len().min(MAX_MESH_ENTRIES);
    if n == 0 {
        return;
    }
    put_u32(buf, MESH_MAGIC);
    buf.push(n as u8);
    for e in &mesh[..n] {
        put_mesh_entry(buf, e);
    }
}

/// Разбор хвоста `GROUP_STATE`. Нет байт или хвост не наш (чужое будущее
/// расширение) — mesh-метаданных нет: старый сервер и старый клиент
/// совместимы без смены версии (§4.3).
pub fn dec_mesh_section(r: &mut Reader) -> Result<Vec<MeshEntry>> {
    if r.peek_u32() != Some(MESH_MAGIC) {
        return Ok(Vec::new());
    }
    let _magic = r.u32()?;
    let n = r.u8()? as usize;
    let mut out = Vec::with_capacity(r.capacity_for(n, MESH_ENTRY_MIN));
    for _ in 0..n {
        out.push(read_mesh_entry(r)?);
    }
    Ok(out)
}

/// Хвост `GROUP_UPDATE` kind 1: `MESH_MAGIC | x_pub(32) | caps(1)` — только
/// метаданные изменившегося участника (`ip` есть в самой дельте).
pub fn enc_update_mesh_tail(buf: &mut Vec<u8>, mesh: &[MeshEntry]) {
    let Some(e) = mesh.first() else { return };
    put_u32(buf, MESH_MAGIC);
    put_pub(buf, &e.x_pub);
    buf.push(e.caps);
}

/// Разбор хвоста `GROUP_UPDATE`. `ip` в хвосте нет — в возвращаемой записи
/// он нулевой: адрес берётся из `MemberInfo` дельты.
pub fn dec_update_mesh_tail(r: &mut Reader) -> Result<Vec<MeshEntry>> {
    if r.peek_u32() != Some(MESH_MAGIC) {
        return Ok(Vec::new());
    }
    let _magic = r.u32()?;
    let x_pub = r.pub_key()?;
    let caps = r.u8()?;
    Ok(vec![MeshEntry { ip: 0, x_pub, caps }])
}

// ---------- клиент -> сервер ----------

/// CREATE_GROUP: имя + приватность.
pub fn enc_create_group(name: &str, private: bool) -> Vec<u8> {
    let mut v = Vec::new();
    put_str(&mut v, name);
    put_bool(&mut v, private);
    v
}

pub fn dec_create_group(p: &[u8]) -> Result<(String, bool)> {
    let mut r = Reader::new(p);
    let name = r.str()?;
    let private = r.boolean()?;
    Ok((name, private))
}

/// Один u32: gid (JOIN / LEAVE / DELETE / DECLINE_INVITE / GET_GROUP /
/// GROUP_ADMIN) или `from` (LIST_INVITES).
pub fn enc_gid(gid: u32) -> Vec<u8> {
    gid.to_be_bytes().to_vec()
}

pub fn dec_gid(p: &[u8]) -> Result<u32> {
    Reader::new(p).u32()
}

/// LIST_INVITES: from u32 (то же, что `enc_gid`).
pub fn enc_u32(v: u32) -> Vec<u8> {
    enc_gid(v)
}

pub fn dec_u32(p: &[u8]) -> Result<u32> {
    dec_gid(p)
}

/// INVITE / KICK / BAN / UNBAN / TRANSFER_OWNER: gid + pubkey цели.
pub fn enc_gid_target(gid: u32, target: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(36);
    put_u32(&mut v, gid);
    put_pub(&mut v, target);
    v
}

pub fn dec_gid_target(p: &[u8]) -> Result<(u32, [u8; 32])> {
    let mut r = Reader::new(p);
    let gid = r.u32()?;
    let target = r.pub_key()?;
    Ok((gid, target))
}

/// RENAME: gid + имя.
pub fn enc_rename(gid: u32, name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    put_u32(&mut v, gid);
    put_str(&mut v, name);
    v
}

pub fn dec_rename(p: &[u8]) -> Result<(u32, String)> {
    let mut r = Reader::new(p);
    let gid = r.u32()?;
    let name = r.str()?;
    Ok((gid, name))
}

/// STATUS: статус-текст.
pub fn enc_status(text: &str) -> Vec<u8> {
    let mut v = Vec::new();
    put_str(&mut v, text);
    v
}

pub fn dec_status(p: &[u8]) -> Result<String> {
    Reader::new(p).str()
}

/// FRIEND_GROUPS: pubkey друга.
pub fn enc_pubkey(pubkey: &[u8; 32]) -> Vec<u8> {
    pubkey.to_vec()
}

pub fn dec_pubkey(p: &[u8]) -> Result<[u8; 32]> {
    Reader::new(p).pub_key()
}

/// CANDIDATES: `n u8 (≤ 4) | n × str "ip:port"`. Больше 4 — берутся первые.
pub fn enc_candidates(addrs: &[SocketAddr]) -> Vec<u8> {
    let mut v = Vec::new();
    put_candidates(&mut v, addrs);
    v
}

/// n > 4 — ошибка; адреса, не разбираемые как `SocketAddr`, выбрасываются.
pub fn dec_candidates(p: &[u8]) -> Result<Vec<SocketAddr>> {
    read_candidates(&mut Reader::new(p))
}

/// PRESENCE: invisible bool.
pub fn enc_presence(invisible: bool) -> Vec<u8> {
    vec![invisible as u8]
}

pub fn dec_presence(p: &[u8]) -> Result<bool> {
    Reader::new(p).boolean()
}

/// MESH_INFO: `x_pub(32) | caps(1)` — публикация mesh-контакта клиента.
pub fn enc_mesh_info(x_pub: &[u8; 32], caps: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(33);
    put_pub(&mut v, x_pub);
    v.push(caps);
    v
}

pub fn dec_mesh_info(p: &[u8]) -> Result<([u8; 32], u8)> {
    let mut r = Reader::new(p);
    let x = r.pub_key()?;
    let caps = r.u8()?;
    Ok((x, caps))
}

/// Наибольшее число кандидатов-серверов в `SERVER_HINT` (§3.5).
pub const MAX_SERVER_HINT: usize = 8;

/// Кандидат-сервер для федерации: адрес (строка) и ожидаемый ed-ключ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHint {
    pub addr: String,
    pub ed_pub: [u8; 32],
}

/// SERVER_HINT: `n u8 (≤ 8) | n × (addr str | ed_pub 32)`. Больше 8 — берутся
/// первые: сервер и так не доверяет кандидатам, но лишние байты ему не нужны.
pub fn enc_server_hint(items: &[ServerHint]) -> Vec<u8> {
    let items = &items[..items.len().min(MAX_SERVER_HINT)];
    let mut v = Vec::new();
    v.push(items.len() as u8);
    for i in items {
        put_str(&mut v, &i.addr);
        put_pub(&mut v, &i.ed_pub);
    }
    v
}

pub fn dec_server_hint(p: &[u8]) -> Result<Vec<ServerHint>> {
    let mut r = Reader::new(p);
    let n = r.u8()? as usize;
    ensure!(n <= MAX_SERVER_HINT, "кандидатов {n} > {MAX_SERVER_HINT}");
    let mut out = Vec::with_capacity(r.capacity_for(n, 1 + 32));
    for _ in 0..n {
        out.push(ServerHint {
            addr: r.str()?,
            ed_pub: r.pub_key()?,
        });
    }
    Ok(out)
}

/// PROBE_REQ: ровно 64 байта — падинг, чтобы ответ (56 макс) был не длиннее
/// запроса. Падинг не имеет смысла и не проверяется.
pub const PROBE_REQ_LEN: usize = 64;
/// Длина nonce пробы.
pub const PROBE_NONCE_LEN: usize = 16;
/// PROBE_RESP без ключа: nonce(16) | ts_ms(8).
pub const PROBE_RESP_LEN: usize = PROBE_NONCE_LEN + 8;
/// PROBE_RESP с ключом: + ed_pub(32).
pub const PROBE_RESP_KEY_LEN: usize = PROBE_RESP_LEN + 32;

/// Тело PROBE_REQ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeReq {
    pub nonce: [u8; PROBE_NONCE_LEN],
    /// Время отправки, unix мс (сервер не отвечает на просроченные).
    pub ts_ms: u64,
    /// Просить ed-ключ сервера в ответе (сверка с закреплённым).
    pub want_key: bool,
}

/// PROBE_REQ: `nonce(16) | ts_ms(8, BE) | want_key(1) | pad` — ровно 64 байта.
pub fn enc_probe_req(req: &ProbeReq) -> Vec<u8> {
    let mut v = vec![0u8; PROBE_REQ_LEN];
    v[..PROBE_NONCE_LEN].copy_from_slice(&req.nonce);
    v[PROBE_NONCE_LEN..PROBE_NONCE_LEN + 8].copy_from_slice(&req.ts_ms.to_be_bytes());
    v[PROBE_NONCE_LEN + 8] = req.want_key as u8;
    v
}

pub fn dec_probe_req(p: &[u8]) -> Result<ProbeReq> {
    ensure!(
        p.len() == PROBE_REQ_LEN,
        "PROBE_REQ: длина {} вместо {PROBE_REQ_LEN}",
        p.len()
    );
    let mut r = Reader::new(p);
    let nonce = r.array()?;
    let ts_ms = r.u64()?;
    let want_key = r.boolean()?;
    Ok(ProbeReq {
        nonce,
        ts_ms,
        want_key,
    })
}

/// Тело PROBE_RESP: `nonce(16) | ts_ms(8) | [ed_pub(32)]` — 24 или 56 байт.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeResp {
    pub nonce: [u8; PROBE_NONCE_LEN],
    /// Эхо `ts_ms` запроса (клиент считает RTT по своим часам).
    pub ts_ms: u64,
    /// Ключ сервера — только если просили (`want_key`).
    pub ed_pub: Option<[u8; 32]>,
}

pub fn enc_probe_resp(resp: &ProbeResp) -> Vec<u8> {
    let mut v = Vec::with_capacity(match resp.ed_pub {
        Some(_) => PROBE_RESP_KEY_LEN,
        None => PROBE_RESP_LEN,
    });
    v.extend_from_slice(&resp.nonce);
    put_u64(&mut v, resp.ts_ms);
    if let Some(k) = &resp.ed_pub {
        put_pub(&mut v, k);
    }
    v
}

pub fn dec_probe_resp(p: &[u8]) -> Result<ProbeResp> {
    ensure!(
        p.len() == PROBE_RESP_LEN || p.len() == PROBE_RESP_KEY_LEN,
        "PROBE_RESP: длина {} не 24/56",
        p.len()
    );
    let mut r = Reader::new(p);
    let nonce = r.array()?;
    let ts_ms = r.u64()?;
    let ed_pub = if p.len() == PROBE_RESP_KEY_LEN {
        Some(r.pub_key()?)
    } else {
        None
    };
    Ok(ProbeResp {
        nonce,
        ts_ms,
        ed_pub,
    })
}

/// Наибольшее число контактов в `MESH_SEED` (§3.3: сервер шлёт до 16).
pub const MAX_MESH_SEED: usize = 16;

/// Контакт mesh-сети: ed-ключ (DHT-идентификатор), статический x-ключ и
/// публичный endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshSeed {
    pub ed_pub: [u8; 32],
    pub x_pub: [u8; 32],
    pub addr: SocketAddr,
}

/// MESH_SEED: `n u8 (≤ 16) | n × (ed_pub 32 | x_pub 32 | addr str)`.
/// Неразборчивый адрес выбрасывается (как в CANDIDATES): такой контакт
/// бесполезен, а ошибка из-за одного битого поля — нет.
pub fn enc_mesh_seed(items: &[MeshSeed]) -> Vec<u8> {
    let items = &items[..items.len().min(MAX_MESH_SEED)];
    let mut v = Vec::new();
    v.push(items.len() as u8);
    for i in items {
        put_pub(&mut v, &i.ed_pub);
        put_pub(&mut v, &i.x_pub);
        put_str(&mut v, &i.addr.to_string());
    }
    v
}

pub fn dec_mesh_seed(p: &[u8]) -> Result<Vec<MeshSeed>> {
    let mut r = Reader::new(p);
    let n = r.u8()? as usize;
    ensure!(n <= MAX_MESH_SEED, "контактов {n} > {MAX_MESH_SEED}");
    let mut out = Vec::with_capacity(r.capacity_for(n, 32 + 32 + 1));
    for _ in 0..n {
        let ed_pub = r.pub_key()?;
        let x_pub = r.pub_key()?;
        if let Ok(addr) = r.str()?.parse() {
            out.push(MeshSeed {
                ed_pub,
                x_pub,
                addr,
            });
        }
    }
    Ok(out)
}

/// Федерированная группа в FED_GROUPS (§3.5): `uuid` — идентификатор у
/// владельца, `gid` — локальный номер на этом сервере.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FedGroup {
    pub uuid: [u8; 16],
    pub gid: u32,
    pub name: String,
    pub owner: [u8; 32],
    /// Сколько участников (для экрана «группы федерации»).
    pub members: u16,
}

/// FED_GROUPS: `n u8 | n × (uuid 16 | gid 4 | name str | owner 32 | members 2)`.
pub fn enc_fed_groups(items: &[FedGroup]) -> Vec<u8> {
    let items = &items[..items.len().min(255)];
    let mut v = Vec::new();
    v.push(items.len() as u8);
    for i in items {
        v.extend_from_slice(&i.uuid);
        put_u32(&mut v, i.gid);
        put_str(&mut v, &i.name);
        put_pub(&mut v, &i.owner);
        put_u16(&mut v, i.members);
    }
    v
}

pub fn dec_fed_groups(p: &[u8]) -> Result<Vec<FedGroup>> {
    let mut r = Reader::new(p);
    let n = r.u8()? as usize;
    let mut out = Vec::with_capacity(r.capacity_for(n, 16 + 4 + 1 + 32 + 2));
    for _ in 0..n {
        out.push(FedGroup {
            uuid: r.array()?,
            gid: r.u32()?,
            name: r.str()?,
            owner: r.pub_key()?,
            members: r.u16()?,
        });
    }
    Ok(out)
}

// ---------- сервер -> клиент ----------

/// GROUP_STATE: полное состояние одной группы.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupState {
    pub gid: u32,
    /// Ревизия состояния (растёт на любое видимое изменение).
    pub rev: u32,
    /// Номер ключа `key`.
    pub epoch: u32,
    /// Прошлый ключ забыть сразу (выход/кик/бан), без grace.
    pub revoke_prev: bool,
    pub name: String,
    pub owner: [u8; 32],
    pub private: bool,
    pub key: [u8; 32],
    pub deleted: bool,
    pub my_ip: u32,
    pub members: Vec<MemberInfo>,
    /// Mesh-метаданные участников (хвост `'MSH1'`, §4.2). Пусто — старый
    /// сервер или никто ещё не публиковал mesh-контакт.
    pub mesh: Vec<MeshEntry>,
}

pub fn enc_group_state(g: &GroupState) -> Vec<u8> {
    let mut v = Vec::with_capacity(128 + g.members.len() * 96);
    put_u32(&mut v, g.gid);
    put_u32(&mut v, g.rev);
    put_u32(&mut v, g.epoch);
    put_bool(&mut v, g.revoke_prev);
    put_str(&mut v, &g.name);
    put_pub(&mut v, &g.owner);
    put_bool(&mut v, g.private);
    v.extend_from_slice(&g.key);
    put_bool(&mut v, g.deleted);
    put_u32(&mut v, g.my_ip);
    put_u32(&mut v, g.members.len() as u32);
    for m in &g.members {
        put_member(&mut v, m);
    }
    enc_mesh_section(&mut v, &g.mesh);
    v
}

pub fn dec_group_state(p: &[u8]) -> Result<GroupState> {
    let mut r = Reader::new(p);
    let gid = r.u32()?;
    let rev = r.u32()?;
    let epoch = r.u32()?;
    let revoke_prev = r.boolean()?;
    let name = r.str()?;
    let owner = r.pub_key()?;
    let private = r.boolean()?;
    let key = r.array()?;
    let deleted = r.boolean()?;
    let my_ip = r.u32()?;
    let n = r.u32()? as usize;
    let mut members = Vec::with_capacity(r.capacity_for(n, MEMBER_MIN));
    for _ in 0..n {
        members.push(read_member(&mut r)?);
    }
    let mesh = dec_mesh_section(&mut r)?;
    Ok(GroupState {
        gid,
        rev,
        epoch,
        revoke_prev,
        name,
        owner,
        private,
        key,
        deleted,
        my_ip,
        members,
        mesh,
    })
}

/// Тело дельты GROUP_UPDATE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupDelta {
    /// kind 1: участник добавлен/изменён.
    Member(MemberInfo),
    /// kind 2: участник удалён.
    Removed([u8; 32]),
    /// kind 3: метаданные группы.
    Meta {
        name: String,
        owner: [u8; 32],
        private: bool,
    },
}

impl GroupDelta {
    pub fn kind(&self) -> u8 {
        match self {
            GroupDelta::Member(_) => 1,
            GroupDelta::Removed(_) => 2,
            GroupDelta::Meta { .. } => 3,
        }
    }
}

/// GROUP_UPDATE: дельта к ревизии `base_rev`, результат — `rev`. Ключ —
/// текущий (эпохи `epoch`) в каждой дельте.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupUpdate {
    pub gid: u32,
    pub rev: u32,
    pub base_rev: u32,
    pub epoch: u32,
    pub revoke_prev: bool,
    pub key: [u8; 32],
    pub delta: GroupDelta,
    /// Mesh-метаданные изменившегося участника (хвост kind 1, §4.2).
    /// Не больше одной записи; `ip` в хвосте нет — он в `GroupDelta::Member`
    /// (у записи из разбора `ip == 0`). Пусто — хвоста нет.
    pub mesh: Vec<MeshEntry>,
}

pub fn enc_group_update(u: &GroupUpdate) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + 96);
    put_u32(&mut v, u.gid);
    put_u32(&mut v, u.rev);
    put_u32(&mut v, u.base_rev);
    put_u32(&mut v, u.epoch);
    put_bool(&mut v, u.revoke_prev);
    v.extend_from_slice(&u.key);
    v.push(u.delta.kind());
    match &u.delta {
        GroupDelta::Member(m) => put_member(&mut v, m),
        GroupDelta::Removed(pk) => put_pub(&mut v, pk),
        GroupDelta::Meta {
            name,
            owner,
            private,
        } => {
            put_str(&mut v, name);
            put_pub(&mut v, owner);
            put_bool(&mut v, *private);
        }
    }
    if matches!(u.delta, GroupDelta::Member(_)) {
        enc_update_mesh_tail(&mut v, &u.mesh);
    }
    v
}

/// Неизвестный kind — ошибка (клиент в ответ делает GET_GROUP).
pub fn dec_group_update(p: &[u8]) -> Result<GroupUpdate> {
    let mut r = Reader::new(p);
    let gid = r.u32()?;
    let rev = r.u32()?;
    let base_rev = r.u32()?;
    let epoch = r.u32()?;
    let revoke_prev = r.boolean()?;
    let key = r.array()?;
    let kind = r.u8()?;
    let delta = match kind {
        1 => GroupDelta::Member(read_member(&mut r)?),
        2 => GroupDelta::Removed(r.pub_key()?),
        3 => GroupDelta::Meta {
            name: r.str()?,
            owner: r.pub_key()?,
            private: r.boolean()?,
        },
        k => bail!("GROUP_UPDATE: неизвестный kind {k}"),
    };
    let mesh = if kind == 1 {
        dec_update_mesh_tail(&mut r)?
    } else {
        Vec::new()
    };
    Ok(GroupUpdate {
        gid,
        rev,
        base_rev,
        epoch,
        revoke_prev,
        key,
        delta,
        mesh,
    })
}

/// GROUP_LIST: сводка по группам (свои + публичные).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GroupSummary {
    pub gid: u32,
    pub name: String,
    pub private: bool,
    pub mine: bool,
    pub online: u32,
    pub total: u32,
    /// Только для своих групп (иначе 0): сверка с локальной ревизией.
    pub rev: u32,
    pub epoch: u32,
}

const SUMMARY_MIN: usize = 4 + 1 + 1 + 1 + 4 * 4;

pub fn enc_group_list(items: &[GroupSummary]) -> Vec<u8> {
    let mut v = Vec::new();
    put_u32(&mut v, items.len() as u32);
    for g in items {
        put_u32(&mut v, g.gid);
        put_str(&mut v, &g.name);
        put_bool(&mut v, g.private);
        put_bool(&mut v, g.mine);
        put_u32(&mut v, g.online);
        put_u32(&mut v, g.total);
        put_u32(&mut v, g.rev);
        put_u32(&mut v, g.epoch);
    }
    v
}

pub fn dec_group_list(p: &[u8]) -> Result<Vec<GroupSummary>> {
    let mut r = Reader::new(p);
    let n = r.u32()? as usize;
    let mut out = Vec::with_capacity(r.capacity_for(n, SUMMARY_MIN));
    for _ in 0..n {
        out.push(GroupSummary {
            gid: r.u32()?,
            name: r.str()?,
            private: r.boolean()?,
            mine: r.boolean()?,
            online: r.u32()?,
            total: r.u32()?,
            rev: r.u32()?,
            epoch: r.u32()?,
        });
    }
    Ok(out)
}

/// INVITE_RCVD / элемент INVITE_LIST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteInfo {
    pub gid: u32,
    pub group_name: String,
    pub from_pubkey: [u8; 32],
    pub from_name: String,
    /// Сколько секунд приглашение ещё действует.
    pub expires_in: u32,
}

const INVITE_MIN: usize = 4 + 1 + 32 + 1 + 4;

fn put_invite(v: &mut Vec<u8>, i: &InviteInfo) {
    put_u32(v, i.gid);
    put_str(v, &i.group_name);
    put_pub(v, &i.from_pubkey);
    put_str(v, &i.from_name);
    put_u32(v, i.expires_in);
}

fn read_invite(r: &mut Reader) -> Result<InviteInfo> {
    Ok(InviteInfo {
        gid: r.u32()?,
        group_name: r.str()?,
        from_pubkey: r.pub_key()?,
        from_name: r.str()?,
        expires_in: r.u32()?,
    })
}

pub fn enc_invite(i: &InviteInfo) -> Vec<u8> {
    let mut v = Vec::new();
    put_invite(&mut v, i);
    v
}

pub fn dec_invite(p: &[u8]) -> Result<InviteInfo> {
    read_invite(&mut Reader::new(p))
}

/// INVITE_LIST — окно неотвеченных приглашений: те, у кого gid ≥ `from`,
/// по возрастанию gid (сервер шлёт не больше 16 за раз). `complete` — после
/// последнего в окне неотвеченных больше нет.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteList {
    pub from: u32,
    pub items: Vec<InviteInfo>,
    pub complete: bool,
}

impl InviteList {
    /// Достоверен ли список для `gid`: окно покрывает gid от `from` до
    /// последнего в нём (полное — и дальше). Нет `gid` в покрытом окне —
    /// приглашения в него на сервере нет.
    pub fn covers(&self, gid: u32) -> bool {
        gid >= self.from && (self.complete || self.items.last().is_some_and(|l| l.gid >= gid))
    }

    /// Начало следующего окна (список неполный), иначе `None`.
    pub fn next_from(&self) -> Option<u32> {
        if self.complete {
            return None;
        }
        self.items.last().and_then(|l| l.gid.checked_add(1))
    }
}

/// INVITE_LIST: `from u32 | complete bool | n u8 × InviteInfo`. Больше 255
/// записей не кодируется (тогда и `complete` снимается).
pub fn enc_invite_list(l: &InviteList) -> Vec<u8> {
    let items = &l.items[..l.items.len().min(255)];
    let mut v = Vec::new();
    put_u32(&mut v, l.from);
    put_bool(&mut v, l.complete && items.len() == l.items.len());
    v.push(items.len() as u8);
    for i in items {
        put_invite(&mut v, i);
    }
    v
}

pub fn dec_invite_list(p: &[u8]) -> Result<InviteList> {
    let mut r = Reader::new(p);
    let from = r.u32()?;
    let complete = r.boolean()?;
    let n = r.u8()? as usize;
    let mut items = Vec::with_capacity(r.capacity_for(n, INVITE_MIN));
    for _ in 0..n {
        items.push(read_invite(&mut r)?);
    }
    Ok(InviteList {
        from,
        items,
        complete,
    })
}

/// INVITE_DECLINED: `gid | group_name str | by pk | by_name str`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteDeclined {
    pub gid: u32,
    pub group_name: String,
    pub by_pubkey: [u8; 32],
    pub by_name: String,
}

pub fn enc_invite_declined(d: &InviteDeclined) -> Vec<u8> {
    let mut v = Vec::new();
    put_u32(&mut v, d.gid);
    put_str(&mut v, &d.group_name);
    put_pub(&mut v, &d.by_pubkey);
    put_str(&mut v, &d.by_name);
    v
}

pub fn dec_invite_declined(p: &[u8]) -> Result<InviteDeclined> {
    let mut r = Reader::new(p);
    Ok(InviteDeclined {
        gid: r.u32()?,
        group_name: r.str()?,
        by_pubkey: r.pub_key()?,
        by_name: r.str()?,
    })
}

/// KICKED: клиента удалили из группы (`banned` — ещё и забанили). `rev` —
/// ревизия группы после кика: состояние группы не новее неё — запоздавшее
/// (раздел 5), а своей ревизии клиента для этого мало — она могла отставать.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kicked {
    pub gid: u32,
    pub group_name: String,
    pub banned: bool,
    pub rev: u32,
}

pub fn enc_kicked(k: &Kicked) -> Vec<u8> {
    let mut v = Vec::new();
    put_u32(&mut v, k.gid);
    put_str(&mut v, &k.group_name);
    put_bool(&mut v, k.banned);
    put_u32(&mut v, k.rev);
    v
}

pub fn dec_kicked(p: &[u8]) -> Result<Kicked> {
    let mut r = Reader::new(p);
    Ok(Kicked {
        gid: r.u32()?,
        group_name: r.str()?,
        banned: r.boolean()?,
        rev: r.u32()?,
    })
}

/// Забаненный в ADMIN_INFO. `name` — последнее известное серверу имя.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanEntry {
    pub pubkey: [u8; 32],
    pub name: String,
}

/// Висящее приглашение в ADMIN_INFO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingInvite {
    pub pubkey: [u8; 32],
    pub name: String,
    pub expires_in: u32,
}

/// ADMIN_INFO: `gid | n_bans u16 × (pk | name) | n_inv u16 × (pk | name | expires_in)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminInfo {
    pub gid: u32,
    pub bans: Vec<BanEntry>,
    pub invites: Vec<PendingInvite>,
}

/// Списки обрезаются так, чтобы payload влез в FRAG (`FRAG_MAX_PAYLOAD`) и
/// в u16-счётчики: сначала полностью баны, затем приглашения — в порядке
/// входа.
pub fn enc_admin_info(a: &AdminInfo) -> Vec<u8> {
    let mut budget = FRAG_MAX_PAYLOAD - 4 - 2 - 2;
    let mut take = |sizes: &mut dyn Iterator<Item = usize>| -> usize {
        let mut n = 0;
        for s in sizes {
            if s > budget || n == u16::MAX as usize {
                break;
            }
            budget -= s;
            n += 1;
        }
        n
    };
    let nb = take(&mut a.bans.iter().map(|b| 32 + str_wire_len(&b.name)));
    let ni = take(&mut a.invites.iter().map(|i| 32 + str_wire_len(&i.name) + 4));
    let mut v = Vec::new();
    put_u32(&mut v, a.gid);
    put_u16(&mut v, nb as u16);
    for b in &a.bans[..nb] {
        put_pub(&mut v, &b.pubkey);
        put_str(&mut v, &b.name);
    }
    put_u16(&mut v, ni as u16);
    for i in &a.invites[..ni] {
        put_pub(&mut v, &i.pubkey);
        put_str(&mut v, &i.name);
        put_u32(&mut v, i.expires_in);
    }
    v
}

pub fn dec_admin_info(p: &[u8]) -> Result<AdminInfo> {
    let mut r = Reader::new(p);
    let gid = r.u32()?;
    let nb = r.u16()? as usize;
    let mut bans = Vec::with_capacity(r.capacity_for(nb, 33));
    for _ in 0..nb {
        bans.push(BanEntry {
            pubkey: r.pub_key()?,
            name: r.str()?,
        });
    }
    let ni = r.u16()? as usize;
    let mut invites = Vec::with_capacity(r.capacity_for(ni, 37));
    for _ in 0..ni {
        invites.push(PendingInvite {
            pubkey: r.pub_key()?,
            name: r.str()?,
            expires_in: r.u32()?,
        });
    }
    Ok(AdminInfo { gid, bans, invites })
}

/// ERROR: текст ошибки.
pub fn enc_error(text: &str) -> Vec<u8> {
    let mut v = Vec::new();
    put_str(&mut v, text);
    v
}

pub fn dec_error(p: &[u8]) -> Result<String> {
    Reader::new(p).str()
}

/// Группа друга в FRIEND_GROUPS_RESP.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FriendGroup {
    pub gid: u32,
    pub name: String,
    pub private: bool,
    /// Оба в группе.
    pub shared: bool,
}

/// FRIEND_GROUPS_RESP: о ком ответ (`target`) и его группы (публичные + общие).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendGroups {
    pub target: [u8; 32],
    pub groups: Vec<FriendGroup>,
}

pub fn enc_friend_groups(f: &FriendGroups) -> Vec<u8> {
    let mut v = Vec::new();
    put_pub(&mut v, &f.target);
    put_u32(&mut v, f.groups.len() as u32);
    for g in &f.groups {
        put_u32(&mut v, g.gid);
        put_str(&mut v, &g.name);
        put_bool(&mut v, g.private);
        put_bool(&mut v, g.shared);
    }
    v
}

pub fn dec_friend_groups(p: &[u8]) -> Result<FriendGroups> {
    let mut r = Reader::new(p);
    let target = r.pub_key()?;
    let n = r.u32()? as usize;
    let mut groups = Vec::with_capacity(r.capacity_for(n, 4 + 1 + 1 + 1));
    for _ in 0..n {
        groups.push(FriendGroup {
            gid: r.u32()?,
            name: r.str()?,
            private: r.boolean()?,
            shared: r.boolean()?,
        });
    }
    Ok(FriendGroups { target, groups })
}

/// RTT-зонд (grp::PING / PONG): 8-байтовая метка времени.
pub fn enc_ping(nonce: u64) -> Vec<u8> {
    nonce.to_be_bytes().to_vec()
}

pub fn dec_ping(p: &[u8]) -> Result<u64> {
    ensure!(p.len() == 8, "bad ping payload");
    Ok(u64::from_be_bytes(p.try_into().unwrap()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    pub(crate) fn member(i: u8) -> MemberInfo {
        MemberInfo {
            pubkey: [i; 32],
            name: format!("участник{i}"),
            ip: 0x6442_0100 + i as u32,
            online: i.is_multiple_of(2),
            status: "в игре".into(),
            endpoint: (!i.is_multiple_of(3)).then(|| sa("203.0.113.9:4000")),
            candidates: vec![sa("192.168.1.5:4000"), sa("[fe80::1]:4000")],
        }
    }

    pub(crate) fn group_state() -> GroupState {
        GroupState {
            gid: 3,
            rev: 17,
            epoch: 5,
            revoke_prev: true,
            name: "игра".into(),
            owner: [1; 32],
            private: true,
            key: [9; 32],
            deleted: false,
            my_ip: 0x6442_0302,
            members: (0..6).map(member).collect(),
            mesh: Vec::new(),
        }
    }

    /// То же состояние с mesh-метаданными двух участников.
    pub(crate) fn group_state_mesh() -> GroupState {
        GroupState {
            mesh: vec![
                MeshEntry {
                    ip: 0x6442_0100,
                    x_pub: [0xAA; 32],
                    caps: crate::mesh::caps::MESH | crate::mesh::caps::RELAY,
                },
                MeshEntry {
                    ip: 0x6442_0102,
                    x_pub: [0xBB; 32],
                    caps: crate::mesh::caps::MESH,
                },
            ],
            ..group_state()
        }
    }

    /// Каждая строгая обрезка — ошибка, не паника.
    fn truncations_fail<T>(enc: &[u8], dec: impl Fn(&[u8]) -> Result<T>) {
        for n in 0..enc.len() {
            assert!(dec(&enc[..n]).is_err(), "обрезка до {n} из {}", enc.len());
        }
    }

    #[test]
    fn group_state_туда_обратно() {
        let g = group_state();
        let enc = enc_group_state(&g);
        assert_eq!(dec_group_state(&enc).unwrap(), g);
        truncations_fail(&enc, dec_group_state);
        let deleted = GroupState {
            deleted: true,
            members: vec![],
            ..g
        };
        assert_eq!(
            dec_group_state(&enc_group_state(&deleted)).unwrap(),
            deleted
        );
    }

    #[test]
    fn member_кандидаты_и_endpoint() {
        let mut m = member(1);
        m.candidates = (0..6).map(|i| sa(&format!("10.0.0.{i}:1"))).collect();
        let mut v = Vec::new();
        put_member(&mut v, &m);
        let got = read_member(&mut Reader::new(&v)).unwrap();
        assert_eq!(got.candidates, m.candidates[..4], "больше 4 не кодируется");
        // Неразборчивый endpoint — None, неразборчивый кандидат выброшен.
        let mut raw = Vec::new();
        put_pub(&mut raw, &[0; 32]);
        put_str(&mut raw, "n");
        put_u32(&mut raw, 1);
        put_bool(&mut raw, true);
        put_str(&mut raw, "");
        put_str(&mut raw, "не адрес");
        raw.push(2);
        put_str(&mut raw, "1.2.3.4");
        put_str(&mut raw, "1.2.3.4:5");
        let got = read_member(&mut Reader::new(&raw)).unwrap();
        assert_eq!(got.endpoint, None);
        assert_eq!(got.candidates, vec![sa("1.2.3.4:5")]);
        // n_cand > 4 — ошибка.
        let mut bad = v.clone();
        let at = bad.len()
            - (1 + m.candidates[..4]
                .iter()
                .map(|a| 1 + a.to_string().len())
                .sum::<usize>());
        bad[at] = 5;
        assert!(read_member(&mut Reader::new(&bad)).is_err());
    }

    #[test]
    fn group_update_все_kind() {
        let base = GroupUpdate {
            gid: 3,
            rev: 18,
            base_rev: 17,
            epoch: 6,
            revoke_prev: false,
            key: [4; 32],
            delta: GroupDelta::Member(member(2)),
            mesh: Vec::new(),
        };
        let deltas = [
            GroupDelta::Member(member(2)),
            GroupDelta::Removed([7; 32]),
            GroupDelta::Meta {
                name: "новое".into(),
                owner: [8; 32],
                private: false,
            },
        ];
        for d in deltas {
            let u = GroupUpdate {
                delta: d,
                ..base.clone()
            };
            let enc = enc_group_update(&u);
            assert_eq!(dec_group_update(&enc).unwrap(), u);
            truncations_fail(&enc, dec_group_update);
            assert!(
                enc.len() <= crate::FRAG_THRESHOLD,
                "дельта влезает без FRAG"
            );
        }
        let mut enc = enc_group_update(&base);
        enc[4 * 4 + 1 + 32] = 4;
        assert!(dec_group_update(&enc).is_err(), "неизвестный kind");
    }

    #[test]
    fn group_list_туда_обратно() {
        let items = vec![
            GroupSummary {
                gid: 1,
                name: "a".into(),
                private: false,
                mine: true,
                online: 2,
                total: 3,
                rev: 9,
                epoch: 4,
            },
            GroupSummary {
                gid: 2,
                name: "б".into(),
                private: true,
                mine: false,
                online: 0,
                total: 1,
                rev: 0,
                epoch: 0,
            },
        ];
        let enc = enc_group_list(&items);
        assert_eq!(dec_group_list(&enc).unwrap(), items);
        truncations_fail(&enc, dec_group_list);
        assert!(dec_group_list(&enc_group_list(&[])).unwrap().is_empty());
    }

    fn inv(gid: u32) -> InviteInfo {
        InviteInfo {
            gid,
            group_name: format!("г{gid}"),
            from_pubkey: [gid as u8; 32],
            from_name: "alpha".into(),
            expires_in: 604_800u32.saturating_sub(gid),
        }
    }

    #[test]
    fn приглашение_и_отказ_туда_обратно() {
        let i = inv(42);
        let enc = enc_invite(&i);
        assert_eq!(dec_invite(&enc).unwrap(), i);
        truncations_fail(&enc, dec_invite);

        let d = InviteDeclined {
            gid: 7,
            group_name: "игра".into(),
            by_pubkey: [9; 32],
            by_name: "bravo".into(),
        };
        let enc = enc_invite_declined(&d);
        assert_eq!(dec_invite_declined(&enc).unwrap(), d);
        truncations_fail(&enc, dec_invite_declined);
    }

    #[test]
    fn список_приглашений_туда_обратно() {
        let l = InviteList {
            from: 0,
            items: vec![inv(1), inv(7)],
            complete: true,
        };
        let enc = enc_invite_list(&l);
        assert_eq!(dec_invite_list(&enc).unwrap(), l);
        truncations_fail(&enc, dec_invite_list);
        let empty = InviteList {
            from: 5,
            items: vec![],
            complete: false,
        };
        assert_eq!(dec_invite_list(&enc_invite_list(&empty)).unwrap(), empty);
        // Больше 255 — обрезается, complete снимается.
        let big = InviteList {
            from: 0,
            items: (0..300).map(inv).collect(),
            complete: true,
        };
        let got = dec_invite_list(&enc_invite_list(&big)).unwrap();
        assert_eq!(got.items.len(), 255);
        assert!(!got.complete);
    }

    #[test]
    fn окно_списка_приглашений_покрывает_от_from_до_последнего() {
        let part = InviteList {
            from: 10,
            items: vec![inv(12), inv(20)],
            complete: false,
        };
        assert!(!part.covers(9), "до from — не известно");
        assert!(part.covers(10) && part.covers(15) && part.covers(20));
        assert!(
            !part.covers(21),
            "после последнего в неполном — не известно"
        );
        assert_eq!(part.next_from(), Some(21));
        let full = InviteList {
            complete: true,
            ..part.clone()
        };
        assert!(full.covers(300) && !full.covers(9));
        assert_eq!(full.next_from(), None);
        let none = InviteList {
            from: 0,
            items: vec![],
            complete: true,
        };
        assert!(none.covers(0) && none.covers(u32::MAX));
        let last = InviteList {
            from: 0,
            items: vec![inv(u32::MAX)],
            complete: false,
        };
        assert_eq!(last.next_from(), None, "без переполнения");
    }

    #[test]
    fn kicked_admin_friend_туда_обратно() {
        let k = Kicked {
            gid: 5,
            group_name: "игра".into(),
            banned: true,
            rev: 42,
        };
        let enc = enc_kicked(&k);
        assert_eq!(dec_kicked(&enc).unwrap(), k);
        truncations_fail(&enc, dec_kicked);

        let a = AdminInfo {
            gid: 5,
            bans: vec![
                BanEntry {
                    pubkey: [1; 32],
                    name: "плохой".into(),
                },
                BanEntry {
                    pubkey: [2; 32],
                    name: String::new(),
                },
            ],
            invites: vec![PendingInvite {
                pubkey: [3; 32],
                name: "c".into(),
                expires_in: 100,
            }],
        };
        let enc = enc_admin_info(&a);
        assert_eq!(dec_admin_info(&enc).unwrap(), a);
        truncations_fail(&enc, dec_admin_info);
        let empty = AdminInfo {
            gid: 1,
            bans: vec![],
            invites: vec![],
        };
        assert_eq!(dec_admin_info(&enc_admin_info(&empty)).unwrap(), empty);

        let f = FriendGroups {
            target: [6; 32],
            groups: vec![FriendGroup {
                gid: 1,
                name: "x".into(),
                private: false,
                shared: true,
            }],
        };
        let enc = enc_friend_groups(&f);
        assert_eq!(dec_friend_groups(&enc).unwrap(), f);
        truncations_fail(&enc, dec_friend_groups);
    }

    #[test]
    fn admin_info_обрезается_под_frag() {
        let long = "ж".repeat(127);
        let a = AdminInfo {
            gid: 1,
            bans: (0..2000)
                .map(|i| BanEntry {
                    pubkey: [(i % 256) as u8; 32],
                    name: long.clone(),
                })
                .collect(),
            invites: vec![PendingInvite {
                pubkey: [0; 32],
                name: "x".into(),
                expires_in: 1,
            }],
        };
        let enc = enc_admin_info(&a);
        assert!(enc.len() <= FRAG_MAX_PAYLOAD);
        let got = dec_admin_info(&enc).unwrap();
        assert!(got.bans.len() < 2000 && !got.bans.is_empty());
        assert_eq!(got.bans[..], a.bans[..got.bans.len()]);
        assert!(crate::frag::split_frag(0, crate::ctrl::ADMIN_INFO, &enc).is_ok());
    }

    #[test]
    fn худший_group_state_влезает_в_frag() {
        // 253 участника с максимальными именами, статусами и адресами.
        let long = "w".repeat(255);
        let v6 = sa("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535");
        let m = MemberInfo {
            pubkey: [1; 32],
            name: long.clone(),
            ip: 1,
            online: true,
            status: long.clone(),
            endpoint: Some(v6),
            candidates: vec![v6; 4],
        };
        let g = GroupState {
            name: long,
            members: vec![m; 253],
            ..group_state()
        };
        let enc = enc_group_state(&g);
        assert!(
            enc.len() <= FRAG_MAX_PAYLOAD,
            "{} > {FRAG_MAX_PAYLOAD}",
            enc.len()
        );
    }

    #[test]
    fn candidates_и_presence() {
        let c = vec![sa("192.168.0.2:5000"), sa("[::1]:6000")];
        let enc = enc_candidates(&c);
        assert_eq!(dec_candidates(&enc).unwrap(), c);
        truncations_fail(&enc, dec_candidates);
        assert!(dec_candidates(&enc_candidates(&[])).unwrap().is_empty());
        // n > 4 — ошибка; мусорный адрес выбрасывается.
        assert!(dec_candidates(&[5]).is_err());
        let mut raw = vec![3u8];
        for s in ["10.0.0.1:1", "abc", "10.0.0.2"] {
            put_str(&mut raw, s);
        }
        assert_eq!(dec_candidates(&raw).unwrap(), vec![sa("10.0.0.1:1")]);
        assert!(dec_presence(&enc_presence(true)).unwrap());
        assert!(!dec_presence(&enc_presence(false)).unwrap());
        assert!(dec_presence(&[]).is_err());
    }

    #[test]
    fn простые_кодеки() {
        assert_eq!(dec_gid(&enc_gid(200)).unwrap(), 200);
        assert_eq!(dec_u32(&enc_u32(u32::MAX)).unwrap(), u32::MAX);
        assert_eq!(
            dec_gid_target(&enc_gid_target(4, &[5; 32])).unwrap(),
            (4, [5; 32])
        );
        assert!(dec_gid_target(&enc_gid_target(4, &[5; 32])[..35]).is_err());
        assert_eq!(
            dec_rename(&enc_rename(4, "имя")).unwrap(),
            (4, "имя".to_string())
        );
        assert_eq!(dec_status(&enc_status("ок")).unwrap(), "ок");
        assert_eq!(dec_error(&enc_error("ошибка")).unwrap(), "ошибка");
        assert_eq!(dec_pubkey(&enc_pubkey(&[3; 32])).unwrap(), [3; 32]);
        assert_eq!(
            dec_create_group(&enc_create_group("g", true)).unwrap(),
            ("g".to_string(), true)
        );
        assert_eq!(dec_ping(&enc_ping(77)).unwrap(), 77);
        assert!(dec_gid(&[1, 2, 3]).is_err());
        assert!(dec_ping(&[0; 7]).is_err());
    }

    // ---------- этап 9: mesh-секция, probe, hint/fed/seed ----------

    /// Копия декодера `GROUP_STATE` до этапа 9 (без mesh-хвоста) — так его
    /// читает v4-клиент: известные поля разбираются, хвост игнорируется.
    fn dec_group_state_v4(p: &[u8]) -> Result<GroupState> {
        let mut r = Reader::new(p);
        let gid = r.u32()?;
        let rev = r.u32()?;
        let epoch = r.u32()?;
        let revoke_prev = r.boolean()?;
        let name = r.str()?;
        let owner = r.pub_key()?;
        let private = r.boolean()?;
        let key = r.array()?;
        let deleted = r.boolean()?;
        let my_ip = r.u32()?;
        let n = r.u32()? as usize;
        let mut members = Vec::with_capacity(r.capacity_for(n, MEMBER_MIN));
        for _ in 0..n {
            members.push(read_member(&mut r)?);
        }
        Ok(GroupState {
            gid,
            rev,
            epoch,
            revoke_prev,
            name,
            owner,
            private,
            key,
            deleted,
            my_ip,
            members,
            mesh: Vec::new(),
        })
    }

    #[test]
    fn mesh_секция_group_state_и_v4_совместимость() {
        let with_mesh = group_state_mesh();
        let enc = enc_group_state(&with_mesh);
        assert_eq!(dec_group_state(&enc).unwrap(), with_mesh);
        let plain = enc_group_state(&group_state());
        assert_eq!(
            enc.len(),
            plain.len() + 4 + 1 + 2 * MESH_ENTRY_MIN,
            "хвост = магия + n + записи"
        );
        // Хвост — ровно после участников, ничего не сдвинулось.
        assert_eq!(&enc[..plain.len()], &plain[..]);
        assert_eq!(
            u32::from_be_bytes(enc[plain.len()..plain.len() + 4].try_into().unwrap()),
            MESH_MAGIC
        );
        // Пустой mesh не кодируется: старые серверы не платят за фичу.
        assert_eq!(
            enc_group_state(&GroupState {
                mesh: Vec::new(),
                ..with_mesh.clone()
            }),
            plain
        );
        // Обрезка ровно до конца участников — валидный payload без mesh; хвост
        // короче магии — «чужое расширение» и тоже игнорируется.
        assert_eq!(dec_group_state(&enc[..plain.len()]).unwrap(), group_state());
        for n in plain.len() + 1..plain.len() + 4 {
            assert!(
                dec_group_state(&enc[..n]).is_ok(),
                "хвост короче магии: {n}"
            );
        }
        // Обрезка внутри хвоста (магия и записи) — ошибка.
        for n in plain.len() + 4..enc.len() {
            assert!(dec_group_state(&enc[..n]).is_err(), "обрезка до {n}");
        }
        // Чужой хвост (не наша магия) игнорируется — расширение без смены
        // версии допустимо.
        let mut future = plain.clone();
        put_u32(&mut future, 0x5745_4952);
        future.extend_from_slice("будущее расширение".as_bytes());
        assert_eq!(dec_group_state(&future).unwrap(), group_state());
        // **v4-декодер игнорирует хвост**: читает то же состояние, mesh пуст.
        assert_eq!(dec_group_state_v4(&enc).unwrap(), group_state());
    }

    #[test]
    fn mesh_секция_счётчик_из_сети_не_аллоцирует() {
        // n больше остатка: ошибка, без раздувания аллокации.
        let mut raw = Vec::new();
        put_u32(&mut raw, MESH_MAGIC);
        raw.push(255);
        assert!(dec_mesh_section(&mut Reader::new(&raw)).is_err());
        // n = 0 — валидный пустой хвост.
        let mut raw = Vec::new();
        put_u32(&mut raw, MESH_MAGIC);
        raw.push(0);
        assert!(dec_mesh_section(&mut Reader::new(&raw)).unwrap().is_empty());
        // Мусорный хвост без магии — пусто (совместимость).
        assert!(
            dec_mesh_section(&mut Reader::new(&[1, 2, 3, 4, 5]))
                .unwrap()
                .is_empty()
        );
        assert!(dec_mesh_section(&mut Reader::new(&[])).unwrap().is_empty());
    }

    #[test]
    fn group_update_mesh_хвост() {
        let m = member(2);
        let u = GroupUpdate {
            gid: 3,
            rev: 18,
            base_rev: 17,
            epoch: 6,
            revoke_prev: false,
            key: [4; 32],
            delta: GroupDelta::Member(m.clone()),
            mesh: vec![MeshEntry {
                ip: 0,
                x_pub: [0xCC; 32],
                caps: crate::mesh::caps::MESH,
            }],
        };
        let enc = enc_group_update(&u);
        let got = dec_group_update(&enc).unwrap();
        assert_eq!(got.delta, GroupDelta::Member(m));
        assert_eq!(
            got.mesh,
            vec![MeshEntry {
                ip: 0,
                x_pub: [0xCC; 32],
                caps: crate::mesh::caps::MESH
            }],
            "ip в хвосте нет — адрес берётся из дельты"
        );
        // Без хвоста (старый сервер) — пусто.
        let no_mesh = GroupUpdate {
            mesh: Vec::new(),
            ..u.clone()
        };
        assert!(
            dec_group_update(&enc_group_update(&no_mesh))
                .unwrap()
                .mesh
                .is_empty()
        );
        // Обрезка внутри хвоста — ошибка; ровно без хвоста (и короче магии) —
        // валидно, хвост считается чужим/отсутствующим.
        let base = enc_group_update(&no_mesh);
        assert_eq!(dec_group_update(&enc[..base.len()]).unwrap().mesh, vec![]);
        for n in base.len() + 1..base.len() + 4 {
            assert!(
                dec_group_update(&enc[..n]).is_ok(),
                "хвост короче магии: {n}"
            );
        }
        for n in base.len() + 4..enc.len() {
            assert!(dec_group_update(&enc[..n]).is_err(), "обрезка до {n}");
        }
        // Хвост не для kind 1 не кодируется (у Removed/Meta нет x_pub).
        for delta in [
            GroupDelta::Removed([7; 32]),
            GroupDelta::Meta {
                name: "n".into(),
                owner: [8; 32],
                private: false,
            },
        ] {
            let u = GroupUpdate {
                delta,
                mesh: vec![MeshEntry {
                    ip: 0,
                    x_pub: [0xCC; 32],
                    caps: 1,
                }],
                ..u.clone()
            };
            let enc = enc_group_update(&u);
            assert_eq!(
                enc,
                enc_group_update(&GroupUpdate {
                    mesh: Vec::new(),
                    ..u.clone()
                })
            );
            assert!(dec_group_update(&enc).unwrap().mesh.is_empty());
        }
    }

    #[test]
    fn mesh_info_и_server_hint() {
        let enc = enc_mesh_info(
            &[0xAB; 32],
            crate::mesh::caps::MESH | crate::mesh::caps::RELAY,
        );
        assert_eq!(enc.len(), 33);
        assert_eq!(
            dec_mesh_info(&enc).unwrap(),
            (
                [0xAB; 32],
                crate::mesh::caps::MESH | crate::mesh::caps::RELAY
            )
        );
        truncations_fail(&enc, dec_mesh_info);
        // Хвост после известных полей допускается (расширение без смены версии).
        let mut tail = enc.clone();
        tail.push(0);
        assert_eq!(
            dec_mesh_info(&tail).unwrap(),
            (
                [0xAB; 32],
                crate::mesh::caps::MESH | crate::mesh::caps::RELAY
            )
        );

        let items = vec![
            ServerHint {
                addr: "203.0.113.9:5555".into(),
                ed_pub: [1; 32],
            },
            ServerHint {
                addr: "[2001:db8::1]:5555".into(),
                ed_pub: [2; 32],
            },
        ];
        let enc = enc_server_hint(&items);
        assert_eq!(dec_server_hint(&enc).unwrap(), items);
        truncations_fail(&enc, dec_server_hint);
        assert!(dec_server_hint(&enc_server_hint(&[])).unwrap().is_empty());
        // Больше 8 не кодируется; 9 в заголовке — ошибка.
        let many: Vec<ServerHint> = (0..12)
            .map(|i| ServerHint {
                addr: format!("10.0.0.{i}:1"),
                ed_pub: [i as u8; 32],
            })
            .collect();
        let enc = enc_server_hint(&many);
        assert_eq!(dec_server_hint(&enc).unwrap().len(), MAX_SERVER_HINT);
        assert!(dec_server_hint(&[9]).is_err());
    }

    #[test]
    fn probe_req_ровно_64_и_ответ_не_длиннее() {
        let req = ProbeReq {
            nonce: [7; PROBE_NONCE_LEN],
            ts_ms: 1_700_000_000_123,
            want_key: true,
        };
        let enc = enc_probe_req(&req);
        assert_eq!(enc.len(), PROBE_REQ_LEN, "запрос всегда 64 байта");
        assert_eq!(dec_probe_req(&enc).unwrap(), req);
        assert!(
            enc[PROBE_NONCE_LEN + 8 + 1..].iter().all(|b| *b == 0),
            "падинг нулевой"
        );
        // Ответ не длиннее запроса при любом want_key.
        let key = [9u8; 32];
        let with_key = enc_probe_resp(&ProbeResp {
            nonce: req.nonce,
            ts_ms: req.ts_ms,
            ed_pub: Some(key),
        });
        let without = enc_probe_resp(&ProbeResp {
            nonce: req.nonce,
            ts_ms: req.ts_ms,
            ed_pub: None,
        });
        assert_eq!(
            (with_key.len(), without.len()),
            (PROBE_RESP_KEY_LEN, PROBE_RESP_LEN)
        );
        assert!(with_key.len() <= enc.len() && without.len() <= enc.len());
        assert_eq!(
            dec_probe_resp(&with_key).unwrap(),
            ProbeResp {
                nonce: req.nonce,
                ts_ms: req.ts_ms,
                ed_pub: Some(key)
            }
        );
        assert_eq!(
            dec_probe_resp(&without).unwrap(),
            ProbeResp {
                nonce: req.nonce,
                ts_ms: req.ts_ms,
                ed_pub: None
            }
        );
        // Строгие длины: не 24 и не 56 — ошибка; у запроса — не 64.
        for n in 0..PROBE_REQ_LEN {
            assert!(dec_probe_req(&enc[..n]).is_err(), "обрезка запроса до {n}");
        }
        assert!(dec_probe_req(&[0u8; PROBE_REQ_LEN + 1]).is_err());
        for n in 0..PROBE_RESP_LEN {
            assert!(
                dec_probe_resp(&without[..n]).is_err(),
                "обрезка ответа до {n}"
            );
        }
        assert!(dec_probe_resp(&[0u8; PROBE_RESP_LEN + 1]).is_err());
        assert!(dec_probe_resp(&[0u8; PROBE_RESP_KEY_LEN - 1]).is_err());
        // want_key = 0 сохраняется.
        let no_key = ProbeReq {
            want_key: false,
            ..req
        };
        assert!(!dec_probe_req(&enc_probe_req(&no_key)).unwrap().want_key);
    }

    #[test]
    fn mesh_seed_туда_обратно_и_лимит() {
        let items = vec![
            MeshSeed {
                ed_pub: [1; 32],
                x_pub: [2; 32],
                addr: sa("203.0.113.7:4000"),
            },
            MeshSeed {
                ed_pub: [3; 32],
                x_pub: [4; 32],
                addr: sa("[2001:db8::5]:4000"),
            },
        ];
        let enc = enc_mesh_seed(&items);
        assert_eq!(dec_mesh_seed(&enc).unwrap(), items);
        truncations_fail(&enc, dec_mesh_seed);
        assert!(dec_mesh_seed(&enc_mesh_seed(&[])).unwrap().is_empty());
        // Неразборчивый адрес выбрасывается, остальные читаются.
        let mut raw = vec![2u8];
        put_pub(&mut raw, &[1; 32]);
        put_pub(&mut raw, &[2; 32]);
        put_str(&mut raw, "не адрес");
        put_pub(&mut raw, &[3; 32]);
        put_pub(&mut raw, &[4; 32]);
        put_str(&mut raw, "10.0.0.1:9");
        let got = dec_mesh_seed(&raw).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].ed_pub, [3; 32]);
        // n > 16 — ошибка; кодируется не больше 16.
        assert!(dec_mesh_seed(&[17]).is_err());
        let many: Vec<MeshSeed> = (0..20)
            .map(|i| MeshSeed {
                ed_pub: [i as u8; 32],
                x_pub: [i as u8; 32],
                addr: sa("10.0.0.1:1"),
            })
            .collect();
        assert_eq!(
            dec_mesh_seed(&enc_mesh_seed(&many)).unwrap().len(),
            MAX_MESH_SEED
        );
    }

    #[test]
    fn fed_groups_туда_обратно() {
        let items = vec![
            FedGroup {
                uuid: [7u8; 16],
                gid: 12,
                name: "федерация".into(),
                owner: [8; 32],
                members: 3,
            },
            FedGroup {
                uuid: [9u8; 16],
                gid: 13,
                name: String::new(),
                owner: [10; 32],
                members: u16::MAX,
            },
        ];
        let enc = enc_fed_groups(&items);
        assert_eq!(dec_fed_groups(&enc).unwrap(), items);
        truncations_fail(&enc, dec_fed_groups);
        assert!(dec_fed_groups(&enc_fed_groups(&[])).unwrap().is_empty());
        // Счётчик — из сети: 255 записей на 1 байте входа — ошибка, не паника.
        assert!(dec_fed_groups(&[255]).is_err());
    }

    #[test]
    fn худший_group_state_с_mesh_влезает_в_frag() {
        let long = "w".repeat(255);
        let m = MemberInfo {
            pubkey: [1; 32],
            name: long.clone(),
            ip: 2,
            online: true,
            status: long.clone(),
            endpoint: Some(sa("203.0.113.9:4000")),
            candidates: vec![sa("192.168.1.5:4000")],
        };
        let mesh: Vec<MeshEntry> = (0..253)
            .map(|i| MeshEntry {
                ip: 0x6442_0000 + i,
                x_pub: [7; 32],
                caps: 0xFF,
            })
            .collect();
        let g = GroupState {
            name: long,
            members: vec![m; 253],
            mesh,
            ..group_state()
        };
        let enc = enc_group_state(&g);
        assert!(
            enc.len() <= FRAG_MAX_PAYLOAD,
            "{} > {FRAG_MAX_PAYLOAD}",
            enc.len()
        );
        assert_eq!(dec_group_state(&enc).unwrap().mesh.len(), 253);
    }
}
