//! Кодеки payload'ов управляющих сообщений (клиент ↔ сервер), разделы 4–6
//! спецификации. Рукопожатие — в [`crate::handshake`], FRAG — в [`crate::frag`].
//!
//! Декодеры не паникуют, отвергают обрезку и не выделяют память по счётчику
//! из сети больше, чем может поместиться в остаток payload'а. Хвост после
//! известных полей допускается (расширение без смены версии).

use std::net::SocketAddr;

use crate::{FRAG_MAX_PAYLOAD, Reader, put_bool, put_pub, put_str, put_u16, put_u32, str_wire_len};
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
    let delta = match r.u8()? {
        1 => GroupDelta::Member(read_member(&mut r)?),
        2 => GroupDelta::Removed(r.pub_key()?),
        3 => GroupDelta::Meta {
            name: r.str()?,
            owner: r.pub_key()?,
            private: r.boolean()?,
        },
        k => bail!("GROUP_UPDATE: неизвестный kind {k}"),
    };
    Ok(GroupUpdate {
        gid,
        rev,
        base_rev,
        epoch,
        revoke_prev,
        key,
        delta,
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
}
