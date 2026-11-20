//! Рандомизированная проверка: случайные байты и мутации валидных кодировок
//! во все декодеры — ни одной паники.

use std::time::{Duration, Instant};

use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

use crate::handshake::{self, EphemeralKey, Hello3, RotationLink, Welcome, make_link};
use crate::mesh::{MeshForward, MeshHello};
use crate::payloads::{self as p, *};
use crate::*;

fn mutate(rng: &mut StdRng, src: &[u8]) -> Vec<u8> {
    let mut v = src.to_vec();
    for _ in 0..rng.random_range(1..=4) {
        match rng.random_range(0..6) {
            0 if !v.is_empty() => {
                let i = rng.random_range(0..v.len());
                v[i] ^= 1 << rng.random_range(0..8);
            }
            1 if !v.is_empty() => {
                let i = rng.random_range(0..v.len());
                v[i] = rng.random();
            }
            2 => v.truncate(rng.random_range(0..=v.len())),
            3 => {
                let i = rng.random_range(0..=v.len());
                v.insert(i, rng.random());
            }
            4 if !v.is_empty() => {
                // Счётчики и длины — крайние значения.
                let i = rng.random_range(0..v.len());
                v[i] = *[0u8, 1, 4, 5, 0x7f, 0x80, 0xff]
                    .get(rng.random_range(0..7))
                    .unwrap();
            }
            _ => {
                let n = rng.random_range(0..8);
                v.extend((0..n).map(|_| rng.random::<u8>()));
            }
        }
    }
    v
}

/// Все декодеры payload'ов и рукопожатия на одном входе.
///
/// `mesh_ed` — ed-ключ, которого ждём в mesh-рукопожатии: на нём проверяется
/// ветка «свой ключ → проверка просрочки и подписи», а не только дешёвый
/// отказ по чужому ed.
fn feed_all(
    b: &[u8],
    client_ed: &[u8; 32],
    client_eph: &[u8; 32],
    pin: &[u8; 32],
    mesh_ed: &[u8; 32],
) {
    let _ = dec_create_group(b);
    let _ = dec_gid(b);
    let _ = dec_gid_target(b);
    let _ = dec_rename(b);
    let _ = dec_status(b);
    let _ = dec_pubkey(b);
    let _ = dec_candidates(b);
    let _ = dec_presence(b);
    let _ = dec_group_state(b);
    let _ = dec_group_update(b);
    let _ = dec_group_list(b);
    let _ = dec_invite(b);
    let _ = dec_invite_list(b).map(|l| (l.covers(5), l.next_from()));
    let _ = dec_invite_declined(b);
    let _ = dec_kicked(b);
    let _ = dec_admin_info(b);
    let _ = dec_error(b);
    let _ = dec_friend_groups(b);
    let _ = dec_ping(b);
    // Этап 9: mesh, probe, hint/fed/seed.
    let _ = dec_mesh_info(b);
    let _ = dec_server_hint(b);
    let _ = dec_probe_req(b);
    let _ = dec_probe_resp(b);
    let _ = dec_mesh_seed(b);
    let _ = dec_fed_groups(b);
    let _ = dec_mesh_section(&mut Reader::new(b));
    if let Ok(h) = MeshHello::decode(b) {
        let _ = h.verify_from(mesh_ed, 1_700_000_000_000);
        let _ = h.dh(&EphemeralKey::generate());
        let _ = h.signing_payload();
    }
    let _ = MeshForward::decode(b);
    // RPC внутри mesh-сессии: каждый тип и «чужой» тип на том же входе.
    for typ in crate::mesh::MESH_PING..=crate::mesh::MESH_BYE {
        let _ = crate::mesh::Rpc::decode(typ, b);
    }
    let _ = crate::mesh::Rpc::decode(crate::mesh::MESH_FORWARD, b);
    let _ = crate::mesh::Rpc::decode(0xFF, b);
    let _ = read_member(&mut Reader::new(b));
    let _ = handshake::hello_version(b);
    let _ = Hello3::decode(b).map(|h| h.verify());
    let _ = handshake::dec_challenge(b);
    let _ = handshake::dec_unsupported(b);
    let _ = RotationLink::from_bytes(b).map(|l| l.verify());
    if let Ok(w) = Welcome::decode(b, client_ed, client_eph) {
        let _ = handshake::resolve_pin(pin, &w);
    }
    let _ = frag::dec_frag(b);
    let key = [1u8; 32];
    let _ = split_frame(b).map(|(t, body)| {
        let _ = ctrl_counter(body);
        open_ctrl(&key, t, body)
    });
    let _ = parse_group_header(b);
    let _ = open_group(&key, b);
}

#[test]
fn декодеры_не_паникуют_на_мусоре_и_мутациях() {
    let mut rng = StdRng::seed_from_u64(0xF022);
    let client = Identity::generate();
    let server = Identity::generate();
    let old = Identity::generate();
    let c_eph = EphemeralKey::generate();
    let s_eph = EphemeralKey::generate();
    let links = vec![make_link(&old, &server)];
    let welcome = Welcome::encode(
        &server,
        &s_eph.public(),
        &links,
        &client.ed_pub(),
        &c_eph.public(),
    );
    let key = [1u8; 32];
    let gh = GroupHeader {
        gid: 1,
        src: 2,
        dst: 3,
        epoch: 4,
    };
    // Mesh-рукопожатие: подписано `mesh_id`, его же и ждём при проверке.
    let mesh_id = Identity::generate();
    let mesh_eph = EphemeralKey::generate();
    let mesh_hello = MeshHello::new(
        &mesh_id,
        mesh_eph.public(),
        [5u8; crate::mesh::MESH_NONCE_LEN],
        1_700_000_000_000,
        crate::mesh::caps::MESH | crate::mesh::caps::RELAY,
    );
    let inner = seal_group(&key, grp::DATA, &gh, 0, &[0x45; 40]);

    let gs = p::tests::group_state();
    let gs_mesh = p::tests::group_state_mesh();
    let seeds: Vec<Vec<u8>> = vec![
        enc_group_state(&gs_mesh),
        enc_mesh_info(&[3; 32], 0b111),
        enc_server_hint(&[ServerHint {
            addr: "203.0.113.9:5555".into(),
            ed_pub: [4; 32],
        }]),
        enc_probe_req(&ProbeReq {
            nonce: [6; PROBE_NONCE_LEN],
            ts_ms: 1_700_000_000_000,
            want_key: true,
        }),
        enc_probe_resp(&ProbeResp {
            nonce: [6; PROBE_NONCE_LEN],
            ts_ms: 1_700_000_000_000,
            ed_pub: Some([7; 32]),
        }),
        enc_probe_resp(&ProbeResp {
            nonce: [6; PROBE_NONCE_LEN],
            ts_ms: 1_700_000_000_000,
            ed_pub: None,
        }),
        enc_mesh_seed(&[MeshSeed {
            ed_pub: [8; 32],
            x_pub: [9; 32],
            addr: "198.51.100.4:4000".parse().unwrap(),
        }]),
        enc_fed_groups(&[FedGroup {
            uuid: [11; 16],
            gid: 3,
            name: "федерация".into(),
            owner: [12; 32],
            members: 4,
        }]),
        mesh_hello.encode(),
        MeshForward {
            dst_ed: [1; 32],
            src_ed: [2; 32],
            hops: 1,
            visited: vec![[13; 32]],
            inner,
        }
        .encode()
        .expect("валидный forward"),
        enc_create_group("g", true),
        enc_gid(7),
        enc_gid_target(7, &[2; 32]),
        enc_rename(1, "имя"),
        enc_status("статус"),
        enc_candidates(&["1.2.3.4:5".parse().unwrap(), "[::1]:9".parse().unwrap()]),
        enc_presence(true),
        enc_group_state(&gs),
        enc_group_update(&GroupUpdate {
            gid: 1,
            rev: 2,
            base_rev: 1,
            epoch: 3,
            revoke_prev: true,
            key: [0; 32],
            delta: GroupDelta::Member(p::tests::member(1)),
            mesh: vec![MeshEntry {
                ip: 0,
                x_pub: [14; 32],
                caps: 0b101,
            }],
        }),
        enc_group_update(&GroupUpdate {
            gid: 1,
            rev: 2,
            base_rev: 1,
            epoch: 3,
            revoke_prev: false,
            key: [0; 32],
            delta: GroupDelta::Meta {
                name: "n".into(),
                owner: [1; 32],
                private: true,
            },
            mesh: Vec::new(),
        }),
        enc_group_list(&[GroupSummary {
            gid: 1,
            name: "a".into(),
            private: false,
            mine: true,
            online: 1,
            total: 2,
            rev: 3,
            epoch: 4,
        }]),
        enc_invite_list(&InviteList {
            from: 0,
            items: vec![InviteInfo {
                gid: 1,
                group_name: "g".into(),
                from_pubkey: [1; 32],
                from_name: "f".into(),
                expires_in: 9,
            }],
            complete: true,
        }),
        enc_invite_declined(&InviteDeclined {
            gid: 1,
            group_name: "g".into(),
            by_pubkey: [1; 32],
            by_name: "b".into(),
        }),
        enc_kicked(&Kicked {
            gid: 1,
            group_name: "g".into(),
            banned: false,
            rev: 3,
        }),
        enc_admin_info(&AdminInfo {
            gid: 1,
            bans: vec![BanEntry {
                pubkey: [1; 32],
                name: "b".into(),
            }],
            invites: vec![PendingInvite {
                pubkey: [2; 32],
                name: "i".into(),
                expires_in: 5,
            }],
        }),
        enc_friend_groups(&FriendGroups {
            target: [3; 32],
            groups: vec![FriendGroup {
                gid: 1,
                name: "f".into(),
                private: true,
                shared: false,
            }],
        }),
        Hello3::encode(&client, &c_eph.public(), "alpha", 1, Some(&[5; 16])),
        Hello3::encode(&client, &c_eph.public(), "alpha", 0, None),
        handshake::enc_challenge(&[6; 16]),
        handshake::enc_unsupported("старый"),
        welcome.clone(),
        links[0].to_bytes().to_vec(),
        frag::split_frag(1, ctrl::GROUP_STATE, &[7; 2500])
            .unwrap()
            .unwrap()[1]
            .clone(),
        seal_ctrl(&key, 3, ctrl::STATUS, b"hi"),
        seal_group(&key, grp::DATA, &gh, 9, &[0x45; 40]),
    ];

    let (ced, ceph, pin) = (client.ed_pub(), c_eph.public(), old.ed_pub());
    let mesh_ed = mesh_id.ed_pub();
    // Валидные входы разбираются (проверка, что сиды осмысленны).
    assert!(Welcome::decode(&welcome, &ced, &ceph).is_ok());
    assert!(MeshHello::decode(&mesh_hello.encode()).is_ok());
    for _ in 0..20_000 {
        let input = if rng.random_range(0..4) == 0 {
            let n = rng.random_range(0..600);
            let mut v = vec![0u8; n];
            rng.fill_bytes(&mut v);
            v
        } else {
            let s = &seeds[rng.random_range(0..seeds.len())];
            mutate(&mut rng, s)
        };
        feed_all(&input, &ced, &ceph, &pin, &mesh_ed);
    }
}

#[test]
fn сборщик_frag_не_паникует_и_ограничен() {
    let mut rng = StdRng::seed_from_u64(0xF7A6);
    let mut r = Reassembler::new();
    let t0 = Instant::now();
    let good = frag::split_frag(3, ctrl::GROUP_LIST, &[1; 9000])
        .unwrap()
        .unwrap();
    for i in 0..20_000u64 {
        let now = t0 + Duration::from_millis(i);
        let input = if rng.random_range(0..2) == 0 {
            // Валидные заголовки с малым msg_id, чтобы сборки пересекались.
            let mut v = good[rng.random_range(0..good.len())].clone();
            v[..4].copy_from_slice(&rng.random_range(0u32..20).to_be_bytes());
            if rng.random_range(0..4) == 0 {
                v = mutate(&mut rng, &v);
            }
            v
        } else {
            let n = rng.random_range(0..1200);
            let mut v = vec![0u8; n];
            rng.fill_bytes(&mut v);
            v
        };
        if let Ok(Some((_, msg))) = r.push(&input, now) {
            assert!(msg.len() <= FRAG_MAX_PAYLOAD);
        }
        assert!(r.pending() <= frag::FRAG_MAX_PENDING);
    }
}
