//! Протокол туннеля v3 (нормативно — `docs/PROTOCOL.md`).
//!
//! Все UDP-фреймы имеют общий заголовок:
//! ```text
//! magic "TNL2" (4) | typ (1) | body_len (2, LE) | body
//! ```
//!
//! * **Рукопожатие** (открытым текстом, модуль [`handshake`]): HELLO3 →
//!   CHALLENGE (cookie) → HELLO3 с cookie → WELCOME. Сеансовые ключи `c2s` /
//!   `s2c` выводятся из static-static и ephemeral-ephemeral X25519 — прямая
//!   секретность.
//! * **Управляющие фреймы** (клиент ↔ сервер, [`seal_ctrl`] / [`open_ctrl`]):
//!   body = counter(8, LE) || ChaCha20-Poly1305(payload, aad = заголовок),
//!   nonce = 4 нуля || counter. Повторы отсекает [`ReplayWindow`]. Длинные
//!   ответы сервера режутся на FRAG ([`frag`]).
//! * **Фреймы группы** (клиент ↔ клиент, в т.ч. через релей, [`seal_group`] /
//!   [`open_group`]): открытая часть [`GroupHeader`] (gid, src_ip, dst_ip,
//!   epoch) читается релеем, payload шифруется ключом группы эпохи `epoch`;
//!   nonce = src_ip || counter. Ключи групп выдаёт сервер (GROUP_STATE) и
//!   хранит в `server.json`: релей трафик не читает, но оператор сервера
//!   или тот, кто прочёл его данные, — может (модель доверия — раздел 7
//!   спецификации). Прямая секретность — только у ctrl-канала.
//! * Кодеки payload'ов — в [`payloads`].

use anyhow::{Result, anyhow, ensure};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::Rng;
use x25519_dalek::{PublicKey, StaticSecret};

pub mod frag;
pub mod handshake;
pub mod payloads;
pub mod replay;

#[cfg(test)]
mod fuzz_tests;

pub use frag::{FRAG_MAX_COUNT, FRAG_MAX_PAYLOAD, FRAG_THRESHOLD, Reassembler};
pub use handshake::{
    CookieSecret, DirKeys, EphemeralKey, Hello3, PinResolution, Role, RotationLink, SessionKeys,
    Welcome, resolve_pin, session_keys,
};
pub use replay::ReplayWindow;

pub const MAGIC: [u8; 4] = *b"TNL2";
pub const HDR_LEN: usize = 4 + 1 + 2;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const PUBKEY_LEN: usize = 32;
/// Счётчик фрейма в открытой части (u64 LE).
pub const COUNTER_LEN: usize = 8;

/// v4: адрес оверлея закреплён за identity на сервере (один на все группы),
/// а не выдаётся каждой группой из её `/24` — раскладка фреймов та же, но
/// клиент v3 выводил группу из адреса и с сервером v4 работать не может.
pub const PROTOCOL_VERSION: u8 = 4;

/// Прошлый ключ группы принимается на приём ещё столько после ротации без
/// `revoke_prev` (участники получают новый ключ не одновременно).
pub const PREV_KEY_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// Наибольший payload шифрованного ctrl-фрейма (body_len — u16).
pub const MAX_CTRL_PAYLOAD: usize = u16::MAX as usize - COUNTER_LEN - TAG_LEN;
/// Наибольший payload фрейма группы.
pub const MAX_GROUP_PAYLOAD: usize = u16::MAX as usize - GRP_HDR_LEN - COUNTER_LEN - TAG_LEN;

/// Типы управляющих фреймов (`docs/PROTOCOL.md`, раздел 4).
pub mod ctrl {
    /// v2 HELLO: тело не разбирается, ответ — UNSUPPORTED (открытым текстом).
    pub const HELLO: u8 = 0x01;
    pub const CREATE_GROUP: u8 = 0x02;
    pub const LIST_GROUPS: u8 = 0x03;
    pub const JOIN_GROUP: u8 = 0x04;
    pub const LEAVE_GROUP: u8 = 0x05;
    pub const INVITE: u8 = 0x06;
    /// Приглашённому (ещё не участнику) — отзыв приглашения.
    pub const KICK: u8 = 0x07;
    pub const BAN: u8 = 0x08;
    pub const RENAME_GROUP: u8 = 0x09;
    pub const DELETE_GROUP: u8 = 0x0A;
    pub const STATUS: u8 = 0x0B;
    pub const CTRL_PING: u8 = 0x0C;
    pub const FRIEND_GROUPS: u8 = 0x0D;
    /// Отклонить приглашение: gid (`enc_gid`). Идемпотентно.
    pub const DECLINE_INVITE: u8 = 0x0E;
    /// Окно неотвеченных приглашений с gid ≥ from (`enc_u32`), ответ —
    /// INVITE_LIST. Без побочных эффектов: так дочитывается неполный список.
    pub const LIST_INVITES: u8 = 0x0F;
    /// Рукопожатие v3, открытым текстом (`handshake::Hello3`).
    pub const HELLO3: u8 = 0x10;
    /// gid → GROUP_STATE только запросившему.
    pub const GET_GROUP: u8 = 0x11;
    /// gid, pk — снять бан (владелец, идемпотентно).
    pub const UNBAN: u8 = 0x12;
    /// gid → ADMIN_INFO (только владелец).
    pub const GROUP_ADMIN: u8 = 0x13;
    /// gid, pk — передать группу участнику.
    pub const TRANSFER_OWNER: u8 = 0x14;
    /// Адреса для пробития NAT (`enc_candidates`).
    pub const CANDIDATES: u8 = 0x15;
    /// invisible bool (`enc_presence`).
    pub const PRESENCE: u8 = 0x16;

    /// Открытым текстом, `handshake::Welcome`.
    pub const WELCOME: u8 = 0x81;
    pub const GROUP_STATE: u8 = 0x82;
    pub const GROUP_LIST: u8 = 0x83;
    pub const GROUP_UPDATE: u8 = 0x84;
    pub const INVITE_RCVD: u8 = 0x85;
    pub const ERROR: u8 = 0x86;
    /// Владельцу группы: приглашённый отклонил приглашение.
    pub const INVITE_DECLINED: u8 = 0x87;
    /// Окно неотвеченных приглашений (`payloads::InviteList`, ≤ 16 за раз).
    /// Сразу после HELLO3, в ответ на DECLINE_INVITE / LIST_INVITES, после
    /// JOIN, потратившего приглашение или отклонённого, и после BAN/KICK,
    /// снявшего приглашение. Чего нет в покрытом окне (`InviteList::covers`),
    /// на сервере уже недействительно.
    pub const INVITE_LIST: u8 = 0x88;
    /// Клиента удалили из группы (kick/ban): `payloads::Kicked`.
    pub const KICKED: u8 = 0x89;
    pub const ADMIN_INFO: u8 = 0x8A;
    /// Открытым текстом: cookie для повтора HELLO3.
    pub const CHALLENGE: u8 = 0x8B;
    pub const CTRL_PONG: u8 = 0x8C;
    pub const FRIEND_GROUPS_RESP: u8 = 0x8D;
    /// Открытым текстом, пустое тело: «сессии с этого адреса нет». Клиент
    /// сразу делает HELLO3, не дожидаясь таймаута.
    pub const RESET: u8 = 0x8E;
    /// Кусок длинного сообщения сервера (`frag`).
    pub const FRAG: u8 = 0x8F;
    /// Открытым текстом: версия не поддерживается (`handshake::enc_unsupported`).
    pub const UNSUPPORTED: u8 = 0x90;
    /// Подтверждение PRESENCE: invisible bool — значение, действующее на
    /// сервере после обработки (`enc_presence`). Шлётся на каждый PRESENCE,
    /// и на повтор без изменения: клиент повторяет PRESENCE, пока не получит.
    pub const PRESENCE_ACK: u8 = 0x91;

    /// Фреймы, которые ходят открытым текстом (всё прочее — шифрованные ctrl
    /// или фреймы группы).
    pub fn is_plaintext(typ: u8) -> bool {
        matches!(
            typ,
            HELLO | HELLO3 | WELCOME | CHALLENGE | RESET | UNSUPPORTED
        )
    }
}

/// Типы фреймов внутри группы.
pub mod grp {
    /// IP-пакет: payload = сырой IPv4.
    pub const DATA: u8 = 0x21;
    /// RTT-зонд: payload = 8-байтовая метка времени отправителя.
    pub const PING: u8 = 0x22;
    /// Ответ: payload = та же метка.
    pub const PONG: u8 = 0x23;
    /// Пробивание NAT: без payload. Ответ на PUNCH — KEEPALIVE, **не** PUNCH:
    /// иначе два клиента бесконечно отражают PUNCH друг другу.
    pub const PUNCH: u8 = 0x24;
    /// Поддержание NAT-маппинга и liveness: без payload. На него не отвечают.
    pub const KEEPALIVE: u8 = 0x25;

    /// Тип относится к фреймам группы (релей пересылает только их).
    pub fn is_group(typ: u8) -> bool {
        (DATA..=KEEPALIVE).contains(&typ)
    }
}

pub type SymKey = [u8; 32];

// ---------- identity ----------

/// Постоянная личность: ed25519 (подписи) + x25519 (static DH рукопожатия).
#[derive(Clone)]
pub struct Identity {
    pub ed_seed: [u8; 32],
    pub x_seed: [u8; 32],
}

impl Identity {
    pub fn generate() -> Self {
        let mut ed_seed = [0u8; 32];
        let mut x_seed = [0u8; 32];
        rand::rng().fill_bytes(&mut ed_seed);
        rand::rng().fill_bytes(&mut x_seed);
        Self { ed_seed, x_seed }
    }

    pub fn ed(&self) -> SigningKey {
        SigningKey::from_bytes(&self.ed_seed)
    }

    /// Публичный ключ ed25519 (identity для сервера/друзей).
    pub fn ed_pub(&self) -> [u8; 32] {
        self.ed().verifying_key().to_bytes()
    }

    /// Публичный ключ x25519 (static-часть рукопожатия).
    pub fn x_pub(&self) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(self.x_seed)).to_bytes()
    }

    /// Static DH с x25519-ключом пира. Нулевой (non-contributory) результат —
    /// ошибка: пир прислал точку малого порядка, общий секрет предсказуем.
    pub fn dh(&self, peer_x_pub: &[u8; 32]) -> Result<[u8; 32]> {
        let shared = StaticSecret::from(self.x_seed).diffie_hellman(&PublicKey::from(*peer_x_pub));
        ensure!(
            shared.was_contributory(),
            "x25519: ключ пира малого порядка"
        );
        Ok(shared.to_bytes())
    }

    /// Подписывает данные identity-ключом.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.ed().sign(msg).to_bytes()
    }

    pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(pubkey)?;
        vk.verify(msg, &ed25519_dalek::Signature::from_bytes(sig))
            .map_err(|_| anyhow!("bad signature"))
    }

    /// Friend code: base32 (Crockford, без I/L/O/U) публичного ключа.
    pub fn friend_code(&self) -> String {
        friend_code_of(&self.ed_pub())
    }

    /// Разбор friend code → ed25519 pubkey.
    pub fn parse_friend_code(code: &str) -> Result<[u8; 32]> {
        parse_friend_code(code)
    }
}

/// `blake3(tag || material)` — KDF протокола (`blake3_derive` в спецификации).
pub fn derive_key(tag: &[u8], material: &[u8]) -> SymKey {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(material);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Сравнение без раннего выхода: время не выдаёт, сколько байт совпало.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

const B32: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn friend_code_of(pubkey: &[u8; 32]) -> String {
    let mut bits: u32 = 0;
    let mut nbits = 0;
    let mut emitted = 0usize;
    let mut out = String::from("TUN-");
    for b in pubkey.iter() {
        bits = (bits << 8) | *b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(B32[((bits >> nbits) & 31) as usize] as char);
            emitted += 1;
            if emitted.is_multiple_of(8) && emitted < 52 {
                out.push('-');
            }
        }
    }
    // 256 бит = 51 группа по 5 бит + 1 бит остатка → паддинг-символ до 52.
    if nbits > 0 {
        out.push(B32[((bits << (5 - nbits)) & 31) as usize] as char);
    }
    out
}

/// Длина friend code без префикса и разделителей (256 бит / 5 бит, вверх).
pub const FRIEND_CODE_CHARS: usize = 52;

/// Нормализация символа friend code: Crockford-алиасы (O→0, I/L→1) и
/// кириллические двойники латиницы (набор или копирование в русской
/// раскладке). Проверка алфавита — дальше.
fn normalize_code_char(c: char) -> char {
    match c {
        'А' | 'а' => 'A',
        'В' | 'в' => 'B',
        'Е' | 'е' => 'E',
        'К' | 'к' => 'K',
        'М' | 'м' => 'M',
        'Н' | 'н' => 'H',
        'О' | 'о' => '0',
        'Р' | 'р' => 'P',
        'С' | 'с' => 'C',
        'Т' | 'т' => 'T',
        'Х' | 'х' => 'X',
        _ => match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        },
    }
}

/// Разбор friend code. Терпим к тому, что приходит из буфера обмена и
/// мессенджеров: регистр, пробелы, переводы строк, дефисы и любые другие
/// разделители (в т.ч. рамка TUI `│`), отсутствие префикса `TUN-`.
pub fn parse_friend_code(code: &str) -> Result<[u8; 32]> {
    let cleaned: String = code
        .chars()
        .map(normalize_code_char)
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    // В алфавите Crockford нет «U», поэтому «TUN» в начале — всегда префикс.
    let body = cleaned.strip_prefix("TUN").unwrap_or(&cleaned);
    ensure!(
        body.len() == FRIEND_CODE_CHARS,
        "friend code: нужно {FRIEND_CODE_CHARS} символов после TUN-, получено {} — код скопирован не целиком?",
        body.len()
    );
    let mut acc: u64 = 0;
    let mut nbits = 0;
    let mut out = [0u8; 32];
    let mut oi = 0;
    for c in body.chars() {
        let v = B32
            .iter()
            .position(|b| *b as char == c)
            .ok_or_else(|| anyhow!("неверный символ {c:?} в friend code"))? as u64;
        acc = (acc << 5) | v;
        nbits += 5;
        if nbits >= 8 && oi < 32 {
            nbits -= 8;
            out[oi] = (acc >> nbits) as u8;
            oi += 1;
        }
    }
    ensure!(oi == 32, "friend code неверной длины");
    Ok(out)
}

pub fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>> {
    let s = s.trim().to_lowercase();
    ensure!(s.len().is_multiple_of(2), "odd hex length");
    ensure!(s.is_ascii(), "bad hex");
    Ok((0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16))
        .collect::<std::result::Result<Vec<u8>, _>>()?)
}

// ---------- фреймы ----------

/// Собирает датаграмму с незашифрованным body (HELLO3, CHALLENGE, WELCOME,
/// RESET, UNSUPPORTED). Body длиннее u16 — паника (такие не строятся).
pub fn plain_frame(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HDR_LEN + body.len());
    out.extend_from_slice(&frame_header(typ, body.len()));
    out.extend_from_slice(body);
    out
}

/// Разбирает общий заголовок. Возвращает (typ, body).
pub fn split_frame(datagram: &[u8]) -> Result<(u8, &[u8])> {
    ensure!(datagram.len() >= HDR_LEN, "frame too short");
    ensure!(datagram[..4] == MAGIC, "bad magic");
    let typ = datagram[4];
    let len = u16::from_le_bytes([datagram[5], datagram[6]]) as usize;
    let body = &datagram[HDR_LEN..];
    ensure!(body.len() == len, "length mismatch");
    Ok((typ, body))
}

fn frame_header(typ: u8, body_len: usize) -> [u8; HDR_LEN] {
    let len = u16::try_from(body_len).expect("frame body longer than u16");
    let mut hdr = [0u8; HDR_LEN];
    hdr[..4].copy_from_slice(&MAGIC);
    hdr[4] = typ;
    hdr[5..].copy_from_slice(&len.to_le_bytes());
    hdr
}

fn cipher(key: &SymKey) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(key.into())
}

fn read_counter(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..COUNTER_LEN].try_into().unwrap())
}

// ---------- счётчик отправителя ----------

/// Счётчик nonce отправителя: с 0, строго растёт. Повтор счётчика под тем
/// же ключом раскрыл бы трафик, поэтому переполнение — паника, а не обёртка
/// (2^64 фреймов недостижимо).
#[derive(Debug, Default, Clone)]
pub struct SendCounter(u64);

impl SendCounter {
    pub fn new() -> Self {
        Self(0)
    }

    /// Следующий счётчик для отправки.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u64 {
        let c = self.0;
        self.0 = c.checked_add(1).expect("nonce counter exhausted");
        c
    }

    /// Сколько счётчиков уже выдано.
    pub fn issued(&self) -> u64 {
        self.0
    }
}

// ---------- управляющие фреймы ----------

/// Шифрованный ctrl-фрейм: `hdr | counter LE | ct`, nonce = 0⁴ || counter,
/// aad = hdr. Ключ — `tx` своей роли (`DirKeys`), counter — из `SendCounter`.
/// Payload длиннее `MAX_CTRL_PAYLOAD` — паника (длинное режется `frag`).
pub fn seal_ctrl(key: &SymKey, counter: u64, typ: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= MAX_CTRL_PAYLOAD, "ctrl payload too long");
    let hdr = frame_header(typ, COUNTER_LEN + payload.len() + TAG_LEN);
    let ct = cipher(key)
        .encrypt(
            &ctrl_nonce(counter),
            Payload {
                msg: payload,
                aad: &hdr,
            },
        )
        .expect("ctrl encrypt");
    let mut out = Vec::with_capacity(HDR_LEN + COUNTER_LEN + ct.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&counter.to_le_bytes());
    out.extend_from_slice(&ct);
    out
}

fn ctrl_nonce(counter: u64) -> Nonce {
    let mut n = [0u8; NONCE_LEN];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(n)
}

/// Счётчик ctrl-фрейма до расшифровки — для дешёвой предпроверки
/// `ReplayWindow::check`. Окно сдвигать только после [`open_ctrl`].
pub fn ctrl_counter(body: &[u8]) -> Option<u64> {
    (body.len() >= COUNTER_LEN + TAG_LEN).then(|| read_counter(body))
}

/// Расшифровывает body ctrl-фрейма (`typ`, `body` — из [`split_frame`]).
/// Возвращает (counter, payload); counter затем проходит
/// `ReplayWindow::commit` — расшифровка сама повторы не отсекает.
pub fn open_ctrl(key: &SymKey, typ: u8, body: &[u8]) -> Result<(u64, Vec<u8>)> {
    ensure!(body.len() >= COUNTER_LEN + TAG_LEN, "ctrl body too short");
    let counter = read_counter(body);
    let hdr = frame_header(typ, body.len());
    let pt = cipher(key)
        .decrypt(
            &ctrl_nonce(counter),
            Payload {
                msg: &body[COUNTER_LEN..],
                aad: &hdr,
            },
        )
        .map_err(|_| anyhow!("ctrl decrypt failed"))?;
    Ok((counter, pt))
}

// ---------- фреймы группы ----------

/// Открытая часть после общего заголовка: gid | src_ip | dst_ip | epoch.
pub const GRP_HDR_LEN: usize = 16;

/// Открытый заголовок фрейма группы (читает релей; целиком входит в AAD).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupHeader {
    pub gid: u32,
    pub src: u32,
    pub dst: u32,
    /// Номер ключа группы, которым зашифрован payload.
    pub epoch: u32,
}

impl GroupHeader {
    pub fn to_bytes(&self) -> [u8; GRP_HDR_LEN] {
        let mut b = [0u8; GRP_HDR_LEN];
        b[..4].copy_from_slice(&self.gid.to_be_bytes());
        b[4..8].copy_from_slice(&self.src.to_be_bytes());
        b[8..12].copy_from_slice(&self.dst.to_be_bytes());
        b[12..].copy_from_slice(&self.epoch.to_be_bytes());
        b
    }

    fn from_bytes(b: &[u8]) -> Self {
        let u = |i: usize| u32::from_be_bytes(b[i..i + 4].try_into().unwrap());
        Self {
            gid: u(0),
            src: u(4),
            dst: u(8),
            epoch: u(12),
        }
    }
}

fn group_nonce(src: u32, counter: u64) -> Nonce {
    let mut n = [0u8; NONCE_LEN];
    n[..4].copy_from_slice(&src.to_be_bytes());
    n[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(n)
}

/// Разбирает открытую часть фрейма группы без расшифровки: (typ, заголовок).
/// Проверяет и минимальную длину (есть место под counter и тег), чтобы
/// релей не пересылал заведомый мусор. Тип не проверяется (`grp::is_group`).
pub fn parse_group_header(datagram: &[u8]) -> Result<(u8, GroupHeader)> {
    let (typ, body) = split_frame(datagram)?;
    ensure!(
        body.len() >= GRP_HDR_LEN + COUNTER_LEN + TAG_LEN,
        "group frame too short"
    );
    Ok((typ, GroupHeader::from_bytes(&body[..GRP_HDR_LEN])))
}

/// Шифрованный фрейм группы:
/// `hdr | GroupHeader | counter LE | ct`, nonce = src_ip BE || counter LE,
/// aad = hdr || GroupHeader. `key` — ключ эпохи `h.epoch`, counter — на
/// (gid, epoch). Payload длиннее `MAX_GROUP_PAYLOAD` — паника.
pub fn seal_group(key: &SymKey, typ: u8, h: &GroupHeader, counter: u64, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= MAX_GROUP_PAYLOAD, "group payload too long");
    let mut out = Vec::with_capacity(HDR_LEN + GRP_HDR_LEN + COUNTER_LEN + payload.len() + TAG_LEN);
    out.extend_from_slice(&frame_header(
        typ,
        GRP_HDR_LEN + COUNTER_LEN + payload.len() + TAG_LEN,
    ));
    out.extend_from_slice(&h.to_bytes());
    let ct = cipher(key)
        .encrypt(
            &group_nonce(h.src, counter),
            Payload {
                msg: payload,
                aad: &out,
            },
        )
        .expect("group encrypt");
    out.extend_from_slice(&counter.to_le_bytes());
    out.extend_from_slice(&ct);
    out
}

/// Разбирает и расшифровывает фрейм группы: (typ, заголовок, counter,
/// payload). Проверки получателя (эпоха, dst, участник, окно повторов,
/// адрес) — на вызывающем, см. раздел 7 спецификации.
pub fn open_group(key: &SymKey, datagram: &[u8]) -> Result<(u8, GroupHeader, u64, Vec<u8>)> {
    let (typ, h) = parse_group_header(datagram)?;
    let aad = &datagram[..HDR_LEN + GRP_HDR_LEN];
    let rest = &datagram[HDR_LEN + GRP_HDR_LEN..];
    let counter = read_counter(rest);
    let pt = cipher(key)
        .decrypt(
            &group_nonce(h.src, counter),
            Payload {
                msg: &rest[COUNTER_LEN..],
                aad,
            },
        )
        .map_err(|_| anyhow!("group decrypt failed"))?;
    Ok((typ, h, counter, pt))
}

// ---------- кодирование payload'ов (общие хелперы) ----------

/// Строка с префиксом длины (1 байт). Длиннее 255 байт — обрезается по
/// границе символа (раньше был assert, и длинное имя/статус кириллицей
/// — 2 байта на букву — роняло поток движка).
pub fn put_str(buf: &mut Vec<u8>, s: &str) {
    let s = truncate_bytes(s, 255);
    buf.push(s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
}

/// Сколько байт займёт строка в `put_str`.
pub fn str_wire_len(s: &str) -> usize {
    1 + truncate_bytes(s, 255).len()
}

/// Префикс строки не длиннее `max` байт, не разрезая UTF-8 символ.
pub fn truncate_bytes(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

pub fn put_pub(buf: &mut Vec<u8>, p: &[u8; 32]) {
    buf.extend_from_slice(p);
}

pub fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub fn put_bool(buf: &mut Vec<u8>, v: bool) {
    buf.push(v as u8);
}

/// Читатель payload'а: любое чтение за концом — ошибка, не паника.
pub struct Reader<'a> {
    pub b: &'a [u8],
    pub p: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    /// Сколько байт осталось.
    pub fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.p)
    }
    /// Ёмкость под `n` записей по ≥ `min_size` байт: не больше, чем реально
    /// может поместиться в остаток, — счётчик от атакующего не раздувает
    /// аллокацию.
    pub fn capacity_for(&self, n: usize, min_size: usize) -> usize {
        n.min(self.remaining() / min_size.max(1))
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.remaining(), "truncated");
        let r = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(r)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.bytes(N)?.try_into().unwrap())
    }
    pub fn pub_key(&mut self) -> Result<[u8; 32]> {
        self.array()
    }
    pub fn str(&mut self) -> Result<String> {
        let n = self.u8()? as usize;
        Ok(String::from_utf8_lossy(self.bytes(n)?).into_owned())
    }
    pub fn boolean(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }
    pub fn tail(&mut self) -> &'a [u8] {
        let r = &self.b[self.p.min(self.b.len())..];
        self.p = self.b.len();
        r
    }
    /// Всё прочитано (строгие форматы рукопожатия не терпят хвостов).
    pub fn finish(&self) -> Result<()> {
        ensure!(self.remaining() == 0, "trailing bytes");
        Ok(())
    }
}

/// IP-адреса — в network byte order (big-endian), как внутри IPv4-пакета.
pub fn ipv4_dst(packet: &[u8]) -> Result<u32> {
    ensure!(packet.len() >= 20, "packet too short");
    ensure!(packet[0] >> 4 == 4, "not ipv4");
    Ok(u32::from_be_bytes(packet[16..20].try_into().unwrap()))
}

pub fn ipv4_src(packet: &[u8]) -> Result<u32> {
    ensure!(packet.len() >= 20, "packet too short");
    ensure!(packet[0] >> 4 == 4, "not ipv4");
    Ok(u32::from_be_bytes(packet[12..16].try_into().unwrap()))
}

/// Сеть оверлея `100.66.0.0/16`: у каждой identity на сервере один адрес
/// из неё, общий для всех групп.
pub const OVERLAY_NET: u32 = 0x6442_0000;
pub const OVERLAY_MASK: u32 = 0xFFFF_0000;
/// Длина префикса оверлея (маска адаптера).
pub const OVERLAY_PREFIX_LEN: u8 = 16;

/// Адрес из сети оверлея `100.66.0.0/16`.
pub fn is_overlay_ip(ip: u32) -> bool {
    ip & OVERLAY_MASK == OVERLAY_NET
}

pub fn ip_str(ip: u32) -> String {
    std::net::Ipv4Addr::from(ip).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_и_подписи() {
        let a = Identity::generate();
        let b = Identity::generate();
        // Friend code туда-обратно.
        let code = a.friend_code();
        assert_eq!(Identity::parse_friend_code(&code).unwrap(), a.ed_pub());
        // Подпись проверяется, чужая не проходит.
        let msg = b"hello";
        let sig = a.sign(msg);
        Identity::verify(&a.ed_pub(), msg, &sig).unwrap();
        assert!(Identity::verify(&b.ed_pub(), msg, &sig).is_err());
        // Static DH симметричен.
        assert_eq!(a.dh(&b.x_pub()).unwrap(), b.dh(&a.x_pub()).unwrap());
        // Точка малого порядка (ноль) — отказ.
        assert!(a.dh(&[0u8; 32]).is_err());
    }

    #[test]
    fn friend_code_терпим_к_копированию() {
        let a = Identity::generate();
        let pk = a.ed_pub();
        let code = a.friend_code();
        assert_eq!(
            code.len(),
            4 + FRIEND_CODE_CHARS + 6,
            "TUN- + 52 символа + 6 дефисов"
        );
        // Перевод строки и пробелы из буфера обмена, нижний регистр.
        assert_eq!(parse_friend_code(&format!("  {code}\r\n")).unwrap(), pk);
        assert_eq!(parse_friend_code(&code.to_lowercase()).unwrap(), pk);
        // Без префикса и без дефисов.
        let bare: String = code[4..].chars().filter(|c| *c != '-').collect();
        assert_eq!(parse_friend_code(&bare).unwrap(), pk);
        // Рамка TUI и перенос посередине.
        let (l, r) = code.split_at(30);
        assert_eq!(parse_friend_code(&format!("│{l}\n{r}│")).unwrap(), pk);
        // Кириллические двойники латиницы в теле кода.
        let cyr: String = code
            .chars()
            .enumerate()
            .map(|(i, c)| match c {
                'A' if i > 3 => 'А',
                'B' if i > 3 => 'В',
                'E' if i > 3 => 'Е',
                'K' if i > 3 => 'К',
                'M' if i > 3 => 'М',
                'H' if i > 3 => 'Н',
                'P' if i > 3 => 'Р',
                'C' if i > 3 => 'С',
                'T' if i > 3 => 'Т',
                'X' if i > 3 => 'Х',
                other => other,
            })
            .collect();
        assert_eq!(parse_friend_code(&cyr).unwrap(), pk);
        // Обрезанный код — понятная ошибка с длиной.
        let err = parse_friend_code(&code[..40]).unwrap_err().to_string();
        assert!(err.contains("получено"), "{err}");
    }

    #[test]
    fn hex_туда_обратно_и_мусор_без_паники() {
        assert_eq!(
            hex_to_bytes(&hex_of(&[0, 1, 0xab, 0xff])).unwrap(),
            vec![0, 1, 0xab, 0xff]
        );
        assert!(hex_to_bytes("abc").is_err());
        assert!(hex_to_bytes("zz").is_err());
        // Многобайтовый UTF-8 не режется посреди символа.
        assert!(hex_to_bytes("жж").is_err());
    }

    #[test]
    fn длинная_строка_обрезается_а_не_паникует() {
        let long = "ж".repeat(200); // 400 байт
        let mut buf = Vec::new();
        put_str(&mut buf, &long);
        assert_eq!(buf[0] as usize, buf.len() - 1);
        assert_eq!(str_wire_len(&long), buf.len());
        let mut r = Reader::new(&buf);
        assert_eq!(r.str().unwrap(), "ж".repeat(127));
    }

    #[test]
    fn ctrl_туда_обратно_и_tamper() {
        let key = [42u8; 32];
        let frame = seal_ctrl(&key, 7, ctrl::STATUS, b"payload");
        let (typ, body) = split_frame(&frame).unwrap();
        assert_eq!(typ, ctrl::STATUS);
        assert_eq!(ctrl_counter(body), Some(7));
        let (ctr, p) = open_ctrl(&key, typ, body).unwrap();
        assert_eq!((ctr, p.as_slice()), (7, &b"payload"[..]));
        // Пустой payload и счётчик-граница.
        let f0 = seal_ctrl(&key, u64::MAX, ctrl::CTRL_PING, b"");
        let (t0, b0) = split_frame(&f0).unwrap();
        assert_eq!(open_ctrl(&key, t0, b0).unwrap(), (u64::MAX, vec![]));
        // Чужой ключ.
        assert!(open_ctrl(&[7u8; 32], typ, body).is_err());
        // Подмена типа (он в AAD).
        assert!(open_ctrl(&key, ctrl::ERROR, body).is_err());
        // Порча любого байта body — ошибка (счётчик в nonce, ct под тегом).
        for i in 0..body.len() {
            let mut t = body.to_vec();
            t[i] ^= 0x01;
            assert!(open_ctrl(&key, typ, &t).is_err(), "байт {i}");
        }
        // Порча заголовка ловит split_frame или AAD.
        for i in 0..HDR_LEN {
            let mut t = frame.clone();
            t[i] ^= 0x80;
            let ok = split_frame(&t)
                .and_then(|(ty, b)| open_ctrl(&key, ty, b))
                .is_ok();
            assert!(!ok, "заголовок {i}");
        }
        // Обрезка.
        assert!(open_ctrl(&key, typ, &body[..COUNTER_LEN + TAG_LEN - 1]).is_err());
        assert!(ctrl_counter(&body[..3]).is_none());
        // Nonce: 4 нуля || counter LE.
        assert_eq!(
            ctrl_nonce(0x0102).as_slice(),
            &[0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn group_туда_обратно_и_tamper() {
        let key = [42u8; 32];
        let h = GroupHeader {
            gid: 7,
            src: 0x6442_0702,
            dst: 0x6442_0703,
            epoch: 9,
        };
        let g = seal_group(&key, grp::DATA, &h, 5, b"data");
        assert_eq!(g.len(), HDR_LEN + GRP_HDR_LEN + COUNTER_LEN + 4 + TAG_LEN);
        assert_eq!(parse_group_header(&g).unwrap(), (grp::DATA, h));
        let (t, h2, c, p) = open_group(&key, &g).unwrap();
        assert_eq!((t, h2, c, p.as_slice()), (grp::DATA, h, 5, &b"data"[..]));
        // Порча любого байта после magic/len — ошибка расшифровки (заголовок
        // группы в AAD, счётчик в nonce).
        for i in 4..g.len() {
            if (5..7).contains(&i) {
                continue; // длина — ловит split_frame
            }
            let mut t = g.clone();
            t[i] ^= 0x01;
            assert!(open_group(&key, &t).is_err(), "байт {i}");
        }
        // Другая эпоха с тем же ключом не открывается (epoch в AAD).
        let mut e = g.clone();
        e[HDR_LEN + 12..HDR_LEN + 16].copy_from_slice(&10u32.to_be_bytes());
        assert!(open_group(&key, &e).is_err());
        assert!(open_group(&[1u8; 32], &g).is_err());
        // Короткий фрейм — ошибка и у релея.
        let short = plain_frame(grp::DATA, &[0u8; GRP_HDR_LEN + COUNTER_LEN + TAG_LEN - 1]);
        assert!(parse_group_header(&short).is_err());
        assert!(open_group(&key, &short).is_err());
        // Nonce: src BE || counter LE.
        assert_eq!(
            group_nonce(0x0A0B0C0D, 1).as_slice(),
            &[10, 11, 12, 13, 1, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn счётчик_отправителя_растёт_с_нуля() {
        let mut c = SendCounter::new();
        assert_eq!((c.next(), c.next(), c.next()), (0, 1, 2));
        assert_eq!(c.issued(), 3);
    }

    #[test]
    fn типы_не_пересекаются() {
        use crate::ctrl::*;
        let all = [
            HELLO,
            CREATE_GROUP,
            LIST_GROUPS,
            JOIN_GROUP,
            LEAVE_GROUP,
            INVITE,
            KICK,
            BAN,
            RENAME_GROUP,
            DELETE_GROUP,
            STATUS,
            CTRL_PING,
            FRIEND_GROUPS,
            DECLINE_INVITE,
            LIST_INVITES,
            HELLO3,
            GET_GROUP,
            UNBAN,
            GROUP_ADMIN,
            TRANSFER_OWNER,
            CANDIDATES,
            PRESENCE,
            WELCOME,
            GROUP_STATE,
            GROUP_LIST,
            GROUP_UPDATE,
            INVITE_RCVD,
            ERROR,
            INVITE_DECLINED,
            INVITE_LIST,
            KICKED,
            ADMIN_INFO,
            CHALLENGE,
            CTRL_PONG,
            FRIEND_GROUPS_RESP,
            RESET,
            FRAG,
            UNSUPPORTED,
        ];
        let uniq: std::collections::HashSet<u8> = all.iter().copied().collect();
        assert_eq!(uniq.len(), all.len());
        assert!(all.iter().all(|t| !grp::is_group(*t)));
        assert!(is_plaintext(HELLO3) && is_plaintext(WELCOME) && !is_plaintext(FRAG));
        assert_eq!(HELLO3, 0x10);
        assert_eq!(UNSUPPORTED, 0x90);
    }
}
