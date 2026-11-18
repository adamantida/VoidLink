//! Рукопожатие v3 (раздел 2 спецификации): HELLO3 / CHALLENGE / WELCOME /
//! UNSUPPORTED, cookie, сеансовые ключи, цепочка ротации ключа сервера.
//!
//! Все кодеки работают с **body** открытого фрейма; обёртка —
//! [`crate::plain_frame`] с типом из [`crate::ctrl`].

use std::net::SocketAddr;

use anyhow::{Result, anyhow, bail, ensure};
use rand::Rng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{Identity, PROTOCOL_VERSION, Reader, SymKey, ct_eq, derive_key, put_pub, put_str};

const HELLO_TAG: &[u8] = b"tunnel/v3/hello";
const WELCOME_TAG: &[u8] = b"tunnel/v3/welcome";
const ROTATE_TAG: &[u8] = b"tunnel/v3/rotate";
const COOKIE_TAG: &[u8] = b"tunnel/v3/cookie";

pub const COOKIE_LEN: usize = 16;
/// Ширина bucket'а cookie: принимаются текущий и предыдущий (30–60 с).
pub const COOKIE_BUCKET_SECS: u64 = 30;
/// HELLO3 flags, bit0: invisible (другие участники видят клиента офлайн).
pub const HELLO_FLAG_INVISIBLE: u8 = 0x01;
/// Сколько звеньев ротации несёт WELCOME (последние).
pub const MAX_LINKS: usize = 8;
pub const SIG_LEN: usize = 64;

// ---------- эфемерный ключ ----------

/// Эфемерный X25519 одной попытки подключения. Повторы HELLO3 до WELCOME —
/// с тем же ключом, поэтому DH не поглощает секрет. Секрет стирается при
/// drop (zeroize в x25519-dalek) — это и даёт прямую секретность.
pub struct EphemeralKey {
    secret: StaticSecret,
    public: [u8; 32],
}

impl EphemeralKey {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// DH с эфемерным ключом пира; точка малого порядка — ошибка.
    pub fn dh(&self, peer_eph: &[u8; 32]) -> Result<[u8; 32]> {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer_eph));
        ensure!(
            shared.was_contributory(),
            "x25519: эфемерный ключ пира малого порядка"
        );
        Ok(shared.to_bytes())
    }
}

impl std::fmt::Debug for EphemeralKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EphemeralKey({})", crate::hex_of(&self.public))
    }
}

// ---------- сеансовые ключи ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Ключи сессии по направлениям.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    pub c2s: SymKey,
    pub s2c: SymKey,
}

/// Ключи сессии с точки зрения одной стороны: `tx` — для `seal_ctrl`,
/// `rx` — для `open_ctrl`.
#[derive(Clone, PartialEq, Eq)]
pub struct DirKeys {
    pub tx: SymKey,
    pub rx: SymKey,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKeys(..)")
    }
}

impl std::fmt::Debug for DirKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DirKeys(..)")
    }
}

impl SessionKeys {
    /// `k = derive("tunnel/v3/session", ss || ee || client_eph || server_eph)`,
    /// `c2s = derive("tunnel/v3/c2s", k)`, `s2c = derive("tunnel/v3/s2c", k)`.
    pub fn derive(
        ss: &[u8; 32],
        ee: &[u8; 32],
        client_eph: &[u8; 32],
        server_eph: &[u8; 32],
    ) -> Self {
        let mut m = [0u8; 128];
        m[..32].copy_from_slice(ss);
        m[32..64].copy_from_slice(ee);
        m[64..96].copy_from_slice(client_eph);
        m[96..].copy_from_slice(server_eph);
        let k = derive_key(b"tunnel/v3/session", &m);
        Self {
            c2s: derive_key(b"tunnel/v3/c2s", &k),
            s2c: derive_key(b"tunnel/v3/s2c", &k),
        }
    }

    pub fn for_role(&self, role: Role) -> DirKeys {
        match role {
            Role::Client => DirKeys {
                tx: self.c2s,
                rx: self.s2c,
            },
            Role::Server => DirKeys {
                tx: self.s2c,
                rx: self.c2s,
            },
        }
    }
}

/// Сеансовые ключи одной стороны: `ss = X25519(my_x, peer_x)`,
/// `ee = X25519(my_eph, peer_eph)`. Клиент передаёт `server_x`/`server_eph`
/// из WELCOME, сервер — `x_pub`/`eph_pub` из HELLO3.
pub fn session_keys(
    role: Role,
    me: &Identity,
    my_eph: &EphemeralKey,
    peer_x: &[u8; 32],
    peer_eph: &[u8; 32],
) -> Result<DirKeys> {
    let ss = me.dh(peer_x)?;
    let ee = my_eph.dh(peer_eph)?;
    let mine = my_eph.public();
    let (client_eph, server_eph) = match role {
        Role::Client => (&mine, peer_eph),
        Role::Server => (peer_eph, &mine),
    };
    Ok(SessionKeys::derive(&ss, &ee, client_eph, server_eph).for_role(role))
}

// ---------- cookie ----------

/// Секрет cookie сервера: 32 случайных байта при старте, не сохраняется.
#[derive(Clone)]
pub struct CookieSecret([u8; 32]);

/// `bucket = unix_secs / 30`.
pub fn cookie_bucket(unix_secs: u64) -> u64 {
    unix_secs / COOKIE_BUCKET_SECS
}

/// Текущее unix-время в секундах (для `CookieSecret::make/verify`).
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl CookieSecret {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        rand::rng().fill_bytes(&mut k);
        Self(k)
    }

    pub fn from_bytes(k: [u8; 32]) -> Self {
        Self(k)
    }

    /// `blake3_keyed(secret, "tunnel/v3/cookie" || ip(16) || port u16 BE ||
    /// eph_pub || bucket u64 BE)[..16]`. IPv4 кодируется как `::ffff:a.b.c.d`,
    /// поэтому v4-адрес и он же через dual-stack сокет дают один cookie.
    pub fn compute(&self, addr: SocketAddr, eph_pub: &[u8; 32], bucket: u64) -> [u8; COOKIE_LEN] {
        let ip = match addr {
            SocketAddr::V4(a) => a.ip().to_ipv6_mapped(),
            SocketAddr::V6(a) => *a.ip(),
        };
        let mut h = blake3::Hasher::new_keyed(&self.0);
        h.update(COOKIE_TAG);
        h.update(&ip.octets());
        h.update(&addr.port().to_be_bytes());
        h.update(eph_pub);
        h.update(&bucket.to_be_bytes());
        let mut out = [0u8; COOKIE_LEN];
        out.copy_from_slice(&h.finalize().as_bytes()[..COOKIE_LEN]);
        out
    }

    /// Cookie для CHALLENGE на момент `unix_secs`.
    pub fn make(&self, addr: SocketAddr, eph_pub: &[u8; 32], unix_secs: u64) -> [u8; COOKIE_LEN] {
        self.compute(addr, eph_pub, cookie_bucket(unix_secs))
    }

    /// Cookie верен для текущего или предыдущего bucket'а.
    pub fn verify(
        &self,
        addr: SocketAddr,
        eph_pub: &[u8; 32],
        cookie: &[u8; COOKIE_LEN],
        unix_secs: u64,
    ) -> bool {
        let b = cookie_bucket(unix_secs);
        let cur = ct_eq(&self.compute(addr, eph_pub, b), cookie);
        let prev = b
            .checked_sub(1)
            .is_some_and(|p| ct_eq(&self.compute(addr, eph_pub, p), cookie));
        cur | prev
    }
}

// ---------- HELLO3 ----------

/// Версия из первого байта HELLO3 — до полного разбора: на чужую версию
/// сервер отвечает UNSUPPORTED, не разбирая раскладку, которой не знает.
pub fn hello_version(body: &[u8]) -> Option<u8> {
    body.first().copied()
}

/// Разобранный HELLO3. Подпись **не проверена**, пока не вызван
/// [`verify`](Self::verify): сервер сначала проверяет cookie (дешевле).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello3 {
    pub cookie: Option<[u8; COOKIE_LEN]>,
    pub ed_pub: [u8; 32],
    pub x_pub: [u8; 32],
    pub eph_pub: [u8; 32],
    pub name: String,
    pub flags: u8,
    pub sig: [u8; SIG_LEN],
    /// Байты body до подписи — то, что подписано (после тега).
    signed: Vec<u8>,
}

impl Hello3 {
    /// Body HELLO3, подписанный `id`. `cookie` — из CHALLENGE (первая
    /// попытка — `None`); подпись покрывает и cookie, и flags.
    pub fn encode(
        id: &Identity,
        eph_pub: &[u8; 32],
        name: &str,
        flags: u8,
        cookie: Option<&[u8; COOKIE_LEN]>,
    ) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + COOKIE_LEN + 96 + 256 + 1 + SIG_LEN);
        v.push(PROTOCOL_VERSION);
        match cookie {
            Some(c) => {
                v.push(COOKIE_LEN as u8);
                v.extend_from_slice(c);
            }
            None => v.push(0),
        }
        put_pub(&mut v, &id.ed_pub());
        put_pub(&mut v, &id.x_pub());
        put_pub(&mut v, eph_pub);
        put_str(&mut v, name);
        v.push(flags);
        let sig = id.sign(&[HELLO_TAG, &v].concat());
        v.extend_from_slice(&sig);
        v
    }

    /// Разбор без проверки подписи. Версия не 3, cookie_len не 0/16, обрезка
    /// или хвост — ошибка (фрейм отбрасывается).
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let version = r.u8()?;
        ensure!(version == PROTOCOL_VERSION, "HELLO3: версия {version}");
        let cookie = match r.u8()? {
            0 => None,
            16 => Some(r.array()?),
            n => bail!("HELLO3: cookie_len {n}"),
        };
        let ed_pub = r.pub_key()?;
        let x_pub = r.pub_key()?;
        let eph_pub = r.pub_key()?;
        let name = r.str()?;
        let flags = r.u8()?;
        let signed_len = r.p;
        let sig = r.array()?;
        r.finish()?;
        Ok(Self {
            cookie,
            ed_pub,
            x_pub,
            eph_pub,
            name,
            flags,
            sig,
            signed: body[..signed_len].to_vec(),
        })
    }

    /// Проверка подписи `ed_pub` над `"tunnel/v3/hello" || байты до sig`.
    pub fn verify(&self) -> Result<()> {
        Identity::verify(&self.ed_pub, &[HELLO_TAG, &self.signed].concat(), &self.sig)
            .map_err(|_| anyhow!("HELLO3: неверная подпись"))
    }

    pub fn invisible(&self) -> bool {
        self.flags & HELLO_FLAG_INVISIBLE != 0
    }
}

// ---------- CHALLENGE ----------

/// CHALLENGE: `version u8 | cookie [16]`.
pub fn enc_challenge(cookie: &[u8; COOKIE_LEN]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + COOKIE_LEN);
    v.push(PROTOCOL_VERSION);
    v.extend_from_slice(cookie);
    v
}

pub fn dec_challenge(body: &[u8]) -> Result<[u8; COOKIE_LEN]> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    ensure!(version == PROTOCOL_VERSION, "CHALLENGE: версия {version}");
    let cookie = r.array()?;
    r.finish()?;
    Ok(cookie)
}

// ---------- UNSUPPORTED ----------

/// UNSUPPORTED: `server_version u8 | text str` (версия — своя).
pub fn enc_unsupported(text: &str) -> Vec<u8> {
    let mut v = vec![PROTOCOL_VERSION];
    put_str(&mut v, text);
    v
}

/// (версия сервера, текст).
pub fn dec_unsupported(body: &[u8]) -> Result<(u8, String)> {
    let mut r = Reader::new(body);
    Ok((r.u8()?, r.str()?))
}

// ---------- ротация ключа сервера ----------

pub const LINK_LEN: usize = 32 + 32 + 32 + SIG_LEN;

/// Звено цепочки ротации: `old_ed` подписал переход на (`new_ed`, `new_x`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationLink {
    pub old_ed: [u8; 32],
    pub new_ed: [u8; 32],
    pub new_x: [u8; 32],
    pub sig: [u8; SIG_LEN],
}

/// Звено ротации `old` → `new` (`tunnel-server rotate-key`).
pub fn make_link(old: &Identity, new: &Identity) -> RotationLink {
    let new_ed = new.ed_pub();
    let new_x = new.x_pub();
    let sig = old.sign(&[ROTATE_TAG, &new_ed, &new_x].concat());
    RotationLink {
        old_ed: old.ed_pub(),
        new_ed,
        new_x,
        sig,
    }
}

impl RotationLink {
    /// Подпись `old_ed` над `"tunnel/v3/rotate" || new_ed || new_x`.
    pub fn verify(&self) -> Result<()> {
        Identity::verify(
            &self.old_ed,
            &[ROTATE_TAG, &self.new_ed, &self.new_x].concat(),
            &self.sig,
        )
        .map_err(|_| anyhow!("звено ротации: неверная подпись"))
    }

    /// Проводная раскладка (она же — для хранения в `server.json`).
    pub fn to_bytes(&self) -> [u8; LINK_LEN] {
        let mut b = [0u8; LINK_LEN];
        b[..32].copy_from_slice(&self.old_ed);
        b[32..64].copy_from_slice(&self.new_ed);
        b[64..96].copy_from_slice(&self.new_x);
        b[96..].copy_from_slice(&self.sig);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        ensure!(b.len() == LINK_LEN, "звено ротации: длина {}", b.len());
        let mut r = Reader::new(b);
        Ok(Self {
            old_ed: r.pub_key()?,
            new_ed: r.pub_key()?,
            new_x: r.pub_key()?,
            sig: r.array()?,
        })
    }

    fn read(r: &mut Reader) -> Result<Self> {
        Self::from_bytes(r.bytes(LINK_LEN)?)
    }
}

// ---------- WELCOME ----------

/// Проверенный WELCOME: подпись `server_ed` под эфемерный ключ клиента.
/// Совпадение `server_ed` с закреплённым — отдельно, [`resolve_pin`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Welcome {
    pub server_ed: [u8; 32],
    pub server_x: [u8; 32],
    pub server_eph: [u8; 32],
    /// От старых к новым.
    pub links: Vec<RotationLink>,
}

impl Welcome {
    /// Body WELCOME, подписанный `server` под (`client_ed`, `client_eph`).
    /// Из `links` (от старых к новым) берутся последние `MAX_LINKS`.
    pub fn encode(
        server: &Identity,
        server_eph: &[u8; 32],
        links: &[RotationLink],
        client_ed: &[u8; 32],
        client_eph: &[u8; 32],
    ) -> Vec<u8> {
        let links = &links[links.len().saturating_sub(MAX_LINKS)..];
        let mut v = Vec::with_capacity(1 + 96 + 1 + links.len() * LINK_LEN + SIG_LEN);
        v.push(PROTOCOL_VERSION);
        put_pub(&mut v, &server.ed_pub());
        put_pub(&mut v, &server.x_pub());
        put_pub(&mut v, server_eph);
        v.push(links.len() as u8);
        for l in links {
            v.extend_from_slice(&l.to_bytes());
        }
        let sig = server.sign(&welcome_signed(client_ed, client_eph, &v));
        v.extend_from_slice(&sig);
        v
    }

    /// Разбор и проверка подписи под свой `client_ed` / текущий `client_eph`:
    /// WELCOME для другой попытки (другого eph) не проходит.
    pub fn decode(body: &[u8], client_ed: &[u8; 32], client_eph: &[u8; 32]) -> Result<Self> {
        let mut r = Reader::new(body);
        let version = r.u8()?;
        ensure!(version == PROTOCOL_VERSION, "WELCOME: версия {version}");
        let server_ed = r.pub_key()?;
        let server_x = r.pub_key()?;
        let server_eph = r.pub_key()?;
        let n = r.u8()? as usize;
        ensure!(n <= MAX_LINKS, "WELCOME: {n} звеньев ротации");
        let links = (0..n)
            .map(|_| RotationLink::read(&mut r))
            .collect::<Result<Vec<_>>>()?;
        let signed_len = r.p;
        let sig = r.array()?;
        r.finish()?;
        Identity::verify(
            &server_ed,
            &welcome_signed(client_ed, client_eph, &body[..signed_len]),
            &sig,
        )
        .map_err(|_| anyhow!("WELCOME: неверная подпись"))?;
        Ok(Self {
            server_ed,
            server_x,
            server_eph,
            links,
        })
    }
}

fn welcome_signed(client_ed: &[u8; 32], client_eph: &[u8; 32], before_sig: &[u8]) -> Vec<u8> {
    [WELCOME_TAG, client_ed, client_eph, before_sig].concat()
}

/// Итог сверки ключа сервера с закреплённым.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinResolution {
    /// `server_ed` равен закреплённому.
    Same,
    /// Ключ сменён по цепочке от закреплённого: перезакрепить `new_ed`
    /// (`Event::ServerKeyRotated`, сохранение `client.json`).
    Rotated { new_ed: [u8; 32] },
}

/// Сверка проверенного WELCOME с закреплённым ключом (разделы 2 и 8):
/// равен — `Same`; иначе нужно звено с `old_ed == pinned`, от которого все
/// подписи верны, звенья сцеплены (`old_ed` = предыдущему `new_ed`), а
/// последнее ведёт к (`server_ed`, `server_x`). Иначе — ошибка.
pub fn resolve_pin(pinned: &[u8; 32], w: &Welcome) -> Result<PinResolution> {
    if w.server_ed == *pinned {
        return Ok(PinResolution::Same);
    }
    let chain_ok = |start: usize| -> bool {
        let tail = &w.links[start..];
        let Some(last) = tail.last() else {
            return false;
        };
        last.new_ed == w.server_ed
            && last.new_x == w.server_x
            && tail.windows(2).all(|p| p[1].old_ed == p[0].new_ed)
            && tail.iter().all(|l| l.verify().is_ok())
    };
    // Подделать звено от закреплённого ключа может только его владелец,
    // поэтому годится любое вхождение, от которого цепочка верна.
    if (0..w.links.len()).any(|i| w.links[i].old_ed == *pinned && chain_ok(i)) {
        Ok(PinResolution::Rotated {
            new_ed: w.server_ed,
        })
    } else {
        bail!("ключ сервера не совпадает")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Полный обмен на уровне криптографии: HELLO3 → CHALLENGE → HELLO3 с
    /// cookie → WELCOME, ключи сторон совпадают.
    #[test]
    fn рукопожатие_целиком() {
        let client = Identity::generate();
        let server = Identity::generate();
        let cookies = CookieSecret::generate();
        let from = addr("203.0.113.5:40000");
        let now = 1_700_000_000;
        let c_eph = EphemeralKey::generate();

        // 1. Первый HELLO3 без cookie.
        let h1 = Hello3::encode(&client, &c_eph.public(), "alpha", 0, None);
        assert_eq!(hello_version(&h1), Some(PROTOCOL_VERSION));
        let p1 = Hello3::decode(&h1).unwrap();
        assert!(p1.cookie.is_none());
        p1.verify().unwrap();
        // 2. CHALLENGE.
        let ch = enc_challenge(&cookies.make(from, &p1.eph_pub, now));
        let cookie = dec_challenge(&ch).unwrap();
        // 3. Повтор с cookie, тем же eph и invisible.
        let h2 = Hello3::encode(
            &client,
            &c_eph.public(),
            "alpha",
            HELLO_FLAG_INVISIBLE,
            Some(&cookie),
        );
        let p2 = Hello3::decode(&h2).unwrap();
        assert!(cookies.verify(from, &p2.eph_pub, p2.cookie.as_ref().unwrap(), now + 5));
        p2.verify().unwrap();
        assert!(p2.invisible());
        assert_eq!(
            (p2.ed_pub, p2.x_pub, p2.name.as_str()),
            (client.ed_pub(), client.x_pub(), "alpha")
        );
        // 4. WELCOME и ключи.
        let s_eph = EphemeralKey::generate();
        let w = Welcome::encode(&server, &s_eph.public(), &[], &p2.ed_pub, &p2.eph_pub);
        let srv = session_keys(Role::Server, &server, &s_eph, &p2.x_pub, &p2.eph_pub).unwrap();
        let wd = Welcome::decode(&w, &client.ed_pub(), &c_eph.public()).unwrap();
        assert_eq!(
            resolve_pin(&server.ed_pub(), &wd).unwrap(),
            PinResolution::Same
        );
        let cli =
            session_keys(Role::Client, &client, &c_eph, &wd.server_x, &wd.server_eph).unwrap();
        assert_eq!(cli.tx, srv.rx);
        assert_eq!(cli.rx, srv.tx);
        assert_ne!(cli.tx, cli.rx, "направления разведены");

        // Шифрованный канал работает в обе стороны.
        let f = crate::seal_ctrl(&cli.tx, 0, crate::ctrl::CTRL_PING, b"");
        let (t, b) = crate::split_frame(&f).unwrap();
        assert!(crate::open_ctrl(&srv.rx, t, b).is_ok());
        assert!(
            crate::open_ctrl(&srv.tx, t, b).is_err(),
            "свой же ключ направления не подходит"
        );

        // Новая попытка с другим eph даёт другие ключи (прямая секретность).
        let c_eph2 = EphemeralKey::generate();
        let cli2 =
            session_keys(Role::Client, &client, &c_eph2, &wd.server_x, &wd.server_eph).unwrap();
        assert_ne!(cli2.tx, cli.tx);
    }

    #[test]
    fn welcome_для_другого_eph_или_клиента_отвергается() {
        let client = Identity::generate();
        let server = Identity::generate();
        let eph = EphemeralKey::generate();
        let s_eph = EphemeralKey::generate();
        let w = Welcome::encode(
            &server,
            &s_eph.public(),
            &[],
            &client.ed_pub(),
            &eph.public(),
        );
        Welcome::decode(&w, &client.ed_pub(), &eph.public()).unwrap();
        let other = EphemeralKey::generate();
        assert!(Welcome::decode(&w, &client.ed_pub(), &other.public()).is_err());
        assert!(Welcome::decode(&w, &Identity::generate().ed_pub(), &eph.public()).is_err());
        // Порча любого байта, обрезка, хвост.
        for i in 0..w.len() {
            let mut t = w.clone();
            t[i] ^= 0x10;
            assert!(
                Welcome::decode(&t, &client.ed_pub(), &eph.public()).is_err(),
                "байт {i}"
            );
        }
        assert!(Welcome::decode(&w[..w.len() - 1], &client.ed_pub(), &eph.public()).is_err());
        let mut long = w.clone();
        long.push(0);
        assert!(Welcome::decode(&long, &client.ed_pub(), &eph.public()).is_err());
        // Подпись чужим ключом при подменённом server_ed не проходит.
        let fake = Identity::generate();
        let fw = Welcome::encode(&fake, &s_eph.public(), &[], &client.ed_pub(), &eph.public());
        let wd = Welcome::decode(&fw, &client.ed_pub(), &eph.public()).unwrap();
        assert!(resolve_pin(&server.ed_pub(), &wd).is_err());
    }

    #[test]
    fn подпись_hello3_покрывает_cookie_и_flags() {
        let id = Identity::generate();
        let eph = EphemeralKey::generate();
        let h = Hello3::encode(&id, &eph.public(), "имя", 0, Some(&[7; 16]));
        Hello3::decode(&h).unwrap().verify().unwrap();
        // Каждый байт до подписи (и сама подпись) под защитой.
        for i in 0..h.len() {
            let mut t = h.clone();
            t[i] ^= 0x01;
            let ok = Hello3::decode(&t).and_then(|p| p.verify()).is_ok();
            assert!(!ok, "байт {i}");
        }
        // Явно: другой cookie и другие flags.
        let mut p = Hello3::decode(&h).unwrap();
        p.signed[2] ^= 1; // первый байт cookie
        assert!(p.verify().is_err());
        let flags_at = h.len() - SIG_LEN - 1;
        let mut t = h.clone();
        t[flags_at] = HELLO_FLAG_INVISIBLE;
        assert!(Hello3::decode(&t).unwrap().verify().is_err());
        // Без cookie подпись другая, чем с cookie.
        let h0 = Hello3::encode(&id, &eph.public(), "имя", 0, None);
        assert_ne!(h0[h0.len() - SIG_LEN..], h[h.len() - SIG_LEN..]);
    }

    #[test]
    fn hello3_неверные_форматы() {
        let id = Identity::generate();
        let h = Hello3::encode(&id, &[1; 32], "n", 0, None);
        let mut v2 = h.clone();
        v2[0] = 2;
        assert!(Hello3::decode(&v2).is_err());
        assert_eq!(hello_version(&v2), Some(2));
        assert_eq!(hello_version(&[]), None);
        let mut bad_len = h.clone();
        bad_len[1] = 8;
        assert!(Hello3::decode(&bad_len).is_err());
        for n in 0..h.len() {
            assert!(Hello3::decode(&h[..n]).is_err(), "обрезка до {n}");
        }
        let mut long = h.clone();
        long.push(0);
        assert!(Hello3::decode(&long).is_err());
    }

    #[test]
    fn cookie_привязан_к_адресу_ключу_и_времени() {
        let s = CookieSecret::from_bytes([5; 32]);
        let a = addr("198.51.100.7:5000");
        let eph = [9u8; 32];
        let t = 1_000_000_020; // начало bucket'а (кратно 30)
        assert_eq!(t % COOKIE_BUCKET_SECS, 0);
        let c = s.make(a, &eph, t);
        assert!(s.verify(a, &eph, &c, t));
        assert!(s.verify(a, &eph, &c, t + 29), "тот же bucket");
        assert!(
            s.verify(a, &eph, &c, t + 59),
            "следующий bucket — ещё принимается"
        );
        assert!(!s.verify(a, &eph, &c, t + 60), "через два — нет");
        assert!(!s.verify(a, &eph, &c, t - 1), "из будущего bucket'а — нет");
        assert!(
            !s.verify(addr("198.51.100.7:5001"), &eph, &c, t),
            "другой порт"
        );
        assert!(
            !s.verify(addr("198.51.100.8:5000"), &eph, &c, t),
            "другой IP"
        );
        assert!(!s.verify(a, &[8u8; 32], &c, t), "другой eph");
        assert!(
            !CookieSecret::from_bytes([6; 32]).verify(a, &eph, &c, t),
            "другой секрет"
        );
        // IPv4 и он же как v4-mapped IPv6 — один cookie; настоящий IPv6 — свой.
        let mapped = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(198, 51, 100, 7).to_ipv6_mapped()),
            5000,
        );
        assert_eq!(s.make(mapped, &eph, t), c);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5000);
        assert_ne!(s.make(v6, &eph, t), c);
        assert!(s.verify(v6, &eph, &s.make(v6, &eph, t), t));
        // bucket 0: предыдущего нет, переполнения нет.
        let c0 = s.make(a, &eph, 0);
        assert!(s.verify(a, &eph, &c0, 0));
        assert_eq!(cookie_bucket(59), 1);
    }

    #[test]
    fn challenge_и_unsupported_туда_обратно() {
        let ch = enc_challenge(&[3; 16]);
        assert_eq!(dec_challenge(&ch).unwrap(), [3; 16]);
        assert!(dec_challenge(&ch[..16]).is_err());
        let mut v = ch.clone();
        v[0] = PROTOCOL_VERSION - 1;
        assert!(dec_challenge(&v).is_err());
        let u = enc_unsupported("обновите клиент");
        assert_eq!(
            dec_unsupported(&u).unwrap(),
            (PROTOCOL_VERSION, "обновите клиент".to_string())
        );
        assert!(dec_unsupported(&u[..3]).is_err());
        assert!(dec_unsupported(&[]).is_err());
    }

    #[test]
    fn dh_малого_порядка_отвергается() {
        let id = Identity::generate();
        let eph = EphemeralKey::generate();
        assert!(eph.dh(&[0; 32]).is_err());
        assert!(
            session_keys(
                Role::Client,
                &id,
                &eph,
                &[0; 32],
                &EphemeralKey::generate().public()
            )
            .is_err()
        );
        assert!(
            session_keys(
                Role::Client,
                &id,
                &eph,
                &Identity::generate().x_pub(),
                &[0; 32]
            )
            .is_err()
        );
    }

    /// Цепочка A → B → C → D; сервер сейчас D.
    fn chain(n: usize) -> (Vec<Identity>, Vec<RotationLink>) {
        let ids: Vec<Identity> = (0..n).map(|_| Identity::generate()).collect();
        let links = ids.windows(2).map(|p| make_link(&p[0], &p[1])).collect();
        (ids, links)
    }

    fn welcome_from(server: &Identity, links: &[RotationLink]) -> Welcome {
        let (ced, ceph) = ([1u8; 32], [2u8; 32]);
        Welcome::decode(
            &Welcome::encode(server, &[3; 32], links, &ced, &ceph),
            &ced,
            &ceph,
        )
        .unwrap()
    }

    #[test]
    fn цепочка_ротации() {
        let (ids, links) = chain(4);
        let cur = &ids[3];
        let w = welcome_from(cur, &links);
        assert_eq!(w.links, links);
        // Закреплён текущий — Same.
        assert_eq!(resolve_pin(&cur.ed_pub(), &w).unwrap(), PinResolution::Same);
        // Любой старый ключ цепочки — Rotated на текущий.
        for old in &ids[..3] {
            assert_eq!(
                resolve_pin(&old.ed_pub(), &w).unwrap(),
                PinResolution::Rotated {
                    new_ed: cur.ed_pub()
                }
            );
        }
        // Чужой ключ — ошибка.
        let err = resolve_pin(&Identity::generate().ed_pub(), &w)
            .unwrap_err()
            .to_string();
        assert!(err.contains("не совпадает"), "{err}");
        // Без цепочки старый ключ не принимается.
        assert!(resolve_pin(&ids[0].ed_pub(), &welcome_from(cur, &[])).is_err());
    }

    #[test]
    fn битое_звено_рвёт_цепочку() {
        let (ids, mut links) = chain(4);
        // Подпись среднего звена испорчена: от A и B — ошибка, от C — ещё верно.
        links[1].sig[0] ^= 1;
        let w = welcome_from(&ids[3], &links);
        assert!(resolve_pin(&ids[0].ed_pub(), &w).is_err());
        assert!(resolve_pin(&ids[1].ed_pub(), &w).is_err());
        assert!(resolve_pin(&ids[2].ed_pub(), &w).is_ok());

        // Разрыв сцепки: звено X → D вместо C → D.
        let (ids, mut links) = chain(4);
        let x = Identity::generate();
        links[2] = make_link(&x, &ids[3]);
        let w = welcome_from(&ids[3], &links);
        assert!(resolve_pin(&ids[0].ed_pub(), &w).is_err());
        assert!(resolve_pin(&x.ed_pub(), &w).is_ok(), "от X цепочка цела");

        // Последнее звено ведёт не к server_ed.
        let (ids, links) = chain(3);
        let w = welcome_from(&Identity::generate(), &links);
        assert!(resolve_pin(&ids[0].ed_pub(), &w).is_err());
    }

    #[test]
    fn чужая_цепочка_не_принимается() {
        // Атакующий M строит свою цепочку P → M, где P — его же ключ: от
        // закреплённого A звена нет.
        let a = Identity::generate();
        let (ids, links) = chain(3);
        let w = welcome_from(&ids[2], &links);
        assert!(resolve_pin(&a.ed_pub(), &w).is_err());
        // Звено с old_ed = A, но подписанное не A.
        let m = Identity::generate();
        let mut forged = make_link(&m, &ids[2]);
        forged.old_ed = a.ed_pub();
        let w = welcome_from(&ids[2], &[forged]);
        assert!(resolve_pin(&a.ed_pub(), &w).is_err());
        // Последнее звено с другим new_x (подмена x-ключа) — ошибка.
        let (ids, mut links) = chain(2);
        links[0].new_x = Identity::generate().x_pub();
        let w = welcome_from(&ids[1], &links);
        assert!(resolve_pin(&ids[0].ed_pub(), &w).is_err());
    }

    #[test]
    fn welcome_несёт_не_больше_8_звеньев() {
        let (ids, links) = chain(12);
        let w = welcome_from(&ids[11], &links);
        assert_eq!(w.links.len(), MAX_LINKS);
        assert_eq!(w.links, links[links.len() - MAX_LINKS..]);
        // Самые старые ключи (за пределами 8 звеньев) уже не перезакрепляются.
        assert!(resolve_pin(&ids[0].ed_pub(), &w).is_err());
        assert!(resolve_pin(&ids[3].ed_pub(), &w).is_ok());
        // Декодер отвергает n_links > 8.
        let mut raw = Welcome::encode(&ids[11], &[3; 32], &links, &[1; 32], &[2; 32]);
        raw[97] = 9;
        assert!(Welcome::decode(&raw, &[1; 32], &[2; 32]).is_err());
    }

    #[test]
    fn звено_туда_обратно() {
        let (_, links) = chain(2);
        let l = &links[0];
        l.verify().unwrap();
        assert_eq!(&RotationLink::from_bytes(&l.to_bytes()).unwrap(), l);
        assert!(RotationLink::from_bytes(&l.to_bytes()[..LINK_LEN - 1]).is_err());
    }
}
