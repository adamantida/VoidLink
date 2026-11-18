//! Персистентность сервера: server.json (identity, цепочка ротации ключа,
//! группы, leases, бан-листы, приглашения).
//!
//! Новые поля v3 — с `#[serde(default)]` и в отдельных картах по hex-ключу
//! участника: server.json сервера v2 загружается как есть (эпоха и ревизия
//! начинаются заново, имена офлайн-участников — «…», срок приглашений —
//! от момента загрузки).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Default)]
pub struct Persisted {
    pub ed_seed: [u8; 32],
    pub x_seed: [u8; 32],
    pub next_gid: u32,
    pub groups: Vec<PGroup>,
    /// Цепочка ротации ключа сервера: hex 160-байтовых звеньев
    /// (`RotationLink::to_bytes`), от старых к новым. Пишет `rotate-key`.
    #[serde(default)]
    pub rotations: Vec<String>,
    /// hex pubkey → адрес оверлея identity (v4: один на все группы). В
    /// файле сервера v3 поля нет: адреса берутся из групп (`PGroup::members`).
    #[serde(default)]
    pub user_ips: BTreeMap<String, u32>,
}

#[derive(Serialize, Deserialize)]
pub struct PGroup {
    pub id: u32,
    pub name: String,
    pub owner: String, // hex pubkey
    #[serde(default)]
    pub private: bool,
    pub key: [u8; 32],
    /// (hex pubkey, ip). С v4 ip равен `Persisted::user_ips` этой identity.
    pub members: Vec<(String, u32)>,
    #[serde(default)]
    pub banned: Vec<String>,
    #[serde(default)]
    pub invites: Vec<String>,
    /// Номер ключа `key` и ревизия состояния (раздел 5 спецификации).
    #[serde(default)]
    pub epoch: u32,
    #[serde(default)]
    pub rev: u32,
    #[serde(default)]
    pub revoke_prev: bool,
    /// hex pubkey → имя / статус участника (офлайн-участники после
    /// рестарта показываются с последним именем, а не «…»).
    #[serde(default)]
    pub member_names: BTreeMap<String, String>,
    #[serde(default)]
    pub member_status: BTreeMap<String, String>,
    /// hex pubkey → последнее известное имя забаненного (ADMIN_INFO).
    #[serde(default)]
    pub ban_names: BTreeMap<String, String>,
    /// hex pubkey → время приглашения (unix мс) — для `invite_ttl`.
    #[serde(default)]
    pub invite_times: BTreeMap<String, u64>,
    #[serde(default)]
    pub invite_names: BTreeMap<String, String>,
}

/// Только ключ сервера и цепочка из server.json (без групп): им запущенный
/// сервер проверяет, не сменил ли ключ `rotate-key`.
#[derive(Deserialize)]
pub struct PKey {
    pub ed_seed: [u8; 32],
    pub x_seed: [u8; 32],
    #[serde(default)]
    pub rotations: Vec<String>,
}

/// Отпечаток файла (время изменения, размер): изменился ли он с нашей записи.
pub type Stamp = Option<(std::time::SystemTime, u64)>;

pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new(dir: &Path) -> Self {
        let _ = std::fs::create_dir_all(dir);
        Self {
            path: dir.join("server.json"),
        }
    }

    /// `Ok(None)` — файла нет (первый запуск). Битый файл — ошибка: раньше
    /// сервер молча создавал новую identity и затирал файл, после чего все
    /// клиенты (они пиннят ключ сервера) переставали подключаться.
    pub fn load(&self) -> anyhow::Result<Option<Persisted>> {
        let raw = match std::fs::read(&self.path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => anyhow::bail!("не прочитать {}: {e}", self.path.display()),
        };
        serde_json::from_slice(&raw).map(Some).map_err(|e| {
            anyhow::anyhow!(
                "{} повреждён ({e}); почини или убери файл (новая identity сервера = новый код для всех клиентов)",
                self.path.display()
            )
        })
    }

    /// Ключ и цепочка из файла на диске (`None` — нет файла или не читается).
    pub fn load_key(&self) -> Option<PKey> {
        let raw = std::fs::read(&self.path).ok()?;
        serde_json::from_slice(&raw).ok()
    }

    /// Эксклюзивная (advisory) блокировка `server.json.lock` до drop
    /// результата. Под ней пишут и сервер, и `rotate-key`: оба делают
    /// чтение-изменение-запись, и без неё запись одного вклинивалась бы
    /// между проверкой и записью другого.
    pub fn lock(&self) -> std::io::Result<std::fs::File> {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.path.with_extension("json.lock"))?;
        f.lock()?;
        Ok(f)
    }

    pub fn stamp(&self) -> Stamp {
        let m = std::fs::metadata(&self.path).ok()?;
        Some((m.modified().ok()?, m.len()))
    }

    /// Атомарная запись: tmp + rename.
    pub fn save(&self, data: &Persisted) -> std::io::Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(data)?;
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}
