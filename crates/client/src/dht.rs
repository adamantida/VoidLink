//! DHT-оверлей клиента (§3.3 плана этапа 9).
//!
//! Идентификатор узла — ed25519-ключ клиента, расстояние — XOR (Kademlia:
//! 32 корзины × 8 контактов, индекс — старшие 5 бит расстояния,
//! `tunnel_protocol::mesh::distance_bucket`). Бутстрап: `MESH_SEED` от
//! сервера, кэш контактов из состава групп, сохранённая таблица
//! (`client.json` → `mesh.contacts`).
//!
//! T1 — каркас: [`Dht`] и [`Dht::bootstrap`] (no-op). Поиск (`find_node`,
//! α=3/β=2/глубина 2), пинг 8 ближайших раз в 5 минут, TTL и персистенция —
//! T3.

use tunnel_protocol::payloads::MeshSeed;

/// Таблица маршрутизации DHT. T3 наполнит корзинами/контактами.
#[derive(Debug, Default)]
pub struct Dht {}

impl Dht {
    pub fn new() -> Self {
        Self::default()
    }

    /// Наполнить таблицу контактами (MESH_SEED, кэш групп, сохранённая
    /// таблица). T3; пока — no-op.
    pub fn bootstrap(&self, _seeds: &[MeshSeed]) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_protocol::mesh;

    #[test]
    fn каркас_dht() {
        let d = Dht::new();
        // Пустой бутстрап безопасен (в т.ч. до T3).
        d.bootstrap(&[]);
        let seed = MeshSeed {
            ed_pub: [1; 32],
            x_pub: [2; 32],
            addr: "203.0.113.9:4000".parse().unwrap(),
        };
        d.bootstrap(&[seed]);
        // Корзина — старшие 5 бит XOR-расстояния: 32 корзины укладываются в u8.
        let me = [0u8; 32];
        let mut far = [0u8; 32];
        far[0] = 0xFF;
        assert_eq!(mesh::distance_bucket(&me, &far), 31);
        assert!(mesh::distance_bucket(&me, &me) == 0);
    }
}