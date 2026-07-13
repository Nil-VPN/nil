//! Inner-tunnel IPv4 address pool — the node side of the RFC 9484 ADDRESS_ASSIGN subset.
//!
//! Each concurrent CONNECT-IP client is handed a UNIQUE inner address from this pool so two
//! clients never collide on one tunnel IP (the bug where every client hardcoded `10.74.0.2`). The
//! address is released the moment the client's connection closes, so the pool churns without any
//! persisted, user-linkable state (PD-2: nothing retained beyond the live session).
//!
//! The pool carries NO identity: it maps an opaque connection key (the QUIC SCID bytes) to a
//! freshly-allocated host address and back. It never sees an account, token, or source IP.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

/// A pool of assignable inner host addresses inside one tunnel CIDR. Hands out unique `/32`s and
/// reclaims them on release. Default range is `10.74.0.0/16` with the network, the node/peer
/// address (`.0.1`), and the broadcast reserved.
pub struct AddressPool {
    /// Inclusive range of assignable host integers `[first, last]` (already excludes reserved).
    first: u32,
    last: u32,
    /// Next candidate to try (a rotating cursor so we don't always re-probe from the bottom).
    cursor: u32,
    /// Currently-allocated host integers.
    in_use: HashSet<u32>,
    /// Connection key → assigned host integer, so release is O(1) and idempotent.
    by_conn: HashMap<Vec<u8>, u32>,
}

impl AddressPool {
    /// The default tunnel pool: `10.74.0.0/16`, peer/gateway at `10.74.0.1`. Assignable hosts are
    /// `10.74.0.2 ..= 10.74.255.254`.
    pub fn default_v4() -> Self {
        // 10.74.0.0 with a /16 mask.
        Self::new(Ipv4Addr::new(10, 74, 0, 0), 16, Ipv4Addr::new(10, 74, 0, 1))
            .expect("the built-in default pool is valid")
    }

    /// Build a pool for `base/prefix`, reserving the network address, the broadcast address, and
    /// `gateway` (the node's own inner address). Returns `None` for a prefix that leaves no
    /// assignable host (`/31`, `/32`) or a `gateway`/`base` mismatch.
    pub fn new(base: Ipv4Addr, prefix: u8, gateway: Ipv4Addr) -> Option<Self> {
        if prefix >= 31 {
            return None; // no room for distinct host addresses
        }
        let host_bits = 32 - prefix as u32;
        let mask = !0u32 << host_bits; // network mask
        let base_u = u32::from(base) & mask; // normalize to the network address
        let network = base_u;
        let broadcast = base_u | !mask;
        // Assignable host range: everything strictly between network and broadcast.
        let first = network + 1;
        let last = broadcast - 1;
        if first > last {
            return None;
        }
        let gw = u32::from(gateway);
        if gw & mask != network {
            return None; // gateway is not inside this network
        }
        let mut in_use = HashSet::new();
        // Reserve the gateway if it falls in the assignable band (it normally does, e.g. .0.1).
        if (first..=last).contains(&gw) {
            in_use.insert(gw);
        }
        Some(Self {
            first,
            last,
            cursor: first,
            in_use,
            by_conn: HashMap::new(),
        })
    }

    /// Allocate a unique address for `conn_key`. Idempotent: a key that already holds an address
    /// gets the same one back (so a duplicated accept never leaks a second address). Returns `None`
    /// only when the pool is exhausted.
    pub fn assign(&mut self, conn_key: &[u8]) -> Option<Ipv4Addr> {
        if let Some(&existing) = self.by_conn.get(conn_key) {
            return Some(Ipv4Addr::from(existing));
        }
        let span = self.last - self.first + 1;
        let mut tried = 0u32;
        while tried < span {
            let candidate = self.cursor;
            // Advance the cursor with wraparound within [first, last].
            self.cursor = if self.cursor >= self.last {
                self.first
            } else {
                self.cursor + 1
            };
            tried += 1;
            if !self.in_use.contains(&candidate) {
                self.in_use.insert(candidate);
                self.by_conn.insert(conn_key.to_vec(), candidate);
                return Some(Ipv4Addr::from(candidate));
            }
        }
        None // exhausted
    }

    /// Release the address held by `conn_key` (no-op if it held none). Called on disconnect so the
    /// address returns to the pool immediately.
    pub fn release(&mut self, conn_key: &[u8]) {
        if let Some(addr) = self.by_conn.remove(conn_key) {
            self.in_use.remove(&addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigns_unique_addresses_and_skips_reserved() {
        let mut p = AddressPool::default_v4();
        let a = p.assign(b"conn-a").unwrap();
        let b = p.assign(b"conn-b").unwrap();
        assert_ne!(a, b, "two clients get distinct inner addresses");
        // The gateway .0.1 is reserved and never handed out.
        assert_ne!(a, Ipv4Addr::new(10, 74, 0, 1));
        assert_ne!(b, Ipv4Addr::new(10, 74, 0, 1));
        // First assignable is .0.2 (the old hardcoded value).
        assert_eq!(a, Ipv4Addr::new(10, 74, 0, 2));
    }

    #[test]
    fn assign_is_idempotent_per_connection() {
        let mut p = AddressPool::default_v4();
        let first = p.assign(b"same").unwrap();
        let again = p.assign(b"same").unwrap();
        assert_eq!(first, again, "same connection key → same address");
    }

    #[test]
    fn release_returns_address_to_the_pool() {
        // Tiny /29 = 8 addrs: network, .1 gw, .2..=.6 assignable (5), broadcast.
        let mut p = AddressPool::new(
            Ipv4Addr::new(192, 168, 9, 0),
            29,
            Ipv4Addr::new(192, 168, 9, 1),
        )
        .unwrap();
        let mut handed = Vec::new();
        for i in 0..5u8 {
            handed.push(p.assign(&[i]).expect("address available"));
        }
        // Pool exhausted now.
        assert!(p.assign(b"overflow").is_none(), "pool exhausted");
        // Release one; the next assign succeeds and reuses a freed address.
        p.release(&[2u8]);
        let reused = p.assign(b"new").expect("freed address reusable");
        assert!(
            handed.contains(&reused),
            "reused a previously-freed address"
        );
    }

    #[test]
    fn distinct_clients_never_share_a_live_address() {
        let mut p =
            AddressPool::new(Ipv4Addr::new(10, 0, 0, 0), 29, Ipv4Addr::new(10, 0, 0, 1)).unwrap();
        let mut seen = std::collections::HashSet::new();
        for i in 0..5u8 {
            let a = p.assign(&[i]).unwrap();
            assert!(seen.insert(a), "no live address handed to two clients");
        }
    }

    #[test]
    fn rejects_prefixes_with_no_room() {
        assert!(
            AddressPool::new(Ipv4Addr::new(10, 0, 0, 0), 31, Ipv4Addr::new(10, 0, 0, 0)).is_none()
        );
        assert!(
            AddressPool::new(Ipv4Addr::new(10, 0, 0, 0), 32, Ipv4Addr::new(10, 0, 0, 0)).is_none()
        );
    }
}
