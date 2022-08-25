use crate::device::allowed_ips::AllowedIps;
use crate::device::peer::{AllowedIP, Peer};
use parking_lot::Mutex;
use std::collections::hash_map::{Iter, IterMut};
use std::collections::HashMap;
use std::sync::Arc;

/// Representation of a Peer registry.
pub trait Registry: Send + Sync + 'static {
    /// Register a new peer with the registry
    fn insert(
        &mut self,
        public_key: x25519_dalek::PublicKey,
        peer: Arc<Mutex<Peer>>,
        allowed_ips: &[AllowedIP],
    );

    /// Get a registry peer by its public key
    fn get(&mut self, public_key: &x25519_dalek::PublicKey) -> RegistryPeer;

    /// Get the trie of IP/cidr addresses with the associated peer
    fn get_by_allowed_ip(&self) -> &AllowedIps<Arc<Mutex<Peer>>>;

    /// Get the peer at a given index
    fn get_peer_at(&self, idx: u32) -> Option<Arc<Mutex<Peer>>>;

    /// An iterator visiting all the key-value peer pairings in arbitrary order.
    fn iter(&self) -> Iter<x25519_dalek::PublicKey, Arc<Mutex<Peer>>>;

    /// An iterator visiting all the key-value peer pairings in arbitrary order, with mutable
    /// references to the peers.
    fn iter_mut(&mut self) -> IterMut<x25519_dalek::PublicKey, Arc<Mutex<Peer>>>;

    /// Removes a registered peer by its public key
    fn remove(&mut self, public_key: &x25519_dalek::PublicKey) -> Option<Arc<Mutex<Peer>>>;

    /// Clear the registry of all peers
    fn clear(&mut self);

    /// Get the next available peer index
    fn next_index(&mut self) -> u32;
}

/// Encapsulates a peer type defined in the registry
pub enum RegistryPeer {
    /// A candidate created by the registry but not yet full initialized
    Candidate(PeerCandidate),
    /// A full fledged peer
    Peer(Arc<Mutex<Peer>>),
    None,
}

impl From<RegistryPeer> for Option<Arc<Mutex<Peer>>> {
    fn from(c: RegistryPeer) -> Self {
        match c {
            RegistryPeer::Peer(peer) => Some(peer),
            _ => None,
        }
    }
}

/// A peer candidate which has been staged in the registry but does not yet have a full
/// [Peer](crate::device::peer::Peer) representation within the registry
#[derive(Clone)]
pub struct PeerCandidate {
    pub public_key: x25519_dalek::PublicKey,
    pub allowed_ips: Vec<AllowedIP>,
    pub keepalive: Option<u16>,
}

/// An in memory registry.
pub struct InMemoryRegistry {
    next_index: u32,
    peers: HashMap<x25519_dalek::PublicKey, Arc<Mutex<Peer>>>,
    peers_by_ip: AllowedIps<Arc<Mutex<Peer>>>,
    peers_by_idx: HashMap<u32, Arc<Mutex<Peer>>>,
}

impl Default for InMemoryRegistry {
    fn default() -> Self {
        Self {
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_ip: AllowedIps::new(),
            peers_by_idx: Default::default(),
        }
    }
}

impl Registry for InMemoryRegistry {
    fn insert(
        &mut self,
        public_key: x25519_dalek::PublicKey,
        peer: Arc<Mutex<Peer>>,
        allowed_ips: &[AllowedIP],
    ) {
        self.peers.insert(public_key, peer.clone());
        self.peers_by_idx.insert(peer.lock().index(), peer.clone());
        for AllowedIP { addr, cidr } in allowed_ips {
            self.peers_by_ip.insert(*addr, *cidr as _, peer.clone());
        }
    }

    fn get(&mut self, public_key: &x25519_dalek::PublicKey) -> RegistryPeer {
        self.peers
            .get(public_key)
            .cloned()
            .map(|peer| RegistryPeer::Peer(peer))
            .unwrap_or(RegistryPeer::None)
    }

    fn get_by_allowed_ip(&self) -> &AllowedIps<Arc<Mutex<Peer>>> {
        &self.peers_by_ip
    }

    fn get_peer_at(&self, idx: u32) -> Option<Arc<Mutex<Peer>>> {
        self.peers_by_idx.get(&idx).cloned()
    }

    fn iter(&self) -> Iter<x25519_dalek::PublicKey, Arc<Mutex<Peer>>> {
        self.peers.iter()
    }

    fn iter_mut(&mut self) -> IterMut<x25519_dalek::PublicKey, Arc<Mutex<Peer>>> {
        self.peers.iter_mut()
    }

    fn remove(&mut self, public_key: &x25519_dalek::PublicKey) -> Option<Arc<Mutex<Peer>>> {
        self.peers.remove(public_key).map(|peer| {
            {
                let p = peer.lock();
                p.shutdown_endpoint();
                self.peers_by_idx.remove(&p.index());
            }

            self.peers_by_ip
                .remove(&|p: &Arc<Mutex<Peer>>| Arc::ptr_eq(&peer, p));

            peer
        })
    }

    fn clear(&mut self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.clear();
    }

    fn next_index(&mut self) -> u32 {
        let next = self.next_index;
        self.next_index += 1;
        assert!(next < (1 << 24), "Too many peers created");
        next
    }
}

impl Registry for () {
    fn insert(&mut self, _: x25519_dalek::PublicKey, _: Arc<Mutex<Peer>>, _: &[AllowedIP]) {
        unimplemented!();
    }

    fn get(&mut self, _: &x25519_dalek::PublicKey) -> RegistryPeer {
        unimplemented!();
    }

    fn get_by_allowed_ip(&self) -> &AllowedIps<Arc<Mutex<Peer>>> {
        unimplemented!();
    }

    fn get_peer_at(&self, _: u32) -> Option<Arc<Mutex<Peer>>> {
        unimplemented!();
    }

    fn iter(&self) -> Iter<x25519_dalek::PublicKey, Arc<Mutex<Peer>>> {
        unimplemented!();
    }

    fn iter_mut(&mut self) -> IterMut<x25519_dalek::PublicKey, Arc<Mutex<Peer>>> {
        unimplemented!();
    }

    fn remove(&mut self, _: &x25519_dalek::PublicKey) -> Option<Arc<Mutex<Peer>>> {
        unimplemented!();
    }

    fn clear(&mut self) {
        unimplemented!();
    }

    fn next_index(&mut self) -> u32 {
        unimplemented!();
    }
}
