//! Per-connection traffic obfuscation (opt-in, negotiated).
//!
//! The steady-state EasyTier frame has several cleartext, fixed-layout fields
//! (the UDP tunnel header, the peer-manager header, and — in secure mode — an
//! incrementing nonce counter) that make it easy to fingerprint. This module
//! hangs off the peer-connection tunnel filter chain and will, once the
//! transforms land, mask those fields so two cooperating nodes produce a far
//! less distinctive byte stream.
//!
//! It is strictly negotiated: a link obfuscates only when BOTH ends advertise
//! [`FEATURE`] during the Noise handshake. A peer on an older build, or one
//! that cannot be updated (e.g. an iOS/macOS device), never advertises the
//! feature, so that link transparently keeps the legacy wire format. Because
//! negotiation is per hop, a mesh can mix obfuscated and legacy links freely.
//!
//! Phase 1 (this change) wires the negotiation and the per-link key through
//! without altering a single byte on the wire; [`before_send`] and
//! [`after_received`] are pass-throughs. The Phase 2 transforms plug in behind
//! the [`is_enabled`](PeerConnObfs::is_enabled) gate.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use arc_swap::ArcSwapOption;
use sha2::{Digest, Sha256};

use crate::tunnel::{SinkItem, StreamItem, filter::TunnelFilter};

/// Feature string advertised in the handshake. Present only when the local
/// node both runs secure mode and supports obfuscation, so observing it on a
/// link implies mutual agreement.
pub(super) const FEATURE: &str = "obfs-v1";

/// Domain separator so the obfuscation key can never collide with any other
/// key derived from the same handshake material.
const KEY_DOMAIN: &[u8] = b"easytier-peerconn-obfs-v1";

#[derive(Clone, Default)]
pub(super) struct PeerConnObfs {
    inner: Arc<PeerConnObfsInner>,
}

#[derive(Default)]
struct PeerConnObfsInner {
    enabled: AtomicBool,
    key: ArcSwapOption<[u8; 32]>,
}

impl PeerConnObfs {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Settle whether this link uses the obfuscated format. All three inputs
    /// are required:
    /// - `local_enabled`: the local node wants obfuscation (secure mode on).
    /// - `remote_features`: the peer advertised [`FEATURE`].
    /// - `key_seed`: a per-link secret identical on both ends and never sent on
    ///   the wire (the final Noise handshake hash). Absent on the legacy,
    ///   non-secure handshake, which keeps obfuscation off.
    pub(super) fn negotiate(
        &self,
        local_enabled: bool,
        remote_features: &[String],
        key_seed: Option<&[u8]>,
    ) {
        let remote_supports = remote_features.iter().any(|f| f == FEATURE);
        match key_seed {
            Some(seed) if local_enabled && remote_supports && !seed.is_empty() => {
                self.inner.key.store(Some(Arc::new(derive_key(seed))));
                self.inner.enabled.store(true, Ordering::Release);
            }
            _ => {
                self.inner.enabled.store(false, Ordering::Release);
                self.inner.key.store(None);
            }
        }
    }

    // Gate for the Phase 2 transforms in `before_send`/`after_received`.
    #[allow(dead_code)]
    pub(super) fn is_enabled(&self) -> bool {
        self.inner.enabled.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn key(&self) -> Option<[u8; 32]> {
        self.inner.key.load().as_deref().copied()
    }
}

fn derive_key(seed: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_DOMAIN);
    hasher.update(seed);
    hasher.finalize().into()
}

impl TunnelFilter for PeerConnObfs {
    type FilterOutput = ();

    fn before_send(&self, data: SinkItem) -> Option<SinkItem> {
        // Phase 1: negotiation plumbing only. The Phase 2 transforms gate on
        // `self.is_enabled()` and mutate the frame here before it reaches the
        // raw tunnel.
        Some(data)
    }

    fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
        Some(data)
    }

    fn filter_output(&self) {}
}

#[cfg(test)]
mod tests {
    use super::{FEATURE, PeerConnObfs};

    const SEED: &[u8] = b"shared-noise-handshake-hash";

    #[test]
    fn enables_only_when_both_ends_and_a_key_agree() {
        let obfs = PeerConnObfs::new();

        // Peer on an old build: no feature advertised -> stays legacy.
        obfs.negotiate(true, &[], Some(SEED));
        assert!(!obfs.is_enabled());
        assert_eq!(obfs.key(), None);

        // Local node opted out (e.g. secure mode off) -> stays legacy even if
        // the peer supports it.
        obfs.negotiate(false, &[FEATURE.to_owned()], Some(SEED));
        assert!(!obfs.is_enabled());

        // No per-link key (legacy handshake, no Noise hash) -> stays legacy.
        obfs.negotiate(true, &[FEATURE.to_owned()], None);
        assert!(!obfs.is_enabled());
        obfs.negotiate(true, &[FEATURE.to_owned()], Some(&[]));
        assert!(!obfs.is_enabled());

        // Both ends agree and a key seed is present -> obfuscation on.
        obfs.negotiate(true, &[FEATURE.to_owned()], Some(SEED));
        assert!(obfs.is_enabled());
        assert!(obfs.key().is_some());

        // Re-negotiating to a disabled outcome clears the key.
        obfs.negotiate(true, &[], Some(SEED));
        assert!(!obfs.is_enabled());
        assert_eq!(obfs.key(), None);
    }

    #[test]
    fn both_ends_derive_the_same_key_from_the_shared_seed() {
        let a = PeerConnObfs::new();
        let b = PeerConnObfs::new();
        a.negotiate(true, &[FEATURE.to_owned()], Some(SEED));
        b.negotiate(true, &[FEATURE.to_owned()], Some(SEED));
        assert_eq!(a.key(), b.key());
        assert!(a.key().is_some());

        // A different handshake hash yields a different key.
        let c = PeerConnObfs::new();
        c.negotiate(true, &[FEATURE.to_owned()], Some(b"another-hash"));
        assert_ne!(a.key(), c.key());
    }
}
