//! Per-connection traffic obfuscation (opt-in, negotiated).
//!
//! The steady-state EasyTier frame has several cleartext, fixed-layout fields
//! (the peer-manager header, and — in secure mode — an incrementing nonce
//! counter) plus unencrypted ping/pong bodies that make it easy to
//! fingerprint. This filter sits outermost on the peer-connection chain (last
//! on send, first on receive) and wraps the whole transport payload in a
//! reversible keyed transform, so two cooperating nodes produce a byte stream
//! that, after the transport header, looks like uniform random bytes of a
//! padding-varied length.
//!
//! Wire format of an obfuscated frame's transport payload:
//! `mask(peer-manager header .. AEAD tail || random pad || pad_len) || nonce`,
//! where `mask` is a per-packet keystream keyed by the per-link obfuscation key
//! and the cleartext `nonce`. The transport header (UDP/TCP), added below this
//! filter, is not touched. This masks the peer-manager header and the nonce
//! counter, hides ping/pong contents, and (for small packets) spreads sizes.
//!
//! It is strictly negotiated: a link obfuscates only when BOTH ends advertise
//! [`FEATURE`] during the Noise handshake. A peer on an older build, or one
//! that cannot be updated (e.g. an iOS/macOS device), never advertises the
//! feature, so that link transparently keeps the legacy wire format. Because
//! negotiation is per hop, a mesh can mix obfuscated and legacy links freely.
//!
//! This is obfuscation, not an extra security layer: confidentiality and
//! integrity still come from the inner secure-datagram AEAD. Handshake packets
//! are never obfuscated, since they are exchanged before both ends enable it.

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng, thread_rng};
use sha2::{Digest, Sha256};

use crate::packet::{PacketType, ZCPacket};
use crate::tunnel::{SinkItem, StreamItem, filter::TunnelFilter};

/// Feature string advertised in the handshake. Present only when the local
/// node both runs secure mode and supports obfuscation, so observing it on a
/// link implies mutual agreement.
pub(super) const FEATURE: &str = "obfs-v1";

/// Domain separator so the obfuscation key can never collide with any other
/// key derived from the same handshake material.
const KEY_DOMAIN: &[u8] = b"easytier-peerconn-obfs-v1";

/// Domain separator for the per-packet keystream seed.
const STREAM_DOMAIN: &[u8] = b"easytier-peerconn-obfs-v1-stream";

/// Per-packet random nonce, in clear at the tail of the obfuscated frame.
/// 12 bytes keeps the nonce-reuse horizon (~2^48 packets per link) far beyond
/// any real link lifetime while costing almost nothing against the MTU.
const NONCE_LEN: usize = 12;

/// Upper bound on random padding. Fits the 1-byte length marker.
const MAX_PAD: usize = 255;

/// Only packets smaller than this are padded, and never past it. Keeps the
/// distinctive small control/ping/handshake packets from standing out by size,
/// while leaving near-MTU data packets with just the fixed nonce + marker
/// overhead so they do not risk fragmentation.
const PAD_CEIL: usize = 1024;

/// Fixed per-packet overhead: the cleartext nonce plus the 1-byte padding
/// length marker (the marker is inside the masked region).
const FIXED_OVERHEAD: usize = NONCE_LEN + 1;

#[derive(Clone, Default)]
pub(super) struct PeerConnObfs {
    inner: Arc<PeerConnObfsInner>,
}

#[derive(Default)]
struct PeerConnObfsInner {
    // Presence of a key is the single source of truth for "obfuscation is on".
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
        let key = match key_seed {
            Some(seed) if local_enabled && remote_supports && !seed.is_empty() => {
                Some(Arc::new(derive_key(seed)))
            }
            _ => None,
        };
        self.inner.key.store(key);
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

/// XOR `data` with a per-packet keystream derived from `key` and `nonce`.
///
/// The keystream is a ChaCha-based CSPRNG (the one behind `StdRng`) seeded by
/// `SHA256(domain || key || nonce)`, so without `key` the mask is
/// unpredictable, and both ends — running the same build — reproduce it from
/// the cleartext `nonce`. This is an obfuscation mask, not an additional
/// authenticated cipher; confidentiality and integrity still come from the
/// inner secure-datagram AEAD.
fn apply_keystream(key: &[u8; 32], nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    let mut hasher = Sha256::new();
    hasher.update(STREAM_DOMAIN);
    hasher.update(key);
    hasher.update(nonce);
    let seed: [u8; 32] = hasher.finalize().into();

    let mut rng = StdRng::from_seed(seed);
    // Generate the keystream in blocks to avoid a per-packet heap allocation.
    let mut block = [0u8; 256];
    for chunk in data.chunks_mut(block.len()) {
        rng.fill_bytes(&mut block[..chunk.len()]);
        for (b, k) in chunk.iter_mut().zip(block.iter()) {
            *b ^= *k;
        }
    }
}

/// Handshake-class packets must never be obfuscated. They are exchanged
/// before both ends have obfuscation on, and — because the outbound sink is
/// asynchronous — one can still be in the send queue when this side flips
/// obfuscation on at the end of its own handshake. The peer parses them with
/// the legacy format, so wrapping them would break the connection before it is
/// established. By the time steady-state traffic (data, ping, control) flows,
/// both ends are enabled, so skipping only these types is safe.
fn is_bootstrap_packet(pkt: &ZCPacket) -> bool {
    let Some(hdr) = pkt.peer_manager_header() else {
        return true;
    };
    let t = hdr.packet_type;
    t == PacketType::NoiseHandshakeMsg1 as u8
        || t == PacketType::NoiseHandshakeMsg2 as u8
        || t == PacketType::NoiseHandshakeMsg3 as u8
        || t == PacketType::HandShake as u8
        || t == PacketType::RelayHandshake as u8
        || t == PacketType::RelayHandshakeAck as u8
}

fn choose_pad_len(payload_len: usize) -> usize {
    if payload_len >= PAD_CEIL {
        return 0;
    }
    let room = MAX_PAD.min(PAD_CEIL - payload_len);
    thread_rng().gen_range(0..=room)
}

impl PeerConnObfs {
    /// Wrap the transport payload of `pkt` in place:
    /// `mask(PM-header .. tail || pad || pad_len) || nonce`.
    /// The transport header (added below this filter) is untouched.
    fn wrap(&self, key: &[u8; 32], pkt: &mut crate::packet::ZCPacket) {
        let start = pkt
            .packet_type()
            .get_packet_offsets()
            .peer_manager_header_offset;
        let buf = pkt.mut_inner();
        if buf.len() < start {
            return;
        }
        let payload_len = buf.len() - start;
        let pad_len = choose_pad_len(payload_len);

        // Append `pad_len` random bytes then the 1-byte length marker.
        let mut trailer = vec![0u8; pad_len + 1];
        thread_rng().fill_bytes(&mut trailer[..pad_len]);
        trailer[pad_len] = pad_len as u8;
        buf.extend_from_slice(&trailer);

        // Mask everything from the peer-manager header to the length marker.
        let mut nonce = [0u8; NONCE_LEN];
        thread_rng().fill_bytes(&mut nonce);
        apply_keystream(key, &nonce, &mut buf[start..]);

        // The nonce rides in clear at the very end.
        buf.extend_from_slice(&nonce);
    }

    /// Reverse [`wrap`](Self::wrap), restoring the exact original transport
    /// payload. Returns false if the frame is too short or malformed, in which
    /// case the caller drops it.
    fn unwrap(&self, key: &[u8; 32], pkt: &mut crate::packet::ZCPacket) -> bool {
        let start = pkt
            .packet_type()
            .get_packet_offsets()
            .peer_manager_header_offset;
        let buf = pkt.mut_inner();
        let total = buf.len();
        if total < start + FIXED_OVERHEAD {
            return false;
        }

        let region_end = total - NONCE_LEN;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&buf[region_end..total]);
        apply_keystream(key, &nonce, &mut buf[start..region_end]);

        let pad_len = buf[region_end - 1] as usize;
        if region_end - start < 1 + pad_len {
            return false;
        }
        buf.truncate(region_end - 1 - pad_len);
        true
    }
}

impl TunnelFilter for PeerConnObfs {
    type FilterOutput = ();

    fn before_send(&self, mut data: SinkItem) -> Option<SinkItem> {
        if let Some(key) = self.inner.key.load().as_deref()
            && !is_bootstrap_packet(&data)
        {
            self.wrap(key, &mut data);
        }
        Some(data)
    }

    fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
        let Ok(mut pkt) = data else {
            return Some(data);
        };
        if let Some(key) = self.inner.key.load().as_deref()
            && !self.unwrap(key, &mut pkt)
        {
            // A peer that negotiated obfuscation must send wrapped frames;
            // anything we cannot unwrap is corrupt or spoofed, so drop it.
            return None;
        }
        Some(Ok(pkt))
    }

    fn filter_output(&self) {}
}

#[cfg(test)]
mod tests {
    use super::{FEATURE, FIXED_OVERHEAD, PeerConnObfs};
    use crate::{
        packet::{PacketType, ZCPacket, ZCPacketType},
        tunnel::filter::TunnelFilter,
    };

    const SEED: &[u8] = b"shared-noise-handshake-hash";

    fn enabled_pair() -> (PeerConnObfs, PeerConnObfs) {
        let a = PeerConnObfs::new();
        let b = PeerConnObfs::new();
        a.negotiate(true, &[FEATURE.to_owned()], Some(SEED));
        b.negotiate(true, &[FEATURE.to_owned()], Some(SEED));
        (a, b)
    }

    fn data_packet(payload: &[u8]) -> ZCPacket {
        let mut pkt = ZCPacket::new_with_payload(payload);
        pkt.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        pkt
    }

    #[test]
    fn enables_only_when_both_ends_and_a_key_agree() {
        let obfs = PeerConnObfs::new();

        // Peer on an old build: no feature advertised -> stays legacy.
        obfs.negotiate(true, &[], Some(SEED));
        assert!(obfs.key().is_none());
        assert_eq!(obfs.key(), None);

        // Local node opted out (e.g. secure mode off) -> stays legacy even if
        // the peer supports it.
        obfs.negotiate(false, &[FEATURE.to_owned()], Some(SEED));
        assert!(obfs.key().is_none());

        // No per-link key (legacy handshake, no Noise hash) -> stays legacy.
        obfs.negotiate(true, &[FEATURE.to_owned()], None);
        assert!(obfs.key().is_none());
        obfs.negotiate(true, &[FEATURE.to_owned()], Some(&[]));
        assert!(obfs.key().is_none());

        // Both ends agree and a key seed is present -> obfuscation on.
        obfs.negotiate(true, &[FEATURE.to_owned()], Some(SEED));
        assert!(obfs.key().is_some());
        assert!(obfs.key().is_some());

        // Re-negotiating to a disabled outcome clears the key.
        obfs.negotiate(true, &[], Some(SEED));
        assert!(obfs.key().is_none());
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

    #[test]
    fn wrap_unwrap_round_trips_through_the_wire() {
        let (a, b) = enabled_pair();

        for payload in [
            b"x".as_slice(),
            b"a short control-ish payload".as_slice(),
            &[0x5au8; 1300], // near-MTU data packet
        ] {
            let original = data_packet(payload);
            let expected_tunnel_payload = original.tunnel_payload().to_vec();

            let sent = a.before_send(original).unwrap();
            // The obfuscated frame is larger and no longer exposes the
            // cleartext peer-manager header.
            assert!(sent.buf_len() > expected_tunnel_payload.len() + FIXED_OVERHEAD);
            assert_ne!(sent.tunnel_payload(), expected_tunnel_payload.as_slice());

            // The raw tunnel would serialize it as a UDP frame; mimic that.
            let on_wire = sent.convert_type(ZCPacketType::UDP);
            let received = b.after_received(Ok(on_wire)).unwrap().unwrap();
            assert_eq!(received.tunnel_payload(), expected_tunnel_payload.as_slice());
            assert_eq!(
                received.peer_manager_header().unwrap().packet_type,
                PacketType::Data as u8
            );
            assert_eq!(received.payload(), payload);
        }
    }

    #[test]
    fn disabled_obfs_is_a_passthrough() {
        let obfs = PeerConnObfs::new();
        let original = data_packet(b"legacy peer, no obfuscation");
        let expected = original.clone().into_bytes();
        let sent = obfs.before_send(original).unwrap();
        assert_eq!(sent.into_bytes(), expected);
    }

    #[test]
    fn a_legacy_peers_frame_is_rejected_when_we_expect_obfuscation() {
        let (_, b) = enabled_pair();
        // An unwrapped (legacy) frame is far too short to carry a trailer and
        // must be dropped rather than mis-parsed.
        let legacy = data_packet(b"hi").convert_type(ZCPacketType::UDP);
        assert!(b.after_received(Ok(legacy)).is_none());
    }

    #[test]
    fn handshake_packets_are_never_obfuscated() {
        let (a, _b) = enabled_pair();
        for ty in [
            PacketType::NoiseHandshakeMsg1,
            PacketType::NoiseHandshakeMsg2,
            PacketType::NoiseHandshakeMsg3,
            PacketType::HandShake,
        ] {
            let mut pkt = ZCPacket::new_with_payload(b"handshake body");
            pkt.fill_peer_manager_hdr(1, 2, ty as u8);
            let expected = pkt.clone().into_bytes();
            let sent = a.before_send(pkt).unwrap();
            assert_eq!(
                sent.into_bytes(),
                expected,
                "{ty:?} must pass through unobfuscated during bootstrap"
            );
        }
    }

    #[test]
    fn padding_spreads_small_packet_sizes() {
        let (a, _) = enabled_pair();
        let mut sizes = std::collections::HashSet::new();
        for _ in 0..200 {
            let sent = a.before_send(data_packet(b"ping")).unwrap();
            sizes.insert(sent.buf_len());
        }
        assert!(sizes.len() > 1, "small packets were not padded: {sizes:?}");
    }
}
