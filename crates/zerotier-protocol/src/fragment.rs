//! Fragment reassembly buffer for ZeroTier V1 fragmented packets.
//!
//! ZeroTier fragments large packets into up to 7 pieces. The reassembly buffer
//! collects fragments keyed by packet ID and returns the complete packet once
//! all pieces arrive. Stale entries are evicted after a configurable timeout.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::constants::{FRAGMENT_INDICATOR, ZT_MAX_PACKET_FRAGMENTS, ZT_PROTO_MIN_FRAGMENT_LENGTH};
use crate::header::PacketHeader;

struct FragmentSlot {
    fragments: [Option<Vec<u8>>; ZT_MAX_PACKET_FRAGMENTS],
    total_expected: u8,
    received_count: u8,
    created_at: u64,
}

/// Reassembly buffer that collects packet fragments and returns complete packets.
pub struct ReassemblyBuffer {
    pending: BTreeMap<u64, FragmentSlot>,
    max_pending: usize,
}

impl ReassemblyBuffer {
    /// Create a new reassembly buffer with the given maximum pending entries.
    pub fn new(max_pending: usize) -> Self {
        ReassemblyBuffer {
            pending: BTreeMap::new(),
            max_pending,
        }
    }

    /// Insert a fragment. Returns the reassembled packet if all fragments have arrived.
    ///
    /// `packet_id`: identifies which packet this fragment belongs to.
    /// `fragment_number`: 0-based index of this fragment.
    /// `total_fragments`: total number of fragments for this packet.
    /// `data`: the fragment payload bytes.
    /// `now_ms`: current monotonic time in milliseconds.
    pub fn insert(
        &mut self,
        packet_id: u64,
        fragment_number: u8,
        total_fragments: u8,
        data: Vec<u8>,
        now_ms: u64,
    ) -> Option<Vec<u8>> {
        if total_fragments == 0
            || total_fragments as usize > ZT_MAX_PACKET_FRAGMENTS
            || fragment_number >= total_fragments
        {
            return None;
        }

        // Evict oldest if at capacity
        if !self.pending.contains_key(&packet_id) && self.pending.len() >= self.max_pending {
            let oldest_id = self
                .pending
                .iter()
                .min_by_key(|(_, slot)| slot.created_at)
                .map(|(&id, _)| id);
            if let Some(id) = oldest_id {
                self.pending.remove(&id);
            }
        }

        let slot = self.pending.entry(packet_id).or_insert_with(|| {
            const NONE: Option<Vec<u8>> = None;
            FragmentSlot {
                fragments: [NONE; ZT_MAX_PACKET_FRAGMENTS],
                total_expected: total_fragments,
                received_count: 0,
                created_at: now_ms,
            }
        });

        let idx = fragment_number as usize;
        if slot.fragments[idx].is_none() {
            slot.fragments[idx] = Some(data);
            slot.received_count += 1;
        }

        if slot.received_count >= slot.total_expected {
            let slot = self.pending.remove(&packet_id).unwrap();
            let mut assembled = Vec::new();
            for i in 0..slot.total_expected as usize {
                if let Some(frag_data) = &slot.fragments[i] {
                    assembled.extend_from_slice(frag_data);
                }
            }
            Some(assembled)
        } else {
            None
        }
    }

    /// Evict stale entries older than `timeout_ms`.
    pub fn evict_stale(&mut self, now_ms: u64, timeout_ms: u64) {
        self.pending
            .retain(|_, slot| now_ms.saturating_sub(slot.created_at) < timeout_ms);
    }
}

/// Split a full ZeroTier packet into fragment packets that fit within `mtu`.
///
/// The fragment payloads are contiguous slices of the original packet bytes, so
/// successful reassembly reconstructs the original packet verbatim.
pub fn fragment_packet(packet: &[u8], mtu: usize) -> Option<Vec<Vec<u8>>> {
    if packet.len() <= mtu {
        return Some(alloc::vec![packet.to_vec()]);
    }
    if mtu <= ZT_PROTO_MIN_FRAGMENT_LENGTH {
        return None;
    }

    let header = PacketHeader::from_bytes(packet)?;
    let max_payload = mtu - ZT_PROTO_MIN_FRAGMENT_LENGTH;
    if max_payload == 0 {
        return None;
    }

    let total_fragments = (packet.len() + max_payload - 1) / max_payload;
    if total_fragments == 0 || total_fragments > ZT_MAX_PACKET_FRAGMENTS {
        return None;
    }

    let packet_id = header.packet_id();
    let dest = header.dest_address();
    let hops = header.hops();

    let mut fragments = Vec::with_capacity(total_fragments);
    for fragment_number in 0..total_fragments {
        let start = fragment_number * max_payload;
        let end = core::cmp::min(start + max_payload, packet.len());
        let payload = &packet[start..end];

        let mut fragment = Vec::with_capacity(ZT_PROTO_MIN_FRAGMENT_LENGTH + payload.len());
        fragment.extend_from_slice(&packet_id.to_be_bytes());
        fragment.extend_from_slice(&dest);
        fragment.push(FRAGMENT_INDICATOR);
        fragment.push(((total_fragments as u8) << 4) | fragment_number as u8);
        fragment.push(hops);
        fragment.extend_from_slice(payload);
        fragments.push(fragment);
    }

    Some(fragments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn single_fragment_returns_immediately() {
        let mut buf = ReassemblyBuffer::new(256);
        let result = buf.insert(1, 0, 1, vec![0x01, 0x02, 0x03], 100);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn two_fragments_in_order() {
        let mut buf = ReassemblyBuffer::new(256);
        assert!(buf.insert(1, 0, 2, vec![0x01, 0x02], 100).is_none());
        let result = buf.insert(1, 1, 2, vec![0x03, 0x04], 100);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn two_fragments_out_of_order() {
        let mut buf = ReassemblyBuffer::new(256);
        assert!(buf.insert(1, 1, 2, vec![0x03, 0x04], 100).is_none());
        let result = buf.insert(1, 0, 2, vec![0x01, 0x02], 100);
        assert!(result.is_some());
        // Should be reassembled in order regardless of arrival order
        assert_eq!(result.unwrap(), vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn returns_none_until_all_arrive() {
        let mut buf = ReassemblyBuffer::new(256);
        assert!(buf.insert(1, 0, 3, vec![0x01], 100).is_none());
        assert!(buf.insert(1, 2, 3, vec![0x03], 100).is_none());
        let result = buf.insert(1, 1, 3, vec![0x02], 100);
        assert_eq!(result.unwrap(), vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn duplicate_fragment_ignored() {
        let mut buf = ReassemblyBuffer::new(256);
        assert!(buf.insert(1, 0, 2, vec![0x01], 100).is_none());
        // Send fragment 0 again -- should be ignored
        assert!(buf.insert(1, 0, 2, vec![0xFF], 100).is_none());
        let result = buf.insert(1, 1, 2, vec![0x02], 100);
        // Should use the first fragment 0
        assert_eq!(result.unwrap(), vec![0x01, 0x02]);
    }

    #[test]
    fn evict_stale_entries() {
        let mut buf = ReassemblyBuffer::new(256);
        buf.insert(1, 0, 2, vec![0x01], 100);
        buf.insert(2, 0, 2, vec![0x02], 200);
        buf.evict_stale(350, 200);
        // packet 1 (created at 100) should be evicted (350 - 100 = 250 >= 200)
        // packet 2 (created at 200) should remain (350 - 200 = 150 < 200)
        assert!(buf.insert(1, 1, 2, vec![0x03], 350).is_none()); // slot gone, starts fresh
        assert!(buf.insert(2, 1, 2, vec![0x04], 350).is_some()); // completes
    }

    #[test]
    fn max_pending_evicts_oldest() {
        let mut buf = ReassemblyBuffer::new(2);
        buf.insert(1, 0, 2, vec![0x01], 100);
        buf.insert(2, 0, 2, vec![0x02], 200);
        // Buffer is full (2 entries). Inserting new packet evicts oldest (packet 1)
        buf.insert(3, 0, 2, vec![0x03], 300);
        // Packet 1 was evicted, packet 2 and 3 remain
        // Complete packet 3
        assert!(buf.insert(3, 1, 2, vec![0x04], 300).is_some());
        // Packet 2 should still work
        assert!(buf.insert(2, 1, 2, vec![0x05], 300).is_some());
    }

    #[test]
    fn rejects_invalid_fragment_number() {
        let mut buf = ReassemblyBuffer::new(256);
        // fragment_number >= total_fragments
        assert!(buf.insert(1, 2, 2, vec![0x01], 100).is_none());
    }

    #[test]
    fn rejects_zero_total() {
        let mut buf = ReassemblyBuffer::new(256);
        assert!(buf.insert(1, 0, 0, vec![0x01], 100).is_none());
    }

    #[test]
    fn seven_fragments() {
        let mut buf = ReassemblyBuffer::new(256);
        for i in 0..6 {
            assert!(buf.insert(1, i, 7, vec![i], 100).is_none());
        }
        let result = buf.insert(1, 6, 7, vec![6], 100);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), vec![0, 1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn separate_packet_ids() {
        let mut buf = ReassemblyBuffer::new(256);
        buf.insert(1, 0, 2, vec![0x01], 100);
        buf.insert(2, 0, 2, vec![0x0A], 100);
        let r1 = buf.insert(1, 1, 2, vec![0x02], 100);
        let r2 = buf.insert(2, 1, 2, vec![0x0B], 100);
        assert_eq!(r1.unwrap(), vec![0x01, 0x02]);
        assert_eq!(r2.unwrap(), vec![0x0A, 0x0B]);
    }

    fn make_packet(payload_len: usize) -> Vec<u8> {
        let mut packet = vec![0u8; 28 + payload_len];
        packet[0..8].copy_from_slice(&0x1122334455667788u64.to_be_bytes());
        packet[8..13].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        packet[13..18].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]);
        packet[18] = 0b0000_0011; // hops=3
        packet[27] = 0x07; // EXT_FRAME
        for (i, byte) in packet[28..].iter_mut().enumerate() {
            *byte = (i & 0xff) as u8;
        }
        packet
    }

    #[test]
    fn fragment_packet_returns_original_when_under_mtu() {
        let packet = make_packet(32);
        let fragments = fragment_packet(&packet, 128).unwrap();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0], packet);
    }

    #[test]
    fn fragment_packet_splits_and_sets_headers() {
        let packet = make_packet(64);
        let fragments = fragment_packet(&packet, 40).unwrap();
        assert_eq!(fragments.len(), 4);

        for (idx, fragment) in fragments.iter().enumerate() {
            assert_eq!(&fragment[0..8], &0x1122334455667788u64.to_be_bytes());
            assert_eq!(&fragment[8..13], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
            assert_eq!(fragment[13], FRAGMENT_INDICATOR);
            assert_eq!(fragment[14] >> 4, 4);
            assert_eq!(fragment[14] & 0x0f, idx as u8);
            assert_eq!(fragment[15], 3);
            assert!(fragment.len() <= 40);
        }
    }

    #[test]
    fn fragment_packet_roundtrips_through_reassembly() {
        let packet = make_packet(96);
        let fragments = fragment_packet(&packet, 48).unwrap();
        let mut reassembly = ReassemblyBuffer::new(8);
        let mut reassembled = None;

        for fragment in fragments.into_iter().rev() {
            reassembled = reassembly.insert(
                0x1122334455667788,
                fragment[14] & 0x0f,
                fragment[14] >> 4,
                fragment[16..].to_vec(),
                100,
            );
        }

        assert_eq!(reassembled.unwrap(), packet);
    }
}
