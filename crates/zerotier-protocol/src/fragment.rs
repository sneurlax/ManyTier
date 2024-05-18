//! Fragment reassembly buffer for ZeroTier V1 fragmented packets.
//!
//! ZeroTier fragments large packets into up to 7 pieces. The reassembly buffer
//! collects fragments keyed by packet ID and returns the complete packet once
//! all pieces arrive. Stale entries are evicted after a configurable timeout.

extern crate alloc;

use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::constants::ZT_MAX_PACKET_FRAGMENTS;

struct FragmentSlot {
    fragments: [Option<Vec<u8>>; ZT_MAX_PACKET_FRAGMENTS],
    total_expected: u8,
    received_count: u8,
    created_at: u64,
}

/// Reassembly buffer that collects packet fragments and returns complete packets.
pub struct ReassemblyBuffer {
    pending: HashMap<u64, FragmentSlot>,
    max_pending: usize,
}

impl ReassemblyBuffer {
    /// Create a new reassembly buffer with the given maximum pending entries.
    pub fn new(max_pending: usize) -> Self {
        ReassemblyBuffer {
            pending: HashMap::new(),
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
}
