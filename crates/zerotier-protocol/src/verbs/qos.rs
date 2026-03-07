extern crate alloc;

use crate::error::ProtocolError;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosRecord {
    pub packet_id: u64,
    pub sojourn_time: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosMeasurementPayload {
    pub records: Vec<QosRecord>,
}

impl QosMeasurementPayload {
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let mut offset = 0;
        for rec in &self.records {
            buf[offset..offset + 8].copy_from_slice(&rec.packet_id.to_be_bytes());
            offset += 8;
            buf[offset..offset + 2].copy_from_slice(&rec.sojourn_time.to_be_bytes());
            offset += 2;
        }
        offset
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() % 10 != 0 {
            return Err(ProtocolError::InvalidPacket);
        }
        let count = data.len() / 10;
        let mut records = Vec::with_capacity(count);
        let mut offset = 0;
        for _ in 0..count {
            let packet_id = u64::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            offset += 8;
            let sojourn_time = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            records.push(QosRecord {
                packet_id,
                sojourn_time,
            });
        }
        Ok(QosMeasurementPayload { records })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn qos_roundtrip_multiple() {
        let payload = QosMeasurementPayload {
            records: vec![
                QosRecord {
                    packet_id: 0x0102030405060708,
                    sojourn_time: 1500,
                },
                QosRecord {
                    packet_id: 0xFFFFFFFFFFFFFFFF,
                    sojourn_time: 0,
                },
                QosRecord {
                    packet_id: 1,
                    sojourn_time: 65535,
                },
            ],
        };
        let mut buf = [0u8; 256];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 30);
        let parsed = QosMeasurementPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn qos_empty() {
        let payload = QosMeasurementPayload { records: vec![] };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 0);
        let parsed = QosMeasurementPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.records.len(), 0);
    }

    #[test]
    fn qos_invalid_length() {
        assert!(QosMeasurementPayload::deserialize(&[0; 7]).is_err());
        assert!(QosMeasurementPayload::deserialize(&[0; 11]).is_err());
    }
}
