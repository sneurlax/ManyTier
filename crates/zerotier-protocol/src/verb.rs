// Verb enum mapping all ZeroTier V1 protocol verbs to their numeric IDs.
//
// The verb byte in a packet has upper 3 bits for flags and lower 5 bits
// for the verb ID. Use `from_byte` to parse with flag masking.

/// All ZeroTier V1 protocol verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Verb {
    Nop = 0x00,
    Hello = 0x01,
    Error = 0x02,
    Ok = 0x03,
    Whois = 0x04,
    Rendezvous = 0x05,
    Frame = 0x06,
    ExtFrame = 0x07,
    Echo = 0x08,
    MulticastLike = 0x09,
    NetworkCredentials = 0x0a,
    NetworkConfigRequest = 0x0b,
    NetworkConfig = 0x0c,
    MulticastGather = 0x0d,
    MulticastFrame = 0x0e,
    PushDirectPaths = 0x10,
    Ack = 0x12,
    QosMeasurement = 0x13,
    UserMessage = 0x14,
    RemoteTrace = 0x15,
    PathNegotiationRequest = 0x16,
}

impl Verb {
    /// Parse a verb from a raw byte, masking off the upper 3 flag bits.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b & 0x1f {
            0x00 => Some(Verb::Nop),
            0x01 => Some(Verb::Hello),
            0x02 => Some(Verb::Error),
            0x03 => Some(Verb::Ok),
            0x04 => Some(Verb::Whois),
            0x05 => Some(Verb::Rendezvous),
            0x06 => Some(Verb::Frame),
            0x07 => Some(Verb::ExtFrame),
            0x08 => Some(Verb::Echo),
            0x09 => Some(Verb::MulticastLike),
            0x0a => Some(Verb::NetworkCredentials),
            0x0b => Some(Verb::NetworkConfigRequest),
            0x0c => Some(Verb::NetworkConfig),
            0x0d => Some(Verb::MulticastGather),
            0x0e => Some(Verb::MulticastFrame),
            0x10 => Some(Verb::PushDirectPaths),
            0x12 => Some(Verb::Ack),
            0x13 => Some(Verb::QosMeasurement),
            0x14 => Some(Verb::UserMessage),
            0x15 => Some(Verb::RemoteTrace),
            0x16 => Some(Verb::PathNegotiationRequest),
            _ => None,
        }
    }

    /// Get the raw byte value of this verb.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_byte_hello() {
        assert_eq!(Verb::from_byte(0x01), Some(Verb::Hello));
    }

    #[test]
    fn from_byte_masks_flag_bits() {
        // 0x81 = 0b1000_0001 => masked to 0x01 = Hello
        assert_eq!(Verb::from_byte(0x81), Some(Verb::Hello));
        // 0xe1 = 0b1110_0001 => masked to 0x01 = Hello
        assert_eq!(Verb::from_byte(0xe1), Some(Verb::Hello));
    }

    #[test]
    fn from_byte_invalid() {
        // 0x0f is not a defined verb
        assert_eq!(Verb::from_byte(0x0f), None);
        // 0x11 is not a defined verb
        assert_eq!(Verb::from_byte(0x11), None);
        // 0x1f masked from 0xff
        assert_eq!(Verb::from_byte(0xff), None);
    }

    #[test]
    fn to_byte_roundtrip() {
        let verbs = [
            Verb::Nop,
            Verb::Hello,
            Verb::Error,
            Verb::Ok,
            Verb::Whois,
            Verb::Rendezvous,
            Verb::Frame,
            Verb::ExtFrame,
            Verb::Echo,
            Verb::MulticastLike,
            Verb::NetworkCredentials,
            Verb::NetworkConfigRequest,
            Verb::NetworkConfig,
            Verb::MulticastGather,
            Verb::MulticastFrame,
            Verb::PushDirectPaths,
            Verb::Ack,
            Verb::QosMeasurement,
            Verb::UserMessage,
            Verb::RemoteTrace,
            Verb::PathNegotiationRequest,
        ];
        for v in verbs {
            assert_eq!(Verb::from_byte(v.to_byte()), Some(v));
        }
    }

    #[test]
    fn all_known_verb_ids() {
        assert_eq!(Verb::Nop.to_byte(), 0x00);
        assert_eq!(Verb::Hello.to_byte(), 0x01);
        assert_eq!(Verb::Error.to_byte(), 0x02);
        assert_eq!(Verb::Ok.to_byte(), 0x03);
        assert_eq!(Verb::Whois.to_byte(), 0x04);
        assert_eq!(Verb::Rendezvous.to_byte(), 0x05);
        assert_eq!(Verb::Frame.to_byte(), 0x06);
        assert_eq!(Verb::ExtFrame.to_byte(), 0x07);
        assert_eq!(Verb::Echo.to_byte(), 0x08);
        assert_eq!(Verb::MulticastLike.to_byte(), 0x09);
        assert_eq!(Verb::NetworkCredentials.to_byte(), 0x0a);
        assert_eq!(Verb::NetworkConfigRequest.to_byte(), 0x0b);
        assert_eq!(Verb::NetworkConfig.to_byte(), 0x0c);
        assert_eq!(Verb::MulticastGather.to_byte(), 0x0d);
        assert_eq!(Verb::MulticastFrame.to_byte(), 0x0e);
        assert_eq!(Verb::PushDirectPaths.to_byte(), 0x10);
        assert_eq!(Verb::Ack.to_byte(), 0x12);
        assert_eq!(Verb::QosMeasurement.to_byte(), 0x13);
        assert_eq!(Verb::UserMessage.to_byte(), 0x14);
        assert_eq!(Verb::RemoteTrace.to_byte(), 0x15);
        assert_eq!(Verb::PathNegotiationRequest.to_byte(), 0x16);
    }
}
