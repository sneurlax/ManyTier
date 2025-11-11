/// Internal hex encoding/decoding utilities.
///
/// Avoids adding a `hex` crate dependency -- keeps deps minimal.
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::CryptoError;

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Encode bytes to lowercase hex string.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        hex.push(HEX_CHARS[(b >> 4) as usize] as char);
        hex.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    hex
}

/// Decode hex string to bytes. Returns error if string length is odd
/// or contains non-hex characters.
pub(crate) fn decode(hex: &str) -> Result<Vec<u8>, CryptoError> {
    if hex.len() % 2 != 0 {
        return Err(CryptoError::InvalidFormat);
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let hex_bytes = hex.as_bytes();
    for i in (0..hex_bytes.len()).step_by(2) {
        let high = nibble(hex_bytes[i])?;
        let low = nibble(hex_bytes[i + 1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn nibble(c: u8) -> Result<u8, CryptoError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(CryptoError::InvalidFormat),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn encode_empty() {
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn encode_bytes() {
        assert_eq!(encode(&[0xa0, 0xb1, 0xc2]), "a0b1c2");
    }

    #[test]
    fn decode_valid() {
        assert_eq!(decode("a0b1c2").unwrap(), vec![0xa0, 0xb1, 0xc2]);
    }

    #[test]
    fn decode_uppercase() {
        assert_eq!(decode("A0B1C2").unwrap(), vec![0xa0, 0xb1, 0xc2]);
    }

    #[test]
    fn decode_odd_length() {
        assert!(decode("abc").is_err());
    }

    #[test]
    fn decode_invalid_char() {
        assert!(decode("zz").is_err());
    }

    #[test]
    fn roundtrip() {
        let bytes = [0x00, 0xff, 0x42, 0xde, 0xad];
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
    }
}
