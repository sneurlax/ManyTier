//! Dictionary serializer/deserializer for ZeroTier NetworkConfig wire format.
//!
//! The ZeroTier dictionary format encodes key-value pairs:
//! - Text entries: `key=value\n` (ASCII key, ASCII value, newline terminated)
//! - Binary entries: `key\0` + u16 BE length + raw bytes (no newline)

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// A single dictionary entry, either text or binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DictEntry {
    /// Text entry: key=value\n
    Text { key: String, value: String },
    /// Binary entry: key\0 + u16 BE length + raw bytes
    Binary { key: String, data: Vec<u8> },
}

/// A ZeroTier dictionary: ordered collection of text and binary entries.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Dictionary {
    entries: Vec<DictEntry>,
}

/// Format a u64 as lowercase hex without 0x prefix.
fn format_hex(value: u64) -> String {
    alloc::format!("{:x}", value)
}

/// Format a u64 as decimal string.
fn format_decimal(value: u64) -> String {
    alloc::format!("{}", value)
}

/// Error type for dictionary deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DictionaryError {
    /// Unexpected end of input.
    UnexpectedEof,
    /// Key contained invalid UTF-8.
    InvalidKey,
    /// Text value contained invalid UTF-8.
    InvalidValue,
    /// Binary entry length exceeds remaining data.
    BinaryLengthOverflow,
}

impl core::fmt::Display for DictionaryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of dictionary data"),
            Self::InvalidKey => write!(f, "dictionary key is not valid UTF-8"),
            Self::InvalidValue => write!(f, "dictionary text value is not valid UTF-8"),
            Self::BinaryLengthOverflow => write!(f, "binary entry length exceeds data"),
        }
    }
}

impl Dictionary {
    /// Create a new empty dictionary.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a text entry (key=value\n).
    pub fn add_text(&mut self, key: &str, value: &str) {
        self.entries.push(DictEntry::Text {
            key: String::from(key),
            value: String::from(value),
        });
    }

    /// Add a text entry with a u64 value formatted as lowercase hex (no 0x prefix).
    pub fn add_hex(&mut self, key: &str, value: u64) {
        self.add_text(key, &format_hex(value));
    }

    /// Add a text entry with a u64 value formatted as decimal.
    pub fn add_int(&mut self, key: &str, value: u64) {
        self.add_text(key, &format_decimal(value));
    }

    /// Add a binary entry (key\0 + u16 BE length + raw bytes).
    pub fn add_binary(&mut self, key: &str, data: Vec<u8>) {
        self.entries.push(DictEntry::Binary {
            key: String::from(key),
            data,
        });
    }

    /// Serialize the dictionary to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for entry in &self.entries {
            match entry {
                DictEntry::Text { key, value } => {
                    buf.extend_from_slice(key.as_bytes());
                    buf.push(b'=');
                    buf.extend_from_slice(value.as_bytes());
                    buf.push(b'\n');
                }
                DictEntry::Binary { key, data } => {
                    buf.extend_from_slice(key.as_bytes());
                    buf.push(0x00);
                    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    buf.extend_from_slice(data);
                }
            }
        }
        buf
    }

    /// Deserialize a dictionary from bytes.
    ///
    /// Parsing logic:
    /// - Scan for `=` or `\0` after key bytes to determine entry type
    /// - If `=` found: read until `\n` for text value
    /// - If `\0` found: read u16 BE length, then that many raw bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, DictionaryError> {
        let mut entries = Vec::new();
        let mut pos = 0;
        let len = data.len();

        while pos < len {
            // Find the key delimiter: '=' for text, '\0' for binary
            let key_start = pos;
            let mut delimiter = None;
            while pos < len {
                if data[pos] == b'=' {
                    delimiter = Some(b'=');
                    break;
                } else if data[pos] == 0x00 {
                    delimiter = Some(0x00);
                    break;
                }
                pos += 1;
            }

            let delim = delimiter.ok_or(DictionaryError::UnexpectedEof)?;
            let key = core::str::from_utf8(&data[key_start..pos])
                .map_err(|_| DictionaryError::InvalidKey)?;

            pos += 1; // skip delimiter

            match delim {
                b'=' => {
                    // Text entry: read until newline
                    let value_start = pos;
                    while pos < len && data[pos] != b'\n' {
                        pos += 1;
                    }
                    let value = core::str::from_utf8(&data[value_start..pos])
                        .map_err(|_| DictionaryError::InvalidValue)?;
                    entries.push(DictEntry::Text {
                        key: String::from(key),
                        value: String::from(value),
                    });
                    if pos < len {
                        pos += 1; // skip newline
                    }
                }
                0x00 => {
                    // Binary entry: u16 BE length + raw bytes
                    if pos + 2 > len {
                        return Err(DictionaryError::BinaryLengthOverflow);
                    }
                    let bin_len =
                        u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;
                    if pos + bin_len > len {
                        return Err(DictionaryError::BinaryLengthOverflow);
                    }
                    let bin_data = data[pos..pos + bin_len].to_vec();
                    entries.push(DictEntry::Binary {
                        key: String::from(key),
                        data: bin_data,
                    });
                    pos += bin_len;
                }
                _ => unreachable!(),
            }
        }

        Ok(Dictionary { entries })
    }

    /// Get a text entry value by key.
    pub fn get_text(&self, key: &str) -> Option<&str> {
        for entry in &self.entries {
            if let DictEntry::Text { key: k, value } = entry {
                if k == key {
                    return Some(value);
                }
            }
        }
        None
    }

    /// Get a binary entry data by key.
    pub fn get_binary(&self, key: &str) -> Option<&[u8]> {
        for entry in &self.entries {
            if let DictEntry::Binary { key: k, data } = entry {
                if k == key {
                    return Some(data);
                }
            }
        }
        None
    }

    /// Get all entries.
    pub fn entries(&self) -> &[DictEntry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn text_entry_roundtrip() {
        let mut dict = Dictionary::new();
        dict.add_text("nwid", "ff00001234560001");
        dict.add_text("n", "my-network");
        dict.add_text("v", "7");

        let bytes = dict.serialize();
        let parsed = Dictionary::deserialize(&bytes).unwrap();

        assert_eq!(parsed.get_text("nwid"), Some("ff00001234560001"));
        assert_eq!(parsed.get_text("n"), Some("my-network"));
        assert_eq!(parsed.get_text("v"), Some("7"));
    }

    #[test]
    fn binary_entry_roundtrip() {
        let mut dict = Dictionary::new();
        dict.add_binary("C", vec![0x01, 0x02, 0x03, 0x04, 0x05]);
        dict.add_binary("R", vec![0x01, 0x00]);

        let bytes = dict.serialize();
        let parsed = Dictionary::deserialize(&bytes).unwrap();

        assert_eq!(parsed.get_binary("C"), Some(&[0x01, 0x02, 0x03, 0x04, 0x05][..]));
        assert_eq!(parsed.get_binary("R"), Some(&[0x01, 0x00][..]));
    }

    #[test]
    fn mixed_text_and_binary_roundtrip() {
        let mut dict = Dictionary::new();
        dict.add_text("nwid", "ff00001234560001");
        dict.add_binary("C", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        dict.add_text("mtu", "2800");
        dict.add_binary("R", vec![0x01, 0x00]);
        dict.add_text("n", "test");

        let bytes = dict.serialize();
        let parsed = Dictionary::deserialize(&bytes).unwrap();

        assert_eq!(parsed.get_text("nwid"), Some("ff00001234560001"));
        assert_eq!(parsed.get_binary("C"), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
        assert_eq!(parsed.get_text("mtu"), Some("2800"));
        assert_eq!(parsed.get_binary("R"), Some(&[0x01, 0x00][..]));
        assert_eq!(parsed.get_text("n"), Some("test"));
    }

    #[test]
    fn empty_dictionary_serialize() {
        let dict = Dictionary::new();
        let bytes = dict.serialize();
        assert!(bytes.is_empty());

        let parsed = Dictionary::deserialize(&bytes).unwrap();
        assert!(parsed.entries().is_empty());
    }

    #[test]
    fn hex_and_int_helpers() {
        let mut dict = Dictionary::new();
        dict.add_hex("nwid", 0xff00001234560001);
        dict.add_int("mtu", 2800);

        let bytes = dict.serialize();
        let parsed = Dictionary::deserialize(&bytes).unwrap();

        assert_eq!(parsed.get_text("nwid"), Some("ff00001234560001"));
        assert_eq!(parsed.get_text("mtu"), Some("2800"));
    }

    #[test]
    fn binary_entry_with_empty_data() {
        let mut dict = Dictionary::new();
        dict.add_binary("E", vec![]);

        let bytes = dict.serialize();
        // key 'E' (1 byte) + \0 (1 byte) + u16 len 0 (2 bytes) = 4 bytes
        assert_eq!(bytes.len(), 4);

        let parsed = Dictionary::deserialize(&bytes).unwrap();
        assert_eq!(parsed.get_binary("E"), Some(&[][..]));
    }

    #[test]
    fn text_wire_format() {
        let mut dict = Dictionary::new();
        dict.add_text("k", "v");

        let bytes = dict.serialize();
        // k=v\n
        assert_eq!(bytes, b"k=v\n");
    }

    #[test]
    fn binary_wire_format() {
        let mut dict = Dictionary::new();
        dict.add_binary("B", vec![0xAA, 0xBB]);

        let bytes = dict.serialize();
        // B\0 + 00 02 + AA BB
        assert_eq!(bytes, &[b'B', 0x00, 0x00, 0x02, 0xAA, 0xBB]);
    }
}
