//! Dictionary serializer/deserializer for ZeroTier NetworkConfig wire format.
//!
//! ZeroTier encodes dictionaries as newline-delimited `key=value` pairs.
//! Values may contain binary data; reserved bytes are escaped so the serialized
//! form remains a valid C string in upstream zerotier-one.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// A single dictionary entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictEntry {
    key: String,
    value: Vec<u8>,
}

impl DictEntry {
    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn value_as_text(&self) -> Option<&str> {
        core::str::from_utf8(&self.value).ok()
    }
}

/// A ZeroTier dictionary: ordered collection of key/value entries.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Dictionary {
    entries: Vec<DictEntry>,
}

/// Format a u64 as lowercase hex without 0x prefix.
fn format_hex(value: u64) -> String {
    alloc::format!("{:x}", value)
}

/// Error type for dictionary deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DictionaryError {
    /// Key contained invalid UTF-8.
    InvalidKey,
    /// Entry did not contain `=` before the line terminator or EOF.
    MissingEquals,
}

impl core::fmt::Display for DictionaryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "dictionary key is not valid UTF-8"),
            Self::MissingEquals => write!(f, "dictionary entry is missing '=' separator"),
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

    /// Add a text entry.
    pub fn add_text(&mut self, key: &str, value: &str) {
        self.entries.push(DictEntry {
            key: String::from(key),
            value: value.as_bytes().to_vec(),
        });
    }

    /// Add a text entry with a u64 value formatted as lowercase hex (no 0x prefix).
    pub fn add_hex(&mut self, key: &str, value: u64) {
        self.add_text(key, &format_hex(value));
    }

    /// Add an integer entry using upstream ZeroTier's lowercase-hex encoding.
    pub fn add_int(&mut self, key: &str, value: u64) {
        self.add_hex(key, value);
    }

    /// Add a binary entry.
    pub fn add_binary(&mut self, key: &str, data: Vec<u8>) {
        self.entries.push(DictEntry {
            key: String::from(key),
            value: data,
        });
    }

    /// Serialize the dictionary to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for (index, entry) in self.entries.iter().enumerate() {
            if index > 0 {
                buf.push(b'\n');
            }
            buf.extend_from_slice(entry.key.as_bytes());
            buf.push(b'=');
            for &byte in &entry.value {
                match byte {
                    0 => buf.extend_from_slice(br"\0"),
                    b'\r' => buf.extend_from_slice(br"\r"),
                    b'\n' => buf.extend_from_slice(br"\n"),
                    b'\\' => buf.extend_from_slice(br"\\"),
                    b'=' => buf.extend_from_slice(br"\e"),
                    _ => buf.push(byte),
                }
            }
        }
        buf
    }

    /// Deserialize a dictionary from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, DictionaryError> {
        let mut entries = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            while pos < data.len() && matches!(data[pos], b'\r' | b'\n') {
                pos += 1;
            }
            if pos >= data.len() {
                break;
            }

            let key_start = pos;
            while pos < data.len() && !matches!(data[pos], b'=' | b'\r' | b'\n') {
                pos += 1;
            }
            if pos >= data.len() || data[pos] != b'=' {
                return Err(DictionaryError::MissingEquals);
            }
            let key = core::str::from_utf8(&data[key_start..pos])
                .map_err(|_| DictionaryError::InvalidKey)?;
            pos += 1;

            let mut value = Vec::new();
            let mut escape = false;
            while pos < data.len() {
                let byte = data[pos];
                if escape {
                    escape = false;
                    match byte {
                        b'r' => value.push(b'\r'),
                        b'n' => value.push(b'\n'),
                        b'0' => value.push(0),
                        b'e' => value.push(b'='),
                        _ => value.push(byte),
                    }
                    pos += 1;
                    continue;
                }

                match byte {
                    b'\\' => {
                        escape = true;
                        pos += 1;
                    }
                    b'\r' | b'\n' => break,
                    _ => {
                        value.push(byte);
                        pos += 1;
                    }
                }
            }

            entries.push(DictEntry {
                key: String::from(key),
                value,
            });

            if pos < data.len() {
                if data[pos] == b'\r' {
                    pos += 1;
                    if pos < data.len() && data[pos] == b'\n' {
                        pos += 1;
                    }
                } else {
                    pos += 1;
                }
            }
        }

        Ok(Dictionary { entries })
    }

    /// Get a text entry value by key.
    pub fn get_text(&self, key: &str) -> Option<&str> {
        for entry in &self.entries {
            if entry.key == key {
                return entry.value_as_text();
            }
        }
        None
    }

    /// Get a binary entry data by key.
    pub fn get_binary(&self, key: &str) -> Option<&[u8]> {
        for entry in &self.entries {
            if entry.key == key {
                return Some(entry.value());
            }
        }
        None
    }

    /// Get a lowercase-hex integer value by key.
    pub fn get_hex_u64(&self, key: &str) -> Option<u64> {
        u64::from_str_radix(self.get_text(key)?, 16).ok()
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
        dict.add_binary("C", vec![0x01, 0x02, 0x00, 0x0a, 0x0d, b'=', b'\\', 0xff]);
        dict.add_binary("R", vec![0x01, 0x00]);

        let bytes = dict.serialize();
        let parsed = Dictionary::deserialize(&bytes).unwrap();

        assert_eq!(
            parsed.get_binary("C"),
            Some(&[0x01, 0x02, 0x00, 0x0a, 0x0d, b'=', b'\\', 0xff][..])
        );
        assert_eq!(parsed.get_binary("R"), Some(&[0x01, 0x00][..]));
    }

    #[test]
    fn mixed_text_and_binary_roundtrip() {
        let mut dict = Dictionary::new();
        dict.add_text("nwid", "ff00001234560001");
        dict.add_binary("C", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        dict.add_text("mtu", "af0");
        dict.add_binary("R", vec![0x01, 0x00]);
        dict.add_text("n", "test");

        let bytes = dict.serialize();
        let parsed = Dictionary::deserialize(&bytes).unwrap();

        assert_eq!(parsed.get_text("nwid"), Some("ff00001234560001"));
        assert_eq!(parsed.get_binary("C"), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
        assert_eq!(parsed.get_text("mtu"), Some("af0"));
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
        assert_eq!(parsed.get_text("mtu"), Some("af0"));
        assert_eq!(parsed.get_hex_u64("mtu"), Some(2800));
    }

    #[test]
    fn binary_entry_with_empty_data() {
        let mut dict = Dictionary::new();
        dict.add_binary("E", vec![]);

        let bytes = dict.serialize();
        assert_eq!(bytes, b"E=");

        let parsed = Dictionary::deserialize(&bytes).unwrap();
        assert_eq!(parsed.get_binary("E"), Some(&[][..]));
    }

    #[test]
    fn text_wire_format() {
        let mut dict = Dictionary::new();
        dict.add_text("k", "v");

        let bytes = dict.serialize();
        assert_eq!(bytes, b"k=v");
    }

    #[test]
    fn binary_wire_format_escapes_reserved_bytes() {
        let mut dict = Dictionary::new();
        dict.add_binary("B", vec![0x00, b'\r', b'\n', b'\\', b'=', b'A']);

        let bytes = dict.serialize();
        assert_eq!(bytes, b"B=\\0\\r\\n\\\\\\eA");

        let parsed = Dictionary::deserialize(&bytes).unwrap();
        assert_eq!(
            parsed.get_binary("B"),
            Some(&[0x00, b'\r', b'\n', b'\\', b'=', b'A'][..])
        );
    }
}
