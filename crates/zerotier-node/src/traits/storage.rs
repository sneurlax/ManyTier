use alloc::string::String;
use alloc::vec::Vec;

/// Persistent key-value storage abstraction.
///
/// Native implementations use the filesystem. WASM implementations
/// can use IndexedDB or localStorage.
pub trait Storage: Send + Sync {
    type Error: core::fmt::Debug + core::fmt::Display;

    /// Load a value by key. Returns None if the key does not exist.
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Store a value under the given key, overwriting any existing value.
    async fn store(&self, key: &str, value: &[u8]) -> Result<(), Self::Error>;

    /// Delete the value for the given key. No error if the key does not exist.
    async fn delete(&self, key: &str) -> Result<(), Self::Error>;

    /// List all keys with the given prefix.
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, Self::Error>;
}
