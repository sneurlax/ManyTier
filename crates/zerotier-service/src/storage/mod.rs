//! Controller storage backend implementations.
//!
//! Three backends implementing `ControllerStorage`:
//! - `SqliteStorage` -- production SQLite backend
//! - `InMemoryStorage` -- lightweight in-memory backend for testing
//! - `FilesystemStorage` -- JSON-file-based fallback backend

pub mod filesystem;
pub mod memory;
pub mod sqlite;

pub use filesystem::FilesystemStorage;
pub use memory::InMemoryStorage;
pub use sqlite::SqliteStorage;
