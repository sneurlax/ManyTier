use std::path::{Component, Path, PathBuf};

use tokio::fs;
use zerotier_node::traits::Storage;

/// Native filesystem-based storage.
pub struct NativeStorage {
    base_dir: PathBuf,
}

impl NativeStorage {
    pub fn new(base_dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    pub fn resolve(&self, key: &str) -> std::io::Result<PathBuf> {
        let key_path = Path::new(key);
        if key_path.as_os_str().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage key cannot be empty",
            ));
        }

        for component in key_path.components() {
            match component {
                Component::Normal(_) => {}
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("unsupported storage key: {key}"),
                    ));
                }
            }
        }

        Ok(self.base_dir.join(key_path))
    }
}

fn collect_keys(dir: &Path, root: &Path, keys: &mut Vec<String>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_keys(&path, root, keys)?;
        } else if entry.file_type()?.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| std::io::Error::other("failed to relativize storage key"))?;
            keys.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }

    Ok(())
}

impl Storage for NativeStorage {
    type Error = std::io::Error;

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        let path = self.resolve(key)?;
        match fs::read(path).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn store(&self, key: &str, value: &[u8]) -> Result<(), Self::Error> {
        let path = self.resolve(key)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(path, value).await
    }

    async fn delete(&self, key: &str) -> Result<(), Self::Error> {
        let path = self.resolve(key)?;
        match fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, Self::Error> {
        let mut keys = Vec::new();
        collect_keys(&self.base_dir, &self.base_dir, &mut keys)?;
        keys.retain(|key| key.starts_with(prefix));
        keys.sort();
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::NativeStorage;
    use zerotier_node::traits::Storage;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "manytier-native-storage-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn store_load_list_and_delete_roundtrip() {
        let dir = temp_dir("roundtrip");
        let storage = NativeStorage::new(&dir).unwrap();

        storage
            .store("identity/secret.txt", b"hello")
            .await
            .unwrap();

        assert_eq!(
            storage.load("identity/secret.txt").await.unwrap(),
            Some(b"hello".to_vec())
        );
        assert_eq!(
            storage.list_keys("identity").await.unwrap(),
            vec!["identity/secret.txt".to_string()]
        );

        storage.delete("identity/secret.txt").await.unwrap();
        assert_eq!(storage.load("identity/secret.txt").await.unwrap(), None);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn rejects_parent_dir_keys() {
        let dir = temp_dir("invalid");
        let storage = NativeStorage::new(&dir).unwrap();

        let error = storage.store("../escape", b"nope").await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

        std::fs::remove_dir_all(dir).unwrap();
    }
}
