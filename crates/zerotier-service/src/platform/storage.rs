use zerotier_node::traits::Storage;

/// Native filesystem-based storage.
#[allow(unused)]
pub struct NativeStorage {
    // TODO: base directory path
}

impl Storage for NativeStorage {
    type Error = std::io::Error;

    async fn load(&self, _key: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        todo!("native storage")
    }

    async fn store(&self, _key: &str, _value: &[u8]) -> Result<(), Self::Error> {
        todo!("native storage")
    }

    async fn delete(&self, _key: &str) -> Result<(), Self::Error> {
        todo!("native storage")
    }

    async fn list_keys(&self, _prefix: &str) -> Result<Vec<String>, Self::Error> {
        todo!("native storage")
    }
}
