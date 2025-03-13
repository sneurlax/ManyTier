use zerotier_node::traits::CryptoProvider;

/// Native CryptoProvider using zerotier-crypto crate functions.
///
/// This will be a real implementation (not a stub) once Plans 02 and 03
/// complete the crypto crate's identity, key agreement, and signing modules.
pub struct NativeCryptoProvider;

impl CryptoProvider for NativeCryptoProvider {
    type Error = zerotier_crypto::error::CryptoError;

    fn generate_identity(
        &self,
        _rng: &mut dyn rand_core::CryptoRng,
    ) -> Result<Vec<u8>, Self::Error> {
        todo!("depends on crypto crate identity module (Plan 02)")
    }

    fn validate_identity(&self, _identity_bytes: &[u8]) -> Result<bool, Self::Error> {
        todo!("depends on crypto crate identity module (Plan 02)")
    }

    fn key_agreement(
        &self,
        _our_secret: &[u8],
        _their_public: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        todo!("depends on crypto crate key agreement module (Plan 02)")
    }

    fn encrypt_packet(
        &self,
        _shared_secret: &[u8],
        _packet: &mut [u8],
        _encrypt_payload: bool,
    ) -> Result<(), Self::Error> {
        todo!("depends on crypto crate salsa module (Plan 03)")
    }

    fn decrypt_packet(
        &self,
        _shared_secret: &[u8],
        _packet: &mut [u8],
    ) -> Result<bool, Self::Error> {
        todo!("depends on crypto crate salsa module (Plan 03)")
    }

    fn sign(&self, _secret_key: &[u8], _message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        todo!("depends on crypto crate signing module (Plan 03)")
    }

    fn verify(
        &self,
        _public_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<bool, Self::Error> {
        todo!("depends on crypto crate signing module (Plan 03)")
    }
}
