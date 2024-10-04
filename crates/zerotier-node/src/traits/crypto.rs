use alloc::vec::Vec;

/// Cryptographic operations abstraction for the ZeroTier protocol.
///
/// Single trait, not split by domain.
/// V2-extensible -- uses `&[u8]` slices rather than concrete types
/// so V2 can pass different-sized keys (P-384/Kyber1024) without changing the trait.
/// The `protocol_version()` method with default impl allows future V2 providers to coexist.
pub trait CryptoProvider: Send + Sync {
    type Error: core::fmt::Debug + core::fmt::Display;

    /// Generate a new identity (V1: x25519 + ed25519 + memory-hard PoW).
    /// Returns the identity serialized to bytes.
    fn generate_identity(&self, rng: &mut dyn rand_core::CryptoRng)
        -> Result<Vec<u8>, Self::Error>;

    /// Validate an identity's address derivation.
    /// Returns true if the identity bytes are well-formed and the address PoW is valid.
    fn validate_identity(&self, identity_bytes: &[u8]) -> Result<bool, Self::Error>;

    /// X25519 key agreement (V1) -- returns shared secret.
    fn key_agreement(&self, our_secret: &[u8], their_public: &[u8])
        -> Result<Vec<u8>, Self::Error>;

    /// Symmetric encrypt-then-MAC (V1: Salsa20/12 + Poly1305).
    /// Encrypts the packet payload in-place and appends/updates the MAC.
    fn encrypt_packet(
        &self,
        shared_secret: &[u8],
        packet: &mut [u8],
        encrypt_payload: bool,
    ) -> Result<(), Self::Error>;

    /// Symmetric verify-then-decrypt (V1: Salsa20/12 + Poly1305).
    /// Returns true if MAC verification succeeded and decryption was performed.
    fn decrypt_packet(&self, shared_secret: &[u8], packet: &mut [u8]) -> Result<bool, Self::Error>;

    /// Sign a message (V1: Ed25519, returns 96-byte padded signature).
    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Verify a signature (V1: Ed25519).
    /// Returns true if the signature is valid for the given message and public key.
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error>;

    /// Protocol version this provider supports (1 for V1, 2 for future V2).
    fn protocol_version(&self) -> u8 {
        1
    }
}
