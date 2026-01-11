use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};
use zerotier_crypto::error::CryptoError;
use zerotier_crypto::identity::{
    Identity, PublicKey as IdentityPublicKey, SecretKey as IdentitySecretKey,
};
use zerotier_node::traits::CryptoProvider;

/// Native CryptoProvider using zerotier-crypto crate functions.
pub struct NativeCryptoProvider;

impl CryptoProvider for NativeCryptoProvider {
    type Error = CryptoError;

    fn generate_identity(
        &self,
        _rng: &mut dyn rand_core::CryptoRng,
    ) -> Result<Vec<u8>, Self::Error> {
        struct ProviderRng;

        impl rand_core::RngCore for ProviderRng {
            fn next_u32(&mut self) -> u32 {
                let mut bytes = [0u8; 4];
                getrandom::getrandom(&mut bytes).expect("getrandom failed");
                u32::from_le_bytes(bytes)
            }

            fn next_u64(&mut self) -> u64 {
                let mut bytes = [0u8; 8];
                getrandom::getrandom(&mut bytes).expect("getrandom failed");
                u64::from_le_bytes(bytes)
            }

            fn fill_bytes(&mut self, dest: &mut [u8]) {
                getrandom::getrandom(dest).expect("getrandom failed");
            }

            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                getrandom::getrandom(dest).map_err(|_| {
                    rand_core::Error::from(
                        core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
                    )
                })
            }
        }

        impl rand_core::CryptoRng for ProviderRng {}

        let mut rng = ProviderRng;
        let identity = Identity::generate(&mut rng)?;
        Ok(identity
            .to_secret_string()
            .expect("generated identity must include a secret key")
            .into_bytes())
    }

    fn validate_identity(&self, identity_bytes: &[u8]) -> Result<bool, Self::Error> {
        let identity = std::str::from_utf8(identity_bytes)
            .map_err(|_| CryptoError::InvalidFormat)
            .and_then(Identity::parse)?;
        Ok(identity.validate_address())
    }

    fn key_agreement(
        &self,
        our_secret: &[u8],
        their_public: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let our_secret: [u8; 32] = our_secret
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        let their_public: [u8; 32] = their_public
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;

        Ok(zerotier_crypto::key_agreement::key_agree(
            &StaticSecret::from(our_secret),
            &PublicKey::from(their_public),
        )
        .to_vec())
    }

    fn encrypt_packet(
        &self,
        shared_secret: &[u8],
        packet: &mut [u8],
        encrypt_payload: bool,
    ) -> Result<(), Self::Error> {
        let shared_secret: [u8; 32] = shared_secret
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        zerotier_crypto::salsa::armor_packet(&shared_secret, packet, encrypt_payload)
    }

    fn decrypt_packet(&self, shared_secret: &[u8], packet: &mut [u8]) -> Result<bool, Self::Error> {
        let shared_secret: [u8; 32] = shared_secret
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        match zerotier_crypto::salsa::dearmor_packet(&shared_secret, packet) {
            Ok(()) => Ok(true),
            Err(CryptoError::MacVerificationFailed) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let signing_key = match secret_key.len() {
            32 => {
                let bytes: [u8; 32] = secret_key
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKeyLength)?;
                SigningKey::from_bytes(&bytes)
            }
            64 => IdentitySecretKey::from_bytes(secret_key)?.signing.clone(),
            _ => return Err(CryptoError::InvalidKeyLength),
        };

        Ok(zerotier_crypto::signing::sign(&signing_key, message).to_vec())
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let verifying_key = match public_key.len() {
            32 => {
                let bytes: [u8; 32] = public_key
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKeyLength)?;
                VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidKeyLength)?
            }
            64 => {
                let key = IdentityPublicKey::from_bytes(public_key)?;
                VerifyingKey::from_bytes(&key.signing).map_err(|_| CryptoError::InvalidKeyLength)?
            }
            _ => return Err(CryptoError::InvalidKeyLength),
        };

        let signature: [u8; 96] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        match zerotier_crypto::signing::verify(&verifying_key, message, &signature) {
            Ok(()) => Ok(true),
            Err(CryptoError::SignatureError) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NativeCryptoProvider;
    use zerotier_node::traits::CryptoProvider;

    struct TestRng(u64);

    impl rand_core::RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            rand_core::impls::fill_bytes_via_next(self, dest);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rand_core::CryptoRng for TestRng {}

    #[test]
    fn identity_generation_roundtrips() {
        let provider = NativeCryptoProvider;
        let mut rng = TestRng(0x1234_5678_9abc_def0);

        let identity = provider.generate_identity(&mut rng).unwrap();

        assert!(provider.validate_identity(&identity).unwrap());
    }

    #[test]
    fn packet_encryption_roundtrips() {
        let provider = NativeCryptoProvider;
        let shared_secret = [0x42u8; 32];
        let mut packet = [0u8; 64];
        packet[0..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        packet[8..13].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        packet[13..18].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]);
        packet[18] = 0x08;
        packet[27] = 0x05;
        packet[28..].copy_from_slice(&[0x77; 36]);
        let original = packet;

        provider
            .encrypt_packet(&shared_secret, &mut packet, true)
            .unwrap();
        assert_ne!(packet[27..], original[27..]);
        assert!(provider
            .decrypt_packet(&shared_secret, &mut packet)
            .unwrap());
        assert_eq!(packet[..19], original[..19]);
        assert_eq!(packet[27..], original[27..]);
    }

    #[test]
    fn signing_roundtrips() {
        let provider = NativeCryptoProvider;
        let secret = [0x19u8; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
        let verifying = signing.verifying_key();
        let message = b"manytier";

        let signature = provider.sign(&secret, message).unwrap();

        assert!(provider
            .verify(verifying.as_bytes(), message, &signature)
            .unwrap());
        assert!(!provider
            .verify(verifying.as_bytes(), b"wrong", &signature)
            .unwrap());
    }
}
