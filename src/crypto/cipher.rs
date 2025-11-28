//! AES-256-GCM cipher implementation for authenticated encryption.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::Rng;

use crate::common::constants::{ENCRYPTION_KEY_SIZE, NONCE_SIZE};
use crate::common::error::{GhostQueryError, Result};
use crate::crypto::Cipher;

/// AES-256-GCM cipher for encrypting chunk data
#[derive(Clone)]
pub struct AesGcmCipher {
    cipher: Aes256Gcm,
}

impl AesGcmCipher {
    /// Create a new cipher with the given key
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != ENCRYPTION_KEY_SIZE {
            return Err(GhostQueryError::InvalidKeyLength {
                expected: ENCRYPTION_KEY_SIZE,
                actual: key.len(),
            });
        }

        let key_array: [u8; 32] = key.try_into().map_err(|_| {
            GhostQueryError::InvalidKeyLength {
                expected: ENCRYPTION_KEY_SIZE,
                actual: key.len(),
            }
        })?;

        let cipher = Aes256Gcm::new(&key_array.into());
        Ok(Self { cipher })
    }

    /// Create a cipher with a randomly generated key
    pub fn generate() -> (Self, [u8; ENCRYPTION_KEY_SIZE]) {
        let mut key = [0u8; ENCRYPTION_KEY_SIZE];
        rand::thread_rng().fill(&mut key);

        let cipher = Aes256Gcm::new(&key.into());
        (Self { cipher }, key)
    }

    /// Generate a random nonce
    fn generate_nonce() -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        rand::thread_rng().fill(&mut nonce);
        nonce
    }

    /// Encrypt with associated data (for additional authentication)
    pub fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = Self::generate_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create cipher with AAD
        let ciphertext = self
            .cipher
            .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
            .map_err(|e| GhostQueryError::EncryptionError(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt with associated data verification
    pub fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE {
            return Err(GhostQueryError::DecryptionError(
                "Ciphertext too short".to_string(),
            ));
        }

        let (nonce_bytes, actual_ciphertext) = ciphertext.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: actual_ciphertext,
                    aad,
                },
            )
            .map_err(|e| GhostQueryError::DecryptionError(e.to_string()))
    }
}

impl Cipher for AesGcmCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_with_aad(plaintext, &[])
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_with_aad(ciphertext, &[])
    }
}

/// Encrypt data for a specific session (uses session ID as AAD)
pub fn encrypt_for_session(
    cipher: &AesGcmCipher,
    session_id: &[u8; 8],
    chunk_id: u32,
    data: &[u8],
) -> Result<Vec<u8>> {
    // Create AAD from session ID and chunk ID
    let mut aad = Vec::with_capacity(12);
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(&chunk_id.to_be_bytes());

    cipher.encrypt_with_aad(data, &aad)
}

/// Decrypt data for a specific session
pub fn decrypt_for_session(
    cipher: &AesGcmCipher,
    session_id: &[u8; 8],
    chunk_id: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let mut aad = Vec::with_capacity(12);
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(&chunk_id.to_be_bytes());

    cipher.decrypt_with_aad(ciphertext, &aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (cipher, _key) = AesGcmCipher::generate();
        let plaintext = b"Hello, World! This is secret data.";

        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_with_aad() {
        let (cipher, _key) = AesGcmCipher::generate();
        let plaintext = b"Secret message";
        let aad = b"session123";

        let ciphertext = cipher.encrypt_with_aad(plaintext, aad).unwrap();
        let decrypted = cipher.decrypt_with_aad(&ciphertext, aad).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_aad_fails() {
        let (cipher, _key) = AesGcmCipher::generate();
        let plaintext = b"Secret message";
        let aad = b"session123";
        let wrong_aad = b"session456";

        let ciphertext = cipher.encrypt_with_aad(plaintext, aad).unwrap();
        let result = cipher.decrypt_with_aad(&ciphertext, wrong_aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_session_encryption() {
        let (cipher, _key) = AesGcmCipher::generate();
        let session_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let chunk_id = 42u32;
        let data = b"Chunk data to exfiltrate";

        let encrypted = encrypt_for_session(&cipher, &session_id, chunk_id, data).unwrap();
        let decrypted = decrypt_for_session(&cipher, &session_id, chunk_id, &encrypted).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_ciphertext_includes_nonce() {
        let (cipher, _key) = AesGcmCipher::generate();
        let plaintext = b"test";

        let ciphertext = cipher.encrypt(plaintext).unwrap();

        // Ciphertext should be at least nonce + tag + plaintext
        assert!(ciphertext.len() >= NONCE_SIZE + 16 + plaintext.len());
    }
}

