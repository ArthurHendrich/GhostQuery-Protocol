//! Key management for encryption operations.

use rand::Rng;

use crate::common::constants::ENCRYPTION_KEY_SIZE;
use crate::common::error::{GhostQueryError, Result};
use crate::crypto::cipher::AesGcmCipher;

/// Key manager for generating and storing encryption keys
#[derive(Clone)]
pub struct KeyManager {
    /// Master key for session encryption
    master_key: [u8; ENCRYPTION_KEY_SIZE],
}

impl KeyManager {
    /// Create a new key manager with a random master key
    pub fn new() -> Self {
        let mut master_key = [0u8; ENCRYPTION_KEY_SIZE];
        rand::thread_rng().fill(&mut master_key);
        Self { master_key }
    }

    /// Create a key manager from an existing master key
    pub fn from_key(key: [u8; ENCRYPTION_KEY_SIZE]) -> Self {
        Self { master_key: key }
    }

    /// Create from a hex-encoded key string
    pub fn from_hex(hex_key: &str) -> Result<Self> {
        let bytes = hex::decode(hex_key).map_err(|e| {
            GhostQueryError::InvalidKeyLength {
                expected: ENCRYPTION_KEY_SIZE,
                actual: 0,
            }
        })?;

        if bytes.len() != ENCRYPTION_KEY_SIZE {
            return Err(GhostQueryError::InvalidKeyLength {
                expected: ENCRYPTION_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut key = [0u8; ENCRYPTION_KEY_SIZE];
        key.copy_from_slice(&bytes);
        Ok(Self::from_key(key))
    }

    /// Get the master key bytes
    pub fn master_key(&self) -> &[u8; ENCRYPTION_KEY_SIZE] {
        &self.master_key
    }

    /// Get master key as hex string
    pub fn master_key_hex(&self) -> String {
        hex::encode(self.master_key)
    }

    /// Derive a session key from the master key and session ID
    pub fn derive_session_key(&self, session_id: &[u8; 8]) -> [u8; ENCRYPTION_KEY_SIZE] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&self.master_key);
        hasher.update(session_id);
        hasher.update(b"GhostQuery-SessionKey-v1");

        let result = hasher.finalize();
        let mut key = [0u8; ENCRYPTION_KEY_SIZE];
        key.copy_from_slice(&result);
        key
    }

    /// Create a cipher for a specific session
    pub fn cipher_for_session(&self, session_id: &[u8; 8]) -> Result<AesGcmCipher> {
        let session_key = self.derive_session_key(session_id);
        AesGcmCipher::new(&session_key)
    }

    /// Create a cipher using the master key directly
    pub fn master_cipher(&self) -> Result<AesGcmCipher> {
        AesGcmCipher::new(&self.master_key)
    }

    /// Generate a new random key (for key rotation)
    pub fn rotate_key(&mut self) {
        rand::thread_rng().fill(&mut self.master_key);
    }

    /// Zero out the key material (for secure cleanup)
    pub fn zeroize(&mut self) {
        self.master_key.fill(0);
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for KeyManager {
    fn drop(&mut self) {
        // Attempt to clear key material on drop
        // Note: This is best-effort; compiler may optimize away
        self.zeroize();
    }
}

/// Generate a random key for use as a shared secret
pub fn generate_shared_key() -> [u8; ENCRYPTION_KEY_SIZE] {
    let mut key = [0u8; ENCRYPTION_KEY_SIZE];
    rand::thread_rng().fill(&mut key);
    key
}

/// Derive a key from a password using a simple KDF
/// Note: For production, use a proper KDF like Argon2 or scrypt
pub fn derive_key_from_password(password: &[u8], salt: &[u8]) -> [u8; ENCRYPTION_KEY_SIZE] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.update(salt);
    hasher.update(b"GhostQuery-KDF-v1");

    // Simple iteration for some work factor
    let mut intermediate = hasher.finalize();
    for _ in 0..10000 {
        let mut hasher = Sha256::new();
        hasher.update(&intermediate);
        hasher.update(salt);
        intermediate = hasher.finalize();
    }

    let mut key = [0u8; ENCRYPTION_KEY_SIZE];
    key.copy_from_slice(&intermediate);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_manager_creation() {
        let km1 = KeyManager::new();
        let km2 = KeyManager::new();

        // Keys should be different
        assert_ne!(km1.master_key(), km2.master_key());
    }

    #[test]
    fn test_session_key_derivation() {
        let km = KeyManager::new();
        let session1 = [0x01; 8];
        let session2 = [0x02; 8];

        let key1 = km.derive_session_key(&session1);
        let key2 = km.derive_session_key(&session2);

        // Different sessions should have different keys
        assert_ne!(key1, key2);

        // Same session should produce same key
        let key1_again = km.derive_session_key(&session1);
        assert_eq!(key1, key1_again);
    }

    #[test]
    fn test_cipher_for_session() {
        let km = KeyManager::new();
        let session_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let cipher = km.cipher_for_session(&session_id).unwrap();
        let plaintext = b"Test data";

        let encrypted = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_from_hex() {
        let km = KeyManager::new();
        let hex = km.master_key_hex();

        let km2 = KeyManager::from_hex(&hex).unwrap();
        assert_eq!(km.master_key(), km2.master_key());
    }

    #[test]
    fn test_password_derivation() {
        let password = b"mysecretpassword";
        let salt = b"randomsalt12345";

        let key1 = derive_key_from_password(password, salt);
        let key2 = derive_key_from_password(password, salt);

        // Same password and salt should produce same key
        assert_eq!(key1, key2);

        // Different salt should produce different key
        let key3 = derive_key_from_password(password, b"differentsalt");
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_key_rotation() {
        let mut km = KeyManager::new();
        let original_key = *km.master_key();

        km.rotate_key();

        assert_ne!(original_key, *km.master_key());
    }
}

