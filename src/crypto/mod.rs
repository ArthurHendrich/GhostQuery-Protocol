//! Cryptographic module for end-to-end encryption.
//!
//! Uses AES-256-GCM for authenticated encryption to ensure
//! confidentiality and integrity of exfiltrated data.

pub mod cipher;
pub mod hash;
pub mod keys;

pub use cipher::AesGcmCipher;
pub use hash::Hasher;
pub use keys::KeyManager;

use crate::common::error::Result;

/// Trait for encryption/decryption operations
pub trait Cipher {
    /// Encrypt plaintext data
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext data
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

