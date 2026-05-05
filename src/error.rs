//! Structured error types for `cry`.
//!
//! The library layer returns `CryError`; the CLI layer formats them for
//! human consumption via the `Display` impl provided by `thiserror`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Encryption failed (AEAD error)")]
    EncryptionFailed,

    #[error("Decryption failed — wrong passphrase, corrupted file, or tampered ciphertext")]
    DecryptionFailed,

    #[error("Header authentication failed — file may have been tampered with")]
    HeaderTampered,

    #[error("File is truncated — expected {expected} chunks, got {got}")]
    Truncated { expected: u64, got: u64 },

    #[error("Invalid file format: {0}")]
    InvalidFormat(String),

    #[error("Key derivation failed: {0}")]
    Kdf(String),

    #[error("Output file '{0}' already exists — use --force to overwrite")]
    FileExists(String),

    #[error("Passphrase must not be empty")]
    EmptyPassphrase,

    #[error("Passphrases do not match")]
    PassphraseMismatch,

    #[error("Chunk {index} length {len} is suspiciously large — file may be corrupted")]
    SuspiciousChunkLen { index: u64, len: usize },

    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}
