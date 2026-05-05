//! Key derivation from a passphrase using Argon2id.
//!
//! Parameters (OWASP recommended minimums for interactive use):
//!   - Memory      : 64 MiB
//!   - Iterations  : 3
//!   - Parallelism : 1
//!
//! The 16-byte salt is randomly generated per file and stored in the header.
//! The derived key is 32 bytes (256 bits) — suitable for AES-256-GCM and
//! ChaCha20-Poly1305.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::CryError;

pub const KEY_LEN: usize = 32;

/// Derive a 32-byte key from `passphrase` and `salt` using Argon2id.
///
/// Returns a `Zeroizing` wrapper so the key bytes are wiped from memory
/// when the value is dropped.
pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, CryError> {
    let params =
        Params::new(65536, 3, 1, Some(KEY_LEN)).map_err(|e| CryError::Kdf(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| CryError::Kdf(e.to_string()))?;

    Ok(key)
}
