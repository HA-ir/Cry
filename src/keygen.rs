//! Key file generation and fingerprinting.
//!
//! Note: `keygen` produces a raw 32-byte key file for inspection and
//! archival purposes. The encrypt/decrypt commands use passphrase-based
//! key derivation (Argon2id) and do not consume these key files directly.
//! A future `--key-file` flag could wire them together.

use std::path::Path;

use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::CryError;

pub const KEY_SIZE: usize = 32;

/// Generate a cryptographically secure random 32-byte key and write it to
/// `output_path`. Prints a SHA-256 fingerprint so the user can later verify
/// they're using the correct key without exposing its raw bytes.
pub fn generate_key(output_path: &Path, force: bool) -> Result<(), CryError> {
    if output_path.exists() && !force {
        return Err(CryError::FileExists(output_path.display().to_string()));
    }

    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    rand::rngs::OsRng.fill_bytes(key.as_mut());

    std::fs::write(output_path, key.as_ref())?;

    // Tighten permissions on Unix so other users can't read the key.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(output_path, perms)?;
        eprintln!("  Permissions : 600 (owner read/write only)");
    }

    let fingerprint = key_fingerprint(key.as_ref());

    eprintln!("  Size        : {} bytes ({}-bit key)", KEY_SIZE, KEY_SIZE * 8);
    eprintln!("  Source      : OsRng (OS cryptographic RNG)");
    eprintln!("  Fingerprint : {fingerprint}");
    eprintln!(
        "  ⚠  Keep '{}' secret — loss means permanent data loss.",
        output_path.display()
    );

    Ok(())
}

/// Compute a short human-readable SHA-256 fingerprint of a key.
/// Shows first 8 bytes as hex groups (e.g. `a3f1e209:bb047c11`).
pub fn key_fingerprint(key: &[u8]) -> String {
    let hash = Sha256::digest(key);
    format!(
        "{:08x}:{:08x}",
        u32::from_be_bytes(hash[0..4].try_into().unwrap()),
        u32::from_be_bytes(hash[4..8].try_into().unwrap()),
    )
}