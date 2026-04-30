//! Key file generation and fingerprinting.

use std::path::Path;

use anyhow::{bail, Context, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const KEY_SIZE: usize = 32;

/// Generate a cryptographically secure random 32-byte key and write it to
/// `output_path`.  Prints a SHA-256 fingerprint so the user can later verify
/// they're using the correct key without exposing its contents.
pub fn generate_key(output_path: &Path, force: bool) -> Result<()> {
    if output_path.exists() && !force {
        bail!(
            "Key file '{}' already exists. Use --force to overwrite.",
            output_path.display()
        );
    }

    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    rand::rngs::OsRng.fill_bytes(key.as_mut());

    std::fs::write(output_path, key.as_ref())
        .with_context(|| format!("Failed to write key to '{}'", output_path.display()))?;

    // Tighten permissions on Unix so other users can't read the key.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(output_path, perms)
            .with_context(|| format!("Failed to set permissions on '{}'", output_path.display()))?;
        println!("  Permissions : 600 (owner read/write only)");
    }

    let fingerprint = key_fingerprint(key.as_ref());

    println!("  Size        : {} bytes ({}-bit key)", KEY_SIZE, KEY_SIZE * 8);
    println!("  Source      : OsRng (OS cryptographic RNG)");
    println!("  Fingerprint : {fingerprint}");
    println!("  ⚠️  Keep '{}' secret — loss means permanent data loss.", output_path.display());

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