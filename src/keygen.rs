use std::path::Path;

use anyhow::{bail, Context, Result};
use rand::RngCore;

/// Key size in bytes required for AES-256.
pub const KEY_SIZE: usize = 32;

/// Generate a cryptographically secure random 32-byte key and write it to
/// `output_path`.
///
/// Fails if the file already exists and `force` is false, so callers can't
/// accidentally overwrite a key they are still using.
pub fn generate_key(output_path: &Path, force: bool) -> Result<()> {
    if output_path.exists() && !force {
        bail!(
            "Key file '{}' already exists. Use --force to overwrite.",
            output_path.display()
        );
    }

    let mut key = [0u8; KEY_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut key);

    std::fs::write(output_path, &key)
        .with_context(|| format!("Failed to write key to '{}'", output_path.display()))?;

    // Tighten permissions on Unix so other users can't read the key.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(output_path, perms)
            .with_context(|| format!("Failed to set permissions on '{}'", output_path.display()))?;
        println!("  Permissions set to 600 (owner read/write only)");
    }

    println!("  Size      : {} bytes ({}-bit key)", KEY_SIZE, KEY_SIZE * 8);
    println!("  Source    : OsRng (OS cryptographic RNG)");
    println!(
        "  ⚠️  Keep '{}' secret — loss means permanent data loss.",
        output_path.display()
    );

    Ok(())
}