use std::path::Path;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{bail, Context, Result};

/// Supported encryption algorithms.
///
/// New variants can be added here (e.g. ChaCha20Poly1305, AES-128-GCM) and
/// wired up in `encrypt_file` / `decrypt_file` below.
#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum Algorithm {
    /// AES-256-GCM (authenticated encryption) — default
    #[value(name = "aes256gcm", alias = "aes")]
    Aes256Gcm,

    // Future algorithms — uncomment and implement as needed:
    // #[value(name = "chacha20poly1305", alias = "chacha")]
    // ChaCha20Poly1305,
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::Aes256Gcm => write!(f, "AES-256-GCM"),
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypt the file at `plain_path` using the key at `key_path` and write the
/// ciphertext to `cipher_path`.
pub fn encrypt_file(
    plain_path: &Path,
    key_path: &Path,
    cipher_path: &Path,
    algorithm: Algorithm,
) -> Result<()> {
    println!("  Algorithm : {algorithm}");

    let plaintext = std::fs::read(plain_path)
        .with_context(|| format!("Failed to read plaintext: {}", plain_path.display()))?;

    let key_bytes = read_key(key_path)?;

    let ciphertext = match algorithm {
        Algorithm::Aes256Gcm => aes256gcm_encrypt(&plaintext, &key_bytes)?,
    };

    std::fs::write(cipher_path, &ciphertext)
        .with_context(|| format!("Failed to write ciphertext: {}", cipher_path.display()))?;

    println!(
        "  Input     : {} bytes → Output: {} bytes",
        plaintext.len(),
        ciphertext.len()
    );

    Ok(())
}

/// Decrypt the file at `cipher_path` using the key at `key_path` and write
/// the recovered plaintext to `plain_path`.
pub fn decrypt_file(
    plain_path: &Path,
    key_path: &Path,
    cipher_path: &Path,
    algorithm: Algorithm,
) -> Result<()> {
    println!("  Algorithm : {algorithm}");

    let ciphertext = std::fs::read(cipher_path)
        .with_context(|| format!("Failed to read ciphertext: {}", cipher_path.display()))?;

    let key_bytes = read_key(key_path)?;

    let plaintext = match algorithm {
        Algorithm::Aes256Gcm => aes256gcm_decrypt(&ciphertext, &key_bytes)?,
    };

    std::fs::write(plain_path, &plaintext)
        .with_context(|| format!("Failed to write plaintext: {}", plain_path.display()))?;

    println!(
        "  Input     : {} bytes → Output: {} bytes",
        ciphertext.len(),
        plaintext.len()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Key loading
// ---------------------------------------------------------------------------

/// Read and validate the key file.
///
/// AES-256 requires exactly 32 bytes. The key file can be raw binary or you
/// can extend this to support hex/base64 in the future.
fn read_key(key_path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(key_path)
        .with_context(|| format!("Failed to read key file: {}", key_path.display()))?;

    if bytes.len() != 32 {
        bail!(
            "Key file must be exactly 32 bytes for AES-256, got {} bytes ({})",
            bytes.len(),
            key_path.display()
        );
    }

    Ok(bytes)
}

// ---------------------------------------------------------------------------
// AES-256-GCM implementation
// ---------------------------------------------------------------------------
//
// Wire format (all written to the cipher file):
//
//   [ 12-byte nonce ][ N-byte GCM ciphertext+tag ]
//
// The nonce is freshly generated for every encryption call (never reused).
// GCM appends a 16-byte authentication tag automatically, so the output is
// always plaintext_len + 12 (nonce) + 16 (tag) bytes.

const NONCE_LEN: usize = 12;

fn aes256gcm_encrypt(plaintext: &[u8], key_bytes: &[u8]) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Fresh random 96-bit nonce — MUST never be reused with the same key.
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let encrypted = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("AES-256-GCM encryption failed: {e}"))?;

    // Prepend nonce so we can recover it at decryption time.
    let mut output = Vec::with_capacity(NONCE_LEN + encrypted.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted);

    Ok(output)
}

fn aes256gcm_decrypt(ciphertext: &[u8], key_bytes: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < NONCE_LEN + 16 {
        bail!(
            "Ciphertext is too short ({} bytes). Expected at least {} bytes.",
            ciphertext.len(),
            NONCE_LEN + 16
        );
    }

    let (nonce_bytes, encrypted) = ciphertext.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| anyhow::anyhow!(
            "Decryption failed — wrong key, corrupted file, or tampered ciphertext."
        ))?;

    Ok(plaintext)
}