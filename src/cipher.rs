//! Streaming encryption / decryption.
//!
//! Files are processed in fixed-size chunks so arbitrarily large inputs never
//! require loading the whole file into memory.  Each chunk is independently
//! authenticated with its own GCM / Poly1305 tag, and the chunk index is
//! mixed into the nonce to prevent reordering attacks.
//!
//! Chunk wire format (repeated until EOF):
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │ length   4 bytes  u32 big-endian          │  ← ciphertext + tag length
//! │ data     N bytes  AEAD ciphertext + tag   │
//! └──────────────────────────────────────────┘
//! ```
//!
//! The header (magic, algo, salt, nonce) is written / read by `header.rs`.

use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use aes_gcm::{aead::KeyInit, Aes256Gcm, Key as AesKey, Nonce as AesNonce};
use aes_gcm::aead::Aead as AesAead;
use chacha20poly1305::{
    ChaCha20Poly1305,
    Key as ChaChaKey, Nonce as ChaChaNonce,
};
use anyhow::{bail, Context, Result};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::header::{AlgoId, Header, NONCE_LEN, SALT_LEN};
use crate::kdf::derive_key;

/// Chunk size for streaming encryption (1 MiB).
const CHUNK_SIZE: usize = 1024 * 1024;

/// Algorithms exposed to the CLI (encrypt side only — decrypt reads from header).
#[derive(clap::ValueEnum, Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Algorithm {
    /// AES-256-GCM — hardware-accelerated on most x86/ARM64 CPUs (default)
    #[value(name = "aes256gcm", alias = "aes")]
    Aes256Gcm,

    /// ChaCha20-Poly1305 — preferred on devices without AES hardware
    #[value(name = "chacha20poly1305", alias = "chacha")]
    ChaCha20Poly1305,
}

impl From<Algorithm> for AlgoId {
    fn from(a: Algorithm) -> Self {
        match a {
            Algorithm::Aes256Gcm => AlgoId::Aes256Gcm,
            Algorithm::ChaCha20Poly1305 => AlgoId::ChaCha20Poly1305,
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::Aes256Gcm => write!(f, "AES-256-GCM"),
            Algorithm::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
        }
    }
}

impl std::fmt::Display for AlgoId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlgoId::Aes256Gcm => write!(f, "AES-256-GCM"),
            AlgoId::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn encrypt_file(
    plain_path: &Path,
    cipher_path: &Path,
    passphrase: &Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
) -> Result<()> {
    println!("  Algorithm : {algorithm}");
    println!("  KDF       : Argon2id (64 MiB, 3 iterations)");

    // Generate fresh random salt and nonce.
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    // Derive key — this is intentionally slow.
    print!("  Deriving key… ");
    std::io::stdout().flush().ok();
    let key = derive_key(passphrase.as_slice(), &salt)?;
    println!("done.");

    let header = Header {
        algo: algorithm.into(),
        salt,
        nonce: nonce_bytes,
    };

    let plain_file = std::fs::File::open(plain_path)
        .with_context(|| format!("Cannot open plaintext: {}", plain_path.display()))?;
    let plain_len = plain_file.metadata()?.len();
    let mut reader = BufReader::new(plain_file);

    let cipher_file = std::fs::File::create(cipher_path)
        .with_context(|| format!("Cannot create ciphertext: {}", cipher_path.display()))?;
    let mut writer = BufWriter::new(cipher_file);

    header.write(&mut writer)?;

    let chunks = encrypt_chunks(&mut reader, &mut writer, &key, &nonce_bytes, algorithm)?;

    writer.flush().context("Failed to flush output")?;

    let cipher_len = std::fs::metadata(cipher_path)?.len();
    println!("  Input     : {plain_len} bytes");
    println!("  Output    : {cipher_len} bytes ({chunks} chunk(s))");

    Ok(())
}

pub fn decrypt_file(
    plain_path: &Path,
    cipher_path: &Path,
    passphrase: &Zeroizing<Vec<u8>>,
) -> Result<()> {
    let cipher_file = std::fs::File::open(cipher_path)
        .with_context(|| format!("Cannot open ciphertext: {}", cipher_path.display()))?;
    let cipher_len = cipher_file.metadata()?.len();
    let mut reader = BufReader::new(cipher_file);

    // Parse header — algo is discovered here, not passed in by the user.
    let header = Header::read(&mut reader)?;

    println!("  Algorithm : {} (from file header)", header.algo);
    println!("  KDF       : Argon2id (64 MiB, 3 iterations)");

    print!("  Deriving key… ");
    std::io::stdout().flush().ok();
    let key = derive_key(passphrase.as_slice(), &header.salt)?;
    println!("done.");

    let plain_file = std::fs::File::create(plain_path)
        .with_context(|| format!("Cannot create plaintext: {}", plain_path.display()))?;
    let mut writer = BufWriter::new(plain_file);

    let chunks = decrypt_chunks(&mut reader, &mut writer, &key, &header.nonce, header.algo)?;

    writer.flush().context("Failed to flush output")?;

    let plain_len = std::fs::metadata(plain_path)?.len();
    println!("  Input     : {cipher_len} bytes");
    println!("  Output    : {plain_len} bytes ({chunks} chunk(s))");

    Ok(())
}

// ---------------------------------------------------------------------------
// Streaming chunk helpers
// ---------------------------------------------------------------------------

/// Derive a per-chunk nonce by XOR-ing the base nonce with the chunk index.
/// This prevents chunk reordering attacks without changing nonce length.
fn chunk_nonce(base: &[u8; NONCE_LEN], index: u64) -> [u8; NONCE_LEN] {
    let mut n = *base;
    let idx_bytes = index.to_be_bytes(); // 8 bytes
    // XOR into the last 8 bytes of the 12-byte nonce
    for i in 0..8 {
        n[NONCE_LEN - 8 + i] ^= idx_bytes[i];
    }
    n
}

fn encrypt_chunks(
    reader: &mut impl Read,
    writer: &mut impl Write,
    key: &Zeroizing<[u8; 32]>,
    base_nonce: &[u8; NONCE_LEN],
    algo: Algorithm,
) -> Result<u64> {
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut chunk_index: u64 = 0;

    loop {
        let n = read_full(reader, &mut buf)?;
        if n == 0 { break; }

        let nonce = chunk_nonce(base_nonce, chunk_index);
        let ct = encrypt_chunk(&buf[..n], key, &nonce, algo)?;

        let len = ct.len() as u32;
        writer.write_all(&len.to_be_bytes()).context("write chunk length")?;
        writer.write_all(&ct).context("write chunk data")?;

        chunk_index += 1;
        if n < CHUNK_SIZE { break; } // last chunk
    }

    Ok(chunk_index)
}

fn decrypt_chunks(
    reader: &mut impl Read,
    writer: &mut impl Write,
    key: &Zeroizing<[u8; 32]>,
    base_nonce: &[u8; NONCE_LEN],
    algo: AlgoId,
) -> Result<u64> {
    let mut chunk_index: u64 = 0;

    loop {
        // Read 4-byte length prefix.
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("read chunk length"),
        }
        let ct_len = u32::from_be_bytes(len_buf) as usize;

        if ct_len > CHUNK_SIZE + 64 {
            bail!("Chunk length {ct_len} is suspiciously large — file may be corrupted.");
        }

        let mut ct = vec![0u8; ct_len];
        reader.read_exact(&mut ct).context("read chunk data")?;

        let nonce = chunk_nonce(base_nonce, chunk_index);
        let plain = decrypt_chunk(&ct, key, &nonce, algo)?;

        writer.write_all(&plain).context("write plaintext chunk")?;
        chunk_index += 1;
    }

    Ok(chunk_index)
}

/// Read up to `buf.len()` bytes, returning how many were actually read.
/// Unlike `read_exact`, this won't error on EOF mid-stream.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("read plaintext"),
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Single-chunk AEAD operations (dispatch to algorithm)
// ---------------------------------------------------------------------------

fn encrypt_chunk(plain: &[u8], key: &[u8; 32], nonce: &[u8; NONCE_LEN], algo: Algorithm) -> Result<Vec<u8>> {
    match algo {
        Algorithm::Aes256Gcm => {
            let k = AesKey::<Aes256Gcm>::from_slice(key);
            let cipher = Aes256Gcm::new(k);
            cipher
                .encrypt(AesNonce::from_slice(nonce), plain)
                .map_err(|e| anyhow::anyhow!("AES-256-GCM encryption failed: {e}"))
        }
        Algorithm::ChaCha20Poly1305 => {
            let k = ChaChaKey::from_slice(key);
            let cipher = ChaCha20Poly1305::new(k);
            cipher
                .encrypt(ChaChaNonce::from_slice(nonce), plain)
                .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 encryption failed: {e}"))
        }
    }
}

fn decrypt_chunk(ct: &[u8], key: &[u8; 32], nonce: &[u8; NONCE_LEN], algo: AlgoId) -> Result<Vec<u8>> {
    match algo {
        AlgoId::Aes256Gcm => {
            let k = AesKey::<Aes256Gcm>::from_slice(key);
            let cipher = Aes256Gcm::new(k);
            cipher
                .decrypt(AesNonce::from_slice(nonce), ct)
                .map_err(|_| anyhow::anyhow!(
                    "Decryption failed — wrong passphrase, corrupted file, or tampered ciphertext."
                ))
        }
        AlgoId::ChaCha20Poly1305 => {
            let k = ChaChaKey::from_slice(key);
            let cipher = ChaCha20Poly1305::new(k);
            cipher
                .decrypt(ChaChaNonce::from_slice(nonce), ct)
                .map_err(|_| anyhow::anyhow!(
                    "Decryption failed — wrong passphrase, corrupted file, or tampered ciphertext."
                ))
        }
    }
}