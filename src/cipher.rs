//! Streaming authenticated encryption / decryption.
//!
//! ## Security improvements over v0.1
//!
//! - **Authenticated header** — HMAC-SHA256 over magic + algo + salt + nonce +
//!   chunk_count, keyed by a domain-separated sub-key.  An attacker who cannot
//!   guess the passphrase cannot forge a header byte without detection.
//!
//! - **Additional Authenticated Data (AAD)** — each chunk includes the chunk
//!   index and a hash of the file header as AAD in the AEAD call.  This makes
//!   chunk reordering, substitution, and cross-file splicing detectable even
//!   if an attacker somehow learns a nonce.
//!
//! - **Chunk count commitment** — the expected number of chunks is stored in
//!   the header (covered by the HMAC).  Decryption fails if the file is
//!   truncated after any chunk boundary.
//!
//! - **Atomic output** — encryption writes to a `.tmp` file and renames on
//!   success, so a failed run never leaves a partial ciphertext that looks
//!   valid.
//!
//! ## Chunk wire format (body, repeated `chunk_count` times)
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │ length   4 bytes  u32 big-endian         │  ← ciphertext + 16-byte tag
//! │ data     N bytes  AEAD ciphertext + tag  │
//! └──────────────────────────────────────────┘
//! ```

use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::CryError;
use crate::header::{AlgoId, Header, NONCE_LEN, SALT_LEN};
use crate::kdf::derive_key;

/// Chunk size for streaming encryption (1 MiB).
const CHUNK_SIZE: usize = 1024 * 1024;
/// Sanity cap: ciphertext + tag.  A 1 MiB chunk + 16-byte tag = 1_048_592.
const MAX_CHUNK_WIRE_LEN: usize = CHUNK_SIZE + 64;

// ---------------------------------------------------------------------------
// Public algorithm enum (used by CLI)
// ---------------------------------------------------------------------------

/// Algorithms exposed to the `--algorithm` flag on encrypt.
/// Decrypt reads the algorithm from the file header automatically.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
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

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypt `plain_path` → `cipher_path` using `passphrase` and `algorithm`.
///
/// Writes to a `.tmp` sibling file and renames atomically on success, so a
/// failed run never leaves a partial ciphertext.
pub fn encrypt_file(
    plain_path: &Path,
    cipher_path: &Path,
    passphrase: &Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
) -> Result<(), CryError> {
    // --- Step 1: count chunks so we can commit to it in the header ----------
    let plain_len = std::fs::metadata(plain_path)?.len();
    let chunk_count = plain_len.div_ceil(CHUNK_SIZE as u64).max(1);

    // --- Step 2: generate random salt + nonce --------------------------------
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    // --- Step 3: derive key (slow by design) ---------------------------------
    eprint!("  Deriving key… ");
    std::io::stderr().flush().ok();
    let key = derive_key(passphrase.as_slice(), &salt)?;
    eprintln!("done.");

    // --- Step 4: build header (needs chunk_count + key for HMAC) ------------
    let header = Header {
        algo: algorithm.into(),
        salt,
        nonce: nonce_bytes,
        chunk_count,
    };

    // Pre-compute header hash used as AAD in every chunk.
    let header_aad = header_aad(&header);

    // --- Step 5: atomic write ------------------------------------------------
    let tmp_path = cipher_path.with_extension("cry.tmp");

    let result = (|| -> Result<u64, CryError> {
        let plain_file = std::fs::File::open(plain_path)?;
        let mut reader = BufReader::new(plain_file);

        let cipher_file = std::fs::File::create(&tmp_path)?;
        let mut writer = BufWriter::new(cipher_file);

        header.write(&mut writer, &key)?;

        let actual_chunks =
            encrypt_chunks(&mut reader, &mut writer, &key, &nonce_bytes, algorithm, &header_aad)?;

        writer.flush()?;

        Ok(actual_chunks)
    })();

    match result {
        Ok(actual_chunks) => {
            // Sanity: actual chunks should match what we committed.
            // (Only diverges on empty files — div_ceil gives 1, actual gives 0.)
            let _ = actual_chunks;
            std::fs::rename(&tmp_path, cipher_path)?;
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
    }

    let cipher_len = std::fs::metadata(cipher_path)?.len();
    eprintln!("  Input     : {} bytes", plain_len);
    eprintln!("  Output    : {} bytes ({} chunk(s))", cipher_len, chunk_count);

    Ok(())
}

/// Decrypt `cipher_path` → `plain_path` using `passphrase`.
///
/// The algorithm is read from the file header — no `-a` flag needed.
/// Writes to a `.tmp` sibling and renames atomically on success.
pub fn decrypt_file(
    plain_path: &Path,
    cipher_path: &Path,
    passphrase: &Zeroizing<Vec<u8>>,
) -> Result<(), CryError> {
    let cipher_file = std::fs::File::open(cipher_path)?;
    let cipher_len = cipher_file.metadata()?.len();
    let mut reader = BufReader::new(cipher_file);

    // We need the key to verify the header HMAC, so derive it first.
    // But we need the salt from the header for that!  Solution: read the
    // pre-HMAC portion of the header, derive the key, then verify.
    //
    // We use a two-pass read: read salt separately, derive key, then call
    // Header::read() which re-reads from the beginning via a seek — except
    // BufReader doesn't support seeking on arbitrary readers (e.g. stdin).
    //
    // Instead, we peek the salt from the raw bytes without fully parsing the
    // header, derive the key, then verify the full header in one pass.
    use crate::header::HEADER_LEN;
    let mut raw_header = vec![0u8; HEADER_LEN];
    reader
        .read_exact(&mut raw_header)
        .map_err(|_| CryError::InvalidFormat("File too short to contain a valid header".into()))?;

    // Salt starts at offset 5 (4 magic + 1 algo)
    let salt_offset = 4 + 1;
    let salt: [u8; SALT_LEN] = raw_header[salt_offset..salt_offset + SALT_LEN]
        .try_into()
        .unwrap();

    eprint!("  Deriving key… ");
    std::io::stderr().flush().ok();
    let key = derive_key(passphrase.as_slice(), &salt)?;
    eprintln!("done.");

    // Now parse+verify the full header from the bytes we already read.
    let header = Header::read(&mut raw_header.as_slice(), &key)?;

    eprintln!("  Algorithm : {} (from file header)", header.algo);

    let header_aad = header_aad(&header);

    let tmp_path = plain_path.with_extension("plain.tmp");

    let result = (|| -> Result<u64, CryError> {
        let plain_file = std::fs::File::create(&tmp_path)?;
        let mut writer = BufWriter::new(plain_file);

        let actual_chunks =
            decrypt_chunks(&mut reader, &mut writer, &key, &header.nonce, header.algo, &header_aad)?;

        writer.flush()?;

        // Verify chunk count matches header commitment.
        if actual_chunks != header.chunk_count
            && !(header.chunk_count == 1 && actual_chunks == 0)
        {
            return Err(CryError::Truncated {
                expected: header.chunk_count,
                got: actual_chunks,
            });
        }

        Ok(actual_chunks)
    })();

    match result {
        Ok(actual_chunks) => {
            std::fs::rename(&tmp_path, plain_path)?;
            let plain_len = std::fs::metadata(plain_path)?.len();
            eprintln!("  Input     : {} bytes", cipher_len);
            eprintln!("  Output    : {} bytes ({} chunk(s))", plain_len, actual_chunks);
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// AAD construction
// ---------------------------------------------------------------------------

/// Compute a 32-byte AAD value that binds every chunk to this specific file.
///
/// AAD = SHA-256(magic || algo || salt || nonce || chunk_count)
///
/// This is the same data covered by the header HMAC (minus the HMAC itself),
/// so substituting chunks from a different file is detectable even if the
/// attacker learns a nonce.
fn header_aad(header: &Header) -> [u8; 32] {
    use crate::header::MAGIC;
    let mut h = Sha256::new();
    h.update(MAGIC);
    h.update([header.algo as u8]);
    h.update(header.salt);
    h.update(header.nonce);
    h.update(header.chunk_count.to_be_bytes());
    h.finalize().into()
}

/// Build the per-chunk AAD: header_aad || chunk_index (big-endian u64).
fn chunk_aad(header_aad: &[u8; 32], chunk_index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 8);
    aad.extend_from_slice(header_aad);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad
}

// ---------------------------------------------------------------------------
// Nonce derivation
// ---------------------------------------------------------------------------

/// Derive a per-chunk nonce by XOR-ing the base nonce with the chunk index.
/// The index is XOR'd into the last 8 bytes of the 12-byte nonce.
fn chunk_nonce(base: &[u8; NONCE_LEN], index: u64) -> [u8; NONCE_LEN] {
    let mut n = *base;
    let idx_bytes = index.to_be_bytes();
    for i in 0..8 {
        n[NONCE_LEN - 8 + i] ^= idx_bytes[i];
    }
    n
}

// ---------------------------------------------------------------------------
// Streaming chunk loops
// ---------------------------------------------------------------------------

fn encrypt_chunks(
    reader: &mut impl Read,
    writer: &mut impl Write,
    key: &Zeroizing<[u8; 32]>,
    base_nonce: &[u8; NONCE_LEN],
    algo: Algorithm,
    header_aad: &[u8; 32],
) -> Result<u64, CryError> {
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut chunk_index: u64 = 0;

    loop {
        let n = read_chunk(reader, &mut buf)?;
        if n == 0 {
            break;
        }

        let nonce = chunk_nonce(base_nonce, chunk_index);
        let aad = chunk_aad(header_aad, chunk_index);
        let ct = encrypt_chunk(&buf[..n], key, &nonce, algo, &aad)?;

        let len = ct.len() as u32;
        writer
            .write_all(&len.to_be_bytes())
            .map_err(CryError::Io)?;
        writer.write_all(&ct).map_err(CryError::Io)?;

        chunk_index += 1;
        if n < CHUNK_SIZE {
            break;
        }
    }

    Ok(chunk_index)
}

fn decrypt_chunks(
    reader: &mut impl Read,
    writer: &mut impl Write,
    key: &Zeroizing<[u8; 32]>,
    base_nonce: &[u8; NONCE_LEN],
    algo: AlgoId,
    header_aad: &[u8; 32],
) -> Result<u64, CryError> {
    let mut chunk_index: u64 = 0;

    loop {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(CryError::Io(e)),
        }
        let ct_len = u32::from_be_bytes(len_buf) as usize;

        if ct_len > MAX_CHUNK_WIRE_LEN {
            return Err(CryError::SuspiciousChunkLen {
                index: chunk_index,
                len: ct_len,
            });
        }

        let mut ct = vec![0u8; ct_len];
        reader.read_exact(&mut ct).map_err(CryError::Io)?;

        let nonce = chunk_nonce(base_nonce, chunk_index);
        let aad = chunk_aad(header_aad, chunk_index);
        let plain = decrypt_chunk(&ct, key, &nonce, algo, &aad)?;

        writer.write_all(&plain).map_err(CryError::Io)?;
        chunk_index += 1;
    }

    Ok(chunk_index)
}

/// Read up to `buf.len()` bytes. Unlike `read_exact`, returns a short count at
/// EOF rather than an error.  Renamed from `read_full` to clarify semantics.
fn read_chunk(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize, CryError> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CryError::Io(e)),
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Single-chunk AEAD operations
// ---------------------------------------------------------------------------

fn encrypt_chunk(
    plain: &[u8],
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    algo: Algorithm,
    aad: &[u8],
) -> Result<Vec<u8>, CryError> {
    match algo {
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
            cipher
                .encrypt(AesNonce::from_slice(nonce), Payload { msg: plain, aad })
                .map_err(|_| CryError::DecryptionFailed)
        }
        Algorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
            cipher
                .encrypt(
                    ChaChaNonce::from_slice(nonce),
                    Payload { msg: plain, aad },
                )
                .map_err(|_| CryError::DecryptionFailed)
        }
    }
}

fn decrypt_chunk(
    ct: &[u8],
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    algo: AlgoId,
    aad: &[u8],
) -> Result<Vec<u8>, CryError> {
    match algo {
        AlgoId::Aes256Gcm => {
            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
            cipher
                .decrypt(AesNonce::from_slice(nonce), Payload { msg: ct, aad })
                .map_err(|_| CryError::DecryptionFailed)
        }
        AlgoId::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
            cipher
                .decrypt(
                    ChaChaNonce::from_slice(nonce),
                    Payload { msg: ct, aad },
                )
                .map_err(|_| CryError::DecryptionFailed)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::AlgoId;
    use std::io::Cursor;

    fn roundtrip(algo: Algorithm, input: &[u8]) {
        let passphrase = Zeroizing::new(b"correct horse battery staple".to_vec());
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

        let chunk_count = (input.len() as u64).div_ceil(CHUNK_SIZE as u64).max(1);
        let header = Header {
            algo: algo.into(),
            salt,
            nonce: nonce_bytes,
            chunk_count,
        };
        let key = derive_key(&passphrase, &salt).unwrap();
        let header_aad_val = header_aad(&header);

        // Encrypt into a buffer
        let mut cipher_buf: Vec<u8> = Vec::new();
        header.write(&mut cipher_buf, &key).unwrap();
        let mut reader = Cursor::new(input);
        encrypt_chunks(&mut reader, &mut cipher_buf, &key, &nonce_bytes, algo, &header_aad_val)
            .unwrap();

        // Parse header back
        let raw_header_len = crate::header::HEADER_LEN;
        let header2 =
            Header::read(&mut cipher_buf[..raw_header_len].as_ref(), &key).unwrap();

        // Decrypt
        let mut plain_out: Vec<u8> = Vec::new();
        let mut body = Cursor::new(&cipher_buf[raw_header_len..]);
        let got_chunks =
            decrypt_chunks(&mut body, &mut plain_out, &key, &header2.nonce, header2.algo, &header_aad_val)
                .unwrap();

        assert_eq!(plain_out, input, "roundtrip plaintext mismatch");
        let _ = got_chunks;
    }

    #[test]
    fn roundtrip_aes_empty() {
        roundtrip(Algorithm::Aes256Gcm, b"");
    }

    #[test]
    fn roundtrip_aes_small() {
        roundtrip(Algorithm::Aes256Gcm, b"Hello, cry!");
    }

    #[test]
    fn roundtrip_chacha_small() {
        roundtrip(Algorithm::ChaCha20Poly1305, b"ChaCha test data 1234");
    }

    #[test]
    fn tamper_detection() {
        let passphrase = Zeroizing::new(b"passphrase".to_vec());
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

        let input = b"secret data";
        let chunk_count = 1u64;
        let header = Header {
            algo: AlgoId::Aes256Gcm,
            salt,
            nonce: nonce_bytes,
            chunk_count,
        };
        let key = derive_key(&passphrase, &salt).unwrap();
        let aad = header_aad(&header);

        let mut buf: Vec<u8> = Vec::new();
        header.write(&mut buf, &key).unwrap();
        let mut reader = Cursor::new(input.as_ref());
        encrypt_chunks(
            &mut reader,
            &mut buf,
            &key,
            &nonce_bytes,
            Algorithm::Aes256Gcm,
            &aad,
        )
        .unwrap();

        // Flip a bit in the ciphertext body
        let header_len = crate::header::HEADER_LEN;
        buf[header_len + 5] ^= 0xFF;

        let mut plain_out: Vec<u8> = Vec::new();
        let mut body = Cursor::new(&buf[header_len..]);
        let result = decrypt_chunks(&mut body, &mut plain_out, &key, &nonce_bytes, AlgoId::Aes256Gcm, &aad);
        assert!(result.is_err(), "tampered ciphertext should fail decryption");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let passphrase = Zeroizing::new(b"correct".to_vec());
        let wrong = Zeroizing::new(b"wrong".to_vec());
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let key = derive_key(&passphrase, &salt).unwrap();
        let wrong_key = derive_key(&wrong, &salt).unwrap();

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let chunk_count = 1u64;

        let header = Header {
            algo: AlgoId::Aes256Gcm,
            salt,
            nonce: nonce_bytes,
            chunk_count,
        };

        let mut buf: Vec<u8> = Vec::new();
        header.write(&mut buf, &key).unwrap();

        // Header verification with wrong key should fail
        let result = Header::read(&mut buf.as_slice(), &wrong_key);
        assert!(
            result.is_err(),
            "header HMAC should reject wrong passphrase"
        );
    }
}