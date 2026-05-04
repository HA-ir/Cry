//! Streaming authenticated encryption / decryption.
//!
//! ## Security properties
//!
//! - **Authenticated header** — HMAC-SHA256 over magic + algo + salt + nonce +
//!   chunk_count, keyed by a domain-separated sub-key. Forgery requires the
//!   passphrase.
//!
//! - **AAD per chunk** — each chunk binds the header hash and its own index as
//!   Additional Authenticated Data. Chunk reordering, substitution, and
//!   cross-file splicing are detectable.
//!
//! - **Chunk count commitment** — stored in the header (covered by HMAC).
//!   Decryption fails if the file is truncated after any chunk boundary.
//!
//! - **Counter nonce** — per-chunk nonce is derived by treating the base nonce
//!   as a 96-bit big-endian integer and adding the chunk index. This is the
//!   standard GCM counter construction and avoids the fragility of XOR-based
//!   schemes.
//!
//! - **Atomic output** — writes to a `.tmp` sibling, renames on success. A
//!   failed run never leaves a partial or zero-length output file.
//!
//! - **`--force` guard** — encrypt and decrypt refuse to overwrite an existing
//!   output file unless `force` is true.
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
use crate::header::{Algorithm, Header, NONCE_LEN, SALT_LEN};
use crate::kdf::derive_key;

/// Chunk size for streaming encryption (1 MiB).
const CHUNK_SIZE: usize = 1024 * 1024;
/// Sanity cap: ciphertext + tag. A 1 MiB chunk + 16-byte tag = 1_048_592.
const MAX_CHUNK_WIRE_LEN: usize = CHUNK_SIZE + 64;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypt `plain_path` → `cipher_path` using `passphrase` and `algorithm`.
///
/// Refuses to overwrite `cipher_path` unless `force` is true.
/// Writes to a `.tmp` sibling file and renames atomically on success.
pub fn encrypt_file(
    plain_path: &Path,
    cipher_path: &Path,
    passphrase: &Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    force: bool,
) -> Result<(), CryError> {
    // Guard: don't silently overwrite existing output.
    if cipher_path.exists() && !force {
        return Err(CryError::FileExists(cipher_path.display().to_string()));
    }

    let plain_len = std::fs::metadata(plain_path)?.len();

    // Commit to the exact chunk count upfront.
    // Empty files produce 0 chunks — no special-casing needed.
    let chunk_count = plain_len.div_ceil(CHUNK_SIZE as u64);

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    eprint!("  Deriving key… ");
    std::io::stderr().flush().ok();
    let key = derive_key(passphrase.as_slice(), &salt)?;
    eprintln!("done.");

    let header = Header { algo: algorithm, salt, nonce: nonce_bytes, chunk_count };
    let header_aad = header_aad(&header);

    let tmp_path = cipher_path.with_extension("cry.tmp");

    let result = (|| -> Result<(), CryError> {
        let plain_file = std::fs::File::open(plain_path)?;
        let mut reader = BufReader::new(plain_file);

        let cipher_file = std::fs::File::create(&tmp_path)?;
        let mut writer = BufWriter::new(cipher_file);

        header.write(&mut writer, &key)?;

        let actual_chunks =
            encrypt_chunks(&mut reader, &mut writer, &key, &nonce_bytes, algorithm, &header_aad, chunk_count)?;

        writer.flush()?;

        // Verify our pre-computed count matches reality. Should never fire
        // unless the file was modified while we were reading it.
        if actual_chunks != chunk_count {
            return Err(CryError::Truncated {
                expected: chunk_count,
                got: actual_chunks,
            });
        }

        Ok(())
    })();

    match result {
        Ok(()) => {
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
/// Refuses to overwrite `plain_path` unless `force` is true.
/// Writes to a `.tmp` sibling and renames atomically on success.
pub fn decrypt_file(
    plain_path: &Path,
    cipher_path: &Path,
    passphrase: &Zeroizing<Vec<u8>>,
    force: bool,
) -> Result<(), CryError> {
    // Guard: don't silently overwrite existing output.
    if plain_path.exists() && !force {
        return Err(CryError::FileExists(plain_path.display().to_string()));
    }

    let cipher_file = std::fs::File::open(cipher_path)?;
    let cipher_len = cipher_file.metadata()?.len();
    let mut reader = BufReader::new(cipher_file);

    // We need the key to verify the header HMAC, but we need the salt from the
    // header to derive the key. We resolve this by reading the entire header
    // into a buffer first, extracting the salt, deriving the key, then parsing
    // and verifying the full header from the same buffer (not re-reading from
    // the stream). This avoids a double-read and is safe because BufReader does
    // not support seeking on arbitrary streams.
    use crate::header::HEADER_LEN;
    let mut raw_header = vec![0u8; HEADER_LEN];
    reader
        .read_exact(&mut raw_header)
        .map_err(|_| CryError::InvalidFormat("File too short to contain a valid header".into()))?;

    // Salt starts at offset 5: 4 bytes magic + 1 byte algo.
    const SALT_OFFSET: usize = 4 + 1;
    let salt: [u8; SALT_LEN] = raw_header[SALT_OFFSET..SALT_OFFSET + SALT_LEN]
        .try_into()
        .unwrap();

    eprint!("  Deriving key… ");
    std::io::stderr().flush().ok();
    let key = derive_key(passphrase.as_slice(), &salt)?;
    eprintln!("done.");

    // Parse and HMAC-verify the full header from the buffered bytes.
    let header = Header::read(&mut raw_header.as_slice(), &key)?;

    eprintln!("  Algorithm : {} (from file header)", header.algo);

    let header_aad = header_aad(&header);

    let tmp_path = plain_path.with_extension("plain.tmp");

    let result = (|| -> Result<u64, CryError> {
        let plain_file = std::fs::File::create(&tmp_path)?;
        let mut writer = BufWriter::new(plain_file);

        let actual_chunks = decrypt_chunks(
            &mut reader,
            &mut writer,
            &key,
            &header.nonce,
            header.algo,
            &header_aad,
            header.chunk_count,
        )?;

        writer.flush()?;

        if actual_chunks != header.chunk_count {
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

/// Compute a 32-byte value that binds every chunk to this specific file.
///
/// AAD = SHA-256(magic || algo || salt || nonce || chunk_count)
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

/// Derive a per-chunk nonce using the standard counter construction:
/// treat the 12-byte base nonce as a 96-bit big-endian integer and add
/// the chunk index. This is the same construction used by TLS 1.3 and
/// is robust against any base-nonce bit pattern.
fn chunk_nonce(base: &[u8; NONCE_LEN], index: u64) -> [u8; NONCE_LEN] {
    // Load the full 96-bit nonce as two parts: top 4 bytes, bottom 8 bytes.
    let hi = u32::from_be_bytes(base[0..4].try_into().unwrap());
    let lo = u64::from_be_bytes(base[4..12].try_into().unwrap());

    // Add the index to the 96-bit value with carry.
    let (new_lo, carry) = lo.overflowing_add(index);
    let new_hi = hi.wrapping_add(carry as u32);

    let mut n = [0u8; NONCE_LEN];
    n[0..4].copy_from_slice(&new_hi.to_be_bytes());
    n[4..12].copy_from_slice(&new_lo.to_be_bytes());
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
    total_chunks: u64,
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
        writer.write_all(&len.to_be_bytes()).map_err(CryError::Io)?;
        writer.write_all(&ct).map_err(CryError::Io)?;

        chunk_index += 1;

        // Report progress for multi-chunk files.
        if total_chunks > 1 {
            eprint!("\r  Progress  : chunk {}/{}", chunk_index, total_chunks);
            std::io::stderr().flush().ok();
        }

        if n < CHUNK_SIZE {
            break;
        }
    }

    if total_chunks > 1 {
        eprintln!(); // newline after progress line
    }

    Ok(chunk_index)
}

fn decrypt_chunks(
    reader: &mut impl Read,
    writer: &mut impl Write,
    key: &Zeroizing<[u8; 32]>,
    base_nonce: &[u8; NONCE_LEN],
    algo: Algorithm,
    header_aad: &[u8; 32],
    total_chunks: u64,
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

        if total_chunks > 1 {
            eprint!("\r  Progress  : chunk {}/{}", chunk_index, total_chunks);
            std::io::stderr().flush().ok();
        }
    }

    if total_chunks > 1 {
        eprintln!();
    }

    Ok(chunk_index)
}

/// Read up to `buf.len()` bytes, returning a short count at EOF.
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
                .map_err(|_| CryError::EncryptionFailed)
        }
        Algorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
            cipher
                .encrypt(ChaChaNonce::from_slice(nonce), Payload { msg: plain, aad })
                .map_err(|_| CryError::EncryptionFailed)
        }
    }
}

fn decrypt_chunk(
    ct: &[u8],
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    algo: Algorithm,
    aad: &[u8],
) -> Result<Vec<u8>, CryError> {
    match algo {
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
            cipher
                .decrypt(AesNonce::from_slice(nonce), Payload { msg: ct, aad })
                .map_err(|_| CryError::DecryptionFailed)
        }
        Algorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
            cipher
                .decrypt(ChaChaNonce::from_slice(nonce), Payload { msg: ct, aad })
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
    use crate::header::Algorithm;
    use std::io::Cursor;

    fn make_key_and_header(algo: Algorithm, input: &[u8]) -> (Zeroizing<[u8; 32]>, Header, [u8; 32]) {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

        let chunk_count = (input.len() as u64).div_ceil(CHUNK_SIZE as u64);
        let header = Header { algo, salt, nonce: nonce_bytes, chunk_count };
        let key = derive_key(b"correct horse battery staple", &salt).unwrap();
        let aad = header_aad(&header);
        (key, header, aad)
    }

    fn roundtrip(algo: Algorithm, input: &[u8]) {
        let (key, header, aad) = make_key_and_header(algo, input);
        let nonce = header.nonce;
        let chunk_count = header.chunk_count;

        let mut cipher_buf: Vec<u8> = Vec::new();
        header.write(&mut cipher_buf, &key).unwrap();
        encrypt_chunks(
            &mut Cursor::new(input),
            &mut cipher_buf,
            &key,
            &nonce,
            algo,
            &aad,
            chunk_count,
        )
        .unwrap();

        let raw_header_len = crate::header::HEADER_LEN;
        let header2 = Header::read(&mut cipher_buf[..raw_header_len].as_ref(), &key).unwrap();

        let mut plain_out: Vec<u8> = Vec::new();
        decrypt_chunks(
            &mut Cursor::new(&cipher_buf[raw_header_len..]),
            &mut plain_out,
            &key,
            &header2.nonce,
            header2.algo,
            &aad,
            header2.chunk_count,
        )
        .unwrap();

        assert_eq!(plain_out, input, "roundtrip plaintext mismatch");
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
    fn roundtrip_aes_multi_chunk() {
        // 2.5 MiB — forces 3 chunks
        let data = vec![0xABu8; (CHUNK_SIZE * 2) + (CHUNK_SIZE / 2)];
        roundtrip(Algorithm::Aes256Gcm, &data);
    }

    #[test]
    fn roundtrip_chacha_multi_chunk() {
        let data = vec![0x42u8; CHUNK_SIZE + 1];
        roundtrip(Algorithm::ChaCha20Poly1305, &data);
    }

    #[test]
    fn nonce_counter_no_collision() {
        // Verify chunk 0 and chunk 1 produce distinct nonces for any base nonce,
        // including the all-zeros case that XOR would handle poorly.
        let base = [0u8; NONCE_LEN];
        assert_ne!(chunk_nonce(&base, 0), chunk_nonce(&base, 1));

        let base2 = [0xFF; NONCE_LEN];
        assert_ne!(chunk_nonce(&base2, 0), chunk_nonce(&base2, 1));
    }

    #[test]
    fn tamper_detection() {
        let (key, header, aad) = make_key_and_header(Algorithm::Aes256Gcm, b"secret data");
        let nonce = header.nonce;
        let chunk_count = header.chunk_count;

        let mut buf: Vec<u8> = Vec::new();
        header.write(&mut buf, &key).unwrap();
        encrypt_chunks(
            &mut Cursor::new(b"secret data".as_ref()),
            &mut buf,
            &key,
            &nonce,
            Algorithm::Aes256Gcm,
            &aad,
            chunk_count,
        )
        .unwrap();

        // Flip a bit in the ciphertext body.
        let header_len = crate::header::HEADER_LEN;
        buf[header_len + 5] ^= 0xFF;

        let mut plain_out: Vec<u8> = Vec::new();
        let result = decrypt_chunks(
            &mut Cursor::new(&buf[header_len..]),
            &mut plain_out,
            &key,
            &nonce,
            Algorithm::Aes256Gcm,
            &aad,
            chunk_count,
        );
        assert!(result.is_err(), "tampered ciphertext should fail decryption");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let key = derive_key(b"correct", &salt).unwrap();
        let wrong_key = derive_key(b"wrong", &salt).unwrap();

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

        let header = Header {
            algo: Algorithm::Aes256Gcm,
            salt,
            nonce: nonce_bytes,
            chunk_count: 1,
        };

        let mut buf: Vec<u8> = Vec::new();
        header.write(&mut buf, &key).unwrap();

        let result = Header::read(&mut buf.as_slice(), &wrong_key);
        assert!(result.is_err(), "header HMAC should reject wrong passphrase");
    }
}