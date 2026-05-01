//! Authenticated file header for `cry` encrypted files.
//!
//! Wire layout (all fields big-endian):
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────────┐
//! │ Magic        4 bytes   "CRY\x02"  (version bump from v0.1)          │
//! │ Algorithm    1 byte    AlgoId enum                                   │
//! │ Salt        16 bytes   Argon2 salt (random per file)                 │
//! │ Nonce       12 bytes   AEAD base nonce (random per file)             │
//! │ ChunkCount   8 bytes   u64 big-endian — expected number of chunks    │
//! │ HeaderHMAC  32 bytes   HMAC-SHA256 over all preceding bytes          │
//! └──────────────────────────────────────────────────────────────────────┘
//!   Total: 73 bytes
//! ```
//!
//! The HMAC key is derived from the passphrase-derived key via a domain
//! separation constant, so header authentication is tied to the key.
//! An attacker who cannot guess the passphrase cannot forge a valid header.
//!
//! `ChunkCount` closes the truncation attack: the receiver checks that the
//! number of decrypted chunks matches the value committed in the header.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::CryError;

type HmacSha256 = Hmac<Sha256>;

pub const MAGIC: &[u8; 4] = b"CRY\x02";
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const HMAC_LEN: usize = 32;
/// 4 (magic) + 1 (algo) + 16 (salt) + 12 (nonce) + 8 (chunk_count) + 32 (hmac)
pub const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN + 8 + HMAC_LEN;

/// Domain-separation prefix used when deriving the header-HMAC sub-key.
const HMAC_DOMAIN: &[u8] = b"cry-header-hmac-v2";

// ---------------------------------------------------------------------------
// Algorithm identifier
// ---------------------------------------------------------------------------

/// One-byte algorithm identifier stored in the header.
/// Unifies what was previously a split between `Algorithm` (clap) and `AlgoId`
/// (header byte) — this single enum serves both roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlgoId {
    Aes256Gcm = 0x01,
    ChaCha20Poly1305 = 0x02,
}

impl AlgoId {
    pub fn from_byte(b: u8) -> Result<Self, CryError> {
        match b {
            0x01 => Ok(AlgoId::Aes256Gcm),
            0x02 => Ok(AlgoId::ChaCha20Poly1305),
            _ => Err(CryError::InvalidFormat(format!(
                "Unknown algorithm identifier 0x{b:02x} — was this file created with a newer \
                 version of cry?"
            ))),
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
// Header
// ---------------------------------------------------------------------------

pub struct Header {
    pub algo: AlgoId,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    /// Number of ciphertext chunks in the file body.
    /// Written during encryption; verified during decryption.
    pub chunk_count: u64,
}

impl Header {
    /// Serialize the header (without HMAC) into a byte buffer.
    fn pre_hmac_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_LEN - HMAC_LEN);
        buf.extend_from_slice(MAGIC);
        buf.push(self.algo as u8);
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.chunk_count.to_be_bytes());
        buf
    }

    /// Compute HMAC-SHA256 over the pre-HMAC header bytes using a
    /// domain-separated sub-key derived from `key`.
    fn compute_hmac(pre_hmac: &[u8], key: &[u8; 32]) -> [u8; HMAC_LEN] {
        // Sub-key: SHA-256(domain || key)
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(HMAC_DOMAIN);
        h.update(key);
        let sub_key: [u8; 32] = h.finalize().into();

        let mut mac =
            HmacSha256::new_from_slice(&sub_key).expect("HMAC-SHA256 accepts any key size");
        mac.update(pre_hmac);
        mac.finalize().into_bytes().into()
    }

    /// Write the fully authenticated header to `w`.
    pub fn write(&self, w: &mut impl std::io::Write, key: &[u8; 32]) -> Result<(), CryError> {
        let pre_hmac = self.pre_hmac_bytes();
        let hmac = Self::compute_hmac(&pre_hmac, key);
        w.write_all(&pre_hmac)?;
        w.write_all(&hmac)?;
        Ok(())
    }

    /// Read and authenticate the header from `r`.
    ///
    /// Returns `CryError::HeaderTampered` if the HMAC does not match —
    /// this catches both wrong-passphrase and active-tampering scenarios
    /// before any chunk decryption is attempted.
    pub fn read(r: &mut impl std::io::Read, key: &[u8; 32]) -> Result<Self, CryError> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)
            .map_err(|_| CryError::InvalidFormat("Failed to read magic bytes".into()))?;

        if &magic != MAGIC {
            return Err(CryError::InvalidFormat(format!(
                "Not a cry v2 encrypted file (bad magic {:?}). \
                 Files from cry v0.1 are not compatible — re-encrypt with the new version.",
                magic
            )));
        }

        let mut algo_byte = [0u8; 1];
        r.read_exact(&mut algo_byte)
            .map_err(|_| CryError::InvalidFormat("Failed to read algorithm byte".into()))?;
        let algo = AlgoId::from_byte(algo_byte[0])?;

        let mut salt = [0u8; SALT_LEN];
        r.read_exact(&mut salt)
            .map_err(|_| CryError::InvalidFormat("Failed to read salt".into()))?;

        let mut nonce = [0u8; NONCE_LEN];
        r.read_exact(&mut nonce)
            .map_err(|_| CryError::InvalidFormat("Failed to read nonce".into()))?;

        let mut count_buf = [0u8; 8];
        r.read_exact(&mut count_buf)
            .map_err(|_| CryError::InvalidFormat("Failed to read chunk count".into()))?;
        let chunk_count = u64::from_be_bytes(count_buf);

        let mut stored_hmac = [0u8; HMAC_LEN];
        r.read_exact(&mut stored_hmac)
            .map_err(|_| CryError::InvalidFormat("Failed to read header HMAC".into()))?;

        // Re-compute and verify the HMAC in constant time using HMAC::verify_slice.
        let header = Header { algo, salt, nonce, chunk_count };
        let pre_hmac = header.pre_hmac_bytes();

        // Build the same sub-key used in compute_hmac.
        use sha2::{Digest, Sha256 as Sha256Inner};
        let mut h = Sha256Inner::new();
        h.update(HMAC_DOMAIN);
        h.update(key);
        let sub_key: [u8; 32] = h.finalize().into();

        let mut mac =
            HmacSha256::new_from_slice(&sub_key).expect("HMAC-SHA256 accepts any key size");
        mac.update(&pre_hmac);
        mac.verify_slice(&stored_hmac)
            .map_err(|_| CryError::HeaderTampered)?;

        Ok(header)
    }
}