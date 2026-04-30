//! Authenticated file header for cry encrypted files.
//!
//! Wire layout (all fields big-endian):
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │ Magic      4 bytes  "CRY\x01"  (catches wrong-file mistakes)   │
//! │ Algorithm  1 byte   AlgoId enum                                 │
//! │ Salt       16 bytes Argon2 salt (random per file)               │
//! │ Nonce      12 bytes AEAD nonce  (random per file)               │
//! └─────────────────────────────────────────────────────────────────┘
//!   Total: 33 bytes
//! ```
//!
//! The header is written before the ciphertext chunks and is NOT encrypted,
//! but the Argon2 salt and nonce are unpredictable random values.

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};

pub const MAGIC: &[u8; 4] = b"CRY\x01";
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
#[allow(dead_code)]
pub const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN; // 33

/// One-byte algorithm identifier stored in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlgoId {
    Aes256Gcm = 0x01,
    ChaCha20Poly1305 = 0x02,
}

impl AlgoId {
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(AlgoId::Aes256Gcm),
            0x02 => Ok(AlgoId::ChaCha20Poly1305),
            _ => bail!("Unknown algorithm identifier 0x{b:02x} in file header. \
                        Was this file created with a newer version of cry?"),
        }
    }
}

pub struct Header {
    pub algo: AlgoId,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    pub fn write(&self, w: &mut impl Write) -> Result<()> {
        w.write_all(MAGIC).context("write magic")?;
        w.write_all(&[self.algo as u8]).context("write algo")?;
        w.write_all(&self.salt).context("write salt")?;
        w.write_all(&self.nonce).context("write nonce")?;
        Ok(())
    }

    pub fn read(r: &mut impl Read) -> Result<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic).context("Failed to read file header — is this a cry file?")?;

        if &magic != MAGIC {
            bail!(
                "Not a cry encrypted file (bad magic bytes). \
                 Expected CRY\\x01, got {:?}.",
                magic
            );
        }

        let mut algo_byte = [0u8; 1];
        r.read_exact(&mut algo_byte).context("Failed to read algorithm byte")?;
        let algo = AlgoId::from_byte(algo_byte[0])?;

        let mut salt = [0u8; SALT_LEN];
        r.read_exact(&mut salt).context("Failed to read salt")?;

        let mut nonce = [0u8; NONCE_LEN];
        r.read_exact(&mut nonce).context("Failed to read nonce")?;

        Ok(Header { algo, salt, nonce })
    }
}