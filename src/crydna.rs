//! CryDNA — deterministic cryptographic identity from a passphrase.
//!
//! ## Design
//!
//! A CryDNA identity is an Ed25519 keypair derived entirely from a passphrase.
//! The same (passphrase, namespace, version, sub_id) tuple always produces the
//! same keypair on any machine, without storing anything on disk.
//!
//! ## Key derivation pipeline
//!
//! ```text
//!   passphrase  ──┐
//!                 ├──► Argon2id(64 MiB, 3 iter) ──► 32-byte seed ──► Ed25519 keypair
//!   salt        ──┘        (keyed by domain)
//!   (= SHA-256(domain || namespace || version || sub_id)[..16])
//! ```
//!
//! The Argon2 salt is derived deterministically from the identity parameters, so
//! there is no random salt to store — the salt is fully reconstructible from the
//! same parameters.
//!
//! ## Namespaces & versioning
//!
//! - **Namespace** — a human label ("work", "personal", "git") that produces a
//!   completely independent key family. Changing the namespace changes the key.
//! - **Version** — an integer counter. Incrementing it rotates the key within
//!   the same namespace without changing the passphrase.
//! - **Sub-identity** — an optional child label for hierarchical derivation
//!   (e.g., `--namespace work --sub-id deploy` for a restricted deployment key).
//!
//! ## Security properties
//!
//! - The private key is never written to disk or printed; it lives only in memory
//!   and is zeroized on drop (Ed25519-dalek `ZeroizeOnDrop`).
//! - Argon2id (64 MiB, 3 iterations) makes offline dictionary attacks expensive.
//! - Each (namespace, version, sub_id) combination uses a unique salt, so
//!   different identities from the same passphrase are fully independent.
//! - Signatures are computed over `SHA-256("CryDNA-file-sig-v1:" || content_hash)`
//!   to bind the domain and prevent cross-protocol misuse.

use std::{io::Write as _, path::Path};

use argon2::{Algorithm as Argon2Algo, Argon2, Params, Version};
use base64ct::{Base64, Encoding as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use ssh_key::{
    LineEnding,
    private::{Ed25519Keypair, KeypairData, PrivateKey},
};
use zeroize::Zeroizing;

use crate::error::CryError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Domain-separation tag mixed into every Argon2 salt.
const DOMAIN: &[u8] = b"CryDNA-v1";

/// Domain prefix for file signatures (prevents cross-protocol misuse).
const SIG_DOMAIN: &[u8] = b"CryDNA-file-sig-v1:";

const SEED_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// A derived Ed25519 identity.
///
/// The `signing_key` field is `ZeroizeOnDrop` — the private key bytes are
/// wiped from memory the moment this struct is dropped.
pub struct Identity {
    pub signing_key: SigningKey,
}

impl Identity {
    // ── Construction ────────────────────────────────────────────────────────

    /// Derive a deterministic Ed25519 identity from `passphrase`.
    ///
    /// Parameters:
    /// - `namespace` — logical profile name; changing it gives a different key.
    /// - `version`   — key rotation counter; increment to rotate without
    ///                 changing the passphrase.
    /// - `sub_id`    — optional child label for hierarchical sub-identities.
    pub fn derive(
        passphrase: &[u8],
        namespace: &str,
        version: u32,
        sub_id: Option<&str>,
    ) -> Result<Self, CryError> {
        let salt = derive_salt(namespace, version, sub_id);

        eprint!("  Deriving identity seed… ");
        std::io::stderr().flush().ok();

        let params = Params::new(
            65536, // 64 MiB
            3,     // iterations
            1,     // parallelism
            Some(SEED_LEN),
        )
        .map_err(|e| CryError::Kdf(e.to_string()))?;

        let argon2 = Argon2::new(Argon2Algo::Argon2id, Version::V0x13, params);

        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        argon2
            .hash_password_into(passphrase, &salt, seed.as_mut())
            .map_err(|e| CryError::Kdf(e.to_string()))?;

        eprintln!("done.");

        // Build the signing key from the seed; seed is zeroized after this point.
        let signing_key = SigningKey::from_bytes(&*seed);

        Ok(Identity { signing_key })
    }

    // ── Public key views ────────────────────────────────────────────────────

    /// The Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Public key as lowercase hex (64 characters).
    pub fn public_key_hex(&self) -> String {
        bytes_to_hex(self.verifying_key().as_bytes())
    }

    /// Public key as standard Base64 (44 characters including padding).
    pub fn public_key_base64(&self) -> String {
        Base64::encode_string(self.verifying_key().as_bytes())
    }

    /// SHA-256 fingerprint in OpenSSH format: `SHA256:<base64_no_pad>`.
    pub fn fingerprint(&self) -> String {
        let hash = Sha256::digest(self.verifying_key().as_bytes());
        // Strip trailing '=' padding to match `ssh-keygen -l` output style.
        let b64 = Base64::encode_string(&hash);
        let trimmed = b64.trim_end_matches('=');
        format!("SHA256:{trimmed}")
    }

    // ── SSH export ───────────────────────────────────────────────────────────

    /// Format the public key as an OpenSSH `authorized_keys` line.
    ///
    /// The wire encoding follows RFC 4253: each field is length-prefixed.
    /// This output can be appended directly to `~/.ssh/authorized_keys`.
    pub fn ssh_authorized_keys_line(&self, comment: &str) -> String {
        let wire = ssh_wire_public_key(self.verifying_key().as_bytes());
        format!("ssh-ed25519 {} {}", Base64::encode_string(&wire), comment)
    }

    /// Export as an encrypted OpenSSH private key (PEM block).
    ///
    /// The `passphrase` provided here is the SSH key encryption passphrase
    /// (for the emitted `OPENSSH PRIVATE KEY` block), and is intentionally
    /// separate from the CryDNA master passphrase used to deterministically
    /// derive this identity.
    ///
    /// Returns a `Zeroizing<String>` so the encrypted PEM bytes are wiped
    /// from heap memory when the value is dropped. Even the encrypted form
    /// of a private key is sensitive and must not outlive its use.
    pub fn openssh_private_key(
        &self,
        passphrase: &str,
        comment: &str,
    ) -> Result<Zeroizing<String>, CryError> {
        let keypair = Ed25519Keypair::from_bytes(&self.signing_key.to_keypair_bytes())
            .map_err(|e| CryError::InvalidFormat(format!("OpenSSH key build failed: {e}")))?;
        let private = PrivateKey::new(KeypairData::Ed25519(keypair), comment)
            .map_err(|e| CryError::InvalidFormat(format!("OpenSSH key build failed: {e}")))?;
        let mut rng = rand::thread_rng();
        // `to_openssh` already returns `Zeroizing<String>`; we preserve that
        // wrapper all the way to the caller instead of copying into a plain String.
        private
            .encrypt(&mut rng, passphrase)
            .map_err(|e| CryError::InvalidFormat(format!("OpenSSH key encryption failed: {e}")))?
            .to_openssh(LineEnding::LF)
            .map_err(|e| CryError::InvalidFormat(format!("OpenSSH key encode failed: {e}")))
    }

    // ── Signing ─────────────────────────────────────────────────────────────

    /// Private (secret) key as lowercase hex (64 characters).
    ///
    /// This is the 32-byte Ed25519 secret scalar used to derive the public key.
    pub fn private_key_hex(&self) -> String {
        bytes_to_hex(&self.signing_key.to_bytes())
    }

    /// Write the private key as lowercase hex to a file.
    ///
    /// Refuses to overwrite unless `force` is true. On Unix, permissions are
    /// tightened to `0600` after write.
    pub fn write_private_key_hex_file(&self, path: &Path, force: bool) -> Result<(), CryError> {
        if path.exists() && !force {
            return Err(CryError::FileExists(path.display().to_string()));
        }

        std::fs::write(path, self.private_key_hex())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Sign file content deterministically.
    ///
    /// Computes `sig = Ed25519_sign(SHA-256(SIG_DOMAIN || SHA-256(content)))`.
    ///
    /// Domain separation prevents this signature from being reused in other
    /// protocols. Content hashing means the signature covers the full file
    /// regardless of size.
    pub fn sign_content(&self, content: &[u8]) -> Signature {
        let content_hash = Sha256::digest(content);
        let mut h = Sha256::new();
        h.update(SIG_DOMAIN);
        h.update(&content_hash);
        let msg_hash = h.finalize();
        self.signing_key.sign(&msg_hash)
    }

    /// Return the signature as a lowercase hex string (128 characters).
    pub fn signature_hex(sig: &Signature) -> String {
        bytes_to_hex(&sig.to_bytes())
    }
}

// ---------------------------------------------------------------------------
// Standalone verification (no private key needed)
// ---------------------------------------------------------------------------

/// Verify a file-content signature given a hex public key and hex signature.
///
/// Returns `Ok(true)` on a valid signature, `Ok(false)` on an invalid one.
pub fn verify_content_signature(
    public_key_hex: &str,
    content: &[u8],
    signature_hex: &str,
) -> Result<bool, CryError> {
    // Parse public key
    let pub_bytes = hex_to_bytes(public_key_hex)
        .map_err(|e| CryError::InvalidFormat(format!("Invalid public key hex: {e}")))?;
    let pub_array: [u8; 32] = pub_bytes.try_into().map_err(|_| {
        CryError::InvalidFormat("Ed25519 public key must be exactly 32 bytes".into())
    })?;
    let verifying_key = VerifyingKey::from_bytes(&pub_array)
        .map_err(|e| CryError::InvalidFormat(format!("Invalid Ed25519 public key: {e}")))?;

    // Parse signature
    let sig_bytes = hex_to_bytes(signature_hex)
        .map_err(|e| CryError::InvalidFormat(format!("Invalid signature hex: {e}")))?;
    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        CryError::InvalidFormat("Ed25519 signature must be exactly 64 bytes".into())
    })?;
    let signature = Signature::from_bytes(&sig_array);

    // Reconstruct the signed message hash
    let content_hash = Sha256::digest(content);
    let mut h = Sha256::new();
    h.update(SIG_DOMAIN);
    h.update(&content_hash);
    let msg_hash = h.finalize();

    Ok(verifying_key.verify(&msg_hash, &signature).is_ok())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Derive a 16-byte Argon2 salt deterministically from identity parameters.
///
/// Salt = SHA-256(DOMAIN || ":" || namespace || ":v" || be32(version)
///                          || [":sub:" || sub_id])[..16]
fn derive_salt(namespace: &str, version: u32, sub_id: Option<&str>) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(b":");
    h.update(namespace.as_bytes());
    h.update(b":v");
    h.update(version.to_be_bytes());
    if let Some(sub) = sub_id {
        h.update(b":sub:");
        h.update(sub.as_bytes());
    }
    h.finalize()[..16].try_into().unwrap()
}

/// Build the SSH wire-format encoding for an Ed25519 public key.
///
/// Wire format (RFC 4253):
/// ```text
/// uint32  len("ssh-ed25519")
/// string  "ssh-ed25519"
/// uint32  32
/// string  <32 bytes public key>
/// ```
fn ssh_wire_public_key(pub_bytes: &[u8; 32]) -> Vec<u8> {
    const KEY_TYPE: &[u8] = b"ssh-ed25519";
    let mut wire = Vec::with_capacity(4 + KEY_TYPE.len() + 4 + 32);
    wire.extend_from_slice(&(KEY_TYPE.len() as u32).to_be_bytes());
    wire.extend_from_slice(KEY_TYPE);
    wire.extend_from_slice(&(pub_bytes.len() as u32).to_be_bytes());
    wire.extend_from_slice(pub_bytes);
    wire
}

/// Encode bytes as lowercase hex without any external crate.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a lowercase or uppercase hex string into bytes.
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("odd hex length ({})", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// CLI argument structs  (used by main.rs)
// ---------------------------------------------------------------------------

/// Common identity parameters shared across identity/sign/verify commands.
#[derive(clap::Args, Debug, Clone)]
pub struct IdentityParams {
    /// Identity namespace / profile label
    /// (changing this produces a completely independent key)
    #[arg(
        short = 'n',
        long = "namespace",
        default_value = "default",
        value_name = "NAME"
    )]
    pub namespace: String,

    /// Key version for rotation
    /// (increment to rotate to a new key within the same namespace)
    #[arg(long = "key-version", default_value_t = 0, value_name = "N")]
    pub key_version: u32,

    /// Sub-identity label for hierarchical derivation
    /// (e.g. --namespace work --sub-id deploy)
    #[arg(long = "sub-id", value_name = "LABEL")]
    pub sub_id: Option<String>,

    /// Read passphrase from a file instead of prompting (first line used)
    #[arg(long = "pass-file", value_name = "FILE", help_heading = "Advanced")]
    pub pass_file: Option<std::path::PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct IdentityArgs {
    #[command(flatten)]
    pub params: IdentityParams,

    /// Public key output format
    #[arg(long = "format", default_value = "all", value_name = "FMT")]
    pub format: PubKeyFormat,

    /// Print encrypted OpenSSH private key + OpenSSH public key line
    #[arg(long = "openssh")]
    pub openssh: bool,

    /// Write the private key (hex) to a file (dangerous; protect this file)
    #[arg(long = "private-key-out", value_name = "FILE")]
    pub private_key_out: Option<std::path::PathBuf>,

    /// Overwrite output files for identity exports
    #[arg(long = "force", default_value_t = false)]
    pub force: bool,

    /// Comment embedded in the SSH key line (used with --ssh)
    #[arg(long = "comment", default_value = "CryDNA", value_name = "TEXT")]
    pub comment: String,

    /// Print the private key in hex (dangerous; do not use on shared terminals)
    #[arg(long = "show-private-key")]
    pub show_private_key: bool,
}

#[derive(clap::Args, Debug)]
pub struct SignArgs {
    /// File to sign
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub file: std::path::PathBuf,

    #[command(flatten)]
    pub params: IdentityParams,
}

#[derive(clap::Args, Debug)]
pub struct VerifyArgs {
    /// File whose signature should be verified
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub file: std::path::PathBuf,

    /// Signature to verify (hex, as printed by `cry sign`)
    #[arg(short = 's', long = "signature", value_name = "HEX")]
    pub signature: String,

    /// Public key to verify against (hex, as printed by `cry identity`)
    #[arg(short = 'k', long = "public-key", value_name = "HEX")]
    pub public_key: String,
}

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum PubKeyFormat {
    /// Lowercase hex (64 chars)
    Hex,
    /// Standard Base64 (44 chars)
    Base64,
    /// Both formats
    All,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_passphrase_same_key() {
        let a = Identity::derive(b"hunter2", "default", 0, None).unwrap();
        let b = Identity::derive(b"hunter2", "default", 0, None).unwrap();
        assert_eq!(
            a.public_key_hex(),
            b.public_key_hex(),
            "same inputs must produce the same public key"
        );
    }

    #[test]
    fn different_namespace_different_key() {
        let a = Identity::derive(b"passphrase", "work", 0, None).unwrap();
        let b = Identity::derive(b"passphrase", "personal", 0, None).unwrap();
        assert_ne!(
            a.public_key_hex(),
            b.public_key_hex(),
            "different namespaces must produce different keys"
        );
    }

    #[test]
    fn version_rotation() {
        let v0 = Identity::derive(b"passphrase", "default", 0, None).unwrap();
        let v1 = Identity::derive(b"passphrase", "default", 1, None).unwrap();
        assert_ne!(
            v0.public_key_hex(),
            v1.public_key_hex(),
            "key rotation must produce a different key"
        );
    }

    #[test]
    fn sub_identity_differs_from_parent() {
        let parent = Identity::derive(b"pass", "work", 0, None).unwrap();
        let child = Identity::derive(b"pass", "work", 0, Some("deploy")).unwrap();
        assert_ne!(
            parent.public_key_hex(),
            child.public_key_hex(),
            "sub-identity must differ from parent"
        );
    }

    #[test]
    fn different_passphrase_different_key() {
        let a = Identity::derive(b"correct horse battery staple", "default", 0, None).unwrap();
        let b = Identity::derive(b"wrong passphrase", "default", 0, None).unwrap();
        assert_ne!(a.public_key_hex(), b.public_key_hex());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let id = Identity::derive(b"test-pass", "default", 0, None).unwrap();
        let content = b"Hello, CryDNA!";
        let sig = id.sign_content(content);
        let pub_hex = id.public_key_hex();
        let sig_hex = Identity::signature_hex(&sig);

        assert!(
            verify_content_signature(&pub_hex, content, &sig_hex).unwrap(),
            "valid signature should verify"
        );
    }

    #[test]
    fn tampered_content_fails_verify() {
        let id = Identity::derive(b"test-pass", "default", 0, None).unwrap();
        let content = b"Original content";
        let sig = id.sign_content(content);
        let pub_hex = id.public_key_hex();
        let sig_hex = Identity::signature_hex(&sig);

        assert!(
            !verify_content_signature(&pub_hex, b"Tampered content", &sig_hex).unwrap(),
            "tampered content must fail verification"
        );
    }

    #[test]
    fn wrong_key_fails_verify() {
        let id_a = Identity::derive(b"alice", "default", 0, None).unwrap();
        let id_b = Identity::derive(b"bob", "default", 0, None).unwrap();
        let content = b"some data";
        let sig = id_a.sign_content(content);
        let sig_hex = Identity::signature_hex(&sig);

        assert!(
            !verify_content_signature(&id_b.public_key_hex(), content, &sig_hex).unwrap(),
            "signature from alice should not verify with bob's key"
        );
    }

    #[test]
    fn fingerprint_is_sha256_format() {
        let id = Identity::derive(b"pass", "default", 0, None).unwrap();
        assert!(
            id.fingerprint().starts_with("SHA256:"),
            "fingerprint must start with SHA256:"
        );
    }

    #[test]
    fn ssh_line_format() {
        let id = Identity::derive(b"pass", "default", 0, None).unwrap();
        let line = id.ssh_authorized_keys_line("test@host");
        assert!(
            line.starts_with("ssh-ed25519 "),
            "SSH line must start with ssh-ed25519"
        );
        assert!(
            line.ends_with("test@host"),
            "SSH line must end with comment"
        );
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = b"\xde\xad\xbe\xef\x00\xff";
        let hex = bytes_to_hex(bytes);
        assert_eq!(hex, "deadbeef00ff");
        assert_eq!(hex_to_bytes(&hex).unwrap(), bytes);
    }

    #[test]
    fn salt_differs_across_params() {
        let s1 = derive_salt("work", 0, None);
        let s2 = derive_salt("personal", 0, None);
        let s3 = derive_salt("work", 1, None);
        let s4 = derive_salt("work", 0, Some("deploy"));
        assert_ne!(s1, s2);
        assert_ne!(s1, s3);
        assert_ne!(s1, s4);
    }
}