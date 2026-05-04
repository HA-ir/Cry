//! `cry` — a fast, minimal CLI cryptography tool.
//!
//! Supported algorithms: AES-256-GCM, ChaCha20-Poly1305
//! Key derivation: Argon2id (64 MiB, 3 iterations)

mod bench;
mod cipher;
mod error;
mod header;
mod kdf;
mod keygen;

use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::{CommandFactory, Parser};
use zeroize::Zeroizing;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use cipher::{decrypt_file, encrypt_file};
use error::CryError;
use header::Algorithm;
use kdf::derive_key;
use rand::RngCore;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Banner / formatting helpers
// ---------------------------------------------------------------------------

fn banner() {
    let ver = env!("CARGO_PKG_VERSION");
    eprintln!("\n  cry 🔐  \x1b[2mv{ver}\x1b[0m\n");
}

fn section(icon: &str, label: &str, value: &str) {
    eprintln!("  {}  \x1b[2m{:<12}\x1b[0m  {}", icon, label, value);
}

fn divider() {
    eprintln!("  \x1b[2m{}\x1b[0m", "─".repeat(48));
}

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// cry — encrypt and decrypt files with AES-256-GCM or ChaCha20-Poly1305
#[derive(Parser, Debug)]
#[command(
    name = "cry",
    version = env!("CARGO_PKG_VERSION"),
    about = "Encrypt and decrypt files — passphrase-protected, authenticated",
    after_help = concat!(
        "\x1b[2mExamples:\x1b[0m\n",
        "  cry encrypt -p secret.txt -c secret.cry\n",
        "  cry encrypt -p secret.txt -c secret.cry -a chacha20poly1305\n",
        "  cry decrypt -c secret.cry -p recovered.txt\n",
        "  cry decrypt -c secret.cry -p recovered.txt --force\n",
        "  cry keygen  -o my.key\n",
    )
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Encrypt a plaintext file
    #[command(name = "encrypt", alias = "-en", alias = "en")]
    Encrypt(EncryptArgs),

    /// Decrypt an encrypted file (algorithm detected from header)
    #[command(name = "decrypt", alias = "-de", alias = "de")]
    Decrypt(DecryptArgs),

    /// Generate a cryptographically secure random key file
    #[command(name = "keygen", alias = "-kg", alias = "kg")]
    Keygen(KeygenArgs),

    /// Run quick crypto benchmarks
    #[command(name = "bench")]
    Bench(BenchArgs),
}

// ── Encrypt ───────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
struct EncryptArgs {
    /// Plaintext input file
    #[arg(short = 'p', long = "plain", value_name = "FILE")]
    plain: PathBuf,

    /// Encrypted output file
    #[arg(short = 'c', long = "cipher", value_name = "FILE")]
    cipher: PathBuf,

    /// Encryption algorithm
    #[arg(
        short = 'a',
        long = "algorithm",
        value_name = "ALGO",
        default_value = "aes256gcm"
    )]
    algorithm: Algorithm,

    /// Overwrite the output file if it already exists
    #[arg(long = "force", default_value_t = false)]
    force: bool,

    /// Read passphrase from a file (first line used; useful in containers/CI)
    #[arg(long = "pass-file", value_name = "FILE", help_heading = "Advanced")]
    pass_file: Option<PathBuf>,
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
struct DecryptArgs {
    /// Encrypted input file
    #[arg(short = 'c', long = "cipher", value_name = "FILE")]
    cipher: PathBuf,

    /// Plaintext output file
    #[arg(short = 'p', long = "plain", value_name = "FILE")]
    plain: PathBuf,

    /// Overwrite the output file if it already exists
    #[arg(long = "force", default_value_t = false)]
    force: bool,

    /// Read passphrase from a file (first line used; useful in containers/CI)
    #[arg(long = "pass-file", value_name = "FILE", help_heading = "Advanced")]
    pass_file: Option<PathBuf>,
}

// ── Keygen ────────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
struct KeygenArgs {
    /// Where to write the generated key
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: PathBuf,

    /// Overwrite the output file if it already exists
    #[arg(long = "force", default_value_t = false)]
    force: bool,
}

#[derive(clap::Args, Debug)]
struct BenchArgs {
    /// Number of MiB to process per benchmark run
    #[arg(long = "size-mib", default_value_t = 64)]
    size_mib: usize,

    /// Number of Argon2id derivations to time
    #[arg(long = "kdf-runs", default_value_t = 3)]
    kdf_runs: u32,
}
// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    let Some(command) = cli.command else {
        Cli::command().print_help().unwrap();
        eprintln!();
        return;
    };

    banner();

    let result: Result<(), CryError> = match command {
        Command::Encrypt(args) => {
            eprintln!(
                "  🔒  \x1b[1mEncrypting\x1b[0m  {} \x1b[2m→\x1b[0m {}",
                args.plain.display(),
                args.cipher.display()
            );
            section("⚙", "Algorithm", &args.algorithm.to_string());
            section("🔑", "KDF", "Argon2id  (64 MiB · 3 iter · 1 thread)");
            divider();

            read_passphrase(args.pass_file.as_deref(), true).and_then(|p| {
                encrypt_file(&args.plain, &args.cipher, &p, args.algorithm, args.force)
            })
        }

        Command::Decrypt(args) => {
            eprintln!(
                "  🔓  \x1b[1mDecrypting\x1b[0m  {} \x1b[2m→\x1b[0m {}",
                args.cipher.display(),
                args.plain.display()
            );
            section("🔑", "KDF", "Argon2id  (64 MiB · 3 iter · 1 thread)");
            divider();

            read_passphrase(args.pass_file.as_deref(), false)
                .and_then(|p| decrypt_file(&args.plain, &args.cipher, &p, args.force))
        }

        Command::Keygen(args) => {
            eprintln!(
                "  🎲  \x1b[1mGenerating key\x1b[0m  \x1b[2m→\x1b[0m {}",
                args.output.display()
            );
            divider();
            keygen::generate_key(&args.output, args.force)
        }

        Command::Bench(args) => bench::run_bench(args),
    };

    eprintln!();
    match result {
        Ok(()) => eprintln!("  \x1b[32m✔\x1b[0m  Done."),
        Err(e) => {
            eprintln!("  \x1b[31m✘\x1b[0m  {e}");
            std::process::exit(1);
        }
    }
    eprintln!();
}

// ---------------------------------------------------------------------------
// Passphrase helpers
// ---------------------------------------------------------------------------

/// Read a passphrase from (in priority order):
///   1. a file (`--pass-file PATH`, first line)
///   2. an interactive terminal prompt (with optional confirmation)
///
/// Status output goes to stderr; stdout stays clean for piping.
/// Returns `Zeroizing<Vec<u8>>` so the bytes are wiped on drop.
///
/// Environment variables are not supported as a passphrase source: they are
/// visible via `/proc/<pid>/environ`, `ps`, and child-process inheritance.
/// Use `--pass-file` with a mode-0600 file, or prompt interactively.
fn read_passphrase(
    pass_file: Option<&Path>,
    confirm: bool,
) -> Result<Zeroizing<Vec<u8>>, CryError> {
    // 1. Passphrase file
    if let Some(path) = pass_file {
        let contents = std::fs::read_to_string(path)?;
        let first_line = contents.lines().next().unwrap_or("").to_string();
        if first_line.is_empty() {
            return Err(CryError::EmptyPassphrase);
        }
        return Ok(Zeroizing::new(first_line.into_bytes()));
    }

    // 2. Interactive prompt (stderr; stdout stays clean)
    let pass = Zeroizing::new(rpassword::prompt_password("  Passphrase : ").map_err(CryError::Io)?);

    if pass.is_empty() {
        return Err(CryError::EmptyPassphrase);
    }

    if confirm {
        let confirm_pass =
            Zeroizing::new(rpassword::prompt_password("  Confirm    : ").map_err(CryError::Io)?);
        if *pass != *confirm_pass {
            return Err(CryError::PassphraseMismatch);
        }
    }

    Ok(Zeroizing::new(pass.as_bytes().to_vec()))
}

// ---------------------------------------------------------------------------
// Integration tests (file-based, cover atomic rename / --force paths)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod integration {
    use super::*;
    use tempfile::TempDir;

    fn passphrase(s: &str) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(s.as_bytes().to_vec())
    }

    fn write_file(dir: &TempDir, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn encrypt_decrypt_roundtrip_aes() {
        let dir = TempDir::new().unwrap();
        let plain = write_file(&dir, "plain.txt", b"Hello from integration test!");
        let cipher = dir.path().join("out.cry");
        let recovered = dir.path().join("recovered.txt");

        let pass = passphrase("hunter2");
        encrypt_file(&plain, &cipher, &pass, Algorithm::Aes256Gcm, false).unwrap();
        decrypt_file(&recovered, &cipher, &pass, false).unwrap();

        assert_eq!(
            std::fs::read(&plain).unwrap(),
            std::fs::read(&recovered).unwrap()
        );
    }

    #[test]
    fn encrypt_decrypt_roundtrip_chacha() {
        let dir = TempDir::new().unwrap();
        let plain = write_file(&dir, "plain.txt", b"ChaCha integration test data.");
        let cipher = dir.path().join("out.cry");
        let recovered = dir.path().join("recovered.txt");

        let pass = passphrase("passphrase123");
        encrypt_file(&plain, &cipher, &pass, Algorithm::ChaCha20Poly1305, false).unwrap();
        decrypt_file(&recovered, &cipher, &pass, false).unwrap();

        assert_eq!(
            std::fs::read(&plain).unwrap(),
            std::fs::read(&recovered).unwrap()
        );
    }

    #[test]
    fn encrypt_decrypt_empty_file() {
        let dir = TempDir::new().unwrap();
        let plain = write_file(&dir, "empty.txt", b"");
        let cipher = dir.path().join("out.cry");
        let recovered = dir.path().join("recovered.txt");

        let pass = passphrase("emptytest");
        encrypt_file(&plain, &cipher, &pass, Algorithm::Aes256Gcm, false).unwrap();
        decrypt_file(&recovered, &cipher, &pass, false).unwrap();

        assert_eq!(std::fs::read(&recovered).unwrap(), b"");
    }

    #[test]
    fn refuses_to_overwrite_without_force() {
        let dir = TempDir::new().unwrap();
        let plain = write_file(&dir, "plain.txt", b"data");
        let cipher = dir.path().join("out.cry");

        // Create a pre-existing output file.
        std::fs::write(&cipher, b"existing").unwrap();

        let pass = passphrase("test");
        let err = encrypt_file(&plain, &cipher, &pass, Algorithm::Aes256Gcm, false).unwrap_err();
        assert!(
            matches!(err, CryError::FileExists(_)),
            "expected FileExists, got {err:?}"
        );

        // File should still contain the original content.
        assert_eq!(std::fs::read(&cipher).unwrap(), b"existing");
    }

    #[test]
    fn force_flag_allows_overwrite() {
        let dir = TempDir::new().unwrap();
        let plain = write_file(&dir, "plain.txt", b"new data");
        let cipher = dir.path().join("out.cry");
        std::fs::write(&cipher, b"old").unwrap();

        let pass = passphrase("test");
        encrypt_file(&plain, &cipher, &pass, Algorithm::Aes256Gcm, true).unwrap();

        // Output should be the new cry file, not "old".
        assert_ne!(std::fs::read(&cipher).unwrap(), b"old");
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let dir = TempDir::new().unwrap();
        let plain = write_file(&dir, "plain.txt", b"secret");
        let cipher = dir.path().join("out.cry");
        let recovered = dir.path().join("recovered.txt");

        encrypt_file(
            &plain,
            &cipher,
            &passphrase("correct"),
            Algorithm::Aes256Gcm,
            false,
        )
        .unwrap();
        let err = decrypt_file(&recovered, &cipher, &passphrase("wrong"), false).unwrap_err();
        assert!(
            matches!(err, CryError::HeaderTampered | CryError::DecryptionFailed),
            "expected auth failure, got {err:?}"
        );

        // Partial output must not remain.
        assert!(
            !recovered.exists(),
            "tmp file should be cleaned up on failure"
        );
    }

    #[test]
    fn no_tmp_file_left_on_failure() {
        let dir = TempDir::new().unwrap();
        let plain = write_file(&dir, "plain.txt", b"test");
        let cipher = dir.path().join("out.cry");
        let recovered = dir.path().join("recovered.txt");

        encrypt_file(
            &plain,
            &cipher,
            &passphrase("pw"),
            Algorithm::Aes256Gcm,
            false,
        )
        .unwrap();
        let _ = decrypt_file(&recovered, &cipher, &passphrase("bad"), false);

        let tmp = recovered.with_extension("plain.tmp");
        assert!(!tmp.exists(), ".plain.tmp should be cleaned up on failure");
    }
}
