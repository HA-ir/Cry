//! `cry` — a fast, minimal CLI cryptography tool.
//!
//! Supported algorithms: AES-256-GCM, ChaCha20-Poly1305
//! Key derivation: Argon2id (64 MiB, 3 iterations)

mod cipher;
mod error;
mod header;
mod kdf;
mod keygen;

use std::path::PathBuf;

use clap::{CommandFactory, Parser};
use zeroize::Zeroizing;

use cipher::{decrypt_file, encrypt_file, Algorithm};
use error::CryError;

// ── ANSI colour helpers ───────────────────────────────────────────────────────

macro_rules! style {
    (bold    $s:expr) => { concat!("\x1b[1m",    $s, "\x1b[0m") };
    (dim     $s:expr) => { concat!("\x1b[2m",    $s, "\x1b[0m") };
    (cyan    $s:expr) => { concat!("\x1b[36m",   $s, "\x1b[0m") };
    (green   $s:expr) => { concat!("\x1b[32m",   $s, "\x1b[0m") };
    (yellow  $s:expr) => { concat!("\x1b[33m",   $s, "\x1b[0m") };
    (red     $s:expr) => { concat!("\x1b[31m",   $s, "\x1b[0m") };
    (magenta $s:expr) => { concat!("\x1b[35m",   $s, "\x1b[0m") };
}

fn banner() {
    /*
    eprintln!(
        "\n{}  {}",
        style!(bold "╔═╗ ╦═╗ ╦ ╦"),
        style!(dim "v") ,
    );
    */
    // Simpler banner that's definitely valid
    let ver = env!("CARGO_PKG_VERSION");
    eprintln!(
        "  {}  {}",
        style!(bold "cry 🔐"),
        format!("\x1b[2mv{ver}\x1b[0m")
    );
    eprintln!();
}

fn section(icon: &str, label: &str, value: &str) {
    eprintln!(
        "  {}  \x1b[2m{:<12}\x1b[0m  {}",
        icon, label, value
    );
}

fn divider() {
    eprintln!("  \x1b[2m{}\x1b[0m", "─".repeat(48));
}

// ── CLI definition ────────────────────────────────────────────────────────────

/// cry — encrypt and decrypt files with AES-256-GCM or ChaCha20-Poly1305
#[derive(Parser, Debug)]
#[command(
    name = "cry",
    version = env!("CARGO_PKG_VERSION"),
    about = "Encrypt and decrypt files — passphrase-protected, authenticated",
    long_about = None,
    after_help = concat!(
        "\x1b[2mExamples:\x1b[0m\n",
        "  cry encrypt -p secret.txt -c secret.cry\n",
        "  cry decrypt -c secret.cry -p recovered.txt\n",
        "  cry encrypt -p secret.txt -c secret.cry -a chacha20poly1305\n",
        "  cry keygen -o my.key\n",
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
}

// ── Encrypt ───────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
struct EncryptArgs {
    /// Plaintext input file  (use - for stdin)
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

    /// Read passphrase from this environment variable (useful in scripts)
    #[arg(long = "pass-env", value_name = "VAR", help_heading = "Advanced")]
    pass_env: Option<String>,

    /// Read passphrase from a file (first line used)
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

    /// Read passphrase from this environment variable
    #[arg(long = "pass-env", value_name = "VAR", help_heading = "Advanced")]
    pass_env: Option<String>,

    /// Read passphrase from a file (first line used)
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

// ── Entry point ───────────────────────────────────────────────────────────────

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

            read_passphrase(args.pass_env.as_deref(), args.pass_file.as_deref(), true)
                .and_then(|p| encrypt_file(&args.plain, &args.cipher, &p, args.algorithm))
        }

        Command::Decrypt(args) => {
            eprintln!(
                "  🔓  \x1b[1mDecrypting\x1b[0m  {} \x1b[2m→\x1b[0m {}",
                args.cipher.display(),
                args.plain.display()
            );
            section("🔑", "KDF", "Argon2id  (64 MiB · 3 iter · 1 thread)");
            divider();

            read_passphrase(args.pass_env.as_deref(), args.pass_file.as_deref(), false)
                .and_then(|p| decrypt_file(&args.plain, &args.cipher, &p))
        }

        Command::Keygen(args) => {
            eprintln!(
                "  🎲  \x1b[1mGenerating key\x1b[0m  \x1b[2m→\x1b[0m {}",
                args.output.display()
            );
            divider();
            keygen::generate_key(&args.output, args.force)
        }
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

// ── Passphrase helpers ────────────────────────────────────────────────────────

/// Read a passphrase from (in priority order):
///   1. an environment variable (`--pass-env VAR`)
///   2. a file (`--pass-file PATH`, first line)
///   3. an interactive terminal prompt (with optional confirmation)
///
/// Returns `Zeroizing<Vec<u8>>` so the bytes are wiped on drop.
fn read_passphrase(
    env_var: Option<&str>,
    pass_file: Option<&std::path::Path>,
    confirm: bool,
) -> Result<Zeroizing<Vec<u8>>, CryError> {
    // 1. Environment variable
    if let Some(var) = env_var {
        let val = std::env::var(var).map_err(|_| CryError::MissingEnvVar(var.to_string()))?;
        return Ok(Zeroizing::new(val.into_bytes()));
    }

    // 2. Passphrase file
    if let Some(path) = pass_file {
        let contents = std::fs::read_to_string(path)?;
        let first_line = contents.lines().next().unwrap_or("").to_string();
        if first_line.is_empty() {
            return Err(CryError::EmptyPassphrase);
        }
        return Ok(Zeroizing::new(first_line.into_bytes()));
    }

    // 3. Interactive prompt
    let pass = Zeroizing::new(
        rpassword::prompt_password("  Passphrase : ")
            .map_err(|e| CryError::Io(e))?,
    );

    if pass.is_empty() {
        return Err(CryError::EmptyPassphrase);
    }

    if confirm {
        let confirm_pass = Zeroizing::new(
            rpassword::prompt_password("  Confirm    : ")
                .map_err(|e| CryError::Io(e))?,
        );
        if *pass != *confirm_pass {
            return Err(CryError::PassphraseMismatch);
        }
    }

    Ok(Zeroizing::new(pass.as_bytes().to_vec()))
}