mod cipher;
mod header;
mod kdf;
mod keygen;

use clap::{CommandFactory, Parser};
use std::path::PathBuf;
use zeroize::Zeroizing;

use cipher::{Algorithm, decrypt_file, encrypt_file};

/// cry — a cryptography CLI tool
#[derive(Parser, Debug)]
#[command(
    name = "cry",
    version = "0.2.0",
    about = "Encrypt and decrypt files — AES-256-GCM or ChaCha20-Poly1305, passphrase-protected",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Encrypt a plaintext file
    #[command(name = "-en", alias = "en", alias = "encrypt")]
    Encrypt(EncryptArgs),

    /// Decrypt an encrypted file (algorithm detected automatically from file header)
    #[command(name = "-de", alias = "de", alias = "decrypt")]
    Decrypt(DecryptArgs),

    /// Generate a cryptographically secure random key file
    #[command(name = "-kg", alias = "kg", alias = "keygen")]
    Keygen(KeygenArgs),
}

// ── Encrypt ──────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
struct EncryptArgs {
    /// Path to the plaintext file (input)
    #[arg(short = 'p', long = "plain", value_name = "PLAIN_FILE")]
    plain: PathBuf,

    /// Path to the encrypted file (output)
    #[arg(short = 'c', long = "cipher", value_name = "CIPHER_FILE")]
    cipher: PathBuf,

    /// Encryption algorithm
    #[arg(
        short = 'a',
        long = "algorithm",
        value_name = "ALGO",
        default_value = "aes256gcm"
    )]
    algorithm: Algorithm,

    /// Read passphrase from this env variable instead of prompting
    #[arg(long = "pass-env", value_name = "VAR_NAME", hide = true)]
    pass_env: Option<String>,
}

// ── Decrypt ──────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
struct DecryptArgs {
    /// Path to the encrypted file (input)
    #[arg(short = 'c', long = "cipher", value_name = "CIPHER_FILE")]
    cipher: PathBuf,

    /// Path to the plaintext file (output)
    #[arg(short = 'p', long = "plain", value_name = "PLAIN_FILE")]
    plain: PathBuf,

    /// Read passphrase from this env variable instead of prompting
    #[arg(long = "pass-env", value_name = "VAR_NAME", hide = true)]
    pass_env: Option<String>,
}

// ── Keygen ───────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
struct KeygenArgs {
    /// Where to write the generated key
    #[arg(short = 'o', long = "output", value_name = "KEY_FILE")]
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
        println!();
        return;
    };

    let result = match command {
        Command::Encrypt(args) => {
            println!(
                "🔒 Encrypting: {} → {}",
                args.plain.display(),
                args.cipher.display()
            );
            let pass = read_passphrase(args.pass_env.as_deref(), true);
            match pass {
                Ok(p) => encrypt_file(&args.plain, &args.cipher, &p, args.algorithm),
                Err(e) => Err(e),
            }
        }
        Command::Decrypt(args) => {
            println!(
                "🔓 Decrypting: {} → {}",
                args.cipher.display(),
                args.plain.display()
            );
            let pass = read_passphrase(args.pass_env.as_deref(), false);
            match pass {
                Ok(p) => decrypt_file(&args.plain, &args.cipher, &p),
                Err(e) => Err(e),
            }
        }
        Command::Keygen(args) => {
            println!("🔑 Generating key → {}", args.output.display());
            keygen::generate_key(&args.output, args.force)
        }
    };

    match result {
        Ok(()) => println!("✅ Done."),
        Err(e) => {
            eprintln!("❌ Error: {e}");
            std::process::exit(1);
        }
    }
}

// ── Passphrase helpers ────────────────────────────────────────────────────────

/// Prompt for a passphrase (with confirmation on encrypt) or read from env var.
/// Returns a `Zeroizing<Vec<u8>>` so memory is wiped on drop.
fn read_passphrase(env_var: Option<&str>, confirm: bool) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if let Some(var) = env_var {
        let val = std::env::var(var)
            .map_err(|_| anyhow::anyhow!("Environment variable '{var}' is not set"))?;
        return Ok(Zeroizing::new(val.into_bytes()));
    }

    let pass = Zeroizing::new(
        rpassword::prompt_password("  Passphrase: ")
            .map_err(|e| anyhow::anyhow!("Failed to read passphrase: {e}"))?,
    );

    if pass.is_empty() {
        anyhow::bail!("Passphrase must not be empty.");
    }

    if confirm {
        let confirm = Zeroizing::new(
            rpassword::prompt_password("  Confirm   : ")
                .map_err(|e| anyhow::anyhow!("Failed to read passphrase: {e}"))?,
        );
        if *pass != *confirm {
            anyhow::bail!("Passphrases do not match.");
        }
    }

    Ok(Zeroizing::new((*pass).clone().into_bytes()))
}