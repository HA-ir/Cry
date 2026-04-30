mod cipher;
mod keygen;

use clap::{CommandFactory, Parser};
use std::path::PathBuf;

use cipher::{Algorithm, decrypt_file, encrypt_file};

/// cry — a cryptography CLI tool
#[derive(Parser, Debug)]
#[command(
    name = "cry",
    version = "0.1.0",
    about = "Encrypt and decrypt files using strong cryptographic algorithms",
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
    Encrypt(CryptoArgs),

    /// Decrypt an encrypted file
    #[command(name = "-de", alias = "de", alias = "decrypt")]
    Decrypt(CryptoArgs),

    /// Generate a cryptographically secure random key file
    #[command(name = "-kg", alias = "kg", alias = "keygen")]
    Keygen(KeygenArgs),
}

#[derive(clap::Args, Debug)]
struct CryptoArgs {
    /// Path to the plaintext file
    #[arg(short = 'p', long = "plain", value_name = "PLAIN_FILE")]
    plain: PathBuf,

    /// Path to the key file (32 bytes for AES-256)
    #[arg(short = 'k', long = "key", value_name = "KEY_FILE")]
    key: PathBuf,

    /// Path to the encrypted (ciphertext) file
    #[arg(short = 'c', long = "cipher", value_name = "CIPHER_FILE")]
    cipher: PathBuf,

    /// Encryption algorithm to use
    #[arg(
        short = 'a',
        long = "algorithm",
        value_name = "ALGO",
        default_value = "aes256gcm"
    )]
    algorithm: Algorithm,
}

#[derive(clap::Args, Debug)]
struct KeygenArgs {
    /// Where to write the generated key
    #[arg(short = 'o', long = "output", value_name = "KEY_FILE")]
    output: PathBuf,

    /// Overwrite the output file if it already exists
    #[arg(long = "force", default_value_t = false)]
    force: bool,
}

fn main() {
    let cli = Cli::parse();

    let Some(command) = cli.command else {
        // No subcommand given — print help and exit cleanly (code 0).
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
            encrypt_file(&args.plain, &args.key, &args.cipher, args.algorithm)
        }
        Command::Decrypt(args) => {
            println!(
                "🔓 Decrypting: {} → {}",
                args.cipher.display(),
                args.plain.display()
            );
            decrypt_file(&args.plain, &args.key, &args.cipher, args.algorithm)
        }
        Command::Keygen(args) => {
            println!("🔑 Generating key → {}", args.output.display());
            keygen::generate_key(&args.output, args.force)
        }
    };

    match result {
        Ok(()) => println!("✅ Done."),
        Err(e) => {
            eprintln!("❌ Error: {}", e);
            std::process::exit(1);
        }
    }
}