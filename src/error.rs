use thiserror::Error;

/// Top-level errors for `cry`.
///
/// These are returned from the library layer; the CLI layer converts them
/// to human-readable messages via the `Display` impl (provided by thiserror).
#[derive(Debug, Error)]
pub enum CryError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),
}