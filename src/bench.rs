use std::time::Instant;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::CryError;
use crate::header::Algorithm;
use crate::kdf::derive_key;

#[derive(clap::Args, Debug, Clone)]
pub struct BenchArgs {
    /// Number of MiB to process per benchmark sample
    #[arg(long = "size-mib", default_value_t = 256)]
    pub size_mib: usize,

    /// Number of throughput samples per algorithm
    #[arg(long = "samples", default_value_t = 7)]
    pub samples: u32,

    /// Warmup rounds per algorithm (not included in reported samples)
    #[arg(long = "warmup", default_value_t = 2)]
    pub warmup: u32,

    /// Number of Argon2id derivations to time
    #[arg(long = "kdf-runs", default_value_t = 5)]
    pub kdf_runs: u32,
}

pub fn run_bench(args: BenchArgs) -> Result<(), CryError> {
    let size_mib = args.size_mib.max(1);
    let size_bytes = size_mib * 1024 * 1024;
    let samples = args.samples.max(1);
    let warmup = args.warmup;
    let kdf_runs = args.kdf_runs.max(1);

    let mut plain = vec![0u8; size_bytes];
    rand::rngs::OsRng.fill_bytes(&mut plain);

    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let passphrase = b"benchmark-passphrase";

    eprintln!(
        "  🧪  \x1b[1mBenchmarking\x1b[0m  {} MiB payload · {} sample(s) · {} warmup",
        size_mib, samples, warmup
    );
    super::divider();

    let kdf_ms = benchmark_kdf(passphrase, &salt, kdf_runs)?;
    let key = derive_key(passphrase, &salt)?;

    benchmark_algorithm(Algorithm::Aes256Gcm, &plain, &*key, warmup, samples);
    benchmark_algorithm(Algorithm::ChaCha20Poly1305, &plain, &*key, warmup, samples);

    eprintln!(
        "  Argon2id avg : {:.1} ms/derive ({} run(s))",
        kdf_ms, kdf_runs
    );
    Ok(())
}

fn benchmark_kdf(passphrase: &[u8], salt: &[u8; 16], runs: u32) -> Result<f64, CryError> {
    let start = Instant::now();
    for _ in 0..runs {
        let _ = derive_key(passphrase, salt)?;
    }
    Ok(start.elapsed().as_secs_f64() * 1000.0 / runs as f64)
}

fn benchmark_algorithm(algo: Algorithm, plain: &[u8], key: &[u8; 32], warmup: u32, samples: u32) {
    let mut base_nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut base_nonce);

    let mut h = Sha256::new();
    h.update(b"cry-bench-aad");
    let aad = h.finalize();

    let mut enc_rates = Vec::with_capacity(samples as usize);
    let mut dec_rates = Vec::with_capacity(samples as usize);

    for i in 0..(warmup + samples) {
        let (enc, dec) = single_run(algo, plain, key, &base_nonce, &aad);
        if i >= warmup {
            enc_rates.push(enc);
            dec_rates.push(dec);
        }
    }

    let enc = Stats::from(&enc_rates);
    let dec = Stats::from(&dec_rates);

    eprintln!(
        "  {} encrypt: {:>7.1} MiB/s (median), {:>7.1} p95",
        algo, enc.median, enc.p95
    );
    eprintln!(
        "  {} decrypt: {:>7.1} MiB/s (median), {:>7.1} p95",
        algo, dec.median, dec.p95
    );
}

fn single_run(
    algo: Algorithm,
    plain: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
) -> (f64, f64) {
    let enc_start = Instant::now();
    let ciphertext = match algo {
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
            cipher
                .encrypt(AesNonce::from_slice(nonce), Payload { msg: plain, aad })
                .expect("benchmark encryption should not fail")
        }
        Algorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
            cipher
                .encrypt(ChaChaNonce::from_slice(nonce), Payload { msg: plain, aad })
                .expect("benchmark encryption should not fail")
        }
    };
    let enc_secs = enc_start.elapsed().as_secs_f64();

    let dec_start = Instant::now();
    match algo {
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
            let _ = cipher
                .decrypt(
                    AesNonce::from_slice(nonce),
                    Payload {
                        msg: &ciphertext,
                        aad,
                    },
                )
                .expect("benchmark decryption should not fail");
        }
        Algorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
            let _ = cipher
                .decrypt(
                    ChaChaNonce::from_slice(nonce),
                    Payload {
                        msg: &ciphertext,
                        aad,
                    },
                )
                .expect("benchmark decryption should not fail");
        }
    }
    let dec_secs = dec_start.elapsed().as_secs_f64();

    let mib = plain.len() as f64 / (1024.0 * 1024.0);
    (mib / enc_secs.max(1e-9), mib / dec_secs.max(1e-9))
}

struct Stats {
    median: f64,
    p95: f64,
}

impl Stats {
    fn from(values: &[f64]) -> Self {
        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        Self {
            median: percentile(&sorted, 0.50),
            p95: percentile(&sorted, 0.95),
        }
    }
}

fn percentile(sorted: &[f64], q: f64) -> f64 {
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[idx]
}
