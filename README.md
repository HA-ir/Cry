# cry 🔐  v0.6.0

A fast, minimal CLI cryptography tool written in Rust.  
Ephemeral SSH keys. Passphrase-protected. Authenticated. Streaming — handles files of any size.

---

## What is cry?

`cry` is a security-focused command-line tool for:

- **File encryption and decryption** — AES-256-GCM or ChaCha20-Poly1305, with streaming chunk-based processing, authenticated headers, and atomic output writes.
- **Deterministic key derivation** — reproduce the same Ed25519 or AES key on any machine from the same passphrase + context tuple. No key files to sync or back up.
- **Random key generation** — fresh, cryptographically secure keys when reproducibility is not needed.
- **File signing and verification** — Ed25519 signatures over file content with domain separation.
- **Ephemeral SSH authentication** — derive a key, inject it into a short-lived agent subprocess, run an SSH session, and let the key vanish when the session ends.

`cry` is designed for workflows where reproducibility, minimal key exposure, and auditability matter more than feature breadth.

---

## Feature summary

| Feature | Algorithm / Primitive |
|---|---|
| File encryption | AES-256-GCM or ChaCha20-Poly1305 (AEAD) |
| Key derivation (KDF) | Argon2id — 64 MiB, 3 iterations, 1 thread |
| Header authentication | HMAC-SHA256 with HKDF-Expand sub-key |
| Identity | Ed25519 (deterministic from passphrase) |
| SSH | Ephemeral Ed25519 via `ssh-agent` (Unix) or temp file (Windows) |
| Random keygen | Ed25519, RSA, AES-256 |
| Deterministic keygen | Ed25519, AES-256 (via passphrase + context) |

---

## What's new in v0.6

| # | Change |
|---|--------|
| 1 | Added `cry ssh` — ephemeral in-memory SSH key injection |
| 2 | Added `cry keygen` — secure random key generation |
| 3 | Added `cry derive` — deterministic keys from passphrases |
| 4 | Removed legacy `identity` command (replaced by `derive`) |
| 5 | Standardized key file extensions (`.cry_id`, `.cry_pub_id`) |
| 6 | Improved cross-platform SSH support (Linux, macOS, Windows) |
| 7 | HMAC sub-key now uses HKDF-Expand (RFC 5869) for auditability |

---

## Platform support

| Platform | `encrypt` / `decrypt` | `sign` / `verify` | `cry ssh` |
|---|---|---|---|
| Linux | ✅ | ✅ | ✅ via `ssh-agent` |
| macOS | ✅ | ✅ | ✅ via `ssh-agent` |
| FreeBSD / OpenBSD / NetBSD | ✅ | ✅ | ✅ via `ssh-agent` |
| Windows (native) | ✅ | ✅ | ✅ via temp key file |
| WSL | ✅ | ✅ | ✅ via `ssh-agent` |

**Prerequisites for `cry ssh`:** `ssh` and `ssh-agent` must be on `PATH`. Most Linux distros need `openssh-client`. macOS includes both.

---

## Documentation

- [Identity, derive, and SSH guide](docs/identity-and-ssh.md)
- [Architecture and security deep dive](docs/architecture-and-security.md)
- [Developer guide](docs/developer-guide.md)
- [Repository review and roadmap](docs/repo-review.md)

---

## Build

```sh
cargo build --release
```

The binary is placed at `target/release/cry`.

---

## Usage examples

### Encrypt a file

```sh
cry encrypt -p secret.txt -c secret.cry
```

Prompts for a passphrase (with confirmation). Algorithm defaults to AES-256-GCM.

```sh
# Use ChaCha20-Poly1305 instead (preferred on devices without AES hardware)
cry encrypt -p secret.txt -c secret.cry -a chacha20poly1305

# Overwrite an existing output file
cry encrypt -p secret.txt -c secret.cry --force
```

### Decrypt a file

```sh
cry decrypt -c secret.cry -p recovered.txt
```

The algorithm is read automatically from the file header — no `-a` flag needed.

```sh
cry decrypt -c secret.cry -p recovered.txt --force
```

### Non-interactive passphrase (CI / automation)

```sh
cry encrypt -p secret.txt -c secret.cry --pass-file /run/secrets/passphrase
cry decrypt -c secret.cry -p out.txt    --pass-file /run/secrets/passphrase
```

The first line of the file is used as the passphrase. Set file permissions to `0600`.  
Do not pass passphrases via environment variables or command-line arguments — both are observable in process listings.

---

### Sign a file

```sh
cry sign -f report.pdf -n work
```

Prints the signature hex and the public key. Copy both somewhere safe.

### Verify a signature

```sh
cry verify -f report.pdf -s <SIGNATURE_HEX> -k <PUBLIC_KEY_HEX>
```

Returns exit code 0 on success, non-zero on failure. Safe to use in scripts.

---

### SSH with an ephemeral derived key

`cry ssh` derives an Ed25519 identity from your passphrase and uses it for an SSH session without ever writing the private key to disk.

**One-time setup — get your public key:**

```sh
cry derive --openssh
```

Copy the printed `ssh-ed25519 ...` line into `~/.ssh/authorized_keys` on the server.

**Connecting:**

```sh
# Basic — prompts for passphrase
cry ssh user@host

# Named namespace (must match what you added to authorized_keys)
cry ssh user@host -n work

# Key version rotation (after you've rotated the key on the server)
cry ssh user@host -n work --key-version 2

# Sub-identity
cry ssh user@host -n work --sub-id deploy

# Non-interactive passphrase file (CI)
cry ssh user@host --pass-file /run/secrets/passphrase

# Custom port
cry ssh user@host -p 2222

# Forward extra flags to ssh(1) after --
cry ssh user@host -- -v -L 8080:localhost:8080 -A
cry ssh user@host -- -o StrictHostKeyChecking=accept-new
```

**What happens under the hood (Unix):**

1. Argon2id derives a 32-byte seed from the passphrase (namespace + version + sub-id scoped).
2. An Ed25519 keypair is produced from the seed.
3. A fresh `ssh-agent` subprocess is spawned on a temporary Unix socket.
4. The keypair is injected into the agent via stdin pipe (`ssh-add -`). It never touches the filesystem.
5. `ssh` is run with `SSH_AUTH_SOCK` pointing to the ephemeral agent.
6. When the session ends, the agent is killed and its socket disappears. Your existing SSH agent (if any) is completely unaffected.

**What happens under the hood (Windows):**

1–2 are the same. Then:
3. The private key PEM is written to a restricted temp file in `%TEMP%`. ACLs are applied _before_ key data is written.
4. `ssh -i <tempfile>` is run.
5. On exit, the temp file is overwritten with zeros, flushed, and deleted.

---

### Keygen — random keys

```sh
# Random Ed25519 keypair → k.cry_id + k.cry_pub_id
cry keygen --algo ed25519 -o k

# Random AES-256-GCM key → aes.cry_id
cry keygen --algo aes256gcm -o aes

# Random RSA keypair (defaults to 3072-bit)
cry keygen --algo rsa -o server

# Random RSA keypair with custom bit size
cry keygen --algo rsa --bits 4096 -o server
```

### Derive — deterministic keys from a passphrase

```sh
# Deterministic Ed25519 from prompted passphrase
cry derive --algo ed25519 -n work -o work

# Deterministic AES key from an explicit passphrase (useful in scripts)
cry derive --algo aes256gcm --passphrase 'correct horse battery staple' -n backup -o backup

# Namespace + sub-id scoping
cry derive --algo ed25519 -n prod --sub-id deploy -o deploy

# Output encrypted OpenSSH private key format as well
cry derive -n work --openssh --private-key-out ./work.id
```

The `--openssh` flag writes:
- `./work.id` — raw CryDNA private key (lowercase hex, 0600 permissions)
- `./work.id.openssh_id` — encrypted OpenSSH private key (for use with standard SSH tooling)
- `./work.id.openssh_pub` — OpenSSH public key line

Use `--force` to overwrite existing files.

---

## Deterministic key derivation — how it works

CryDNA derives keys from this four-part tuple:

| Input | CLI flag | Effect of changing |
|---|---|---|
| Passphrase | (prompted or `--pass-file`) | Completely different key family |
| Namespace | `-n` / `--namespace` | Independent key per name |
| Key version | `--key-version` | Rotate key without changing passphrase |
| Sub-identity | `--sub-id` | Child key scoped under parent namespace |

Same tuple → same key. Any change → completely different key. This is by design.

### Key rotation

Increment `--key-version` to rotate:

```sh
# Derive and publish the new public key
cry derive -n work --key-version 2 --openssh

# Update authorized_keys on the server, then connect with the new version
cry ssh user@host -n work --key-version 2
```

---

## All command aliases

```sh
cry encrypt / en / -en
cry decrypt / de / -de
cry keygen
cry derive
cry sign
cry verify
cry ssh
cry bench
```

---

## File format

```
┌──────────────────────────────────────────────────────────────┐
│ Header  73 bytes                                             │
│   Magic        4 bytes  "CRY\x02"                            │
│   AlgoID       1 byte   0x01=AES-256-GCM                     │
│                         0x02=ChaCha20-Poly1305               │
│   Salt        16 bytes  Argon2 salt (random per file)        │
│   Nonce       12 bytes  AEAD base nonce (random per file)    │
│   ChunkCount   8 bytes  u64 big-endian (0 for empty files)   │
│   HeaderHMAC  32 bytes  HMAC-SHA256(header fields, sub-key)  │
├──────────────────────────────────────────────────────────────┤
│ Chunks  (repeated ChunkCount times)                          │
│   Length       4 bytes  u32 big-endian                       │
│   Data         N bytes  AEAD ciphertext + 16-byte auth tag   │
└──────────────────────────────────────────────────────────────┘
```

### Header HMAC

The HMAC sub-key is derived from the master key using HKDF-Expand (RFC 5869):

```
sub-key = HKDF-Expand(PRK=master_key, info="cry-header-hmac-v2", L=32)
hmac    = HMAC-SHA256(sub-key, magic || algo || salt || nonce || chunk_count)
```

HKDF-Extract is skipped because the master key is already the output of Argon2id (uniformly distributed).

### Per-chunk AAD

Each chunk's AEAD call includes **Additional Authenticated Data**:

```
AAD = SHA-256(magic || algo || salt || nonce || chunk_count) || chunk_index_u64_be
```

This binds each chunk to its position in this specific file. Chunk reordering, substitution, cross-file splicing, and truncation are all detectable.

### Chunk nonce derivation

The 12-byte base nonce is treated as a 96-bit big-endian integer. The chunk nonce is:

```
chunk_nonce(index) = base_nonce + index   (96-bit add-with-carry)
```

This is the same counter construction used by TLS 1.3, and is robust against any base-nonce bit pattern (unlike XOR-based schemes which break on all-zeros).

---

## KDF parameters (Argon2id)

| Parameter   | Value  | Rationale                         |
|-------------|--------|-----------------------------------|
| Memory      | 64 MiB | OWASP recommended minimum         |
| Iterations  | 3      | OWASP recommended minimum         |
| Parallelism | 1      | Single-threaded, portable         |
| Output      | 32 B   | 256-bit key for AES-256 / ChaCha  |

The same parameters are used for file encryption KDF and CryDNA identity derivation.

---

## Benchmarks

```sh
cry bench
cry bench --size-mib 256 --samples 9 --warmup 2 --kdf-runs 7
```

Prints local throughput (MiB/s) for AES-256-GCM and ChaCha20-Poly1305, plus median, p95, and Argon2id derivation time.

---

## Running tests

```sh
cargo test
```

Covers: round-trip (AES + ChaCha), multi-chunk, empty files, tamper detection, wrong-passphrase rejection, `--force`, overwrite guard, temp-file cleanup, identity determinism, sign/verify round-trip, and the SSH agent protocol parser.

---

## Adding a new algorithm

1. Add a variant to `Algorithm` in `src/header.rs` with a unique `repr(u8)` value.
2. Add the crate to `Cargo.toml`.
3. Implement `encrypt_chunk` / `decrypt_chunk` match arms in `src/cipher.rs`.
4. The CLI picks it up automatically via `clap`'s `ValueEnum` derive.

---

## Security notes

### Deterministic vs random keys

- Use **`derive`** when you need reproducibility across machines without copying private key files.
- Use **`keygen`** when you want fresh, independent random keys each time.
- Deterministic keys are only as strong as the passphrase entropy and the discipline of not reusing context tuples across environments.

### Passphrase strength

For deterministic derivation, weak passphrases reduce effective security regardless of algorithm. Prefer long, unique, high-entropy passphrases.

### In-memory key handling

`cry ssh` avoids writing SSH private keys to disk entirely on Unix. On Windows, the key is written to a restricted temp file with ACLs applied _before_ the key data is written, and the file is overwritten with zeros and deleted when the session ends.

### Zeroize

All key material (passphrase bytes, derived keys, seeds) uses `Zeroizing<T>` wrappers from the `zeroize` crate. These wipe memory on drop, reducing the risk of key material appearing in swap, crash dumps, or memory scanners after use.

### Environment variable passphrase sources

Passing secrets via environment variables (`MY_PASS=secret cry encrypt ...`) is intentionally not supported. Environment variables are observable in `/proc/<pid>/environ` on Linux, in `ps` output on some platforms, and by any process with the same UID. Use `--pass-file` with a `0600` file instead.

---

## Threat model

### Assets we protect

- **Plaintext confidentiality** of file contents at rest and in transit as `.cry` blobs.
- **Integrity and authenticity** of encrypted files (header + chunk stream).
- **Passphrase-derived key secrecy** during runtime and after process exit.
- **SSH private key secrecy** — the key lives only in a short-lived agent process (Unix) or a restricted temp file (Windows) and is never written to long-term disk storage.

### Trust assumptions

- The host OS, Rust toolchain, and CPU are not actively compromised.
- Cryptographic primitives (AES-256-GCM, ChaCha20-Poly1305, HMAC-SHA256, Argon2id, SHA-256, Ed25519) behave as designed.
- Users choose sufficiently strong passphrases, or use high-entropy secrets via `--pass-file`.
- The `ssh-agent` binary is the genuine OpenSSH implementation from the OS package manager.

### In scope

- Reading encrypted `.cry` files without the passphrase.
- Offline brute-force attacks against captured ciphertext.
- File tampering: modifying header bytes, chunk lengths, chunk ciphertext/tag, reordering/removing chunks, or truncation.
- Nonce-misuse from chunking logic.
- Accidental destructive overwrite of output files.
- SSH private key exposure via disk writes (Unix).

### Out of scope / not guaranteed

- Compromised endpoint security (malware, keyloggers, root/admin attackers, memory scraping while the process runs).
- Passphrase theft from unsafe user practices.
- Metadata privacy: file names, paths, sizes, timestamps, and access patterns are not hidden.
- Plausible deniability or hidden-volume semantics.
- Secure deletion of source plaintext or filesystem/journal remnants.
- Side-channel resistance beyond what the underlying libraries and platform provide.
- Multi-user policy controls, remote KMS/HSM integration, or enterprise key lifecycle management.
- Protection against a malicious `ssh-agent` binary or a compromised `SSH_AUTH_SOCK` socket.
- Cryptographic erasure of the SSH private key temp file on Windows (NTFS journaling and SSD wear-leveling limit physical-media guarantees).

### Security properties that hold

- Passphrases are read with `rpassword` (no terminal echo, no history).
- All key material uses `Zeroizing<T>` — wiped from memory on drop.
- The file header is not encrypted, but it is HMAC-authenticated. Any bit-flip in the header is detectable before chunk decryption begins.
- Decryption fails loudly on wrong passphrase, corruption, truncation, or tampering. There is no "best effort" partial output.
- Environment variables are intentionally not supported as a passphrase source.
- On Unix, `cry ssh` injects keys into an isolated, ephemeral `ssh-agent` subprocess. The agent only lives for the SSH session and is killed on exit. Your persistent SSH agent (if any) is completely unaffected.
- Keep backups — there is no key recovery mechanism. If you lose your passphrase (for derive) or your key file (for keygen), the encrypted data is unrecoverable.