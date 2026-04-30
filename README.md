# cry 🔐

A fast, minimal CLI cryptography tool written in Rust.

## Features

- **AES-256-GCM** authenticated encryption (default)
- Built-in key generation — no external tools needed
- Extensible algorithm design — add new ciphers in one place
- Clean error messages
- Zero unsafe code

---

## Build

```bash
cargo build --release
# Binary at: ./target/release/cry
```

---

## Usage

### Generate a key

```bash
cry -kg -o my.key            # generate a random 32-byte key (OsRng)
cry -kg -o my.key --force    # overwrite an existing key file
```

Aliases: `-kg`, `kg`, `keygen`

### Encrypt

```bash
cry -en -p /path/to/plain.txt -k /path/to/my.key -c /path/to/output.enc
```

### Decrypt

```bash
cry -de -p /path/to/recovered.txt -k /path/to/my.key -c /path/to/output.enc
```

### All command aliases

```bash
cry -en ...      # short flag
cry en  ...      # no dash
cry encrypt ...  # full word

cry -de ...
cry de  ...
cry decrypt ...

cry -kg -o my.key
cry kg  -o my.key
cry keygen -o my.key
```

### Choose algorithm explicitly

```bash
cry -en -p plain.txt -k my.key -c out.enc -a aes256gcm
```

---

## File format (AES-256-GCM)

```
[ 12-byte random nonce ][ ciphertext + 16-byte GCM auth tag ]
```

The nonce is randomly generated per encryption call and prepended to the
output file. The GCM tag authenticates the ciphertext and provides tamper
detection — decryption fails loudly on any corruption or wrong key.

---

## Adding a new algorithm

1. Add a variant to `Algorithm` in `src/cipher.rs`:

```rust
#[value(name = "chacha20poly1305", alias = "chacha")]
ChaCha20Poly1305,
```

2. Add the crate to `Cargo.toml`:

```toml
chacha20poly1305 = "0.10"
```

3. Implement `chacha20poly1305_encrypt` / `chacha20poly1305_decrypt`
   following the same pattern as the AES-256-GCM functions.

4. Wire up the new variant in the `match algorithm { ... }` blocks
   inside `encrypt_file` and `decrypt_file`.

The CLI picks up the new `--algorithm` flag value automatically via
`clap`'s `ValueEnum` derive.

---

## Security notes

- The key file must be exactly **32 bytes** (256 bits).
- Keys are generated using `OsRng` — the OS's CSPRNG.
- On Unix, generated key files are chmod'd to **600** (owner read/write only).
- AES-256-GCM authenticated encryption means decryption fails loudly if
  the file has been tampered with or the wrong key is used.
- Keep key files out of version control — add `*.key` to `.gitignore`.