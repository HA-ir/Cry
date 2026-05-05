# Developer Guide

This guide helps contributors build, test, and modify `cry` safely.

## Prerequisites

- Rust stable toolchain (`rustup default stable`)
- `cargo`
- POSIX shell environment

## Build & run

```bash
cargo build
cargo run -- encrypt -p ./plain.txt -c ./plain.cry
cargo run -- decrypt -c ./plain.cry -p ./recovered.txt
```

Release build:

```bash
cargo build --release
./target/release/cry --help
```

## Test strategy

Current tests are integration-style and file-system grounded (temp dirs, atomic write paths, overwrite semantics, wrong-passphrase behavior).

Run full suite:

```bash
cargo test
```

Run one test:

```bash
cargo test wrong_passphrase_rejected -- --nocapture
```

## Contributor checklist

Before opening a PR:

1. `cargo fmt`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test`
4. Verify README/docs examples still match CLI output.
5. If format logic changed, include migration/backward-compatibility notes.

## Code conventions

- Prefer explicit error returns (`Result<_, CryError>`) over panic paths.
- Keep cryptographic boundaries simple and auditable.
- Avoid implicit behavior that could surprise users (especially overwrite/passphrase sources).
- Keep security-critical comments close to implementation.

## Release hardening checklist

- Confirm version bump in `Cargo.toml` and changelog/release notes.
- Re-run benchmarks on representative hardware (`cry bench`).
- Validate `encrypt/decrypt` round-trip for both algorithms on small + large files.
- Validate identity/sign/verify flows and OpenSSH export path.
- Validate `--private-key-out` writes both `<FILE>` and `<FILE>.openssh_id` when `--openssh` is set.
- Re-read threat-model section for any new out-of-scope assumptions introduced by changes.
