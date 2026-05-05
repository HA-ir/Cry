# CryDNA Identity + SSH Guide

This guide explains how CryDNA identity derivation works, why keys can differ
even with the same passphrase, and how to use CryDNA output safely with SSH.

---

## 1) Deterministic identity inputs

CryDNA key derivation depends on the full identity tuple:

1. passphrase
2. namespace (`--namespace`)
3. key version (`--key-version`)
4. sub-identity (`--sub-id`, optional)

The same tuple always yields the same keypair. Any change to any element yields
a different keypair.

### Example

- `cry identity` uses default namespace `default`
- `cry identity -n work` uses namespace `work`

These produce different keys by design.

---

## 2) Output modes: public vs private

`cry identity` prints:

- public key (hex/base64)
- fingerprint
- optional SSH public line (`--ssh`)

By default it does not print private key material.

If you pass `--show-private-key`, CryDNA prints the raw 32-byte Ed25519 private
key as lowercase hex.

> Important: this is raw secret key material, **not** an OpenSSH private key
> file (`OPENSSH PRIVATE KEY` block).

---

## 3) Recommended SSH setup

### Server

1. Run:

```bash
cry identity -n work --ssh
# equivalent:
cry identity -n work --openssh
```

2. Copy printed line:

```text
ssh-ed25519 AAAA... comment
```

3. Append it to server:

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo 'ssh-ed25519 AAAA... comment' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### Client

Use a standard OpenSSH private key file for authentication:

```bash
ssh -i ~/.ssh/id_ed25519 user@server
```

If you want to use CryDNA private-key hex directly with OpenSSH, you must first
convert it to a valid OpenSSH private key file using trusted external tooling.

---

## 4) Troubleshooting

### “Same passphrase, different keys”

Check:

- namespace mismatch (`default` vs `work`)
- key version mismatch (`--key-version`)
- sub-id mismatch (`--sub-id`)
- accidental passphrase typo/spacing/case mismatch

### “I can’t SSH using printed private key hex”

Expected. OpenSSH expects private key file formats, not raw hex scalars.

---

## 5) Security checklist

- Avoid `--show-private-key` unless necessary.
- Never share printed private key hex in chat/screenshots/logs.
- Prefer dedicated identities per role (`--namespace work`, `--namespace ci`).
- Rotate with `--key-version` if key material may have been exposed.
- Keep passphrase high-entropy and unique.
