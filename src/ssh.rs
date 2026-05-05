//! `cry ssh` — ephemeral-key SSH using a CryDNA-derived Ed25519 identity.
//!
//! ## What happens
//!
//! 1. Derive an Ed25519 keypair deterministically from the passphrase via
//!    Argon2id (same pipeline as `cry identity`).
//! 2. Spawn a fresh, isolated `ssh-agent` subprocess.
//! 3. Inject the derived key into the agent via the SSH agent protocol
//!    (Unix socket, in-process — the private key bytes never reach the
//!    filesystem).
//! 4. Exec `ssh(1)` with `SSH_AUTH_SOCK` pointing at the ephemeral agent.
//! 5. When the session ends (or on any error), kill the agent and drop
//!    all key material — `Zeroizing<[u8; 64]>` wipes the keypair on drop.
//!
//! ## Security properties
//!
//! | Property                       | Status |
//! |--------------------------------|--------|
//! | Private key written to disk    | ✗ Never |
//! | Private key in agent memory    | ✓ For session duration only |
//! | Agent isolated from user agent | ✓ Fresh subprocess per session |
//! | Agent killed on session end    | ✓ Via `Drop` impl |
//! | Keypair bytes zeroized on drop | ✓ `Zeroizing` wrapper |
//! | Same passphrase → same keypair | ✓ Argon2id deterministic KDF |
//!
//! ## Limitations / tradeoffs
//!
//! - Requires `ssh` and `ssh-agent` to be on `PATH`.
//! - Unix only (`UnixStream` for the agent socket).
//! - If the process receives `SIGKILL`, the child agent may briefly outlive
//!   the session.  The OS will reap it; the socket path disappears with it.
//! - The passphrase stays in memory (as a `Zeroizing<Vec<u8>>`) for the
//!   duration of the key derivation and is wiped immediately after.

use std::io::{Read, Write as IoWrite};
use std::os::unix::net::UnixStream;
use std::process::Command;

use zeroize::Zeroizing;

use crate::crydna::{Identity, IdentityParams};
use crate::error::CryError;

// ── SSH agent protocol constants (draft-miller-ssh-agent) ────────────────────

/// Add a plain (unconstrained) identity to the agent.
const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
/// Operation succeeded.
const SSH_AGENT_SUCCESS: u8 = 6;

// ---------------------------------------------------------------------------
// CLI arguments
// ---------------------------------------------------------------------------

/// Arguments for `cry ssh`.
#[derive(clap::Args, Debug)]
pub struct SshArgs {
    /// SSH target — `[user@]hostname`
    #[arg(value_name = "USER@HOST")]
    pub target: String,

    /// CryDNA identity parameters (namespace, key-version, sub-id, pass-file)
    #[command(flatten)]
    pub params: IdentityParams,

    /// SSH port (forwarded as `-p PORT` to ssh)
    #[arg(short = 'p', long = "port", value_name = "PORT")]
    pub port: Option<u16>,

    /// Extra flags forwarded verbatim to `ssh(1)` (place after `--`)
    ///
    /// Example: `cry ssh user@host -- -v -L 8080:localhost:8080`
    #[arg(last = true, value_name = "SSH_ARG")]
    pub ssh_args: Vec<String>,
}

// ---------------------------------------------------------------------------
// Ephemeral ssh-agent wrapper
// ---------------------------------------------------------------------------

/// A freshly spawned `ssh-agent` subprocess.
///
/// The agent is killed (and its socket removed) when this value is dropped,
/// even if the SSH session exits abnormally.
struct TempAgent {
    /// Path of the agent's Unix-domain socket (`SSH_AUTH_SOCK`).
    socket_path: String,
    /// PID of the `ssh-agent` process (`SSH_AGENT_PID`).
    pid: u32,
}

impl TempAgent {
    /// Spawn `ssh-agent -s`, parse its env-var output, and return a handle.
    fn spawn() -> Result<Self, CryError> {
        let output = Command::new("ssh-agent")
            .arg("-s") // sh-style output: VAR=value; export VAR;
            .output()
            .map_err(|e| {
                CryError::InvalidFormat(format!(
                    "Failed to spawn ssh-agent: {e}. \
                     Make sure openssh-client (or equivalent) is installed and on PATH."
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CryError::InvalidFormat(format!(
                "ssh-agent exited with non-zero status. stderr: {stderr}"
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        let socket_path = extract_sh_var(&stdout, "SSH_AUTH_SOCK").ok_or_else(|| {
            CryError::InvalidFormat(
                "Could not parse SSH_AUTH_SOCK from ssh-agent output. \
                 Try running `ssh-agent -s` manually to check its output."
                    .into(),
            )
        })?;

        let pid_str = extract_sh_var(&stdout, "SSH_AGENT_PID").ok_or_else(|| {
            CryError::InvalidFormat("Could not parse SSH_AGENT_PID from ssh-agent output".into())
        })?;

        let pid = pid_str.parse::<u32>().map_err(|_| {
            CryError::InvalidFormat(format!(
                "ssh-agent produced an invalid PID string: {pid_str:?}"
            ))
        })?;

        eprintln!("  Agent     : PID {pid}  socket={socket_path}");

        Ok(TempAgent { socket_path, pid })
    }

    /// Inject an Ed25519 identity into the agent via `SSH2_AGENTC_ADD_IDENTITY`.
    ///
    /// Wire layout for `ssh-ed25519` (draft-miller-ssh-agent §3.2):
    ///
    /// ```text
    /// Frame = u32_be(body_len) || body
    ///
    /// body =
    ///   byte    17                  SSH2_AGENTC_ADD_IDENTITY
    ///   string  "ssh-ed25519"       key type
    ///   string  ENC(A)              32-byte Ed25519 public key
    ///   string  k || ENC(A)         64-byte private key: seed (32) || pubkey (32)
    ///   string  comment
    /// ```
    ///
    /// `string` = u32_be(len) || bytes.
    fn inject_ed25519(&self, identity: &Identity, comment: &str) -> Result<(), CryError> {
        let mut sock = UnixStream::connect(&self.socket_path).map_err(|e| {
            CryError::InvalidFormat(format!(
                "Cannot connect to ephemeral agent socket {}: {e}",
                self.socket_path
            ))
        })?;

        // Public key — 32 raw bytes.
        let pub_bytes: [u8; 32] = *identity.verifying_key().as_bytes();

        // ed25519-dalek `to_keypair_bytes()` → seed (32) || pubkey (32) = 64 bytes.
        // Wrap in Zeroizing so bytes are wiped when this frame goes out of scope.
        let kp = Zeroizing::new(identity.signing_key.to_keypair_bytes());

        // Build message body: type byte + payload.
        let mut body: Vec<u8> = Vec::with_capacity(4 + 11 + 4 + 32 + 4 + 64 + 4 + comment.len() + 8);
        body.push(SSH_AGENTC_ADD_IDENTITY);
        write_ssh_str(&mut body, b"ssh-ed25519"); // key type
        write_ssh_str(&mut body, &pub_bytes);     // ENC(A) — public key
        write_ssh_str(&mut body, kp.as_ref());    // k || ENC(A) — private key
        write_ssh_str(&mut body, comment.as_bytes()); // comment

        // Frame: 4-byte big-endian length prefix + body.
        sock.write_all(&(body.len() as u32).to_be_bytes())
            .map_err(CryError::Io)?;
        sock.write_all(&body).map_err(CryError::Io)?;
        sock.flush().map_err(CryError::Io)?;

        // Read response frame (type byte is all we care about).
        let mut len_buf = [0u8; 4];
        sock.read_exact(&mut len_buf).map_err(CryError::Io)?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        // Cap read at 16 bytes — we only need the type byte.
        let mut resp = vec![0u8; resp_len.min(16)];
        sock.read_exact(&mut resp).map_err(CryError::Io)?;

        match resp.first().copied() {
            Some(SSH_AGENT_SUCCESS) => {
                eprintln!("  Key       : injected into agent (in-memory only)");
                Ok(())
            }
            Some(code) => Err(CryError::InvalidFormat(format!(
                "ssh-agent refused key injection (protocol response code {code}). \
                 This may indicate a key format mismatch."
            ))),
            None => Err(CryError::InvalidFormat(
                "Empty response from ssh-agent after key injection".into(),
            )),
        }
    }
}

impl Drop for TempAgent {
    /// Kill the agent process when done.  Best-effort — we don't panic on
    /// failure because the process may already have exited.
    fn drop(&mut self) {
        let killed = Command::new("kill")
            .arg(self.pid.to_string())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if killed {
            eprintln!("  Agent     : killed (PID {})", self.pid);
        } else {
            eprintln!("  Agent     : PID {} may have already exited", self.pid);
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Derive an Ed25519 keypair from `passphrase`, inject it into an ephemeral
/// ssh-agent, and exec `ssh` pointing at that agent.
///
/// The private key is never written to disk.  The agent is killed when this
/// function returns (or panics).
pub fn run_ssh(args: SshArgs, passphrase: &Zeroizing<Vec<u8>>) -> Result<(), CryError> {
    let p = &args.params;

    // ── 1. Derive deterministic Ed25519 identity ──────────────────────────
    let identity = Identity::derive(
        passphrase,
        &p.namespace,
        p.key_version,
        p.sub_id.as_deref(),
    )?;

    let comment = match p.sub_id.as_deref() {
        Some(sub) => format!("CryDNA:{}:{}", p.namespace, sub),
        None => format!("CryDNA:{}", p.namespace),
    };

    eprintln!("  Public key: {}", identity.public_key_hex());
    eprintln!("  Fingerprint: {}", identity.fingerprint());

    // ── 2. Spawn an isolated, fresh ssh-agent ─────────────────────────────
    let agent = TempAgent::spawn()?;

    // ── 3. Inject the key (in-memory, via Unix socket) ───────────────────
    agent.inject_ed25519(&identity, &comment)?;

    // Drop the Identity struct — zeroes the private key bytes immediately.
    // The agent holds its own copy in its process memory.
    drop(identity);

    // ── 4. Build the ssh command ──────────────────────────────────────────
    let mut cmd = Command::new("ssh");

    // Route through our ephemeral agent, not the user's persistent one.
    cmd.env("SSH_AUTH_SOCK", &agent.socket_path);
    // Clear SSH_AGENT_PID so nested ssh-add/ssh-add -l don't get confused.
    cmd.env_remove("SSH_AGENT_PID");

    // Prefer public-key; still allows fallback to other methods in case the
    // server doesn't have the public key yet (e.g., first-time setup).
    // Users can override with `-- -o PreferredAuthentications=publickey`.
    cmd.arg("-o")
        .arg("PreferredAuthentications=publickey,keyboard-interactive,password");

    if let Some(port) = args.port {
        cmd.arg("-p").arg(port.to_string());
    }

    // Forward any extra user-supplied ssh flags verbatim.
    for extra in &args.ssh_args {
        cmd.arg(extra);
    }

    cmd.arg(&args.target);

    eprintln!();
    eprintln!("  Connecting : ssh {}", args.target);
    eprintln!(
        "  {}",
        "─".repeat(56)
    );

    // ── 5. Exec and wait ─────────────────────────────────────────────────
    let status = cmd.status().map_err(|e| {
        CryError::InvalidFormat(format!(
            "Failed to exec ssh: {e}. \
             Ensure the `ssh` binary is on PATH."
        ))
    })?;

    // `agent` is dropped here → kills the subprocess → socket disappears.
    // Rust drops local variables in reverse declaration order; `agent` was
    // declared after `identity` (which is already gone), so it drops last.
    drop(agent); // explicit for clarity

    // Non-zero exit from ssh is normal (remote command exited non-zero, etc.)
    // We print the code but don't propagate it as a hard error.
    if !status.success() {
        if let Some(code) = status.code() {
            eprintln!("  ssh exited with status {code}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Append `data` as an SSH length-prefixed string into `buf`.
///
/// Format: `u32_be(data.len()) || data`
#[inline]
fn write_ssh_str(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Extract a shell variable value from `ssh-agent -s` (or `-c`) output.
///
/// Handles both sh/bash style:
/// ```text
/// SSH_AUTH_SOCK=/tmp/ssh-XYZ/agent.1234; export SSH_AUTH_SOCK;
/// ```
/// and csh style:
/// ```text
/// setenv SSH_AUTH_SOCK /tmp/ssh-XYZ/agent.1234;
/// ```
fn extract_sh_var(text: &str, var: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();

        // sh/bash: `VAR=value; export VAR;`
        let sh_prefix = format!("{var}=");
        if let Some(rest) = line.strip_prefix(sh_prefix.as_str()) {
            let val = rest.split(';').next()?.trim().to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }

        // csh: `setenv VAR value;`
        if let Some(rest) = line.strip_prefix("setenv ") {
            let mut parts = rest.splitn(2, ' ');
            let name = parts.next()?.trim();
            if name == var {
                let val = parts.next()?.split(';').next()?.trim().to_string();
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sh_style_agent_output() {
        let output = "\
SSH_AUTH_SOCK=/tmp/ssh-abc123XYZ/agent.9876; export SSH_AUTH_SOCK;\n\
SSH_AGENT_PID=9876; export SSH_AGENT_PID;\n\
echo Agent pid 9876;\n";

        assert_eq!(
            extract_sh_var(output, "SSH_AUTH_SOCK"),
            Some("/tmp/ssh-abc123XYZ/agent.9876".into())
        );
        assert_eq!(
            extract_sh_var(output, "SSH_AGENT_PID"),
            Some("9876".into())
        );
    }

    #[test]
    fn parse_csh_style_agent_output() {
        let output = "\
setenv SSH_AUTH_SOCK /tmp/ssh-abc/agent.42;\n\
setenv SSH_AGENT_PID 42;\n";

        assert_eq!(
            extract_sh_var(output, "SSH_AUTH_SOCK"),
            Some("/tmp/ssh-abc/agent.42".into())
        );
        assert_eq!(
            extract_sh_var(output, "SSH_AGENT_PID"),
            Some("42".into())
        );
    }

    #[test]
    fn parse_missing_var_returns_none() {
        assert_eq!(extract_sh_var("", "SSH_AUTH_SOCK"), None);
        assert_eq!(extract_sh_var("unrelated=foo; export unrelated;", "SSH_AUTH_SOCK"), None);
    }

    #[test]
    fn write_ssh_str_length_prefix() {
        let mut buf = Vec::new();
        write_ssh_str(&mut buf, b"ssh-ed25519");
        // u32 BE length (11) + the bytes
        assert_eq!(&buf[..4], &[0, 0, 0, 11]);
        assert_eq!(&buf[4..], b"ssh-ed25519");
    }

    #[test]
    fn write_ssh_str_empty() {
        let mut buf = Vec::new();
        write_ssh_str(&mut buf, b"");
        assert_eq!(buf, vec![0, 0, 0, 0]);
    }
}