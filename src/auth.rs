//! Authentication of inbound host→agent messages.
//!
//! The virtio-serial channel is **not** inherently trusted. Any process
//! inside the guest that can open the virtio-serial device, or a compromised
//! host, could inject command messages that the agent would execute as
//! root/SYSTEM. Historically the agent parsed and executed whatever JSON line
//! arrived, with no authentication whatsoever — i.e. a single spoofed line was
//! unauthenticated remote/local code execution as the most privileged account.
//!
//! This module closes that hole. Every inbound line MUST be a
//! [`SignedEnvelope`]: an HMAC-SHA256 signature, computed by the host over a
//! canonical `(version, timestamp, nonce, payload)` tuple keyed by a per-VM
//! shared secret. The secret is provisioned **only** through the
//! `INFINISERVICE_SHARED_SECRET` environment variable (systemd
//! `EnvironmentFile` / the Windows service environment) and is never written
//! to disk or to the serialized config.
//!
//! The policy is strictly **fail-closed**:
//!   * no secret configured            → every inbound message rejected;
//!   * malformed / wrong-version frame → rejected;
//!   * signature mismatch              → rejected (constant-time compare);
//!   * timestamp outside the window    → rejected (stale / replay-from-future);
//!   * nonce already seen              → rejected (replay).
//!
//! Only after all checks pass is the verbatim inner `payload` handed back to
//! the normal message parser. Outbound metrics (agent→host) are autonomous and
//! unaffected: locking the inbound channel never stops the agent reporting.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Current envelope protocol version. The signature input is versioned so the
/// scheme can evolve without silently accepting an attacker-chosen format.
const ENVELOPE_VERSION: u32 = 1;

/// Maximum age (and forward clock skew) tolerated for a signed message, in
/// milliseconds. Bounds the replay window; a fresh VM may have meaningful
/// clock skew before NTP settles, so this is deliberately generous.
const FRESHNESS_WINDOW_MS: u64 = 300_000; // 5 minutes

/// Hard cap on the replay cache. Only validly-*signed* messages ever reach the
/// cache (signature is checked first), so an unauthenticated flooder cannot
/// grow it; this is a backstop against a compromised-secret flood.
const MAX_REPLAY_ENTRIES: usize = 100_000;

/// Signed envelope wrapping an inner host→agent message.
///
/// Wire form (single NDJSON line):
/// ```json
/// {"type":"signed","v":1,"ts":1719000000000,"nonce":"<uuid>",
///  "payload":"<exact inner-message JSON>","sig":"<hex hmac-sha256>"}
/// ```
#[derive(Deserialize)]
struct SignedEnvelope {
    #[serde(rename = "type")]
    msg_type: String,
    v: u32,
    ts: u64,
    nonce: String,
    payload: String,
    sig: String,
}

/// Why an inbound message was rejected. Never carries the payload, so logging
/// an `AuthError` cannot leak a (possibly secret-bearing) command body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// No `INFINISERVICE_SHARED_SECRET` configured — the agent is locked.
    NoSecret,
    /// Not a well-formed signed envelope.
    Malformed,
    /// Envelope version the agent does not understand.
    UnsupportedVersion(u32),
    /// Signature hex was not decodable.
    BadSignatureEncoding,
    /// HMAC did not verify.
    BadSignature,
    /// Timestamp is too old or too far in the future.
    Stale,
    /// Nonce has already been used inside the freshness window.
    Replay,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::NoSecret => write!(
                f,
                "INFINISERVICE_SHARED_SECRET is not set — inbound command channel is locked (fail-closed)"
            ),
            AuthError::Malformed => write!(f, "message is not a well-formed signed envelope"),
            AuthError::UnsupportedVersion(v) => write!(f, "unsupported envelope version {}", v),
            AuthError::BadSignatureEncoding => write!(f, "signature is not valid hex"),
            AuthError::BadSignature => write!(f, "HMAC signature verification failed"),
            AuthError::Stale => write!(f, "message timestamp outside the freshness window"),
            AuthError::Replay => write!(f, "message nonce already seen (replay)"),
        }
    }
}

impl std::error::Error for AuthError {}

/// The per-VM shared secret, read once from the environment.
///
/// `None` means the variable is unset or empty → the agent is locked
/// (fail-closed). Read exactly once; rotating the secret requires a service
/// restart, which is the intended provisioning model.
fn shared_secret() -> Option<&'static [u8]> {
    static SECRET: OnceLock<Option<Vec<u8>>> = OnceLock::new();
    SECRET
        .get_or_init(|| match std::env::var("INFINISERVICE_SHARED_SECRET") {
            Ok(s) if !s.is_empty() => Some(s.into_bytes()),
            _ => None,
        })
        .as_deref()
}

/// True when a shared secret is configured. Used at startup to emit a single,
/// loud warning if the agent is running locked (rejecting all commands).
pub fn is_authentication_configured() -> bool {
    shared_secret().is_some()
}

/// Process-wide replay cache: nonce → signing timestamp (ms). Guarded by a
/// `Mutex`; acquisition is poison-tolerant so a panic elsewhere can never wedge
/// the auth path.
fn replay_cache() -> &'static Mutex<HashMap<String, u64>> {
    static CACHE: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Canonical bytes that both sides feed into HMAC. The `payload` is signed
/// **verbatim** (exact bytes), so there is no JSON-canonicalization ambiguity
/// between the Rust agent and the TypeScript host.
fn signing_input(v: u32, ts: u64, nonce: &str, payload: &str) -> Vec<u8> {
    format!("{}\n{}\n{}\n{}", v, ts, nonce, payload).into_bytes()
}

/// Record a freshly-verified nonce, pruning anything outside the window. Call
/// only after the signature has been verified. Returns `Err(Replay)` if the
/// nonce was already present.
fn remember_nonce(nonce: &str, ts: u64, now: u64) -> Result<(), AuthError> {
    let mut cache = replay_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Drop entries whose signing time has aged out of the window.
    let cutoff = now.saturating_sub(FRESHNESS_WINDOW_MS);
    cache.retain(|_, &mut t| t >= cutoff);

    if cache.contains_key(nonce) {
        return Err(AuthError::Replay);
    }

    // Backstop against runaway growth (would only happen with a leaked secret).
    if cache.len() >= MAX_REPLAY_ENTRIES {
        // Keep only the freshest half by re-pruning to a tighter cutoff.
        let tight = now.saturating_sub(FRESHNESS_WINDOW_MS / 2);
        cache.retain(|_, &mut t| t >= tight);
    }

    cache.insert(nonce.to_string(), ts);
    Ok(())
}

/// Verify a raw inbound NDJSON line and, on success, return the verbatim inner
/// message JSON for normal parsing.
///
/// Fail-closed at every step. The returned `String` is the exact `payload` the
/// host signed — nothing else from the envelope is trusted downstream.
pub fn verify_and_extract(raw: &str) -> Result<String, AuthError> {
    let secret = shared_secret().ok_or(AuthError::NoSecret)?;
    verify_with_secret(raw, secret)
}

/// Core verification against an explicit key. Split out from
/// [`verify_and_extract`] so the full path (parse → signature → freshness →
/// replay) is unit-testable without the process-global secret `OnceLock`.
fn verify_with_secret(raw: &str, secret: &[u8]) -> Result<String, AuthError> {
    let env: SignedEnvelope = serde_json::from_str(raw).map_err(|_| AuthError::Malformed)?;
    if env.msg_type != "signed" {
        return Err(AuthError::Malformed);
    }
    if env.v != ENVELOPE_VERSION {
        return Err(AuthError::UnsupportedVersion(env.v));
    }

    let provided_sig = hex::decode(env.sig.as_bytes()).map_err(|_| AuthError::BadSignatureEncoding)?;

    // 1. Authenticate first: only genuine messages get to touch the clock check
    //    or the replay cache. `verify_slice` is constant-time.
    let mut mac =
        HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(&signing_input(env.v, env.ts, &env.nonce, &env.payload));
    mac.verify_slice(&provided_sig).map_err(|_| AuthError::BadSignature)?;

    // 2. Freshness: reject stale messages and ones too far in the future.
    let now = now_ms();
    let age = now.abs_diff(env.ts);
    if age > FRESHNESS_WINDOW_MS {
        return Err(AuthError::Stale);
    }

    // 3. Replay: each nonce may be used once within the window.
    remember_nonce(&env.nonce, env.ts, now)?;

    Ok(env.payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(secret: &[u8], v: u32, ts: u64, nonce: &str, payload: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(&signing_input(v, ts, nonce, payload));
        hex::encode(mac.finalize().into_bytes())
    }

    fn envelope(v: u32, ts: u64, nonce: &str, payload: &str, sig: &str) -> String {
        format!(
            r#"{{"type":"signed","v":{},"ts":{},"nonce":"{}","payload":{},"sig":"{}"}}"#,
            v,
            ts,
            nonce,
            serde_json::to_string(payload).unwrap(),
            sig
        )
    }

    // These tests drive verify_and_extract against the real (env-derived)
    // secret. We can't set the process env mid-test reliably across the OnceLock,
    // so we exercise the pure pieces directly and keep one end-to-end check
    // behind an explicitly-set secret.

    #[test]
    fn signing_input_is_stable_and_versioned() {
        let a = signing_input(1, 10, "n", "p");
        let b = signing_input(1, 10, "n", "p");
        assert_eq!(a, b);
        assert_ne!(a, signing_input(2, 10, "n", "p"));
        assert_ne!(a, signing_input(1, 11, "n", "p"));
    }

    #[test]
    fn nonce_replay_is_rejected_within_window() {
        let now = now_ms();
        assert!(remember_nonce("auth-test-nonce-unique-1", now, now).is_ok());
        assert_eq!(
            remember_nonce("auth-test-nonce-unique-1", now, now),
            Err(AuthError::Replay)
        );
    }

    #[test]
    fn good_signature_verifies_and_bad_one_does_not() {
        let secret = b"super-secret-key-of-decent-length-0123456789";
        let ts = now_ms();
        let payload = r#"{"type":"Metrics"}"#;
        let good = sign(secret, ENVELOPE_VERSION, ts, "nonce-sig-test", payload);
        let bad = sign(secret, ENVELOPE_VERSION, ts, "nonce-sig-test", payload)
            .replacen('a', "b", 1);

        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(&signing_input(ENVELOPE_VERSION, ts, "nonce-sig-test", payload));
        assert!(mac.verify_slice(&hex::decode(&good).unwrap()).is_ok());

        if good != bad {
            let mut mac2 = HmacSha256::new_from_slice(secret).unwrap();
            mac2.update(&signing_input(ENVELOPE_VERSION, ts, "nonce-sig-test", payload));
            assert!(mac2.verify_slice(&hex::decode(&bad).unwrap()).is_err());
        }
    }

    #[test]
    fn envelope_helper_round_trips_through_serde() {
        // Sanity that our test envelope string parses as the struct.
        let secret = b"k";
        let ts = now_ms();
        let payload = r#"{"type":"Metrics"}"#;
        let sig = sign(secret, ENVELOPE_VERSION, ts, "n1", payload);
        let line = envelope(ENVELOPE_VERSION, ts, "n1", payload, &sig);
        let env: SignedEnvelope = serde_json::from_str(&line).unwrap();
        assert_eq!(env.msg_type, "signed");
        assert_eq!(env.payload, payload);
    }

    const KEY: &[u8] = b"end-to-end-test-secret-0123456789abcdef";

    fn valid_line(nonce: &str, payload: &str) -> String {
        let ts = now_ms();
        let sig = sign(KEY, ENVELOPE_VERSION, ts, nonce, payload);
        envelope(ENVELOPE_VERSION, ts, nonce, payload, &sig)
    }

    #[test]
    fn e2e_valid_envelope_yields_payload() {
        let payload = r#"{"type":"SafeCommand","id":"x","command_type":{"action":"ServiceList"},"params":null,"timeout":30}"#;
        let line = valid_line("e2e-valid-1", payload);
        assert_eq!(verify_with_secret(&line, KEY).unwrap(), payload);
    }

    #[test]
    fn e2e_tampered_payload_is_rejected() {
        let ts = now_ms();
        let payload = r#"{"type":"Metrics"}"#;
        let sig = sign(KEY, ENVELOPE_VERSION, ts, "e2e-tamper-1", payload);
        // Sign one payload, ship a different one.
        let evil = envelope(ENVELOPE_VERSION, ts, "e2e-tamper-1", r#"{"type":"UnsafeCommand","id":"x","raw_command":"rm -rf /"}"#, &sig);
        assert_eq!(verify_with_secret(&evil, KEY), Err(AuthError::BadSignature));
    }

    #[test]
    fn e2e_wrong_key_is_rejected() {
        let line = valid_line("e2e-wrongkey-1", r#"{"type":"Metrics"}"#);
        assert_eq!(verify_with_secret(&line, b"different-key"), Err(AuthError::BadSignature));
    }

    #[test]
    fn e2e_stale_timestamp_is_rejected() {
        let old_ts = now_ms().saturating_sub(FRESHNESS_WINDOW_MS + 60_000);
        let payload = r#"{"type":"Metrics"}"#;
        let sig = sign(KEY, ENVELOPE_VERSION, old_ts, "e2e-stale-1", payload);
        let line = envelope(ENVELOPE_VERSION, old_ts, "e2e-stale-1", payload, &sig);
        assert_eq!(verify_with_secret(&line, KEY), Err(AuthError::Stale));
    }

    #[test]
    fn e2e_replayed_nonce_is_rejected() {
        let payload = r#"{"type":"Metrics"}"#;
        let line = valid_line("e2e-replay-unique", payload);
        assert_eq!(verify_with_secret(&line, KEY).unwrap(), payload);
        // Second presentation of the same nonce (re-sign with same nonce/fresh ts) is replay.
        let line2 = valid_line("e2e-replay-unique", payload);
        assert_eq!(verify_with_secret(&line2, KEY), Err(AuthError::Replay));
    }

    #[test]
    fn e2e_wrong_version_is_rejected() {
        let ts = now_ms();
        let payload = r#"{"type":"Metrics"}"#;
        let sig = sign(KEY, 999, ts, "e2e-ver-1", payload);
        let line = envelope(999, ts, "e2e-ver-1", payload, &sig);
        assert_eq!(verify_with_secret(&line, KEY), Err(AuthError::UnsupportedVersion(999)));
    }

    #[test]
    fn e2e_non_envelope_is_malformed() {
        // A bare (unsigned) command — exactly what the old agent would execute.
        let bare = r#"{"type":"UnsafeCommand","id":"x","raw_command":"rm -rf /"}"#;
        assert_eq!(verify_with_secret(bare, KEY), Err(AuthError::Malformed));
    }
}
