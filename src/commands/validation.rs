//! Strict, allowlist-based validation of host-supplied command parameters.
//!
//! Even though the command channel is now HMAC-authenticated, message *content*
//! is still treated as hostile (defense in depth: a bug, a compromised host, or
//! a future unauthenticated path must never reach a shell with attacker data).
//!
//! Validation is by **allowlist** — only a known-safe character set passes —
//! never by blacklist. The previous `name.contains("&"|"|"|";"|"$")` checks were
//! blacklists, and they let `'`, backtick, and newline through, which is exactly
//! what enabled the PowerShell injection in `control_service`
//! (`Start-Service -Name '{}'`). An allowlist cannot be bypassed by a
//! metacharacter the author forgot to think of.

use anyhow::{anyhow, Result};

/// Generic upper bound for an identifier-like field.
const MAX_NAME_LEN: usize = 256;
/// Search queries are free-text-ish but still bounded.
const MAX_QUERY_LEN: usize = 256;

fn ensure(value: &str, field: &str, max_len: usize, allowed: impl Fn(char) -> bool) -> Result<()> {
    if value.is_empty() {
        return Err(anyhow!("{} must not be empty", field));
    }
    if value.len() > max_len {
        return Err(anyhow!("{} exceeds {} bytes", field, max_len));
    }
    if let Some(bad) = value.chars().find(|&c| !allowed(c)) {
        return Err(anyhow!(
            "{} contains a disallowed character: {:?}",
            field, bad
        ));
    }
    Ok(())
}

/// Service name (systemd unit / Windows service). No spaces, quotes, or shell
/// metacharacters — only `[A-Za-z0-9._@:-]`.
pub fn validate_service_name(name: &str) -> Result<()> {
    ensure(name, "service name", MAX_NAME_LEN, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | ':')
    })
}

/// Package identifier (apt/dnf/winget). winget IDs use dots (e.g.
/// `Microsoft.Edge`); allow `[A-Za-z0-9._+:-]`.
pub fn validate_package_name(name: &str) -> Result<()> {
    ensure(name, "package name", MAX_NAME_LEN, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | ':')
    })
}

/// Generic service-or-package entity name — the union of the service and
/// package character sets. Used by the trait implementations' `validate_name`
/// so they share one allowlist instead of a (previously single-quote-permitting)
/// blacklist. `entity_type` is only for the error message.
pub fn validate_entity_name(name: &str, entity_type: &str) -> Result<()> {
    ensure(name, entity_type, MAX_NAME_LEN, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | ':' | '+')
    })
}

/// Package search query: free-text-ish but still allowlisted to alnum, space,
/// and a few separators. Rejects quotes, backticks, `$`, `;`, `&`, `|`, etc.
pub fn validate_search_query(query: &str) -> Result<()> {
    ensure(query, "search query", MAX_QUERY_LEN, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | ' ')
    })
}

/// Fully-qualified domain name: `[A-Za-z0-9.-]`.
pub fn validate_domain(name: &str) -> Result<()> {
    ensure(name, "domain", MAX_NAME_LEN, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '-')
    })
}

/// Account name, allowing `DOMAIN\user`, `user@domain`, and bare names:
/// `[A-Za-z0-9._@\-]` plus backslash.
pub fn validate_account_name(name: &str) -> Result<()> {
    ensure(name, "account name", MAX_NAME_LEN, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | '\\')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_the_powershell_injection_vectors() {
        // The exact bypasses the old blacklist allowed.
        for evil in ["a'; Stop-Computer #", "svc`whoami`", "a\nb", "a$b", "a;b", "a|b", "a&b", "'"] {
            assert!(validate_service_name(evil).is_err(), "should reject {:?}", evil);
        }
    }

    #[test]
    fn accepts_legitimate_names() {
        for ok in ["sshd", "nginx.service", "infiniservice", "user@host", "systemd-journald"] {
            assert!(validate_service_name(ok).is_ok(), "should accept {:?}", ok);
        }
        assert!(validate_package_name("Microsoft.Edge").is_ok());
        assert!(validate_package_name("lib32-mesa+extras").is_ok());
        assert!(validate_search_query("visual studio code").is_ok());
        assert!(validate_domain("corp.example.com").is_ok());
        assert!(validate_account_name("CORP\\admin").is_ok());
        assert!(validate_account_name("admin@corp.example.com").is_ok());
    }

    #[test]
    fn rejects_empty_and_oversized() {
        assert!(validate_service_name("").is_err());
        assert!(validate_search_query(&"a".repeat(10_000)).is_err());
    }

    #[test]
    fn search_query_rejects_quotes_and_metachars() {
        for evil in ["a\"b", "a'b", "a`b", "a$b", "a;b"] {
            assert!(validate_search_query(evil).is_err(), "should reject {:?}", evil);
        }
    }
}
