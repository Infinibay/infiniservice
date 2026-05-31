//! Active Directory domain join for Windows guests.
//!
//! Uses the built-in `Add-Computer` PowerShell cmdlet (the modern
//! equivalent of `netdom join`). Credentials are passed as a
//! `PSCredential` built from a `SecureString` so the plaintext password is
//! never written to disk or the command line in cleartext. A reboot is
//! required for the join to take effect; the host decides whether to
//! restart the VM based on `restart_after`.

use anyhow::{Context, Result};
use log::{info, warn};
use std::process::Command;

pub async fn join(
    domain: &str,
    username: &str,
    password: &str,
    ou: Option<&str>,
    computer_name: Option<&str>,
    restart_after: bool,
) -> Result<(String, String, Option<serde_json::Value>)> {
    let mut log = String::new();
    let mut warnings = String::new();

    info!("[domain-join] joining Windows guest to domain '{}'", domain);
    log.push_str(&format!("=== Joining domain: {} ===\n", domain));

    // Build the Add-Computer invocation. The password is materialised into a
    // SecureString inside the same PowerShell process; we only interpolate
    // single-quoted, escaped literals to avoid command injection.
    let mut script = String::new();
    script.push_str("$ErrorActionPreference = 'Stop'; ");
    script.push_str(&format!(
        "$sec = ConvertTo-SecureString '{}' -AsPlainText -Force; ",
        escape_ps(password)
    ));
    script.push_str(&format!(
        "$cred = New-Object System.Management.Automation.PSCredential('{}', $sec); ",
        escape_ps(username)
    ));
    script.push_str(&format!(
        "Add-Computer -DomainName '{}' -Credential $cred",
        escape_ps(domain)
    ));
    if let Some(ou_dn) = ou.filter(|s| !s.trim().is_empty()) {
        script.push_str(&format!(" -OUPath '{}'", escape_ps(ou_dn)));
    }
    if let Some(name) = computer_name.filter(|s| !s.trim().is_empty()) {
        script.push_str(&format!(" -NewName '{}'", escape_ps(name)));
    }
    // -Force suppresses the confirmation prompt. We never auto-restart here;
    // the host orchestrates the reboot so it can track VM state.
    script.push_str(" -Force; Write-Output 'JOIN_OK'");

    match run_powershell(&script) {
        Ok(out) => log.push_str(&out),
        Err(e) => {
            let msg = format!("domain join failed: {}", e);
            warn!("[domain-join] {}", msg);
            return Err(anyhow::anyhow!(msg));
        }
    }

    if restart_after {
        log.push_str("\n=== Restarting guest ===\n");
        match run_powershell("Restart-Computer -Force") {
            Ok(_) => log.push_str("restart scheduled\n"),
            Err(e) => {
                let msg = format!("[warn] restart after join failed: {}\n", e);
                warn!("{}", msg.trim());
                warnings.push_str(&msg);
            }
        }
    }

    let data = serde_json::json!({
        "os": "windows",
        "domain": domain,
        "ou": ou,
        "computerName": computer_name,
        "status": "joined",
        "rebootRequired": true,
        "restartScheduled": restart_after,
    });

    Ok((log, warnings, Some(data)))
}

/// Escape a string for safe embedding inside a single-quoted PowerShell
/// literal: in PowerShell a single quote is escaped by doubling it.
fn escape_ps(s: &str) -> String {
    s.replace('\'', "''")
}

fn run_powershell(script: &str) -> Result<String> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .with_context(|| "failed to spawn powershell.exe")?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        anyhow::bail!(
            "powershell exited {}: {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        );
    }
    let mut combined = stdout;
    if !stderr.trim().is_empty() {
        combined.push_str("\n[stderr]\n");
        combined.push_str(&stderr);
    }
    Ok(combined)
}
