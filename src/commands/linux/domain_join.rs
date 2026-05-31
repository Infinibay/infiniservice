//! Active Directory / LDAP domain join for Linux guests.
//!
//! Uses `realm join` with the sssd backend — the standard, distro-agnostic
//! path that also wires up PAM/NSS so domain users can log in. The realmd
//! and sssd packages are installed first via the distro package manager.
//! The join password is piped to realm's stdin (`--stdin-password`) so it
//! never appears in the process list.

use crate::os_detection::LinuxDistro;
use anyhow::{Context, Result};
use log::{info, warn};
use std::io::Write;
use std::process::{Command, Stdio};

pub async fn join(
    distro: &LinuxDistro,
    domain: &str,
    username: &str,
    password: &str,
    ou: Option<&str>,
    computer_name: Option<&str>,
    restart_after: bool,
) -> Result<(String, String, Option<serde_json::Value>)> {
    let mut log = String::new();
    let mut warnings = String::new();

    info!("[domain-join] joining Linux guest to domain '{}'", domain);
    log.push_str(&format!("=== Joining domain: {} ===\n", domain));

    // 1. Install realmd + sssd toolchain for the distro.
    let install_cmd = match distro {
        LinuxDistro::Ubuntu | LinuxDistro::Debian => Some(
            "export DEBIAN_FRONTEND=noninteractive; \
             apt-get update && apt-get install -y \
             realmd sssd sssd-tools libnss-sss libpam-sss adcli samba-common-bin oddjob oddjob-mkhomedir packagekit",
        ),
        LinuxDistro::Fedora | LinuxDistro::RedHat | LinuxDistro::CentOS => Some(
            "dnf install -y realmd sssd sssd-tools adcli samba-common-tools oddjob oddjob-mkhomedir",
        ),
        _ => None,
    };

    if let Some(cmd) = install_cmd {
        log.push_str("\n=== Installing realmd / sssd ===\n");
        match run_sh(cmd) {
            Ok(out) => log.push_str(&out),
            Err(e) => {
                let msg = format!("[warn] package install reported an issue: {}\n", e);
                warn!("{}", msg.trim());
                warnings.push_str(&msg);
            }
        }
    } else {
        let msg = format!(
            "[warn] unsupported distro {:?}; attempting realm join with whatever is installed\n",
            distro
        );
        warn!("{}", msg.trim());
        warnings.push_str(&msg);
    }

    // 2. Build the realm join command. The password comes via stdin so it is
    //    never visible in `ps`. OU / computer name are optional realm flags.
    let mut realm_cmd = format!(
        "realm join --user={} --stdin-password",
        shell_quote(username)
    );
    if let Some(ou_dn) = ou.filter(|s| !s.trim().is_empty()) {
        realm_cmd.push_str(&format!(" --computer-ou={}", shell_quote(ou_dn)));
    }
    if let Some(name) = computer_name.filter(|s| !s.trim().is_empty()) {
        realm_cmd.push_str(&format!(" --computer-name={}", shell_quote(name)));
    }
    realm_cmd.push(' ');
    realm_cmd.push_str(&shell_quote(domain));

    log.push_str("\n=== realm join ===\n");
    match run_sh_with_stdin(&realm_cmd, password) {
        Ok(out) => log.push_str(&out),
        Err(e) => {
            let msg = format!("domain join failed: {}", e);
            warn!("[domain-join] {}", msg);
            return Err(anyhow::anyhow!(msg));
        }
    }

    // 3. Enable home-dir creation on first login (best-effort).
    log.push_str("\n=== Configure home directory creation ===\n");
    match run_sh("pam-auth-update --enable mkhomedir 2>/dev/null || authselect enable-feature with-mkhomedir 2>/dev/null || true") {
        Ok(out) => log.push_str(&out),
        Err(e) => warnings.push_str(&format!("[warn] mkhomedir config: {}\n", e)),
    }

    // 4. Verify membership.
    log.push_str("\n=== Verify membership ===\n");
    match run_sh("realm list") {
        Ok(out) => log.push_str(&out),
        Err(e) => warnings.push_str(&format!("[warn] realm list: {}\n", e)),
    }

    if restart_after {
        log.push_str("\n=== Restarting guest ===\n");
        // Schedule a reboot shortly so the response can flush first.
        match run_sh("(sleep 3 && systemctl reboot) >/dev/null 2>&1 &") {
            Ok(_) => log.push_str("restart scheduled\n"),
            Err(e) => warnings.push_str(&format!("[warn] restart after join failed: {}\n", e)),
        }
    }

    let data = serde_json::json!({
        "os": "linux",
        "distro": format!("{:?}", distro).to_lowercase(),
        "domain": domain,
        "ou": ou,
        "computerName": computer_name,
        "status": "joined",
        "rebootRequired": false,
        "restartScheduled": restart_after,
    });

    Ok((log, warnings, Some(data)))
}

/// POSIX single-quote escaping: wrap in single quotes, and close/reopen
/// around any embedded single quote.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn run_sh(cmd: &str) -> Result<String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .with_context(|| "failed to spawn sh")?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        anyhow::bail!(
            "command exited {}: {}",
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

/// Like `run_sh` but feeds `stdin_data` to the command's standard input.
/// Used to pass the join password to `realm --stdin-password`.
fn run_sh_with_stdin(cmd: &str, stdin_data: &str) -> Result<String> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| "failed to spawn sh")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_data.as_bytes())
            .with_context(|| "failed to write password to realm stdin")?;
        // Drop closes the pipe so realm stops reading.
    }

    let output = child
        .wait_with_output()
        .with_context(|| "failed to wait for realm join")?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        anyhow::bail!(
            "command exited {}: {}",
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
