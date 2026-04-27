//! Golden-image preparation for Linux guests (Ubuntu/Debian + Fedora).
//!
//! The pattern mirrors Windows sysprep conceptually: wipe machine-unique
//! state so first boot regenerates it. For Linux that means cloud-init
//! state, machine-id, SSH host keys, DHCP leases, and logs. On Fedora we
//! also touch `/.autorelabel` so SELinux rebuilds context labels against
//! the new ID.

use super::super::CleanupLevel;
use crate::os_detection::LinuxDistro;
use anyhow::{Context, Result};
use log::{info, warn};
use std::process::Command;
use std::thread;
use std::time::Duration;

pub async fn prepare(
    distro: &LinuxDistro,
    cleanup_level: CleanupLevel,
    sanitize_user_data: bool,
    shutdown_after: bool,
) -> Result<(String, String, Option<serde_json::Value>)> {
    let mut log = String::new();
    let mut warnings = String::new();

    macro_rules! step {
        ($label:expr, $cmd:expr) => {{
            let label: &str = $label;
            let cmd: &str = $cmd;
            info!("[golden-image] step: {}", label);
            log.push_str(&format!("\n=== {} ===\n", label));
            match run_sh(cmd) {
                Ok(out) => log.push_str(&out),
                Err(e) => {
                    let msg = format!("[warn] {}: {}\n", label, e);
                    warn!("{}", msg.trim());
                    warnings.push_str(&msg);
                }
            }
        }};
    }

    step!(
        "cloud-init clean",
        "command -v cloud-init >/dev/null 2>&1 && cloud-init clean --logs --seed || true"
    );

    step!(
        "Truncate /var/log",
        "find /var/log -type f \\( -name '*.log' -o -name '*.gz' -o -name '*.old' -o -name '*.[0-9]' \\) \
         -exec truncate -s 0 {} \\; 2>/dev/null; \
         journalctl --rotate >/dev/null 2>&1 || true; \
         journalctl --vacuum-time=1s >/dev/null 2>&1 || true; \
         rm -rf /var/log/journal/*/*.journal 2>/dev/null || true"
    );

    step!(
        "Regenerate machine-id on next boot",
        "truncate -s 0 /etc/machine-id 2>/dev/null || rm -f /etc/machine-id; \
         rm -f /var/lib/dbus/machine-id"
    );

    step!(
        "Remove SSH host keys",
        "rm -f /etc/ssh/ssh_host_*"
    );

    step!(
        "Clear shell history",
        "shred -u /root/.bash_history 2>/dev/null || rm -f /root/.bash_history; \
         for h in /home/*/.bash_history; do [ -f \"$h\" ] && shred -u \"$h\" 2>/dev/null || rm -f \"$h\"; done; \
         history -c 2>/dev/null || true"
    );

    if matches!(cleanup_level, CleanupLevel::Standard | CleanupLevel::Deep) {
        step!(
            "Reset NetworkManager connections",
            "rm -f /etc/NetworkManager/system-connections/*.nmconnection 2>/dev/null || true; \
             rm -f /etc/netplan/50-cloud-init.yaml 2>/dev/null || true"
        );

        step!(
            "Clear DHCP leases",
            "rm -f /var/lib/dhcp/*.leases /var/lib/NetworkManager/*.lease 2>/dev/null || true"
        );
    }

    // Package-manager cache cleanup varies per distro.
    match distro {
        LinuxDistro::Ubuntu | LinuxDistro::Debian => {
            step!(
                "apt clean",
                "apt-get clean 2>/dev/null || true; \
                 rm -rf /var/lib/apt/lists/* 2>/dev/null || true"
            );
        }
        LinuxDistro::Fedora | LinuxDistro::RedHat | LinuxDistro::CentOS => {
            step!(
                "dnf clean all + SELinux autorelabel",
                "(dnf clean all 2>/dev/null || yum clean all 2>/dev/null || true); \
                 touch /.autorelabel"
            );
        }
        _ => {
            log.push_str(&format!(
                "\n[info] no package-cache cleanup for distro {:?}\n",
                distro
            ));
        }
    }

    if matches!(cleanup_level, CleanupLevel::Deep) {
        step!(
            "Zero free space (deep)",
            "command -v fstrim >/dev/null 2>&1 && fstrim -a 2>/dev/null || true"
        );
    }

    if sanitize_user_data {
        // Only deletes users with UID >= 1000 (non-system). Does not
        // touch root or system accounts. Removes home dirs after userdel
        // in case some left orphans behind.
        step!(
            "Delete non-system users and their home directories",
            "awk -F: '$3>=1000 && $1!=\"nobody\" {print $1}' /etc/passwd | while read u; do \
               userdel -rf \"$u\" 2>/dev/null || true; \
             done; \
             rm -rf /home/* 2>/dev/null || true"
        );
    }

    let data = serde_json::json!({
        "os": "linux",
        "distro": format!("{:?}", distro).to_lowercase(),
        "cleanup_level": format!("{:?}", cleanup_level).to_lowercase(),
        "sanitize_user_data": sanitize_user_data,
        "shutdown_after": shutdown_after,
    });

    if shutdown_after {
        // Spawn shutdown in the background with a short grace window so
        // the caller gets a response before systemd tears the agent down.
        info!("[golden-image] scheduling poweroff in 3s");
        thread::spawn(|| {
            thread::sleep(Duration::from_secs(3));
            let _ = Command::new("sh")
                .arg("-c")
                .arg("systemctl poweroff --no-wall 2>/dev/null || poweroff -f")
                .status();
        });
    }

    Ok((log, warnings, Some(data)))
}

fn run_sh(cmd: &str) -> Result<String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .with_context(|| "failed to spawn sh")?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    // Non-zero exit is surfaced as a warning, not an error — cleanup
    // scripts intentionally tolerate partial failures.
    let mut combined = stdout;
    if !output.status.success() {
        combined.push_str(&format!(
            "\n[exit {}] {}\n",
            output.status.code().unwrap_or(-1),
            stderr
        ));
    } else if !stderr.trim().is_empty() {
        combined.push_str("\n[stderr]\n");
        combined.push_str(&stderr);
    }
    Ok(combined)
}
