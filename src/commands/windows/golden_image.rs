//! Golden-image preparation for Windows guests.
//!
//! Cleans transient state and invokes sysprep /generalize so the host can
//! snapshot the disk as a sealed template. On next boot the guest runs
//! OOBE with a fresh SID, machine name, and RDP/Windows Update state.
//!
//! Note on the sysprep rearm limit: Windows imposes a hard cap (3 by
//! default, SKU-dependent) on how many times /generalize can be invoked
//! on the same image. Repeated captures from the same source VM will
//! eventually fail; the design choice (Fase 5 plan, open question #3) is
//! to document this rather than auto-slmgr /rearm.

use super::super::CleanupLevel;
use anyhow::{Context, Result};
use log::{info, warn};
use std::process::Command;

/// Minimal sysprep answer file. Skips OOBE prompts after generalize so
/// the next boot lands in the logon screen with the built-in admin.
/// Intentionally does NOT bake in credentials — those belong to the
/// per-VM unattended ISO at clone time, not to the sealed image.
const SYSPREP_UNATTEND_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
    </component>
  </settings>
</unattend>
"#;

pub async fn prepare(
    cleanup_level: CleanupLevel,
    sanitize_user_data: bool,
    shutdown_after: bool,
) -> Result<(String, String, Option<serde_json::Value>)> {
    let mut log = String::new();
    let mut warnings = String::new();

    macro_rules! step {
        ($label:expr, $script:expr) => {{
            let label: &str = $label;
            let script: &str = $script;
            info!("[golden-image] step: {}", label);
            log.push_str(&format!("\n=== {} ===\n", label));
            match run_powershell(script) {
                Ok(out) => {
                    log.push_str(&out);
                }
                Err(e) => {
                    let msg = format!("[warn] {}: {}\n", label, e);
                    warn!("{}", msg.trim());
                    warnings.push_str(&msg);
                }
            }
        }};
    }

    step!("Stop Windows Update service + purge download cache",
        "Stop-Service wuauserv -Force -ErrorAction SilentlyContinue; \
         if (Test-Path \"$env:windir\\SoftwareDistribution\\Download\") { \
           Get-ChildItem \"$env:windir\\SoftwareDistribution\\Download\" -Recurse -Force -ErrorAction SilentlyContinue | \
             Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }");

    step!("Clear temp directories",
        "Remove-Item -Recurse -Force -ErrorAction SilentlyContinue \
           \"$env:TEMP\\*\", \"$env:windir\\Temp\\*\", \"$env:windir\\Prefetch\\*\"");

    step!("Clear event logs",
        "wevtutil el | ForEach-Object { try { wevtutil cl \"$_\" } catch { } }");

    if matches!(cleanup_level, CleanupLevel::Standard | CleanupLevel::Deep) {
        step!("Delete VSS shadow copies (restore points)",
            "vssadmin delete shadows /all /quiet 2>$null; exit 0");

        step!("Release DHCP lease and flush DNS",
            "ipconfig /release | Out-Null; ipconfig /flushdns | Out-Null");

        step!("Remove Terminal Server / RDP certificates",
            "Remove-Item -Recurse -Force -ErrorAction SilentlyContinue \
               'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\RCM\\Certificate'");
    }

    if matches!(cleanup_level, CleanupLevel::Deep) {
        step!("Compact NTFS (deep)",
            "compact.exe /c /s:$env:windir /i /q 2>$null; exit 0");
    }

    if sanitize_user_data {
        step!(
            "Delete non-built-in user profiles",
            "Get-CimInstance -ClassName Win32_UserProfile | \
               Where-Object { -not $_.Special -and \
                              $_.LocalPath -notmatch '\\\\Administrator$' -and \
                              $_.LocalPath -notmatch '\\\\DefaultAccount$' -and \
                              $_.LocalPath -notmatch '\\\\Guest$' -and \
                              $_.LocalPath -notmatch '\\\\WDAGUtilityAccount$' } | \
               ForEach-Object { try { $_ | Remove-CimInstance } catch { } }"
        );
    }

    step!("Write sysprep unattend.xml",
        &format!(
            "$dir = 'C:\\sysprep'; if (-not (Test-Path $dir)) {{ New-Item -ItemType Directory -Path $dir | Out-Null }}; \
             Set-Content -Path 'C:\\sysprep\\unattend.xml' -Value @'\n{}\n'@ -Encoding UTF8",
            SYSPREP_UNATTEND_XML
        ));

    // Trigger sysprep. /generalize resets SID and machine-specific state;
    // /oobe drops the guest back into OOBE; /shutdown (or /quit) controls
    // what happens after sealing completes.
    //
    // We spawn-and-detach — sysprep tears down processes including this
    // agent, so we must let the host detect shutdown via infinization
    // lifecycle events rather than waiting for a reply here.
    let post_action = if shutdown_after { "/shutdown" } else { "/quit" };
    let sysprep_cmd = format!(
        "Start-Process -FilePath 'C:\\Windows\\System32\\Sysprep\\sysprep.exe' \
         -ArgumentList '/generalize','/oobe','{}','/quiet','/unattend:C:\\sysprep\\unattend.xml'",
        post_action
    );
    info!("[golden-image] launching sysprep: {}", post_action);
    log.push_str(&format!("\n=== Launch sysprep ({}) ===\n", post_action));
    match run_powershell(&sysprep_cmd) {
        Ok(out) => log.push_str(&out),
        Err(e) => {
            // Even if the launch command itself returns an error (e.g.
            // because sysprep kills the parent mid-output), we want the
            // host to see what we attempted.
            warnings.push_str(&format!("[warn] sysprep launch: {}\n", e));
        }
    }

    let data = serde_json::json!({
        "os": "windows",
        "cleanup_level": format!("{:?}", cleanup_level).to_lowercase(),
        "sanitize_user_data": sanitize_user_data,
        "shutdown_after": shutdown_after,
        "sysprep_launched": true,
    });

    Ok((log, warnings, Some(data)))
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
