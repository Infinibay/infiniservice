# Linux Commands Reference

This document provides a comprehensive reference for all Linux-specific commands supported by InfiniService.

## Table of Contents

- [Overview](#overview)
- [Update Management Commands](#update-management-commands)
- [Security Commands](#security-commands)
- [Application Inventory Commands](#application-inventory-commands)
- [Disk Cleanup Commands](#disk-cleanup-commands)
- [Health Check Commands](#health-check-commands)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)

## Overview

InfiniService automatically detects the Linux distribution and uses the appropriate package manager and tools. The detection hierarchy is:

1. **Ubuntu/Debian**: Uses `apt`, `dpkg`, `ufw`, AppArmor
2. **Fedora**: Uses `dnf`, `rpm`, `firewalld`, SELinux
3. **CentOS/RHEL**: Uses `yum` or `dnf`, `rpm`, `firewalld`, SELinux
4. **Arch**: Uses `pacman`
5. **OpenSUSE**: Uses `zypper`, `rpm`

All commands are platform-aware and will return appropriate errors when run on unsupported platforms.

## Update Management Commands

### CheckLinuxUpdates

Checks for pending system updates using the detected package manager.

**Request:**
```json
{
  "id": "cmd-001",
  "command_type": {
    "action": "CheckLinuxUpdates"
  },
  "params": null,
  "timeout": 60
}
```

**Response (Success):**
```json
{
  "id": "cmd-001",
  "success": true,
  "stdout": null,
  "stderr": "",
  "exit_code": 0,
  "command_type": "safe",
  "execution_time_ms": 1250,
  "structured_result": {
    "pending_updates": [
      {
        "package_name": "vim",
        "current_version": "2:8.2.3995-1ubuntu2.16",
        "available_version": "2:8.2.3995-1ubuntu2.17",
        "repository": "jammy-security",
        "is_security": true,
        "architecture": "amd64"
      }
    ],
    "security_updates_count": 1,
    "total_pending_count": 5,
    "package_manager": "apt",
    "reboot_required": false,
    "distro": "Ubuntu"
  }
}
```

### GetLinuxUpdateHistory

Retrieves update history from package manager logs.

**Request:**
```json
{
  "id": "cmd-002",
  "command_type": {
    "action": "GetLinuxUpdateHistory",
    "days": 30
  },
  "params": {
    "days": 30
  },
  "timeout": 30
}
```

**Response (Success):**
```json
{
  "id": "cmd-002",
  "success": true,
  "structured_result": [
    {
      "package_name": "vim",
      "version": "2:8.2.3995-1ubuntu2.17",
      "installed_on": "2024-01-15 10:30:45",
      "repository": "jammy-security",
      "action": "Upgrade"
    }
  ]
}
```

**Ubuntu/Debian Source:** `/var/log/apt/history.log`
**Fedora/RHEL Source:** `/var/log/dnf.log` or `/var/log/yum.log`

## Security Commands

### GetLinuxSecurityStatus

Retrieves comprehensive security status including firewall and security module state.

**Request:**
```json
{
  "id": "cmd-003",
  "command_type": {
    "action": "GetLinuxSecurityStatus"
  },
  "params": null,
  "timeout": 30
}
```

**Response (Success):**
```json
{
  "id": "cmd-003",
  "success": true,
  "structured_result": {
    "firewall": {
      "firewall_type": "ufw",
      "enabled": true,
      "status": "active",
      "rules_count": 5,
      "default_incoming": "deny",
      "default_outgoing": "allow",
      "allowed_services": ["22/tcp", "80/tcp", "443/tcp"]
    },
    "security_module": {
      "module_type": "apparmor",
      "enabled": true,
      "profiles_loaded": 50,
      "profiles_enforce": 45,
      "profiles_complain": 5
    },
    "security_updates": [
      {
        "package_name": "openssl",
        "available_version": "3.0.2-0ubuntu1.13",
        "severity": "Critical",
        "advisory_id": "USN-5678-1"
      }
    ],
    "security_updates_count": 2,
    "distro": "Ubuntu"
  }
}
```

### CheckFirewallStatus

Checks the status of the detected firewall.

**Request:**
```json
{
  "id": "cmd-004",
  "command_type": {
    "action": "CheckFirewallStatus"
  },
  "params": null,
  "timeout": 15
}
```

**Response (UFW):**
```json
{
  "id": "cmd-004",
  "success": true,
  "structured_result": {
    "firewall_type": "ufw",
    "enabled": true,
    "status": "active",
    "rules_count": 5,
    "default_incoming": "deny",
    "default_outgoing": "allow",
    "service_status": "active",
    "allowed_services": ["ssh", "http", "https"]
  }
}
```

**Response (firewalld):**
```json
{
  "id": "cmd-004",
  "success": true,
  "structured_result": {
    "firewall_type": "firewalld",
    "enabled": true,
    "status": "active",
    "rules_count": 8,
    "active_zone": "public",
    "service_status": "running",
    "allowed_services": ["ssh", "dhcpv6-client", "http", "https"]
  }
}
```

### Firewall Type Detection

The detection order is:
1. **UFW** - If `ufw status` succeeds and returns status
2. **firewalld** - If `firewall-cmd --state` is available
3. **nftables** - If `nft list tables` returns output
4. **iptables** - Fallback if `iptables` command exists
5. **None** - No firewall detected

## Application Inventory Commands

### GetInstalledApplications

Retrieves a complete inventory of installed applications from all available sources.

**Request:**
```json
{
  "id": "cmd-005",
  "command_type": {
    "action": "GetInstalledApplications"
  },
  "params": null,
  "timeout": 120
}
```

**Response (Success):**
```json
{
  "id": "cmd-005",
  "success": true,
  "structured_result": [
    {
      "name": "vim",
      "version": "2:8.2.3995-1ubuntu2.17",
      "vendor": null,
      "install_date": "2024-01-10",
      "install_type": "DEB",
      "can_update": true,
      "install_location": "/usr/bin/vim",
      "size_mb": 10
    },
    {
      "name": "firefox",
      "version": "120.0-1",
      "vendor": "mozilla",
      "install_type": "Snap",
      "can_update": true,
      "install_location": "/snap/firefox"
    },
    {
      "name": "GIMP",
      "version": "2.10.34",
      "vendor": "gimp.org",
      "install_type": "Flatpak",
      "can_update": true,
      "install_location": "/var/lib/flatpak/app/org.gimp.GIMP"
    }
  ]
}
```

### Package Source Details

| Source | Command | Install Type | Notes |
|--------|---------|--------------|-------|
| dpkg | `dpkg-query -W -f='...'` | DEB | Debian/Ubuntu native packages |
| rpm | `rpm -qa --queryformat '...'` | RPM | Fedora/RHEL/CentOS native packages |
| snap | `snap list` | Snap | Universal Linux packages |
| flatpak | `flatpak list --app` | Flatpak | Universal Linux applications |

### Deduplication Logic

Applications are deduplicated based on:
- Name (case-insensitive)
- Version
- Install type

This means the same application installed via different sources (e.g., Firefox from both DEB and Snap) will be listed separately.

## Disk Cleanup Commands

### EstimateDiskCleanup

Estimates reclaimable disk space from various cleanup operations.

**Request:**
```json
{
  "id": "cmd-006",
  "command_type": {
    "action": "EstimateDiskCleanup"
  },
  "params": null,
  "timeout": 60
}
```

**Response (Success):**
```json
{
  "id": "cmd-006",
  "success": true,
  "structured_result": {
    "total_reclaimable_mb": 2048,
    "breakdown": {
      "package_cache_mb": 512,
      "old_kernels_mb": 1024,
      "temp_files_mb": 256,
      "log_files_mb": 128,
      "autoremove_packages_mb": 128
    },
    "cleanup_commands": {
      "apt_clean": "sudo apt-get clean",
      "apt_autoremove": "sudo apt-get autoremove",
      "journal_vacuum": "sudo journalctl --vacuum-time=7d",
      "tmp_cleanup": "sudo rm -rf /tmp/*"
    },
    "warnings": [
      "Old kernels found: 3 (keeping current + 1 previous)"
    ]
  }
}
```

### Cleanup Locations

| Path | Description | Cleanup Command |
|------|-------------|-----------------|
| `/var/cache/apt/archives` | APT package cache | `apt-get clean` |
| `/var/cache/dnf` | DNF package cache | `dnf clean all` |
| `/tmp` | Temporary files | Manual cleanup |
| `/var/tmp` | Persistent temp files | Manual cleanup |
| `/var/log/journal` | Systemd journal | `journalctl --vacuum-time=7d` |
| Old kernels | Unused kernel packages | `apt autoremove` or `dnf autoremove` |

### Safety Exclusions

The following patterns are never cleaned:
- `/tmp/.X11-unix` - X11 sockets
- `/tmp/.ICE-unix` - ICE sockets
- `/tmp/systemd-private-*` - Systemd private temp directories
- Running kernel - Always preserved

## Health Check Commands

### LinuxUpdatesCheck

Automated health check for Linux update status.

**Check Metadata:**
```json
{
  "name": "linux_updates",
  "category": "Security",
  "can_auto_remediate": false
}
```

**Status Thresholds:**
- **Healthy**: No pending updates
- **Warning**: < 5 security updates, or any regular updates
- **Critical**: > 5 security updates

### LinuxSecurityCheck

Automated health check for Linux security configuration.

**Check Metadata:**
```json
{
  "name": "linux_security",
  "category": "Security",
  "can_auto_remediate": true
}
```

**Remediation Actions:**
- Enable UFW: `sudo ufw enable`
- Start firewalld: `sudo systemctl start firewalld`
- Set SELinux enforcing: `sudo setenforce 1`

**Status Thresholds:**
- **Healthy**: Firewall enabled, security module active
- **Warning**: Firewall disabled OR security module in permissive mode
- **Critical**: Both firewall disabled AND security module disabled

## Error Handling

### Common Error Codes

| Error | Description | Resolution |
|-------|-------------|------------|
| `PLATFORM_NOT_SUPPORTED` | Command run on non-Linux platform | Use Windows-specific command |
| `PACKAGE_MANAGER_NOT_FOUND` | No package manager detected | Install appropriate package manager |
| `PERMISSION_DENIED` | Insufficient privileges | Run with elevated permissions |
| `COMMAND_TIMEOUT` | Command execution timed out | Increase timeout or check system load |
| `PARSE_ERROR` | Failed to parse command output | Check for unusual output format |

### Error Response Format

```json
{
  "id": "cmd-001",
  "success": false,
  "stdout": "",
  "stderr": "Linux Updates check is only available on Linux",
  "exit_code": 1,
  "command_type": "safe",
  "execution_time_ms": 5,
  "error": {
    "code": "PLATFORM_NOT_SUPPORTED",
    "message": "This command is only available on Linux systems"
  }
}
```

## Best Practices

### Performance Optimization

1. **Use Appropriate Timeouts**
   - Update checks: 60-120 seconds (package metadata refresh)
   - Security checks: 15-30 seconds
   - Application inventory: 60-120 seconds (multiple sources)

2. **Batch Related Requests**
   - Combine `CheckLinuxUpdates` and `GetLinuxSecurityStatus` in health checks
   - Cache application inventory results (changes infrequently)

3. **Handle Rate Limiting**
   - Package manager operations may lock databases
   - Implement retry logic with exponential backoff

### Security Considerations

1. **Privilege Escalation**
   - Update installation requires sudo
   - Firewall modification requires sudo
   - Health checks are read-only (no sudo required)

2. **Input Validation**
   - All safe commands validate parameters before execution
   - Package names are sanitized to prevent command injection

3. **Audit Logging**
   - All commands are logged with timestamps
   - Failed commands include error details
   - Security-sensitive operations have enhanced logging

### Distribution-Specific Notes

#### Ubuntu/Debian
- Security updates identified by `-security` in repository name
- AppArmor profiles in `/etc/apparmor.d/`
- Update history in `/var/log/apt/history.log`

#### Fedora
- Security updates from `dnf updateinfo list security`
- SELinux status from `getenforce` command
- DNF modules may require additional handling

#### CentOS/RHEL
- May use `yum` (older) or `dnf` (newer)
- SELinux policies in `/etc/selinux/config`
- EPEL repository may be needed for some packages

## Flow Diagrams

### Update Check Flow

```
┌─────────────────┐
│ CheckLinuxUpdates│
└────────┬────────┘
         │
    ┌────▼────┐
    │ Detect  │
    │ Distro  │
    └────┬────┘
         │
    ┌────▼────────────┐
    │ apt list        │ ◄── Ubuntu/Debian
    │ --upgradable    │
    └─────────────────┘
         │
    ┌────▼────────────┐
    │ dnf check-update│ ◄── Fedora
    └─────────────────┘
         │
    ┌────▼────────────┐
    │ Parse output    │
    │ - Count total   │
    │ - Count security│
    └────────┬────────┘
         │
    ┌────▼────────────┐
    │ Check reboot    │
    │ required flag   │
    └────────┬────────┘
         │
    ┌────▼────────────┐
    │ Return          │
    │ LinuxUpdateStatus│
    └─────────────────┘
```

### Security Check Flow

```
┌───────────────────┐
│GetLinuxSecurityStatus│
└─────────┬─────────┘
          │
     ┌────▼────┐
     │ Detect  │
     │ Firewall│
     └────┬────┘
          │
    ┌─────┴─────┐
    │           │
┌───▼───┐  ┌───▼───┐
│  UFW  │  │firewalld│
│ status│  │ --state │
└───┬───┘  └───┬───┘
    │          │
    └────┬─────┘
         │
    ┌────▼────────────┐
    │ Detect Security │
    │ Module          │
    └────┬────────────┘
         │
    ┌────┴────┐
    │         │
┌───▼───┐ ┌───▼───┐
│AppArmor│ │SELinux│
│status  │ │getenforce│
└───┬───┘ └───┬───┘
    │         │
    └────┬────┘
         │
    ┌────▼────────────┐
    │ Check Security  │
    │ Updates         │
    └────────┬────────┘
         │
    ┌────▼────────────┐
    │ Return          │
    │ LinuxSecurityStatus│
    └─────────────────┘
```
