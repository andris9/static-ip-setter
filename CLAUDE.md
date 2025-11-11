# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Rules for This Repository

1. **No emojis**: Do not use emojis anywhere (not in code, not in documentation, not in commit messages)
2. **Git commits**: Do not include Claude as co-contributor in git commit messages
3. **Use ocr-exercise-builder agent**: This is an OCR Deputy package - use the ocr-exercise-builder agent for all development tasks related to this package
4. **CLAUDE.md is internal**: Do not reference CLAUDE.md from package.toml or other project files - it is for Claude Code only, not part of the package distribution

## Project Overview

This is an Open Cyber Range (OCR) Deputy package that provides static IPv4 configuration for Ubuntu/Kali Linux systems in offline/air-gapped CTF environments where DHCP and Internet connectivity cannot be assumed.

The package installs as a feature service that configures network interfaces during system initialization.

## Architecture

**Package Type**: Deputy feature package (OCR exercise component)
**Package Format**: TOML-based package definition with shell script asset
**Deployment**: Installs script to `/tmp/static-ip-setter/static-ip.sh` with executable permissions

### Core Components

- `package.toml`: Deputy package manifest defining the feature service
- `src/static-ip.sh`: Main network configuration script

### Network Configuration Strategy

The script attempts network configuration in priority order:

1. **netplan** (primary method for modern Ubuntu)
2. **NetworkManager** via `nmcli` (Kali desktop images)
3. **systemd-networkd** (if active)
4. **Temporary IP** (fallback using `ip` commands, non-persistent)

Each method is attempted only if the corresponding tool/service is available.

## Configuration

The script is controlled via environment variables:

- `STATIC_IP` (required): IP address with CIDR notation (e.g., `10.1.1.3/24`)
- `IFACE` (optional): Network interface name; auto-detected if not set
- `GATEWAY` (optional): Default gateway IP address
- `DNS` (optional): Comma-separated DNS servers

### Interface Auto-Detection

When `IFACE` is not specified, detection logic:
1. Filters out loopback, docker, bridge, and virtual interfaces
2. Prefers predictable naming patterns: `enp*`, `ens*`, `eth*`
3. Checks for carrier status (LOWER_UP) and operational state
4. Falls back to first available physical interface

## Special Handling

**Cloud-init & Installer Netplan Neutralization**: The script disables cloud-init networking and removes conflicting netplan YAML files that may contain hardcoded IPs from system installation. This prevents conflicts in CTF VM environments.

**Offline-Safe Design**: No external connectivity required; all operations work in air-gapped environments.

## Testing

Since this is a system-level networking script requiring root privileges:

- Test in isolated VMs (Ubuntu/Kali)
- Verify each configuration method independently
- Test auto-detection with various network interface configurations
- Validate behavior when multiple network managers are present

## Common Development Tasks

**Syntax validation**:
```bash
shellcheck src/static-ip.sh
```

**Manual testing** (requires root):
```bash
sudo STATIC_IP=10.1.1.3/24 GATEWAY=10.1.1.1 ./src/static-ip.sh
```

## Release Process

This package uses the universal Deputy release script located at `../release.sh`.

**Prerequisites**:
- Docker installed and running
- Deputy credentials configured in `~/.deputy`
- `deputy-ubuntu:24.04` Docker image available
- All changes committed to git

**Release steps**:
```bash
# From the package directory
../release.sh <version> -y

# Example:
../release.sh 1.0.0 -y
```

The release script will:
1. Update version in `package.toml`
2. Commit version bump
3. Create git tag `v<version>`
4. Push commit and tag to origin
5. Publish package to Deputy registry
6. Verify publication

**Version format**: Use semantic versioning (e.g., 1.0.0, 1.1.0, 2.0.0)
