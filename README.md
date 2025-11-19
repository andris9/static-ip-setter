# static-ip-setter

**GitHub Repository:** https://github.com/andris9/static-ip-setter

Static IPv4 configuration package for Ubuntu/Kali Linux systems in Open Cyber Range.

## Overview

This OCR Deputy feature package configures static IPv4 addresses on systems where DHCP and Internet connectivity cannot be assumed. It selects the appropriate network configuration method based on what's available on the system.

## Features

- **Multi-method configuration**: Supports netplan, NetworkManager, systemd-networkd, and temporary IP fallback
- **Interface detection**: Automatically detects physical network interfaces, filtering out virtual/container interfaces
- **Cloud-init neutralization**: Disables cloud-init networking and removes conflicting netplan configurations
- **Configuration verification**: Verifies IP assignment with 10-second polling
- **systemd-resolved aware**: Properly handles DNS configuration on modern systems
- **Comprehensive logging**: Detailed logs to `/var/log/static-ip-setter.log` for debugging
- **Offline-safe design**: No external connectivity required

## Configuration

The script is controlled via environment variables:

- `STATIC_IP` (required): IP address with CIDR notation (e.g., `10.1.1.20/24`)
- `IFACE` (optional): Network interface name (default: `ens192`; auto-detected if interface does not exist)
- `GATEWAY` (optional): Default gateway IP address
- `DNS` (optional): Comma-separated DNS servers (e.g., `8.8.8.8,8.8.4.4`)
- `SUDO_PASSWORD` (optional): Password for sudo elevation if required (e.g., on Kali Linux)

## Network Configuration Methods

The script attempts configuration in priority order:

1. **netplan** - Modern Ubuntu systems (18.04+)
2. **NetworkManager** - Kali desktop and Ubuntu desktop variants
3. **systemd-networkd** - Server configurations
4. **Temporary IP** - Universal fallback (non-persistent across reboots)

## Interface Auto-Detection

When `IFACE` is not specified or the specified interface does not exist, the script:

1. Defaults to `ens192` if not specified
2. If default interface does not exist, starts auto-detection:
   - Lists all network interfaces from `/sys/class/net`
   - Filters out loopback, Docker, bridge, and virtual interfaces
   - Prefers predictable naming patterns: `enp*`, `ens*`, `eth*`
   - Checks for carrier status (LOWER_UP) and operational state
   - Falls back to first available physical interface

## Special Handling

### Cloud-init Neutralization

The script disables cloud-init networking and removes installer-created netplan files that may contain hardcoded IP addresses. This prevents conflicts in CTF VM environments where VMs are often cloned from templates.

### DNS Configuration

On systems with systemd-resolved, the script uses `resolvectl` for DNS configuration. Otherwise, it writes directly to `/etc/resolv.conf` with appropriate warnings if the file is managed by systemd-resolved.

## Logging

All operations are logged to `/var/log/static-ip-setter.log`

## Publishing

To publish this package:

```bash
# 1. Update version in package.toml
# 2. Publish to Deputy registry
deputy publish
```

## Usage in SDL

This package is used in OCR SDL files as a feature. Environment variables are passed through the SDL configuration.

### Basic Example

```yaml
features:
  vm-static-ip:
    type: configuration
    source: static-ip-setter
    version: "1.0.9"
    environment:
      - STATIC_IP=10.1.1.20/24
      - IFACE=ens192
```

### Complete Example with Gateway and DNS

```yaml
features:
  kali-static-ip:
    type: configuration
    source: static-ip-setter
    version: "1.0.9"
    environment:
      - STATIC_IP=10.1.1.10/24
      - IFACE=ens192
      - GATEWAY=10.1.1.1
      - DNS=8.8.8.8,8.8.4.4
      - SUDO_PASSWORD=kali  # Required for Kali (no NOPASSWD sudo by default)

  server-static-ip:
    type: configuration
    source: static-ip-setter
    version: "1.0.9"
    environment:
      - STATIC_IP=10.1.1.20/24
      - IFACE=ens192
      # No SUDO_PASSWORD needed for ubuntu2404-base-web (has NOPASSWD sudo)
```

### Applying Features to Nodes

```yaml
nodes:
  attacker-vm:
    type: vm
    source: kali_2025_2
    roles:
      kali-user:
        username: kali
    features:
      kali-static-ip: kali-user  # Apply feature to this role

  target-vm:
    type: vm
    source: ubuntu2404-base-web
    roles:
      server-user:
        username: user
    features:
      server-static-ip: server-user  # Apply feature to this role
```

## License

MIT

## Authors

Andris <andris@postalsys.com>
