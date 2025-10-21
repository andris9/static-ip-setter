# static-ip-setter

Static IPv4 configuration package for Ubuntu/Kali Linux systems in offline/air-gapped CTF environments.

## Overview

This OCR Deputy feature package configures static IPv4 addresses on systems where DHCP and Internet connectivity cannot be assumed. It intelligently selects the appropriate network configuration method based on what's available on the system.

## Features

- **Multi-method configuration**: Supports netplan, NetworkManager, systemd-networkd, and temporary IP fallback
- **Intelligent interface detection**: Automatically detects physical network interfaces, filtering out virtual/container interfaces
- **Cloud-init neutralization**: Disables cloud-init networking and removes conflicting netplan configurations
- **Configuration verification**: Verifies IP assignment with 10-second polling
- **systemd-resolved aware**: Properly handles DNS configuration on modern systems
- **Comprehensive logging**: Detailed logs to `/var/log/static-ip-setter.log` for debugging
- **Offline-safe design**: No external connectivity required

## Configuration

The script is controlled via environment variables:

- `STATIC_IP` (required): IP address with CIDR notation (e.g., `10.1.1.3/24`)
- `IFACE` (optional): Network interface name; auto-detected if not set
- `GATEWAY` (optional): Default gateway IP address
- `DNS` (optional): Comma-separated DNS servers (e.g., `8.8.8.8,8.8.4.4`)

## Network Configuration Methods

The script attempts configuration in priority order:

1. **netplan** - Modern Ubuntu systems (18.04+)
2. **NetworkManager** - Kali desktop and Ubuntu desktop variants
3. **systemd-networkd** - Server configurations
4. **Temporary IP** - Universal fallback (non-persistent across reboots)

## Interface Auto-Detection

When `IFACE` is not specified, the script:

1. Lists all network interfaces from `/sys/class/net`
2. Filters out loopback, Docker, bridge, and virtual interfaces
3. Prefers predictable naming patterns: `enp*`, `ens*`, `eth*`
4. Checks for carrier status (LOWER_UP) and operational state
5. Falls back to first available physical interface

## Special Handling

### Cloud-init Neutralization

The script disables cloud-init networking and removes installer-created netplan files that may contain hardcoded IP addresses. This prevents conflicts in CTF VM environments where VMs are often cloned from templates.

### DNS Configuration

On systems with systemd-resolved, the script uses `resolvectl` for DNS configuration. Otherwise, it writes directly to `/etc/resolv.conf` with appropriate warnings if the file is managed by systemd-resolved.

## Logging

All operations are logged to `/var/log/static-ip-setter.log` with extensive detail:

- System information (OS, kernel, hostname)
- Available network managers
- Initial network state (interfaces, IPs, routes, DNS)
- Interface detection process and reasoning
- Configuration method selection and attempts
- Configuration file contents (for debugging)
- Command outputs from network tools
- Verification results
- Final network state

## Installation

This package is installed via OCR Deputy:

```bash
deputy install static-ip-setter
```

The script is installed to `/opt/static-ip-setter/static-ip.sh` with executable permissions.

## Usage Example

```bash
# Basic usage with auto-detected interface
STATIC_IP=10.1.1.3/24 /opt/static-ip-setter/static-ip.sh

# With gateway and DNS
STATIC_IP=10.1.1.3/24 GATEWAY=10.1.1.1 DNS=8.8.8.8,8.8.4.4 /opt/static-ip-setter/static-ip.sh

# With explicit interface
STATIC_IP=10.1.1.3/24 IFACE=enp0s3 GATEWAY=10.1.1.1 /opt/static-ip-setter/static-ip.sh
```

## Troubleshooting

If the script fails or behaves unexpectedly:

1. Check `/var/log/static-ip-setter.log` for detailed execution logs
2. Verify the interface name: `ip link show`
3. Check available network managers: `which netplan nmcli`
4. Verify systemd-networkd status: `systemctl status systemd-networkd`
5. Test interface detection: Run script with only `STATIC_IP` set to see what interface is selected

## Requirements

- Ubuntu 18.04+ or Kali Linux
- Root privileges
- At least one physical network interface
- One of: netplan, NetworkManager, systemd-networkd, or `ip` command

## License

MIT

## Authors

Andris <andris@postalsys.com>
