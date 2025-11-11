#!/usr/bin/env bash
#
# static-ip-setter: Static IPv4 Configuration for OCR Deputy Packages
#
# Purpose:
#   Configures static IPv4 addresses on Ubuntu/Kali Linux systems in offline
#   or air-gapped CTF environments where DHCP and Internet connectivity cannot
#   be assumed. Designed as an OCR Deputy feature service.
#
# Environment Variables:
#   STATIC_IP (optional) - IP address with CIDR notation (default: 10.1.1.0/24)
#   IFACE (optional)     - Network interface name (default: ens192)
#   GATEWAY (optional)   - Default gateway IP address
#   DNS (optional)       - Comma-separated DNS servers (e.g., 8.8.8.8,8.8.4.4)
#
# Strategy:
#   Attempts configuration methods in priority order based on what's available:
#   1. netplan        - Modern Ubuntu systems (18.04+)
#   2. NetworkManager - Kali desktop and some Ubuntu desktop variants
#   3. systemd-networkd - Server configurations
#   4. Temporary IP   - Universal fallback (non-persistent across reboots)
#
# Special Handling:
#   - Disables cloud-init networking to prevent conflicts in VM environments
#   - Removes installer netplan files that may contain hardcoded IPs
#   - Detects and works with systemd-resolved for DNS configuration
#   - Auto-detects physical network interfaces, filtering out virtual/container interfaces
#
# Exit Codes:
#   0 - Success
#   1 - Fatal error (missing required variables, interface detection failed)
#
# Author: Andris <andris@postalsys.com>
# License: MIT
#

set -euo pipefail

# Logging functions (defined early before sudo elevation)
# log()  - Normal informational messages
# warn() - Non-fatal warnings that should be investigated
# fail() - Fatal errors that terminate execution
log(){ echo "[static-ip-setter] $*"; }
warn(){ echo "[static-ip-setter][WARN] $*"; }
fail(){ echo "[static-ip-setter][ERROR] $*" >&2; exit 1; }

# =============================================================================
# ROOT PRIVILEGE ELEVATION
# =============================================================================
#
# Network configuration requires root privileges. In OCR Deputy deployments,
# passwordless sudo is typically configured for the deployment user.
#
# Strategy:
#   - Check if running as root (UID 0)
#   - If not root, re-execute script with sudo
#   - Use 'exec sudo' to replace current process (preserves environment)
#   - If sudo fails (password required), exit with error
#
# Environment preservation:
#   - All environment variables (STATIC_IP, IFACE, etc.) are preserved
#   - Script arguments are preserved via "$@"
#
if [ "$(id -u)" -ne 0 ]; then
  log "Not running as root, attempting to elevate with sudo..."

  # Check if sudo is available
  if ! command -v sudo >/dev/null 2>&1; then
    fail "sudo command not found. This script requires root privileges."
  fi

  # Re-execute script with sudo
  # exec replaces current process, preserving environment and arguments
  # shellcheck disable=SC2093
  exec sudo "$0" "$@"

  # If we reach here, sudo failed
  fail "Failed to elevate privileges with sudo. Passwordless sudo may not be configured."
fi

log "Running as root (UID=$(id -u))"

# Setup logging to file and stdout
# Both streams are captured to allow post-exercise log analysis while
# maintaining real-time visibility in Deputy service output
LOG_FILE="/var/log/static-ip-setter.log"
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

# =============================================================================
# INPUT VALIDATION AND CONFIGURATION
# =============================================================================

# Set default values for environment variables
STATIC_IP="${STATIC_IP:-10.1.1.0/24}"  # Default CIDR if not specified
IFACE="${IFACE:-ens192}"                # Default interface name if not specified
GATEWAY="${GATEWAY:-}"                  # Default gateway (no routing if not specified)
DNS="${DNS:-}"                          # DNS servers (no DNS config if not specified, suitable for offline ranges)

# =============================================================================
# NETWORK INTERFACE AUTO-DETECTION
# =============================================================================
#
# Detects the most appropriate physical network interface when IFACE is not
# explicitly set. This is critical for CTF environments where interface names
# vary across different VM configurations.
#
# Detection strategy (in priority order):
#   1. Use IFACE if already set (explicit user preference)
#   2. If only one physical interface exists, use it (simple case)
#   3. Prefer predictable naming: enp*, ens*, eth* (modern Linux conventions)
#   4. Prefer interfaces with carrier signal (LOWER_UP flag via ip command)
#   5. Prefer interfaces with operstate up/dormant (active or ready)
#   6. Fallback to first available physical interface
#
# Filtering logic:
#   - Excludes loopback (lo) - not suitable for network communication
#   - Excludes Docker/container interfaces (docker*, veth*, br-*) - virtual
#   - Excludes bridge interfaces (virbr*) - used for VMs, not physical networking
#   - Excludes tunnel/tap interfaces (tun*, tap*) - VPN and virtual devices
#
# This ensures we configure the actual physical NIC used for CTF network
# connectivity, not virtual interfaces that may exist on the system.
#
detect_iface() {
  # If IFACE is explicitly set and exists, use it without detection
  if [[ -n "${IFACE:-}" ]]; then
    if [[ -e "/sys/class/net/$IFACE" ]]; then
      log "Interface detection: using IFACE=$IFACE (exists)" >&2
      echo "$IFACE"; return
    else
      log "Interface detection: specified IFACE=$IFACE does not exist, starting auto-detection" >&2
    fi
  fi

  log "Interface detection: starting auto-detection" >&2

  # Build list of non-loopback physical interface candidates
  # Iterate through /sys/class/net which contains all network interfaces
  local -a nonlo=()
  local -a all_ifaces=()
  for ifc in /sys/class/net/*; do
    ifc="$(basename "$ifc")"
    all_ifaces+=("$ifc")

    # Skip loopback interface
    if [[ "$ifc" == "lo" ]]; then
      log "Interface detection: skipping loopback interface: $ifc" >&2
      continue
    fi

    # Skip virtual/container interfaces that shouldn't be configured
    # with static IPs in a CTF context
    if [[ "$ifc" =~ ^(docker|veth|br-|virbr|tun|tap) ]]; then
      log "Interface detection: skipping virtual/container interface: $ifc" >&2
      continue
    fi

    nonlo+=("$ifc")
  done

  log "Interface detection: found ${#all_ifaces[@]} total interfaces: ${all_ifaces[*]}" >&2
  log "Interface detection: ${#nonlo[@]} physical candidates: ${nonlo[*]}" >&2

  # Simple case: exactly one physical interface found
  if [[ ${#nonlo[@]} -eq 1 ]]; then
    log "Interface detection: selected ${nonlo[0]} (only physical interface)" >&2
    echo "${nonlo[0]}"; return
  fi

  # Multiple interfaces found - apply priority selection logic
  log "Interface detection: multiple interfaces found, applying priority logic" >&2

  # Priority 1: Prefer predictable NIC naming patterns
  # Modern Linux uses predictable naming: enp0s3, ens33, etc.
  # These are more reliable than legacy eth0/eth1 which can change order
  for pat in '^enp[0-9]+s[0-9]+' '^ens[0-9]+' '^eth[0-9]+'; do
    cand="$(printf "%s\n" "${nonlo[@]}" | grep -E "$pat" | head -n1 || true)"
    if [[ -n "$cand" ]]; then
      log "Interface detection: selected $cand (matched pattern: $pat)" >&2
      echo "$cand"
      return
    fi
  done
  log "Interface detection: no interfaces matched predictable naming patterns" >&2

  # Priority 2: Prefer interfaces with active carrier signal
  # LOWER_UP flag indicates physical link is established (cable connected)
  # This helps avoid configuring disconnected interfaces
  if command -v ip >/dev/null 2>&1; then
    cand="$(ip -o link show | awk -F': ' '{print $2" "$3}' \
      | grep -v '^lo ' \
      | grep -vE '^(docker|veth|br-|virbr|tun|tap)' \
      | awk '/LOWER_UP/ {print $1; exit}')"
    if [[ -n "$cand" ]]; then
      log "Interface detection: selected $cand (has carrier signal - LOWER_UP)" >&2
      echo "$cand"
      return
    fi
    log "Interface detection: no interfaces with carrier signal found" >&2
  fi

  # Priority 3: Prefer interfaces in operational states (up or dormant)
  # operstate reflects the interface's current operational status
  # 'dormant' means ready but not actively used (still suitable for config)
  for n in "${nonlo[@]}"; do
    st="$(cat "/sys/class/net/$n/operstate" 2>/dev/null || echo unknown)"
    if [[ "$st" == "up" || "$st" == "dormant" ]]; then
      log "Interface detection: selected $n (operstate: $st)" >&2
      echo "$n"
      return
    fi
    log "Interface detection: $n operstate is $st (not up/dormant)" >&2
  done

  # Priority 4: Fallback to first available physical interface
  # If all heuristics fail, just use the first one we found
  if [[ ${#nonlo[@]} -gt 0 ]]; then
    log "Interface detection: selected ${nonlo[0]} (first available physical interface - fallback)" >&2
    echo "${nonlo[0]}"
    return
  fi

  # No suitable interface found
  log "Interface detection: FAILED - no suitable interfaces found" >&2
  echo ""
}

# Execute interface detection
IFACE="$(detect_iface)"
[[ -n "$IFACE" ]] || fail "Could not auto-detect network interface. Set IFACE in env."

# Log the configuration that will be applied
log "Using interface: $IFACE"
log "STATIC_IP: $STATIC_IP"
[[ -n "$GATEWAY" ]] && log "GATEWAY: $GATEWAY"
[[ -n "$DNS" ]] && log "DNS: $DNS"

# =============================================================================
# CLOUD-INIT AND INSTALLER NETPLAN NEUTRALIZATION
# =============================================================================
#
# Problem:
#   Ubuntu VMs deployed in cloud or virtualization environments often have
#   cloud-init or installer-created netplan configurations that:
#   - May contain hardcoded IP addresses from installation
#   - Conflict with our static IP configuration
#   - Get applied after our script runs, overwriting our settings
#
# Solution:
#   1. Disable cloud-init's network configuration capability
#   2. Remove pre-existing netplan YAML files that could conflict
#
# This is essential for CTF VMs where:
#   - VMs are often cloned from templates with existing network config
#   - The original network config is inappropriate for the CTF network
#   - We need our static IP to persist without cloud-init interference
#
disable_cloudinit() {
  # Check if cloud-init is installed (indicated by /etc/cloud directory)
  if [[ -d /etc/cloud ]]; then
    log "Disabling cloud-init network config"
    mkdir -p /etc/cloud/cloud.cfg.d

    # Create a config file that tells cloud-init to ignore networking
    # This prevents cloud-init from managing network configuration
    # while allowing it to handle other initialization tasks
    if ! echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg; then
      warn "Failed to write cloud-init disable config"
    fi
  fi

  # Remove netplan configuration files that may conflict
  # These files are commonly created by:
  #   - cloud-init (50-cloud-init.yaml)
  #   - Ubuntu installer (00/01-installer-config.yaml, 01-netcfg.yaml)
  #
  # We remove them to prevent conflicts with our 99-ocr-static.yaml
  # Note: Higher numbered netplan files (like our 99-*) take precedence,
  # but it's cleaner to remove conflicts entirely
  for f in /etc/netplan/50-cloud-init.yaml \
           /etc/netplan/00-installer-config.yaml \
           /etc/netplan/01-installer-config.yaml \
           /etc/netplan/01-netcfg.yaml \
           /etc/netplan/*cloud-init*.yaml; do
    if [[ -f "$f" ]]; then
      log "Removing conflicting netplan file: $f"
      rm -f "$f"
    fi
  done
}

# Utility function to check if a command exists
# Returns 0 (success) if command is available, 1 otherwise
have_cmd(){ command -v "$1" >/dev/null 2>&1; }

# =============================================================================
# IP CONFIGURATION VERIFICATION
# =============================================================================
#
# After applying network configuration through any method, we verify that:
#   1. The IP address is actually present on the interface
#   2. The interface is in UP state (operational)
#   3. The default gateway is in the routing table (if configured)
#
# Why verification is necessary:
#   - Network managers may apply configuration asynchronously
#   - Configuration files may be syntactically correct but fail to apply
#   - Helps detect issues early in CTF setup rather than during competition
#
# Verification approach:
#   - Polls for up to 10 seconds (network managers need time to apply config)
#   - Returns success as soon as verification passes
#   - Logs warnings for issues that don't prevent basic connectivity
#
verify_ip_config() {
  local expected_addr="${STATIC_IP%/*}"  # Extract IP without CIDR suffix
  local max_attempts=10
  local attempt=1

  log "Verifying IP configuration..."

  # Poll for IP address to appear on interface
  # Network managers (especially NetworkManager) may take 1-3 seconds to apply
  while [[ $attempt -le $max_attempts ]]; do
    # Check if the expected IP address is assigned to our interface
    if ip -4 addr show dev "$IFACE" | grep -q "inet ${expected_addr}/"; then
      log "IP address ${expected_addr} verified on ${IFACE}"

      # Verify interface is operationally UP
      # An interface can have an IP but not be UP (rare but possible)
      if ip link show "$IFACE" | grep -q "state UP"; then
        log "Interface ${IFACE} is UP"
      else
        warn "Interface ${IFACE} is not in UP state"
      fi

      # Verify default gateway is in routing table
      # Gateway is optional, only check if one was configured
      if [[ -n "$GATEWAY" ]]; then
        if ip route | grep -q "default via ${GATEWAY}"; then
          log "Default gateway ${GATEWAY} verified"
        else
          warn "Default gateway ${GATEWAY} not found in routing table"
        fi
      fi

      return 0
    fi

    # Wait 1 second between attempts (except on last attempt)
    if [[ $attempt -lt $max_attempts ]]; then
      sleep 1
      ((attempt++))
    else
      break
    fi
  done

  # Verification failed after all attempts
  warn "Failed to verify IP address ${expected_addr} on ${IFACE} after ${max_attempts} attempts"
  return 1
}

# Parse DNS configuration
# Convert comma-separated DNS list to space-separated for easier iteration
# Example: "8.8.8.8,8.8.4.4" becomes "8.8.8.8 8.8.4.4"
DNS_SPACES="$(echo "$DNS" | tr ',' ' ' | xargs || true)"
SET_DNS=false
if [[ -n "$DNS_SPACES" ]]; then
  SET_DNS=true
fi

# =============================================================================
# CONFIGURATION METHOD 1: NETPLAN
# =============================================================================
#
# Netplan is the default network configuration system for:
#   - Ubuntu 18.04+ (both server and desktop)
#   - Modern Ubuntu derivatives
#
# How it works:
#   - YAML configuration files in /etc/netplan/
#   - netplan generate converts YAML to backend-specific config
#   - netplan apply activates the configuration
#   - Uses systemd-networkd or NetworkManager as backend (we specify networkd)
#
# Our approach:
#   - Create 99-ocr-static.yaml (high number ensures it overrides others)
#   - Flush existing IPs to avoid conflicts/duplicates
#   - Generate and apply the configuration
#
# Priority: Method 1 (preferred for Ubuntu environments)
#
apply_netplan() {
  # Check if netplan command is available
  if ! have_cmd netplan; then
    log "Method netplan: command not available, skipping"
    return 1  # netplan not available, try next method
  fi

  log "Method netplan: attempting configuration"

  local NP_FILE="/etc/netplan/99-ocr-static.yaml"
  log "Method netplan: writing config to $NP_FILE"
  mkdir -p /etc/netplan

  # Build optional configuration blocks based on what's provided
  local gw_block=""
  local dns_block=""

  # Add default gateway route if GATEWAY is specified
  # Uses netplan v2 routes syntax
  if [[ -n "$GATEWAY" ]]; then
    log "Method netplan: including gateway ${GATEWAY}"
    gw_block="      routes:
        - to: 0.0.0.0/0
          via: ${GATEWAY}"
  fi

  # Add DNS nameservers if DNS is specified
  # Build YAML array of nameserver entries
  if [[ "$SET_DNS" == true && -n "$DNS_SPACES" ]]; then
    log "Method netplan: including DNS servers: ${DNS_SPACES}"
    local dns_yaml=""
    for d in $DNS_SPACES; do
      dns_yaml="${dns_yaml}        - ${d}\n"
    done
    dns_block="      nameservers:
        addresses:
${dns_yaml%\\n}"
  fi

  # Write netplan configuration file
  # Note: renderer=networkd is more reliable than NetworkManager for static IPs
  cat > "$NP_FILE" <<YAML
# generated by static-ip-setter
network:
  version: 2
  renderer: networkd
  ethernets:
    ${IFACE}:
      dhcp4: false
      addresses: [${STATIC_IP}]
${gw_block}
${dns_block}
YAML

  # Log the configuration file contents for debugging
  log "Method netplan: configuration file contents:"
  sed 's/^/  /' "$NP_FILE" | while IFS= read -r line; do log "$line"; done

  # Flush any existing IP addresses on the interface
  # This prevents duplicate IPs and ensures clean state
  log "Method netplan: flushing existing addresses on ${IFACE}"
  if ! ip addr flush dev "$IFACE"; then
    warn "Failed to flush addresses on $IFACE"
  fi

  # Generate backend-specific configuration from YAML
  log "Method netplan: running 'netplan generate'"
  if ! netplan generate 2>&1 | while IFS= read -r line; do log "netplan generate: $line"; done; then
    warn "netplan generate failed"
  fi

  # Apply the generated configuration
  # This activates the network settings
  log "Method netplan: running 'netplan apply'"
  if ! netplan apply 2>&1 | while IFS= read -r line; do log "netplan apply: $line"; done; then
    warn "netplan apply failed"
    log "Method netplan: FAILED"
    return 1  # Critical failure, try next method
  fi

  log "Method netplan: SUCCESS"
  return 0  # Success
}

# =============================================================================
# CONFIGURATION METHOD 2: NETWORKMANAGER (via nmcli)
# =============================================================================
#
# NetworkManager is commonly found on:
#   - Kali Linux desktop images
#   - Ubuntu desktop variants
#   - Any Linux desktop with GUI network management
#
# How it works:
#   - NetworkManager manages "connections" (saved network configurations)
#   - nmcli is the command-line interface to NetworkManager
#   - Connections can be created, modified, and activated
#   - Settings persist in /etc/NetworkManager/system-connections/
#
# Our approach:
#   - Check if an active connection exists for our interface
#   - Create new connection "ocr-{interface}" if none exists
#   - Configure static IP, gateway, and DNS
#   - Activate the connection
#
# Priority: Method 2 (fallback if netplan not available)
#
apply_nmcli() {
  # Check if nmcli command is available
  if ! have_cmd nmcli; then
    log "Method NetworkManager: command not available, skipping"
    return 1  # NetworkManager not available, try next method
  fi

  log "Method NetworkManager: attempting configuration"

  # Find existing active connection for this interface
  # Output format: CONNECTION_NAME:DEVICE
  # We extract the connection name if device matches our interface
  local conn
  conn="$(nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null | awk -F: -v ifc="$IFACE" '$2==ifc{print $1; exit}')"

  if [[ -z "$conn" ]]; then
    # No existing connection, create a new one
    conn="ocr-${IFACE}"
    log "Method NetworkManager: no active connection found, creating '$conn' for $IFACE"
    if ! nmcli connection add type ethernet ifname "$IFACE" con-name "$conn" 2>&1 | while IFS= read -r line; do log "nmcli add: $line"; done; then
      warn "Failed to create NM connection '$conn'"
      log "Method NetworkManager: FAILED"
      return 1  # Critical failure, try next method
    fi
  else
    # Use existing connection (modify it in-place)
    log "Method NetworkManager: found existing connection '$conn'"
  fi

  # Parse IP and prefix from CIDR notation
  # Example: "10.1.1.3/24" becomes addr="10.1.1.3" prefix="24"
  local addr prefix
  addr="${STATIC_IP%/*}"
  prefix="${STATIC_IP##*/}"

  # Configure static IP address
  # ipv4.method=manual disables DHCP
  # ipv4.addresses sets the static IP with prefix
  log "Method NetworkManager: configuring IP ${addr}/${prefix}"
  if ! nmcli connection modify "$conn" ipv4.method manual ipv4.addresses "${addr}/${prefix}" 2>&1 | while IFS= read -r line; do log "nmcli modify IP: $line"; done; then
    warn "Failed to set IP address in NM connection"
  fi

  # Configure default gateway if specified
  if [[ -n "$GATEWAY" ]]; then
    log "Method NetworkManager: configuring gateway ${GATEWAY}"
    if ! nmcli connection modify "$conn" ipv4.gateway "$GATEWAY" 2>&1 | while IFS= read -r line; do log "nmcli modify gateway: $line"; done; then
      warn "Failed to set gateway in NM connection"
    fi
  else
    # Remove gateway if not specified (using -ipv4.gateway)
    log "Method NetworkManager: removing gateway (not specified)"
    nmcli connection modify "$conn" -ipv4.gateway 2>/dev/null || true
  fi

  # Configure DNS servers if specified
  if [[ "$SET_DNS" == true && -n "$DNS_SPACES" ]]; then
    # Set DNS servers and ignore auto-DNS from DHCP
    # (even though DHCP is disabled, this prevents any auto-configuration)
    log "Method NetworkManager: configuring DNS: ${DNS_SPACES}"
    if ! nmcli connection modify "$conn" ipv4.dns "$DNS_SPACES" ipv4.ignore-auto-dns yes 2>&1 | while IFS= read -r line; do log "nmcli modify DNS: $line"; done; then
      warn "Failed to set DNS in NM connection"
    fi
  else
    # Remove DNS configuration if not specified
    log "Method NetworkManager: removing DNS config (not specified)"
    nmcli connection modify "$conn" -ipv4.dns 2>/dev/null || true
    nmcli connection modify "$conn" ipv4.ignore-auto-dns no 2>/dev/null || true
  fi

  # Activate the connection
  # This brings the interface up with the configured settings
  log "Method NetworkManager: activating connection '$conn'"
  if ! nmcli connection up "$conn" 2>&1 | while IFS= read -r line; do log "nmcli up: $line"; done; then
    warn "Failed to bring up NM connection '$conn'"
    log "Method NetworkManager: FAILED"
    return 1  # Critical failure, try next method
  fi

  log "Method NetworkManager: SUCCESS"
  return 0  # Success
}

# =============================================================================
# CONFIGURATION METHOD 3: SYSTEMD-NETWORKD
# =============================================================================
#
# systemd-networkd is commonly found on:
#   - Ubuntu Server installations (minimal/headless)
#   - Systems using systemd without NetworkManager
#   - Containers and embedded systems
#
# How it works:
#   - Configuration files in /etc/systemd/network/ (*.network format)
#   - systemd-networkd daemon reads config and manages interfaces
#   - Simple INI-style configuration format
#   - Integrated with systemd ecosystem
#
# Our approach:
#   - Only use if systemd-networkd is actively running
#   - Create 10-ocr-{interface}.network configuration file
#   - Restart systemd-networkd to apply changes
#
# Priority: Method 3 (fallback if netplan and NetworkManager not available)
#
apply_systemd_networkd() {
  # Only proceed if systemd-networkd is actively running
  # Some systems have it installed but use NetworkManager instead
  if ! systemctl is-active --quiet systemd-networkd 2>/dev/null; then
    log "Method systemd-networkd: service not active, skipping"
    return 1  # systemd-networkd not active, try next method
  fi

  log "Method systemd-networkd: attempting configuration"

  local NET_DIR="/etc/systemd/network"
  local NET_FILE="$NET_DIR/10-ocr-${IFACE}.network"
  mkdir -p "$NET_DIR"

  # Parse IP and prefix from CIDR notation
  local addr prefix
  addr="${STATIC_IP%/*}"
  prefix="${STATIC_IP##*/}"

  log "Method systemd-networkd: writing config to $NET_FILE"

  # Write systemd-networkd configuration file
  # INI-style format with [Match] and [Network] sections
  {
    # [Match] section specifies which interface this config applies to
    echo "[Match]"
    echo "Name=${IFACE}"
    echo ""

    # [Network] section specifies network configuration
    echo "[Network]"
    echo "Address=${addr}/${prefix}"

    # Add optional gateway (default route)
    if [[ -n "$GATEWAY" ]]; then
      log "Method systemd-networkd: including gateway ${GATEWAY}"
      echo "Gateway=${GATEWAY}"
    fi

    # Add optional DNS servers (one DNS= line per server)
    if [[ "$SET_DNS" == true && -n "$DNS_SPACES" ]]; then
      log "Method systemd-networkd: including DNS servers: ${DNS_SPACES}"
      for d in $DNS_SPACES; do
        echo "DNS=${d}"
      done
    fi
  } > "$NET_FILE"

  # Log the configuration file contents for debugging
  log "Method systemd-networkd: configuration file contents:"
  sed 's/^/  /' "$NET_FILE" | while IFS= read -r line; do log "$line"; done

  # Restart systemd-networkd to apply the new configuration
  # systemd-networkd reads config files on start/restart
  log "Method systemd-networkd: restarting service"
  if ! systemctl restart systemd-networkd 2>&1 | while IFS= read -r line; do log "systemctl restart: $line"; done; then
    warn "Failed to restart systemd-networkd"
    log "Method systemd-networkd: FAILED"
    return 1  # Critical failure, try next method
  fi

  log "Method systemd-networkd: SUCCESS"
  return 0  # Success
}

# =============================================================================
# CONFIGURATION METHOD 4: TEMPORARY IP (Universal Fallback)
# =============================================================================
#
# This is the last-resort method used when no network manager is available.
# It applies configuration directly using the 'ip' command.
#
# When this method is used:
#   - None of the network managers (netplan/NM/systemd-networkd) are available
#   - Minimal systems or unusual configurations
#   - Emergency situations where persistence isn't critical
#
# Limitations:
#   - Configuration is NOT persistent across reboots
#   - Will be lost if network services restart
#   - Suitable for CTF VMs that run for duration of exercise only
#
# How it works:
#   - Use 'ip addr add' to assign IP directly to interface
#   - Use 'ip route add' to set default gateway
#   - Handle DNS via resolvectl (systemd-resolved) or /etc/resolv.conf
#
# DNS handling is complex because:
#   - Modern systems use systemd-resolved (dynamic DNS management)
#   - /etc/resolv.conf may be a symlink to /run (ephemeral)
#   - We try resolvectl first, then fall back to direct file manipulation
#
# Priority: Method 4 (last resort, non-persistent fallback)
#
apply_temporary_ip() {
  log "Method temporary IP: attempting configuration (non-persistent)"
  log "Method temporary IP: this configuration will NOT survive reboot"

  # Parse IP and prefix from CIDR notation
  local addr prefix
  addr="${STATIC_IP%/*}"
  prefix="${STATIC_IP##*/}"

  # Flush any existing IP addresses on the interface
  # This ensures clean state and avoids conflicts
  log "Method temporary IP: flushing existing addresses on ${IFACE}"
  if ! ip addr flush dev "$IFACE" 2>&1 | while IFS= read -r line; do log "ip addr flush: $line"; done; then
    warn "Failed to flush addresses on $IFACE"
  fi

  # Add the static IP address to the interface
  # This is the core operation - if this fails, nothing else matters
  log "Method temporary IP: adding ${addr}/${prefix} to ${IFACE}"
  if ! ip addr add "${addr}/${prefix}" dev "$IFACE" 2>&1 | while IFS= read -r line; do log "ip addr add: $line"; done; then
    fail "Failed to add IP address ${addr}/${prefix} to $IFACE"
  fi

  # Bring the interface up (set to operational state)
  # An interface can have an IP but be administratively down
  log "Method temporary IP: bringing up interface ${IFACE}"
  if ! ip link set dev "$IFACE" up 2>&1 | while IFS= read -r line; do log "ip link set up: $line"; done; then
    fail "Failed to bring up interface $IFACE"
  fi

  # Configure default gateway if specified
  # This allows routing to networks beyond the local subnet
  if [[ -n "$GATEWAY" ]]; then
    log "Method temporary IP: setting default gateway ${GATEWAY}"
    if ! ip route replace default via "$GATEWAY" dev "$IFACE" 2>&1 | while IFS= read -r line; do log "ip route: $line"; done; then
      warn "Failed to set default gateway $GATEWAY"
    fi
  fi

  # Configure DNS if specified
  # DNS configuration in modern Linux is complex due to systemd-resolved
  if [[ -n "$DNS_SPACES" ]]; then
    log "Method temporary IP: configuring DNS: ${DNS_SPACES}"

    # Method 1: Try resolvectl (systemd-resolved interface)
    # Check if systemd-resolved is active AND /etc/resolv.conf is a symlink
    # (symlink indicates systemd-resolved is managing DNS)
    if systemctl is-active --quiet systemd-resolved 2>/dev/null && [[ -L /etc/resolv.conf ]]; then
      log "Method temporary IP: systemd-resolved is active, trying resolvectl"

      # Set DNS servers for this specific interface
      # We want word splitting for multiple DNS servers
      # shellcheck disable=SC2086
      if resolvectl dns "$IFACE" $DNS_SPACES 2>&1 | while IFS= read -r line; do log "resolvectl: $line"; done; then
        log "Method temporary IP: DNS configured via resolvectl"
        log "Method temporary IP: SUCCESS"
        return 0  # DNS successfully configured, we're done
      else
        warn "Failed to set DNS via resolvectl, falling back to resolv.conf"
        # Continue to Method 2 below
      fi
    fi

    # Method 2: Direct /etc/resolv.conf manipulation (traditional approach)
    log "Method temporary IP: falling back to /etc/resolv.conf"

    # Check if resolv.conf is managed by systemd-resolved
    # If so, our changes may not persist or may be overwritten
    if [[ -L /etc/resolv.conf ]]; then
      local target
      target="$(readlink -f /etc/resolv.conf)"
      log "Method temporary IP: /etc/resolv.conf is a symlink to $target"
      # Warn if pointing to systemd-resolved stub or /run (ephemeral)
      if [[ "$target" == "/run/systemd/resolve/stub-resolv.conf" ]] || [[ "$target" =~ ^/run/ ]]; then
        warn "/etc/resolv.conf is managed by systemd-resolved or resides in /run; DNS may not persist"
      fi
    fi

    # Create temporary resolv.conf file
    local tmp="/etc/resolv.conf.static-by-static-ip-setter"
    {
      echo "# generated by static-ip-setter"
      # Set aggressive timeouts for offline environments
      # attempts:1 = only try once, timeout:1 = 1 second timeout
      echo "options attempts:1 timeout:1"
      # Add each DNS server as a nameserver entry
      for d in $DNS_SPACES; do
        echo "nameserver $d"
      done
    } > "$tmp"

    log "Method temporary IP: generated resolv.conf contents:"
    sed 's/^/  /' "$tmp" | while IFS= read -r line; do log "$line"; done

    # Backup existing resolv.conf if it exists
    if [[ -f /etc/resolv.conf ]]; then
      log "Method temporary IP: backing up existing /etc/resolv.conf"
      if ! cp -a /etc/resolv.conf /etc/resolv.conf.bak.static-ip-setter 2>/dev/null; then
        warn "Failed to backup /etc/resolv.conf"
      fi
    fi

    # Replace resolv.conf with our generated version
    log "Method temporary IP: writing to /etc/resolv.conf"
    if ! mv "$tmp" /etc/resolv.conf; then
      warn "Failed to write /etc/resolv.conf"
    else
      log "Method temporary IP: DNS configured via /etc/resolv.conf"
    fi
  fi

  log "Method temporary IP: SUCCESS (not persisted across reboot)"
  return 0  # Always return success - we did our best
}

# =============================================================================
# MAIN EXECUTION FLOW
# =============================================================================
#
# Execution strategy:
#   1. Disable cloud-init networking (prevent conflicts)
#   2. Try configuration methods in priority order (cascade pattern)
#   3. Verify the configuration was actually applied
#   4. Display final network state for troubleshooting
#
# The cascade pattern:
#   - Try netplan first (most common on Ubuntu)
#   - Fall back to NetworkManager (Kali/desktop systems)
#   - Fall back to systemd-networkd (minimal server systems)
#   - Final fallback to temporary IP (always succeeds but non-persistent)
#
# Each method returns:
#   - 0 on success (configuration applied successfully)
#   - 1 on failure (method not available or failed to apply)
#
# We stop at the first successful method and verify it worked.
#
main() {
  # Log execution context for debugging
  log "=========================================="
  log "static-ip-setter starting"
  log "=========================================="
  log "Timestamp: $(date)"
  log "User: $(whoami)"
  log "Hostname: $(hostname)"
  log "Kernel: $(uname -r)"
  log "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo 'unknown')"

  # Log system state before configuration
  log "System state before configuration:"
  log "Available network managers:"
  if have_cmd netplan; then
    log "  - netplan: available"
  else
    log "  - netplan: not available"
  fi
  if have_cmd nmcli; then
    log "  - nmcli (NetworkManager): available"
  else
    log "  - nmcli (NetworkManager): not available"
  fi
  if systemctl is-active --quiet systemd-networkd 2>/dev/null; then
    log "  - systemd-networkd: active"
  else
    log "  - systemd-networkd: not active"
  fi

  log "Current network interfaces:"
  ip -o link show | while IFS= read -r line; do log "  $line"; done

  log "Current IP addresses:"
  ip -4 addr show | while IFS= read -r line; do log "  $line"; done

  log "Current routes:"
  ip route | while IFS= read -r line; do log "  $line"; done

  if [[ -f /etc/resolv.conf ]]; then
    log "Current DNS configuration (/etc/resolv.conf):"
    cat /etc/resolv.conf | while IFS= read -r line; do log "  $line"; done
  fi

  log "=========================================="

  # Neutralize cloud-init and remove conflicting netplan files
  # This must happen before any configuration attempts
  disable_cloudinit

  # Try each configuration method in priority order
  # Stop at the first one that succeeds
  log "Attempting network configuration methods in priority order..."
  local method=""
  if apply_netplan; then
    method="netplan"
    log "Applied via netplan."

  elif apply_nmcli; then
    method="NetworkManager"
    log "Applied via NetworkManager."

  elif apply_systemd_networkd; then
    method="systemd-networkd"
    log "Applied via systemd-networkd."

  else
    # No persistent method available, use temporary IP
    # This method always succeeds (or fails fatally)
    method="temporary IP"
    apply_temporary_ip
  fi

  # Verify the configuration was actually applied
  # Waits up to 10 seconds for network managers to apply settings
  if verify_ip_config; then
    log "IP configuration verified successfully via ${method}"
  else
    # Verification failed, but don't abort - show what we have
    warn "IP configuration could not be verified, but showing current state"
  fi

  # Display final network configuration state
  # This helps with troubleshooting if something went wrong
  log "=========================================="
  log "Final network state after configuration:"
  log "Addresses on ${IFACE}:"
  ip -4 addr show dev "$IFACE" | sed 's/^/  /' | while IFS= read -r line; do log "$line"; done

  log "All routes:"
  ip route | sed 's/^/  /' | while IFS= read -r line; do log "$line"; done

  if [[ -f /etc/resolv.conf ]]; then
    log "Final DNS configuration (/etc/resolv.conf):"
    cat /etc/resolv.conf | sed 's/^/  /' | while IFS= read -r line; do log "$line"; done
  fi

  log "=========================================="
  log "static-ip-setter completed successfully"
  log "Method used: ${method}"
  log "Configuration timestamp: $(date)"
  log "=========================================="
}

# Execute main function
# All script logic is in functions above, main() orchestrates execution
main

