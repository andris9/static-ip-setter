# SDL Environment Variable Format

## Issue

The static-ip-setter feature was assigning the network address `10.1.1.0/24` instead of the intended host IP `10.1.1.20/24`.

## Root Causes

### 1. Invalid Default Value (Fixed)

The script had a default value of `10.1.1.0/24` which is a network address, not a valid host IP. This was being used when the environment variable was not properly set.

**Fixed**: Made `STATIC_IP` a required environment variable with no default.

### 2. SDL Environment Variable Format

The SDL environment variable format must use **dictionary/map syntax**, not array syntax.

#### INCORRECT (Array Format)

```yaml
features:
  server-static-ip:
    type: configuration
    source: static-ip-setter
    version: "1.0.0"
    environment:
      - STATIC_IP=10.1.1.20/24
      - IFACE=ens192
```

This array format may not properly set the environment variables, causing the script to fail with "STATIC_IP environment variable is required" error.

#### CORRECT (Dictionary Format)

```yaml
features:
  server-static-ip:
    type: configuration
    source: static-ip-setter
    version: "1.0.0"
    environment:
      STATIC_IP: "10.1.1.20/24"
      IFACE: "ens192"
```

Or with additional variables:

```yaml
features:
  server-static-ip:
    type: configuration
    source: static-ip-setter
    version: "1.0.0"
    environment:
      STATIC_IP: "10.1.1.20/24"
      IFACE: "ens192"
      GATEWAY: "10.1.1.1"
      DNS: "8.8.8.8,8.8.4.4"
```

## Changes Made

1. **src/static-ip.sh**:
   - Removed invalid default value `10.1.1.0/24`
   - Made `STATIC_IP` a required environment variable
   - Added validation to fail with clear error message if not provided

2. **README.md**:
   - Updated documentation to reflect `STATIC_IP` as required
   - Changed examples to use valid host IPs
   - Removed reference to invalid default

## Testing

After these changes, the script will:

1. Fail fast with a clear error if `STATIC_IP` is not provided
2. Never use the invalid `10.1.1.0/24` network address
3. Require proper SDL environment variable format

## Verification

To verify the fix works correctly:

1. Update the SDL to use dictionary format for environment variables
2. Deploy the feature with version 1.0.6 or later
3. Check `/var/log/static-ip-setter.log` on the target VM
4. Verify the correct IP address is assigned with: `ip addr show`

If the SDL still uses array format, you will see an error:
```
[static-ip-setter][ERROR] STATIC_IP environment variable is required (e.g., STATIC_IP=10.1.1.20/24)
```

This is intentional - it forces correct SDL syntax to be used.
