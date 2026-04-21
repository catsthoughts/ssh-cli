# SSH CLI

A Go-based SSH client that uses non-exportable private keys stored in the macOS Secure Enclave, macOS Keychain, or a YubiKey PIV smart card. Designed to integrate with [ssh-proxy-server](https://github.com/catsthoughts/ssh-proxy-server) for certificate-based authentication.

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Command Reference](#command-reference)
   - [ssh-cli](#ssh-cli)
   - [ssh-cli-init](#ssh-cli-init)
4. [Configuration](#configuration)
   - [Config File Location](#config-file-location)
   - [Profile Format](#profile-format)
   - [Config Fields Reference](#config-fields-reference)
5. [Key Sources](#key-sources)
   - [Secure Enclave](#secure-enclave)
   - [YubiKey PIV](#yubikey-piv)
   - [Choosing a Key Source](#choosing-a-key-source)
6. [Connecting](#connecting)
   - [Via ssh-proxy-server](#via-ssh-proxy-server)
   - [Direct Connection](#direct-connection)
7. [Multiple Proxies](#multiple-proxies)
8. [Multiple Profiles](#multiple-profiles)
9. [Certificate Authentication](#certificate-authentication)
   - [Auto-Refresh via step-ca](#auto-refresh-via-step-ca)
   - [Local SSH CA Certificate](#local-ssh-ca-certificate)
   - [X.509 Certificates](#x509-certificates)
10. [SSH Agent Forwarding](#ssh-agent-forwarding)
11. [Security Model](#security-model)
12. [Troubleshooting](#troubleshooting)
13. [Testing](#testing)
14. [Related Documentation](#related-documentation)

---

## Overview

ssh-cli provides secure SSH authentication using private keys that never leave the secure hardware:

| Key Source | Hardware | Platforms | Key Algorithm |
|------------|----------|----------|--------------|
| Secure Enclave | Apple T2 or SoC | macOS only | ECDSA P-256 |
| macOS Keychain | Secure Enclave fallback | macOS only | ECDSA P-256 |
| YubiKey PIV | YubiKey smart card | macOS, Linux, Windows | ECDSA P-256 (via PIV) |

**Key features:**
- Non-exportable private keys stored in secure hardware
- Automatic SSH certificate obtain and refresh via step-ca + OIDC
- SSH agent forwarding backed by non-exportable keys
- Multiple proxy support with failover/round-robin/random balancing
- Multi-profile configuration
- SSH alias resolution from `~/.ssh/config`

---

## Quick Start

```bash
# 1. Build
go build -o ssh-cli ./cmd/ssh-cli
go build -o ssh-cli-init ./cmd/ssh-cli-init

# 2. Create config
ssh-cli-init init-config          # creates ~/.ssh-cli/config.json
# Edit ~/.ssh-cli/config.json with your settings

# 3. Create key
ssh-cli-init create-key

# 4. Show public key (for CA enrollment)
ssh-cli-init show-public-key

# 5. Connect
ssh-cli target-host:22
ssh-cli your-user@target-host:22
```

---

## Command Reference

### ssh-cli

The main SSH client.

```bash
ssh-cli [options] [destination]
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | `~/.ssh-cli/config.json` | Path to JSON config |
| `-profile` | `active_profile` | Profile name in multi-profile config |

**Destination format:** `[user@]host[:port]`

**Examples:**

```bash
ssh-cli                                    # connect to bastion (no destination)
ssh-cli target-host:22                     # connect to target via proxy
ssh-cli your-user@target-host:22          # specify user
ssh-cli prod-host                         # use SSH alias from ~/.ssh/config
ssh-cli -profile staging target-host:22   # use staging profile
```

### ssh-cli-init

Key and certificate management tool.

```bash
ssh-cli-init <command> [options]
```

**Commands:**

| Command | Description |
|---------|-------------|
| `init-config` | Create example config file |
| `list-profiles` | List all profiles (`*` = active) |
| `use-profile <name>` | Set active profile |
| `create-key` | Create or load non-exportable key |
| `show-public-key` | Display SSH public key |
| `create-cert` | Create SSH/X.509 certificate (local CA) |
| `get-cert` | Obtain certificate via step-ca + OIDC |

**Global Flags (for create-key, show-public-key, create-cert, get-cert):**

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | `~/.ssh-cli/config.json` | Path to JSON config |
| `-profile` | `active_profile` | Profile name |

**Command-specific Flags:**

- `init-config -force` — Overwrite existing config without prompting
- `create-key -force` — Delete existing key and create new one
- `get-cert -username -password` — Use password grant instead of device flow

**Examples:**

```bash
ssh-cli-init init-config
ssh-cli-init init-config -force
ssh-cli-init list-profiles
ssh-cli-init use-profile staging
ssh-cli-init create-key
ssh-cli-init create-key -force
ssh-cli-init create-key -profile staging
ssh-cli-init show-public-key -profile prod
ssh-cli-init create-cert -profile prod
ssh-cli-init get-cert -profile prod
```

---

## Configuration

### Config File Location

Default: `~/.ssh-cli/config.json`

Override with `-config` flag on all commands.

### Profile Format

ssh-cli supports two config formats:

**Multi-profile format (recommended):**

```json
{
  "active_profile": "prod",
  "profiles": {
    "prod": { ... },
    "staging": { ... }
  }
}
```

**Legacy flat format (still supported):**

```json
{
  "key": { ... },
  "proxy": { ... },
  "target": { ... },
  "certificate": { ... }
}
```

### Config Fields Reference

#### `key` — Key Configuration

| Field | Required | Description |
|-------|----------|-------------|
| `tag` | Yes | Unique identifier for the key (used by Keychain/Secure Enclave) |
| `label` | Yes | Human-readable label |
| `comment` | No | Arbitrary comment stored with the key |
| `key_source` | Yes | `secure_enclave` or `yubikey_piv` |
| `public_key_path` | Yes | Where to save the SSH public key |
| `yubikey.slot` | No | PIV slot (default: `9a`). See [YubiKey PIV slots](#yubikey-piv) |
| `yubikey.pin` | No | PIV PIN (if not using PC/SC PIN prompt) |
| `yubikey.pkcs11_path` | No | Path to PC/SC library (Linux only) |

#### `proxy` — Proxy Configuration

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `use_proxy` | No | `true` | Enable proxy mode |
| `address` | If `use_proxy` | — | Single string or array of proxy addresses |
| `user` | No | OS user | SSH username for proxy |
| `known_hosts` | No | `~/.ssh/known_hosts` | Path to known_hosts file |
| `host_key_policy` | No | `accept-new` | `accept-new`, `strict`, `insecure-ignore` |
| `insecure_ignore_hostkey` | No | `false` | Skip host key verification (dangerous) |
| `use_agent_forwarding` | No | `true` | Forward SSH agent to target |
| `connect_timeout_seconds` | No | `10` | Connection timeout |
| `balance_mode` | No | `failover` | `failover`, `round-robin`, `random` |
| `retry_attempts` | No | `1` | Number of retry rounds |
| `retry_delay_seconds` | No | `0` | Delay between retry rounds |

#### `target` — Target Configuration

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `command` | No | — | Command to execute on target |
| `request_tty` | No | `true` | Request PTY (`ssh -t` behavior) |
| `forward_ctrl_c` | No | `false` | Double-ctrl-c to exit locally |

#### `certificate` — Certificate Configuration

| Field | Required | Description |
|-------|----------|-------------|
| `type` | Yes* | `ssh-user`, `x509-selfsigned`, `x509-csr` (*for create-cert) |
| `ca_key_path` | For local CA | Path to CA private key |
| `output_path` | Yes* | Where to save the certificate |
| `auth_cert_path` | No | Path for SSH auth certificate |
| `identity` | Yes** | SSH user identity (email or username) |
| `principals` | Yes** | List of allowed principals |
| `valid_for` | No | Certificate validity duration (e.g., `8h`, `24h`) |
| `cert_refresh_before` | No | Refresh threshold (default: `1h`) |
| `step_ca.ca_url` | For step-ca | step-ca server URL |
| `step_ca.authority_id` | For step-ca | OIDC provisioner name |
| `step_ca.skip_tls_verify` | No | Skip TLS verification (dev only) |
| `oidc.provider_url` | For step-ca | OIDC provider URL |
| `oidc.client_id` | For step-ca | OIDC client ID |
| `oidc.client_secret` | For step-ca | OIDC client secret |
| `oidc.scope` | No | OIDC scope (default: `openid profile email`) |

---

## Key Sources

### Secure Enclave

macOS-only hardware key storage. Uses ECDSA P-256. If Secure Enclave is unavailable (e.g., in a CLI environment), automatically falls back to macOS Keychain with a non-exportable key.

```json
{
  "key": {
    "tag": "com.example.sshcli.prod",
    "label": "Production Key",
    "key_source": "secure_enclave",
    "public_key_path": "~/.ssh-cli/id_prod.pub"
  }
}
```

**Requirements:**
- macOS with Secure Enclave (T2 chip or Apple Silicon)
- Keychain access for the user

### YubiKey PIV

Cross-platform smart card support. Works on macOS, Linux, and Windows.

**PIV Slots:**

| Slot | Purpose |
|------|---------|
| `9a` | PIV Authentication (default) |
| `9c` | Digital Signature |
| `9d` | Key Management |
| `9e` | Card Authentication |
| `82`–`95` | Retired Key Management (20 slots) |

```json
{
  "key": {
    "tag": "com.example.sshcli.prod",
    "label": "Production YubiKey",
    "key_source": "yubikey_piv",
    "public_key_path": "~/.ssh-cli/id_prod.pub",
    "yubikey": {
      "slot": "9a"
    }
  }
}
```

**Requirements:**
- YubiKey with PIV support
- PC/SC library installed (automatic on macOS, `libpcsclite` on Linux)

### Choosing a Key Source

| Criteria | Secure Enclave | YubiKey PIV |
|----------|----------------|--------------|
| macOS only | Yes | No |
| Cross-platform | No | Yes |
| Hardware portability | No (tied to Mac) | Yes (move YubiKey) |
| Key algorithm | ECDSA P-256 | ECDSA P-256 (PIV) |
| PIN entry | Via Keychain prompt | On-device keypad or PC/SC |

---

## Connecting

### Via ssh-proxy-server

ssh-proxy-server acts as a bastion host. The client forwards an agent to the target through the proxy.

```bash
ssh-cli prod-host              # use SSH alias
ssh-cli target-host:22        # explicit destination
ssh-cli -profile prod target-host:22  # with profile
```

Without a destination, connects to the proxy (bastion) without agent forwarding:

```bash
ssh-cli  # logs into bastion only
```

**Proxy requirements:**
- Public key authentication on the proxy
- Agent forwarding to target host
- Destination passed as CLI argument

ssh-cli resolves SSH aliases from `~/.ssh/config` automatically. If `proxy.user` is empty, uses the current OS user.

### Direct Connection

Connect directly to an SSH server without a proxy:

```json
{
  "proxy": {
    "use_proxy": false
  }
}
```

```bash
ssh-cli -profile direct-se your-user@target.example.com:22
```

---

## Multiple Proxies

Configure multiple proxy addresses with load balancing:

```json
{
  "proxy": {
    "address": ["proxy-1.example.com:2222", "proxy-2.example.com:2222"],
    "balance_mode": "failover",
    "retry_attempts": 3,
    "retry_delay_seconds": 5
  }
}
```

**Balance modes:**

| Mode | Behavior |
|------|----------|
| `failover` | Try proxies in order; stop at first success (default) |
| `round-robin` | Rotate starting proxy each invocation |
| `random` | Shuffle proxy order randomly each invocation |

In all modes, every proxy is tried before giving up.

---

## Multiple Profiles

Manage multiple configurations (e.g., prod/staging/dev, different keys):

```bash
ssh-cli-init list-profiles     # show all profiles (* = active)
ssh-cli-init use-profile staging
ssh-cli -profile prod target-host:22   # override active profile
```

---

## Certificate Authentication

ssh-cli integrates with [step-ca](https://smallstep.com/docs/step-ca/) for automatic SSH certificate management.

### Auto-Refresh via step-ca

On every `ssh-cli` invocation, the cached certificate is checked. If missing or expiring within `cert_refresh_before`, a new certificate is obtained via OIDC before connecting.

```bash
ssh-cli-init get-cert  # manual certificate fetch
```

Certificate flow:
1. Check cached cert in `~/.ssh-cli/certs/<profile>/`
2. If refresh needed: OIDC device flow → Keycloak authentication
3. POST to step-ca `/ssh/sign` with token + public key
4. Cache certificate until expiry

### Local SSH CA Certificate

Sign a certificate with a local CA key on disk:

```json
{
  "certificate": {
    "type": "ssh-user",
    "ca_key_path": "./ssh_user_ca",
    "output_path": "./id-cert.pub",
    "identity": "your-user",
    "principals": ["your-user"],
    "valid_for": "8h"
  }
}
```

```bash
ssh-cli-init create-cert
```

### X.509 Certificates

**CSR (for external CA):**

```json
{
  "certificate": {
    "type": "x509-csr",
    "output_path": "./client.csr",
    "subject_common_name": "your-user"
  }
}
```

**Self-signed certificate:**

```json
{
  "certificate": {
    "type": "x509-selfsigned",
    "output_path": "./client.crt",
    "subject_common_name": "your-user"
  }
}
```

---

## SSH Agent Forwarding

When `use_agent_forwarding` is enabled, ssh-cli creates a read-only SSH agent backed by the non-exportable key and forwards it to the target host.

**Key points:**
- Agent is read-only (cannot extract private keys)
- Works only with proxy mode (not direct connections)
- The same certificate+key are presented to both proxy and target

---

## Security Model

1. **Private keys never leave secure hardware** — Secure Enclave, Keychain, or YubiKey PIV
2. **Non-exportable keys** — Keys are generated inside secure hardware and cannot be extracted
3. **SSH agent is read-only** — Agent only holds the public key and certificate; cannot export private key material
4. **Certificate caching** — Certificates cached in `~/.ssh-cli/certs/` with metadata for expiry checking
5. **Host key verification** — By default, accepts new hosts and records them in `known_hosts`

---

## Troubleshooting

### Connection Issues

**`connection refused` or timeout**
- Verify proxy address and port
- Check `connect_timeout_seconds` (try increasing)
- Ensure ssh-proxy-server is running

**`no such host`**
- Check DNS resolution for proxy/target host
- SSH aliases must be defined in `~/.ssh/config`

**`host key verification failed`**
- Check `known_hosts` file path
- If testing, set `host_key_policy: "insecure-ignore"` temporarily
- For testing with proxy, ensure `known_hosts` contains the proxy's host key

### Key Issues

**`key.tag is required`**
- Config is missing `key.tag` field

**`profile not found`**
- Specified profile doesn't exist in config
- Check spelling: `ssh-cli-init list-profiles`

**`failed to find YubiKey`**
- YubiKey not inserted or not detected
- On Linux: ensure PC/SC service is running
- Try specifying `yubikey.pkcs11_path` explicitly

**`failed to verify certificate` (TLS)**
- step-ca uses self-signed certificate
- Option 1: Set `step_ca.skip_tls_verify: true` (development only)
- Option 2: Add step-ca root cert to OS trust store

**`principal not allowed`**
- Certificate principal doesn't match Unix user
- Check `certificate.principals` matches server's `AuthorizedPrincipalsFile`
- Verify step-ca template generates expected principals

### Certificate Issues

**Certificate not refreshing**
```bash
# Check cert expiry
ssh-keygen -L -f ~/.ssh-cli/certs/<profile>/id_ecdsa-cert.pub

# Force refresh
rm -rf ~/.ssh-cli/certs/<profile>/
ssh-cli-init get-cert -profile <profile>
```

**`oidc authentication: ...`**
- Browser-based login failed or session expired
- For testing: use `get-cert -username -password` for non-interactive auth

---

## Testing

```bash
# Unit tests
go test ./...

# E2E tests (requires Docker and ssh-proxy-server)
go test -v -tags e2e -timeout 120s ./e2e/
```

E2E test prerequisites:
1. Add to `/etc/hosts`: `127.0.0.1 keycloak`
2. `cp e2e/testenv.json.example e2e/testenv.json`
3. Start services: `cd e2e && docker compose up -d --wait`

See [TESTING.md](TESTING.md) for full E2E setup.

---

## Related Documentation

| Document | Topic |
|----------|-------|
| [CERTIFICATES.md](CERTIFICATES.md) | Certificate authentication walkthrough, server setup, step-ca configuration |
| [TESTING.md](TESTING.md) | E2E testing with Docker Compose |
| [AGENTS.md](AGENTS.md) | Internal architecture for contributors |

---

## Notes

- Secure Enclave uses ECDSA P-256; YubiKey PIV uses ECDSA P-256 via the PIV standard
- Private keys are never exported from secure hardware
- If Secure Enclave storage is blocked in CLI environment, automatically falls back to macOS Keychain
- SSH aliases from `~/.ssh/config` are resolved automatically
- `proxy.address` accepts single string or array with `balance_mode`
