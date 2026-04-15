# SSH CLI — Cross-Platform SSH Client with Hardware-Backed Keys

A Go-based SSH client that uses non-exportable private keys stored in platform-specific hardware security modules. It is designed to integrate well with [catsthoughts/ssh-proxy-server](https://github.com/catsthoughts/ssh-proxy-server) and is recommended when you want to use agent-based authentication with that project. It can:

- create a non-exportable client key in the Secure Enclave (macOS), TPM 2.0 (Linux), or CNG/Platform Crypto Provider (Windows)
- fall back to a software ECDSA P-256 key when no hardware module is available
- print the SSH public key for enrollment on a proxy or target host
- create an SSH user certificate signed by an existing CA key
- create an X.509 CSR or self-signed X.509 certificate
- connect directly to an SSH server or through catsthoughts/ssh-proxy-server
- forward a read-only SSH agent backed by the same non-exportable key

## Build

```bash
go build -o ssh-cli ./cmd/ssh-cli
go build -o ssh-cli-init ./cmd/ssh-cli-init
```

## Quick start

```bash
ssh-cli-init init-config
# this creates ~/.ssh-cli/config.json
# edit values in that file if needed

ssh-cli-init create-key
ssh-cli-init show-public-key
```

## Connect through ssh-proxy-server

Project link: [catsthoughts/ssh-proxy-server](https://github.com/catsthoughts/ssh-proxy-server)

The proxy expects:

- public key authentication on the proxy itself
- agent forwarding to the target host
- a target destination passed at connect time

This client keeps the proxy details in JSON and passes the final destination as a CLI argument, similar to a regular SSH client. If proxy.user is empty, the current macOS user is used automatically. SSH aliases from ~/.ssh/config are also resolved. On first connection, the bastion host key is accepted and written to known_hosts when host_key_policy is set to accept-new.

Then connect:

```bash
ssh-cli
ssh-cli target-host:22
ssh-cli your-user@target-host:22
ssh-cli prod-host
```

Running the command without a destination logs you into the bastion from the JSON config.

## Multiple proxies

`proxy.address` accepts either a single string or an array of addresses. All other proxy settings are shared across them.

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

### Balance modes

| Mode | Behavior |
|------|----------|
| `failover` | Try proxies in config order; stop at first success (default) |
| `round-robin` | Rotate starting proxy each invocation so load is spread across proxies |
| `random` | Shuffle proxy order randomly each invocation |

In all modes every proxy is tried before giving up. On failure the full list is retried up to `retry_attempts` times with a `retry_delay_seconds` pause between rounds.

## Options

### request_tty

Controls whether the client requests a pseudo-terminal (PTY) on the remote side. Enabled by default. Disable it when running a single command via `target.command` and you need clean stdout without terminal processing (e.g. for pipes or scripts). Analogous to `ssh -t` / `ssh -T`.

```json
{
  "target": {
    "request_tty": false
  }
}
```

### forward_ctrl_c

By default, Ctrl+C in a raw-mode session is sent directly to the remote side. Enable `forward_ctrl_c` to add a safety mechanism: the first Ctrl+C is still forwarded to the remote session, but pressing Ctrl+C a second time within 1 second will terminate the local ssh-cli process.

```json
{
  "target": {
    "forward_ctrl_c": true
  }
}
```

## Certificate modes

### SSH user certificate

Provide a CA private key path in the config:

```json
{
  "certificate": {
    "type": "ssh-user",
    "ca_key_path": "./ssh_user_ca",
    "output_path": "./id_secure_enclave-cert.pub",
    "auth_cert_path": "./id_secure_enclave-cert.pub",
    "identity": "your-user",
    "principals": ["your-user"],
    "valid_for": "8h"
  }
}
```

Generate it:

```bash
ssh-cli-init create-cert
```

### X.509 CSR

```json
{
  "certificate": {
    "type": "x509-csr",
    "output_path": "./client.csr",
    "subject_common_name": "your-user"
  }
}
```

### Self-signed X.509 certificate

```json
{
  "certificate": {
    "type": "x509-selfsigned",
    "output_path": "./client.crt",
    "subject_common_name": "your-user"
  }
}
```

## Key backends

The `key.backend` field controls which key storage is used. Set to `"auto"` (default) for automatic platform detection.

| Backend | Platform | Storage |
|---------|----------|---------|
| `auto` | any | Automatic: Secure Enclave on macOS, TPM on Linux (if `/dev/tpmrm0` exists), CNG on Windows, file fallback otherwise |
| `secure-enclave` | macOS | Secure Enclave / Keychain (ECDSA P-256, non-exportable) |
| `tpm` | Linux | TPM 2.0 via `/dev/tpmrm0` (ECDSA P-256, persistent handle) |
| `cng` | Windows | CNG Platform Crypto Provider or Software KSP (ECDSA P-256) |
| `file` | any | Software ECDSA P-256 key stored as PEM in `~/.ssh-cli/keys/` |

```json
{
  "key": {
    "backend": "auto"
  }
}
```

## Full config reference

```json
{
  "profile": "default",
  "key": {
    "tag": "com.example.sshcli.default",
    "label": "SSH CLI Default",
    "comment": "secure-enclave@mac",
    "secure_enclave": true,
    "public_key_path": "./id_secure_enclave.pub",
    "backend": "auto"
  },
  "proxy": {
    "address": ["proxy-1.example.com:2222", "proxy-2.example.com:2222"],
    "user": "",
    "known_hosts": "~/.ssh/known_hosts",
    "host_key_policy": "accept-new",
    "insecure_ignore_hostkey": false,
    "use_agent_forwarding": true,
    "connect_timeout_seconds": 10,
    "balance_mode": "failover",
    "retry_attempts": 1,
    "retry_delay_seconds": 5
  },
  "target": {
    "command": "",
    "request_tty": true,
    "forward_ctrl_c": false
  },
  "certificate": {
    "type": "ssh-user",
    "ca_key_path": "",
    "output_path": "./id_secure_enclave-cert.pub",
    "auth_cert_path": "",
    "identity": "your-user",
    "principals": ["your-user"],
    "valid_for": "8h",
    "subject_common_name": "your-user"
  }
}
```

## Notes

- All key backends use ECDSA P-256.
- On macOS, the private key never leaves Keychain / Secure Enclave. If Secure Enclave storage is blocked by the local CLI environment, the client automatically falls back to a non-exportable key stored in the macOS Keychain.
- On Linux, the key is stored as a persistent object in the TPM 2.0. Requires access to `/dev/tpmrm0`.
- On Windows, the key is stored via CNG. The Platform Crypto Provider (TPM-backed) is tried first; if unavailable, the Software KSP is used.
- The `file` backend stores a PEM-encoded private key on disk — use only when no hardware module is available.
