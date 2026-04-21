# SSH CLI for macOS Secure Enclave / YubiKey

A Go-based SSH client that uses non-exportable private keys stored in the macOS Secure Enclave, Keychain, or a YubiKey PIV smart card. It is designed to integrate well with [catsthoughts/ssh-proxy-server](https://github.com/catsthoughts/ssh-proxy-server) and is recommended when you want to use agent-based authentication with that project. It can:

- create a non-exportable client key in the Secure Enclave, macOS Keychain, or YubiKey PIV slot
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
ssh-cli-init init-config         # creates ~/.ssh-cli/config.json (prompts if exists)
ssh-cli-init init-config -force  # overwrite without prompt
# edit values in that file, then:

ssh-cli-init create-key
ssh-cli-init show-public-key

# switch between profiles:
ssh-cli-init list-profiles
ssh-cli-init use-profile staging
```

## Connect through ssh-proxy-server

Project link: [catsthoughts/ssh-proxy-server](https://github.com/catsthoughts/ssh-proxy-server)

The proxy expects:

- public key authentication on the proxy itself
- agent forwarding to the target host
- a target destination passed at connect time

This client keeps the proxy details in JSON and passes the final destination as a CLI argument, similar to a regular SSH client. If proxy.user is empty, the current OS user is used automatically. SSH aliases from ~/.ssh/config are also resolved. On first connection, the bastion host key is accepted and written to known_hosts when host_key_policy is set to accept-new.

Then connect:

```bash
ssh-cli
ssh-cli target-host:22
ssh-cli your-user@target-host:22
ssh-cli prod-host
```

Running the command without a destination logs you into the bastion from the JSON config.

## Connect directly (no proxy)

To connect directly to an SSH server without a proxy, set `use_proxy: false` in the proxy section. The destination is passed as a CLI argument:

```bash
ssh-cli -profile direct-se your-user@target.example.com
ssh-cli -profile direct-yubikey your-user@target.example.com:22
```

Example profile configuration:

```json
{
  "profiles": {
    "direct-se": {
      "key": {
        "key_source": "secure_enclave"
      },
      "proxy": {
        "use_proxy": false,
        "user": "your-user",
        "known_hosts": "~/.ssh/known_hosts",
        "host_key_policy": "accept-new"
      }
    },
    "direct-yubikey": {
      "key": {
        "key_source": "yubikey_piv",
        "yubikey": { "slot": "9a" }
      },
      "proxy": {
        "use_proxy": false,
        "user": "your-user"
      }
    }
  }
}
```

`use_agent_forwarding` is ignored for direct connections since agent forwarding only applies to proxy tunnels.

## Key sources

Use `key.key_source` to select the key backend:

| Value | Backend |
|-------|---------|
| `"secure_enclave"` | macOS Secure Enclave (ECDSA P-256, non-exportable, darwin only) |
| `"yubikey_piv"` | YubiKey PIV smart card (cross-platform via PC/SC) |

The legacy boolean `"secure_enclave": true` is still accepted for backward compatibility and is equivalent to `"key_source": "secure_enclave"`.

### YubiKey PIV

The PIV standard defines 24 slots (00–95 hex). YubiKey supports all of them via the piv-go library:

| Slot(s) | Common use |
|---------|------------|
| `9a` | PIV Authentication (default) |
| `9c` | Digital Signature |
| `9d` | Key Management |
| `9e` | Card Authentication |
| `82`–`95` | Retired Key Management (20 slots) |

```json
{
  "key": {
    "tag":             "com.example.sshcli.prod",
    "label":           "Production YubiKey",
    "key_source":      "yubikey_piv",
    "public_key_path": "~/.ssh-cli/id_prod.pub",
    "yubikey": {
      "slot": "9a"
    }
  }
}
```

`slot` defaults to `"9a"` when omitted. Optional fields: `pin` (PIV PIN) and `pkcs11_path` (path to PC/SC library, Linux only).

### Replacing an existing key

Use `-force` to delete the existing key and generate a new one. A confirmation prompt is shown before destructive action:

```bash
ssh-cli-init create-key -force
ssh-cli-init create-key -force -profile staging
```

For Secure Enclave: removes the key from Keychain by tag, then creates a new one.  
For YubiKey PIV: resets the PIV slot, then generates a new key.

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

## Multiple profiles

`~/.ssh-cli/config.json` supports a multi-profile format. Use `active_profile` to select the default profile, or override it per-command with `-profile`:

```json
{
  "active_profile": "prod",
  "profiles": {
    "prod": {
      "key": { "key_source": "secure_enclave", "..." : "..." },
      "proxy": { "address": "proxy.example.com:2222", "...": "..." }
    },
    "staging": {
      "key": { "key_source": "yubikey_piv", "...": "..." },
      "proxy": { "address": "proxy-staging.example.com:2222", "...": "..." }
    }
  }
}
```

Manage profiles with `ssh-cli-init`:

```bash
ssh-cli-init list-profiles           # list all profiles, * marks the active one
ssh-cli-init use-profile staging     # persist active_profile = "staging" in config
```

The `-profile` flag overrides the active profile for a single invocation on all commands that read the config:

```bash
ssh-cli-init create-key -profile staging
ssh-cli-init create-key -force -profile staging  # replace existing key
ssh-cli-init show-public-key -profile prod
ssh-cli                                          # uses active_profile
ssh-cli -profile staging target-host:22
```

The legacy flat format (a single JSON object without a `profiles` key) is still supported.

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

### Auto-refresh via step-ca (recommended)

The client integrates with [Smallstep step-ca](https://smallstep.com/docs/step-ca/) to automatically obtain and refresh SSH user certificates. On every `ssh-cli` invocation the stored certificate is checked; if it is missing or expires within `cert_refresh_before` (default `1h`), a new one is requested via OIDC device flow before connecting.

```json
{
  "certificate": {
    "identity":            "your-user",
    "principals":          ["your-user"],
    "valid_for":           "8h",
    "cert_refresh_before": "1h",
    "step_ca": {
      "ca_url":       "https://ca.example.com",
      "authority_id": "oidc-provisioner"
    },
    "oidc": {
      "provider_url":  "https://sso.example.com/realms/ssh",
      "client_id":     "ssh-cli",
      "client_secret": "secret",
      "scope":         "openid profile email"
    }
  }
}
```

Certificates are cached in `~/.ssh-cli/certs/<profile>/` and reused across invocations until they expire.

Obtain a certificate manually (useful for enrolling a new key or testing):

```bash
ssh-cli-init get-cert
ssh-cli-init get-cert -profile staging
```

### SSH user certificate (local CA)

Sign a certificate locally with a CA key on disk:

```json
{
  "certificate": {
    "type":          "ssh-user",
    "ca_key_path":   "./ssh_user_ca",
    "output_path":   "./id_secure_enclave-cert.pub",
    "auth_cert_path":"./id_secure_enclave-cert.pub",
    "identity":      "your-user",
    "principals":    ["your-user"],
    "valid_for":     "8h"
  }
}
```

```bash
ssh-cli-init create-cert
```

### X.509 CSR

```json
{
  "certificate": {
    "type":                "x509-csr",
    "output_path":         "./client.csr",
    "subject_common_name": "your-user"
  }
}
```

### Self-signed X.509 certificate

```json
{
  "certificate": {
    "type":                "x509-selfsigned",
    "output_path":         "./client.crt",
    "subject_common_name": "your-user"
  }
}
```

## Full config reference

### Proxy via step-ca (Secure Enclave)

```json
{
  "key": {
    "tag":             "com.example.sshcli.prod",
    "label":           "Production Key",
    "comment":         "prod@mac",
    "key_source":      "secure_enclave",
    "public_key_path": "~/.ssh-cli/id_prod.pub"
  },
  "proxy": {
    "address":                 ["proxy-1.example.com:2222", "proxy-2.example.com:2222"],
    "user":                    "your-user",
    "known_hosts":             "~/.ssh/known_hosts",
    "host_key_policy":         "accept-new",
    "insecure_ignore_hostkey": false,
    "use_agent_forwarding":    true,
    "connect_timeout_seconds": 10,
    "balance_mode":            "failover",
    "retry_attempts":          1,
    "retry_delay_seconds":     5
  },
  "target": {
    "command":        "",
    "request_tty":    true,
    "forward_ctrl_c": false
  },
  "certificate": {
    "identity":            "your-user",
    "principals":          ["your-user"],
    "valid_for":           "8h",
    "cert_refresh_before": "1h",
    "step_ca": {
      "ca_url":       "https://ca.example.com",
      "authority_id": "oidc-provisioner"
    },
    "oidc": {
      "provider_url":  "https://sso.example.com/realms/ssh",
      "client_id":     "ssh-cli",
      "client_secret": "secret",
      "scope":         "openid profile email"
    }
  }
}
```

### Proxy via step-ca (YubiKey PIV)

```json
{
  "key": {
    "tag":             "com.example.sshcli.prod",
    "label":           "Production YubiKey",
    "comment":         "prod@yubikey",
    "key_source":      "yubikey_piv",
    "public_key_path": "~/.ssh-cli/id_prod.pub",
    "yubikey": {
      "slot": "9a"
    }
  },
  "proxy": {
    "address":                 "proxy.example.com:2222",
    "user":                    "your-user",
    "known_hosts":             "~/.ssh/known_hosts",
    "host_key_policy":         "accept-new",
    "insecure_ignore_hostkey": false,
    "use_agent_forwarding":    true,
    "connect_timeout_seconds": 10,
    "balance_mode":            "failover",
    "retry_attempts":          1,
    "retry_delay_seconds":     5
  },
  "target": {
    "command":        "",
    "request_tty":    true,
    "forward_ctrl_c": false
  },
  "certificate": {
    "identity":            "your-user",
    "principals":          ["your-user"],
    "valid_for":           "8h",
    "cert_refresh_before": "1h",
    "step_ca": {
      "ca_url":       "https://ca.example.com",
      "authority_id": "oidc-provisioner"
    },
    "oidc": {
      "provider_url":  "https://sso.example.com/realms/ssh",
      "client_id":     "ssh-cli",
      "client_secret": "secret",
      "scope":         "openid profile email"
    }
  }
}
```

### Direct connection (Secure Enclave)

```json
{
  "key": {
    "tag":             "com.example.sshcli.direct",
    "label":           "Direct Connection Key",
    "comment":         "direct@mac",
    "key_source":      "secure_enclave",
    "public_key_path": "~/.ssh-cli/id_direct.pub"
  },
  "proxy": {
    "use_proxy":               false,
    "user":                    "your-user",
    "known_hosts":             "~/.ssh/known_hosts",
    "host_key_policy":         "accept-new",
    "connect_timeout_seconds": 10
  },
  "target": {
    "command":        "",
    "request_tty":    true,
    "forward_ctrl_c": false
  }
}
```

### Direct connection (YubiKey PIV)

```json
{
  "key": {
    "tag":             "com.example.sshcli.direct",
    "label":           "Direct Connection Key (YubiKey)",
    "comment":         "direct@yubikey",
    "key_source":      "yubikey_piv",
    "public_key_path": "~/.ssh-cli/id_direct.pub",
    "yubikey": {
      "slot": "9a"
    }
  },
  "proxy": {
    "use_proxy":               false,
    "user":                    "your-user",
    "known_hosts":             "~/.ssh/known_hosts",
    "host_key_policy":         "accept-new",
    "connect_timeout_seconds": 10
  },
  "target": {
    "command":        "",
    "request_tty":    true,
    "forward_ctrl_c": false
  }
}
```

## Testing

```bash
go test ./...                                        # unit tests
go test -v -tags e2e -timeout 120s ./e2e/            # E2E (requires docker)
```

See [TESTING.md](TESTING.md) for full E2E setup instructions.

For a detailed walkthrough of certificate-based authentication — including step-ca, sshd, and Keycloak setup — see [CERTIFICATES.md](CERTIFICATES.md).

## Notes

- Secure Enclave keys are ECDSA P-256 on macOS.
- The private key never leaves Keychain / Secure Enclave / YubiKey.
- If Secure Enclave storage is blocked by the local CLI environment, the client automatically falls back to a non-exportable key stored in the macOS Keychain.
- Secure Enclave and Keychain backends are macOS-only. YubiKey PIV works on macOS, Linux, and Windows.
