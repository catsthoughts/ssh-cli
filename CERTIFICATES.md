# Certificate-based authentication

This document describes how SSH certificate authentication works with ssh-cli, what needs to be configured on the client and on the server, and how the automatic refresh flow operates.

## How it works

SSH certificate authentication is an extension of public key authentication. Instead of enrolling every user's public key on every server, a Certificate Authority (CA) signs user public keys and servers are configured to trust the CA. When a user connects, the server verifies the certificate signature rather than looking up a specific public key.

```
┌─────────────────────────────────────────────────────────────────┐
│  Enrollment (once per key)                                      │
│                                                                 │
│  ssh-cli-init create-key          ──► key stored in SE/YubiKey  │
│  ssh-cli-init show-public-key     ──► public key (for CA)       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  Certificate issuance (automatic, on every ssh-cli connect)     │
│                                                                 │
│  ssh-cli                                                        │
│    │                                                            │
│    ├─1─► check ~/.ssh-cli/certs/<profile>/                      │
│    │      cert missing or expires within cert_refresh_before?   │
│    │                                                            │
│    ├─2─► OIDC device flow  ──►  Keycloak / IdP                  │
│    │      browser login, get access token                       │
│    │                                                            │
│    ├─3─► POST /ssh/sign    ──►  step-ca                         │
│    │      token + public key → SSH user certificate             │
│    │                                                            │
│    ├─4─► cert cached to ~/.ssh-cli/certs/<profile>/             │
│    │                                                            │
│    └─5─► SSH connect with cert + non-exportable private key     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  SSH server verification (on every connection)                  │
│                                                                 │
│  sshd                                                           │
│    └─► TrustedUserCAKeys = /etc/ssh/ssh_user_ca.pub             │
│         verify cert signature → check principals, expiry        │
└─────────────────────────────────────────────────────────────────┘
```

## Components

| Component | Role |
|-----------|------|
| **ssh-cli** | SSH client; holds non-exportable key, obtains and presents cert |
| **step-ca** | SSH Certificate Authority; signs certs after validating OIDC token |
| **Keycloak / IdP** | OIDC identity provider; authenticates the user, issues access token |
| **sshd** | Target SSH server; trusts the CA public key, accepts signed certs |
| **ssh-proxy-server** | Optional bastion; also trusts the CA, forwards agent to target |

## Server setup

### sshd (target host)

1. Obtain the SSH user CA public key from step-ca:

```bash
step ca root --ca-url https://ca.example.com > /etc/ssh/ssh_user_ca.pub
# or for the SSH-specific CA key:
curl -sk https://ca.example.com/ssh/authorities/public | \
  jq -r '.userKey' > /etc/ssh/ssh_user_ca.pub
```

2. Add to `/etc/ssh/sshd_config`:

```
TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub
```

3. Optionally restrict which principals (Linux users) are allowed. Create `/etc/ssh/auth_principals/<unix-user>` with one principal per line:

```bash
echo "your-user" > /etc/ssh/auth_principals/your-user
```

Then add to `sshd_config`:

```
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

4. Reload sshd:

```bash
systemctl reload sshd
```

### ssh-proxy-server (bastion, optional)

If you route connections through [ssh-proxy-server](https://github.com/catsthoughts/ssh-proxy-server), the proxy must also trust the same CA so it can accept the certificate presented by the client:

```
TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub
```

The proxy then forwards the client's agent (which holds the same cert+key) to the target host. The target host verifies the certificate independently.

### step-ca

step-ca must have an OIDC provisioner configured. The provisioner maps the OIDC `email` or `sub` claim to SSH principals.

Example `ca.json` provisioner block:

```json
{
  "type": "OIDC",
  "name": "oidc-provisioner",
  "clientID": "ssh-cli",
  "clientSecret": "secret",
  "configurationEndpoint": "https://sso.example.com/realms/ssh/.well-known/openid-configuration",
  "claims": {
    "enableSSHCA": true,
    "defaultUserSSHDuration": "8h",
    "maxUserSSHDuration": "24h"
  },
  "options": {
    "ssh": {
      "template": {
        "type": "user",
        "keyId": "{{ .Token.email }}",
        "principals": ["{{ .Token.email | splitList \"@\" | first }}"],
        "extensions": {
          "permit-pty": "",
          "permit-agent-forwarding": "",
          "permit-port-forwarding": "",
          "permit-user-rc": ""
        }
      }
    }
  }
}
```

## Client setup

### 1. Create key

```bash
ssh-cli-init create-key -profile prod-se
ssh-cli-init show-public-key -profile prod-se   # enroll this on the CA if needed
```

### 2. Configure the profile

Add `step_ca` and `oidc` sections to the profile in `~/.ssh-cli/config.json`:

```json
{
  "active_profile": "prod-se",
  "profiles": {
    "prod-se": {
      "key": {
        "tag":             "com.example.sshcli.prod",
        "label":           "Production Key",
        "comment":         "prod@mac",
        "key_source":      "secure_enclave",
        "public_key_path": "~/.ssh-cli/id_prod.pub"
      },
      "proxy": {
        "use_proxy":               true,
        "address":                 "proxy.example.com:2222",
        "user":                    "your-user",
        "known_hosts":             "~/.ssh/known_hosts",
        "host_key_policy":         "accept-new",
        "use_agent_forwarding":    true,
        "connect_timeout_seconds": 10
      },
      "target": {
        "request_tty": true
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
  }
}
```

### 3. Obtain a certificate manually (first time or for testing)

```bash
ssh-cli-init get-cert
ssh-cli-init get-cert -profile prod-se
```

This runs the OIDC device flow, signs the certificate, and caches it in `~/.ssh-cli/certs/<profile>/`.

### 4. Connect

```bash
ssh-cli                             # uses active_profile
ssh-cli -profile prod-se target:22
```

On every invocation, ssh-cli checks the cached certificate. If it is missing or will expire within `cert_refresh_before`, it runs the OIDC device flow and requests a new certificate automatically before connecting.

## Certificate lifecycle

```
cert_refresh_before (default 1h)
        │
        ▼
────────┼────────────────────────────────────────── cert validity ──►
        │                                                           │
   refresh window                                               ValidBefore
   (auto-refresh triggered)
```

| Field | Default | Description |
|-------|---------|-------------|
| `valid_for` | `8h` | Certificate validity duration requested from step-ca |
| `cert_refresh_before` | `1h` | How far before expiry to trigger a refresh |

Certificates are cached at `~/.ssh-cli/certs/<profile>/id_ecdsa-cert.pub`. The cache also stores a `metadata.json` with the expiry time so ssh-cli can check without parsing the certificate on every run.

## skip_tls_verify

If step-ca uses a self-signed or internal CA certificate that is not trusted by the OS, set `skip_tls_verify: true` in the `step_ca` block:

```json
{
  "step_ca": {
    "ca_url":          "https://ca.example.com",
    "authority_id":    "oidc-provisioner",
    "skip_tls_verify": true
  }
}
```

> **Warning:** only use this in development or when you fully control the network path to step-ca. In production, add the step-ca root certificate to the OS trust store instead:
>
> ```bash
> # macOS
> step ca root root_ca.crt --ca-url https://ca.example.com
> sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root_ca.crt
>
> # Linux
> sudo cp root_ca.crt /usr/local/share/ca-certificates/
> sudo update-ca-certificates
> ```

## Troubleshooting

### `tls: failed to verify certificate`

The OS does not trust the step-ca TLS certificate. Either add the root CA to the OS trust store (recommended) or set `"skip_tls_verify": true` in `step_ca` for development.

### `certificate is not trusted` on sshd

`TrustedUserCAKeys` on the server does not point to the correct CA public key, or the file is stale. Re-fetch it from step-ca and reload sshd.

### `principal not allowed`

The principal in the certificate does not match the Unix user or the `AuthorizedPrincipalsFile` on the server. Check that `certificate.principals` in the client config matches what the step-ca OIDC provisioner template generates and what the server expects.

### Certificate not refreshing

Check the cached cert expiry:

```bash
ssh-keygen -L -f ~/.ssh-cli/certs/<profile>/id_ecdsa-cert.pub
```

If the cert is valid but refresh is not triggering, verify `cert_refresh_before` is set and that system time is correct.

### Force a manual refresh

```bash
rm -rf ~/.ssh-cli/certs/<profile>/
ssh-cli-init get-cert -profile <profile>
```
