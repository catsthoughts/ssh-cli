# SSH CLI for macOS Secure Enclave

A Go-based SSH client for macOS that uses non-exportable private keys stored in the Keychain or Secure Enclave. It is designed to integrate well with [catsthoughts/ssh-proxy-server](https://github.com/catsthoughts/ssh-proxy-server) and is recommended when you want to use agent-based authentication with that project. It can:

- create a non-exportable client key in the Secure Enclave or macOS Keychain
- print the SSH public key for enrollment on a proxy or target host
- create an SSH user certificate signed by an existing CA key
- create an X.509 CSR or self-signed X.509 certificate
- connect directly to an SSH server or through catsthoughts/ssh-proxy-server
- forward a read-only SSH agent backed by the same non-exportable key

## Build

```bash
go build ./cmd/ssh-cli
```

## Quick start

```bash
go run ./cmd/ssh-cli-init init-config
# this creates ~/.ssh-cli/config.json
# edit values in that file if needed

go run ./cmd/ssh-cli-init create-key
go run ./cmd/ssh-cli-init show-public-key
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
go run ./cmd/ssh-cli
go run ./cmd/ssh-cli target-host:22
go run ./cmd/ssh-cli your-user@target-host:22
go run ./cmd/ssh-cli prod-host
```

Running the command without a destination logs you into the bastion from the JSON config.

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
go run ./cmd/ssh-cli-init create-cert
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

## Notes

- Secure Enclave keys are ECDSA P-256 on macOS.
- The private key never leaves Keychain / Secure Enclave.
- If Secure Enclave storage is blocked by the local CLI environment, the client automatically falls back to a non-exportable key stored in the macOS Keychain.
- This repository is intended for macOS. Non-darwin builds return a clear error.
