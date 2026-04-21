# Agent Instructions

## Build

```bash
go build -o ssh-cli ./cmd/ssh-cli
go build -o ssh-cli-init ./cmd/ssh-cli-init
```

## Test

```bash
go test ./...                 # unit tests only
go test -v -tags e2e -timeout 120s ./e2e/   # E2E (requires ssh-proxy-server on 127.0.0.1:2222)
```

**E2E prerequisites:** `cp e2e/testenv.json.example e2e/testenv.json` and edit with your credentials.

## Architecture

- Two binaries: `ssh-cli` (client) and `ssh-cli-init` (key/cert management) in `cmd/`
- All business logic in `internal/` — `keychain/`, `sshclient/`, `config/`, `certutil/`, `agent/`, `target/`
- Single Go module; no monorepo, no workspaces

## Key Facts

- Secure Enclave: ECDSA P-256, macOS only. Falls back to macOS Keychain if SE is unavailable.
- YubiKey PIV: cross-platform (macOS/Linux/Windows). Default slot: `9a`.
- Private keys are never exportable.
- SSH aliases from `~/.ssh/config` are resolved automatically.
- Config: `~/.ssh-cli/config.json` (legacy flat format still supported)
- `proxy.address` accepts single string or array with `balance_mode` (failover/round-robin/random)
- E2E tests tagged `e2e`; they connect to a real ssh-proxy-server and target host
