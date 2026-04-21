# Testing

## Unit tests

```bash
go test ./...
```

## E2E tests

E2E tests spin up a full local environment (Keycloak, step-ca, sshd) via Docker Compose and verify the complete flow: key creation → OIDC auth → cert signing → SSH connection.

### Prerequisites

- Docker with Compose plugin
- `/etc/hosts` entry for Keycloak (needed so the browser can follow the device-flow redirect):

```
127.0.0.1 keycloak
```

### Start the environment

```bash
cd e2e
docker compose up -d --wait
```

Services started:

| Service  | Address                  | Description               |
|----------|--------------------------|---------------------------|
| Keycloak | `http://127.0.0.1:8080`  | OIDC identity provider    |
| step-ca  | `https://127.0.0.1:443`  | SSH certificate authority |
| sshd     | `127.0.0.1:2222`         | Target SSH server (Alpine)|

Default credentials: `testuser / password`.

### Setup testenv

```bash
cp e2e/testenv.json.example e2e/testenv.json
# defaults work with the docker-compose environment as-is
```

### Run

```bash
go test -v -tags e2e -timeout 120s ./e2e/
```

### Tests covered

| Test | Description |
|------|-------------|
| `TestE2E_SecureEnclave_Direct` | SE key creation + direct SSH connection |
| `TestE2E_YubiKey_Direct` | YubiKey key creation + direct SSH connection (skipped if no YubiKey) |
| `TestE2E_YubiKey_SlotPreservation` | Verifies test keys don't overwrite slot 9a |

### Tear down

```bash
docker compose down
```

### How the environment works

```
Browser / CLI (host)
  │
  ├─ http://127.0.0.1:8080  ──►  Keycloak (Docker)
  │                                  │ issues tokens with
  │                                  │ iss=http://keycloak:8080/realms/ssh
  │
  ├─ https://127.0.0.1:443  ──►  step-ca (Docker)
  │                                  │ validates token iss against
  │                                  │ configurationEndpoint=http://keycloak:8080/...
  │                                  │ (Docker DNS resolves keycloak → container)
  │
  └─ ssh testuser@127.0.0.1:2222 ──► sshd (Docker, Alpine)
                                         TrustedUserCAKeys = step-ca SSH user CA
```

Keycloak uses `KC_HOSTNAME=http://keycloak:8080` so every issued token carries
`iss=http://keycloak:8080/realms/ssh`. step-ca fetches the OIDC discovery doc
from the same hostname via Docker DNS and expects that issuer — they match.
The CLI opens the device-flow URL using `verification_uri_complete` from
Keycloak's response (not a self-constructed URL), so browser cookies stay
on the `keycloak` domain throughout the login flow.
