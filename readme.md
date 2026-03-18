# Vow

> [!WARNING]
> This is highly experimental software. Use with caution, especially during account migration.

> [!IMPORTANT]
> **Vow implements a two-key model for signing using WebAuthn PRF extension.** After registering a passkey, the server never stores a private signing key — the passkey authenticates and provides PRF output, from which a deterministic signing key is derived on-the-fly for each commit. Users fully control their DID.

Vow is a Go PDS (Personal Data Server) for AT Protocol.

## Quick Start with Docker Compose

### Prerequisites

- Docker and Docker Compose installed
- A domain name pointing to your server

### Installation

1. **Clone repository**

```bash
git clone https://pkg.rbrt.fr/vow.git
cd vow
```

2. **Create your configuration file**

```bash
cp .env.example .env
```

3. **Edit `.env` with your settings**

```bash
VOW_DID="did:web:your-domain.com"
VOW_HOSTNAME="your-domain.com"
VOW_CONTACT_EMAIL="you@example.com"
VOW_RELAYS="https://bsky.network"

# Generate with: openssl rand -hex 16
VOW_ADMIN_PASSWORD="your-secure-password"

# Generate with: openssl rand -hex 32
VOW_SESSION_SECRET="your-session-secret"
```

4. **Start services**

```bash
docker compose pull
docker compose up -d
```

This starts three services:

- **ipfs** — a Kubo node for repo blocks and blobs
- **vow** — the PDS
- **create-invite** — creates an initial invite code on first run

5. **Get your invite code**

On first run, an invite code is automatically created:

```bash
docker compose logs create-invite
```

Or check saved file:

```bash
cat keys/initial-invite-code.txt
```

6. **Monitor services**

```bash
docker compose logs -f
```

### What Gets Set Up

- **init-keys**: Generates rotation key and JWK on first run
- **ipfs**: A Kubo node for repo blocks and blobs. The RPC API (port 5001) stays internal; gateway (port 8080) is exposed on `127.0.0.1:8081` for your reverse proxy.
- **vow**: The main PDS service on port 8080
- **create-invite**: Creates an initial invite code on first run

### Data Persistence

- `./keys/` — generated keys
  - `rotation.key` — PDS rotation key
  - `jwk.key` — JWK private key
  - `initial-invite-code.txt` — first invite code (first run only)
- `./data/` — SQLite metadata database
- `/opt/ipfs` Docker volume — IPFS blocks and blobs

### Reverse Proxy

You need a reverse proxy (nginx, Caddy, etc.) in front of the PDS:

| Service | Internal address | Purpose                       |
| ------- | ---------------- | ----------------------------- |
| vow     | `127.0.0.1:8080` | AT Protocol PDS               |
| ipfs    | `127.0.0.1:8081` | IPFS gateway for blob serving |

Set `VOW_IPFS_GATEWAY_URL` to your public gateway URL so `sync.getBlob` redirects clients there instead of proxying through vow.

## Configuration

### Database

Vow uses SQLite for relational metadata such as accounts, sessions, record indexes, and tokens.

```bash
VOW_DB_NAME="/data/vow/vow.db"
```

### IPFS Node

```bash
# URL of Kubo RPC API
VOW_IPFS_NODE_URL="http://127.0.0.1:5001"

# Optional: redirect sync.getBlob to a public gateway
VOW_IPFS_GATEWAY_URL="https://ipfs.example.com"
```

### SMTP Email

```bash
VOW_SMTP_USER="your-smtp-username"
VOW_SMTP_PASS="your-smtp-password"
VOW_SMTP_HOST="smtp.example.com"
VOW_SMTP_PORT="587"
VOW_SMTP_EMAIL="noreply@example.com"
VOW_SMTP_NAME="Vow PDS"
```

### BYOK (Bring Your Own Key)

The PDS holds two keys:

- **Rotation key** (`rotation.key`) — used for DID genesis operations and for signing the PLC operation that transfers control to the user's passkey during passkey registration.
- **JWK key** (`jwk.key`) — a P-256 ECDSA key used exclusively to sign ATProto session JWTs (access and refresh tokens) and OAuth tokens. It has no role in repo writes or identity operations.

Neither key is ever used to sign repo commits or service-auth JWTs.

## How It Works

### Browser-Based Signer

The account page (`/account`) connects over WebSocket and runs entirely in the browser. No browser extension or extra software is needed — the user just keeps the tab open and signs commits automatically when prompted.

### Key Flow

1. **Before passkey registration** — PDS controls DID with its rotation key
2. **After passkey registration** — User's passkey becomes the rotation key, derived via WebAuthn PRF extension. Only the user can modify their DID.
3. **Signing commits** — Passkey authenticates user and provides PRF output. A deterministic signing key is derived from PRF output and used to sign commits.

### Two-Key Model

Vow implements a two-key model:

| Property               | PDS Server Key     | Passkey-Derived Key         |
| ---------------------- | ------------------ | --------------------------- |
| **DID slot**           | `#atproto_service` | `#atproto`                  |
| **Purpose**            | Service-auth JWTs  | Repo commits                |
| **Passkey required**   | No                 | Yes (for repo writes)       |
| **Private key stored** | Yes (in `jwk.key`) | **No** (derived on-the-fly) |

## Management Commands

Create an invite code:

```bash
docker exec vow-pds /vow create-invite-code --uses 1
```

Reset a user's password:

```bash
docker exec vow-pds /vow reset-password --did "did:plc:xxx"
```

## Updating

```bash
docker compose build
docker compose up -d
```

## Implemented Endpoints

> [!NOTE]
> Just because something is implemented doesn't mean it is finished. Many endpoints still have rough edges around validation and error handling.

### Identity

- [x] `com.atproto.identity.getRecommendedDidCredentials`
- [x] `com.atproto.identity.requestPlcOperationSignature`
- [x] `com.atproto.identity.resolveHandle`
- [x] `com.atproto.identity.signPlcOperation`
- [x] `com.atproto.identity.submitPlcOperation`
- [x] `com.atproto.identity.updateHandle`

### Repo

- [x] `com.atproto.repo.applyWrites`
- [x] `com.atproto.repo.createRecord`
- [x] `com.atproto.repo.putRecord`
- [x] `com.atproto.repo.deleteRecord`
- [x] `com.atproto.repo.describeRepo`
- [x] `com.atproto.repo.getRecord`
- [x] `com.atproto.repo.importRepo` (Works "okay". Use with extreme caution.)
- [x] `com.atproto.repo.listRecords`
- [x] `com.atproto.repo.listMissingBlobs`

### Server

- [x] `com.atproto.server.activateAccount`
- [x] `com.atproto.server.checkAccountStatus`
- [x] `com.atproto.server.confirmEmail`
- [x] `com.atproto.server.createAccount`
- [x] `com.atproto.server.createInviteCode`
- [x] `com.atproto.server.createInviteCodes`
- [x] `com.atproto.server.deactivateAccount`
- [x] `com.atproto.server.deleteAccount`
- [x] `com.atproto.server.deleteSession`
- [x] `com.atproto.server.describeServer`
- [x] `com.atproto.server.getAccountInviteCodes`
- [x] `com.atproto.server.getServiceAuth`
- [x] `com.atproto.server.refreshSession`
- [x] `com.atproto.server.requestAccountDelete`
- [x] `com.atproto.server.requestEmailConfirmation`
- [x] `com.atproto.server.requestEmailUpdate`
- [x] `com.atproto.server.requestPasswordReset`
- [x] `com.atproto.server.resetPassword`
- [x] `com.atproto.server.updateEmail`

### Sync

- [x] `com.atproto.sync.getBlob`
- [x] `com.atproto.sync.getBlocks`
- [x] `com.atproto.sync.getLatestCommit`
- [x] `com.atproto.sync.getRecord`
- [x] `com.atproto.sync.getRepoStatus`
- [x] `com.atproto.sync.getRepo`
- [x] `com.atproto.sync.listBlobs`
- [x] `com.atproto.sync.requestCrawl`
- [x] `com.atproto.sync.subscribeRepos`

### Other

- [x] `com.atproto.label.queryLabels`
- [x] `com.atproto.moderation.createReport`
- [x] `app.bsky.actor.getPreferences`
- [x] `app.bsky.actor.putPreferences`

## License

[MIT](license). `server/static/pico.css` is also MIT licensed, available at [https://github.com/picocss/pico](https://github.com/picocss/pico).

## Thanks

Vow is based on [Cocoon](https://tangled.org/hailey.at/cocoon). Many thanks for the solid foundation.

### Vow vs Cocoon

| Feature                 | Vow        | Cocoon |
| ----------------------- | ---------- | ------ |
| Language                | Go         | Go     |
| SQLite (metadata)       | ✅         | ✅     |
| SQLite blockstore       | ❌ removed | ✅     |
| PostgreSQL support      | ❌ removed | ✅     |
| S3 blob storage         | ❌ removed | ✅     |
| IPFS repo block storage | ✅ (Kubo)  | ❌     |
| IPFS blob storage       | ✅ (Kubo)  | ❌     |
| Email 2FA               | ❌ removed | ✅     |
| BYOK (keyless PDS)      | ✅         | ❌     |
| Passkey signer          | ✅         | ❌     |

## Technical Details

For in-depth specifications, flows, trade-offs, and maintenance considerations, see [specs.md](specs.md).
