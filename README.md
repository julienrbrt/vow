# Vow

> [!WARNING]
> This is highly experimental software. Use with caution, especially during account migration.

Vow is a PDS (Personal Data Server) implementation in Go for the AT Protocol.

## Quick Start with Docker Compose

### Prerequisites

- Docker and Docker Compose installed
- A domain name pointing to your server
- Ports 80 and 443 open

### Installation

1. **Clone the repository**

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

4. **Start the services**

   ```bash
   docker-compose pull
   docker-compose up -d
   ```

5. **Get your invite code**

   On first run, an invite code is automatically created. View it with:

   ```bash
   docker-compose logs create-invite
   ```

   Or check the saved file:

   ```bash
   cat keys/initial-invite-code.txt
   ```

6. **Monitor the services**
   ```bash
   docker-compose logs -f
   ```

### What Gets Set Up

- **init-keys**: Generates cryptographic keys (rotation key and JWK) on first run
- **vow**: The main PDS service running on port 8080
- **create-invite**: Creates an initial invite code on first run

### Data Persistence

- `./keys/` — Cryptographic keys (generated automatically)
  - `rotation.key` — PDS rotation key
  - `jwk.key` — JWK private key
  - `initial-invite-code.txt` — Your first invite code (first run only)
- `./data/` — SQLite database and blockstore

## Configuration

### Database

Vow uses SQLite by default. No additional setup required.

```bash
VOW_DB_NAME="/data/vow/vow.db"
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

### IPFS Blob Storage

By default blobs are stored in SQLite. Optionally, blobs can be stored on IPFS via a local [Kubo](https://github.com/ipfs/kubo) node:

```bash
VOW_IPFS_BLOBSTORE_ENABLED=true

# URL of the local Kubo RPC API (default: http://127.0.0.1:5001)
VOW_IPFS_NODE_URL="http://127.0.0.1:5001"

# Optional: redirect getBlob to a public gateway instead of proxying
VOW_IPFS_GATEWAY_URL="https://ipfs.io"

# Optional: remote pinning service
VOW_IPFS_PINNING_SERVICE_URL="https://api.pinata.cloud/psa"
VOW_IPFS_PINNING_SERVICE_TOKEN="your-token"
```

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
docker-compose pull
docker-compose up -d
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
- [ ] `com.atproto.server.getAccountInviteCodes`
- [x] `com.atproto.server.getServiceAuth`
- [x] `com.atproto.server.refreshSession`
- [x] `com.atproto.server.requestAccountDelete`
- [x] `com.atproto.server.requestEmailConfirmation`
- [x] `com.atproto.server.requestEmailUpdate`
- [x] `com.atproto.server.requestPasswordReset`
- [x] `com.atproto.server.reserveSigningKey`
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
- [x] `com.atproto.sync.listRepos`
- [x] `com.atproto.sync.requestCrawl`
- [x] `com.atproto.sync.subscribeRepos`

### Other

- [x] `com.atproto.label.queryLabels`
- [x] `com.atproto.moderation.createReport`
- [x] `app.bsky.actor.getPreferences`
- [x] `app.bsky.actor.putPreferences`

## License

MIT. `server/static/pico.css` is also MIT licensed, available at [https://github.com/picocss/pico/](https://github.com/picocss/pico/).
