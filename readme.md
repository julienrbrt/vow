# Vow

> [!WARNING]
> This is highly experimental software. Use with caution, especially during account migration.

Vow is a Go PDS (Personal Data Server) for the AT Protocol.

## Features

- ✅ **IPFS storage** — repo blocks and blobs are stored on a local Kubo node and indexed in SQLite by DID and CID.
- ✅ **Keyless PDS** — the server never stores a private key. Every write is signed by the user's secp256k1 key in their Ethereum wallet (Rabby, MetaMask, etc.).
- ✅ **Browser signer** — the account page connects over WebSocket and signs commits with the user's Ethereum wallet. No browser extension is needed; just keep the tab open. Standard ATProto clients do not need to know about it.
- ✅ **User-controlled DID** — when the user registers a key, the PDS transfers the `did:plc` rotation key to the user's wallet. After that, only the user can change their identity.
- 🔜 **x402 payments for IPFS storage** — blob uploads will be gated by on-chain payments via the [x402 protocol](https://x402.org), using the same Ethereum wallet.

## Quick Start with Docker Compose

### Prerequisites

- Docker and Docker Compose installed
- A domain name pointing to your server

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
   docker compose pull
   docker compose up -d
   ```

   This starts three services:
   - **ipfs** — a Kubo node for repo blocks and blobs
   - **vow** — the PDS
   - **create-invite** — creates an initial invite code on first run

5. **Get your invite code**

   On first run, an invite code is automatically created. View it with:

   ```bash
   docker compose logs create-invite
   ```

   Or check the saved file:

   ```bash
   cat keys/initial-invite-code.txt
   ```

6. **Monitor the services**
   ```bash
   docker compose logs -f
   ```

### What Gets Set Up

- **init-keys**: Generates the rotation key and JWK on first run
- **ipfs**: A Kubo node for repo blocks and blobs. The RPC API (port 5001) stays internal; the gateway (port 8080) is exposed on `127.0.0.1:8081` for your reverse proxy.
- **vow**: The main PDS service on port 8080
- **create-invite**: Creates an initial invite code on first run

### Data Persistence

- `./keys/` — generated keys
  - `rotation.key` — PDS rotation key
  - `jwk.key` — JWK private key
  - `initial-invite-code.txt` — first invite code (first run only)
- `./data/` — SQLite metadata database
- `ipfs_data` Docker volume — IPFS blocks and blobs

### Reverse Proxy

You need a reverse proxy (nginx, Caddy, etc.) in front of both services:

| Service | Internal address | Purpose                       |
| ------- | ---------------- | ----------------------------- |
| vow     | `127.0.0.1:8080` | AT Protocol PDS               |
| ipfs    | `127.0.0.1:8081` | IPFS gateway for blob serving |

Set `VOW_IPFS_GATEWAY_URL` to your public gateway URL so `sync.getBlob` redirects clients there instead of proxying through vow.

## Configuration

### Database

Vow uses SQLite for relational metadata such as accounts, sessions, record indexes, and tokens. No extra setup is required.

```bash
VOW_DB_NAME="/data/vow/vow.db"
```

### IPFS Node

In Docker Compose, the local Kubo node is configured automatically through the internal hostname `ipfs`. For bare-metal deployments, point vow at your local node:

```bash
# URL of the Kubo RPC API
VOW_IPFS_NODE_URL="http://127.0.0.1:5001"

# Optional: redirect sync.getBlob to a public gateway instead of proxying
# through vow. Set to your own gateway or a public one like https://ipfs.io
VOW_IPFS_GATEWAY_URL="https://ipfs.example.com"
```

`VOW_IPFS_NODE_URL` is the only required IPFS setting. The local Kubo node is the only storage backend for now; remote pinning will come later through x402 payments.

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

The PDS **never stores or uses a private key**. Every write from the Bluesky app, Tangled, or any other standard ATProto client is held open until the user's Ethereum wallet returns a signature through the browser signer on the account page.

#### End-to-end signing flow

Standard ATProto clients do not need to know about this flow. The PDS keeps the HTTP request open while it waits for the signature, then responds normally.

```
ATProto client          PDS (vow)                  Account page (browser)   Ethereum wallet
      |                     |                               |                      |
      |-- createRecord ----->|                               |                      |
      |                     |-- 1. build unsigned commit     |                      |
      |                     |-- 2. push signing request      |                      |
      |                     |      over WebSocket ---------->|                      |
      |   (HTTP held open,  |                               |-- personal_sign() --->|
      |    up to 30 s)      |                               |<-- signature ---------|
      |                     |<-- 3. signature over WS -------|                      |
      |                     |-- 4. verify signature          |                      |
      |                     |-- 5. finalise & persist commit |                      |
      |<-- 200 result -------|                               |                      |
```

**What requires a wallet signature:**

Only operations that change the user's repo or identity need a wallet signature:

- **Repo writes** — `createRecord`, `putRecord`, `deleteRecord`, `applyWrites`
- **Identity operations** — PLC operations, handle updates
- **x402 payments** — EIP-712 payment authorisations for gated pinning

Read-only operations (browsing feeds, loading profiles, fetching notifications, etc.) do **not** prompt the wallet. The PDS proxies them to the AppView using cached service-auth JWTs — see [Service auth caching](#service-auth-caching) below.

#### Service auth caching

In standard ATProto, the PDS signs service-auth JWTs itself because it holds the signing key. In Vow, the signing key is in the user's wallet, so without caching, every proxied request (feeds, profiles, notifications, and so on) would trigger a wallet prompt.

Vow solves this by **caching service-auth JWTs**. When the proxy needs a token for an `(aud, lxm)` pair, it checks an in-memory cache first. Only a cache miss triggers a wallet signing request. Cached tokens live for 30 minutes with a 15-second reuse margin, so in practice the wallet is prompted at most **once every ~30 minutes per remote service endpoint** instead of on every request.

Tokens requested explicitly via `com.atproto.server.getServiceAuth` (where the caller controls the expiry) bypass the cache and always go to the wallet.

#### WebSocket connection

The account page connects with the session cookie set at sign-in:

```
GET /account/signer
Cookie: <session-cookie>
```

The connection is upgraded to a WebSocket and kept alive with ping/pong. Only one active connection per DID is supported; a new connection replaces the old one. The connection stays open while the tab is open and reconnects automatically with exponential backoff if interrupted.

A legacy Bearer-token endpoint is also available for programmatic clients:

```
GET /xrpc/com.atproto.server.signerConnect
Authorization: Bearer <access-token>
```

**Signing request message (PDS → browser):**

```json
{
  "type": "sign_request",
  "requestId": "uuid",
  "did": "did:plc:...",
  "payload": "<base64url-encoded unsigned commit bytes>",
  "ops": [
    { "type": "create", "collection": "app.bsky.feed.post", "rkey": "3abc..." }
  ],
  "expiresAt": "2025-01-01T00:00:30Z"
}
```

**Signature response message (browser → PDS):**

```json
{
  "type": "sign_response",
  "requestId": "uuid",
  "signature": "<base64url-encoded EIP-191 signature bytes>"
}
```

**Rejection message (browser → PDS):**

```json
{
  "type": "sign_reject",
  "requestId": "uuid"
}
```

### Browser-Based Signer

The signer runs entirely in the PDS account page. No browser extension or extra software is needed. The user keeps the page open (a pinned tab works well) and signing happens automatically.

## Identity & DID Sovereignty

Vow uses `did:plc` for full ATProto federation compatibility. AppViews, relays, and other PDSes can resolve DIDs through `plc.directory` without custom logic. The main difference from a standard PDS is **who controls the rotation key**.

### The problem with standard ATProto

In a typical PDS, the server holds the `did:plc` rotation key. That means the operator can change the user's DID document, rotate signing keys, change service endpoints, or effectively hijack the identity. The user has to trust the operator not to do that.

### Vow's approach: trust-then-transfer

Vow uses a two-phase model:

**Phase 1 — Account creation.** `createAccount` works like standard ATProto: the PDS creates the `did:plc` with its own rotation key.

**Phase 2 — Key registration.** When the user completes onboarding and calls `supplySigningKey`, the PDS submits one PLC operation that makes the user's wallet key both the signing key and the **only rotation key**, removing the PDS key. After that, only the user's Ethereum wallet can authorise future PLC operations.

### What the user gets

| Property                    | Before key registration    | After key registration                            |
| --------------------------- | -------------------------- | ------------------------------------------------- |
| Who signs commits           | Nobody (no key registered) | User's wallet                                     |
| Who controls the DID        | PDS rotation key           | User's wallet key                                 |
| PDS can hijack identity     | Yes                        | **No**                                            |
| User can migrate to new PDS | No (PDS must cooperate)    | **Yes** (sign a PLC op to update serviceEndpoint) |
| Federation compatibility    | Full                       | Full (unchanged)                                  |

### Verifiability

The transfer is publicly verifiable. The PLC audit log at `plc.directory` shows the full history of rotation key changes. After `supplySigningKey`, the log shows the PDS rotation key being replaced by the user's wallet `did:key`.

### Why not `did:key` or on-chain?

- **`did:key`** — elegant, but current ATProto AppViews and relays do not resolve it.
- **On-chain registry** — fully trustless, but every PDS would need blockchain support.
- **`did:web`** — if hosted on the PDS domain, the PDS controls it. If hosted on the user's domain, most users do not have one.

`did:plc` with rotation key transfer is the pragmatic choice: it works with existing ATProto implementations today and gives users real control over their identity.

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

[MIT](license). `server/static/pico.css` is also MIT licensed, available at [https://github.com/picocss/pico/](https://github.com/picocss/pico/).

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
| S3 database backups     | ❌ removed | ✅     |
| IPFS blob storage       | ✅ (Kubo)  | ❌     |
| IPFS repo block storage | ✅ (Kubo)  | ❌     |
| Email 2FA               | ❌ removed | ✅     |
| BYOK (keyless PDS)      | ✅         | ❌     |
| Ethereum wallet signer  | ✅         | ❌     |
| User-sovereign DID      | ✅         | ❌     |
| x402 payments for IPFS  | ✅         | ❌     |
