# Vow Technical Specifications

This document contains technical specifications for Vow's two-key WebAuthn PRF signing architecture. It describes the protocol, security properties, trade-offs, and maintenance considerations for operators and developers.

## Overview

Vow implements a keyless PDS architecture using WebAuthn PRF (Pseudorandom Function) extension to derive signing keys deterministically from passkeys. The server never stores the private signing key — it is derived on-the-fly for each commit operation.

### Key Design Principles

1. **Server never holds signing key** — The passkey provides PRF output; server derives signing key deterministically
2. **Deterministic derivation** — Same PRF output always produces same signing key
3. **Two-key model** — Separate keys for repo commits (passkey-derived) vs service-auth (PDS server)
4. **User-controlled DID** — After passkey registration, only user can authorize identity operations via passkey

## Architecture

### Database Schema

```sql
CREATE TABLE repos (
    did TEXT PRIMARY KEY,
    created_at DATETIME,
    email TEXT UNIQUE,
    auth_public_key BLOB,           -- Passkey P-256 public key (for WebAuthn assertion verification)
    signing_public_key BLOB,         -- PRF-derived secp256k1 signing key (for commit signature verification)
    credential_id BLOB,              -- WebAuthn credential ID (for building allowCredentials list)
    rev TEXT,
    root BLOB,
    preferences BLOB,
    deactivated BOOLEAN
);
```

### Key Types

| Key                     | Type      | Purpose                           | Stored                     |
| ----------------------- | --------- | --------------------------------- | -------------------------- |
| `auth_public_key`       | P-256     | WebAuthn assertion verification   | ✅ Yes                     |
| `signing_public_key`    | secp256k1 | Commit signature verification     | ✅ Yes                     |
| PRF-derived private key | secp256k1 | Commit signing                    | ❌ No (derived on-the-fly) |
| PDS rotation key        | secp256k1 | PLC genesis, initial key transfer | ✅ Yes                     |
| PDS service key         | P-256     | Session/OAuth JWT signing         | ✅ Yes                     |

### DID Document Structure

```json
{
  "verificationMethods": {
    "atproto": "did:key:z6Mkq... (PRF-derived signing key)",
    "atproto_service": "did:key:z5Mka... (PDS server key)"
  },
  "rotationKeys": ["did:key:z6Mkq... (PRF-derived signing key)"]
}
```

After key registration, PDS rotation key is **removed** from DID document. Only user's passkey-derived key is the rotation key.

## Protocol Flows

### Passkey Registration Flow

**Objective:** Register a new passkey and transfer DID control from PDS to user.

```
┌─────────────┐      ┌──────────────────┐      ┌──────────────────┐
│   Browser   │      │   PDS Server    │      │   PLC Directory │
└─────┬───────┘      └──────┬───────────┘      └────────┬─────────┘
      │                      │                        │
      │ 1. Request         │                        │
      │    challenge          │                        │
      ├──────────────────────>│                        │
      │                      │ 2. Get DID audit        │
      │                      ├───────────────────────>│
      │                      │                        │ 3. Submit
      │                      │<────────────────────────┘   operation
      │ 3. Create          │                        │ (signing key becomes
      │    passkey           │                        │  rotation key)
      │<───────────────────────┤
      │                      │                        │
      │ 4. Extract &        │                        │
      │    derive signing    │                        │
      │    key               │                        │
      │                      │                        │
      │ 5. Send signing    │                        │
      │    public key        │                        │
      ├──────────────────────>│                        │
      │                      │ 4. Update DB           │
      │                      ├──────────────────────────>│
      │                      │                        │
      │                      │<──────────────────────────┘
      │<───────────────────────┘
```

**Steps:**

1. **Client requests challenge** — Server returns WebAuthn creation options with random challenge and PRF extension
2. **Client creates passkey** — Passkey generated with PRF extension using fixed seed
3. **Client extracts PRF output** — Retrieved from passkey response extensions
4. **Client derives signing key** — Deterministic HKDF-SHA256 derivation from PRF output
5. **Client sends public key** — Sends attestation and derived signing public key
6. **Server validates and stores** — Validates passkey attestation, stores keys, updates DID via PLC
7. **Key transfer** — Server signs PLC operation to make user's key the rotation key

### Commit Signing Flow

**Objective:** Sign a repo commit using passkey-derived signing key.

```
┌─────────────┐      ┌──────────────────┐      ┌──────────────────┐
│   Browser   │      │   PDS Server    │      │   Account Page  │
│  (ATProto   │      │                 │      │   (Signer)     │
│   Client)    │      │                 │      └────────┬─────────┘
└─────┬───────┘      └──────┬───────────┘               │
      │                      │                        │
      │ 1. applyWrites     │                        │
      ├──────────────────────>│                        │
      │                      │ 2. WebSocket sign request │
      │<───────────────────────┼───────────────────────>│
      │                      │                        │ 3. Request passkey
      │                      │                        │    assertion (no PRF)
      │                      │                        │
      │                      │ 4. Retrieve PRF         │
      │                      │    output from storage  │
      │                      │                        │
      │                      │<──────────────────────────┘
      │                      │
      │                      │ 5. Derive signing key
      │                      │    from stored PRF
      │                      │
      │                      │ 6. Sign commit
      │                      │
      │<───────────────────────┤
      │ 7. sign_response     │
      ├──────────────────────>│ 8. Verify assertion
      │                      │    against authPublicKey
      │                      │
      │                      │ 9. Verify commit signature
      │                      │    against signingPublicKey
      │                      │
      │                      │ 10. Persist commit
      │<───────────────────────┘
```

**Steps:**

1. **Client initiates write** — Standard ATProto client sends write request
2. **Server sends sign request** — Holds HTTP request, sends WebSocket sign request
3. **Client retrieves PRF output** — Retrieves from browser storage
4. **Client derives signing key** — Same deterministic derivation as registration
5. **Client signs commit** — Signs with derived key
6. **Client gets passkey assertion** — Passkey assertion for authentication (no PRF needed)
7. **Client sends sign response** — Sends passkey assertion and commit signature
8. **Server verifies assertion** — Verifies passkey authentication
9. **Server verifies commit signature** — Verifies commit against stored signing public key
10. **Server persists commit** — Finalizes and stores commit

### Service-Auth Flow

**Objective:** Generate JWT for background requests (feeds, notifications) without passkey.

```
┌─────────────┐      ┌──────────────────┐
│   Any Client│      │   PDS Server    │
└─────┬───────┘      └──────┬───────────┘
       │                      │
       │ getServiceAuth          │
       ├──────────────────────>│ 1. Validate session
       │                      │ 2. Look up did:key
       │                      │ 3. Sign JWT with PDS key
       │                      │ 4. Return JWT
       │<───────────────────────┘
```

**Steps:**

1. **Client requests service auth** — Standard ATProto call
2. **Server validates session** — From JWT or session cookie
3. **Server loads PDS key** — Server's private service key
4. **Server signs JWT** — Signed with PDS key
5. **Returns signed JWT** — Standard ES256 signature, no passkey required

**Note:** Service-auth JWTs are verified by checking `verificationMethods.atproto_service` (PDS key), not `verificationMethods.atproto` (passkey-derived key).

### Identity Operation Flow

**Objective:** User updates handle, email, or other PLC-managed identity data.

#### Before Passkey Registration (PDS Controlled)

```
┌─────────────┐      ┌──────────────────┐
│   Browser   │      │   PDS Server    │
│  (Request)  │      │                 │
└─────┬───────┘      └──────┬───────────┘
       │                      │
       │ requestPlcOperation          │
       ├──────────────────────>│ 1. Sign with rotation.key
       │                      │ 2. Submit to PLC
       │                      │ 3. Return signed op
       │<───────────────────────┘
```

PDS has full authority — can modify DID document freely.

#### After Passkey Registration (User Controlled)

```
┌─────────────┐      ┌──────────────────┐      ┌──────────────────┐
│   Browser   │      │   PDS Server    │      │   Account Page  │
│  (Request)  │      │                 │      │   (Signer)     │
└─────┬───────┘      └──────┬───────────┘      └──────┬──────────┘
       │                      │                        │
       │ requestPlcOperation          │                        │
       ├──────────────────────>│                        │
       │                      │ 1. Request signature    │ 2. Get passkey
       │                      │    from SignerHub       │    assertion
       │                      │<──────────────────────┼───────────────────>│
       │                      │                        │ 3. Re-derive signing
       │                      │                        │    key from PRF
       │                      │                        │
       │                      │ 4. Sign PLC operation│
       │                      │<──────────────────────┘
       │                      │ 5. Submit to PLC
       │                      │<──────────────────────────┘
       │<───────────────────────┘
```

**Steps:**

1. **Client requests operation** — Standard ATProto call
2. **Server builds PLC operation** — Constructs operation CBOR
3. **Server requests signature** — Via SignerHub WebSocket
4. **SignerHub prompts user** — Passkey assertion required
5. **Client derives signing key** — From stored PRF output
6. **Client signs PLC operation** — With derived signing key
7. **Server submits to PLC** — With user's signature
8. **Only user's key** — Is now the rotation key

## Security Properties

### Key Isolation

| Concern                          | Passkey          | PRF-Derived Signing Key     | PDS Server Key           |
| -------------------------------- | ---------------- | --------------------------- | ------------------------ |
| **Private key stored on server** | ❌ No            | ❌ No                       | ✅ Yes                   |
| **Can sign repo commits**        | ❌ No            | ✅ Yes                      | ❌ No                    |
| **Can sign PLC operations**      | ❌ No (directly) | ✅ Yes (via PRF derivation) | ✅ Yes (before transfer) |
| **Can sign service-auth JWTs**   | ❌ No            | ❌ No                       | ✅ Yes                   |
| **Requires user interaction**    | ✅ Yes           | ✅ Yes (via passkey)        | ❌ No                    |

### Threat Model Mitigation

| Threat                         | Standard PDS                       | Vow                                             |
| ------------------------------ | ---------------------------------- | ----------------------------------------------- |
| **Server repo key compromise** | Server can forge any commit        | ❌ Server never sees signing private key        |
| **Server admin abuse**         | Server can rotate keys, change DID | ❌ After key transfer, only user can modify DID |
| **Database exfiltration**      | Exposes all private keys           | ❌ Only public keys stored                      |

### Deterministic Key Derivation

Same PRF output produces the same signing key deterministically:

- **Derivation method:** HKDF-SHA256 with fixed parameters
- **PRF seed:** Fixed value for reproducibility
- **Result:** Derivation is reproducible across sessions, browsers, devices

**Why this matters:**

1. **Consistent signatures** — Same commit always produces same signature
2. **Key recovery** — Lost browser storage can be recovered by re-registering passkey with same seed
3. **Auditability** — PRF output never needs to leave device, but same key material always derivable

## Trade-offs

### Advantages

| Advantage                | Description                                                              |
| ------------------------ | ------------------------------------------------------------------------ |
| **User-controlled DID**  | After passkey registration, PDS cannot modify user's identity            |
| **Key isolation**        | Compromised database never exposes signing private keys                  |
| **Hardware security**    | Passkey private key lives in TPM/Secure Enclave, never in browser memory |
| **No extensions needed** | Works in any modern browser (WebAuthn Level 3 with PRF support)          |
| **Portable identity**    | User can migrate to new PDS by updating serviceEndpoint via PLC          |
| **Standard federation**  | Uses `did:plc` — full compatibility with ATProto ecosystem               |

### Disadvantages

| Disadvantage             | Mitigation                                              |
| ------------------------ | ------------------------------------------------------- | ------------------------------------------------------------------------- |
| **Requires browser tab** | User must keep account page open for signing            | Pin tab, use separate device                                              |
| **PRF browser support**  | Not all browsers passkeys support PRF extension         | Chrome 126+, Edge 126+, Safari 18+, Firefox 130+                          |
| **Storage dependency**   | Lost PRF output on cache clear requires re-registration | Re-register passkey (seed produces same key)                              |
| **Service-auth gap**     | Standard ATProto clients don't check `#atproto_service` | [RFC pending](https://github.com/bluesky-social/atproto/discussions/4739) |
| **Passkey loss**         | Lost passkey = lost identity (no recovery mechanism)    | This is inherent to passkeys, not Vow-specific                            |

### Compatibility Gaps

### Compat Mode

**Problem:** Standard ATProto reference implementation and AppViews verify service-auth JWTs by checking `verificationMethods.atproto` only, ignoring `verificationMethods.atproto_service`. Additionally, external AppViews (like official Bluesky) only accept ES256K (secp256k1) signed service-auth JWTs.

**Solution:** Vow provides a "compat mode" that:

1. Signs service-auth JWTs with the user's passkey-derived secp256k1 key (not the PDS P-256 key)
2. Uses ES256K algorithm with `alg: "ES256K"` and `crv: "secp256k1"` in JWT header
3. Requires browser interaction for each service-auth request (passkey assertion)

**Current Status:**

- ✅ Vow correctly sets `#atproto_service` in DID document
- ✅ Vow correctly signs service-auth JWTs with that key (non-compat mode)
- ✅ Compat mode signs with secp256k1 key that external AppViews accept
- ❌ Standard clients without compat mode reject tokens with `BadJwtSignature` until RFC is implemented.
- ✅ Vow's own account page works (reads `#atproto_service`)

**Impact:**

- ✅ Compat mode: Background feed loading, notifications work with external AppViews
- ⚠️ Compat mode UX: More frequent passkey approvals required
- ❌ Non-compat mode: External AppViews reject service-auth tokens
- ✅ Vow's built-in UI works fully regardless of mode

## Maintenance

### Key Management

#### Server Keys (Persistent)

| Key            | Location              | Rotation Policy              | Backup Required |
| -------------- | --------------------- | ---------------------------- | --------------- |
| `rotation.key` | `./keys/rotation.key` | Never (used for DID genesis) | ✅ Yes          |
| `jwk.key`      | `./keys/jwk.key`      | Never                        | ✅ Yes          |

**Best Practices:**

- Store `./keys/` backups in secure, off-site location
- `rotation.key` compromise = complete DID takeover (all accounts before key transfer)
- `jwk.key` compromise = session hijacking (cannot forge commits, but can issue JWTs)
- Use strong permissions on `./keys/` directory

#### User Keys (Transient)

| Key                     | Storage                       | Derivation                     | Lifetime |
| ----------------------- | ----------------------------- | ------------------------------ | -------- |
| Passkey private key     | Hardware (TPM/Secure Enclave) | Permanent (until deregistered) |
| PRF output              | Browser storage               | Until browser data cleared     |
| PRF-derived signing key | Derived on-the-fly            | Ephemeral (per-session)        |

**Recovery:**

- **Lost passkey:** No recovery — identity lost (passkey limitation)
- **Lost PRF output:** Re-register same passkey → same signing key (deterministic)

### Database Maintenance

#### Schema

The `repos` table structure is stable:

- `auth_public_key` — Passkey P-256 public key
- `signing_public_key` — PRF-derived secp256k1 signing key
- `credential_id` — WebAuthn credential ID

**Upgrade path:**

- Stop services
- Delete old database
- Restart services
- ⚠️ This deletes all user data — backup first!

#### Index Maintenance

Automatic indexing:

- Records indexed by `did`, `nsid`, `rkey`
- Blobs indexed by `did`, `cid` (reference counting)
- Session indexed by `token`, `did`

No manual index maintenance required.

### PLC Operations

#### Key Transfer Operation

When user registers an existing passkey:

1. PDS builds PLC operation with user's signing key
2. Operation is signed by:
   - **First registration:** PDS rotation key (still has authority)
   - **Key rotation:** User's passkey-derived signing key (new rotation key)
3. Submit to PLC directory

**Audit trail:**

- PLC audit log shows clear transfer
- `rotationKeys` changes from PDS key to user key
- Timestamp proves when user took control

#### Future Identity Updates

After key transfer, user can:

1. **Update handle** — Requires passkey signature
2. **Update email** — Requires email confirmation link (no passkey)
3. **Deactivate account** — Requires passkey signature

All identity changes require passkey authentication after transfer.

### Disaster Recovery

#### Scenario: Complete Server Loss

1. **PDS rotation key compromised:**
   - Attackers can create new accounts, transfer control before user registers passkey
   - Detection: Multiple new registrations with different emails
   - Recovery: Generate new `rotation.key` (invalidates old key)

2. **Database exfiltration:**
   - Attackers get public keys only
   - **Cannot sign commits** (no private signing key)
   - Impact: Read-only access to past commits
   - Recovery: Revoke passkeys, rotate PDS keys

3. **IPFS data loss:**
   - Users lose repos and blobs
   - Recovery: Users re-sync from relays

#### Scenario: User Loss Recovery

1. **Lost passkey (after DID transfer):**
   - ❌ No recovery possible
   - Mitigation: Register multiple passkeys on different devices before loss

2. **Accidentally deleted browser storage (PRF output):**
   - ✅ Re-register same passkey
   - ✅ Deterministic derivation produces same signing key
   - ✅ Identity remains intact

## WebSocket Protocol Specification

### Connection

**Endpoint:** `wss://<hostname>/account/signer`

**Authentication:** Session cookie or Bearer token

### Message Types

#### sign_request (Server → Client)

```json
{
  "type": "sign_request",
  "requestId": "uuid-v4",
  "did": "did:plc:abc123...",
  "payload": "base64url-encoded unsigned commit CBOR",
  "ops": [
    {
      "type": "create|update|delete",
      "collection": "app.bsky.feed.post|app.bsky.graph.follows|...",
      "rkey": "record key (for updates)"
    }
  ],
  "expiresAt": "ISO-8601 timestamp"
}
```

**Fields:**

- `requestId`: Unique identifier for this request
- `did`: User's DID
- `payload`: CBOR bytes of unsigned commit
- `ops`: Array of operations (for UI display)
- `expiresAt`: When request becomes invalid

#### sign_response (Client → Server)

```json
{
  "type": "sign_response",
  "requestId": "uuid-v4",
  "authenticatorData": "base64url authenticatorData bytes",
  "clientDataJSON": "base64url clientDataJSON bytes",
  "signature": "base64url DER-encoded ECDSA signature",
  "commitSignature": "base64url 64-byte raw r||s signature"
}
```

**Fields:**

- `requestId`: Must match original request
- `authenticatorData`: WebAuthn authenticator data
- `clientDataJSON`: WebAuthn client data JSON
- `signature`: DER-encoded ECDSA signature from passkey
- `commitSignature`: Raw signature from PRF-derived signing key

#### sign_reject (Client → Server)

```json
{
  "type": "sign_reject",
  "requestId": "uuid-v4"
}
```

**Used when:**

- User cancelled passkey prompt
- Passkey not found
- Request expired
- Technical error

### Connection Lifecycle

1. **Handshake**
   - HTTP GET → WebSocket upgrade
   - Server verifies session/bearer token
   - Connection accepted or rejected

2. **Keepalive**
   - Server sends `ping` messages
   - Client responds with `pong`
   - Missing `pong` → connection terminated

3. **Reconnection**
   - Exponential backoff
   - Automatic on page visible, tab focus
   - Manual: User clicks "Connect" button

4. **Single connection per DID**
   - New connection immediately closes old connection
   - "Replacing existing connection" logged

## Error Handling

### Client-Side Errors

| Error                                | Cause                               | User Action                                          |
| ------------------------------------ | ----------------------------------- | ---------------------------------------------------- |
| `PRF extension output not available` | Browser/passkey doesn't support PRF | Use Chrome 126+, Edge 126+, Safari 18+, Firefox 130+ |
| `PRF output not found`               | Browser storage cleared             | Re-register passkey (same key)                       |
| `Passkey creation was cancelled`     | User dismissed prompt               | Try again                                            |
| `Passkey assertion was cancelled`    | User dismissed prompt               | Try again                                            |

### Server-Side Errors

| Error                                    | HTTP Status | Cause                                   |
| ---------------------------------------- | ----------- | --------------------------------------- |
| `no public key registered for account`   | 400         | No signing key in DB (register passkey) |
| `assertion verification failed`          | 401         | Invalid passkey signature               |
| `signature verification failed`          | 400         | Derived key mismatch (BUG)              |
| `challenge mismatch`                     | 400         | Tampered request                        |
| `rpIdHash mismatch`                      | 400         | Wrong origin/domain                     |
| `no extension data in authenticatorData` | 400         | PRF not supported                       |
| `failed to parse attestation object`     | 400         | Invalid WebAuthn response               |

## Appendix

### References

- [WebAuthn Level 3 Specification](https://www.w3.org/TR/webauthn-3/)
- [WebAuthn PRF Extension](https://w3cg.github.io/webauthn/sctn-prf-extension/)
- [ATProto DID Spec](https://github.com/bluesky-social/atproto/blob/main/identifiers/did-plc.md)
- [Service-Auth RFC Discussion](https://github.com/bluesky-social/atproto/discussions/4739)
