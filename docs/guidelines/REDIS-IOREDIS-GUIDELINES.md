# Redis & ioredis Guidelines — @bymax-one/nest-auth

> **Audience:** AI agents and developers working on this codebase.
> **Stack:** ioredis ^6.x, Redis 7+, NestJS 11
> **Rule:** Follow these guidelines for all Redis operations in this project.

---

## Table of Contents

1. [Connection and Injection Pattern](#1-connection-and-injection-pattern)
2. [Key Naming Conventions](#2-key-naming-conventions)
3. [JWT Blacklisting](#3-jwt-blacklisting)
4. [Refresh Token Storage](#4-refresh-token-storage)
5. [Brute-Force Protection](#5-brute-force-protection)
6. [Session Management](#6-session-management)
7. [OTP Storage](#7-otp-storage)
8. [Pipeline and Transaction Patterns](#8-pipeline-and-transaction-patterns)
9. [Error Handling and Resilience](#9-error-handling-and-resilience)
10. [Anti-Patterns](#10-anti-patterns)
11. [Quick Reference Checklist](#quick-reference-checklist)

---

## 1. Connection and Injection Pattern

### 1.1 Principle: The Library Never Creates a Redis Connection

`@bymax-one/nest-auth` is a library consumed by host applications. It **never** instantiates its own Redis connection. The host application owns the Redis lifecycle — creating, configuring, and destroying the connection. The library receives a fully initialized `Redis` instance through NestJS dependency injection.

### 1.2 The Injection Token

The library defines a Symbol-based injection token:

```typescript
export const BYMAX_AUTH_REDIS_CLIENT = Symbol('BYMAX_AUTH_REDIS_CLIENT')
```

This Symbol guarantees zero collision with any other providers in the host application's DI container.

### 1.3 How the Host Application Provides Redis

The host application registers the Redis client when calling `BymaxAuthModule.registerAsync()`:

```typescript
import { BYMAX_AUTH_REDIS_CLIENT } from '@bymax-one/nest-auth'
import { RedisService } from './redis/redis.service' // Host's own Redis wrapper

@Module({
  imports: [
    BymaxAuthModule.registerAsync({
      imports: [ConfigModule, RedisModule],
      useFactory: (config: ConfigService, redisService: RedisService) => ({
        // ... other options
      }),
      inject: [ConfigService],
      extraProviders: [
        {
          provide: BYMAX_AUTH_REDIS_CLIENT,
          useFactory: (redisService: RedisService) => redisService.getClient(),
          inject: [RedisService]
        }
      ]
    })
  ]
})
export class AppModule {}
```

### 1.4 How Services Consume the Redis Client

Within the library, services inject the client via the Symbol token:

```typescript
import { Inject, Injectable } from '@nestjs/common'
import { Redis } from 'ioredis'
import { BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'

@Injectable()
export class AuthRedisService {
  constructor(@Inject(BYMAX_AUTH_REDIS_CLIENT) private readonly redis: Redis) {}

  // All Redis operations go through this.redis
}
```

### 1.5 Rules for Library Code

| Rule                                                                  | Rationale                                |
| --------------------------------------------------------------------- | ---------------------------------------- |
| Never call `new Redis(...)` or `new Cluster(...)` inside library code | Connection lifecycle belongs to the host |
| Never call `redis.quit()` or `redis.disconnect()` inside library code | The host manages shutdown                |
| Never modify connection settings (e.g., `redis.options`)              | Respect the host's configuration         |
| Always type the injected client as `Redis` from `ioredis`             | Ensures full type safety with ioredis ^6 |
| Never store the Redis client in a static/global variable              | Breaks testability and DI isolation      |

### 1.6 Testing with the Injection Token

In unit tests, provide a mock Redis instance through the same token:

```typescript
import { Test } from '@nestjs/testing'
import { BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'

const mockRedis = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  incr: jest.fn(),
  expire: jest.fn(),
  sadd: jest.fn(),
  srem: jest.fn(),
  smembers: jest.fn(),
  sismember: jest.fn(),
  eval: jest.fn(),
  pipeline: jest.fn().mockReturnValue({
    exec: jest.fn().mockResolvedValue([])
  })
}

const module = await Test.createTestingModule({
  providers: [AuthRedisService, { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedis }]
}).compile()
```

---

## 2. Key Naming Conventions

### 2.1 Namespace Pattern

Every Redis key in this library follows a strict three-part format:

```
{namespace}:{prefix}:{identifier}
```

- **`{namespace}`** is the value of the `redisNamespace` configuration option (default: `auth`). This prevents collisions with keys from other parts of the host application or other libraries that share the same Redis instance.
- **`{prefix}`** is a short, fixed abbreviation identifying the entity type (e.g. `rt` for the refresh token, `rv` for the access-token blacklist).
- **`{identifier}`** is always a hash of the sensitive value, never the raw value: SHA-256 for opaque tokens (`rt`, `mfa`, `pw_reset`, `inv`, `os`, `ec`, `wst`...) and HMAC-SHA-256 keyed by `options.hmacKey` (derived from `identifierKey ?? jwt.secret`) for anything that names an account, an email or an IP (`sess`, `ep`, `lf`, `otp`, `tu`, `rl`...). Raw tokens and emails never appear in key names. `rv` uses the token's `jti`, which is a random UUID and not sensitive data.

### 2.2 Why SHA-256 in Key Names

All identifiers that derive from sensitive data (tokens, emails, user-scoped lookups) are hashed with SHA-256 before being used as Redis keys. This ensures:

- **No token leakage:** If an attacker gains read access to Redis (via MONITOR, RDB dump, or a misconfigured ACL), they cannot extract raw tokens from key names.
- **Fixed-length keys:** SHA-256 produces a consistent 64-character hex string regardless of input length, keeping key sizes predictable.
- **Deterministic lookups:** The same input always produces the same hash, so lookups remain O(1).

```typescript
import { createHash } from 'node:crypto'

function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex')
}

// Key construction examples:
const refreshKey = `${namespace}:rt:${sha256(refreshToken)}`
const bruteForceKey = `${namespace}:lf:${hmacSha256(`dashboard:${tenantId}:${email}`, hmacKey)}`
```

### 2.3 Complete Key Reference Table

| Prefix      | Key Pattern                                                                                       | Value                                                                                                       | TTL                                             | Purpose                                                                                                                |
| ----------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `rt`        | `auth:rt:{sha256(token)}`                                                                         | JSON: `{ userId, tenantId, role, device, ip, createdAt, familyId, familyCreatedAt, mfaEnabled }`            | `refreshExpiresInDays` (converted to seconds)   | Refresh token session data                                                                                             |
| `rp`        | `auth:rp:{sha256(oldToken)}`                                                                      | `{sha256(newToken)}:{session JSON}`                                                                         | `refreshGraceWindowSeconds` (default: 30s)      | Rotation pointer (grace window)                                                                                        |
| `fam`       | `auth:fam:{familyId}`                                                                             | SET of the family's live `sha256(token)` values                                                             | Refresh TTL                                     | Refresh family (revocation on reuse); `pfam` for the platform                                                          |
| `cf`        | `auth:cf:{sha256(oldToken)}`                                                                      | `familyId`                                                                                                  | Refresh TTL                                     | Consumed-token marker (detects reuse after the grace window); `pcf` for the platform                                   |
| `rv`        | `auth:rv:{jti}`                                                                                   | `'1'`                                                                                                       | Remaining JWT TTL                               | Access token blacklist (revocation)                                                                                    |
| `ep`        | `auth:ep:{hmac_sha256(hmacKey, userSubject)}`                                                     | Integer (user epoch, `INCR`)                                                                                | 30 days, renewed on each increment              | Token epoch: bulk-invalidates access tokens issued earlier (password change/reset, revoke-all); `pep` for the platform |
| `ra`        | `auth:ra:{hmac_sha256(hmacKey, userSubject)}`                                                     | `'1'`                                                                                                       | 300s                                            | Recent re-authentication marker                                                                                        |
| `us`        | `auth:us:{tenantId}:{userId}` (each part passed through `encodeURIComponent`)                     | Status string (e.g. `'ACTIVE'`, `'BANNED'`)                                                                 | `userStatusCacheTtlSeconds` (default: 60s)      | User status cache                                                                                                      |
| `uev`       | `auth:uev:{tenantId}:{userId}` (same scope as `us`)                                               | Verified-email flag                                                                                         | Same TTL as the status cache                    | Verified-email cache                                                                                                   |
| `lf`        | `auth:lf:{hmac_sha256(hmacKey, "dashboard:{tenantId}:{email}")}` (platform: `"platform:{email}"`) | Numeric counter (string)                                                                                    | `windowSeconds` (default: 900s)                 | Login failure counter (brute-force)                                                                                    |
| `pw_reset`  | `auth:pw_reset:{sha256(token)}`                                                                   | JSON: `{ userId, email, tenantId, passwordFingerprint }`                                                    | `passwordReset.tokenTtlSeconds` (default: 600s) | Password reset token                                                                                                   |
| `pw_vtok`   | `auth:pw_vtok:{sha256(token)}`                                                                    | JSON: `{ userId, email, tenantId, passwordFingerprint }`                                                    | 300s                                            | Password reset OTP verification token                                                                                  |
| `otp`       | `auth:otp:{purpose}:{hmac_sha256(hmacKey, "{tenantId}:{email}")}`                                 | HASH: fields `code` (fingerprint HMAC) and `attempts`                                                       | `otpTtlSeconds` (varies by purpose)             | OTP codes with attempt counting                                                                                        |
| `resend`    | `auth:resend:{purpose}:{hmac_sha256(hmacKey, "{tenantId}:{email}")}`                              | `'1'`                                                                                                       | 60s                                             | OTP resend cooldown                                                                                                    |
| `mfa`       | `auth:mfa:{sha256(jti)}` (jti of the MFA temp token)                                              | `userId` (string)                                                                                           | 300s (5 minutes)                                | MFA temp token (single use)                                                                                            |
| `mfa_setup` | `auth:mfa_setup:{hmac_sha256(hmacKey, userSubject)}`                                              | JSON: `{ encryptedSecret, hashedCodes }`                                                                    | 600s (10 minutes)                               | Temporary MFA setup data                                                                                               |
| `mfalock`   | `auth:mfalock:{hmac_sha256(hmacKey, userSubject)}`                                                | Nonce of the call that took the lock                                                                        | 10s                                             | Lock that serializes MFA state transitions                                                                             |
| `rcu`       | `auth:rcu:{hmac_sha256(hmacKey, "{userSubject}:{code}")}`                                         | Marker (`SET NX`)                                                                                           | 300s                                            | Single-use claim of the recovery code                                                                                  |
| `tu`        | `auth:tu:{hmac_sha256(hmacKey, "{userSubject}:{code}")}`                                          | `'1'`                                                                                                       | `(2 x window + 1) x 30s` (90s with window 1)    | TOTP replay prevention                                                                                                 |
| `sess`      | `auth:sess:{hmac_sha256(hmacKey, "dashboard:{utf8ByteLength(tenantId)}:{tenantId}:{userId}")}`    | SET of `rt:{hash}` and `rp:{hash}` members                                                                  | Refresh TTL                                     | Per-user index of active sessions                                                                                      |
| `sd`        | `auth:sd:{sessionHash}`                                                                           | JSON: `{ device, ip, createdAt, lastActivityAt }`                                                           | Refresh TTL                                     | Session metadata                                                                                                       |
| `inv`       | `auth:inv:{sha256(token)}`                                                                        | JSON: `{ email, role, tenantId, inviterUserId, createdAt }`                                                 | `invitations.tokenTtlSeconds` (default: 48h)    | Pending invitations                                                                                                    |
| `invidx`    | `auth:invidx:{tenantId}:{hmac_sha256(hmacKey, email)}`                                            | `sha256(token)` of the pending invitation                                                                   | `invitations.tokenTtlSeconds`                   | Invitee index: one pending invitation per address                                                                      |
| `os`        | `auth:os:{sha256(state)}`                                                                         | JSON: `{ provider, tenantId, codeVerifier }`                                                                | 600s (10 minutes)                               | OAuth CSRF state (with the PKCE verifier)                                                                              |
| `ec`        | `auth:ec:{sha256(token)}`                                                                         | JSON: `{ userId, newEmail, tenantId, passwordFingerprint }`                                                 | `emailChange.tokenTtlSeconds` (default: 3600s)  | Email change token                                                                                                     |
| `wst`       | `auth:wst:{sha256(ticket)}`                                                                       | JSON: identity snapshot (`sub`, `tenantId?`, `role`, `status`, `mfaEnabled`, `mfaVerified`, `jti`, `epoch`) | 30s                                             | Single-use ticket for the WebSocket upgrade                                                                            |
| `rl`        | `auth:rl:{Class.handler}:{hmac_sha256(hmacKey, IP bucket)}`                                       | Numeric counter                                                                                             | Route window (fixed TTL)                        | Per-route, per-IP rate limit                                                                                           |
| `prt`       | `auth:prt:{sha256(token)}`                                                                        | Same record as `rt`, with an empty `tenantId`                                                               | `refreshExpiresInDays` (converted to seconds)   | Platform admin refresh token                                                                                           |
| `prp`       | `auth:prp:{sha256(oldToken)}`                                                                     | `{sha256(newToken)}:{session JSON}`                                                                         | `refreshGraceWindowSeconds` (default: 30s)      | Platform rotation pointer                                                                                              |
| `psess`     | `auth:psess:{hmac_sha256(hmacKey, "platform:{userId}")}`                                          | SET of `prt:{hash}` and `prp:{hash}` members                                                                | Refresh TTL                                     | Platform admin session index                                                                                           |
| `psd`       | `auth:psd:{sessionHash}`                                                                          | JSON: `{ device, ip, createdAt, lastActivityAt }`                                                           | Refresh TTL                                     | Platform session metadata                                                                                              |

`userSubject` is `dashboard:{utf8ByteLength(tenantId)}:{tenantId}:{userId}` on the dashboard plane and `platform:{userId}` on the platform plane (`src/server/constants/user-subject.ts`). The length prefix keeps the key injective even when the `tenantId` contains `:`.

### 2.4 Key Expiration Strategy

Every key in this library **must** have a TTL. There are no persistent keys. This is enforced by design:

- **SET operations** always include `EX` (seconds) or `PX` (milliseconds) arguments.
- **INCR-based counters** (brute-force) are paired with `EXPIRE` to ensure cleanup.
- **Redis SETs** (`sess`, `psess`) inherit the TTL of the longest-lived member (max refresh token TTL).

The zero-orphan policy means that even if application logic fails to clean up a key (e.g., a crash during logout), Redis will automatically evict it when the TTL expires.

### 2.5 Building Keys in Code

Centralize key construction in the `AuthRedisService` to prevent typos and ensure consistency:

```typescript
@Injectable()
export class AuthRedisService {
  private readonly ns: string

  constructor(
    @Inject(BYMAX_AUTH_REDIS_CLIENT) private readonly redis: Redis,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {
    this.ns = options.redisNamespace ?? 'auth'
  }

  private key(prefix: string, id: string): string {
    return `${this.ns}:${prefix}:${id}`
  }

  // Usage:
  // this.key('rt', sha256(refreshToken))  => "auth:rt:a1b2c3..."
  // this.key('rv', jti)                   => "auth:rv:some-jti-uuid"
}
```

---

## 3. JWT Blacklisting

### 3.1 Why Blacklisting Is Needed

JWTs are stateless — once issued, they remain valid until expiration. When a user logs out, changes their password, or has their account suspended, the access token must be invalidated before its natural expiry. Redis provides a fast, centralized blacklist.

### 3.2 Blacklist Key Structure

```
Key:   auth:rv:{jti}
Value: '1'
TTL:   Remaining seconds until the JWT's exp claim
```

- **The `jti` is mandatory.** The `jti` claim (JWT ID) is a UUID included in the token payload and is the entry's key. A token without a valid `jti` is rejected with `TOKEN_INVALID` before the lookup; there is no `sha256(jwt)` fallback.

### 3.3 Setting the Blacklist Entry

```typescript
async blacklistAccessToken(jwt: string, payload: JwtPayload): Promise<void> {
  const key = payload.jti
    ? this.key("rv", payload.jti)
    : this.key("rv", sha256(jwt));

  // Calculate remaining TTL from the exp claim
  const now = Math.floor(Date.now() / 1000);
  const remainingSeconds = payload.exp - now;

  if (remainingSeconds <= 0) {
    // Token already expired — no need to blacklist
    return;
  }

  await this.redis.set(key, "1", "EX", remainingSeconds);
}
```

### 3.4 Checking the Blacklist on Every Request

The `JwtAuthGuard` checks the blacklist after verifying the JWT signature and before granting access:

```typescript
async canActivate(context: ExecutionContext): Promise<boolean> {
  // ... extract and verify JWT ...

  // Check blacklist
  const blacklistKey = payload.jti
    ? this.key("rv", payload.jti)
    : this.key("rv", sha256(rawJwt));

  const isRevoked = await this.redis.exists(blacklistKey);
  if (isRevoked) {
    // TOKEN_REVOKED is internal-only — never throw it. A caller must not be able to tell
    // "valid until revoked" from "never a token", so the blacklist hit answers TOKEN_INVALID
    // like every other token failure.
    throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID);
  }

  // ... continue with request ...
}
```

### 3.5 Blacklisting Rules

| Rule                                                                        | Detail                                                                                  |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| TTL must equal the remaining token lifetime                                 | Never use a fixed TTL — it wastes memory if too long, or misses the window if too short |
| Skip blacklisting if `exp` has passed                                       | Saves a write for already-expired tokens                                                |
| Use `EXISTS` not `GET` for checking                                         | `EXISTS` returns 0 or 1 and avoids transferring the value                               |
| Do not use `SETNX`                                                          | Blacklisting the same token twice is idempotent and harmless                            |
| Blacklist on logout, password change, account suspension, forced revocation | Cover all invalidation scenarios                                                        |

### 3.6 Bulk Revocation

When all sessions for a user must be invalidated (e.g., password change, account compromise), the library does not blacklist every access token individually. Instead:

1. All refresh sessions are deleted (atomic sweep of the `sess:` index).
2. The user epoch (`ep:`/`pep:`) is advanced: every access token issued earlier is rejected immediately, without listing `jti`.
3. To revoke one specific access token, its `jti` goes to the blacklist (`rv:`).

This approach is intentional: blacklisting every possible access token for a user would require tracking all issued `jti` values, adding complexity with marginal benefit given the short access token TTL.

---

## 4. Refresh Token Storage

### 4.1 Refresh Token Design

Refresh tokens in this library are **opaque random tokens** (not JWTs): 32 random bytes encoded as 64 hex characters. They are stored in Redis with session metadata, enabling stateful session management without database queries.

```
Token format:  64 hex characters from 32 random bytes (generateSecureToken)
Storage key:   auth:rt:{sha256(token)}
Storage value: JSON string with session data
TTL:           refreshExpiresInDays converted to seconds
```

### 4.2 Session Data Structure

```typescript
interface RefreshSessionData {
  userId: string
  tenantId: string
  role: string
  device: string // User-Agent or device identifier
  ip: string // Client IP address
  createdAt: string // ISO 8601 timestamp
}
```

This data is stored as a JSON string value. It contains everything needed to reissue an access token without hitting the database, improving refresh latency.

### 4.3 Storing a Refresh Token

```typescript
async storeRefreshToken(
  refreshToken: string,
  sessionData: RefreshSessionData,
  ttlSeconds: number,
): Promise<void> {
  const key = this.key("rt", sha256(refreshToken));
  await this.redis.set(key, JSON.stringify(sessionData), "EX", ttlSeconds);
}
```

### 4.4 Token Rotation with Atomic Lua Script

When a client uses a refresh token to get new tokens, the old token must be invalidated and a new one issued. This is a **critical section** — without atomicity, two concurrent requests with the same refresh token could both succeed, creating duplicate sessions.

The library uses a Lua script to perform the rotation atomically:

```lua
-- Atomic refresh token rotation script
-- Executes as a single Redis operation, preventing race conditions
local old_key = KEYS[1]              -- auth:rt:{sha256(old)}
local new_key = KEYS[2]              -- auth:rt:{sha256(new)}
local pointer_key = KEYS[3]          -- auth:rp:{sha256(old)}
local new_session_data = ARGV[1]     -- JSON for the new session
local new_raw_token = ARGV[2]        -- New token raw value (for the pointer)
local refresh_ttl = tonumber(ARGV[3])  -- TTL in seconds
local grace_ttl = tonumber(ARGV[4])  -- refreshGraceWindowSeconds

-- Step 1: Attempt to fetch and atomically delete the old session
local session_data = redis.call('GET', old_key)
if session_data then
  redis.call('DEL', old_key)
  -- Step 2: Create rotation pointer (grace window)
  redis.call('SET', pointer_key, new_raw_token, 'EX', grace_ttl)
  -- Step 3: Create new session
  redis.call('SET', new_key, new_session_data, 'EX', refresh_ttl)
  return session_data
end

-- Step 4: If old token not found, check grace window (concurrent request)
local pointed_token = redis.call('GET', pointer_key)
if pointed_token then
  return 'GRACE:' .. pointed_token  -- Return the token from the grace window
end

-- Step 5: Token invalid or expired
return nil
```

### 4.5 Grace Window for Concurrent Requests

The rotation pointer (`rp` prefix) solves a real-world problem: when a browser has multiple tabs or a mobile app makes concurrent API calls, two requests may arrive with the same refresh token before either has completed the rotation.

The grace window works as follows:

1. **First request** rotates the token normally. The old token is deleted, a new one is created, and a pointer from old to new is stored with a short TTL (default: 30 seconds).
2. **Second request** (within the grace window) finds the old token missing, checks the rotation pointer, discovers the new token, and returns a `GRACE:` response. The service then responds with the already-issued new tokens instead of failing.
3. **After the grace window expires**, any attempt to use the old token fails with `TOKEN_EXPIRED`.

### 4.6 Calling the Lua Script from ioredis

```typescript
async rotateRefreshToken(
  oldToken: string,
  newToken: string,
  sessionData: RefreshSessionData,
  refreshTtlSeconds: number,
  graceWindowSeconds: number,
): Promise<{ sessionData: RefreshSessionData } | { graceToken: string } | null> {
  const result = await this.redis.eval(
    ROTATE_REFRESH_TOKEN_SCRIPT,
    3,  // number of KEYS
    this.key("rt", sha256(oldToken)),
    this.key("rt", sha256(newToken)),
    this.key("rp", sha256(oldToken)),
    JSON.stringify(sessionData),
    newToken,
    refreshTtlSeconds.toString(),
    graceWindowSeconds.toString(),
  ) as string | null;

  if (result === null) return null;
  if (result.startsWith("GRACE:")) {
    return { graceToken: result.slice(6) };
  }
  return { sessionData: JSON.parse(result) };
}
```

### 4.7 Platform Admin Refresh Tokens

Platform admin tokens follow the same pattern but use distinct prefixes (`prt`, `prp`) to maintain complete namespace isolation between tenant users and platform administrators:

| Tenant User      | Platform Admin    |
| ---------------- | ----------------- |
| `auth:rt:{hash}` | `auth:prt:{hash}` |
| `auth:rp:{hash}` | `auth:prp:{hash}` |

The Lua script is reused; only the key prefixes change.

---

## 5. Brute-Force Protection

### 5.1 Design Overview

Brute-force protection uses Redis atomic counters to track failed login attempts per tenant-scoped email address. When the counter exceeds `maxAttempts`, login is blocked until the TTL window expires.

### 5.2 Key Structure

```
Key:   auth:lf:{hmac_sha256(hmacKey, "dashboard:{tenantId}:{email}")}
Value: Numeric counter (stored as string by Redis)
TTL:   windowSeconds (default: 900s = 15 minutes)
```

The key is scoped by `tenantId + ":" + email` so that a lockout on tenant A does not affect the same email on tenant B (multi-tenant isolation).

### 5.3 Recording a Failed Attempt

The `INCR` command is atomic and returns the new counter value. Combined with `EXPIRE`, it creates a sliding window:

```typescript
async recordFailure(identifier: string): Promise<number> {
  const key = this.key("lf", sha256(identifier));

  // INCR creates the key with value 1 if it does not exist
  const attempts = await this.redis.incr(key);

  // Set TTL only on the first failure (when INCR returns 1)
  // This prevents resetting the window on subsequent failures
  if (attempts === 1) {
    await this.redis.expire(key, this.options.bruteForce.windowSeconds);
  }

  return attempts;
}
```

### 5.4 Why `INCR` + Conditional `EXPIRE`, Not `SET` with `EX`

Using `SET counter (current+1) EX 900` on every failure would reset the TTL window each time, giving the attacker unlimited attempts as long as they space them within 15 minutes. The correct approach is:

1. `INCR` increments the counter without touching the TTL.
2. `EXPIRE` is set only on the first failure (`attempts === 1`), starting the window.
3. Subsequent failures increment the counter but the window continues counting down.

### 5.5 Checking If Locked Out

```typescript
async isLockedOut(identifier: string): Promise<boolean> {
  const key = this.key("lf", sha256(identifier));
  const attempts = await this.redis.get(key);
  return attempts !== null && parseInt(attempts, 10) >= this.options.bruteForce.maxAttempts;
}
```

### 5.6 Resetting on Successful Login

After a successful login, the counter is deleted so the user starts fresh:

```typescript
async resetFailures(identifier: string): Promise<void> {
  const key = this.key("lf", sha256(identifier));
  await this.redis.del(key);
}
```

### 5.7 Atomic Alternative with Pipeline

For checking and recording in a single round-trip:

```typescript
async checkAndRecordFailure(identifier: string): Promise<{
  isLocked: boolean;
  attempts: number;
}> {
  const key = this.key("lf", sha256(identifier));
  const pipeline = this.redis.pipeline();
  pipeline.incr(key);
  pipeline.ttl(key);

  const results = await pipeline.exec();
  // results[0] = [null, attempts], results[1] = [null, ttl]
  const attempts = results![0]![1] as number;
  const ttl = results![1]![1] as number;

  // If TTL is -1 (no expiry set), set it now
  if (ttl === -1) {
    await this.redis.expire(key, this.options.bruteForce.windowSeconds);
  }

  return {
    isLocked: attempts >= this.options.bruteForce.maxAttempts,
    attempts,
  };
}
```

### 5.8 MFA Brute-Force Protection

MFA verification has its own brute-force counters, one per flow, keyed by `hmac_sha256(hmacKey, "{flow}:{userSubject}")`, so a pre-auth attacker cannot exhaust the budget of the authenticated user's other flows. A wrong code does not revoke the `mfaTempToken`: the user can retry under it until the flow's counter reaches `bruteForce.maxAttempts`, after which the flow answers `ACCOUNT_LOCKED`.

---

## 6. Session Management

### 6.1 Architecture

Session management is opt-in (`sessions.enabled: true`). When enabled, the library tracks active sessions per user using Redis Sets, with per-session metadata stored in separate keys.

The data model uses two complementary structures:

- **A Redis SET** (`auth:sess:{hmac_sha256(hmacKey, "dashboard:{utf8ByteLength(tenantId)}:{tenantId}:{userId}")}`) whose members are `rt:{hash}` (live sessions) and `rp:{hash}` (grace pointers).
- **Individual keys** (`auth:sd:{sessionHash}`) containing JSON metadata for each session.

### 6.2 Creating a Session

```typescript
async createSession(
  userId: string,
  refreshToken: string,
  metadata: SessionMetadata,
  ttlSeconds: number,
): Promise<void> {
  const sessionHash = sha256(refreshToken);
  const sessionKey = this.key("sd", sessionHash);
  const sessionsSetKey = this.key("sess", userId);

  const pipeline = this.redis.pipeline();

  // Store session details
  pipeline.set(
    sessionKey,
    JSON.stringify({
      device: metadata.device,
      ip: metadata.ip,
      createdAt: new Date().toISOString(),
      lastActivityAt: new Date().toISOString(),
    }),
    "EX",
    ttlSeconds,
  );

  // Add to user's session set
  pipeline.sadd(sessionsSetKey, sessionHash);
  pipeline.expire(sessionsSetKey, ttlSeconds);

  await pipeline.exec();
}
```

### 6.3 Listing Active Sessions

```typescript
async listSessions(userId: string): Promise<SessionInfo[]> {
  const sessionsSetKey = this.key("sess", userId);
  const sessionHashes = await this.redis.smembers(sessionsSetKey);

  if (sessionHashes.length === 0) return [];

  // Fetch all session details in a single pipeline
  const pipeline = this.redis.pipeline();
  for (const hash of sessionHashes) {
    pipeline.get(this.key("sd", hash));
  }
  const results = await pipeline.exec();

  const sessions: SessionInfo[] = [];
  for (let i = 0; i < sessionHashes.length; i++) {
    const data = results![i]![1] as string | null;
    if (data) {
      sessions.push({
        sessionHash: sessionHashes[i],
        ...JSON.parse(data),
      });
    }
  }

  return sessions;
}
```

### 6.4 FIFO Eviction When Max Sessions Exceeded

When a new session is created and the user has reached their session limit, the oldest session is evicted using a FIFO (First In, First Out) strategy:

```typescript
async enforceSessionLimit(userId: string, user: AuthUser | null): Promise<void> {
  const maxSessions = this.options.sessions.maxSessionsResolver && user
    ? await this.options.sessions.maxSessionsResolver(user)
    : this.options.sessions.defaultMaxSessions ?? 5;

  const sessionsSetKey = this.key("sess", userId);
  const sessionHashes = await this.redis.smembers(sessionsSetKey);

  if (sessionHashes.length <= maxSessions) return;

  // Fetch createdAt for all sessions to determine the oldest
  const pipeline = this.redis.pipeline();
  for (const hash of sessionHashes) {
    pipeline.get(this.key("sd", hash));
  }
  const results = await pipeline.exec();

  // Sort by createdAt ascending (oldest first)
  const sessionsWithAge = sessionHashes
    .map((hash, i) => {
      const data = results![i]![1] as string | null;
      return { hash, createdAt: data ? JSON.parse(data).createdAt : "0" };
    })
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));

  // Evict oldest sessions to bring count within limit
  const toEvict = sessionsWithAge.slice(0, sessionHashes.length - maxSessions);

  const evictPipeline = this.redis.pipeline();
  for (const session of toEvict) {
    evictPipeline.del(this.key("rt", session.hash));  // Remove refresh token
    evictPipeline.del(this.key("sd", session.hash));  // Remove session details
    evictPipeline.srem(sessionsSetKey, session.hash);  // Remove from set
  }
  await evictPipeline.exec();
}
```

### 6.5 Revoking a Single Session

Authorization check: verify the session belongs to the requesting user before revoking:

```typescript
async revokeSession(userId: string, sessionHash: string): Promise<void> {
  const sessionsSetKey = this.key("sess", userId);

  // SISMEMBER prevents BOLA/IDOR — user can only revoke their own sessions
  const belongs = await this.redis.sismember(sessionsSetKey, sessionHash);
  if (!belongs) {
    throw new AuthException(AUTH_ERROR_CODES.SESSION_NOT_FOUND);
  }

  const pipeline = this.redis.pipeline();
  pipeline.del(this.key("rt", sessionHash));
  pipeline.del(this.key("sd", sessionHash));
  pipeline.srem(sessionsSetKey, sessionHash);
  await pipeline.exec();
}
```

### 6.6 Revoking All Sessions (Logout Everywhere)

```typescript
async revokeAllSessions(userId: string): Promise<void> {
  const sessionsSetKey = this.key("sess", userId);
  const sessionHashes = await this.redis.smembers(sessionsSetKey);

  if (sessionHashes.length === 0) return;

  const pipeline = this.redis.pipeline();
  for (const hash of sessionHashes) {
    pipeline.del(this.key("rt", hash));
    pipeline.del(this.key("sd", hash));
  }
  pipeline.del(sessionsSetKey);
  await pipeline.exec();
}
```

### 6.7 Platform Admin Sessions

Platform admin sessions use the same architecture with distinct prefixes:

| Entity          | Tenant User                                                     | Platform Admin                         |
| --------------- | --------------------------------------------------------------- | -------------------------------------- |
| Session set     | `auth:sess:{hmac(dashboard:{bytes(tenant)}:{tenant}:{userId})}` | `auth:psess:{hmac(platform:{userId})}` |
| Session details | `auth:sd:{hash}`                                                | `auth:psd:{hash}`                      |
| Refresh token   | `auth:rt:{hash}`                                                | `auth:prt:{hash}`                      |

This separation ensures that a tenant-level session revocation operation never accidentally affects platform admin sessions, and vice versa.

---

## 7. OTP Storage

### 7.1 OTP Design

OTPs (One-Time Passwords) are short numeric codes sent via email for password reset and email verification flows. They are stored in Redis with a limited TTL and an attempt counter to prevent brute-forcing the code.

### 7.2 Key Structure

```
Key:   auth:otp:{purpose}:{hmac_sha256(hmacKey, "{tenantId}:{email}")}
Value: HASH { code: "<hmac_sha256(identifier:code)>", attempts: 0 }
TTL:   otpTtlSeconds (varies by purpose)
```

The `purpose` segment (`password_reset` or `email_verification`) prevents a code issued for one purpose from being used for another.

### 7.3 Storing an OTP

The record is a HASH, written together with its expiry in one script so the key never exists without a TTL (an `HSET` followed by a separate `EXPIRE` leaves a window where a crash strands the record with no expiry):

```typescript
const OTP_STORE_LUA = `
redis.call('HSET', KEYS[1], 'code', ARGV[1], 'attempts', 0)
redis.call('EXPIRE', KEYS[1], ARGV[2])
`

async storeOtp(
  purpose: "password_reset" | "email_verification",
  identifier: string,
  code: string,
  ttlSeconds: number,
): Promise<void> {
  // `fingerprint` is the keyed HMAC of identifier + code; the code itself is never stored.
  await this.redis.eval(
    OTP_STORE_LUA,
    [`otp:${purpose}:${identifier}`],
    [this.fingerprint(identifier, code), String(ttlSeconds)],
  );
}
```

### 7.4 Atomic Check-and-Delete (Verify OTP)

OTP verification must be atomic to prevent race conditions where the same code is verified twice, and so that parallel wrong guesses cannot exceed the attempt ceiling. A read in JS followed by a write back would let N concurrent guesses all read `attempts: 0`. The decision is made inside one script, with `HINCRBY` bumping the counter in place (it leaves the key's TTL untouched, so a wrong guess cannot extend the OTP's lifetime):

```typescript
const OTP_VERIFY_LUA = `
local code = redis.call('HGET', KEYS[1], 'code')
if not code then
    return { 'EXPIRED', '' }
end
local attempts = tonumber(redis.call('HGET', KEYS[1], 'attempts')) or 0
if attempts >= tonumber(ARGV[2]) then
    redis.call('DEL', KEYS[1])
    return { 'MAX', '' }
end
if code == ARGV[1] then
    redis.call('DEL', KEYS[1])
else
    redis.call('HINCRBY', KEYS[1], 'attempts', 1)
end
return { 'PRESENT', code }
`

const raw = await this.redis.eval(OTP_VERIFY_LUA, [key], [fingerprint, String(MAX_ATTEMPTS)])
```

The caller re-compares the returned stored fingerprint to the submitted one in constant time (`timingSafeEqual`), and answers every failure (missing record, exhausted ceiling, wrong code) with the same `OTP_INVALID` error in the same time, so the responses do not reveal whether a record exists.

### 7.5 Resend Cooldown

To prevent attackers from endlessly resending OTPs (which would reset the attempt counter), a cooldown key is set:

```
Key:   auth:resend:{purpose}:{hmac_sha256(hmacKey, "{tenantId}:{email}")}
Value: '1'
TTL:   60 seconds
```

```typescript
async canResendOtp(purpose: string, tenantId: string, email: string): Promise<boolean> {
  const key = this.key("resend", `${purpose}:${sha256(tenantId + ":" + email)}`);
  const exists = await this.redis.exists(key);
  return !exists;
}

async markOtpResent(purpose: string, tenantId: string, email: string): Promise<void> {
  const key = this.key("resend", `${purpose}:${sha256(tenantId + ":" + email)}`);
  await this.redis.set(key, "1", "EX", 60);
}
```

### 7.6 TOTP Replay Prevention

For MFA TOTP codes, the library prevents replay attacks by storing used codes temporarily:

```
Key:   auth:tu:{hmac_sha256(hmacKey, "{userSubject}:{code}")}
Value: '1'
TTL:   (2 x window + 1) x 30 seconds (90s with the default window of 1)
```

This ensures the same TOTP code cannot be reused within its validity window, even though the TOTP algorithm would accept it.

---

## 8. Pipeline and Transaction Patterns

### 8.1 When to Use Pipeline

A **pipeline** batches multiple commands into a single network round-trip. Commands execute independently — the failure of one does not affect others. Use pipelines when:

- You need to perform multiple reads or writes that are independent of each other.
- You want to reduce network latency (important: each pipeline saves one round-trip).
- The operations do not need to be atomic (one can fail without rolling back others).

**Examples in this library:**

```typescript
// Listing sessions: fetch multiple keys in one round-trip
const pipeline = this.redis.pipeline()
for (const hash of sessionHashes) {
  pipeline.get(this.key('sd', hash))
}
const results = await pipeline.exec()

// Revoking all sessions: delete multiple keys in one round-trip
const pipeline = this.redis.pipeline()
for (const hash of sessionHashes) {
  pipeline.del(this.key('rt', hash))
  pipeline.del(this.key('sd', hash))
}
pipeline.del(sessionsSetKey)
await pipeline.exec()
```

### 8.2 When to Use MULTI/EXEC (Transactions)

A **transaction** (`MULTI`/`EXEC`) guarantees that all commands execute atomically — either all succeed or none are applied. Use transactions when:

- Multiple writes must be consistent (all-or-nothing).
- You need isolation from other clients modifying the same keys concurrently.
- The operations do not depend on intermediate results (MULTI queues commands without returning values until EXEC).

```typescript
// Atomic session cleanup during logout
const multi = this.redis.multi()
multi.set(this.key('rv', jti), '1', 'EX', remainingSeconds)
multi.del(this.key('rt', sha256(refreshToken)))
multi.srem(this.key('sess', userId), sessionHash)
multi.del(this.key('sd', sessionHash))
await multi.exec()
```

### 8.3 When to Use Lua Scripts

Use **Lua scripts** when you need atomicity AND need intermediate results to determine subsequent actions within the same atomic block. Lua scripts execute on the Redis server as a single operation. In this library, the primary use case is refresh token rotation (Section 4.4).

**Decision matrix:**

| Need                                             | Tool       |
| ------------------------------------------------ | ---------- |
| Batch independent reads/writes to reduce latency | Pipeline   |
| All-or-nothing writes without intermediate reads | MULTI/EXEC |
| Atomic read-then-write (conditional logic)       | Lua script |

### 8.4 Pipeline Error Handling

`pipeline.exec()` returns an array of `[error, result]` tuples. Always check for errors:

```typescript
const results = await pipeline.exec()
if (!results) {
  throw new Error('Pipeline execution returned null')
}

for (const [err, result] of results) {
  if (err) {
    // Log the error but continue — pipeline errors are per-command
    this.logger.error(`Redis pipeline command failed: ${err.message}`)
  }
}
```

### 8.5 MULTI/EXEC Error Handling

```typescript
const results = await multi.exec()
if (!results) {
  // Transaction was aborted (e.g., WATCH detected a modification)
  throw new Error('Redis transaction aborted')
}

// Check for per-command errors
for (const [err, result] of results) {
  if (err) {
    // Unlike pipeline, a MULTI error is more serious
    throw new Error(`Redis transaction command failed: ${err.message}`)
  }
}
```

### 8.6 Lua Script Registration with defineCommand

For frequently used Lua scripts, register them with ioredis `defineCommand` to enable automatic SHA-based caching (EVALSHA). This avoids sending the full script text on every call:

```typescript
// Register during service initialization
this.redis.defineCommand('rotateRefreshToken', {
  numberOfKeys: 3,
  lua: ROTATE_REFRESH_TOKEN_SCRIPT
})

// Call using the defined command name
// TypeScript: extend the Redis interface or use type assertion
const result = await (this.redis as any).rotateRefreshToken(
  this.key('rt', sha256(oldToken)),
  this.key('rt', sha256(newToken)),
  this.key('rp', sha256(oldToken)),
  JSON.stringify(sessionData),
  newToken,
  refreshTtlSeconds.toString(),
  graceWindowSeconds.toString()
)
```

Benefits of `defineCommand`:

- ioredis automatically uses `EVALSHA` (sends just the script hash) and falls back to `EVAL` (sends full script) only if the script is not cached on the Redis server.
- Reduces bandwidth for large or frequently called scripts.
- Provides a named method on the Redis client for clarity.

---

## 9. Error Handling and Resilience

### 9.1 Connection Error Types

ioredis distinguishes between two categories of errors:

- **Connection errors:** Occur when Redis is unreachable. ioredis automatically retries based on `retryStrategy`.
- **Command errors:** Occur when a command fails (e.g., wrong argument type). These are not retried.

### 9.2 Retry Strategy (Host Application Responsibility)

The retry strategy is configured by the host application when creating the Redis client. The library must tolerate connection drops gracefully. A recommended configuration for the host:

```typescript
// This code lives in the HOST APPLICATION, not in the library.
// Shown here for reference and to document expectations.
import Redis from 'ioredis'

const redis = new Redis({
  host: process.env.REDIS_HOST,
  port: parseInt(process.env.REDIS_PORT ?? '6379', 10),
  password: process.env.REDIS_PASSWORD,
  db: 0,
  maxRetriesPerRequest: 3,
  retryStrategy(times: number): number | null {
    if (times > 10) {
      // Stop retrying after 10 attempts
      return null
    }
    // Exponential backoff: 50ms, 100ms, 200ms, ..., capped at 2000ms
    return Math.min(times * 50, 2000)
  },
  enableReadyCheck: true,
  lazyConnect: false
})
```

### 9.3 Handling Redis Errors in Library Code

The library wraps Redis operations to provide meaningful error contexts:

```typescript
async safeGet(key: string): Promise<string | null> {
  try {
    return await this.redis.get(key);
  } catch (error) {
    this.logger.error(`Redis GET failed for key pattern ${key.split(":").slice(0, 2).join(":")}:*`, error);
    throw error; // Re-throw — callers decide on degradation
  }
}
```

### 9.4 Graceful Degradation Patterns

Different features have different criticality levels when Redis is unavailable:

| Feature                | Degradation Strategy                                                                                                                                                |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| JWT blacklist check    | **Fail open with logging.** If Redis is unreachable, allow the request but log a security warning. The token is still signature-verified and will expire naturally. |
| Refresh token rotation | **Fail closed.** Refuse the refresh. The user must re-authenticate.                                                                                                 |
| Brute-force check      | **Fail open.** Allow the login attempt but log a warning. No counter increment.                                                                                     |
| User status cache      | **Fail through to database.** Query the database directly if cache is unavailable.                                                                                  |
| Session management     | **Fail closed for writes, fail gracefully for reads.** Session listing may return partial data; session creation must succeed or fail the operation.                |
| OTP verification       | **Fail closed.** Refuse verification if Redis is unreachable.                                                                                                       |

### 9.5 Implementing Graceful Degradation

```typescript
async isTokenBlacklisted(jwt: string, payload: JwtPayload): Promise<boolean> {
  try {
    const key = payload.jti
      ? this.key("rv", payload.jti)
      : this.key("rv", sha256(jwt));
    return (await this.redis.exists(key)) === 1;
  } catch (error) {
    // Fail open: allow request, but log security warning
    this.logger.warn(
      "Redis unavailable for blacklist check — allowing request. " +
      "JWT signature is still valid. Token will expire at " +
      new Date(payload.exp * 1000).toISOString(),
    );
    return false;
  }
}
```

### 9.6 Timeout Configuration

The host application should configure appropriate timeouts. The library does not set timeouts internally, but library code should be aware of them:

```typescript
// Host application configuration (reference)
const redis = new Redis({
  connectTimeout: 5000, // 5s to establish connection
  commandTimeout: 3000, // 3s per command
  enableOfflineQueue: true // Queue commands while reconnecting
})
```

### 9.7 Health Check

The library's `AuthRedisService` can expose a health check for use by the host application's health endpoint:

```typescript
async isHealthy(): Promise<boolean> {
  try {
    const pong = await this.redis.ping();
    return pong === "PONG";
  } catch {
    return false;
  }
}
```

### 9.8 Logging Conventions

- **Never log raw tokens or key values** in error messages. Log key patterns (e.g., `auth:rt:*`) instead.
- **Always log the Redis error class** — distinguish `MaxRetriesPerRequestError`, `ConnectionClosedError`, etc.
- **Use structured logging** with the NestJS `Logger`:

```typescript
private readonly logger = new Logger(AuthRedisService.name);
```

---

## 10. Anti-Patterns

### 10.1 Connection Management

**WRONG: Creating Redis connections inside the library**

```typescript
// NEVER do this in library code
@Injectable()
export class AuthRedisService {
  private redis = new Redis({ host: 'localhost', port: 6379 })
}
```

**CORRECT: Injecting the Redis client provided by the host**

```typescript
@Injectable()
export class AuthRedisService {
  constructor(@Inject(BYMAX_AUTH_REDIS_CLIENT) private readonly redis: Redis) {}
}
```

---

### 10.2 Keys Without TTL

**WRONG: Setting keys without expiration**

```typescript
await this.redis.set(key, value)
// This key will persist forever, causing memory leaks
```

**CORRECT: Always include a TTL**

```typescript
await this.redis.set(key, value, 'EX', ttlSeconds)
```

---

### 10.3 Raw Tokens in Key Names

**WRONG: Using raw tokens directly as Redis keys**

```typescript
const key = `auth:rt:${refreshToken}`
// Exposes the actual token in Redis key space
```

**CORRECT: Hash sensitive identifiers**

```typescript
const key = `auth:rt:${sha256(refreshToken)}`
// Token value is never visible in Redis
```

---

### 10.4 Non-Atomic Token Rotation

**WRONG: Using separate GET/DEL/SET for token rotation**

```typescript
const session = await this.redis.get(oldKey)
await this.redis.del(oldKey) // Race condition window here
await this.redis.set(newKey, session, 'EX', ttl)
// Two concurrent requests can both read the old token before either deletes it
```

**CORRECT: Using a Lua script for atomic rotation**

```typescript
const result = await this.redis.eval(ROTATE_SCRIPT, 3, oldKey, newKey, pointerKey, ...args)
// Atomic: no other client can interleave between read and delete
```

---

### 10.5 Resetting Brute-Force Window on Each Failure

**WRONG: Using SET with EX for counters (resets the window)**

```typescript
const current = parseInt((await this.redis.get(key)) ?? '0', 10)
await this.redis.set(key, (current + 1).toString(), 'EX', 900)
// Every failure resets the 15-minute window — attacker gets unlimited attempts
```

**CORRECT: Using INCR with conditional EXPIRE**

```typescript
const attempts = await this.redis.incr(key)
if (attempts === 1) {
  await this.redis.expire(key, 900) // Window starts on first failure only
}
```

---

### 10.6 Blocking Commands

**WRONG: Using blocking commands (BLPOP, BRPOP, SUBSCRIBE) on the shared client**

```typescript
// Blocks the shared Redis connection for all other operations
await this.redis.blpop('some-queue', 0)
```

**CORRECT: Never use blocking or pub/sub commands on the injected client.** The injected client is shared across all authentication operations. Blocking or subscribing on it would stall all other Redis calls. If the host application needs pub/sub or blocking queues, it should provide a separate dedicated connection.

---

### 10.7 Using KEYS Command

**WRONG: Using KEYS for pattern matching in production**

```typescript
const keys = await this.redis.keys(`auth:rt:*`)
// KEYS scans the entire keyspace — O(N) and blocks Redis for all clients
```

**CORRECT: Use SCAN for iterating, or design data structures that avoid pattern matching**

```typescript
// Preferred: use a SET to track related keys
const sessions = await this.redis.smembers(this.key('sess', userId))

// If SCAN is truly needed (rare in this library):
let cursor = '0'
do {
  const [newCursor, keys] = await this.redis.scan(cursor, 'MATCH', `${this.ns}:rt:*`, 'COUNT', 100)
  cursor = newCursor
  // Process keys...
} while (cursor !== '0')
```

---

### 10.8 Large JSON Values

**WRONG: Storing large objects or entire user profiles in Redis**

```typescript
await this.redis.set(key, JSON.stringify(entireUserRecord), 'EX', ttl)
// Wastes memory and increases serialization cost
```

**CORRECT: Store only the minimum data needed**

```typescript
// Refresh session: only what's needed to reissue tokens
await this.redis.set(
  key,
  JSON.stringify({
    userId,
    tenantId,
    role,
    device,
    ip,
    createdAt
  }),
  'EX',
  ttl
)
```

---

### 10.9 Ignoring Pipeline/Transaction Errors

**WRONG: Not checking `exec()` results**

```typescript
const results = await pipeline.exec()
// Assuming everything worked — silent data loss if commands failed
```

**CORRECT: Always check results**

```typescript
const results = await pipeline.exec()
if (!results) throw new Error('Pipeline returned null')
for (const [err] of results) {
  if (err) this.logger.error('Pipeline command failed', err)
}
```

---

### 10.10 Hardcoded Namespace

**WRONG: Hardcoding the namespace string throughout the code**

```typescript
const key = `auth:rt:${hash}`
// Cannot be configured; breaks if host uses a different namespace
```

**CORRECT: Using the configurable namespace from options**

```typescript
const key = `${this.ns}:rt:${hash}`
// this.ns is set from options.redisNamespace in the constructor
```

---

## Quick Reference Checklist

Use this checklist when writing or reviewing any Redis operation in the library:

### Key Design

- [ ] Key follows `{namespace}:{prefix}:{identifier}` format
- [ ] Sensitive identifiers (tokens, emails) are SHA-256 hashed before use in keys
- [ ] Namespace is read from `options.redisNamespace`, not hardcoded
- [ ] Key prefix is documented in the key reference table (Section 2.3)

### TTL

- [ ] Every `SET` includes `EX` or `PX`
- [ ] TTL value matches the logical lifetime of the data (e.g., remaining JWT TTL for blacklist)
- [ ] No persistent keys are created (every key must expire)

### Atomicity

- [ ] Operations that read-then-write on the same key use Lua scripts
- [ ] Independent bulk operations use pipelines
- [ ] All-or-nothing writes use MULTI/EXEC
- [ ] Brute-force counters use `INCR` + conditional `EXPIRE`, not `SET` with `EX`

### Security

- [ ] Raw tokens never appear in key names or log messages
- [ ] SISMEMBER is used to verify ownership before session operations (prevents BOLA/IDOR)
- [ ] OTP verification checks and increments attempt counter
- [ ] TOTP replay prevention key is set after successful verification

### Error Handling

- [ ] Redis errors are caught and logged with context (but without sensitive values)
- [ ] Degradation strategy matches the feature's criticality (fail-open vs fail-closed)
- [ ] Pipeline/transaction `exec()` results are checked for per-command errors

### Connection

- [ ] No `new Redis()` or `new Cluster()` calls in library code
- [ ] No `redis.quit()` or `redis.disconnect()` calls in library code
- [ ] No blocking commands (`BLPOP`, `BRPOP`, `SUBSCRIBE`) on the injected client
- [ ] No `KEYS` command in production code paths
- [ ] Redis client is obtained only through `@Inject(BYMAX_AUTH_REDIS_CLIENT)`

### Testing

- [ ] Redis is mocked via the DI token, not by monkey-patching
- [ ] Lua scripts are tested with `eval` mock that returns expected values
- [ ] Pipeline mocks return `[null, value]` tuple arrays matching ioredis format

### Code Organization

- [ ] All key construction goes through a centralized `key()` helper method
- [ ] Lua scripts are stored as constants, not inline strings
- [ ] `defineCommand` is used for frequently called Lua scripts
