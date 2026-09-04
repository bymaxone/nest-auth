# `src/server/` — server-plane instructions

Loaded by Codex only when the working directory is `src/server/` or below, so these rules cost a
reviewer nothing when the diff is under `src/react/`, `src/nextjs/`, `src/client/` or
`src/shared/`. Repository-wide rules stay in the root [AGENTS.md](../../AGENTS.md); this file
carries the ones that are true only here.

## Backend patterns

### Injection Tokens (7 Symbols)

| Token                                 | Type                      | Required                                                                                  |
| ------------------------------------- | ------------------------- | ----------------------------------------------------------------------------------------- |
| `BYMAX_AUTH_OPTIONS`                  | `ResolvedOptions`         | Always                                                                                    |
| `BYMAX_AUTH_USER_REPOSITORY`          | `IUserRepository`         | Always                                                                                    |
| `BYMAX_AUTH_PLATFORM_USER_REPOSITORY` | `IPlatformUserRepository` | If `platformAdmin.enabled`                                                                |
| `BYMAX_AUTH_EMAIL_PROVIDER`           | `IEmailProvider`          | Always (NoOp default)                                                                     |
| `BYMAX_AUTH_HOOKS`                    | `IAuthHooks`              | Always (NoOp default)                                                                     |
| `BYMAX_AUTH_REDIS_CLIENT`             | `Redis`                   | Always                                                                                    |
| `BYMAX_AUTH_BREACH_CHECKER`           | `IPasswordBreachChecker`  | Always (`AllowAllBreachChecker` default — the check reaches the network, so it is opt-in) |

### Service and controller shape

A service method runs in one order: **validate** (find the user, check status, check brute-force),
**execute** (verify the credential, apply the MFA rule), **generate** (tokens, session), **deliver**
(cookies or body), **hook**, return. `AuthService.login` is the reference implementation.

A controller does none of that. It carries the route decorator, the throttle config and the status
code, and delegates in one line — validate, delegate, return, nothing else. Any logic in a
controller belongs in the service it calls.

### Error Response Format

```json
{ "error": { "code": "INVALID_CREDENTIALS", "message": "...", "details": {} } }
```

All codes from `AUTH_ERROR_CODES` (33 codes). Throw `AuthException(code, statusCode?, details?)`.

### Redis Key Patterns

Format: `{namespace}:{prefix}:{identifier}`

| Prefix | Purpose                                                   | TTL                         |
| ------ | --------------------------------------------------------- | --------------------------- |
| `rt`   | Refresh token hash                                        | `refreshExpiresInDays`      |
| `rp`   | Rotation grace pointer (old hash → new session)           | `refreshGraceWindow`        |
| `cf`   | Consumed-token family marker (proves a replay is a reuse) | Refresh TTL                 |
| `fam`  | Family index — the live hashes of one login's lineage     | Refresh TTL                 |
| `ep`   | Per-user token epoch (bulk access-token revocation)       | 30 days                     |
| `rv`   | Revoked JWT (blacklist)                                   | Remaining token lifetime    |
| `lf`   | Login failures                                            | `bruteForce.windowSeconds`  |
| `rl`   | Per-IP rate-limit counter, keyed by `HMAC(ip)`            | The route's window          |
| `otp`  | OTP codes                                                 | `otpTtlSeconds`             |
| `sess` | Session set per user                                      | Session lifetime            |
| `sd`   | Session detail                                            | Session lifetime            |
| `us`   | Cached account status (`us:{tenantId}:{userId}`)          | `userStatusCacheTtlSeconds` |
| `uev`  | Cached email-verified flag (same scoping)                 | `userStatusCacheTtlSeconds` |

**Do not build these keys from the format, in library code or consumer code.** `us` and `uev` are
derived in exactly one place — a module-private helper in `account-status.service.ts`, deliberately
not exported — and dropped through `AccountStatusService.invalidate` — a second statement of a key format drifts out of agreement
silently, because a delete that stops matching raises nothing and merely defers the change by a
TTL. The same applies to a consumer: the prefix is readable, the format is not a contract, and the
supported way to name one of these entries is the method.

`us` and `uev` have no platform counterpart: the platform status check is uncached, because there
is no tenant to scope a cache key by and the population is small enough that a read per call beats
a keyspace nothing invalidates. The other prefixes DO mirror onto the platform plane under their
own names (`prt`, `prp`, `pcf`, `pfam`, `pep`, …)
so a "sign out everywhere" on one plane can never reach the other. The full keyspace, including
which of these are a contract with `rust-auth`, is in
[`conformance/wire-contract.json`](./conformance/wire-contract.json).

---

## Security specification

### Cryptographic Operations

| Operation        | Algorithm                            | File                     |
| ---------------- | ------------------------------------ | ------------------------ |
| Password hashing | scrypt (N=2^15, r=8, p=1, keyLen=64) | `crypto/scrypt.ts`       |
| MFA encryption   | AES-256-GCM (12-byte IV)             | `crypto/aes-gcm.ts`      |
| TOTP             | HMAC-SHA1 (RFC 4226/6238)            | `crypto/totp.ts`         |
| Token generation | `crypto.randomBytes` → hex           | `crypto/secure-token.ts` |
| Token storage    | SHA-256 hash                         | `crypto/secure-token.ts` |
| OTP codes        | `crypto.randomInt` (max length 8)    | `crypto/secure-token.ts` |

### JWT Token Types

| Type             | Lifetime | Transport       | Key Claims                                    |
| ---------------- | -------- | --------------- | --------------------------------------------- |
| Dashboard access | 15min    | Cookie/Bearer   | jti, sub, tenantId, role, status, mfaVerified |
| Platform access  | 15min    | Cookie/Bearer   | jti, sub, role, mfaVerified                   |
| Refresh          | 7d       | HttpOnly cookie | Opaque UUID → SHA-256 in Redis                |
| MFA temp         | 5min     | Cookie/Bearer   | sub, context (dashboard\|platform)            |

### Key Validations at Startup

- JWT secret: >= 32 chars, Shannon entropy >= 3.5 bits/char, reject repetitive patterns
- MFA encryption key: must decode from base64 to exactly 32 bytes
- Roles hierarchy: must not be empty
- OTP length: must be <= 8 (randomInt MAX_SAFE_INTEGER limit)

---
