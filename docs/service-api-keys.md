# Service API keys: reference

The repository contract, how a key is stored and checked, the audit hook, and operating notes for [service API keys](../README.md#-service-api-keys-machine-callers).

## The repository

You implement `IApiKeyRepository`, as you do for users. The library supplies the `id` and the
`digest`; the store only persists them.

| Method                   | Contract                                                                                                                                                                                                                                                                                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `findById(id)`           | One primary-key read per request. Return revoked and expired rows too: the library decides validity.                                                                                                                                                                                                                                             |
| `create(row)`            | Insert `{ id, label, digest, scopes, createdAt, expiresAt }`. Do not make `label` unique.                                                                                                                                                                                                                                                        |
| `markRevoked(id, at)`    | `false` when unknown. Revoking twice is not an error. A row with `revokedAt` set is revoked at once on every instance, whatever instant it holds: a future date is not a schedule, so schedule with `expiresAt`.                                                                                                                                 |
| `setExpiry(id, at)`      | `false` when unknown. The scheduling field: a key stops verifying at `expiresAt`. Used by rotation to retire the old key after the overlap.                                                                                                                                                                                                      |
| `limitExpiry(id, at)`    | **Optional, recommended.** An atomic minimum: lower the expiry to `at`, never raise it (`SET expires_at = LEAST(COALESCE(expires_at, :at), :at)`). `false` when unknown. Rotation uses it when present; without it two rotations of one key can interleave and leave the old key valid past the shortest overlap, so serialize rotation per key. |
| `touchLastUsed(entries)` | One batch. **Must be monotonic**: `GREATEST(last_used_at, :at)`, never backwards — several instances flush independently.                                                                                                                                                                                                                        |
| `listByLabel(label)`     | Every key of a label, for your admin screen.                                                                                                                                                                                                                                                                                                     |

## How a key is stored and checked

A key looks like `bak_<keyId>_<secret>`: a prefix (`bak` by default), the row's UUID (a public handle that
makes verification an indexed read), and 43 base64url characters carrying 32 random bytes. Only
`HMAC-SHA-256(pepper, secret)` is stored, as lowercase hex. Labels and scopes are not part of the
digest, so editing them never invalidates a key. The grammar and the digest are pinned by
[`conformance/wire-contract.json`](../conformance/wire-contract.json) with a vector.

**Why a fast HMAC rather than a slow password hash.** This is the library's own reasoning, not
an OWASP rule: the OWASP Password Storage Cheat Sheet's case against fast hashes is about
passwords, which people choose and which can be guessed. A key's secret is 256 bits from the
CSPRNG, so the work factor of the hash adds nothing to its resistance, and a per-request scrypt
would only hand an attacker a cheap way to burn CPU. The pepper is what the cheat sheet calls
the HMAC key: kept apart from the database, so a leaked table of digests cannot be tested
offline.

**Every key takes the same steps.** Parse (substituting a dummy when it does not parse), read a
row (always), compute the digest, compare two 32-byte buffers with `timingSafeEqual` (against a
dummy digest when there is no row), and only then decide. An unknown, malformed, wrong, revoked
or expired key all answer `401 auth.api_key_invalid` with the same body; the operator sees the
real reason in the audit event. A key is valid strictly before its `expiresAt`, and not at all once `revokedAt` is set.

Two things this does _not_ claim. The store round trip costs differently for a present and an
absent row, and no library can hide that — put a per-address throttle in front (below). And the
fail-closed branch (a bound route with no scopes) intentionally takes different steps: it
depends on route configuration, not on the key, so there is nothing for the key to leak.

**Changing the pepper makes every issued key unverifiable.** Digests are not portable across
peppers, so a new pepper means re-issuing every key. There is no pepper rotation in this
version.

## Audit

Implement `onApiKeyRequest` on your `IAuthHooks`. It fires once for every guarded request:

```typescript
import type { ApiKeyAccessEvent, HookContext, IAuthHooks } from '@bymax-one/nest-auth'

export class AuditHooks implements IAuthHooks {
  async onApiKeyRequest(event: ApiKeyAccessEvent, context: HookContext): Promise<void> {
    // event.outcome: 'allowed' | 'denied'
    // event.reason:  null, or missing | malformed | unknown | wrong_secret | revoked | expired
    //                | scope_insufficient | route_undeclared | store_error
    // event.label, event.keyId, event.method, event.route (the PATTERN, e.g. /videos/:id),
    // event.requiredScopes, event.ip
    await this.audit.write({ ...event, userAgent: context.userAgent })
  }
}
```

Every refused request reaches the hook too, so anonymous traffic can write audit rows: throttle by address before the guard. By default the hook is fired without being awaited and its failure is logged. With `apiKeys.auditMode: 'required'` it is awaited, and **if it throws the request is
denied** (`500 auth.internal`): use that when the audit row is a record you must have.

## Keep the key out of your logs

The library never logs, throws or emits the presented key, and strips the key header from the
hook's `sanitizedHeaders`. Your HTTP logger sits outside the library, so redact the header
there, custom `apiKeys.header` included:

```typescript
// nest-logger
LoggerModule.forRoot({ redactPaths: ['req.headers["x-machine-key"]'] })
```

```typescript
// plain pino
const logger = pino({ redact: ['req.headers["x-api-key"]'] })
```

## Rate limiting

Rate limiting is deliberately not built in. Use `@nestjs/throttler` in two layers: a per-address
limit in front of everything, which is the only protection for the pre-verification lookup; and
a per-key limit placed **after** `ApiKeyGuard`, keyed on the verified key id:

```typescript
import { UseGuards, Get } from '@nestjs/common'
import { ServiceKey } from '@bymax-one/nest-auth'
import type { ApiKeyPrincipal } from '@bymax-one/nest-auth'
import { ThrottlerGuard } from '@nestjs/throttler'

export class KeyThrottlerGuard extends ThrottlerGuard {
  protected override async getTracker(req: Record<string, unknown>): Promise<string> {
    const key = req['apiKey'] as ApiKeyPrincipal | undefined
    return key?.id ?? String(req['ip'])
  }
}

export class LimitedController {
  // @UseGuards sits ABOVE @ServiceKey: decorators run bottom-up and the guards run in that
  // order, so the key guard verifies first and the tracker sees `request.apiKey`.
  @UseGuards(KeyThrottlerGuard)
  @ServiceKey('read')
  @Get('limited')
  limited() {}
}
```

A request that fails verification never reaches the second guard, so garbage cannot spend a real
key's budget. This example is exercised end to end in `test/e2e/api-keys.e2e-spec.ts`.

## Last-used tracking, and what it costs

A verified request does a map write, nothing else; every `lastUsedFlushSeconds` the values are
written to your repository in one batch. With **N instances** a key is written up to N times
per window instead of once, and a crash loses at most one window of `lastUsedAt`. The field is
advisory: authorization never reads it.

## Who did it

`issue`, `revoke` and `rotate` emit no hook of their own — they run inside
your admin route, which already knows the operator, so attribute them there (log or audit it
beside the call). The per-request hook below covers requests _made with_ a key. If you want
provenance stored with the key, add your own columns: `IApiKeyRepository.create` receives the
row and your implementation can persist whatever else it knows. That is why `issue()` takes
no `createdBy`.
