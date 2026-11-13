# Server services

Services for operations that are not routes. Part of the [`@bymax-one/nest-auth` README](../README.md).

## Administrative operations — methods, deliberately not routes

Two support-desk operations ship as **methods with no HTTP route**. Every route above is scoped
to the caller's own account, and both of these act on somebody else's — so exposing them would
mean inventing an authorization model ("who is an admin?") that this library does not have and
your application already does. Call them from your own admin surface, where the caller is
already authorized.

| Method                                             | Answers                                             |
| -------------------------------------------------- | --------------------------------------------------- |
| `AuthService.unlockAccount(email, tenant)`         | "I am locked out and I need in now"                 |
| `MfaService.resetMfa(userId, context?, tenantId?)` | "I lost my authenticator **and** my recovery codes" |

**`unlockAccount`** clears the brute-force lockout. It grants no access: the password, the
status gate, the verification gate and MFA all still apply — it restores the ability to _try_.
It exists because the counter is keyed by an HMAC under the library's own `hmacKey`, which no
consumer can derive, so until it existed a lockout could only be waited out. It is also the
lever an attacker pulls to deny service to one specific account, which makes undoing it part of
the defence. Idempotent.

**`resetMfa`** removes a second factor without one. Every self-service exit needs the factor
itself — `disable` wants a valid TOTP code, the recovery codes want the codes — so a user who
has lost both is locked out permanently by the control meant to protect them (ASVS v5 §6.1.1
asks for this path for exactly that reason). It invalidates every session and bumps the token
epoch, so access tokens carrying `mfaVerified: true` die with the factor; it **notifies the
account holder** through the same channel a self-service disable uses; and it logs at `warn`
under its own prefix. The notification is not optional: an administrative reset the owner
cannot see is an account-takeover path, and it is what makes the event detectable and
disputable. `tenantId` is required when `context` is `'dashboard'` (the default) and ignored for
`'platform'`. Idempotent; throws for an id that resolves to nobody, so a typo cannot read as
"done".

> `MfaService` is only registered when `controllers.mfa` or `controllers.platform` is on —
> otherwise add it to `extraProviders` to inject it.

## Checking revocation outside a guard — `AuthRevocationService`

The three JWT guards do not decide revocation themselves; they delegate to one service, and that
service is exported so **you can consult the same two channels from a transport the guards never
see** — a WebSocket, an SSE stream, a message consumer. Without it there is no way to ask the
question at all outside an HTTP request: a connection whose user logs out keeps its stream until
the access token expires, while that user's HTTP calls are refused at once.

```ts
import { AuthRevocationService } from '@bymax-one/nest-auth'

const revoked = await this.revocation.isAccessTokenRevoked(
  { jti: payload.jti, sub: payload.sub, epoch: payload.epoch, tenantId: payload.tenantId },
  'dashboard'
)
```

It is registered and exported unconditionally, so it is injectable wherever `BymaxAuthModule` is
imported — no `extraProviders` entry and no controller flag to turn on.

> [!IMPORTANT]
> **On the dashboard plane you must forward `tenantId` from the verified token.** It is optional
> on `RevocableTokenPayload` because the platform plane genuinely has none — its admins are
> cross-tenant — so **`tsc` will not catch the omission**, and a dashboard payload without it is
> treated as **revoked** without a store read, with a `warn` naming the missing field.
>
> Failing closed is deliberate. The epoch key derives from the tenant-scoped subject, so an absent
> tenant names a keyspace belonging to no tenant, where nothing has ever been bumped: the read
> would answer `0`, `stamped < 0` is false for every token, and a bulk-revoked token would be
> reported **valid**. A revocation check that fails open on malformed input is worse than no check.
>
> **Recognise the symptom, because it does not look like an auth bug.** The refusal answers the
> same `true` a genuinely revoked token answers, throws nothing and emits no event — so a
> transport that gates a stream on it simply registers nothing: an SSE handshake answers `200`
> and the connection registry stays empty. Declaring the tenant **required** on your own port type is the stronger fix, because it turns the
> next occurrence into a compile error rather than a log line.

**What this method is and is not.** It answers two channels at the moment you call it: the
per-token blacklist and the user's token epoch. It reads no `exp`, holds no subscription, emits no
event, and knows nothing about account status, roles, tenant binding or the identity plane. It is
therefore **one check among the many a guarded HTTP route performs**, and not a substitute for
them.

Using it to authorise a long-lived transport takes more than this method. Use
`AuthTokenVerifierService` for that, below.

## Authorising a long-lived transport — `AuthTokenVerifierService`

A guarded HTTP route establishes seven things before a handler runs. A WebSocket, an SSE stream or
a message consumer has no guard in front of it, so it must establish the same seven itself — and on
a cadence, because a connection outlives the request that opened it. Assembling that from the
exported parts is where it goes wrong: a bridge that calls `isAccessTokenRevoked` alone has checked
a signature and a blacklist while checking neither the token's **type**, nor its **`exp`**, nor
whether the **account** behind it still exists.

`AuthTokenVerifierService.verifyAccessToken` is all seven in one call:

```ts
import { AuthTokenVerifierService } from '@bymax-one/nest-auth'

const { plane, payload } = await this.verifier.verifyAccessToken(token, { plane: 'dashboard' })
registry.add(socket, { plane, userId: payload.sub, tenantId: payload.tenantId })
```

| It checks                                                                              | So that                                                                                                                                                                                                                                                                                                                                                                 |
| -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Signature, pinned algorithm, `issuer`/`audience`, and any secret retired by a rotation | `alg: none` and a token carrying no binding claim are refused, and a rotation drains instead of disconnecting everyone                                                                                                                                                                                                                                                  |
| `exp`                                                                                  | A revocation check answers "was this withdrawn", never "is this still current" — `isAccessTokenRevoked` reads no `exp` at all                                                                                                                                                                                                                                           |
| `jti` a UUID v4; `sub` and (dashboard) `tenantId` bounded non-empty strings            | A malformed claim cannot build a Redis key nobody intended                                                                                                                                                                                                                                                                                                              |
| Token `type`, against the plane **you** name                                           | An `mfa_challenge` token — signed with the same secret, half a credential — cannot read as a session                                                                                                                                                                                                                                                                    |
| Both revocation channels                                                               | A logout's `jti` blacklist AND the epoch a password reset or revoke-all advances                                                                                                                                                                                                                                                                                        |
| Account status (`checkStatus`, default on)                                             | Runs before the MFA decision. A suspension landing between two reconnects is seen, and so is an unverified email on the dashboard plane (`auth.email_not_verified`) — the token's own `status` claim is a snapshot taken at issuance                                                                                                                                    |
| MFA policy (`requireMfa`, default on)                                                  | Runs after the account-status check, so a blocked account is refused with its own code even while a challenge is pending. A refresh mints `mfaEnabled: true, mfaVerified: false`; the type alone does not imply the second factor was completed. A token whose `mfaEnabled` claim is missing or not a boolean is refused `auth.token_invalid` before the account lookup |

On the dashboard plane that last row reads a cache, and **its freshness is bounded by
`userStatusCacheTtlSeconds` (default 60 s), not by how often you call**: a stream re-verifying every
five seconds still serves a banned account until the entry expires. What shortens that is
[`AccountStatusService.invalidate`](#invalidating-the-account-cache--accountstatusserviceinvalidate)
— call it wherever you change a status, and read the caveat under that method: a request already
resolving when you invalidate can write the old value back, so the window narrows to one repository
read rather than to zero. Failing that, lower the TTL. The platform plane is uncached and genuinely current, at one repository read per call.

The plane is **yours to declare**, never inferred from the token. Inferring it would make the plane
attacker-chosen: a platform token would open a dashboard stream by saying it is one. Passing a
value that is neither throws a `TypeError` rather than refusing quietly — the fall-through would
otherwise be the cross-tenant platform arm.

Every refusal is an `AuthException`, and each mirrors the code the equivalent guard already
answers. Most answer `auth.token_invalid` so a caller cannot tell "valid but revoked" from "never
valid"; `auth.mfa_required`, the `ACCOUNT_*` codes, `auth.email_not_verified` (dashboard plane) and — on
the platform plane only — `auth.platform_auth_required` name themselves, because a legitimate
client acts on each differently. The account codes are answered whether or not an MFA challenge
is pending; `auth.mfa_required` is answered only for a usable account.

> [!IMPORTANT]
> **Three things it still does not do.** Route **authorization** is yours — this answers who the
> caller is, never what they may do, so your `@Roles()` equivalent belongs on every message a
> stream carries, not only on the handshake. **Tenant binding** (`enforceTenantBinding`) needs the
> request its resolver reads, so pass the handshake as `request` to `verifyAccessToken` (the same
> `headers`/`url`/`hostname` request as on `WsJwtGuard`, fail-closed on a resolver that cannot answer);
> without it the binding is not applied to that call, and one warning per service instance says so. And it holds **no
> subscription**: it answers at the moment you call it, so a stream that calls it once at connect
> is authorized for the lifetime of the token rather than of the session. Call it again on a
> cadence and treat a rejection as a disconnect.

`AccountStatusService` is exported alongside it for the narrower case: you already hold a verified
payload and want to re-ask only the one question whose answer changes while a stream is open.

## Invalidating the account cache — `AccountStatusService.invalidate`

Account status is read through a Redis cache with a `userStatusCacheTtlSeconds` lifetime (60 s by
default), so a change made **outside** this library is not seen until the entry expires. Suspend a
user through your own admin surface and they keep reaching protected routes for up to a minute.

```ts
import { AccountStatusService } from '@bymax-one/nest-auth'

await this.accountStatus.invalidate({ userId, tenantId })
```

Call it whenever you change an account's status yourself. It drops both cached facts — the status
and the email-verified flag — and is idempotent, so you need not know whether the account was
cached. The tenant is required: a repository id is unique only within one, so a bare id would name
another tenant's entry. An empty or blank `userId` or `tenantId` throws a `TypeError` rather than
deleting nothing and resolving.

**Persist the status change first, then invalidate.** The read path fills the cache in two steps —
resolve from the repository, then write — so a request that resolved the old value just before your
update lands will write it back afterwards, with a full TTL, however promptly you call this. The
window is one repository read wide rather than one TTL, which is the improvement; it is not zero.
Writing first means any request whose read starts after your write already sees the new value, and
only genuinely concurrent ones can lose the race. Closing it entirely would need the fill to be
conditional on nothing having invalidated in between, which this service does not do today.

> [!IMPORTANT]
> **Do not delete the cache keys yourself**, even though the `<namespace>:*` prefix is yours to
> read. Their format is this library's to change — it already changed once, in v1.3.2, which added
> the tenant segment — and a delete that stops matching **fails silently**: no error, no event, just
> a status change that takes a full TTL to land. That is a security control degrading quietly. This
> method is the supported way to ask, and it is the only thing that stays correct when the format
> moves.
