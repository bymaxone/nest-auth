# When Redis stops answering

Every authentication decision in this library reads or writes Redis. This note says what a request
gets when Redis cannot answer, why it gets that, and which test pins each case. The short version:
`503` with `error.code` `auth.service_unavailable`, nothing admitted, nothing of the store in the
body.

## The answer

```json
{
  "error": {
    "code": "auth.service_unavailable",
    "message": "Service temporarily unavailable",
    "details": null
  }
}
```

- Status `503`. The code is in `AUTH_ERROR_CODES.SERVICE_UNAVAILABLE`, its status in
  `AUTH_ERROR_STATUS`, and both are pinned in `conformance/wire-contract.json`, which
  rust-auth shares.
- The ioredis error is the exception's `cause`. It is never serialized. A host filter that logs 5xx
  answers records the real reason; the library's own `AuthExceptionFilter` writes no line for an
  `AuthException`, so the operator's signal is a Redis health check beside the readiness probe.
- No `Retry-After`. Nothing in the library knows when Redis returns, and a fixed number would be a
  guess. The one `Retry-After` the library sends, on a rate-limit refusal, is a real window.

## What counts as an outage

One function decides, `redisOutageKindOf` in `src/server/redis/redis-outage.ts`. The messages were
captured from a real ioredis client against a real Redis 8 container, paused, stopped and with each of
the other two client configurations a host may use.

| Kind          | What the client reports                                                                            | Situation                                               |
| ------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `timeout`     | `Command timed out`                                                                                | server paused or partitioned; client still reconnecting |
| `closed`      | `Connection is closed.` · `Stream isn't writeable and enableOfflineQueue options is false`         | connection gone and no queue to hold the command        |
| `unreachable` | `MaxRetriesPerRequestError` · `ECONNREFUSED`, `ECONNRESET`, `ETIMEDOUT`, `EPIPE`, `ENOTFOUND`, ... | the client gave up its retries, or the network said so  |
| `unavailable` | reply error `READONLY` · `LOADING` · `MASTERDOWN` · `CLUSTERDOWN` · `TRYAGAIN`                     | Redis answered that it cannot serve this command now    |

A reply error that is a mistake (`NOSCRIPT`, `WRONGTYPE`, `ERR ...`) is **not** an outage: it is a
defect, stays the error it is, and is answered as `500 auth.internal`.

`READONLY` is an outage on purpose. After a failover a client still attached to the demoted node is
told it cannot serve writes right now; that clears when the client reconnects to the new primary.

## Where it is mapped

Every Redis call goes through `AuthRedisService`, which holds the only client the services use.
`mappingOutages` wraps that client in a proxy that turns an outage rejection of any
method into the typed 503 and passes every other error through untouched. It wraps every method
rather than a list of commands, so a command added later is covered without anyone remembering to add
it. `RedisReadinessService` holds the raw client for the boot probe and is not wrapped: it needs
`.status` and the events.

## Paths and outcomes

"Pinned by" names the spec that fails if the outcome changes. `real-redis/redis-outage` is
`test/e2e/real-redis/redis-outage.e2e-spec.ts`: it boots the full HTTP stack on a Redis container that
the suite pauses and stops itself, under each client configuration a host may use.

| Path group                                      | Entry points                                                     | Under an outage                                                   | Pinned by                                                                                       |
| ----------------------------------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Login, brute-force counters, session birth      | `POST login`, `POST register`                                    | 503; neither the right nor the wrong password gets a 401 or token | `real-redis/redis-outage`                                                                       |
| JWT guard: revocation, epoch, account status    | every authenticated route, platform plane, WebSocket bearer path | 503, not 401: a client is not told it is signed out               | `real-redis/redis-outage`                                                                       |
| Refresh rotation and reuse detection            | `POST refresh`, platform refresh                                 | 503; the refresh token is not reported invalid                    | `real-redis/redis-outage`                                                                       |
| Logout                                          | `POST logout`, platform logout                                   | 503, the first revocation write that failed                       | `real-redis/redis-outage`, `pending-logout.outage.spec`                                         |
| MFA setup, verify, challenge, disable, recovery | `mfa/*`                                                          | 503                                                               | `real-redis/redis-outage` (setup); the rest at the primitives, `auth-redis.service.outage.spec` |
| OTP, password reset, email change               | `forgot-password`, `reset-password`, `verify-*`, `email-change`  | 503; a reset request: same 503 for every address, after the floor | `real-redis/redis-outage` (reset request), `answer-reset-request.outage.spec`                   |
| Rate limiting, lockout counters                 | `@AuthRateLimit` routes                                          | 503, fail-closed kept                                             | the primitives (`auth-redis.service.outage.spec`, `eval`); not driven over HTTP                 |
| Sessions, workspaces, invitations               | `sessions`, `workspaces/*`, `invitations/*`                      | 503, except the fail-open caches below                            | `real-redis/redis-outage` (`GET sessions`), `workspace-access.e2e-spec`                         |
| OAuth                                           | initiate, callback                                               | 503, or a redirect carrying `error=auth.service_unavailable`      | not driven over HTTP: the controller's existing branch for an `AuthException`                   |
| WebSocket ticket and guards                     | `POST ws-ticket`, `WsJwtGuard`                                   | the typed exception reaches `WsAuthExceptionFilter` as an event   | the primitives (`auth-redis.service.outage.spec`); not driven over HTTP                         |
| Platform plane                                  | `platform/*`                                                     | 503                                                               | the primitives (`auth-redis.service.outage.spec`); not driven over HTTP                         |
| A process that boots with Redis down            | `RedisReadinessService`                                          | boot fails with the address in the message                        | `redis-readiness.e2e-spec`                                                                      |

Absorbed on purpose. The rule, with its examples, is `serviceUnavailable.absorption` in
`conformance/wire-contract.json`: a call whose result the answer does not depend on is logged and
absorbed, and a call the answer does depend on never is. The two cases a literal reader of the path
table would get wrong are pinned in `test/e2e/outage-absorbed.e2e-spec.ts`: a logout whose
session-metadata cleanup (`AuthService.revokeSessionMetadata`) fails still answers 204, because the
revocation writes that decide it already succeeded; and a failed login whose lockout reads after
`recordFailure` (`AuthService.fireLockoutIfCrossed`, which runs only when the host defines
`onLockout`) fail still answers its 401. The lockout pre-check before the password is judged is not
absorbed and answers 503.

## Three catches that would turn the 503 back

| Site                                                  | Before                              | Now                                                                                             |
| ----------------------------------------------------- | ----------------------------------- | ----------------------------------------------------------------------------------------------- |
| `answer-reset-request`, the cooldown `setnx`          | `500 auth.internal` after the floor | the 503 after the floor, for every address                                                      |
| `answer-reset-request`, a failed `issue`              | `200`, no mail                      | unchanged: it runs only for an existing account, so a 5xx would answer the enumeration question |
| `pending-logout`, the claim and the stale-marker read | `500 auth.internal`                 | the 503                                                                                         |

The reset request is safe to answer 503 because the cooldown is the first thing every request
consults, before any step that depends on the account: under a Redis outage an address that exists
and one that does not get the same status, body and floor-bounded timing
(`real-redis/redis-outage`, "answers a reset request for a known and an unknown address identically").
A store that fails between the cooldown and the code costs that one mail and nothing else.

## The browser side

`AuthProvider` revalidates the session in the background. A failure that says nothing about the
session, a `503`, any other 5xx, a `429` throttle or a network failure, no longer signs a signed-in
user out: the user and the state stay and the next tick tries again. Only a final answer, a 4xx other
than 429, ends the session. The first check of a page load has nothing to keep and behaves as it
did. Pinned by `AuthProvider.outage.spec.tsx`.

## Known and out of scope

These were found while mapping the paths. None is changed here; each has its own task.

- `token-manager.service.ts` and `session.service.ts` write after the session is already live, so a
  failure there answers an error for a login that left a live session.
- `mfa-record.service.ts` releases its lock in a `finally`: a rejected release replaces a committed
  transition's result.
- `account-status.service.ts` fails a request when only the cache fill failed, after the repository
  read succeeded.
