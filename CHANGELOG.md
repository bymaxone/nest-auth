# Changelog

All notable changes to `@bymax-one/nest-auth` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This cycle closes the divergences between this library and its Rust counterpart
[`bymaxone/rust-auth`](https://github.com/bymaxone/rust-auth) — the two can back the same
deployment over one Redis, so keys, stored record shapes, JWT claims and Lua scripts are a
contract between them — and then ships five security items that came out of auditing both
against `better-auth`. Every change here has a matching change on the Rust side, and
`conformance/wire-contract.json` is held byte-identical in both repositories.

### Added

- **`pnpm check:exports`** runs `attw --profile strict` against the tarball this
  package would publish. Its absence is why both resolution defects above went
  unnoticed: a source-level typecheck compiles `src` and never resolves through the
  `exports` map. The gate packs the tarball itself rather than letting `attw --pack`
  do it, because `npm publish --dry-run` exports `npm_config_dry_run`, a nested pack
  inherits it, and a dry pack writes no file — so the gate could not otherwise run
  from inside `prepublishOnly`, which is the one place standing between a manual
  `npm publish` and the registry.
- **`pnpm check:runtime`** packs the tarball, lays it out the way npm would, and
  loads every subpath from it in ESM _and_ CommonJS. `./nextjs` is excluded by
  design — it reaches `next/server`, which Next ships without an `exports` map, so
  a bare ESM specifier cannot resolve it outside a bundler, and under CommonJS it
  trips Next's own Server-Component guard. Both are Next's behaviour, not this
  package's.

- **Refresh-token reuse detection by family lineage** ([`src/server/redis/auth-redis.service.ts`](src/server/redis/auth-redis.service.ts), [`src/server/services/token-manager.service.ts`](src/server/services/token-manager.service.ts)). A login opens a family; every rotation inherits it; replaying a consumed token past its grace window revokes that lineage — and only that lineage. Previously a theft signed the user out of every device they owned. Platform rotation gains the same detection, which it never had.
- **Bulk access-token revocation by epoch** ([`src/server/redis/auth-redis.service.ts`](src/server/redis/auth-redis.service.ts)). A per-user generation counter replaces the `utc:` cutoff timestamp. The counter has no clock semantics — a token issued in the same second as a password reset was previously indistinguishable from one issued just before it — and does not depend on the token carrying a well-formed `iat`.
- **Cross-site request refusal** ([`src/server/guards/trusted-origin.guard.ts`](src/server/guards/trusted-origin.guard.ts)). `Origin` / `Sec-Fetch-Site` verification on cookie-authenticated writes. `SameSite` covers this for `lax`/`strict`; it does not for `SameSite=None`, which this library allows and which sends the session cookie cross-site. On by default; `cookies.trustedOrigins` is required as soon as `cookies.sameSite: 'none'` is set.
- **Breached-password refusal** ([`src/server/providers/hibp-breach-checker.provider.ts`](src/server/providers/hibp-breach-checker.provider.ts)). `IPasswordBreachChecker` with an opt-in `HibpBreachChecker` using Have I Been Pwned k-anonymity ranges: only a 5-character SHA-1 prefix leaves the process. Fails **open** by contract — an unreachable corpus must never stop someone changing their password. Off by default (`AllowAllBreachChecker`): it is the only part of the credential path that reaches the network.
- **Per-IP rate limiting enforced by the library** ([`src/server/guards/auth-rate-limit.guard.ts`](src/server/guards/auth-rate-limit.guard.ts), [`src/server/decorators/auth-rate-limit.decorator.ts`](src/server/decorators/auth-rate-limit.decorator.ts)). `AUTH_THROTTLE_CONFIGS` existed but was advisory: the numbers only applied if the host wired `ThrottlerModule`, and nothing said so. The refusal is now the library's own `auth.too_many_requests` envelope with `Retry-After`, matching what `rust-auth` already returned. On by default (`rateLimit.enabled`).
- **Absolute session lifetime** ([`src/server/services/token-manager.service.ts`](src/server/services/token-manager.service.ts)). `jwt.absoluteSessionLifetimeDays` caps how long one login can be extended by rotation. `refreshExpiresInDays` bounds a single token, not a session — a client rotating every fifteen minutes renews it forever. Off by default: switching it on ends sessions already older than the cap.
- **Startup validation of `jwt.accessExpiresIn` against the token-epoch retention window** ([`src/server/config/resolved-options.ts`](src/server/config/resolved-options.ts), [`src/server/constants/token-epoch.ts`](src/server/constants/token-epoch.ts)). The epoch is what makes a stateless access token revocable, and it only holds while the bumped value is still readable. An access token allowed to outlive the 30-day record sat past that: the lookup falls back to `0`, the staleness check stops firing, and a token a password reset had revoked verified again. The Redis TTL now derives from the same constant the validation reads, so the bound enforced and the bound honoured cannot drift. An unreadable time string or a non-positive lifetime is refused here too, rather than at the first token issued. `rust-auth` enforces the identical rule.
- **`server-only` guard on the Next.js JWT helper** ([`src/nextjs/helpers/jwt.ts`](src/nextjs/helpers/jwt.ts)). The module receives the HS256 secret; importing it from a Client Component is now a build error rather than a secret published to every visitor. Declared as an **optional peer dependency**, so the zero-direct-dependency rule holds and a consumer not using `./nextjs` installs nothing — install it alongside `next` if you do. `rust-auth`'s Next.js package guards its verifier the same way.

- **Single-use WebSocket upgrade tickets** ([`src/server/services/ws-ticket.service.ts`](src/server/services/ws-ticket.service.ts), [`POST {prefix}/ws-ticket`](src/server/controllers/auth.controller.ts)). The browser `WebSocket` API cannot set handshake headers, and `WsJwtGuard` refuses a token in the query string — correctly, since that writes a long-lived credential into access logs, browser history and proxy caches. Between the two, browser clients had no supported path, which in practice means the consumer writes the query-string token themselves. A ticket is the alternative: opaque, 30 seconds, consumed by the first redemption, and stored as a verified-identity snapshot with no `jti`, no signature and no expiry of its own — so it authorizes a socket and cannot be turned back into a session. Minting requires an authenticated session in good standing with its second factor already satisfied. `rust-auth` has authenticated its upgrades this way from the start; this closes the gap.

- **`rateLimit.clientIpSource`** (`'peer'` | `'trusted-proxy'`, **required** when rate limiting is enabled — `rateLimit` itself is now a required, discriminated option group, so the omission is a compile error and not only a startup one). The limiter keyed on `req.ip`, which honours Express's `trust proxy` setting: with it enabled — the usual configuration behind a proxy — `req.ip` is whatever the client wrote in `X-Forwarded-For` unless the hop count is exactly right, and a caller who chooses their own key is not limited at all. Reading the socket address instead is not a safe default either: behind any proxy it is the proxy's address for every client, so all of them share one bucket and a single caller sending a handful of logins locks out the whole user base, with no credential. Each value is a working limiter in one deployment and no limiter at all in the other, both look like a working limiter at runtime, and nothing detects the mismatch — so the deployment states which shape it is, or the module refuses to start. Pass `rateLimit.enabled: false` if the limits are enforced at the edge. `rust-auth` draws the same distinction (`ClientIpSource`) and requires it too.
- **`jwt.previousSecrets`** — secrets retired by a rotation, accepted for verification only. Rotating `jwt.secret` used to sign every user out at once **and** invalidate every stored recovery-code digest, which is keyed by an HMAC derived from that secret: users would lose the codes they printed and filed, and find out at the moment they most need them. Both stay readable while the old tokens drain. Signing always uses the current secret, so a rotation is one-way.
- **`mfa.previousEncryptionKeys`** ([`src/server/services/mfa.service.ts`](src/server/services/mfa.service.ts)) — AES-256 keys retired by a rotation of `mfa.encryptionKey`. The stored ciphertext carries no key identifier, so changing that key made every enrolled user's TOTP secret undecryptable at once, with no way back: the authenticator they set up simply stops matching, and nothing in the library could tell them why. A secret that opens under a retired key is now re-encrypted under the current one on the next successful challenge, so the rotation drains instead of requiring the retired key to stay configured forever — a key that still opens every stored secret is not retired. Every entry is held to the same bar as the current key at startup (base64, exactly 32 bytes, never equal to the current key or to another entry), because a malformed one would otherwise surface at a user's first challenge. Same option on both sides.

- **Startup bounds on the parameters that carry a control's strength** ([`src/server/config/resolved-options.ts`](src/server/config/resolved-options.ts)). `mfa.totpWindow` (`0..=10`), `mfa.recoveryCodeCount` (`1..=50`), `password.blockSize` (`>= 8`) and `password.parallelization` (`>= 1`) had no validation while every sibling parameter did. The window counts 30-second steps on _either_ side of now, so `2n + 1` codes are valid at once: at 60 that is 121, and a six-digit code becomes a hundred times easier to guess while the configuration still reads as "MFA enabled". Zero recovery codes enrols an account with no way back if the authenticator is lost. And scrypt's memory cost is `128 * N * r`, so a block size below 8 divides the hardness that `password.costFactor`'s floor exists to guarantee — invisibly, because the parameter that _is_ bounded stays intact. `rust-auth` enforces the identical ranges.

- **`tenantIdResolver` is now honoured by every tenant-scoped flow** ([`src/server/utils/resolve-tenant-id.ts`](src/server/utils/resolve-tenant-id.ts)). The option documents itself as ignoring the body's `tenantId` when a resolver is configured, "to prevent tenant spoofing" — but only `login` and `register` called it. Password reset (all four steps) and email verification (both) read the caller's value verbatim, so on a deployment that derives the tenant from the request, a caller on one tenant could drive reset and verification mail at accounts in another, and a reset started under the resolved tenant could never be completed because the two steps derived different identifiers. **Breaking:** `PasswordResetService`'s four methods and `AuthService.verifyEmail` / `resendVerificationEmail` now take the request as their final argument; the library's own controllers pass it. The resolution itself moved out of `AuthService` into a shared helper — one rule with two implementations is how the gap opened. `rust-auth` takes the same change as `&RequestContext`.

- **`POST /auth/logout` no longer requires a live access token** ([`src/server/controllers/auth.controller.ts`](src/server/controllers/auth.controller.ts)). The route sat behind `JwtAuthGuard`, so the overwhelmingly common case — a user returning after the 15-minute access token expired and clicking "sign out" — answered 401 and `logout` never ran: the refresh session, the long-lived credential logout exists to kill, stayed live for its full seven days on a device the user had just signed out. The refresh token is what authorizes the operation now, and the session's owner is read from the stored record rather than from the token's claims. The access token is still _verified_ (signature + pinned algorithm) before its `jti` is blacklisted, waiving only the expiry check — reading it unverified would let a caller blacklist a token they do not own by naming its id. **Breaking:** `AuthService.logout` drops its `userId` parameter and returns the revoked session's owner. `rust-auth` takes the same change.

- **MFA enrolment re-authenticates against the account password** ([`src/server/dto/mfa-setup.dto.ts`](src/server/dto/mfa-setup.dto.ts), [`src/server/services/mfa.service.ts`](src/server/services/mfa.service.ts)). `POST /mfa/setup` and `/platform/mfa/setup` were guarded by the access token alone, so a token lifted by XSS or from a shared machine could enrol an authenticator the attacker holds — and the enable then revokes every session and bumps the epoch, locking the real owner out of an account they still know the password to, with the recovery codes displayed only to the attacker. ASVS requires re-authentication before an authentication factor changes; `disable` already demanded a TOTP code. Gating `setup` rather than `verify-enable` means the attacker cannot even obtain a secret they control, at the cost of one prompt at the natural moment. An account provisioned purely through OAuth has no local password and is exempt — its credential belongs to the provider, which this library cannot re-verify inline. **Breaking:** `MfaService.setup` takes the password as a third argument and the two `setup` endpoints accept a `password` body field. `rust-auth` takes the same change.

- **The OAuth `state` is bound to the browser that started the flow** ([`src/server/oauth/oauth.service.ts`](src/server/oauth/oauth.service.ts), [`src/server/constants/oauth-state-cookie.ts`](src/server/constants/oauth-state-cookie.ts)). The `state` nonce was validated against Redis alone, which proves only that _somebody_ started a flow. An attacker could run their own authorization, complete consent at the provider, capture the resulting `?code=…&state=…` callback URL without visiting it, and lure the victim there: the victim's browser then received the attacker's session, and everything they did next — a payment method, an uploaded document, a linked account — landed in the attacker's hands. PKCE does not cover this, because the verifier is held server-side and replayed for whoever presents the state. `initiateOAuth` now plants the raw state as an HttpOnly cookie and the callback refuses any request that does not carry it back, as RFC 6749 §10.12 requires. The cookie is `SameSite=Lax` regardless of `cookies.sameSite` — the provider's callback is a cross-site top-level GET, and `strict` would withhold the cookie on exactly that hop — and the check runs _before_ the state is consumed, so a lured victim cannot burn a state the legitimate browser is still entitled to spend. **Consumers must mount `cookie-parser`** for the OAuth routes; without it every callback is refused. `rust-auth` takes the same change.

- **Session cookies are host-only unless `cookies.resolveDomains` says otherwise** ([`src/server/services/token-delivery.service.ts`](src/server/services/token-delivery.service.ts)). With no resolver configured the library derived the `Domain` attribute from the request host, and a cookie carrying `Domain=app.example.com` is sent to **every subdomain** of that name (RFC 6265 §5.2.3) — so the session was readable by a marketing site, a user-content host, or a stale DNS record someone else now answers for, on a deployment that never asked for any of that. The default is now no `Domain` attribute at all; sharing across subdomains stays available and is what `resolveDomains` is for. The logout clear follows the same rule, since a browser matches a deletion on name, domain and path. `rust-auth` is host-only by default too, and now actually honours its `resolve_domains` resolver, which it had been ignoring.

- **Six documented defaults corrected** ([`src/server/interfaces/auth-module-options.interface.ts`](src/server/interfaces/auth-module-options.interface.ts), [README](README.md)). `bruteForce.maxAttempts` documented `10` against a real `5`; `passwordReset.tokenTtlSeconds` documented `3600` against a real `600`; `emailVerification.required` documented `false` against a real `true`; and `controllers.sessions` / `.platform` / `.invitations` claimed to default on "when the feature is enabled" when all three are opt-in and refuse to mount without an explicit `true`. A consumer reading the JSDoc — the only place most of these are described — would size a lockout window, a reset window, and a login gate wrongly, and would wait for endpoints that were never going to appear.

- **The Next.js proxy refuses a token that is not an access token** ([`src/nextjs/internal/tokenState.ts`](src/nextjs/internal/tokenState.ts)). A valid signature was the only question asked, but the server signs several kinds of token with one key — including the short-lived `mfa_challenge` temp token, issued to a user who has proven their password and **not** their second factor. Moving that value into the access cookie walked past every proxy-protected page, which is precisely the state the second factor exists to stop. The upstream API rejected it all along, because its guards check `type`; the gap was the edge, where the page renders. The proxy now admits `dashboard` and `platform` and nothing else, matching `rust-auth`'s `ACCESS_TOKEN_TYPES`, which had this gate from the start.

- **`isSafeSameOriginPath` rejects every C0 control and DEL** ([`src/nextjs/helpers/routeHandlerUtils.ts`](src/nextjs/helpers/routeHandlerUtils.ts)), not just the CR / LF / NUL trio. Those three are the ones that smuggle a header; the others have no business in a path either, and enumerating the dangerous characters is the kind of allowlist-by-omission that only looks complete until someone finds the character nobody thought of.

- **The provider's error callback reaches the OAuth error handling instead of the `ValidationPipe`** ([`src/server/dto/oauth-callback-query.dto.ts`](src/server/dto/oauth-callback-query.dto.ts), [`src/server/oauth/oauth.controller.ts`](src/server/oauth/oauth.controller.ts)). RFC 6749 §4.1.2.1 defines a callback carrying `error` and no `code` — the response a provider sends when the user declines consent. The DTO required `code`, so a user who simply clicked "Cancel" got a raw validation envelope rather than the configured error redirect. `code` is now optional and the controller refuses a callback carrying neither it nor `error` on the same path. The provider's value is logged and never echoed: it is provider-chosen text that would otherwise land in a URL the browser follows, and `oauth_failed` already says everything the library is willing to vouch for. `rust-auth` takes the same change.

- **A second token-epoch bump extends the record's lifetime** ([`src/server/redis/auth-redis.service.ts`](src/server/redis/auth-redis.service.ts)). `bumpUserTokenEpoch` was built on the rate-limiter's `incrWithFixedTtl`, which applies the expiry only on the first increment — correct for a fixed window, wrong here. It anchored the 30-day retention to the _first_ bump a user ever took: a password reset on day 0 and a "sign out everywhere" on day 29 shared one expiry, the key vanished on day 30 while the tokens the second bump revoked were still inside their lifetime, and `getUserTokenEpoch` then answered `0` — under which `stamped < epoch` is false for every token and the revocation quietly stopped applying. `rust-auth` has always issued the unconditional `EXPIRE`; a shared Redis cannot have the two libraries disagree about when the key dies.

- **`initiateReset` shares the resend cooldown** ([`src/server/services/password-reset.service.ts`](src/server/services/password-reset.service.ts)). `resendOtp` was throttled and `initiateReset` was not, which made the throttle decorative — a caller just used the other door. It also made the OTP's 5-attempt ceiling per-issuance rather than per-account, because every issuance rewrites the record with `attempts: 0`: an attacker who knew an address could loop "initiate, guess five times" at a six-digit code indefinitely, mailing the victim once per lap. Both entry points now claim one budget under one key. `rust-auth` takes the same change.

- **The absolute session-lifetime cap is enforced on the grace-recovery path** ([`src/server/services/token-manager.service.ts`](src/server/services/token-manager.service.ts)). The check ran against the seed, and on that path the seed is the placeholder used when the live key is already gone — its `familyCreatedAt` is `now`, so the check compared `now - now` and always passed. A lineage that had just passed its cap could still mint a fresh access token and a full-length refresh session by presenting a token inside its grace window: the cap ended normal rotation and left the one remaining door open. `rust-auth` takes the same check on both planes.

- **`POST /auth/logout` and `POST /auth/ws-ticket` are rate-limited** (20/60s each, pinned in `conformance/wire-contract.json`). Logout became public in this cycle by necessity — a user whose access token expired has to be able to sign out — but public and unlimited are different things, and each call costs a SHA-256 and several Redis round trips for an unknown caller. `ws-ticket` is authenticated but writes a fresh single-use key per call.

- **The Next.js proxy strips the caller's identity headers on `/api/auth/*` too** ([`src/nextjs/createAuthProxy.ts`](src/nextjs/createAuthProxy.ts)). That arm returned before sanitisation ran, so a client-forged `x-user-id: admin` reached whatever the consumer mounts there — in direct contradiction of the module's own promise that a forged header cannot reach a server component via _any_ response path. `rust-auth`'s proxy had the same gap on its public-path arm and takes the same fix.

- **The OAuth state cookie is cleared only when the browser sent it** ([`src/server/oauth/oauth.controller.ts`](src/server/oauth/oauth.controller.ts)). The callback is a `GET`, so `SameSite=Lax` withholds the cookie from a cross-site subresource — an `<img src=…/callback>` carries none — but a `Set-Cookie` deleting it took effect anyway. Any page could therefore kill an OAuth login that was still at the consent screen, repeatably. The provider's `error` and the `provider` path segment are also no longer interpolated into a log line verbatim: both are attacker-controlled, and a newline in either forges whole log records.

- **Refresh re-reads the account and re-applies the status and email-verification gates** ([`src/server/services/auth.service.ts`](src/server/services/auth.service.ts)). Rotation worked entirely from the Redis record, so nothing on that path ever looked at the user again — and rotation is the door a signed-in caller actually uses. Two consequences, both in the default configuration. A banned or suspended account renewed its access token every fifteen minutes for the refresh token's whole seven days, because the ban closes only the login door (ASVS v5 §7.4.2 requires disabling an account to terminate its sessions). And an address that was never verified held an authenticated session **indefinitely**: `register` issues a session deliberately, this library's own specification bounds that window at one access-token lifetime, and rotation is what un-bounded it. Both gates now run on refresh, and a blocked account that touches the system has every session revoked and its epoch bumped in the same breath. The account is returned with the rotation, so the caller does not pay a second repository read.

- **`AuthService.revokeAllSessions(userId)`** — the dashboard twin of `PlatformAuthService.revokeAllPlatformSessions`. A library cannot see the moment a host suspends, bans, or deletes an account, so the host needs a supported way to say so; `SessionService.revokeAllExceptCurrent` could not serve, because it wants the hash of a session to keep and an administrator banning somebody else has none.

- **`POST /platform/logout` no longer requires a live access token** ([`src/server/controllers/platform-auth.controller.ts`](src/server/controllers/platform-auth.controller.ts)). The route sat behind `JwtPlatformGuard`, which refuses an expired token — so an operator who stepped away for longer than the fifteen-minute access lifetime could not sign out at all, and the seven-day refresh session of the highest-privilege identity in the system stayed live on a console they believed they had left. This is the same fix the dashboard plane took earlier in this cycle; the platform plane kept the old shape. The owner is now read from the stored record instead of the token's claims, and the access token is still verified — signature and pinned algorithm — before its `jti` is blacklisted. **Breaking:** `PlatformAuthService.logout` takes `(accessToken, rawRefreshToken)` and returns the revoked session's owner.

- **The absolute session-lifetime cap now covers the platform grace path too** ([`src/server/services/token-manager.service.ts`](src/server/services/token-manager.service.ts)). The check was added to the dashboard twin earlier in this cycle and not to its platform counterpart, which left the higher-privilege identity with the hole the dashboard one had just closed: the pre-script check runs against the seed, and on the grace path the seed is the placeholder used when the live key is gone — its `familyCreatedAt` is `now`, so the cap compared `now - now`.

- **`POST {prefix}/password/change` — authenticated password change** ([`src/server/controllers/password-reset.controller.ts`](src/server/controllers/password-reset.controller.ts), [`src/server/dto/change-password.dto.ts`](src/server/dto/change-password.dto.ts)). ASVS v5 §6.2.2 and §6.2.3 require it at **Level 1** — "users can change their password", and the change "requires the user's current and new password" — and it was the one credential operation this library did not own. Without it a consumer either sent users through the _unauthenticated_ recovery flow to rotate a password they already knew, or rebuilt the operation against a hash format the README forbids them to touch. The current password is what makes it safe: a session alone is not proof of identity, so a token lifted by XSS or from a shared machine could otherwise rotate the credential, lock the real owner out of an account they still know the password to, and keep the attacker in. Every other session ends on success and the token epoch is bumped (§7.4.3), while the caller's own session survives when the request carries its refresh token — so the device that made the change stays signed in.

- **`@Authenticated()`** ([`src/server/decorators/authenticated.decorator.ts`](src/server/decorators/authenticated.decorator.ts)) — un-exempts a single handler from a class-level `@Public()`. Until now that exemption was irreversible: the guards resolve the flag with `getAllAndOverride([handler, class])` and only `true` was ever written, so adding `@UseGuards(JwtAuthGuard)` to a method of a public controller changed nothing. The route mounted, the guard ran, and everyone was let through — a silent failure, and the reason the new change endpoint could not simply be added to the password controller.

- **`CommonPasswordChecker` is the default password screen** ([`src/server/providers/common-password-checker.provider.ts`](src/server/providers/common-password-checker.provider.ts)). NIST SP 800-63B §3.1.1.2 states a verifier **SHALL** compare a prospective secret against a blocklist of commonly used values, and ASVS v5 §6.2.4 asks for it at **Level 1**. The previous default, `AllowAllBreachChecker`, approved everything: a deployment on defaults accepted `password1` and `12345678`, and the brute-force machinery never fired, because a spraying campaign that tries one password across ten thousand accounts never crosses any single account's threshold. The new default is offline — no network call, so it can be on by default where the HIBP checker could not. It refuses the base words behind the bulk of real-world weak passwords, keyboard walks, repeats, sequential runs, and any _decorated_ form of those: `Password1`, `P@ssw0rd`, and `PASSWORD123!` all reduce to the same base, which is why a few hundred entries stand in for a list many times longer. It is a floor, not a corpus — `password.blocklist` adds the deployment's own context words (§6.2.11), and `HibpBreachChecker` remains the opt-in upgrade to a real breach corpus. `AllowAllBreachChecker` is still exported for a deployment with a deliberate reason to screen nothing.

- **Password-change notification** ([`src/server/interfaces/email-provider.interface.ts`](src/server/interfaces/email-provider.interface.ts)). `IEmailProvider` gains an optional `sendPasswordChangedNotification`, fired after both a completed change and a completed reset. NIST SP 800-63B §4.6 requires the subscriber to be notified through a channel independent of the transaction that bound the new credential, and this was the one credential change the interface stayed silent about while announcing every MFA change unprompted. The classic takeover starts with a compromised mailbox — trigger a reset, complete it, delete the mail — so the notice is what turns "the victim finds out days later, at a failed login" into "the victim finds out now". Optional, so an existing provider keeps compiling; delivery failures never fail the password change.

- **An invitation is re-validated against its inviter at redemption** ([`src/server/services/invitation.service.ts`](src/server/services/invitation.service.ts)). The inviter's authority was checked when the link was minted and never again, so for the token's whole 48-hour life the invitation outlived the person behind it: an admin could send one, be banned and stripped of their role, and the invitee would still arrive as an admin of that tenant with a live session. That is a clean way to keep a foothold across the account kill switch, which makes the switch advisory. The inviter must now still exist, still be in good standing, still belong to the tenant, and still out-rank the role being granted. `POST /invitations` also gains `UserStatusGuard`, closing the window in which a just-suspended admin could still mint one. `rust-auth` takes the same change.

- **A completed password change or reset invalidates the reset tokens issued beside it** ([`src/server/services/password-reset.service.ts`](src/server/services/password-reset.service.ts)). Each `forgot-password` writes its own `pw_reset:` key, so several can be alive at once — a 60-second cooldown against a 600-second TTL allows up to ten. Completing a reset with one left the others valid, which is the wrong end state precisely when it matters: a victim who resets _because_ an attacker read a link from their mailbox had not closed the link the attacker read, and the attacker could set the password again for the rest of the TTL. Each token now carries `passwordFingerprint` — a digest of the password hash in force when it was minted — and is refused once that no longer matches. The hash itself never leaves the repository. An absent field reads as "no binding" and is accepted, so a rolling deploy does not break the resets already in flight.

- **Revoking a named session cuts its access token too** ([`src/server/services/session.service.ts`](src/server/services/session.service.ts)). `DELETE /sessions/:id` deleted the refresh session, which stops rotation but says nothing about the stateless access token that device is already carrying — and that token kept working until it expired, up to whatever `jwt.accessExpiresIn` allows. Someone who opens their session list and revokes a device does so because they think it is compromised: a decision about _right now_. The new `SessionService.revokeOtherSession` bumps the token epoch, which is the only lever available since a session hash names no `jti`. The collateral is that the account's other devices re-mint their access token on the next rotation, which the shipped client does silently. `logout` deliberately keeps the plain `revokeSession`: it blacklists its own `jti` by name, and ending one session must not reach every other device.

- **Failure-side hooks: `onLoginFailed`, `onLockout`, `onRefreshTokenReuseDetected`** ([`src/server/interfaces/auth-hooks.interface.ts`](src/server/interfaces/auth-hooks.interface.ts)). Every one of the fourteen existing hooks fired on a success path, which left the failure side of authentication with no structured seam at all: a burst of wrong passwords, an account tripping its lockout, and a stolen refresh token being replayed existed only as English log lines whose wording is not a contract and whose change is not semver-visible. ASVS v5 §16.3.1 expects authentication operations to be logged with their outcome and §6.1.1 an _adaptive_ response, which needs a signal to adapt to. `onLoginFailed` carries the reason and — only when the account resolved — the user id, so a consumer can tell "someone is guessing at this account" from "someone is spraying addresses". `onLockout` fires on the attempt that _crosses_ the threshold, not the next one, because an attacker who trips the lock and walks away would otherwise never produce the event. `onRefreshTokenReuseDetected` is the strongest evidence of compromise the library produces: a token already exchanged has been presented again, so one of its two holders is not the owner.

- **Reuse detection can finally name its victim, and fires on the platform plane too**
  ([`src/server/redis/auth-redis.service.ts`](src/server/redis/auth-redis.service.ts)).
  `revokeFamily` now returns `{ removed, ownerId }` instead of a bare count. The owner could
  not be read any other way: the replayed token's own `rt:` key is deleted the moment it is
  rotated, so the previous lookup — `readSessionOwner('rt:' + sha256(oldRefresh))` — was
  reading a key that reuse detection guarantees is gone, and `onRefreshTokenReuseDetected`
  would have been skipped every time in production. The family index is the last surviving
  link between a replayed token and an account, and the revocation already reads a member
  record to find the session index it prunes. The platform rotation now emits the hook as
  well: an operator watching for account takeover cares about a replayed platform token at
  least as much as a dashboard one.

- **`POST /invitations/revoke` — withdrawing a pending invitation**
  ([`src/server/controllers/invitation.controller.ts`](src/server/controllers/invitation.controller.ts)).
  `controllers.invitations` has always been documented as "send, accept, **revoke** invitations"
  and there was no revoke: an invitation provisions an account, at a role, inside a tenant, to
  whoever holds the link — a credential in every sense — and once sent it stayed redeemable for
  its whole TTL with nothing an operator could do about it. A link sent to the wrong address was
  simply unrecoverable. ASVS v5 §6.1.1 expects an administrative path to invalidate a credential
  that should no longer work.

  The record is keyed by the hash of a token only the invitee's mailbox ever held, so nothing on
  the issuing side could _name_ a pending invitation. A new `invidx:{tenantId}:{sha256(email)}`
  index carries the invitation's TTL and points at its record; the email is hashed so a dump of
  the keyspace does not enumerate who a tenant has been inviting. Re-inviting an address now
  supersedes the previous invitation through that index rather than adding a second live token —
  two tokens for one invitee is two chances for an intercepted link, and a revoke would only ever
  have reached the newest. The revoker is held to the same bar as the issuer (in the tenant, in
  good standing, out-ranking the granted role), and the endpoint answers `204` whether or not
  anything was pending, so it cannot be used as an oracle for which addresses have invitations.

- **`AuthService.unlockAccount(email, tenantId)` — clearing a brute-force lockout**
  ([`src/server/services/auth.service.ts`](src/server/services/auth.service.ts)). A lockout is
  a denial of service the library imposes on its own users, and it could only be waited out:
  the counter is keyed by an HMAC of `{tenantId}:{email}` under the library's own `hmacKey`,
  which no consumer can derive, so a support desk facing "I am locked out and I need in now"
  had nothing to offer. The lockout is also the lever an attacker pulls to deny service to one
  specific account, which makes the ability to undo it part of the defence rather than a
  convenience (ASVS v5 §6.1.1). It grants no access — the password, the status gate, the
  verification gate and MFA all still apply; it restores the ability to _try_. No route ships
  with it, because who may unlock whom is a decision only the host application can make.
  `BruteForceService` is now exported for consumers building their own lockout tooling.

- **The session index is maintained by the rotation script, not after it**
  ([`src/server/redis/auth-redis.service.ts`](src/server/redis/auth-redis.service.ts)).
  `rotateRefreshSession` now takes the owner and does the `sess:{userId}` bookkeeping inside
  the Lua. Doing it in the service afterwards left a window between the atomic consume and the
  `SADD` in which "log out everywhere" could sweep the index without seeing the session the
  rotation had just minted: that session survived a revocation the user was told had happened,
  and went on rotating — re-stamping a fresh access token under every later epoch, so the token
  epoch did not contain it either. The window is attacker-aimable: a thief holding a stolen
  refresh token and refreshing in a loop is most likely to be mid-rotation exactly when a
  password reset is trying to evict them. Inside the script the two operations serialize —
  either the sweep sees the new member and revokes it, or the rotation runs after the sweep and
  finds no live key to rotate. Held byte-compatible with rust-auth, which rotates the same
  sessions.

  The grace-recovery path still writes its session after the script (the recovered identity is
  only known once the script has answered), so it keeps a much narrower version of this window.
  Unlike the primary path it cannot be summoned on demand — it is reachable only by a client
  retrying a rotation whose response it lost, inside a grace window measured in seconds.

- **A recovery code is claimed before it is accepted**
  ([`src/server/services/mfa.service.ts`](src/server/services/mfa.service.ts)). Consuming a
  recovery code is a read-modify-write against the consumer's user repository: the challenge
  reads the whole array, removes one entry, and writes the rest back. Two challenges landing
  together both read the array containing the code, both match it, and both write — one code
  minting two sessions, which is the one property a recovery code has. The library cannot make
  the consumer's repository atomic, because that repository is theirs and its atomicity is
  theirs to define; it can be atomic in the store it owns. A `SET NX` over
  `rcu:{hmac(plane:userId:code)}` claims the code, and the losing challenge reads as an invalid
  code — which is what a code already spent is. Same construction as the TOTP anti-replay
  marker, for the same reason: the key discloses neither the user nor the code, and binding the
  plane stops a dashboard user and a platform admin sharing an id from burning each other's
  codes. The marker is deliberately short-lived (5 minutes): it serializes a race, it is not
  the durable record of consumption, and outliving the repository write would turn a failed
  write into a code the account can see but can never use.

- **`jwt.issuer` and `jwt.audience` — binding tokens to who minted them and who they are for**
  ([`src/server/utils/verify-with-rotation.ts`](src/server/utils/verify-with-rotation.ts)).
  Optional and absent by default, so an existing deployment is unchanged. When set, the value
  is stamped on every token the backend mints — access, platform and MFA challenge alike — and
  **required** on every token it verifies: one carrying a different value, or none at all, is
  rejected. Accepting an unstamped token would give an attacker a way to opt out of the check
  simply by omitting the claim.

  This matters here specifically because HS256 means the verifier can also sign. Every service
  holding the secret to check a token can mint one, so audience binding is what stops a token
  minted for one service being replayed at another that trusts the same secret. It is opt-in
  because both backends of a shared deployment must carry the same pair or they stop accepting
  each other's tokens, and because turning it on invalidates the access tokens already in
  flight — a window of one access-token lifetime, which clients close by refreshing, since the
  refresh token is opaque and carries no claims.

  An empty string reads as unconfigured rather than as "require the empty issuer", so a
  consumer threading an unset environment variable through does not silently turn the check on
  and start minting tokens their own verifier rejects.

- **`createAuthValidationPipe` and `auth.validation`** ([`src/server/pipes/auth-validation.pipe.ts`](src/server/pipes/auth-validation.pipe.ts)). Nest's default rejection is `{ statusCode, message, error }`, while everything else this library throws answers `{ error: { code, message, details } }` — so a client parsing `error.code` needed a second parser, and the one shape it could not read was the one that says which field to fix. Every auth controller now mounts the shared pipe, which raises `auth.validation` with the per-field failures as `[{ field, message }]` under `error.details`. Same code and same shape `rust-auth` emits.
- **`AuthExceptionFilter` and `auth.internal`** ([`src/server/filters/auth-exception.filter.ts`](src/server/filters/auth-exception.filter.ts)). Opt-in, because a library does not get to decide how an application answers failures it did not raise. Registered, it gives every failure the library envelope: an `AuthException` passes through with its `details` intact, a body already in the envelope is left alone, any other `HttpException` keeps the status the application chose, and an unhandled throw answers `auth.internal` with the generic message — never the thrown one, which is the one path where a stack detail or a connection string would reach a response body. `rust-auth` answered `auth.internal` in its own envelope already.
- **`PlatformAuthService`, `InvitationService` and `EmailChangeService` are exported** ([`src/server/index.ts`](src/server/index.ts)). Every other service already was, for consumers driving a custom route; these three had the same reason to be.
- **`identifierPreimages`, `requestFieldBounds` and `errorCatalog` in the shared contract** ([`conformance/wire-contract.json`](conformance/wire-contract.json)). The preimages each backend HMACs, the length bounds every request DTO applies, and the full `auth.*` vocabulary with the codes that must never reach a client. Both conformance tiers assert against them by exercising the real derivations and the real validators, not by reading the numbers back to themselves. Writing the catalog down immediately found that `rust-auth`'s own catalog test was missing three codes it does emit.

### Changed

- **The release publishes with `npm publish` rather than `pnpm publish`.** pnpm 11
  does not send the registry's `readme` field; every package in this family
  published under it carries an empty one, which renders the npm page with no
  documentation. It already cost this family two corrective patch releases.
- **Dependabot groups the `github/codeql-action/*` bumps.** Split one per
  sub-action, merging any single one leaves the default branch with mismatched
  versions — `init` writes a config that `analyze` refuses to read back.

- **The stored password hash records the parameters it was written under** ([`src/server/services/password.service.ts`](src/server/services/password.service.ts)). The format is now `scrypt:{N}:{r}:{p}:{salt}:{derived}`. Without this a verify can only assume the cost configured today, which made `password.costFactor` unchangeable: raise it and every stored hash becomes unreproducible — every user locked out, irreversibly, because the value they were derived under is gone. No test could see it, because a suite that writes and reads inside one configuration never represents "written yesterday, read today under a new setting". `rust-auth` has always carried its parameters (PHC strings); this is the same guarantee.
- **Rehash on verify** ([`src/server/services/auth.service.ts`](src/server/services/auth.service.ts)). A hash written under weaker parameters is re-derived at the current cost after a successful login and stored, fire-and-forget. This is what makes raising the cost factor a migration rather than a mass invalidation — `rust-auth` had it, this side did not.
- **`mfaEnabled` is required on a stored session record.** It used to default to `false` when absent, which turns a truncated or corrupt record into a silent second-factor bypass: the gate refuses only a token whose claims say `mfaEnabled && !mfaVerified`, so a missing field reads as "no second factor here" and the rotated token clears every MFA-gated route. Refusing the record costs the holder a login; defaulting it costs the account. Same change on both sides.
- **The decoy derivation no longer reads a stored hash.** With parameters recorded per hash, a constant decoy would carry whatever they were the day it was generated, and the moment a deployment configured a different cost it would stop taking the same time as a real verify — reopening the timing oracle it exists to close. It derives under the configured parameters instead.

- **`OAuthProfile.emailVerified` is now required** ([`src/server/oauth/oauth.service.ts`](src/server/oauth/oauth.service.ts)). `createWithOAuth` was called with `emailVerified: true` unconditionally. There is no bug today — the one shipped plugin is Google's, and it refuses an unverified profile before building one — but the roadmap opens `oauth.plugins` for GitHub, Microsoft and Apple, and GitHub hands back unverified addresses. The field cannot be defaulted to `true` without reintroducing exactly that assumption. **Breaking** for anyone implementing a custom OAuth plugin.
- **`cookies.sameSite: 'none'` now requires `cookies.trustedOrigins`**, and the allowlist is refused only where it genuinely cannot be consulted ([`src/server/config/resolved-options.ts`](src/server/config/resolved-options.ts)). `'none'` with no list rejects every cross-site call, so that half is required. The inverse holds only for a single host: `lax` withholds the cookie cross-**site**, not cross-**origin**, so a deployment serving `app.example.com` and `api.example.com` from one `.example.com` cookie is same-site and the browser does send it — while `Sec-Fetch-Site: same-site` is not proof the request came from the app itself, so the guard falls through to the origin check. The list is therefore accepted whenever `cookies.resolveDomains` is configured, and still refused without one. **Breaking** for a deployment already on `SameSite=None`.
- **Signing out other devices now advances the token epoch** ([`src/server/services/session.service.ts`](src/server/services/session.service.ts)). Deleting a refresh session stops that device rotating, but its already-issued access token is stateless and kept verifying for the rest of its lifetime — up to `jwt.accessExpiresIn` of continued access on a device the user had just revoked. Someone doing that because they believe a device is compromised means now. The caller's own access token is invalidated too, and the caller is the one party who recovers instantly: their refresh session is the one deliberately preserved. **Behavioural** for a client without silent refresh, which sees one 401 after the call.
- **The default scrypt cost is `131072` (2¹⁷)**, OWASP's recommended minimum at `r=8, p=1`, up from `32768`. **Behavioural**: roughly 128 MiB and ~100 ms per hash. Lower `password.costFactor` deliberately if the memory is not there.
- **A duplicate registration now spends the same derivation as a new one** ([`src/server/services/auth.service.ts`](src/server/services/auth.service.ts)). Skipping it was cheaper and leaked: a taken address answered in single-digit milliseconds against ~100 ms for a free one, which enumerates accounts by clock regardless of the status code.
- **`revokeAllUserTokens` is removed** ([`src/server/services/token-manager.service.ts`](src/server/services/token-manager.service.ts)). The password reset names its two steps directly. **Breaking** for a consumer calling it.

- **Every OTP failure answers `auth.otp_invalid`, in the same time.** `forgot-password` answers the same whether or not the address exists — but it only writes an OTP record when it does, so `auth.otp_expired` for an absent record and `auth.otp_invalid` for a wrong code turned that uniform answer definitive after one extra request. `auth.otp_max_attempts` said the same thing more slowly, since only a record that exists can reach a ceiling. Both sentinels stay in the catalog as internal, diagnostic codes — the treatment `auth.token_expired` and `auth.token_revoked` already get. `rust-auth` collapses them the same way, and now derives the HTTP status from the wire code so the oracle does not survive as 429-vs-401.
- **The reset and verification flows canonicalize the address** ([`src/server/services/password-reset.service.ts`](src/server/services/password-reset.service.ts), [`src/server/services/auth.service.ts`](src/server/services/auth.service.ts)). Every control on them is keyed on `hmac(tenantId:email)` — the OTP record, its five-attempt ceiling, the resend cooldown — so a change of case was a change of key: the same six-digit code could be guessed five times per spelling, and one send per minute became one send per spelling. `login` and `register` had always canonicalized; the four reset doors and both verification doors had not. `rust-auth` normalizes on all of them, which is what made this a disparity rather than a shared blind spot.
- **The invitee index is keyed by an HMAC of the address** ([`src/server/services/invitation.service.ts`](src/server/services/invitation.service.ts)). It used a bare SHA-256, which an address carries far too little entropy to survive — and this key is the one handle anyone reading a keyspace dump has on who a tenant has been inviting, which is the reason every other identifier here is an HMAC. **Breaking for the keyspace:** invitations pending across the upgrade stay redeemable but can no longer be superseded or withdrawn by address. Same change on both sides, pinned by the contract.
- **OAuth runs the configured `tenantIdResolver`, and tells `onOAuthLogin` what it resolved** ([`src/server/oauth/oauth.service.ts`](src/server/oauth/oauth.service.ts)). Every other entry point already did, on the stated principle that a deployment deriving the tenant from the request has said the caller's value is not to be trusted — and this is the door that decides which tenant an account gets provisioned into. The resolved value goes into the state record, so the callback cannot be talked into a different one. The hook context now carries that tenant and the verified address: `onOAuthLogin` is the only place a deployment can enforce tenant membership, and it was being asked to decide without being told which tenant. **Breaking:** `initiateOAuth` takes the request as its third argument.
- **The new password is judged before any reset proof is spent** ([`src/server/services/password-reset.service.ts`](src/server/services/password-reset.service.ts)). Every proof is single-use and consumed atomically, so a breach-list rejection that arrived afterwards burned it: the caller was told their password was unacceptable and, in the same breath, that the credential they needed to fix it was gone. Same change on both sides.
- **`revokeInvitation` answers an outranked revoker exactly as it answers an address with nothing pending** ([`src/server/services/invitation.service.ts`](src/server/services/invitation.service.ts)). The caller names an address and nothing else, so `INSUFFICIENT_ROLE` said "there is a pending invitation here, at a role above yours" while `204` said "there is none" — an oracle any member could walk an address list through, and precisely the disclosure hashing the address into the index exists to prevent. The revoker's own standing is a fact about the caller, so it still refuses out loud, and now does so before any lookup.
- **The platform login password floors at 1, not 12** ([`src/server/dto/platform-login.dto.ts`](src/server/dto/platform-login.dto.ts)). A policy floor on a door that _proves_ a credential refuses an operator whose password predates the current policy — with a validation error rather than an authentication one — and tells an unauthenticated caller what the policy is before any key derivation runs. The dashboard login always floored at 1 and `rust-auth` bounds the field the same way. Blank is still refused.
- **Request bounds are held identical to `rust-auth`'s** and pinned by `requestFieldBounds`. The email-verification OTP is exactly six digits on both sides, which is the only length either backend issues.
- **`controllers` returned from `useFactory` is now a startup error** ([`src/server/bymax-auth.module.ts`](src/server/bymax-auth.module.ts)). Nest decides a module's shape before any factory runs, so the flags were read by nothing: the endpoints they were meant to enable were simply absent, surfacing as a 404 whose cause lives in a different object from the one the developer edited. It had been documented for as long as it existed; documentation is not a control.

### Removed

- **Every legacy-compatibility path in the credential surface.** The libraries are new and
  unreleased into production, so a parsing allowance for a corpus that does not exist is a
  widened input for nothing — and each of these sat in the credential-verification core, which
  is exactly where an unused branch is most expensive:
  - the parameterless `scrypt:{salt}:{hash}` password form,
  - the `scrypt:`-prefixed recovery-code digest, which cost one key derivation **per stored
    code** on every wrong submission — an amplifier reachable by anyone holding a temp token,
  - the UUID-v4 refresh-token shape,
  - and the corresponding `refreshTokenLegacy` / `recoveryCodeDigestLegacy` contract entries.

- **Five error codes nothing could emit.** `SESSION_EXPIRED` and `SESSION_LIMIT_REACHED` describe behaviours the library chose not to have — rotation answers `REFRESH_TOKEN_INVALID`, and the session cap evicts rather than refuses. `RECOVERY_CODE_INVALID` is unreachable on purpose: a wrong recovery code answers `MFA_INVALID_CODE`, so a caller cannot learn which kind of credential they guessed wrong. `PASSWORD_TOO_WEAK` is the DTO's job, and `PASSWORD_RESET_TOKEN_EXPIRED` was documented as unreachable by design. A code nothing can emit is a client branch that never fires. **Breaking** for a consumer switching on them; gone from both libraries.
- **`AuthRedisModule`** ([`src/server/redis/auth-redis.module.ts`](src/server/redis/auth-redis.module.ts)). It documented itself as imported by `BymaxAuthModule`, which registers `AuthRedisService` directly instead — reachable from nothing, and its own docblock said otherwise.
- **`sessions.evictionStrategy`.** A union of one value: a knob that configures nothing while looking like a choice. Eviction is still FIFO, and the caveat the option carried — that it is silent, so an attacker opening a session pushes a legitimate one out with no signal — moves onto the limit it actually describes.
- **The unreachable platform branches in the dashboard MFA controller** ([`src/server/controllers/mfa.controller.ts`](src/server/controllers/mfa.controller.ts)). `JwtAuthGuard` runs `assertTokenType(payload, 'dashboard')`, so a platform token never reaches it — the platform surface has its own controller. The tests that covered the arm were feeding the methods a payload the guard would have refused, which is how a branch stays at 100% while being unreachable.

### Fixed

- **CommonJS consumers resolved ESM type declarations, on every subpath.** The
  `exports` map declared a single `types` condition, so `require()` landed on
  `.d.ts` instead of the `.d.cts` that was being built all along — `attw` reports
  it as _Masquerading as ESM_ on all five subpaths of the published `1.0.11`.
- **`node10` type resolution failed outright**, the manifest carrying no `main`,
  `module`, `types` or `typesVersions`. A resolver that does not read the
  `exports` map found nothing at all. Each `typesVersions` entry lists the
  CommonJS declaration first and the ESM one as a fallback: a resolver old enough
  to ignore the `exports` map may also be old enough not to load a `.d.cts`, and
  would then find no declarations at all — the state `typesVersions` exists to
  prevent. TypeScript takes the first path that resolves, so nothing changes for a
  toolchain that understands `.d.cts`. `@types/react` 19 ships the same shape for
  TypeScript 5.0 and below.
- **Four README examples did not compile against the package they document.** The
  module-registration example omitted `rateLimit`, which is a required option group;
  the client example omitted `baseUrl` and a comment claimed it was needed only
  cross-origin, when `AuthClientConfig` requires it (a relative `'/api'` is what
  routes through the Next.js proxy); a component read `user.name` after checking
  `status`, which does not narrow the separate `user` field away from `null`; and the
  proxy example passed `process.env.JWT_SECRET` into an optional property, which
  `exactOptionalPropertyTypes` refuses. Every one of them is a type error the moment
  a reader pastes it. `pnpm check:published` compiles the README's snippets against
  `dist/`, and it was not run before.
- **`check:published` collected links from inside fenced code blocks.** An
  `<a href="${url}">` in an example email template is a string the example builds at
  runtime, not a link a reader can click, and the checker tried to resolve the
  placeholder as a repository path. It now reads the prose, as the anchor check
  already did.

- **The platform guard never read the token epoch back** ([`src/server/guards/jwt-platform.guard.ts`](src/server/guards/jwt-platform.guard.ts)). Platform access tokens have carried an `epoch` stamp since they were introduced — issuing reads `pep:{sub}` — but the guard never consulted it, so a platform epoch bump revoked nothing: the mechanism existed on the wire and was dead on the door. `rust-auth`'s verify has always enforced the admin epoch; the guard now mirrors `JwtAuthGuard` with the platform key.
- **An auth-state change now revokes the outstanding access tokens too** ([`src/server/services/mfa.service.ts`](src/server/services/mfa.service.ts), [`src/server/services/platform-auth.service.ts`](src/server/services/platform-auth.service.ts)). Enabling or disabling MFA, and the platform "log out everywhere", invalidated the refresh sessions but left every access token working to expiry. For MFA enable that is the worst possible window: every pre-enable token is stamped `mfaEnabled: false`, and the MFA gate refuses only `mfaEnabled && !mfaVerified` — so a stolen token kept clearing every MFA-gated route at the exact moment the user enabled a second factor because they suspected that theft. All three flows now advance the plane-scoped token epoch alongside the session sweep, the same rule the password-reset flow already applied. ASVS requires stateless tokens relied on for access control to be revocable on an auth-state change; same change on both sides.
- **Every auth response is stamped `Cache-Control: no-store`** ([`src/server/interceptors/no-store.interceptor.ts`](src/server/interceptors/no-store.interceptor.ts)). RFC 6749 §5.1 requires it on any response carrying a token, and a CDN or corporate proxy that caches a login response serves one user's tokens to the next caller. The Next.js proxy layer already set it on its own responses; nothing set it for consumers reaching the NestJS API directly. Applied per-controller via an interceptor (with `Pragma: no-cache` for HTTP/1.0 intermediaries) and pinned by a test that fails if a future controller forgets it. `rust-auth` stamps the identical headers via router middleware.
- **A grace pointer could resurrect a revoked lineage** ([`src/server/redis/auth-redis.service.ts`](src/server/redis/auth-redis.service.ts)). Reuse detection only proves the _replayed_ token's own pointer expired; a pointer planted by an earlier rotation of the same lineage can still be live, and recovering from it handed the thief back the family the revocation had just killed. A recovery now requires its family index to still exist. Red-checked: the test needs a three-token lineage to fail without the fix.
- **The MFA challenge did not re-check account status** ([`src/server/services/mfa.service.ts`](src/server/services/mfa.service.ts)). A temp token stays valid for its whole TTL, so an account blocked between the password step and the second factor could still complete the challenge.
- **Platform sessions shared the dashboard's Redis index** ([`src/server/redis/auth-redis.service.ts`](src/server/redis/auth-redis.service.ts)), so "sign out everywhere" on one plane could reach the other.
- **Recovery-code verification amplified CPU** ([`src/server/services/mfa.service.ts`](src/server/services/mfa.service.ts)) by running the KDF once per stored code; refresh tokens widened to the documented entropy.
- **The client parsed its own error shape rather than the server's envelope** ([`src/client/createAuthClient.ts`](src/client/createAuthClient.ts)), so `code` and `details` were lost on every failure.
- **Logout left the rotation grace pointer behind** ([`src/server/services/auth.service.ts`](src/server/services/auth.service.ts)). It deleted `rt:{hash}` but not `rp:{hash}`, so a refresh token that had already rotated and was still inside its grace window could recover into a fresh session _after_ the user logged out — logout was final only for a token that had not yet rotated. The platform plane already cleared its `prp:` twin.
- **An OAuth `create` onto an address that was already taken surfaced as a 500** ([`src/server/oauth/oauth.service.ts`](src/server/oauth/oauth.service.ts)). `findByOAuthId` cannot see an account that owns the address without being linked to this OAuth identity — a local registration, or a link to another provider — so the insert hit the repository's uniqueness constraint and became an opaque error. It is a conflict and it is actionable (sign in and link instead), so it answers **409 `auth.oauth_email_mismatch`**, the code and status `rust-auth` already returned. The concurrent case still reaches the constraint: `IUserRepository` is host-implemented and its errors are untyped.

- **Both login doors answered before proving the password** ([`src/server/services/auth.service.ts`](src/server/services/auth.service.ts), [`src/server/services/platform-auth.service.ts`](src/server/services/platform-auth.service.ts)). The status and email-verification gates ran ahead of the KDF, so a caller who never held the credential learned an account's moderation state from the error code alone — and learned it in single-digit milliseconds, because the derivation was skipped. A wrong password now answers `INVALID_CREDENTIALS` whatever the account's state is, and only the password holder is told why they still cannot sign in. Same change on both sides.
- **A tenant named `platform` shared the platform lockout counter.** The brute-force identifier was written out by hand at four call sites as `dashboard:${tenantId}:${email}`, while the platform door builds `platform:${email}` — and `tenantId` comes from the request body whenever no resolver is configured, which is the default. Nothing stopped the two preimages colliding, so five unauthenticated dashboard logins against an operator's address could lock that operator out of the console, repeatably, without the platform surface being touched — and a successful one cleared their lockout mid-attack. Both planes now derive through a single private helper, and the three preimages are pinned by the contract.
- **Platform rotation never re-read the admin** ([`src/server/services/platform-auth.service.ts`](src/server/services/platform-auth.service.ts)). It worked entirely from the session record, so blocking an administrator closed only the login door: they kept minting access tokens for the refresh token's whole lifetime, which ASVS v5 §7.4.2 asks a disable to end. A blocked or deleted admin now loses every platform session, including the one just minted.
- **Rotation froze the role and the tenant** ([`src/server/services/auth.service.ts`](src/server/services/auth.service.ts)). Claims were built from the session record written at login and inherited unchanged through every later rotation, so demoting an ADMIN to MEMBER, or moving a user between tenants, had no effect on a live session for up to seven days — while every role guard reads that claim. The gates above already re-read the account; the current authority was sitting there, unused. It is re-stamped now, and only when it differs.
- **The WebSocket guard leaked `TOKEN_REVOKED`** ([`src/server/guards/ws-jwt.guard.ts`](src/server/guards/ws-jwt.guard.ts)). `JwtAuthGuard` deliberately collapses a revoked token into `TOKEN_INVALID` so a caller cannot distinguish "valid until someone logged it out" from "never valid". The upgrade handshake is a cheaper place to ask that question, not a more private one.

### Tests

- **`responseBodies` joins the contract, and it caught a real one.** The tier covered stored
  records, claims and prefixes but never the client-facing payloads — the shapes a consumer's
  TypeScript actually describes. `rust-auth`'s generated type named the platform account `user`
  while its own adapter emitted `admin`, so a consumer reading `result.user` got `undefined` at
  runtime. Both sides now assert the login body per delivery mode, the platform body, the
  challenge and the ws-ticket against what each serializes. The cookie-mode entry is the
  load-bearing one: the tokens are in `Set-Cookie` so script cannot read them, and a refresh
  token repeated in the JSON body would make the HttpOnly flag decorative.
- **The conformance tier now covers every section of the shared contract.**
  `credentialFormats` was read as prose — the assertions checked that the agreement still said
  what it said, which a drift in the implementation leaves green — and `errorEnvelope` was not
  asserted at all. Both are now pinned against what the code actually does: a minted refresh
  token, a TOTP secret prepared the way `MfaService` prepares it, and a real serialized
  exception. The envelope assertion is what surfaced a live divergence: `rust-auth` was omitting
  `error.details` where this library sends `null`, so a client reading both backends saw two
  shapes for one meaning.

- **100% mutation score** ([docs/mutation_testing_results.md](docs/mutation_testing_results.md)) — 3,474 seeded faults killed, no survivors and nothing left uncovered, against a `break` threshold of 95. The pass closed 57 open mutants across 19 files; not one was a bug in the library, and every one was a test that could not see its own subject.
- **2,458 tests** at 100% coverage on all four metrics, including a conformance tier that reads `conformance/wire-contract.json` — the same file `rust-auth` reads — and an adversarial suite for the credential paths.

### Security

- **Peer floors raised to exclude known-vulnerable versions.** Three declared
  ranges admitted versions carrying published advisories:

  | Peer             | Was       | Now        | Advisories cleared                                                                                                                          |
  | ---------------- | --------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
  | `@nestjs/common` | `^11.0.0` | `^11.0.16` | [GHSA-cj7v-w2c7-cp7c](https://github.com/advisories/GHSA-cj7v-w2c7-cp7c) — remote code execution via the `Content-Type` header              |
  | `@nestjs/core`   | `^11.0.0` | `^11.1.18` | [GHSA-36xv-jgw5-4q75](https://github.com/advisories/GHSA-36xv-jgw5-4q75) — improper neutralization of special elements in downstream output |
  | `next`           | `^16.0.0` | `^16.2.11` | 37 advisories, worst high — SSRF in Server Actions and in rewrites, middleware/proxy bypasses, several DoS paths                            |

  A peer range is a statement about which versions this library supports. A floor
  below a published advisory tells a consumer that a vulnerable install is a
  supported one, and nothing in their tooling contradicts it — the install
  resolves cleanly and silently. Dependabot does not catch this: it audits what
  is installed in this repository, never what the package declares it supports.

  Each new floor is the highest first-patched version among the advisories that
  range admitted, which is what clears every one of them at once. No runtime
  behaviour changed.

## [1.0.11] - 2026-05-30

### Security

- **`tmp` forced to `>=0.2.6` via pnpm `overrides`** ([`package.json`](package.json)). The vulnerable `tmp` (`<0.2.6`) shipped transitively through `ioredis-mock` → `fengari` (dev-only). Dependabot cannot bump a sub-dependency, so its security update reported `security_update_not_possible`. The override resolves `tmp` to `0.2.7`, clearing the advisory. Dev-only — not present in the published bundle.

## [1.0.10] - 2026-05-26

### Added

- **`AuthService.issueTokensForUserId(userId, ip, userAgent)`** ([`src/server/services/auth.service.ts`](src/server/services/auth.service.ts)). Password-less token issuance for consumer apps that implement "silent workspace switch", "impersonate user", or any flow where ownership has already been proven through a different mechanism (typically: an authenticated JWT for a sibling user row sharing the same email). The method mirrors every status guard the password-login path applies — `ACCOUNT_SUSPENDED`, `ACCOUNT_BANNED`, `ACCOUNT_INACTIVE`, `PENDING_APPROVAL`, `EMAIL_NOT_VERIFIED` (when verification is required) — and additionally throws `MFA_REQUIRED` when the target user has MFA enabled, so the consumer is forced to route through `MfaService.challenge` rather than silently issuing a session with `mfaVerified: false` that the dashboard's `MfaRequiredGuard` would reject on every request.

  Side effects match `login()`: concurrent-session limit via `SessionService.createSession` when sessions are enabled, fire-and-forget `userRepo.updateLastLogin`, fire-and-forget `IAuthHooks.afterLogin`. **Authorisation is the caller's responsibility** — the method does NOT verify the calling identity has any relationship to `userId`. A consumer using this for workspace switch must enforce the ownership rule (typically: same-email between the calling session and the target user) before invoking.

  Use case for the example app: the workspace switcher needs to issue a session for the target tenant's `User` row (distinct row, same email) without forcing the user to re-type their password. The controller validates the email match against the current JWT, calls `issueTokensForUserId(targetUserId, ip, ua)`, then delivers the result via `TokenDeliveryService.deliverAuthResponse` (also newly exported — see below).

- **`TokenDeliveryService` now public** ([`src/server/index.ts`](src/server/index.ts)). Previously internal to the lib's own controllers. Exporting it gives consumer apps the only correct way to write the lib's auth cookies on a custom controller's response — replicating the cookie attribute set (`httpOnly`, `secure`, `sameSite`, paths, `maxAge`) inline would silently drift when the lib changes one of those values. Pair this with `AuthService.issueTokensForUserId` (above) or any future password-less path. Exports cover both the service class and the four response-shape types it returns: `BearerAuthResponse`, `BothAuthResponse`, `CookieAuthResponse`, `PlatformBearerAuthResponse`.

### Tests

- **8 new unit tests** in [`src/server/services/auth.service.spec.ts`](src/server/services/auth.service.spec.ts) covering `issueTokensForUserId`: happy path (active, verified, MFA off), `TOKEN_INVALID` on missing user, `ACCOUNT_SUSPENDED` propagation, `EMAIL_NOT_VERIFIED` when verification is required, `MFA_REQUIRED` for MFA-enabled targets, `SessionService.createSession` invocation when sessions are enabled, `afterLogin` hook fire-and-forget, `updateLastLogin` error swallow, `afterLogin` error swallow, and the no-hooks-configured branch.
- **104 test suites · 2153 tests · 100% statement / branch / function / line coverage** maintained (verified via `pnpm test:cov:all`).

### Notes on backward compatibility

Every addition is additive: no existing signature, return shape, or behaviour changes. Consumers that do not call `issueTokensForUserId` or `TokenDeliveryService` see zero change.

## [1.0.9] - 2026-05-26

### Fixed

- **OAuth + MFA cookie path now configurable for apps with `setGlobalPrefix`** ([`src/server/interfaces/auth-module-options.interface.ts`](src/server/interfaces/auth-module-options.interface.ts), [`src/server/config/default-options.ts`](src/server/config/default-options.ts), [`src/server/oauth/oauth.controller.ts`](src/server/oauth/oauth.controller.ts), [`src/server/controllers/mfa.controller.ts`](src/server/controllers/mfa.controller.ts)). Prior to v1.0.9, the OAuth callback planted the `mfa_temp_token` cookie with `Path` hard-derived from `routePrefix` (`/${routePrefix}/mfa`). When the consuming Nest app calls `app.setGlobalPrefix('api')`, the lib's routes mount at `/api/auth/mfa/challenge` — but the cookie path stayed at `/auth/mfa`, which the browser refuses to send on requests under `/api/auth/mfa/...` per RFC 6265 prefix-match. The OAuth-driven MFA flow was silently broken end-to-end: cookie set, cookie dropped, every subsequent challenge attempt surfaced as `MFA_TEMP_TOKEN_INVALID` ("MFA session expired") because the controller received no token at all. The lib could not detect this — the global prefix is configured on the Nest app instance after the auth module is constructed, so it is not observable at option resolution time.

  A new `cookies.mfaTempCookiePath?: string` option lets the consumer set the exact `Path` attribute used when the OAuth callback plants the temp cookie and when the MFA challenge controller clears it. Defaults to `'/auth/mfa'` — correct when the lib's routes are mounted at the application root. Apps that call `app.setGlobalPrefix('api')` MUST set this to `'/api/auth/mfa'`. The default keeps existing consumers without a global prefix on the path that worked for them in v1.0.7+; only consumers with a Nest global prefix need to opt in.

  Both call sites (`OAuthController.setMfaTempCookie` and `MfaController.clearMfaTempCookie`) now read from `options.cookies.mfaTempCookiePath` instead of computing `/${routePrefix}/mfa` inline. This also means the set + clear paths can never diverge — the browser uses the path attribute to scope cookie deletion, so a mismatch between set and clear would leave dead cookies in the jar.

  **Backward compatibility**: every existing consumer that did NOT use OAuth + MFA continues to work unchanged. Consumers that DID use OAuth + MFA AND did NOT use `setGlobalPrefix` see no change (default `'/auth/mfa'` matches what they had). Consumers that DID use both and ARE using a global prefix had a silently-broken flow before v1.0.9 — setting `cookies.mfaTempCookiePath` fixes it.

### Tests

- **Updated existing `mfa.controller.spec.ts` and `oauth.controller.spec.ts` fixtures** to surface `cookies.mfaTempCookiePath` on the mocked `ResolvedOptions`. The dedicated path-attribute test that previously pinned the value via `routePrefix: 'api/auth'` is reframed to pin it via `cookies.mfaTempCookiePath: '/api/auth/mfa'`.
- **104 test suites · 2143 tests · 100% statement / branch / function / line coverage** maintained (verified via `pnpm test:cov:all`).

## [1.0.8] - 2026-05-26

### Fixed

- **MFA challenge retry — wrong TOTP no longer invalidates the temp token** ([`src/server/services/token-manager.service.ts`](src/server/services/token-manager.service.ts), [`src/server/services/mfa.service.ts`](src/server/services/mfa.service.ts), [`src/server/controllers/mfa.controller.ts`](src/server/controllers/mfa.controller.ts)). Prior to v1.0.8, `TokenManagerService.verifyMfaTempToken` used an atomic Redis `GETDEL` as its FIRST step — so a single mistyped TOTP digit consumed the JWT, and the user's retry attempt always failed with `MFA_TEMP_TOKEN_INVALID` ("MFA session expired. Please sign in again.") regardless of whether the next code was correct. Affected both flows: the password-login path (sessionStorage temp token) and the OAuth-driven path (HttpOnly cookie temp token added in v1.0.7). The only recovery was to re-drive the whole login or OAuth flow on every typo.

  `verifyMfaTempToken` now uses a non-destructive `GET` and returns the token's `jti` claim alongside `userId` / `context`. A new sibling method `consumeMfaTempToken(jti)` performs an idempotent `DEL` and is invoked by `MfaService.challenge` only AFTER the TOTP / recovery code has been validated. Wrong codes throw `MFA_INVALID_CODE` with the JWT still alive in Redis — the user can retry inside the existing 5-minute TTL. The brute-force counter (`bruteForce.recordFailure` keyed on `challenge:${userId}`) caps how many wrong attempts can be tried under one token before the account is locked, so the security model is unchanged at the boundary.

  The TOCTOU race the original `GETDEL` was designed to prevent (two concurrent successful submissions both completing) collapses into a benign duplicate: two valid sessions for the same legitimate user, not a privilege escalation. Defence-in-depth: the JWT itself is signed and short-lived (5 min), so a stolen token cannot be replayed beyond its TTL, and the brute-force lockout caps the attacker's TOTP-guessing window the same way it caps a legitimate user's typo budget.

  The OAuth-MFA controller's cookie-clearing policy now matches the retry-friendly service contract:
  - On success → clear the (now-consumed) `mfa_temp_token` cookie.
  - On `MFA_TEMP_TOKEN_INVALID` → clear the cookie (token is dead, retry impossible — surface that physically in the jar).
  - On `MFA_INVALID_CODE`, `ACCOUNT_LOCKED`, transient errors → KEEP the cookie so the user can retry without re-driving OAuth.

  **Backward compatibility**: `verifyMfaTempToken`'s public return shape gained a third field (`jti`); callers that destructured only `userId` and `context` continue to compile and run unchanged. The new `consumeMfaTempToken` method is additive. Existing throttle limits, brute-force thresholds, error codes, and cookie attributes are untouched. The `MFA_TEMP_TOKEN_INVALID` shape and HTTP status are identical for every legitimately-expired/forged token.

### Tests

- **3 new unit tests** in [`src/server/services/token-manager.service.spec.ts`](src/server/services/token-manager.service.spec.ts) covering `consumeMfaTempToken`: deletes the `mfa:{sha256(jti)}` entry, hashes the `jti` (never persists it raw), idempotent on repeat calls.
- **Updated existing `verifyMfaTempToken` tests** to assert the new GET-not-GETDEL contract and the new `jti` in the return shape.
- **4 new unit tests** in [`src/server/controllers/mfa.controller.spec.ts`](src/server/controllers/mfa.controller.spec.ts) covering the cookie-clearing matrix: keep on `MFA_INVALID_CODE`, keep on `ACCOUNT_LOCKED`, clear on `MFA_TEMP_TOKEN_INVALID`, keep on a non-`AuthException` transient error.
- **Updated existing integration smoke tests** (`mfa-integration.spec.ts`, `mfa.service.spec.ts`) to mock the split `verifyMfaTempToken` + `consumeMfaTempToken` flow.
- **104 test suites · 2142 tests · 100% statement / branch / function / line coverage** maintained (verified via `pnpm test:cov:all`).

## [1.0.7] - 2026-05-26

### Added

- **OAuth + MFA challenge flow** ([`src/server/oauth/oauth.service.ts`](src/server/oauth/oauth.service.ts), [`src/server/oauth/oauth.controller.ts`](src/server/oauth/oauth.controller.ts), [`src/server/controllers/mfa.controller.ts`](src/server/controllers/mfa.controller.ts)). When an MFA-enabled user authenticates via OAuth, the callback no longer issues a session directly — the resulting JWT would carry `mfaVerified: false`, which the global `MfaRequiredGuard` rejects on every subsequent request, leaving the user effectively locked out. `OAuthService.handleCallback` now branches on `authUser.mfaEnabled` and returns an `OAuthMfaChallengeResult` (`{ mfaRequired: true, mfaTempToken }`) instead. The MFA temp token is issued via the same `TokenManagerService.issueMfaTempToken` path the password-login flow uses, so no additional service dependency is introduced.

  The controller plants the temp token in a short-lived HttpOnly `mfa_temp_token` cookie scoped to `Path=/${routePrefix}/mfa` (5-minute `Max-Age` exactly matching the underlying JWT TTL, `Secure`/`SameSite` derived from `secureCookies`/`cookies.sameSite`). With the new `oauth.mfaRedirectUrl?: string` option configured the callback follows up the cookie with a 302 to that URL; without it, the same temp token is also surfaced as `{ mfaRequired: true, mfaTempToken }` in the JSON body so SPA consumers can drive the redirect themselves. The cookie is HttpOnly so it cannot be read from JavaScript — the JSON fallback is the explicit handshake for clients that need the value.

  The dashboard `MfaController.challenge` route gains a cookie fallback: when `dto.mfaTempToken` is missing, the controller reads `mfa_temp_token` from `req.cookies` and forwards it to `MfaService.challenge`. The body value continues to win when both are present, preserving the existing sessionStorage password-login contract. The cookie is cleared whenever it is present in the jar at challenge time — regardless of whether the cookie or the body drove the call. Rationale: `verifyMfaTempToken` GETDELs the Redis entry as its first step, so on ANY outcome (success, `MFA_INVALID_CODE`, `ACCOUNT_LOCKED`) the token in the cookie is already dead; leaving it would only invite a misleading `MFA_TEMP_TOKEN_INVALID` on a retry. A retry needs the user to re-drive the OAuth flow to mint a fresh token. `MfaChallengeDto.mfaTempToken` is now `@IsOptional()` to support the cookie-only request shape — passing the field continues to work unchanged. The platform `/platform/mfa/challenge` endpoint surfaces `MFA_TEMP_TOKEN_INVALID` directly when the field is omitted (platform admins do not participate in the OAuth + MFA flow).

  A new `OAuthMfaChallengeResult` interface is exported from [`src/server/interfaces/auth-result.interface.ts`](src/server/interfaces/auth-result.interface.ts) and the public surface in [`src/server/index.ts`](src/server/index.ts). Structurally identical to `MfaChallengeResult` but kept as a distinct type so downstream consumers can write OAuth-specific type guards without coupling to the password-login challenge type.

- **`oauth.mfaRedirectUrl?: string` configuration option** ([`src/server/interfaces/auth-module-options.interface.ts`](src/server/interfaces/auth-module-options.interface.ts), [`src/server/config/resolved-options.ts`](src/server/config/resolved-options.ts)). New optional URL the browser is redirected to after the OAuth callback determines that an MFA challenge is required. Validated at startup with the same shape rules as `successRedirectUrl` (non-empty string, HTTPS or same-origin path in production). Unlike `successRedirectUrl`, this option is compatible with every `tokenDelivery` mode because no session token travels through the redirect — only the dedicated `mfa_temp_token` cookie carries credential material on this leg.

- **`oauth.errorRedirectUrl?: string` configuration option** ([`src/server/interfaces/auth-module-options.interface.ts`](src/server/interfaces/auth-module-options.interface.ts), [`src/server/oauth/oauth.controller.ts`](src/server/oauth/oauth.controller.ts), [`src/server/config/resolved-options.ts`](src/server/config/resolved-options.ts)). Symmetric polish for `successRedirectUrl`: when an `AuthException` propagates out of `OAuthService.handleCallback` (provider error, hook reject, invalid state, etc.) the controller redirects to the configured URL with `?error=<code>` appended (e.g. `?error=oauth_failed`). Existing query parameters on the URL are preserved via the WHATWG `URL` constructor. Non-`AuthException` errors are deliberately NOT swallowed — they propagate so monitoring tooling can surface programmer/infrastructure bugs. Same startup validation as the other two redirect URLs (non-empty, production HTTPS, same-origin path allowed).

### Tests

- **5 new unit tests** in [`src/server/oauth/oauth.service.spec.ts`](src/server/oauth/oauth.service.spec.ts) covering the MFA branch (create + link actions, log line shape, session NOT created on the MFA branch).
- **8 new unit tests** in [`src/server/oauth/oauth.controller.spec.ts`](src/server/oauth/oauth.controller.spec.ts) covering: MFA cookie + JSON branch, MFA cookie + 302 (`mfaRedirectUrl`), cookie `Path` shaped by `routePrefix`, error redirect with code extraction, absolute-URL error redirect with existing query params, `AuthException` rethrow when no `errorRedirectUrl` is set, non-`AuthException` errors propagate, error-code fallback paths.
- **8 new unit tests** in [`src/server/controllers/mfa.controller.spec.ts`](src/server/controllers/mfa.controller.spec.ts) covering: cookie-sourced challenge, body-over-cookie precedence, `clearCookie` on cookie-sourced success, no clear on body-sourced success, no clear on challenge failure, `MFA_TEMP_TOKEN_INVALID` when neither source carries a token, non-string cookie defence.
- **1 new unit test** in [`src/server/controllers/platform-auth.controller.spec.ts`](src/server/controllers/platform-auth.controller.spec.ts) pinning that the platform endpoint rejects empty `mfaTempToken` directly.
- **15 new unit tests** in [`src/server/config/resolved-options.spec.ts`](src/server/config/resolved-options.spec.ts) covering `mfaRedirectUrl` and `errorRedirectUrl` validation (empty rejection, production HTTPS, same-origin path, dev HTTP allowed, no-throw when absent, bearer compatibility for `mfaRedirectUrl`, and one combined-options scenario).
- **5 new e2e tests** in [`test/e2e/oauth-flow.e2e-spec.ts`](test/e2e/oauth-flow.e2e-spec.ts) covering the full lifecycle: MFA-enabled OAuth user without `mfaRedirectUrl` (cookie + JSON), cookie-only challenge completion through `POST /mfa/challenge`, MFA-enabled OAuth user with `mfaRedirectUrl` (cookie + 302), OAuth error redirect with `errorRedirectUrl` set, OAuth error JSON when `errorRedirectUrl` is absent.
- **Backward compatibility**: every existing test continues to pass without modification (1992 → 2027 unit tests, 102 → 107 e2e tests). 100% statement / branch / function / line coverage maintained across every source file (verified via `pnpm test:cov`).

### Notes on backward compatibility

Every new option is optional and defaults to `undefined`. Existing consumers that do not opt in see ZERO behaviour change:

- `OAuthService.handleCallback` still returns `AuthResult` for non-MFA users; the union widening to `AuthResult | OAuthMfaChallengeResult` is additive.
- `OAuthController.callback` still returns the JSON body (or the `successRedirectUrl` 302) for non-MFA users; the MFA and error redirect branches only activate when the new options are set.
- `MfaChallengeDto.mfaTempToken` becoming `@IsOptional()` does not break callers that pass the field — the validator still rejects oversized / non-string values and the service-layer error path is unchanged when the field is absent (now surfaces `MFA_TEMP_TOKEN_INVALID` directly instead of forwarding `undefined`).

## [1.0.6] - 2026-05-26

### Added

- **MFA recovery code regeneration endpoint** ([`src/server/services/mfa.service.ts`](src/server/services/mfa.service.ts), [`src/server/controllers/mfa.controller.ts`](src/server/controllers/mfa.controller.ts), [`src/server/dto/mfa-regenerate-recovery-codes.dto.ts`](src/server/dto/mfa-regenerate-recovery-codes.dto.ts)). New `POST /mfa/recovery-codes` route on the dashboard `MfaController` (and `POST /platform/mfa/recovery-codes` on the new `PlatformMfaController` — see Feature B below) lets an MFA-enabled user rotate their recovery code list without having to disable + re-enrol MFA. The endpoint requires a valid TOTP code (recovery codes are intentionally NOT accepted as the proof factor — a user who has lost their authenticator should disable and re-enrol so the TOTP secret rotates too). Returns the fresh plain-text codes once; only their scrypt hashes are persisted. Shares the `mfaDisable` throttle config and the `disable:` brute-force counter namespace, mirroring the security posture of the disable endpoint.

  A companion lifecycle hook `IAuthHooks.afterMfaRecoveryCodesRegenerated(user, context)` ([`src/server/interfaces/auth-hooks.interface.ts`](src/server/interfaces/auth-hooks.interface.ts)) fires after a successful rotation (fire-and-forget — hook errors do not undo the DB write). Existing hook implementations are unaffected because the new method is optional, exactly like every other `IAuthHooks` lifecycle method.

  **Backward compatibility**: the dashboard `MfaController` adds a new route only — no existing route changes shape, no existing DTO gains or loses fields, no existing hook callsite changes. Consumers that do not add the new hook continue to work unchanged.

- **Platform admin MFA enrolment / disable / recovery-code surface** ([`src/server/controllers/platform-mfa.controller.ts`](src/server/controllers/platform-mfa.controller.ts), [`src/server/bymax-auth.module.ts`](src/server/bymax-auth.module.ts)). New `PlatformMfaController` mounted under `/platform/mfa/*` when `controllers.platform: true` is set, mirroring the dashboard `MfaController` routes (`setup`, `verify-enable`, `disable`, `recovery-codes`) but protected by `JwtPlatformGuard` instead of `JwtAuthGuard`. Closes the previous gap where platform admins could authenticate against a pre-existing MFA secret via `/platform/mfa/challenge` but had no in-lib endpoint to enrol, disable, or rotate that secret — host applications were forced to reimplement the entire flow.

  `MfaService.setup()` and `MfaService.verifyAndEnable()` now accept the same `context: 'dashboard' | 'platform' = 'dashboard'` parameter the existing `disable()` already shipped. The internal routing reads from `userRepo` or `platformUserRepo` based on this flag, matching the existing `disable()` pattern. A misconfiguration guard fires fast: if `context === 'platform'` is passed but `BYMAX_AUTH_PLATFORM_USER_REPOSITORY` was not provided in `extraProviders`, the call throws `MFA_NOT_ENABLED` instead of silently falling back to the dashboard repo (which would persist a platform admin's MFA secret on the wrong table).

  **Backward compatibility**: the new `context` parameter has a default of `'dashboard'`, so existing callers continue to work without changes. The dashboard `MfaController.setup` and `MfaController.verifyEnable` routes pass no `context` argument (dashboard remains the default). The `PlatformMfaController` is registered conditionally — only when `controllers.platform: true` — alongside the existing `PlatformAuthController`, so consumers who do not opt into the platform surface see no change in registered routes.

### Tests

- **15 new unit tests** across `mfa.service.spec.ts` (8: platform context branches for `setup`, `verifyAndEnable`, and the full `regenerateRecoveryCodes` happy path + 6 negative paths) and `mfa-regenerate-recovery-codes.dto.spec.ts` (6: 6-digit acceptance, empty/short/long/non-digit/recovery-shape rejection).
- **6 new unit tests** in `mfa.controller.spec.ts` for the new `POST /mfa/recovery-codes` route (delegation, platform-context routing, empty IP/UA fallback, MFA_NOT_ENABLED / MFA_INVALID_CODE / ACCOUNT_LOCKED propagation).
- **14 new unit tests** in the new `platform-mfa.controller.spec.ts` exercising every route on the platform MFA controller.
- **1 new unit assertion** in `bymax-auth.module.spec.ts` pinning that `PlatformMfaController` is registered alongside `PlatformAuthController` when `controllers.platform: true`.
- **11 new e2e tests** in [`test/e2e/mfa-recovery-codes-flow.e2e-spec.ts`](test/e2e/mfa-recovery-codes-flow.e2e-spec.ts): full dashboard regenerate flow (old codes rejected via /mfa/challenge, new codes accepted), wrong-TOTP and MFA-not-enabled negative paths, and the platform enrol → mfa-required-login → challenge → rotate / disable lifecycle including dashboard-token rejection by `JwtPlatformGuard`.
- Existing 1948 unit + 91 e2e tests continue to pass unchanged. 100% statement / branch / function / line coverage maintained across every source file (verified via `pnpm test:cov:all`).

## [1.0.5] - 2026-05-25

### Changed

- **Default `cookies.sameSite` lowered from `'strict'` to `'lax'`** ([`src/server/config/default-options.ts`](src/server/config/default-options.ts), [`src/server/services/token-delivery.service.ts`](src/server/services/token-delivery.service.ts)). The previous `'strict'` default broke the OAuth return-trip: Chromium does not include `SameSite=Strict` cookies on the very first request after a cross-site-initiated navigation (e.g. `accounts.google.com → /auth/oauth/google/callback → /dashboard`), so the freshly-issued auth cookies never reached the destination route. The `'lax'` default mirrors what Chromium applies to cookies that omit the attribute entirely and is the industry posture for browser auth cookies (Passport, Auth0, NextAuth all default to or expect Lax). The CSRF margin loss is negligible — POST endpoints are still cross-site safe under Lax, and the lib already short-circuits forgery vectors with origin checks at the controller boundary.

  This is a **behavior change** for consumers that relied on the `'strict'` posture; they can restore it explicitly with `cookies.sameSite: 'strict'`. SemVer-wise this is a patch because the previous behavior broke a documented feature (OAuth callbacks).

### Added

- **`cookies.sameSite?: 'lax' | 'strict' | 'none'` configuration option** ([`src/server/interfaces/auth-module-options.interface.ts`](src/server/interfaces/auth-module-options.interface.ts)). Lets consumers explicitly pick the SameSite posture for every cookie the module issues (access token, refresh token, session signal). Defaults to `'lax'` (see Changed above).

  Validated at startup by [`src/server/config/resolved-options.ts`](src/server/config/resolved-options.ts): `cookies.sameSite: 'none'` requires `secureCookies: true` (browser-spec rule — `SameSite=None` cookies without `Secure` are silently dropped, which would surface as "auth doesn't work" instead of a configuration error).

  Covered by 3 new unit tests in [`src/server/services/token-delivery.service.spec.ts`](src/server/services/token-delivery.service.spec.ts) (default propagates, explicit `'strict'` overrides, explicit `'none'` propagates) and 5 new validator tests in [`src/server/config/resolved-options.spec.ts`](src/server/config/resolved-options.spec.ts) (default to `'lax'`, explicit override, `'none' + secureCookies: true` accepted, `'none' + secureCookies: false` rejected, `'none'` accepted in production via `NODE_ENV`-driven default). One existing e2e cookie-header assertion in [`test/e2e/auth-flow.e2e-spec.ts`](test/e2e/auth-flow.e2e-spec.ts) updated to match the new default; the rest of the suite continues to pass unmodified.

## [1.0.4] - 2026-05-25

### Added

- **`oauth.successRedirectUrl?: string` configuration option** ([`src/server/interfaces/auth-module-options.interface.ts`](src/server/interfaces/auth-module-options.interface.ts), [`src/server/oauth/oauth.controller.ts`](src/server/oauth/oauth.controller.ts)). When set, `GET /auth/oauth/:provider/callback` issues a `302` redirect to the configured URL after delivering tokens, instead of returning the JSON body that API/SPA consumers expect. Cookies are still set on the same response — the destination page lands fully authenticated. This closes a UX gap that left browser users on the JSON payload after a successful OAuth round-trip (every consumer was forced to reimplement the OAuth controller just to get a redirect). The option is opt-in and the legacy JSON-body contract is preserved when it is omitted. Aligns the lib with `passport.successRedirect`, `next-auth.callbackUrl`, and `auth0.returnTo`.

  Validated at startup by [`src/server/config/resolved-options.ts`](src/server/config/resolved-options.ts) with three rules:
  1. Must be a non-empty string when set.
  2. Must use `https://` or be a same-origin path (`/...`) in production — HTTP rejected so the post-callback leg cannot strip cookie `Secure` guarantees.
  3. Requires `tokenDelivery: 'cookie'` or `'both'` — `bearer` is rejected because the 302 would discard the JSON body that carries the access token.

  Covered by 3 new unit tests in [`src/server/oauth/oauth.controller.spec.ts`](src/server/oauth/oauth.controller.spec.ts), 7 new validator tests in [`src/server/config/resolved-options.spec.ts`](src/server/config/resolved-options.spec.ts), and 2 new e2e scenarios in [`test/e2e/oauth-flow.e2e-spec.ts`](test/e2e/oauth-flow.e2e-spec.ts) (cookie-attached 302 to the configured URL + Set-Cookie headers on the redirect response).

## [1.0.3] - 2026-05-25

### Fixed

- **OAuth callback accepts standard provider query parameters** ([`src/server/dto/oauth-callback-query.dto.ts`](src/server/dto/oauth-callback-query.dto.ts)). Previously the controller-level `ValidationPipe(forbidNonWhitelisted: true)` paired with a `code` + `state`-only DTO rejected real-world Google callbacks with `HTTP 400 — property iss should not exist` because Google appends `iss` (OAuth 2.0 Issuer Identification, RFC 9207), `scope` (RFC 6749 §3.3 echoed grants), `authuser` (Google Account-chooser index), `prompt` (which prompt was shown), and `hd` (Workspace hosted-domain) to the redirect. The DTO now declares all five as `@IsOptional()` strings with sensible `@MaxLength` bounds — the values are validated for shape and ignored by the service. Covered by a new e2e scenario in [`test/e2e/oauth-flow.e2e-spec.ts`](test/e2e/oauth-flow.e2e-spec.ts) that submits the exact param set Google sends. No breaking change — existing `code` + `state`-only callbacks continue to work.

### Tests — E2E coverage (audit-driven, surface gaps closed)

A systematic audit of `test/e2e/` against the lib's HTTP surface identified
several uncovered scenarios. Each new spec exercises real routes via supertest
against a fully-bootstrapped NestJS app — no controller methods are called
directly, no network is touched (Google OAuth + email + Redis are mocked).
The full e2e count goes from **9 suites / 59 tests** to **14 suites / 89 tests**.

- **[`test/e2e/platform-auth-flow.e2e-spec.ts`](test/e2e/platform-auth-flow.e2e-spec.ts)** — closes
  the entire platform admin HTTP surface (previously zero e2e coverage):
  `/platform/login`, `/platform/me`, `/platform/refresh`, `/platform/logout`,
  `DELETE /platform/sessions`, plus cross-context rejection (dashboard token →
  `/platform/me` returns 401, and platform token → `/me` returns 401).
- **[`test/e2e/mfa-disable-flow.e2e-spec.ts`](test/e2e/mfa-disable-flow.e2e-spec.ts)** — closes
  the MFA lifecycle's final transition. Asserts `/mfa/disable` returns 204
  with a valid TOTP, flips `mfaEnabled` to false on the persisted user,
  restores the no-challenge login path, and rejects with `MFA_INVALID_CODE` /
  `MFA_NOT_ENABLED` on the negative paths.
- **[`test/e2e/email-verification-flow.e2e-spec.ts`](test/e2e/email-verification-flow.e2e-spec.ts)** —
  closes `/verify-email` + `/resend-verification` (both previously untouched
  by e2e). Verifies the OTP-driven happy path, OTP_INVALID rejection, fresh
  OTP dispatch on resend, and anti-enumeration responses for unknown +
  already-verified emails.
- **[`test/e2e/negative-paths.e2e-spec.ts`](test/e2e/negative-paths.e2e-spec.ts)** — bundles
  eight negative-path scenarios that were silent gaps: unknown invitation
  token, single-use invitation replay, foreign-user session revoke (auth-
  bypass class), `DELETE /sessions/all` without a refresh token, unknown
  password-reset token, wrong reset OTP, unknown OAuth provider, OAuth init
  without `tenantId`.
- **[`test/e2e/hooks-lifecycle.e2e-spec.ts`](test/e2e/hooks-lifecycle.e2e-spec.ts)** — replaces
  the implicit "if it works, the hook fired" assumption with explicit spy
  assertions on `beforeRegister`, `afterRegister`, `beforeLogin`, `afterLogin`,
  `afterLogout`, `afterMfaEnabled`, `afterEmailVerified`, and
  `afterPasswordReset`. Each hook is verified to receive a `HookContext`
  carrying `ip`, `userAgent`, and sanitized headers — a regression that drops
  any single dispatch would fail the corresponding scenario.

### Tests — Helpers

- **`MockPlatformUserRepository.seed(user)`** ([`test/e2e/setup.ts`](test/e2e/setup.ts)) — exposes
  a deterministic seed entry-point that populates both the user map AND the
  internal `emailIndex` so `findByEmail` resolves the row. Required for the
  platform spec; useful for any future test that needs pre-existing platform
  admins (the lib intentionally ships no `createPlatformUser` endpoint).

## [1.0.2] - 2026-05-25

### Security

- **Forced patched versions of four transitive dependencies via `pnpm.overrides`** to close GitHub Security Advisories surfaced by OpenSSF Scorecard's `Vulnerabilities` check. None of these affect runtime behavior of the published package — they live exclusively in the build/test dependency graph — but pinning them tightens our supply-chain posture and removes the warnings from any consumer running `npm audit` against a clone of the repo:
  - `brace-expansion@>=5.0.6` ([GHSA-jxxr-4gwj-5jf2](https://github.com/advisories/GHSA-jxxr-4gwj-5jf2) — DoS via large numeric range bypassing `max` protection)
  - `postcss@>=8.5.10` ([GHSA-qx2v-qp2m-jg93](https://github.com/advisories/GHSA-qx2v-qp2m-jg93) — XSS via unescaped `</style>` in CSS stringify output)
  - `qs@>=6.15.2` ([GHSA-q8mj-m7cp-5q26](https://github.com/advisories/GHSA-q8mj-m7cp-5q26) — DoS via `TypeError` on null/undefined entries in comma-format arrays)
  - `ws@>=8.20.1` ([GHSA-58qx-3vcg-4xpx](https://github.com/advisories/GHSA-58qx-3vcg-4xpx) — uninitialized memory disclosure)

### Internal / CI

- **OpenSSF Scorecard pipeline** — added `.github/workflows/scorecard.yml` running on push to `main`, weekly schedule (Mondays 06:00 UTC), and manual dispatch. Results upload SARIF to the GitHub Security tab and publish publicly to [scorecard.dev](https://scorecard.dev/viewer/?uri=github.com/bymaxone/nest-auth). The OpenSSF Scorecard badge is now visible in the README alongside CI, coverage, mutation, and license badges.
- **Vulnerability disclosure policy** — added `SECURITY.md` covering supported versions, the GitHub Private Vulnerability Reporting flow, response timeline (acknowledgement < 72 h, coordinated fix for High/Critical < 90 days), and in/out-of-scope categories tuned for an authentication library. Issue templates now point to `support@bymax.one` for security questions.
- **Contact address consolidation** — every `contact@` / `security@bymax.one` reference across `package.json` author, README security note, `SECURITY.md`, and `.github/ISSUE_TEMPLATE/{config.yml,bug_report.md}` unified to **`support@bymax.one`**. Eliminates ambiguity for vulnerability reporters and aligns with the single-inbox routing on `bymax.one`.
- **Top-level workflow permissions** — `codeql.yml` and `release.yml` now declare `permissions: contents: read` at the workflow root, with the analyze/publish jobs widening only where necessary. Closes the OpenSSF Scorecard `Token-Permissions` gap (9/10 → 10/10) by ensuring every workflow has an explicit least-privilege default.

## [1.0.1] - 2026-05-25

### Fixed

- **README license badge** — replaced the npm-registry-backed `shields.io/npm/l/...` badge with the GitHub-backed `shields.io/github/license/...` equivalent. The npm-based badge fails on first-publish for several hours while npm's full-document CDN propagates; the GitHub-based badge reads the `LICENSE` file directly from the repo and resolves immediately and consistently.

### Internal / CI

- **First end-to-end exercise of the OIDC trusted publishing pipeline** — tag `v1.0.1` exercises `release.yml`: tag-version verification → `prepublishOnly` (typecheck + lint + 100% coverage + build) → `npm-publish` environment approval gate → `pnpm publish --provenance` via OIDC trusted publisher → automatic GitHub Release. No production-code or public-API changes in this version.

## [1.0.0] - 2026-05-25

### Added

**Next.js subpath (`@bymax-one/nest-auth/nextjs`)**

- `createAuthProxy(config)` — Edge-Runtime factory that produces a Next.js 16 proxy function. Classifies routes (`/api/auth/*`, public, protected, unmatched), reads the access-cookie JWT (HS256 verify via Web Crypto when `jwtSecret` is provided; decode-only fallback otherwise), and dispatches to public / protected handlers. Strips client-spoofed identity headers on every response path and propagates trusted `x-user-id`, `x-user-role`, `x-tenant-id`, `x-tenant-domain` from the verified token via `NextResponse.next({ request: { headers } })`.
- **Anti-redirect-loop defence-in-depth** — two guards must BOTH fail before the proxy issues a silent-refresh redirect: a `_r` query-param counter (clamped to `maxRefreshAttempts`, rides on the DESTINATION so it survives the handler round-trip) AND a `reason=expired` signal that the silent-refresh handler sets on its terminal fallback. Either guard alone stops the loop.
- **RBAC + status blocking** — `protectedRoutes` patterns support exact, `:segment`, and trailing-wildcard matches. Role mismatch redirects to `getDefaultDashboard(role)?error=forbidden`; blocked `status` claim (case-insensitive against `blockedUserStatuses` via `toLocaleLowerCase('en-US')`) redirects to `loginPath?reason=<allowlist-entry>`. The `reason` value is pulled from the configured allowlist, never from the raw JWT claim.
- **Background-request handling** — RSC, `Next-Router-Prefetch`, and `Next-Router-State-Tree` fetches return `401 + Cache-Control: no-store, no-cache` instead of redirecting, preventing visible redirect loops on client-side navigation.
- **Decode-only warning at factory time** — `warnOnInsecureConfiguration` logs a `console.warn` when `jwtSecret` is omitted so the trust-boundary decision is visible in startup logs.
- `createSilentRefreshHandler(config)` — GET handler for `/api/auth/silent-refresh`. Forwards cookies to the upstream refresh endpoint, propagates deduplicated `Set-Cookie` headers on success, and redirects to `loginPath?reason=expired` with the three auth cookies cleared (`Max-Age=0`) on failure. **Open-redirect defence**: rejects `redirect` query-param values that (a) are empty/null, (b) do not start with `/`, (c) start with `//`, (d) contain CR/LF/NUL/backslash, or (e) resolve to a different origin. Opaque-redirect responses from the upstream and 2xx responses with no `Set-Cookie` are treated as failures.
- `createClientRefreshHandler(config)` — POST bridge for client-side JavaScript refresh. Returns 200 + propagated `Set-Cookie` on success, 401 empty body on any failure. Rejects non-POST methods with 405.
- `createLogoutHandler(config)` — POST logout handler with discriminated-union config: `mode: 'redirect'` requires `loginPath` and returns 302; `mode: 'status'` returns 200 empty body. Cookies are cleared unconditionally regardless of upstream response — the logout guarantee survives network failures.
- **Helpers**: `isBackgroundRequest`, `buildSilentRefreshUrl`, `parseSetCookieHeader` / `dedupeSetCookieHeaders` / `getSetCookieHeaders` (multi-domain white-label dedup by `(name, domain)` with last-writer-wins, CRLF-smuggling rejection, comma-split fallback for pre-Node 18.14 runtimes), `decodeJwtToken` / `verifyJwtToken` (HS256 pinning via `globalThis.crypto.subtle`; rejects `alg: none`, RS256, HS384/512, and whitespace-suffix bypass attempts), `isTokenExpired`, `getUserId`, `getUserRole`, `getTenantId`, `resolveSafeDestination`, and `SILENT_REFRESH_ROUTE` / `CLIENT_REFRESH_ROUTE` / `LOGOUT_ROUTE` constants.
- **Types**: `AuthProxyConfig`, `AuthProxyInstance`, `ResolvedAuthProxyConfig`, `ProtectedRoutePattern`, `SilentRefreshHandler` / `SilentRefreshHandlerConfig`, `ClientRefreshHandler` / `ClientRefreshHandlerConfig`, `LogoutHandler` / `LogoutHandlerConfig` (discriminated union) / `LogoutHandlerRedirectConfig` / `LogoutHandlerStatusConfig`, `DecodedToken`, `JwtHeader`, `ParsedSetCookie`, `HeadersLike`, `RequestWithHeaders`, `RequestWithUrl`.
- **Factory-time validation** — every factory validates its config at construction time: `apiBase` must be absolute HTTP(S); `loginPath` / `redirectPath` must be same-origin pathnames with no CR/LF/NUL/backslash; cookie names must match RFC 6265 token grammar; cookie paths must start with `/` and contain no attribute-smuggling characters; `logoutPath` / `refreshPath` must not contain `..`, `?`, `#`, or control bytes; protected-route patterns reject mid-pattern wildcards and segment-0 catch-alls.

**React subpath (`@bymax-one/nest-auth/react`)**

- `AuthProvider({ client, onSessionExpired?, revalidateInterval? })` — React 19 provider that owns the `loading → authenticated / unauthenticated` state machine, bridges a `createAuthClient` instance into the auth context, and schedules a best-effort revalidation loop (default 5 minutes) so long-lived UIs surface role/status changes without a manual refresh. `onSessionExpired` fires only on a live `authenticated → unauthenticated` transition (not on initial mount or explicit logout).
- `useAuth()` — imperative API: `login`, `register`, `logout`, `forgotPassword`, and `resetPassword`, bound to the provider's client with stable identity. The MFA challenge is exposed through `AuthClient.mfaChallenge()`; session revalidation is exposed through `useSession().refresh()`.
- `useSession()` — reactive snapshot: `{ user, status, isLoading, refresh, lastValidation }` read from context (the `refresh` method triggers an ad-hoc revalidation).
- `useAuthStatus()` — lightweight selector returning just the `AuthStatus` string for components that only need to branch on it.
- `AuthContext`, `AuthContextValue`, `AuthStatus`, `AuthProviderProps` types exported from the subpath barrel.

**Client subpath (`@bymax-one/nest-auth/client`)**

- `createAuthFetch(config)` — fetch wrapper with cookie-mode defaults, single-flight 401 refresh interception, per-instance dedup, configurable timeout (`AbortController`-based), prototype-pollution-safe header merging, and `routePrefix` option for deployments mounted under non-default prefixes
- `createAuthClient(config)` — typed `AuthClient` facade with `login`, `register`, `logout`, `refresh`, `getMe`, `mfaChallenge`, `forgotPassword`, and `resetPassword` methods; composes on top of `createAuthFetch` and supports a pre-built `authFetch` override for sharing dedup state across clients
- `AuthFetch`, `AuthFetchConfig`, `AuthClient`, `AuthClientConfig`, `LoginInput`, `RegisterInput`, `ResetPasswordInput` types exported from the subpath barrel

**Shared subpath (`@bymax-one/nest-auth/shared`)**

- `buildAuthRefreshSkipSuffixes(routePrefix?)` — factory producing the pathname-suffix skip list used by the client's 401 refresh interception, parameterized by the NestJS `routePrefix`; backwards-compat `AUTH_REFRESH_SKIP_PATH_SUFFIXES` retained for the default `'auth'` prefix
- `AuthResponseCode` type — `AuthErrorCode | (string & {})` union so consumers get autocomplete on known codes while preserving flexibility for non-auth Nest exceptions (e.g. `ValidationPipe` 400s)

### Changed

- `AuthErrorResponse.code` and `AuthClientError.code` retyped from plain `string` to `AuthResponseCode`, enabling exhaustive narrowing on `AUTH_ERROR_CODES` values at consumer call sites
- `parseJsonOrThrow` inside `createAuthClient` now throws `AuthClientError` on an empty 2xx body instead of silently returning `undefined` cast as `T`; void endpoints continue to route through `expectNoContent`
- `AuthResult.accessToken` and `PlatformAuthResult.accessToken` JSDoc now carries a `@warning` block explicitly forbidding persistent storage (`localStorage`, `sessionStorage`, `IndexedDB`) in bearer mode — consumers must hold the token in memory only
- `AuthFetch` JSDoc now documents that `Request` objects carrying stream bodies are unsupported when a refresh-retry may occur (the retry would fail with `body already used`)
- `onSessionExpired` callback errors are now surfaced via `console.warn` instead of being silently swallowed, aiding consumer debugging without breaking the fetch contract

### Security

- Split `tsconfig.json` into a root config (used for editors, client, react, nextjs) and a dedicated `tsconfig.server.json` (lib `ES2022` only, no `DOM`) so server-side code cannot silently typecheck against browser globals like `window`, `document`, or `localStorage`; `pnpm typecheck` now runs both configs
- **JWT algorithm pinning** in `verifyJwtToken` (HS256 only) blocks `alg: none`, RS256→HS256 confusion, `alg: 'HS256 '` whitespace bypass, and the `HS384`/`HS512` downgrade attempts before any key material is imported. Empty-string secrets fail closed instead of silently degrading to decode-only mode
- **Anti-redirect-loop defence-in-depth** via two independent guards (the `_r` counter rides on the DESTINATION so it survives the silent-refresh round-trip; `reason=expired` breaks the loop even when the counter is attacker-reset to 0)
- **Open-redirect defence** in `createSilentRefreshHandler` rejects `redirect` query params that do not start with `/`, start with `//`, contain CR/LF/NUL/backslash, or resolve cross-origin
- **Header-spoofing defence** — `buildSanitizedRequestHeaders` deletes the configured `userHeaders.*` slots AND a hardcoded baseline (`x-user-id`, `x-user-role`, `x-tenant-id`, `x-tenant-domain`) from the inbound request before any handler runs, so a client-sent `x-user-id: admin` never reaches server components on any response path (public, protected, unmatched, or silent-refresh redirect)
- **Cookie-smuggling defence** — `parseSetCookieHeader` rejects inputs containing CR/LF (response-header splitting); `assertSafeCookieName`/`assertSafeCookiePath` validate consumer-configured cookie names and paths at factory time against RFC 6265 token grammar and attribute-terminator characters (`;`)
- **Factory-time validation** throws on absolute-URL `loginPath` / `redirectPath`, relative `apiBase`, mid-pattern protected-route wildcards, and segment-0 catch-alls, preventing misconfigurations from manifesting as silent runtime behaviour
- **Cache-Control: no-store, no-cache** on every 401 and redirect response prevents CDN poisoning (a cached 401 or expired-session redirect replayed for an authenticated user)

### Tests

- **221 tests** in the `nextjs` subpath across 10 suites covering the proxy pipeline (redirect-loop prevention, RBAC, status blocking, background-request handling, identity-header sanitisation), the three route handlers (silent-refresh, client-refresh, logout) including open-redirect vectors and method guards, the JWT helpers (algorithm-confusion attacks, UTF-8 validity, base64url alphabet, Web-Crypto failure-path mocks), the cookie helpers (RFC 6265 token coverage, legacy comma-split, CRLF rejection, length bounds), and all validators
- Co-located `*.spec.ts` per helper; every `it()` carries a dedicated English comment explaining the security vector or correctness invariant under test
- New `createAuthFetch.spec.ts` and `createAuthClient.spec.ts` covering refresh interception, timeout, header merge, prototype-pollution guards, MFA handshake, error body parsing, and retry semantics
- New `routes.spec.ts` giving `buildAuthRefreshSkipSuffixes` 100% statement/branch/function coverage (default prefix, custom prefix, slash normalization, empty-prefix branch, unprefixed proxy routes)
- New `barrel.spec.ts` asserting the `shared` subpath public surface
- React subpath specs cover the `loading → authenticated / unauthenticated` state machine, revalidation loop, `onSessionExpired` firing policy (transition-only, not on mount or explicit logout), MFA challenge short-circuit, and the three hook selectors
- Existing `error-codes.spec.ts` drift guard between `server` and `shared` `AUTH_ERROR_CODES`

## Pre-release development — 2026-04-16

This section predates the first publish. `1.0.0` reached npm on 2026-05-25 and is
the section above; what follows is the scaffold-and-foundation work that led to it,
kept for history and deliberately not labelled as a release — no such version was
ever installable.

### Added

#### Phase 1 — Foundation and Infrastructure (NEST-001 to NEST-042)

**Scaffold and tooling**

- `package.json` with scope `@bymax-one`, peer dependencies (NestJS 11, ioredis, class-validator), zero direct runtime dependencies
- `tsconfig.json` and `tsconfig.build.json` with `strict: true`, ES2022 target, decorator support
- `tsconfig.jest.json` for ts-jest compilation
- ESLint flat config (`eslint.config.mjs`) with `@typescript-eslint`, `eslint-plugin-import`, `eslint-plugin-security`, `eslint-plugin-prettier`
- Prettier configuration (`.prettierrc`)
- Jest configuration (`jest.config.ts`) with ts-jest, 80% global coverage threshold, 95% for `crypto/` and `guards/`
- tsup build configuration (`tsup.config.ts`) for 5 subpaths with dual ESM+CJS output and `.d.ts` declarations
- Source directory structure: `server/{interfaces,config,services,controllers,guards,decorators,redis,dto,crypto,errors,oauth,constants,providers,hooks,utils}`, `shared`, `client`, `react`, `nextjs`
- MIT License, `.gitignore`, `AGENTS.md`, `CLAUDE.md`

**Interfaces**

- `BymaxAuthModuleOptions` — full module configuration interface with 15 optional groups (jwt, password, tokenDelivery, cookies, mfa, sessions, bruteForce, passwordReset, emailVerification, platform, invitations, roles, blockedStatuses, oauth, controllers)
- `AuthUser` and `SafeAuthUser` — user entity interfaces (15 fields) with credential-free safe variant
- `IUserRepository` — data access interface with 11 methods (findById, findByEmail, create, updatePassword, updateMfa, updateLastLogin, updateStatus, updateEmailVerified, findByOAuthId, linkOAuth, createWithOAuth)
- `AuthPlatformUser` and `IPlatformUserRepository` — platform admin entity and repository interfaces
- `IEmailProvider` — email delivery interface with 7 methods (OTP, reset, MFA notifications, session alert, invitation), each with optional `locale` parameter
- `IAuthHooks` — lifecycle hook interface with 12 optional hooks (beforeRegister, afterRegister, beforeLogin, afterLogin, afterLogout, afterMfaEnabled, afterMfaDisabled, onNewSession, afterEmailVerified, afterPasswordReset, onOAuthLogin, afterInvitationAccepted)
- `HookContext` — sanitized request context passed to all hooks (ip, userAgent, sanitizedHeaders, optional userId/email/tenantId)
- `BeforeRegisterResult` — hook result type with `allowed`, `reason`, and `modifiedData` fields
- `DashboardJwtPayload`, `PlatformJwtPayload`, `MfaTempPayload` — JWT payload interfaces
- `AuthResult`, `PlatformAuthResult`, `MfaChallengeResult`, `RotatedTokenResult` — service result types
- `AuthenticatedRequest` and `PlatformAuthenticatedRequest` — Express Request extensions with typed `user` payload
- `OAuthProviderPlugin` — native OAuth2 plugin interface (no Passport)
- `OAuthProfile` and `OAuthLoginResult` — OAuth profile and hook result types

**Constants and configuration**

- 6 Symbol-based DI injection tokens: `BYMAX_AUTH_OPTIONS`, `BYMAX_AUTH_USER_REPOSITORY`, `BYMAX_AUTH_PLATFORM_USER_REPOSITORY`, `BYMAX_AUTH_EMAIL_PROVIDER`, `BYMAX_AUTH_HOOKS`, `BYMAX_AUTH_REDIS_CLIENT`
- `DEFAULT_OPTIONS` — all default values (jwt.accessExpiresIn `'15m'`, refreshExpiresInDays `7`, tokenDelivery `'cookie'`, bruteForce 5 attempts / 900s window, etc.)
- `resolveOptions()` — startup function that merges consumer options with defaults, validates all security invariants, and produces `ResolvedOptions` with no optional fields
- Throttle configurations (`THROTTLE_CONFIGS`) per endpoint category

**Crypto utilities** (`src/server/crypto/`)

- `sha256(input)` — deterministic SHA-256 hex digest via `node:crypto`
- `hmacSha256(input, secret)` — keyed HMAC-SHA256 hex digest for low-entropy inputs (composite keys with email addresses)
- `encrypt(plaintext, keyBase64)` / `decrypt(ciphertext, keyBase64)` — AES-256-GCM authenticated encryption using random 12-byte IV per call; wire format `base64(iv):base64(authTag):base64(ciphertext)`
- `generateSecureToken()` — cryptographically random opaque token via `node:crypto.randomBytes`

**Error handling** (`src/server/errors/`)

- `AUTH_ERROR_CODES` — typed string union of all 30+ error codes with Portuguese end-user messages
- `AuthException` — NestJS `HttpException` subclass carrying structured `{ code, message, details? }` response body

**Redis layer** (`src/server/redis/`)

- `AuthRedisService` — typed wrapper around ioredis with automatic namespace prefixing; exposes `get`, `set`, `del`, `setnx`, `incr`, `expire`, `ttl`, `sadd`, `srem`, `smembers`, `sismember`, `eval`, `getdel`, `incrWithFixedTtl`
- `AuthRedisModule` — internal NestJS module registering `AuthRedisService`

**Services** (`src/server/services/`)

- `PasswordService` — scrypt-based password hashing and constant-time comparison; configurable cost factor, block size, and parallelization
- `BruteForceService` — fixed-window rate limiting via atomic `incrWithFixedTtl` Lua script; lockout with `getRemainingLockoutSeconds`
- `TokenManagerService` — JWT issuance (`issueTokens`, `issueMfaTempToken`), token rotation (`reissueTokens`), revocation blacklist via Redis `rv:{jti}` keys, raw refresh token storage via `rt:{sha256(token)}`
- `TokenDeliveryService` — cookie/bearer/both delivery modes; multi-domain support via `resolveDomains` callback; `extractAccessToken`, `extractRefreshToken`, `clearAuthSession`

**Utilities** (`src/server/utils/`)

- `sanitizeHeaders()` — removes sensitive headers (authorization, cookie, x-api-key, x-auth-token, x-csrf-token, x-session-id, pattern `/^x-.*-token$/i`) before passing to hook context
- `sleep(ms)` — Promise-based delay for timing normalization in anti-enumeration flows
- `hasRole(userRole, requiredRole, hierarchy)` — recursive role hierarchy checker supporting denormalized role trees

**NoOp fallback providers**

- `NoOpEmailProvider` — silent no-op implementation of `IEmailProvider` (registered when consumer does not supply one)
- `NoOpAuthHooks` — silent no-op implementation of `IAuthHooks` (registered when consumer does not supply one)

**Phase 1 barrel export** (`src/server/index.ts`) — all interfaces, types, constants, error codes, and injectable tokens

---

#### Phase 2 — Core Authentication (NEST-043 to NEST-064)

**Guards** (`src/server/guards/`)

- `JwtAuthGuard` — native NestJS guard (no Passport); verifies JWT via `@nestjs/jwt` `JwtService.verify()` with algorithm pinning from `ResolvedOptions.jwt.algorithm`; checks `rv:{jti}` revocation blacklist; skips public routes decorated with `@Public()`; asserts token type is `'dashboard'` via `assertTokenType` utility
- `RolesGuard` — hierarchical role guard using denormalized `roles.hierarchy`; reads `@Roles()` metadata via `Reflector`; throws `INSUFFICIENT_ROLE` (403) on failure
- `UserStatusGuard` — status-based access guard with Redis caching (`us:{userId}`, TTL from `userStatusCacheTtlSeconds`); maps blocked statuses to specific error codes (ACCOUNT_BANNED, ACCOUNT_INACTIVE, ACCOUNT_SUSPENDED, PENDING_APPROVAL) with ACCOUNT_INACTIVE as fallback
- `assertTokenType` utility — reusable guard helper that throws `TOKEN_INVALID` when the JWT `type` claim does not match the expected value

**Decorators** (`src/server/decorators/`)

- `@CurrentUser(property?)` — param decorator extracting `request.user` or a specific property from it
- `@Roles(...roles)` — metadata decorator setting `ROLES_KEY` for `RolesGuard`
- `@Public()` — metadata decorator setting `IS_PUBLIC_KEY` to skip `JwtAuthGuard`

**DTOs** (`src/server/dto/`)

- `RegisterDto` — `email`, `password` (8–128 chars), `name` (2+ chars), `tenantId`; all with class-validator decorators
- `LoginDto` — `email`, `password` (no `@MinLength` — deliberate anti-enumeration), `tenantId`

**Services** (`src/server/services/`)

- `OtpService` — `generate(length)` via `crypto.randomInt` with leading-zero padding; `store(purpose, identifier, code, ttl)` to Redis; `verify(purpose, identifier, code)` with constant-time comparison via `crypto.timingSafeEqual` (safe for different-length inputs), max-attempt enforcement (5), key deletion on exhaustion, and timing normalization (100ms floor); atomic attempt increment via Lua eval (single round-trip preserving TTL)
- `AuthService` — full authentication lifecycle: `register`, `login`, `logout`, `refresh`, `getMe`, `verifyEmail`, `resendVerificationEmail`; `@Optional()` hooks with fire-and-forget error isolation; tenant resolution via `tenantIdResolver`; brute-force integration; MFA challenge path

**Controllers** (`src/server/controllers/`)

- `AuthController` — 7 endpoints: `POST /register`, `POST /login`, `POST /logout`, `POST /refresh`, `GET /me`, `POST /verify-email`, `POST /resend-verification`; `@UsePipes(new ValidationPipe({ whitelist: true }))` at class level; conditional registration via `controllers.auth` option

**Module**

- `BymaxAuthModule.registerAsync(options)` — dynamic NestJS module; wraps consumer factory with `resolveOptions()`; conditionally registers `AuthController`; registers NoOp fallback providers when consumer omits email/hooks tokens; class-shorthand provider detection in `hasProviderToken`; `JwtModule.registerAsync` reads `jwt.secret` directly (no double `resolveOptions` call)

**Phase 2 barrel export** — adds `BymaxAuthModule`, `AuthService`, `JwtAuthGuard`, `RolesGuard`, `UserStatusGuard`, `CurrentUser`, `Roles`, `ROLES_KEY`, `Public`, `IS_PUBLIC_KEY`, `RegisterDto`, `LoginDto`

---

#### Phase 3 — Multi-Factor Authentication (TOTP)

**Crypto utilities** (`src/server/crypto/totp.ts`)

- `generateTotpSecret()` — generates a cryptographically random 20-byte TOTP secret via `node:crypto.randomBytes`; returns both raw `Buffer` and `base32`-encoded string
- `buildTotpUri(secret, account, issuer)` — constructs a standard `otpauth://totp/` URI for QR code generation
- `verifyTotp(secret, code, window)` — validates a 6-digit TOTP code within a configurable step window (±1 by default) using HMAC-SHA1 per RFC 6238
- `generateHotp(secret, counter)` — low-level HOTP generation (RFC 4226) used internally by `verifyTotp` and exposed for testing
- `fromBase32(input)` / `toBase32(buf)` — pure Base32 encode/decode without external dependencies; `fromBase32` strips whitespace, hyphens, and padding before decoding

**Services** (`src/server/services/mfa.service.ts`)

- `MfaService.setup(userId)` — generates TOTP secret and recovery codes; uses atomic `setIfAbsent` to guarantee idempotency under concurrent requests; encrypts secret with AES-256-GCM; returns plain recovery codes once (then discarded)
- `MfaService.verifyAndEnable(userId, code, ip, userAgent)` — validates the first TOTP code against the pending setup key; atomically consumes the setup key to prevent double-enable races; persists encrypted secret and hashed recovery codes to the user repository; invalidates all existing refresh sessions
- `MfaService.challenge(tempToken, code, ip, userAgent)` — exchanges a short-lived MFA temp token for full auth tokens; accepts both TOTP codes and recovery codes; enforces anti-replay via 90-second `setnx` key; brute-force lockout with `challenge:`-namespaced counter; supports both `dashboard` and `platform` contexts
- `MfaService.disable(userId, code, ip, userAgent, context)` — disables MFA after TOTP verification; only accepts TOTP (recovery codes cannot disable by design); invalidates all sessions; supports both dashboard and platform repositories via `context` parameter

**Guards** (`src/server/guards/mfa-required.guard.ts`)

- `MfaRequiredGuard` — enforces MFA verification on routes where the authenticated JWT has `mfaEnabled: true`; gates on `mfaVerified: true` claim; respects `@SkipMfa()` decorator to exclude specific endpoints (e.g. the challenge endpoint itself)

**Decorators** (`src/server/decorators/skip-mfa.decorator.ts`)

- `@SkipMfa()` — metadata decorator that marks an endpoint as exempt from `MfaRequiredGuard`; used on `POST /mfa/challenge` and any other pre-MFA routes

**DTOs** (`src/server/dto/`)

- `MfaChallengeDto` — `mfaTempToken` (string) + `code` (string); `@MaxLength(14)` as defence-in-depth before regex
- `MfaVerifyDto` — 6-digit TOTP code; `@MaxLength(6)` + `@Matches(/^\d{6}$/)`
- `MfaDisableDto` — 6-digit TOTP code; `@MaxLength(6)` + `@Matches(/^\d{6}$/)`; JSDoc explains why recovery codes are not accepted

**Controllers** (`src/server/controllers/mfa.controller.ts`)

- `POST /mfa/setup` — initiates TOTP setup; returns secret, QR URI, and plain recovery codes (shown once); idempotent within 10-minute window; dashboard users only
- `POST /mfa/verify-enable` — submits the first TOTP code to permanently activate MFA; returns 204 No Content
- `POST /mfa/challenge` — public endpoint (protected only by temp token); exchanges temp token + TOTP or recovery code for full auth tokens; returns cookie or bearer response for dashboard, plain JSON for platform
- `POST /mfa/disable` — disables MFA for dashboard or platform users; derived `context` from `user.type` JWT claim; returns 204 No Content

**Redis additions** (`src/server/redis/auth-redis.service.ts`)

- `setIfAbsent(key, value, ttl)` — atomic `SET NX EX`; returns `true` if the key was newly created, `false` if it already existed; used for idempotent setup key reservation
- `invalidateUserSessions(userId)` — Lua script that reads all members of `sess:{userId}`, deletes each session key (including grace pointers tracked in the SET), and removes the SET itself in a single round-trip

**Module integration** (`src/server/bymax-auth.module.ts`)

- `controllers.mfa: true` option conditionally registers `MfaController`; startup validation throws if `controllers.mfa: true` is set without the `mfa` configuration group

---

#### Phase 4 — Sessions & Password Reset

**Services** (`src/server/services/`)

- `SessionService` — full session lifecycle management: `createSession` records device/IP metadata and enforces concurrent session limit via FIFO eviction; `listSessions` returns sorted `SessionInfo[]` with `isCurrent` marked via timing-safe comparison; `revokeSession` atomically verifies ownership (SISMEMBER) before deletion; `revokeAllExceptCurrent` preserves the caller's session while revoking all others; `rotateSession` atomically renames session detail key on token rotation, preserving `createdAt`; device parsing is regex-only (no external libraries); two Lua scripts (`REVOKE_SESSION_LUA`, `ROTATE_SESSION_DETAIL_LUA`) prevent TOCTOU races
- `PasswordResetService` — dual-flow password reset supporting `token` and `otp` modes (configured via `passwordReset.method`); `initiateReset` always returns success (anti-enumeration); `resetPassword` validates mutual exclusivity of proof fields and delegates to `resetWithToken`, `resetWithOtp`, or `resetWithVerifiedToken`; `verifyOtp` exchanges a validated OTP for a 5-minute `verifiedToken`; `resendOtp` subject to atomic 60-second cooldown via Redis NX key; all tokens consumed atomically via `getdel()` (single-use); `applyPasswordReset` hashes the new password and invalidates all sessions via Lua script; `initiateReset` and `resendOtp` apply a 300ms timing floor to prevent email-existence probing

**Controllers** (`src/server/controllers/`)

- `SessionController` — 3 endpoints: `GET /sessions` (list active sessions), `DELETE /sessions/all` (revoke all except current), `DELETE /sessions/:id` (revoke single session by 64-char hash); all require `JwtAuthGuard` + `UserStatusGuard`; current session identified by extracting refresh token via `TokenDeliveryService`
- `PasswordResetController` — 4 endpoints: `POST /password/forgot-password`, `POST /password/reset-password`, `POST /password/verify-otp`, `POST /password/resend-otp`; all `@Public()`; all return 200/204 regardless of email existence; per-endpoint throttle configs

**DTOs** (`src/server/dto/`)

- `ForgotPasswordDto` — `email` (normalized lowercase) + `tenantId`
- `ResetPasswordDto` — `email`, `newPassword` (8–128 chars), exactly one of `token` / `otp` / `verifiedToken`, `tenantId`
- `VerifyOtpDto` — `email`, `otp` (4–8 chars), `tenantId`
- `ResendOtpDto` — `email` + `tenantId`

**Configuration** (`BymaxAuthModuleOptions`)

- `sessions.enabled`, `sessions.defaultMaxSessions` (default 5), `sessions.maxSessionsResolver`, `sessions.evictionStrategy` (`'fifo'`)
- `passwordReset.method` (`'token'` | `'otp'`, default `'token'`), `passwordReset.tokenTtlSeconds` (default 3600), `passwordReset.otpTtlSeconds` (default 600), `passwordReset.otpLength` (default 6)

**Module integration** (`src/server/bymax-auth.module.ts`)

- `controllers.sessions: true` opt-in gate with startup cross-validation: throws if `sessions.enabled` is not `true` in the factory return value
- `controllers.passwordReset` opt-out gate (enabled by default); `PasswordResetService` only registered when controller is active
- `SessionService` always registered unconditionally — `AuthService.login()` and `AuthService.refresh()` call session methods regardless of whether the sessions controller is exposed

**Phase 4 barrel export** — adds `SessionService`, `PasswordResetService`, `ForgotPasswordDto`, `ResetPasswordDto`, `VerifyOtpDto`, `ResendOtpDto`, and `ActiveSessionInfo` type

---

#### Phase 5 — Platform Authentication, OAuth & Invitations

**Services**

- `PlatformAuthService` (`src/server/services/`) — operator/super-admin authentication layer backed by `IPlatformUserRepository`; `login` validates credentials, applies brute-force protection (HMAC-SHA-256 identifier, no PII in Redis), and returns `PlatformAuthResult` or `MfaChallengeResult`; `logout` blacklists JTI and deletes primary + grace session keys; `refresh` delegates to `TokenManagerService.reissuePlatformTokens()`; `getMe` returns `SafeAuthPlatformUser` (no credential fields); `revokeAllPlatformSessions` atomically deletes all session keys via `invalidateUserSessions()` Lua script; platform sessions are always bearer-mode (never cookies)
- `OAuthService` (`src/server/oauth/`) — provider-agnostic Authorization Code flow; `initiateOAuth` validates provider name format, generates 64-char hex CSRF state nonce stored under `os:{sha256(state)}` (10-min TTL), and redirects to provider authorize URL; `handleCallback` atomically consumes state via `getdel()`, exchanges authorization code for access token, fetches normalized profile, calls required `hooks.onOAuthLogin` for account resolution (`'create'` / `'link'` / `'reject'`), and issues dashboard tokens; creates session if `sessions.enabled: true`; currently supports Google OAuth 2.0
- `InvitationService` (`src/server/services/`) — `invite` validates the target role against the inviter's own role via `hasRole()` (cannot invite higher), stores `StoredInvitation` JSON under `inv:{sha256(token)}`, and emails the raw token; `acceptInvitation` atomically consumes the token via `getdel()`, re-validates role against the hierarchy (prevents Redis tampering), verifies email uniqueness, hashes password, creates the user with `emailVerified: true`, issues dashboard tokens, creates session if enabled, and fires `hooks.afterInvitationAccepted`

**Guards** (`src/server/guards/`)

- `JwtPlatformGuard` — validates HS256-signed JWTs for platform routes; reads token exclusively from Authorization Bearer header; enforces `type: 'platform'` claim; throws `PLATFORM_AUTH_REQUIRED` (not `TOKEN_INVALID`) when a dashboard token is submitted, enabling precise cross-context error detection; algorithm pinned from `options.jwt.algorithm`; checks `rv:{jti}` revocation blacklist; respects `@Public()`
- `PlatformRolesGuard` — enforces role-based access on platform routes via `@PlatformRoles()` metadata; requires fully denormalized `roles.platformHierarchy`; denies access by default when hierarchy is missing

**Decorators** (`src/server/decorators/`)

- `@PlatformRoles(...roles)` — metadata decorator under `PLATFORM_ROLES_KEY` symbol; declares required platform role(s) for a route handler

**Controllers**

- `PlatformAuthController` (`src/server/controllers/`) — 6 endpoints: `POST /platform/login`, `POST /platform/mfa/challenge`, `GET /platform/me`, `POST /platform/logout`, `POST /platform/refresh`, `DELETE /platform/sessions`; all authenticated routes use `JwtPlatformGuard`; `mfa/challenge` cross-validates token context and throws `PLATFORM_AUTH_REQUIRED` on dashboard-context token submission
- `OAuthController` (`src/server/oauth/`) — 2 endpoints: `GET /oauth/:provider` (initiate, 302 redirect) and `GET /oauth/:provider/callback` (handle, issues auth tokens); both `@Public()` + `@SkipMfa()`; per-endpoint throttle configs
- `InvitationController` (`src/server/controllers/`) — 2 endpoints: `POST /invitations` (authenticated, `tenantId` extracted from JWT never from body) and `POST /invitations/accept` (public, returns 201 with auth response)

**DTOs** (`src/server/dto/`)

- `PlatformLoginDto` — `email` (normalized lowercase) + `password` (12–128 chars)
- `CreateInvitationDto` — `email`, `role`, optional `tenantName` (max 128 chars)
- `AcceptInvitationDto` — `token` (exactly 64 hex chars), `name` (2–100 chars), `password` (8–128 chars)
- `OAuthInitiateQueryDto` — `tenantId` (1–128 chars)
- `OAuthCallbackQueryDto` — `code` (32–2048 chars), `state` (max 128 chars)

**OAuth module** (`src/server/oauth/`)

- `OAuthModule` — exposes `getOAuthProviders()` and `getOAuthControllers()` static methods for inline inclusion in `BymaxAuthModule` providers/controllers arrays, avoiding sub-module circular dependency; `buildOAuthPlugins()` factory constructs registered provider plugins from `ResolvedOptions`
- `OAUTH_PLUGINS` — Symbol injection token for the `OAuthProviderPlugin[]` array; internal to the library (not exported in public API)

**Configuration** (`BymaxAuthModuleOptions`)

- `platform.enabled` (default `false`); requires `roles.platformHierarchy`
- `oauth.google` — `clientId`, `clientSecret`, `callbackUrl` (required), `scope` (optional, default `['openid', 'email', 'profile']`)
- `invitations.enabled` (default `false`), `invitations.tokenTtlSeconds` (default 172800 — 48 hours)
- `roles.platformHierarchy` — required when `platform.enabled: true`

**Module integration** (`src/server/bymax-auth.module.ts`)

- `controllers.platform: true` opt-in gate with three startup cross-validations: requires `platform.enabled: true`, the `mfa` config group, and `BYMAX_AUTH_PLATFORM_USER_REPOSITORY` in `extraProviders`
- `controllers.oauth: true` opt-in gate with startup cross-validation: requires `oauth` config group; `OAUTH_PLUGINS` built lazily via factory provider after `BYMAX_AUTH_OPTIONS` resolves
- `controllers.invitations: true` opt-in gate with startup cross-validation: requires `invitations.enabled: true`
- `OAuthService` exported individually (not `OAUTH_PLUGINS` — internal token not part of the public integration surface)

**Phase 5 barrel export** — adds `PlatformAuthService`, `OAuthService`, `InvitationService`, `JwtPlatformGuard`, `PlatformRolesGuard`, `PlatformRoles`, `PLATFORM_ROLES_KEY`, `PlatformLoginDto`, `CreateInvitationDto`, `AcceptInvitationDto`, `SafeAuthPlatformUser`, `IPlatformUserRepository`, `OAuthProfile`, `OAuthProviderPlugin`

---

#### Phase 6 — Integration, Polish, and Publication (NEST-122 to NEST-151)

**Additional guards** (3)

- `WsJwtGuard` — WebSocket dashboard JWT guard (header-only, soft peer-dep on `@nestjs/websockets`, runtime check via dynamic import)
- `SelfOrAdminGuard` — self-access or admin override with strict SHA-256 session-hash validation; documents multi-tenant ownership limitation
- `OptionalAuthGuard` — extends `JwtAuthGuard`, allows unauthenticated access while validating tokens when present

**E2E test suite** (`test/e2e/`)

- Full auth flow (bearer + cookie modes)
- MFA flow (setup, verify, challenge with TOTP and recovery codes)
- Sessions flow (3-device login, list, revoke single, revoke all-except-current)
- Password reset flow (token method + OTP method)
- Invitations flow (admin creates, invitee accepts, login)
- OAuth flow (mocked Google plugin, create/link actions, CSRF state)
- FIFO session eviction (sessions.defaultMaxSessions exceeded → oldest evicted)
- Refresh concurrency (Promise.all on /refresh, grace window served distinct rotated tokens, original invalidated after grace expiry)
- Security scenarios (brute-force lockout, blacklist, missing jti, MFA cross-context token rejection, OTP cooldown)

**Security audits**

- Password & crypto audit — scrypt parameters, AES-256-GCM, recovery code hashing, opaque refresh tokens, `crypto.timingSafeEqual` (PASS)
- Token & session audit — refresh rotation grace window, blacklist, HttpOnly+SameSite cookies, algorithm pinning HS256, SHA-256 Redis keys (PASS)
- Anti-enumeration & brute-force audit — per-tenant identifier (fixed prefix-collision in identifier separator), rate limiting on 15 sensitive endpoints, generic error responses, PII masking, TOTP anti-replay, OTP attempt limit, hook header sanitization

**Documentation**

- README.md — install, configuration, IUserRepository + IEmailProvider reference implementations with XSS warning, endpoints table, guards/decorators table, security checklist, throttler version note
- JSDoc completion across all public services, guards, and decorators

**Test infrastructure**

- Jest E2E config (`jest.e2e.config.ts`)
- ioredis-mock + supertest test harness
- Shared bootstrap helper (`test/e2e/setup.ts`) with mock repositories, email capture, and in-memory Redis

---

### Fixed

#### Phase 6 — Bug fixes

- `auth.service.ts` brute-force identifier separator: added explicit `:` between tenantId and email to prevent prefix-collision (e.g., tenant `'abc'` + email `'x@y.com'` no longer collides with tenant `'abcx'` + email `'@y.com'`)
- `self-or-admin.guard.ts` (during initial implementation): replaced `ForbiddenException` wrapping `AuthException` with direct `AuthException` throw for correct error response shape
- `ws-jwt.guard.ts` (during initial implementation): replaced `require.resolve` with dynamic `await import()` for ESM compatibility

---

### Security

- **Grace pointer survivorship fix** — `rotateFromPrimary` and `rotateFromGrace` now add grace pointer keys (`rp:{hash}`) to the `sess:{userId}` Redis SET so that `invalidateUserSessions` (called on MFA enable/disable) deletes them atomically, preventing stale refresh tokens from surviving MFA state changes
- **Brute-force counter namespacing** — MFA challenge and disable endpoints use HMAC identifiers prefixed with `challenge:` and `disable:` respectively, preventing a pre-auth attacker from exhausting the disable counter via the public challenge endpoint
- **`verifyAndEnable` re-entry guard** — added `MFA_ALREADY_ENABLED` check at entry so that a stale Redis setup key from a previous attempt cannot overwrite an active MFA secret and recovery codes
- **`disable()` context-awareness** — the disable flow now accepts a `context` parameter (`'dashboard'` | `'platform'`) and dispatches to the correct repository, preventing platform admins from receiving `TOKEN_INVALID` when attempting to disable MFA
- **HMAC keying for composite Redis keys** — all `sha256(tenantId + email)` call sites replaced with `hmacSha256(..., jwt.secret)` to prevent rainbow-table reversal of email addresses stored as Redis key segments
- **Atomic resend cooldown** — GET+SET TOCTOU race in `resendVerificationEmail` replaced with atomic `SET NX EX` (`setnx`) preventing duplicate OTP sends under concurrent requests
- **Immutable DTO merging** — `Object.assign(dto, hookResult.modifiedData)` replaced with `dto = { ...dto, ...modifiedData }` preventing mutation of the class-validator–validated DTO and bypassing decorator constraints
- **`secureCookies` resolved at startup** — `process.env.NODE_ENV === 'production'` check moved from per-request code inside `TokenDeliveryService` to `resolveOptions()`, eliminating an environment-variable read inside library service methods
- **Algorithm pinning from options** — `JwtAuthGuard` now reads `algorithms: [this.options.jwt.algorithm]` instead of hardcoding `['HS256']`, ensuring the algorithm is validated once at startup and consistent across the full JWT lifecycle
- **Atomic OTP attempt increment** — `incrementAttempts` now uses a single Lua `EVAL` (GET+SET with preserved TTL) instead of separate `TTL` + `SET EX` calls, eliminating a race window between reads and writes
- **OTP key deleted on max-attempt exhaustion** — `verify()` now calls `redis.del(key)` when `attempts >= MAX_ATTEMPTS` before throwing `OTP_MAX_ATTEMPTS`, preventing further probing after lockout
- **`refreshCookiePath` validation is now a hard error** — mismatched `routePrefix` without explicit `refreshCookiePath` previously logged a warning; now throws at startup to prevent misconfigured cookie paths reaching production
- **`validateRefreshGraceWindowSeconds`** — startup validation added: throws if `refreshGraceWindowSeconds >= refreshExpiresInDays * 86400` to prevent a grace window larger than the token's lifetime
- **Anti-enumeration timing normalization** — `initiateReset` and `resendOtp` apply a 300ms minimum floor via `sleep()` so response time cannot reveal whether an email is registered
- **Single-use token enforcement** — password-reset tokens, OTP `verifiedToken`, OAuth CSRF state, and invitation tokens all consumed atomically via `redis.getdel()`, preventing concurrent redemption races
- **Session ownership verification** — `revokeSession` performs an SISMEMBER check before deletion; throws `SESSION_NOT_FOUND` for sessions not owned by the requesting user, preventing cross-user revocation
- **OAuth CSRF protection** — state nonce is 64 hex chars (256 bits), stored under `os:{sha256(state)}` and consumed in a single atomic `getdel()` call; provider format validated before the state is touched to prevent probe-and-consume attacks
- **Platform token type isolation** — `JwtPlatformGuard` throws `PLATFORM_AUTH_REQUIRED` (not the generic `TOKEN_INVALID`) when a dashboard-context token is submitted to a platform route, enabling clients to distinguish wrong-context from expired/invalid token errors
- **Tenant spoofing prevention** — `InvitationController` extracts `tenantId` exclusively from the authenticated JWT payload; body field is absent from `CreateInvitationDto`, making tenant injection structurally impossible
- **Invitation role re-validation on acceptance** — `acceptInvitation` re-validates the stored role against the live `roles.hierarchy` after consuming the token, preventing privilege escalation via Redis tampering between invite creation and acceptance
- **Platform brute-force HMAC identifiers** — `PlatformAuthService` uses `hmacSha256(email, jwt.secret)` as the brute-force counter key, consistent with dashboard pattern; no PII stored in Redis key segments

---

### Tests

- 561 tests across 34 co-located spec files through Phase 3; Phase 4 and Phase 5 add spec files for `session.service`, `password-reset.service`, `platform-auth.service`, `oauth.service`, `invitation.service`, `jwt-platform.guard`, and `platform-roles.guard`
- **100% coverage** on all metrics (Statements, Branches, Functions, Lines) across every source file
- Per-directory coverage thresholds enforced: 95% for `crypto/` and `guards/`, 80% global
- Every `it()` block has an English comment explaining the branch under test
- All spec files have a file-level JSDoc docblock describing strategy, mocks, and special setup
- Phase 3 integration smoke test (`mfa-integration.spec.ts`) validates: full setup→enable→challenge flow, idempotency, recovery codes, anti-replay, brute-force lockout, counter namespacing, platform context, session invalidation, disable TOTP-only enforcement, and `@SkipMfa()` guard bypass
- Phase 4 session tests cover: `createSession` FIFO eviction, `listSessions` `isCurrent` marking, `revokeSession` ownership check, `revokeAllExceptCurrent` current-session preservation, `rotateSession` atomic rename, and stale member cleanup
- Phase 4 password-reset tests cover: both `token` and `otp` flows, mutual exclusivity validation, `verifiedToken` exchange, resend cooldown, anti-enumeration (no error on unknown email), and session invalidation on reset
- Phase 5 tests cover: platform login with MFA path and brute-force lockout, `JwtPlatformGuard` cross-context rejection, `PlatformRolesGuard` hierarchy enforcement, OAuth CSRF state lifecycle, `onOAuthLogin` hook resolution strategies, and invitation role-authorization + acceptance single-use enforcement

[Unreleased]: https://github.com/bymaxone/nest-auth/compare/v1.0.11...HEAD
[1.0.11]: https://github.com/bymaxone/nest-auth/compare/v1.0.10...v1.0.11
[1.0.10]: https://github.com/bymaxone/nest-auth/compare/v1.0.9...v1.0.10
[1.0.9]: https://github.com/bymaxone/nest-auth/compare/v1.0.8...v1.0.9
[1.0.8]: https://github.com/bymaxone/nest-auth/compare/v1.0.7...v1.0.8
[1.0.7]: https://github.com/bymaxone/nest-auth/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/bymaxone/nest-auth/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/bymaxone/nest-auth/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/bymaxone/nest-auth/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/bymaxone/nest-auth/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/bymaxone/nest-auth/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/bymaxone/nest-auth/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/bymaxone/nest-auth/releases/tag/v1.0.0
