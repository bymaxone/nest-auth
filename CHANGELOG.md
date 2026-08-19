# Changelog

All notable changes to `@bymax-one/nest-auth` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

**Versioning, while the library is pre-adoption.** [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
is the target, not yet the practice. Until the API settles, breaking changes ship in **minor and
patch** releases rather than driving the major, deliberately: the library has no production
dependant, the surface is still being corrected as audits land, and a major per breaking change
would put a young library in double digits while saying nothing useful about its stability.
Strict SemVer starts when the API is declared stable, and that transition will be announced here.

**What this means for you:** do not infer compatibility from the version number in the `1.x` line
— `^1.4.0` and `~1.4.0` both resolve to releases that may break you. Read the entry before
upgrading. Every breaking change carries an **Apply to a derived backend** note saying exactly
what moves, and that note is the compatibility contract until strict SemVer begins.

## [Unreleased]

### Changed

- **`SessionInfo` now names the shape `GET /sessions` returns.** (#156) Two interfaces answered to
  that name — the session listing in `SessionService`, and the contextual payload sent in
  new-login alert emails — and the barrel exported the **email** one under the plain name, with
  the listing type exported as `ActiveSessionInfo`. That is backwards: a consumer typing a session
  listing imports `SessionInfo`, receives `device` and `ip` with no `id` — and a `sessionHash` that
  means something different. On the alert type it is the TRUNCATED display value; on the listing it
  is the full 64-hex hash. Same field name, same type, different value, and the truncated one is
  precisely what `DELETE /sessions/:id` refuses.

  It does. Two consumer sessions disagreed for a day over exactly that — one read the wire and saw
  an `id`, the other read the published type and did not. Neither was careless; the name resolved
  to the wrong shape.

  **Apply to a derived backend.** The email-alert type is now `SessionAlertInfo`, named for what
  it is. If you implement `IEmailProvider`, rename the parameter type on `sendNewSessionAlert` —
  the fields are unchanged. If you imported `ActiveSessionInfo` to type a session listing, import
  `SessionInfo` instead: same shape, correct name. No runtime behaviour moves.

- **A malformed `sessionHash` answers `VALIDATION`, not `SESSION_NOT_FOUND`.** (#156) The two were
  deliberately indistinguishable, on the argument that telling them apart would let a caller
  enumerate valid hash formats. The format is not a secret: it is 64 hex characters,
  `SessionInfo.sessionHash` publishes it on every listed session, and the route documents it. So
  the pairing protected nothing and cost something real — a consumer sending a malformed hash got
  the same answer as one sending an already-revoked session, and read a UI bug as a race between
  the session list and the click. Twenty minutes chasing a race that cannot happen.

  A well-formed hash that names nothing still answers `SESSION_NOT_FOUND`. That is where the
  no-enumeration argument does apply, because that answer really would say whether a session
  exists.

  **Apply to a derived backend.** If you branch on `auth.session_not_found` to mean "bad input",
  branch on `auth.validation` for that case; the payload names `sessionHash` in `details`.

### Fixed

- **`DELETE /sessions/:id` documented a prefix it has always refused.** (#156) The controller
  described the parameter as accepting "its hash prefix (display id) **or** full 64-character
  SHA-256 session hash". The handler has only ever accepted the full hash — and until the change
  above, a prefix was refused with the same error as a session that no longer exists, which is
  what made it read as a race rather than as a rejected input.

  The prefix will **not** be made to work: `SessionInfo.id` is the first 8 characters of the hash
  and is not unique by construction, so resolving one on a revocation could revoke a different
  session than the one the user clicked. The documentation now says so and names the display value
  as display-only.

- **`mergeHeaders` sent every header twice when the caller's key case differed from the default,
  which broke every authenticated call carrying a body.** (#156)

  Header names are case-insensitive; plain object keys are not. `DEFAULT_HEADERS` keys
  `Content-Type`, `Headers.prototype.forEach` yields lowercase names, and both survived into the
  merged record — so `fetch` joined them on the wire:

  ```
  content-type: application/json, application/json
  ```

  Legal HTTP, so nothing rejects it. The backend simply stops parsing the body and answers
  `400 "role is required"` naming a field that IS present, which reads as a caller bug while the
  caller is correct. The header is the last place anyone looks.

  **Both reports put arrays in the safe column, and that is one notch too narrow.** Measured
  against the shipped function, the rule is only _"the key case differs from the default"_ — the
  `HeadersInit` shape does not enter into it. A record written `content-type`, the spelling the
  platform itself uses, duplicates just as surely as a `Headers` instance does, and so does an
  array of pairs written lowercase. `Headers` merely makes it unavoidable, because `forEach`
  lowercases for you. "We do not pass `Headers`" was not the reassurance it looked like.

  **A second site neither report reached:** the factory built its defaults with the same
  case-sensitive spread, so overriding the content type through the documented
  `defaultHeaders` option also duplicated it — set up once, poisoning every request, far from
  the call anyone is debugging.

  Fixed by letting `Headers` own the semantics on both paths: names normalise per the spec, and
  `set` replaces rather than appends, which is the intent the old code expressed and did not
  achieve. `mergeHeaders` now returns a `Headers` rather than a record, because handing back a
  record hands back a structure in which `Content-Type` and `content-type` are two different
  things — the shape the defect grew in.

  Three `eslint-disable security/detect-object-injection` comments and one Stryker disable went
  with it: a `Headers` has no prototype to pollute, so the guard is no longer working against the
  type it is written on. The unsafe-name drop is kept as observable behaviour, and now also
  covers the factory defaults, which the previous spread never guarded.

  **The class, for anyone auditing the rest of the client surface:** case-insensitive header
  semantics implemented with case-sensitive object keys. Anywhere this library keys a header by
  string, the same latent duplicate exists.

  The regression test asserts what the wire carries rather than what the record contains, and the
  distinction is the whole reason this survived: the previous tests read ONE case-sensitive key
  off the raw record, which held the default's value, while the caller's lowercase twin sat beside
  it unread. Nothing ever asserted against the joined value, so nothing failed. A mock server does
  not help either — it accepts the duplicate without complaint, because the request is well-formed
  and wrong.

### Added

- **`AuthService.isAccountLockedOut()` and `getAccountLockoutSeconds()` — read the lockout, not
  just clear it.** (#157)

  `unlockAccount` was already public, so a host could **clear** a dashboard lockout. There was no
  public way to **read** one, so a console could offer an Unlock button and could not tell anyone
  whether it had anything to do. The write side was exposed and the read side was not.

  The primitives existed — `BruteForceService.isLockedOut` and `getRemainingLockoutSeconds` are
  both public — but the identifier was out of reach. It is an HMAC of
  `dashboard:{tenantId}:{email}` under the library's own derived `hmacKey`, which a consumer does
  not have, and reproducing that preimage is exactly what keeping the derivation in one place
  prevents: a third copy in a consumer repository is a third chance to drift, and a drifted key
  reads a record that never exists. That reports **"not locked out" for every account, including
  locked ones** — a false negative on a security indicator, delivered confidently and silently.

  The second method matters more than it looks. A bare flag with no horizon is the interface that
  invites the support call the indicator was meant to prevent: it can say an account is locked and
  cannot say for how long, so the only honest advice left is "try again later".

  **Cheap enough for every row of a directory listing — issue them concurrently.** The reporter
  measured twenty of these against a local Redis over ioredis: `0.39 ms` issued concurrently
  against `0.33 ms` for a single one, and `6.25 ms` awaited one at a time in a loop. Concurrency is
  what buys that, by overlapping the round trips; use `Promise.all` and not `await` inside a loop.

  Those numbers are one environment's, not a guarantee this library makes. Each call is its own
  Redis command, the ioredis client is the host's, and whether the commands are also **batched**
  into a single write depends on `enableAutoPipelining`, which ioredis leaves off by default.

  `getAccountLockoutSeconds` reads the threshold before the TTL. The underlying counter is created
  on the FIRST failed attempt, so its raw TTL is positive long before the lockout exists —
  returned unchecked it would show "locked for 14 minutes" beside an account whose next attempt
  would succeed, with the two reads contradicting each other on the same account.

  Argument order mirrors `unlockAccount(email, tenantId)` so the three read as a set, and a test
  asserts all three address the SAME record rather than pinning three copies of the preimage.

- **`authDocumentSecurity()` — the document-level default, derived instead of copied.** An OpenAPI
  contributor carries operations and components, never the document root, so the top-level
  `security` that covers a consumer's OWN routes stays theirs to set. But the scheme it has to
  name, and whether that scheme exists at all, are decided by THIS library's configuration. The
  consumer was left writing a name they do not control.

  Exporting `AUTH_SECURITY_SCHEMES` narrowed that and did not close it: a correct spelling read
  off a constant still leaves "which of the four applies to my deployment" unanswered, and the
  answer takes the guard family and `tokenDelivery` together. Every consumer setting a default was
  re-deriving it by reading this package's source.

  ```ts
  import { authDocumentSecurity } from '@bymax-one/nest-auth'

  security: authDocumentSecurity({ guard: 'dashboard', tokenDelivery })
  ```

  **Pass the option exactly as you wrote it, `undefined` included.** `tokenDelivery` is optional
  on the module, so a deployment relying on the documented `'cookie'` default has nothing to
  forward — and requiring a narrowed value here would have forced `options.tokenDelivery ?? 'cookie'`
  at the call site, putting a library decision back into consumer code one line further out.
  Omission resolves through the same constant the module resolves it with.

  It also settles the part a hand-written default usually gets wrong. Under `tokenDelivery: 'both'`
  the result is a two-entry **list** — OpenAPI reads that as OR, either transport satisfies it.
  Merged into one entry with two schemes it would mean AND, describing a server that demands the
  same credential twice.

  **Reported from a live failure, not from review.** A consumer whose `tokenDelivery` is a
  validated environment enum kept a hard-coded cookie scheme in their document default. Setting
  that variable to `bearer` stopped the process from booting: no cookie scheme is declared in that
  mode, and `assertSchemesDeclared` refuses a default naming one rather than serving a dangling
  reference. Reachable by configuration alone, with no code change and no warning.

  What it does **not** answer is what you mounted — the dashboard schemes are declared only where
  a dashboard controller is registered, and an OAuth-only or platform-only deployment declares
  neither. That row of the README's table is still yours, and the JSDoc says so rather than
  implying the call is sufficient.

  A conformance test now asserts that every scheme this function names is one the contributor
  declares for the same delivery mode. The two derive independently — the requirement from the
  guard family and the mode, the definitions from the resolved options and the registration — so
  nothing but that assertion makes them agree.

### Fixed

- **The sink's own documentation routed consumers into the wiring that drops
  `containsCredential`.** `AuthEmailSink` said `@bymax-one/nest-notification`'s
  `EmailService.send` "satisfies it structurally". True of the shape and false of the semantics:
  passed in directly, as that sentence invites, `containsCredential: true` lands in a property
  that library does not read, while its own switch — `publishProviderText` — stays at its
  default. A relay answering `550` with the offending body quoted then puts a reset code in an
  audit record, from a `send` call that looked correctly wired.

  The JSDoc now states that structural fit is not enough, that an implementation owes a
  **translation** of the flag into whatever its channel calls the same thing, and it names that
  library as both the worked example and the trap, with the adapter to copy. Nothing about the
  types changed; the field was always emitted. What changed is that the documentation stops
  pointing at the one configuration where it is ignored.

  Raised by the `nest-notification` seat, which is taking the symmetric half on its side. Emitting
  `publishProviderText` from here was considered and rejected: it would put another contract's
  vocabulary into this package's published surface, and that field has a rename open upstream.

- **The reuse-detection hook reported a compromise and no way to act on it.**
  `onRefreshTokenReuseDetected` fires on the strongest evidence this library produces — a refresh
  token presented after it was already exchanged, so one of its two holders is not the owner — and
  it received a context whose `ip` and `userAgent` were **empty strings**. `HookContext` declares
  both as required `string`, so the type promised a value the path did not deliver.

  The values were never unavailable: `reissueTokens(oldRefresh, ip, userAgent)` and its platform
  twin have both in scope as their own parameters, and the emit built
  `createEmptyHookContext()` anyway. `userId` says whose account the family belongs to; `ip` and
  `userAgent` are the only description of **who presented** the token. A report carrying the first
  and not the second names a victim and says nothing about the party holding a credential that
  should not exist.

  Both planes now carry them. `sanitizedHeaders` stays `{}` deliberately — the rotation path
  receives the address and the agent, never the header map, so there is nothing to sanitize and an
  invented value would be worse than an empty object a consumer can see is empty.

  Found by a consumer wiring the hook into a real backend and reading the emitted record, not by a
  test: the two specs covering this hook asserted the context as `expect.anything()`, which cannot
  distinguish a populated context from an empty one. Both now pin it exactly.

### Added

- **`AUTH_SECURITY_SCHEMES` is exported from the package entry**, and `AUTH_ERROR_STATUS` now
  also from `./shared`. Two different defects, worth keeping apart: `AUTH_SECURITY_SCHEMES` was
  declared and never re-exported, so there was nowhere to import it from at all;
  `AUTH_ERROR_STATUS` shipped from the server entry and only from there, so reaching it meant
  pulling the NestJS peer dependencies — which the three cases the README points at (a typed
  client, an API document, a browser test) are precisely the ones that must not.

  The scheme names are stable identifiers — renaming one is a break a generated client feels —
  while their DEFINITIONS are derived from configuration, which is why the names are worth
  exporting and the definitions are not. A platform-only deployment guarding its own routes with
  `JwtAuthGuard` has to declare the dashboard access scheme itself, because `schemesFor` gates
  dashboard schemes on `dashboardMounted`; before this it was told to write
  `bymaxAuthAccessCookie` by hand, with nothing checking the spelling, in a section whose whole
  subject is that literals drift from configuration.

  The 1.4.3 entry and the README both said the constant was not public and to use string
  literals. **That advice is now wrong**; the 1.4.3 section is left as written, because it was
  true when it shipped, and this entry is the correction. The README paragraph is rewritten.

### Security

- **The tenant-scoped user port did not bind, and a stale implementation destroyed the password
  hash.** `IUserRepository`'s ten account-naming methods took the tenant as a positional
  `string`. TypeScript accepts an implementation with FEWER parameters, so a consumer who
  upgraded and did not touch their repository still type-checked — proven, not argued:

  ```
  $ tsc --noEmit --strict   # a pre-upgrade implementation against the shipped port
  exit code: 0
  ```

  Two consequences. Their `findById(id)` ignored the tenant, so the cross-tenant read the entry
  below closes stayed open on a clean build, with no error and no warning. And the library calls
  `updatePassword(userId, tenantId, hash)`: a stale two-parameter implementation bound
  `passwordHash = tenantId` and wrote the tenant id into the credential column.

  **Every one of those methods now takes a single object.** An object parameter is structurally
  incompatible with the old positional shape, so the same implementation fails to compile instead
  of failing in production. `TenantScopedUserRef` and the eight params types are exported from the
  package entry, because a consumer implements this port and needs to name what it receives.

  **Apply to a derived backend.** Every `IUserRepository` method that names an account takes ONE
  object now — `findById`, `findByEmail`, `updatePassword`, `updateMfa`, `updateLastLogin`,
  `updateStatus`, `updateEmailVerified`, `updateEmail`, `findByOAuthId` and `linkOAuth`. Destructure
  it and keep filtering on the tenant. **Eight of the ten are keyed by `id`.** Seven of those are
  writes: on Prisma they are still `updateMany({ where: { id, tenantId } })` rather than
  `update({ where: { id } })`, because `update` takes a unique clause and cannot carry the pair.
  The eighth, `findById`, is a **read** — it filters on the same pair through `findFirst`, because
  `findUnique` by id alone can answer with another tenant's row. **The other two are not keyed by
  `id` at all:** `findByEmail` receives `{ email, tenantId }` and `findByOAuthId` receives
  `{ provider, providerId, tenantId }`, and each filters on its own lookup key plus the tenant.

  ```ts
  // before → after, for every signature that changed
  findById(id, tenantId)
  findById({ id, tenantId })

  findByEmail(email, tenantId)
  findByEmail({ email, tenantId })

  updatePassword(id, tenantId, passwordHash)
  updatePassword({ id, tenantId, passwordHash })

  updateMfa(id, tenantId, data)
  updateMfa({ id, tenantId, data })

  updateLastLogin(id, tenantId)
  updateLastLogin({ id, tenantId })

  updateStatus(id, tenantId, status)
  updateStatus({ id, tenantId, status })

  updateEmailVerified(id, tenantId, verified)
  updateEmailVerified({ id, tenantId, verified })

  updateEmail(id, tenantId, email)
  updateEmail({ id, tenantId, email })

  findByOAuthId(provider, providerId, tenantId)
  findByOAuthId({ provider, providerId, tenantId })

  linkOAuth(userId, tenantId, provider, providerId)
  linkOAuth({ id, tenantId, provider, providerId })
  ```

  **This supersedes the note in the tenant-scoping entry below**, which told you to take `tenantId`
  as the _second argument_. Follow that note today and the implementation does not compile:
  `findById(id: string, tenantId: string)` is rejected against `findById(params: TenantScopedUserRef)`
  with `TS2416 — Target signature provides too few arguments`. That loud failure is the entire point
  of the shape.

  What still passes silently is narrower, and worth stating exactly rather than overstating:
  TypeScript accepts an implementation declaring FEWER parameters than the signature, so one taking
  no parameters at all compiles — and so does one that takes the object and never reads `tenantId`
  off it. The compiler rules out a value bound into the wrong slot. It cannot rule out a body that
  ignores the tenant, which is why every method documents the scoping as a MUST.

  The `AuthService` guidance in that note is unaffected:
  `getMe(userId, tenantId)` and `issueTokensForUserId(userId, tenantId, ip, userAgent)` are
  unchanged. The README's example implementation shows the whole shape.

  ```ts
  // before
  await repo.updatePassword(userId, tenantId, hash)
  // after
  await repo.updatePassword({ id: userId, tenantId, passwordHash: hash })
  ```

  The property is pinned by a type test that compiles a stale implementation against the real port
  and requires `tsc` to refuse it, with a positive twin that compiles the current shape — a
  negative test that cannot pass for the wrong reason. Nothing else in the suite can see this:
  every other check reads the declaration, and a positional signature reads as correct in all of
  them. One residual hole is stated rather than hidden: TypeScript always accepts an
  implementation taking NO parameters, which cannot put a value in the wrong slot.

- **Two re-authentication counters were tenant-blind.** `changePassword` and `requestChange`
  scoped their account read and then derived the brute-force identifier from
  `reauth:{flow}:{userId}` — the bare id. A repository id is unique only within a tenant, so
  failures against `t1/u1` spent `t2/u1`'s budget and locked that account out of changing its own
  password or address without any credential, and a success on either side cleared the other's
  count. Both now derive from the injective `userSubject`, and the tests assert the separation
  rather than pinning a digest — a pinned hex string is satisfied by any preimage that produces
  it, so updating the constant after a preimage change keeps the test green with its rule gone.

- **Two tenants could share one session index, one token epoch and one recovery-code claim.**
  The subject every user-derived key is HMACed over was `dashboard:{tenantId}:{userId}`, and a
  bare `:` between two free-form components is not injective. Both halves may legitimately
  contain it — the DTO charset deliberately admits a tenant id like `acme.eu-west-1:prod`, and a
  composite `tenant:user` subject is a documented `sub` shape — so:

  ```
  tenantId 'acme:prod' + userId 'u1'      ->  dashboard:acme:prod:u1
  tenantId 'acme'      + userId 'prod:u1' ->  dashboard:acme:prod:u1   <- same preimage, same HMAC
  ```

  Two unrelated tenants then shared every key derived from it: the session index, the token
  epoch, the five MFA store keys, the three MFA failure counters, the recent-authentication
  marker and — worst — `rcu:`, the claim that stops a recovery code being spent twice. Revoking
  one tenant's sessions swept the other's, and one tenant could spend the other's recovery code.
  That is precisely the cross-tenant revocation the entry below removes, reintroduced through the
  delimiter.

  **Whether a given deployment could reach that collision depends on its user ids, and the two
  halves are not equally exposed.** The `tenantId` half is attacker-chosen by default: it arrives
  in the request body, validated only for length and control characters, and a deployment only
  takes that away by configuring `tenantIdResolver`. The `userId` half comes from
  `IUserRepository`, and the **scheme** is the host's — but the resulting value is not
  automatically outside the caller's reach, because `CreateUserData` carries `email` and `name`
  straight from the registration request. `name` in particular is validated for length and
  nothing else: no charset constraint, so `:` passes. A host that derives its id from either
  field has handed the caller influence over both halves.

  The arithmetic makes the user id the gate. For `{t1}:{u1}` and `{t2}:{u2}` to render the same
  string with `(t1,u1) ≠ (t2,u2)`, one of the two **user ids** must itself contain a `:` — there
  is no way to move the boundary otherwise. Three tiers follow, and they are not the same risk:

  - **Host-generated ids with no colon** (UUID, a sequence): unreachable. The preimage is
    ambiguous in principle and no input can exercise it.
  - **Composite host-assigned ids** (`dept:1234`, a stored `tenant:user` subject): reachable by
    accident. Two unrelated accounts can collide with nobody trying.
  - **Ids derived from caller-supplied input in a way that PRESERVES the delimiter** (the display
    name stored verbatim; a `{name}:{n}` disambiguator): reachable **on purpose**. The attacker
    picks the tenant, then picks a value that splits the preimage where they want, and both
    halves are theirs. `name` is the field that carries this: `@IsString`, `@MinLength(2)`,
    `@MaxLength(128)` and **no charset rule**, so a `:` passes.

    The address is the instructive near-miss. `@IsEmail` does accept a colon —
    `"ana:silva"@x.com` is a valid addr-spec with a quoted local part, and class-validator
    takes it. What saves the scheme is the second half of the condition below: splitting there
    leaves `silva"@x.com`, and that is not a valid address, so no second account can hold it.
    The colon is present and the suffix pair still cannot be formed.

    The qualifier carries the tier, and it is a property of the **sets of values the two sides
    admit**, not of one id and not of the transform that made it. A colon in the id is necessary
    and not sufficient. Both halves have to cooperate:

    > can the id scheme produce two valid ids `u1` and `u2` with `u1 = p + ":" + u2`, **and** is
    > `t + ":" + p` still a valid tenant for some tenant `t` the caller can send?

    Only then does moving the boundary turn one pair into the other. The tenant clause is not
    decoration: a body-supplied tenant is non-empty, at most 128 characters and control-free, so
    a scheme whose only suffix pair needs a 200-character or control-bearing `p` satisfies the
    first clause and is still unreachable.

    A worked pair that clears every validator this library applies:

    ```
    name 'ana:silva' -> id 'ana:silva'      tenant 'acme'      -> dashboard:acme:ana:silva
    name 'silva'     -> id 'silva'          tenant 'acme:ana'  -> dashboard:acme:ana:silva
    ```

    And the case that does **not** qualify despite carrying a colon: a fixed-width
    `sha256:{64 hex}` id. Every id in that scheme is the same length, so none is a proper suffix
    of another, and no tenant makes `t1:u1` equal `t2:u2`. Slugging to `[a-z0-9-]`, or rendering
    a digest as bare hex or base64url, removes the delimiter and settles it a step earlier.

    Read the value sets you can actually store — not the provenance of the input, not the
    transform's reputation, and not one example id in isolation.

  That third tier is the reason the previous wording mattered: it read as though the user id were
  always the host's to control, which would have left this the mildest of the three. The tier is
  narrow on purpose — a note that over-warns gets discounted the same way one that under-warns
  gets ignored, and only one of those failures is visible to whoever wrote it.

  That does not make the fix conditional. A library may not assume the shape of ids its consumers
  assign — it is the same assumption `findById` taking a tenant already refuses to make — and a
  preimage that is injective only for well-behaved input is not injective. But an operator
  reading this entry should be able to tell which side of that line they are on, and the previous
  wording did not let them.

  **This predates the release.** The same preimage shipped in 1.4.3 as `mfaSubject`, backing the
  MFA keyspace; renaming it to `userSubject` and extending it to `sess:`/`ep:` widened the blast
  radius rather than creating it.

  The dashboard arm now carries a length prefix —
  `dashboard:{utf8ByteLength(tenantId)}:{tenantId}:{userId}` — which makes the split unambiguous
  while rejecting no identifier, and the charset is deliberately permissive. The platform arm has
  one component after the plane and is unchanged.

  **The prefix counts UTF-8 bytes, not characters**, and the contract says so: JavaScript's
  `String.length` counts UTF-16 code units while Rust's `str::len()` counts bytes, so `açaí` is 4
  by one measure and 6 by the other. A character count would agree for ASCII and derive different
  keys on the first accented tenant id — a split between the paired libraries that shows up only
  in production, in one locale.

  **Apply to a derived backend.** The MFA keyspace relocates too, on top of the session and epoch
  migration described below, under the same first rule — copy state forward, never drop it — but
  **not** under the same fan-out. Those keys already carried the tenant, so the remap is 1:1 for
  every pair, with one exception that is the entire point of this entry: a pair that was
  **colliding** shared one old key, and that key has to be written to each of the pairs that shared
  it. There is no way to tell from the old key which of them last wrote it, so copy it to all of
  them and let the safe direction win — for `rcu:`, a claim present on a code that was never spent
  costs one unusable recovery code, while a claim missing on a code that WAS spent makes it usable
  again. The MFA keys are where dropping is least acceptable for exactly that reason.

- **Suspending one tenant's user revoked another tenant's.** The session index and the token
  epoch were keyed on the bare user id — `sess:{userId}` and `ep:{userId}` — while the status
  cache beside them had been tenant-scoped for releases. `IUserRepository.findById` takes a
  `tenantId` precisely because ids may not be unique across tenants, so on a deployment that
  numbers users per tenant, deleting or suspending `t1/u1` swept the sessions and bumped the
  token epoch of `t2/u1`. A **credential-free cross-tenant revocation**, reachable by anyone who
  can get an account suspended in their own tenant.

  Both keys now derive the way every other account-naming key in this library already did:
  `{prefix}:{hmac_sha256(hmacKey, userSubject)}`. The **derivation** was not invented here — it is
  what the five MFA store keys, the three MFA failure counters and the recent-authentication
  marker have used since they were fixed for the same reason, and the wire contract already
  carried its argument. The two joining it close the gap between what `recentAuthKey`'s own
  documentation claimed — _"keyed by HMAC rather than the raw id, like every other user-derived
  key in this library"_ — and what was true.

  The **subject** those keys are derived from does change in this release, and the entry above is
  why: it is now `dashboard:{utf8ByteLength(tenantId)}:{tenantId}:{userId}` on the dashboard plane
  and `platform:{userId}` on the platform one. The form it inherited from the MFA keyspace —
  `dashboard:{tenantId}:{userId}`, without the length prefix — is the one that was not injective.

  The HMAC is the second half and it matters on its own: rust-auth reads this keyspace, so a
  bare id there was an account identifier in the clear to anyone with store access. A user id
  carries too little entropy for a plain digest to hide, which is why the identifier preimages
  are HMACed rather than merely hashed.

  The platform plane keeps no tenant segment. Its admins are cross-tenant and have none, exactly
  as `userSubject`'s platform arm has always said.

  **Apply to a derived backend.** The five `SessionService` methods —
  `createSession`, `listSessions`, `revokeSession`, `revokeOtherSession`,
  `revokeAllExceptCurrent` — now take a **single object** instead of positional arguments:

  ```ts
  // before
  await sessions.listSessions(user.sub, currentHash)
  // after
  await sessions.listSessions({ userId: user.sub, tenantId: user.tenantId, currentSessionHash })
  ```

  The object is the point, not a style preference. Threading the tenant through positionally put
  a second `string` beside `userId`, and the old two-argument call **still compiled** against the
  new signature — binding the session hash to `tenantId` and returning an empty listing that is
  indistinguishable from "this user has no sessions". On `revokeSession` the same transposition
  is a revocation that silently reaches nothing. A named field cannot be transposed; the worst it
  can be is misspelled, which the compiler catches. `CreateSessionParams`, `ListSessionsParams`,
  `RevokeSessionParams` and `RevokeAllExceptCurrentParams` are exported from the package entry so
  a caller can name the shape.

  `AuthService.revokeAllSessions` takes the same treatment and for the same reason — two
  unconstrained strings side by side, where `revokeAllSessions(user.tenantId, user.id)` compiled,
  derived an unrelated subject and returned normally:

  ```ts
  await auth.revokeAllSessions({ userId: user.sub, tenantId: user.tenantId })
  ```

  Also taking the tenant they always needed: the three
  `AuthRedisService` entry points (`invalidateUserSessions`, `getUserTokenEpoch`,
  `bumpUserTokenEpoch`), whose `kind` argument also **loses its default** — a positional tenant
  next to a positional plane is a transposition nobody notices, and the two call sites that
  passed `'platform'` in what became the tenant slot compiled silently until the default was
  gone. If you call any of these, pass `user.tenantId`; on the platform plane pass `undefined`
  and name the plane.

  `readSessionOwner` now answers `{ userId, tenantId }`. Logout takes both off the record the
  refresh token just proved possession of, rather than from a caller who could aim the
  revocation at a colliding id. A record written before this carries no tenant: the index revoke
  is skipped rather than guessed, and the session still dies because `rt:{hash}` is deleted
  either way.

  **This is a paired wire change and it has no compatibility path.** `sess` and `ep` are pinned
  in `conformance/wire-contract.json` and byte-shared with `@bymax-one/rust-auth`; a backend on
  the old shape writes `sess:{userId}` while one on the new shape reads `sess:{hmac}`, so
  sessions survive a revoke-all that never saw them. **Both libraries must ship this in the same
  release.**

  **Three paths now fail closed on a dashboard subject with no tenant**, because an absent
  tenant interpolates as the literal text `undefined`, so `userSubject` builds
  `dashboard:9:undefined:{userId}` — a keyspace belonging to no tenant, in which nothing has ever
  been written. The MFA flows already refused a blank tenant for exactly this reason; these three did
  not.

  - `AuthRevocationService.isAccessTokenRevoked` **failed open**: it read the epoch under
    `dashboard:9:undefined:{sub}`, got `0`, and reported a bulk-revoked token as valid. It is
    exported for callers that never pass a guard — a realtime bridge checking a socket — and its
    payload type marks `tenantId` optional, so the omission is a shape a caller can produce. A
    dashboard payload without a tenant is now treated as **revoked**, without touching the store.
  - `reissueTokens` accepted a **pre-upgrade record**: `parseSession` validates `userId`, `role`
    and `mfaEnabled` but never `tenantId`, so a session written before this change rotated into
    `dashboard:9:undefined:{userId}` and minted an access token with no tenant claim — one every
    dashboard guard then refuses. The caller held a session that could be neither used nor
    revoked. Both the primary and the grace-recovery path now refuse it as
    `REFRESH_TOKEN_INVALID`; the platform plane is exempt, its subject carries no tenant segment.
  - `revokeFamily` derived an index for such a record and pruned a key nobody writes while the
    real index kept every member. It now omits the index, exactly as logout already did.

  **Deploy this as a cutover, not a rolling upgrade.** Drain the pods on the old release before
  the new ones serve. The MFA keyspace is where this bites hardest: `mutate`'s transition lock,
  which serializes the read-modify-write on the recovery-code list, is keyed by the same subject
  as everything else — so two pods that disagree about the subject take **different locks and do
  not exclude each other at all**, and the `rcu:` claim that stops a code being spent twice splits
  the same way. The library carries a fallback for the _pre-tenant_ preimage but deliberately none
  for the tenant-scoped one this release replaces: a fallback is compatibility weight for a
  deployment shape the cutover removes the need for.

  **A live keyspace must be migrated, not dropped.** Deleting the old keys is unsafe in both
  directions, and each direction is a hole rather than an inconvenience.

  **On the dashboard plane the migration is a fan-out: one old key becomes N new ones.** The old
  keys are tenant-blind — `ep:{userId}` and `sess:{userId}` name a bare user id — which is the
  defect this release removes, so a single old key served **every** tenant that has a user with
  that id, and each of those pairs derives its own key now. Copying an old key to one derived key
  and dropping it migrates one tenant and silently resets all the others: for them it is not a
  partial migration, it is exactly the deletion described below. Enumerate the tenants that user
  id appears in and write every one of them. On the platform plane the mapping is 1:1 — that
  subject carries no tenant — so the fan-out is a dashboard-only obligation.

  Deleting an old `ep:{userId}` does not expire the tokens it revoked. `getUserTokenEpoch` answers
  `0` for an absent key — `Number(null)` is `0`, and that is deliberately the "never bumped"
  default — and under `0` the `stamped < epoch` test is false for **every** token. A password
  reset, an MFA reset or a sign-out-everywhere that had already invalidated an access token is
  undone by the migration, and that token works again for the rest of its lifetime. Epochs must be
  **copied to every derived key the old one served**, each with at least the old value and at
  least the remainder of its TTL, and only then dropped. An epoch may never move backwards.

  Deleting an old `sess:{userId}` does not end the sessions it listed. Its `rt:`/`rp:` members
  outlive the index and become unreachable: a later revoke-all reads the new, empty index, finds
  nothing to delete, and reports success while those refresh tokens keep rotating. Either re-add
  the members under the derived index keys, or delete the member keys and their `sd:` details
  **before** dropping the index. The second costs a forced re-login and is the safer of the two;
  the first preserves sessions and must be done atomically per user.

  Re-adding is where the fan-out bites hardest, because the old index **mixes tenants**: its
  members are the sessions of every tenant's user with that id, so emptying it into one derived
  index would hand that tenant another's live sessions — worse than the collision being fixed,
  because it turns a shared keyspace into a listable, revocable cross-tenant handle. Partition
  instead: every member names an `rt:`/`rp:` record carrying its **own** `tenantId`, so read the
  record, derive that pair's index, and place the member there. A member whose record is already
  gone is a dead session and is dropped rather than guessed at.

  **Both obligations apply to the PLATFORM twins, `pep:{userId}` and `psess:{userId}`, which this
  release relocates identically.** They are the easier pair to forget and the worse pair to get
  wrong: a platform epoch left behind revalidates previously revoked **admin** JWTs, and a
  platform index left behind hides an admin's live refresh sessions from revoke-all. The platform
  subject carries no tenant segment — `platform:{userId}` — but the HMAC relocates the key just as
  it does on the dashboard plane, so "we have no tenants" is not a reason to skip either step.

- **The dashboard user port let every account read and write skip the tenant.** The sibling half
  of the entry above, on the layer the keyspace fix cannot reach. `IUserRepository` documented the
  rule — _"ids may not be unique across tenants"_ — and then declined to enforce it, in three
  shapes that hid one another because they sat on adjacent lines:

  - `findById(id, tenantId?)` took the tenant as **optional**, for _"internal admin flows where
    cross-tenant access is intentional"_. All twelve of this library's own call sites omitted it,
    and not one was such a flow: `getMe`, `changePassword`, the email-change request and confirm,
    the three invitation authority checks, the OAuth re-fetch, the session-limit resolver, the
    WebSocket ticket snapshot and the password-reset fingerprint all read the account by bare id.
    On a host that numbers users per tenant, each of those could resolve **another tenant's row**
    — and then decide status, role, MFA state or a password change against it.
  - Six mutators — `updatePassword`, `updateLastLogin`, `updateStatus`, `updateEmailVerified`,
    `updateEmail`, `linkOAuth` — took **no tenant at all**, under JSDoc telling implementations
    they MUST scope the write. An obligation the signature does not permit fulfilling is not a
    contract; the implementation has nothing to scope by.
  - `updateMfa` typed its tenant `string | undefined` beneath a sentence promising it was _"never
    omitted for a dashboard account"_.

  Every method now requires `tenantId: string`, positioned immediately after the account id, and
  the library passes it everywhere. `MfaService` gained `assertDashboardTenant`, an assertion
  signature splitting the dashboard half out of the existing `assertPlaneTenant` so the guard the
  entry points already ran narrows the type instead of only throwing.

  **The rule is now a test, not a paragraph.** `test/e2e/tenant-scoped-port.e2e-spec.ts` reads the
  port's TypeScript AST and fails when a method can name an account without a tenant, when the
  tenant is typed anything but `string`, when it does not follow the id, or when
  `IPlatformUserRepository` — whose admins belong to no tenant — grows one. It also compares the
  README's example `PrismaUserRepository` signature-for-signature against the port: that example
  is what a consumer pastes in, and it had drifted to `update({ where: { id } })` on six mutators,
  a query that crosses tenants by construction. Prose does not close by grep.

  **Apply to a derived backend.** **Superseded — see the object-parameter entry above.** The
  positional shape described here no longer compiles against the port: written as this note
  describes it, the implementation is rejected with `TS2416`. Kept as written because this entry
  describes the release it shipped in; the note above is the one to follow.

  Your `IUserRepository` implementation must take `tenantId` as
  the second argument of `findById`, `updatePassword`, `updateMfa`, `updateLastLogin`,
  `updateStatus`, `updateEmailVerified`, `updateEmail` and `linkOAuth`, and must filter on it. On
  Prisma that means `updateMany({ where: { id, tenantId } })` rather than
  `update({ where: { id } })` — `update` takes a unique clause and so cannot carry the pair. Two
  service methods take the tenant too: `AuthService.getMe(userId, tenantId)` and
  `AuthService.issueTokensForUserId(userId, tenantId, ip, userAgent)`; pass `user.tenantId` from
  the verified claims. The README's example implementation shows the whole shape.

### Fixed

- **The compromise line left `userId` empty on repeat attack traffic.** `revokeFamily` resolves
  the owner by reading the first LIVE member of the token family. On the second and later replay
  of an already-revoked family there is none — the consumed marker outlives the sessions it points
  at, so reuse is detected again while every record that could name the owner is gone — and the
  line read `userId= familyId=…`.

  That is an empty field on what this library's own documentation calls the strongest evidence of
  compromise it produces, and `userId` is the only field an on-call can act on. It emptied
  precisely on **repeat** attack traffic, which is the traffic worth reading.

  The line now says what is unknown and what was measured:
  `userId=<unknown: no live session remains in this family to name it>`. An empty field reads as a
  defect in the logger and makes a reader distrust the tool instead of the event; a family with no
  readable member is itself the fact worth seeing. The `familyId` is still named, because it is
  the only handle left on the lineage.

  It names the observation and not a cause on purpose. `readFamilyOwner` answers with nothing for
  three different reasons — every member record gone, a member whose JSON will not parse, a member
  carrying no `userId` — and only the first is the already-revoked case, which even then cannot be
  told apart from ordinary TTL expiry. A line asserting "already revoked" would send an on-call
  looking for a revocation during what may be store corruption.

  Reported by the `@bymax-one/bymax-one` seat from a measured audit against real Postgres and
  Redis — two runs of the same path, one populated and one not. The cause was traced rather than
  guessed, and it also explains their second observation: a `revoked` line with no `detected` line
  before it is the same repeat replay.

- **The README's own contract test could not fail for a name mentioned anywhere in a barrel.**
  It searched the barrel's SOURCE TEXT for the identifier, so a name in a comment, a JSDoc
  paragraph or an internal import satisfied it without being exported. `src/client/index.ts`
  carries the sharpest instance — a comment reading _"Constants like `AUTH_ERROR_CODES` and
  `AUTH_ROUTES` stay [in shared]"_ — so a README documenting either import FROM `/client` passed
  on the strength of the very sentence saying it does not export them. Measured: across the five
  barrels, 77 capitalised tokens appear in text without being exports.

  It now reads the barrel's export DECLARATIONS from the TypeScript AST, and four arms joined it:
  no barrel may `export *` (which would name nothing and make the check under-report); the README
  may not call a symbol non-public that a barrel exports (the contradiction this release ships the
  fix for); the documented subpaths are checked against **`package.json#exports`** rather than the
  suite's own hand-kept map, which agreed with the manifest only for as long as somebody kept both
  in step; and every published subpath must have a source barrel mapped, because an unmapped one
  was skipped silently by the arms above.

  The scheme-table check had the same defect in a second form: it searched the **whole README** for
  each scheme name, so deleting the `controllers.platform` row still passed — the name appears
  three more times below the table. That table had already lost a row twice, under a check that
  was running the whole time. Completeness is now asked of the table alone; invention is still
  asked of the whole document, because a name the prose made up is wrong wherever it sits.

  And the claim that `AUTH_ERROR_STATUS` ships from `/shared` was prose, which this suite does not
  read — removing the export left it green. It is shown as an import now, which the suite does
  read.

- **A rate-limited refresh signed the user out of a session that was still valid.**
  `createAuthFetch`'s refresh reduced the response to `response.ok`, so `429`, `401`, `503` and a
  `404` from a mistyped `routePrefix` arrived at the caller as one indistinguishable `false` — and
  the caller treats `false` as expiry. Measured by a consumer against a real browser round; twelve
  browser specs passed on both runs that produced the finding, so no green suite covered it.

  `performRefresh` now returns a `RefreshOutcome`: `{ ok: true }`, or `{ ok: false, reason, status }`
  where `reason` is `'rejected'` (a 401, **or a 403 whose error code names a terminal account
  state** — the server looked at the credential and refused it, so `rejected.status` is `401` or
  `403`), `'unavailable'` (it answered, but not with a session) or `'unreachable'` (no answer at
  all).
  **`onSessionExpired` now fires only on `'rejected'`.**

  403 is decided by the error **code**, because the route answers it for two unrelated reasons.
  `TrustedOriginGuard` covers `/refresh` and answers `auth.untrusted_origin` with 403 — reading
  that as expiry would sign out every user of a deployment whose `trustedOrigins` is wrong. But
  `refresh` also revokes every session before rethrowing a blocked-account status
  (`auth.account_suspended`, `auth.account_banned`, `auth.account_inactive`,
  `auth.pending_approval`), and there the session really is over. The wrapper reads the code
  itself, since it drains the refresh body and the caller only ever sees the original response.

  A new `onRefreshFailed?: (failure: RefreshFailure) => void` reports **every** failure with its
  reason and status, before the expiry decision. That is what makes the answer to _why_ usable: a
  rate limit deserves "retrying", a dropped connection deserves "you appear to be offline", and
  only a refused credential deserves the sign-in screen.

  A `429` branch was offered and declined by the consumer who found it: _"the refresh needs to
  report why it failed, not whether"_. A boolean with one carve-out reproduces the same defect for
  whichever status matters next.

  **Behaviour change for consumers.** Before, any refresh failure invoked `onSessionExpired`. Now a
  dropped connection, a rate limit or a server fault does not — the caller still receives the
  original `401`, so a failed request stays failed, but it no longer receives a claim that the
  session is over. If you relied on the callback to mean "the refresh did not succeed", read the
  `reason` instead: `RefreshOutcome` and `RefreshFailureReason` are exported from
  `@bymax-one/nest-auth/client`.

### Security

- **No error object reaches the logger any more.** Twenty-seven log sites passed the thrown value
  as Nest's second `Logger` argument, which prints its `stack`. On every one of those paths the
  thrower is code this library does not own: a hook, an OAuth plugin, the consumer's repository,
  a Redis client — and in `AuthExceptionFilter`'s case, literally anything the surrounding
  application threw. None of them hands the logger an error object any more, and on the twenty
  sites where the caller could not name what the thrower held, **nothing the thrower authored is
  published at all** — `describeChannelStatus` reports the shape of the failure (that a throw
  happened, and how many links its `cause` chain has) and reads neither `message` nor `name` nor
  `stack`. Where the caller CAN name the values it passed in, `describeError` still publishes the
  text with those removed.

  **An empty redaction list is the shape that looked safe and was not.** `describeError(err, [])`
  publishes the thrower's `name` and `message` with an empty list asserting there is nothing to
  remove — an assertion none of these call sites can make, because every thrower on them is
  consumer code: a repository handed `findByEmail(dto.email, tenantId)`, a hook handed the IP and
  user agent, a `maxSessionsResolver` handed the full `AuthUser` including the password hash, a
  repository call carrying re-encrypted MFA material. A consumer error that quotes its own input
  put those in the log. The empty list did not make the line safe; it removed the only defence
  being attempted while reading like one. The form is now banned outright and the guard suite
  enforces it.

  **A partial list is the same defect with a longer sleeve.** Seven more sites named one to three
  fields while the thrower had been handed a whole object: every `afterRegister`, `afterLogin`,
  `afterEmailVerified`, `afterPasswordReset`, `afterInvitationAccepted` and `onNewSession` hook
  receives the complete `SafeAuthUser`, so a hook throwing `new Error(user.name)` published a name
  that no list mentioned. Those are opaque now too. What survives is the rule the list was always
  meant to express — **name the values the thrower actually received** — which three sites can
  still satisfy honestly, because they hand a repository or a hook exactly one identifier and
  name exactly that.

  Those three also had the list naming the wrong string: `describeError(err, [logSafe(user.id)])`
  redacted the SANITISED id, and `logSafe` returns `<malformed>` for precisely the ids worth
  worrying about — so the value the repository was handed was not in the list at all. They name
  the value as passed now, and the guard rejects any redaction list containing a call.

  **The highest-value site was not in the original report.** `OAuthService.handleCallback` wraps
  `plugin.exchangeCode(code, codeVerifier)` and `plugin.fetchProfile(accessToken)`. The plugin is
  consumer code that RECEIVED all three, and an HTTP client attaching its request config to the
  error is the ordinary case rather than an exotic one — axios does it by default. A live access
  token could reach the operator's pipeline through a rejection this library then logged in full.
  The handler publishes nothing the plugin wrote. Naming the three values was the first fix and it
  was the weaker half by its own reasoning: redaction is a substring match, so it holds for a token
  the plugin echoed as given and not for one it re-encoded — and a token inside a base64 or
  URL-encoded request body is not present as written. The test drives exactly that: the plugin
  echoes the token base64url-encoded, and the line contains neither form.

  The second was found by the guard rather than by reading: `AuthExceptionFilter`, whose parameter
  is called `exception`, not `err`. It is the branch a re-thrown mail-channel error lands in under
  `onDeliveryError: 'rethrow'` — this library's own documentation says so — so it is the most
  exposed log site of the set, and a name-based sweep walked straight past it.

  **What you lose:** the stack trace for a hook, plugin or repository failure. That stack belongs
  to the consumer's own code, which can log it where the audience is known; a library's log line
  reaches a wider one. Same argument that took the recipient address out of the delivery-failure
  line. On the twenty opaque sites you also lose the message and the error's class; what remains
  is that a failure happened, where, and how deep its `cause` chain ran.

  `redactSecrets` was hardened in the process. It read `.length` off each element, so a single
  `undefined` in the list threw a `TypeError` — out of a `catch` block, turning a failure the
  caller meant to absorb into an unhandled rejection with no log line at all, which is worse than
  the leak it exists to prevent. It is exported, so a consumer reaches that edge from plain
  JavaScript. Found when a caller named a field the compiler believed was a `string`; the suite
  did not fail an assertion, it crashed the worker.

- **A consumer-supplied identifier could forge a second record in the log.** Every value this
  library interpolates into a log template now passes a guard: `logSafe` for identifiers,
  `maskEmail` for addresses, `describeError` for a rejection's own text. Forty-eight
  interpolations did not, across nine files.

  `IUserRepository` places no character constraint on `id`, `role` or `tenantId` — `role` is a
  bare `string` in the interface — so a value carrying CR/LF closes the log record and opens one
  the reader attributes to this library. That is the attack `logSafe` was written for.

  **The convention already existed and had been applied to `tenantId` at fourteen sites.** It was
  never extended to anything else, and the omission was invisible because it sat on the SAME
  LINES: `userId=${user.id} tenantId=${logSafe(tenantId)}` reads as deliberate until you ask why
  one half is wrapped and the other is not.

  Two sites went further and stringified a rejection straight into the line
  (`logout: session cleanup failed — ${String(err)}`). `String()` strips nothing and bounds
  nothing; those now go through `describeError`, which does both. The rejection is Redis's rather
  than a mail channel's, so no credential is implied — but the failing key it names embeds the
  consumer's user id.

  A guard suite (`test/e2e/log-injection-guard.e2e-spec.ts`) now walks every `this.logger.*` call
  in `src/` and fails on any interpolation that is neither guarded nor named in an explicit
  allowlist of values this library authors. It fails **closed**: a new interpolation breaks the
  build until somebody decides which it is. The guard call must BE the whole expression —
  `${logSafe(a) || attackerValue}` is rejected, as are a concatenation, a ternary arm, and a
  helper whose name merely starts with a guard's.

  It reads the **TypeScript AST**, not the text. Three hand-rolled scanners preceded it and each
  was fooled by ordinary punctuation: a comma inside a message read as an argument separator, a
  `)` inside a template's literal text ended the call early, and a guard's name matched anywhere
  in the expression. Parentheses and quotes inside string literals defeat every version of that
  approach, and a gate whose parser can be fooled by punctuation is not a gate. It caught the two `String(err)` sites on its first
  run, which is the argument for it — forty-eight had drifted silently under a convention that
  lived only in reviewers' heads.

  Two corrections to the walker itself, both held by synthetic fixtures because `src/` has no
  example of either. It now knows `fatal`, the sixth level Nest 11's `Logger` exposes — a level
  list has to be complete rather than sufficient, and the first `this.logger.fatal(...)` anyone
  wrote would otherwise have been invisible to a gate claiming to walk them all. And it no longer
  descends into a guard's argument: what reaches the record is the guard's OUTPUT, so
  ``logSafe(`id=${user.id}`)`` was being reported twice, once as guarded and once as bare, failing
  a line that cannot carry a control character. A false positive on correct code is how a gate
  gets weakened by whoever hits it next.

  Requires no action from a consumer: `logSafe` returns an ordinary identifier unchanged, so log
  lines are byte-identical unless a value actually carried a control character, in which case the
  field is replaced with `<malformed>` and the record stays one record.

  **`maskEmail` was one of those guards and did not enforce the boundary.** It preserves the
  domain verbatim to keep the line useful to an operator, so `a@example.com\nforged` masked to
  `a***@example.com\nforged`: the address was hidden and the injection was not, and being on the
  allowlist meant the gate reported those sites as safe. Masking and record safety are two
  separate duties and the helper owed both; it now passes its result through `logSafe`. The
  addresses reaching those lines are not all DTO-validated — `profile.email` is whatever an OAuth
  provider's userinfo response contained and `oldEmail` is whatever the host's repository stored,
  so `@IsEmail()` saw neither. The allowlist's claim is now a test rather than a sentence: every
  name on it is fed a value carrying LF, CR, NEL and both Unicode separators, and must return
  something that cannot end a record. `safeLogLine` was removed from the allowlist in the same
  pass — it is a check on a fully composed line, not a field guard (`safeLogLine(raw, [])` is
  `raw`), and it appears inside no interpolation in `src/`.

- **`onDeliveryError` takes a per-message map, so an opt-in stops being all-or-nothing.** It was one
  switch for all ten messages. A deployment sets `'rethrow'` for a specific benefit — deleting an
  undelivered reset token early, not recording "verification sent" for a send that failed — and the
  same setting then handed it the channel's **original, unlaundered** error on every other path.
  Five messages render a credential, and those two flows are two of the five — so the bare form
  reached three further credential-bearing paths that neither flow asked for.

  ```typescript
  new DefaultAuthEmailProvider(sink, {
    onDeliveryError: { passwordResetToken: 'rethrow', emailChangeVerification: 'rethrow' }
  })
  ```

  A message left out keeps `'swallow'`, so the safe value is what you get by saying nothing and
  widening the opt-in is always explicit. A bare `'swallow' | 'rethrow'` still works and still
  applies to all ten. A key the catalogue does not know is dropped — a typo leaves the message
  swallowing, never exposed. The resolved policy is read from a `Map` and built by iterating the
  deployment's own entries, so no lookup walks a prototype chain.

  `AUTH_EMAIL_KINDS`, `AuthEmailKind` and `DeliveryErrorPolicyMap` are exported. A catalogue entry
  added without a matching kind fails to compile.

- **`AuthEmailSink.send` now states which message it is carrying and whether it holds a live
  credential** — anywhere in the rendered message, subject included, since all three fields reach
  the sink. `kind` and `containsCredential` are always set. The obligation is in the port's own
  documentation, where an implementer meets it: **a sink must not publish the content of a message
  flagged `containsCredential`** — not in an error it throws, not in a log line, not in an audit
  record that outlives delivery.

  This is a statement of fact, **not** protection, and the docs say so plainly. Once the body leaves
  `send`, what happens to it belongs to the sink. It is delivered at the only moment a sink could
  act on it.

  **A rendering can declare a credential its kind does not imply.** `AuthEmailMessage` gained an
  optional `containsCredential`, OR-ed with the kind's baseline. `messages` replaces a renderer
  outright, so a product whose own `mfaEnabled` copy hands the user recovery codes has turned a
  notice into a credential-bearing message while its kind still reads `mfaEnabled` — and the sink
  would have been told `false` about a body carrying a live secret. That is the flag being _wrong_,
  which is worse than the flag being merely non-protective. The combination is one-way: a renderer
  can only add. Returning `containsCredential: false` from an override of `passwordResetOtp`
  changes nothing, because a consumer does not get to switch off a statement this library makes
  about its own messages.

  Why a flag and not a list of values to redact: that was measured and rejected. Redaction is a
  substring match, so it holds for a value quoted as written and not for the same bytes re-encoded —
  a relay may answer with the body in base64, and then no list matches. A categorical "publish none
  of this message" has to find nothing, which is the only shape that survives an encoding it cannot
  predict. The same reasoning took every channel-authored byte out of this library's own log lines.

  Adding fields to the input is not breaking for a sink: an implementation taking fewer properties
  still satisfies the port.

- **A one-time code could reach the operator's log in clear text when the mail relay rejected the
  message.** `DefaultAuthEmailProvider` logged the raw error object on a delivery failure. The
  comment justifying it read "the error is the channel's own, not the rendered body" — and a
  measurement against a real relay disproved exactly that premise. A policy, DLP or anti-spam
  relay answering `550` **quotes the offending content**, so the channel's error _is_ the rendered
  body, and for this provider that body carries a live password-reset OTP, an email-verification
  OTP, a reset token, an email-change token or an invitation token. The credential landed in the
  log pipeline valid until it expired. Reported by the `@bymax-one/nest-notification` seat from a
  run measured on a real relay, where the code captured from the SMTP `DATA` appeared verbatim in
  the consumer's error entry under the same request id.

  **The rule that came out of it, after four weaker ones failed: this library publishes nothing a
  mail channel authored.** Not the error's `message`, not its `name`, not the rendered subject —
  and not on "credential paths" only, but on every path. What a delivery failure logs is the
  message's own label and, per link of the error's cause chain, an opaque stand-in:

  ```
  delivery failed sending passwordResetOtp: <error>
  ```

  Every part of that line is text this library wrote. The guarantee is simpler to hold than any
  amount of stripping, and it is what the four earlier attempts each failed to reach.

  **Why redaction is not enough.** It is a substring match, so it assumes the credential reaches
  the error the way this library wrote it. A relay is free to quote what it rejected in transfer
  encoding instead, and base64 is the ordinary case. Measured: the whole reset-code body is 96
  base64 characters, and the first 200 characters of the line decode straight back to the OTP.

  **Why a length cap is not enough either.** The encoding runs from the body's FIRST byte, so the
  code sits in the first sentence, well inside any cap that leaves enough text to decode. A bound
  on volume was never a bound on disclosure, and this changelog described it as a second lock
  before the measurement above.

  **Why validating the `name` by shape is not enough.** Closing only `message` moves the leak one
  field over: an error class built around a relay reply is a normal thing for a mail client to do.
  Requiring the name to look like an identifier excludes a quoted body and does **not** exclude an
  encoded one — `MTIzNDU2` is the base64 of the OTP `123456`, eight characters, alphanumeric,
  leading letter, a valid identifier by any such rule, and reversible by anyone reading the log.

  **Why redacting the rendered subject is not enough.** A subject comes from the `messages`
  catalogue, which a consumer may override with arbitrary code. Redaction only ever covered a
  subject that reproduced a value verbatim, and `Code 123-456` for the OTP `123456` is a
  reasonable-looking thing to write. The line carries a fixed label instead, which also identifies
  the message more stably for anyone parsing it.

  **Nothing is kept.** The line carries the message's label and, when the chain has one, the
  `<error>` stand-in per link — no status, no name, no message. A parsed SMTP status survived
  several rounds on the reasoning that a value rebuilt from a validated grammar cannot carry body
  content, and the test that finally settled it is whether the output DEPENDS on the secret. It
  does: an OTP of `424242` grouped as `424-242` at the head of a quoted body publishes `424`, and a
  different code publishes different digits. That is derivation, not the coincidence that `550
5.7.1` reassembling into `550571` turned out to be — and no grammar separates a reply from body
  text shaped like one, because a reply code and a grouped credential prefix are the same three
  digits and a separator.

  What an operator loses is the transient-versus-permanent split, which their mail provider's own
  dashboard carries. What they keep is which message failed, which is the half this library is the
  only source for.

  **The same defect was one port over, in the breach checker.** `IPasswordBreachChecker.isBreached`
  receives the PLAINTEXT PASSWORD by contract, so an error it raises is a place the plaintext can
  be — an HTTP client that echoes the request it failed on is the ordinary shape. The fail-open
  handler passed that error straight to `logger.error(msg, err)`, publishing it with its stack and
  whatever the client hung on it, under a comment claiming the plaintext never reached the logger.
  **Nothing** from that error reaches the line now — not the object, not a description, not a status
  parsed off its front. The first fix described it with `describeChannelStatus` and was wrong in a
  way worth recording: that helper validates the SMTP reply grammar, and a breach checker is not an
  SMTP channel. A password of `424 Correct Horse!` echoed back parses as the reply `424` and
  publishes the first three characters of the credential. Right tool, wrong port. No status is lost
  by dropping it, because an HTTP checker's own code would have to come from a structured field the
  interface does not expose.

  Two DTO comments carried the same over-claim (`RegisterDto.password`,
  `AcceptInvitationDto.password`: _"never logged or persisted in plaintext"_) and now say **by this
  library**, pointing at the ceiling. Found by sweeping for the CLAIM rather than for the wording
  already corrected — the method comes from the `@bymax-one/nest-notification` seat, who found two
  more in their own README the same way. A sweep by phrase misses the siblings written in other
  words, and the most scannable claim in a file is rarely worded like the one you just fixed.

  **What still needs you: `onDeliveryError: 'rethrow'`.** What the provider re-throws is the
  channel's original error, deliberately unaltered — a caller that opted into that policy did so to
  branch on the channel's codes, and handing it a laundered replacement would take those away. So
  the quoted body travels with it. Whatever catches it must not log it raw, and must not merely
  redact it either: describe it with **`describeChannelStatus`**, which is exported for exactly
  this. Deployments on the default `'swallow'` policy need no action.

  **Apply to a derived backend:** nothing to change for the fix itself — it is internal to the
  provider. **Three** things to check.

  If you parse the log line, it changed from `delivery failed for "<subject>"` with the error
  attached as a second argument to a single string, `delivery failed sending <label>: <error>`,
  with `<-` between cause links and no status anywhere in it; `<label>` is a fixed name this
  library owns (`passwordResetOtp`, `mfaEnabled`, …) and the rendered subject is gone.

  If you run `onDeliveryError: 'rethrow'`, audit what your handler does with the error, per the
  paragraph above.

  And **the three MFA notices no longer reject the operation that triggered them** — enabling a
  factor, disabling one, and resetting one now send detached, with the failure logged instead. A
  deployment on `'rethrow'` that relied on an undelivered MFA notice failing the request will stop
  seeing that failure. The change is deliberate: by the time the notice is sent, the factor is
  already enabled or removed, and answering the caller with an error reports a change that HAPPENED
  as one that did not. The other seven messages are unaffected — `'rethrow'` still surfaces their
  failures, which is the whole reason the two flows that react to a throw opt in.

  One more, if you catch errors from `EmailChangeService.requestChange` or
  `InvitationService.invite`: **what they throw is now laundered.** Both awaited the provider with
  no handler, so a rejection travelled to your code carrying the channel's own error — its
  `message`, its `name`, whatever fields your mailer attached. They now throw
  `new Error(describeChannelStatus(err))`, whose message is the opaque description and nothing
  else. This is not about `'rethrow'`: a custom `IEmailProvider` that throws is laundered here too.
  The reason is that on these two paths the caller **is this library** — the rejection reaches
  `AuthExceptionFilter`'s unknown-exception branch, which logs it — so propagating the original
  publishes the credential through this library's own filter, with no consumer given a chance to
  contain it. The HTTP response is unchanged: that branch answered `auth.internal` with the generic
  message before and does now.

  Not exploitable by an unauthenticated caller on its own — it requires a relay configured to
  quote rejected content — but it needs no attacker at all where such a relay is in the path, and
  the value exposed is a working credential.

### Changed

- **Stryker deletes its sandbox even when the run fails (`cleanTempDir: "always"`).** `true` — the
  previous value, and the default — deletes `.stryker-tmp` only after a run that PASSED, and a run
  that fails the 100 threshold is the normal state while iterating, so a 45 MB copy of `src/` was
  left behind on every failed run. Wanted on its own terms: `jest.coverage.config.ts` has to name
  it in `modulePathIgnorePatterns` precisely because a second copy of `src/` in the tree is
  hazardous, and the cheapest way to hold that is for it not to be there. Contributor-facing only;
  nothing ships differently.

### Added

- **A table key must now name a route handler, not merely a method that exists.** The conformance
  spec already checked both directions between the operations table and the controllers — every
  route handler described, every described key naming a real method — so the second half was
  looser than it read: `typeof === 'function'` accepts a method carrying no verb decorator, and
  the lookup resolves through the **prototype chain**, so `toString`, `valueOf` and
  `hasOwnProperty` answer `'function'` on any class. A typo landing on an inherited member passed
  here and would have failed in a consumer's document build instead, which is the wrong
  repository to find out in. It is the same prototype-chain reach that once let a catalog lookup
  hand a **function** to `HttpException` as a status.

  Both halves falsified before the change was trusted: `'AuthController.toString'` and
  `'AuthController.onModuleInit'` are now red, and were not.

  Recorded because the first draft of this entry claimed the table could fall behind the
  controllers unnoticed. It could not — that direction has been covered since the contributor
  shipped, and removing `AuthController.wsTicket` from the table already failed the conformance
  spec. Caught in review, verified by running it.

## [1.4.3] - 2026-08-15

### Changed

- **BREAKING — the bulk session revocation moved to `POST {prefix}/sessions/revoke-all`.** It was
  `DELETE {prefix}/sessions/all`, and the verb was the defect. The handler reads the refresh token
  that names the caller's own session — the one session it must NOT revoke — and under
  `tokenDelivery: 'bearer'` that token arrives in the request body. OpenAPI 3.0.3 defers to
  RFC 7231 there: a payload on DELETE has no defined semantics, so `requestBody` on it **SHALL be
  ignored by consumers**. A generated client therefore sent no body, the server found no refresh
  token, and every call answered `auth.session_not_found` — an operation the document could not
  describe and a generated client could not reach, in the delivery mode a mobile or cross-origin
  consumer runs. POST is the method whose body semantics are defined.

  Found in review of the contributed OpenAPI fragment rather than by a failing test, which is the
  uncomfortable part: the e2e suite drove the endpoint with a hand-written request that DID carry
  a body, so it passed throughout. The suite proved the server works; nothing proved a client
  built from the document could reach it.

  Two smaller truths came out of the same reading. `GET {prefix}/sessions` reads the same token to
  mark which session is the caller's, and a GET has no body either — so on a bearer-only
  deployment the cookie is its only channel, the fragment no longer contributes a body it would
  never receive, and the listing simply marks nothing as current. And `test/e2e` now asserts, from
  the router Nest actually built, that no contributed `requestBody` lands on a method without
  payload semantics; the rule is enforced rather than remembered.

  **Apply to a derived backend.** Change `DELETE {prefix}/sessions/all` to
  `POST {prefix}/sessions/revoke-all` wherever a client calls it — or read it from
  `AUTH_ROUTES.sessions.revokeAll`, which is what that constant is for. The request body,
  response (`204`), guards, rate limit and error codes are unchanged; only the method and the last
  path segment move. `DELETE {prefix}/sessions/:id` is untouched, and no longer has to out-rank a
  static sibling in routing.

### Added

- **Nine routes this library serves were missing from `AUTH_ROUTES`,** which is the map a client
  composes URLs with — so a consumer reaching any of them had to hardcode the path the constants
  exist to spare them, and would keep it hardcoded through a rename. Added:
  `AUTH_DASHBOARD_ROUTES.wsTicket`, `AUTH_MFA_ROUTES.recoveryCodes`,
  `AUTH_PASSWORD_ROUTES.changePassword`, the whole `AUTH_PLATFORM_MFA_ROUTES` family (setup,
  verify-enable, disable, recovery-codes) and `AUTH_OAUTH_ROUTES` (initiate, callback).
  `AUTH_EMAIL_CHANGE_ROUTES` and the two new families are exported from `./shared` by name, the
  way every other family already was.

  A test now compares the map against `PATH_METADATA` on the controllers — the same metadata Nest
  routes with — in **both** directions: no route served without a constant, and no constant
  pointing at a route nobody serves. It is worth saying how the platform MFA family was found,
  because it is the failure mode this test exists for: a manual sweep reported those four paths as
  present, because they appear elsewhere in the same file (in the refresh skip list) and a grep
  for the literal cannot tell one list from another. The test reads the map, not the file.

### Fixed

- **A wrong password no longer spends a refresh — and ten of them no longer sign the user out.**
  `createAuthFetch` treated every 401 outside its path skip list as an expired session. A consumer
  measured what that costs on a live instance: a wrong `currentPassword` on
  `POST {prefix}/password/change` answers `401 auth.invalid_credentials`, the client refreshed,
  and the retry then surfaced the real error — one refresh per typo. Ten typos inside a minute
  exhaust the refresh limiter (`429 auth.too_many_requests`), the client read **that** as an
  irrecoverable expiry and called `onSessionExpired`.

  The session was never revoked: `GET {prefix}/me` answered `200` throughout. The sign-out was
  entirely client-side — the wrapper discarding a session the server still honoured, triggered by
  a rate limit that exists for something else. Behind a proxy with `clientIpSource: 'peer'` the
  bucket is shared, so the ten are the whole deployment's.

  **The skip list could not fix it, which is the finding under the finding.** That route is behind
  the JWT guard: an expired token 401s there too. One path, two meanings — so the decision moved
  to the error **code**, the only thing that separates them. `auth.token_invalid` is the expiry
  (every guard collapses expired, revoked, malformed and absent onto it deliberately); every other
  code is the server answering about something else, and a new token would not change its mind.

  Measured across the family rather than fixing the one route reported: `password/change`,
  `mfa/recovery-codes` and `email/change` all answer a non-expiry 401 and none was on the list,
  while `mfa/setup` and `mfa/disable` answer the same codes and were. The list was three entries
  short, not one — which is why the mechanism changed instead of the data.

  **And the whole platform surface joined it.** The list carried five platform routes and left
  out `platform/me` and all four `platform/mfa/*` — every one of them JWT-**platform**-guarded, so
  an expired platform token answers `auth.token_invalid`, the code that means "refresh me" on the
  dashboard plane. A dashboard refresh cannot fix another plane's credential: it spends the
  budget and can call `onSessionExpired` for a session that is perfectly healthy. Found in review
  of the paragraph claiming the list already covered the plane.

  **Three routes left the path skip list**: `mfa/setup`, `mfa/verify-enable` and `mfa/disable`.
  They were there because a wrong password or a wrong TOTP code 401s from them — which the code
  check now recognises — but all three are **JWT-guarded**, so an expired token 401s from them
  too, and skipping the refresh would have left the exact inverse of the defect above: a client
  refusing to refresh a session that only needed refreshing. Found in review, and it is the same
  one-path-two-meanings shape as `password/change`.

  What remains on the list is the narrower set where a refresh cannot help **whatever** the code
  says: the token endpoints themselves (recursion), the credential-issuing endpoints (no session
  to refresh yet), and the **platform** surface — a dashboard refresh cannot fix a platform
  credential, so attempting one spends the refresh budget and can call `onSessionExpired` for a
  dashboard session that is perfectly healthy.

  **The classification is time-bounded.** Reading the error body waits at most two seconds; on
  expiry the pre-existing behaviour applies and a refresh is attempted. The request itself has
  already completed and its timeout has already been cleared, so an unbounded read would hang the
  wrapper on a 401 whose body never terminates — including on deployments that disable `timeout`
  for long-polling. This step may narrow what refreshes; it may never suspend the wrapper.

  **A 401 the client cannot read still refreshes.** No envelope, an empty body, a non-JSON body, a
  code that is not a string — every one behaves exactly as before, so this wrapper stays usable as
  a general fetch against an application's own API. Both envelope shapes are read: this library's
  `{error: {code}}` and the flat `{statusCode, code, …}` a `@bymax-one/nest-core` backend answers
  with. The body is read from a **clone**, so the caller still receives an unconsumed response —
  otherwise every consumer parsing the error body would meet `TypeError: body already used`.

  **Apply to a derived backend.** No server change. If your frontend relied on the old behaviour —
  a 401 from any endpoint eventually reaching `onSessionExpired` — note that only
  `auth.token_invalid` does now. A 401 your own API answers with no auth envelope is unaffected.

- **Two internal-only error codes now say so in the shared catalogue.** `auth.token_expired` and
  `auth.token_revoked` are never on the wire — both implementations collapse them onto
  `auth.token_invalid`, deliberately, because telling a caller "expired" rather than "invalid"
  separates a token that WAS valid from one that never was, which is what an attacker holding a
  captured value wants to learn. `rust-auth` maps them through `AuthErrorCode::to_wire`; this
  library never throws them at all.

  Three of the five internal-only codes already carried that note (`auth.token_missing`,
  `auth.otp_expired`, `auth.otp_max_attempts`) and these two did not — so a reader concluded,
  reasonably, that the unmarked ones do appear. A consumer seat did exactly that while reviewing
  the refresh fix above, and asked whether it had a hole for `auth.token_expired`. It does not,
  and now the catalogue answers the question without anyone reading the emit sites. **A code in a
  published catalogue is something a consumer will write a branch for**, so an unreachable one has
  to say it is unreachable.

### Added

- **The OpenAPI security posture is contributed at the consumer's boot, not shipped as a file.**
  A deployment building its document with `@bymax-one/nest-core` >= 1.4.0 now gets this library's
  operations described automatically: which schemes exist, which operation requires which, and
  which are reachable unauthenticated. The module registers a contributor; nest-core discovers it
  while building the document. Nothing to enable, nothing to import.

  It cannot be a static file, and that is the whole reason the contract exists. The same build
  serves `/auth/login` here and `/api/v2/identity/login` there, with the credential in a cookie
  on one deployment and an `Authorization` header on the next, under cookie names the consumer
  chose. So the fragment is derived from the options that actually resolved, and keyed by handler
  identity — which survives every prefix, version and mount point.

  | resolved options             | contributed                                                                                                                                                                                                                                                                                                                                                                                                                              |
  | ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | `tokenDelivery: 'cookie'`    | `bymaxAuthAccessCookie`, `bymaxAuthRefreshCookie`, carrying the configured cookie names                                                                                                                                                                                                                                                                                                                                                  |
  | `tokenDelivery: 'bearer'`    | `bymaxAuthAccessBearer` only; `refresh` gets `security: []` and a `{refreshToken}` body that is **required twice** — the body must be sent and the property must be in it, because with no cookie to carry the token a generated client accepting `{}` would be describing a call that fails. `logout` takes the same body **optional**: measured, the two differ, since logout answers 204 with no credential at all where refresh 401s |
  | `tokenDelivery: 'both'`      | both access schemes as a **two-entry requirement list**, which OpenAPI reads as OR; the refresh operations add an **empty** alternative beside the cookie — how OpenAPI says "or a credential this member cannot model", without which the document would refuse to describe the valid body-only caller                                                                                                                                  |
  | `controllers.platform: true` | `bymaxPlatformAccessBearer`, in every mode — platform credentials are header-read whatever `tokenDelivery` says. The registration switch decides, not `platform.enabled`                                                                                                                                                                                                                                                                 |
  | a controller not mounted     | no operation, and no scheme only it would have referenced                                                                                                                                                                                                                                                                                                                                                                                |

  **Two operations need two credentials at once, and the document says so.** Found in review of
  this PR, against the controllers rather than against the guard stack: `revokeAllSessions` is
  JWT-guarded AND reads the refresh token, because it revokes every session except the caller's
  and cannot spare a session it cannot name — without one it answers `auth.session_not_found`.
  `listSessions` and `changePassword` read the same token and succeed without it, with a lesser
  answer (`isCurrent` false everywhere; every session ended, the caller's included). Describing
  all three as access-only told a bearer-mode client to send no body to an endpoint that refuses
  without one, and a cookie-mode client that the refresh cookie was not read.

  OpenAPI writes AND as one requirement entry carrying both schemes, so that is what they get —
  and under `'both'` the list is the product of the two channels: each access form, once with the
  refresh cookie beside it and once without, the second being the body-borne token that `security`
  cannot name. The required and the optional case produce the same document in that mode, which is
  a property of OpenAPI rather than a shortcut: once a body-borne alternative exists, no
  requirement list can insist on a credential that might be arriving in the body.

  **The fragment also carries one sentence of prose, and it is there because a document cannot
  say this any other way.** `logout` requires nothing — an operator whose access token expired
  must still be able to sign out — so `security` renders "requires none" and "accepts and acts on
  whichever arrives" identically to anyone skimming. A consumer read the `@Public()` decorator,
  simplified to `security: []`, and measured what that produced: a logout called with no
  credential answers `204` and revokes **nothing**, with the same access token still getting `200`
  from `/me` afterwards. The user clicks sign out, sees success, and stays signed in, and no layer
  reports a failure. Under `tokenDelivery: 'bearer'` the refresh token in the body is the only
  channel there is, so omitting it is exactly that silent no-op. The operation therefore carries a
  `description` saying so. It is contributed the way everything else is — nest-core merges a
  fragment member only where the scan produced none, so a consumer who wrote their own
  `@ApiOperation` keeps it.

  **And `logout` names the access token it revokes.** Also found in review, and the one with a
  security consequence rather than an ergonomic one: `logout` is `@Public()` — deliberately, so a
  user whose 15-minute access token expired can still sign out — but it READS that token and
  blacklists its `jti` for whatever life it has left. Described as refresh-only, a generated
  client sent no `Authorization` header, so the refresh session was revoked while a valid access
  token stayed usable until it expired. Every form it reads is now an alternative, richest first,
  with the empty entry last saying that nothing is required. Its platform twin already worked this
  way (`[{platformBearer}, {}]`), which is what made the dashboard side look like the oversight it
  was.

  The refresh-cookie scheme is now defined when **any** of the three controllers that reference it
  is mounted, not only `auth` — a deployment mounting the session surface alone was referencing a
  scheme its own document never declared.

  **A scheme the options cannot satisfy is absent**, never defined-and-unreferenced: nest-core
  fails a boot on a requirement naming an undefined scheme, and a document defining a credential
  the server will not read tells a generated client to offer it. Both directions are asserted —
  no dangling reference, and no unreferenced definition — under all three delivery modes.

  **No coupling at all** — not a dependency, not a peer, not a devDependency, and no import even
  in tests. The contributor class is unexported, the contract revision is inlined and the marker
  is the documented string literal, so nothing published or unpublished names
  `@bymax-one/nest-core`. A conformance gate walks the whole tree and fails on an import of any
  other `@bymax-one/*` package, this package's own subpaths excepted; falsified from both a
  production file and a test file.

  An earlier draft of this work took nest-core as a devDependency so the conformance suite could
  compare its constants as values, on the reasoning that test files do not ship. That reasoning
  is true and beside the point: **a library does not take a dependency on its consumers' stack in
  order to assert a composition** — the rule this repository already applies to
  `AuthExceptionFilter`. The check moves to the consumer, who can make it better anyway, because
  their suite runs both packages at the versions they installed. The README carries the two
  expectations to write, and says which of the two failures is silent.

  Two acceptance checks run in both directions over the handler table: every declared key names a
  method that exists on the controller it names, and every route handler on every controller is
  declared. The first matters because a key nest-core cannot resolve **fails a consumer's
  document build** — a renamed handler here would break their repository on upgrade, not ours.
  The second is what stops the table falling quietly behind: a new endpoint that nobody described
  would inherit the consumer's document-level default, which is the wrong answer for a public
  route and an unenforced promise for a protected one.

  **On nest-core older than 1.4.0 the fragments are silently ignored** — no contributor lane, so
  the document renders exactly as before with no error and no warning. Documented symptom-first
  in the README, with the diagnosis order, because "the contributor has not shipped yet" and "the
  nest-core version is too old" are indistinguishable from the document.

  **Apply to a derived backend.** If you wrote `securitySchemes` or `openapi.operationSecurity`
  entries for this library's routes by hand, **delete them** — and note what that sentence is
  not saying. Those entries are not stale and not wrong: they are what makes the document correct
  today, and a maintainer told to remove "incorrect config" will go looking for a defect and find
  none. The accurate instruction is _delete the entries that currently do this job correctly,
  because the library now does it_ — the deletion is what transfers the work, and it is needed
  exactly because the entries were doing it. Precedence — read from nest-core's
  `augmentOperation`, not summarised — is: the generated operation's own `security`, then your
  override, then this library's fragment. So the stale vocabulary keeps winning and the
  contributed one never lands.

  **And your own document test will not catch it.** A consumer seat measured their case: ten
  `operationSecurity` entries, all for this library's routes, and a suite asserting the
  operation-to-posture map with `toEqual`. On adoption every fragment loses to those entries, the
  old scheme names survive, and the suite stays **green** — it is asserting the old answer that is
  still being served. A test that pins your document confirms the staleness instead of finding
  it, so nothing downstream will remind you. Delete the literals, update whatever pins the
  document to the four-name vocabulary, rebuild, and regenerate any typed client.

  **Delete the entries for THIS library's routes. Keep your document-level `security`.** Reported
  after publication by the consumer who ran the comparison this note asks for, and it is the one
  way following this instruction makes a document **worse**: the two usually live in the same
  options block, and removing the block removes the default. In `augmentOperation`, an operation
  with no requirement of its own, no override and no fragment falls through to `ownRouteSecurity`,
  which answers `undefined` for anything that is not a health or metrics route — so a backend's
  **own** guarded routes carry no requirement and inherit the document default. Take the default
  away and every one of those routes reads as public. The condition travels with the claim: this
  reaches routes that state nothing of their own — no decorator feeding the scanned operation, no
  `operationSecurity` entry, not a health or metrics route a policy answers for. Anything carrying
  its own requirement outranks the default and is untouched, which is why the fix works at all. A
  backend that annotates every guarded route individually is unaffected; the reason this bit two
  consumers is that annotating each route is what a document-level default exists to avoid. The
  health probes do move, losing their explicit `[]`, since `ownRouteSecurity` returns it only
  while `openapi.security.length > 0`.

  On nest-core below 1.5.0 nothing reports it: no error, no unmatched key, no failing build. The
  document just stops asking for credentials on those routes — the ones the backend owns.
  nest-core 1.5.0 warns on this shape and names the bare operations, which makes
  it visible rather than impossible. Keep the default, and **derive it instead of writing a
  literal** — from the guard your own routes use, your `tokenDelivery`, and the controllers you
  registered, all three. A literal goes wrong in two distinct ways: where the named scheme is not
  declared, nest-core's `assertSchemesDeclared` throws the build; under `both`, where both access
  schemes exist, nothing throws and the default is merely incomplete, describing one of the two
  channels the routes accept. Loud in one place, quiet in the other. Two cases a delivery-only
  recipe gets wrong: `schemesFor` gates both dashboard schemes on a dashboard controller being
  registered — and `oauth` is not one of them, since its operations are public — so **any
  deployment with no dashboard surface declares neither and throws under `cookie` too**,
  platform-only and OAuth-only alike;
  and a route behind `JwtPlatformGuard` always wants `bymaxPlatformAccessBearer`, since
  `extractPlatformAccessToken` reads the `Authorization` header whatever the mode says. A backend
  guarding different routes with both families needs per-operation `security` for one of them —
  not because the default holds only one entry, but because its entries are alternatives applied
  to every inheriting operation, so listing both would document each credential as valid for
  either family.

  The no-dashboard case gets a remedy rather than only a diagnosis, because those deployments are
  legitimate: `JwtAuthGuard` is registered and exported unconditionally, so mounting no dashboard
  controller does not stop a backend from guarding its own routes with a dashboard access token.
  Deriving correctly there answers "the scheme does not exist", which is true and unusable — so
  that deployment **declares the scheme itself** in `openapi.securitySchemes`. Which scheme is
  still a function of delivery, not a fixed recipe: `cookie` needs the `apiKey`-in-cookie
  definition carrying the configured `cookies.accessTokenName`; `bearer` needs the HTTP bearer
  definition and has no cookie name to carry; `both` needs **both**, or the document is incomplete
  in the same quiet way described above. `AUTH_SECURITY_SCHEMES` is not public API today, so the
  names are written as literals for now; exporting them is tracked.

  Per-operation beats document-level, so the default cannot reach this library's operations.
  Verified on a real adoption: thirteen contributed operations render byte-identical with and
  without it.

  **Not in this change:** per-operation error responses (the `4xx` set each operation can answer,
  read from `errorCatalog.statuses`) and the DTO request schemas. Both are additive to the same
  contributor and are next; the security posture is the half a consumer asserts today.

- **`WsJwtGuard` is now driven by a real WebSocket handshake.** 228 lines at **0% e2e coverage**:
  every other guard here is reached by an HTTP request, this one by a socket upgrade, and no
  suite spoke that protocol — so its only proof was unit tests handing it an `ExecutionContext`
  whose `switchToWs()` returned an object literal. That proves the code runs; it cannot prove a
  real handshake presents the credential where the guard looks for it, which is the entire
  question about a guard fed by a transport.

  The alternative was to exclude it from the e2e-only rule with the residual risk written down.
  The devDependency was taken instead — `@nestjs/platform-socket.io`, `socket.io` and
  `socket.io-client`, dev-only, none of them in the published bundle. Statements 0% → **90.16%**,
  branches → **81.25%**, functions → **100%**, from a gateway declared in the test module the way
  a consumer declares one.

  Both credential channels are exercised: the single-use ticket in the upgrade query (the only
  path a browser has, since the `WebSocket` API cannot set handshake headers) and the
  `Authorization` header. So are the refusals that matter — a replayed ticket, a token this
  deployment never signed, a token killed by a logout, a token killed by an epoch bump, one
  carrying no `jti`, and a ticket redeeming to a snapshot with **no tenant**, which is the shape
  `rust-auth` writes for a platform ticket into the `wst:` keyspace both libraries share.

  **A second finding, from taking a review question seriously enough to measure it: the guard
  crashed the socket on the native `ws` adapter.** `WsJwtGuard` reads both credential channels
  from `client.handshake`, and `@nestjs/platform-ws` hands a gateway the raw `ws` socket, which
  has none — so the first property access threw a `TypeError`. Not an `AuthException`, so no
  filter could answer it: the connection dropped with no close frame and the caller learned
  nothing at all. It now **refuses** with `auth.token_invalid`, the same code a missing
  credential gets, and the filter delivers it. The guard still cannot authenticate on that
  adapter — `ws` does not retain the upgrade request — and the README says so where a consumer
  chooses an adapter.

  **The finding this surfaced, and its fix — `WsAuthExceptionFilter`, exported.** The library's
  error catalogue did not reach the socket: `WsJwtGuard` throws `AuthException`, which extends
  `HttpException`, and Nest's WebSocket exception layer understands only `WsException` — so a
  refused client received `{status: 'error', message: 'Internal server error'}`. The refusal was
  correct (the handler never runs); what was lost is everything the client could act on. A
  reconnect policy cannot tell a dead credential from a crashed handler, and the sensible default
  for an unknown error is to retry, so an expired token became a reconnect loop against an
  endpoint that will refuse it forever.

  Register it on a gateway that applies the guard (`@UseFilters(new WsAuthExceptionFilter())`) and
  the client reads `error.code` instead. `status: 'error'` is kept — the field Nest itself sets
  and the one socket.io clients branch on — with the envelope added beside it. The
  `AuthException` travels whole, so a `details` payload survives.

  **Scoped to `AuthException`, and answering both transports.** An argument-less `@Catch()` would
  claim every exception the gateway raises, so a `WsException` an unrelated handler throws — a
  domain error with its own contract — would come back as an `auth.*` code: following the README
  would silently rewrite errors a consumer already ships. Everything that is not this library's
  refusal keeps travelling through Nest's own layer. And a native `ws` client is written to with
  `send`, not emitted on: it extends `EventEmitter`, so `emit` succeeds, dispatches a local event
  and sends the peer nothing — a filter that only emits is inert on exactly the transport whose
  refusal this fix exists to deliver.

  Opt-in, like its HTTP twin: a library does not get to decide how an application answers
  failures it did not raise. It imports neither `socket.io` nor `@nestjs/websockets` — the client
  is typed structurally — so it costs a consumer with no gateway nothing. The e2e runs **two
  gateways under one application**, one filtered and one not, because the claim is that the two
  answer a refused client differently and one gateway can only show one of the two answers.

  Three branches remain unreachable through this transport and say so in the suite: the
  missing-`@nestjs/websockets` arm of `onModuleInit`, `assertDashboardSnapshot`'s non-string
  `sub` (`redeemWsTicket` refuses such a record before it becomes a snapshot), and
  `readUpgradeTicket`'s unparseable-URL arm (Socket.IO builds the URL itself).

- **`AuthService.refresh` read the account without its tenant.** `findById(session.userId)` with
  no tenant argument, in the path that re-validates the account on every rotation — while the
  interface documents that ids may collide across tenants, and `UserStatusGuard` passes both for
  that reason. On a deployment whose ids are per-tenant, a homonym in another tenant could pass
  the status gate on the caller's behalf, and the re-stamp path a line below would sign **that
  account's tenant and role** into the token handed back. Now scoped to the tenant the session
  already carries, with a test that goes red without it.

  Found in review of the documentation change below, which was recommending tenant-scoped reads
  to consumers while the library's own refresh path did not do one.

- **The access token's `status` claim is documented as point-in-time and never authoritative.**
  Three states, and a client can tell them apart from nothing: minted at login it carries the
  account's value _at that moment_; an ordinary refresh rotation stamps an **empty string**,
  because the session record holds no live status; and a refresh that re-signs — which
  `AuthService.refresh` does when `role`, `tenantId` or `mfaEnabled` changed — stamps the value
  read during _that_ request. `rust-auth` stamps the same empty string on its rotation path, with
  a test pinning it, so the middle state is a shared contract rather than a defect in either
  library.

  Reported by a consumer seat that measured it on a live boot: `"pending"` before the first
  refresh, `""` after. Nothing in this library's own enforcement reads the claim — `UserStatusGuard`
  resolves status from the cache and the repository — so it is not a bypass. The exposure is a
  derived backend reading `request.user.status`, which is wrong in **both** directions:
  `!== 'active'` refuses everyone once a session has been refreshed, `=== 'suspended'` refuses
  nobody, ever. Both fail quietly, hours from the code that caused them.

  Every populated value is stale the instant the account changes, because nothing re-stamps a live
  token — so the exceptional re-stamp is the worst of the three for a reader, not the best: it
  makes the claim _usually_ wrong rather than reliably empty. That is also why backfilling the
  rotation path was considered and rejected: it would extend the failure mode that survives
  testing. The empty string is the one state that cannot be mistaken for an answer.

  Stated in the README as a three-row table and at the call site, with `mfaVerified: false` on
  rotation beside it, and the `userStatusCacheTtlSeconds` window (default 60) that decides how
  quickly a suspension bites.

  **Apply to a derived backend.** Read status per request — `UserStatusGuard` on the route, and
  for anything richer `findById(request.user.sub, request.user.tenantId)`, **tenant-scoped**, the
  way that guard reads it — and never from the token. The tenant argument matters: ids may collide
  across tenants and `findById` accepts an absent tenant only for deliberately cross-tenant flows,
  so an unscoped read can resolve another tenant's account. If you already gate
  on the claim, that gate is either refusing everyone or nobody depending on which way you wrote
  the comparison.

- **The controller layer is now measured by the suite that goes through the framework.** E2E-only
  branch coverage of `src/server/controllers` was **75%**, and the shortfall was mostly whole
  endpoints nobody drove over HTTP. It is now **87%**, and everything still uncovered is named
  below rather than left as a number.

  What had no e2e at all: the **address-change flow** (`EmailChangeController` sat at 0%
  functions — request, mail, confirm, replay, and the boot-time refusal when the provider cannot
  deliver the token), **invitation revocation**, the **two challenge routes crossed** (a platform
  temp token on the dashboard route and a dashboard one on the platform route — the branches that
  stop a credential from one surface becoming a session on the other), **logout and refresh with
  no credential at all** on both surfaces, and a **host that never mounted a cookie parser**,
  which is a supported deployment this library takes no dependency on.

  Two of those found real defects: the MFA one is under _Fixed_ below, and the invitation case
  corrected the test rather than the code — revocation is by **rank**, not admin-only, and an
  outranked revoke answers the same `204` a permitted one does, on purpose. Asserting the two
  responses **against each other** is what makes that an anti-enumeration property instead of two
  endpoints agreeing because nothing happened in either; the effect is then read where the
  invitee's token is spent.

  **What remains, and why it stays uncovered:** eight occurrences of `req.ip ?? ''` and one
  `err instanceof AuthException` fallback. Express sets `req.ip` for every request with a live
  socket, so the fallback needs a socket that is already gone — real, and not producible over
  supertest. They are one duplication rather than nine independent gaps, and folding them into a
  single helper (which would also fix the User-Agent bound being applied by `OAuthController` and
  by nobody else) is its own change.

- **The five guards this library exports and never mounts are now driven from a host's own
  controller.** `RolesGuard`, `PlatformRolesGuard`, `MfaRequiredGuard`, `OptionalAuthGuard` and
  `SelfOrAdminGuard` exist for a consumer to apply to their routes, and nothing here applied them
  — so their only proof was unit tests handing each guard an `ExecutionContext` no middleware
  would build. E2E-only branch coverage of `src/server/guards` was **34.19%**; it is now
  **65.16%**, and the five are at 100% apart from two branches named below.

  The fixture controller is declared in the **test module**, not inside `BymaxAuthModule`, and
  that is the point: `@UseGuards(...)` re-instantiates a guard in the declaring module's injector,
  so it resolves only what this library actually **exports**. The module's export list has carried
  comments claiming that works — `AuthRedisService`, `AuthRevocationService`,
  `BYMAX_AUTH_USER_REPOSITORY`, `WsTicketService` and `JwtModule` are all exported for exactly
  this reason — and nothing exercised the claim until now. It holds: every one of the five mounts
  and runs from a consumer's controller.

  Three of them are proven by falsification rather than by watching green: admitting a
  user-less request in `RolesGuard`, swallowing an invalid token in `OptionalAuthGuard`, and
  dropping the `mfaEnabled` type check in `MfaRequiredGuard` each turn exactly the case that
  names them red.

  With the wildcard route and the literal-`admin` deployment both driven, `SelfOrAdminGuard`
  reaches **100% on every axis from e2e alone**, and `RolesGuard`, `OptionalAuthGuard` and
  `MfaRequiredGuard` were already there.

  **`SelfOrAdminGuard`'s array-valued param is reachable, and is now driven.** The first draft of
  this work called it impossible — Express builds `req.params` from the path, where a name cannot
  repeat — and that was wrong: Express 5 (path-to-regexp 8) fills a **named wildcard**'s param
  with an array of segments, `['abc']` even for a single one. Any consumer writing
  `@Get('files/*path')` behind the guard reaches it on every request, including the URLs that
  look exactly like a plain param. Measured, then covered: the fixture declares a wildcard route
  and the suite drives one segment and three. Refusing is deliberate — picking an element would
  compare an identity against one segment of a caller-chosen path and admit the rest unlooked-at.

  **One branch is out of reach of the compositions this library supports**, and says so in its own
  source rather than being quietly missing from the report: `PlatformRolesGuard`'s missing
  `platformHierarchy`. Reaching it needs `JwtPlatformGuard`, which needs `platform.enabled`, which
  `resolveOptions` refuses without that map — so nothing this library mounts gets there, while a
  consumer's own guard populating `request.user` does, over HTTP, which is what the arm defends.
  Covered by its unit spec.

- **The shared wire contract is pinned by hash, so it cannot change unnoticed.**
  `conformance/wire-contract.json` is the one artifact `rust-auth` and this library are supposed
  to hold **byte-identically** — it is the source on both sides rather than a derivation of one.
  Nothing asserted it had not moved. The conformance suite now pins its SHA-256.

  **What it catches:** an _unaccompanied_ byte change — an edit that forgets to advance the
  constant, a formatter rewriting the file, a merge resolving it differently. Falsified by
  re-serialising the file with identical data and different bytes.

  **What it does not catch, stated because the first draft of this note claimed otherwise:**
  cross-implementation divergence. Changing the file _and_ the constant in one commit leaves this
  suite green while `rust-auth`'s untouched pair leaves theirs green too — both green, bytes
  divergent. Two independent local hashes cannot enforce agreement between two repositories,
  because neither reads the other. Closing that needs a real cross-repository comparison (one
  side fetching the other's committed blob in CI, or both consuming an immutable versioned
  artifact); it is proposed and unbuilt.

- **The E2E config was the one place the OOM bounds from #41 were never applied.**
  `jest.config.ts` and `jest.coverage.config.ts` both carry `maxWorkers: '50%'` and
  `workerIdleMemoryLimit: '1GB'` — added in #41, _"bound mutation and jest memory to stop OOM
  restarts"_ — and `jest.e2e.config.ts` carried neither. E2E is where they matter most: every spec
  boots a full Nest application with its own `ioredis-mock`, so per-worker memory grows with the
  number of spec **files**, not with the number of tests.

  Found by adding spec files. Three unrelated suites began failing intermittently — password
  reset, platform MFA, refresh-token reuse — alongside `Test suite failed to run`, which is a
  worker dying rather than a test disagreeing. Which suites break depends on how Jest distributes
  files across workers, so it presents as a flake in whatever spec was added last, and the first
  diagnosis is always the new spec.

- **The cookie flags are pinned, and the half no server-side suite can reach is stated as a
  consumer contract.** Cookie delivery exists for one guarantee — the tokens are never readable
  from JavaScript — and a leak into JS-readable storage is invisible from the server: the API
  answers identically, the wire looks correct, and every test here passes. Only a browser
  observes it.

  This suite now asserts **its half**: `access_token` and `refresh_token` carry `HttpOnly` and
  `Secure`, the refresh cookie is path-scoped to the auth prefix rather than origin-wide, and the
  set of cookies is pinned so a new credential-bearing one cannot appear outside those checks.
  Asserted **per cookie**, not as a blanket rule, because `has_session` is deliberately
  JS-readable — it carries no credential and is what lets a SPA know a session probably exists
  without touching a token. A blanket "everything is HttpOnly" assertion would fail on it, and the
  obvious fix for that would remove the feature silently.

  The README now states the other half as the consumer's: assert in a browser suite that
  `localStorage` and `sessionStorage` are empty and that `document.cookie` carries neither token.

- **The framework-fed layers are now proven by a suite that goes through the framework.**
  Per-layer measurement, which the aggregate 100% hides: filters were at **0%** e2e coverage and
  guards at **30.4% of branches**. A unit test on a controller, guard or filter _invents_ its
  input — it proves the code runs, never that it is reachable.

  `AuthExceptionFilter` reached 100% on every axis, and was found never to have been registered in
  the harness at all while three specs carried comments crediting it for envelopes it was not
  producing. The guard work drove the **refusals** — every prior e2e exercised guards admitting a
  valid caller on the way somewhere else — including every refusal branch of the CSRF guard, a
  token whose account was deleted after issue, and `/ws-ticket`, which had no e2e of its own.

### Changed

- **An OAuth callback carrying neither `code` nor `error` now answers `401 auth.oauth_failed`
  instead of `400 auth.validation`.** Wire change, and the one place this library and `rust-auth`
  still disagreed on the same request.

  `OAuthCallbackQueryDto.code` no longer carries a requirement: it is validated when it is present
  and `error` is not, so its bounds are unchanged and an empty or oversized `code` is still the
  pipe's to refuse, naming the field. What moved is the **absent** case. The handler already
  carried the answer — `if (query.code === undefined) return this.handleCallbackFailure(...)`,
  written when the "user clicked Cancel" path was fixed — and the DTO's conditional requirement
  made that branch **unreachable over HTTP**: the pipe refused the request first, every time. The
  branch nonetheless read as covered, by a unit test handing the controller a query object the
  HTTP surface could not produce (`{ state } as never`). A test that invents its input proves the
  code runs, never that it is reachable.

  A codeless callback is a failed authorization, not a malformed request, and both libraries now
  say so in the same code. Under `oauth.errorRedirectUrl` it takes the same `?error=oauth_failed`
  redirect every other OAuth failure takes, rather than escaping the redirect as a validation
  envelope.

  `conformance/openapi-declared-structures.json` follows the behaviour: the `anyOf` over
  `code | error` was a request structure while the pipe enforced it, and is now a handler refusal
  (`OAuthController.callback#codelessCallback`) with probes both layers answer — the pipe half
  read where the pipe answers, the HTTP half over a bootstrapped application. Falsified by putting
  the requirement back: exactly one case goes red in each suite, and it is the codeless callback
  in both.

  **Apply to a derived backend.** No code change. If you match on the response to a malformed
  OAuth callback — an error page keyed by `code`, a log alert, an e2e assertion — a callback with
  no `code` and no `error` now arrives as `401 auth.oauth_failed` with no `details` array, where
  it used to arrive as `400 auth.validation` with `details[0].field === 'code'`. The provider's
  own error callback (`?error=access_denied`) is unaffected; it already answered
  `auth.oauth_failed`.

### Fixed

- **A malformed `mfaTempToken` answered `500 auth.internal` instead of `401
auth.mfa_temp_token_invalid`.** `TokenManagerService.verifyMfaTempToken` let the verifier's own
  error propagate — its JSDoc said so — and nothing above catches it, so any garbage in the body's
  `mfaTempToken` or in the `mfa_temp_token` cookie an OAuth callback plants produced a 5xx. Every
  other failure in that method already answered `MFA_TEMP_TOKEN_INVALID`; the verification failure
  now says the same thing.

  Three consequences, none visible from a unit test that only ever passed it a token it had just
  minted: an attacker-controlled input produced a 5xx (free noise in an operator's error budget,
  and cover for the 500s that mean something); `MfaController` clears the temp cookie only for an
  `AuthException` it recognises, so a browser holding a malformed cookie was never told to drop
  it and replayed the same dead value on every attempt; and **`rust-auth` maps the same failure to
  `MfaTempTokenInvalid`** (`token_manager.rs`,
  `verify_rotating(...).map_err(|_| AuthError::MfaTempTokenInvalid)`), so the two backends
  answered one request differently. Found by driving the cookie path over HTTP for the first
  time.

  **Apply to a derived backend.** No code change. A request that used to come back `500` now
  comes back `401 auth.mfa_temp_token_invalid`. If you alert on 5xx from `/auth/mfa/challenge`,
  that alert was firing on client input and will now go quiet.

- **`AuthExceptionFilter` silently displaces `@bymax-one/nest-core`'s envelope filter.**
  Documented rather than code-changed: the behaviour is correct and only the advice was
  incomplete. **Nothing in this repository verifies it** — doing so would mean depending on
  `@bymax-one/nest-core`, and this library does not depend on its consumers' stack. The
  measurement below was taken once, deliberately, and then the dependency was removed; a consumer
  composing both libraries owns the standing assertion. `useGlobalFilters` binds ahead of an `APP_FILTER` provider and this filter is
  `@Catch()` with no argument, so registering it in a nest-core application means nest-core's
  never runs. Measured — the same request answers `{error: {code, message, details}}` with it and
  the flat `{statusCode, code, message, timestamp, path, details}` without it.

  **Apply to a derived backend.** Building on `@bymax-one/nest-core`? **Do not register
  `AuthExceptionFilter`.** Take theirs — it already recognises this library's envelope and passes
  the code, message and per-field details through unchanged. Registering both loses `statusCode`,
  `timestamp`, `path` and the correlation id, which is the opposite of what adding a filter looks
  like it should do. The symptom is a body nested under `error` where your other endpoints answer
  flat.

- **The declared structural overlay**
  ([`conformance/openapi-declared-structures.json`](conformance/openapi-declared-structures.json)).
  The 1.4.2 schema artifact named three contracts in its own header that it could not express,
  plus the anti-enumeration semantics that are a property of two responses rather than of either
  one. They are now **structure** — `oneOf` for `reset-password`'s exactly-one-of proof set,
  `required` + `anyOf` for the OAuth callback's conditional requirement — and executable probes
  for the two that are not structural at all: the 8-vs-15 password floor and the four endpoints
  that answer identically for an address with no account.

  Kept honest by three rules. The evaluator understands `required`, `oneOf` and `anyOf` and
  nothing else, and a structure using `allOf` or `not` — both valid OpenAPI 3.0 — is **refused at
  load** rather than skipped, because a keyword nothing evaluates publishes a claim nothing
  checks. Every entry ships probes, split across the two suites that can actually answer them:
  the unit suite evaluates each body against its own structure and enforces the pipe-refused
  ones, the e2e suite answers the service-enforced and response-level ones against a real
  application. And each entry must **discriminate** — a probe set that all expected the same
  refusal would be satisfied by a server that refuses everything, so at least one accepted body
  must be answered differently.

  Presence, for `required`, means present **and not `null`** — this server's rule rather than
  JSON Schema's. Measured, not assumed: `@IsOptional()` registers a conditional whose predicate is
  `value !== null && value !== undefined`, so `{"token": null, "otp": "…"}` carries one proof, not
  two. The probes carrying an explicit `null` are what prove it.

  One correction to how the exactly-one-of had been described, including in the 1.4.2 header: it
  is **necessary but not sufficient**. Which of `token`, `otp`, `verifiedToken` is eligible
  depends on the deployment's `passwordReset.method`, and an ineligible proof is refused with the
  same `auth.password_reset_token_invalid` a structural violation gets — indistinguishable to the
  client, and inexpressible in any committed document because it is option-derived. It is declared
  with its own probes, under its own name, so a reader is not left inferring a symmetry that is
  not there.

- **`POST {prefix}/password/change` refused the `refreshToken` it reads.**
  The handler takes the caller's own refresh token through
  `TokenDeliveryService.extractRefreshToken`, which reads **the request body** under
  `tokenDelivery: 'bearer'` and body-after-cookie under `'both'` — but `ChangePasswordDto` never
  declared the field, and the controller pipe runs `forbidNonWhitelisted: true`. So a bearer-mode
  caller sending it was answered `auth.validation` naming `refreshToken`, and the only way to
  change a password was to lose every other session. `refreshToken?: string` is now declared, and
  appears in the generated request schema.

  **A `tokenDelivery: 'cookie'` deployment was never affected** — the credential arrives in the
  cookie and no body field exists — which is why this survived: the default hides it. Confirmed
  live on a derived backend against the published 1.4.2, in both modes: `bearer` answers
  `400 auth.validation` with `details: [{ field: 'refreshToken', message: 'property refreshToken
should not exist' }]`, and the same call without the field answers `204` while ending every
  other session; `cookie` answers `204` clean.

  Found by the harness fix below: the global `ValidationPipe` stripped the property before the
  controller's own pipe could refuse it, so every E2E exercised a request production never sees.

  The README's request-body table is updated in the same release: it had listed the old body, so
  the documentation shipped in the tarball was stale about the very field this fixes. `tenantId`
  aside, the table now names `refreshToken` and says what both answers mean — send it and the
  calling device stays signed in, omit it and every session ends. `check:published` cannot catch
  that class: it compares exported types against the docs and does not see a prose table drift
  from a DTO.

- **The E2E harness shadowed the library's own validation pipe, so no E2E had ever seen
  `auth.validation`.** `test/e2e/setup.ts` installed a global `ValidationPipe`, and global pipes
  run **before** the controller-scoped `@UsePipes(createAuthValidationPipe())` every auth
  controller declares. A DTO failure therefore answered with the framework's
  `{ statusCode, message, error }` instead of `{ error: { code: 'auth.validation', details:
[{ field, message }] } }` — measured: a seven-character `newPassword` came back as
  `{"message":["newPassword must be longer than or equal to 8 characters"],"error":"Bad
Request","statusCode":400}`.

  The suite would have stayed green if `createAuthValidationPipe` had stopped producing the
  envelope entirely. The one E2E touching the path asserted `status === 400`, which the
  framework's shape satisfies exactly as well as the library's — the same range-assertion
  blindness that let thirteen wrong statuses survive.

  The harness now installs **no** global pipe at all, so each auth controller's own runs first.
  Installing the library's pipe globally was not enough: with `whitelist: true` it strips unknown
  properties before the controller's `forbidNonWhitelisted: true` can refuse them, so the harness
  still would not have exercised the production contract — which is how the `refreshToken` defect
  above stayed invisible. That assertion now names the code and the field.

  **Apply to a derived backend.** This is a test-harness fix, but it names a real deployment
  hazard: **if your application registers `app.useGlobalPipes(new ValidationPipe(...))`, it
  shadows this library's pipe on every auth route.** DTO failures then answer the framework's
  shape rather than `auth.validation`, and a client switching on `error.code` never sees it. With
  `@bymax-one/nest-core`'s envelope filter in front, the failure is re-shaped again and surfaces
  as `BYMAX_VALIDATION_FAILED` with `details: [{ issue }]` — a different code **and** a different
  details shape from the `auth.validation` / `[{ field, message }]` this library and `rust-auth`
  both document.

  **How to tell in one query:** you have it if a DTO failure on an auth route answers
  `BYMAX_VALIDATION_FAILED` with `details[].issue`; you do not if it answers `auth.validation`
  with `details[].field`. Grep your own error logs for the first pair rather than auditing where
  pipes are registered.

  **The fix:** scope your global pipe away from the auth routes, or build it with
  `createAuthValidationPipe()`, which is exported for exactly this.

  **The durable guard — assert the composed envelope in your application's E2E**, because neither
  library can. This library's suite sees its own pipe; `nest-core`'s suite sees its own filter;
  the shape a client actually receives exists only where the two are wired together, which is your
  application. A consumer who fixes the pipe today and adds a global one next quarter is back here
  otherwise. One scenario is enough: drive a real request that fails validation and shape-match
  both `code: 'auth.validation'` and `details: [{ field, … }]`.

- **`/client` required a `tenantId` the server refuses, so a consumer had to bypass it.**
  `LoginInput`, `RegisterInput`, `ResetPasswordInput` and `forgotPassword(email, tenantId)` all
  demanded the field. On a deployment with a configured `tenantIdResolver` — the case 1.4.2 made
  breaking — sending it answers `400 auth.validation` with a `tenantId` field detail, so the
  library's own typed client could not talk to the library's own server. A consumer building an
  SPA rejected `createAuthClient` and `AuthProvider` over exactly this and hand-wrote the request
  shapes.

  All four are now `tenantId?: string`. The defect was type-level rather than on the wire —
  `JSON.stringify` already dropped an `undefined` property — which is why the guard is that the
  client suite now calls `login`/`register`/`forgotPassword`/`resetPassword` **without** a tenant
  and would stop compiling if the field went back to required.

  The JSDoc was the worse half. It read _"`tenantId` is required because the server-side
  `LoginDto` enforces it with `@IsNotEmpty()`"_ — and that was never true: `@IsNotEmpty()` sits
  under `@IsOptional()`, so it rejects an empty string when the field is present and says nothing
  about absence. `LoginDto.tenantId` has been optional since **1.3.0**; the comment misread its own
  decorator stack and survived three minors, because a comment is checked by nobody. The
  replacements state the consequence and name where the mechanism is asserted, rather than
  restating decorators they cannot see.

- **Draining the response body deadlocked under request interception.**
  `await response.body?.cancel()` in `createAuthFetch` and `createAuthClient`. Under MSW or
  undici-in-jsdom the promise never settles, so every call whose response carries a body hung.
  `/auth/refresh` carries one on success as well as on failure, which put it on the happy path at
  every token rotation.

  **Production was never affected, and that is measured rather than assumed** — a real browser
  cancels the stream cleanly, confirmed under Playwright by deleting only the `access_token`
  cookie and watching a reload produce exactly one `POST /auth/refresh`, status 200, with no
  bounce to sign-in. So this is a **testing defect**, and the cost is precise: every consumer
  using request interception cannot test refresh-and-retry at all, and it is the _success_ path
  that is untestable. A four-way probe established the body's construction is irrelevant —
  `HttpResponse.json`, a raw string and a hand-built `ReadableStream` all hang while `.json()` on
  the same response resolves — so it is the interceptor's stream teardown, and dropping the
  `await` fixes it for every consumer without MSW changing anything.

  The drain is no longer awaited; nothing downstream needs it to have completed, the status has
  already been read. Regression test: a response whose `cancel()` never settles.

- **`refreshEndpoint` was undocumented, and its default 404s in a plain SPA.**
  It defaults to `/api/auth/client-refresh`, a Next.js proxy route, and a Vite/CRA app serves
  nothing there — refresh silently fails and every access-token expiry presents as a session bug.
  The README now covers it, with the symptom: _if every expiry logs the user out, check
  `refreshEndpoint` before looking at cookies._

  **Apply to a derived backend.** Nothing changes server-side. Frontends on a non-Next stack
  should set `refreshEndpoint` explicitly, and frontends on a resolver deployment should now stop
  passing `tenantId` — the client no longer forces them to.

## [1.4.2] - 2026-08-13

Closes the two findings that came out of auditing this library from the outside: every DTO it
ships published an empty schema, and a request naming a tenant a configured resolver would not
honour was answered `201` with the account created elsewhere. **One breaking change rides along
in a patch** — the tenant refusal — so `^1.4.0` and `~1.4.1` both pick it up on a routine update.
Read the `Apply to a derived backend` note before upgrading.

### Added

- **Request-body schemas, generated from the DTOs' own decorators**
  ([`conformance/openapi-request-schemas.json`](conformance/openapi-request-schemas.json)).
  OpenAPI 3.0 for all 22 DTOs, derived from class-validator metadata and regenerated by
  `pnpm gen:openapi-schemas`. It closes a gap a consumer's OpenAPI audit found: because the
  `@nestjs/swagger` CLI plugin does not run over precompiled `node_modules`, every DTO this
  library ships published as `{"type":"object","properties":{}}`, and the real contracts were
  discoverable only by triggering validation errors.

  The artifact is data rather than code so `rust-auth` can assert the same file, and it is
  **generated, not hand-written**: the suite regenerates and fails on drift, so a decorator
  change nobody mirrored is a red test in the repository that caused it. Three guards make the
  gate mean what it says — the committed copy must equal the regeneration, the set of validators
  the derivation understands is pinned by name (an unmapped decorator is silent, so a new one
  must fail rather than thin the schema), and the DTO list is asserted so a DTO added later
  cannot be quietly uncovered.

  A regex carrying flags is **refused** rather than rendered: `pattern` is the ECMA 262 dialect
  with no flags slot (JSON Schema Wright Draft 00 §5.2.3) and ECMA 262 has no inline modifier to
  rewrite them into, so emitting `.source` would publish a stricter pattern than the server
  enforces, silently.

- **Normalisation descriptions, each carrying the probe that verifies it**
  ([`conformance/openapi-request-descriptions.json`](conformance/openapi-request-descriptions.json)).
  Twelve e-mail fields are trimmed and lowercased before validation — a fact a client needs and
  no schema keyword expresses. A generator cannot derive it, because `@Transform` runs an opaque
  lambda, so the prose is written by hand and every entry ships an `{ input, expected }` probe the
  suite runs through `plainToInstance`. The probe is the sentence's operational meaning rather
  than a test beside it, so prose and behaviour cannot drift.

  The opposite direction is covered by a canary sweep: one rich input through every string
  property of all 22 DTOs, failing when a property transforms without a declared entry. Stated
  limit, in the artifact itself: a future transform that is the identity on that canary escapes
  both checks. The rejected alternative — reading class-transformer's `cjs/storage` internals —
  has no type declarations and is an unpublished path that can move between minors.

### Fixed

- **BREAKING: a request body naming `tenantId` is now refused when the deployment configures a
  `tenantIdResolver`**, instead of being accepted and silently discarded. A security audit of a
  derived backend found `POST /register` answering `201` for
  `{"tenantId": "attacker-chosen-tenant", ...}` while creating the account under the resolved
  tenant — the caller's belief about which tenant it registered into diverging from server state,
  on the boundary the resolver exists to defend, with nothing in the response saying so. No
  privilege crossed, and that is why it survived: accept-and-ignore is the worst of the three
  available answers precisely because it looks like success.

  The refusal is **conditional, and the asymmetry is the point**. Without a resolver the field is
  the only thing that can name a tenant — `resolveTenantId` already answers `400` when it is
  absent — so rejecting it outright would break every deployment that relies on it. With a
  resolver configured it does not participate at all, and whitelist validation already refuses
  `role` and `status` on exactly that principle. This makes the principle config-aware rather
  than carving an exception out of it.

  `null` and an omitted field are not refused: the caller asserted nothing, so there is nothing
  to contradict.

  **Apply to a derived backend:** if you configure `tenantIdResolver`, stop sending `tenantId` on
  the nine endpoints that accept it. Eight read it from the **request body** — `register`,
  `login`, `verify-email`, `resend-verification`, `forgot-password`, `reset-password`,
  `verify-otp`, `resend-otp` — and one reads it from the **query string**:
  `GET /oauth/:provider?tenantId=…`, so dropping a body field is not the change to make there.
  All nine answered `201`/`200` while discarding the value and now answer `400 auth.validation`
  with `field: "tenantId"`. Deployments without a resolver are unaffected — the field remains
  required there.

## [1.4.1] - 2026-08-12

Aligns every HTTP status with `rust-auth` and makes the pairing structural rather than
conventional. **Two breaking changes ride along in a patch release** — the `AuthException`
signature and thirteen HTTP status codes — matching how this line has shipped breaking changes
before (see `1.3.2`). Both `^1.4.0` and `~1.4.0` resolve to it, so a routine update picks it up:
read the migration notes below before upgrading. The `AuthException` half is compiler-guided;
the status half is not, and will surface as failing assertions in any suite that pins statuses.

### Fixed

- **BREAKING: thirteen error codes answered the wrong HTTP status, and five answered two.**
  A consumer's OpenAPI audit surfaced `auth.email_already_exists` answering `401` here and `409`
  in `rust-auth`. It was not one code. `auth.session_not_found` answered `401` instead of `404`;
  `auth.mfa_already_enabled` `401` instead of `409`; `auth.mfa_not_enabled`,
  `auth.mfa_setup_required`, `auth.password_reset_token_invalid`,
  `auth.email_change_token_invalid` and `auth.invalid_invitation_token` `401` instead of `400`.
  Five more disagreed with _themselves_ depending on the throw site: `auth.account_locked` was
  `429` on login but `401` on the MFA and password-reset lockouts — so a client backing off on
  `429` did not back off on the others — and `auth.email_not_verified`, `auth.mfa_required`,
  `auth.forbidden` and `auth.token_invalid` each answered two statuses across the codebase.
  Every value now matches `rust-auth`, which was the correct side throughout.

  **Root cause, and why no gate caught it.** `conformance/wire-contract.json` pinned the code
  _vocabulary_ and not the status per code, so the field had no gate at all; and
  `AuthException`'s status argument defaulted to `401`, making an omission neither a type error
  nor a lint error but a plausible-looking wrong answer. Both libraries' suites were green
  throughout — each side was self-consistent, and neither read the other.

  **Apply to a derived backend:** if you assert on HTTP statuses, thirteen codes move. The eight
  above take their new value everywhere. The five that answered two statuses now answer one, and
  a route-level assertion can fail on any of them even where the code itself is unchanged:
  `auth.account_locked` is `429` on every path (it was `401` on the MFA and password-reset
  lockouts), `auth.email_not_verified` is `403` (it was `401` on login and in `UserStatusGuard`),
  `auth.mfa_required` is `403` (it was `401` on the login MFA gate), `auth.forbidden` is `403`
  (it was `401` at every throw site), and `auth.token_invalid` is `401` (it was `400` in
  `SelfOrAdminGuard`'s hash-format rejection). Statuses only — no code string, message or
  envelope shape changed.

### Changed

- **BREAKING: `AuthException` no longer takes a status argument.** The signature is now
  `new AuthException(code, details?)`; the status is derived from the code via the new
  `AUTH_ERROR_STATUS` table. One code answering two statuses is no longer expressible, which is
  what the defaulted argument allowed. **Apply to a derived backend:** drop the second argument
  where you passed a status — `new AuthException(CODE, HttpStatus.FORBIDDEN)` becomes
  `new AuthException(CODE)`, and `new AuthException(CODE, status, details)` becomes
  `new AuthException(CODE, details)`. TypeScript flags the old three-argument form and any
  numeric status passed where `details` is now expected, so the migration is compiler-guided
  rather than silent.

### Added

- **`AUTH_ERROR_STATUS`** ([`src/server/errors/auth-error-codes.ts`](src/server/errors/auth-error-codes.ts)),
  exported from the package root: the `code → HTTP status` map every error answers by. Useful
  for a generated client, an API document, or a test asserting against the wire contract.

- **`errorCatalog.statuses` in [`conformance/wire-contract.json`](conformance/wire-contract.json)**,
  byte-identical with `rust-auth` like the rest of that file, plus conformance tests asserting
  `AUTH_ERROR_STATUS` against it, that the table covers the catalog exactly, and that each
  internal-only code carries the status of the public code it collapses onto — a differing
  status would hand back through the status line what the collapse removes from the body.
  These are wire statuses: `auth.otp_max_attempts` is `401` because a caller receives it as
  `auth.otp_invalid`, and a `429` would say the address was registered, since only a record
  that exists can reach an attempt ceiling.

### Tests

- **19 end-to-end status-window assertions replaced with an exact `(code, status)` pair**, across
  six spec files, via a shared `expectAuthError` helper: 16 were a bounded `status >= 400 &&
status < 500`, and 3 asserted only the `>= 400` lower bound, which is looser still. That form
  is why the drift above survived the suite — `401` where the contract says `404` is still a 4xx,
  so the check was satisfied by the right answer and the wrong one alike. Four of them asserted
  no error code at all and now do.

- **Two negated status assertions replaced in the rate-limit spec.** `expect(status).not.toBe(429)`
  accepts every wrong answer but one: the allowed login attempts now assert
  `auth.invalid_credentials` at the contract's status, and the separate-budget reset asserts
  `200` exactly, which also pins the anti-enumeration answer. Same defect as the range, one
  shape further out — and harder to spot, because a negation reads like a deliberate claim
  about a specific status.

- **The internal-only code list is now pinned by name.** Every other assertion about those codes
  lives inside a `for … of contract.errorCatalog.internalOnly` loop, so an empty or shortened
  list did not fail them — it stopped them running, and they reported success for having checked
  nothing. Unlike `codes` and `statuses`, nothing had pinned that array's contents.

- **MFA specs derive TOTP codes from the live step rather than a remembered one**
  ([`mfa-disable-flow`](test/e2e/mfa-disable-flow.e2e-spec.ts),
  [`mfa-recovery-codes-flow`](test/e2e/mfa-recovery-codes-flow.e2e-spec.ts)). The fixtures spend
  two adjacent TOTP counters and then reached one step backwards for a free slot, assuming the
  whole fixture lands inside a single 30-second step. Crossing a step boundary inverted that
  assumption: the slot reached for was the one `verify-enable` had burned, the anti-replay guard
  refused it, and `/mfa/disable` answered `401`, which surfaced as a pre-disable token still
  being accepted. A test defect, not a library one — the guard and the ±1 window behaved as
  designed.

- **`AuthException` is now tested against inherited `Object` members** (`constructor`,
  `toString`, `__proto__`, `hasOwnProperty`) and against a code absent from the catalog.

### Internal / CI

- **OSV-Scanner workflow** ([`.github/workflows/osv-scanner.yml`](.github/workflows/osv-scanner.yml)),
  a thin caller of the shared reusable. It scans the full resolved dependency tree on push, pull
  request and a weekly schedule — coverage neither `dependency-review` (pull-request diff only)
  nor `peer-advisory-drift` (declared ranges only) provides, since an already-installed
  transitive package can turn vulnerable between releases.

- **`conformance/wire-contract.json` excluded from Prettier**
  ([`.prettierignore`](.prettierignore)). Its bytes are the contract — the file must stay
  byte-identical with `rust-auth`'s copy, and the `lint-staged` glob `*.{json,md,yml,yaml}` runs
  `prettier --write` over it, so an ordinary commit was one formatting-default change away from
  breaking the pairing with no signal at all. Nothing in either repository compares one copy to
  the other, which is what makes a silent reformat unrecoverable rather than merely wrong.

## [1.4.0] - 2026-08-11

### Changed

- **BREAKING: `ioredis` peer range raised to `^6.0.0`** ([`package.json`](package.json); the `^5`
  and `^6` ranges are disjoint, so an existing ioredis 5 consumer no longer satisfies the peer
  contract). A host that also
  runs `@bymax-one/nest-queue` (which peers `ioredis ^6.0.0`) can now resolve a single copy of
  `ioredis` across the workspace, which is what lets a queue `Redis` and the client injected here
  as `BYMAX_AUTH_REDIS_CLIENT` be the same instance and typecheck as such. The bump is a peer
  contract only: this package imports `ioredis` for its `Redis` type alone — it never constructs a
  client — so no runtime path changed. ioredis 6 defaults to the RESP3 protocol but keeps its
  legacy reply mapping, so every reply shape this library reads is byte-for-byte what it read under
  ioredis 5; the wire contract with `rust-auth` is untouched. **Apply to a derived backend:** raise the
  `ioredis` version your app installs to `^6.0.0` so it satisfies the new peer range.

- **Mutation gate raised to a perfect score** ([`stryker.config.json`](stryker.config.json)). The
  `break`, `high` and `low` thresholds are now 100, and the suite meets it: every mutant in
  `src/` is killed or a documented equivalent, with no survivors. Six equivalent mutants in
  `otp.service.ts` — the empty-code guard and the EXPIRED/MAX arms of `verify`, each of which
  answers the same `OTP_INVALID` after the same padding as the constant-time comparison that
  follows — are marked inline with their reason rather than being removed, keeping the verifier's
  defense in depth and anti-enumeration structure intact. **Apply to a derived backend:** if your
  backend runs the shared mutation gate, expect it to require 100 rather than 95.

## [1.3.2] - 2026-08-10

Binds the MFA challenge to its tenant and scopes every MFA key, counter and write by it — the
multi-tenant hardening rust-auth mirrors byte-for-byte. It stays in the 1.3.x line, where the
library still has no published dependents; the one breaking change is the
`IUserRepository.updateMfa` signature, which a derived backend adopts as it upgrades.

### Security

- **The MFA challenge is bound to its tenant, and every MFA key is scoped by it.** The MFA temp
  token carried no tenant, so the challenge resolved its subject by id across every tenant
  (`findById(sub)` with no tenant) — and the status gate, the decrypted secret, the recovery
  digests and the account the session was finally minted for all ran against whatever row the
  repository returned. A library cannot assume a host's user ids are unique across tenants —
  `findById` takes a tenant precisely because they may not be — so under a schema that numbers users
  per tenant, every tenant has a user `1`. The token now carries `tenantId` (present on the
  dashboard plane, absent on the platform plane), `verifyMfaTempToken` refuses a dashboard token
  that lacks it and a platform token that carries it — a refusal, not a fallback (RFC 8725 §3.9 /
  §3.12, ASVS 5.0 6.6.2) — and `assertPlaneTenant` enforces the same rule at the five public
  `MfaService` entry points before any repository read.

- **Eight MFA store keys and failure counters were scoped by plane but not by tenant**, so two
  tenants' user `1` shared all of them. The three `lf:` counters were the worst: a shared lockout
  counter is a credential-free cross-tenant lockout — failures against one tenant's user spend
  another's budget, and a success on either clears the other — which is not the per-subscriber
  rate limiting NIST SP 800-63B requires. All eight now derive from one tenant-scoped `mfaSubject`,
  driven by the plane rather than by whether a tenant was supplied. The wire contract gains
  `mfaSubjectPreimages` and `mfaSubjectDerivedKeys`, pinning the shape rust-auth mirrors byte-for-byte.

- **The MFA write is scoped by tenant too, and a blank tenant is refused.** Every MFA transition
  writes — the recovery-code splice and the key-rotation re-encrypt — and both wrote through
  `updateMfa(id, data)`, keyed by id alone, so under colliding ids the write could land on another
  tenant's row and leave a spent recovery code in the list. **`IUserRepository.updateMfa` now takes
  the tenant: `updateMfa(id, tenantId, data)`** — a breaking change that forces every implementation
  to scope the write as its read is scoped (the platform repository is unchanged). And
  `assertPlaneTenant` now refuses a blank `tenantId`, not merely a missing one: `''` — what an unset
  environment variable becomes — would build `dashboard::{userId}`, a third keyspace.

**Apply to a derived backend:** upgrade and deploy this release **in full** before the one that
follows it. For a rolling upgrade this release dual-writes the anti-replay marker and the three
failure counters (every read consults both the old plane-only key and the new tenant-scoped key,
every write touches both) and dual-acquires the transition lock, so old and new pods stay
consistent while both are live. A later release drops the legacy arm; deploying it before this one
has fully rolled out would split the anti-replay and lockout state across the two key shapes. No
host code changes: the tenant is sourced from the authenticated account, never from the request.

## [1.3.1] - 2026-08-08

Adds the revocation checker and the overridable default auth-email provider, carries the tenant
on the email port, and refreshes the mutation figures the packaged README and CHANGELOG report.
All of it stays in the 1.3.x line: there are no published dependents, so nothing installed breaks.

### Added

- **`DefaultAuthEmailProvider` is exported**, the overridable default that fills the email port so a
  derived backend no longer hand-writes the same bridge onto its notification channel. It carries
  the policy that should not be copied per backend: HTML escaping on a path that renders
  caller-chosen text (an inviter's name, a tenant's name, the address an account moved to), the
  NIST SP 800-63B notification catalogue (a password-changed notice, MFA enable/disable notices, an
  email-changed notice to the _previous_ address), and a swallow-and-log failure policy so a down
  channel never turns "enable MFA" into a failed request. It sends through `AuthEmailSink`, a port
  narrow enough that the class imports no concrete mailer — `@bymax-one/nest-notification`'s
  `EmailService` satisfies it structurally — and it consumes the tenant the email port now carries,
  so a multi-tenant channel can attribute and route each message. Pass `messages` to override any
  subset of the copy with a product's own wording or branding; the escaping and failure policy
  still apply. It closes bymaxone/nest-notification#54.

- **`AuthRevocationService` is exported**, answering whether a verified access token has been
  revoked across both channels the module writes to — the per-token blacklist a logout writes and
  the per-user epoch a password reset or revoke-all advances. It closes bymaxone/nest-auth#92: a
  backend bridging this library to a realtime transport can inject it and consult the same two
  channels the HTTP guards do, instead of verifying a token's signature and granting a stream that
  outlives every revocation window. The `JwtAuthGuard`, `WsJwtGuard` and `JwtPlatformGuard` now
  delegate to it rather than each carrying its own copy of the two Redis reads — one source of
  truth for the check, so a fix reaches all three and every consumer at once. No behaviour changed:
  the guards' full suites pass unmodified.

### Changed

- **`IEmailProvider` carries the tenant on every method.** Each of the ten methods now
  takes `tenantId: string` as its first parameter, ahead of the recipient address. A notification
  backend serving more than one tenant could not, before this, tell which tenant a password-reset
  or invitation email belonged to: it saw only an address, so it could not pick the right sender
  identity, branding, locale default or audit stream. The tenant was known at every call site — a
  dashboard user carries its own `tenantId`, and a cross-tenant platform admin is attributed to the
  `'platform'` plane, mirroring the `pep:` epoch namespace — it simply was not being passed. It
  closes bymaxone/nest-auth#93.

  **Apply to a derived backend.** Any `IEmailProvider` implementation must add `tenantId: string`
  as the first argument of every method it defines and route on it as its backend requires; a
  provider that ignores tenancy can name the parameter `_tenantId` and change nothing else. The
  bundled `NoOpEmailProvider` already conforms.

  Migrate **every** method, not only the one the compiler flags. Because the added argument is a
  `string` prepended to methods whose other arguments are also strings, a stale
  `sendPasswordResetToken(email, token)` stays assignable to the new type — TypeScript accepts an
  implementation with fewer parameters — so it compiles while binding `tenantId` to the recipient
  at runtime. Only `sendInvitation`, whose second argument is an object, fails compilation. Fixing
  that one is not proof the rest are done; the surest path is to extend the `DefaultAuthEmailProvider`
  this release adds rather than hand-write the port.

  The library has no published dependents yet, so this breaks nothing already released and ships in
  the ordinary `1.3.x` line rather than as a major — SemVer's promise is to existing consumers, and
  there are none to break.

- **The mutation score is re-measured rather than restated.** The last recorded run was
  2026-07-28, before 1.1.0, 1.1.1, 1.2.0, 1.3.0 and the third security audit, and the README still
  quoted its figures: 3,474 faults killed against 2,458 tests. A cold run on 2026-08-08 —
  incremental baseline deleted, nothing inherited, and now covering this release's own additions —
  puts the library at **100.00% with 4,870 mutants detected (4,849 killed, 21 timed out), no
  survivors and none without coverage**, out of 7,718 instrumented across 147 files. The suite
  behind it is **3,547 tests** (3,420 unit, 127 end-to-end). All five subpaths are individually at
  100.00%.

  The count of documented equivalents is now reported as the number it is — **350 mutants under
  217 `// Stryker disable` directives** — instead of "the handful that no test can kill". Nothing
  about them changed; the README's description of them had simply stopped matching their size, and
  a number that is written down can be audited.

- **`docs/mutation_testing_results.md` records the run** in a new dated section, with the full
  outcome table, the per-subpath split, and where the twenty-one timeouts sit. The earlier
  sections are left as they were — they are the record of the passes that produced them. The
  reproduce instructions are corrected in the same pass: they named `pnpm mutation:incremental`,
  which is not a script in this package, and promised a ten-minute run that now takes
  forty-eight at `--concurrency 2`.

## [1.3.0] - 2026-08-08

Minor rather than patch because the API now accepts a request it previously rejected: with a
`tenantIdResolver` configured, `tenantId` may be omitted from the body. Nothing a consumer sends
today stops working, and no option changed meaning.

### Fixed

- **`tenantId` is optional on every DTO that carries it**, so a deployment that configures
  `tenantIdResolver` no longer forces its clients to send a value the server discards. The
  option's whole purpose is that the resolved tenant wins and the body's is ignored, but the nine
  DTOs declared the field with `@IsString() @IsNotEmpty()` and no `@IsOptional()`, so a request
  that omitted it was rejected before any service ran. The two configurations were both wrong in
  opposite directions: without a resolver the body named the tenant and was trusted, and with one
  the body was mandatory and ignored.

  `resolveTenantId` now refuses a request that no resolver and no body value can scope, answering
  `auth.validation` with the same `{ field, message }[]` shape the validation pipe produces. It is
  refused rather than defaulted deliberately: inventing a tenant name would gather into one scope
  every account a misconfigured deployment created. `null` counts as absent there, because
  `@IsOptional()` skips validation for `null` as well as for `undefined` — a caller may send
  `tenantId: null` past every DTO constraint, and admitting it would carry `null` into the
  tenant-scoped lookups and into the Redis and HMAC keys built from it.

  Nothing changes for a consumer that sends `tenantId` today, with or without a resolver.

- **`jwt.absoluteSessionLifetimeDays` is documented as the 30-day default it actually is.** The
  option's doc comment, the README's option table, the README's "deliberately off by default"
  note and the specification's table all still described the pre-1.2.0 behaviour, where the cap
  was off unless a deployment asked for it. 1.2.0 turned it on at 30 days as a security fix and
  the prose did not follow, so the surface a consumer reads in their editor argued for planning
  around sessions that never end.

### Changed

- `AuthService.register`, `AuthService.login`, `AuthService.verifyEmail`,
  `AuthService.resendVerificationEmail` and `OAuthService.initiateOAuth` accept `tenantId` as
  optional, matching the DTOs that feed them. The password-reset flows now read the resolved
  tenant from the local binding rather than from the reassigned DTO, which is the same value and
  removes the question of whether the reassignment happened.

## [1.2.0] - 2026-08-08

Carries the third security audit and the findings that surfaced while driving the mutation
score, across two pull requests that landed without versions of their own.

> **Action required for two deployments.** The Next.js proxy now **requires** `jwtSecret`;
> the decode-only fallback is gone, so a consumer that never set it fails at boot instead of
> trusting an unverified token. And the password floor moved from 8 to **15** by default —
> existing stored passwords keep working, but a set or change below 15 is now refused unless
> `password.minLength` says otherwise.

### Security

- **A live session could hide from revoke-all.** Pruning removed members whose `rt:` key was
  still present, so a session survived the call meant to end every session for an account.
  Prune now removes only a member whose `rt:` key is actually gone.
- **The Next.js proxy fell back to decoding a token without verifying it.** `jwtSecret` is
  required and the decode-only path is removed. An unverified decode answers with whatever
  the token claims.
- **A crafted password record could OOM-kill the process.** `compare()` derived scrypt's
  `maxmem` from the stored PHC parameters and widened it to fit, so `ln=31` with the shipped
  `r=8` asked for 2 TiB — which does not fail the request, it takes the process and every
  in-flight connection with it. The ceiling is a constant that input cannot widen. A block
  size above the parameter ceiling that the memory ceiling let through is closed with it.
- **An OTP check could pass on two absent values.** A non-string stored code fell back to
  `''`, and `timingSafeEqual` answers true for two empty buffers, so an empty submitted code
  compared equal to the placeholder and verification succeeded. The non-string record is
  refused instead.
- **Two guards were exported but unusable.** `UserStatusGuard` was missing
  `BYMAX_AUTH_USER_REPOSITORY` and `WsJwtGuard` was missing `WsTicketService` from the
  module's exports, so `@UseGuards(JwtAuthGuard, UserStatusGuard)` failed a consumer's boot
  and every route on a derived backend was protected by token validity alone — a suspended
  or deleted account kept access for a full access-token lifetime. The ticket handshake was
  likewise unreachable, so realtime authenticators replayed the access-token cookie and never
  consulted the revocation blacklist. All nine guards' constructor deps were audited; these
  were the only gaps.
- **OAuth `state` was not bound to its provider** (RFC 9700 mix-up). The provider is carried
  in the state record.
- **A cookie prefix whose attributes cannot satisfy it** is dropped silently by the browser.
  The contract is validated at boot.
- **The absolute session lifetime inherited no cap.** Capped at 30 days (NIST SP 800-63B-4
  §3).
- **The rate limit charged a single IPv6 address**, which costs an attacker nothing to move
  within. Charged to the /64.
- **"Is this production" was sniffed from `NODE_ENV`** in six places. An explicit
  `environment` option decides it, defaulting to production.

### Added

- **`password.minLength`** — configurable, defaulting to **15**. NIST SP 800-63B-4 §3.1.1.1
  allows 8 only for a password used as part of multi-factor authentication and requires 15
  for a single factor; MFA here is opt-in per user, so the default deployment is
  single-factor. The check moved to `PasswordService.assertAcceptable`, one entry point for
  the four sites that set a password, screening length before the breach corpus — a password
  refused for being short should not cost a round trip nor be sent anywhere first.
- **`MfaService.resetMfa`** — administrative removal of a second factor, for a user who lost
  both the authenticator and the recovery codes. Every self-service exit needs the factor
  itself, so without it that user is locked out permanently by the control meant to protect
  them (ASVS v5 §6.1.1). It ships as a method and **not** a route, the decision
  `unlockAccount` already made: every route this library exposes is scoped to the caller's
  own account, and who may reset whom is a question only the host can answer. It invalidates
  sessions, bumps the token epoch so `mfaVerified: true` tokens die with the factor, and
  notifies the account holder — an administrative reset the owner cannot see is an
  account-takeover path.
- Log lines where the response is deliberately uninformative, so the log is the only record
  the event happened: ws-ticket refusals, invitation and revoke-rank refusals, email-change
  and change-password lockouts, MFA re-authentication refusals, and corrupted MFA setup
  payloads.

### Changed

- **`sendNewSessionAlert` is optional.** It was a required provider method the library never
  called, with a docstring claiming it fired on login. Without device recognition it would
  fire on every login, and an alert on every login is one the user learns to dismiss — the
  control stops existing while appearing to be in place. `onNewSession` already fires on
  every session created; the docs now say what is true.

## [1.1.1] - 2026-08-05

This release carries the second cross-implementation security audit as well as the dependency-injection fix below. Both landed as separate pull requests; the audit one carried no version of its own, so its account is here.

### Security

- **The AES key over every stored second factor was enumerable.** `1.1.0` hid `jwt.secret`, its
  rotation predecessors and the derived HMAC keys, but not `mfa.encryptionKey` or
  `mfa.previousEncryptionKeys` — the AES-256-GCM key protecting every enrolled user's TOTP secret
  and their recovery-code set. `JSON.stringify`, object spread and `util.inspect` on the resolved
  options all emitted it, which is what a structured logger does when handed a provider.
- **Refresh-token reuse was logged anonymously.** The strongest compromise signal this library
  produces reached only a consumer who had wired the hook, and the shipped hooks are no-ops.
- **A `getMe()` in flight could resurrect a session after logout.** `status` returned to
  `authenticated` and the profile returned to context, so `useAuthStatus().isAuthenticated` — which
  this library's own JSDoc calls safe to gate protected routes on — answered `true` after sign-out.

### Fixed

- **The two libraries could not read each other's password hashes.** This library wrote
  `scrypt:N:r:p:{saltHex}:{derivedHex}` while `rust-auth` writes PHC. Neither parser accepted the
  other's output, and because verification is total the failure surfaced as `invalid_credentials`
  rather than a parse error — so five correct attempts by the owner tripped the brute-force
  counter the two backends key identically and locked the account out of both.
- **Every non-Latin password was refused as compromised.** Two ASCII filters in the breach screen:
  `isDecoration` used `\W`, so Cyrillic, Greek, Han, Kana, Arabic, Hebrew and Thai characters all
  counted as decoration and were stripped, and what survived was filtered to `[a-z0-9]`.
- **`baseUrl: '/api'` sent every request to `/api/api/auth/*`.** The client composed the full URL
  and also handed `baseUrl` to the fetch wrapper it builds — the value the README and
  `AuthProvider`'s own example document for the same-origin/Next-proxy setup.
- **A new session was written with five loose Redis commands**, where `rust-auth` does the same
  work in one `MULTI/EXEC`. A revoke-all landing between the record write and the index `SADD`
  swept an index the session was not in yet, and a dropped connection between the `SADD` and the
  `EXPIRE` left the index with no expiry at all, permanently.
- **The session index grew one permanent member per refresh.** A rotation adds `rp:{old}`
  alongside `rt:{new}`, only a full revoke-all ever removed it, and the rotation re-armed the
  set's TTL each time. Every reader is linear in its size, including the script a password reset
  runs, which blocks the whole single-threaded store.

### Fixed

- **Dependency injection no longer depends on a transitive dev dependency.** Seventy-one
  constructor parameters across thirty classes were resolved from `design:paramtypes`,
  the metadata TypeScript emits — and this package emitted it only because `@swc/core`
  happened to be in the tree via `ts-node`. tsup enables its SWC transform when that
  package is present and prints a warning when it is not:

  ```
  You have emitDecoratorMetadata enabled but @swc/core was not installed, skipping swc plugin
  ```

  Nine sibling packages get that second path and none of their bundles carry the metadata. Had the transitive dependency moved,
  every one of those parameters would have stopped resolving at once — silently wherever
  `@Optional()` is present. They now carry explicit `@Inject`, which writes
  `self:paramtypes` and is independent of any build transform.

- `@swc/core` is a declared devDependency. The metadata is still needed — `ValidationPipe`
  finds a DTO class through the reflected parameter type, and thirty-one controller
  parameters here are typed by DTO — so the emission stays. It is now deliberate rather
  than inherited.

## [1.1.0] - 2026-08-03

The API changes marked **Breaking** below are breaking against `1.0.11`. They are
released as a minor because the package has no consumers yet — it is published but
not in use anywhere. The marks stay because the changelog records what changed, not
who it reached.

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
  TypeScript 5.0 and below. The package root is covered too, keyed on the path in
  `types` rather than on `"."` — TypeScript matches `typesVersions` patterns against
  the value of the `types` field, so a `"."` entry never fires.
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

- **Secrets are no longer disclosed when an injected provider is serialized.** The signing
  secret, its rotation predecessors, the HMAC keys derived from them and each configured
  OAuth `clientSecret` were plain fields on the resolved options, and `AuthRedisService`
  held its ioredis client — which carries `options.password` — in a TypeScript `private`
  property, which is erased at runtime. The resolved options are injected into roughly a
  dozen guards, controllers and services, so `JSON.stringify`, object spread and
  `util.inspect` on any of them emitted key material in plaintext. That is what a
  structured logger does when it renders its arguments, and what an error reporter does
  when it captures the scope of a throw. Every one of those fields is now a
  non-enumerable accessor or an ECMAScript private field, withheld from `showHidden` as
  well. Reads are unchanged, no public type moved, and the consumer's own options object
  is never rewritten — the OAuth provider configs are copied before being adjusted.

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

[Unreleased]: https://github.com/bymaxone/nest-auth/compare/v1.4.3...HEAD
[1.4.3]: https://github.com/bymaxone/nest-auth/compare/v1.4.2...v1.4.3
[1.4.2]: https://github.com/bymaxone/nest-auth/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/bymaxone/nest-auth/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/bymaxone/nest-auth/compare/v1.3.2...v1.4.0
[1.3.2]: https://github.com/bymaxone/nest-auth/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/bymaxone/nest-auth/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/bymaxone/nest-auth/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/bymaxone/nest-auth/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/bymaxone/nest-auth/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/bymaxone/nest-auth/compare/v1.0.11...v1.1.0
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
