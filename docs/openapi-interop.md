# OpenAPI documents and `@bymax-one/nest-core`

How this library contributes its security posture and request bodies to an OpenAPI document built with `@bymax-one/nest-core`. Part of the [`@bymax-one/nest-auth` README](../README.md).

## On `@bymax-one/nest-core`, the security posture writes itself

A deployment that builds its OpenAPI document with `@bymax-one/nest-core` **1.4.0 or later** gets
this library's operations described automatically — which schemes exist, which operation requires
which, and which are reachable unauthenticated. Nothing to enable and nothing to import: the
module registers a contributor, nest-core discovers it while building the document, and the
fragments are merged.

It has to be derived at your boot rather than shipped as a static file, because the answer
depends on your configuration:

| your options                   | what the document says                                                                                                                                                                                                                                                                                                           |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tokenDelivery: 'cookie'`      | `bymaxAuthAccessCookie` and `bymaxAuthRefreshCookie`, **carrying your cookie names**                                                                                                                                                                                                                                             |
| `tokenDelivery: 'bearer'`      | `bymaxAuthAccessBearer` only — no refresh scheme exists, and `logout`/`refresh` instead carry a documented `{ refreshToken }` body                                                                                                                                                                                               |
| `tokenDelivery: 'both'`        | both access schemes as **alternatives** (`security: [{cookie}, {bearer}]`, which OpenAPI reads as OR)                                                                                                                                                                                                                            |
| `controllers.platform: true`   | `bymaxPlatformAccessBearer` — always bearer, in every mode, because platform credentials are read from the header whatever `tokenDelivery` says. The **registration** switch decides, not `platform.enabled`: the module mounts the platform controllers on `controllers.platform` and validates the `platform` config only then |
| a controller you did not mount | nothing at all: no operation, and no scheme only it would have referenced                                                                                                                                                                                                                                                        |

A scheme the resolved options cannot satisfy is **absent**, never defined-and-unreferenced — a
document that defines a credential the server will not read tells a generated client to offer it.

The four names — `bymaxAuthAccessCookie`, `bymaxAuthAccessBearer`, `bymaxAuthRefreshCookie`,
`bymaxPlatformAccessBearer` — are stable identifiers. Renaming one is a break a generated client
feels, so they will not change; their **definitions** are config-derived.

Import them rather than spelling them. A platform-only deployment guarding its own routes with
`JwtAuthGuard` has to declare the dashboard access scheme itself — the fragment will not, because
`schemesFor` gates dashboard schemes on what you mounted — and a hand-written literal in a section
about literals drifting from configuration is the wrong instruction:

```typescript
import { AUTH_SECURITY_SCHEMES } from '@bymax-one/nest-auth'

// [{ bymaxAuthAccessCookie: [] }], spelled by the package that owns the name
const security = [{ [AUTH_SECURITY_SCHEMES.accessCookie]: [] }]
```

> **This package does not depend on `@bymax-one/nest-core`** — not as a dependency, a peer, or a
> devDependency. The contract revision is inlined, the discovery marker is the documented string
> literal, and a gate fails the build if any file here imports another Bymax library. That keeps
> your install graph free of a package you may not use, and it moves one check to your side:
>
> ```typescript
> // in your suite, where both packages are installed at the versions you run
> import {
>   BYMAX_OPENAPI_CONTRACT_VERSION,
>   BYMAX_OPENAPI_CONTRIBUTOR_METADATA
> } from '@bymax-one/nest-core/openapi'
>
> expect(fragment.contractVersion).toBe(BYMAX_OPENAPI_CONTRACT_VERSION)
> expect(Reflect.getMetadata(BYMAX_OPENAPI_CONTRIBUTOR_METADATA, contributor.constructor)).toBe(
>   true
> )
> ```
>
> Worth writing once. A revision mismatch fails your document build loudly and names the
> contributor, but a **marker** mismatch is silent: the provider is simply never discovered and
> the document renders without the fragments — the same symptom as running nest-core < 1.4.0.

> **On nest-core older than 1.4.0 the fragments are silently ignored.** There is no contributor
> lane to discover them, so the document renders exactly as before — no error, no warning, no
> failed boot. If you add a document and the auth schemes do not appear, check in this order:
> whether this library is new enough to contribute them at all, and only then your nest-core
> version. The two states look identical from the document.

## On `@bymax-one/nest-core` 1.6.1 or later, the request bodies are described too

The same contributor offers the request-body schema of every DTO that the controllers your
deployment mounted take (`LoginDto`, `RegisterDto`, `ResetPasswordDto` and the rest), derived from
their `class-validator` decorators. Without a contribution `@nestjs/swagger` registers each of them as
`{"type":"object","properties":{}}`, because this package is built without its CLI plugin, and a
client generated from the document types every request body as `{}`.

> **Request schemas appear with `@bymax-one/nest-core` ≥ 1.6.1; older versions ignore the
> contribution without a signal.** Through 1.6.0 an empty placeholder counts as a declaration, so
> the schema offered here is dropped and the document renders exactly as before: no error, no
> warning, and no `discarded` field on what `applyBymaxOpenApi` returns. From 1.6.1 the
> placeholder is filled from the contribution. A schema of the same name that carries properties
> of its own is a declaration and wins, and `applyBymaxOpenApi` reports the contribution that
> lost in `discarded`. Components are keyed by the DTO's class name, so a DTO of your own that
> shares a name with one of this library's (a `LoginDto`, say) and is itself an empty placeholder
> is filled with this library's schema: name your own classes differently.

Two limits, so a missing field is not mistaken for a bug. The OAuth endpoints take their input as
query parameters, which the builder describes as operation parameters rather than as a component,
so no schema is offered for those two DTOs. And what a decorator cannot express (which proof
`ResetPasswordDto` accepts for the configured `passwordReset.method`, the deployment's
`password.minLength`) is not in the schema and is not described elsewhere in the served document.

**If you already wrote these by hand, delete them** — not because they are wrong. They are what
makes your document correct today; the deletion is what hands the job to the library, and it is
needed precisely because they were doing it. Precedence, read from nest-core's
`augmentOperation` rather than summarised: the generated operation's own `security` outranks
everything, then your `openapi.operationSecurity` override, then this library's fragment, then
nest-core's policy. So a stale scheme name or an override for an auth route keeps winning and the
contributed one never lands — the document goes on describing whatever you wrote when you wrote
it, including cookie names you have since changed.

> **Delete the entries for THESE routes. Keep your document-level `security`.** They are usually
> written in the same options block, and taking the block out is the failure this warning exists
> for: a document can end up **more wrong after adopting than before**. The mechanism is in `augmentOperation`: an operation with no
> requirement of its own, no override and no fragment falls through to `ownRouteSecurity`, which
> answers `undefined` for anything that is not a route nest-core answers for itself — the health
> probes, and from **nest-core 1.5.3** an unprotected metrics endpoint (through 1.5.2 metrics was
> not among them). So **your** guarded routes carry no requirement and inherit the document
> default. Remove that default and every one of those routes reads as needing no credential.
>
> **Keep the condition attached, because it decides how much of your API is affected.** This
> reaches the routes that state nothing of their own — no `@ApiSecurity`-style decorator feeding
> the scanned operation, no entry in nest-core's `operationSecurity`, and not a route nest-core
> answers for itself. Anything carrying its own requirement outranks the document default and is
> untouched, which is exactly why the fix works at all. If your backend annotates every guarded
> route individually, this note does not apply to you; annotating each route is the thing a
> document-level default exists to avoid.
>
> **nest-core's own routes are the exception that still moves.** It emits an explicit `security: []`
> for the health probes — and, from 1.5.3, for a metrics endpoint left unprotected — but only when
> the **served document actually carries a non-empty top-level `security`**, whether that came from
> `openapi.security` or was already on the generated document handed to nest-core.
> Remove the default and the `[]` goes with it. Write the default as an explicit empty list and
> nothing is being overridden, so the member stays absent either way.
>
> **On nest-core below 1.5.0, nothing reports this.** No error, no unmatched key, no failing
> build — the document simply stops asking for credentials on the routes the library never knew
> about, which are the ones your backend owns. **nest-core 1.5.0 warns**, on exactly this shape:
> a document with no top-level `security` where some other operation does state a requirement, so
> the bare ones are bare against a described posture rather than in a document that describes
> none. It names the operations and never throws. That makes the failure visible, not impossible —
> a warning in a build log is still something a person has to read.
>
> Keep the default, and **derive it rather than writing a literal**. The derivation
> ships, so the common case is one call rather than a rule you apply by hand:
>
> ```ts
> import { authDocumentSecurity } from '@bymax-one/nest-auth'
>
> BymaxCoreModule.forRoot({
>   openapi: {
>     // `tokenDelivery` here is the SAME value you pass to BymaxAuthModule.registerAsync — read it from
>     // one place. A default derived from a second copy drifts exactly like a literal does.
>     security: authDocumentSecurity({ guard: 'dashboard', tokenDelivery })
>   }
> })
> ```
>
> It answers the delivery axis of both questions below — the scheme name for your guard family,
> and the two-entry alternation under `'both'` that a hand-written default usually collapses into
> a single AND entry. **It does not know what you mounted**, which is the third row of the table
> in question 2 and the one case you still have to answer yourself. Read on for that, and for why
> the recipe takes two questions rather than one:
>
> **1. Which guard protects your own routes?** That decides the credential family, and
> `tokenDelivery` does not enter into it for one of them.
>
> - `JwtAuthGuard` (the dashboard family) → an access scheme, chosen by delivery. Go to question 2.
> - `JwtPlatformGuard` → **`bymaxPlatformAccessBearer`, in every mode**. `extractPlatformAccessToken`
>   reads the `Authorization` header whatever `tokenDelivery` says, and `schemesFor` declares that
>   scheme with no delivery condition on it. A platform-guarded route wants it under `cookie`
>   delivery exactly as much as under `bearer`.
> - **Both, on different routes** → the default cannot express this, though not because it is
>   limited to one entry. A document `security` array may hold both requirements — but the entries
>   are **alternatives**, and the whole array applies to every operation that inherits it. Listing
>   both therefore documents each credential as valid for _either_ family, which says your platform
>   routes accept a member token. That is not a missing detail; it is a false statement about who
>   can call what. Give the minority family per-operation `security` (via your own decorator or
>   nest-core's `operationSecurity`) and let the default cover the majority.
>
> **2. For the dashboard family — which schemes does this deployment actually declare?** Delivery
> decides, and so does what you mounted. Take a default written as `[{ bymaxAuthAccessCookie: [] }]`:
>
> | deployment                             | this contributor declares         | that literal default                                        |
> | -------------------------------------- | --------------------------------- | ----------------------------------------------------------- |
> | dashboard mounted, `cookie`            | the cookie scheme only            | correct                                                     |
> | dashboard mounted, `both`              | the cookie **and** bearer schemes | resolves, but describes only one of the two channels        |
> | dashboard mounted, `bearer`            | no cookie scheme at all           | names an undeclared scheme — `assertSchemesDeclared` throws |
> | **no dashboard surface, any delivery** | **neither dashboard scheme**      | names an undeclared scheme — throws, `cookie` included      |
>
> That last row is the one a delivery-only recipe gets wrong, and **"no dashboard surface" is
> wider than it first sounds.** `schemesFor` gates both dashboard schemes on one of `auth`,
> `passwordReset`, `mfa`, `sessions`, `invitations` or `emailChange` being registered. `oauth` is
> **not** in that list — its operations are public and reference no credential — so an OAuth-only
> deployment contributes operations and zero schemes, exactly like a platform-only one. Any
> deployment with no dashboard controller is in this row, and `cookie` delivery, which the recipe
> would call the safe case, throws just as hard as `bearer`.
>
> **And that row needs a remedy, not just a warning, because these deployments are legitimate.**
> `JwtAuthGuard` is registered and exported unconditionally — it is not gated on any controller
> flag — so mounting no dashboard controller does **not** stop you from guarding your own routes
> with a dashboard access token. Both shapes are real: the platform surface plus your own routes
> on the member credential; or the OAuth surface alone, where sign-in happens through a provider
> and your app issues member tokens itself. In each case the guard is available and the scheme
> describing it is not. Deriving correctly there lands you on "the scheme I need does not exist",
> which is an accurate answer and not a usable
> one.
>
> **Declare it yourself, in your own `openapi.securitySchemes`.** This is the one case where
> "delete your hand-written `securitySchemes`" has an exception, and the exception exists because
> the contributor deliberately declares only what its own operations reference — defining a
> dashboard scheme on a deployment with no dashboard operation would put an unreferenced
> credential in every such document, which is the opposite error and the reason for the gate.
>
> **Which scheme you declare is still a function of delivery** — the exception is to the deletion
> rule, not to the derivation rule, and writing one fixed definition here reintroduces the very
> literal this section is about:
>
> - `cookie` → the `apiKey`-in-cookie definition, carrying the `cookies.accessTokenName` you
>   configured. The cookie name is yours to choose, so this is the one that must match what the
>   server actually reads.
> - `bearer` → the HTTP bearer definition. There is no cookie name to carry.
> - `both` → **both of them**, or your document is incomplete in exactly the quiet way described
>   above.
>
> One note on doing any of it: **`AUTH_SECURITY_SCHEMES` is exported from the package entry**, so
> import the names rather than writing `bymaxAuthAccessCookie` and `bymaxAuthAccessBearer` as
> string literals. The compiler then checks the PROPERTY you reach for, so a typo is a build
> error rather than a document declaring a scheme nothing defines — and if a scheme's identifier
> is ever renamed, your document carries the new one instead of a literal that has quietly gone
> stale. Renaming the value is not itself a build error, since `AUTH_SECURITY_SCHEMES.accessCookie`
> stays valid and only its string changes; that is precisely why importing beats copying.
>
> **The wrong outcomes are not one failure, and the difference is the point.** Where the scheme
> does not exist, nest-core's `assertSchemesDeclared` **throws** and the document never builds —
> loud, immediate, impossible to ship. Under `both` the scheme does exist, so nothing throws; the
> default is merely **incomplete**, telling a reader that your own routes take a cookie when they
> equally accept a bearer token. That one is quiet, and it is the same class of quiet as the bug
> this whole note is about. A literal written against a bearer-only deployment inverts the table
> and fails under `cookie` for the same reasons.
>
> So the advice that fixes a silently wrong document can introduce a loud broken one **or a second
> quiet one**, depending on where you land. Derive from the same inputs the contributor reads —
> the guard your routes use, your delivery mode, and the controllers you registered — and the
> answer is right everywhere at once, instead of correct in one configuration and checked forever.
>
> The default is what covers your routes, and it cannot disturb this library's: a per-operation
> requirement outranks a document-level one, and every operation the contributor describes carries
> its own.
>
> **What an empty `{}` alternative says, and where this library uses it as an approximation.**
> In OpenAPI it means one thing: authentication is **optional** for that operation — a caller
> presenting none of the named schemes is valid. Tooling reads it as anonymous access and infers
> nothing about a request body from it.
>
> On `logout` that is exactly right, in **every** delivery mode including `cookie`: the operation
> really does answer a caller who presents nothing, which is why a user whose access token
> expired can still sign out. How many alternatives you see depends on the mode, since each one
> is a combination of the credentials that mode actually has:
>
> | operation         | `cookie` | `bearer` | `both` |
> | ----------------- | -------- | -------- | ------ |
> | `logout`          | 4        | 2        | 6      |
> | `password/change` | 2        | 1        | 4      |
>
> On `refresh` under `tokenDelivery: 'both'` it is an **approximation, and a permissive one**.
> That operation refuses a caller with no credential at all; the token may simply arrive in the
> request body, which `security` has no vocabulary for. The empty entry is what lets the document
> describe the body-only caller, and the cost is that it also tells tooling anonymous access is
> acceptable when it is not.
>
> The `requestBody` beside it **documents the body channel; it does not carry the requirement**.
> Under `'both'` it is `required: false` and its schema does not list `refreshToken` as required,
> because either channel satisfies the server and a body that omits the token is valid when the
> cookie carries it. So the document as a whole permits a request with neither, and the server
> refuses that request. **OpenAPI cannot express "one of these two channels" across a security
> requirement and a request body**, and this is the shape of that limitation rather than an
> oversight. Under `'bearer'`, where the cookie does not exist, the body becomes required at both
> levels and the document is exact.
>
> **Verify with a diff, not by reasoning.** Render the document with the contributor active and
> again with your entries in place, and compare only the operations you mount. A regression here
> is invisible to a status-code probe, because the routes it breaks still answer correctly at
> runtime.
>
> **And there is one shape no warning will catch for you, however new your nest-core.** If you
> remove _every_ requirement at once — no library describing anything, no decorator, no override,
> no document default — what remains is indistinguishable from the document of an API that is
> public on purpose. Both are a set of operations that ask for nothing. **No general-purpose tool** can separate the two from the rendered document alone
> without also shouting at every genuinely public API, which is how a warning earns the right to
> be ignored. This is why nest-core's warning requires that _some_ operation still state a
> requirement: the gap is deliberate, not an omission, and no version closes it.
>
> **But it is a limit on document-only checks, not on you** — and the distinction matters, because
> the better answer is the one a general-purpose tool cannot supply. **You** know your API is not
> public, which is exactly the intent no renderer can recover, so write it down as an assertion in
> your own suite: that the built document carries a top-level `security`, or that every route
> behind your auth guard renders with some requirement. That is a standing check, it runs on every
> commit, and it does not depend on anyone remembering to compare. Prefer it to the diff.
>
> Render the document twice and compare when you are **changing** this — adopting the contributor,
> moving delivery mode, adding a surface — because a diff shows you what moved without your having
> to predict it in advance. Then turn what you learned into the assertion, so the next change is
> caught rather than inspected.

**That chain is about `security` alone, and the other members run the opposite rule** — worth
stating because generalising either one produces a wrong belief about the other. There is no
configuration channel for a `description`, a `summary` or a tag: `mergeFragment` merges the
scanned operation **over** the fragment, so a contributed member lands unless the handler itself
declared that member, and the handler is this library's. Concretely, the `description` on
`logout` cannot be shadowed by anything in your options — only by an `@ApiOperation` on a handler
you do not own. Nothing to delete for that half; the deletion above is entirely about `security`.

> **Your own document test will not catch this.** If a suite asserts your operation-to-posture map
> with `toEqual` and your `operationSecurity` holds entries for this library's routes, every
> contributed fragment loses to those entries on adoption, the old scheme names survive, and the
> suite stays **green**, because it asserts the old answer that is still being served. The
> deletion is the step; nothing downstream will remind you.

Do it as one change: delete the literals, update whatever pins your document to the four-name
vocabulary, rebuild it, and regenerate any typed client — the operation ids do not move, but the
scheme names and the per-operation requirements do.

## Machine-readable schemas

The same contracts are published as data in
[`conformance/openapi-request-schemas.json`](../conformance/openapi-request-schemas.json) —
OpenAPI 3.0 schemas for all 22 DTOs, generated from the decorators themselves and regenerated by
`pnpm gen:openapi-schemas`. Alongside it,
[`openapi-request-descriptions.json`](../conformance/openapi-request-descriptions.json) carries the
facts no keyword expresses: the twelve e-mail fields that are **trimmed and lowercased before
validation**, each entry shipping the probe that verifies its own sentence.

A third file,
[`openapi-declared-structures.json`](../conformance/openapi-declared-structures.json), carries the
contracts the generated header names and no decorator can express — as **structure**, not prose:

| Declared                                                                                                         | As                                                                  |
| ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `reset-password` takes exactly one of `token`, `otp`, `verifiedToken`                                            | `oneOf`                                                             |
| An OAuth callback with neither `code` nor `error` is the **handler's** refusal, not the pipe's                   | probes the pipe accepts and the handler answers `auth.oauth_failed` |
| The 8-character floor is structural, not your policy                                                             | probes showing the pipe accepting what the deployment refuses       |
| `forgot-password`, `resend-otp`, `resend-verification`, `verify-email` answer identically for an unknown address | probes asserting the two responses are **equal**                    |

Three rules keep it honest. Only `required`, `oneOf` and `anyOf` may appear — `allOf` and `not`
are valid OpenAPI 3.0 and are **refused at load**, because a keyword nothing evaluates publishes
a claim nothing checks. Every entry carries probes, and both suites run them: the unit suite
evaluates each body against its own structure and reads what the pipe answers, the e2e suite
answers the rest with a real application. An entry whose two layers disagree — the pipe accepting
what the handler or the service then refuses — is split across the two suites on purpose, because
neither can see the pair. And presence means _present and not `null`_ — this
server's rule rather than JSON Schema's, because `@IsOptional()` treats `null` as absent, so a
body sending `null` and one omitting the key are the same request.

A structure is a **necessary** condition, never a sufficient one, and `reset-password` shows why:
which of the three proofs is eligible depends on `passwordReset.method`, and an ineligible proof
is refused with the same code a structural violation gets. That narrowing is declared with its
own probes and is deliberately not something a client can generate against.

Another file,
[`openapi-operation-security.json`](../conformance/openapi-operation-security.json), maps every
operation this library mounts (`METHOD /path`, relative to your route prefix) to the **kind** of
credential it requires, with the meaning of each kind alongside. It is generated from the table the
OpenAPI fragment is built from and the controllers' route metadata, regenerated by
`pnpm gen:openapi-security`, and a spec fails when it differs. How a kind becomes a security
requirement depends on your `tokenDelivery` and is not in the file.

These are development artifacts — they are not in the published tarball, and nothing reads
them at runtime yet. They exist so the schemas are a function of the decorators rather than a
second description maintained by hand.
