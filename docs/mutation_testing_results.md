# Mutation Testing

`@bymax-one/nest-auth` is verified with mutation testing using [Stryker](https://stryker-mutator.io/).
Line coverage proves a line _executed_ during a test; mutation testing proves a test _would
fail_ if that line were wrong. We seeded thousands of small faults into the source — flipped
booleans, removed guards, mangled string literals, swapped operators — and measured how many our
suite detects. This document reports the hardening pass that took the library from a **73.59%**
mutation score to **99.10%**, the five configuration corrections that made the run trustworthy,
and an honest accounting of every mutant that remains. Later passes
([Where the score stands since](#where-the-score-stands-since)) closed the rest and have held it
there as the library grew: the most recent cold run — **2026-08-15**, 5 333 valid mutants — is
**100.00%**, with no surviving mutants and none without coverage. All numbers below come from the
recorded Stryker runs; nothing is estimated.

---

## Results: Before → After

The pass ran in three recorded snapshots:

- **Initial** — first end-to-end run, `ignoreStatic: true`.
- **Re-baseline** — after correcting the configuration (most importantly `ignoreStatic: false`,
  see [Setup corrections](#setup-corrections-discovered-during-execution)). This is the honest
  starting line for the test-writing work.
- **Final** — after writing tests for every coverable gap and documenting every equivalent mutant.

> **Note on `crypto/` and `guards/`.** These two security-critical areas were brought to 100% in a
> hand-authored pass _just before_ the re-baseline snapshot, so their re-baseline column already
> reads ~100%. Their scores under the original run were lower — for example `totp.ts` 90.68%,
> `assert-token-type.ts` 59.38%, and the guards in the 86–95% band. The re-baseline column reflects
> that head start; it is not where those files began.

### Overall and per-directory

| Area          | Initial (`ignoreStatic:true`) | Re-baseline (config fixed) |      Final |
| ------------- | ----------------------------: | -------------------------: | ---------: |
| **All files** |                    **73.59%** |                 **74.45%** | **99.10%** |
| client        |                        70.27% |                     70.59% |     97.47% |
| nextjs        |                        70.14% |                     70.20% |     98.49% |
| react         |                        65.22% |                     65.71% |     93.65% |
| server        |                        75.75% |                     76.99% |     99.68% |
| shared        |                        80.00% |                     86.67% |    100.00% |

#### server sub-areas

| Sub-area    | Initial | Re-baseline |   Final |
| ----------- | ------: | ----------: | ------: |
| crypto      |  92.64% |     100.00% | 100.00% |
| guards      |  86.16% |      98.09% | 100.00% |
| services    |  67.73% |      67.43% |  99.45% |
| oauth       |  91.23% |      91.45% |  99.12% |
| config      |  77.39% |      77.14% | 100.00% |
| controllers |  96.97% |      96.97% | 100.00% |
| decorators  | 100.00% |      83.33% | 100.00% |
| hooks       |  83.33% |      83.33% | 100.00% |
| errors      |  10.53% |      13.16% | 100.00% |

#### nextjs / shared sub-areas

| Sub-area           | Initial | Re-baseline |   Final |
| ------------------ | ------: | ----------: | ------: |
| helpers            |  77.12% |      76.94% |  97.84% |
| internal           |  67.67% |      68.18% |  98.52% |
| utils (server)     |  93.10% |      85.11% | 100.00% |
| constants (shared) |  78.57% |      85.71% | 100.00% |

### Per-file breakdown (largest gains)

These are the files that moved the most. Several began in single or low double digits.

| File                                       | Initial | Re-baseline |   Final |
| ------------------------------------------ | ------: | ----------: | ------: |
| `errors/auth-error-codes.ts`               |   0.00% |       2.94% | 100.00% |
| `decorators/skip-mfa.decorator.ts`         |       — |       0.00% | 100.00% |
| `internal/tokenState.ts`                   |  14.29% |      14.29% | 100.00% |
| `nextjs/createLogoutHandler.ts`            |  41.86% |      42.22% | 100.00% |
| `services/token-manager.service.ts`        |  46.79% |      46.36% | 100.00% |
| `services/otp.service.ts`                  |  50.00% |      50.00% | 100.00% |
| `nextjs/createSilentRefreshHandler.ts`     |  53.23% |      53.97% | 100.00% |
| `nextjs/helpers/jwt.ts`                    |  55.96% |      55.96% |  91.36% |
| `services/password.service.ts`             |  56.52% |      56.52% | 100.00% |
| `guards/utils/assert-token-type.ts`        |  59.38% |     100.00% | 100.00% |
| `internal/routeClassifier.ts`              |  59.77% |      59.77% |  97.26% |
| `client/createAuthClient.ts`               |  64.29% |      64.29% |  97.47% |
| `react/AuthProvider.tsx`                   |  62.50% |      63.08% |  93.10% |
| `services/auth.service.ts`                 |  65.89% |      65.89% | 100.00% |
| `services/mfa.service.ts`                  |  66.94% |      66.94% |  99.19% |
| `server/utils/sleep.ts`                    |  66.67% |      66.67% | 100.00% |
| `nextjs/createClientRefreshHandler.ts`     |  68.57% |      68.57% | 100.00% |
| `services/session.service.ts`              |  71.07% |      69.95% |  98.91% |
| `services/token-delivery.service.ts`       |  71.25% |      71.43% | 100.00% |
| `services/password-reset.service.ts`       |  72.07% |      71.43% |  99.09% |
| `internal/proxyUtils.ts`                   |  72.73% |      72.73% | 100.00% |
| `internal/proxyHandlers.ts`                |  73.96% |      73.96% |  98.89% |
| `nextjs/helpers/dedupeSetCookieHeaders.ts` |  76.92% |      76.92% |  99.42% |
| `client/createAuthFetch.ts`                |  77.01% |      77.53% |  97.47% |
| `config/resolved-options.ts`               |  77.39% |      77.14% | 100.00% |
| `server/bymax-auth.module.ts`              |  79.29% |      79.29% | 100.00% |
| `oauth/oauth.service.ts`                   |  80.00% |      80.00% |  97.83% |
| `services/invitation.service.ts`           |  81.97% |      81.97% |  98.25% |
| `services/platform-auth.service.ts`        |  82.35% |      82.35% | 100.00% |
| `crypto/totp.ts`                           |  90.68% |     100.00% | 100.00% |
| `crypto/aes-gcm.ts`                        |  96.77% |     100.00% | 100.00% |

Files already at 100% before this pass — `auth-redis.service.ts`, the controllers
(`auth.controller.ts` after a final +7.14%, `session.controller.ts`, `mfa.controller.ts`,
`oauth.controller.ts`, …), `useAuth.ts`, `useAuthStatus.ts`, `useSession.ts`,
`secure-token.ts`, `mask-email.ts`, `shared/routes.ts` and others — held at 100%.

---

## Headline metrics

> **Mutation score: 73.59% → 99.10%.**
> **Line coverage: 100%, maintained throughout.**
>
> - **1980 tests** total across the unit and e2e suites.
> - The unit suite grew from **1506 → 1922 tests** — roughly **415 tests added** in this pass.
> - **Final mutant accounting:** 2856 killed + 20 timed-out = **2876 detected** out of **2902
>   valid mutants** (10 survived + 16 with no coverage). A further **1534 mutants were discarded
>   as compile errors** by the TypeScript checker before any test ran.

The detected/valid ratio (2876 / 2902) is the 99.10% figure. Timeouts count as detected: a mutant
that sends the code into a non-terminating loop is a fault the suite catches by other means.

---

## Toolchain and configuration

The mutation toolchain is entirely **dev-only and has zero impact on the published package**. None
of it appears in `dependencies`, in any subpath's `peerDependencies`, or in the build output.

| Component         | Version / setting                     |
| ----------------- | ------------------------------------- |
| Stryker core      | 9.6.1                                 |
| Test runner       | `@stryker-mutator/jest-runner`        |
| Type filter       | `@stryker-mutator/typescript-checker` |
| Runtime           | Node 24                               |
| Test transform    | ts-jest                               |
| Coverage analysis | `perTest`                             |

`coverageAnalysis: "perTest"` lets Stryker run only the tests that actually cover a given mutant,
which is what makes a run of this size finish in minutes rather than hours. The TypeScript checker
type-checks each mutant first and **discards the ~1530 that do not compile** (for example, a mutant
that changes a value to a type the signature rejects), so test time is never spent on faults the
compiler would already reject in review.

Mutation runs against a dedicated `jest.stryker.config.ts` rather than the default Jest config.
Scoped runs (a single file or directory) use Stryker's `--mutate` flag, e.g.
`--mutate "src/server/services/session.service.ts"`.

---

## Setup corrections discovered during execution

Getting a _trustworthy_ run — one whose survivors are real — required five corrections. The first
four make Stryker work correctly under this repo's toolchain; the fifth changed the results
materially.

1. **Explicit `plugins` array.** pnpm installs into a symlinked `node_modules`, which defeats
   Stryker's plugin auto-discovery. The jest-runner and typescript-checker plugins are therefore
   listed explicitly in the config so they are always loaded.

2. **Dedicated `jest.stryker.config.ts`.** This wraps the base Jest config with Stryker's
   instrumented test environment so `perTest` coverage is collected, while keeping `pnpm test`
   completely independent of the mutation toolchain. Day-to-day testing does not pull in Stryker.

3. **Transparent jsdom for React specs.** The four React specs declare `@jest-environment jsdom`
   via docblock. Those docblocks were switched to Stryker's transparent jsdom wrapper so the
   browser-like environment survives instrumentation.

4. **Node 24 at runtime.** The run is pinned to Node 24 to match the library's supported runtime.

5. **`ignoreStatic: false` — the key finding.** Under `perTest` coverage, `ignoreStatic: true`
   causes mutants on module-level `const` initializers to **falsely survive**. A const such as the
   UUID-v4 validation regex is evaluated **once at import time**, before any test runs and toggles
   the mutant — so the mutated value is never the one under test, and Stryker records a survivor
   that no test could ever kill. Flipping this setting to `false` exposed those mutants to the
   tests that genuinely exercise them. The clearest single example:
   `assert-token-type.ts` went from **59% → 100%** on this change alone, with no new tests.

---

## Methodology

Every surviving mutant is triaged into one of two outcomes:

- **GAP** — the suite _should_ have caught it. We write a test that fails under the mutation and
  passes against the original, then confirm the mutant is killed.
- **EQUIVALENT** — the mutation produces behavior that is genuinely indistinguishable from the
  original (no input can tell them apart). These cannot be killed by definition. Each is documented
  inline with a directive and a reason:

  ```ts
  // Stryker disable next-line <Mutator>: <why this mutation is behaviorally equivalent>
  ```

The bulk test-writing was **parallelized across 10 specialized sub-agents**, partitioned by area
(services, client, nextjs helpers, nextjs internal, nextjs route handlers, react, config + module,
and misc + oauth). Each sub-agent wrote tests only. **Equivalence decisions were owned centrally**
and every one was verified by re-running Stryker — an equivalence claim is only accepted if the
mutant still survives a suite that otherwise kills its neighbors.

### A concrete gotcha that was caught

Jest's `toHaveBeenCalledWith` **ignores trailing `undefined` items in an array argument**, so
`[undefined, undefined]` matches `[]`. NestJS metadata reads look like:

```ts
reflector.getAllAndOverride(IS_PUBLIC_KEY, [context.getHandler(), context.getClass()])
```

A naive assertion on that second argument passed even when a mutant **emptied the target array** —
the two `undefined`s from unmocked `getHandler()`/`getClass()` collapsed to `[]` and matched. We
replaced the assertions with **defined sentinel mocks** so an emptied array is now a detectable,
killable difference.

---

## Why this matters: security-relevant gaps now pinned

This is an authentication library. Several mutants that initially survived correspond to
faults that would weaken a real security property. Each now has a dedicated test pinning it.

- **Refresh-token cookie `httpOnly: true`.** Previously untested. A mutant flipping it to `false`
  survived — meaning nothing stopped the refresh token from becoming readable by JavaScript, an
  XSS-exfiltration risk. Now asserted.
- **Session-hash format guard.** The `^...$` anchors on the session-hash regex must reject a
  malformed hash _before_ any Redis key is constructed from it. Pinned by asserting that Redis is
  **never called** when the hash fails the format check.
- **TOTP code zero-padding.** `padStart(6, '0')` ensures a code with a leading zero is compared as
  six digits. Without it, a legitimate 5-digit-looking code would fail verification roughly 10% of
  the time. Now pinned.
- **Bare-CR detection in Set-Cookie de-duplication.** Part of the HTTP response-splitting defense;
  a mutant relaxing the bare-`\r` check now fails a test.
- **`@Public` / `@Roles` / `@SkipMfa` metadata targets.** The decorator metadata-target arrays must
  be non-empty; an emptied target array would **silently disable the decorator** (see the Jest
  gotcha above). Now caught by sentinel-mock assertions.

The **constant-time TOTP comparison window and the HMAC paths are fully killed** — `crypto/` and
`guards/` both stand at **100%**.

---

## The documented equivalent mutants

92 mutants are documented as equivalent. They fall into a few recurring categories:

- **Defensive guards masked by a downstream check.** A `catch {}` whose effect is identical because
  a later `=== null` guard produces the same result either way. Removing the inner guard changes
  nothing observable.
- **Mutually redundant guards.** `value.length === 64 && /^[0-9a-f]{64}$/.test(value)` — each
  conjunct _independently_ forces "exactly 64 hex characters", so deleting either still rejects the
  same set of inputs.
- **Symmetric operations.** The TOTP verification window enumerates `currentStep ± delta`; mutating
  the sign of `delta` enumerates the same set of steps, so verification behaves identically.
- **Referentially stable React dependency arrays.** `useEffect` / `useMemo` dependency lists whose
  members never change identity across renders — reordering or trimming them yields the same render
  behavior.
- **Cosmetic strings.** Portuguese end-user error messages and internal log labels. Consumers branch
  on **error codes**, never on message text, so mutating a string is unobservable to any caller.

---

## Honesty: why the report still shows 10 survivors

The final report lists **10 survivors**, and they are all in the _equivalent_ set above — but they
appear as "survived" rather than "ignored" because of a Stryker limitation:

> Stryker's `// Stryker disable next-line` directive does **not** attach when the comment is the
> **trailing comment of a block body** — i.e. immediately before `}, [dep])`, before `} catch {`,
> or inside a multi-line `if (` condition. The directive has no statement to bind to on the next
> line, so Stryker reports the mutant normally.

These 10 are documented inline regardless of the directive not binding. This is the entire reason
the **`react` directory reads 93.65%** instead of ~100%.

| Where                  | Count | Mutator               | Nature                                      |
| ---------------------- | ----: | --------------------- | ------------------------------------------- |
| `AuthProvider.tsx`     |     4 | ArrayDeclaration      | Referentially-stable hook dependency arrays |
| (catch blocks)         |     5 | BlockStatement        | Defensive `catch {}` masked downstream      |
| (multi-line condition) |     1 | ConditionalExpression | Redundant clause in a multi-line `if (`     |

By final report location, the 10 are: `react/AuthProvider.tsx` (4), `server/services` (4 —
`session.service.ts` ×2, `invitation.service.ts` ×1, `password-reset.service.ts` ×1),
`server/oauth/oauth.service.ts` (1), and `client/createAuthFetch.ts` (1). The remaining 16
no-coverage mutants are concentrated in `nextjs/helpers/jwt.ts` (7) and a scattering of
compile-adjacent branches; the 20 timeouts are dominated by `nextjs/helpers/dedupeSetCookieHeaders.ts`
(7) and the `nextjs` helpers, where a mutation drives a loop non-terminating — itself a form of detection.

---

## Where the score stands since

The 99.10% above is the snapshot at the end of that hardening pass. The number moves as the
library grows: new code arrives with survivors, and each subsequent pass drives them out. Every
figure here is from a recorded run; none is estimated.

| Date       | Score       | Killed | Survived | No coverage | Timeout | What moved it                                                                                                                                                            |
| ---------- | ----------- | -----: | -------: | ----------: | ------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 2026-07-26 | 98.37%      |  3 419 |       41 |          16 |      16 | Parity hardening + five security items, then a pass over the new code's survivors                                                                                        |
| 2026-07-27 | **100.00%** |  3 446 |    **0** |       **0** |      16 | Closed every remaining survivor: 57 mutants across 19 files                                                                                                              |
| 2026-07-28 | 99.97%      |  3 478 |        1 |           0 |      16 | The audit's parity work landed; its one survivor is the anchor below                                                                                                     |
| 2026-07-28 | **100.00%** |  3 474 |    **0** |       **0** |      16 | That survivor recorded as an equivalent, after checking it against 211k inputs                                                                                           |
| 2026-08-08 | **100.00%** |  4 849 |    **0** |       **0** |      21 | Re-measured cold with the 1.3.1 additions folded in (revocation service, default email provider, tenant on the port)                                                     |
| 2026-08-12 | **100.00%** |  4 968 |    **0** |       **0** |      21 | Re-measured cold for the 1.4.1 wire-status alignment: the status derives from the code, and both catalog lookups became `Map`s with an explicit fallback                 |
| 2026-08-14 | **100.00%** |  5 252 |    **0** |       **0** |      22 | Re-measured cold for the 1.4.3 surface (OpenAPI contributor, WS filter, code-driven 401): 28 survivors closed, all of them assertions too loose to see their own subject |
| 2026-08-15 | **100.00%** |  5 311 |    **0** |       **0** |      22 | The tree tagged as 1.4.3: the session route move, the two completeness gates, and the contributed `logout` description                                                   |

The 2026-07-28 pair is one day's work read twice: the cross-implementation parity fixes landed
with a single survivor of their own, and the second row is that survivor recorded rather than
killed. It is the `^` in the pattern that strips the leading amount from a duration string
(`jwt.accessExpiresIn`), and it is equivalent under the `amount > 0` guard that follows: a value
that reaches the unit lookup with a usable amount has its numeric run at index 0, so an unanchored
search finds the same match, and one whose numeric run starts later fails `Number.parseFloat` and
is rejected on the amount, never on the unit. That was checked against 211 000 generated inputs
rather than argued — anchored and unanchored agree on every one — before the disable was written.
The killed count drops by four between the rows because the block-form disable takes the mutator's
whole region, which is why the region is one declaration long.

The gate is the `break` threshold of **100**, not the peak: a run fails below it. It was 95
until the score had held at 100 across three cold runs; locking it there makes a single new
survivor a red run rather than a number nobody reads. The 2026-07-26
figure was new surface area — the trusted-origin guard, the rate limiter, the breach checker, the
family-lineage rotation — arriving with its own gaps, not a regression in what was already
covered; the pass the day after closed all of them.

### What the last 57 were

Not one was a bug in the library. Every one was a test that could not see its own subject, and
the fix was almost always to move the assertion to where the behaviour actually shows:

- **Guards asserted from one side only.** A redirect URL was rejected as an empty string but
  never as a non-string, so the `typeof` half was free to disappear — and a number is exactly
  what arrives from env parsing. The MFA platform-misconfiguration guards were asserted by
  "throws something", which any downstream failure satisfies.
- **Fallbacks nothing could reach.** The OAuth error-code extractor's four fallbacks are only
  observable through a malformed exception envelope, including the `null` and callable shapes
  that separate its type check from its null check.
- **Values written and read through the same symbol.** The rate-limit metadata key round-tripped
  perfectly under any value, because the guard read it through the same constant a test wrote it
  with; it is pinned to its literal now, and read back by name the way a consumer would.
- **`catch` bodies whose throw is reached again a line later.** Four of them. Emptying the body
  changed nothing observable, so each now logs what only it knows: a stored record that exists
  but does not parse is _corrupted storage_, not an expired token, and a session-detail read that
  throws is an _infrastructure fault_, not a stale index member. The caller cannot tell those
  apart by design — the log line is the only place they differ.

### Equivalent mutants, and a directive that does not always bind

Sixteen timeouts remain (a mutation that makes a loop non-terminating is caught by other means),
and the equivalents carry an inline `// Stryker disable` with the reason each cannot be killed.
Two of those directives were **silently inert** before this pass, which is worth knowing:

- `// Stryker disable next-line` binds to the line immediately after it. When the mutant shares
  its line with a callback's closing brace (`}, [])`) or sits below a comment that wrapped onto a
  second line, the directive points somewhere else and the mutant is reported as surviving.
- The block form (`// Stryker disable X` … `// Stryker restore X`) binds in both cases and is
  what `AuthProvider.tsx` and `createAuthClient.ts` use now.

If a mutant you documented keeps showing up as a survivor, check that the directive lands on the
line you think it does — it fails quietly, in the direction of reporting more work, not less.

### Re-measured cold — 2026-08-15

The tree that ships as `1.4.3`, measured after the last merge rather than before it. Run cold with
the incremental baseline deleted, in **37 minutes 49 seconds**, over **154 instrumented files with
8 394 mutants**.

| Outcome                          |   Mutants |
| -------------------------------- | --------: |
| Killed                           |     5 311 |
| Timed out (counts as detected)   |        22 |
| **Survived**                     |     **0** |
| **No coverage**                  |     **0** |
| Discarded — compile error        |     2 686 |
| Discarded — runtime error        |         8 |
| Ignored — documented equivalents |       367 |
| **Instrumented, total**          | **8 394** |

**5 333 detected out of 5 333 valid mutants — 100.00%,** behind the unit suite alone: 3 721 tests
across 128 files. The 250 end-to-end tests run under a separate config and no mutant is ever
exposed to them.

**Why this row exists when CI had already run the gate.** The post-merge job on `main` reported
100.00% for the same commit in 3 minutes 56 seconds — because it is **incremental**, reusing
verdicts from a stored baseline. That is the right trade for a per-merge gate and the wrong one
for a number printed in a released README: this release cycle produced a first-hand demonstration
of an incremental report being wrong, listing 46 survivors of which 18 were already dead, killed
by tests the baseline predated. The dangerous direction is the mirror image — a cached `Killed`
verdict for code that changed in a way the invalidation missed — and no amount of reading the
report distinguishes the two. So the published figure comes from a cold run, and both are recorded
rather than blended: **incremental 5 311 killed in 3m56s, cold 5 311 killed in 37m49s**. They
agree here, which is evidence about this tree and not a guarantee about the next one.

### Re-measured cold — 2026-08-14

The `1.4.3` release surface: the runtime OpenAPI contributor, `WsAuthExceptionFilter`, the
handshake-less refusal in `WsJwtGuard`, and the code-driven 401 classification in
`createAuthFetch`. Run cold with the incremental baseline deleted, in **32 minutes 33 seconds**,
over **154 instrumented files with 8 324 mutants**.

| Outcome                          |   Mutants |
| -------------------------------- | --------: |
| Killed                           |     5 252 |
| Timed out (counts as detected)   |        22 |
| **Survived**                     |     **0** |
| **No coverage**                  |     **0** |
| Discarded — compile error        |     2 675 |
| Discarded — runtime error        |         8 |
| Ignored — documented equivalents |       367 |
| **Instrumented, total**          | **8 324** |

**5 274 detected out of 5 274 valid mutants — 100.00%,** behind the **unit suite only: 3 703 tests
across 127 files** at the moment the run started (3 707 now — four tests added in review of the
work this row measures, none of which touches `src/`). The 248 end-to-end tests run under a separate config and no mutant is ever
exposed to them.

**The incremental run that preceded this one said 99.13%, and it was wrong in both directions.**
It reported 46 survivors; the first one checked was already dead — reproducing the mutant by hand
failed the existing test — while the real count in those files was 28. An incremental baseline is
a cache keyed on a diff, and after a branch of new code and new tests, part of it describes a tree
that no longer exists. The working loop is a **scoped cold run** — `--mutate` with a
comma-separated list plus `--incrementalFile` pointing at a throwaway path — which measures four
files in under two minutes instead of thirty-two.

What the 28 were is the more useful record, because none of them was an untested behaviour:

- **25 in `auth-openapi-fragment.ts`**, all in a file with 100% line coverage, and all one shape:
  the fragment's own literals were never asserted. `expect.objectContaining({ type, in, name })`
  on a security scheme leaves `description`, `bearerFormat` and every field it does not name free
  to become `""` — in an object that is copied verbatim into a consumer's published document and
  read literally by a client generator. They are pinned whole with `toEqual` now, the 38-entry
  operations table is asserted handler by handler, and one test walks four registrations × three
  delivery modes asserting the invariant nest-core enforces at boot: no requirement names a scheme
  the fragment did not define. That invariant is what killed `registered.platform ||
registered.platformMfa` → `&&`, a mutant every fixture with both flags set passes.
- **5 in `ws-auth-exception.filter.ts`**, all redundant conjuncts. `typeof client === 'object' &&
client !== null && typeof client.emit === 'function'` cannot fail on its first operand for any
  input the second and third accept — so the operand was deleted rather than tested. What was left
  needed one real test: a client carrying `send` without `readyState` (and the reverse) must still
  be emitted to, which is the case that separates `&&` from `||`.
- **1 in `ws-jwt.guard.ts`** — the `handshake === null` arm, refused by a test and not by an
  argument, alongside the `undefined` one.
- **1 in `createAuthFetch.ts`**, the interesting one. A `catch` whose body returned the same
  answer the fall-through produced: genuinely equivalent, measured, and **impossible to suppress**
  — `// Stryker disable next-line` before `} catch {` binds to the last statement of the `try`,
  and the block form does not bind either. The fix was not a better-placed directive but deleting
  the construct: `clone.json().catch(() => undefined)` inside the `Promise.race` says the same
  thing with no `try/catch/finally` at all, so the mutant no longer exists. The file went to
  100.00% with one fewer suppression than it had before, and slightly less bundle.

The lesson under all four is one lesson: **line coverage says a literal was executed; only an
assertion that names it says it was published correctly.** A contract object — an OpenAPI
fragment, a wire envelope, anything crossing a package boundary — is asserted whole or it is not
asserted.

### Re-measured cold — 2026-08-12

The `1.4.1` wire-status alignment: the HTTP status became a property of the error code rather than
a constructor argument, 34 throw sites lost their status argument, and both catalog lookups inside
`AuthException` became `Map`s with an explicit fallback. Run cold with the incremental baseline
deleted, in **35 minutes 39 seconds**, over **102 instrumented files with 7 886 mutants**.

| Outcome                          |   Mutants |
| -------------------------------- | --------: |
| Killed                           |     4 968 |
| Timed out (counts as detected)   |        21 |
| **Survived**                     |     **0** |
| **No coverage**                  |     **0** |
| Discarded — compile error        |     2 530 |
| Discarded — runtime error        |         8 |
| Ignored — documented equivalents |       359 |
| **Instrumented, total**          | **7 886** |

**4 989 detected out of 4 989 valid mutants — 100.00%.** The suite behind it is the **unit suite
only — 3 483 tests across 119 files** at the moment the run started. Stryker is pointed at
`jest.stryker.config.ts`, which wraps `jest.config.ts`; the 127 end-to-end tests run under a
separate config and **no mutant is ever exposed to them**. That is worth stating rather than
folding the two counts together, because it is exactly what let the drift this release fixes
survive: the e2e assertions that exercised the wrong statuses were outside the gate that would
have noticed they were too weak to see it. A weak assertion is only as dangerous as the gates that
do not cover it.

(One test was added after this run started — the count is 3 484 now. It pins the contract's
internal-only list and asserts nothing about `src/`, so it cannot change the score.)

Two of the mutants are worth naming, because the change that introduced them is the reason this
row exists. `STATUS_BY_CODE.get(code) ?? HttpStatus.INTERNAL_SERVER_ERROR` puts a fallback on a
path no catalog code reaches, so nothing in ordinary use covers it; it is killed by tests that
pass a cast non-catalog code and an inherited `Object` member (`constructor`, `toString`,
`__proto__`, `hasOwnProperty`). Before the `Map`, indexing the object literal resolved those from
the prototype chain and handed a **function** to `HttpException` as the status. The fallback is
not defensive dressing — it is the branch that makes the lookup total, and the mutation gate is
what forces it to carry a test rather than an assumption.

### Re-measured cold — 2026-08-08

The 2026-07-28 row was the last recorded measurement, and four releases landed on top of it
(1.1.0, 1.1.1, 1.2.0, 1.3.0) including the third security audit. This run re-measures from cold —
`pnpm mutation:full --concurrency 2` under Node 24, with the incremental baseline deleted first, so
no verdict is inherited from an earlier run. It took **27 minutes 6 seconds** and instrumented
**147 of 746 source files with 7 718 mutants**.

| Outcome                          |   Mutants |
| -------------------------------- | --------: |
| Killed                           |     4 849 |
| Timed out (counts as detected)   |        21 |
| **Survived**                     |     **0** |
| **No coverage**                  |     **0** |
| Discarded — compile error        |     2 490 |
| Discarded — runtime error        |         8 |
| Ignored — documented equivalents |       350 |
| **Instrumented, total**          | **7 718** |

The score is the detected-over-valid ratio: **4 870 detected out of 4 870 valid mutants —
100.00%**. The 2 498 discarded are faults the TypeScript checker rejected before any test ran, and
the 350 ignored are the documented equivalents, which never enter the denominator. All five
subpaths are individually at 100.00%:

| Subpath | Killed | Timed out |
| ------- | -----: | --------: |
| server  |  3 766 |         9 |
| nextjs  |    843 |        11 |
| client  |    163 |         0 |
| react   |     60 |         0 |
| shared  |     17 |         1 |

The suite behind it is **3 547 tests** — 3 420 unit across 118 files, plus 127 end-to-end across a
further 17. That is 1 089 more than the 2 458 the 2026-07-28 run was measured against, and the
mutant population grew with it: 4 870 valid mutants against the 3 474 killed then.

Twenty-one timeouts, up from sixteen, and in the same places: `nextjs/helpers/dedupeSetCookieHeaders.ts`
(7), `crypto/totp.ts` (3), `providers/common-password-checker.provider.ts` (3),
`services/mfa.service.ts` (2), `nextjs/helpers/jwt.ts` (2), and one each in `configValidation.ts`,
`routeClassifier.ts`, `invitation.service.ts` and `shared/constants/routes.ts`. A mutation that
drives one of those loops non-terminating is a fault the suite detects by other means.

Two things are worth recording rather than leaving implicit. The **350 ignored mutants sit under
217 directives** (211 per-line, 6 block-form) — that is no longer "a handful", and the count is
reported here so a future pass can audit whether each is still genuinely unkillable rather than
trusting the label. And the **run no longer takes ten minutes**: at `--concurrency 2` on a 14-core
machine it is three quarters of an hour, so the figure in [How to reproduce](#how-to-reproduce)
below is the measured one, not the one from when the suite was half this size.

---

## How to reproduce

```bash
# Cold run — deletes the incremental baseline first, so nothing is inherited.
# This is the one that measures the truth: ~48 minutes at --concurrency 2, Node 24.
pnpm mutation:full --concurrency 2

# Incremental run — reuses reports/stryker-incremental.json, re-testing only what changed
pnpm mutation

# Sandbox smoke test — no mutants, just proves the config still boots
pnpm mutation:dry-run
```

- **Override the concurrency on the command line.** `stryker.config.json` asks for 4, which with
  the TypeScript checker means four runners plus four checkers, and every worker reloads the whole
  module graph. On a 36 GB machine that is enough to push into swap if anything else is running.
  `--concurrency 2` costs wall-clock and buys headroom; the run above never moved swap off its
  baseline.
- The HTML report is written to **`reports/mutation/mutation.html`**.
- The `break` threshold is **100** (default 80, raised to 95 during this pass and to 100 once the
  score had held) so the result is locked in: any change that leaves a single new survivor fails
  the run.
- The full execution plan, including the per-area task breakdown, lives in
  [`docs/mutation_testing_plan.md`](./mutation_testing_plan.md).
