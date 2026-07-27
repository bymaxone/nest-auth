# Mutation Testing

`@bymax-one/nest-auth` is verified with mutation testing using [Stryker](https://stryker-mutator.io/).
Line coverage proves a line _executed_ during a test; mutation testing proves a test _would
fail_ if that line were wrong. We seeded thousands of small faults into the source — flipped
booleans, removed guards, mangled string literals, swapped operators — and measured how many our
suite detects. This document reports the hardening pass that took the library from a **73.59%**
mutation score to **99.10%**, the five configuration corrections that made the run trustworthy,
and an honest accounting of every mutant that remains. A later pass
([Where the score stands since](#where-the-score-stands-since)) closed the rest: the current run
is **100.00%**, with no surviving mutants and none without coverage. All numbers below come from the recorded
Stryker runs; nothing is estimated.

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

| Date       | Score       | Killed | Survived | No coverage | Timeout | What moved it                                                                     |
| ---------- | ----------- | -----: | -------: | ----------: | ------: | --------------------------------------------------------------------------------- |
| 2026-07-26 | 98.37%      |  3 419 |       41 |          16 |      16 | Parity hardening + five security items, then a pass over the new code's survivors |
| 2026-07-27 | **100.00%** |  3 458 |    **0** |       **0** |      16 | Closed every remaining survivor: 57 mutants across 19 files                       |

The gate is the `break` threshold of **95**, not the peak: a run fails below it. The 2026-07-26
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

---

## How to reproduce

```bash
# Full run — about 10 minutes on a multi-core machine, Node 24
pnpm mutation

# Incremental run — only re-tests what changed since the last run
pnpm mutation:incremental
```

- The HTML report is written to **`reports/mutation/mutation.html`**.
- The `break` threshold is **95** (raised from the default 80) so the result is locked in: any
  future change that drops the score below 95% fails the run.
- The full execution plan, including the per-area task breakdown, lives in
  [`docs/mutation_testing_plan.md`](./mutation_testing_plan.md).
