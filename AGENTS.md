# @bymax-one/nest-auth — Agent Specification

`@bymax-one/nest-auth` is a **published npm library**, not an application: full-stack authentication
for NestJS, React and Next.js, with zero direct dependencies and all crypto through `node:crypto`.
Everything merged here reaches consumers as a versioned package, so a breaking change is one they
read about in the changelog rather than one they discover.

> **Prerequisite:** Read [CLAUDE.md](./CLAUDE.md) first for critical rules. This file extends it with architecture and patterns — load on demand, not every session.

---

## Code Review Rules

## Scope of this file

Only rules that change a review's outcome. Codex loads this on every turn before reading the diff,
so anything that changes no finding is paid for on every review and used on none.
`src/server/`-scoped rules are in [`src/server/AGENTS.md`](./src/server/AGENTS.md), loaded
automatically when the diff is there. Narrative is in
[`docs/repository-guide.md`](./docs/repository-guide.md) and is **not** loaded — Codex does not
follow links, so nothing normative may live behind one.

<!-- shared:begin -->
<!--
  CANONICAL COPY: bymaxone/.github → agents/code-review-rules.md
  Do not edit this block in a consuming repository. It is replaced wholesale by
  the `agents-sync` reusable workflow, so a local edit is reverted on the next
  run. Change it here, cut a release, and every repository is offered the update.

  Repository-specific rules go OUTSIDE this block, below the closing marker.

  FOR WHOEVER EDITS THIS FILE, not for the reviewer who reads it:

  Codex reads one AGENTS.md per directory, root to nested, within
  project_doc_max_bytes (32 KiB default). Never name a template or fixture
  AGENTS.md below the root: a change under it is read as the repo's guidance.

  This block is charged against every consumer's budget. A rule added here must
  be worth the bytes in the smallest-headroom repository, not only in this one;
  agents-sync reports each consumer's headroom and fails when it is exceeded.

  When you scope a rule, scope every rule in its paragraph or split the
  paragraph -- an unscoped neighbour reads as deliberate.
-->

These rules hold in every Bymax repository. What is specific to this one is written after this
block, and the two are read together.

The pipeline already enforces formatting, linting, dependency policy, coverage and — where the
repository has one — the mutation gate. Do not spend a review on a **violation** of one of those: it
is a red check, not a comment. What follows is what CI cannot see.

A violation of a rule in this block is reported at **P1** at minimum. Codex surfaces only P0 and P1
on a pull request, so a rule whose violations land at P2 is a rule nobody sees.

**When a rule moves from here into a check, it leaves here.** A red check is proportionate to a
correctness failure that is invisible without it, and disproportionate to style enforced at an
inconvenient moment. Never carry both: a rule stated here _and_ enforced by CI spends a reviewer's
attention on what a gate already reports.

**A change to the enforcing configuration is the opposite case, and it is in scope.** Every gate runs
the configuration from the branch under review — that branch's lint config, its coverage thresholds,
its mutation thresholds. So a pull request that deletes a rule, lowers a threshold or widens an
ignore glob turns the check **green**, because a gate reports on the rules it was handed. For those
diffs the review is the only independent check there is, and a weakened gate needs the same
justification a suppression does.

### A finding names what it read

Every factual claim in a review — about a library's API, about this repository's history, about what
a file contains — has to come from something read in the tree under review, and the finding should
say which. A claim assembled from recollection is likely to describe a previous version of whatever
it is about.

**Safe path**, by the kind of claim:

| Claim about                             | Read this                                                                      |
| --------------------------------------- | ------------------------------------------------------------------------------ |
| A library's API **shape**               | `node_modules/<pkg>/dist/**/*.d.ts` in this tree                               |
| A library's **runtime behaviour**       | that version's changelog entry, its documentation, or a test that exercises it |
| A commit's author or committer identity | out of scope: it is not text a change introduces                               |
| What a file contains                    | the file at the revision under review, not an earlier one                      |

The first two rows are separate on purpose, and the rule below says why: a field can stay optional
in the published type while becoming mandatory in behaviour. A `.d.ts` settles what a signature
accepts and nothing about what the implementation does with it, so a behavioural claim resting on
one is unfounded.

Weight the checking by what acting on the finding would cost. A comment that asks for a reworded
sentence is cheap to be wrong about; one that asks for history to be rewritten, a merge reverted, or
a release pulled is not — verify that class before raising it, and raise it at the severity the
evidence supports rather than the severity the consequence would deserve if true.

### A dependency upgrade migrates every call site, not only the ones that fail to compile

When an upgrade tightens a contract, the compiler catches only the call sites whose **shape**
changed. A field that stays optional in the published type while becoming mandatory in behaviour
compiles, passes the unit suite, and fails in production.

A `@bymax-one/*` version number carries **no compatibility information** while the libraries are
pre-stable: breaking changes ship in minor and patch releases by explicit policy, so `^` and `~`
protect against nothing. The migration note under **Apply to a derived backend** in the library's own
changelog is the compatibility contract.

**Safe path:** read **every** changelog entry from the version being replaced up to the proposed
one, not only the proposed one's, and check every call site they name — not only the ones the
compiler rejected. Upgrades routinely skip releases, and the entry that matters is often not the
last one: adopting `@bymax-one/nest-cache` 1.1.0 → 1.2.1 skipped 1.2.0, where a namespace-validation
security fix lives; 1.2.1's own entry is a field rename. Diff the `.d.ts` of the **previously adopted** version against
the **proposed** one — `npm pack` both, and name the two versions. Reaching for "the installed
declarations" is the trap: in a checkout of the branch under review the installed tree is already
the new version, so that diff compares a release with itself and shows nothing.

### Settled decisions are not review findings

Both are settled deliberately, and reopening either costs a round trip and changes nothing:

- **Do not propose a major version bump** for a breaking change in a `@bymax-one/*` library, and do
  not assert that this ecosystem follows strict SemVer. Until an API is declared stable, breaking
  changes ship in minor and patch releases; the migration note carries the compatibility information
  the number does not. If a document claims strict SemVer, the finding is that the claim is wrong —
  not that the version should be raised.
- **Do not propose pinning `bymaxone/.github` reusable workflows to a commit SHA.** They are
  referenced by the `@v1` alias on purpose: a fix has to land once and reach every repository, the
  tag is immutable and the alias moves only on a release, and pinning was measured to cost ~58
  dependency pull requests to propagate one change. Third-party actions are the opposite case and
  **are** pinned by SHA.

**Safe path:** if you believe a settled decision is now wrong, say so as a question in the pull
request rather than as a finding.

### Suppressions are refusals, not exceptions

`@ts-ignore`, `@ts-expect-error`, `@ts-nocheck`, `eslint-disable` in any form,
`as unknown as` laundering a real type error, `istanbul ignore`, and in Rust `#[allow(...)]` over a
lint gate or `unsafe` without a `// SAFETY:` comment are blocking findings.

Anything a configured gate already reports belongs to the gate, not to a review: where a repository
lints `no-explicit-any` as an error — most do — an `as any` is a red check, and raising it here only
duplicates it. Check the repository's lint configuration before reporting a suppression rather than
assuming the list is exhaustive in either direction.

A failing gate means the code is wrong, the type is wrong, or the rule is wrong. **Safe path:** fix
whichever it is. Changing a rule's configuration with a stated reason is legitimate; scattering
per-call-site silencers is not.

### Comments state constraints, never history

A comment must read as true for whoever opens the file next. Flag any comment that narrates what a
previous version did, names a phase, task, ticket or review round, or explains a change rather than
the code. **Safe path:** state the constraint that still holds, and let `git log` carry the history.

Evidence for a constraint is not history, and how the evidence was obtained does not decide which it
is. The test is whether the fact still binds the next reader. A measurement that predicts what they
will hit if they take the other path — what the alternative did when it was tried, what the cost is
in numbers — belongs beside the constraint it supports, whether it came from a deliberate trial or
from something breaking. What ages is the part that cannot recur for them: what a previous version
of this code did, a version number, a registry state, a review round, a failure that has since been
fixed. Flag those; keep the measurement.

### Size and layering

Functions over **50 lines** and nesting deeper than four levels are findings **for what a change
introduces** — a new function, or a change that pushes an existing one past the limit — in the
repository's own source and test directories. A test-suite grouping construct (`describe`, `context`,
`mod tests`, a table of cases) is not a function; the unit under the limit is the body of a single
`it`/`test`/`#[test]`. On the same terms, every non-trivial source file a change introduces opens
with a header stating its purpose and its layer, and every exported symbol a change introduces
carries a doc comment.

**The 800-line file limit applies to what a change introduces, not to what it inherits.** A
repository that already carries a file past the line — a generator, a long end-to-end suite — would
otherwise produce a finding on every pull request touching three lines of it, which the author
cannot act on and did not cause. Raise it for a **new** file over the limit, or when a change pushes
a file past it or materially grows one already over.

Markdown, generated output and lockfiles are **out of scope**: a changelog is an append-only log that
only grows, a lockfile is generated, and neither has layers. Reporting their length is a false
positive on every dependency bump and every release note.

**Safe path:** extract by responsibility rather than by line count — the limit is a symptom, and one
file doing two jobs is the defect.

### Language and attribution

Everything published is English — source, comments, tests, commit messages, pull request titles and
bodies, `README.md`, `CHANGELOG.md` and everything under `.github/`.

Each repository states its language policy for `docs/` below this block. Report a language finding in
`docs/` only against what the repository states; where it states nothing, `docs/` is English like
everything else. A `docs/` language other than English is a repository-owner decision recorded in the
narrowings, not a convention a contributor may introduce.

No commit, pull request, comment or code may attribute authorship to an AI assistant or coding tool,
in any form. **Only text the change introduces is in scope** — a trailer, a "generated with" line, a
signature in a comment or a description.

A commit's author and committer fields are not that: they come from the contributor's git
configuration rather than from the diff, and a review reading the diff cannot see them. Never report
an identity field, and never present a command's reconstructed output as evidence for one. Measured:
eight P1 findings in a single day across four pull requests, each naming a commit SHA that does not
exist in the repository it was reported against and quoting `git log` output no review had run. What
each one asked for was a force-push rewriting published history.

<!-- shared:end -->

## Where this repository narrows a shared rule

<!--
  BYTE BUDGET. Codex reads this file per directory, root to changed file, and stops at
  `project_doc_max_bytes` — 32768 by default — counting the root file and any nested
  `AGENTS.md` together. Past that it truncates silently: no error, no warning, and the tail
  of this file simply stops being guidance.

  The shared block above is centrally managed and grows when the org adds a rule, so the
  headroom is not yours alone to spend. Check `wc -c AGENTS.md` before adding a section, and
  prefer `docs/guidelines/` for anything a reviewer does not need in the diff.

  A nested `AGENTS.md` is guidance for its directory, loaded automatically whenever Codex works
  there or below, and it costs nothing on any other path. That makes it the right home for a rule
  true only under one directory — and the reason a FIXTURE, TEMPLATE or consumer-facing example
  must never carry that name: under it, sample content becomes real guidance for every change in
  its directory and spends the cap of every chain that passes through. Add one deliberately or
  not at all, and measure the worst CHAIN — root plus the nested files on one path — never the
  sum of every such file, since siblings are never loaded together.
-->

Only the rules a reviewer of **this** repository gets wrong. Each one has cost something real here.

### A bare user id is a defect, not a simplification

`IUserRepository.findById` takes a tenant because **user ids are unique only within a tenant** — a
host that numbers users per tenant gives every tenant a user `1`. So any Redis key, index, cache,
counter or fan-out keyed on a bare id lets one tenant's action reach another's account. That is a
credential-free cross-tenant revocation, and removing it from the session index and the token epoch
is what 1.4.4 was.

The wrong version reads as the tidier one: a reviewer sees a composite key or a length-prefixed
subject and suggests collapsing it. Do not. The same rule holds outside the keyspace — a disconnect
that matches sockets by `userId` alone drops another tenant's user, and repeated logouts in one
tenant become a denial of service against another.

The dashboard and platform planes need separating for the same reason: their ids come from
different repositories and may collide.

### The OpenAPI security-scheme NAMES are stable; their definitions are not

`AUTH_SECURITY_SCHEMES` exports four names — `bymaxAuthAccessCookie`, `bymaxAuthAccessBearer`,
`bymaxAuthRefreshCookie`, `bymaxPlatformAccessBearer`. Renaming one is a break a generated client
feels, so treat a rename suggestion as a breaking change and not a tidy-up.

Their **definitions** are derived from resolved options and the registered controllers, which is why
the names are exported and the definitions are not. A scheme the options cannot satisfy is neither
defined nor referenced. Do not suggest hard-coding a definition or exporting one.

### `environment` is the only input that answers "is this production"

The library reads **no environment variable at runtime** — every `process.env` occurrence in `src/`
is inside a JSDoc example. Configuration arrives through `registerAsync`, and
`BymaxAuthModuleOptions.environment` is the single input deciding cookie `Secure`, OAuth redirect
enforcement and the production-gated validations. **An unset value resolves to `'production'`**,
which is deliberate: it fails safe rather than open.

So an absent `process.env['NODE_ENV']` read is the design, not a missing check. It replaced exactly
that test, which failed open on `NODE_ENV` unset, `staging`, `prod`, or `production ` with a
trailing space.

### `conformance/` does not ship

`files` is `dist`, `LICENSE`, `README.md`, `CHANGELOG.md`. The shared wire contract and the
generated OpenAPI artifacts live in `conformance/` and reach consumers through GitHub, never through
`node_modules`. A path that resolves from the repository and not from the published package is
correct; do not "fix" it.

### Only a `mutation:full` verdict may be reported

`stryker.config.json` sets `incremental: true`, so `pnpm mutation` and **any** `--mutate <file>` run
reuse recorded verdicts and print a whole-project score in seconds. Measured here: a scoped run over
a brand-new file answered `Final mutation score of 100.00` in 18 seconds having tested nothing in it.

A score in a pull-request description is therefore not evidence. What distinguishes a real run, in
order of reliability: an `Instrumented N source file(s) with M mutant(s)` line naming a real count,
the file appearing as a row in the final table, and wall-clock — the cold run here is about two
hours. Treat a reported score with none of those as unmeasured.

### Equivalent mutants carry their reason inline

`// Stryker disable next-line <Mutator>: <reason>` is acceptable **only** for a mutant no test can
kill, and never for one a test could. The per-line form binds to the line immediately after it,
which is not always the line intended — a mutant sharing its line with a callback's closing brace,
or a directive whose comment wrapped, both bind wrong and report as surviving. Use the block form
there and say why in the reason.

---

## Frontend patterns

The four subpaths and what each exports are documented in the README's
[Frontend](./README.md) sections, and in depth in
[REACT-GUIDELINES](./docs/guidelines/REACT-GUIDELINES.md) and
[NEXTJS-GUIDELINES](./docs/guidelines/NEXTJS-GUIDELINES.md). Only the rules that
bite without warning are repeated here:

- **React** — hooks only; memoize the context value; `AbortController` on unmount.
- **Next.js 16** — `cookies()` is async, `params`/`searchParams` are Promises, and the proxy
  runs on the **Node.js runtime, not Edge**. `proxy.ts` is the file middleware was renamed to.
- **`./shared` and `./client`** carry zero dependencies, and must keep carrying zero.
  `./client` is the one subpath with no guidelines file: `createAuthClient(config)` returns typed
  methods for every endpoint, and `createAuthFetch(config)` wraps `fetch` with 401 interception and
  single-flight refresh.

---

## Testing strategy

**100% statements / branches / functions / lines, every layer, no exceptions** — enforced by
`jest.config.ts` and `jest.coverage.config.ts`, both of which fail below it. A pre-publish gate,
not a target.

**Mutation testing is the deeper gate** (Stryker `break: 100`, currently holding 100%). Only a
cold `pnpm mutation:full` verdict may be reported, for the reason given under the review rules
above; `pnpm mutation` and any `--mutate` run reuse recorded verdicts. Survivors are a missing
test or an equivalent mutant carrying its reason. Full methodology, config rationale and the
per-file workflow: [docs/mutation_testing_plan.md](./docs/mutation_testing_plan.md); results:
[docs/mutation_testing_results.md](./docs/mutation_testing_results.md).

**Mock external dependencies, never the module.** Redis, repositories, the email provider,
`JwtService` and `fetch` are `jest.fn()`; `node:crypto` is spied per function and never mocked
whole. Detail: [JEST-TESTING-GUIDELINES](./docs/guidelines/JEST-TESTING-GUIDELINES.md).

---

## Common pitfalls

Read every pair as **wrong → right**. The left side is the mistake; the right side is what the
code must do instead.

**Security** — `===` on a token → `crypto.timingSafeEqual`; a token or secret in a log line → the
event type and user id alone; a JWT secret under 32 characters accepted → rejected at startup; an
external crypto package → `node:crypto`; a raw refresh token stored → its SHA-256 stored.

**Architecture** — importing an ORM directly → `IUserRepository`; a string injection token →
`Symbol()`; registering a feature the options disabled → conditional registration; `Scope.REQUEST`
→ the default singleton; a cross-subpath import (`react` reaching into `server`) → import from
`shared` only.

**TypeScript** — `any` → `unknown`, a generic, or the real type; a missing `export type` for an
interface → a separate `export type`; a barrel re-exporting internals → the public API only; a
default export → a named export.

**Testing** — asserting a call happened → asserting what it was called with; a spec pinned to its
own literal → pinned to the value the code derives; replacing all of `node:crypto` → spreading
`jest.requireActual` and overriding only the function under test; real Redis in a unit test → a
mocked `ioredis`; state shared across tests → fresh mocks in `beforeEach`. (`jest.mock()` on a
module is correct and used here for import-time replacement — see
[JEST-TESTING-GUIDELINES](./docs/guidelines/JEST-TESTING-GUIDELINES.md) §6.3. The pitfall is
discarding the real behaviour the test exists to check, not the call itself.)

---
