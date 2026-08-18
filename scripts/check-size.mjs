#!/usr/bin/env node
// Zero-dependency bundle-size gate. Measures every published subpath's ESM
// bundle (raw + brotli-compressed) and fails when any subpath exceeds the
// hard-coded budget below.
//
// Why zero deps: this is an auth library that ships `"dependencies": {}` on
// purpose. The CI/release runner must stay free of third-party tooling so a
// compromised devDep cannot tamper with the bundle before `pnpm publish`.
// `node:zlib`'s brotli matches what npm/CDN compression produces on the wire.

import { readFileSync, statSync } from 'node:fs'
import { brotliCompressSync, constants } from 'node:zlib'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

// Budgets are in bytes (KiB units, `n * 1024`, matching the table's ÷1024
// display) measured against the brotli'd .mjs bundle — what a consumer's
// bundler/CDN ships. Brotli, not gzip, to match real wire compression.
//
// Bymax bundle-size convention (canonical: Obsidian → 03 - Resources/NestJS/
// Bymax-Conventions.md → "Bundle-size budgets"):
//   1. The .mjs ships UNMINIFIED with JSDoc (tsup `minify: false`) on purpose —
//      readable stack traces inside a consumer's node_modules outweigh a few KB
//      on a backend lib that never reaches a browser. We do NOT minify just to
//      satisfy a budget.
//   2. The budget is CALIBRATED to the real built artifact + MODEST headroom
//      (~20-25%): tight enough to catch accidental bloat (e.g. a dep leaking in),
//      loose enough that a normal feature commit passes. Avoid >2× headroom — it
//      silently lets bloat through. When real growth is legitimate, raise it and
//      say why here; when the artifact shrinks, tighten it.
//
// Calibration snapshot (point-in-time, 2026-05-30 against dist/) — indicative
// only; this comment is NOT the source of truth and goes stale as the code
// changes. For the LIVE measured sizes vs. these budgets, run `pnpm build &&
// pnpm size` and read the Brotli column. Re-derive headroom from that output
// before changing any budget below.
//   server 100.84 KiB → 108 KiB  (~7% headroom; large module, active dev)
//     Raised from 68 KiB when the first security-audit work landed (the single-use
//     WebSocket ticket and JWT verification across a secret rotation), then from 72 KiB
//     when the blind-audit fixes did. That second round is: the MFA encryption-key
//     rotation, the atomic OTP verify/store scripts, the grace-pointer successor probe,
//     the trusted-origin and no-store layers, plane-namespaced MFA keys, and the tenant
//     resolver reaching every tenant-scoped flow. Every one of those is a shipped control
//     with a test behind it, which is the distinction this budget exists to force someone
//     to make — growth for features, not drift.
//     Raised again from 76 KiB for the two ASVS Level 1 gaps the capability audit found:
//     the authenticated password-change flow, and `CommonPasswordChecker` becoming the
//     default screen. Most of the delta is that checker's word list — about 2.5 KiB — and
//     it is the one kind of growth worth taking without argument: NIST SP 800-63B §3.1.1.2
//     says a verifier SHALL screen against a blocklist, the previous default approved
//     everything, and this bundle runs on a server rather than being shipped to a browser.
//     Raised again from 82 KiB for the third audit round: the failure-side hooks
//     (`onLoginFailed`/`onLockout`/`onRefreshTokenReuseDetected`), the invitation-revoke
//     flow with its invitee index, and the administrative lockout clear. Three capabilities
//     the audits found missing rather than three refactors — the same test this budget
//     exists to apply.
//     Raised again from 86 KiB for the address-change flow: a service, a controller, two DTOs
//     and their config. It is the last of the four feature-scale gaps the capability audit
//     found that is worth taking — the address is the account's recovery credential, and until
//     now the library could mint one and never move it, so a user whose address died was
//     locked out permanently.
//     Raised again from 92 KiB for the fifth audit round, which is entirely controls rather
//     than capabilities: the serialized MFA transition point (every MFA state change is now
//     one locked read-modify-write, closing the resurrected-recovery-code, rolled-back-
//     regenerate and reverted-disable races), the atomic grace-recovery write, the invitation
//     supersede gated on rank and claimed atomically, the account-backed WebSocket-ticket
//     snapshot, `logSafe` plus a charset constraint against log-record forgery, `tenantScoped`
//     binding every lookup to the tenant that was asked for, and the relative-`Location`
//     redirect helper. Each carries a red-checked test; none adds a feature. That is the
//     distinction this budget exists to force, and it is the answer it was built to accept.
//     Raised again from 100 KiB for the third audit round's remaining work: `password.minLength`
//     with its service-layer screen, the cookie-prefix contract validated at boot, the explicit
//     `environment` option replacing six `NODE_ENV` reads, the OAuth state's provider binding,
//     and `MfaService.resetMfa`. Measured 97.63 → 100.84 KiB, so +3.21 KiB against 2.37 KiB of
//     headroom. Three of those five are shipped controls and two are capabilities the audit
//     found missing, which is the test this budget applies — but be clear about where the bytes
//     actually went: a large share is PROSE, not code. `tsup` builds with `minify: false`, so
//     every JSDoc block ships inside `index.mjs`, and this module's comments carry the reasoning
//     that makes its security decisions reviewable. That is worth paying for in a bundle that
//     runs on a server. It is also the obvious future lever if this budget gets tight again:
//     consumers read the `.d.ts`, never the comments in the `.mjs`, so stripping comments from
//     the JS output alone would give several KiB back without losing a word of documentation.
//     Raised to 115 KiB for the runtime OpenAPI contributor: a deployment building its document
//     with @bymax-one/nest-core now gets this library's operations described automatically —
//     which schemes exist, which operation requires which, and which are reachable
//     unauthenticated — derived from the resolved options, because the same build serves
//     different paths, transports and cookie names in every deployment. Measured 108.00 -> 108.21
//     KiB against 0 headroom, so ~6% back, matching this entry's historical band.
//     Worth recording because it contradicts the note above: for THIS subpath the prose lever did
//     not apply. Trimming ~4 KB of JSDoc out of the two new files changed the bundle by ZERO
//     bytes — measured, not assumed — because tsup does not carry those files' comments into the
//     output. The growth is the handler table and the derivation: code, not documentation.
//     Raised to 122 KiB for the tenant-scoping round: the session index and token epoch keyed on
//     the tenant-scoped subject, that subject made injective with a byte-length prefix, and the
//     seven `IUserRepository` mutators taking the tenant their reads already took. Measured
//     114.82 -> 115.27 KiB across the two changes, against 0.18 KiB of headroom — so the second
//     one failed the gate by 0.27 KiB. Both are shipped controls with red-checked tests behind
//     them, which is the distinction this budget exists to force, and 122 puts headroom back at
//     ~5.8%, inside this entry's historical band.
//     One correction to the entry above, because it left a wrong impression of the WHOLE bundle:
//     the prose lever emphatically DOES apply here. Measured on the built artifact, stripping
//     every block comment takes `dist/server/index.mjs` from 115.27 to 63.39 KiB brotli — 51.88
//     KiB, or 45% of the subpath, is JSDoc. The zero-byte result above was true of the two
//     OpenAPI files specifically, not of the module. Acting on that is a build-config decision
//     with a stack-trace tradeoff rather than something to do while unblocking a PR, so it is
//     tracked separately; recorded here so the next person reads a measurement instead of the
//     narrower claim.
//   shared   2.35 KiB →  3 KiB  (~28% headroom)
//     Raised to 3.5 KiB: the subpath gained the two error codes that close the catalog gap
//     with rust-auth (`auth.token_missing`, `auth.internal`) and a linear slash trimmer that
//     replaced a regex CodeQL reports as a polynomial ReDoS. Both are small and both are
//     load-bearing; the budget was at ~28% headroom and is back to ~16%.
//     Raised to 4.25 KiB for the nine routes this library serves that `AUTH_ROUTES` did not name
//     — `ws-ticket`, `mfa/recovery-codes`, `password/change`, the four `platform/mfa/*` and both
//     OAuth routes — plus the two families they needed. Every one of them was a path a consumer
//     had to hardcode, and would have kept hardcoded through a rename; the map exists to make
//     that unnecessary. Measured 3.45 -> 3.84 KiB against 0.05 of headroom.
//     For THIS subpath the prose lever is real and worth stating rather than re-measuring later:
//     of the 3.84 KiB, comments are 2.09 and code is 1.75. `shared` ships to the browser through
//     `client`, `react` and `nextjs`, so that is documentation travelling to end users — the one
//     place in this package where stripping comments from the `.mjs` would buy more than half the
//     bundle back without losing a word a consumer reads (they read the `.d.ts`). Not done here
//     because it is a build change with its own blast radius, and this PR is a route fix.
//     Recorded so the next raise is argued against that number instead of discovering it again.
//   client   2.64 KiB →  3.5 KiB (~33% headroom; fetch client may grow with auth flows)
//     Raised to 4.25 KiB: the 401 interceptor stopped deciding by path alone and now reads the
//     error code, because a path list cannot separate the two meanings a single JWT-guarded
//     route carries — an expired token and a wrong current password both 401 from
//     `password/change`. A consumer measured what the old behaviour cost: one refresh per typo,
//     ten typos inside a minute exhausting the refresh limiter, and the client reading that 429
//     as an expiry and discarding a session the server still honoured. The bytes are the
//     classification plus the bounded body read that keeps it from hanging the wrapper on a 401
//     whose body never terminates. Measured 3.40 → 3.62 KiB, so +0.22 against 0.10 of headroom.
//     A shipped control with a red-checked test behind it, which is the distinction this budget
//     exists to force. Back to ~17% headroom.
//     NOTE, since it is not obvious from the numbers: unlike `server` and `shared`, the client
//     bundle carries NO prose — tsup emits it without comments — so every byte here is code.
//   react    1.71 KiB →  2.5 KiB (~46% headroom; hooks surface may expand)
//   nextjs   8.16 KiB → 10 KiB  (~22% headroom)
const BUDGETS = [
  { name: 'server  (NestJS module)', path: 'dist/server/index.mjs', brotli: 122 * 1024 },
  { name: 'shared  (types + constants)', path: 'dist/shared/index.mjs', brotli: 4.25 * 1024 },
  { name: 'client  (fetch auth client)', path: 'dist/client/index.mjs', brotli: 4.25 * 1024 },
  { name: 'react   (hooks + AuthProvider)', path: 'dist/react/index.mjs', brotli: 2.5 * 1024 },
  { name: 'nextjs  (proxy + handlers)', path: 'dist/nextjs/index.mjs', brotli: 10 * 1024 }
]

// Divides by 1024, so the unit is KiB (not the SI kB = 1000 bytes).
const fmt = (n) => `${(n / 1024).toFixed(2)} KiB`

const BROTLI_OPTS = {
  params: { [constants.BROTLI_PARAM_QUALITY]: constants.BROTLI_MAX_QUALITY }
}

let failed = 0
const rows = []

for (const { name, path, brotli: limit } of BUDGETS) {
  const abs = resolve(ROOT, path)
  try {
    statSync(abs)
  } catch {
    console.error(`Missing build artifact: ${path} — run \`pnpm build\` first.`)
    process.exit(2)
  }
  const raw = readFileSync(abs)
  const compressed = brotliCompressSync(raw, BROTLI_OPTS).length
  const ok = compressed <= limit
  if (!ok) failed += 1
  rows.push({
    name,
    raw: raw.length,
    brotli: compressed,
    limit,
    delta: compressed - limit,
    ok
  })
}

const pad = (s, n) => String(s).padEnd(n)
const padL = (s, n) => String(s).padStart(n)

console.log('')
console.log(
  `  ${pad('Subpath', 38)}${padL('Raw', 12)}${padL('Brotli', 12)}${padL('Budget', 12)}  Status`
)
console.log(`  ${'-'.repeat(38)}${'-'.repeat(12)}${'-'.repeat(12)}${'-'.repeat(12)}  ------`)
for (const r of rows) {
  const status = r.ok ? 'PASS' : `FAIL +${fmt(r.delta)}`
  console.log(
    `  ${pad(r.name, 38)}${padL(fmt(r.raw), 12)}${padL(fmt(r.brotli), 12)}${padL(fmt(r.limit), 12)}  ${status}`
  )
}
console.log('')

if (failed > 0) {
  console.error(`${failed} subpath(s) exceeded the brotli budget.`)
  process.exit(1)
}
