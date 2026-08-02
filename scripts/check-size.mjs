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
//   server  92.9 KiB → 100 KiB  (~7% headroom; large module, active dev)
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
//   shared   2.35 KiB →  3 KiB  (~28% headroom)
//     Raised to 3.5 KiB: the subpath gained the two error codes that close the catalog gap
//     with rust-auth (`auth.token_missing`, `auth.internal`) and a linear slash trimmer that
//     replaced a regex CodeQL reports as a polynomial ReDoS. Both are small and both are
//     load-bearing; the budget was at ~28% headroom and is back to ~16%.
//   client   2.64 KiB →  3.5 KiB (~33% headroom; fetch client may grow with auth flows)
//   react    1.71 KiB →  2.5 KiB (~46% headroom; hooks surface may expand)
//   nextjs   8.16 KiB → 10 KiB  (~22% headroom)
const BUDGETS = [
  { name: 'server  (NestJS module)', path: 'dist/server/index.mjs', brotli: 100 * 1024 },
  { name: 'shared  (types + constants)', path: 'dist/shared/index.mjs', brotli: 3.5 * 1024 },
  { name: 'client  (fetch auth client)', path: 'dist/client/index.mjs', brotli: 3.5 * 1024 },
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
