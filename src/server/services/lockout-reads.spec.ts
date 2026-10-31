/**
 * @fileoverview Every read of the lockout state is either a decision or inside a `try`.
 *
 * `BruteForceService.isLockedOut` and `getRemainingLockoutSeconds` are called from places where
 * the answer IS the refusal (the pre-check that answers 429) and from a place where it only
 * feeds a notification (`onLockout`). A store fault in the first must refuse the request; in the
 * second it must cost the event and nothing else. The two look identical at the call site, so
 * this walks every call in the services and makes each one declare which it is: a read that is
 * neither listed as a decision nor guarded by a `try` fails here, where a grep could not tell
 * the two apart.
 */
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import ts from 'typescript'

const READS = new Set(['isLockedOut', 'getRemainingLockoutSeconds'])

/** Reads whose answer is the refusal itself, so a fault must propagate. `file#method`. */
const DECISIONS = new Set([
  'auth.service.ts#login',
  'auth.service.ts#isAccountLockedOut',
  'auth.service.ts#getAccountLockoutSeconds',
  'platform-auth.service.ts#login',
  'mfa.service.ts#isMfaFlowLockedOut',
  'email-change.service.ts#requestChange',
  'password-reset.service.ts#changePassword'
])

/** The `file#method` of every lockout read in `source` that is not inside a `try` block. */
export function unguardedReads(file: string, source: string): string[] {
  const tree = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true)
  const found: string[] = []
  const visit = (node: ts.Node, method: string, guarded: boolean): void => {
    let m = method
    let g = guarded
    if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name)) m = node.name.text
    if (ts.isTryStatement(node)) {
      visit(node.tryBlock, m, true)
      if (node.catchClause) visit(node.catchClause, m, g)
      if (node.finallyBlock) visit(node.finallyBlock, m, g)
      return
    }
    const callee = ts.isCallExpression(node) ? node.expression : undefined
    if (callee && ts.isPropertyAccessExpression(callee) && READS.has(callee.name.text) && !g) {
      found.push(`${file}#${m}`)
    }
    ts.forEachChild(node, (child) => visit(child, m, g))
  }
  visit(tree, '', false)
  return [...new Set(found)]
}

describe('lockout reads', () => {
  const dir = __dirname
  const services = readdirSync(dir).filter((f) => f.endsWith('.service.ts'))

  it('walks the services it claims to', () => {
    expect(services).toEqual(
      expect.arrayContaining(['auth.service.ts', 'platform-auth.service.ts'])
    )
  })

  // Verifies that no read of the lockout state sits outside both a declared decision and a
  // `try`. A hook-feeding read added bare would let a store fault replace the caller's answer.
  it('lists every unguarded read as a decision', () => {
    const unguarded = services.flatMap((f) => unguardedReads(f, readFileSync(join(dir, f), 'utf8')))

    expect(unguarded.filter((site) => !DECISIONS.has(site))).toEqual([])
  })

  // Verifies that every allowlisted decision still exists, so the list cannot outlive the code.
  it('keeps no allowlist entry for a read that is gone', () => {
    const unguarded = new Set(
      services.flatMap((f) => unguardedReads(f, readFileSync(join(dir, f), 'utf8')))
    )

    expect([...DECISIONS].filter((site) => !unguarded.has(site))).toEqual([])
  })

  // Verifies that the walker sees a bare read next to a guarded one: planting the former in a
  // service must be reported, the latter must not.
  it('reports a planted bare read and ignores a guarded one', () => {
    const planted = `class X {
      async fire() { try { await this.bruteForce.isLockedOut('a') } catch { return } }
      async leak() { await this.bruteForce.getRemainingLockoutSeconds('a') }
    }`

    expect(unguardedReads('x.service.ts', planted)).toEqual(['x.service.ts#leak'])
  })
})
