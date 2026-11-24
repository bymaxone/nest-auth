/**
 * @fileoverview The decisions of the library made while a host replaces the constructor of a promise or plants a `then`: each one is
 * run in a process of its own, because the plant has to outlive the first microtask, and the outcome it answers is compared with
 * what the repositories said. Before the helpers waited under the root check, these answered what the host's `then` chose: an owner
 * for a user who is not a member, and "not revoked" for a token that is on the blacklist.
 *
 * @layer Test
 */

import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { buildSync } from 'esbuild'

interface Outcome {
  outcome: string
  unhandled: number
}

/** Bundles the harness once and runs one scenario of it in a child process. */
function run(scenario: string, file: string): Outcome {
  const out = execFileSync(process.execPath, [file], {
    encoding: 'utf8',
    env: { ...process.env, SCENARIO: scenario, NODE_PATH: join(process.cwd(), 'node_modules') }
  })
  return JSON.parse(out) as Outcome
}

describe('a decision made while a host forges what a promise answers', () => {
  const directory = mkdtempSync(join(tmpdir(), 'forged-then-'))
  const file = join(directory, 'harness.cjs')

  beforeAll(() => {
    const bundle = buildSync({
      entryPoints: [join(__dirname, '__tests__', 'forged-then.harness.ts')],
      bundle: true,
      platform: 'node',
      format: 'cjs',
      packages: 'external',
      write: false
    }).outputFiles[0]?.text as string
    writeFileSync(file, bundle)
  })

  afterAll(() => {
    rmSync(directory, { recursive: true, force: true })
  })

  // Scenario: a route handler returns what a service answered, and a `then` forging another account is planted by the code the
  // service called. Expected: the account the service answered. Why: a handler that returns the promise bare resolves its own from
  // it, which reads that promise's `then`; `return await pinned(...)` reads the pinned constructor instead.
  it('answers the account the service returned through a route handler', () => {
    expect(run('route', file)).toEqual({ outcome: 'account:real', unhandled: 0 })
  })

  // Scenario: no host interference. Expected: a user with no membership is denied. Why: the other rows mean nothing unless this holds.
  it('denies a non-member when nothing is forged', () => {
    expect(run('baseline', file)).toEqual({ outcome: 'denied', unhandled: 0 })
  })

  // Scenario: the constructor of a promise replaced, and a `then` that puts it back and answers an owner for the membership read.
  // Expected: refused with auth.internal. Why: `await` asks the constructor, so a replaced one makes it call the host's `then`.
  it('refuses a membership read answered through a replaced constructor', () => {
    expect(run('ctor', file)).toEqual({ outcome: 'refused:auth.internal', unhandled: 0 })
  })

  // Scenario: a `then` on `Array.prototype` that answers the pair of reads, as the array a combined wait resolves with.
  it('refuses a read answered through a then on Array.prototype', () => {
    expect(run('array', file)).toEqual({ outcome: 'refused:auth.internal', unhandled: 0 })
  })

  // Scenario: a `then` on `Object.prototype` planted by the repository read itself, after the check at the entry.
  it('refuses a read answered through a then planted on Object.prototype during it', () => {
    expect(run('mid-read', file)).toEqual({ outcome: 'refused:auth.internal', unhandled: 0 })
  })

  // Scenario: the membership read answers none after a while, and a `then` on `Object.prototype` that erases itself is planted while
  // the library waits for it. Expected: refused with auth.internal, not the owner the then answers. Why: an async function that
  // returns an object makes the engine ask it for `then`, and nothing guarded that read once the last wait was over.
  it('refuses an answer read for a then planted after the last wait began', () => {
    expect(run('late', file)).toEqual({ outcome: 'refused:auth.internal', unhandled: 0 })
  })

  // Scenario: the status check of an account is the host's code, and it plants a then that answers another subject while the library
  // waits for it. Expected: refused with auth.internal, never the payload of someone else. Why: the verified token is an object.
  it.each(['late-dashboard', 'late-platform'])(
    'refuses a verified token read for a then planted during the wait (%s)',
    (scenario) => {
      expect(run(scenario, file)).toEqual({ outcome: 'refused:auth.internal', unhandled: 0 })
    }
  )

  // Scenario: a queued job re-checks its actor and the membership read plants a then that answers an owner. Expected: refused, not
  // the owner the then answers, for the editor the repository holds.
  it('refuses the member of a job read for a then planted during the wait', () => {
    expect(run('late-job', file)).toEqual({ outcome: 'refused:auth.internal', unhandled: 0 })
  })

  // Scenario: the constructor of promises is replaced and a then planted before the call, and a plain async caller awaits what the
  // service returns. Expected: the refusal, not the owner the then answers. Why: the caller's await is the last hop of a decision.
  it('refuses at the outermost caller that awaits a decision', () => {
    expect(run('hop', file)).toEqual({ outcome: 'refused:auth.internal', unhandled: 0 })
  })

  // Scenario: the host's code, called by the library, plants while it makes the promise the library awaits next, for a token that is
  // revoked. Expected: never verified. Why: the await of a dependency's promise reads the constructor after the host's code ran.
  it('does not verify a revoked token for a constructor planted by the code it awaits', () => {
    expect(run('sync-revoked', file)).toEqual({
      outcome: 'refused:auth.token_invalid',
      unhandled: 0
    })
  })

  // Scenario: a `then` on the root object, or on functions, before the call. Expected: refused at the entry.
  it.each(['object', 'function'])('refuses a then planted on %s before the call', (scenario) => {
    expect(run(scenario, file)).toEqual({ outcome: 'refused:auth.internal', unhandled: 0 })
  })

  // Scenario: a token on the blacklist, a replaced constructor and a `then` that answers "not on it". Expected: refused, and never
  // the answer `false`. Why: that answer is a revoked token accepted.
  it('does not accept a revoked token through a replaced constructor', () => {
    expect(run('revoked-token', file)).toEqual({ outcome: 'refused:auth.internal', unhandled: 0 })
  })

  // Scenario: a read that fails while the root is compromised, so the library refuses what it started. Expected: no unhandled
  // rejection. Why: an unhandled rejection ends the process, and the refusal would turn a 500 into an outage.
  it('leaves no rejection unhandled when it refuses a read that failed', () => {
    expect(run('unhandled', file)).toEqual({ outcome: 'refused:auth.internal', unhandled: 0 })
  })

  // Scenario: every command of the store passes through the outage proxy, and one fails while the root is compromised. Expected: refused,
  // and no unhandled rejection from the command the proxy had already issued.
  it('leaves no rejection unhandled when the outage proxy refuses a command that failed', () => {
    expect(run('redis', file)).toEqual({ outcome: 'refused:auth.internal', unhandled: 0 })
  })
  // Scenario: the species of promises throws while a command of the store fails and the root is compromised. Expected: refused, and
  // no unhandled rejection. Why: marking a rejection handled with `then` or `catch` reads the species first, and that throw left the
  // rejection with no handler.
  it('leaves no rejection unhandled when the species of promises throws', () => {
    expect(run('species', file)).toEqual({ outcome: 'refused:auth.internal', unhandled: 0 })
  })

  // Scenario: a command answers a rejecting promise whose `then` is an accessor that throws. Expected: the read throws to the caller
  // and the rejection is still handled. Why: `isThenable` reads `then`, and marking the rejection handled came after that read.
  it('leaves no rejection unhandled when reading then of the answer throws', () => {
    expect(run('then-throws', file)).toEqual({ outcome: 'threw:then read', unhandled: 0 })
  })
  // Scenario: the client of the store plants a `then` that answers an absent value while it makes the promise the library returns, for
  // a key that holds a revoked marker. Expected: the marker, never the absence. Why: a promise returned bare is resolved through its `then`.
  it('answers the value the store holds for a promise the client forged a then on', () => {
    expect(run('bare-redis', file)).toEqual({ outcome: 'value:1', unhandled: 0 })
  })

  // Scenario: a membership cache whose store read is waited for while host code plants a `then` answering an owner's entry. Expected:
  // refused with auth.internal, not an owner. Why: the parsed read is an object returned after a wait, and nothing read the root last.
  it('refuses a membership parsed from a cache read for a then planted during the wait', () => {
    expect(run('parse-read', file)).toEqual({ outcome: 'refused:auth.internal', unhandled: 0 })
  })

  // Scenario: the verification of a TOTP code says the code is wrong while host code plants a `then` answering a valid one. Expected:
  // refused with auth.internal, never `valid: true`. Why: that answer is an MFA challenge passed with a wrong code.
  it('does not pass a wrong code for a then planted while the code is verified', () => {
    expect(run('mfa-valid', file)).toEqual({ outcome: 'refused:auth.internal', unhandled: 0 })
  })

  // Scenario: a repository of the host answers no membership and installs one-shot accessors for `constructor` and `then` on the
  // prototype of promises while it makes the promise, the way a host that restores them on first read would. Expected: not an owner.
  // Why: the wait must not read the prototype at all, so the accessor that is never read stays and the next check refuses.
  it('does not make an owner of a membership read when accessors restore themselves', () => {
    expect(run('self-restoring-member', file)).toEqual({
      outcome: 'refused:auth.internal',
      unhandled: 0
    })
  })

  // Scenario: the revocation check says the token is revoked while the accessors answer that it is not. Expected: the token is invalid.
  it('does not verify a revoked token when accessors restore themselves', () => {
    expect(run('self-restoring-revoked', file)).toEqual({
      outcome: 'refused:auth.token_invalid',
      unhandled: 0
    })
  })

  // Scenario: the status check refuses the account while the accessors answer that it passed. Expected: the refusal reaches the caller.
  it('does not pass a blocked account when accessors restore themselves', () => {
    expect(run('self-restoring-status', file)).toEqual({ outcome: 'refused:other', unhandled: 0 })
  })

  // Scenario: the client of the store makes the promise that answers a marker, with the accessors installed. Expected: `value:1` or a
  // refusal, never an absent marker. Why: a read answered through the forged `then` is a revoked token that is not.
  it('answers the marker the store holds when accessors restore themselves', () => {
    expect(run('self-restoring-redis', file)).toEqual({
      outcome: 'refused:auth.internal',
      unhandled: 0
    })
  })

  // Scenario: the store says a recovery code is spent, with the accessors installed that say it was claimed. Expected: not claimed.
  it('does not claim a spent recovery code when accessors restore themselves', () => {
    expect(run('self-restoring-claim', file)).toEqual({ outcome: 'claimed:false', unhandled: 0 })
  })
})
