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
})
