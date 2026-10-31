import * as apiKeyCrypto from '../crypto/api-key'
import { formatApiKey, parseApiKey } from '../crypto/api-key'
import { ApiKeyLastUsedService } from './api-key-last-used.service'
import { ApiKeyVerifierService } from './api-key-verifier.service'
import type { ApiKeyVerdict } from './api-key-verifier.service'
import {
  FakeClock,
  KEY_ID,
  MemoryApiKeyRepository,
  NOW,
  SENTINEL_KEY,
  SENTINEL_SECRET,
  makeOptions,
  makeRow
} from './__tests__/api-key-fixtures'

const OTHER_ID = '5a1d9e40-7b3c-4f6a-8c21-0e9d4b6a3f12'
const WRONG_KEY = formatApiKey('bak', KEY_ID, 'A'.repeat(43))
const UNKNOWN_KEY = formatApiKey('bak', OTHER_ID, SENTINEL_SECRET)

/** Builds a verifier over a repository and clock, with the last-used recorder observable. */
function build(rows = [makeRow()]): {
  verifier: ApiKeyVerifierService
  repo: MemoryApiKeyRepository
  clock: FakeClock
  recorded: Array<{ id: string; at: Date }>
} {
  const repo = new MemoryApiKeyRepository(rows)
  const clock = new FakeClock()
  const recorded: Array<{ id: string; at: Date }> = []
  const lastUsed = {
    record: (id: string, at: Date) => recorded.push({ id, at })
  } as unknown as ApiKeyLastUsedService
  const verifier = new ApiKeyVerifierService(repo, clock, makeOptions(), lastUsed)
  return { verifier, repo, clock, recorded }
}

/**
 * Runs one verification and returns the ordered list of steps it took.
 *
 * The steps are observed at their real call sites by wrapping the functions the verifier calls,
 * so the list is what the code DID, not what a comment says it does.
 */
async function stepsOf(
  run: (verifier: ApiKeyVerifierService) => Promise<ApiKeyVerdict>,
  rows = [makeRow()],
  adjust: (ctx: ReturnType<typeof build>) => void = () => undefined
): Promise<{ steps: string[]; verdict: ApiKeyVerdict }> {
  const ctx = build(rows)
  adjust(ctx)
  const steps: string[] = []
  const realParse = apiKeyCrypto.parseApiKey
  const realDigest = apiKeyCrypto.apiKeyDigest
  const realMatch = apiKeyCrypto.digestsMatch
  jest.spyOn(apiKeyCrypto, 'parseApiKey').mockImplementation((...args) => {
    steps.push('parse')
    return realParse(...args)
  })
  jest.spyOn(apiKeyCrypto, 'apiKeyDigest').mockImplementation((...args) => {
    steps.push('digest')
    return realDigest(...args)
  })
  jest.spyOn(apiKeyCrypto, 'digestsMatch').mockImplementation((...args) => {
    steps.push('compare')
    return realMatch(...args)
  })
  const realFind = ctx.repo.findById.bind(ctx.repo)
  jest.spyOn(ctx.repo, 'findById').mockImplementation(async (id) => {
    steps.push('lookup')
    return realFind(id)
  })
  const realNow = ctx.clock.now.bind(ctx.clock)
  jest.spyOn(ctx.clock, 'now').mockImplementation(() => {
    steps.push('clock')
    return realNow()
  })
  const verdict = await run(ctx.verifier)
  return { steps, verdict }
}

afterEach(() => {
  jest.restoreAllMocks()
})

describe('ApiKeyVerifierService', () => {
  describe('verdicts', () => {
    // A well-formed key for an active row is accepted and the row is returned.
    it('accepts a valid key', async () => {
      const { verifier } = build()
      const verdict = await verifier.verify(SENTINEL_KEY)
      expect(verdict).toEqual({ ok: true, key: makeRow() })
    })

    // A successful verification tells the last-used recorder, with the clock's instant.
    it('records the use of an accepted key and nothing for a refused one', async () => {
      const { verifier, recorded } = build()
      await verifier.verify(WRONG_KEY)
      await verifier.verify(undefined)
      expect(recorded).toEqual([])
      await verifier.verify(SENTINEL_KEY)
      expect(recorded).toEqual([{ id: KEY_ID, at: NOW }])
    })

    it.each([
      ['missing', undefined, 'missing'],
      ['malformed', 'not-a-key', 'malformed'],
      ['an array header', [SENTINEL_KEY], 'malformed'],
      ['unknown', UNKNOWN_KEY, 'unknown'],
      ['wrong secret', WRONG_KEY, 'wrong_secret']
    ])('refuses a %s key', async (_name, header, reason) => {
      const { verifier } = build()
      const verdict = await verifier.verify(header)
      expect(verdict.ok).toBe(false)
      expect(verdict).toMatchObject({ reason })
    })

    // A refusal carries the identified row only when the presented key parsed, so a malformed
    // value never reports a row even if the dummy id happened to exist.
    it('reports the identified row for a wrong secret and none for a malformed key', async () => {
      const { verifier } = build()
      expect(await verifier.verify(WRONG_KEY)).toMatchObject({ key: { id: KEY_ID } })
      expect(await verifier.verify('nope')).toMatchObject({ key: null })
      expect(await verifier.verify(UNKNOWN_KEY)).toMatchObject({ key: null })
    })

    // Even when a row exists under the dummy id the dummy substitution can never admit it.
    it('never admits a malformed key even if a row exists under the dummy id', async () => {
      const dummyRow = makeRow({ id: apiKeyCrypto.API_KEY_DUMMY_KEY_ID })
      const { verifier } = build([dummyRow])
      const verdict = await verifier.verify('nope')
      expect(verdict).toMatchObject({ ok: false, reason: 'malformed', key: null })
    })

    // A corrupted stored digest is a mismatch, not an exception and not a match.
    it('treats a corrupted stored digest as a wrong secret', async () => {
      const { verifier } = build([makeRow({ digest: 'corrupt' })])
      expect(await verifier.verify(SENTINEL_KEY)).toMatchObject({
        ok: false,
        reason: 'wrong_secret'
      })
    })

    // A store fault propagates so the guard can fail closed; nothing is swallowed here.
    it('propagates a store fault', async () => {
      const { verifier, repo } = build()
      repo.failWith = new Error('db down')
      await expect(verifier.verify(SENTINEL_KEY)).rejects.toThrow('db down')
    })
  })

  describe('revocation and expiry at the exact boundary', () => {
    // A key is valid strictly before its expiry instant and invalid AT it.
    it('is valid one millisecond before expiresAt and expired at it', async () => {
      const expiresAt = new Date(NOW.getTime() + 1000)
      const { verifier, clock } = build([makeRow({ expiresAt })])
      clock.current = new Date(expiresAt.getTime() - 1)
      expect((await verifier.verify(SENTINEL_KEY)).ok).toBe(true)
      clock.current = new Date(expiresAt.getTime())
      expect(await verifier.verify(SENTINEL_KEY)).toMatchObject({ ok: false, reason: 'expired' })
      clock.current = new Date(expiresAt.getTime() + 1)
      expect(await verifier.verify(SENTINEL_KEY)).toMatchObject({ ok: false, reason: 'expired' })
    })

    // Same boundary for revocation: a key revoked at an instant stops verifying AT that instant.
    it('is valid one millisecond before revokedAt and revoked at it', async () => {
      const revokedAt = new Date(NOW.getTime() + 1000)
      const { verifier, clock } = build([makeRow({ revokedAt })])
      clock.current = new Date(revokedAt.getTime() - 1)
      expect((await verifier.verify(SENTINEL_KEY)).ok).toBe(true)
      clock.current = new Date(revokedAt.getTime())
      expect(await verifier.verify(SENTINEL_KEY)).toMatchObject({ ok: false, reason: 'revoked' })
    })

    // A revoked key that is also expired reports revoked: one fixed precedence.
    it('reports revoked before expired when both apply', async () => {
      const past = new Date(NOW.getTime() - 1000)
      const { verifier } = build([makeRow({ revokedAt: past, expiresAt: past })])
      expect(await verifier.verify(SENTINEL_KEY)).toMatchObject({ reason: 'revoked' })
    })
  })

  describe('identical steps for every key', () => {
    const ok = (verifier: ApiKeyVerifierService): Promise<ApiKeyVerdict> =>
      verifier.verify(SENTINEL_KEY)
    const baseline = ['parse', 'lookup', 'digest', 'compare', 'clock']

    // The accepted path defines the sequence every refusal must repeat.
    it('takes parse, lookup, digest, compare, then the clock, in that order', async () => {
      const { steps, verdict } = await stepsOf(ok)
      expect(verdict.ok).toBe(true)
      expect(steps).toEqual(baseline)
    })

    // Each refusal reason runs the same steps in the same order as the accepted key: nothing
    // returns early, so no reason can be told apart by what the code did.
    it.each([
      ['missing', (v: ApiKeyVerifierService) => v.verify(undefined), [makeRow()], 'missing'],
      ['malformed', (v: ApiKeyVerifierService) => v.verify('garbage'), [makeRow()], 'malformed'],
      ['unknown', (v: ApiKeyVerifierService) => v.verify(UNKNOWN_KEY), [makeRow()], 'unknown'],
      [
        'wrong secret',
        (v: ApiKeyVerifierService) => v.verify(WRONG_KEY),
        [makeRow()],
        'wrong_secret'
      ],
      ['revoked', ok, [makeRow({ revokedAt: new Date(NOW.getTime() - 1) })], 'revoked'],
      ['expired', ok, [makeRow({ expiresAt: new Date(NOW.getTime() - 1) })], 'expired']
    ])('takes the accepted sequence for a %s key', async (_name, run, rows, reason) => {
      const { steps, verdict } = await stepsOf(run, rows)
      expect(verdict).toMatchObject({ ok: false, reason })
      expect(steps).toEqual(baseline)
    })

    // The comparison is always between two 32-byte buffers of the same length, including when
    // there is no row to compare against.
    it('compares against a well-formed digest even when the row is absent', async () => {
      const compared: Array<[string, string]> = []
      const real = apiKeyCrypto.digestsMatch
      jest.spyOn(apiKeyCrypto, 'digestsMatch').mockImplementation((a, b) => {
        compared.push([a, b])
        return real(a, b)
      })
      const { verifier } = build()
      await verifier.verify(UNKNOWN_KEY)
      expect(compared).toHaveLength(1)
      expect(compared[0]?.[0]).toMatch(/^[0-9a-f]{64}$/)
      expect(compared[0]?.[1]).toBe(apiKeyCrypto.API_KEY_DUMMY_DIGEST)
    })

    // Proof the instrumentation can fail: a planted shortcut that answers a malformed key
    // before the verifier runs is observed taking a DIFFERENT sequence. Without this, the
    // assertions above could pass for steps nobody is actually watching.
    it('detects a planted early return for malformed keys', async () => {
      const { steps } = await stepsOf(async (verifier) => {
        if (parseApiKey('garbage', 'bak') === null) {
          return { ok: false, reason: 'malformed', key: null }
        }
        return verifier.verify('garbage')
      })
      expect(steps).toEqual(['parse'])
      expect(steps).not.toEqual(baseline)
    })
  })
})
