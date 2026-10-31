import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { parseApiKey } from '../crypto/api-key'
import {
  API_KEY_MAX_LABEL_LENGTH,
  API_KEY_MAX_OVERLAP_SECONDS,
  ApiKeyService
} from './api-key.service'
import {
  FakeClock,
  KEY_ID,
  MemoryApiKeyRepository,
  NOW,
  PEPPER,
  makeOptions,
  makeRow
} from './__tests__/api-key-fixtures'
import { apiKeyDigest } from '../crypto/api-key'

function build(rows = [makeRow()]): {
  service: ApiKeyService
  repo: MemoryApiKeyRepository
  clock: FakeClock
} {
  const repo = new MemoryApiKeyRepository(rows)
  const clock = new FakeClock()
  return { service: new ApiKeyService(repo, clock, makeOptions()), repo, clock }
}

async function codeOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise
  } catch (err) {
    return (err as { getResponse(): { error: { code: string } } }).getResponse().error.code
  }
  return undefined
}

async function detailsOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise
  } catch (err) {
    return (err as { getResponse(): { error: { details: unknown } } }).getResponse().error.details
  }
  return undefined
}

describe('ApiKeyService', () => {
  describe('issue', () => {
    // The plaintext is returned once, parses back to the stored id, and only its digest is stored.
    it('returns a plaintext key whose digest is what was stored', async () => {
      const { service, repo } = build([])
      const { key, record } = await service.issue({ label: 'automation', scopes: ['read'] })
      const parsed = parseApiKey(key, 'bak')
      expect(parsed).not.toBeNull()
      expect(parsed?.keyId).toBe(record.id)
      const stored = repo.rows.get(record.id)
      expect(stored?.digest).toBe(apiKeyDigest(parsed?.secret ?? '', PEPPER))
      expect(JSON.stringify([...repo.rows.values()])).not.toContain(parsed?.secret)
    })

    // The returned record never carries the digest.
    it('returns a record without the digest', async () => {
      const { service } = build([])
      const { record } = await service.issue({ label: 'automation', scopes: ['read'] })
      expect(record).not.toHaveProperty('digest')
      expect(record).toMatchObject({
        label: 'automation',
        scopes: ['read'],
        createdAt: NOW,
        expiresAt: null,
        revokedAt: null,
        lastUsedAt: null
      })
    })

    // Two keys issued for one label coexist: that is what makes an overlapping rotation work.
    it('lets several keys share one label', async () => {
      const { service, repo } = build([])
      const a = await service.issue({ label: 'automation', scopes: ['read'] })
      const b = await service.issue({ label: 'automation', scopes: ['read'] })
      expect(a.record.id).not.toBe(b.record.id)
      expect(await repo.listByLabel('automation')).toHaveLength(2)
    })

    // A configured prefix is used in the key.
    it('uses the configured prefix', async () => {
      const repo = new MemoryApiKeyRepository()
      const service = new ApiKeyService(repo, new FakeClock(), makeOptions({ prefix: 'svc' }))
      const { key } = await service.issue({ label: 'a', scopes: ['read'] })
      expect(key.startsWith('svc_')).toBe(true)
    })

    // The expiry, when given, is stored.
    it('stores a future expiry', async () => {
      const { service } = build([])
      const expiresAt = new Date(NOW.getTime() + 1000)
      const { record } = await service.issue({ label: 'a', scopes: ['read'], expiresAt })
      expect(record.expiresAt).toEqual(expiresAt)
    })

    it.each([
      ['empty', ''],
      ['blank', '   '],
      ['too long', 'x'.repeat(API_KEY_MAX_LABEL_LENGTH + 1)],
      ['a control character', 'bad\nlabel'],
      ['a delete character', 'bad\u007flabel'],
      ['not a string', 42 as unknown as string]
    ])('refuses a label that is %s', async (_name, label) => {
      const { service } = build([])
      expect(await codeOf(service.issue({ label, scopes: ['read'] }))).toBe(
        AUTH_ERROR_CODES.VALIDATION
      )
    })

    // A label at exactly the bound is accepted.
    it('accepts a label at the length bound', async () => {
      const { service } = build([])
      await expect(
        service.issue({ label: 'x'.repeat(API_KEY_MAX_LABEL_LENGTH), scopes: ['read'] })
      ).resolves.toBeDefined()
    })

    it.each([
      ['no scopes', []],
      ['an unknown scope', ['nope']],
      ['a repeated scope', ['read', 'read']],
      ['a non-string scope', [1] as unknown as string[]],
      ['not a list', 'read' as unknown as string[]]
    ])('refuses %s', async (_name, scopes) => {
      const { service, repo } = build([])
      expect(await codeOf(service.issue({ label: 'a', scopes }))).toBe(AUTH_ERROR_CODES.VALIDATION)
      expect(repo.calls).toEqual([])
    })

    it.each([
      ['the present instant', NOW],
      ['the past', new Date(NOW.getTime() - 1)],
      ['an invalid date', new Date('nope')],
      ['not a date', '2030-01-01' as unknown as Date]
    ])('refuses an expiry in %s', async (_name, expiresAt) => {
      const { service } = build([])
      expect(await codeOf(service.issue({ label: 'a', scopes: ['read'], expiresAt }))).toBe(
        AUTH_ERROR_CODES.VALIDATION
      )
    })

    // Each validation failure names its field and says what is wrong, never echoing the value.
    it.each([
      [
        'label',
        { label: '', scopes: ['read'] },
        'label must be 1 to 128 characters with no control characters'
      ],
      ['scopes', { label: 'a', scopes: [] }, 'scopes must be a non-empty list'],
      [
        'scopes',
        { label: 'a', scopes: ['nope'] },
        'every scope must come from the configured vocabulary'
      ],
      ['scopes', { label: 'a', scopes: ['read', 'read'] }, 'scopes must not repeat'],
      [
        'expiresAt',
        { label: 'a', scopes: ['read'], expiresAt: NOW },
        'expiresAt must be a valid date in the future'
      ]
    ])('names %s and the reason in the failure details', async (field, input, message) => {
      const { service } = build([])
      expect(await detailsOf(service.issue(input))).toEqual([{ field, message }])
    })
  })

  describe('revoke', () => {
    // Revocation takes effect from the clock's instant.
    it('revokes a key now', async () => {
      const { service, repo } = build()
      await service.revoke(KEY_ID)
      expect(repo.rows.get(KEY_ID)?.revokedAt).toEqual(NOW)
    })

    it('answers not found for an unknown id', async () => {
      const { service } = build()
      expect(await codeOf(service.revoke('5a1d9e40-7b3c-4f6a-8c21-0e9d4b6a3f12'))).toBe(
        AUTH_ERROR_CODES.API_KEY_NOT_FOUND
      )
    })

    // A malformed id never reaches the store.
    it('answers not found for a malformed id without a store call', async () => {
      const { service, repo } = build()
      expect(await codeOf(service.revoke('not-an-id'))).toBe(AUTH_ERROR_CODES.API_KEY_NOT_FOUND)
      expect(repo.calls).toEqual([])
    })
  })

  describe('rotate', () => {
    // With no overlap the old key is retired immediately and the new one carries its label and scopes.
    it('issues a replacement and revokes the old key at once with zero overlap', async () => {
      const { service, repo } = build()
      const { record } = await service.rotate(KEY_ID, { overlapSeconds: 0 })
      expect(record).toMatchObject({ label: 'automation', scopes: ['read', 'operate'] })
      expect(record.id).not.toBe(KEY_ID)
      expect(repo.rows.get(KEY_ID)?.revokedAt).toEqual(NOW)
    })

    // With an overlap the old key keeps verifying until the overlap ends.
    it('leaves the old key valid for the overlap', async () => {
      const { service, repo } = build()
      await service.rotate(KEY_ID, { overlapSeconds: 3600 })
      expect(repo.rows.get(KEY_ID)?.revokedAt).toBeNull()
      expect(repo.rows.get(KEY_ID)?.expiresAt).toEqual(new Date(NOW.getTime() + 3_600_000))
    })

    // An old key already expiring sooner than the overlap keeps its earlier expiry.
    it('never extends an old key that expires sooner than the overlap', async () => {
      const sooner = new Date(NOW.getTime() + 60_000)
      const { service, repo } = build([makeRow({ expiresAt: sooner })])
      await service.rotate(KEY_ID, { overlapSeconds: 3600 })
      expect(repo.rows.get(KEY_ID)?.expiresAt).toEqual(sooner)
    })

    // An old expiry later than the overlap is shortened to the overlap.
    it('shortens an old key that expires later than the overlap', async () => {
      const later = new Date(NOW.getTime() + 10_000_000)
      const { service, repo } = build([makeRow({ expiresAt: later })])
      await service.rotate(KEY_ID, { overlapSeconds: 3600 })
      expect(repo.rows.get(KEY_ID)?.expiresAt).toEqual(new Date(NOW.getTime() + 3_600_000))
    })

    // The new key does not inherit the old expiry; it takes the one given.
    it('gives the new key the requested expiry only', async () => {
      const { service } = build([makeRow({ expiresAt: new Date(NOW.getTime() + 5000) })])
      const plain = await service.rotate(KEY_ID, { overlapSeconds: 0 })
      expect(plain.record.expiresAt).toBeNull()
      const { service: again } = build()
      const expiresAt = new Date(NOW.getTime() + 9000)
      const dated = await again.rotate(KEY_ID, { overlapSeconds: 0, expiresAt })
      expect(dated.record.expiresAt).toEqual(expiresAt)
    })

    // The replacement is created before the old key is retired, so a failure in between never
    // leaves the caller with neither.
    it('issues before it retires', async () => {
      const { service, repo } = build()
      await service.rotate(KEY_ID, { overlapSeconds: 0 })
      expect(repo.calls.indexOf('create')).toBeLessThan(repo.calls.indexOf('markRevoked'))
    })

    it.each([
      ['negative', -1],
      ['fractional', 1.5],
      ['not a number', Number.NaN],
      ['above the maximum', API_KEY_MAX_OVERLAP_SECONDS + 1]
    ])('refuses an overlap that is %s', async (_name, overlapSeconds) => {
      const { service, repo } = build()
      expect(await codeOf(service.rotate(KEY_ID, { overlapSeconds }))).toBe(
        AUTH_ERROR_CODES.VALIDATION
      )
      expect(repo.calls).toEqual([])
    })

    // The maximum itself is accepted.
    it('accepts the maximum overlap', async () => {
      const { service } = build()
      await expect(
        service.rotate(KEY_ID, { overlapSeconds: API_KEY_MAX_OVERLAP_SECONDS })
      ).resolves.toBeDefined()
    })

    it('refuses an expiry for the new key that is not in the future', async () => {
      const { service } = build()
      expect(await codeOf(service.rotate(KEY_ID, { overlapSeconds: 0, expiresAt: NOW }))).toBe(
        AUTH_ERROR_CODES.VALIDATION
      )
      expect(
        await detailsOf(service.rotate(KEY_ID, { overlapSeconds: 0, expiresAt: NOW }))
      ).toEqual([{ field: 'expiresAt', message: 'expiresAt must be a valid date in the future' }])
    })

    // The overlap failure names its field and the documented range.
    it('names the overlap field and the range', async () => {
      const { service } = build()
      expect(await detailsOf(service.rotate(KEY_ID, { overlapSeconds: -1 }))).toEqual([
        {
          field: 'overlapSeconds',
          message: `overlapSeconds must be an integer from 0 to ${API_KEY_MAX_OVERLAP_SECONDS}`
        }
      ])
    })

    // An id is a whole UUID: text before or after one is not an id, and never reaches the store.
    it.each([`x${KEY_ID}`, `${KEY_ID}x`, ` ${KEY_ID}`, KEY_ID.toUpperCase()])(
      'answers not found for the malformed id %j without a store call',
      async (id) => {
        const { service, repo } = build()
        expect(await codeOf(service.rotate(id, { overlapSeconds: 0 }))).toBe(
          AUTH_ERROR_CODES.API_KEY_NOT_FOUND
        )
        expect(await codeOf(service.revoke(id))).toBe(AUTH_ERROR_CODES.API_KEY_NOT_FOUND)
        expect(repo.calls).toEqual([])
      }
    )

    // A key nobody can use any more is not re-issued.
    it.each([
      ['unknown', 'unknown', []],
      ['malformed id', 'nope', [makeRow()]],
      ['revoked', KEY_ID, [makeRow({ revokedAt: new Date(NOW.getTime() - 1) })]],
      ['expired', KEY_ID, [makeRow({ expiresAt: new Date(NOW.getTime() - 1) })]]
    ])('answers not found for a %s key', async (_name, id, rows) => {
      const { service, repo } = build(rows)
      const target = id === 'unknown' ? '5a1d9e40-7b3c-4f6a-8c21-0e9d4b6a3f12' : id
      expect(await codeOf(service.rotate(target, { overlapSeconds: 0 }))).toBe(
        AUTH_ERROR_CODES.API_KEY_NOT_FOUND
      )
      expect(repo.calls).not.toContain('create')
    })

    // A key is active strictly before its revocation and expiry instants: AT either it is not.
    it.each([
      ['revokedAt', { revokedAt: NOW }],
      ['expiresAt', { expiresAt: NOW }]
    ])('answers not found for a key whose %s is exactly now', async (_name, patch) => {
      const { service } = build([makeRow(patch)])
      expect(await codeOf(service.rotate(KEY_ID, { overlapSeconds: 0 }))).toBe(
        AUTH_ERROR_CODES.API_KEY_NOT_FOUND
      )
    })

    // A key whose revocation or expiry lies in the future is still active and can be rotated.
    it('rotates a key whose revocation and expiry are still ahead', async () => {
      const ahead = new Date(NOW.getTime() + 1000)
      const { service } = build([makeRow({ revokedAt: ahead, expiresAt: ahead })])
      await expect(service.rotate(KEY_ID, { overlapSeconds: 0 })).resolves.toBeDefined()
    })
  })
})
