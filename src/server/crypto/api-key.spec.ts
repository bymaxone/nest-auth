import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import {
  API_KEY_DUMMY_DIGEST,
  API_KEY_DUMMY_KEY_ID,
  API_KEY_DUMMY_SECRET,
  apiKeyDigest,
  digestsMatch,
  formatApiKey,
  generateApiKeySecret,
  parseApiKey
} from './api-key'

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../../conformance/wire-contract.json'), 'utf8')
) as {
  apiKeys: {
    vector: { pepper: string; keyId: string; secret: string; key: string; digest: string }
  }
}
const vector = contract.apiKeys.vector

describe('api-key crypto', () => {
  describe('apiKeyDigest', () => {
    // Pins the digest function against the vector the shared contract carries, so the two
    // libraries cannot drift: a key issued by one must verify on the other.
    it('matches the conformance vector', () => {
      expect(apiKeyDigest(vector.secret, vector.pepper)).toBe(vector.digest)
    })

    // The pepper is the HMAC key: the same secret under another pepper is another digest.
    it('depends on the pepper', () => {
      expect(apiKeyDigest(vector.secret, `${vector.pepper}x`)).not.toBe(vector.digest)
    })
  })

  describe('formatApiKey / parseApiKey', () => {
    // The vector key is exactly prefix + id + secret joined by the separator.
    it('formats the conformance vector key', () => {
      expect(formatApiKey('bak', vector.keyId, vector.secret)).toBe(vector.key)
    })

    // A well-formed key parses back into its two parts.
    it('parses the conformance vector key', () => {
      expect(parseApiKey(vector.key, 'bak')).toEqual({
        keyId: vector.keyId,
        secret: vector.secret
      })
    })

    // The secret is base64url, whose alphabet contains the separator: parsing must split on the
    // first two separators only, so a secret holding `_` survives.
    it('keeps a secret that contains the separator', () => {
      const secret = `${'a_b-c'.repeat(8)}abc`
      expect(secret).toHaveLength(43)
      expect(parseApiKey(formatApiKey('bak', vector.keyId, secret), 'bak')).toEqual({
        keyId: vector.keyId,
        secret
      })
    })

    // Every malformed shape answers null, never throws: a refusal must not be distinguishable
    // from another by an exception.
    it.each([
      ['undefined', undefined],
      ['a number', 42],
      ['an array', [vector.key]],
      ['empty', ''],
      ['no separators', 'bakxyz'],
      ['one separator', `bak_${vector.keyId}`],
      [
        'a wrong separator after the key id',
        vector.key.replace(`${vector.keyId}_`, `${vector.keyId}-`)
      ],
      ['wrong prefix', vector.key.replace('bak_', 'xxx_')],
      ['prefix case', vector.key.replace('bak_', 'BAK_')],
      ['uppercase key id', vector.key.replace(vector.keyId, vector.keyId.toUpperCase())],
      ['short key id', vector.key.replace(vector.keyId, vector.keyId.slice(1))],
      ['non uuid key id', vector.key.replace(vector.keyId, 'z'.repeat(36))],
      ['short secret', vector.key.slice(0, -1)],
      ['long secret', `${vector.key}A`],
      ['padded secret', `${vector.key.slice(0, -1)}=`],
      ['secret with a space', `${vector.key.slice(0, -1)} `],
      ['leading space', ` ${vector.key}`],
      ['trailing newline', `${vector.key}\n`]
    ])('rejects %s', (_name, value) => {
      expect(parseApiKey(value, 'bak')).toBeNull()
    })

    // The prefix is deployment configuration, so another prefix is honoured and the default is not.
    it('honours a configured prefix', () => {
      const key = formatApiKey('svc', vector.keyId, vector.secret)
      expect(parseApiKey(key, 'svc')).not.toBeNull()
      expect(parseApiKey(key, 'bak')).toBeNull()
    })
  })

  describe('generateApiKeySecret', () => {
    // 32 random bytes, base64url, no padding: 43 characters from the alphabet the grammar accepts.
    it('produces a 43-character base64url secret', () => {
      const secret = generateApiKeySecret()
      expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/)
    })

    // Two draws never collide: it comes from the CSPRNG, not a counter or a clock.
    it('draws a fresh secret each time', () => {
      expect(generateApiKeySecret()).not.toBe(generateApiKeySecret())
    })

    // A generated secret is always accepted by the parser it will be presented to.
    it('round-trips through the parser', () => {
      const secret = generateApiKeySecret()
      expect(parseApiKey(formatApiKey('bak', vector.keyId, secret), 'bak')?.secret).toBe(secret)
    })
  })

  describe('digestsMatch', () => {
    // Equal digests match.
    it('accepts equal digests', () => {
      expect(digestsMatch(vector.digest, vector.digest)).toBe(true)
    })

    // A single differing nibble does not.
    it('rejects a differing digest', () => {
      expect(digestsMatch(vector.digest, `${vector.digest.slice(0, 63)}0`)).toBe(false)
    })

    // A stored value that is not a 32-byte digest (a corrupted row) must not throw — the
    // comparison API throws on unequal lengths — and must never match, even against itself.
    it.each([
      ['empty', ''],
      ['short', 'abcd'],
      ['long', `${vector.digest}00`],
      ['not hex', 'z'.repeat(64)]
    ])('never matches a %s stored value, even against itself', (_name, bad) => {
      expect(digestsMatch(vector.digest, bad)).toBe(false)
      expect(digestsMatch(bad, bad)).toBe(false)
    })
  })

  describe('dummies', () => {
    // The dummies stand in for a missing row: they must be well-formed so the same code path
    // runs, and the dummy digest must not equal the digest of the dummy secret under any pepper
    // the tests use, or an absent key could verify.
    it('are well-formed and cannot verify', () => {
      expect(
        parseApiKey(formatApiKey('bak', API_KEY_DUMMY_KEY_ID, API_KEY_DUMMY_SECRET), 'bak')
      ).not.toBeNull()
      expect(API_KEY_DUMMY_DIGEST).toMatch(/^[0-9a-f]{64}$/)
      expect(
        digestsMatch(apiKeyDigest(API_KEY_DUMMY_SECRET, vector.pepper), API_KEY_DUMMY_DIGEST)
      ).toBe(false)
    })
  })
})
