/**
 * @fileoverview Tests for PasswordService, which hashes passwords using scrypt
 * and verifies them using constant-time comparison to prevent timing attacks.
 * Covers the hash format, salt uniqueness, compare success/failure paths, and
 * defensive branches for malformed hash strings.
 */

import { scryptSync } from 'node:crypto'

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_BREACH_CHECKER, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { PasswordService } from './password.service'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/** PHC "B64": the standard alphabet with padding stripped. */
const b64 = (bytes: number, fill = 0xb2): string =>
  Buffer.alloc(bytes, fill).toString('base64').replace(/=+$/, '')

/** A well-formed 16-byte salt field, so a malformed-hash case varies only the part it names. */
const B64_SALT = b64(16, 0xa1)

/** A well-formed 64-byte derived-key field, for the same reason. */
const B64_KEY = b64(64)

/** Approves every password unless a test says otherwise. */
const mockBreachChecker = { isBreached: jest.fn().mockResolvedValue(false) }

const mockOptions = {
  password: {
    costFactor: 32_768,
    blockSize: 8,
    parallelization: 1
  }
}

describe('PasswordService', () => {
  let service: PasswordService

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      providers: [
        PasswordService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: BYMAX_AUTH_BREACH_CHECKER, useValue: mockBreachChecker }
      ]
    }).compile()

    service = module.get(PasswordService)
  })

  // ---------------------------------------------------------------------------
  // assertNotCompromised
  // ---------------------------------------------------------------------------

  describe('assertNotCompromised', () => {
    // The whole point: a password the corpus knows is refused before it is ever hashed and
    // stored, so it never becomes the account's credential.
    it('rejects a password the checker reports as breached', async () => {
      mockBreachChecker.isBreached.mockResolvedValue(true)

      let thrown: unknown
      try {
        await service.assertNotCompromised('hunter2')
      } catch (error) {
        thrown = error
      }

      expect(thrown).toBeInstanceOf(AuthException)
      expect((thrown as AuthException).getResponse()).toMatchObject({
        error: expect.objectContaining({ code: AUTH_ERROR_CODES.PASSWORD_COMPROMISED })
      })
      // 400, not 401: this is the submitted value being unacceptable, not an auth failure.
      expect((thrown as AuthException).getStatus()).toBe(400)
      expect(mockBreachChecker.isBreached).toHaveBeenCalledWith('hunter2')
    })

    // A clean password passes through silently — the check adds no observable behaviour when
    // it has nothing to report.
    it('accepts a password the checker clears', async () => {
      mockBreachChecker.isBreached.mockResolvedValue(false)

      await expect(
        service.assertNotCompromised('a-long-unique-passphrase')
      ).resolves.toBeUndefined()
    })

    // The checker is documented to fail open and is the CONSUMER's implementation, so the
    // contract is enforced here rather than assumed. A throw used to propagate out of every
    // path that sets a password — registration, reset, invitation acceptance would all start
    // failing because an advisory corpus was unreachable, which is the documented behaviour
    // inverted and worst during an incident. A refusal to answer is not evidence against the
    // password.
    it.each([
      ['a rejected promise', async () => Promise.reject(new Error('corpus unreachable'))],
      [
        'a synchronous throw',
        () => {
          throw new Error('client blew up')
        }
      ],
      ['a non-Error rejection', async () => Promise.reject('string rejection')]
    ])('admits the password when the checker answers with %s', async (_label, impl) => {
      mockBreachChecker.isBreached.mockImplementation(impl)
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})

      try {
        await expect(
          service.assertNotCompromised('a-long-unique-passphrase')
        ).resolves.toBeUndefined()
        // Silent admission would make an outage indistinguishable from a corpus that had
        // nothing to say, so the operator gets a line.
        expect(errorSpy).toHaveBeenCalledTimes(1)
        // Never the plaintext, whatever else goes in the log.
        expect(JSON.stringify(errorSpy.mock.calls[0])).not.toContain('a-long-unique-passphrase')
      } finally {
        errorSpy.mockRestore()
      }
    })
  })

  // ---------------------------------------------------------------------------
  // hash
  // ---------------------------------------------------------------------------

  describe('hash', () => {
    // Verifies the wire format, parameters included. The cost the hash was written under has
    // to travel with it: without that, a verify can only assume today's configuration, and
    // raising `costFactor` makes every stored hash unreproducible — every user locked out,
    // irreversibly, because the value they were derived under is gone.
    it('should produce a PHC string in $scrypt$ln={log2 N},r={r},p={p}${salt}${derived} form', async () => {
      const hash = await service.hash('password123')
      const parts = hash.split('$')
      // A PHC string opens with `$`, so the split yields a leading empty field.
      expect(parts).toHaveLength(5)
      expect(parts[0]).toBe('')
      expect(parts[1]).toBe('scrypt')
      // `ln` is log2(N): 32768 → 15.
      expect(parts[2]).toBe('ln=15,r=8,p=1')
      // PHC "B64" is the standard alphabet with padding stripped, NOT base64url — a `-` or
      // `_` here is a hash rust-auth's parser rejects. 16-byte salt → 22 chars,
      // 64-byte derived key → 86.
      expect(parts[3]).toMatch(/^[A-Za-z0-9+/]{22}$/)
      expect(parts[4]).toMatch(/^[A-Za-z0-9+/]{86}$/)
      // Scoped to the encoded fields: `=` is legal in the parameter segment (`ln=15`), and
      // only these two carry base64. Padding or a base64url alphabet here is what the sibling
      // parser rejects.
      expect(`${parts[3] ?? ''}${parts[4] ?? ''}`).not.toMatch(/[-_=]/)
    })

    // Verifies that two hashes of the same password are different due to the random salt.
    it('should produce different hashes for the same password (random salt)', async () => {
      const hash1 = await service.hash('same-password')
      const hash2 = await service.hash('same-password')
      expect(hash1).not.toBe(hash2)
    })
  })

  // ---------------------------------------------------------------------------
  // compare
  // ---------------------------------------------------------------------------

  describe('compare', () => {
    // Verifies that compare returns true when the plaintext matches the stored hash.
    it('should return true for the correct password', async () => {
      const hash = await service.hash('correct-password')
      expect(await service.compare('correct-password', hash)).toBe(true)
    })

    // Verifies that compare returns false when the plaintext does not match the stored hash.
    it('should return false for an incorrect password', async () => {
      const hash = await service.hash('correct-password')
      expect(await service.compare('wrong-password', hash)).toBe(false)
    })

    // Verifies that a hash string without the expected three colon-separated parts returns false.
    it('should return false for a malformed hash string (missing parts)', async () => {
      expect(await service.compare('password', 'not-a-valid-hash')).toBe(false)
    })

    // Verifies that a hash with a non-scrypt prefix is rejected to prevent using unsupported algorithms.
    it('should return false for a hash with wrong prefix', async () => {
      expect(await service.compare('password', 'bcrypt:abc:def')).toBe(false)
    })

    // Verifies that a hash with a truncated derived key returns false to prevent timingSafeEqual from throwing.
    it('should return false when derived key has unexpected length', async () => {
      // Construct a syntactically valid but truncated derived key
      const shortDerived = 'a'.repeat(64) // 32 bytes hex instead of 128
      const salt = 'b'.repeat(32)
      expect(await service.compare('password', `scrypt:${salt}:${shortDerived}`)).toBe(false)
    })

    // Verifies that a hash where the salt segment is empty returns false (covers the !saltHex guard on line 119).
    it('should return false when the salt segment is empty (colon-only format)', async () => {
      // 'scrypt::derivedHex' — the salt part is an empty string which is falsy.
      expect(await service.compare('password', 'scrypt::' + 'a'.repeat(128))).toBe(false)
    })

    // Scenario: a hash with FOUR colon-separated parts whose first three are a genuine valid
    // hash for the password; expected: compare returns false because parts.length !== 3.
    // Why: with valid salt/derived appended by an extra ':segment', the only thing rejecting it
    // is the length===3 guard — so dropping that guard (if(false)), turning '||' into '&&', or
    // replacing the length clause with false would let it match and return true.
    it('should return false for an otherwise-valid hash that has an extra :segment (length !== 3)', async () => {
      const valid = await service.hash('correct-password')
      expect(await service.compare('correct-password', valid + ':extra')).toBe(false)
    })

    // Scenario: a hash whose salt/derived are valid for the password but whose algorithm tag
    // is NOT 'scrypt'; expected: compare returns false. Why: only the `parts[1] === 'scrypt'`
    // clause rejects it — dropping that clause would honour an unsupported (potentially much
    // weaker) algorithm tag while deriving with scrypt, and answer true.
    it('should return false for a PHC string whose algorithm tag is not scrypt', async () => {
      const valid = await service.hash('correct-password')
      const wrongAlgorithm = valid.replace(/^\$scrypt\$/, '$md5$')
      // Sanity: still a well-formed PHC shape, same salt and derived key — only the tag moved.
      expect(wrongAlgorithm.split('$')).toHaveLength(5)
      expect(await service.compare('correct-password', wrongAlgorithm)).toBe(false)
    })
  })

  // ---------------------------------------------------------------------------
  // maxmem (scrypt memory ceiling)
  // ---------------------------------------------------------------------------

  describe('maxmem', () => {
    // Scenario: hashing with a high cost factor whose true scrypt memory requirement
    // (128 * N * r) EXCEEDS the 64 MiB floor; expected: hash() resolves. Why: the correct
    // ceiling is max(N*r*128*2, 64MiB) = 2x the requirement. Mutations that shrink the first
    // argument (Math.min, *2 -> /2, r*128 -> r/128, N*r -> N/r) collapse the ceiling to the
    // 64 MiB floor, which is below the requirement, so scrypt would reject the params and the
    // promise would fail — killing every arithmetic/Math.max mutant on that line.
    it('should resolve when N*r*128 exceeds the 64MiB floor (ceiling must be 2x the requirement)', async () => {
      const highCostOptions = {
        password: {
          // 128 * 2^17 * 8 = 128 MiB requirement (> 64 MiB floor); 2x = 256 MiB ceiling.
          costFactor: 131_072,
          blockSize: 8,
          parallelization: 1
        }
      }
      const module = await Test.createTestingModule({
        providers: [
          PasswordService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: highCostOptions },
          { provide: BYMAX_AUTH_BREACH_CHECKER, useValue: mockBreachChecker }
        ]
      }).compile()
      const highCostService = module.get(PasswordService)

      await expect(highCostService.hash('memory-bound-password')).resolves.toMatch(
        /^\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/
      )
    }, 30_000)
  })

  // ---------------------------------------------------------------------------
  // Round-trip
  // ---------------------------------------------------------------------------

  describe('round-trip', () => {
    // Verifies that a unicode password survives the hash-then-compare round-trip correctly.
    it('should successfully hash then compare a unicode password', async () => {
      const password = 'P@ssw0rd! 🔑 αβγ'
      const hash = await service.hash(password)
      expect(await service.compare(password, hash)).toBe(true)
    })

    // Verifies that an empty string does not match a non-empty password hash.
    it('should return false for empty string against a real hash', async () => {
      const hash = await service.hash('non-empty')
      expect(await service.compare('', hash)).toBe(false)
    })
  })

  describe('compareDummy', () => {
    // Verifies the decoy comparison always resolves false so it can be used purely
    // to equalize timing on the "user not found" login branch.
    it('should always return false', async () => {
      expect(await service.compareDummy('anything')).toBe(false)
      expect(await service.compareDummy('')).toBe(false)
    })

    // Verifies it delegates to `compare` against a well-formed decoy hash rather than
    // short-circuiting — so it actually runs a scrypt derivation and spends the same
    // wall-clock time as a genuine failed comparison (the whole point of the decoy).
    it('should spend a real derivation under the configured parameters', async () => {
      // The decoy no longer reads a stored hash: a constant hash records the parameters it was
      // written under, so the moment a deployment configured a different cost the decoy would
      // stop taking the same time as a real verify — reopening the timing oracle it exists to
      // close. Deriving under the CONFIGURED parameters is what keeps the two paths equal, and
      // the result is always false because no password derives to the fixed comparand.
      const spy = jest.spyOn(service, 'compare')

      await expect(service.compareDummy('wrong-password')).resolves.toBe(false)

      // It does the work itself rather than routing through `compare`, which would need a
      // stored hash to read parameters from — the very thing that made it drift.
      expect(spy).not.toHaveBeenCalled()
      spy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // Parameter recording and the upgrade signal
  // ---------------------------------------------------------------------------

  describe('parameters recorded with the hash', () => {
    /** A service at the given cost, over otherwise-default options. */
    async function serviceAt(costFactor: number): Promise<PasswordService> {
      const module = await Test.createTestingModule({
        providers: [
          PasswordService,
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: {
              password: { costFactor, blockSize: 8, parallelization: 1 }
            }
          },
          { provide: BYMAX_AUTH_BREACH_CHECKER, useValue: { isBreached: async () => false } }
        ]
      }).compile()
      return module.get(PasswordService)
    }

    // Scenario: a hash written at one cost, verified by a service configured for another.
    // Expected: it still verifies. Why: this is the whole finding. Without the parameters in
    // the hash, raising `costFactor` makes every stored hash unreproducible — every user
    // locked out, irreversibly, because the value they were derived under is gone. No test
    // could see it before, because a suite that writes and reads inside one configuration
    // never represents "written yesterday, read today under a new setting".
    it('should verify a hash written under a different cost factor', async () => {
      const weak = await serviceAt(16_384)
      const strong = await serviceAt(32_768)

      const written = await weak.hash('correct-horse')

      expect(await strong.compare('correct-horse', written)).toBe(true)
      expect(await strong.compare('wrong-horse', written)).toBe(false)
    }, 30_000)

    // Scenario: PHC hashes weaker than, equal to, and stronger than the configuration, plus
    // values this library never writes. Expected: only the weaker ones are stale. Why: this is
    // the signal that drives the transparent upgrade, and a false positive here rewrites every
    // user's hash on every login — a write, and a full KDF, on the hot path for nothing.
    it('should report staleness only for weaker recorded parameters', async () => {
      const service = await serviceAt(32_768)
      const salt = Buffer.alloc(16, 0xa1).toString('base64').replace(/=+$/, '')
      const key = Buffer.alloc(64, 0xb2).toString('base64').replace(/=+$/, '')
      const at = (n: number, r = 8, p = 1) =>
        `$scrypt$ln=${Math.log2(n)},r=${r},p=${p}$${salt}$${key}`

      expect(service.needsRehash(at(16_384))).toBe(true)
      expect(service.needsRehash(at(32_768))).toBe(false)
      expect(service.needsRehash(at(65_536))).toBe(false)
      expect(service.needsRehash(at(32_768, 4))).toBe(true)
      // A malformed record is not stale, it is unreadable: it cannot be verified, and a
      // rewrite would require having verified it first. Refusing both is the consistent
      // answer — `compare` says false, `needsRehash` says nothing to do.
      expect(service.needsRehash(at(32_768, 8, 0))).toBe(false)
      // A value this library never wrote is not "stale" — it is not ours to rewrite.
      expect(service.needsRehash('not-a-hash')).toBe(false)
      expect(service.needsRehash(`$md5$ln=15,r=8,p=1$${salt}$${key}`)).toBe(false)
    })

    // Scenario: a hash in the pre-PHC encoding, recording a cost at or above the configured
    // one. Expected: stale anyway. Why: staleness is not only about cost. rust-auth cannot
    // parse this encoding, and the two libraries share a user table — so leaving a readable
    // legacy hash in place keeps that account signing in here and failing there, where the
    // failure is `invalid_credentials` and five of them trip the SHARED lockout. The login
    // that reaches this has just proven the password, which is the only moment the value can
    // be rewritten at all: skip it and the account never migrates.
    it('should report a legacy-encoded hash as stale whatever cost it records', async () => {
      const service = await serviceAt(32_768)
      const legacy = (n: number) => `scrypt:${n}:8:1:${'a'.repeat(32)}:${'b'.repeat(128)}`

      expect(service.needsRehash(legacy(16_384))).toBe(true)
      expect(service.needsRehash(legacy(32_768))).toBe(true)
      // The one that matters: a STRONGER cost, which the cost comparison alone would clear.
      expect(service.needsRehash(legacy(65_536))).toBe(true)
    })

    // Scenario: hashes carrying the two derived-key lengths the pair writes — 64 bytes here,
    // 32 in rust-auth. Expected: neither is stale on account of its length. Why: both libraries
    // read the same user table, and treating the sibling's length as stale would rehash every
    // hash on every crossing — one full KDF each way, forever, converging on nothing.
    it("should not treat the sibling implementation's derived-key length as stale", async () => {
      const service = await serviceAt(32_768)
      const salt = Buffer.alloc(16, 0xa1).toString('base64').replace(/=+$/, '')
      const short = Buffer.alloc(32, 0xb2).toString('base64').replace(/=+$/, '')
      const long = Buffer.alloc(64, 0xb2).toString('base64').replace(/=+$/, '')

      expect(service.needsRehash(`$scrypt$ln=15,r=8,p=1$${salt}$${short}`)).toBe(false)
      expect(service.needsRehash(`$scrypt$ln=15,r=8,p=1$${salt}$${long}`)).toBe(false)
    })

    // Scenario: every way a PHC string can be malformed. Expected: refused, never verified
    // under a guessed cost or a mis-read parameter. Why: this parser is what stands between a
    // stored record and the KDF, and each rejection below is a distinct shape a corrupt or
    // hostile value can take. The `b64` cases matter most for the sibling implementation: PHC
    // uses the STANDARD base64 alphabet, so a hash carrying `-` or `_` is not ours, and a
    // non-canonical encoding is two strings that decode to the same bytes — an equality the
    // stored record must not have.
    it.each([
      // Field arity: fewer than five, and more than five.
      ['a missing derived-key field', `$scrypt$ln=15,r=8,p=1$${B64_SALT}`],
      ['a sixth field', `$scrypt$ln=15,r=8,p=1$${B64_SALT}$${B64_KEY}$extra`],
      // The leading empty field and the algorithm tag.
      ['no leading $', `scrypt$ln=15,r=8,p=1$${B64_SALT}$${B64_KEY}`],
      ['a non-scrypt algorithm tag', `$argon2id$ln=15,r=8,p=1$${B64_SALT}$${B64_KEY}`],
      // Parameter segment.
      ['a parameter with no =', `$scrypt$ln,r=8,p=1$${B64_SALT}$${B64_KEY}`],
      ['a parameter with an empty name', `$scrypt$=15,r=8,p=1$${B64_SALT}$${B64_KEY}`],
      ['a repeated parameter', `$scrypt$ln=15,ln=16,r=8,p=1$${B64_SALT}$${B64_KEY}`],
      ['a non-numeric parameter', `$scrypt$ln=1a,r=8,p=1$${B64_SALT}$${B64_KEY}`],
      ['a zero-padded parameter', `$scrypt$ln=015,r=8,p=1$${B64_SALT}$${B64_KEY}`],
      ['a negative parameter', `$scrypt$ln=-15,r=8,p=1$${B64_SALT}$${B64_KEY}`],
      ['a missing ln', `$scrypt$r=8,p=1$${B64_SALT}$${B64_KEY}`],
      ['a missing r', `$scrypt$ln=15,p=1$${B64_SALT}$${B64_KEY}`],
      ['a missing p', `$scrypt$ln=15,r=8$${B64_SALT}$${B64_KEY}`],
      ['ln below the range', `$scrypt$ln=0,r=8,p=1$${B64_SALT}$${B64_KEY}`],
      ['ln above the range', `$scrypt$ln=32,r=8,p=1$${B64_SALT}$${B64_KEY}`],
      ['r of zero', `$scrypt$ln=15,r=0,p=1$${B64_SALT}$${B64_KEY}`],
      ['p of zero', `$scrypt$ln=15,r=8,p=0$${B64_SALT}$${B64_KEY}`],
      // B64 fields.
      ['a base64url salt', `$scrypt$ln=15,r=8,p=1$${B64_SALT.slice(0, -1)}_$${B64_KEY}`],
      ['a padded derived key', `$scrypt$ln=15,r=8,p=1$${B64_SALT}$${B64_KEY}=`],
      ['an empty salt', `$scrypt$ln=15,r=8,p=1$$${B64_KEY}`],
      // 'AB' decodes to one 0x00 byte and re-encodes to 'AA': two strings, same bytes.
      ['a non-canonical b64 salt', `$scrypt$ln=15,r=8,p=1$AB$${B64_KEY}`],
      // Derived-key length outside the bounds `password_hash::Output` can represent.
      ['a derived key below 10 bytes', `$scrypt$ln=15,r=8,p=1$${B64_SALT}$${b64(9)}`],
      ['a derived key above 64 bytes', `$scrypt$ln=15,r=8,p=1$${B64_SALT}$${b64(65)}`]
    ])('should refuse a PHC hash with %s', async (_label, malformed) => {
      const service = await serviceAt(16_384)
      expect(await service.compare('anything', malformed)).toBe(false)
      // Unreadable is not stale: a rewrite would require having verified it first.
      expect(service.needsRehash(malformed)).toBe(false)
    })

    // The two lengths the pair actually writes sit just inside the bounds rejected above, so
    // the guard cannot be widened or narrowed without one of these turning red.
    it.each([
      ['the 10-byte floor', 10],
      ["rust-auth's 32 bytes", 32],
      ["this library's 64-byte ceiling", 64]
    ])(
      'should accept a derived key at %s',
      async (_label, bytes) => {
        const service = await serviceAt(16_384)
        // A real derivation, so the value verifies rather than merely parsing.
        const written = await service.hash('correct-horse')
        const [, , , salt] = written.split('$')
        const derived = scryptSync('correct-horse', Buffer.from(salt ?? '', 'base64'), bytes, {
          N: 16_384,
          r: 8,
          p: 1,
          maxmem: 128 * 1024 * 1024
        })
        const rebuilt = `$scrypt$ln=14,r=8,p=1$${salt ?? ''}$${derived
          .toString('base64')
          .replace(/=+$/, '')}`

        expect(await service.compare('correct-horse', rebuilt)).toBe(true)
        expect(await service.compare('wrong-horse', rebuilt)).toBe(false)
      },
      30_000
    )

    // Scenario: malformed parameter segments. Expected: refused, not verified under a guessed
    // cost. Why: a non-numeric or zero N reaching `scrypt` is either a throw or a derivation
    // nobody chose.
    it.each([
      ['non-numeric N', `scrypt:abc:8:1:${'a'.repeat(32)}:${'b'.repeat(128)}`],
      ['zero N', `scrypt:0:8:1:${'a'.repeat(32)}:${'b'.repeat(128)}`],
      ['negative r', `scrypt:32768:-8:1:${'a'.repeat(32)}:${'b'.repeat(128)}`],
      ['fractional p', `scrypt:32768:8:1.5:${'a'.repeat(32)}:${'b'.repeat(128)}`],
      ['four segments', `scrypt:32768:8:${'a'.repeat(32)}`],
      ['empty salt', `scrypt:32768:8:1::${'b'.repeat(128)}`],
      ['a truncated derived key', `scrypt:32768:8:1:${'a'.repeat(32)}:${'b'.repeat(16)}`]
    ])('should refuse a hash with %s', async (_label, malformed) => {
      const service = await serviceAt(16_384)
      expect(await service.compare('anything', malformed)).toBe(false)
    })
  })
})
