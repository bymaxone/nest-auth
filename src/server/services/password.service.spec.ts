/**
 * @fileoverview Tests for PasswordService, which hashes passwords using scrypt
 * and verifies them using constant-time comparison to prevent timing attacks.
 * Covers the hash format, salt uniqueness, compare success/failure paths, and
 * defensive branches for malformed hash strings.
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_BREACH_CHECKER, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { PasswordService } from './password.service'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

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
    it('should produce a string in scrypt:{N}:{r}:{p}:{salt_hex}:{derived_hex} format', async () => {
      const hash = await service.hash('password123')
      const parts = hash.split(':')
      expect(parts).toHaveLength(6)
      expect(parts[0]).toBe('scrypt')
      expect(Number(parts[1])).toBe(32_768)
      expect(Number(parts[2])).toBe(8)
      expect(Number(parts[3])).toBe(1)
      // 16-byte salt → 32 hex chars
      expect(parts[4]).toMatch(/^[0-9a-f]{32}$/)
      // 64-byte derived key → 128 hex chars
      expect(parts[5]).toMatch(/^[0-9a-f]{128}$/)
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

    // Scenario: a hash whose salt/derived are valid for the password but whose prefix is NOT
    // 'scrypt'; expected: compare returns false. Why: only the parts[0] === 'scrypt' clause
    // rejects it — replacing that clause with false would accept a non-scrypt algorithm tag and
    // return true, silently honouring an unsupported (potentially weaker) hash format.
    it('should return false for a 3-part hash whose payload is valid but prefix is not scrypt', async () => {
      const valid = await service.hash('correct-password')
      const wrongPrefix = valid.replace(/^scrypt:/, 'sha256:')
      // Sanity: still three parts, valid salt + derived, only the algorithm tag differs.
      expect(wrongPrefix.split(':')).toHaveLength(6)
      expect(await service.compare('correct-password', wrongPrefix)).toBe(false)
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
        /^scrypt:\d+:\d+:\d+:[0-9a-f]{32}:[0-9a-f]{128}$/
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

    // Scenario: hashes weaker than, equal to, and stronger than the configuration, plus a
    // value this library never writes. Expected: only the weaker ones and the unreadable one
    // are stale. Why: this is the signal that drives the transparent upgrade, and a false
    // positive here rewrites every user's hash on every login — a write on the hot path for
    // nothing.
    it('should report staleness only for weaker recorded parameters', async () => {
      const service = await serviceAt(32_768)
      const at = (n: number, r = 8, p = 1) =>
        `scrypt:${n}:${r}:${p}:${'a'.repeat(32)}:${'b'.repeat(128)}`

      expect(service.needsRehash(at(16_384))).toBe(true)
      expect(service.needsRehash(at(32_768))).toBe(false)
      expect(service.needsRehash(at(65_536))).toBe(false)
      expect(service.needsRehash(at(32_768, 4))).toBe(true)
      // The parameterless form this library used to write is not "stale", it is unreadable —
      // and with no deployments carrying one, there is nothing to keep a reader for.
      expect(service.needsRehash(`scrypt:${'a'.repeat(32)}:${'b'.repeat(128)}`)).toBe(false)
      // A malformed record is not stale, it is unreadable: it cannot be verified, and a
      // rewrite would require having verified it first. Refusing both is the consistent
      // answer — `compare` says false, `needsRehash` says nothing to do.
      expect(service.needsRehash(at(32_768, 8, 0))).toBe(false)
      // A value this library never wrote is not "stale" — it is not ours to rewrite.
      expect(service.needsRehash('not-a-hash')).toBe(false)
      expect(service.needsRehash(`bcrypt:1:1:1:${'a'.repeat(32)}:${'b'.repeat(128)}`)).toBe(false)
    })

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
