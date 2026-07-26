/**
 * @fileoverview Tests for PasswordService, which hashes passwords using scrypt
 * and verifies them using constant-time comparison to prevent timing attacks.
 * Covers the hash format, salt uniqueness, compare success/failure paths, and
 * defensive branches for malformed hash strings.
 */

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
  })

  // ---------------------------------------------------------------------------
  // hash
  // ---------------------------------------------------------------------------

  describe('hash', () => {
    // Verifies that the hash output follows the expected wire format with correct hex segment lengths.
    it('should produce a string in scrypt:{salt_hex}:{derived_hex} format', async () => {
      const hash = await service.hash('password123')
      const parts = hash.split(':')
      expect(parts).toHaveLength(3)
      expect(parts[0]).toBe('scrypt')
      // 16-byte salt → 32 hex chars
      expect(parts[1]).toMatch(/^[0-9a-f]{32}$/)
      // 64-byte derived key → 128 hex chars
      expect(parts[2]).toMatch(/^[0-9a-f]{128}$/)
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
      expect(wrongPrefix.split(':')).toHaveLength(3)
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
        /^scrypt:[0-9a-f]{32}:[0-9a-f]{128}$/
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
    it('should run a real scrypt compare against a valid decoy hash', async () => {
      const spy = jest.spyOn(service, 'compare')
      await service.compareDummy('wrong-password')
      expect(spy).toHaveBeenCalledTimes(1)
      const [plain, hash] = spy.mock.calls[0] as [string, string]
      expect(plain).toBe('wrong-password')
      // Decoy is in the canonical scrypt wire format so `compare` reaches the scrypt
      // derivation (not the malformed-hash early return that would skip the work).
      expect(hash).toMatch(/^scrypt:[0-9a-f]{32}:[0-9a-f]{128}$/)
      spy.mockRestore()
    })
  })
})
