/**
 * @fileoverview Tests for PasswordService, which hashes passwords using scrypt
 * and verifies them using constant-time comparison to prevent timing attacks.
 * Covers the hash format, salt uniqueness, compare success/failure paths, and
 * defensive branches for malformed hash strings.
 */

import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-one-nest-auth.constants'
import { PasswordService } from './password.service'

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
      providers: [PasswordService, { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions }]
    }).compile()

    service = module.get(PasswordService)
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
})
