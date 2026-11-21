/**
 * @fileoverview A challenge that is refused for a locked account or a wrong code marks the refusal with the
 * plane of the token it verified, on both planes, so the shared route can count it where it belongs. The
 * answer the caller receives is unchanged. A token that does not verify names no plane and is not marked.
 *
 * @layer Test
 */

import { createHash } from 'node:crypto'

import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  GUARDED_PLATFORM_USER_REPOSITORY,
  GUARDED_USER_REPOSITORY
} from '../bymax-auth.constants'
import { encrypt } from '../crypto/aes-gcm'
import { generateHotp, generateTotpSecret } from '../crypto/totp'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { markedPlane } from '../observability/observed-outcome'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'
import { MFA_COLLABORATORS } from './__tests__/mfa-collaborators'
import { MfaService } from './mfa.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'

/** TEST FIXTURE ONLY: a structurally valid 32-byte AES-256-GCM key, not a credential. */
const VALID_ENCRYPTION_KEY = Buffer.from('nest-auth-test-encryption-key-32').toString('base64')
const JWT_SECRET = 'nest-auth-test-jwt-secret-32chars+'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const TOKENS = {
  dashboard: {
    userId: 'user-1',
    context: 'dashboard' as const,
    tenantId: 'tenant-1',
    jti: 'jti-d'
  },
  platform: { userId: 'admin-1', context: 'platform' as const, jti: 'jti-p' }
}

const mockUserRepo = { findById: jest.fn(), updateMfa: jest.fn(), updateLastLogin: jest.fn() }
const mockPlatformUserRepo = {
  findById: jest.fn(),
  updateMfa: jest.fn(),
  updateLastLogin: jest.fn()
}
const mockRedis = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  getdel: jest.fn(),
  setnx: jest.fn(),
  sadd: jest.fn(),
  srem: jest.fn(),
  expire: jest.fn(),
  setIfAbsent: jest.fn(),
  eval: jest.fn(),
  invalidateUserSessions: jest.fn(),
  bumpUserTokenEpoch: jest.fn()
}
const mockTokenManager = {
  verifyMfaTempToken: jest.fn(),
  consumeMfaTempToken: jest.fn(),
  issueTokens: jest.fn(),
  issuePlatformTokens: jest.fn()
}
const mockBruteForce = {
  isLockedOut: jest.fn(),
  recordFailure: jest.fn(),
  resetFailures: jest.fn()
}
const mockOptions = {
  jwt: { secret: JWT_SECRET },
  hmacKey: HMAC_KEY,
  previousHmacKeys: [],
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED'],
  mfa: {
    encryptionKey: VALID_ENCRYPTION_KEY,
    issuer: 'TestApp',
    totpWindow: 1,
    recoveryCodeCount: 2
  },
  sessions: { enabled: true, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
}

/** The error a challenge rejects with. */
async function refusalOf(call: Promise<unknown>): Promise<AuthException> {
  const error: unknown = await call.then(
    () => undefined,
    (rejected: unknown) => rejected
  )
  if (!(error instanceof AuthException)) throw new Error('expected an AuthException')
  return error
}

/** The code an exception answers with. */
function codeOf(error: AuthException): unknown {
  return (error.getResponse() as { error: { code: string } }).error.code
}

describe('MfaService.challenge — the plane of a refusal', () => {
  let service: MfaService

  beforeEach(async () => {
    jest.resetAllMocks()
    mockRedis.get.mockResolvedValue(null)
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.del.mockResolvedValue(true)
    mockRedis.setIfAbsent.mockResolvedValue(true)
    mockRedis.setnx.mockResolvedValue(true)
    mockBruteForce.isLockedOut.mockResolvedValue(false)
    mockBruteForce.recordFailure.mockResolvedValue(undefined)
    mockTokenManager.consumeMfaTempToken.mockResolvedValue(true)

    const module = await Test.createTestingModule({
      providers: [
        MfaService,
        ...MFA_COLLABORATORS,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: GUARDED_USER_REPOSITORY, useValue: mockUserRepo },
        { provide: GUARDED_PLATFORM_USER_REPOSITORY, useValue: mockPlatformUserRepo },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: TokenManagerService, useValue: mockTokenManager },
        { provide: BruteForceService, useValue: mockBruteForce },
        { provide: PasswordService, useValue: { hash: jest.fn(), compare: jest.fn() } },
        {
          provide: SessionService,
          useValue: { createSession: jest.fn(), revokeSession: jest.fn() }
        },
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: {} },
        { provide: BYMAX_AUTH_HOOKS, useValue: {} }
      ]
    }).compile()
    service = module.get(MfaService)
  })

  /** Arranges the account of the plane, with a TOTP secret the submitted code will not match. */
  function arrange(plane: 'dashboard' | 'platform', base32 = generateTotpSecret().base32): void {
    const account = {
      id: plane === 'dashboard' ? 'user-1' : 'admin-1',
      ...(plane === 'dashboard' ? { tenantId: 'tenant-1' } : {}),
      email: 'a@example.com',
      name: 'A',
      role: 'member',
      status: 'active',
      mfaEnabled: true,
      mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
      mfaRecoveryCodes: [],
      passwordHash: 'hash',
      lastLoginAt: null,
      createdAt: new Date('2026-01-01'),
      updatedAt: new Date('2026-01-01')
    }
    mockTokenManager.verifyMfaTempToken.mockResolvedValue(TOKENS[plane])
    ;(plane === 'dashboard' ? mockUserRepo : mockPlatformUserRepo).findById.mockResolvedValue(
      account
    )
  }

  // Scenario: an account at its failure ceiling, on each plane. Expected: ACCOUNT_LOCKED, marked with the
  // plane of the token, with the same answer an unmarked refusal gives.
  it.each(['dashboard', 'platform'] as const)(
    'marks a locked %s account with its plane',
    async (plane) => {
      arrange(plane)
      mockBruteForce.isLockedOut.mockResolvedValue(true)

      const error = await refusalOf(service.challenge('temp.jwt', '123456', '1.2.3.4', 'ua'))

      expect(codeOf(error)).toBe(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
      expect(markedPlane(error)).toBe(plane)
    }
  )

  // Scenario: a wrong code, on each plane. Expected: MFA_INVALID_CODE, marked with the plane.
  it.each(['dashboard', 'platform'] as const)(
    'marks a wrong code on %s with its plane',
    async (plane) => {
      arrange(plane)

      const error = await refusalOf(service.challenge('temp.jwt', '000000', '1.2.3.4', 'ua'))

      expect(codeOf(error)).toBe(AUTH_ERROR_CODES.MFA_INVALID_CODE)
      expect(markedPlane(error)).toBe(plane)
    }
  )

  // Scenario: two submissions race and this one loses the consume of the temp token, on each plane. Expected:
  // MFA_TEMP_TOKEN_INVALID, marked with the plane of the token. Why: the token verified, so the plane is known.
  it.each(['dashboard', 'platform'] as const)(
    'marks a lost temp-token consume on %s with its plane',
    async (plane) => {
      const { base32 } = generateTotpSecret()
      arrange(plane, base32)
      mockTokenManager.consumeMfaTempToken.mockResolvedValue(false)
      const code = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const error = await refusalOf(service.challenge('temp.jwt', code, '1.2.3.4', 'ua'))

      expect(codeOf(error)).toBe(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
      expect(markedPlane(error)).toBe(plane)
    }
  )

  // Scenario: every other way a challenge for a verified token can end, on each plane: the account cannot be
  // loaded, MFA is not enabled on it, and issuing the session fails. Expected: the refusal carries the plane,
  // whatever its code. Why: the plane is established once the token verifies, so a refusal added to the flow
  // later is marked by being inside it.
  describe.each(['dashboard', 'platform'] as const)('on %s', (plane) => {
    const repo = (): typeof mockUserRepo =>
      plane === 'dashboard' ? mockUserRepo : mockPlatformUserRepo

    it('marks an account that cannot be loaded', async () => {
      arrange(plane)
      repo().findById.mockResolvedValue(null)

      const error = await refusalOf(service.challenge('temp.jwt', '123456', '1.2.3.4', 'ua'))

      expect(markedPlane(error)).toBe(plane)
    })

    it('marks an account without MFA', async () => {
      arrange(plane)
      repo().findById.mockResolvedValue({ ...(await repo().findById()), mfaEnabled: false })

      const error = await refusalOf(service.challenge('temp.jwt', '123456', '1.2.3.4', 'ua'))

      expect(codeOf(error)).toBe(AUTH_ERROR_CODES.MFA_NOT_ENABLED)
      expect(markedPlane(error)).toBe(plane)
    })

    it('marks a session that cannot be issued', async () => {
      const { base32 } = generateTotpSecret()
      arrange(plane, base32)
      const failure = new AuthException(AUTH_ERROR_CODES.SERVICE_UNAVAILABLE)
      mockTokenManager.issueTokens.mockRejectedValue(failure)
      mockTokenManager.issuePlatformTokens.mockRejectedValue(failure)
      const code = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const error = await refusalOf(service.challenge('temp.jwt', code, '1.2.3.4', 'ua'))

      expect(error).toBe(failure)
      expect(markedPlane(error)).toBe(plane)
    })
  })

  // Scenario: a temp token that does not verify. Expected: the verifier's own error, unmarked: no plane has
  // been established.
  it('leaves a token that does not verify unmarked', async () => {
    const failure = new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
    mockTokenManager.verifyMfaTempToken.mockRejectedValue(failure)

    const error = await refusalOf(service.challenge('bad.jwt', '123456', '1.2.3.4', 'ua'))

    expect(error).toBe(failure)
    expect(markedPlane(error)).toBeUndefined()
  })
})
