/**
 * MfaService.challengePlatformOnly — the platform challenge entry point.
 *
 * The challenge consumes the temp token, burns the TOTP code, stores a session, stamps the last
 * login and fires the hooks, so the plane has to be decided before any of that: a dashboard token
 * presented where only a platform one is acceptable is refused with nothing spent. Kept apart from
 * `mfa.service.spec.ts` because it is a separate responsibility and that file is already over the
 * size limit.
 */

import { createHash } from 'node:crypto'

import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { encrypt } from '../crypto/aes-gcm'
import { generateHotp, generateTotpSecret } from '../crypto/totp'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'
import { MfaService } from './mfa.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'

/** TEST FIXTURE ONLY: a structurally valid 32-byte AES-256-GCM key, not a credential. */
const VALID_ENCRYPTION_KEY = Buffer.from('nest-auth-test-encryption-key-32').toString('base64')

/** TEST FIXTURE ONLY: not a real JWT secret. */
const JWT_SECRET = 'nest-auth-test-jwt-secret-32chars+'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const PLATFORM_ADMIN = {
  id: 'admin-1',
  email: 'admin@platform.com',
  name: 'Platform Admin',
  role: 'super-admin',
  status: 'active',
  lastLoginAt: null,
  createdAt: new Date('2026-01-01'),
  updatedAt: new Date('2026-01-01'),
  passwordHash: 'hash',
  mfaEnabled: true,
  mfaRecoveryCodes: ['$scrypt$hashed$code1']
}

const PLATFORM_RESULT = {
  admin: { id: 'admin-1' },
  accessToken: 'platform.access.jwt',
  rawRefreshToken: 'platform-refresh'
}

const DASHBOARD_TOKEN = {
  userId: 'user-1',
  context: 'dashboard' as const,
  tenantId: 'tenant-1',
  jti: 'jti-dashboard'
}

const PLATFORM_TOKEN = { userId: 'admin-1', context: 'platform' as const, jti: 'jti-platform' }

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
const mockPasswordService = { hash: jest.fn(), compare: jest.fn() }
const mockEmailProvider = {
  sendMfaEnabledNotification: jest.fn(),
  sendMfaDisabledNotification: jest.fn()
}
const mockHooks = { afterLogin: jest.fn() }
const mockSessionService = { createSession: jest.fn(), revokeSession: jest.fn() }

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

/** Every collaborator through which a challenge could spend something. */
const SIDE_EFFECTS: ReadonlyArray<[string, jest.Mock]> = [
  ['brute-force check', mockBruteForce.isLockedOut],
  ['brute-force failure', mockBruteForce.recordFailure],
  ['brute-force reset', mockBruteForce.resetFailures],
  ['dashboard user read', mockUserRepo.findById],
  ['platform user read', mockPlatformUserRepo.findById],
  ['redis write', mockRedis.set],
  ['redis claim', mockRedis.setIfAbsent],
  ['TOTP anti-replay claim', mockRedis.setnx],
  ['redis delete', mockRedis.del],
  ['temp token consumption', mockTokenManager.consumeMfaTempToken],
  ['dashboard token issue', mockTokenManager.issueTokens],
  ['platform token issue', mockTokenManager.issuePlatformTokens],
  ['session creation', mockSessionService.createSession],
  ['dashboard last login', mockUserRepo.updateLastLogin],
  ['platform last login', mockPlatformUserRepo.updateLastLogin],
  ['afterLogin hook', mockHooks.afterLogin]
]

describe('MfaService.challengePlatformOnly', () => {
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
    mockBruteForce.resetFailures.mockResolvedValue(undefined)
    mockTokenManager.consumeMfaTempToken.mockResolvedValue(true)
    mockPlatformUserRepo.updateLastLogin.mockResolvedValue(undefined)
    mockHooks.afterLogin.mockResolvedValue(undefined)

    const module = await Test.createTestingModule({
      providers: [
        MfaService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
        { provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY, useValue: mockPlatformUserRepo },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: TokenManagerService, useValue: mockTokenManager },
        { provide: BruteForceService, useValue: mockBruteForce },
        { provide: PasswordService, useValue: mockPasswordService },
        { provide: SessionService, useValue: mockSessionService },
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
        { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
      ]
    }).compile()

    service = module.get(MfaService)
  })

  // Scenario: the temp token names the dashboard plane, and the code is a valid one. Expected:
  // PLATFORM_AUTH_REQUIRED, with the token read once and not one of the collaborators that spend
  // anything touched. Why: a refusal that arrives after the challenge has run leaves an orphan
  // session, a login stamp, hook calls and a spent token behind it.
  it('should refuse a dashboard-plane temp token with nothing spent', async () => {
    mockTokenManager.verifyMfaTempToken.mockResolvedValue(DASHBOARD_TOKEN)

    await expect(
      service.challengePlatformOnly('dashboard.temp.jwt', '123456', '1.2.3.4', 'ua')
    ).rejects.toMatchObject({
      response: { error: { code: AUTH_ERROR_CODES.PLATFORM_AUTH_REQUIRED } }
    })

    expect(mockTokenManager.verifyMfaTempToken).toHaveBeenCalledTimes(1)
    expect(mockTokenManager.verifyMfaTempToken).toHaveBeenCalledWith('dashboard.temp.jwt')
    for (const [, collaborator] of SIDE_EFFECTS) expect(collaborator).not.toHaveBeenCalled()
  })

  // Scenario: the token does not verify. Expected: the verifier's own error, nothing else.
  it('should propagate a temp token verification error with nothing spent', async () => {
    const error = new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
    mockTokenManager.verifyMfaTempToken.mockRejectedValue(error)

    await expect(
      service.challengePlatformOnly('bad.temp.jwt', '123456', '1.2.3.4', 'ua')
    ).rejects.toBe(error)

    for (const [, collaborator] of SIDE_EFFECTS) expect(collaborator).not.toHaveBeenCalled()
  })

  // Scenario: a platform token and a valid code. Expected: the platform result, and the token read
  // exactly once. Why: the entry point exists to decide the plane before the work, not to read the
  // token a second time inside the challenge.
  it('should complete a platform-plane challenge and verify the token once', async () => {
    const { base32 } = generateTotpSecret()
    const code = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))
    mockTokenManager.verifyMfaTempToken.mockResolvedValue(PLATFORM_TOKEN)
    mockPlatformUserRepo.findById.mockResolvedValue({
      ...PLATFORM_ADMIN,
      mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
    })
    mockTokenManager.issuePlatformTokens.mockResolvedValue(PLATFORM_RESULT)

    const result = await service.challengePlatformOnly('platform.temp.jwt', code, '1.2.3.4', 'ua')

    expect(result).toBe(PLATFORM_RESULT)
    expect(mockTokenManager.verifyMfaTempToken).toHaveBeenCalledTimes(1)
    expect(mockTokenManager.consumeMfaTempToken).toHaveBeenCalledWith('jti-platform')
  })
})
