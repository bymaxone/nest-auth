/**
 * AuthService — a refused write of the email-verification code.
 *
 * The code is stored after the account is created, so a store that refuses it is not a reason to
 * answer an error for an account that exists. Registration and the resend route answer as they do
 * when the write succeeds, no email carries a code that was not stored, and one log line with a
 * closed code records the refusal. Kept apart from `auth.service.spec.ts` because that file is
 * already over the size limit.
 */

import { createHash } from 'node:crypto'

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import type { Request } from 'express'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  GUARDED_USER_REPOSITORY
} from '../bymax-auth.constants'
import { hmacSha256 } from '../crypto/secure-token'
import { AuthRedisService } from '../redis/auth-redis.service'
import { AccountStatusService } from './account-status.service'
import { AuthService } from './auth.service'
import { BruteForceService } from './brute-force.service'
import { OtpService } from './otp.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'
import { AUTH_LOG_EVENTS } from '../observability/log-events'

const JWT_SECRET = 'test-jwt-secret-for-hmac-that-is-at-least-32-chars-long'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const EMAIL = 'new.user@example.com'
const USER_ID = 'user-4242'
const CODE = '918273'
const USER = { id: USER_ID, email: EMAIL, tenantId: 'tenant-1', emailVerified: false }
const AUTH_RESULT = { user: USER, accessToken: 'a', rawRefreshToken: 'r' }

const mockUserRepo = { findByEmail: jest.fn(), create: jest.fn() }
const mockEmailProvider = { sendEmailVerificationOtp: jest.fn() }
const mockPasswordService = { assertAcceptable: jest.fn(), hash: jest.fn() }
const mockTokenManager = { issueTokens: jest.fn() }
const mockRedis = { setnx: jest.fn() }
const mockOtpService = { generate: jest.fn(), store: jest.fn() }

const mockOptions = {
  jwt: { secret: JWT_SECRET },
  hmacKey: HMAC_KEY,
  previousHmacKeys: [],
  emailVerification: { required: true, otpTtlSeconds: 600 },
  blockedStatuses: [],
  sessions: { enabled: false, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
}

const REQUEST = { ip: '1.2.3.4', headers: { 'user-agent': 'TestBrowser' } } as Request
const DTO = { email: EMAIL, password: 'SecureP@ss1', name: 'New User', tenantId: 'tenant-1' }

/** What a store under memory pressure answers to a write it refuses. */
const STORE_REFUSED = new Error(`OOM command not allowed for ${EMAIL} ${USER_ID} ${CODE}`)

/** Lets the detached email send settle before the assertion reads it. */
async function flush(): Promise<void> {
  await new Promise((resolve) => setImmediate(resolve))
}

describe('AuthService — a refused write of the verification code', () => {
  let service: AuthService
  let errorLog: jest.SpyInstance

  beforeEach(async () => {
    jest.resetAllMocks()
    errorLog = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
    mockUserRepo.findByEmail.mockResolvedValue(null)
    mockUserRepo.create.mockResolvedValue(USER)
    mockPasswordService.assertAcceptable.mockResolvedValue(undefined)
    mockPasswordService.hash.mockResolvedValue('scrypt:salt:hash')
    mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
    mockEmailProvider.sendEmailVerificationOtp.mockResolvedValue(undefined)
    mockOtpService.generate.mockReturnValue(CODE)
    mockRedis.setnx.mockResolvedValue(true)

    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: GUARDED_USER_REPOSITORY, useValue: mockUserRepo },
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
        { provide: BYMAX_AUTH_HOOKS, useValue: {} },
        { provide: PasswordService, useValue: mockPasswordService },
        { provide: TokenManagerService, useValue: mockTokenManager },
        { provide: BruteForceService, useValue: {} },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: OtpService, useValue: mockOtpService },
        { provide: SessionService, useValue: {} },
        { provide: AccountStatusService, useValue: {} }
      ]
    }).compile()
    service = module.get(AuthService)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  // Scenario: registration where the account is created and the store then refuses the code. Expected:
  // the same result as a registration whose write succeeds, the account created, and the tokens issued.
  // Why: the caller must not be able to tell a stored code from a refused one, and the account exists.
  it('answers a registration as it does when the write succeeds', async () => {
    mockOtpService.store.mockResolvedValue(undefined)
    const stored = await service.register(DTO, REQUEST)
    mockOtpService.store.mockRejectedValue(STORE_REFUSED)
    const refused = await service.register(DTO, REQUEST)

    expect(refused).toBe(stored)
    expect(refused).toBe(AUTH_RESULT)
    // Each registration creates this account in this tenant and issues tokens for the created user,
    // with the caller's address and agent, so the refused write changes none of it.
    for (const call of [1, 2]) {
      expect(mockUserRepo.create).toHaveBeenNthCalledWith(
        call,
        expect.objectContaining({
          email: EMAIL,
          name: DTO.name,
          passwordHash: 'scrypt:salt:hash',
          tenantId: 'tenant-1',
          emailVerified: false
        })
      )
      expect(mockTokenManager.issueTokens).toHaveBeenNthCalledWith(
        call,
        expect.objectContaining({ id: USER_ID, email: EMAIL, tenantId: 'tenant-1' }),
        '1.2.3.4',
        'TestBrowser',
        expect.anything()
      )
    }
    expect(mockUserRepo.create).toHaveBeenCalledTimes(2)
    expect(mockTokenManager.issueTokens).toHaveBeenCalledTimes(2)
    // The write that was refused is the one for this address and this code.
    expect(mockOtpService.store).toHaveBeenLastCalledWith(
      'email_verification',
      hmacSha256(`tenant-1:${EMAIL}`, HMAC_KEY),
      CODE,
      600
    )
  })

  // Scenario: the same registration. Expected: no email is sent, since the code in it would match
  // nothing stored.
  it('sends no email for a code that was not stored', async () => {
    mockOtpService.store.mockRejectedValue(STORE_REFUSED)

    await service.register(DTO, REQUEST)
    await flush()

    expect(mockEmailProvider.sendEmailVerificationOtp).not.toHaveBeenCalled()
  })

  // Scenario: the same registration. Expected: exactly one error event with the closed code, carrying a
  // description of the failure and neither the address, the user id nor the code, even though the store's own
  // message holds all three.
  it('logs one closed-code event that carries no address, user id or code', async () => {
    mockOtpService.store.mockRejectedValue(STORE_REFUSED)

    await service.register(DTO, REQUEST)

    expect(errorLog).toHaveBeenCalledTimes(1)
    const [event] = errorLog.mock.calls[0] as [Record<string, unknown>]
    expect(event).toMatchObject({
      event: 'AUTH_OTP_STORE_FAILED',
      message: AUTH_LOG_EVENTS.AUTH_OTP_STORE_FAILED.message
    })
    expect(Object.keys(event).sort()).toEqual(['detail', 'event', 'message'])
    expect(JSON.stringify(event)).not.toContain(EMAIL)
    expect(JSON.stringify(event)).not.toContain(USER_ID)
    expect(JSON.stringify(event)).not.toContain(CODE)
  })

  // Scenario: the resend route, for an unverified account, with the store refusing. Expected: it
  // resolves as it does on success, sends nothing and logs the same closed code once.
  it('answers a resend as it does when the write succeeds', async () => {
    mockUserRepo.findByEmail.mockResolvedValue(USER)
    mockOtpService.store.mockRejectedValue(STORE_REFUSED)

    await expect(
      service.resendVerificationEmail('tenant-1', EMAIL, REQUEST)
    ).resolves.toBeUndefined()
    await flush()

    expect(mockUserRepo.findByEmail).toHaveBeenCalledWith({ email: EMAIL, tenantId: 'tenant-1' })
    expect(mockOtpService.store).toHaveBeenCalledWith(
      'email_verification',
      hmacSha256(`tenant-1:${EMAIL}`, HMAC_KEY),
      CODE,
      600
    )
    expect(mockEmailProvider.sendEmailVerificationOtp).not.toHaveBeenCalled()
    expect(errorLog).toHaveBeenCalledTimes(1)
    expect(errorLog.mock.calls[0]?.[0]).toMatchObject({ event: 'AUTH_OTP_STORE_FAILED' })
  })

  // Scenario: the write succeeds. Expected: the email is sent with the stored code and nothing is
  // logged as an error. Why: the best-effort path must not swallow the ordinary one.
  it('still sends the email and logs nothing when the write succeeds', async () => {
    mockOtpService.store.mockResolvedValue(undefined)

    await service.register(DTO, REQUEST)
    await flush()

    expect(mockEmailProvider.sendEmailVerificationOtp).toHaveBeenCalledWith('tenant-1', EMAIL, CODE)
    expect(errorLog).not.toHaveBeenCalled()
  })
})
