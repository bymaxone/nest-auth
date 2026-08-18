/**
 * @fileoverview Unit tests for PasswordResetService.
 *
 * Covers `initiateReset`, `resetPassword`, `verifyOtp`, and `resendOtp` across
 * both token and OTP reset methods. All external dependencies (Redis, email
 * provider, OtpService, PasswordService, user repository) are mocked — no real
 * Redis or I/O is exercised.
 *
 * Coverage target: ≥80% statements/lines.
 */

// Mock sleep so tests don't wait 300ms in timing normalization paths
jest.mock('../utils/sleep', () => ({ sleep: jest.fn().mockResolvedValue(undefined) }))

import { createHash } from 'node:crypto'

import { Logger } from '@nestjs/common'
import { Test, type TestingModule } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { hmacSha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'
import { OtpService } from './otp.service'
import { PasswordResetService } from './password-reset.service'
import { sha256 } from '../crypto/secure-token'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { sleep } from '../utils/sleep'
import type { Request } from 'express'

const mockSleep = sleep as jest.MockedFunction<typeof sleep>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Extracts the error code from a thrown AuthException. */
function getErrorCode(err: unknown): string {
  if (!(err instanceof AuthException)) throw new Error('Not an AuthException')
  const res = err.getResponse() as { error?: { code?: string } }
  return res.error?.code ?? ''
}

/** Flushes the microtask queue (fire-and-forget email calls). */
async function flushMicrotasks(ticks = 2): Promise<void> {
  for (let i = 0; i < ticks; i++) await Promise.resolve()
}

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const JWT_SECRET = 'test-secret-32-characters-minimum'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const mockOptions = {
  passwordReset: {
    method: 'token' as const,
    tokenTtlSeconds: 3600,
    otpLength: 6,
    otpTtlSeconds: 300
  },
  blockedStatuses: ['banned', 'suspended'],
  jwt: { secret: JWT_SECRET, accessCookieMaxAgeMs: 900_000 },
  hmacKey: HMAC_KEY,
  previousHmacKeys: []
}

const mockUserRepo = {
  findByEmail: jest.fn(),
  findById: jest.fn(),
  updatePassword: jest.fn()
}

const mockHooks = {
  afterPasswordReset: jest.fn()
}

const mockEmailProvider = {
  sendPasswordResetToken: jest.fn(),
  sendPasswordResetOtp: jest.fn(),
  sendPasswordChangedNotification: jest.fn()
}

const mockOtpService = {
  generate: jest.fn(),
  store: jest.fn(),
  verify: jest.fn()
}

const mockPasswordService = {
  hash: jest.fn(),
  compare: jest.fn(),
  assertNotCompromised: jest.fn().mockResolvedValue(undefined),
  assertAcceptable: jest.fn().mockResolvedValue(undefined),
  assertLongEnough: jest.fn()
}

/** The current-password re-proof is counted like a login; unlocked unless a case says otherwise. */
const mockBruteForce = {
  isLockedOut: jest.fn().mockResolvedValue(false),
  recordFailure: jest.fn(),
  resetFailures: jest.fn()
}

const mockSessionService = {
  revokeAllExceptCurrent: jest.fn()
}

const mockRedis = {
  set: jest.fn(),
  get: jest.fn(),
  del: jest.fn(),
  getdel: jest.fn(),
  setnx: jest.fn(),
  invalidateUserSessions: jest.fn(),
  bumpUserTokenEpoch: jest.fn()
}

// ---------------------------------------------------------------------------
// Module factory
// ---------------------------------------------------------------------------

async function buildModule(
  emailProviderValue: unknown = mockEmailProvider,
  hooksValue: unknown = null
): Promise<TestingModule> {
  return Test.createTestingModule({
    providers: [
      PasswordResetService,
      { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
      { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
      { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: emailProviderValue },
      { provide: BYMAX_AUTH_HOOKS, useValue: hooksValue },
      { provide: OtpService, useValue: mockOtpService },
      { provide: PasswordService, useValue: mockPasswordService },
      { provide: AuthRedisService, useValue: mockRedis },
      { provide: SessionService, useValue: mockSessionService },
      { provide: BruteForceService, useValue: mockBruteForce }
    ]
  }).compile()
}

// ---------------------------------------------------------------------------
// Suite setup
// ---------------------------------------------------------------------------

/** A minimal request double — the reset flows only hand it to the tenant resolver. */
const mockReq = {
  ip: '1.2.3.4',
  headers: { 'user-agent': 'TestBrowser' }
} as unknown as Request

describe('PasswordResetService', () => {
  let service: PasswordResetService

  beforeEach(async () => {
    jest.clearAllMocks()

    // Default mock implementations
    mockUserRepo.findByEmail.mockResolvedValue(null)
    mockUserRepo.findById.mockResolvedValue(null)
    mockUserRepo.updatePassword.mockResolvedValue(undefined)
    mockHooks.afterPasswordReset.mockResolvedValue(undefined)
    mockEmailProvider.sendPasswordResetToken.mockResolvedValue(undefined)
    mockEmailProvider.sendPasswordResetOtp.mockResolvedValue(undefined)
    mockOtpService.generate.mockReturnValue('123456')
    mockOtpService.store.mockResolvedValue(undefined)
    mockOtpService.verify.mockResolvedValue(undefined)
    mockPasswordService.hash.mockResolvedValue('$hashed$')
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.get.mockResolvedValue(null)
    mockRedis.del.mockResolvedValue(undefined)
    mockRedis.getdel.mockResolvedValue(null)
    mockRedis.setnx.mockResolvedValue(true)
    mockRedis.invalidateUserSessions.mockResolvedValue(undefined)
    mockRedis.bumpUserTokenEpoch.mockResolvedValue(1)
    mockSleep.mockResolvedValue(undefined)

    const module = await buildModule()
    service = module.get(PasswordResetService)
  })

  // =========================================================================
  // initiateReset
  // =========================================================================

  describe('changePassword', () => {
    const dto = { currentPassword: 'the-old-one', newPassword: 'a-brand-new-one' }

    beforeEach(() => {
      mockUserRepo.findById.mockResolvedValue({
        id: 'u1',
        email: 'user@example.com',
        status: 'active',
        tenantId: 'tenant-1',
        passwordHash: 'scrypt:stored'
      })
      mockPasswordService.compare.mockResolvedValue(true)
      mockPasswordService.hash.mockResolvedValue('scrypt:new')
      mockPasswordService.assertAcceptable.mockResolvedValue(undefined)
    })

    // The happy path, and the shape of it: the current password is verified against the STORED
    // hash before anything is written, the new one goes through the breach checker, and the
    // write lands.
    it('verifies the current password, screens the new one, and persists it', async () => {
      await service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')

      expect(mockPasswordService.compare).toHaveBeenCalledWith('the-old-one', 'scrypt:stored')
      expect(mockPasswordService.assertAcceptable).toHaveBeenCalledWith(
        'a-brand-new-one',
        'newPassword'
      )
      expect(mockUserRepo.updatePassword).toHaveBeenCalledWith('u1', 'tenant-1', 'scrypt:new')
    })

    // The reason ASVS §6.2.3 asks for the current password at all: a session is not proof of
    // identity. A token lifted by XSS or from a shared machine must not be enough to rotate the
    // credential, lock the real owner out, and keep the attacker in.
    it('refuses when the current password does not match, and writes nothing', async () => {
      mockPasswordService.compare.mockResolvedValue(false)

      await expect(
        service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INVALID_CREDENTIALS } }
      })
      expect(mockUserRepo.updatePassword).not.toHaveBeenCalled()
      expect(mockSessionService.revokeAllExceptCurrent).not.toHaveBeenCalled()
    })

    // An account provisioned purely through OAuth has no local password. There is nothing to
    // prove and nothing to change — its credential belongs to the provider. Answering the same
    // `INVALID_CREDENTIALS` as a wrong password keeps the two indistinguishable.
    it('refuses an account with no local password', async () => {
      mockUserRepo.findById.mockResolvedValue({ id: 'u1', email: 'o@e.com', status: 'active' })

      await expect(
        service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INVALID_CREDENTIALS } }
      })
      expect(mockPasswordService.compare).not.toHaveBeenCalled()
    })

    // `login` refuses an account after N wrong passwords. This door asks for the SAME secret
    // and used to refuse nothing, so a caller holding a stolen access token but not the
    // password could guess it here without limit — and winning replaces the credential, which
    // locks the owner out of their own account. The per-route IP limit is not that control: a
    // distributed caller sidesteps it, and it is not keyed to the account being attacked.
    it('refuses once the re-proof failure budget for this account is spent', async () => {
      mockBruteForce.isLockedOut.mockResolvedValueOnce(true)

      await expect(
        service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.ACCOUNT_LOCKED } }
      })
      // Refused before the KDF, so a locked account is not an amplifier either.
      expect(mockPasswordService.compare).not.toHaveBeenCalled()
      expect(mockUserRepo.updatePassword).not.toHaveBeenCalled()
    })

    it('counts a wrong current password against that budget', async () => {
      mockPasswordService.compare.mockResolvedValue(false)
      mockBruteForce.recordFailure.mockClear()

      await expect(
        service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')
      ).rejects.toBeDefined()

      expect(mockBruteForce.recordFailure).toHaveBeenCalledTimes(1)
    })

    // Cleared on success, so a user who mistypes twice and then gets it right is not carrying
    // a budget toward a lockout they never earned.
    it('clears the budget once the current password is proved', async () => {
      mockBruteForce.resetFailures.mockClear()

      await service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')

      expect(mockBruteForce.resetFailures).toHaveBeenCalledTimes(1)
    })

    // A verified token whose subject no longer exists answers the same way, rather than
    // throwing something that tells the caller the account is gone.
    it('refuses when the account no longer exists', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(
        service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INVALID_CREDENTIALS } }
      })
    })

    // ASVS v5 §7.4.3: a credential change offers to end every other session. The caller's own
    // survives — the device that just changed the password should not be signed out by doing
    // so — and `revokeAllExceptCurrent` bumps the epoch, which is what reaches the stateless
    // access tokens the other devices hold.
    it('ends every other session, keeping the caller signed in', async () => {
      await service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')

      expect(mockSessionService.revokeAllExceptCurrent).toHaveBeenCalledWith({
        userId: 'u1',
        tenantId: 'tenant-1',
        currentSessionHash: sha256('raw-refresh')
      })
      expect(mockRedis.invalidateUserSessions).not.toHaveBeenCalled()
    })

    // Without the caller's refresh token there is no session to spare, and the safe reading is
    // that every one of them goes — a change that leaves an unidentified session alive is the
    // failure this control exists to prevent.
    it('ends every session when the caller cannot be identified', async () => {
      await service.changePassword('u1', 'tenant-1', dto, undefined)

      expect(mockSessionService.revokeAllExceptCurrent).not.toHaveBeenCalled()
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('u1', 'tenant-1', 'dashboard')
      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('u1', 'tenant-1', 'dashboard')
    })

    // An EMPTY token is "cannot be identified" too, not a token. Treated as one it would spare the
    // session whose hash is `sha256('')` — a constant, so it names no real session but does send
    // the request down the keep-one path, where the sweep is scoped to "all except this hash"
    // rather than the unconditional invalidation this case calls for.
    it('ends every session when the caller presents an empty token', async () => {
      await service.changePassword('u1', 'tenant-1', dto, '')

      expect(mockSessionService.revokeAllExceptCurrent).not.toHaveBeenCalled()
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('u1', 'tenant-1', 'dashboard')
      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('u1', 'tenant-1', 'dashboard')
    })

    // The re-proof budget is keyed to this account AND this flow. Dropping the account id gives
    // the whole deployment one shared counter, so anyone's failures lock out everyone; dropping
    // the flow prefix merges it with `login`'s, so guessing here locks the owner out of signing in
    // — which is the outcome this control exists to prevent, arrived at from the other side.
    it('keys the failure budget to the account and to this flow alone', async () => {
      await service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')

      expect(mockBruteForce.resetFailures).toHaveBeenCalledWith(
        hmacSha256('reauth:change-password:u1', HMAC_KEY)
      )
    })

    // Both refusals below answer with a code that says nothing about which account or why, so
    // these lines are the only record of a caller holding a token and guessing at the password
    // behind it.
    it('names the account whose re-proof budget ran out', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      // `Once`, because `clearAllMocks` resets calls but keeps implementations — a persistent
      // lockout would decide every test after this one.
      mockBruteForce.isLockedOut.mockResolvedValueOnce(true)

      await expect(service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')).rejects.toThrow(
        AuthException
      )

      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).toContain('account locked')
      expect(warned).toContain('userId=u1')
      warnSpy.mockRestore()
    })

    // The wrong-password refusal, counted against the same budget: `invalid_credentials` says
    // nothing about which account, so the log line carries it.
    it('names the account whose current password was rejected', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockPasswordService.compare.mockResolvedValueOnce(false)

      await expect(service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')).rejects.toThrow(
        AuthException
      )

      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).toContain('current password rejected')
      expect(warned).toContain('userId=u1')
      warnSpy.mockRestore()
    })

    // The notification is fire-and-forget by design — a delivery failure must not undo a password
    // already written, nor change the answer. That makes the log line the only trace of it, and
    // the notification is the control that turns "the victim finds out days later, at a failed
    // login" into "the victim finds out now". Losing it silently loses that.
    // A provider that throws SYNCHRONOUSLY rather than rejecting, which is why the send runs inside
    // an async IIFE. `Promise.resolve(send.call(...))` evaluates the call before the promise wraps
    // it, so the throw would skip the handler and fail a password change that already completed —
    // and the rejection test below stays green through that regression, which is what makes this
    // one load-bearing. A provider is consumer code and may do either.
    // The property no rejection test can see: every one of those settles IMMEDIATELY, so an
    // implementation that awaited the send inside a `try/catch` satisfies them all — the operation
    // still completes and the failure is still logged. "Detached" means the operation does not
    // WAIT, and only a send that has not settled distinguishes the two. A relay that accepts the
    // connection and stalls is the realistic case.
    it('completes the change without waiting for a notice that never settles', async () => {
      // Initialised to a no-op rather than declared with `!`: the executor below runs
      // SYNCHRONOUSLY, so the real resolver is in place before this line's promise is returned.
      // The no-op is unreachable, and it keeps a definite-assignment assertion out of the file.
      let release = (): void => {}
      mockEmailProvider.sendPasswordChangedNotification.mockReturnValueOnce(
        new Promise<void>((resolve) => {
          release = resolve
        })
      )

      await expect(
        service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')
      ).resolves.toBeUndefined()

      expect(mockUserRepo.updatePassword).toHaveBeenCalled()
      expect(mockEmailProvider.sendPasswordChangedNotification).toHaveBeenCalled()

      release()
      await Promise.resolve()
    })

    it('records a synchronous throw without failing the change', async () => {
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockEmailProvider.sendPasswordChangedNotification.mockImplementationOnce(() => {
        throw new Error('550 user@example.com: recipient rejected — smtp down')
      })

      await expect(
        service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')
      ).resolves.toBeUndefined()
      await new Promise((resolve) => setImmediate(resolve))

      expect(mockUserRepo.updatePassword).toHaveBeenCalled()
      const logged = errorSpy.mock.calls[0]?.[0] as string
      expect(errorSpy.mock.calls[0]).toHaveLength(1)
      expect(logged).toContain('notifyPasswordChanged: delivery failed for user u1')
      expect(logged).not.toContain('user@example.com')
      // Nothing the transport wrote reaches the line, so the address cannot — not because it was
      // matched and removed, but because its carrier was never published. Asserting the exact line
      // is what keeps this from passing on a build that logs nothing at all.
      expect(logged).not.toContain('recipient rejected')
      expect(logged).not.toContain('550')
      expect(logged).toBe('notifyPasswordChanged: delivery failed for user u1: <error>')
      errorSpy.mockRestore()
    })

    it('records a failed notification without failing the change', async () => {
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      // The likeliest shape, and it needs no quoted body: an SMTP rejection NAMES the recipient it
      // refused. The provider strips the address from its own line and rethrows the ORIGINAL under
      // `onDeliveryError: 'rethrow'`, so this line was putting back what that one removed.
      mockEmailProvider.sendPasswordChangedNotification.mockRejectedValueOnce(
        new Error('550 user@example.com: recipient rejected — smtp down')
      )

      await expect(
        service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')
      ).resolves.toBeUndefined()
      // The rejection is handled on a later tick than the resolution of `changePassword`.
      await new Promise((resolve) => setImmediate(resolve))

      expect(mockUserRepo.updatePassword).toHaveBeenCalled()

      const logged = errorSpy.mock.calls[0]?.[0] as string
      // One argument, not two: the error object is never handed to the logger, because a logger
      // that receives it prints whatever the transport hung on it.
      expect(errorSpy.mock.calls[0]).toHaveLength(1)
      // Which flow, and whose account. Without both, an operator has a delivery failure with no
      // way to reach the affected user.
      expect(logged).toContain('notifyPasswordChanged: delivery failed for user u1')
      // Nothing the transport wrote reaches the line, so the address cannot — not because it was
      // matched and removed, but because its carrier was never published. Asserting the exact line
      // is what keeps this from passing on a build that logs nothing at all.
      expect(logged).not.toContain('user@example.com')
      expect(logged).not.toContain('smtp down')
      expect(logged).not.toContain('550')
      expect(logged).toBe('notifyPasswordChanged: delivery failed for user u1: <error>')
      errorSpy.mockRestore()
    })

    // A new password the breach checker refuses never reaches the repository.
    it('refuses a compromised new password before writing', async () => {
      mockPasswordService.assertAcceptable.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.PASSWORD_COMPROMISED)
      )

      await expect(service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')).rejects.toThrow(
        AuthException
      )
      expect(mockUserRepo.updatePassword).not.toHaveBeenCalled()
    })

    // NIST SP 800-63B §4.6 wants the subscriber told through a channel independent of the
    // transaction. The classic takeover starts with a compromised mailbox, so this notice is
    // what turns "the victim finds out days later" into "the victim finds out now".
    it('notifies the account that its password changed', async () => {
      await service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')

      expect(mockEmailProvider.sendPasswordChangedNotification).toHaveBeenCalledWith(
        'tenant-1',
        'user@example.com'
      )
    })

    // The notice is fire-and-forget: a mail failure must not undo a password already written,
    // nor answer differently to the caller.
    it('succeeds even when the notification cannot be delivered', async () => {
      mockEmailProvider.sendPasswordChangedNotification.mockRejectedValueOnce(
        new Error('smtp down')
      )

      await expect(
        service.changePassword('u1', 'tenant-1', dto, 'raw-refresh')
      ).resolves.toBeUndefined()
      expect(mockUserRepo.updatePassword).toHaveBeenCalled()
    })
  })

  describe('initiateReset', () => {
    const dto = { email: 'user@example.com', tenantId: 'tenant1' }

    // The cooldown is shared with `resendOtp`, under the same key, and this is the door that
    // matters more: every issuance rewrites the OTP record with `attempts: 0`, so an untimed
    // initiate turns the 5-attempt ceiling into 5 attempts PER CALL — an unbounded supply of
    // guesses at a six-digit code — and each call also mails an address the caller merely has
    // to know.
    it('claims the shared resend cooldown before sending anything', async () => {
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })

      await service.initiateReset(dto, mockReq)

      const [key, ttl] = mockRedis.setnx.mock.calls[0] as [string, number]
      expect(key.startsWith('resend:password_reset:')).toBe(true)
      expect(ttl).toBe(60)
    })

    // A second call inside the window sends nothing at all: no repository read, no OTP write,
    // no mail. Silent success, so the throttle does not answer whether the account exists.
    it('sends nothing when the cooldown is already claimed', async () => {
      mockRedis.setnx.mockResolvedValue(false)
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })

      await expect(service.initiateReset(dto, mockReq)).resolves.toBeUndefined()

      expect(mockUserRepo.findByEmail).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendPasswordResetOtp).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendPasswordResetToken).not.toHaveBeenCalled()
      expect(mockOtpService.store).not.toHaveBeenCalled()
    })

    // Scenario: the cooldown is already claimed and the check itself took 100 ms. Expected: the
    // pad is exactly the remainder (300 - 100). Why: this early return has its OWN sleep, on the
    // shortest path through the method — it does no repository read and sends no mail, so it is
    // the fastest exit and the one that most needs the floor. Left unpinned it is the exit that
    // answers "you already asked recently", which is only true of an address that exists.
    //
    // The exact value is what separates the three mutants on that line: `Math.min` collapses it
    // to 0, `300 + elapsed` gives 400, and `now + start` gives a large negative clamped to 0.
    it('pads the cooldown exit to exactly the remaining budget', async () => {
      mockRedis.setnx.mockResolvedValue(false)
      let now = 1_700_000_000_000
      const nowSpy = jest.spyOn(Date, 'now').mockImplementation(() => now)
      // `start` is read before the cooldown claim, so the claim is where the elapsed time goes.
      mockRedis.setnx.mockImplementation(async () => {
        now += 100
        return false
      })

      await service.initiateReset(dto, mockReq)

      expect(mockSleep).toHaveBeenCalledTimes(1)
      expect(mockSleep).toHaveBeenCalledWith(200)
      nowSpy.mockRestore()
    })

    // Both entry points must draw on ONE budget: a per-endpoint cooldown lets a caller
    // alternate between them and halve the effective wait.
    it('uses the same cooldown key as resendOtp', async () => {
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })

      await service.initiateReset(dto, mockReq)
      const initiateKey = (mockRedis.setnx.mock.calls[0] as [string, number])[0]

      mockRedis.setnx.mockClear()
      await service.resendOtp(dto, mockReq)
      const resendKey = (mockRedis.setnx.mock.calls[0] as [string, number])[0]

      expect(initiateKey).toBe(resendKey)
    })

    // Verifies that does NOT throw when user is not found (anti-enumeration).
    it('does NOT throw when user is not found (anti-enumeration)', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue(null)

      // Act & Assert
      await expect(service.initiateReset(dto, mockReq)).resolves.toBeUndefined()
    })

    // Verifies that does NOT throw when user is blocked (anti-enumeration).
    it('does NOT throw when user is blocked (anti-enumeration)', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'banned',
        tenantId: 'tenant1'
      })

      // Act & Assert
      await expect(service.initiateReset(dto, mockReq)).resolves.toBeUndefined()
    })

    // The token variant of the same property, and the anti-enumeration argument applies here too:
    // the send is reached only for an address that exists, so awaiting a stalled channel would
    // make the response time carry the distinction the identical body is there to hide.
    it('answers without waiting for a token send that never settles', async () => {
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })
      let release = (): void => {}
      mockEmailProvider.sendPasswordResetToken.mockReturnValueOnce(
        new Promise<void>((resolve) => {
          release = resolve
        })
      )

      await expect(service.initiateReset(dto, mockReq)).resolves.toBeUndefined()

      expect(mockEmailProvider.sendPasswordResetToken).toHaveBeenCalled()

      release()
      await Promise.resolve()
    })

    // Verifies that does NOT throw when user is suspended (blocked status).
    it('does NOT throw when user is suspended (blocked status)', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'suspended',
        tenantId: 'tenant1'
      })

      // Act & Assert
      await expect(service.initiateReset(dto, mockReq)).resolves.toBeUndefined()
    })

    // Verifies that does NOT throw even when email provider throws.
    // Also verifies the Redis token rollback fires so an undeliverable token does not
    // linger in Redis until natural TTL expiry.
    it('does NOT throw even when email provider throws (and rolls back Redis token)', async () => {
      // The service intentionally logs the provider error via its
      // Nest `Logger`. Silence that log in the test output — the
      // assertion below verifies the public contract (the call
      // resolves) which is the real behaviour under test.
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
      try {
        // Arrange
        mockUserRepo.findByEmail.mockResolvedValue({
          id: 'u1',
          status: 'active',
          tenantId: 'tenant1'
        })
        mockEmailProvider.sendPasswordResetToken.mockRejectedValue(new Error('SMTP error'))

        // Act & Assert
        await expect(service.initiateReset(dto, mockReq)).resolves.toBeUndefined()
        await flushMicrotasks()

        // Rollback: the pw_reset:{hash} key written before the email send must be
        // deleted after the email failure so it does not linger until natural TTL.
        expect(mockRedis.del).toHaveBeenCalledWith(expect.stringMatching(/^pw_reset:/))
      } finally {
        loggerSpy.mockRestore()
      }
    })

    // Verifies that the rollback's `del` failure is also caught and logged — never
    // propagates out of `initiateReset` (the public contract is fire-and-forget).
    it('does NOT throw when both email AND rollback Redis del fail', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
      try {
        mockUserRepo.findByEmail.mockResolvedValue({
          id: 'u1',
          status: 'active',
          tenantId: 'tenant1'
        })
        mockEmailProvider.sendPasswordResetToken.mockRejectedValue(new Error('SMTP error'))
        mockRedis.del.mockRejectedValueOnce(new Error('Redis down'))

        await expect(service.initiateReset(dto, mockReq)).resolves.toBeUndefined()
        await flushMicrotasks()

        // Both errors must be logged: the original email failure AND the rollback failure.
        const logged = loggerSpy.mock.calls.map((c) => String(c[0])).join(' | ')
        expect(logged).toMatch(/sendPasswordResetToken failed/)
        expect(logged).toMatch(/pw_reset rollback delete failed/)
      } finally {
        loggerSpy.mockRestore()
      }
    })

    // The same seam at the token site. `userId` is not redacted here (a 64-hex token cannot hide
    // in an identifier), so the composition is the only guard, and `safeLogLine` is what provides
    // it — the per-field redactions cannot see across the `: ` the template inserts.
    it('withholds the line when the identifier and the error compose the address', async () => {
      // The composed value straddles the template's own `': '` separator: the identifier ends
      // one field and the description begins the next, and neither field contains the value.
      // The description opens with the opaque stand-in — nothing the channel wrote gets in — so
      // straddling value has to be built from.
      const named = new Error('channel down')

      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      try {
        mockRedis.setnx.mockResolvedValue(true)
        mockUserRepo.findByEmail.mockResolvedValue({
          id: 'u1',
          status: 'active',
          tenantId: 'tenant1'
        })
        mockEmailProvider.sendPasswordResetToken.mockRejectedValue(named)

        await service.initiateReset({ ...dto, email: 'u1: <error>' }, mockReq)
        await flushMicrotasks()

        const logged = loggerSpy.mock.calls.map((c) => String(c[0])).join(' | ')
        expect(logged).not.toContain('u1: <error>')
        expect(logged).toContain('withheld')
      } finally {
        loggerSpy.mockRestore()
      }
    })

    // Third site of the same leak: `sendPasswordResetToken` hands the provider a raw reset token,
    // and a relay that rejects by quoting the body puts it into the error this path logs. The
    // token is a working password reset until its TTL expires, so it must not survive into the
    // line — including through the rollback branch, which logs a second time.
    it('keeps the reset token out of the log when the relay quotes it back', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      try {
        mockRedis.setnx.mockResolvedValue(true)
        mockUserRepo.findByEmail.mockResolvedValue({
          id: 'u1',
          status: 'active',
          tenantId: 'tenant1'
        })
        mockEmailProvider.sendPasswordResetToken.mockImplementation(
          (_t: string, _e: string, token: string) =>
            Promise.reject(new Error(`550 rejected by policy: "Use ${token} to reset."`))
        )

        await service.initiateReset(dto, mockReq)
        await flushMicrotasks()

        const sent = mockEmailProvider.sendPasswordResetToken.mock.calls[0]?.[2] as string
        const logged = loggerSpy.mock.calls.map((c) => String(c[0])).join(' | ')

        // The token has to have existed for the assertion to mean anything — a build that stopped
        // passing one would otherwise satisfy `not.toContain` trivially. Asserted against the
        // contract rather than for truthiness: `generateSecureToken` returns 64 lower-case hex
        // characters, and a bare `toBeTruthy` survives a mutation that hands the provider any
        // non-empty string at all, which is the shape this assertion exists to rule out.
        expect(sent).toMatch(/^[0-9a-f]{64}$/)
        expect(logged).toContain('sendPasswordResetToken failed')
        expect(logged).not.toContain(sent)
        // On a credential path nothing the relay wrote reaches the line, and nothing is parsed off it
        // either. What remains is the label this library owns plus the opaque stand-in — which IS the
        // diagnosis: it says the send failed and how deep the failure was reported from.
        expect(logged).not.toContain('rejected by policy')
        expect(logged).not.toContain('550')
        expect(logged).toBe('sendPasswordResetToken failed for user u1: <error>')
      } finally {
        loggerSpy.mockRestore()
      }
    })

    // The token path's own synchronous-throw case. The rejection test above passes against the
    // pre-fix direct call too, so without this the deferral at `sendToken` is unpinned and a
    // revert to `Promise.resolve(provider.send(...))` would silently restore raw-token logging
    // through `initiateReset`'s outer catch. A fix at three sites needs a test at three sites.
    it('keeps the reset token out of the log when the provider throws synchronously', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      try {
        mockRedis.setnx.mockResolvedValue(true)
        mockUserRepo.findByEmail.mockResolvedValue({
          id: 'u1',
          status: 'active',
          tenantId: 'tenant1'
        })
        mockEmailProvider.sendPasswordResetToken.mockImplementation(
          (_t: string, _e: string, token: string) => {
            throw new Error(`550 rejected by policy: "Use ${token} to reset."`)
          }
        )

        await service.initiateReset(dto, mockReq)
        await flushMicrotasks()

        const sent = mockEmailProvider.sendPasswordResetToken.mock.calls[0]?.[2] as string
        const logged = loggerSpy.mock.calls.map((c) => String(c[0])).join(' | ')

        expect(sent).toMatch(/^[0-9a-f]{64}$/)
        expect(logged).not.toContain(sent)
        // On a credential path nothing the relay wrote reaches the line, and nothing is parsed off it
        // either. What remains is the label this library owns plus the opaque stand-in — which IS the
        // diagnosis: it says the send failed and how deep the failure was reported from.
        expect(logged).not.toContain('rejected by policy')
        expect(logged).not.toContain('550')
        expect(logged).toBe('sendPasswordResetToken failed for user u1: <error>')
      } finally {
        loggerSpy.mockRestore()
      }
    })

    // Verifies that calls sendToken path (token method) when user exists and is not blocked.
    it('calls sendToken path (token method) when user exists and is not blocked', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })

      // Act
      await service.initiateReset(dto, mockReq)
      await flushMicrotasks()

      // Assert
      expect(mockRedis.set).toHaveBeenCalledTimes(1)
      expect(mockEmailProvider.sendPasswordResetToken).toHaveBeenCalledTimes(1)
      expect(mockEmailProvider.sendPasswordResetToken).toHaveBeenCalledWith(
        'tenant1',
        dto.email,
        expect.any(String)
      )
    })

    // Verifies that skips email and logs warn when no email provider is configured.
    it('skips email and logs warn when no email provider is configured', async () => {
      // Arrange
      const module = await buildModule(null)
      const noEmailService = module.get(PasswordResetService)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })

      // Act
      await noEmailService.initiateReset(dto, mockReq)

      // Assert
      expect(mockEmailProvider.sendPasswordResetToken).not.toHaveBeenCalled()
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('no email provider configured'))

      warnSpy.mockRestore()
    })

    // Verifies that applies timing normalization — calls sleep.
    it('applies timing normalization — calls sleep', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue(null)

      // Act
      await service.initiateReset(dto, mockReq)

      // Assert
      expect(mockSleep).toHaveBeenCalledTimes(1)
    })

    // Scenario: 100 ms elapse between the start timestamp and the finally block; expected: sleep
    // is called with exactly the REMAINING budget (300 - 100 = 200). Why: pins the
    // `Math.max(0, 300 - (now - start))` formula — Math.min collapses it to 0, the `300 + elapsed`
    // mutant yields 400, and the `now + start` mutant yields a huge negative -> 0. Only the
    // original produces 200.
    it('sleeps for the remaining budget (max(0, 300 - elapsed)) in the finally block', async () => {
      // Arrange — first Date.now() is `start`, every later call is 100 ms after.
      mockUserRepo.findByEmail.mockResolvedValue(null)
      const nowSpy = jest.spyOn(Date, 'now')
      nowSpy.mockReturnValue(1_000_100)
      nowSpy.mockReturnValueOnce(1_000_000)

      // Act
      await service.initiateReset(dto, mockReq)

      // Assert
      expect(mockSleep).toHaveBeenCalledWith(200)
      nowSpy.mockRestore()
    })

    // Verifies that logs error when unexpected error occurs during initiation.
    it('logs error when unexpected error occurs during initiation', async () => {
      // Arrange
      const unexpectedError = new Error('Database connection failed')
      mockUserRepo.findByEmail.mockRejectedValue(unexpectedError)
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      // Act
      await service.initiateReset(dto, mockReq)

      // Assert
      expect(errorSpy).toHaveBeenCalledWith('initiateReset: unexpected error: <error>')
      expect(mockSleep).toHaveBeenCalledTimes(1)
      errorSpy.mockRestore()
    })

    // Verifies that does NOT send email to blocked user.
    it('does NOT send email to blocked user', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'banned',
        tenantId: 'tenant1'
      })

      // Act
      await service.initiateReset(dto, mockReq)
      await flushMicrotasks()

      // Assert
      expect(mockRedis.set).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendPasswordResetToken).not.toHaveBeenCalled()
    })

    describe('otp method', () => {
      let otpMethodService: PasswordResetService

      beforeEach(async () => {
        const optionsWithOtp = {
          ...mockOptions,
          passwordReset: { ...mockOptions.passwordReset, method: 'otp' as const }
        }
        const module = await Test.createTestingModule({
          providers: [
            PasswordResetService,
            { provide: BYMAX_AUTH_OPTIONS, useValue: optionsWithOtp },
            { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
            { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
            { provide: BYMAX_AUTH_HOOKS, useValue: null },
            { provide: OtpService, useValue: mockOtpService },
            { provide: PasswordService, useValue: mockPasswordService },
            { provide: AuthRedisService, useValue: mockRedis },
            { provide: SessionService, useValue: mockSessionService },
            { provide: BruteForceService, useValue: mockBruteForce }
          ]
        }).compile()
        otpMethodService = module.get(PasswordResetService)
      })

      // Verifies that calls sendOtp path when user exists and is not blocked.
      it('calls sendOtp path when user exists and is not blocked', async () => {
        // Arrange
        mockUserRepo.findByEmail.mockResolvedValue({
          id: 'u1',
          status: 'active',
          tenantId: 'tenant1'
        })

        // Act
        await otpMethodService.initiateReset(dto, mockReq)
        await flushMicrotasks()

        // Assert
        expect(mockOtpService.generate).toHaveBeenCalledTimes(1)
        expect(mockOtpService.store).toHaveBeenCalledTimes(1)
        expect(mockEmailProvider.sendPasswordResetOtp).toHaveBeenCalledTimes(1)
        // The reset code is attributed to the resolved tenant, passed as the first argument ahead
        // of the recipient: the port contract now propagates the tenant, so a regression that
        // dropped it or swapped it with the address would fail here instead of passing on the
        // call count alone.
        expect(mockEmailProvider.sendPasswordResetOtp).toHaveBeenCalledWith(
          'tenant1',
          'user@example.com',
          '123456'
        )
      })

      // Scenario: OTP send path; expected: otpService.store receives the purpose 'password_reset'
      // and the HMAC identifier derived from `${tenantId}:${email}`. Why: pins the
      // PASSWORD_RESET_PURPOSE constant (emptying it -> '') and the otpIdentifier message
      // (`${tenantId}:${email}` -> '' would change the HMAC), both of which determine the Redis
      // OTP keyspace.
      it('stores the OTP under purpose=password_reset with the tenant:email HMAC identifier', async () => {
        // Arrange
        mockUserRepo.findByEmail.mockResolvedValue({
          id: 'u1',
          status: 'active',
          tenantId: 'tenant1'
        })

        // Act
        await otpMethodService.initiateReset(dto, mockReq)
        await flushMicrotasks()

        // Assert
        const [purpose, identifier] = mockOtpService.store.mock.calls[0] as [string, string]
        expect(purpose).toBe('password_reset')
        expect(identifier).toBe(hmacSha256(`${dto.tenantId}:${dto.email}`, HMAC_KEY))
      })

      // Verifies that does NOT send OTP email to blocked user.
      it('does NOT send OTP email to blocked user', async () => {
        // Arrange
        mockUserRepo.findByEmail.mockResolvedValue({
          id: 'u1',
          status: 'banned',
          tenantId: 'tenant1'
        })

        // Act
        await otpMethodService.initiateReset(dto, mockReq)
        await flushMicrotasks()

        // Assert
        expect(mockOtpService.generate).not.toHaveBeenCalled()
        expect(mockOtpService.store).not.toHaveBeenCalled()
        expect(mockEmailProvider.sendPasswordResetOtp).not.toHaveBeenCalled()
      })
    })
  })

  // =========================================================================
  // resetPassword — token method
  // =========================================================================

  describe('resetPassword (token method)', () => {
    const baseDto = {
      email: 'user@example.com',
      tenantId: 'tenant1',
      newPassword: 'NewPassword123!'
    }

    const validContext = JSON.stringify({
      userId: 'u1',
      email: 'user@example.com',
      tenantId: 'tenant1'
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when proofCount > 1 (token + otp).
    it('throws PASSWORD_RESET_TOKEN_INVALID when proofCount > 1 (token + otp)', async () => {
      // Arrange
      const dto = { ...baseDto, token: 'tok', otp: '123456' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Scenario: proofCount > 1 (token + otp) while the token would otherwise resolve to a VALID
    // context; expected: still rejected by the mutual-exclusivity guard BEFORE any reset happens.
    // Why: prior proofCount tests left getdel=null, so the request would fail downstream anyway —
    // masking the guard. With a valid context, neutering the guard (proofCount filter ->
    // () => undefined / false, or `if (proofCount > 1)` -> if(false)/{}) would let the reset
    // succeed. Asserting it rejects AND that the password is never updated kills all four mutants.
    it('rejects (and never updates the password) when proofCount > 1 even with a valid stored token', async () => {
      // Arrange — token resolves to a context matching the dto, so only the proofCount guard can reject.
      mockRedis.getdel.mockResolvedValue(validContext)
      const dto = { ...baseDto, token: 'mytoken', otp: '123456' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
      expect(mockPasswordService.hash).not.toHaveBeenCalled()
      expect(mockUserRepo.updatePassword).not.toHaveBeenCalled()
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when proofCount > 1 (token + verifiedToken).
    it('throws PASSWORD_RESET_TOKEN_INVALID when proofCount > 1 (token + verifiedToken)', async () => {
      // Arrange
      const dto = { ...baseDto, token: 'tok', verifiedToken: 'v'.repeat(64) }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when proofCount > 1 (otp + verifiedToken).
    it('throws PASSWORD_RESET_TOKEN_INVALID when proofCount > 1 (otp + verifiedToken)', async () => {
      // Arrange
      const dto = { ...baseDto, otp: '123456', verifiedToken: 'v'.repeat(64) }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when method=token but dto.token is absent.
    it('throws PASSWORD_RESET_TOKEN_INVALID when method=token but dto.token is absent', async () => {
      // Arrange
      const dto = { ...baseDto }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when token not in Redis (getdel returns null).
    it('throws PASSWORD_RESET_TOKEN_INVALID when token not in Redis (getdel returns null)', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(null)
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when email mismatch in stored context.
    it('throws PASSWORD_RESET_TOKEN_INVALID when email mismatch in stored context', async () => {
      // Arrange
      const mismatchContext = JSON.stringify({
        userId: 'u1',
        email: 'other@example.com',
        tenantId: 'tenant1'
      })
      mockRedis.getdel.mockResolvedValue(mismatchContext)
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when tenantId mismatch in stored context.
    it('throws PASSWORD_RESET_TOKEN_INVALID when tenantId mismatch in stored context', async () => {
      // Arrange
      const mismatchContext = JSON.stringify({
        userId: 'u1',
        email: 'user@example.com',
        tenantId: 'other-tenant'
      })
      mockRedis.getdel.mockResolvedValue(mismatchContext)
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when stored JSON is malformed.
    it('throws PASSWORD_RESET_TOKEN_INVALID when stored JSON is malformed', async () => {
      // Arrange
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockRedis.getdel.mockResolvedValue('{{{invalid')
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
      // The holder gets the same code as for a replayed token, by design. The operator gets
      // the one line that says the record was corrupted rather than spent.
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('not parseable JSON'))
      warnSpy.mockRestore()
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when stored JSON is missing required fields.
    it('throws PASSWORD_RESET_TOKEN_INVALID when stored JSON is missing required fields', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(JSON.stringify({ userId: 'u1' }))
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that resets password and invalidates sessions on success (token flow).
    it('resets password and invalidates sessions on success (token flow)', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(validContext)
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      await service.resetPassword(dto, mockReq)

      // Assert
      expect(mockPasswordService.hash).toHaveBeenCalledWith(baseDto.newPassword)
      // The FIELD NAME, not just that the screen ran. A reset sends `newPassword`, and that is
      // what a policy failure has to name in its `details` — the same argument on the register
      // path carries `password`, so the two are only distinguishable if each is pinned.
      expect(mockPasswordService.assertAcceptable).toHaveBeenCalledWith(
        baseDto.newPassword,
        'newPassword'
      )
      // 'tenant1' — the reset record's own tenant, not one the caller supplied: the token
      // flow has no authenticated claims to read it from, so the write is scoped by what was
      // stamped when the token was minted.
      expect(mockUserRepo.updatePassword).toHaveBeenCalledWith('u1', 'tenant1', '$hashed$')
      // Full revocation: refresh sessions are deleted AND the user's token epoch is advanced,
      // so already-issued stateless access tokens are rejected immediately rather than staying
      // valid until their exp.
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('u1', 'tenant1', 'dashboard')
      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('u1', 'tenant1', 'dashboard')
    })

    // Scenario: token flow; expected: getdel is called with a `pw_reset:<sha256>` key, never an
    // empty string. Why: pins the Redis key template — emptying it (`getdel('')`) would read the
    // wrong key, breaking single-use token consumption.
    it('reads the token from a pw_reset:{sha256} Redis key', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(validContext)
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      await service.resetPassword(dto, mockReq)

      // Assert
      const [key] = mockRedis.getdel.mock.calls[0] as [string]
      expect(key).toMatch(/^pw_reset:[0-9a-f]{64}$/)
    })

    // ---- the token's binding to the password it was issued against ----
    //
    // Several `pw_reset:` keys can be alive at once. Completing a reset with one used to leave the
    // others valid, which is the wrong end state exactly when it matters: a victim resetting
    // because an attacker read a reset link out of their mailbox had not closed the link the
    // attacker read. The binding is what makes the first completed reset invalidate the rest.
    //
    // Reached only when the stored fingerprint is NON-EMPTY. Every other test here stores a record
    // without one — which is the "predates the binding" case that returns early — so this check
    // had no unit test at all, and the mutation run reported the whole comparison as uncovered.
    // (The E2E suite does exercise it, but Stryker runs the unit config, so nothing there can kill
    // a mutant in these lines.)

    /** The stored record, bound to `hash`'s fingerprint. */
    const boundContext = (hash: string): string =>
      JSON.stringify({
        userId: 'u1',
        email: 'user@example.com',
        tenantId: 'tenant1',
        passwordFingerprint: sha256(hash)
      })

    // The control: a token whose binding still matches must go through, or the check would be
    // refusing every reset rather than only superseded ones.
    it('completes a reset whose token still matches the account password', async () => {
      mockRedis.getdel.mockResolvedValue(boundContext('scrypt:current'))
      mockUserRepo.findById.mockResolvedValue({
        id: 'u1',
        email: 'user@example.com',
        status: 'active',
        passwordHash: 'scrypt:current'
      })

      await service.resetPassword({ ...baseDto, token: 'tok' }, mockReq)

      expect(mockUserRepo.updatePassword).toHaveBeenCalled()
    })

    // The case the binding exists for: a link the victim's attacker still holds, after the
    // victim has already reset. It must stop working the moment the first reset completes.
    it('refuses a token issued against a password that has since changed', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      // The token was minted against the old hash; the row now holds a different one.
      mockRedis.getdel.mockResolvedValue(boundContext('scrypt:old'))
      mockUserRepo.findById.mockResolvedValue({
        id: 'u1',
        email: 'user@example.com',
        status: 'active',
        passwordHash: 'scrypt:changed-since'
      })

      let caught: unknown
      try {
        await service.resetPassword({ ...baseDto, token: 'tok' }, mockReq)
      } catch (err) {
        caught = err
      }

      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
      expect(mockUserRepo.updatePassword).not.toHaveBeenCalled()
      // The caller gets the same `password_reset_token_invalid` an expired or unknown token gets,
      // deliberately — so this line is the only place the distinction exists, and the distinction
      // is the interesting one: a superseded link being presented is what an attacker holding a
      // stolen link looks like after the victim has already reset.
      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).toContain('a password that has since changed')
      expect(warned).toContain('userId=u1')
      warnSpy.mockRestore()
    })

    // An account that has no local password at all yields the empty fingerprint, so a token minted
    // then stops working the moment a password is set — the same rule, in the direction that
    // matters for an account being taken over by whoever sets the first one.
    it('refuses a token minted before the account had a password, once one is set', async () => {
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({
          userId: 'u1',
          email: 'user@example.com',
          tenantId: 'tenant1',
          passwordFingerprint: sha256('scrypt:some-hash')
        })
      )
      mockUserRepo.findById.mockResolvedValue({
        id: 'u1',
        email: 'user@example.com',
        status: 'active',
        passwordHash: null
      })

      let caught: unknown
      try {
        await service.resetPassword({ ...baseDto, token: 'tok' }, mockReq)
      } catch (err) {
        caught = err
      }

      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
      expect(mockUserRepo.updatePassword).not.toHaveBeenCalled()
    })

    // ---- parseResetContext clause isolation (defence against Redis tampering) ----
    // Each test feeds a stored context where exactly ONE validation clause should reject it, with
    // every other field valid (and email/tenantId matching the dto so the later equality check
    // cannot be the cause). This kills the ConditionalExpression `clause -> false` and the
    // LogicalOperator `|| -> &&` mutants on the parseResetContext guard chain. For non-string
    // email/tenantId the bypassed mutant reaches sha256(<number>) which throws a TypeError, so we
    // assert the thrown error is specifically an AuthException (a TypeError would not be).

    // Scenario: stored JSON is the literal null; expected: AuthException. Why: kills the
    // `parsed === null -> false` mutant — bypassing it reaches `'userId' in null`, a TypeError.
    it('throws AuthException when stored context is JSON null', async () => {
      mockRedis.getdel.mockResolvedValue('null')
      const dto = { ...baseDto, token: 'mytoken' }

      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }
      expect(caught).toBeInstanceOf(AuthException)
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Scenario: stored JSON is a number primitive; expected: AuthException. Why: kills the
    // `typeof parsed !== 'object' -> false` mutant — bypassing it reaches `'userId' in 42`, a TypeError.
    it('throws AuthException when stored context is a JSON number primitive', async () => {
      mockRedis.getdel.mockResolvedValue('42')
      const dto = { ...baseDto, token: 'mytoken' }

      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }
      expect(caught).toBeInstanceOf(AuthException)
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Scenario: the `userId` KEY is absent (email/tenantId present and valid); expected: rejected
    // and password never updated. Why: kills the false-prefix mutant that drops the leading
    // clauses through `userId in parsed` — bypassing them would return a context with no userId
    // and call applyPasswordReset(undefined).
    it('throws AuthException when the userId key is missing from the stored context', async () => {
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ email: baseDto.email, tenantId: baseDto.tenantId })
      )
      const dto = { ...baseDto, token: 'mytoken' }

      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }
      expect(caught).toBeInstanceOf(AuthException)
      expect(mockUserRepo.updatePassword).not.toHaveBeenCalled()
    })

    // Scenario: `userId` is a number, all else valid and matching; expected: rejected, no update.
    // Why: kills the `typeof userId !== 'string' -> false` clause and the false-prefix mutant that
    // keeps only `|| email-type || tenantId-type` — both would return the context and reset with a
    // numeric userId.
    it('throws AuthException when stored userId is not a string', async () => {
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ userId: 123, email: baseDto.email, tenantId: baseDto.tenantId })
      )
      const dto = { ...baseDto, token: 'mytoken' }

      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }
      expect(caught).toBeInstanceOf(AuthException)
      expect(mockUserRepo.updatePassword).not.toHaveBeenCalled()
    })

    // Scenario: `email` is a number, userId/tenantId valid; expected: AuthException specifically.
    // Why: kills the `typeof email !== 'string' -> false` clause and the matching `|| -> &&`
    // mutant — bypassing reaches sha256(<number>) (TypeError), which is NOT an AuthException.
    it('throws AuthException (not a TypeError) when stored email is not a string', async () => {
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ userId: 'u1', email: 123, tenantId: baseDto.tenantId })
      )
      const dto = { ...baseDto, token: 'mytoken' }

      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }
      expect(caught).toBeInstanceOf(AuthException)
    })

    // Scenario: `tenantId` is a number, userId/email valid and email matches; expected:
    // AuthException specifically. Why: kills the `typeof tenantId !== 'string' -> false` clause
    // and the last `|| -> &&` mutant — bypassing reaches sha256(<number>) (TypeError).
    it('throws AuthException (not a TypeError) when stored tenantId is not a string', async () => {
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ userId: 'u1', email: baseDto.email, tenantId: 999 })
      )
      const dto = { ...baseDto, token: 'mytoken' }

      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }
      expect(caught).toBeInstanceOf(AuthException)
    })
  })

  // =========================================================================
  // resetPassword — otp method
  // =========================================================================

  describe('resetPassword (otp method)', () => {
    let otpMethodService: PasswordResetService

    const baseDto = {
      email: 'user@example.com',
      tenantId: 'tenant1',
      newPassword: 'NewPassword123!'
    }

    beforeEach(async () => {
      const optionsWithOtp = {
        ...mockOptions,
        passwordReset: { ...mockOptions.passwordReset, method: 'otp' as const }
      }
      const module = await Test.createTestingModule({
        providers: [
          PasswordResetService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: optionsWithOtp },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: OtpService, useValue: mockOtpService },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BruteForceService, useValue: mockBruteForce }
        ]
      }).compile()
      otpMethodService = module.get(PasswordResetService)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when method=otp but dto.token is present (method mismatch).
    it('throws PASSWORD_RESET_TOKEN_INVALID when method=otp but dto.token is present (method mismatch)', async () => {
      // Arrange
      const dto = { ...baseDto, token: 'sometoken' }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that resets password via verifiedToken path when dto.verifiedToken is present.
    it('resets password via verifiedToken path when dto.verifiedToken is present', async () => {
      // Arrange
      const verifiedContext = JSON.stringify({
        userId: 'u2',
        email: 'user@example.com',
        tenantId: 'tenant1'
      })
      mockRedis.getdel.mockResolvedValue(verifiedContext)
      const dto = { ...baseDto, verifiedToken: 'a'.repeat(64) }

      // Act
      await otpMethodService.resetPassword(dto, mockReq)

      // Assert
      expect(mockPasswordService.hash).toHaveBeenCalledWith(baseDto.newPassword)
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('u2', 'tenant1', 'dashboard')
      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('u2', 'tenant1', 'dashboard')
      // Pin the verifiedToken Redis key template — emptying it (`getdel('')`) reads the wrong key.
      const [key] = mockRedis.getdel.mock.calls[0] as [string]
      expect(key).toMatch(/^pw_vtok:[0-9a-f]{64}$/)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when verifiedToken is consumed (getdel returns null).
    it('throws PASSWORD_RESET_TOKEN_INVALID when verifiedToken is consumed (getdel returns null)', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(null)
      const dto = { ...baseDto, verifiedToken: 'b'.repeat(64) }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when verifiedToken context email does not match.
    it('throws PASSWORD_RESET_TOKEN_INVALID when verifiedToken context email does not match', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ userId: 'u2', email: 'other@example.com', tenantId: 'tenant1' })
      )
      const dto = { ...baseDto, verifiedToken: 'c'.repeat(64) }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when verifiedToken context tenantId does not match.
    it('throws PASSWORD_RESET_TOKEN_INVALID when verifiedToken context tenantId does not match', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ userId: 'u2', email: 'user@example.com', tenantId: 'other-tenant' })
      )
      const dto = { ...baseDto, verifiedToken: 'd'.repeat(64) }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that resets password via direct OTP path when dto.otp is present.
    it('resets password via direct OTP path when dto.otp is present', async () => {
      // Arrange
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u3',
        status: 'active',
        tenantId: 'tenant1'
      })
      const dto = { ...baseDto, otp: '654321' }

      // Act
      await otpMethodService.resetPassword(dto, mockReq)

      // Assert
      expect(mockOtpService.verify).toHaveBeenCalledTimes(1)
      // Pin the OTP purpose and the tenant:email HMAC identifier passed to verify, so emptying
      // PASSWORD_RESET_PURPOSE ('' ) or the otpIdentifier message ('') is caught.
      expect(mockOtpService.verify).toHaveBeenCalledWith(
        'password_reset',
        hmacSha256(`${baseDto.tenantId}:${baseDto.email}`, HMAC_KEY),
        '654321'
      )
      expect(mockPasswordService.hash).toHaveBeenCalledWith(baseDto.newPassword)
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('u3', 'tenant1', 'dashboard')
      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('u3', 'tenant1', 'dashboard')
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when no proof field is present (otp method).
    it('throws PASSWORD_RESET_TOKEN_INVALID when no proof field is present (otp method)', async () => {
      // Arrange
      const dto = { ...baseDto }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that propagates OTP_INVALID from OtpService.verify in direct OTP path.
    it('propagates OTP_INVALID from OtpService.verify in direct OTP path', async () => {
      // Arrange
      mockOtpService.verify.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.OTP_INVALID))
      const dto = { ...baseDto, otp: '000000' }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.OTP_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when user disappears between OTP verification and password update (direct OTP path).
    it('throws PASSWORD_RESET_TOKEN_INVALID when user disappears between OTP verification and password update (direct OTP path)', async () => {
      // Arrange
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(null)
      const dto = { ...baseDto, otp: '123456' }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })
  })

  // =========================================================================
  // verifyOtp
  // =========================================================================

  describe('verifyOtp', () => {
    const dto = { email: 'user@example.com', tenantId: 'tenant1', otp: '123456' }

    // Verifies that propagates OTP errors from OtpService.verify.
    it('propagates OTP errors from OtpService.verify', async () => {
      // Arrange
      mockOtpService.verify.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.OTP_EXPIRED))

      // Act
      let caught: unknown
      try {
        await service.verifyOtp(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.OTP_EXPIRED)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when user not found after OTP verification.
    it('throws PASSWORD_RESET_TOKEN_INVALID when user not found after OTP verification', async () => {
      // Arrange
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      // Act
      let caught: unknown
      try {
        await service.verifyOtp(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that returns a 64-character hex string on success.
    it('returns a 64-character hex string on success', async () => {
      // Arrange
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })

      // Act
      const result = await service.verifyOtp(dto, mockReq)

      // Assert
      expect(typeof result).toBe('string')
      expect(result).toHaveLength(64)
      expect(result).toMatch(/^[0-9a-f]{64}$/)
    })

    // Verifies that stores the verifiedToken in Redis with correct key prefix and 300s TTL.
    it('stores the verifiedToken in Redis with correct key prefix and 300s TTL', async () => {
      // Arrange
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })

      // Act
      await service.verifyOtp(dto, mockReq)

      // Assert
      expect(mockRedis.set).toHaveBeenCalledTimes(1)
      const [key, , ttl] = mockRedis.set.mock.calls[0]! as [string, string, number]
      expect(key).toMatch(/^pw_vtok:/)
      expect(ttl).toBe(300)
    })

    // Verifies that stores context JSON with userId, email, tenantId.
    it('stores context JSON with userId, email, tenantId', async () => {
      // Arrange
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })

      // Act
      await service.verifyOtp(dto, mockReq)

      // Assert
      expect(mockRedis.set).toHaveBeenCalledTimes(1)
      const [, contextJson] = mockRedis.set.mock.calls[0]! as [string, string, number]
      const context = JSON.parse(contextJson) as { userId: string; email: string; tenantId: string }
      expect(context.userId).toBe('u1')
      expect(context.email).toBe(dto.email)
      expect(context.tenantId).toBe(dto.tenantId)
    })
  })

  // =========================================================================
  // resendOtp
  // =========================================================================

  // Note: `resendOtp` only applies when method='otp'. This describe uses `otpMethodService`,
  // not the outer `service` (which uses method='token'). The outer beforeEach still runs first
  // — clearing mocks and setting defaults — then this inner beforeEach builds the OTP module.
  // Every control on the reset path is keyed on `hmac(tenantId:email)` — the OTP record, its
  // five-attempt ceiling, and the cooldown `initiateReset` and `resendOtp` share. Left raw, a
  // change of case was a change of key: five fresh guesses at the same code per spelling, and
  // one send per minute per spelling. All four doors canonicalize before deriving it.
  // Every proof on the reset path is single-use and consumed atomically. A breach-list
  // rejection that arrived after the consumption told the caller their password was
  // unacceptable and, in the same breath, that the credential they needed to fix it was gone —
  // the whole mail round trip repeated for a mistake the request itself carried. The judgement
  // now runs first, so nothing is spent on a request that was never going to succeed.
  describe('a rejected new password costs the caller nothing', () => {
    beforeEach(() => {
      mockPasswordService.assertAcceptable.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.PASSWORD_COMPROMISED)
      )
    })

    // `jest.clearAllMocks()` clears recorded calls, not implementations — without this the
    // rejection above would follow the mock into every later suite in the file.
    afterEach(() => {
      mockPasswordService.assertAcceptable.mockResolvedValue(undefined)
    })

    it.each([
      ['token', { token: 'raw-token' }],
      ['verifiedToken', { verifiedToken: 'raw-vtok' }],
      ['otp', { otp: '123456' }]
    ])('leaves the %s unspent', async (_proof, payload) => {
      // `token` is the only proof the token-configured module accepts, and the other two the
      // only ones the OTP-configured module accepts — so each case runs under its own module.
      const method = 'token' in payload ? ('token' as const) : ('otp' as const)
      const module = await Test.createTestingModule({
        providers: [
          PasswordResetService,
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: { ...mockOptions, passwordReset: { ...mockOptions.passwordReset, method } }
          },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: OtpService, useValue: mockOtpService },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BruteForceService, useValue: mockBruteForce }
        ]
      }).compile()
      const svc = module.get(PasswordResetService)

      const caught = await svc
        .resetPassword(
          {
            email: 'user@example.com',
            tenantId: 'tenant1',
            newPassword: 'hunter2hunter2',
            ...payload
          } as never,
          mockReq
        )
        .catch((err: unknown) => err)

      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_COMPROMISED)
      expect(mockRedis.getdel).not.toHaveBeenCalled()
      expect(mockOtpService.verify).not.toHaveBeenCalled()
    })
  })

  describe('email canonicalization', () => {
    const canonical = hmacSha256('tenant1:user@example.com', HMAC_KEY)

    it('initiateReset draws on the canonical cooldown key', async () => {
      mockRedis.setnx.mockResolvedValue(false) // already sent within the window

      await service.initiateReset(
        { email: '  USER@Example.COM ', tenantId: 'tenant1' } as never,
        mockReq
      )

      expect(mockRedis.setnx).toHaveBeenCalledWith(
        `resend:password_reset:${canonical}`,
        expect.any(Number)
      )
    })

    it('resendOtp draws on that same canonical cooldown key', async () => {
      mockRedis.setnx.mockResolvedValue(false)

      await service.resendOtp({ email: 'User@Example.com', tenantId: 'tenant1' } as never, mockReq)

      expect(mockRedis.setnx).toHaveBeenCalledWith(
        `resend:password_reset:${canonical}`,
        expect.any(Number)
      )
    })

    it('verifyOtp verifies against the canonical OTP record', async () => {
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      await service
        .verifyOtp(
          { email: 'USER@EXAMPLE.COM', tenantId: 'tenant1', otp: '123456' } as never,
          mockReq
        )
        .catch(() => undefined)

      expect(mockOtpService.verify).toHaveBeenCalledWith('password_reset', canonical, '123456')
    })
  })

  describe('resendOtp', () => {
    let otpMethodService: PasswordResetService
    const dto = { email: 'user@example.com', tenantId: 'tenant1' }

    beforeEach(async () => {
      const optionsWithOtp = {
        ...mockOptions,
        passwordReset: { ...mockOptions.passwordReset, method: 'otp' as const }
      }
      const module = await Test.createTestingModule({
        providers: [
          PasswordResetService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: optionsWithOtp },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: null },
          { provide: OtpService, useValue: mockOtpService },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BruteForceService, useValue: mockBruteForce }
        ]
      }).compile()
      otpMethodService = module.get(PasswordResetService)
    })

    // Verifies that does NOT throw when user not found (anti-enumeration).
    it('does NOT throw when user not found (anti-enumeration)', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      // Act & Assert
      await expect(otpMethodService.resendOtp(dto, mockReq)).resolves.toBeUndefined()
    })

    // Verifies that does NOT throw when user is blocked.
    it('does NOT throw when user is blocked', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'banned',
        tenantId: 'tenant1'
      })

      // Act & Assert
      await expect(otpMethodService.resendOtp(dto, mockReq)).resolves.toBeUndefined()
    })

    // Verifies that does NOT throw when cooldown is active (setnx returns false).
    it('does NOT throw when cooldown is active (setnx returns false)', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(false)

      // Act & Assert
      await expect(otpMethodService.resendOtp(dto, mockReq)).resolves.toBeUndefined()
    })

    // Verifies that does NOT send OTP when cooldown is active.
    it('does NOT send OTP when cooldown is active', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(false)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)

      // Assert
      expect(mockOtpService.generate).not.toHaveBeenCalled()
      expect(mockOtpService.store).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendPasswordResetOtp).not.toHaveBeenCalled()
    })

    // Scenario: cooldown is active (setnx=false) AND the user exists and is eligible; expected:
    // the method returns early WITHOUT generating/sending an OTP. Why: prior cooldown tests left
    // findByEmail=null, so even if `if (!wasSet)` were neutered the null user would prevent a
    // send — masking the guard. With an active user, dropping the early return (`if(false)` or
    // `{}`) would proceed into the try block and send an OTP. Asserting no generate fires kills both.
    it('returns early without generating an OTP when cooldown is active even if the user exists', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(false)
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })

      // Act
      await otpMethodService.resendOtp(dto, mockReq)
      await flushMicrotasks()

      // Assert
      expect(mockUserRepo.findByEmail).not.toHaveBeenCalled()
      expect(mockOtpService.generate).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendPasswordResetOtp).not.toHaveBeenCalled()
    })

    // Scenario: a resend attempt; expected: the cooldown is registered under a
    // `resend:password_reset:<hmac>` NX key with a 60-second TTL. Why: pins the cooldown key
    // template — emptying it (`''`) or emptying PASSWORD_RESET_PURPOSE / the otpIdentifier message
    // would collide all users onto one cooldown key, breaking per-account flood protection.
    it('registers the cooldown under resend:password_reset:{identifier} with a 60s TTL', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)

      // Assert
      const [key, ttl] = mockRedis.setnx.mock.calls[0] as [string, number]
      const expectedIdentifier = hmacSha256(`${dto.tenantId}:${dto.email}`, HMAC_KEY)
      expect(key).toBe(`resend:password_reset:${expectedIdentifier}`)
      expect(ttl).toBe(60)
    })

    // Verifies that sends OTP when cooldown not active and user found and not blocked.
    it('sends OTP when cooldown not active and user found and not blocked', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })

      // Act
      await otpMethodService.resendOtp(dto, mockReq)
      await flushMicrotasks()

      // Assert
      expect(mockOtpService.generate).toHaveBeenCalledTimes(1)
      expect(mockOtpService.store).toHaveBeenCalledTimes(1)
      expect(mockEmailProvider.sendPasswordResetOtp).toHaveBeenCalledTimes(1)
    })

    // Verifies that applies timing normalization — calls sleep.
    it('applies timing normalization — calls sleep', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)

      // Assert
      expect(mockSleep).toHaveBeenCalledTimes(1)
    })

    // Verifies that applies timing normalization even when cooldown is active.
    it('applies timing normalization even when cooldown is active', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(false)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)

      // Assert
      expect(mockSleep).toHaveBeenCalledTimes(1)
    })

    // Scenario: cooldown active, 100 ms elapsed; expected: the cooldown-branch sleep uses the
    // remaining budget max(0, 300 - 100) = 200. Why: pins that branch's formula — Math.min -> 0,
    // `300 + elapsed` -> 400, `now + start` -> huge negative -> 0. Only the original yields 200.
    it('sleeps for the remaining budget on the cooldown-active branch', async () => {
      // Arrange — first Date.now() is `start`, later calls are 100 ms after.
      mockRedis.setnx.mockResolvedValue(false)
      const nowSpy = jest.spyOn(Date, 'now')
      nowSpy.mockReturnValue(2_000_100)
      nowSpy.mockReturnValueOnce(2_000_000)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)

      // Assert
      expect(mockSleep).toHaveBeenCalledWith(200)
      nowSpy.mockRestore()
    })

    // Scenario: cooldown NOT active, user not found, 100 ms elapsed; expected: the finally-block
    // sleep uses max(0, 300 - 100) = 200. Why: pins the main-path timing formula (same mutants as
    // the cooldown branch, different call site).
    it('sleeps for the remaining budget in the finally block (cooldown not active)', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue(null)
      const nowSpy = jest.spyOn(Date, 'now')
      nowSpy.mockReturnValue(3_000_100)
      nowSpy.mockReturnValueOnce(3_000_000)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)

      // Assert
      expect(mockSleep).toHaveBeenCalledWith(200)
      nowSpy.mockRestore()
    })

    // Verifies that logs error on unexpected error inside resendOtp.
    it('logs error on unexpected error inside resendOtp', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      const unexpectedError = new Error('Unexpected failure')
      mockUserRepo.findByEmail.mockRejectedValue(unexpectedError)
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)

      // Assert
      expect(errorSpy).toHaveBeenCalledWith('resendOtp: unexpected error: <error>')
      errorSpy.mockRestore()
    })

    // Verifies that resendOtp logs a warning and skips the email send when no email provider is configured.
    it('skips email and logs warn when no email provider is configured (sendOtp null path)', async () => {
      // Arrange: build OTP service with null email provider
      const optionsWithOtp = {
        ...mockOptions,
        passwordReset: { ...mockOptions.passwordReset, method: 'otp' as const }
      }
      const noEmailModule = await Test.createTestingModule({
        providers: [
          PasswordResetService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: optionsWithOtp },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: null },
          { provide: BYMAX_AUTH_HOOKS, useValue: null },
          { provide: OtpService, useValue: mockOtpService },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BruteForceService, useValue: mockBruteForce }
        ]
      }).compile()
      const noEmailOtpService = noEmailModule.get(PasswordResetService)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })

      // Act
      await noEmailOtpService.resendOtp(dto, mockReq)

      // Assert
      expect(mockEmailProvider.sendPasswordResetOtp).not.toHaveBeenCalled()
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('no email provider configured'))
      warnSpy.mockRestore()
    })

    // Verifies that a rejection from sendPasswordResetOtp is caught and logged without propagating to the caller.
    it('logs error when sendPasswordResetOtp fire-and-forget rejects', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })
      mockEmailProvider.sendPasswordResetOtp.mockRejectedValue(new Error('SMTP down'))
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)
      await flushMicrotasks()

      // Assert
      // One argument, not two — see the OTP-redaction cases: the error object never reaches the
      // logger, so a relay quoting the body cannot carry the code into the record.
      expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('sendPasswordResetOtp failed'))
      expect(errorSpy.mock.calls[0]).toHaveLength(1)
      errorSpy.mockRestore()
    })

    // The SEAM at this site: the template puts `: ` between the identifier and the description, so
    // a value ending where the id ends and beginning where the error begins is rebuilt from two
    // fields that each contain nothing. An address can hold almost anything in a quoted local part
    // and an identifier is unconstrained, so the composition is constructible. `safeLogLine` is
    // what catches it — the per-field redactions cannot, by construction.
    it('withholds the line when the identifier and the error compose a withheld value', async () => {
      // The address is normalised to lower case before it becomes a withheld value, and the
      // description opens with the error's NAME — so the composition spells the address only when
      // that name is lower case too. A custom error class provides exactly that, which is what
      // makes this reachable rather than theoretical.
      // The composed value straddles the template's own `': '` separator: the identifier ends
      // one field and the description begins the next, and neither field contains the value.
      // The description opens with the opaque stand-in — nothing the channel wrote gets in — so
      // straddling value has to be built from.
      const named = new Error('channel down')

      const seam = { ...dto, email: 'u1: <error>' }
      mockRedis.setnx.mockResolvedValue(true)
      mockOtpService.generate.mockReturnValue('303030')
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })
      mockEmailProvider.sendPasswordResetOtp.mockRejectedValue(named)
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      await otpMethodService.resendOtp(seam, mockReq)
      await flushMicrotasks()

      const logged = errorSpy.mock.calls.map((c) => String(c[0])).join(' | ')
      expect(logged).not.toContain('u1: <error>')
      expect(logged).toContain('withheld')
      errorSpy.mockRestore()
    })

    // The recipient, which needs no quoted body. An SMTP rejection routinely NAMES the address it
    // refused, and the bundled provider strips it from the provider's own line and then rethrows
    // the original — so this service receives an error carrying the address and would log it
    // again. Removing it in one place and not the other removes it nowhere.
    it('keeps the recipient out of the log when the rejection names it', async () => {
      mockRedis.setnx.mockResolvedValue(true)
      mockOtpService.generate.mockReturnValue('204060')
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })
      mockEmailProvider.sendPasswordResetOtp.mockRejectedValue(
        new Error(`550 ${dto.email}: recipient rejected`)
      )
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      await otpMethodService.resendOtp(dto, mockReq)
      await flushMicrotasks()

      const logged = errorSpy.mock.calls.map((c) => String(c[0])).join(' | ')
      expect(logged).toContain('sendPasswordResetOtp failed')
      expect(logged).not.toContain(dto.email)
      errorSpy.mockRestore()
    })

    // `userId` is interpolated into the same line as the error, and a reset OTP is short enough
    // that an identifier containing one is a real possibility rather than a curiosity. Every field
    // the template interpolates has to be sanitised, not only the one carrying channel text.
    it('redacts the reset code from the user id as well as from the error', async () => {
      mockRedis.setnx.mockResolvedValue(true)
      mockOtpService.generate.mockReturnValue('531642')
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u-531642-x',
        status: 'active',
        tenantId: 'tenant1'
      })
      mockEmailProvider.sendPasswordResetOtp.mockRejectedValue(new Error('channel down'))
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      await otpMethodService.resendOtp(dto, mockReq)
      await flushMicrotasks()

      const logged = errorSpy.mock.calls.map((c) => String(c[0])).join(' | ')
      expect(logged).toContain('sendPasswordResetOtp failed')
      expect(logged).not.toContain('531642')
      errorSpy.mockRestore()
    })

    // A provider that throws SYNCHRONOUSLY rather than rejecting. `Promise.resolve(call())`
    // evaluates the call before the promise wraps it, so the throw skipped the redacting handler
    // entirely and surfaced in `resendOtp`'s outer catch, which logs the error raw — with the code
    // in it. The async IIFE the production path uses calls the provider INSIDE its own `try`, so a
    // synchronous throw and a rejection reach the same handler. A provider is consumer code and may
    // do either; the log line must not depend on which.
    it('keeps the reset code out of the log when the provider throws synchronously', async () => {
      mockRedis.setnx.mockResolvedValue(true)
      mockOtpService.generate.mockReturnValue('868686')
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })
      mockEmailProvider.sendPasswordResetOtp.mockImplementation(() => {
        throw new Error('550 rejected by policy: "Your code is 868686."')
      })
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      await otpMethodService.resendOtp(dto, mockReq)
      await flushMicrotasks()

      const logged = errorSpy.mock.calls.map((c) => String(c[0])).join(' | ')
      expect(logged).not.toContain('868686')
      // On a credential path nothing the relay wrote reaches the line, and nothing is parsed off it
      // either. What remains is the label this library owns plus the opaque stand-in — which IS the
      // diagnosis: it says the send failed and how deep the failure was reported from.
      expect(logged).not.toContain('rejected by policy')
      expect(logged).not.toContain('550')
      expect(logged).toBe('sendPasswordResetOtp failed for user u1: <error>')
      errorSpy.mockRestore()
    })

    // The measured shape of the leak, at this call site: a relay rejecting with 550 while quoting
    // the body puts the reset code into the provider's error. This code resets a password, so a
    // log line carrying it is a credential in the operator's pipeline until its TTL expires.
    // Detachment matters MORE here than on the notice paths, and for a reason beyond latency.
    // This endpoint answers identically whether or not the address exists — that is the
    // anti-enumeration guarantee. Awaiting the send would make the response time depend on the
    // channel, and the channel is only reached for an address that EXISTS, so a stalled relay
    // would turn a timing difference into the very distinction the identical body hides.
    it('answers without waiting for a send that never settles', async () => {
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })
      let release = (): void => {}
      mockEmailProvider.sendPasswordResetOtp.mockReturnValueOnce(
        new Promise<void>((resolve) => {
          release = resolve
        })
      )

      await expect(otpMethodService.resendOtp(dto, mockReq)).resolves.toBeUndefined()

      expect(mockEmailProvider.sendPasswordResetOtp).toHaveBeenCalled()

      release()
      await Promise.resolve()
    })

    it('keeps the reset code out of the log when the relay quotes it back', async () => {
      mockRedis.setnx.mockResolvedValue(true)
      mockOtpService.generate.mockReturnValue('424242')
      mockUserRepo.findByEmail.mockResolvedValue({
        id: 'u1',
        status: 'active',
        tenantId: 'tenant1'
      })
      // The error's NAME carries the code too, and the name is as much the channel's field to fill
      // as the message is — which is why neither reaches the line.
      const named = new Error('550 rejected by policy: "Your code is 424242."')
      named.name = 'E424242'
      mockEmailProvider.sendPasswordResetOtp.mockRejectedValue(named)
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      await otpMethodService.resendOtp(dto, mockReq)
      await flushMicrotasks()

      // The error's NAME carries the code here, and no part of it reaches the line: the
      // description carries nothing the channel authored. The assertion is not merely that the
      // code is absent — it is that the ORDINARY line survives, because a build that let the name
      // through would have `safeLogLine` withhold the whole record to stop it, and the operator
      // would lose the diagnosis to a guard that should never have had to fire.
      const logged = errorSpy.mock.calls[0]?.[0] as string
      expect(logged).not.toContain('424242')
      // On a credential path nothing the relay wrote reaches the line, and nothing is parsed off it
      // either. What remains is the label this library owns plus the opaque stand-in — which IS the
      // diagnosis: it says the send failed and how deep the failure was reported from.
      expect(logged).not.toContain('rejected by policy')
      expect(logged).not.toContain('550')
      expect(logged).toBe('sendPasswordResetOtp failed for user u1: <error>')
      errorSpy.mockRestore()
    })
  })

  // =========================================================================
  // afterPasswordReset hook
  // =========================================================================

  describe('afterPasswordReset hook', () => {
    const FULL_USER = {
      id: 'u1',
      email: 'user@example.com',
      tenantId: 'tenant1',
      name: 'Test User',
      role: 'member',
      status: 'active',
      emailVerified: true,
      mfaEnabled: false,
      passwordHash: 'secret',
      mfaSecret: null,
      mfaRecoveryCodes: null,
      lastLoginAt: null,
      createdAt: new Date()
    }

    // Verifies that afterPasswordReset is called once after a successful reset and receives a SafeAuthUser with credential fields stripped.
    it('fires afterPasswordReset hook after successful password reset', async () => {
      // Arrange: build service with hooks injected
      const module = await buildModule(mockEmailProvider, mockHooks)
      const hookedService = module.get(PasswordResetService)
      const validContext = JSON.stringify({
        userId: 'u1',
        email: 'user@example.com',
        tenantId: 'tenant1'
      })
      mockRedis.getdel.mockResolvedValue(validContext)
      mockUserRepo.findById.mockResolvedValue(FULL_USER)

      // Act
      await hookedService.resetPassword(
        {
          email: 'user@example.com',
          tenantId: 'tenant1',
          newPassword: 'NewPass123!',
          token: 'tok'
        },
        mockReq
      )
      await flushMicrotasks()

      // Assert
      expect(mockHooks.afterPasswordReset).toHaveBeenCalledTimes(1)
      // Verify credential fields are stripped from the hook argument
      const [hookUser] = mockHooks.afterPasswordReset.mock.calls[0]! as [Record<string, unknown>]
      expect(hookUser['passwordHash']).toBeUndefined()
      expect(hookUser['mfaSecret']).toBeUndefined()
      expect(hookUser['id']).toBe('u1')
    })

    // Verifies that afterPasswordReset is not called when findById returns null after the reset.
    it('does not fire hook when findById returns null after reset', async () => {
      // Arrange
      const module = await buildModule(mockEmailProvider, mockHooks)
      const hookedService = module.get(PasswordResetService)
      const validContext = JSON.stringify({
        userId: 'u1',
        email: 'user@example.com',
        tenantId: 'tenant1'
      })
      mockRedis.getdel.mockResolvedValue(validContext)
      mockUserRepo.findById.mockResolvedValue(null)

      // Act
      await hookedService.resetPassword(
        {
          email: 'user@example.com',
          tenantId: 'tenant1',
          newPassword: 'NewPass123!',
          token: 'tok'
        },
        mockReq
      )
      await flushMicrotasks()

      // Assert
      expect(mockHooks.afterPasswordReset).not.toHaveBeenCalled()
    })

    // Verifies that a rejection from the afterPasswordReset hook is caught and logged without propagating to the caller.
    it('logs error and does not throw when afterPasswordReset hook throws', async () => {
      // Arrange
      const module = await buildModule(mockEmailProvider, mockHooks)
      const hookedService = module.get(PasswordResetService)
      const validContext = JSON.stringify({
        userId: 'u1',
        email: 'user@example.com',
        tenantId: 'tenant1'
      })
      mockRedis.getdel.mockResolvedValue(validContext)
      mockUserRepo.findById.mockResolvedValue(FULL_USER)
      mockHooks.afterPasswordReset.mockRejectedValue(new Error('hook failure'))
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      // Act
      await hookedService.resetPassword(
        {
          email: 'user@example.com',
          tenantId: 'tenant1',
          newPassword: 'NewPass123!',
          token: 'tok'
        },
        mockReq
      )
      await flushMicrotasks()

      // Assert
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining('afterPasswordReset hook threw: ')
      )
      errorSpy.mockRestore()
    })
  })
})
