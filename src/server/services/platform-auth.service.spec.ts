/**
 * PlatformAuthService — unit tests
 *
 * Tests the full authentication lifecycle for platform administrators:
 * login (with/without MFA, brute-force, credential errors), logout (JTI revocation,
 * grace-pointer cleanup), refresh (delegation), getMe (safe projection), and
 * revokeAllPlatformSessions (atomic delegation).
 *
 * Mocking strategy: all collaborators are plain jest mock objects. No real Redis,
 * no real JWT, no real password hash. The test module is rebuilt in beforeEach
 * so mocks are cleanly reset between every test.
 */

import { createHash } from 'node:crypto'

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_PLATFORM_USER_REPOSITORY } from '../bymax-auth.constants'
import { hmacSha256, sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'
import { PasswordService } from './password.service'
import { PlatformAuthService } from './platform-auth.service'
import { TokenManagerService } from './token-manager.service'

// ---------------------------------------------------------------------------
// Test doubles — platform admin records
// ---------------------------------------------------------------------------

const PLATFORM_ADMIN = {
  id: 'admin-1',
  email: 'admin@example.com',
  name: 'Super Admin',
  passwordHash: 'scrypt:salt:hash',
  role: 'super_admin',
  status: 'active',
  mfaEnabled: false,
  mfaSecret: undefined,
  mfaRecoveryCodes: undefined,
  lastLoginAt: null,
  updatedAt: new Date('2026-01-01'),
  createdAt: new Date('2026-01-01')
}

const PLATFORM_ADMIN_MFA = {
  ...PLATFORM_ADMIN,
  mfaEnabled: true,
  mfaSecret: 'encrypted-totp-secret',
  mfaRecoveryCodes: ['hash1', 'hash2']
}

// Safe view used for result comparison (no credential fields).
const SAFE_ADMIN = {
  id: 'admin-1',
  email: 'admin@example.com',
  name: 'Super Admin',
  role: 'super_admin',
  status: 'active',
  mfaEnabled: false,
  lastLoginAt: null,
  updatedAt: new Date('2026-01-01'),
  createdAt: new Date('2026-01-01')
}

const PLATFORM_AUTH_RESULT = {
  admin: SAFE_ADMIN,
  accessToken: 'access.jwt',
  rawRefreshToken: 'raw-refresh-uuid'
}

const ROTATED_TOKEN_RESULT = {
  session: { userId: 'admin-1', tenantId: '', role: 'super_admin' },
  accessToken: 'new-access.jwt',
  rawRefreshToken: 'new-raw-refresh'
}

// JWT secret used in mockOptions — must be ≥32 chars for hmacSha256 key material.
const JWT_SECRET = 'test-jwt-secret-32bytes-exact-here!!'

/**
 * HMAC key derivation — MUST mirror {@link resolveOptions.deriveHmacKey}.
 * Tests that assert Redis-identifier shapes recompute the key here rather than
 * depending on a runtime export so that any drift in the derivation surface
 * fails loudly at test time.
 */
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

// ---------------------------------------------------------------------------
// Mock collaborators
// ---------------------------------------------------------------------------

const mockPlatformUserRepo = {
  findByEmail: jest.fn(),
  findById: jest.fn(),
  updateLastLogin: jest.fn(),
  updateMfa: jest.fn(),
  updatePassword: jest.fn(),
  updateStatus: jest.fn()
}

const mockPasswordService = {
  hash: jest.fn(),
  compare: jest.fn(),
  compareDummy: jest.fn()
}

const mockTokenManager = {
  issuePlatformTokens: jest.fn(),
  issueMfaTempToken: jest.fn(),
  reissuePlatformTokens: jest.fn(),
  verifyPlatformIgnoringExpiry: jest.fn()
}

const mockBruteForce = {
  isLockedOut: jest.fn(),
  recordFailure: jest.fn(),
  resetFailures: jest.fn(),
  getRemainingLockoutSeconds: jest.fn()
}

const mockRedis = {
  set: jest.fn(),
  del: jest.fn(),
  srem: jest.fn(),
  readSessionOwner: jest.fn(),
  invalidateUserSessions: jest.fn(),
  bumpUserTokenEpoch: jest.fn()
}

const mockOptions = {
  jwt: { secret: JWT_SECRET },
  hmacKey: HMAC_KEY,
  previousHmacKeys: [],
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED']
}

// ---------------------------------------------------------------------------
// Suite — PlatformAuthService
// ---------------------------------------------------------------------------

/** The wire code carried by a thrown `AuthException`. */
function getErrorCode(err: unknown): string {
  if (!(err instanceof AuthException)) throw new Error(`not an AuthException: ${String(err)}`)
  return (err.getResponse() as { error: { code: string } }).error.code
}

describe('PlatformAuthService', () => {
  let service: PlatformAuthService

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [
        PlatformAuthService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY, useValue: mockPlatformUserRepo },
        { provide: PasswordService, useValue: mockPasswordService },
        { provide: TokenManagerService, useValue: mockTokenManager },
        { provide: BruteForceService, useValue: mockBruteForce },
        { provide: AuthRedisService, useValue: mockRedis }
      ]
    }).compile()

    service = module.get(PlatformAuthService)
  })

  // ---------------------------------------------------------------------------
  // login
  // ---------------------------------------------------------------------------

  describe('login', () => {
    const dto = { email: 'admin@example.com', password: 'SecureAdminPass123' }
    const ip = '1.2.3.4'
    const userAgent = 'TestBrowser/1.0'

    beforeEach(() => {
      // Default: not locked, admin found, password matches, no MFA, tokens issued
      mockBruteForce.isLockedOut.mockResolvedValue(false)
      mockBruteForce.recordFailure.mockResolvedValue(undefined)
      mockBruteForce.resetFailures.mockResolvedValue(undefined)
      mockBruteForce.getRemainingLockoutSeconds.mockResolvedValue(120)
      mockPlatformUserRepo.findByEmail.mockResolvedValue(PLATFORM_ADMIN)
      mockPasswordService.compare.mockResolvedValue(true)
      mockPasswordService.compareDummy.mockResolvedValue(false)
      mockTokenManager.issuePlatformTokens.mockResolvedValue(PLATFORM_AUTH_RESULT)
      mockPlatformUserRepo.updateLastLogin.mockResolvedValue(undefined)
    })

    // Verifies the complete happy path: valid credentials with no MFA → auth result + updateLastLogin side effect.
    it('should return PlatformAuthResult and call updateLastLogin on success', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
      const result = await service.login(dto, ip, userAgent)
      expect(result).toBe(PLATFORM_AUTH_RESULT)
      // Fire-and-forget: drain the microtask queue so the updateLastLogin call completes.
      await Promise.resolve()
      expect(mockPlatformUserRepo.updateLastLogin).toHaveBeenCalledWith(PLATFORM_ADMIN.id)
      // Pin the success log template so emptying it is caught.
      const logged = logSpy.mock.calls.map((c) => String(c[0])).join(' ')
      expect(logged).toContain('login: success')
      logSpy.mockRestore()
    })

    // Verifies that the brute-force identifier is computed as hmacSha256('platform:' + email, secret)
    // so the stored Redis key cannot be reversed via dictionary lookup to reveal the admin email.
    it('should build the brute-force identifier as hmacSha256("platform:email", jwt.secret)', async () => {
      await service.login(dto, ip, userAgent)
      const expectedId = hmacSha256('platform:' + dto.email, HMAC_KEY)
      expect(mockBruteForce.isLockedOut).toHaveBeenCalledWith(expectedId)
      expect(mockBruteForce.resetFailures).toHaveBeenCalledWith(expectedId)
    })

    // Verifies that issuePlatformTokens receives the safe admin (no passwordHash/mfaSecret/mfaRecoveryCodes).
    it('should strip credential fields from admin before calling issuePlatformTokens', async () => {
      await service.login(dto, ip, userAgent)
      const adminArg = (mockTokenManager.issuePlatformTokens.mock.calls[0] as [unknown])[0]
      expect(adminArg).not.toHaveProperty('passwordHash')
      expect(adminArg).not.toHaveProperty('mfaSecret')
      expect(adminArg).not.toHaveProperty('mfaRecoveryCodes')
    })

    // Verifies ACCOUNT_LOCKED is thrown when bruteForce.isLockedOut returns true,
    // with the retryAfterSeconds from getRemainingLockoutSeconds attached.
    it('should throw ACCOUNT_LOCKED (429) when the account is locked', async () => {
      mockBruteForce.isLockedOut.mockResolvedValue(true)
      mockBruteForce.getRemainingLockoutSeconds.mockResolvedValue(300)

      let caught: AuthException | undefined
      try {
        await service.login(dto, ip, userAgent)
      } catch (e) {
        caught = e instanceof AuthException ? e : undefined
      }
      expect(caught).toBeInstanceOf(AuthException)
      const response = caught!.getResponse() as {
        error: { code: string; retryAfterSeconds: number }
      }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
      expect(caught!.getStatus()).toBe(429)
    })

    // Scenario: login on a locked account; expected: a warn log identifying the lock event is
    // emitted. Why: pins the "account locked" log template so emptying it is caught — the lock
    // path is otherwise observable only via the thrown ACCOUNT_LOCKED code.
    it('should log a warning identifying the account-locked event', async () => {
      mockBruteForce.isLockedOut.mockResolvedValue(true)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await expect(service.login(dto, ip, userAgent)).rejects.toThrow(AuthException)

      const logged = warnSpy.mock.calls.map((c) => String(c[0])).join(' ')
      expect(logged).toContain('login: account locked')
      warnSpy.mockRestore()
    })

    // Verifies that retryAfterSeconds from getRemainingLockoutSeconds is included in the error.
    it('should include retryAfterSeconds from getRemainingLockoutSeconds in ACCOUNT_LOCKED', async () => {
      mockBruteForce.isLockedOut.mockResolvedValue(true)
      mockBruteForce.getRemainingLockoutSeconds.mockResolvedValue(77)

      let caught: AuthException | undefined
      try {
        await service.login(dto, ip, userAgent)
      } catch (e) {
        caught = e instanceof AuthException ? e : undefined
      }
      const response = caught!.getResponse() as {
        error: { details: { retryAfterSeconds: number } }
      }
      expect(response.error.details.retryAfterSeconds).toBe(77)
    })

    // Verifies INVALID_CREDENTIALS when the email is not found and recordFailure is called.
    it('should record failure and throw INVALID_CREDENTIALS when email is not found', async () => {
      mockPlatformUserRepo.findByEmail.mockResolvedValue(null)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      let caught: AuthException | undefined
      try {
        await service.login(dto, ip, userAgent)
      } catch (e) {
        caught = e instanceof AuthException ? e : undefined
      }
      expect(caught).toBeInstanceOf(AuthException)
      const response = caught!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
      expect(mockBruteForce.recordFailure).toHaveBeenCalled()
      // Pin the email-not-found warn log so emptying its template is caught.
      const logged = warnSpy.mock.calls.map((c) => String(c[0])).join(' ')
      expect(logged).toContain('login: invalid credentials')
      warnSpy.mockRestore()
    })

    // Verifies the anti-enumeration decoy: an unknown admin address must still pay the
    // scrypt cost. Without it the not-found path returns in single-digit milliseconds
    // while a wrong password takes tens, and that delta enumerates which administrator
    // accounts exist even though both responses carry the identical error body.
    it('should run the dummy KDF when the admin address is unknown', async () => {
      mockPlatformUserRepo.findByEmail.mockResolvedValue(null)
      jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await expect(service.login(dto, ip, userAgent)).rejects.toBeInstanceOf(AuthException)

      expect(mockPasswordService.compareDummy).toHaveBeenCalledWith(dto.password)
    })

    // Verifies the status gate refuses a suspended administrator that presents the
    // correct password. Without it a revoked operator keeps full platform access for as
    // long as the credential is known — the password check alone says nothing about
    // whether the account is still permitted to authenticate.
    it('should reject a blocked admin even when the password is correct', async () => {
      mockPlatformUserRepo.findByEmail.mockResolvedValue({
        ...PLATFORM_ADMIN,
        status: 'SUSPENDED'
      })

      let caught: AuthException | undefined
      try {
        await service.login(dto, ip, userAgent)
      } catch (e) {
        caught = e instanceof AuthException ? e : undefined
      }

      expect(caught).toBeInstanceOf(AuthException)
      const response = caught!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.ACCOUNT_SUSPENDED)
      expect(caught!.getStatus()).toBe(403)
      expect(mockTokenManager.issuePlatformTokens).not.toHaveBeenCalled()
    })

    // Verifies the status gate runs BEFORE the KDF. Ordering is the security property:
    // if it ran after, an attacker knowing a disabled address could force unbounded
    // scrypt work with attempts that could never succeed.
    // This used to assert the opposite — that a blocked admin was refused WITHOUT paying the
    // KDF. That saving answered with the administrator's own status in a millisecond, which
    // enumerated operator accounts and read their moderation state on the highest-privilege
    // plane. The password is proved first now, and the state is described only to whoever
    // proved it.
    it('should refuse a blocked admin only after proving the password', async () => {
      mockPlatformUserRepo.findByEmail.mockResolvedValue({ ...PLATFORM_ADMIN, status: 'BANNED' })
      mockPasswordService.compare.mockResolvedValue(true)

      await expect(service.login(dto, ip, userAgent)).rejects.toBeInstanceOf(AuthException)

      expect(mockPasswordService.compare).toHaveBeenCalled()
    })

    // …and a WRONG password on a blocked admin is indistinguishable from a wrong password on
    // any other account: same code, and the attempt is counted so probing is bounded by the
    // lockout rather than only by the per-IP limit.
    it('should answer a wrong password on a blocked admin like any other wrong password', async () => {
      mockPlatformUserRepo.findByEmail.mockResolvedValue({ ...PLATFORM_ADMIN, status: 'BANNED' })
      mockPasswordService.compare.mockResolvedValue(false)

      const err = await service.login(dto, ip, userAgent).catch((e: unknown) => e)

      expect(err).toBeInstanceOf(AuthException)
      expect(getErrorCode(err)).toBe(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
      expect(mockBruteForce.recordFailure).toHaveBeenCalled()
    })

    // Verifies an MFA-enrolled admin whose account is blocked never receives a temp
    // token. The MFA branch sits after the gate, so a blocked account must fail before
    // it — otherwise the challenge flow would hand out a path back to a live session.
    it('should not issue an MFA challenge for a blocked admin', async () => {
      mockPlatformUserRepo.findByEmail.mockResolvedValue({
        ...PLATFORM_ADMIN_MFA,
        status: 'INACTIVE'
      })

      await expect(service.login(dto, ip, userAgent)).rejects.toBeInstanceOf(AuthException)

      expect(mockTokenManager.issueMfaTempToken).not.toHaveBeenCalled()
    })

    // Verifies the lockout identifier is derived from the CANONICAL email. Without
    // normalization each casing of one address is a distinct brute-force bucket that
    // resolves the same admin, so an attacker rotates the case to reset the counter and
    // the lockout never trips — the case-rotation bypass.
    it('should derive the brute-force identifier from the normalized email', async () => {
      await service.login({ ...dto, email: '  ADMIN@Example.COM  ' }, ip, userAgent)

      const canonicalIdentifier = hmacSha256('platform:admin@example.com', HMAC_KEY)
      expect(mockBruteForce.isLockedOut).toHaveBeenCalledWith(canonicalIdentifier)
    })

    // Verifies the repository lookup also receives the canonical address, so the stored
    // identity and the lockout bucket can never be keyed on different values.
    it('should look the admin up by the normalized email', async () => {
      await service.login({ ...dto, email: 'ADMIN@EXAMPLE.COM' }, ip, userAgent)

      expect(mockPlatformUserRepo.findByEmail).toHaveBeenCalledWith('admin@example.com')
    })

    // Verifies INVALID_CREDENTIALS when the password does not match and recordFailure is called.
    it('should record failure and throw INVALID_CREDENTIALS when password is wrong', async () => {
      mockPasswordService.compare.mockResolvedValue(false)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      let caught: AuthException | undefined
      try {
        await service.login(dto, ip, userAgent)
      } catch (e) {
        caught = e instanceof AuthException ? e : undefined
      }
      expect(caught).toBeInstanceOf(AuthException)
      const response = caught!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
      expect(mockBruteForce.recordFailure).toHaveBeenCalled()
      // Pin the wrong-password warn log (a distinct call site from the email-not-found path).
      const logged = warnSpy.mock.calls.map((c) => String(c[0])).join(' ')
      expect(logged).toContain('login: invalid credentials')
      warnSpy.mockRestore()
    })

    // Verifies the MFA path: when admin.mfaEnabled is true, issueMfaTempToken is called
    // and a MfaChallengeResult is returned instead of a full PlatformAuthResult.
    it('should return MfaChallengeResult when admin has MFA enabled', async () => {
      mockPlatformUserRepo.findByEmail.mockResolvedValue(PLATFORM_ADMIN_MFA)
      mockTokenManager.issueMfaTempToken.mockResolvedValue('mfa.temp.token')

      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
      const result = await service.login(dto, ip, userAgent)
      expect(result).toEqual({ mfaRequired: true, mfaTempToken: 'mfa.temp.token' })
      expect(mockTokenManager.issueMfaTempToken).toHaveBeenCalledWith(
        PLATFORM_ADMIN_MFA.id,
        'platform'
      )
      // Tokens should NOT be issued on the MFA path.
      expect(mockTokenManager.issuePlatformTokens).not.toHaveBeenCalled()
      // Pin the MFA-challenge log template so emptying it is caught.
      const logged = logSpy.mock.calls.map((c) => String(c[0])).join(' ')
      expect(logged).toContain('login: MFA challenge issued')
      logSpy.mockRestore()
    })

    // Verifies that when updateLastLogin rejects, the error is swallowed and logged
    // but the auth result is still returned to the caller (fire-and-forget guarantee).
    it('should swallow updateLastLogin errors and still return the auth result', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
      mockPlatformUserRepo.updateLastLogin.mockRejectedValue(new Error('DB timeout'))

      const result = await service.login(dto, ip, userAgent)
      expect(result).toBe(PLATFORM_AUTH_RESULT)
      // Drain microtask queue so the fire-and-forget rejection handler runs.
      await Promise.resolve()
      expect(loggerSpy).toHaveBeenCalledWith('updateLastLogin failed', expect.any(Error))
      loggerSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // logout
  // ---------------------------------------------------------------------------

  describe('logout', () => {
    const userId = 'admin-1'
    const jti = 'a1b2c3d4-1234-4abc-8def-a1b2c3d4e5f6'
    const rawRefreshToken = 'some-opaque-refresh-token'
    const tokenHash = sha256(rawRefreshToken)

    beforeEach(() => {
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)
      mockRedis.srem.mockResolvedValue(1)
      // The stored record names the owner — logout no longer takes it from token claims.
      mockRedis.readSessionOwner.mockResolvedValue(userId)
      mockTokenManager.verifyPlatformIgnoringExpiry.mockReturnValue({
        sub: userId,
        jti,
        exp: Math.floor(Date.now() / 1000) + 3600
      })
    })

    // Verifies that when the access token still has remaining TTL, the JTI is
    // blacklisted in Redis (rv:{jti}) to prevent it being used after logout.
    it('should blacklist the JTI in Redis when the token is not yet expired', async () => {
      await service.logout('access.jwt', rawRefreshToken)
      expect(mockRedis.set).toHaveBeenCalledWith('rv:' + jti, '1', expect.any(Number))
      const ttl = (mockRedis.set.mock.calls[0] as [string, string, number])[2]
      expect(ttl).toBeGreaterThan(0)
    })

    // Verifies that when the token is already expired (exp <= now), no revocation entry
    // is written — there is nothing to blacklist since the token cannot be reused anyway.
    it('should NOT set rv:{jti} when the token has already expired', async () => {
      mockTokenManager.verifyPlatformIgnoringExpiry.mockReturnValue({
        sub: userId,
        jti,
        exp: Math.floor(Date.now() / 1000) - 1
      })
      await service.logout('access.jwt', rawRefreshToken)
      expect(mockRedis.set).not.toHaveBeenCalled()
    })

    // The boundary itself: a token expiring on this very second has zero seconds left. Writing
    // the entry with a TTL of zero is not a shorter blacklist — Redis rejects `EX 0` outright,
    // so the whole logout would throw on a token that needed no blacklisting at all.
    it('should NOT set rv:{jti} when the token expires on this very second', async () => {
      mockTokenManager.verifyPlatformIgnoringExpiry.mockReturnValue({
        sub: userId,
        jti,
        exp: Math.floor(Date.now() / 1000)
      })

      await service.logout('access.jwt', rawRefreshToken)

      expect(mockRedis.set).not.toHaveBeenCalled()
    })

    // The log line names the owner the STORED RECORD gave, and says so plainly when there was
    // none. An operator reading "adminId=" with nothing after it cannot tell an admin whose id
    // is empty from a session that was already gone.
    it.each([
      ['admin-1', 'admin-1'],
      ['', '(no live session)']
    ])('logs the owner as %s when the record names %s', async (owner, expected) => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
      mockRedis.readSessionOwner.mockResolvedValue(owner)

      await service.logout('access.jwt', rawRefreshToken)

      expect(logSpy.mock.calls.map((call) => String(call[0])).join(' ')).toContain(
        `logout: adminId=${expected}`
      )
      logSpy.mockRestore()
    })

    // The operator stepped away for longer than the fifteen-minute access lifetime. The route
    // used to sit behind a guard that refuses an expired token, so they could not sign out at
    // all and the seven-day refresh session of the highest-privilege identity in the system
    // stayed live on a console they believed they had left.
    it('should still revoke the session when the access token is absent or unverifiable', async () => {
      mockTokenManager.verifyPlatformIgnoringExpiry.mockImplementation(() => {
        throw new Error('jwt malformed')
      })

      const owner = await service.logout('', rawRefreshToken)

      expect(owner).toBe(userId)
      expect(mockRedis.del).toHaveBeenCalledWith('prt:' + tokenHash)
      expect(mockRedis.del).toHaveBeenCalledWith('prp:' + tokenHash)
      // Nothing to blacklist without a verifiable token — and nothing that needed to be.
      expect(mockRedis.set).not.toHaveBeenCalled()
    })

    // No live session matched the presented refresh token — already signed out, or expired.
    // There is no owner to prune the index for, and the operation is still a success: logout
    // is idempotent, and answering an error would tell a caller whether a token was live.
    it('should not touch the session index when no live session matched', async () => {
      mockRedis.readSessionOwner.mockResolvedValue('')

      const owner = await service.logout('access.jwt', rawRefreshToken)

      expect(owner).toBe('')
      expect(mockRedis.srem).not.toHaveBeenCalled()
      // The keys are still deleted — a DEL of an absent key is a harmless no-op, and doing it
      // unconditionally is what makes a half-rotated session final.
      expect(mockRedis.del).toHaveBeenCalledWith('prt:' + tokenHash)
    })

    // A forged access token must not be able to blacklist a `jti` it does not own: the
    // signature is still checked, only the expiry is waived.
    it('should read the owner from the stored record, not from the token claims', async () => {
      mockRedis.readSessionOwner.mockResolvedValue('the-real-owner')

      const owner = await service.logout('access.jwt', rawRefreshToken)

      expect(owner).toBe('the-real-owner')
      expect(mockRedis.readSessionOwner).toHaveBeenCalledWith('prt:' + tokenHash)
    })

    // Scenario: logout must prune the session from the platform index and drop its detail
    // record. Expected: the exact psess:/psd: keys, spelled out. Why: the platform plane has
    // its own keyspace, and a prefix typo here would leave the member behind — the session
    // would keep showing up in a listing and, worse, a later revoke-all would try to delete a
    // key that no longer matches the one logout wrote.
    it('should prune both platform index members and the detail record on logout', async () => {
      const futureExp = Math.floor(Date.now() / 1000) + 3600

      await service.logout('access.jwt', rawRefreshToken)

      expect(mockRedis.srem).toHaveBeenCalledWith('psess:' + userId, 'prt:' + tokenHash)
      expect(mockRedis.srem).toHaveBeenCalledWith('psess:' + userId, 'prp:' + tokenHash)
      expect(mockRedis.del).toHaveBeenCalledWith('psd:' + tokenHash)
    })

    // Scenario: the same logout, watching the dashboard index. Expected: untouched. Why: the
    // two planes have separate id spaces that may collide, so a platform logout reaching into
    // `sess:` would prune a member belonging to an unrelated user. `rust-auth` never touches
    // the other plane's index either.
    it('should leave the dashboard index alone on a platform logout', async () => {
      const futureExp = Math.floor(Date.now() / 1000) + 3600

      await service.logout('access.jwt', rawRefreshToken)

      expect(mockRedis.srem).not.toHaveBeenCalledWith('sess:' + userId, 'prt:' + tokenHash)
      expect(mockRedis.srem).not.toHaveBeenCalledWith('sess:' + userId, 'prp:' + tokenHash)
    })

    // Verifies that the primary platform refresh token key (prt:{hash}) is deleted from Redis.
    it('should delete prt:{sha256(rawRefreshToken)} from Redis', async () => {
      await service.logout('access.jwt', rawRefreshToken)
      expect(mockRedis.del).toHaveBeenCalledWith('prt:' + tokenHash)
    })

    // Scenario: logout of an admin; expected: a log identifying the logout event (with the
    // adminId) is emitted. Why: pins the "logout: adminId=" template so emptying it is caught —
    // logout otherwise has only Redis side effects, no return value.
    it('should log the logout event with the admin id', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
      await service.logout('access.jwt', rawRefreshToken)
      const logged = logSpy.mock.calls.map((c) => String(c[0])).join(' ')
      expect(logged).toContain('logout: adminId=')
      logSpy.mockRestore()
    })

    // Verifies that the grace-pointer key (prp:{hash}) is also deleted during logout
    // so a partially-rotated session cannot be reused after the admin logs out.
    it('should delete prp:{sha256(rawRefreshToken)} from Redis', async () => {
      await service.logout('access.jwt', rawRefreshToken)
      expect(mockRedis.del).toHaveBeenCalledWith('prp:' + tokenHash)
    })

    // Verifies that prt:{hash} is removed from the per-user psess: SET so that
    // a future revokeAllPlatformSessions call does not try to delete an already-gone key.
    it('should srem prt:{hash} from psess:{userId}', async () => {
      await service.logout('access.jwt', rawRefreshToken)
      expect(mockRedis.srem).toHaveBeenCalledWith('psess:' + userId, 'prt:' + tokenHash)
    })

    // Verifies that prp:{hash} is also removed from the per-user psess: SET.
    it('should srem prp:{hash} from psess:{userId}', async () => {
      await service.logout('access.jwt', rawRefreshToken)
      expect(mockRedis.srem).toHaveBeenCalledWith('psess:' + userId, 'prp:' + tokenHash)
    })
  })

  // ---------------------------------------------------------------------------
  // refresh
  // ---------------------------------------------------------------------------

  describe('refresh', () => {
    const ip = '1.2.3.4'
    const userAgent = 'TestBrowser/1.0'

    // Verifies that refresh is a thin delegation to TokenManagerService.reissuePlatformTokens —
    // the caller only needs to pass the raw token; complex rotation logic lives in the manager.
    it('should delegate to tokenManager.reissuePlatformTokens and return its result', async () => {
      const rotated = {
        session: { userId: 'admin-1', tenantId: '', role: 'SUPER_ADMIN' },
        accessToken: 'new.access',
        rawRefreshToken: 'new-refresh'
      }
      mockTokenManager.reissuePlatformTokens.mockResolvedValue(rotated)
      mockPlatformUserRepo.findById.mockResolvedValue(PLATFORM_ADMIN)

      const result = await service.refresh('old-refresh', ip, userAgent)

      expect(result).toBe(rotated)
      expect(mockTokenManager.reissuePlatformTokens).toHaveBeenCalledWith(
        'old-refresh',
        ip,
        userAgent
      )
    })

    // The backstop the dashboard plane has carried since ASVS v5 §7.4.2 was applied to it, and
    // which this plane went without: rotation works entirely from the stored `prt:` record, so
    // a SUSPENDED or BANNED operator kept renewing access every fifteen minutes for the
    // refresh token's whole lifetime — on the highest-privilege identity in the system.
    it.each([['BANNED'], ['SUSPENDED'], ['INACTIVE']])(
      'should refuse the rotation and end every platform session for a %s admin',
      async (status) => {
        mockTokenManager.reissuePlatformTokens.mockResolvedValue({
          session: { userId: 'admin-1', tenantId: '', role: 'SUPER_ADMIN' },
          accessToken: 'new.access',
          rawRefreshToken: 'new-refresh'
        })
        mockPlatformUserRepo.findById.mockResolvedValue({ ...PLATFORM_ADMIN, status })

        await expect(service.refresh('old-refresh', ip, userAgent)).rejects.toThrow(AuthException)
        // Compensated, not merely refused: the rotation already minted a live pair, and
        // leaving it would hand back the access this gate exists to end.
        expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('admin-1', 'platform')
        expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('admin-1', 'platform')
      }
    )

    // The account was deleted while the session outlived it.
    it('should refuse the rotation when the admin no longer exists', async () => {
      mockTokenManager.reissuePlatformTokens.mockResolvedValue({
        session: { userId: 'admin-1', tenantId: '', role: 'SUPER_ADMIN' },
        accessToken: 'new.access',
        rawRefreshToken: 'new-refresh'
      })
      mockPlatformUserRepo.findById.mockResolvedValue(null)

      await expect(service.refresh('old-refresh', ip, userAgent)).rejects.toThrow(AuthException)
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('admin-1', 'platform')
    })

    // Verifies that errors thrown by reissuePlatformTokens propagate without wrapping —
    // the REFRESH_TOKEN_INVALID AuthException must surface unchanged to the controller.
    it('should propagate errors from reissuePlatformTokens', async () => {
      mockTokenManager.reissuePlatformTokens.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
      )
      await expect(service.refresh('invalid-token', '1.2.3.4', 'Browser/1')).rejects.toThrow(
        AuthException
      )
    })
  })

  // ---------------------------------------------------------------------------
  // getMe
  // ---------------------------------------------------------------------------

  describe('getMe', () => {
    // Verifies the happy path: admin exists → safe projection returned (no credentials).
    it('should return SafeAuthPlatformUser when admin is found', async () => {
      mockPlatformUserRepo.findById.mockResolvedValue(PLATFORM_ADMIN)
      const result = await service.getMe('admin-1')
      expect(result).not.toHaveProperty('passwordHash')
      expect(result).not.toHaveProperty('mfaSecret')
      expect(result).not.toHaveProperty('mfaRecoveryCodes')
      expect(result.id).toBe('admin-1')
      expect(result.email).toBe('admin@example.com')
    })

    // Verifies that when the admin record cannot be found (deleted/suspended after login),
    // TOKEN_INVALID is thrown so the guard invalidates the session.
    it('should throw TOKEN_INVALID when the admin no longer exists', async () => {
      mockPlatformUserRepo.findById.mockResolvedValue(null)

      let caught: AuthException | undefined
      try {
        await service.getMe('admin-1')
      } catch (e) {
        caught = e instanceof AuthException ? e : undefined
      }
      expect(caught).toBeInstanceOf(AuthException)
      const response = caught!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    })

    // Verifies that an admin with mfaSecret and mfaRecoveryCodes set also has those
    // stripped in the safe projection, even when they are non-undefined values.
    it('should strip mfaSecret and mfaRecoveryCodes even when they are set', async () => {
      mockPlatformUserRepo.findById.mockResolvedValue(PLATFORM_ADMIN_MFA)
      const result = await service.getMe('admin-1')
      expect(result).not.toHaveProperty('passwordHash')
      expect(result).not.toHaveProperty('mfaSecret')
      expect(result).not.toHaveProperty('mfaRecoveryCodes')
      expect((result as { mfaEnabled: boolean }).mfaEnabled).toBe(true)
    })
  })

  // ---------------------------------------------------------------------------
  // revokeAllPlatformSessions
  // ---------------------------------------------------------------------------

  describe('revokeAllPlatformSessions', () => {
    // Verifies that revokeAllPlatformSessions delegates entirely to the atomic Lua helper
    // invalidateUserSessions — no SMEMBERS+loop which would have a TOCTOU race.
    it('should delegate to redis.invalidateUserSessions with the userId', async () => {
      mockRedis.invalidateUserSessions.mockResolvedValue(undefined)
      await service.revokeAllPlatformSessions('admin-1')
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('admin-1', 'platform')
    })

    // Scenario: the same call, watching the token epoch. Expected: bumped, on the PLATFORM
    // plane, after the sweep. Why: "log out everywhere" that leaves every outstanding access
    // token working to expiry is not what those words promise — the epoch is the only thing
    // that reaches stateless tokens. Bumped last so a failed sweep leaves the operation
    // visibly incomplete instead of reading as done while the sessions live on.
    it('should bump the platform token epoch after the sweep', async () => {
      mockRedis.invalidateUserSessions.mockResolvedValue(undefined)
      mockRedis.bumpUserTokenEpoch.mockResolvedValue(1)

      await service.revokeAllPlatformSessions('admin-1')

      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('admin-1', 'platform')
      const sweepOrder = mockRedis.invalidateUserSessions.mock.invocationCallOrder[0] as number
      const bumpOrder = mockRedis.bumpUserTokenEpoch.mock.invocationCallOrder[0] as number
      expect(sweepOrder).toBeLessThan(bumpOrder)
    })

    // Verifies that errors from invalidateUserSessions propagate so the caller can handle
    // them — and that the epoch is then NOT bumped, keeping the failure visible.
    it('should propagate errors from redis.invalidateUserSessions and skip the bump', async () => {
      mockRedis.invalidateUserSessions.mockRejectedValue(new Error('Redis timeout'))
      await expect(service.revokeAllPlatformSessions('admin-1')).rejects.toThrow('Redis timeout')
      expect(mockRedis.bumpUserTokenEpoch).not.toHaveBeenCalled()
    })
  })
})
