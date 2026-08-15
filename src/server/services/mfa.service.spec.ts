/**
 * @fileoverview Tests for MfaService — TOTP setup, verify-enable, challenge, and disable flows.
 *
 * All external dependencies (Redis, repositories, email, brute-force) are mocked.
 * The AES-256-GCM encrypt/decrypt functions are exercised with a real key to avoid
 * mocking crypto internals, consistent with the project's testing guidelines.
 */

import { createHash } from 'node:crypto'

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { hmacSha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'
import { MfaService } from './mfa.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

/**
 * Valid 32-byte AES-256-GCM key for testing encrypt/decrypt.
 * TEST FIXTURE ONLY — not a real credential.
 * A deterministic key derived from a constant, safe to use in tests and
 * structurally valid for AES-256-GCM (exactly 32 bytes).
 */
const VALID_ENCRYPTION_KEY = Buffer.from('nest-auth-test-encryption-key-32').toString('base64')

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const SAFE_USER = {
  id: 'user-1',
  email: 'user@example.com',
  name: 'Test User',
  role: 'member',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}

const AUTH_USER_MFA_DISABLED = {
  ...SAFE_USER,
  passwordHash: 'hash',
  mfaEnabled: false,
  mfaSecret: null,
  mfaRecoveryCodes: null
}

const AUTH_USER_MFA_ENABLED = {
  ...SAFE_USER,
  passwordHash: 'hash',
  mfaEnabled: true,
  mfaSecret: 'PLACEHOLDER_ENCRYPTED_SECRET', // replaced per-test with a real encrypted value
  mfaRecoveryCodes: ['$scrypt$hashed$code1', '$scrypt$hashed$code2']
}

const SAFE_ADMIN = {
  id: 'admin-1',
  email: 'admin@platform.com',
  name: 'Platform Admin',
  role: 'super-admin',
  status: 'active',
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01'),
  updatedAt: new Date('2026-01-01')
}

const mockUserRepo = {
  findById: jest.fn(),
  updateMfa: jest.fn()
}

const mockPlatformUserRepo = {
  findById: jest.fn(),
  updateMfa: jest.fn()
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

const mockPasswordService = {
  hash: jest.fn(),
  compare: jest.fn()
}

const mockEmailProvider = {
  sendMfaEnabledNotification: jest.fn(),
  sendMfaDisabledNotification: jest.fn()
}

const mockHooks = {
  afterMfaEnabled: jest.fn(),
  afterMfaDisabled: jest.fn(),
  afterMfaRecoveryCodesRegenerated: jest.fn(),
  afterLogin: jest.fn()
}

// TEST FIXTURE ONLY — not a real JWT secret.
const JWT_SECRET = 'nest-auth-test-jwt-secret-32chars+'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

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
  sessions: { enabled: false, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
}

const mockSessionService = {
  createSession: jest.fn(),
  revokeSession: jest.fn(),
  rotateSession: jest.fn()
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

/** The account password every enrolment test re-proves. */
const PASSWORD = 'correct horse battery staple'

/**
 * Answer the recent-authentication marker and nothing else.
 *
 * `MfaService.setup` also does a fast-path `get` on the pending-setup key, so a blanket
 * `mockResolvedValue` would feed `'1'` to the setup-record parser too. Keyed on the `ra:`
 * prefix so each test says exactly which lookup it is arranging.
 */
function onlyRecentAuth(present: boolean) {
  return async (key: string) => (present && key.startsWith('ra:') ? '1' : null)
}

describe('MfaService', () => {
  let service: MfaService

  beforeEach(async () => {
    // resetAllMocks clears both call history and mock implementations, preventing state bleed.
    // All default return values are configured below.
    jest.resetAllMocks()

    // Default safe mocks — override per-test as needed
    mockRedis.get.mockResolvedValue(null)
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.del.mockResolvedValue(true)
    // Both single-use markers this service sets — the recovery-code claim and the TOTP
    // anti-replay marker — report "first to arrive" unless a test says otherwise.
    mockRedis.setnx.mockResolvedValue(true)
    // The temp-token consume reports whether THIS call removed the marker — the
    // exactly-once signal the challenge gates on. `true` is the ordinary case: nobody
    // raced us.
    mockTokenManager.consumeMfaTempToken.mockResolvedValue(true)
    mockRedis.sadd.mockResolvedValue(1)
    mockRedis.srem.mockResolvedValue(1)
    mockRedis.expire.mockResolvedValue(undefined)
    mockRedis.setIfAbsent.mockResolvedValue(true)
    mockRedis.invalidateUserSessions.mockResolvedValue(undefined)
    mockUserRepo.findById.mockResolvedValue(AUTH_USER_MFA_DISABLED)
    mockUserRepo.updateMfa.mockResolvedValue(undefined)
    mockBruteForce.isLockedOut.mockResolvedValue(false)
    mockBruteForce.recordFailure.mockResolvedValue(undefined)
    mockBruteForce.resetFailures.mockResolvedValue(undefined)
    mockPasswordService.hash.mockResolvedValue('$scrypt$hashed')
    // The ordinary case for the flows under test: the caller re-proved their password.
    // The negative case arms `false` per test.
    mockPasswordService.compare.mockResolvedValue(true)
    mockEmailProvider.sendMfaEnabledNotification.mockResolvedValue(undefined)
    mockEmailProvider.sendMfaDisabledNotification.mockResolvedValue(undefined)

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

  /**
   * Build a second service over the same doubles with `mockOptions` overridden.
   *
   * Used by the rotation cases, which need a different `previousHmacKeys` than the suite-wide
   * fixture without disturbing every other test in the file.
   */
  async function buildService(overrides: Record<string, unknown>): Promise<MfaService> {
    const module = await Test.createTestingModule({
      providers: [
        MfaService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: { ...mockOptions, ...overrides } },
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
    return module.get(MfaService)
  }

  // ---------------------------------------------------------------------------
  // setup
  // ---------------------------------------------------------------------------

  describe('setup — re-authentication', () => {
    // Scenario: an attacker holding a stolen access token starts enrolment without the
    // password. Expected: refused before any secret is minted. Why: enabling MFA changes how
    // the account authenticates, and a token alone is not proof of who is asking. Without
    // this, a token lifted by XSS or from a shared machine could enrol an authenticator the
    // attacker holds — and the enable then invalidates every session and bumps the epoch,
    // locking the real owner out of an account they still know the password to, with the
    // recovery codes displayed only to the attacker. ASVS requires re-authentication before
    // an authentication factor changes; `disable` already demanded a TOTP code.
    it('should refuse enrolment without the account password', async () => {
      mockUserRepo.findById.mockResolvedValue(AUTH_USER_MFA_DISABLED)
      mockPasswordService.compare.mockResolvedValue(false)

      await expect(
        service.setup('user-1', 'dashboard', undefined, 'tenant-1')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INVALID_CREDENTIALS } }
      })
      // Nothing was minted or claimed — the refusal happens before the setup record exists.
      expect(mockRedis.setIfAbsent).not.toHaveBeenCalled()
    })

    // Scenario: the wrong password. Expected: the same refusal, with the same code a failed
    // login returns — an attacker holding a stolen token learns nothing they did not know.
    it('should refuse enrolment with the wrong password', async () => {
      mockUserRepo.findById.mockResolvedValue(AUTH_USER_MFA_DISABLED)
      mockPasswordService.compare.mockResolvedValue(false)

      await expect(service.setup('user-1', 'dashboard', 'wrong', 'tenant-1')).rejects.toThrow(
        AuthException
      )
    })

    // Scenario: a missing password still pays the KDF. Expected: `compare` is called either
    // way. Why: returning early on an absent password would make "no password sent" faster
    // than "wrong password", separating the two for free.
    it('should spend the KDF even when no password is supplied', async () => {
      mockUserRepo.findById.mockResolvedValue(AUTH_USER_MFA_DISABLED)
      mockPasswordService.compare.mockResolvedValue(false)

      await service.setup('user-1', 'dashboard', undefined, 'tenant-1').catch(() => undefined)

      expect(mockPasswordService.compare).toHaveBeenCalledWith(
        '',
        AUTH_USER_MFA_DISABLED.passwordHash
      )
    })

    // `login` refuses an account after N wrong passwords. This door asks for the SAME secret
    // and used to refuse nothing, so a caller holding a stolen access token but not the
    // password could guess it here without limit — and winning it buys the whole account:
    // enrol a factor, change the password, move the address. The per-route IP limit is not
    // that control; a distributed caller sidesteps it.
    it('should refuse enrolment once the re-proof budget for this account is spent', async () => {
      mockUserRepo.findById.mockResolvedValue(AUTH_USER_MFA_DISABLED)
      mockBruteForce.isLockedOut.mockResolvedValueOnce(true)

      await expect(service.setup('user-1', 'dashboard', 'guess', 'tenant-1')).rejects.toMatchObject(
        {
          response: { error: { code: AUTH_ERROR_CODES.ACCOUNT_LOCKED } }
        }
      )
      // Refused before the KDF, so a locked account is not an amplifier either.
      expect(mockPasswordService.compare).not.toHaveBeenCalled()
      expect(mockRedis.setIfAbsent).not.toHaveBeenCalled()
    })

    it('should count a wrong password against that budget and clear it on success', async () => {
      mockUserRepo.findById.mockResolvedValue(AUTH_USER_MFA_DISABLED)
      mockPasswordService.compare.mockResolvedValue(false)
      mockBruteForce.recordFailure.mockClear()

      await expect(service.setup('user-1', 'dashboard', 'wrong', 'tenant-1')).rejects.toThrow(
        AuthException
      )
      // Two counters, not one: the migration writes the reauth failure under both the legacy
      // plane-only key and the tenant-scoped key so neither an old nor a new pod can bypass it.
      expect(mockBruteForce.recordFailure).toHaveBeenCalledTimes(2)

      mockPasswordService.compare.mockResolvedValue(true)
      mockRedis.setIfAbsent.mockResolvedValue(true)
      mockBruteForce.resetFailures.mockClear()

      await service.setup('user-1', 'dashboard', 'right', 'tenant-1')
      // Success clears BOTH counters — resetting only one would leave the other to lock the user
      // out on the next attempt.
      expect(mockBruteForce.resetFailures).toHaveBeenCalledTimes(2)
    })

    // Scenario: an account provisioned purely through OAuth, which has no local password.
    // Expected: enrolment proceeds. Why: there is nothing to re-authenticate against, and
    // refusing would make MFA unreachable for those users — their credential belongs to the
    // provider, which this library cannot re-verify inline.
    //
    // The downside this reasoning does not weigh, recorded here because the trade-off is
    // deliberate and shared with rust-auth: for such an account a STOLEN ACCESS TOKEN alone is
    // enough to enrol a factor the attacker holds. The enable then invalidates every session
    // and bumps the epoch, and `disable`/`regenerateRecoveryCodes` both demand a live TOTP code
    // while the reset flow refuses an account with no password — so the library ships no way
    // back, and the recovery codes were displayed only to the attacker. The owner IS notified
    // (`sendMfaEnabledNotification`), so it is detectable rather than silent, but recovery
    // needs the host to write to `IUserRepository.updateMfa` directly.
    it('should allow enrolment for an account with no password after a recent sign-in', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_DISABLED, passwordHash: null })
      mockRedis.setIfAbsent.mockResolvedValue(true)
      // The marker `issueTokens` plants: a real authentication completed within the window.
      mockRedis.get.mockImplementation(onlyRecentAuth(true))

      await expect(
        service.setup('user-1', 'dashboard', undefined, 'tenant-1')
      ).resolves.toMatchObject({
        secret: expect.any(String)
      })
      // No password was asked for — there is none to ask for.
      expect(mockPasswordService.compare).not.toHaveBeenCalled()
    })

    // The case this gate exists for, and it was the single worst thing in the library.
    //
    // An access token lifted by XSS or from a shared machine used to be enough to enrol a
    // factor the ATTACKER holds. The enable invalidates every session and bumps the epoch, so
    // the owner — who still signs in with Google perfectly well — is stopped at a challenge
    // they cannot pass, with the recovery codes having been displayed once, to the attacker.
    // And there was no way back: `disable` and `regenerateRecoveryCodes` both demand a live
    // TOTP code, and the reset flow refuses an account with no password. A fifteen-minute
    // token theft became permanent, unrecoverable loss of the account.
    it('should refuse enrolment on a passwordless account with no recent authentication', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_DISABLED, passwordHash: null })
      mockRedis.get.mockImplementation(onlyRecentAuth(false))

      await expect(
        service.setup('user-1', 'dashboard', undefined, 'tenant-1')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.REAUTHENTICATION_REQUIRED } }
      })
      // Nothing minted: the attacker cannot even obtain a secret they control.
      expect(mockRedis.setIfAbsent).not.toHaveBeenCalled()
    })

    // …and it is recorded, naming the account and which surface it was attempted on. This is the
    // refusal that means "someone is holding a token for a passwordless account and trying to
    // enrol a factor on it" — the exact shape of the attack the gate was added for. The response
    // says only `reauthentication_required`, which a legitimate user also sees, so the log line is
    // the only place the attempt is distinguishable at all.
    it('records the refused enrolment with the account and the surface', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_DISABLED, passwordHash: null })
      mockRedis.get.mockImplementation(onlyRecentAuth(false))

      await expect(service.setup('user-1', 'dashboard', undefined, 'tenant-1')).rejects.toThrow(
        AuthException
      )

      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).toContain('no recent authentication')
      expect(warned).toContain('userId=user-1')
      expect(warned).toContain('context=dashboard')
      warnSpy.mockRestore()
    })

    // The re-proof budget for an account WITH a password is keyed to the account and the surface.
    // Dropping either gives the deployment one shared counter: anyone's failed attempts lock out
    // every user, and a caller guessing here would lock the owner out of `login` as well —
    // exactly what namespacing the counter by flow exists to prevent.
    it('keys the re-proof budget to the account and the surface', async () => {
      await service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')

      expect(mockBruteForce.isLockedOut).toHaveBeenCalledWith(
        hmacSha256('reauth:dashboard:user-1', HMAC_KEY)
      )
    })

    // The lockout answers `account_locked`, which names neither the account nor the flow, so
    // this line is what tells an operator whose budget ran out and where.
    it('records a locked re-proof budget with the account and the surface', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockBruteForce.isLockedOut.mockResolvedValueOnce(true)

      await expect(
        service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.ACCOUNT_LOCKED } }
      })

      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).toContain('account locked')
      expect(warned).toContain('userId=user-1')
      expect(warned).toContain('context=dashboard')
      warnSpy.mockRestore()
    })

    // A distinct code rather than `INVALID_CREDENTIALS`, because the two mean different things
    // to the client: one says "that password is wrong", the other says "send the user back
    // through sign-in and retry". Collapsing them would leave a legitimate OAuth user staring
    // at a password error for an account that has no password.
    it('should answer a code the client can act on, not a credential failure', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_DISABLED, passwordHash: null })
      mockRedis.get.mockImplementation(onlyRecentAuth(false))

      await expect(
        service.setup('user-1', 'dashboard', undefined, 'tenant-1')
      ).rejects.not.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INVALID_CREDENTIALS } }
      })
    })
  })

  describe('setup', () => {
    // Verifies that setup returns a valid Base32 TOTP secret, QR URI, and recovery codes.
    it('should return a Base32 secret, qrCodeUri, and recoveryCodes on first call', async () => {
      const result = await service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')

      expect(result.secret).toMatch(/^[A-Z2-7]+$/)
      expect(result.qrCodeUri).toMatch(/^otpauth:\/\/totp\//)
      expect(result.recoveryCodes).toHaveLength(2)
    })

    // Scenario: first-time setup. Expected: each recovery code is 6 groups of 4 UPPERCASE hex
    // chars joined by '-' (XXXX-XXXX-XXXX-XXXX-XXXX-XXXX). Why: a single canonical-format check
    // kills the groups=[] prefill (line 240), the slice loop bound/body mutants (line 241),
    // the slice argument mutants (line 242), the '-' join separator (line 244:32) and the
    // toUpperCase->toLowerCase mutant (line 244:20) — all break the canonical format.
    it('should format every recovery code as 6 groups of 4 uppercase hex chars', async () => {
      const result = await service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')
      for (const code of result.recoveryCodes) {
        expect(code).toMatch(/^[0-9A-F]{4}(-[0-9A-F]{4}){5}$/)
      }
    })

    // Scenario: first-time setup with recoveryCodeCount=2. Expected: the stored payload carries
    // exactly 2 hashedCodes. Why: kills the hashedCodes=["Stryker"] prefill (line 232), which
    // would persist 3 hashes instead of 2.
    it('should persist exactly recoveryCodeCount hashed codes in the setup payload', async () => {
      await service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')
      const payload = mockRedis.setIfAbsent.mock.calls[0]?.[1] as string
      const parsed = JSON.parse(payload) as { hashedCodes: string[] }
      expect(parsed.hashedCodes).toHaveLength(2)
    })

    // Verifies that setup stores the pending setup data in Redis with a 600s TTL.
    it('should store setup data in Redis via setIfAbsent', async () => {
      await service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')

      expect(mockRedis.setIfAbsent).toHaveBeenCalledWith(
        expect.stringMatching(/^mfa_setup:/),
        expect.any(String),
        600
      )
    })

    // Scenario: setIfAbsent wins the race (returns true, the default). Expected: redis.set is NOT
    // called and an info log carries the userId. Why: kills the `if (!wasSet)` -> `if (true)`
    // mutant (line 366), which would re-store via set even on the happy path, and pins the
    // setup log template (line 385).
    it('should not call redis.set and should log when setIfAbsent succeeds', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
      await service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')
      expect(mockRedis.set).not.toHaveBeenCalled()
      expect(logSpy).toHaveBeenCalledWith(
        'setup: MFA setup initiated userId=user-1 context=dashboard'
      )
      logSpy.mockRestore()
    })

    // Scenario: setup for a known user. Expected: the Redis setup key is exactly
    // 'mfa_setup:' + HMAC(tenant-scoped subject). Why: pins the key template so a blanked key or a
    // dropped tenant segment would diverge.
    it('should claim the mfa_setup key derived from the HMAC of the tenant-scoped subject', async () => {
      await service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')
      const expectedKey = `mfa_setup:${hmacSha256('dashboard:tenant-1:user-1', HMAC_KEY)}`
      expect(mockRedis.setIfAbsent).toHaveBeenCalledWith(expectedKey, expect.any(String), 600)
    })

    // Verifies that setup throws MFA_ALREADY_ENABLED when MFA is already active.
    it('should throw MFA_ALREADY_ENABLED when mfaEnabled is true', async () => {
      expect.assertions(1)
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_DISABLED, mfaEnabled: true })

      try {
        await service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_ALREADY_ENABLED })
        })
      }
    })

    // Verifies that setup throws TOKEN_INVALID when the user is not found.
    it('should throw TOKEN_INVALID when user is not found', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(
        service.setup('unknown-user', 'dashboard', PASSWORD, 'tenant-1')
      ).rejects.toThrow(AuthException)
    })

    // Verifies the rare race-condition branch: the fast-path GET returns null
    // (no setup pending), the service generates fresh data, then setIfAbsent
    // loses the race against another concurrent setup, and the second GET (after
    // setIfAbsent) also returns null because the winner's key already expired.
    // Service falls back to redis.set with its own freshly generated data.
    it('should fall back to redis.set when fast-path GET, setIfAbsent and second GET all return null/false', async () => {
      mockRedis.get.mockResolvedValue(null) // both fast-path and post-setIfAbsent GETs return null
      mockRedis.setIfAbsent.mockResolvedValue(false) // racing request claimed the key first

      const result = await service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')

      // Service regenerates and stores new setup data via set()
      expect(mockRedis.set).toHaveBeenCalledWith(
        expect.stringMatching(/^mfa_setup:/),
        expect.any(String),
        expect.any(Number)
      )
      expect(result.secret).toMatch(/^[A-Z2-7]+$/)
    })

    // Verifies the recovery branch where the fast-path GET misses but a concurrent
    // request claims the SET-NX key first. The post-setIfAbsent GET retrieves
    // the winner's payload and the loser returns it for idempotency.
    it('should return winner setup data when fast-path GET is null but setIfAbsent loses the race', async () => {
      const winningSecret = 'WINNERSECRETBASE32ABCDEFGHIJKLMN'
      const winningCodes = ['AAAA-BBBB-CCCC', 'DDDD-EEEE-FFFF']
      const { encrypt } = await import('../crypto/aes-gcm')
      const winnerSetupData = {
        encryptedSecret: encrypt(winningSecret, VALID_ENCRYPTION_KEY),
        hashedCodes: ['hash1', 'hash2'],
        encryptedPlainCodes: encrypt(JSON.stringify(winningCodes), VALID_ENCRYPTION_KEY)
      }

      mockRedis.get
        .mockResolvedValueOnce(null) // fast-path GET — no setup pending yet
        .mockResolvedValueOnce(JSON.stringify(winnerSetupData)) // post-setIfAbsent — winner wrote it
      mockRedis.setIfAbsent.mockResolvedValue(false)

      const result = await service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')

      expect(result.secret).toBe(winningSecret)
      expect(result.recoveryCodes).toEqual(winningCodes)
      // redis.set must NOT be called — we returned the winner's data, not our own
      expect(mockRedis.set).not.toHaveBeenCalled()
    })

    // Verifies that DEFAULT_RECOVERY_CODE_COUNT (8) is used when recoveryCodeCount is absent from mfa options.
    it('should use DEFAULT_RECOVERY_CODE_COUNT when recoveryCodeCount is not configured', async () => {
      const { Test: NestTest } = await import('@nestjs/testing')
      const optionsWithoutCount = {
        jwt: { secret: JWT_SECRET },
        hmacKey: HMAC_KEY,
        previousHmacKeys: [],
        // Every MFA entry point re-reads the account and refuses a blocked one, so even a
        // fixture that is about the recovery-code count has to carry the resolved list.
        blockedStatuses: ['banned', 'suspended'],
        mfa: {
          encryptionKey: VALID_ENCRYPTION_KEY,
          issuer: 'TestApp',
          totpWindow: 1
          // recoveryCodeCount intentionally absent — exercises the ?? DEFAULT_RECOVERY_CODE_COUNT branch
        }
      }
      const module = await NestTest.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: optionsWithoutCount },
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

      const svc = module.get(MfaService)
      // mockPasswordService.hash is already configured to return '$scrypt$hashed'
      const result = await svc.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')

      // The default count is 8 — verify the service produces the default number of codes
      expect(result.recoveryCodes).toHaveLength(8)
    })

    // Verifies the fast-path idempotency: when an existing setup payload is found by
    // the initial GET, the service returns it WITHOUT generating a new TOTP secret or
    // running scrypt on recovery codes (CPU-amplification defence).
    it('should fast-path-return existing setup data without re-running scrypt', async () => {
      const existingSecret = 'EXISTINGSECRETFROMREDIS32CHARS=='
      const existingCodes = ['1111-2222-3333', '4444-5555-6666']

      const { encrypt } = await import('../crypto/aes-gcm')
      const setupData = {
        encryptedSecret: encrypt(existingSecret, VALID_ENCRYPTION_KEY),
        hashedCodes: ['hash1', 'hash2'],
        encryptedPlainCodes: encrypt(JSON.stringify(existingCodes), VALID_ENCRYPTION_KEY)
      }

      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockPasswordService.hash.mockClear()

      const result = await service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')

      expect(result.recoveryCodes).toEqual(existingCodes)
      expect(result.secret).toBe(existingSecret)
      // Critical assertion: no scrypt work performed on the fast path.
      expect(mockPasswordService.hash).not.toHaveBeenCalled()
      // Critical assertion: setIfAbsent was NOT called — the fast path returned earlier.
      expect(mockRedis.setIfAbsent).not.toHaveBeenCalled()
    })

    // Verifies that a corrupted Redis payload on the fast path surfaces opaquely as
    // MFA_SETUP_REQUIRED rather than leaking SyntaxError. Anti-tampering defence.
    it('should throw MFA_SETUP_REQUIRED when fast-path Redis payload is corrupted JSON', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockRedis.get.mockResolvedValue('{not-valid-json')

      await expect(service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')).rejects.toThrow(
        AuthException
      )

      // The refusal is deliberately opaque to the caller — it must not describe the payload — so
      // this line is the only record that a stored record is corrupt, and which account's it is.
      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).toContain('pending-setup payload is not valid JSON')
      expect(warned).toContain('userId=user-1')
      warnSpy.mockRestore()
      try {
        await service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')
      } catch (err) {
        expect(err).toBeInstanceOf(AuthException)
        const code = (err as AuthException).getResponse() as { error: { code: string } }
        expect(code.error.code).toBe(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)
      }
    })

    // Verifies that a corrupted decrypted recovery-code payload surfaces opaquely as
    // MFA_SETUP_REQUIRED — defence against tampering on the encrypted blob in Redis.
    it('should throw MFA_SETUP_REQUIRED when decrypted recovery codes are not valid JSON', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const setupData = {
        encryptedSecret: encrypt('SECRETBASE32ABCDEFGHIJKLMNOPQR12', VALID_ENCRYPTION_KEY),
        hashedCodes: ['hash1'],
        // Encrypt a non-JSON payload so the decrypt succeeds but JSON.parse fails.
        encryptedPlainCodes: encrypt('not-json', VALID_ENCRYPTION_KEY)
      }

      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await expect(service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')).rejects.toThrow(
        AuthException
      )

      // AES-GCM authenticates the ciphertext, so a decrypted value that will not parse means the
      // plaintext was written wrong — an internal bug, and otherwise entirely silent.
      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).toContain('decrypted payload is not valid JSON')
      expect(warned).toContain('userId=user-1')
      warnSpy.mockRestore()
    })

    // Scenario: a pending-setup record that parses but carries no `hashedCodes`. Expected:
    // refused. Why: it used to be cast, not checked, so the field arrived as `undefined` and
    // the account could finish enrolling with no recovery codes at all — a lockout the user
    // discovers only when they have already lost their authenticator. `rust-auth`
    // deserializes into a struct with every field required and refuses the same record.
    it('should refuse a pending-setup record with no hashed recovery codes', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')

      mockRedis.get.mockResolvedValue(
        JSON.stringify({
          encryptedSecret: encrypt('SECRETBASE32ABCDEFGHIJKLMNOPQR12', VALID_ENCRYPTION_KEY),
          encryptedPlainCodes: encrypt('["a"]', VALID_ENCRYPTION_KEY)
        })
      )

      await expect(service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')).rejects.toThrow(
        AuthException
      )
    })

    // The other two fields get the same treatment as `hashedCodes`, and for the same reason: the
    // record is read back out of Redis, so every field is attacker-influenced if the store is.
    // Only `hashedCodes` was pinned, which left the two ciphertext fields checked by a conjunction
    // no test could tell was there — dropping either clause, or turning the `&&` into an `||`, went
    // unnoticed. A non-string `encryptedSecret` reaches `decrypt` as an object; a non-string
    // `encryptedPlainCodes` reaches it as one on the recovery-code path.
    it.each([
      ['encryptedSecret', { encryptedSecret: 42 }],
      ['encryptedSecret absent', { encryptedSecret: undefined }],
      ['encryptedPlainCodes', { encryptedPlainCodes: 42 }],
      ['encryptedPlainCodes absent', { encryptedPlainCodes: undefined }]
    ])(
      'should refuse a pending-setup record whose %s is not a string',
      async (_label, override) => {
        const aesGcm = await import('../crypto/aes-gcm')
        const decryptSpy = jest.spyOn(aesGcm, 'decrypt')

        mockRedis.get.mockResolvedValue(
          JSON.stringify({
            encryptedSecret: aesGcm.encrypt(
              'SECRETBASE32ABCDEFGHIJKLMNOPQR12',
              VALID_ENCRYPTION_KEY
            ),
            hashedCodes: ['hash1'],
            encryptedPlainCodes: aesGcm.encrypt('["a"]', VALID_ENCRYPTION_KEY),
            ...override
          })
        )

        await expect(service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')).rejects.toThrow(
          AuthException
        )
        // Refused by the SHAPE CHECK, before the value reaches the cipher. Asserting only that it
        // throws cannot show that: a record admitted by a weakened check fails a step later, when
        // `decrypt` is handed a number, and surfaces as the same opaque MFA_SETUP_REQUIRED. Which
        // is the point of checking the shape at all — a value read back out of Redis is
        // attacker-influenced if the store is, and it should not be handed to AES-GCM to find out.
        expect(decryptSpy).not.toHaveBeenCalled()
        decryptSpy.mockRestore()
      }
    )

    // Scenario: the decrypted recovery codes are an array with SOME non-string members.
    // Expected: refused. Why: the check has to reject on any bad member, not only when every
    // member is bad — the codes are handed to the user as their way back into the account, and a
    // list where one entry is a number is one the user cannot use and cannot tell apart from the
    // others. A mixed array is also the realistic corruption: a partially rewritten payload.
    it('should refuse decrypted recovery codes that are only partly strings', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')

      mockRedis.get.mockResolvedValue(
        JSON.stringify({
          encryptedSecret: encrypt('SECRETBASE32ABCDEFGHIJKLMNOPQR12', VALID_ENCRYPTION_KEY),
          hashedCodes: ['hash1'],
          encryptedPlainCodes: encrypt('["good-code", 42]', VALID_ENCRYPTION_KEY)
        })
      )

      await expect(service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')).rejects.toThrow(
        AuthException
      )
    })

    // Scenario: a stored pending-setup value that parses to something that is not an object —
    // a bare `null` or a number. Expected: refused before any field read.
    it.each(['null', '42'])(
      'should refuse a pending-setup value that is not an object (%s)',
      async (raw) => {
        mockRedis.get.mockResolvedValue(raw)

        await expect(service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')).rejects.toThrow(
          AuthException
        )
      }
    )

    // Scenario: the same record with `hashedCodes` present but holding a non-string.
    // Expected: refused. Why: the array is written back to the repository verbatim on enable,
    // so a non-string member becomes a stored digest that no comparison can ever match.
    it('should refuse a pending-setup record whose hashed codes are not all strings', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')

      mockRedis.get.mockResolvedValue(
        JSON.stringify({
          encryptedSecret: encrypt('SECRETBASE32ABCDEFGHIJKLMNOPQR12', VALID_ENCRYPTION_KEY),
          hashedCodes: ['hash1', 42],
          encryptedPlainCodes: encrypt('["a"]', VALID_ENCRYPTION_KEY)
        })
      )

      await expect(service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')).rejects.toThrow(
        AuthException
      )
    })

    // Scenario: the decrypted plain-code payload is valid JSON but not an array of strings.
    // Expected: refused. Why: it is returned to the caller as the codes to write down; a
    // shape that is not a string array renders as `[object Object]` in the user's hands.
    it('should refuse decrypted recovery codes that are not an array of strings', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')

      mockRedis.get.mockResolvedValue(
        JSON.stringify({
          encryptedSecret: encrypt('SECRETBASE32ABCDEFGHIJKLMNOPQR12', VALID_ENCRYPTION_KEY),
          hashedCodes: ['hash1'],
          encryptedPlainCodes: encrypt('[{"not":"a string"}]', VALID_ENCRYPTION_KEY)
        })
      )

      await expect(service.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')).rejects.toThrow(
        AuthException
      )
    })
  })

  // ---------------------------------------------------------------------------
  // verifyAndEnable
  // ---------------------------------------------------------------------------

  describe('verifyAndEnable', () => {
    beforeEach(() => {
      jest.useFakeTimers()
      jest.setSystemTime(new Date('2026-01-01T00:00:15.000Z'))
    })

    afterEach(() => {
      jest.useRealTimers()
    })

    // Verifies that verifyAndEnable throws TOKEN_INVALID when the user is not found.
    it('should throw TOKEN_INVALID when user is not found in verifyAndEnable', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(
        service.verifyAndEnable('unknown', '123456', '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
      ).rejects.toThrow(AuthException)
    })

    // Verifies that verifyAndEnable throws MFA_ALREADY_ENABLED when MFA is already active on the account.
    it('should throw MFA_ALREADY_ENABLED when MFA is already enabled', async () => {
      expect.assertions(1)
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_DISABLED, mfaEnabled: true })

      try {
        await service.verifyAndEnable(
          'user-1',
          '123456',
          '1.2.3.4',
          'Browser',
          'dashboard',
          'tenant-1'
        )
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_ALREADY_ENABLED })
        })
      }
    })

    // Verifies that verifyAndEnable throws MFA_SETUP_REQUIRED when no pending setup exists.
    it('should throw MFA_SETUP_REQUIRED when no setup data is in Redis', async () => {
      expect.assertions(1)
      mockRedis.get.mockResolvedValue(null)

      try {
        await service.verifyAndEnable(
          'user-1',
          '123456',
          '1.2.3.4',
          'Browser',
          'dashboard',
          'tenant-1'
        )
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_SETUP_REQUIRED })
        })
      }
    })

    // Verifies that verifyAndEnable surfaces a corrupted Redis payload opaquely as
    // MFA_SETUP_REQUIRED — preventing an attacker with Redis write access from
    // crashing the route handler with an unhandled SyntaxError.
    it('should throw MFA_SETUP_REQUIRED when Redis setup payload is corrupted JSON', async () => {
      expect.assertions(1)
      mockRedis.get.mockResolvedValue('{not-json-at-all')

      try {
        await service.verifyAndEnable(
          'user-1',
          '123456',
          '1.2.3.4',
          'Browser',
          'dashboard',
          'tenant-1'
        )
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_SETUP_REQUIRED })
        })
      }
    })

    // Verifies that verifyAndEnable throws MFA_INVALID_CODE for an incorrect TOTP code.
    it('should throw MFA_INVALID_CODE for an incorrect TOTP code', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      // Anti-replay: SETNX returns true (new key) — but code won't match clock anyway
      mockRedis.setnx.mockResolvedValue(true)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await expect(
        service.verifyAndEnable('user-1', '000000', '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
      ).rejects.toThrow(AuthException)
      // Pin the invalid-code warn template (line 432) so blanking it to '' is caught.
      expect(warnSpy).toHaveBeenCalledWith('verifyAndEnable: invalid TOTP code userId=user-1')
      warnSpy.mockRestore()
    })

    // Verifies that verifyAndEnable calls userRepo.updateMfa and invalidateUserSessions on success.
    it('should update MFA in the DB and invalidate sessions on a valid code', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const currentStep = Math.floor(Date.now() / 1000 / 30)
      const validCode = generateHotp(base32, currentStep)

      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockRedis.setnx.mockResolvedValue(true) // anti-replay: new code
      mockRedis.getdel.mockResolvedValue(JSON.stringify(setupData)) // completion gate wins

      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
      await service.verifyAndEnable(
        'user-1',
        validCode,
        '1.2.3.4',
        'Browser',
        'dashboard',
        'tenant-1'
      )

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith(
        'user-1',
        'tenant-1',
        expect.objectContaining({ mfaEnabled: true })
      )
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('user-1', 'dashboard')
      // The setup key (read + getdel) must be 'mfa_setup:' + HMAC(tenant-scoped subject).
      expect(mockRedis.get).toHaveBeenCalledWith(
        `mfa_setup:${hmacSha256('dashboard:tenant-1:user-1', HMAC_KEY)}`
      )
      // The anti-replay marker is dual-written for the migration: both the tenant-scoped key and
      // the legacy plane-only key are claimed with a 90s TTL, so a code cannot be replayed via
      // either code path during a rolling upgrade.
      expect(mockRedis.setnx).toHaveBeenCalledWith(
        `tu:${hmacSha256(`dashboard:tenant-1:user-1:${validCode}`, HMAC_KEY)}`,
        90
      )
      expect(mockRedis.setnx).toHaveBeenCalledWith(
        `tu:${hmacSha256(`dashboard:user-1:${validCode}`, HMAC_KEY)}`,
        90
      )
      // The afterMfaEnabled hook must be invoked (kills the BlockStatement emptying at line 461)
      // and the success log must carry the userId (kills line 457).
      expect(mockHooks.afterMfaEnabled).toHaveBeenCalledTimes(1)
      // With the dashboard projection, not the platform one: the platform shape blanks the
      // tenant (there is no tenant on that plane), so a hook that received it for a dashboard
      // user would lose the very field a multi-tenant consumer routes on.
      const dashboardHookUser = mockHooks.afterMfaEnabled.mock.calls[0]?.[0] as {
        tenantId: string
      }
      expect(dashboardHookUser.tenantId).toBe('tenant-1')
      expect(logSpy).toHaveBeenCalledWith(
        'verifyAndEnable: MFA enabled userId=user-1 context=dashboard'
      )
      logSpy.mockRestore()
    })

    // Defends against the verify-enable race: two concurrent valid submissions
    // must not both persist MFA state. The completion gate (GETDEL) returns a
    // non-null value to the first caller only; the loser observes null and must
    // throw MFA_SETUP_REQUIRED without touching the database.
    it('should throw MFA_SETUP_REQUIRED when the setup key was consumed by a concurrent request', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockRedis.setnx.mockResolvedValue(true)
      // The racing caller already consumed the setup key — GETDEL returns null.
      mockRedis.getdel.mockResolvedValue(null)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await expect(
        service.verifyAndEnable('user-1', validCode, '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
      ).rejects.toThrow(AuthException)

      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      expect(mockRedis.invalidateUserSessions).not.toHaveBeenCalled()
      // Pin the concurrent-consumption warn template (line 443).
      expect(warnSpy).toHaveBeenCalledWith(
        'verifyAndEnable: setup key consumed by concurrent request userId=user-1'
      )
      warnSpy.mockRestore()
    })

    // Verifies that the email notification is sent after enabling MFA.
    it('should send an MFA enabled email notification', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockRedis.setnx.mockResolvedValue(true)

      await service.verifyAndEnable(
        'user-1',
        validCode,
        '1.2.3.4',
        'Browser',
        'dashboard',
        'tenant-1'
      )

      expect(mockEmailProvider.sendMfaEnabledNotification).toHaveBeenCalledWith(
        'tenant-1',
        AUTH_USER_MFA_DISABLED.email
      )
    })

    // Two properties, and the first one is why the second exists. This send used to be AWAITED
    // with no `catch`, so a rejected delivery left the service and reached `AuthExceptionFilter`:
    // the caller was answered with an error for an operation that had already completed — the
    // secret written, the sessions invalidated, the epoch bumped. Telling a user their second
    // factor failed to enable when it did is how they end up locked out of the account they just
    // secured. And the filter logged that error raw, so the bounce — which NAMES the recipient it
    // refused, needing no quoted body — put the address into a second record after the provider
    // had stripped it from its own.
    it('completes the enable and withholds the recipient when the notice is rejected', async () => {
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockRedis.setnx.mockResolvedValue(true)
      mockEmailProvider.sendMfaEnabledNotification.mockRejectedValueOnce(
        new Error(`550 ${AUTH_USER_MFA_DISABLED.email}: recipient rejected`)
      )

      // A bare `await`, and that IS the assertion that it does not reject: before the fix this
      // threw here, and the caller was told the enable failed for an enable already written.
      await service.verifyAndEnable(
        'user-1',
        validCode,
        '1.2.3.4',
        'Browser',
        'dashboard',
        'tenant-1'
      )
      // Microtasks, NOT `setImmediate`: this describe runs on fake timers, so a macrotask never
      // fires and the wait would hang the test rather than flush it. The handler sits two awaits
      // down the notify chain, and real promises still settle under fake timers.
      await Promise.resolve()
      await Promise.resolve()

      expect(mockUserRepo.updateMfa).toHaveBeenCalled()
      const logged = errorSpy.mock.calls.map((c) => String(c[0])).join(' | ')
      // The ORIGIN is named, not just the fact of the failure. Three flows send an MFA notice and
      // they are different incidents: an administrative reset whose notice never arrives is how an
      // account takeover through the support desk stays silent.
      expect(logged).toContain('verifyAndEnable: MFA notice delivery failed')
      expect(logged).not.toContain(AUTH_USER_MFA_DISABLED.email)
      // The body renders nothing secret, so the relay's own words stay — only the named value is
      // stripped, and the marker is what proves the stripping happened rather than the address
      // simply never having been there.
      expect(logged).toContain('<redacted>')
      errorSpy.mockRestore()
    })

    // Verifies that errors thrown by afterMfaEnabled hook are silently suppressed (fire-and-forget).
    it('should complete successfully even when afterMfaEnabled hook rejects', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockRedis.setnx.mockResolvedValue(true)
      mockHooks.afterMfaEnabled.mockImplementation(() => Promise.reject(new Error('hook failure')))

      // Should resolve without throwing — hook errors must not propagate
      await expect(
        service.verifyAndEnable('user-1', validCode, '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
      ).resolves.toBeUndefined()
      // Drain microtasks so the .catch callback executes (for coverage).
      // Two hops needed: one to resolve the internal Promise.resolve(rejected), one to run .catch.
      // Using Promise.resolve() instead of setTimeout(0) so fake timers don't block execution.
      await Promise.resolve()
      await Promise.resolve()
    })

    // Verifies that anti-replay applies in verifyAndEnable: a replayed code is rejected.
    it('should throw MFA_INVALID_CODE when a valid code is replayed (setnx returns false)', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockRedis.setnx.mockResolvedValue(false) // key already exists = replayed code

      await expect(
        service.verifyAndEnable('user-1', validCode, '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
      ).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // challenge
  // ---------------------------------------------------------------------------

  describe('challenge', () => {
    // Static fixture values — rawRefreshToken is just an opaque string from the service perspective.
    const MOCK_AUTH_RESULT = {
      user: SAFE_USER,
      accessToken: 'access.jwt',
      rawRefreshToken: 'mock-refresh-token-dashboard'
    }

    beforeEach(() => {
      jest.useFakeTimers()
      jest.setSystemTime(new Date('2026-01-01T00:00:15.000Z'))
      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'user-1',
        context: 'dashboard',
        tenantId: 'tenant-1',
        jti: 'jti-test-1'
      })
      mockTokenManager.issueTokens.mockResolvedValue(MOCK_AUTH_RESULT)
    })

    afterEach(() => {
      jest.useRealTimers()
    })

    // Verifies that TOKEN_INVALID is thrown when the dashboard user cannot be found in the repository.
    it('should throw TOKEN_INVALID when dashboard user is not found', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(service.challenge('mfa.temp', '123456', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that TOKEN_INVALID is thrown when the platform admin cannot be found in the repository.
    it('should throw TOKEN_INVALID when platform admin is not found', async () => {
      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'admin-1',
        context: 'platform',
        jti: 'jti-test-platform-1'
      })
      mockPlatformUserRepo.findById.mockResolvedValue(null)

      await expect(service.challenge('mfa.temp', '123456', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that challenge throws MFA_INVALID_CODE when mfaRecoveryCodes is undefined,
    // exercising the ?? [] fallback on the recovery code path.
    it('should throw MFA_INVALID_CODE when mfaRecoveryCodes is undefined (empty fallback)', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: undefined // undefined → ?? [] fallback at line 530
      })
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      // Non-6-digit code routes through the recovery path; empty list → no match → INVALID_CODE
      await expect(
        service.challenge('mfa.temp', 'not-a-totp-code', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
      // The ?? [] fallback must yield an EMPTY array, so no recovery comparison runs. Kills the
      // `?? []` -> `?? ["Stryker"]` ArrayDeclaration mutant (line 530), which would compare once.
      expect(mockPasswordService.compare).not.toHaveBeenCalled()
      // Pin the invalid-code warn template including the context (line 537).
      expect(warnSpy).toHaveBeenCalledWith(
        'challenge: invalid MFA code userId=user-1 context=dashboard'
      )
      warnSpy.mockRestore()
    })

    // Verifies that challenge throws ACCOUNT_LOCKED when brute-force threshold is reached.
    it('should throw ACCOUNT_LOCKED when the user is locked out', async () => {
      expect.assertions(2)
      mockBruteForce.isLockedOut.mockResolvedValue(true)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      try {
        await service.challenge('mfa.temp', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.ACCOUNT_LOCKED })
        })
      }
      // Pin the account-locked warn template (line 509).
      expect(warnSpy).toHaveBeenCalledWith('challenge: account locked userId=user-1')
      warnSpy.mockRestore()
    })

    // Verifies that challenge throws MFA_INVALID_CODE for a wrong TOTP code.
    it('should throw MFA_INVALID_CODE and record a brute-force failure for a wrong code', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)

      await expect(service.challenge('mfa.temp', '000000', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      // Brute-force identifier is an HMAC — verify it is hash-shaped (not the raw user ID).
      expect(mockBruteForce.recordFailure).toHaveBeenCalledWith(
        expect.stringMatching(/^[a-f0-9]{64}$/)
      )
    })

    // Scenario: the same id on both identity planes. Expected: every derived key differs. Why:
    // the two id spaces come from different consumer repositories and may collide —
    // sequential integers make it certain. Keyed on the id alone, a dashboard user and a
    // platform admin shared the pending-enrolment record (so whoever called verify-enable
    // second adopted the FIRST party's secret and recovery digests), the TOTP anti-replay
    // marker, and both brute-force counters. Everything else about the two planes is already
    // separate — Redis prefixes, token types, session indexes; this was the leak.
    it('should namespace every MFA key by identity plane', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const code = generateTotp(base32)
      const sharedId = '1'

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: sharedId,
        context: 'platform',
        jti: 'jti-plane'
      })
      mockTokenManager.issuePlatformTokens.mockResolvedValue({
        admin: SAFE_ADMIN,
        accessToken: 'platform.jwt',
        rawRefreshToken: 'refresh-plane'
      })
      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        id: sharedId,
        passwordHash: 'hash',
        mfaEnabled: true,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: []
      })
      mockRedis.setnx.mockResolvedValue(true)

      await service.challenge('mfa.temp', code, '1.2.3.4', 'Browser')

      // The platform challenge must key on the PLATFORM plane, never the dashboard one.
      expect(mockBruteForce.isLockedOut).toHaveBeenCalledWith(
        hmacSha256(`challenge:platform:${sharedId}`, HMAC_KEY)
      )
      expect(mockBruteForce.isLockedOut).not.toHaveBeenCalledWith(
        hmacSha256(`challenge:dashboard:${sharedId}`, HMAC_KEY)
      )
      expect(mockRedis.setnx).toHaveBeenCalledWith(
        `tu:${hmacSha256(`platform:${sharedId}:${code}`, HMAC_KEY)}`,
        expect.any(Number)
      )
      expect(mockRedis.setnx).not.toHaveBeenCalledWith(
        `tu:${hmacSha256(`dashboard:${sharedId}:${code}`, HMAC_KEY)}`,
        expect.any(Number)
      )
    })

    // Scenario: the temp-token consume loses — another request removed the marker first.
    // Expected: no session, reported as an invalid temp token. Why: two concurrent challenges
    // both observe the marker and both delete it. Before this gate both "succeeded", which was
    // reasoned about as a benign duplicate for the same legitimate user — but on the
    // recovery-code path it is one code and one token minting TWO sessions, and a recovery
    // code's whole security model is that it is single-use. `rust-auth` gates the same point.
    it('should issue no session when the temp-token consume is lost to a concurrent request', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)
      // The code is valid and the marker was there when we read it — only the delete lost.
      mockTokenManager.consumeMfaTempToken.mockResolvedValue(false)

      try {
        await service.challenge('mfa.temp', generateTotp(base32), '1.2.3.4', 'Browser')
        throw new Error('expected a rejection')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: { code: AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID }
        })
      }
      expect(mockTokenManager.issueTokens).not.toHaveBeenCalled()
    })

    // Scenario: a deployment configured at the widest accepted drift window. Expected: the
    // anti-replay marker is sized to that window, not to the default. Why: the TTL used to be
    // a hard-coded 90 s — exactly right for window 1 and silently short for anything larger.
    // At window 2 the verifier accepts a code across 150 s while the marker expired at 90, so
    // a captured code was replayable for the last 60 s of its own acceptance window. The
    // marker exists to make a code single-use; a marker that dies first does not.
    it('should size the anti-replay marker to the configured drift window', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const wide = await buildService({ mfa: { ...mockOptions.mfa, totpWindow: 2 } })

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)

      await wide.challenge('mfa.temp', generateTotp(base32), '1.2.3.4', 'Browser')

      // (2 * 2 + 1) * 30 — the full span over which a code used now stays acceptable.
      expect(mockRedis.setnx).toHaveBeenCalledWith(expect.stringMatching(/^tu:/), 150)
    })

    // Scenario: the loop an attacker who holds the password runs — log in, burn the MFA
    // guess budget, log in again to get a fresh temp token, keep guessing. Expected: the
    // failure counter keeps climbing across logins, so the lockout engages. Why: issuing a
    // temp token used to clear this counter, which made the per-account lockout unreachable
    // and left only the per-IP limit (defeated by distributing). The counter is cleared by
    // exactly one event — a successful challenge — and this test pins that: the identifier
    // recorded across two separate login cycles is the SAME key, so the count accumulates.
    it('should keep accumulating MFA failures across separate logins', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)

      // Two challenge attempts, each following its own login (the service re-reads the
      // identifier from the token's userId every time, so a fresh temp token changes nothing).
      await expect(service.challenge('mfa.temp', '000000', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      await expect(
        service.challenge('mfa.temp.fresh', '111111', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)

      const identifiers = mockBruteForce.recordFailure.mock.calls.map((call) => call[0] as string)
      // Two attempts × the migration's two counters (scoped + legacy) = four records.
      expect(identifiers).toHaveLength(4)
      // Each login records the SAME pair of keys — nothing in the login path reset them between —
      // so both counters accumulate across logins and the lockout engages.
      expect(identifiers[0]).toBe(identifiers[2]) // scoped counter: login 1 === login 2
      expect(identifiers[1]).toBe(identifiers[3]) // legacy counter: login 1 === login 2
      expect(identifiers[0]).not.toBe(identifiers[1]) // scoped and legacy are distinct keys
      expect(mockBruteForce.resetFailures).not.toHaveBeenCalled()
    })

    // Verifies that a valid TOTP code resets the brute-force counter and issues tokens.
    it('should reset brute-force counter and issue tokens for a valid TOTP code', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true) // anti-replay: new code
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      const result = await service.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')

      expect(mockBruteForce.resetFailures).toHaveBeenCalled()
      expect(mockTokenManager.issueTokens).toHaveBeenCalledWith(
        expect.any(Object),
        '1.2.3.4',
        'Browser',
        { mfaVerified: true }
      )
      expect(result).toBe(MOCK_AUTH_RESULT)
      // A TOTP success must NOT touch the recovery-code list: usedRecoveryIndex stays -1, so the
      // `if (usedRecoveryIndex >= 0)` block is skipped. Kills the `-1` -> `+1` UnaryOperator
      // (line 525) and the `if (usedRecoveryIndex >= 0)` -> `if (true)` mutant (line 544), both
      // of which would (wrongly) call updateMfa.
      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      // sessions disabled (default options) -> createSession must NOT run. Kills the
      // `if (this.options.sessions.enabled)` -> `if (true)` mutant (line 575).
      expect(mockSessionService.createSession).not.toHaveBeenCalled()
      // The afterLogin hook must be invoked (kills the dashboard BlockStatement emptying line 579)
      // and the success log must carry userId/context (kills line 565).
      expect(mockHooks.afterLogin).toHaveBeenCalledTimes(1)
      expect(logSpy).toHaveBeenCalledWith(
        'challenge: MFA challenge passed userId=user-1 context=dashboard'
      )
      logSpy.mockRestore()
    })

    // Verifies that a valid recovery code is accepted and the used code is removed.
    it('should accept a recovery code and remove it from the stored list', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'
      const otherDigest = 'a'.repeat(64)
      const hashedCodes = [otherDigest, hmacSha256(plainRecovery, HMAC_KEY)]

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: hashedCodes
      })

      const result = await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith('user-1', 'tenant-1', {
        mfaEnabled: true,
        mfaSecret: expect.any(String),
        mfaRecoveryCodes: [otherDigest] // matched code consumed; mfaSecret preserved
      })
      // The keyed MAC replaces the KDF entirely on this path.
      expect(mockPasswordService.compare).not.toHaveBeenCalled()
      expect(result).toBe(MOCK_AUTH_RESULT)
    })

    // Every MFA transition rewrites one repository record carrying `mfaEnabled`, the secret and
    // the recovery codes TOGETHER, and `updateMfa` replaces all three wholesale with no
    // compare-and-set. Read-modify-write over that with no serialization is last-write-wins,
    // and these are the three ways it bit. The `rcu:` claim does not cover them: it is keyed on
    // the code, so it serializes two attempts at the SAME code and nothing else.
    describe('MFA transitions are serialized against each other', () => {
      // The splice must be computed against the record as it stands INSIDE the lock. Splicing
      // the copy read at the top of `challenge` is what let a concurrent
      // `regenerateRecoveryCodes` be rolled back wholesale: the challenge wrote back the entire
      // OLD list minus one, un-replacing a set the user had just rotated — typically because it
      // had leaked — while the codes they had just printed were gone.
      it('splices against the record inside the lock, not the copy it read first', async () => {
        const { encrypt } = await import('../crypto/aes-gcm')
        const { generateTotpSecret } = await import('../crypto/totp')
        const { base32 } = generateTotpSecret()
        const plainRecovery = '1234-5678-9012'
        const usedDigest = hmacSha256(plainRecovery, HMAC_KEY)
        const staleSibling = 'a'.repeat(64)
        const newerA = 'b'.repeat(64)
        const newerB = 'c'.repeat(64)
        const secret = encrypt(base32, VALID_ENCRYPTION_KEY)

        // First read: the list as it was when the challenge began — the used code at index 1.
        // Second read (inside the lock): a concurrent write has reshaped the list and the used
        // code now sits at index 2. The stale index would splice out the WRONG entry and leave
        // the spent code in place, so the two are distinguishable.
        mockUserRepo.findById
          .mockResolvedValueOnce({
            ...AUTH_USER_MFA_ENABLED,
            mfaSecret: secret,
            mfaRecoveryCodes: [staleSibling, usedDigest]
          })
          .mockResolvedValue({
            ...AUTH_USER_MFA_ENABLED,
            mfaSecret: secret,
            mfaRecoveryCodes: [newerA, newerB, usedDigest]
          })

        await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

        // The spent code is gone and both live siblings survive. Splicing the stale index 1
        // would have produced [newerA, usedDigest] — the used code resurrected.
        expect(mockUserRepo.updateMfa).toHaveBeenCalledWith('user-1', 'tenant-1', {
          mfaEnabled: true,
          mfaSecret: expect.any(String),
          mfaRecoveryCodes: [newerA, newerB]
        })
      })

      // A `disable` that has already completed must stay completed. The challenge used to write
      // `mfaEnabled: true` back unconditionally with the pre-disable secret, putting the account
      // under a factor the user had just removed — and if the disable was part of a device-loss
      // recovery, under an authenticator they no longer hold.
      it('abandons the splice when MFA was disabled while the challenge was in flight', async () => {
        const { encrypt } = await import('../crypto/aes-gcm')
        const { generateTotpSecret } = await import('../crypto/totp')
        const { base32 } = generateTotpSecret()
        const plainRecovery = '1234-5678-9012'
        const usedDigest = hmacSha256(plainRecovery, HMAC_KEY)
        const secret = encrypt(base32, VALID_ENCRYPTION_KEY)

        mockUserRepo.findById
          .mockResolvedValueOnce({
            ...AUTH_USER_MFA_ENABLED,
            mfaSecret: secret,
            mfaRecoveryCodes: [usedDigest]
          })
          // Inside the lock: the disable landed. The codes are deliberately still listed —
          // a host whose `updateMfa` only flips the flag leaves them, and that is the shape
          // where the `mfaEnabled` guard is the only thing standing between a completed
          // disable and a challenge writing `mfaEnabled: true` back with the old secret. A
          // record that also cleared the list would be refused by the index lookup instead,
          // and this test would prove nothing about the guard it is named for.
          .mockResolvedValue({
            ...AUTH_USER_MFA_ENABLED,
            mfaEnabled: false,
            mfaSecret: secret,
            mfaRecoveryCodes: [usedDigest]
          })

        await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

        expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      })

      // The losing caller is refused rather than made to wait: concurrent MFA state changes on
      // one account are pathological, and "try again" is the honest answer.
      it('refuses a transition while another one holds the lock', async () => {
        const { encrypt } = await import('../crypto/aes-gcm')
        const { generateTotpSecret } = await import('../crypto/totp')
        const { base32 } = generateTotpSecret()
        const plainRecovery = '1234-5678-9012'

        mockUserRepo.findById.mockResolvedValue({
          ...AUTH_USER_MFA_ENABLED,
          mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
          mfaRecoveryCodes: [hmacSha256(plainRecovery, HMAC_KEY)]
        })
        mockRedis.setIfAbsent.mockResolvedValue(false)

        await expect(
          service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')
        ).rejects.toMatchObject({
          response: { error: { code: AUTH_ERROR_CODES.MFA_STATE_CONFLICT } }
        })
        expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      })

      // The migration takes two locks on the dashboard plane: the tenant-scoped one first, then the
      // legacy plane-only one an old pod still uses. If the legacy lock is already held — an old pod
      // mid-transition on the same account — the scoped lock this call just took must be rolled back
      // before it refuses, or a refused transition strands a lock for its whole TTL. The rollback is
      // a compare-and-delete against this call's own nonce, and it touches ONLY the scoped lock: the
      // legacy lock was never taken here, so deleting it would remove the holder's.
      it('rolls back the scoped lock when the legacy lock is already held', async () => {
        const { encrypt } = await import('../crypto/aes-gcm')
        const { generateTotpSecret } = await import('../crypto/totp')
        const { base32 } = generateTotpSecret()
        const plainRecovery = '1234-5678-9012'

        mockUserRepo.findById.mockResolvedValue({
          ...AUTH_USER_MFA_ENABLED,
          mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
          mfaRecoveryCodes: [hmacSha256(plainRecovery, HMAC_KEY)]
        })
        // Scoped lock acquired (first call), legacy lock already held by another pod (second call).
        mockRedis.setIfAbsent.mockResolvedValueOnce(true).mockResolvedValueOnce(false)

        await expect(
          service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')
        ).rejects.toMatchObject({
          response: { error: { code: AUTH_ERROR_CODES.MFA_STATE_CONFLICT } }
        })
        // The scoped lock it took is released; the legacy lock it never took is left alone.
        expect(mockRedis.eval).toHaveBeenCalledWith(
          expect.any(String),
          [`mfalock:${hmacSha256('dashboard:tenant-1:user-1', HMAC_KEY)}`],
          [expect.any(String)]
        )
        expect(mockRedis.eval).not.toHaveBeenCalledWith(
          expect.any(String),
          [`mfalock:${hmacSha256('dashboard:user-1', HMAC_KEY)}`],
          [expect.any(String)]
        )
        expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      })

      // The tenant-scoped lock is taken first: if it is already held, the transition is refused
      // immediately, before the legacy lock is even attempted. Pinned so the scoped-acquire failure
      // throws on its own account — not by falling through to a legacy-acquire failure that happens
      // to raise the same code.
      it('refuses immediately when the scoped lock alone is already held', async () => {
        const { encrypt } = await import('../crypto/aes-gcm')
        const { generateTotpSecret } = await import('../crypto/totp')
        const { base32 } = generateTotpSecret()
        const plainRecovery = '1234-5678-9012'

        mockUserRepo.findById.mockResolvedValue({
          ...AUTH_USER_MFA_ENABLED,
          mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
          mfaRecoveryCodes: [hmacSha256(plainRecovery, HMAC_KEY)]
        })
        // Scoped lock already held (first call fails); the legacy lock would be free (second call),
        // so a refusal here can only come from the scoped acquire, not the legacy one.
        mockRedis.setIfAbsent.mockResolvedValueOnce(false).mockResolvedValueOnce(true)

        await expect(
          service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')
        ).rejects.toMatchObject({
          response: { error: { code: AUTH_ERROR_CODES.MFA_STATE_CONFLICT } }
        })
        // The legacy lock was never attempted — the scoped failure short-circuits.
        expect(mockRedis.setIfAbsent).toHaveBeenCalledTimes(1)
        expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      })

      // The code was already spent by something else while this challenge was in flight — a
      // concurrent challenge that spliced the same code out first. Re-locating by value finds
      // nothing, so nothing is written: writing the stale list back would restore every code a
      // concurrent transition had removed, not just this one.
      it('abandons the splice when the code is already gone from the live list', async () => {
        const { encrypt } = await import('../crypto/aes-gcm')
        const { generateTotpSecret } = await import('../crypto/totp')
        const { base32 } = generateTotpSecret()
        const plainRecovery = '1234-5678-9012'
        const usedDigest = hmacSha256(plainRecovery, HMAC_KEY)
        const sibling = 'a'.repeat(64)
        const secret = encrypt(base32, VALID_ENCRYPTION_KEY)

        mockUserRepo.findById
          .mockResolvedValueOnce({
            ...AUTH_USER_MFA_ENABLED,
            mfaSecret: secret,
            mfaRecoveryCodes: [sibling, usedDigest]
          })
          // Inside the lock: the code is no longer listed.
          .mockResolvedValue({
            ...AUTH_USER_MFA_ENABLED,
            mfaSecret: secret,
            mfaRecoveryCodes: [sibling]
          })

        await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

        expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      })

      // A record whose codes were cleared while MFA stayed on — a host whose own admin surface
      // wiped the list without flipping the flag. There is nothing to splice, so nothing is
      // written; the alternative would restore a list this account no longer has.
      it('abandons the splice when the live record lists no codes at all', async () => {
        const { encrypt } = await import('../crypto/aes-gcm')
        const { generateTotpSecret } = await import('../crypto/totp')
        const { base32 } = generateTotpSecret()
        const plainRecovery = '1234-5678-9012'
        const secret = encrypt(base32, VALID_ENCRYPTION_KEY)

        mockUserRepo.findById
          .mockResolvedValueOnce({
            ...AUTH_USER_MFA_ENABLED,
            mfaSecret: secret,
            mfaRecoveryCodes: [hmacSha256(plainRecovery, HMAC_KEY)]
          })
          .mockResolvedValue({
            ...AUTH_USER_MFA_ENABLED,
            mfaSecret: secret,
            mfaRecoveryCodes: null
          })

        await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

        expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      })

      // `regenerateRecoveryCodes` derives a fresh set before it writes. If MFA was disabled in
      // that gap, writing them would re-enable the account with the pre-disable secret — so the
      // transition is abandoned and the caller is told the factor is gone.
      it('refuses to regenerate onto an account whose MFA was disabled meanwhile', async () => {
        const { encrypt } = await import('../crypto/aes-gcm')
        const { generateTotpSecret } = await import('../crypto/totp')
        const { base32, base32: secretBase32 } = generateTotpSecret()
        const secret = encrypt(base32, VALID_ENCRYPTION_KEY)
        const { generateTotp } = await import('../crypto/totp')
        const code = generateTotp(secretBase32)

        mockUserRepo.findById
          .mockResolvedValueOnce({ ...AUTH_USER_MFA_ENABLED, mfaSecret: secret })
          // Inside the lock: the disable landed.
          .mockResolvedValue({
            ...AUTH_USER_MFA_ENABLED,
            mfaEnabled: false,
            mfaSecret: null,
            mfaRecoveryCodes: null
          })

        await expect(
          service.regenerateRecoveryCodes(
            'user-1',
            code,
            '1.2.3.4',
            'Browser',
            'dashboard',
            'tenant-1'
          )
        ).rejects.toMatchObject({
          response: { error: { code: AUTH_ERROR_CODES.MFA_NOT_ENABLED } }
        })
        expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      })

      // The lock is released even when the write fails, so one failed transition does not leave
      // the account unchangeable for the lock's whole TTL.
      it('releases the lock when the write throws', async () => {
        const { encrypt } = await import('../crypto/aes-gcm')
        const { generateTotpSecret } = await import('../crypto/totp')
        const { base32 } = generateTotpSecret()
        const plainRecovery = '1234-5678-9012'

        mockUserRepo.findById.mockResolvedValue({
          ...AUTH_USER_MFA_ENABLED,
          mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
          mfaRecoveryCodes: [hmacSha256(plainRecovery, HMAC_KEY)]
        })
        mockUserRepo.updateMfa.mockRejectedValueOnce(new Error('repository down'))

        await expect(
          service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')
        ).rejects.toThrow('repository down')
        // Both locks the dashboard transition took are released — the tenant-scoped one and the
        // legacy plane-only one the migration also holds.
        expect(mockRedis.eval).toHaveBeenCalledWith(
          expect.any(String),
          [`mfalock:${hmacSha256('dashboard:tenant-1:user-1', HMAC_KEY)}`],
          [expect.any(String)]
        )
        expect(mockRedis.eval).toHaveBeenCalledWith(
          expect.any(String),
          [`mfalock:${hmacSha256('dashboard:user-1', HMAC_KEY)}`],
          [expect.any(String)]
        )
      })

      // The release must be a compare-and-delete against the nonce this call wrote, not a bare
      // `DEL`. The lock's TTL is ten seconds and the transition calls into the host's
      // repository twice; one that overruns has already lost the lock, and an unconditional
      // delete in its `finally` removes whichever transition holds it now — letting a third
      // caller in beside the second. Both halves are asserted: the nonce the script compares
      // is the one `setIfAbsent` stored, and the script itself reads the key before deleting.
      it('releases the lock only while it still holds this transition nonce', async () => {
        const { encrypt } = await import('../crypto/aes-gcm')
        const { generateTotpSecret } = await import('../crypto/totp')
        const { base32 } = generateTotpSecret()
        const plainRecovery = '1234-5678-9012'

        mockUserRepo.findById.mockResolvedValue({
          ...AUTH_USER_MFA_ENABLED,
          mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
          mfaRecoveryCodes: [hmacSha256(plainRecovery, HMAC_KEY)]
        })

        await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

        const lockKey = `mfalock:${hmacSha256('dashboard:user-1', HMAC_KEY)}`
        const acquire = mockRedis.setIfAbsent.mock.calls.find(([key]) => key === lockKey)
        const release = mockRedis.eval.mock.calls.find(([, keys]) => keys[0] === lockKey)
        expect(acquire).toBeDefined()
        expect(release).toBeDefined()
        // A fixed lock value would make these equal for every caller; the nonce is what makes
        // "is this still my lock?" answerable at all, so it must be unpredictable per call.
        expect(acquire?.[1]).toMatch(/^[0-9a-f]{32}$/)
        expect(release?.[2]?.[0]).toBe(acquire?.[1])
        expect(release?.[0]).toContain("redis.call('GET', KEYS[1]) == ARGV[1]")
      })

      // `MfaRecordUpdate` widens to `undefined` for the platform plane, whose record leaves the
      // MFA fields absent rather than nulling them, but `updateMfa` declares `string | null`.
      // An ORM handed `undefined` reads it as "do not touch this column", so a disable would
      // persist `mfaEnabled: false` while leaving the secret and the recovery digests in place
      // — MFA reported off, every factor still able to satisfy a challenge.
      it('writes an explicit null when the platform record leaves an MFA field absent', async () => {
        const { encrypt } = await import('../crypto/aes-gcm')
        const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
        const { base32 } = generateTotpSecret()
        const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))
        const admin = {
          id: 'admin-1',
          email: 'admin@example.com',
          password: 'hashed',
          role: 'PLATFORM_ADMIN',
          status: 'ACTIVE',
          mfaEnabled: true
        }

        mockPlatformUserRepo.findById
          // The read the TOTP is verified against carries the secret...
          .mockResolvedValueOnce({ ...admin, mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY) })
          // ...and the re-read inside the lock does not, as `AuthPlatformUser` permits: the
          // field is optional on that plane, so a repository is free to omit it.
          .mockResolvedValueOnce({ ...admin })

        await service.regenerateRecoveryCodes(
          'admin-1',
          validCode,
          '1.2.3.4',
          'Browser',
          'platform'
        )

        const [, written] = mockPlatformUserRepo.updateMfa.mock.calls[0] as [
          string,
          Record<string, unknown>
        ]
        expect(written['mfaSecret']).toBeNull()
        expect(Object.values(written).every((value) => value !== undefined)).toBe(true)
      })
    })

    // Scenario: a recovery code whose digest was written under a secret since retired, with the
    // rotation configured. Expected: accepted and consumed. Why: the digest is keyed by an HMAC
    // derived from `jwt.secret`, so a rotation without this invalidates every code a user
    // printed and filed — and they discover it at the moment they most need it, locked out of
    // an account they cannot reach any other way.
    it('should accept a recovery code digested under a retired secret', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const retiredKey = 'f'.repeat(64)
      const plainRecovery = '1234-5678-9012'
      const otherDigest = 'a'.repeat(64)
      // Written under the OLD key: nothing in the stored set matches the current one.
      const hashedCodes = [otherDigest, hmacSha256(plainRecovery, retiredKey)]

      const rotated = await buildService({ previousHmacKeys: [retiredKey] })

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: hashedCodes
      })

      const result = await rotated.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith('user-1', 'tenant-1', {
        mfaEnabled: true,
        mfaSecret: expect.any(String),
        mfaRecoveryCodes: [otherDigest]
      })
      expect(result).toBe(MOCK_AUTH_RESULT)
    })

    // Scenario: the same code, but the rotation NOT configured. Expected: refused. Why: this is
    // the failure the test above prevents, and it has to be shown to be real — otherwise the
    // dual read could be doing nothing and both tests would still pass.
    it('should refuse a code digested under a secret that was not listed', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'
      const hashedCodes = ['a'.repeat(64), hmacSha256(plainRecovery, 'f'.repeat(64))]

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: hashedCodes
      })

      await expect(
        service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')
      ).rejects.toThrow()
    })

    // Scenario: the matching digest sits in the MIDDLE of the set. Expected: that entry is the
    // one consumed. Why: the MAC branch deliberately scans to completion instead of returning
    // early, so it has to remember the first match rather than the last one — recording every
    // comparison would consume whichever code happened to be stored last.
    it('should consume the matching code, not the last one scanned', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'
      const before = 'a'.repeat(64)
      const after = 'b'.repeat(64)

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: [before, hmacSha256(plainRecovery, HMAC_KEY), after]
      })

      await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith(
        'user-1',
        'tenant-1',
        expect.objectContaining({ mfaRecoveryCodes: [before, after] })
      )
    })

    // Scenario: ONE code that matches at two different positions, because the list is mixed —
    // the same plaintext digested under the retired key and under the current one, which is
    // exactly what the retired-key support exists to tolerate. Expected: the earlier position
    // is the one consumed.
    //
    // The two-identical-digests case below cannot show this: removing either index from
    // `[d, d]` leaves `[d]`, so it passes whichever position the scan reports. Here the two
    // entries differ, so the surviving one names the index that was picked.
    it('should consume the earliest position when one code matches at two of them', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const retiredKey = 'f'.repeat(64)
      const plainRecovery = '1234-5678-9012'
      const underRetired = hmacSha256(plainRecovery, retiredKey)
      const underCurrent = hmacSha256(plainRecovery, HMAC_KEY)

      const rotated = await buildService({ previousHmacKeys: [retiredKey] })

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: [underRetired, underCurrent]
      })

      await rotated.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      // Index 0 consumed, so index 1 survives. Picking the later match would leave the other.
      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith(
        'user-1',
        'tenant-1',
        expect.objectContaining({ mfaRecoveryCodes: [underCurrent] })
      )
    })

    // Scenario: the same digest stored twice. Expected: the FIRST occurrence is consumed and
    // the duplicate survives. Why: the scan keeps the earliest match, so exactly one code is
    // spent per use — recording later matches too would consume the wrong entry and leave the
    // user's remaining count wrong.
    it('should consume only the first of two identical recovery digests', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'
      const digest = hmacSha256(plainRecovery, HMAC_KEY)

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: [digest, digest]
      })

      await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith(
        'user-1',
        'tenant-1',
        expect.objectContaining({ mfaRecoveryCodes: [digest] })
      )
    })

    // Consuming a recovery code is a read-modify-write against the consumer's repository: two
    // challenges landing together both read the array, both match, both write, and one code
    // mints two sessions — the one property a recovery code has. The library cannot make the
    // consumer's repository atomic, so it claims the code in the store it does own.
    it('refuses a recovery code another challenge already claimed', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'
      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: [hmacSha256(plainRecovery, HMAC_KEY)]
      })
      // The claim was already taken — this is the loser of the race.
      mockRedis.setnx.mockResolvedValue(false)

      await expect(
        service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
      // It reads as an invalid code, which is what a code already spent is — and nothing was
      // written, so the winner's consumption stands.
      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      expect(mockTokenManager.consumeMfaTempToken).not.toHaveBeenCalled()
    })

    // The claim key must not be shareable across identity planes, tenants, or users: the planes
    // are keyed by ids from different repositories that may legitimately collide, two tenants can
    // carry the same id, and a shared marker would let one account burn another's code.
    it('claims the code under a key bound to the tenant-scoped subject and the code', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'
      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: [hmacSha256(plainRecovery, HMAC_KEY)]
      })

      await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      expect(mockRedis.setnx).toHaveBeenCalledWith(
        `rcu:${hmacSha256(`dashboard:tenant-1:user-1:${plainRecovery}`, HMAC_KEY)}`,
        300
      )
    })

    // Scenario: a stored digest in the pre-MAC `scrypt:` shape. Expected: refused, and no key
    // derivation spent on it. Why: the format is gone, not deprecated. Keeping a reader for it
    // meant one scrypt derivation per stored entry on every wrong submission — an amplifier
    // anyone holding a temp token could reach — and the libraries are new, so there is no
    // corpus of such digests to keep readable.
    it('should refuse a digest in the removed scrypt format without spending a derivation', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: ['scrypt:0011223344556677:8899aabbccddeeff']
      })

      await expect(
        service.challenge('mfa.temp', '1234-5678-9012', '1.2.3.4', 'Browser')
      ).rejects.toThrow()
      expect(mockPasswordService.compare).not.toHaveBeenCalled()
    })

    // Verifies a wrong code costs no key derivation at all once the codes are in the MAC
    // format. This is the security property of the change: previously one wrong submission
    // forced one scrypt derivation per stored code, an amplifier reachable by anyone holding
    // a temp token.
    it('should spend no key derivation when a wrong code is scanned against MAC digests', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)]
      })

      await expect(
        service.challenge('mfa.temp', '1234-5678-9012', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)

      expect(mockPasswordService.compare).not.toHaveBeenCalled()
    })

    // Verifies that TOTP anti-replay prevents a code from being used twice.
    it('should reject a replayed TOTP code (setnx returns false = already used)', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(false) // key already exists = replayed

      await expect(service.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      // Anti-replay call: key must be 'tu:' + 64-char HMAC hex; TTL must be 90 seconds.
      expect(mockRedis.setnx).toHaveBeenCalledWith(expect.stringMatching(/^tu:[a-f0-9]{64}$/), 90)
      // Replayed codes count as failed attempts to prevent lockout bypass via known valid codes.
      expect(mockBruteForce.recordFailure).toHaveBeenCalled()
    })

    // Verifies that malformed recovery codes (non-6-digit strings with invalid format) are still
    // routed through passwordService.compare but produce no match, consistent with constant-time behavior.
    it('should route any non-6-digit code through recovery code comparison', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        // The digest of the empty string under the identifier key. If the branch routes to
        // recovery, this matches and the challenge succeeds — which is the observation, since
        // the MAC comparison spends no service call to watch.
        mfaRecoveryCodes: [hmacSha256('', HMAC_KEY)]
      })

      await expect(service.challenge('mfa.temp', '', '1.2.3.4', 'Browser')).resolves.toBe(
        MOCK_AUTH_RESULT
      )
      // …and no key derivation was spent getting there.
      expect(mockPasswordService.compare).not.toHaveBeenCalled()
    })

    // Scenario: a 6-digit prefix followed by a non-digit suffix ('123456X'). The canonical
    // /^\d{6}$/ rejects it (the $ anchor requires the string to END after 6 digits), so it must
    // route through the RECOVERY path (passwordService.compare runs). Why: kills the
    // /^\d{6}$/ -> /^\d{6}/ Regex mutant (line 522), which drops the $ anchor and would
    // (wrongly) treat '123456X' as a TOTP code, skipping the recovery comparison.
    it('should route a 6-digit-prefixed code with a trailing char through the recovery path', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        // Legacy-format digests, so the recovery branch is observable through the KDF call
        // the MAC format no longer needs.
        mfaRecoveryCodes: [hmacSha256('123456X', HMAC_KEY)]
      })

      // Routing to recovery is what lets this match; the TOTP path would reject it outright.
      await expect(service.challenge('mfa.temp', '123456X', '1.2.3.4', 'Browser')).resolves.toBe(
        MOCK_AUTH_RESULT
      )
    })

    // Scenario: a non-digit prefix followed by 6 digits ('X123456'). The canonical /^\d{6}$/
    // rejects it (the ^ anchor requires digits to START the string), so it must route through
    // the RECOVERY path. Why: kills the /^\d{6}$/ -> /\d{6}$/ Regex mutant (line 522), which
    // drops the ^ anchor and would (wrongly) treat 'X123456' as a TOTP code.
    it('should route a code with a non-digit prefix and 6 trailing digits through the recovery path', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        // Legacy-format digests, so the recovery branch is observable through the KDF call
        // the MAC format no longer needs.
        mfaRecoveryCodes: [hmacSha256('X123456', HMAC_KEY)]
      })

      await expect(service.challenge('mfa.temp', 'X123456', '1.2.3.4', 'Browser')).resolves.toBe(
        MOCK_AUTH_RESULT
      )
    })

    // Verifies that TOKEN_INVALID is thrown when the stored mfaSecret is corrupted (decrypt fails).
    it('should throw TOKEN_INVALID when mfaSecret cannot be decrypted', async () => {
      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        // Wire format is iv:authTag:ciphertext — this corrupted value forces decrypt() to throw
        mfaSecret: 'aW52YWxpZA==:aW52YWxpZA==:aW52YWxpZA=='
      })

      await expect(service.challenge('mfa.temp', '123456', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
    })

    // Verifies the challenge re-checks account status. Login gated it before minting the
    // temp token, but that token stays valid for its whole TTL: an account suspended in the
    // meantime must not be able to finish the second factor and walk away with a full
    // session. Revoking access cannot depend on how far through login the holder had got.
    it('should reject the challenge when the account was blocked after the temp token was issued', async () => {
      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        status: 'SUSPENDED'
      })

      let caught: AuthException | undefined
      try {
        await service.challenge('mfa.temp', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        caught = e instanceof AuthException ? e : undefined
      }

      expect(caught).toBeInstanceOf(AuthException)
      expect(caught!.getStatus()).toBe(403)
      expect(mockTokenManager.issueTokens).not.toHaveBeenCalled()
    })

    // Verifies the status gate runs before the code is verified: the recovery-code path
    // costs one scrypt derivation per stored code, so a blocked account must never reach it.
    it('should reject a blocked account without verifying the submitted code', async () => {
      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        status: 'BANNED'
      })

      await expect(
        service.challenge('mfa.temp', 'some-recovery-code', '1.2.3.4', 'Browser')
      ).rejects.toBeInstanceOf(AuthException)

      expect(mockPasswordService.compare).not.toHaveBeenCalled()
    })

    // Verifies that MFA_NOT_ENABLED is thrown when the user record shows mfaEnabled: false.
    it('should throw MFA_NOT_ENABLED when user does not have MFA active in challenge', async () => {
      expect.assertions(1)
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_DISABLED, mfaEnabled: false })

      try {
        await service.challenge('mfa.temp', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_NOT_ENABLED })
        })
      }
    })

    // Verifies that errors thrown by the afterLogin hook (dashboard) are silently suppressed.
    it('should complete successfully even when afterLogin hook rejects (dashboard)', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockHooks.afterLogin.mockImplementation(() => Promise.reject(new Error('hook failure')))

      await expect(
        service.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')
      ).resolves.toBeDefined()
      // Drain microtasks so the .catch callback executes (for coverage).
      // Two hops needed: one to resolve the internal Promise.resolve(rejected), one to run .catch.
      // Using Promise.resolve() instead of setTimeout(0) so fake timers don't block execution.
      await Promise.resolve()
      await Promise.resolve()
    })

    // Verifies that a recovery code is removed via platformUserRepo when context is 'platform'.
    it('should remove the used recovery code via platformUserRepo for platform context', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'
      // MAC digests: the first is another code's, the second is the one being presented, so
      // the assertion below proves the MATCHED entry is the one spliced out.
      const hashedCodes = [
        hmacSha256('0000-0000-0000', HMAC_KEY),
        hmacSha256(plainRecovery, HMAC_KEY)
      ]

      const PLATFORM_AUTH_RESULT = {
        admin: SAFE_ADMIN,
        accessToken: 'platform.jwt',
        rawRefreshToken: 'mock-refresh-token-platform-recovery'
      }

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'admin-1',
        context: 'platform',
        jti: 'jti-test-platform-1'
      })
      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: true,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: hashedCodes
      })
      mockTokenManager.issuePlatformTokens
        .mockResolvedValue(PLATFORM_AUTH_RESULT)
        // First code doesn't match, second does
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(false)

      await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      expect(mockPlatformUserRepo.updateMfa).toHaveBeenCalledWith(
        'admin-1',
        expect.objectContaining({ mfaRecoveryCodes: [hmacSha256('0000-0000-0000', HMAC_KEY)] })
      )
    })

    // Verifies that errors thrown by the afterLogin hook (platform) are silently suppressed.
    it('should complete successfully even when afterLogin hook rejects (platform)', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'admin-1',
        context: 'platform',
        jti: 'jti-test-platform-1'
      })
      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: true,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: []
      })
      mockTokenManager.issuePlatformTokens.mockResolvedValue({
        admin: SAFE_ADMIN,
        accessToken: 'platform.jwt',
        rawRefreshToken: 'token'
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockHooks.afterLogin.mockImplementation(() => Promise.reject(new Error('hook failure')))

      await expect(
        service.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')
      ).resolves.toBeDefined()
      // Drain microtasks so the .catch callback executes (for coverage).
      // Two hops needed: one to resolve the internal Promise.resolve(rejected), one to run .catch.
      // Using Promise.resolve() instead of setTimeout(0) so fake timers don't block execution.
      await Promise.resolve()
      await Promise.resolve()
    })

    // Verifies TOKEN_INVALID when context='platform' but platformUserRepo is not injected.
    it('should throw TOKEN_INVALID when platform context is used without platformUserRepo', async () => {
      // Create a service instance WITHOUT the platform user repo
      const { Test: NestTest } = await import('@nestjs/testing')
      const moduleWithoutRepo = await NestTest.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          // BYMAX_AUTH_PLATFORM_USER_REPOSITORY intentionally omitted
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()

      const serviceWithoutRepo = moduleWithoutRepo.get(MfaService)
      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'admin-1',
        context: 'platform',
        jti: 'jti-test-platform-1'
      })

      await expect(
        serviceWithoutRepo.challenge('mfa.temp', '123456', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
    })

    // Verifies that platform context challenges use issuePlatformTokens and the platform repo.
    it('should use issuePlatformTokens and platformUserRepo for platform context', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const PLATFORM_AUTH_RESULT = {
        admin: SAFE_ADMIN,
        accessToken: 'platform.jwt',
        rawRefreshToken: 'mock-refresh-token-platform'
      }

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'admin-1',
        context: 'platform',
        jti: 'jti-test-platform-1'
      })
      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: true,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: []
      })
      mockTokenManager.issuePlatformTokens.mockResolvedValue(PLATFORM_AUTH_RESULT)
      mockRedis.setnx.mockResolvedValue(true)

      const result = await service.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')

      expect(mockPlatformUserRepo.findById).toHaveBeenCalledWith('admin-1')
      expect(mockTokenManager.issuePlatformTokens).toHaveBeenCalledWith(
        expect.any(Object),
        '1.2.3.4',
        'Browser',
        { mfaVerified: true }
      )
      expect(result).toBe(PLATFORM_AUTH_RESULT)
      // The platform afterLogin hook must be invoked (kills the platform BlockStatement emptying
      // at line 598) with a SafeAuthUser-compatible projection whose platform-sentinel fields are
      // tenantId='' (kills line 301) and emailVerified=true (kills line 302).
      expect(mockHooks.afterLogin).toHaveBeenCalledTimes(1)
      const hookUser = mockHooks.afterLogin.mock.calls[0]?.[0] as {
        tenantId: string
        emailVerified: boolean
      }
      expect(hookUser.tenantId).toBe('')
      expect(hookUser.emailVerified).toBe(true)
    })

    // Verifies that challenge calls sessionService.createSession when sessions.enabled is true.
    it('should call sessionService.createSession when sessions.enabled is true', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const sessionOptions = {
        ...mockOptions,
        sessions: { enabled: true, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
      }
      const sessionModule = await Test.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: sessionOptions },
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
      const sessionEnabledService = sessionModule.get(MfaService)

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: SAFE_USER.id,
        context: 'dashboard',
        tenantId: 'tenant-1',
        jti: 'jti-test-safe-user-1'
      })
      mockTokenManager.issueTokens.mockResolvedValue(MOCK_AUTH_RESULT)
      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockSessionService.createSession.mockResolvedValue('session-hash')

      await sessionEnabledService.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')

      expect(mockSessionService.createSession).toHaveBeenCalledWith(
        SAFE_USER.id,
        MOCK_AUTH_RESULT.rawRefreshToken,
        '1.2.3.4',
        'Browser'
      )
    })
  })

  /**
   * The same misconfiguration guard as `setup`/`verifyAndEnable`, on the third
   * entry point. Without it a platform regenerate falls through to the dashboard
   * repository, which is how one admin's recovery codes end up written onto a
   * dashboard user with the same id.
   */
  describe('regenerateRecoveryCodes — platform misconfiguration', () => {
    it('should throw MFA_NOT_ENABLED when platform context is used without platformUserRepo', async () => {
      const { Test: NestTest } = await import('@nestjs/testing')
      const moduleWithoutRepo = await NestTest.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()
      const serviceWithoutRepo = moduleWithoutRepo.get(MfaService)

      await expect(
        serviceWithoutRepo.regenerateRecoveryCodes(
          'admin-1',
          '123456',
          '1.2.3.4',
          'Browser',
          'platform'
        )
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_NOT_ENABLED } }
      })
      expect(mockUserRepo.findById).not.toHaveBeenCalled()
      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()

      // And only the platform context is a misconfiguration here — a dashboard regenerate on
      // the same platform-less service is an ordinary call and must not be refused by it.
      mockUserRepo.findById.mockResolvedValue(null)
      await expect(
        serviceWithoutRepo.regenerateRecoveryCodes(
          'user-1',
          '123456',
          '1.2.3.4',
          'Browser',
          'dashboard',
          'tenant-1'
        )
      ).rejects.not.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_NOT_ENABLED } }
      })
    })
  })

  // ---------------------------------------------------------------------------
  // disable
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // resetMfa — administrative removal, no second factor required
  // ---------------------------------------------------------------------------

  describe('resetMfa', () => {
    // Scenario: the account has no second factor. Expected: nothing happens, and no error.
    // Why: a support desk retrying a job already done should not be told it failed — the same
    // idempotence `unlockAccount` promises. Asserting the writes did NOT happen is what
    // separates this from a method that quietly re-runs the whole teardown on every call.
    it('is a no-op for an account with no second factor', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_DISABLED, mfaEnabled: false })
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      await expect(service.resetMfa('user-1', 'dashboard', 'tenant-1')).resolves.toBeUndefined()

      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      expect(mockRedis.invalidateUserSessions).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendMfaDisabledNotification).not.toHaveBeenCalled()
      // The log is the only record this call happened at all — the return value is the same
      // `undefined` a real reset produces, so without the line an operator cannot tell a
      // no-op apart from a removal in the audit trail.
      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining('resetMfa: no second factor to remove')
      )
      logSpy.mockRestore()
    })

    // Scenario: a user who has lost both the authenticator and the recovery codes. Expected:
    // the factor is cleared, every session dies with it, and the user is told. Why: each of
    // these is load-bearing. Leaving the sessions alive keeps access tokens carrying
    // `mfaVerified: true` valid past the factor they attest to; skipping the notification
    // makes this an account-takeover path, because an attacker who reaches the support desk
    // removes the second factor with nothing reaching the owner.
    // The notice on this path is what makes a support-desk takeover detectable, so a bounce here
    // is the one an operator most needs named — and it is also where the recipient most easily
    // leaks, because an SMTP rejection quotes the address it refused with no body involved.
    it('completes the reset and withholds the recipient when the notice is rejected', async () => {
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockUserRepo.findById.mockResolvedValue(AUTH_USER_MFA_ENABLED)
      mockEmailProvider.sendMfaDisabledNotification.mockRejectedValueOnce(
        new Error(`550 ${AUTH_USER_MFA_ENABLED.email}: recipient rejected`)
      )

      await service.resetMfa('user-1', 'dashboard', 'tenant-1')
      await Promise.resolve()
      await Promise.resolve()

      expect(mockUserRepo.updateMfa).toHaveBeenCalled()
      const logged = errorSpy.mock.calls.map((c) => String(c[0])).join(' | ')
      expect(logged).toContain('resetMfa: MFA notice delivery failed')
      expect(logged).not.toContain(AUTH_USER_MFA_ENABLED.email)
      expect(logged).toContain('<redacted>')
      warnSpy.mockRestore()
      errorSpy.mockRestore()
    })

    it('clears the factor, kills the sessions and notifies the account holder', async () => {
      mockUserRepo.findById.mockResolvedValue(AUTH_USER_MFA_ENABLED)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await service.resetMfa('user-1', 'dashboard', 'tenant-1')

      // At `warn`, and saying "administratively": an operator reading the log has to be able to
      // tell this apart from a user who disabled their own factor, and both paths otherwise
      // write the same record and send the same mail.
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('resetMfa: MFA removed administratively')
      )
      warnSpy.mockRestore()

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith('user-1', 'tenant-1', {
        mfaEnabled: false,
        mfaSecret: null,
        mfaRecoveryCodes: null
      })
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('user-1', 'dashboard')
      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('user-1', 'dashboard')
      expect(mockEmailProvider.sendMfaDisabledNotification).toHaveBeenCalledWith(
        'tenant-1',
        AUTH_USER_MFA_ENABLED.email
      )
      expect(mockHooks.afterMfaDisabled).toHaveBeenCalled()
    })

    // The hook context carries no IP or User-Agent, because there is no request behind this
    // call. Empty rather than invented: a consumer logging the hook must not record a
    // placeholder address as though someone had connected from it.
    it('fires the hook with no request context', async () => {
      mockUserRepo.findById.mockResolvedValue(AUTH_USER_MFA_ENABLED)

      await service.resetMfa('user-1', 'dashboard', 'tenant-1')

      expect(mockHooks.afterMfaDisabled).toHaveBeenCalledWith(
        // `tenantId` is what separates the two projections: the dashboard one carries the
        // account's own tenant, the platform one forces `''`. Asserting only the id would pass
        // under either, so a reset that handed the hook a platform-shaped user for a dashboard
        // account — losing the tenant every consumer scopes on — would go unnoticed.
        expect.objectContaining({ id: 'user-1', tenantId: 'tenant-1' }),
        { userId: 'user-1', ip: '', userAgent: '', sanitizedHeaders: {} }
      )
    })

    // The platform plane is a separate identity space with its own repository and its own
    // session keys. Without this, a reset aimed at an administrator would look successful and
    // clear nothing.
    it('resets a platform administrator in the platform plane', async () => {
      mockPlatformUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        id: 'admin-1'
      })

      await service.resetMfa('admin-1', 'platform')

      expect(mockPlatformUserRepo.updateMfa).toHaveBeenCalledWith('admin-1', {
        mfaEnabled: false,
        mfaSecret: null,
        mfaRecoveryCodes: null
      })
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('admin-1', 'platform')
      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('admin-1', 'platform')
      // The counterpart of the dashboard assertion above: a platform admin has no tenant, and
      // the projection says so with `''` rather than leaving the field absent. The dashboard
      // projection would leave it `undefined` here, so this is what pins which one ran.
      expect(mockHooks.afterMfaDisabled).toHaveBeenCalledWith(
        expect.objectContaining({ id: 'admin-1', tenantId: '' }),
        expect.objectContaining({ userId: 'admin-1' })
      )
    })

    // An unknown id is refused rather than silently succeeding, so a typo at the support desk
    // does not read as "reset done".
    it('throws when no user with that id exists', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(service.resetMfa('nobody', 'dashboard', 'tenant-1')).rejects.toThrow(
        AuthException
      )
    })

    // The hook is fire-and-forget: a consumer whose alerting is down must not turn an
    // administrative reset into a failed one. The factor is already gone by the time the hook
    // runs, so propagating its error would report a failure for work that succeeded.
    it('survives a hook that rejects', async () => {
      mockUserRepo.findById.mockResolvedValue(AUTH_USER_MFA_ENABLED)
      mockHooks.afterMfaDisabled.mockRejectedValueOnce(new Error('alerting is down'))

      await expect(service.resetMfa('user-1', 'dashboard', 'tenant-1')).resolves.toBeUndefined()

      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('user-1', 'dashboard')
    })

    // A consumer that registers no `afterMfaDisabled` at all: the guard must short-circuit
    // rather than call `undefined`.
    it('completes when the consumer registers no hook', async () => {
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
          { provide: BYMAX_AUTH_HOOKS, useValue: {} }
        ]
      }).compile()
      const noHookService = module.get<MfaService>(MfaService)

      mockUserRepo.findById.mockResolvedValue(AUTH_USER_MFA_ENABLED)

      await expect(
        noHookService.resetMfa('user-1', 'dashboard', 'tenant-1')
      ).resolves.toBeUndefined()
    })
  })

  describe('disable', () => {
    beforeEach(() => {
      jest.useFakeTimers()
      jest.setSystemTime(new Date('2026-01-01T00:00:15.000Z'))
    })

    afterEach(() => {
      jest.useRealTimers()
    })

    // Verifies that disable throws TOKEN_INVALID when the user is not found.
    it('should throw TOKEN_INVALID when user is not found', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(
        service.disable('unknown', '123456', '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
      ).rejects.toThrow(AuthException)
    })

    // Verifies that disable throws MFA_NOT_ENABLED when MFA is not active on the account.
    it('should throw MFA_NOT_ENABLED when MFA is not active', async () => {
      expect.assertions(1)
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_DISABLED, mfaEnabled: false })

      try {
        await service.disable('user-1', '123456', '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_NOT_ENABLED })
        })
      }
    })

    // Verifies that disable throws TOKEN_INVALID when mfaEnabled is true but mfaSecret is null
    // (database inconsistency — should never happen in normal operation but must be handled safely).
    it('should throw TOKEN_INVALID when mfaEnabled is true but mfaSecret is null', async () => {
      expect.assertions(1)
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_ENABLED, mfaSecret: null })

      try {
        await service.disable('user-1', '123456', '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.TOKEN_INVALID })
        })
      }
    })

    // Verifies that disable throws ACCOUNT_LOCKED when the brute-force threshold is reached.
    it('should throw ACCOUNT_LOCKED when user is locked out', async () => {
      expect.assertions(2)
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockBruteForce.isLockedOut.mockResolvedValue(true)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      try {
        await service.disable('user-1', '123456', '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.ACCOUNT_LOCKED })
        })
      }
      // Pin the disable account-locked warn template including the context (line 655).
      expect(warnSpy).toHaveBeenCalledWith(
        'disable: account locked userId=user-1 context=dashboard'
      )
      warnSpy.mockRestore()
    })

    // Verifies that a valid TOTP code disables MFA, clears the DB fields, and invalidates sessions.
    it('should clear MFA fields in DB and invalidate sessions on a valid code', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      await service.disable('user-1', validCode, '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith('user-1', 'tenant-1', {
        mfaEnabled: false,
        mfaSecret: null,
        mfaRecoveryCodes: null
      })
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('user-1', 'dashboard')
      // The disable brute-force identifier must be HMAC('disable:{userId}') — kills line 653.
      expect(mockBruteForce.isLockedOut).toHaveBeenCalledWith(
        hmacSha256('disable:dashboard:user-1', HMAC_KEY)
      )
      // Pin the success log including the context (line 686).
      expect(logSpy).toHaveBeenCalledWith('disable: MFA disabled userId=user-1 context=dashboard')
      // The afterMfaDisabled hook must be invoked (kills the BlockStatement emptying at line 694)
      // with the DASHBOARD projection that retains the real tenantId. The dashboard branch of the
      // `context === 'platform' ? ... : toSafeUser(...)` ternary (line 690) must be taken — kills
      // the `true` and `!==` mutants which would force the platform projection (tenantId='').
      expect(mockHooks.afterMfaDisabled).toHaveBeenCalledTimes(1)
      const hookUser = mockHooks.afterMfaDisabled.mock.calls[0]?.[0] as { tenantId: string }
      expect(hookUser.tenantId).toBe('tenant-1')
      logSpy.mockRestore()
    })

    // Verifies that the MFA disabled email notification is sent after a successful disable.
    it('should send an MFA disabled email notification', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)

      await service.disable('user-1', validCode, '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')

      expect(mockEmailProvider.sendMfaDisabledNotification).toHaveBeenCalledWith(
        'tenant-1',
        AUTH_USER_MFA_DISABLED.email
      )
    })

    // A provider that throws SYNCHRONOUSLY rather than rejecting, which is the whole reason the
    // send runs inside an async IIFE. `Promise.resolve(send(...))` evaluates the call before the
    // promise wraps it, so the throw would skip the handler entirely and fail an MFA transition
    // that already completed — and the three rejection tests stay green through that regression,
    // which is what makes this one load-bearing rather than redundant. A provider is consumer code
    // and may do either; the outcome must not depend on which.
    it('completes the enable when the notice throws synchronously', async () => {
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockRedis.setnx.mockResolvedValue(true)
      mockEmailProvider.sendMfaEnabledNotification.mockImplementationOnce(() => {
        throw new Error(`550 ${AUTH_USER_MFA_DISABLED.email}: recipient rejected`)
      })

      await service.verifyAndEnable(
        'user-1',
        validCode,
        '1.2.3.4',
        'Browser',
        'dashboard',
        'tenant-1'
      )
      await Promise.resolve()
      await Promise.resolve()

      expect(mockUserRepo.updateMfa).toHaveBeenCalled()
      const logged = errorSpy.mock.calls.map((c) => String(c[0])).join(' | ')
      // One argument, not two: the error object never reaches the logger.
      expect(errorSpy.mock.calls[0]).toHaveLength(1)
      expect(logged).toContain('verifyAndEnable: MFA notice delivery failed')
      expect(logged).not.toContain(AUTH_USER_MFA_DISABLED.email)
      expect(logged).toContain('<redacted>')
      errorSpy.mockRestore()
    })

    // The same two properties the enable path asserts, at the site that matters as much: the
    // factor is already gone, so answering the caller with an error for a notice that bounced
    // would report a removal that happened as one that did not. And a bounce NAMES the recipient.
    it('completes the disable and withholds the recipient when the notice is rejected', async () => {
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockEmailProvider.sendMfaDisabledNotification.mockRejectedValueOnce(
        new Error(`550 ${AUTH_USER_MFA_DISABLED.email}: recipient rejected`)
      )

      await service.disable('user-1', validCode, '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
      await Promise.resolve()
      await Promise.resolve()

      expect(mockUserRepo.updateMfa).toHaveBeenCalled()
      const logged = errorSpy.mock.calls.map((c) => String(c[0])).join(' | ')
      expect(logged).toContain('disable: MFA notice delivery failed')
      expect(logged).not.toContain(AUTH_USER_MFA_DISABLED.email)
      expect(logged).toContain('<redacted>')
      errorSpy.mockRestore()
    })

    // Verifies that disable throws MFA_INVALID_CODE and records a brute-force failure for a wrong code.
    it('should throw MFA_INVALID_CODE and record brute-force failure for a wrong code', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await expect(
        service.disable('user-1', '000000', '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
      ).rejects.toThrow(AuthException)
      expect(mockBruteForce.recordFailure).toHaveBeenCalled()
      // Pin the disable invalid-code warn template including the context (line 670).
      expect(warnSpy).toHaveBeenCalledWith(
        'disable: invalid MFA code userId=user-1 context=dashboard'
      )
      warnSpy.mockRestore()
    })

    // Verifies that disable with context='platform' uses platformUserRepo.updateMfa instead of userRepo.updateMfa.
    it('should use platformUserRepo.updateMfa when context is platform', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: true,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: []
      })
      mockRedis.setnx.mockResolvedValue(true)

      await service.disable('admin-1', validCode, '1.2.3.4', 'Browser', 'platform')

      expect(mockPlatformUserRepo.updateMfa).toHaveBeenCalledWith('admin-1', {
        mfaEnabled: false,
        mfaSecret: null,
        mfaRecoveryCodes: null
      })
      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      // On the platform plane the scoped and legacy subjects coincide, so every migration-aware
      // operation runs ONCE, not twice: a single transition lock (and its single release), a single
      // anti-replay marker, a single lockout check, and a single reset on success. Operating the
      // legacy arm here would take the same lock/marker/counter a second time — refusing the
      // transition, rejecting the code, or locking the admin out at half the threshold.
      expect(mockRedis.setIfAbsent).toHaveBeenCalledTimes(1)
      expect(mockRedis.eval).toHaveBeenCalledTimes(1)
      expect(mockRedis.setnx).toHaveBeenCalledTimes(1)
      expect(mockBruteForce.isLockedOut).toHaveBeenCalledTimes(1)
      expect(mockBruteForce.resetFailures).toHaveBeenCalledTimes(1)
      // Revocation is scoped to the PLATFORM plane, sessions and epoch alike: the two id
      // spaces come from different repositories and may collide, so the dashboard variants
      // here would log out — and un-revoke — the wrong account.
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('admin-1', 'platform')
      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('admin-1', 'platform')
      // A platform admin carries no tenant, so the email port is handed the 'platform' plane
      // sentinel as the notification's attribution — never an empty string.
      expect(mockEmailProvider.sendMfaDisabledNotification).toHaveBeenCalledWith(
        'platform',
        SAFE_ADMIN.email
      )
      // The afterMfaDisabled hook must receive the PLATFORM projection: the
      // `context === 'platform' ? platformUserAsSafeUser(...) : ...` ternary (line 690) takes the
      // platform branch, so tenantId is the '' sentinel. Kills the `false` and `!==` mutants on
      // line 690 (which would use toSafeUser and drop the sentinel), plus line 301 (tenantId='').
      const hookUser = mockHooks.afterMfaDisabled.mock.calls[0]?.[0] as {
        tenantId: string
        emailVerified: boolean
      }
      expect(hookUser.tenantId).toBe('')
      expect(hookUser.emailVerified).toBe(true)
    })

    // Verifies that errors thrown by the afterMfaDisabled hook are silently suppressed (fire-and-forget).
    it('should complete successfully even when afterMfaDisabled hook rejects', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockHooks.afterMfaDisabled.mockImplementation(() => Promise.reject(new Error('hook failure')))

      // Should resolve without throwing — hook errors must not propagate
      await expect(
        service.disable('user-1', validCode, '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
      ).resolves.toBeUndefined()
      // Drain microtasks so the .catch callback executes (for coverage).
      // Two hops needed: one to resolve the internal Promise.resolve(rejected), one to run .catch.
      // Using Promise.resolve() instead of setTimeout(0) so fake timers don't block execution.
      await Promise.resolve()
      await Promise.resolve()
    })

    // Scenario: disable succeeds but the consumer registered no afterMfaDisabled hook. Expected:
    // disable completes without throwing. Why: covers the false branch of
    // `if (this.hooks.afterMfaDisabled)` (line 695) where the hook is absent.
    it('should complete disable when no afterMfaDisabled hook is registered', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

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
          // Hooks object without afterMfaDisabled — the `if` guard must short-circuit.
          { provide: BYMAX_AUTH_HOOKS, useValue: {} }
        ]
      }).compile()
      const noHookService = module.get(MfaService)

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)

      await expect(
        noHookService.disable('user-1', validCode, '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
      ).resolves.toBeUndefined()
    })
  })

  // ---------------------------------------------------------------------------
  // setup — platform context
  // ---------------------------------------------------------------------------

  describe('setup — platform context', () => {
    // Verifies that setup with context='platform' resolves the user via
    // platformUserRepo and never touches the dashboard userRepo. Without this,
    // a platform admin's MFA enrolment would silently target a tenant user row.
    it('should resolve user via platformUserRepo when context is platform', async () => {
      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: false,
        mfaRecoveryCodes: []
      })

      const result = await service.setup('admin-1', 'platform', PASSWORD)

      expect(mockPlatformUserRepo.findById).toHaveBeenCalledWith('admin-1')
      expect(mockUserRepo.findById).not.toHaveBeenCalled()
      expect(result.secret).toMatch(/^[A-Z2-7]+$/)
      expect(result.recoveryCodes).toHaveLength(2)
    })

    // Verifies that setup throws MFA_NOT_ENABLED when context='platform' but the
    // platform repository was not configured at module registration — surfacing
    // the misconfiguration at the first request instead of silently falling back
    // to the dashboard repo (which would persist on the wrong table).
    it('should throw MFA_NOT_ENABLED when platform context is used without platformUserRepo', async () => {
      const { Test: NestTest } = await import('@nestjs/testing')
      const moduleWithoutRepo = await NestTest.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          // BYMAX_AUTH_PLATFORM_USER_REPOSITORY intentionally omitted
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()
      const serviceWithoutRepo = moduleWithoutRepo.get(MfaService)

      expect.assertions(1)
      try {
        await serviceWithoutRepo.setup('admin-1', 'platform', PASSWORD)
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_NOT_ENABLED })
        })
      }
    })

    // Verifies that setup logs the resolved context so platform vs dashboard
    // operations can be distinguished in observability streams.
    it('should log the context on a successful platform setup', async () => {
      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: false,
        mfaRecoveryCodes: []
      })
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      await service.setup('admin-1', 'platform', PASSWORD)

      expect(logSpy).toHaveBeenCalledWith(
        'setup: MFA setup initiated userId=admin-1 context=platform'
      )
      logSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // verifyAndEnable — platform context
  // ---------------------------------------------------------------------------

  describe('verifyAndEnable — platform context', () => {
    beforeEach(() => {
      jest.useFakeTimers()
      jest.setSystemTime(new Date('2026-01-01T00:00:15.000Z'))
    })

    afterEach(() => {
      jest.useRealTimers()
    })

    // Verifies that verifyAndEnable persists MFA state via platformUserRepo when
    // context='platform' — never via userRepo. Catches the most dangerous bug
    // class for this feature (silent cross-repo write).
    it('should persist MFA state via platformUserRepo and fire the platform projection hook', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: false,
        mfaRecoveryCodes: []
      })
      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockRedis.setnx.mockResolvedValue(true)
      mockRedis.getdel.mockResolvedValue(JSON.stringify(setupData))

      await service.verifyAndEnable('admin-1', validCode, '1.2.3.4', 'Browser', 'platform')

      // Revocation scoped to the platform plane — see the disable counterpart for why.
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('admin-1', 'platform')
      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('admin-1', 'platform')

      expect(mockPlatformUserRepo.updateMfa).toHaveBeenCalledWith(
        'admin-1',
        expect.objectContaining({ mfaEnabled: true })
      )
      // The dashboard repo must NOT have received the write — pins the
      // `if (context === 'platform' && this.platformUserRepo)` branch and kills
      // mutants that would route both contexts to the same repo.
      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      // The afterMfaEnabled hook must be invoked with the platform projection
      // (tenantId='' sentinel) — kills mutants that would force the dashboard
      // projection (which would carry a real tenantId).
      expect(mockHooks.afterMfaEnabled).toHaveBeenCalledTimes(1)
      const hookUser = mockHooks.afterMfaEnabled.mock.calls[0]?.[0] as { tenantId: string }
      expect(hookUser.tenantId).toBe('')
    })

    // Verifies that verifyAndEnable throws MFA_NOT_ENABLED when the platform
    // repository is not configured. Without this, a platform-context enable
    // request would silently fall back to the dashboard repo at line 478.
    it('should throw MFA_NOT_ENABLED when platform context is used without platformUserRepo', async () => {
      const { Test: NestTest } = await import('@nestjs/testing')
      const moduleWithoutRepo = await NestTest.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()
      const serviceWithoutRepo = moduleWithoutRepo.get(MfaService)

      // The specific code matters: any other AuthException here would mean the guard let the
      // request through and something downstream refused it instead — which is the bug this
      // test exists for, since downstream would be the *dashboard* repository.
      await expect(
        serviceWithoutRepo.verifyAndEnable('admin-1', '123456', '1.2.3.4', 'Browser', 'platform')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_NOT_ENABLED } }
      })
      // Refused before any read: the dashboard repository is never consulted for a platform
      // request, not even to fail.
      expect(mockUserRepo.findById).not.toHaveBeenCalled()

      // And the guard is about the platform context specifically — a dashboard enable on the
      // same (platform-less) service is not a misconfiguration and must run its normal course.
      mockUserRepo.findById.mockResolvedValue({
        ...SAFE_USER,
        passwordHash: 'hash',
        mfaEnabled: false,
        mfaRecoveryCodes: []
      })
      mockRedis.get.mockResolvedValue(null)
      await expect(
        serviceWithoutRepo.verifyAndEnable(
          'user-1',
          '123456',
          '1.2.3.4',
          'Browser',
          'dashboard',
          'tenant-1'
        )
      ).rejects.not.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_NOT_ENABLED } }
      })
    })
  })

  // ---------------------------------------------------------------------------
  // regenerateRecoveryCodes
  // ---------------------------------------------------------------------------

  describe('regenerateRecoveryCodes', () => {
    beforeEach(() => {
      jest.useFakeTimers()
      jest.setSystemTime(new Date('2026-01-01T00:00:15.000Z'))
    })

    afterEach(() => {
      jest.useRealTimers()
    })

    // Verifies that regenerate throws TOKEN_INVALID when the user is not found —
    // mirrors the disable() guard so an unknown user never reaches scrypt.
    it('should throw TOKEN_INVALID when user is not found', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(
        service.regenerateRecoveryCodes(
          'unknown',
          '123456',
          '1.2.3.4',
          'Browser',
          'dashboard',
          'tenant-1'
        )
      ).rejects.toThrow(AuthException)
    })

    // Verifies that regenerate throws MFA_NOT_ENABLED when MFA is not active —
    // the action is meaningless without an existing TOTP secret to rotate against.
    it('should throw MFA_NOT_ENABLED when MFA is not active', async () => {
      expect.assertions(1)
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_DISABLED, mfaEnabled: false })

      try {
        await service.regenerateRecoveryCodes(
          'user-1',
          '123456',
          '1.2.3.4',
          'Browser',
          'dashboard',
          'tenant-1'
        )
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_NOT_ENABLED })
        })
      }
    })

    // Verifies that regenerate throws TOKEN_INVALID when mfaEnabled is true but
    // mfaSecret is null — database inconsistency must surface, not crash.
    it('should throw TOKEN_INVALID when mfaEnabled is true but mfaSecret is null', async () => {
      expect.assertions(1)
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_ENABLED, mfaSecret: null })

      try {
        await service.regenerateRecoveryCodes(
          'user-1',
          '123456',
          '1.2.3.4',
          'Browser',
          'dashboard',
          'tenant-1'
        )
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.TOKEN_INVALID })
        })
      }
    })

    // Verifies that regenerate throws ACCOUNT_LOCKED when the brute-force
    // threshold has been reached. Reuses the disable counter namespace so a
    // pre-auth attacker cannot exhaust it via the public challenge endpoint.
    it('should throw ACCOUNT_LOCKED when user is locked out', async () => {
      expect.assertions(2)
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockBruteForce.isLockedOut.mockResolvedValue(true)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      try {
        await service.regenerateRecoveryCodes(
          'user-1',
          '123456',
          '1.2.3.4',
          'Browser',
          'dashboard',
          'tenant-1'
        )
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.ACCOUNT_LOCKED })
        })
      }
      expect(warnSpy).toHaveBeenCalledWith(
        'regenerateRecoveryCodes: account locked userId=user-1 context=dashboard'
      )
      warnSpy.mockRestore()
    })

    // Verifies that regenerate throws MFA_INVALID_CODE for a wrong TOTP and
    // records a brute-force failure (same counter as disable — kills mutants
    // that would target the challenge counter instead).
    it('should throw MFA_INVALID_CODE and record brute-force failure for a wrong code', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await expect(
        service.regenerateRecoveryCodes(
          'user-1',
          '000000',
          '1.2.3.4',
          'Browser',
          'dashboard',
          'tenant-1'
        )
      ).rejects.toThrow(AuthException)
      expect(mockBruteForce.recordFailure).toHaveBeenCalledWith(
        hmacSha256('disable:dashboard:user-1', HMAC_KEY)
      )
      expect(warnSpy).toHaveBeenCalledWith(
        'regenerateRecoveryCodes: invalid MFA code userId=user-1 context=dashboard'
      )
      warnSpy.mockRestore()
    })

    // Verifies the happy path: a valid TOTP returns fresh plain-text codes,
    // persists new hashes via userRepo, resets the brute-force counter, and
    // preserves the existing TOTP secret (only recovery codes change).
    it('should return fresh recovery codes and persist new hashes on a valid TOTP', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))
      const encryptedSecret = encrypt(base32, VALID_ENCRYPTION_KEY)

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encryptedSecret,
        mfaRecoveryCodes: ['$scrypt$old1', '$scrypt$old2']
      })
      mockRedis.setnx.mockResolvedValue(true)
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      const result = await service.regenerateRecoveryCodes(
        'user-1',
        validCode,
        '1.2.3.4',
        'Browser',
        'dashboard',
        'tenant-1'
      )

      // recoveryCodeCount=2 in mockOptions
      expect(result.recoveryCodes).toHaveLength(2)
      for (const code of result.recoveryCodes) {
        expect(code).toMatch(/^[0-9A-F]{4}(-[0-9A-F]{4}){5}$/)
      }
      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith('user-1', 'tenant-1', {
        mfaEnabled: true,
        mfaSecret: encryptedSecret, // unchanged — only recovery codes rotate
        mfaRecoveryCodes: expect.any(Array)
      })
      // The stored hashes must NOT be the same as the old ones — pins that
      // the new codes are actually fresh.
      const persisted = mockUserRepo.updateMfa.mock.calls[0]?.[2] as {
        mfaRecoveryCodes: string[]
      }
      expect(persisted.mfaRecoveryCodes).not.toEqual(['$scrypt$old1', '$scrypt$old2'])
      expect(mockBruteForce.resetFailures).toHaveBeenCalled()
      expect(logSpy).toHaveBeenCalledWith(
        'regenerateRecoveryCodes: recovery codes regenerated userId=user-1 context=dashboard'
      )
      // The afterMfaRecoveryCodesRegenerated hook must be invoked with the
      // dashboard projection (real tenantId).
      expect(mockHooks.afterMfaRecoveryCodesRegenerated).toHaveBeenCalledTimes(1)
      const hookUser = mockHooks.afterMfaRecoveryCodesRegenerated.mock.calls[0]?.[0] as {
        tenantId: string
      }
      expect(hookUser.tenantId).toBe('tenant-1')
      logSpy.mockRestore()
    })

    // Verifies that the platform context routes the write through
    // platformUserRepo and fires the hook with the platform projection. This is
    // the strongest test against silent cross-repo writes.
    it('should persist via platformUserRepo and fire the platform hook projection for platform context', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: true,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: ['$scrypt$old1']
      })
      mockRedis.setnx.mockResolvedValue(true)

      const result = await service.regenerateRecoveryCodes(
        'admin-1',
        validCode,
        '1.2.3.4',
        'Browser',
        'platform'
      )

      expect(result.recoveryCodes).toHaveLength(2)
      expect(mockPlatformUserRepo.updateMfa).toHaveBeenCalledWith(
        'admin-1',
        expect.objectContaining({ mfaEnabled: true })
      )
      // The dashboard repo must NOT receive the write.
      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      // The hook must receive the platform projection (tenantId='' sentinel).
      expect(mockHooks.afterMfaRecoveryCodesRegenerated).toHaveBeenCalledTimes(1)
      const hookUser = mockHooks.afterMfaRecoveryCodesRegenerated.mock.calls[0]?.[0] as {
        tenantId: string
        emailVerified: boolean
      }
      expect(hookUser.tenantId).toBe('')
      expect(hookUser.emailVerified).toBe(true)
    })

    // Verifies that regenerate throws MFA_NOT_ENABLED when the platform user
    // repository was not configured — caller misconfiguration must fail closed,
    // never silently fall back to the dashboard repo (data corruption risk).
    it('should throw MFA_NOT_ENABLED when platform context is used without platformUserRepo', async () => {
      const { Test: NestTest } = await import('@nestjs/testing')
      const moduleWithoutRepo = await NestTest.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()
      const serviceWithoutRepo = moduleWithoutRepo.get(MfaService)

      await expect(
        serviceWithoutRepo.regenerateRecoveryCodes(
          'admin-1',
          '123456',
          '1.2.3.4',
          'Browser',
          'platform'
        )
      ).rejects.toThrow(AuthException)
    })

    // Verifies that errors thrown by the hook are silently suppressed — a
    // failing audit-log integration must not propagate after a successful
    // rotation. Mirrors the disable() suppression contract.
    it('should complete successfully even when afterMfaRecoveryCodesRegenerated hook rejects', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockHooks.afterMfaRecoveryCodesRegenerated.mockImplementation(() =>
        Promise.reject(new Error('hook failure'))
      )

      await expect(
        service.regenerateRecoveryCodes(
          'user-1',
          validCode,
          '1.2.3.4',
          'Browser',
          'dashboard',
          'tenant-1'
        )
      ).resolves.toEqual(expect.objectContaining({ recoveryCodes: expect.any(Array) }))
      // Drain microtasks so the .catch callback executes (for coverage).
      await Promise.resolve()
      await Promise.resolve()
    })

    // Verifies that regenerate completes without the hook registered — covers
    // the false branch of `if (this.hooks.afterMfaRecoveryCodesRegenerated)`.
    it('should complete regenerate when no afterMfaRecoveryCodesRegenerated hook is registered', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

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
          // Hooks object without afterMfaRecoveryCodesRegenerated — the `if` guard must short-circuit.
          { provide: BYMAX_AUTH_HOOKS, useValue: {} }
        ]
      }).compile()
      const noHookService = module.get(MfaService)

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)

      await expect(
        noHookService.regenerateRecoveryCodes(
          'user-1',
          validCode,
          '1.2.3.4',
          'Browser',
          'dashboard',
          'tenant-1'
        )
      ).resolves.toEqual(expect.objectContaining({ recoveryCodes: expect.any(Array) }))
    })

    // Verifies that the default DEFAULT_RECOVERY_CODE_COUNT (8) is used when
    // recoveryCodeCount is absent from the mfa options — exercises the
    // `?? DEFAULT_RECOVERY_CODE_COUNT` branch at the regenerate path.
    it('should use DEFAULT_RECOVERY_CODE_COUNT when recoveryCodeCount is not configured', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const { Test: NestTest } = await import('@nestjs/testing')
      const optionsWithoutCount = {
        jwt: { secret: JWT_SECRET },
        hmacKey: HMAC_KEY,
        previousHmacKeys: [],
        // Every MFA entry point re-reads the account and refuses a blocked one, so even a
        // fixture that is about the recovery-code count has to carry the resolved list.
        blockedStatuses: ['banned', 'suspended'],
        mfa: {
          encryptionKey: VALID_ENCRYPTION_KEY,
          issuer: 'TestApp',
          totpWindow: 1
          // recoveryCodeCount intentionally absent
        },
        sessions: { enabled: false, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
      }
      const module = await NestTest.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: optionsWithoutCount },
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
      const svc = module.get(MfaService)

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)

      const result = await svc.regenerateRecoveryCodes(
        'user-1',
        validCode,
        '1.2.3.4',
        'Browser',
        'dashboard',
        'tenant-1'
      )

      expect(result.recoveryCodes).toHaveLength(8)
    })
  })

  // ---------------------------------------------------------------------------
  // Misconfiguration: platform context without a platform repository
  // ---------------------------------------------------------------------------

  describe('platform context with no platform repository wired', () => {
    let unwired: MfaService

    beforeEach(async () => {
      // The same module, minus the platform repository. A host can enable MFA without ever
      // wiring the platform plane, and every platform-context entry point has to fail closed
      // rather than fall through to the tenant repository — writing a platform admin's MFA
      // secret onto a tenant user row would be a cross-plane credential leak.
      const module = await Test.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY, useValue: null },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()

      unwired = module.get(MfaService)
    })

    // Verifies setup refuses rather than provisioning against the wrong repository, with the
    // misconfiguration code specifically. Asserting merely "some AuthException" would not
    // distinguish this guard from a later failure on the fall-through path.
    it('should refuse setup for the platform context', async () => {
      await expect(unwired.setup('admin-1', 'platform', PASSWORD)).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_NOT_ENABLED } }
      })

      expect(mockUserRepo.findById).not.toHaveBeenCalled()
    })

    // Verifies verifyAndEnable refuses before it can persist a secret anywhere.
    it('should refuse verifyAndEnable for the platform context', async () => {
      await expect(
        unwired.verifyAndEnable('admin-1', '123456', '1.2.3.4', 'Browser', 'platform')
      ).rejects.toBeInstanceOf(AuthException)

      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
    })

    // Verifies regenerateRecoveryCodes refuses, so a caller cannot mint platform recovery
    // codes that would be written to a tenant row.
    it('should refuse regenerateRecoveryCodes for the platform context', async () => {
      await expect(
        unwired.regenerateRecoveryCodes('admin-1', '123456', '1.2.3.4', 'Browser', 'platform')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_NOT_ENABLED } }
      })

      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      expect(mockBruteForce.isLockedOut).not.toHaveBeenCalled()
    })

    // Verifies the dashboard context is unaffected: the guard must key on the context, not
    // simply refuse whenever the platform repository is absent.
    it('should still serve the dashboard context', async () => {
      mockUserRepo.findById.mockResolvedValue(AUTH_USER_MFA_DISABLED)
      mockRedis.get.mockResolvedValue(null)
      mockRedis.setIfAbsent.mockResolvedValue(true)

      await expect(
        unwired.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')
      ).resolves.toMatchObject({
        secret: expect.any(String)
      })
    })
  })

  // ---------------------------------------------------------------------------
  // Rotating the MFA encryption key
  // ---------------------------------------------------------------------------

  describe('encryption key rotation', () => {
    const RETIRED_KEY = Buffer.alloc(32, 3).toString('base64')
    const ROTATION_AUTH_RESULT = { accessToken: 'at', rawRefreshToken: 'rt', user: {} }

    beforeEach(() => {
      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'user-1',
        context: 'dashboard',
        tenantId: 'tenant-1',
        jti: 'jti-rotation'
      })
      mockTokenManager.issueTokens.mockResolvedValue(ROTATION_AUTH_RESULT)
      mockBruteForce.isLockedOut.mockResolvedValue(false)
    })

    // Scenario: a TOTP secret encrypted under a key since retired, with the rotation
    // configured. Expected: the challenge succeeds. Why: the ciphertext records no key
    // identifier, so without the retired key every stored secret becomes undecryptable the
    // moment `mfa.encryptionKey` changes — every enrolled user's authenticator stops matching
    // at once, with no way back.
    it('should decrypt a secret stored under a retired key', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const rotated = await buildService({
        mfa: { ...mockOptions.mfa, previousEncryptionKeys: [RETIRED_KEY] }
      })

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        // Written under the OLD key: the current one cannot open it.
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: []
      })
      mockRedis.setnx.mockResolvedValue(true)

      await expect(
        rotated.challenge('mfa.temp', generateTotp(base32), '1.2.3.4', 'Browser')
      ).resolves.toBe(ROTATION_AUTH_RESULT)
    })

    // Scenario: the same secret, rotation NOT configured. Expected: refused. Why: this is the
    // failure the test above prevents, and it has to be shown to be real — otherwise the
    // fallback could be doing nothing and both tests would still pass.
    it('should refuse a secret whose key was not listed', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: []
      })

      await expect(
        service.challenge('mfa.temp', generateTotp(base32), '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
    })

    // …and it refuses it after exactly ONE attempt. With no rotation configured the retired-key
    // loop has nothing to iterate, and the absent list has to stand in as empty rather than as a
    // placeholder entry: the refusal looks identical either way, but an AES-GCM open per rejected
    // challenge is not free, and every enrolled account on a deployment that never rotated would
    // pay it on the unauthenticated MFA path — where a flood of wrong codes is what an attacker
    // sends.
    it('should attempt exactly one decryption when no rotation is configured', async () => {
      const aesGcm = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const decryptSpy = jest.spyOn(aesGcm, 'decrypt')

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: aesGcm.encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: []
      })

      await expect(
        service.challenge('mfa.temp', generateTotp(base32), '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)

      expect(decryptSpy).toHaveBeenCalledTimes(1)
      decryptSpy.mockRestore()
    })

    // Scenario: a successful challenge against a secret under a retired key. Expected: the
    // secret is rewritten under the current one. Why: without it the rotation never drains and
    // the retired key has to stay configured forever — a key that still opens every secret.
    it('should re-encrypt the secret under the current key after a successful challenge', async () => {
      const { encrypt, decrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const rotated = await buildService({
        mfa: { ...mockOptions.mfa, previousEncryptionKeys: [RETIRED_KEY] }
      })

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: []
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.updateMfa.mockResolvedValue(undefined)

      await rotated.challenge('mfa.temp', generateTotp(base32), '1.2.3.4', 'Browser')
      await new Promise((resolve) => setImmediate(resolve))

      const [, , update] = mockUserRepo.updateMfa.mock.calls[0] as [
        string,
        string | undefined,
        { mfaSecret: string }
      ]
      // Readable under the CURRENT key, and the plaintext is unchanged.
      expect(decrypt(update.mfaSecret, VALID_ENCRYPTION_KEY)).toBe(base32)
    })

    // Scenario: the re-encryption write fails. Expected: the challenge still succeeded. Why:
    // the retired key still opens the secret, so a failed migration costs nothing but the
    // migration — failing the login over it would turn housekeeping into an outage.
    it('should not fail the challenge when the re-encryption write fails', async () => {
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const rotated = await buildService({
        mfa: { ...mockOptions.mfa, previousEncryptionKeys: [RETIRED_KEY] }
      })

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: []
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.updateMfa.mockRejectedValue(new Error('write failed'))

      await expect(
        rotated.challenge('mfa.temp', generateTotp(base32), '1.2.3.4', 'Browser')
      ).resolves.toBe(ROTATION_AUTH_RESULT)
      await new Promise((resolve) => setImmediate(resolve))

      expect(errorSpy).toHaveBeenCalledWith(
        're-encryption under the current MFA key failed',
        expect.any(Error)
      )
      errorSpy.mockRestore()
    })

    // Scenario: the same rotation, but the account lives on the platform plane. Expected: the
    // rewrite goes to the platform repository. Why: the two planes are separate stores, and a
    // rewrite routed to the wrong one leaves the platform secret under the retired key forever
    // while the log says the migration ran.
    it('should re-encrypt a platform secret through the platform repository', async () => {
      const { encrypt, decrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const rotated = await buildService({
        mfa: { ...mockOptions.mfa, previousEncryptionKeys: [RETIRED_KEY] }
      })

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'admin-1',
        context: 'platform',
        jti: 'jti-rotation-platform'
      })
      mockTokenManager.issuePlatformTokens.mockResolvedValue(ROTATION_AUTH_RESULT)
      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: true,
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: []
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockPlatformUserRepo.updateMfa.mockResolvedValue(undefined)

      await rotated.challenge('mfa.temp', generateTotp(base32), '1.2.3.4', 'Browser')
      await new Promise((resolve) => setImmediate(resolve))

      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      const [, update] = mockPlatformUserRepo.updateMfa.mock.calls[0] as [
        string,
        { mfaSecret: string }
      ]
      expect(decrypt(update.mfaSecret, VALID_ENCRYPTION_KEY)).toBe(base32)
    })

    // Scenario: a RECOVERY-code challenge against a secret under a retired key. Expected: the
    // splice write carries the re-encrypted secret. Why: that path already writes the record,
    // so a separate write would be a second round trip — but it also means the re-encryption
    // rides on a value that is easy to leave untouched, and then only recovery-code users never
    // migrate.
    it('should re-encrypt on the recovery-code path, in the write it already makes', async () => {
      const { encrypt, decrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'
      const rotated = await buildService({
        mfa: { ...mockOptions.mfa, previousEncryptionKeys: [RETIRED_KEY] }
      })

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: [hmacSha256(plainRecovery, HMAC_KEY)]
      })
      mockUserRepo.updateMfa.mockResolvedValue(undefined)

      await rotated.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      const [, , update] = mockUserRepo.updateMfa.mock.calls[0] as [
        string,
        string | undefined,
        { mfaSecret: string; mfaRecoveryCodes: string[] }
      ]
      expect(decrypt(update.mfaSecret, VALID_ENCRYPTION_KEY)).toBe(base32)
      // …and the code that was used is still gone: the re-encryption rides along, it does not
      // replace the write's own job.
      expect(update.mfaRecoveryCodes).toEqual([])
    })

    // Scenario: a TOTP re-encryption for a record whose recovery-code list is absent, not
    // empty. Expected: the rewrite still happens and stores an empty list. Why: a repository
    // that returns `undefined` for a user who never generated codes would otherwise crash the
    // migration — or, worse, write `undefined` over the column.
    it('should re-encrypt a record that carries no recovery-code list', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const rotated = await buildService({
        mfa: { ...mockOptions.mfa, previousEncryptionKeys: [RETIRED_KEY] }
      })

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: undefined
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.updateMfa.mockResolvedValue(undefined)

      await rotated.challenge('mfa.temp', generateTotp(base32), '1.2.3.4', 'Browser')
      await new Promise((resolve) => setImmediate(resolve))

      const [, , update] = mockUserRepo.updateMfa.mock.calls[0] as [
        string,
        string | undefined,
        { mfaRecoveryCodes: string[] }
      ]
      expect(update.mfaRecoveryCodes).toEqual([])
    })
  })
  // A suspended or banned account must not be able to change its own authentication factor.
  //
  // `challenge` gated on status from the start; `setup`, `verifyAndEnable`, `disable` and
  // `regenerateRecoveryCodes` did not. That left an operator's kill switch worth nothing
  // against an attacker still holding an unexpired access token: they could turn the second
  // factor off, or enrol their own authenticator over it, for the token's remaining lifetime.
  // Nothing else covers that window — no status change bumps the token epoch, and neither MFA
  // controller composes `UserStatusGuard` (the platform plane has no status guard at all), so
  // this per-request check is the only defence.
  //
  // The gate lives in `fetchUserForContext`, which every one of these methods calls, so the
  // check is inherited rather than remembered. These cases pin that it actually fires on each.
  describe('plane/tenant binding on the public API', () => {
    // MfaService is a public API. The controller always sources a validated tenant from the JWT,
    // but a host wiring the service directly could hand a dashboard flow no tenant — which would
    // otherwise reach the tenant-blind account read and key derivation. Every entry point refuses
    // it, naming the field, BEFORE any repository read. Each is called here with only its required
    // arguments, so the plane defaults to `'dashboard'` and no tenant is supplied — the very shape
    // a direct caller would produce.
    it.each<[string, (svc: MfaService) => Promise<unknown>]>([
      ['setup', (svc) => svc.setup('user-1')],
      ['verifyAndEnable', (svc) => svc.verifyAndEnable('user-1', '123456', '1.2.3.4', 'Browser')],
      ['disable', (svc) => svc.disable('user-1', '123456', '1.2.3.4', 'Browser')],
      ['resetMfa', (svc) => svc.resetMfa('user-1')],
      [
        'regenerateRecoveryCodes',
        (svc) => svc.regenerateRecoveryCodes('user-1', '123456', '1.2.3.4', 'Browser')
      ]
    ])(
      'refuses %s on the default dashboard plane with no tenant, before the repository',
      async (_label, call) => {
        await expect(call(service)).rejects.toMatchObject({
          response: {
            error: {
              code: AUTH_ERROR_CODES.VALIDATION,
              details: [
                {
                  field: 'tenantId',
                  message:
                    'tenantId must be a non-empty value on the dashboard plane and absent on the platform plane'
                }
              ]
            }
          }
        })
        expect(mockUserRepo.findById).not.toHaveBeenCalled()
      }
    )

    // The mirror rule: a platform flow MUST NOT carry a tenant it does not have. The named field
    // and message are pinned so the refusal keeps telling the caller which claim is wrong.
    it('refuses a platform call that supplies a tenant', async () => {
      await expect(
        service.setup('admin-1', 'platform', PASSWORD, 'tenant-1')
      ).rejects.toMatchObject({
        response: {
          error: {
            code: AUTH_ERROR_CODES.VALIDATION,
            details: [
              {
                field: 'tenantId',
                message:
                  'tenantId must be a non-empty value on the dashboard plane and absent on the platform plane'
              }
            ]
          }
        }
      })
    })

    // An unset environment variable becomes an empty string by the time it reaches the call site,
    // and a blank tenant would build `dashboard::{userId}` — a third keyspace distinct from every
    // real tenant's. A dashboard call needs a non-empty tenant, so `''` is refused exactly as a
    // missing one is, before any repository read.
    it('refuses a dashboard call whose tenant is the empty string', async () => {
      await expect(service.setup('user-1', 'dashboard', PASSWORD, '')).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.VALIDATION } }
      })
      expect(mockUserRepo.findById).not.toHaveBeenCalled()
    })

    // Scoping the READ is not enough: the write every MFA transition makes must be scoped by the
    // same tenant, or a recovery-code splice lands on another tenant's row — or on no row — and the
    // spent code is never removed. The write must carry the FLOW's tenant, not a constant: a
    // challenge authenticated in `tenant-9` splices through `updateMfa(userId, 'tenant-9', …)`.
    it('scopes the recovery-code splice write to the challenge tenant', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'user-1',
        context: 'dashboard',
        tenantId: 'tenant-9',
        jti: 'jti-write-scope'
      })
      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: [hmacSha256(plainRecovery, HMAC_KEY)]
      })

      await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith(
        'user-1',
        'tenant-9',
        expect.objectContaining({ mfaRecoveryCodes: [] })
      )
    })
  })

  describe('account status gates every MFA state change', () => {
    const BLOCKED = { ...AUTH_USER_MFA_ENABLED, status: 'SUSPENDED' }

    beforeEach(() => {
      mockUserRepo.findById.mockResolvedValue(BLOCKED)
      mockPlatformUserRepo.findById.mockResolvedValue({ ...SAFE_ADMIN, status: 'BANNED' })
    })

    it.each([
      ['setup', (svc: MfaService) => svc.setup('user-1', 'dashboard', PASSWORD, 'tenant-1')],
      [
        'verifyAndEnable',
        (svc: MfaService) =>
          svc.verifyAndEnable('user-1', '123456', '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
      ],
      [
        'disable',
        (svc: MfaService) =>
          svc.disable('user-1', '123456', '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
      ],
      [
        'regenerateRecoveryCodes',
        (svc: MfaService) =>
          svc.regenerateRecoveryCodes(
            'user-1',
            '123456',
            '1.2.3.4',
            'Browser',
            'dashboard',
            'tenant-1'
          )
      ]
    ])('refuses %s for a blocked dashboard account', async (_label, call) => {
      await expect(call(service)).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.ACCOUNT_SUSPENDED } }
      })
      // Refused before anything was written, minted or spent.
      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      expect(mockRedis.setIfAbsent).not.toHaveBeenCalled()
    })

    // The platform plane carries the higher-privilege identity and has no status guard of its
    // own, so the service-level gate is the whole defence there.
    it.each([
      ['setup', (svc: MfaService) => svc.setup('admin-1', 'platform', PASSWORD)],
      [
        'verifyAndEnable',
        (svc: MfaService) =>
          svc.verifyAndEnable('admin-1', '123456', '1.2.3.4', 'Browser', 'platform')
      ],
      [
        'disable',
        (svc: MfaService) => svc.disable('admin-1', '123456', '1.2.3.4', 'Browser', 'platform')
      ],
      [
        'regenerateRecoveryCodes',
        (svc: MfaService) =>
          svc.regenerateRecoveryCodes('admin-1', '123456', '1.2.3.4', 'Browser', 'platform')
      ]
    ])('refuses %s for a blocked platform admin', async (_label, call) => {
      await expect(call(service)).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.ACCOUNT_BANNED } }
      })
      expect(mockPlatformUserRepo.updateMfa).not.toHaveBeenCalled()
    })
  })

  describe('MFA subject-derived keys — tenant scoping and migration', () => {
    // The headline hazard: a lockout counter shared across tenants is a CREDENTIAL-FREE
    // cross-tenant lockout — wrong codes against tenant A's user `1` spend tenant B's user `1`
    // budget, and a success on either clears the other. Two tenants' user `1` must land on
    // DIFFERENT scoped counters. This is red without the tenant in the preimage: the scoped
    // identifiers would coincide.
    it('gives two tenants distinct scoped challenge lockout counters for the same user id', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: []
      })
      mockRedis.setnx.mockResolvedValue(true)

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'user-1',
        context: 'dashboard',
        tenantId: 'tenant-a',
        jti: 'jti-a'
      })
      await expect(service.challenge('t.a', '000000', '1.2.3.4', 'B')).rejects.toThrow(
        AuthException
      )
      const tenantA = mockBruteForce.recordFailure.mock.calls.map((c) => c[0] as string)

      mockBruteForce.recordFailure.mockClear()
      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'user-1',
        context: 'dashboard',
        tenantId: 'tenant-b',
        jti: 'jti-b'
      })
      await expect(service.challenge('t.b', '000000', '1.2.3.4', 'B')).rejects.toThrow(
        AuthException
      )
      const tenantB = mockBruteForce.recordFailure.mock.calls.map((c) => c[0] as string)

      // The scoped identifier (recorded first) is tenant-specific and MUST differ; the legacy
      // identifier (recorded second) is shared across tenants — which is exactly the collision the
      // legacy arm is being retired to remove, kept only so a rolling upgrade stays consistent.
      expect(tenantA[0]).not.toBe(tenantB[0])
      expect(tenantA[1]).toBe(tenantB[1])
    })

    // On the platform plane the scoped and legacy subjects coincide (no tenant ever entered the
    // preimage), so a failure records ONE counter, not two — recording it twice would lock a
    // platform admin out at half the configured threshold.
    it('records a single challenge counter on the platform plane', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'admin-1',
        context: 'platform',
        jti: 'jti-platform-fail'
      })
      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: true,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: []
      })
      mockRedis.setnx.mockResolvedValue(true)

      await expect(service.challenge('p.fail', '000000', '1.2.3.4', 'B')).rejects.toThrow(
        AuthException
      )
      expect(mockBruteForce.recordFailure).toHaveBeenCalledTimes(1)
    })

    // A code is a replay when it was already claimed on EITHER key. If the scoped marker is taken
    // (an old code path or a concurrent new one already used it) the code must be refused even
    // though the legacy marker is still free — so the two anti-replay claims are ANDed, not ORed.
    it('rejects a dashboard code already claimed on the scoped anti-replay key', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'user-1',
        context: 'dashboard',
        tenantId: 'tenant-1',
        jti: 'jti-tu-mixed'
      })
      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: []
      })
      // Scoped marker already claimed (first setnx false), legacy marker still free (second true).
      mockRedis.setnx.mockResolvedValueOnce(false).mockResolvedValueOnce(true)

      await expect(service.challenge('mfa.temp', validCode, '1.2.3.4', 'B')).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_INVALID_CODE } }
      })
      expect(mockTokenManager.issueTokens).not.toHaveBeenCalled()
    })
  })
})
