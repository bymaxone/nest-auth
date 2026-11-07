/**
 * MfaService — re-encrypting a secret that opened under a retired key, against a concurrent
 * transition.
 *
 * The re-encryption rewrites the whole MFA record, so it is a read-modify-write like every other
 * MFA transition and must not land over a `disable` or a re-enrolment that completed in the
 * meantime. The repository is an in-memory store whose first `updateMfa` can be held, which makes
 * the interleaving deterministic, not timing-dependent. Kept apart from
 * `mfa.service.spec.ts` because that file is over the size limit.
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
import { decrypt, encrypt } from '../crypto/aes-gcm'
import { hmacSha256 } from '../crypto/secure-token'
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
const CURRENT_KEY = Buffer.from('nest-auth-test-encryption-key-32').toString('base64')
/** TEST FIXTURE ONLY: the key the rotation retired. */
const RETIRED_KEY = Buffer.alloc(32, 3).toString('base64')
/** TEST FIXTURE ONLY: not a real JWT secret. */
const JWT_SECRET = 'nest-auth-test-jwt-secret-32chars+'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const AUTH_RESULT = { accessToken: 'at', rawRefreshToken: 'rt', user: {} }

interface StoredRecord {
  id: string
  email: string
  name: string
  role: string
  status: string
  tenantId: string
  emailVerified: boolean
  lastLoginAt: null
  createdAt: Date
  passwordHash: string
  mfaEnabled: boolean
  mfaSecret: string | null
  mfaRecoveryCodes: string[] | null
}

/** One account's record as the repository holds it. */
function record(patch: Partial<StoredRecord>): StoredRecord {
  return {
    id: 'user-1',
    email: 'user@example.com',
    name: 'Test User',
    role: 'member',
    status: 'active',
    tenantId: 'tenant-1',
    emailVerified: true,
    lastLoginAt: null,
    createdAt: new Date('2026-01-01'),
    passwordHash: 'hash',
    mfaEnabled: true,
    mfaSecret: null,
    mfaRecoveryCodes: [],
    ...patch
  }
}

/**
 * An in-memory dashboard repository. While `hold` is armed the next `updateMfa` call waits for
 * `release()`, and its payload is applied only then — the write of a caller that read the record
 * earlier and has not landed yet.
 */
function createStore(initial: StoredRecord) {
  let current = { ...initial }
  let held: { resolve: () => void } | null = null
  let armed = false
  const writes: Array<{ mfaEnabled: boolean; mfaSecret: string | null }> = []
  return {
    get current(): StoredRecord {
      return current
    },
    set current(next: StoredRecord) {
      current = next
    },
    writes,
    hold(): void {
      armed = true
    },
    release(): void {
      held?.resolve()
      held = null
    },
    repo: {
      findById: jest.fn(async () => ({ ...current })),
      updateLastLogin: jest.fn(async () => undefined),
      updateMfa: jest.fn(
        async (args: {
          data: { mfaEnabled: boolean; mfaSecret: string | null; mfaRecoveryCodes: string[] | null }
        }) => {
          if (armed) {
            armed = false
            await new Promise<void>((resolve) => {
              held = { resolve }
            })
          }
          writes.push({ mfaEnabled: args.data.mfaEnabled, mfaSecret: args.data.mfaSecret })
          current = { ...current, ...args.data }
        }
      )
    }
  }
}

/** Lets every queued continuation and detached task run. */
async function flush(): Promise<void> {
  for (let i = 0; i < 10; i++) await new Promise((resolve) => setImmediate(resolve))
}

const mockPlatformUserRepo = { findById: jest.fn(), updateMfa: jest.fn() }
const mockRedis = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
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
  issueTokens: jest.fn()
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
const mockHooks = { afterMfaEnabled: jest.fn(), afterMfaDisabled: jest.fn() }

const mockOptions = {
  jwt: { secret: JWT_SECRET },
  hmacKey: HMAC_KEY,
  previousHmacKeys: [],
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED'],
  mfa: {
    encryptionKey: CURRENT_KEY,
    previousEncryptionKeys: [RETIRED_KEY],
    issuer: 'TestApp',
    totpWindow: 1,
    recoveryCodeCount: 2
  },
  sessions: { enabled: false, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
}

describe('MfaService — re-encryption against a concurrent MFA transition', () => {
  let service: MfaService
  let store: ReturnType<typeof createStore>

  /** The time step a TOTP code is valid for, offset so two calls never share a code. */
  const stepCode = (base32: string, offset: number): string =>
    generateHotp(base32, Math.floor(Date.now() / 1000 / 30) + offset)

  async function build(initial: StoredRecord): Promise<void> {
    store = createStore(initial)
    const module = await Test.createTestingModule({
      providers: [
        MfaService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: store.repo },
        { provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY, useValue: mockPlatformUserRepo },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: TokenManagerService, useValue: mockTokenManager },
        { provide: BruteForceService, useValue: mockBruteForce },
        { provide: PasswordService, useValue: mockPasswordService },
        { provide: SessionService, useValue: { createSession: jest.fn() } },
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
        { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
      ]
    }).compile()
    service = module.get(MfaService)
  }

  beforeEach(() => {
    jest.resetAllMocks()
    mockRedis.get.mockResolvedValue(null)
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.del.mockResolvedValue(true)
    mockRedis.setnx.mockResolvedValue(true)
    mockRedis.sadd.mockResolvedValue(1)
    mockRedis.srem.mockResolvedValue(1)
    mockRedis.expire.mockResolvedValue(undefined)
    // A lock that behaves like one: taken only when free, released only by its holder.
    const locks = new Map<string, string>()
    mockRedis.setIfAbsent.mockImplementation(async (key: string, token: string) => {
      if (locks.has(key)) return false
      locks.set(key, token)
      return true
    })
    mockRedis.eval.mockImplementation(async (_script: string, keys: string[], args: string[]) => {
      const key = keys[0] ?? ''
      if (locks.get(key) !== args[0]) return 0
      locks.delete(key)
      return 1
    })
    mockRedis.invalidateUserSessions.mockResolvedValue(undefined)
    mockRedis.bumpUserTokenEpoch.mockResolvedValue(undefined)
    mockTokenManager.verifyMfaTempToken.mockResolvedValue({
      userId: 'user-1',
      context: 'dashboard',
      tenantId: 'tenant-1',
      jti: 'jti-race'
    })
    mockTokenManager.consumeMfaTempToken.mockResolvedValue(true)
    mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
    mockBruteForce.isLockedOut.mockResolvedValue(false)
    mockBruteForce.recordFailure.mockResolvedValue(undefined)
    mockBruteForce.resetFailures.mockResolvedValue(undefined)
    mockPasswordService.compare.mockResolvedValue(true)
    mockEmailProvider.sendMfaDisabledNotification.mockResolvedValue(undefined)
  })

  /**
   * Disables MFA the way a user would. While the re-encryption holds the account's transition lock
   * the disable is refused, so it is retried after the held write completes — the order the two
   * run in is not the point, the state they leave behind is.
   */
  async function disableWhenPossible(base32: string): Promise<void> {
    const code = stepCode(base32, 1)
    try {
      await service.disable('user-1', code, '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
    } catch (err) {
      if (!(err instanceof AuthException)) throw err
      expect(err.getResponse()).toMatchObject({
        error: { code: AUTH_ERROR_CODES.MFA_STATE_CONFLICT }
      })
      store.release()
      await flush()
      await service.disable('user-1', code, '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')
    }
  }

  // Scenario: a TOTP challenge against a secret under a retired key schedules the re-encryption,
  // and the user disables MFA before that write lands. Expected: MFA stays disabled. Why: the
  // write replaces the whole record, so landing late it would set `mfaEnabled: true` again with
  // the secret and recovery digests the user just removed.
  it('does not turn MFA back on when it was disabled before the re-encryption landed', async () => {
    const { base32 } = generateTotpSecret()
    await build(record({ mfaSecret: encrypt(base32, RETIRED_KEY), mfaRecoveryCodes: ['digest-a'] }))
    store.hold()

    await service.challenge('mfa.temp', stepCode(base32, 0), '1.2.3.4', 'Browser')
    await disableWhenPossible(base32)
    store.release()
    await flush()

    expect(store.current.mfaEnabled).toBe(false)
    expect(store.current.mfaSecret).toBeNull()
  })

  // Scenario: the same, but the user re-enrols with a new secret and new recovery codes. Expected:
  // the new secret and the new codes are what is stored. Why: a late write would put the old
  // secret back under the current key and unspend the old recovery digests while the codes the
  // user just printed stop working.
  it('keeps a secret and recovery codes enrolled before the re-encryption landed', async () => {
    const { base32 } = generateTotpSecret()
    await build(record({ mfaSecret: encrypt(base32, RETIRED_KEY), mfaRecoveryCodes: ['digest-a'] }))
    store.hold()

    await service.challenge('mfa.temp', stepCode(base32, 0), '1.2.3.4', 'Browser')
    await disableWhenPossible(base32)
    const enrolled = encrypt(generateTotpSecret().base32, CURRENT_KEY)
    store.current = {
      ...store.current,
      mfaEnabled: true,
      mfaSecret: enrolled,
      mfaRecoveryCodes: ['digest-new']
    }
    store.release()
    await flush()

    expect(store.current.mfaSecret).toBe(enrolled)
    expect(store.current.mfaRecoveryCodes).toEqual(['digest-new'])
  })

  // Scenario: nothing else touches the account. Expected: the secret ends up readable under the
  // current key, with the plaintext unchanged and the recovery digests untouched. Why: the
  // serialization must not cost the migration it exists to protect.
  it('re-encrypts the secret when nothing else changed the record', async () => {
    const { base32 } = generateTotpSecret()
    await build(record({ mfaSecret: encrypt(base32, RETIRED_KEY), mfaRecoveryCodes: ['digest-a'] }))

    await service.challenge('mfa.temp', stepCode(base32, 0), '1.2.3.4', 'Browser')
    await flush()

    expect(decrypt(store.current.mfaSecret ?? '', CURRENT_KEY)).toBe(base32)
    expect(store.current.mfaRecoveryCodes).toEqual(['digest-a'])
    expect(store.current.mfaEnabled).toBe(true)
  })

  // Scenario: another transition holds the account's lock when the re-encryption starts.
  // Expected: the challenge still succeeds, the migration is skipped and the skip is logged.
  // Why: the retired key still opens the secret, so a refused migration costs nothing but the
  // migration, and the next challenge retries it.
  it('skips the migration, without failing the challenge, when the lock is taken', async () => {
    const { base32 } = generateTotpSecret()
    await build(record({ mfaSecret: encrypt(base32, RETIRED_KEY), mfaRecoveryCodes: ['digest-a'] }))
    mockRedis.setIfAbsent.mockResolvedValue(false)
    mockRedis.eval.mockResolvedValue(0)

    await expect(
      service.challenge('mfa.temp', stepCode(base32, 0), '1.2.3.4', 'Browser')
    ).resolves.toBe(AUTH_RESULT)
    await flush()

    expect(store.repo.updateMfa).not.toHaveBeenCalled()
  })

  // Scenario: a RECOVERY-code challenge against a retired-key secret, and the user re-enrols
  // while it is in flight. Expected: nothing is written. Why: the splice rewrites the record
  // too, and the code it spends belongs to a list that no longer exists.
  it('does not write a spliced record over a secret enrolled during a recovery challenge', async () => {
    const { base32 } = generateTotpSecret()
    const plain = '1234-5678-9012'
    await build(
      record({
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: [hmacSha256(plain, HMAC_KEY)]
      })
    )
    const enrolled = encrypt(generateTotpSecret().base32, CURRENT_KEY)
    mockTokenManager.consumeMfaTempToken.mockImplementation(async () => {
      store.current = {
        ...store.current,
        mfaSecret: enrolled,
        mfaRecoveryCodes: [hmacSha256(plain, HMAC_KEY)]
      }
      return true
    })

    await service.challenge('mfa.temp', plain, '1.2.3.4', 'Browser')
    await flush()

    expect(store.writes).toEqual([])
    expect(store.current.mfaSecret).toBe(enrolled)
  })

  // Scenario: a sibling challenge re-encrypted the same secret under the current key while a
  // RECOVERY-code challenge was in flight. Expected: the code is still removed from the list.
  // Why: only the ciphertext changed, so treating it as a re-enrolment would skip the splice and
  // leave a spent code redeemable once its single-use claim expires.
  it('spends the recovery code when a sibling only re-encrypted the same secret', async () => {
    const { base32 } = generateTotpSecret()
    const plain = '1234-5678-9012'
    const other = hmacSha256('9999-9999-9999', HMAC_KEY)
    await build(
      record({
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: [hmacSha256(plain, HMAC_KEY), other]
      })
    )
    mockTokenManager.consumeMfaTempToken.mockImplementation(async () => {
      store.current = { ...store.current, mfaSecret: encrypt(base32, CURRENT_KEY) }
      return true
    })

    await service.challenge('mfa.temp', plain, '1.2.3.4', 'Browser')
    await flush()

    expect(store.current.mfaRecoveryCodes).toEqual([other])
    expect(decrypt(store.current.mfaSecret ?? '', CURRENT_KEY)).toBe(base32)
  })

  // Scenario: the stored secret is gone or no configured key opens it when the re-encryption
  // reaches the lock. Expected: nothing is written. Why: a record that cannot be shown to hold
  // this secret is not one to overwrite with it.
  it.each([null, 'not-a-ciphertext'])(
    'writes nothing when the stored secret is %p at the lock',
    async (replacement) => {
      const { base32 } = generateTotpSecret()
      await build(record({ mfaSecret: encrypt(base32, RETIRED_KEY), mfaRecoveryCodes: [] }))
      mockTokenManager.consumeMfaTempToken.mockImplementation(async () => {
        store.current = { ...store.current, mfaSecret: replacement }
        return true
      })

      await service.challenge('mfa.temp', stepCode(base32, 0), '1.2.3.4', 'Browser')
      await flush()

      expect(store.writes).toEqual([])
    }
  )

  // Scenario: a TOTP challenge against a secret already under the current key. Expected: the
  // record is not written. Why: the re-encryption exists only to drain retired keys, and a write
  // on every challenge would take the account's lock and rewrite its record for nothing.
  it('writes nothing for a secret already under the current key', async () => {
    const { base32 } = generateTotpSecret()
    await build(record({ mfaSecret: encrypt(base32, CURRENT_KEY), mfaRecoveryCodes: ['digest-a'] }))

    await service.challenge('mfa.temp', stepCode(base32, 0), '1.2.3.4', 'Browser')
    await flush()

    expect(store.writes).toEqual([])
    expect(mockRedis.setIfAbsent).not.toHaveBeenCalled()
  })
})
