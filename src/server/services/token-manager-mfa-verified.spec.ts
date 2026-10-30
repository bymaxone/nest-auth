/**
 * @fileoverview The second factor a session was established with survives refresh rotation.
 *
 * `MfaRequiredGuard` refuses a token whose claims say `mfaEnabled && !mfaVerified`, and no route
 * lets an authenticated session re-acquire the claim, so every rotation and grace-window recovery,
 * on both planes, must carry the session's verified factor forward. The factor lives on the
 * refresh-session record: written only when `true`, and read back strictly.
 */

import { createHash } from 'node:crypto'

import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_HOOKS, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AuthRedisService } from '../redis/auth-redis.service'
import { TokenManagerService } from './token-manager.service'

jest.mock('node:crypto', () => ({
  ...jest.requireActual('node:crypto'),
  randomUUID: jest.fn().mockReturnValue('00000000-0000-0000-0000-000000000001'),
  randomBytes: jest.fn((size: number) => Buffer.alloc(size, 0x11))
}))

const FAMILY = 'fam-1'

const mockJwtService = {
  sign: jest.fn().mockReturnValue('signed.jwt'),
  decode: jest.fn(),
  verify: jest.fn()
}
const mockHooks = { onRefreshTokenReuseDetected: jest.fn() }
const mockRedis = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  sadd: jest.fn().mockResolvedValue(1),
  srem: jest.fn().mockResolvedValue(1),
  expire: jest.fn().mockResolvedValue(undefined),
  rotateRefreshSession: jest.fn(),
  getUserTokenEpoch: jest.fn().mockResolvedValue(0),
  readSessionOwner: jest.fn().mockResolvedValue({ userId: 'user-1', tenantId: 'tenant-1' }),
  writeRecoveredSession: jest.fn().mockResolvedValue(true),
  writeNewSession: jest.fn().mockResolvedValue(undefined)
}

const mockOptions = {
  jwt: {
    accessExpiresIn: '15m',
    accessCookieMaxAgeMs: 900_000,
    refreshExpiresInDays: 7,
    refreshGraceWindowSeconds: 30,
    algorithm: 'HS256',
    secret: 'test-jwt-secret-for-hmac-that-is-at-least-32-chars-long'
  },
  hmacKey: createHash('sha256').update('bymax-auth:hmac-key:v1:x', 'utf8').digest('hex'),
  previousHmacKeys: []
}

const USER = {
  id: 'user-1',
  email: 'user@example.com',
  name: 'Test User',
  role: 'member',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: true,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}

const ADMIN = {
  id: 'admin-1',
  email: 'admin@platform.com',
  name: 'Platform Admin',
  role: 'super-admin',
  status: 'active',
  mfaEnabled: true,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01'),
  updatedAt: new Date('2026-01-01')
}

/** A stored dashboard session, with the `mfaVerified` field exactly as the test spells it. */
function dashboardRecord(extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    userId: 'user-1',
    tenantId: 'tenant-1',
    role: 'member',
    device: 'Browser',
    ip: '1.2.3.4',
    createdAt: '2026-01-01T00:00:00.000Z',
    mfaEnabled: true,
    familyId: FAMILY,
    familyCreatedAt: new Date().toISOString(),
    ...extra
  })
}

/** A stored platform session. */
function platformRecord(extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    userId: 'admin-1',
    tenantId: '',
    role: 'super-admin',
    device: 'Browser',
    ip: '1.2.3.4',
    createdAt: '2026-01-01T00:00:00.000Z',
    mfaEnabled: true,
    familyId: FAMILY,
    familyCreatedAt: new Date().toISOString(),
    ...extra
  })
}

/** The claims of the access token most recently signed. */
function lastClaims(): Record<string, unknown> {
  const calls = mockJwtService.sign.mock.calls
  return (calls[calls.length - 1] as [Record<string, unknown>])[0]
}

describe('the second factor across refresh rotation', () => {
  let service: TokenManagerService

  beforeEach(async () => {
    jest.clearAllMocks()
    mockJwtService.sign.mockReturnValue('signed.jwt')
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.getUserTokenEpoch.mockResolvedValue(0)
    mockRedis.writeRecoveredSession.mockResolvedValue(true)

    const module = await Test.createTestingModule({
      providers: [
        TokenManagerService,
        { provide: JwtService, useValue: mockJwtService },
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
      ]
    }).compile()
    service = module.get(TokenManagerService)
  })

  /** The session record the last `writeNewSession` stored. */
  const writtenSession = (): Record<string, unknown> =>
    JSON.parse(
      (mockRedis.writeNewSession.mock.calls[0] as [{ sessionJson: string }])[0].sessionJson
    ) as Record<string, unknown>

  describe('recording it when the session is established', () => {
    // Scenario: a login completed through the MFA challenge. Expected: the record says so. Why: that
    // record is the only thing a later rotation can read the factor from.
    it.each([
      ['dashboard', () => service.issueTokens(USER, '1.2.3.4', 'Browser', { mfaVerified: true })],
      [
        'platform',
        () => service.issuePlatformTokens(ADMIN, '1.2.3.4', 'Browser', { mfaVerified: true })
      ]
    ])('stores mfaVerified on a %s session opened through the challenge', async (_plane, issue) => {
      await issue()

      expect(writtenSession()['mfaVerified']).toBe(true)
    })

    // Scenario: a session opened without the challenge. Expected: the key is absent, not `false`.
    // Why: the record stays byte-identical to what rust-auth reads for a session without the factor.
    it.each([
      ['dashboard', () => service.issueTokens(USER, '1.2.3.4', 'Browser')],
      ['platform', () => service.issuePlatformTokens(ADMIN, '1.2.3.4', 'Browser')]
    ])(
      'omits mfaVerified from a %s session opened without the challenge',
      async (_plane, issue) => {
        await issue()

        expect(writtenSession()).not.toHaveProperty('mfaVerified')
      }
    )
  })

  describe('carrying it through a primary rotation', () => {
    // Scenario: a stored session that completed the challenge, rotated. Expected: the new access token
    // claims `mfaVerified: true` and the successor record carries it forward. Why: this is the lockout.
    it('copies a verified dashboard session forward and signs the claim', async () => {
      const stored = dashboardRecord({ mfaVerified: true })
      mockRedis.get.mockResolvedValue(stored)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'rotated', sessionJson: stored })

      await service.reissueTokens('old-refresh', '1.2.3.4', 'Browser')

      expect(lastClaims()).toMatchObject({ mfaEnabled: true, mfaVerified: true })
      const next = (mockRedis.rotateRefreshSession.mock.calls[0] as [{ newSessionJson: string }])[0]
      expect(JSON.parse(next.newSessionJson)).toMatchObject({ mfaVerified: true })
    })

    it('copies a verified platform session forward and signs the claim', async () => {
      const stored = platformRecord({ mfaVerified: true })
      mockRedis.get.mockResolvedValue(stored)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'rotated', sessionJson: stored })

      await service.reissuePlatformTokens('old-refresh', '1.2.3.4', 'Browser')

      expect(lastClaims()).toMatchObject({ mfaEnabled: true, mfaVerified: true })
      const next = (mockRedis.rotateRefreshSession.mock.calls[0] as [{ newSessionJson: string }])[0]
      expect(JSON.parse(next.newSessionJson)).toMatchObject({ mfaVerified: true })
    })

    // Scenario: a record that never carried the field (legacy, or opened without the
    // challenge). Expected: `false`, and the successor record gains no key. Why: persisting the factor
    // must not turn a rotation into a way around the guard.
    it.each([
      [
        'dashboard',
        dashboardRecord(),
        (): Promise<unknown> => service.reissueTokens('old', '1.2.3.4', 'B')
      ],
      [
        'platform',
        platformRecord(),
        (): Promise<unknown> => service.reissuePlatformTokens('old', '1.2.3.4', 'B')
      ]
    ])(
      'still signs mfaVerified false for a %s record without the field',
      async (_plane, stored, rotate) => {
        mockRedis.get.mockResolvedValue(stored)
        mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'rotated', sessionJson: stored })

        await rotate()

        expect(lastClaims()).toMatchObject({ mfaEnabled: true, mfaVerified: false })
        const next = (
          mockRedis.rotateRefreshSession.mock.calls[0] as [{ newSessionJson: string }]
        )[0]
        expect(JSON.parse(next.newSessionJson)).not.toHaveProperty('mfaVerified')
      }
    )

    // Scenario: a corrupt stored value that is truthy but is not the boolean `true`. Expected: not
    // verified. Why: the factor is read strictly, so no damaged record can read as having passed it.
    it.each([['true'], [1], ['yes'], [{}]])(
      'reads a stored value of %p as not verified',
      async (value) => {
        const stored = dashboardRecord({ mfaVerified: value })
        mockRedis.get.mockResolvedValue(stored)
        mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'rotated', sessionJson: stored })

        await service.reissueTokens('old-refresh', '1.2.3.4', 'Browser')

        expect(lastClaims()).toMatchObject({ mfaVerified: false })
      }
    )
  })

  describe('never inventing it', () => {
    // Scenario: a grace recovery of a session that never completed the challenge. Expected: the
    // recovered record gains no field and the token claims false. Why: recovery must copy the
    // stored factor, not assume it.
    it.each([
      [
        'dashboard',
        dashboardRecord(),
        (): Promise<unknown> => service.reissueTokens('old', '1.2.3.4', 'B')
      ],
      [
        'platform',
        platformRecord(),
        (): Promise<unknown> => service.reissuePlatformTokens('old', '1.2.3.4', 'B')
      ]
    ])('recovers an unverified %s session as unverified', async (_plane, stored, recover) => {
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'grace', sessionJson: stored })

      await recover()

      expect(lastClaims()).toMatchObject({ mfaEnabled: true, mfaVerified: false })
      const written = (
        mockRedis.writeRecoveredSession.mock.calls[0] as [{ newSessionJson: string }]
      )[0]
      expect(JSON.parse(written.newSessionJson)).not.toHaveProperty('mfaVerified')
    })

    // Scenario: the presented token's record vanished before the rotation read it, so the seed is
    // the empty placeholder. Expected: the successor record carries no factor. Why: a placeholder
    // must never be able to mint a token that clears the MFA gate.
    it('does not let the empty placeholder seed a verified successor', async () => {
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({
        kind: 'rotated',
        sessionJson: dashboardRecord()
      })

      await service.reissueTokens('old-refresh', '1.2.3.4', 'Browser')

      const next = (mockRedis.rotateRefreshSession.mock.calls[0] as [{ newSessionJson: string }])[0]
      expect(JSON.parse(next.newSessionJson)).not.toHaveProperty('mfaVerified')
    })
  })

  describe('carrying it through a grace-window recovery', () => {
    // Scenario: the presented token was already consumed but is inside its grace window, so the session
    // is recovered from the grace record. Expected: the recovered session and its access token carry the
    // factor. Why: this path builds a session too, and is the easiest one to forget.
    it('copies a verified dashboard session forward on recovery', async () => {
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({
        kind: 'grace',
        sessionJson: dashboardRecord({ mfaVerified: true })
      })

      await service.reissueTokens('old-refresh', '1.2.3.4', 'Browser')

      expect(lastClaims()).toMatchObject({ mfaVerified: true })
      const written = (
        mockRedis.writeRecoveredSession.mock.calls[0] as [{ newSessionJson: string }]
      )[0]
      expect(JSON.parse(written.newSessionJson)).toMatchObject({ mfaVerified: true })
    })

    it('copies a verified platform session forward on recovery', async () => {
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({
        kind: 'grace',
        sessionJson: platformRecord({ mfaVerified: true })
      })

      await service.reissuePlatformTokens('old-refresh', '1.2.3.4', 'Browser')

      expect(lastClaims()).toMatchObject({ mfaVerified: true })
      const written = (
        mockRedis.writeRecoveredSession.mock.calls[0] as [{ newSessionJson: string }]
      )[0]
      expect(JSON.parse(written.newSessionJson)).toMatchObject({ mfaVerified: true })
    })
  })
})
