/**
 * @fileoverview The `sid` claim of the access tokens `TokenManagerService` mints, and the key of the
 * recent-authentication mark it writes: a session names itself through its refresh family id, the
 * id is unchanged through every rotation, and a record with no usable family names no session.
 */

import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { TokenManagerService } from './token-manager.service'
import { BYMAX_AUTH_HOOKS, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { recentAuthKey } from '../constants/recent-auth'
import { AuthRedisService } from '../redis/auth-redis.service'

const HMAC_KEY = 'h'.repeat(48)
const FAMILY = '4d6e1c2a-8b3f-4a5e-9c7d-0e1f2a3b4c5d'
const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

const sign = jest.fn().mockReturnValue('signed.jwt.token')
const redis = {
  get: jest.fn(),
  del: jest.fn().mockResolvedValue(1),
  set: jest.fn().mockResolvedValue(undefined),
  getUserTokenEpoch: jest.fn().mockResolvedValue(0),
  writeNewSession: jest.fn().mockResolvedValue(undefined),
  rotateRefreshSession: jest.fn(),
  writePlatformSessionDetail: jest.fn().mockResolvedValue(undefined)
}
const options = {
  jwt: { accessExpiresIn: '15m', refreshExpiresInDays: 7, refreshGraceWindowSeconds: 30 },
  hmacKey: HMAC_KEY,
  previousHmacKeys: [],
  sessions: { enabled: false }
}
const USER = {
  id: 'user-1',
  email: 'u@example.com',
  name: 'U',
  role: 'member',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}
const ADMIN = {
  id: 'admin-1',
  email: 'a@example.com',
  name: 'A',
  role: 'super-admin',
  status: 'active',
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01'),
  updatedAt: new Date('2026-01-01')
}

/** The claims of the access token the service signed most recently. */
function lastClaims(): Record<string, unknown> {
  const call = sign.mock.calls[sign.mock.calls.length - 1] as [Record<string, unknown>]
  return call[0]
}

/** A stored refresh-session record, with the given family id. */
function stored(familyId: string | undefined, plane: 'dashboard' | 'platform'): string {
  return JSON.stringify({
    userId: plane === 'dashboard' ? 'user-1' : 'admin-1',
    ...(plane === 'dashboard' ? { tenantId: 'tenant-1' } : {}),
    role: 'member',
    device: 'Browser',
    ip: '1.2.3.4',
    mfaEnabled: false,
    createdAt: '2026-01-01T00:00:00.000Z',
    ...(familyId === undefined ? {} : { familyId })
  })
}

describe('the session claim of minted access tokens', () => {
  let service: TokenManagerService

  beforeEach(async () => {
    jest.clearAllMocks()
    const module = await Test.createTestingModule({
      providers: [
        TokenManagerService,
        { provide: JwtService, useValue: { sign, decode: jest.fn(), verify: jest.fn() } },
        { provide: BYMAX_AUTH_OPTIONS, useValue: options },
        { provide: AuthRedisService, useValue: redis },
        { provide: BYMAX_AUTH_HOOKS, useValue: {} }
      ]
    }).compile()
    service = module.get(TokenManagerService)
  })

  // Scenario: a new dashboard session. Expected: the token's `sid` is the family id the session is
  // stored under, in the contract's shape, and the mark it earns is keyed by it.
  // Why: the gate reads the mark under the caller's own session; the two must name the same one.
  it('names a new dashboard session by the family it is stored under', async () => {
    await service.issueTokens(USER, '1.2.3.4', 'Browser', { credentialProved: true })

    const familyId = (redis.writeNewSession.mock.calls[0] as [{ familyId: string }])[0].familyId
    expect(lastClaims()['sid']).toBe(familyId)
    expect(familyId).toMatch(SESSION_ID)
    const extras = (redis.writeNewSession.mock.calls[0] as [{ extras: unknown[] }])[0].extras
    expect(extras).toEqual([
      {
        key: recentAuthKey('dashboard', 'user-1', HMAC_KEY, 'tenant-1', familyId),
        value: '1',
        ttl: 300
      }
    ])
  })

  it('names a new platform session by the family it is stored under', async () => {
    await service.issuePlatformTokens(ADMIN, '1.2.3.4', 'Browser')

    const familyId = (redis.writeNewSession.mock.calls[0] as [{ familyId: string }])[0].familyId
    expect(lastClaims()['sid']).toBe(familyId)
    expect(familyId).toMatch(SESSION_ID)
  })

  // Scenario: two sessions issued for the same account. Expected: different ids.
  // Why: a shared id would let one session use the other's mark.
  it('gives every session its own id', async () => {
    await service.issueTokens(USER, '1.2.3.4', 'Browser')
    const first = lastClaims()['sid']
    await service.issueTokens(USER, '1.2.3.4', 'Browser')

    expect(lastClaims()['sid']).not.toBe(first)
  })

  // Scenario: a rotation of a stored session whose record carries a family. Expected: the rotated
  // token carries that family as its `sid`, on both planes.
  // Why: a refresh is the same session, so it keeps the proof the session earned.
  it.each([
    ['dashboard', 'reissueTokens'],
    ['platform', 'reissuePlatformTokens']
  ] as const)('keeps the session id through a %s rotation', async (plane, method) => {
    const json = stored(FAMILY, plane)
    redis.get.mockResolvedValue(json)
    redis.rotateRefreshSession.mockResolvedValue({ kind: 'rotated', sessionJson: json })

    await service[method]('old-refresh', '1.2.3.4', 'Browser')

    expect(lastClaims()['sid']).toBe(FAMILY)
  })

  // Scenario: a stored record with no family id (written before families existed), or one whose id
  // is not in the contract's shape. Expected: the rotated token carries no `sid`.
  // Why: a token must never name a session this library cannot show it minted.
  it.each([
    ['dashboard', 'reissueTokens'],
    ['platform', 'reissuePlatformTokens']
  ] as const)('gives a %s record with no usable family no session id', async (plane, method) => {
    for (const family of [undefined, '', 'fam-old-1']) {
      const json = stored(family, plane)
      redis.get.mockResolvedValue(json)
      redis.rotateRefreshSession.mockResolvedValue({ kind: 'rotated', sessionJson: json })

      await service[method]('old-refresh', '1.2.3.4', 'Browser')

      expect(lastClaims()['sid']).toBeUndefined()
    }
  })

  // Scenario: the platform authority re-sign. Expected: the claim is carried across unchanged.
  it('carries the session id across a platform authority re-sign', async () => {
    await service.reissuePlatformAccessWithAuthority(
      { sid: FAMILY, sub: 'admin-1', mfaVerified: false } as never,
      'super-admin',
      false
    )

    expect(lastClaims()['sid']).toBe(FAMILY)
  })
})
