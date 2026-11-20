/**
 * @fileoverview A refused refresh says which kind of refusal it was, to the metrics only: a replayed token
 * is marked as reuse and a session past its absolute cap as expired, on both planes, while the answer the
 * caller receives is the same `REFRESH_TOKEN_INVALID` as for any other refused token.
 *
 * @layer Test
 */

import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { TokenManagerService } from './token-manager.service'
import { BYMAX_AUTH_HOOKS, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { markedPlane, observedRefusal } from '../observability/observed-outcome'
import { AuthRedisService } from '../redis/auth-redis.service'

const FAMILY = '4d6e1c2a-8b3f-4a5e-9c7d-0e1f2a3b4c5d'

const redis = {
  get: jest.fn(),
  getUserTokenEpoch: jest.fn(),
  rotateRefreshSession: jest.fn(),
  revokeFamily: jest.fn()
}
const verify = jest.fn()
const options = {
  jwt: {
    accessExpiresIn: '15m',
    refreshExpiresInDays: 7,
    refreshGraceWindowSeconds: 30,
    absoluteSessionLifetimeDays: 30
  },
  hmacKey: 'h'.repeat(48),
  previousHmacKeys: [],
  sessions: { enabled: false }
}

/** The error a refresh call rejects with. */
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

describe('observed refusals of a refresh', () => {
  let service: TokenManagerService

  beforeEach(async () => {
    jest.resetAllMocks()
    // `get` answers `null` for an absent record, as the real contract does; `undefined` would skip the guard.
    redis.get.mockResolvedValue(null)
    redis.revokeFamily.mockResolvedValue({ removed: 1, ownerId: '' })
    const module = await Test.createTestingModule({
      providers: [
        TokenManagerService,
        {
          provide: JwtService,
          useValue: { sign: jest.fn(), decode: jest.fn(), verify }
        },
        { provide: BYMAX_AUTH_OPTIONS, useValue: options },
        { provide: AuthRedisService, useValue: redis },
        { provide: BYMAX_AUTH_HOOKS, useValue: {} }
      ]
    }).compile()
    service = module.get(TokenManagerService)
  })

  // Scenario: a token that was already consumed is presented, on each plane. Expected: the refusal is marked
  // as reuse, and its code is the one every refused token answers with.
  it.each([
    ['dashboard', (s: TokenManagerService) => s.reissueTokens('replayed', '1.2.3.4', 'Browser')],
    [
      'platform',
      (s: TokenManagerService) => s.reissuePlatformTokens('replayed', '1.2.3.4', 'Browser')
    ]
  ])(
    'marks a replayed %s token as reuse and answers REFRESH_TOKEN_INVALID',
    async (_plane, call) => {
      redis.rotateRefreshSession.mockResolvedValue({ kind: 'reused', familyId: FAMILY })

      const error = await refusalOf(call(service))

      expect(observedRefusal(error)).toBe('reuse_detected')
      expect(codeOf(error)).toBe(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
    }
  )

  // Scenario: a token the store does not know. Expected: refused as invalid, not marked.
  it.each([
    ['dashboard', (s: TokenManagerService) => s.reissueTokens('unknown', '1.2.3.4', 'Browser')],
    [
      'platform',
      (s: TokenManagerService) => s.reissuePlatformTokens('unknown', '1.2.3.4', 'Browser')
    ]
  ])('does not mark an unknown %s token', async (_plane, call) => {
    redis.rotateRefreshSession.mockResolvedValue({ kind: 'invalid' })

    const error = await refusalOf(call(service))

    expect(observedRefusal(error)).toBeUndefined()
    expect(codeOf(error)).toBe(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
  })

  // Scenario: a session whose login is older than the absolute cap, on each plane. Expected: marked as
  // expired, with the same answer as any other refused token.
  it.each([
    ['dashboard', (s: TokenManagerService) => s.reissueTokens('old', '1.2.3.4', 'Browser')],
    ['platform', (s: TokenManagerService) => s.reissuePlatformTokens('old', '1.2.3.4', 'Browser')]
  ])('marks a %s session past the absolute cap as expired', async (_plane, call) => {
    redis.get.mockResolvedValue(
      JSON.stringify({
        userId: 'user-1',
        tenantId: 'tenant-1',
        role: 'member',
        device: 'Browser',
        ip: '1.2.3.4',
        mfaEnabled: false,
        createdAt: new Date().toISOString(),
        familyId: FAMILY,
        familyCreatedAt: new Date(Date.now() - 31 * 86_400_000).toISOString()
      })
    )

    const error = await refusalOf(call(service))

    expect(observedRefusal(error)).toBe('expired')
    expect(codeOf(error)).toBe(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
  })
})

describe('the plane of a refused MFA temp token', () => {
  let service: TokenManagerService

  /** The claims of a temp token of the plane that passed its signature. */
  const claims = {
    dashboard: { sub: 'user-1', jti: 'jti-d', context: 'dashboard', tenantId: 'tenant-1' },
    platform: { sub: 'admin-1', jti: 'jti-p', context: 'platform' }
  } as const

  beforeEach(async () => {
    jest.resetAllMocks()
    const module = await Test.createTestingModule({
      providers: [
        TokenManagerService,
        {
          provide: JwtService,
          useValue: { sign: jest.fn(), decode: jest.fn(), verify }
        },
        { provide: BYMAX_AUTH_OPTIONS, useValue: options },
        { provide: AuthRedisService, useValue: redis },
        { provide: BYMAX_AUTH_HOOKS, useValue: {} }
      ]
    }).compile()
    service = module.get(TokenManagerService)
  })

  /** The ways a verified temp token is refused, each arranging the doubles for one. */
  const REFUSALS: ReadonlyArray<[string, (plane: 'dashboard' | 'platform') => void]> = [
    [
      'a tenant binding that does not fit the plane',
      (plane) =>
        verify.mockReturnValue(
          plane === 'dashboard'
            ? { ...claims.dashboard, tenantId: '' }
            : { ...claims.platform, tenantId: 'x' }
        )
    ],
    ['a record that is gone', () => redis.get.mockResolvedValue(null)],
    ['a record of another account', () => redis.get.mockResolvedValue('someone-else')],
    ['an epoch that was bumped', () => redis.getUserTokenEpoch.mockResolvedValue(5)]
  ]

  // Scenario: a temp token that passed its signature and is then refused, on each plane, for each reason.
  // Expected: MFA_TEMP_TOKEN_INVALID, marked with the plane the token names, whatever the reason.
  describe.each(['dashboard', 'platform'] as const)('a verified %s temp token', (plane) => {
    it.each(REFUSALS)('is marked with its plane when it has %s', async (_reason, arrange) => {
      verify.mockReturnValue(claims[plane])
      redis.get.mockResolvedValue(claims[plane].sub)
      redis.getUserTokenEpoch.mockResolvedValue(0)
      arrange(plane)

      const error = await refusalOf(service.verifyMfaTempToken('temp.jwt'))

      expect(codeOf(error)).toBe(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
      expect(markedPlane(error)).toBe(plane)
    })

    // Scenario: the store fails while the entry is read. Expected: the failure is the store's own, unchanged, and
    // carries the plane: whatever ends the check after the signature held is marked.
    it('marks a failure of the store with its plane', async () => {
      verify.mockReturnValue(claims[plane])
      const failure = new Error('READONLY')
      redis.get.mockRejectedValue(failure)

      await expect(service.verifyMfaTempToken('temp.jwt')).rejects.toBe(failure)

      expect(markedPlane(failure)).toBe(plane)
    })
  })

  // Scenario: a token whose signature does not verify. Expected: refused, and no plane is marked, because the
  // claims were not trusted.
  it('leaves a token that does not verify unmarked', async () => {
    verify.mockImplementation(() => {
      throw new Error('invalid signature')
    })

    const error = await refusalOf(service.verifyMfaTempToken('bad.jwt'))

    expect(codeOf(error)).toBe(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
    expect(markedPlane(error)).toBeUndefined()
  })
})
