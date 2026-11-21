/**
 * @fileoverview The secret that was checked at start is the one every token is signed with: the signer service is
 * configured by a second call of the host's options factory, and what that call answered must never sign.
 *
 * @layer Test
 */

import { createHash } from 'node:crypto'

import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_HOOKS, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AuthRedisService } from '../redis/auth-redis.service'
import { TokenManagerService } from './token-manager.service'

const SECRET = 'test-jwt-secret-for-hmac-that-is-at-least-32-chars-long'

const mockJwtService = {
  sign: jest.fn().mockReturnValue('signed.jwt'),
  decode: jest.fn(),
  verify: jest.fn()
}
const mockRedis = {
  get: jest.fn(),
  set: jest.fn().mockResolvedValue(undefined),
  del: jest.fn(),
  getUserTokenEpoch: jest.fn().mockResolvedValue(0),
  writeNewSession: jest.fn().mockResolvedValue(undefined)
}
const mockOptions = {
  jwt: {
    accessExpiresIn: '15m',
    accessCookieMaxAgeMs: 900_000,
    refreshExpiresInDays: 7,
    refreshGraceWindowSeconds: 30,
    algorithm: 'HS256',
    secret: SECRET
  },
  hmacKey: createHash('sha256').update('bymax-auth:hmac-key:v1:x', 'utf8').digest('hex'),
  previousHmacKeys: [],
  sessions: { enabled: false }
}

const USER = {
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

const ADMIN = {
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

describe('the secret every token is signed with', () => {
  let service: TokenManagerService

  beforeEach(async () => {
    jest.clearAllMocks()
    mockJwtService.sign.mockReturnValue('signed.jwt')
    const module = await Test.createTestingModule({
      providers: [
        TokenManagerService,
        { provide: JwtService, useValue: mockJwtService },
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: BYMAX_AUTH_HOOKS, useValue: {} }
      ]
    }).compile()
    service = module.get(TokenManagerService)
  })

  // Scenario: the four tokens the library signs (the dashboard access token, the platform access token and the MFA
  // challenge token of each plane), by a signer whose own default secret is another one. Expected: each sign call names
  // the secret the options resolved to, and the algorithm. Why: a secret that the second call of the host's factory
  // answered (a weak one, after a strong one passed the check) must never be the one that signs.
  it('names the secret the options resolved to in every sign call', async () => {
    await service.issueTokens(USER, '1.2.3.4', 'Browser')
    await service.issuePlatformTokens(ADMIN, '1.2.3.4', 'Browser')
    await service.issueMfaTempToken('user-1', 'dashboard', 'tenant-1')
    await service.issueMfaTempToken('admin-1', 'platform')

    const options = mockJwtService.sign.mock.calls.map((call) => call[1])
    expect(options).toHaveLength(4)
    for (const signed of options)
      expect(signed).toEqual(expect.objectContaining({ secret: SECRET, algorithm: 'HS256' }))
  })
})
