/**
 * @fileoverview Pins every Redis record the wire contract declares against what the code
 * PRODUCES — in both directions.
 *
 * `conformance/wire-contract.json` -> `recordEncodings` lists, per record, the `fields` a
 * reader (this library or the sibling Rust one) relies on and, for `refreshSession`, the
 * `optionalFields` that may appear. A contract-only assertion proves the file says so; it says
 * nothing about the object a writer actually serializes. Here each record is built by the REAL
 * producing code (only Redis, repositories, hooks and the mail provider are doubles) and its key
 * set is compared with the contract's: a declared field missing from the record is a reader
 * that rejects it, and a field the contract never declared is a writer drifting off the
 * contract without anyone deciding it should. `wsTicket` is pinned in `conformance.spec.ts`.
 *
 * A failure means the producer drifted from the contract, or the contract moved without the
 * producer. Neither is fixed by editing the assertion.
 */

// The anti-enumeration floor in the reset flow would otherwise sleep for real.
jest.mock('./utils/sleep', () => ({ sleep: jest.fn().mockResolvedValue(undefined) }))

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'
import type { Request } from 'express'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from './bymax-auth.constants'
import { sha256 } from './crypto/secure-token'
import { AuthRedisService } from './redis/auth-redis.service'
import { BruteForceService } from './services/brute-force.service'
import { EmailChangeService } from './services/email-change.service'
import { InvitationService } from './services/invitation.service'
import { OtpService } from './services/otp.service'
import { PasswordResetService } from './services/password-reset.service'
import { PasswordService } from './services/password.service'
import { SessionService } from './services/session.service'
import { TokenManagerService } from './services/token-manager.service'

interface RecordEncoding {
  key?: string
  fields?: string[]
  optionalFields?: string[]
}

interface RecordsContract {
  redisKeyPrefixes: Record<string, string>
  recordEncodings: Record<string, RecordEncoding>
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as RecordsContract

/** The declared record, read from the contract; a record the contract dropped fails loudly. */
function declared(name: string): { fields: string[]; optionalFields: string[] } {
  const record = contract.recordEncodings[name]
  if (record?.fields === undefined) throw new Error(`contract declares no fields for ${name}`)
  return { fields: record.fields, optionalFields: record.optionalFields ?? [] }
}

/** The contract's Redis prefix for a keyspace, e.g. `inv` for `invitation`. */
function prefixOf(keyspace: string): string {
  const prefix = contract.redisKeyPrefixes[keyspace]
  if (prefix === undefined) throw new Error(`contract declares no prefix for ${keyspace}`)
  return prefix
}

/** The sorted key set of a serialized JSON record. */
function keysOf(json: unknown): string[] {
  if (typeof json !== 'string') throw new Error('the producer did not hand Redis a JSON string')
  return Object.keys(JSON.parse(json) as Record<string, unknown>).sort()
}

/** A sorted copy, so a set comparison reads the same whatever order the contract lists. */
function sorted(names: string[]): string[] {
  return [...names].sort()
}

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

const JWT_SECRET = 'test-jwt-secret-for-hmac-that-is-at-least-32-chars-long'
const HMAC_KEY = 'test-hmac-key'

const mockRedis = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  eval: jest.fn(),
  getdel: jest.fn(),
  setnx: jest.fn(),
  smembers: jest.fn(),
  srem: jest.fn(),
  pruneExpiredGraceMembers: jest.fn(),
  getUserTokenEpoch: jest.fn(),
  writeNewSession: jest.fn(),
  rotateRefreshSession: jest.fn(),
  writeRecoveredSession: jest.fn()
}

const mockOptions = {
  hmacKey: HMAC_KEY,
  previousHmacKeys: [] as string[],
  jwt: {
    secret: JWT_SECRET,
    accessExpiresIn: '15m',
    accessCookieMaxAgeMs: 900_000,
    refreshExpiresInDays: 7,
    refreshGraceWindowSeconds: 30,
    algorithm: 'HS256'
  },
  sessions: {
    enabled: true,
    defaultMaxSessions: 5,
    evictionStrategy: 'fifo',
    maxSessionsResolver: undefined
  },
  roles: { hierarchy: { admin: ['member'], member: [] as string[] } },
  invitations: { tokenTtlSeconds: 86_400 },
  emailChange: { tokenTtlSeconds: 3600 },
  passwordReset: {
    method: 'token' as const,
    tokenTtlSeconds: 3600,
    otpLength: 6,
    otpTtlSeconds: 300
  },
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED']
}

const ACCOUNT = {
  id: 'user-1',
  email: 'user@example.com',
  name: 'Test User',
  passwordHash: 'scrypt:salt:hash',
  role: 'admin',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: true,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}

const SAFE_ADMIN = {
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

const mockUserRepo = {
  findById: jest.fn(),
  findByEmail: jest.fn()
}

const mockEmailProvider = {
  sendInvitation: jest.fn(),
  sendEmailChangeVerification: jest.fn(),
  sendPasswordResetToken: jest.fn()
}

const mockPasswordService = { compare: jest.fn() }
const mockBruteForce = {
  isLockedOut: jest.fn(),
  recordFailure: jest.fn(),
  resetFailures: jest.fn()
}
const mockJwt = { sign: jest.fn(), verify: jest.fn(), decode: jest.fn() }

beforeEach(() => {
  jest.resetAllMocks()
  mockRedis.set.mockResolvedValue('OK')
  mockRedis.del.mockResolvedValue(undefined)
  mockRedis.eval.mockResolvedValue(1)
  mockRedis.setnx.mockResolvedValue(true)
  mockRedis.smembers.mockResolvedValue([])
  mockRedis.get.mockResolvedValue(null)
  mockRedis.pruneExpiredGraceMembers.mockResolvedValue(0)
  mockRedis.getUserTokenEpoch.mockResolvedValue(0)
  mockRedis.writeNewSession.mockResolvedValue(undefined)
  mockRedis.writeRecoveredSession.mockResolvedValue(true)
  mockJwt.sign.mockReturnValue('signed.jwt.token')
  mockUserRepo.findById.mockResolvedValue(ACCOUNT)
  mockUserRepo.findByEmail.mockResolvedValue(ACCOUNT)
  mockEmailProvider.sendInvitation.mockResolvedValue(undefined)
  mockEmailProvider.sendEmailChangeVerification.mockResolvedValue(undefined)
  mockEmailProvider.sendPasswordResetToken.mockResolvedValue(undefined)
  mockPasswordService.compare.mockResolvedValue(true)
  mockBruteForce.isLockedOut.mockResolvedValue(false)
})

/** Compiles a testing module over the shared doubles and returns one service from it. */
async function build<T>(service: new (...args: never[]) => T): Promise<T> {
  const module = await Test.createTestingModule({
    providers: [
      service,
      { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
      { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
      { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
      { provide: BYMAX_AUTH_HOOKS, useValue: null },
      { provide: AuthRedisService, useValue: mockRedis },
      { provide: JwtService, useValue: mockJwt },
      { provide: PasswordService, useValue: mockPasswordService },
      { provide: BruteForceService, useValue: mockBruteForce },
      { provide: OtpService, useValue: { verify: jest.fn().mockResolvedValue(undefined) } },
      // Collaborators are stubbed only when they are not the service under test, or the stub
      // would shadow the real producer.
      ...[SessionService, TokenManagerService]
        .filter((collaborator) => collaborator !== service)
        .map((collaborator) => ({ provide: collaborator, useValue: {} }))
    ]
  }).compile()
  return module.get(service)
}

/** The first call's argument at `index`, for a doubled Redis method. */
function firstCallArg(fn: jest.Mock, index: number): unknown {
  const call = fn.mock.calls[0] as unknown[] | undefined
  if (call === undefined) throw new Error('the producer never called Redis')
  return call[index]
}

// ---------------------------------------------------------------------------
// refreshSession
// ---------------------------------------------------------------------------

describe('wire contract: refreshSession record', () => {
  const { fields, optionalFields } = declared('refreshSession')

  describe.each([
    {
      plane: 'dashboard',
      keyspace: 'dashboardRefreshSession',
      mint: (svc: TokenManagerService, mfa: boolean) =>
        svc.issueTokens(ACCOUNT, '1.2.3.4', 'Chrome', mfa ? { mfaVerified: true } : undefined)
    },
    {
      plane: 'platform',
      keyspace: 'platformRefreshSession',
      mint: (svc: TokenManagerService, mfa: boolean) =>
        svc.issuePlatformTokens(
          SAFE_ADMIN,
          '1.2.3.4',
          'Chrome',
          mfa ? { mfaVerified: true } : undefined
        )
    }
  ])('$plane plane', ({ keyspace, mint, plane }) => {
    // Scenario: a session minted without the MFA challenge. Expected: the stored record's keys
    // are exactly the contract's required `fields` — none missing, none extra, and in
    // particular no `mfaVerified: false`. Why: a reader rejects a record missing a required
    // field, and the contract says `mfaVerified` is written ONLY as true.
    it('stores exactly the declared fields for a non-MFA session', async () => {
      const service = await build(TokenManagerService)

      await mint(service, false)

      const params = firstCallArg(mockRedis.writeNewSession, 0) as {
        kind: string
        sessionJson: string
      }
      expect(params.kind).toBe(plane)
      expect(prefixOf(keyspace)).toBe(plane === 'dashboard' ? 'rt' : 'prt')
      expect(keysOf(params.sessionJson)).toEqual(sorted(fields))
    })

    // Scenario: a session established through the MFA challenge. Expected: the keys are the
    // required fields plus every declared optional one, and nothing else. Why: the optional
    // field is what lets the MFA gate admit the session after the access token ages out.
    it('stores the declared fields plus the optional ones for an MFA-verified session', async () => {
      const service = await build(TokenManagerService)

      await mint(service, true)

      const params = firstCallArg(mockRedis.writeNewSession, 0) as { sessionJson: string }
      expect(keysOf(params.sessionJson)).toEqual(sorted([...fields, ...optionalFields]))
    })
  })
})

// A record is also rewritten on every rotation and every grace-window recovery, by code paths of
// their own. A key set that only holds at issue time lets those paths drift: the successor of a
// verified session must carry the same declared keys as the session it replaces.
describe('wire contract: refreshSession record across rotation', () => {
  const { fields, optionalFields } = declared('refreshSession')

  describe.each([
    {
      plane: 'dashboard',
      mint: (svc: TokenManagerService) =>
        svc.issueTokens(ACCOUNT, '1.2.3.4', 'Chrome', { mfaVerified: true }),
      rotate: (svc: TokenManagerService) => svc.reissueTokens('old-refresh', '1.2.3.4', 'Chrome')
    },
    {
      plane: 'platform',
      mint: (svc: TokenManagerService) =>
        svc.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Chrome', { mfaVerified: true }),
      rotate: (svc: TokenManagerService) =>
        svc.reissuePlatformTokens('old-refresh', '1.2.3.4', 'Chrome')
    }
  ])('$plane plane', ({ mint, rotate }) => {
    /** Mints a verified session with the real producer and returns the record it stored. */
    async function storedVerifiedSession(service: TokenManagerService): Promise<string> {
      await mint(service)
      const params = firstCallArg(mockRedis.writeNewSession, 0) as { sessionJson: string }
      return params.sessionJson
    }

    // Scenario: a verified session rotated while its record is live. Expected: the successor
    // record's keys are the required fields plus the optional ones, nothing else. Why: the
    // rotation builds the record again from the stored one, and a field it forgets is a session
    // that is no longer verified, or a key the sibling backend has never heard of.
    it('writes the declared keys on a primary rotation', async () => {
      const service = await build(TokenManagerService)
      const stored = await storedVerifiedSession(service)
      mockRedis.get.mockResolvedValue(stored)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'rotated', sessionJson: stored })

      await rotate(service)

      const params = firstCallArg(mockRedis.rotateRefreshSession, 0) as { newSessionJson: string }
      expect(keysOf(params.newSessionJson)).toEqual(sorted([...fields, ...optionalFields]))
    })

    // Scenario: the presented token was already consumed and is recovered inside its grace
    // window. Expected: the recovered record has the same declared keys. Why: the recovery path
    // assembles a session of its own, apart from the primary rotation's.
    it('writes the declared keys on a grace-window recovery', async () => {
      const service = await build(TokenManagerService)
      const stored = await storedVerifiedSession(service)
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'grace', sessionJson: stored })

      await rotate(service)

      const params = firstCallArg(mockRedis.writeRecoveredSession, 0) as {
        newSessionJson: string
      }
      expect(keysOf(params.newSessionJson)).toEqual(sorted([...fields, ...optionalFields]))
    })
  })
})

// ---------------------------------------------------------------------------
// sessionDetail
// ---------------------------------------------------------------------------

describe('wire contract: sessionDetail record', () => {
  const { fields, optionalFields } = declared('sessionDetail')
  const HASH = sha256('raw-refresh-token')
  const NEW_HASH = sha256('rotated-refresh-token')

  // Scenario: SessionService.createSession records a new session. Expected: the `sd:` key
  // carries the contract's prefix and the value's keys equal the declared set. Why: the
  // session list evicts a member whose detail fails to parse.
  it('createSession stores exactly the declared fields under the declared prefix', async () => {
    const service = await build(SessionService)

    await service.createSession({
      userId: 'user-1',
      tenantId: 'tenant-1',
      rawRefreshToken: 'raw-refresh-token',
      ip: '1.2.3.4',
      userAgent: 'Mozilla/5.0 Chrome/123.0'
    })

    const key = firstCallArg(mockRedis.set, 0) as string
    expect(key).toBe(`${prefixOf('dashboardSessionDetail')}:${HASH}`)
    expect(keysOf(firstCallArg(mockRedis.set, 1))).toEqual(sorted([...fields, ...optionalFields]))
  })

  // Scenario: a rotation re-keys the detail record. Expected: the record written for the new
  // hash has the same declared key set as a freshly created one. Why: rotation is the second
  // writer of the record, and a field dropped there would only show on a rotated session.
  it('rotateSession stores exactly the declared fields under the declared prefix', async () => {
    const service = await build(SessionService)

    await service.rotateSession(HASH, NEW_HASH, '1.2.3.4', 'Mozilla/5.0 Chrome/123.0')

    const keys = firstCallArg(mockRedis.eval, 1) as string[]
    expect(keys).toEqual([
      `${prefixOf('dashboardSessionDetail')}:${HASH}`,
      `${prefixOf('dashboardSessionDetail')}:${NEW_HASH}`
    ])
    const args = firstCallArg(mockRedis.eval, 2) as string[]
    expect(keysOf(args[0])).toEqual(sorted([...fields, ...optionalFields]))
  })
})

// The platform plane writes its own `psd:` detail from the token manager, on issue and on both
// rotation paths, apart from the dashboard writers above. A field added to or dropped from that
// object would only ever show on a platform session.
describe('wire contract: sessionDetail record, platform writer', () => {
  const { fields, optionalFields } = declared('sessionDetail')
  const PREFIX = prefixOf('platformSessionDetail')

  /** The `psd:` write among everything the producer handed Redis, as `[key, value]`. */
  function detailWrite(): [string, unknown] {
    const call = mockRedis.set.mock.calls.find(
      (args: unknown[]) => typeof args[0] === 'string' && args[0].startsWith(`${PREFIX}:`)
    )
    if (call === undefined) throw new Error('the producer never wrote a platform session detail')
    return [call[0] as string, call[1]]
  }

  // Scenario: a platform session is issued. Expected: a record under the contract's `psd` prefix
  // whose keys equal the declared set. Why: the session listing describes a platform session from
  // this record alone.
  it('issuePlatformTokens stores exactly the declared fields under the declared prefix', async () => {
    const service = await build(TokenManagerService)

    await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Chrome')

    const [key, value] = detailWrite()
    expect(key).toMatch(new RegExp(`^${PREFIX}:[0-9a-f]{64}$`))
    expect(keysOf(value)).toEqual(sorted([...fields, ...optionalFields]))
  })

  // Scenario: a platform refresh token is rotated. Expected: the record written for the new hash
  // has the same declared key set. Why: rotation is a second writer, and a drift there shows only
  // on a rotated session.
  it('reissuePlatformTokens stores exactly the declared fields under the declared prefix', async () => {
    const service = await build(TokenManagerService)
    await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Chrome')
    const stored = (firstCallArg(mockRedis.writeNewSession, 0) as { sessionJson: string })
      .sessionJson
    mockRedis.set.mockClear()
    mockRedis.get.mockResolvedValue(stored)
    mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'rotated', sessionJson: stored })

    await service.reissuePlatformTokens('old-refresh', '1.2.3.4', 'Chrome')

    const [key, value] = detailWrite()
    expect(key).toMatch(new RegExp(`^${PREFIX}:[0-9a-f]{64}$`))
    expect(keysOf(value)).toEqual(sorted([...fields, ...optionalFields]))
  })
})

// ---------------------------------------------------------------------------
// invitation
// ---------------------------------------------------------------------------

describe('wire contract: invitation record', () => {
  const { fields, optionalFields } = declared('invitation')

  // Scenario: an admin invites a member. Expected: the `inv:` key uses the contract's prefix
  // and the stored record's keys equal the declared set. Why: consumption is a single-use
  // GETDEL, so a record the reader rejects is destroyed rather than retried.
  it('invite stores exactly the declared fields under the declared prefix', async () => {
    const service = await build(InvitationService)

    await service.invite('user-1', 'invited@example.com', 'member', 'tenant-1')

    const key = firstCallArg(mockRedis.set, 0) as string
    expect(key).toMatch(new RegExp(`^${prefixOf('invitation')}:[0-9a-f]{64}$`))
    expect(keysOf(firstCallArg(mockRedis.set, 1))).toEqual(sorted([...fields, ...optionalFields]))
  })
})

// ---------------------------------------------------------------------------
// emailChangeContext
// ---------------------------------------------------------------------------

describe('wire contract: emailChangeContext record', () => {
  const { fields, optionalFields } = declared('emailChangeContext')

  // Scenario: an authenticated user requests an address change. Expected: the `ec:` key uses
  // the contract's prefix and the stored context's keys equal the declared set. Why: the
  // confirm step reads it with GETDEL, so a record it cannot read burns the token.
  it('requestChange stores exactly the declared fields under the declared prefix', async () => {
    const service = await build(EmailChangeService)
    // The new address must be free, or the request is refused before anything is stored.
    mockUserRepo.findByEmail.mockResolvedValue(null)

    await service.requestChange('user-1', 'tenant-1', {
      newEmail: 'new@example.com',
      currentPassword: 'right'
    })

    const key = firstCallArg(mockRedis.set, 0) as string
    expect(key).toMatch(new RegExp(`^${prefixOf('emailChangeToken')}:[0-9a-f]{64}$`))
    expect(keysOf(firstCallArg(mockRedis.set, 1))).toEqual(sorted([...fields, ...optionalFields]))
  })
})

// ---------------------------------------------------------------------------
// passwordResetContext
// ---------------------------------------------------------------------------

describe('wire contract: passwordResetContext record', () => {
  const { fields, optionalFields } = declared('passwordResetContext')
  const req = { ip: '1.2.3.4', headers: {} } as unknown as Request

  // Scenario: a reset is initiated by the token method. Expected: the `pw_reset:` key uses
  // the contract's prefix and the stored context's keys equal the declared set. Why: the
  // sibling implementation completes the reset from this record.
  it('initiateReset (token writer) stores exactly the declared fields', async () => {
    const service = await build(PasswordResetService)

    await service.initiateReset({ email: 'user@example.com', tenantId: 'tenant-1' }, req)

    const key = firstCallArg(mockRedis.set, 0) as string
    expect(key).toMatch(new RegExp(`^${prefixOf('passwordResetToken')}:[0-9a-f]{64}$`))
    expect(keysOf(firstCallArg(mockRedis.set, 1))).toEqual(sorted([...fields, ...optionalFields]))
  })

  // Scenario: the OTP is verified and a `pw_vtok:` verified-token is minted. Expected: it
  // stores the same context shape, keyed under its own contract prefix. Why: it is the second
  // writer of the reset context and resets complete from it, so it may not drift from the first.
  it('verifyOtp (verified-token writer) stores exactly the declared fields', async () => {
    const service = await build(PasswordResetService)

    await service.verifyOtp({ email: 'user@example.com', tenantId: 'tenant-1', otp: '123456' }, req)

    const key = firstCallArg(mockRedis.set, 0) as string
    expect(key).toMatch(new RegExp(`^${prefixOf('passwordResetVerifiedToken')}:[0-9a-f]{64}$`))
    expect(keysOf(firstCallArg(mockRedis.set, 1))).toEqual(sorted([...fields, ...optionalFields]))
  })
})
