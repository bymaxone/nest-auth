import { createHash, createHmac } from 'node:crypto'

import { Logger } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_HOOKS, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES, AUTH_ERROR_MESSAGES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { TokenManagerService } from './token-manager.service'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const FIXED_JWT = 'signed.jwt.token'
const FIXED_UUID = '00000000-0000-0000-0000-000000000001'

/** Local sha256 helper mirroring the production crypto util — node:crypto.createHash is the real impl. */
function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex')
}

/**
 * The refresh token every mint produces under the mocked `randomBytes`: 32 bytes of 0x11
 * rendered as 64 hex characters. Pinning the length here is what keeps the 256-bit format
 * from silently regressing to a shorter token.
 */
const FIXED_REFRESH_TOKEN = '11'.repeat(32)

/** SHA-256 of the minted refresh token — the hash keying every new refresh session. */
const NEW_HASH = sha256(FIXED_REFRESH_TOKEN)

const mockJwtService = {
  sign: jest.fn().mockReturnValue(FIXED_JWT),
  decode: jest.fn(),
  verify: jest.fn()
}

const mockHooks = {
  onRefreshTokenReuseDetected: jest.fn()
}

const mockRedis = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  eval: jest.fn(),
  getdel: jest.fn(),
  sadd: jest.fn().mockResolvedValue(1),
  srem: jest.fn().mockResolvedValue(1),
  expire: jest.fn().mockResolvedValue(undefined),
  rotateRefreshSession: jest.fn(),
  getUserTokenEpoch: jest.fn().mockResolvedValue(0),
  bumpUserTokenEpoch: jest.fn().mockResolvedValue(1),
  revokeFamily: jest.fn().mockResolvedValue({ removed: 1, ownerId: 'user-1' }),
  invalidateUserSessions: jest.fn().mockResolvedValue(undefined),
  revokeAllUserTokens: jest.fn().mockResolvedValue(undefined),
  readSessionOwner: jest.fn().mockResolvedValue('user-1'),
  // The grace arm writes its recovered session through one atomic script; the default is the
  // ordinary "the account still has an index, the write landed".
  writeRecoveredSession: jest.fn().mockResolvedValue(true),
  writeNewSession: jest.fn().mockResolvedValue(undefined)
}

const JWT_SECRET = 'test-jwt-secret-for-hmac-that-is-at-least-32-chars-long'

/**
 * HMAC key — mirrors the derivation in `resolveOptions.deriveHmacKey`.
 * Required because `TokenManagerService` reads `options.hmacKey` (not
 * `options.jwt.secret`) for Redis identifier HMACs.
 */
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const mockOptions = {
  jwt: {
    accessExpiresIn: '15m',
    accessCookieMaxAgeMs: 900_000,
    refreshExpiresInDays: 7,
    refreshGraceWindowSeconds: 30,
    algorithm: 'HS256',
    secret: JWT_SECRET
  },
  hmacKey: HMAC_KEY,
  previousHmacKeys: []
}

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

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

// Use inline values to avoid TDZ — jest.mock factories run before const declarations.
// `randomUUID` still backs the access token's jti; `randomBytes` backs the refresh token,
// which is now 32 CSPRNG bytes rendered as 64 hex characters rather than a UUID.
jest.mock('node:crypto', () => ({
  ...jest.requireActual('node:crypto'),
  randomUUID: jest.fn().mockReturnValue('00000000-0000-0000-0000-000000000001'),
  randomBytes: jest.fn((size: number) => Buffer.alloc(size, 0x11))
}))

describe('TokenManagerService', () => {
  let service: TokenManagerService

  beforeEach(async () => {
    jest.clearAllMocks()
    mockJwtService.sign.mockReturnValue(FIXED_JWT)
    // Defaults matching the real contracts, not jest's `undefined`: `get` returns
    // `Promise<string | null>`, so an `undefined` would slip past the `=== null` guard that
    // decides whether a live session was found. Rotation tests override both.
    mockRedis.get.mockResolvedValue(null)
    mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'invalid' })
    mockRedis.getUserTokenEpoch.mockResolvedValue(0)
    mockRedis.getdel.mockReset()
    mockRedis.getdel.mockResolvedValue(null)

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

  // ---------------------------------------------------------------------------
  // issueAccess
  // ---------------------------------------------------------------------------

  describe('issueAccess', () => {
    // Verifies that issueAccess calls JwtService.sign with a generated jti and returns the signed token.
    it('should sign a JWT with a generated jti', () => {
      const token = service.issueAccess({
        sub: 'user-1',
        tenantId: 'tenant-1',
        role: 'member',
        type: 'dashboard',
        status: 'active',
        mfaEnabled: false,
        mfaVerified: false
      })

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ sub: 'user-1', jti: FIXED_UUID }),
        expect.objectContaining({ expiresIn: '15m', algorithm: 'HS256' })
      )
      expect(token).toBe(FIXED_JWT)
    })
  })

  // ---------------------------------------------------------------------------
  // issueTokens
  // ---------------------------------------------------------------------------

  describe('issueTokens', () => {
    // The recent-authentication marker, and the asymmetry that gives it meaning.
    //
    // `issueTokens` is the single point where a dashboard session is BORN — password login,
    // OAuth callback, MFA challenge completion, invitation acceptance, email verification all
    // reach it. `reissueTokens` does not, and must not: a refresh proves possession of a token,
    // not of a credential. That is what makes the marker proof of anything at all, and it is
    // what stops a stolen session from being rotated into a fresh one (see the paired case in
    // `reissueTokens`).
    it('plants the recent-authentication marker, keyed and short-lived', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issueTokens(SAFE_USER, '1.2.3.4', 'TestBrowser')

      const markerWrite = mockRedis.set.mock.calls.find((call) => String(call[0]).startsWith('ra:'))
      expect(markerWrite).toBeDefined()
      // Presence is the whole meaning; the value carries nothing.
      expect(markerWrite?.[1]).toBe('1')
      expect(markerWrite?.[2]).toBe(300)
      // The keyspace is shared and readable — the account id is never in it in the clear.
      expect(String(markerWrite?.[0])).not.toContain(SAFE_USER.id)
    })

    // Verifies that issueTokens stores the refresh session in Redis with the correct TTL in seconds.
    it('should store refresh session in Redis with correct TTL', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      const result = await service.issueTokens(SAFE_USER, '1.2.3.4', 'TestBrowser')

      expect(mockRedis.writeNewSession).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: 'dashboard',
          tokenHash: expect.any(String) as string,
          refreshTtl: 7 * 86_400
        })
      )
      expect(result.accessToken).toBe(FIXED_JWT)
      expect(result.rawRefreshToken).toBe(FIXED_REFRESH_TOKEN)
      expect(result.user).toEqual(SAFE_USER)
    })

    // Scenario: the minted refresh token's shape. Expected: 64 lowercase hex characters, i.e.
    // 32 CSPRNG bytes. Why: this token is a bearer credential that survives for days, and the
    // UUID v4 it replaced carried ~122 bits — six of its 128 bits are fixed version/variant
    // markers. Pinning the length here stops a future change quietly shortening it, and it is
    // the format the sibling Rust backend validates before it will even hash a presented token.
    it('mints a 256-bit refresh token rendered as 64 hex characters', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      const result = await service.issueTokens(SAFE_USER, '1.2.3.4', 'Chrome')

      expect(result.rawRefreshToken).toMatch(/^[0-9a-f]{64}$/)
    })

    // Verifies that the stored session JSON contains the expected fields (userId, tenantId, role, ip, device).
    it('should store a JSON session with correct fields', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issueTokens(SAFE_USER, '127.0.0.1', 'Chrome')

      const written = mockRedis.writeNewSession.mock.calls[0]?.[0] as { sessionJson: string }
      const session = JSON.parse(written.sessionJson) as Record<string, unknown>
      expect(session['userId']).toBe('user-1')
      expect(session['tenantId']).toBe('tenant-1')
      expect(session['role']).toBe('member')
      expect(session['ip']).toBe('127.0.0.1')
      expect(session['device']).toBe('Chrome')
    })

    // Scenario: issueTokens registers the new refresh token in the per-user index under the
    // refresh TTL. Expected: ONE atomic write carrying the plane, the hash, the owner and the
    // TTL. Why: the loose form issued five commands, and both gaps between them were real —
    // a revoke-all landing between the record write and the index SADD swept an index the new
    // session was not in yet, and a dropped connection between the SADD and the EXPIRE left
    // the index with no expiry, permanently. rust-auth has always done this in one MULTI/EXEC.
    //
    // Asserted as one call rather than as five, so the atomicity is the thing under test: the
    // previous assertions passed for a sequence that had these windows in it, which is how the
    // divergence lasted.
    it('writes the session, its index member and its family in one atomic step', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issueTokens(SAFE_USER, '1.2.3.4', 'Chrome')

      expect(mockRedis.writeNewSession).toHaveBeenCalledTimes(1)
      expect(mockRedis.writeNewSession).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: 'dashboard',
          tokenHash: NEW_HASH,
          userId: 'user-1',
          refreshTtl: 7 * 86_400
        })
      )
      // The record, the index member and the family TTL must not ALSO be written loose —
      // a leftover command outside the script reopens the window the script closed.
      expect(mockRedis.sadd).not.toHaveBeenCalled()
      expect(mockRedis.expire).not.toHaveBeenCalled()
    })

    // Scenario: a login opens a refresh-token family and indexes the session in it.
    // Expected: the record carries the family, and the index holds the BARE hash under the
    // family TTL. Why: the family is the unit reuse detection revokes — a login that opened no
    // family could have its stolen token replayed forever without any lineage to kill. The index
    // member is bare because a family only ever tracks live `rt:` sessions.
    it('opens a refresh-token family and indexes the session under it', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issueTokens(SAFE_USER, '1.2.3.4', 'Chrome')

      const written = mockRedis.writeNewSession.mock.calls[0]?.[0] as {
        sessionJson: string
        familyId: string
      }
      const session = JSON.parse(written.sessionJson) as Record<string, unknown>
      expect(session['familyId']).toBe(FIXED_UUID)
      expect(written.familyId).toBe(FIXED_UUID)
    })

    // Scenario: a normal login (no MFA-complete override) must NOT mark the access token mfaVerified.
    // Expected: sign payload has mfaVerified:false. Why: kills the BooleanLiteral mutant on line 172
    // (`overrides?.mfaVerified ?? false` → `?? true`), a security regression that would skip the
    // MFA challenge after a plain password login.
    it('issues a dashboard access token with mfaVerified:false when no override is given', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issueTokens(SAFE_USER, '1.2.3.4', 'Chrome')

      const signCall = mockJwtService.sign.mock.calls[0] as [Record<string, unknown>]
      expect(signCall[0]).toMatchObject({ mfaVerified: false })
    })
  })

  // ---------------------------------------------------------------------------
  // issuePlatformTokens
  // ---------------------------------------------------------------------------

  describe('issuePlatformTokens', () => {
    // Verifies that the access token payload uses type 'platform' for platform admin sessions.
    it('should use type:platform in the access token payload', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      const result = await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'platform', sub: 'admin-1' }),
        expect.any(Object)
      )
      expect(result.rawRefreshToken).toBe(FIXED_REFRESH_TOKEN)
      expect(result.admin).toEqual(SAFE_ADMIN)
    })

    // Verifies that platform refresh sessions are stored under the 'prt:' prefix to separate them from user sessions.
    it('should store the session under prt: prefix', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      expect(mockRedis.writeNewSession).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: 'platform',
          tokenHash: NEW_HASH,
          refreshTtl: 7 * 86_400
        })
      )
    })

    // Scenario: platform issuance registers the prt: member in sess:{adminId} and sets the TTL.
    // Expected: sadd('sess:admin-1', 'prt:<newHash>') and expire('sess:admin-1', 7*86400). Why:
    // kills the StringLiteral mutants on lines 234 (key → '', member → '') and 235 (expire key → '').
    it('adds the prt: member to psess:{adminId} and expires the SET with the refresh TTL', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      expect(mockRedis.writeNewSession).toHaveBeenCalledTimes(1)
      expect(mockRedis.writeNewSession).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: 'platform',
          tokenHash: NEW_HASH,
          userId: 'admin-1',
          refreshTtl: 7 * 86_400
        })
      )
      expect(mockRedis.sadd).not.toHaveBeenCalled()
      expect(mockRedis.expire).not.toHaveBeenCalled()
    })

    // Scenario: a platform login opens its own family, indexed under `pfam:` — the platform
    // analogue of the dashboard `fam:` index, and separate from it for the same reason the
    // session indexes are separate.
    it('opens a platform refresh-token family and indexes the session under it', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      const written = mockRedis.writeNewSession.mock.calls[0]?.[0] as { sessionJson: string }
      const session = JSON.parse(written.sessionJson) as Record<string, unknown>
      expect(session['familyId']).toBe(FIXED_UUID)
      expect(mockRedis.writeNewSession).toHaveBeenCalledWith(
        expect.objectContaining({ kind: 'platform', familyId: FIXED_UUID })
      )
    })

    // Scenario: the platform plane must not write into the dashboard session index. Expected: no
    // sadd targets sess:{adminId}. Why: a platform admin id and a dashboard user id come from
    // different repositories and may collide, so sharing the index let a dashboard revoke-all
    // log the same-id admin out. This pins the separation that fixes it.
    it('never indexes a platform session in the dashboard sess: SET', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      const indexedKeys = mockRedis.sadd.mock.calls.map((call) => call[0] as string)
      expect(indexedKeys).not.toContain('sess:admin-1')
    })

    // Scenario: a platform session needs a detail record so a listing can describe it.
    // Expected: psd:{hash} holds the same field set the dashboard sd: record uses, with
    // Unix-millisecond timestamps. Why: the sibling Rust backend reads psd: when listing
    // platform sessions; without this write it would find nothing for a nest-created session.
    it('writes the psd: detail record with epoch-millisecond timestamps', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      const detailCall = mockRedis.set.mock.calls.find(
        (call) => (call[0] as string) === `psd:${NEW_HASH}`
      )
      expect(detailCall).toBeDefined()
      const detail = JSON.parse(detailCall![1] as string) as Record<string, unknown>
      expect(detail).toMatchObject({ device: 'Firefox', ip: '1.2.3.4' })
      expect(typeof detail['createdAt']).toBe('number')
      expect(typeof detail['lastActivityAt']).toBe('number')
    })

    // Scenario: an oversized User-Agent and IP, both attacker-controlled request headers.
    // Expected: each is truncated to the stored ceiling. Why: without the bound, a caller
    // could push arbitrarily large values into a Redis value on every login — the record is
    // written per session and never validated downstream, so the cap is the only limit.
    it('truncates the device and IP before they reach the psd: record', async () => {
      mockRedis.set.mockResolvedValue(undefined)
      const hugeAgent = 'A'.repeat(500)
      const hugeIp = '1'.repeat(500)

      await service.issuePlatformTokens(SAFE_ADMIN, hugeIp, hugeAgent)

      const detailCall = mockRedis.set.mock.calls.find(
        (call) => (call[0] as string) === `psd:${NEW_HASH}`
      )
      const detail = JSON.parse(detailCall![1] as string) as { device: string; ip: string }
      expect(detail.device.length).toBe(45)
      expect(detail.ip.length).toBe(45)
    })

    // Scenario: a platform admin has no tenant — the stored session tenantId must be an empty string.
    // Expected: stored session JSON has tenantId === ''. Why: kills the StringLiteral mutant on line
    // 229 that passes "Stryker was here!" as the tenantId to buildSession.
    it('stores an empty tenantId in the platform session record', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      const written = mockRedis.writeNewSession.mock.calls[0]?.[0] as { sessionJson: string }
      const session = JSON.parse(written.sessionJson) as Record<string, unknown>
      expect(session['tenantId']).toBe('')
    })

    // Scenario: a plain platform login (no override) must NOT mark the access token mfaVerified.
    // Expected: sign payload has mfaVerified:false. Why: kills the BooleanLiteral mutant on line 223
    // (`overrides?.mfaVerified ?? false` → `?? true`).
    it('issues a platform access token with mfaVerified:false when no override is given', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      const signCall = mockJwtService.sign.mock.calls[0] as [Record<string, unknown>]
      expect(signCall[0]).toMatchObject({ mfaVerified: false })
    })
  })

  // ---------------------------------------------------------------------------
  // reissueTokens
  // ---------------------------------------------------------------------------

  describe('reissueTokens', () => {
    const FAMILY = 'fam-old-1'
    const OLD_SESSION = JSON.stringify({
      userId: 'user-1',
      tenantId: 'tenant-1',
      role: 'member',
      device: 'Browser',
      ip: '1.2.3.4',
      mfaEnabled: false,
      createdAt: '2026-01-01T00:00:00.000Z',
      familyId: FAMILY
    })

    /** Arms the seed read + the rotation script for a live (primary) rotation. */
    function armLiveRotation(sessionJson = OLD_SESSION): void {
      mockRedis.get.mockResolvedValue(sessionJson)
      mockRedis.rotateRefreshSession.mockResolvedValue({
        kind: 'rotated',
        sessionJson
      })
      mockRedis.set.mockResolvedValue(undefined)
    }

    /** Arms a rotation whose presented token was already consumed but is inside its grace window. */
    function armGraceRotation(sessionJson = OLD_SESSION): void {
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'grace', sessionJson })
      mockRedis.set.mockResolvedValue(undefined)
    }

    // THE property that makes the recent-authentication marker worth anything: a rotation must
    // not refresh it. A refresh proves possession of a token, not of a credential — so if
    // rotating re-planted the mark, an attacker holding a stolen session could keep it fresh
    // indefinitely and the freshness gate on MFA enrolment would gate nothing at all. Both
    // rotation paths are covered, because the grace path writes a session record too and is the
    // easier one to forget.
    it.each([
      ['a live rotation', armLiveRotation],
      ['a grace-window recovery', armGraceRotation]
    ])('does not refresh the recent-authentication marker on %s', async (_label, arm) => {
      arm()
      mockRedis.set.mockClear()

      await service.reissueTokens('old-raw-token', '1.2.3.4', 'TestBrowser')

      const markerWrites = mockRedis.set.mock.calls.filter((call) =>
        String(call[0]).startsWith('ra:')
      )
      expect(markerWrites).toHaveLength(0)
    })

    // Verifies that mfaEnabled:true in the stored session is propagated into the rotated access token.
    // This is a critical security property: MfaRequiredGuard must continue to enforce MFA after rotation.
    it('should propagate mfaEnabled:true from the stored session into the rotated access token', async () => {
      armLiveRotation(
        JSON.stringify({
          userId: 'user-1',
          tenantId: 'tenant-1',
          role: 'member',
          device: 'Browser',
          ip: '1.2.3.4',
          createdAt: '2026-01-01T00:00:00.000Z',
          mfaEnabled: true,
          familyId: FAMILY
        })
      )

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      const signCall = mockJwtService.sign.mock.calls[0] as [Record<string, unknown>]
      expect(signCall[0]).toMatchObject({ mfaEnabled: true })
    })

    // Verifies that a primary rotation (the presented token was live) returns new tokens.
    it('should create a new session and return new tokens when old session exists', async () => {
      armLiveRotation()

      const result = await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      expect(mockRedis.rotateRefreshSession).toHaveBeenCalled()
      expect(result.accessToken).toBe(FIXED_JWT)
      expect(result.rawRefreshToken).toBe(FIXED_REFRESH_TOKEN)
      // RotatedTokenResult: identity in session field, not a full SafeAuthUser
      expect(result.session.userId).toBe('user-1')
      expect(result.session.tenantId).toBe('tenant-1')
      expect(result.session.role).toBe('member')
    })

    // Scenario: the rotation is driven by ONE atomic call carrying both hashes, the inherited
    // family, and both TTLs — the script plants `cf:`/`fam:` in the same step that consumes the
    // old token, so it needs the family the presented session already belongs to.
    // Expected: the exact rotation bundle for the dashboard plane.
    it('drives the rotation with the presented session family and both TTLs', async () => {
      const oldHash = sha256('old-refresh-token')
      armLiveRotation()

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      expect(mockRedis.get).toHaveBeenCalledWith(`rt:${oldHash}`)
      expect(mockRedis.rotateRefreshSession).toHaveBeenCalledWith({
        kind: 'dashboard',
        oldHash,
        newHash: NEW_HASH,
        newSessionJson: expect.stringContaining(`"familyId":"${FAMILY}"`),
        familyId: FAMILY,
        // The owner, so the script can maintain the session index itself.
        userId: 'user-1',
        refreshTtl: 7 * 86_400,
        graceTtl: 30
      })
    })

    // Scenario: a session naming no family rotates without inventing one. Expected: an empty
    // family is threaded through, and the stored record omits the key entirely rather than
    // emitting `"familyId":""` — rust-auth skips the field when empty, so emitting it would
    // make the same session serialize to different bytes on each side.
    it('rotates a family-less session and omits the empty key from the record', async () => {
      armLiveRotation(
        JSON.stringify({
          userId: 'user-1',
          tenantId: 'tenant-1',
          role: 'member',
          device: 'Browser',
          ip: '1.2.3.4',
          mfaEnabled: false,
          createdAt: '2026-01-01T00:00:00.000Z'
        })
      )

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      const bundle = mockRedis.rotateRefreshSession.mock.calls[0]?.[0] as {
        familyId: string
        newSessionJson: string
      }
      expect(bundle.familyId).toBe('')
      expect(bundle.newSessionJson).not.toContain('familyId')
    })

    // Scenario: a record from the window where families existed but the birth time did not.
    // Expected: rotation inherits the family and leaves the birth time absent. Inventing one
    // would start an absolute-lifetime clock at the rotation rather than at the login, which
    // is the opposite of what the cap measures — and it would diverge from rust-auth, which
    // omits the field rather than writing a placeholder.
    it('rotates a family-bearing session with no birth time without inventing one', async () => {
      armLiveRotation(
        JSON.stringify({
          userId: 'user-1',
          tenantId: 'tenant-1',
          role: 'member',
          device: 'Browser',
          ip: '1.2.3.4',
          mfaEnabled: false,
          createdAt: '2026-01-01T00:00:00.000Z',
          familyId: FAMILY
        })
      )

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      const bundle = mockRedis.rotateRefreshSession.mock.calls[0]?.[0] as {
        familyId: string
        newSessionJson: string
      }
      expect(bundle.familyId).toBe(FAMILY)
      expect(JSON.parse(bundle.newSessionJson)).toMatchObject({ familyCreatedAt: '' })
    })

    // Verifies that primary rotation tracks the grace pointer in sess:{userId} so
    // invalidateUserSessions can delete it — without that member, a token rotated away moments
    // before "log out everywhere" would still recover a session for the whole grace window.
    it('leaves the session index to the rotation script on primary rotation', async () => {
      armLiveRotation()

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      // The membership moved inside the script: maintaining it out here left a window between
      // the consume and the SADD in which "log out everywhere" could sweep the index without
      // seeing the session the rotation had just minted, leaving it alive and rotating after a
      // revocation the user was told had happened. The script gets the owner it needs; the
      // key-level assertions over `sess:` live in the redis service spec, against the script.
      expect(mockRedis.sadd).not.toHaveBeenCalledWith('sess:user-1', expect.anything())
      expect(mockRedis.srem).not.toHaveBeenCalledWith('sess:user-1', expect.anything())
      expect(mockRedis.rotateRefreshSession).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1' })
      )
    })

    // Scenario: a zero-width grace window writes no `rp:` key, so indexing an `rp:` member for
    // it would leave the index pointing at nothing.
    // Expected: only the live member is indexed. Why: kills the `graceTtl > 0` guard mutants.
    it('indexes no grace member when the grace window is zero', async () => {
      const zeroGrace = await Test.createTestingModule({
        providers: [
          TokenManagerService,
          { provide: JwtService, useValue: mockJwtService },
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: {
              ...mockOptions,
              jwt: { ...mockOptions.jwt, refreshGraceWindowSeconds: 0 }
            }
          },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()
      armLiveRotation()

      await zeroGrace
        .get(TokenManagerService)
        .reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      // The zero window is threaded to the script, which is where the `graceTtl > 0` guard
      // that decides whether an `rp:` member is indexed now lives.
      expect(mockRedis.rotateRefreshSession).toHaveBeenCalledWith(
        expect.objectContaining({ graceTtl: 0 })
      )
    })

    // Verifies that a token replayed inside its grace window still mints a session — the window
    // exists to cover the gap where the old token was consumed but the client never got the new one.
    it('should use grace window session when the live session is gone', async () => {
      armGraceRotation()

      const result = await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      expect(result.rawRefreshToken).toBe(FIXED_REFRESH_TOKEN)
    })

    // Verifies that grace-window rotation writes ONLY the new session key (rt:), never another
    // grace pointer (rp:). Chaining grace pointers would allow an attacker with a single captured
    // refresh token to indefinitely extend the session by consuming consecutive grace windows.
    it('should write only a new session (no new grace pointer) on grace-window rotation', async () => {
      armGraceRotation()

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      // The recovered session goes through the atomic write, so it is not a loose `set` at
      // all — and no second grace pointer is planted anywhere.
      expect(mockRedis.writeRecoveredSession).toHaveBeenCalledWith(
        expect.objectContaining({ kind: 'dashboard', newHash: NEW_HASH })
      )
      const keys = mockRedis.set.mock.calls.map((c: unknown[]) => String(c[0]))
      expect(keys.some((k) => k.startsWith('rp:'))).toBe(false)
    })

    // Verifies that grace-window rotation registers only the new `rt:` session under sess:{userId}
    // and keeps the recovered session inside its own lineage, so a later reuse still revokes it.
    it('should index the new rt: key and keep the recovered session in its family', async () => {
      armGraceRotation()

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      // Index and family membership are written by the same atomic step as the session — see
      // `RECOVER_GRACE_LUA` for why they cannot be separate round trips.
      expect(mockRedis.writeRecoveredSession).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: 'dashboard',
          newHash: NEW_HASH,
          familyId: FAMILY,
          userId: 'user-1',
          refreshTtl: 7 * 86_400
        })
      )
      const addedKeys = (mockRedis.sadd.mock.calls as unknown[][]).map((c) => String(c[1]))
      expect(addedKeys.some((k) => k.startsWith('rp:'))).toBe(false)
    })

    // Scenario: a grace record carrying no family, so there is no index to join. Expected: no
    // `fam:` write at all. Why: kills the `familyId !== ''` guard mutant, which would otherwise
    // create a `fam:` key with an empty id shared by every family-less session.
    it('writes no family index when the recovered session names no family', async () => {
      armGraceRotation(
        JSON.stringify({
          userId: 'user-1',
          tenantId: 'tenant-1',
          role: 'member',
          device: 'Browser',
          ip: '1.2.3.4',
          mfaEnabled: false,
          createdAt: '2026-01-01T00:00:00.000Z'
        })
      )

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      const addedKeys = (mockRedis.sadd.mock.calls as unknown[][]).map((c) => String(c[1]))
      expect(addedKeys.some((k) => k.startsWith('fam:'))).toBe(false)
      expect(mockRedis.sadd).not.toHaveBeenCalledWith('fam:', expect.anything())
    })

    // Verifies that REFRESH_TOKEN_INVALID is thrown when the session contains invalid JSON.
    it('should throw REFRESH_TOKEN_INVALID when the session contains invalid JSON', async () => {
      mockRedis.get.mockResolvedValue('not-valid-json')

      await expect(service.reissueTokens('old-token', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that REFRESH_TOKEN_INVALID is thrown when the session JSON is missing required fields.
    it('should throw REFRESH_TOKEN_INVALID when session JSON is missing userId or role', async () => {
      mockRedis.get.mockResolvedValue(JSON.stringify({ ip: '1.2.3.4', device: 'Browser' }))

      await expect(service.reissueTokens('old-token', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that REFRESH_TOKEN_INVALID is thrown when the token was never issued.
    it('should throw REFRESH_TOKEN_INVALID when neither old session nor grace window found', async () => {
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'invalid' })

      await expect(service.reissueTokens('invalid-token', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )

      try {
        await service.reissueTokens('invalid-token-2', '1.2.3.4', 'Browser')
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID })
        })
      }
    })

    // Reuse detection (RFC 6819): replaying a consumed refresh token past its grace window is
    // the signature of a stolen token. The compromised lineage is revoked and the request still
    // The strongest evidence of compromise the library produces, and it had no structured
    // outlet: a token that was already exchanged has been presented again, so one of its two
    // holders is not the owner. A consumer wanting to force a password reset, page an on-call,
    // or raise the account's risk score had only an English log line to key on.
    it('emits onRefreshTokenReuseDetected with the owner and the revoked family', async () => {
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'reused', familyId: FAMILY })

      await expect(service.reissueTokens('replayed', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      await Promise.resolve()

      expect(mockHooks.onRefreshTokenReuseDetected).toHaveBeenCalledWith(
        { userId: 'user-1', familyId: FAMILY },
        expect.anything()
      )
      // Emitted AFTER the revocation, so a consumer that reacts by paging someone is reacting
      // to a lineage that is already dead rather than one still being torn down.
      expect(mockRedis.revokeFamily).toHaveBeenCalledWith(FAMILY)
    })

    // Both failure shapes of the hook itself: a rejection from an `async` body and a throw
    // from a synchronous one. Neither may change the refusal the caller receives.
    it.each([
      ['rejects', () => mockHooks.onRefreshTokenReuseDetected.mockRejectedValue(new Error('x'))],
      [
        'throws',
        () =>
          mockHooks.onRefreshTokenReuseDetected.mockImplementation(() => {
            throw new Error('x')
          })
      ]
    ])('still refuses when the reuse hook %s', async (_label, arrange) => {
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'reused', familyId: FAMILY })
      arrange()

      await expect(service.reissueTokens('replayed', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      await Promise.resolve()
      await Promise.resolve()

      expect(errorSpy.mock.calls.map((call) => String(call[0])).join(' ')).toContain(
        'onRefreshTokenReuseDetected hook threw'
      )
      errorSpy.mockRestore()
    })

    // A replay whose live key is already gone leaves no owner to read. The hook is skipped
    // rather than fired with an empty identity a consumer would have to guess about.
    it('skips the reuse hook when the family names no owner', async () => {
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'reused', familyId: FAMILY })
      mockRedis.revokeFamily.mockResolvedValue({ removed: 0, ownerId: '' })

      await expect(service.reissueTokens('replayed', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )

      expect(mockHooks.onRefreshTokenReuseDetected).not.toHaveBeenCalled()
    })

    // The same case, in the LOG rather than the hook — and the log is what an on-call reads.
    // A family with no live member is the second-and-later replay of one already torn down: the
    // consumed marker outlives the sessions it points at, so reuse is detected again while every
    // record that could name the owner is gone. The line used to read `userId=` there, an empty
    // field on the strongest compromise signal this library produces, precisely on REPEAT attack
    // traffic. An empty field reads as a defect in the logger and makes a reader distrust the
    // tool rather than the event.
    it('says the owner is unknown, and why, when the family names none', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'reused', familyId: FAMILY })
      mockRedis.revokeFamily.mockResolvedValue({ removed: 0, ownerId: '' })

      await expect(service.reissueTokens('replayed', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )

      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).toContain('token family revoked after reuse detection')
      expect(warned).toContain('already revoked')
      // Never the bare field, which is the shape being fixed.
      expect(warned).not.toContain('userId= ')
      // The family is still named, because it is the only handle left on the lineage.
      expect(warned).toContain(`familyId=${FAMILY}`)
      warnSpy.mockRestore()
    })

    // fails as REFRESH_TOKEN_INVALID — the reaction never resurrects the token.
    it('should revoke the compromised family when a consumed token is replayed', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'reused', familyId: FAMILY })

      await expect(service.reissueTokens('stolen-token', '9.9.9.9', 'Attacker')).rejects.toThrow(
        AuthException
      )

      expect(mockRedis.revokeFamily).toHaveBeenCalledWith(FAMILY)
      // The warning is the operator's only signal that a token theft was detected — an
      // emptied template would make the revocation silent.
      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).toContain('reuse of a consumed refresh token detected')
      warnSpy.mockRestore()
    })

    // Scenario: the revocation is scoped to the stolen token's lineage.
    // Expected: the family is revoked and the user's OTHER sessions are left alone. Why: the
    // previous design revoked every session the user had, so a theft logged all their devices
    // out — this pins the narrower, OWASP-recommended behaviour.
    it('revokes only the family, not every session the user has', async () => {
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'reused', familyId: FAMILY })

      await expect(service.reissueTokens('stolen-token', '9.9.9.9', 'Attacker')).rejects.toThrow(
        AuthException
      )

      expect(mockRedis.revokeFamily).toHaveBeenCalledTimes(1)
      expect(mockRedis.invalidateUserSessions).not.toHaveBeenCalled()
      expect(mockRedis.revokeAllUserTokens).not.toHaveBeenCalled()
    })

    // An unknown token is just an invalid/expired string — no lineage is touched.
    it('should NOT revoke anything when the token was never issued', async () => {
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'invalid' })

      await expect(service.reissueTokens('garbage-token', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )

      expect(mockRedis.revokeFamily).not.toHaveBeenCalled()
    })

    // Scenario: primary rotation rewrites the per-user SET — remove old rt:, add new rt: and the
    // grace pointer, then expire the SET with the refresh TTL (days*86400).
    // Expected: exact srem/sadd/expire calls on 'sess:user-1'. Why: kills the StringLiteral
    // mutants on each key/member and the arithmetic mutant on `* 86_400` via the pinned TTL.
    it('hands the rotation script every key it needs to index the new session', async () => {
      const oldHash = sha256('old-refresh-token')
      armLiveRotation()

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      // The exact `sess:` writes are asserted in the redis service spec against the script's
      // KEYS/ARGV. What this level owns is that the script is given the owner and both hashes
      // — without the owner it has no index to maintain, and the window this change closed
      // would reopen silently.
      expect(mockRedis.rotateRefreshSession).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1', oldHash, newHash: NEW_HASH })
      )
    })

    // Scenario: grace-window rotation registers the new rt: under the per-user SET and expires it.
    // The whole point of moving the write inside a script: a `revoke_all` that lands between
    // the rotation script's return and the recovered session's write swept an index the
    // session was not yet in, so the session survived a revocation the user was told had
    // happened — and its access token, signed afterwards, carried the POST-bump epoch and
    // verified. The attacker gets one grace-eligible token per rotation, so they can keep a
    // stream of these in flight for exactly as long as the victim's password reset takes.
    it('refuses a grace recovery that a concurrent revoke-all swept', async () => {
      armGraceRotation()
      // The atomic write reports that the account no longer has a session index — which is
      // precisely "a revoke-all ran between the script and this write".
      mockRedis.writeRecoveredSession.mockResolvedValueOnce(false)

      await expect(
        service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID } }
      })
    })

    it('updates the sess:{userId} SET with exact key and TTL on grace-window rotation', async () => {
      armGraceRotation()

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      // The index write is inside the atomic step now — a `revoke_all` arriving between the
      // script's return and a loose SADD swept an index the recovered session was not yet in.
      expect(mockRedis.writeRecoveredSession).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1', newHash: NEW_HASH, refreshTtl: 7 * 86_400 })
      )
    })

    // Scenario: the login this session descends from has outlived the configured cap.
    // Expected: the rotation is refused, and it is refused BEFORE the token is consumed —
    // `refreshExpiresInDays` bounds a single token, not a session, so without this a client
    // rotating every fifteen minutes renews its lifetime forever.
    it('refuses a rotation once the family has outlived the absolute cap', async () => {
      const capped = await Test.createTestingModule({
        providers: [
          TokenManagerService,
          { provide: JwtService, useValue: mockJwtService },
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: {
              ...mockOptions,
              jwt: { ...mockOptions.jwt, absoluteSessionLifetimeDays: 30 }
            }
          },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()
      const bornAt = new Date(Date.now() - 31 * 86_400_000).toISOString()
      mockRedis.get.mockResolvedValue(
        JSON.stringify({
          userId: 'user-1',
          tenantId: 'tenant-1',
          role: 'member',
          device: 'Browser',
          ip: '1.2.3.4',
          mfaEnabled: false,
          createdAt: new Date().toISOString(),
          familyId: FAMILY,
          familyCreatedAt: bornAt
        })
      )

      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      await expect(
        capped.get(TokenManagerService).reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
      // Refused before the script ran: the token is still spendable by the legitimate holder
      // right up until they sign in again, and nothing was consumed on their behalf.
      expect(mockRedis.rotateRefreshSession).not.toHaveBeenCalled()
      // The warning is the operator's only signal that sessions are being ended by the cap
      // rather than by a bug.
      expect(warnSpy.mock.calls.map((call) => String(call[0])).join(' ')).toContain(
        'outlived the absolute lifetime cap'
      )
      warnSpy.mockRestore()
    })

    // The cap must hold on the GRACE path too. The check at the top of `reissueTokens` runs
    // against the seed, and on this path the seed is the placeholder returned when the live key
    // is already gone — its `familyCreatedAt` is `now`, so that check compares `now - now` and
    // always passes. Without a second check against the RECOVERED record, a lineage that had
    // just passed its cap could still mint a fresh access token and a full-length refresh
    // session by presenting a token inside its grace window: the cap ends normal rotation and
    // the one remaining door stays open.
    it('refuses a grace recovery for a family that has outlived the absolute cap', async () => {
      const capped = await Test.createTestingModule({
        providers: [
          TokenManagerService,
          { provide: JwtService, useValue: mockJwtService },
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: {
              ...mockOptions,
              jwt: { ...mockOptions.jwt, absoluteSessionLifetimeDays: 30 }
            }
          },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()

      // The live key is gone — exactly the state grace exists to serve — so the seed is the
      // placeholder and the first cap check is a no-op.
      mockRedis.get.mockResolvedValue(null)
      const bornAt = new Date(Date.now() - 31 * 86_400_000).toISOString()
      mockRedis.rotateRefreshSession.mockResolvedValue({
        kind: 'grace',
        sessionJson: JSON.stringify({
          userId: 'user-1',
          tenantId: 'tenant-1',
          role: 'member',
          device: 'Browser',
          ip: '1.2.3.4',
          mfaEnabled: false,
          createdAt: new Date().toISOString(),
          familyId: FAMILY,
          familyCreatedAt: bornAt
        })
      })

      await expect(
        capped.get(TokenManagerService).reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
      // Nothing was minted: no replacement session, no family membership.
      expect(mockRedis.set).not.toHaveBeenCalled()
      expect(mockRedis.sadd).not.toHaveBeenCalled()
    })

    // The platform plane takes the identical check. Adding it to only the dashboard twin left
    // the higher-privilege identity with the hole the dashboard one had just closed.
    it('refuses a platform grace recovery for a family past the absolute cap', async () => {
      const capped = await Test.createTestingModule({
        providers: [
          TokenManagerService,
          { provide: JwtService, useValue: mockJwtService },
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: {
              ...mockOptions,
              jwt: { ...mockOptions.jwt, absoluteSessionLifetimeDays: 30 }
            }
          },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()

      mockRedis.get.mockResolvedValue(null)
      const bornAt = new Date(Date.now() - 31 * 86_400_000).toISOString()
      mockRedis.rotateRefreshSession.mockResolvedValue({
        kind: 'grace',
        sessionJson: JSON.stringify({
          userId: 'admin-1',
          tenantId: '',
          role: 'SUPER_ADMIN',
          device: 'Browser',
          ip: '1.2.3.4',
          mfaEnabled: false,
          createdAt: new Date().toISOString(),
          familyId: FAMILY,
          familyCreatedAt: bornAt
        })
      })

      await expect(
        capped
          .get(TokenManagerService)
          .reissuePlatformTokens('old-refresh-token', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
      expect(mockRedis.set).not.toHaveBeenCalled()
    })

    // Scenario: the same session, one day inside the cap. Expected: it rotates. The boundary
    // matters — an off-by-one here signs users out a day early, every time.
    it('rotates a family that is still inside the absolute cap', async () => {
      const capped = await Test.createTestingModule({
        providers: [
          TokenManagerService,
          { provide: JwtService, useValue: mockJwtService },
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: {
              ...mockOptions,
              jwt: { ...mockOptions.jwt, absoluteSessionLifetimeDays: 30 }
            }
          },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()
      const bornAt = new Date(Date.now() - 29 * 86_400_000).toISOString()
      const session = JSON.stringify({
        userId: 'user-1',
        tenantId: 'tenant-1',
        role: 'member',
        device: 'Browser',
        ip: '1.2.3.4',
        mfaEnabled: false,
        createdAt: new Date().toISOString(),
        familyId: FAMILY,
        familyCreatedAt: bornAt
      })
      mockRedis.get.mockResolvedValue(session)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'rotated', sessionJson: session })
      mockRedis.set.mockResolvedValue(undefined)

      await expect(
        capped.get(TokenManagerService).reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')
      ).resolves.toMatchObject({ rawRefreshToken: FIXED_REFRESH_TOKEN })
    })

    // Scenario: the session's age is exactly the cap, with the clock pinned so it is exactly
    // that and not a millisecond more. Expected: it rotates. The cap is a maximum, not an
    // exclusive bound, and only a record sitting on the boundary can tell the two apart.
    it('rotates a family whose age is exactly the absolute cap', async () => {
      const capped = await Test.createTestingModule({
        providers: [
          TokenManagerService,
          { provide: JwtService, useValue: mockJwtService },
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: {
              ...mockOptions,
              jwt: { ...mockOptions.jwt, absoluteSessionLifetimeDays: 30 }
            }
          },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()
      // Pinned: real time advances between building the record and reading it, which would
      // push the age a millisecond past the cap and make the assertion prove nothing.
      const nowMs = Date.UTC(2026, 0, 31)
      const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(nowMs)
      const session = JSON.stringify({
        userId: 'user-1',
        tenantId: 'tenant-1',
        role: 'member',
        device: 'Browser',
        ip: '1.2.3.4',
        mfaEnabled: false,
        createdAt: new Date(nowMs).toISOString(),
        familyId: FAMILY,
        familyCreatedAt: new Date(nowMs - 30 * 86_400_000).toISOString()
      })
      mockRedis.get.mockResolvedValue(session)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'rotated', sessionJson: session })
      mockRedis.set.mockResolvedValue(undefined)

      await expect(
        capped.get(TokenManagerService).reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')
      ).resolves.toMatchObject({ rawRefreshToken: FIXED_REFRESH_TOKEN })
      nowSpy.mockRestore()
    })

    // Scenario: the cap is off (the default), or the record predates the field, or the field is
    // unparseable. Expected: the rotation proceeds in all three. A malformed timestamp is not
    // evidence a session is old, and ending one on it would be a self-inflicted outage.
    it.each([
      ['the cap is disabled', 0, new Date(0).toISOString()],
      ['the record carries no birth time', 30, ''],
      ['the birth time is unparseable', 30, 'not-a-date']
    ])('rotates when %s', async (_label, capDays, familyCreatedAt) => {
      const module = await Test.createTestingModule({
        providers: [
          TokenManagerService,
          { provide: JwtService, useValue: mockJwtService },
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: {
              ...mockOptions,
              jwt: { ...mockOptions.jwt, absoluteSessionLifetimeDays: capDays }
            }
          },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()
      const session = JSON.stringify({
        userId: 'user-1',
        tenantId: 'tenant-1',
        role: 'member',
        device: 'Browser',
        ip: '1.2.3.4',
        mfaEnabled: false,
        createdAt: new Date().toISOString(),
        familyId: FAMILY,
        ...(familyCreatedAt === '' ? {} : { familyCreatedAt })
      })
      mockRedis.get.mockResolvedValue(session)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'rotated', sessionJson: session })
      mockRedis.set.mockResolvedValue(undefined)

      await expect(
        module.get(TokenManagerService).reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')
      ).resolves.toBeDefined()
    })

    // Scenario: a rotated access token must carry status:'' and mfaVerified:false (state is not
    // persisted in the Redis session, forcing re-auth of MFA after rotation).
    it('issues the rotated access token with an empty status and mfaVerified:false', async () => {
      armLiveRotation()

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      const signCall = mockJwtService.sign.mock.calls[0] as [Record<string, unknown>]
      expect(signCall[0]['status']).toBe('')
      expect(signCall[0]['mfaVerified']).toBe(false)
    })

    // Scenario: a stored session with `mfaEnabled: false` rotates into a token that says the
    // same. Why: kills the BooleanLiteral mutant that would stamp `true` regardless, which
    // turns every rotation into an MFA-gate trip for an account that has no second factor.
    // (A record OMITTING the field is refused outright — see the parseSession suite.)
    it('carries mfaEnabled: false from the stored session into the rotated token', async () => {
      armLiveRotation(
        JSON.stringify({
          userId: 'user-1',
          tenantId: 'tenant-1',
          role: 'member',
          device: 'Browser',
          ip: '1.2.3.4',
          mfaEnabled: false,
          createdAt: '2026-01-01T00:00:00.000Z'
        })
      )

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      const signCall = mockJwtService.sign.mock.calls[0] as [Record<string, unknown>]
      expect(signCall[0]['mfaEnabled']).toBe(false)
    })

    // Scenario: malformed JSON in the session record must be logged AND rejected as REFRESH_TOKEN_INVALID.
    it('warns and throws REFRESH_TOKEN_INVALID on malformed session JSON', async () => {
      const warnSpy = jest.spyOn(service['logger'], 'warn').mockImplementation(() => undefined)
      mockRedis.get.mockResolvedValue('not-valid-json{{{')

      let thrown: unknown
      try {
        await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')
      } catch (e) {
        thrown = e
      }

      expect(thrown).toBeInstanceOf(AuthException)
      expect((thrown as AuthException).getResponse()).toMatchObject({
        error: expect.objectContaining({ code: AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID })
      })
      expect(warnSpy).toHaveBeenCalledWith('parseSession: malformed session JSON in Redis')
      warnSpy.mockRestore()
    })

    // Scenario: a session JSON missing only userId (role present) must be rejected as
    // AuthException. The rotation is armed to SUCCEED, so the only thing that can fail the call
    // is the parse guard itself — otherwise the rejection could come from the rotation and the
    // test would pass with the guard removed.
    it('throws AuthException when the session JSON has role but no userId', async () => {
      mockRedis.get.mockResolvedValue(JSON.stringify({ role: 'member' }))
      mockRedis.rotateRefreshSession.mockResolvedValue({
        kind: 'rotated',
        sessionJson: OLD_SESSION
      })

      await expect(
        service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
    })

    // Same, for a record missing only the role. Rotation armed to succeed for the same reason.
    it('throws AuthException when the session JSON has userId but no role', async () => {
      mockRedis.get.mockResolvedValue(JSON.stringify({ userId: 'user-1' }))
      mockRedis.rotateRefreshSession.mockResolvedValue({
        kind: 'rotated',
        sessionJson: OLD_SESSION
      })

      await expect(
        service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
    })

    // Scenario: the presented token has no live record, so the rotation is seeded with a
    // placeholder. Expected: the placeholder carries an EMPTY identity and MFA off.
    // Why: the script only stores that record when the live key exists — which is exactly the
    // case where the seed came from the live record instead — so the placeholder is never
    // persisted. Pinning it anyway is defense in depth: if that invariant ever broke, the record
    // that leaked would be an empty identity with the MFA gate ON, not a usable session.
    it('seeds an absent live session with an empty, MFA-enforcing placeholder', async () => {
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'grace', sessionJson: OLD_SESSION })
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      const bundle = mockRedis.rotateRefreshSession.mock.calls[0]?.[0] as {
        newSessionJson: string
        familyId: string
      }
      const placeholder = JSON.parse(bundle.newSessionJson) as Record<string, unknown>
      expect(placeholder['userId']).toBe('')
      expect(placeholder['tenantId']).toBe('')
      expect(placeholder['role']).toBe('')
      // The request's own IP and User-Agent are carried through — the placeholder replaces the
      // IDENTITY, never the request metadata.
      expect(placeholder['ip']).toBe('1.2.3.4')
      expect(placeholder['device']).toBe('Browser')
      // MFA off in the record means the gate stays ON for the rotated token, because the gate
      // refuses only when `mfaEnabled && !mfaVerified` — the safe default for a hollow record.
      expect(placeholder['mfaEnabled']).toBe(false)
      // No family: a placeholder must never be able to plant family bookkeeping.
      expect(bundle.familyId).toBe('')
      expect(placeholder['familyId']).toBeUndefined()
    })

    // Scenario: a session record that parses to JSON null must be rejected as AuthException — not
    // a TypeError. Without the null guard the code dereferences null['userId'].
    it('throws AuthException (not TypeError) when the session JSON is null', async () => {
      mockRedis.get.mockResolvedValue('null')

      await expect(
        service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
    })

    // Scenario: when the token was never issued, a warning is logged before throwing.
    it('warns with the no-valid-session message before throwing REFRESH_TOKEN_INVALID', async () => {
      const warnSpy = jest.spyOn(service['logger'], 'warn').mockImplementation(() => undefined)
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'invalid' })

      await expect(service.reissueTokens('gone-token', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      expect(warnSpy).toHaveBeenCalledWith(
        'reissueTokens: no valid session or grace window found — REFRESH_TOKEN_INVALID'
      )
      warnSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // issueMfaTempToken
  // ---------------------------------------------------------------------------

  describe('issueMfaTempToken', () => {
    // Verifies that an MFA challenge token is signed with type 'mfa_challenge' and stored in Redis with a 300s TTL.
    it('should sign an MFA JWT and store it in Redis with 300s TTL', async () => {
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)

      const token = await service.issueMfaTempToken('user-1', 'dashboard', 'tenant-1')

      // The dashboard token carries the tenant as the camelCase `tenantId` wire claim (verbatim,
      // since @nestjs/jwt signs the payload keys as-is) so the challenge resolves it tenant-scoped.
      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          sub: 'user-1',
          type: 'mfa_challenge',
          context: 'dashboard',
          tenantId: 'tenant-1'
        }),
        expect.objectContaining({ expiresIn: '300s' })
      )
      expect(mockRedis.set).toHaveBeenCalledWith(expect.stringMatching(/^mfa:/), 'user-1', 300)
      expect(token).toBe(FIXED_JWT)
    })

    // Verifies that platform MFA challenges use context 'platform' in the token payload.
    it('should use context:platform for platform MFA challenges', async () => {
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)

      await service.issueMfaTempToken('admin-1', 'platform')

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ context: 'platform', sub: 'admin-1' }),
        expect.any(Object)
      )
    })

    // Scenario: a fresh login for an MFA-enabled account. Expected: the per-user MFA challenge
    // counter (`lf:{hmac('challenge:{userId}')}`) is NOT cleared. Why: issuing the temp token
    // used to reset it, on the reasoning that a fresh login proves renewed password
    // possession — but password possession is exactly what the attacker is assumed to have in
    // the threat model the second factor covers. With the reset, they looped
    // `login → five wrong codes → login` and the per-account lockout never engaged; the only
    // remaining control was the per-IP limit, which a distributed caller sidesteps. At
    // totpWindow 1 that turns a ~480-guess/day budget into an unbounded one.
    it('should NOT reset the MFA challenge brute-force counter on token issuance', async () => {
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)

      await service.issueMfaTempToken('user-1', 'dashboard', 'tenant-1')

      const challengeCounter = `lf:${createHmac('sha256', HMAC_KEY)
        .update('challenge:user-1', 'utf8')
        .digest('hex')}`
      expect(mockRedis.del).not.toHaveBeenCalledWith(challengeCounter)
      // …and nothing else in the lockout keyspace is cleared either — the counter is cleared
      // by exactly one event, a successful challenge.
      expect(mockRedis.del).not.toHaveBeenCalledWith(expect.stringMatching(/^lf:/))
    })
  })

  // ---------------------------------------------------------------------------
  // verifyMfaTempToken
  // ---------------------------------------------------------------------------

  describe('verifyMfaTempToken', () => {
    // Verifies that verifyMfaTempToken returns userId, context, and jti when
    // the token is valid and the Redis entry still exists. The Redis entry
    // is NOT removed by verify (split from consume in v1.0.8+) so the caller
    // can retry on wrong TOTP under the same JWT.
    it('should return userId, context, and jti when token is valid and in Redis', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'user-1',
        type: 'mfa_challenge',
        context: 'dashboard',
        tenantId: 'tenant-1',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.get.mockResolvedValue('user-1') // entry exists; not deleted by verify

      const result = await service.verifyMfaTempToken(FIXED_JWT)

      expect(result).toEqual({
        userId: 'user-1',
        context: 'dashboard',
        tenantId: 'tenant-1',
        jti: FIXED_UUID
      })
    })

    // A token no configured secret accepts is refused with the same code every other failure
    // here answers. The verifier's own error used to travel out unchanged, and since no caller
    // catches it, a malformed `mfaTempToken` answered 500 `auth.internal` over HTTP — an
    // attacker-controlled input producing a 5xx, and a temp cookie the controller then never
    // cleared because it only recognises `AuthException`. rust-auth maps the same failure to
    // `MfaTempTokenInvalid`, so this is also the two backends agreeing again.
    it('refuses a token the verifier rejects, without leaking its error', async () => {
      mockJwtService.verify.mockImplementation(() => {
        throw new Error('jwt malformed')
      })

      // The MESSAGE as well as the code. The claim in this test's name is that the verifier's
      // error does not leak, and an implementation that surfaced `jwt malformed` as the public
      // message would satisfy a code-only assertion while doing exactly the thing being ruled
      // out — the catalogue's standard message is what a caller must see.
      await expect(service.verifyMfaTempToken(FIXED_JWT)).rejects.toMatchObject({
        response: {
          error: {
            code: AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID,
            message: AUTH_ERROR_MESSAGES[AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID]
          }
        }
      })
      // Refused on the token alone — the Redis lookup is never reached.
      expect(mockRedis.get).not.toHaveBeenCalled()
    })

    // Plane/tenant binding is mandatory and mutually exclusive: a dashboard token WITHOUT a tenant
    // is refused, never degraded to the tenant-blind lookup. Refusing rather than falling back is
    // what stops an attacker forcing the old path by simply dropping the claim.
    it('refuses a dashboard token that carries no tenant', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'user-1',
        type: 'mfa_challenge',
        context: 'dashboard',
        iat: 0,
        exp: 9999999999
      })

      await expect(service.verifyMfaTempToken(FIXED_JWT)).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID } }
      })
      // Refused on the claim alone — never reaches the Redis single-use lookup.
      expect(mockRedis.get).not.toHaveBeenCalled()
    })

    // The mirror rule: a platform token MUST NOT carry a tenant it does not have. The Redis entry
    // is present and the epoch matches, so the ONLY thing that can refuse this token is the
    // plane/tenant binding — isolating that branch from the single-use and epoch gates.
    it('refuses a platform token that carries a tenant', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'admin-1',
        type: 'mfa_challenge',
        context: 'platform',
        tenantId: 'tenant-1',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.get.mockResolvedValue('admin-1')
      mockRedis.getUserTokenEpoch.mockResolvedValue(0)

      await expect(service.verifyMfaTempToken(FIXED_JWT)).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID } }
      })
    })

    // A valid platform token returns NO tenantId key — not `tenantId: undefined`. toStrictEqual
    // distinguishes the two: it pins that the conditional spread omits the key on the platform
    // plane rather than emitting an explicit undefined.
    it('returns no tenantId key for a valid platform token', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'admin-1',
        type: 'mfa_challenge',
        context: 'platform',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.get.mockResolvedValue('admin-1')
      mockRedis.getUserTokenEpoch.mockResolvedValue(0)

      const result = await service.verifyMfaTempToken(FIXED_JWT)

      expect(result).toStrictEqual({ userId: 'admin-1', context: 'platform', jti: FIXED_UUID })
    })

    // The challenge token is half a credential, held by a caller who has already proved the
    // password. A password reset bumps the epoch and kills every access token, but nothing
    // deleted an outstanding `mfa:` record — so a challenge token minted before the reset
    // stayed redeemable for its whole TTL, and completing it handed back a full session under
    // the NEW epoch. The reset is supposed to end everything the old credential could reach.
    it.each([['dashboard' as const], ['platform' as const]])(
      'refuses a %s challenge token minted before the epoch was bumped',
      async (context) => {
        mockJwtService.verify.mockReturnValue({
          jti: FIXED_UUID,
          sub: 'user-1',
          type: 'mfa_challenge',
          context,
          // Dashboard tokens must carry the tenant (platform must not) or verify rejects on the
          // plane/tenant binding before it ever reaches the epoch check this test is about.
          ...(context === 'dashboard' ? { tenantId: 'tenant-1' } : {}),
          epoch: 2,
          iat: 0,
          exp: 9999999999
        })
        mockRedis.get.mockResolvedValue('user-1')
        mockRedis.getUserTokenEpoch.mockResolvedValue(3)

        await expect(service.verifyMfaTempToken(FIXED_JWT)).rejects.toThrow(AuthException)
        // Read from the plane the challenge names — the two epochs are separate counters.
        expect(mockRedis.getUserTokenEpoch).toHaveBeenCalledWith('user-1', context)
      }
    )

    // The mechanism stays inert until the first bump: a token minted before the claim existed
    // carries none, which reads as 0, and 0 is never below a stored 0.
    it('accepts a challenge token carrying no epoch while the account was never bumped', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'user-1',
        type: 'mfa_challenge',
        context: 'dashboard',
        tenantId: 'tenant-1',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.get.mockResolvedValue('user-1')
      mockRedis.getUserTokenEpoch.mockResolvedValue(0)

      await expect(service.verifyMfaTempToken(FIXED_JWT)).resolves.toEqual({
        userId: 'user-1',
        context: 'dashboard',
        tenantId: 'tenant-1',
        jti: FIXED_UUID
      })
    })

    // Verifies that verifyMfaTempToken uses GET (not GETDEL) so wrong-TOTP
    // attempts can retry under the same JWT. The matching consume step lives
    // in `consumeMfaTempToken` and is invoked only after the code is valid.
    it('uses GET (not GETDEL) so the token survives wrong-code retries', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'user-1',
        type: 'mfa_challenge',
        context: 'dashboard',
        tenantId: 'tenant-1',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.get.mockResolvedValue('user-1')

      await service.verifyMfaTempToken(FIXED_JWT)

      expect(mockRedis.get).toHaveBeenCalledWith(expect.stringMatching(/^mfa:/))
      // The verify step must NOT delete the Redis entry — that is the job
      // of `consumeMfaTempToken` invoked only when the TOTP is valid.
      expect(mockRedis.getdel).not.toHaveBeenCalled()
      expect(mockRedis.del).not.toHaveBeenCalled()
    })

    // Verifies that MFA_TEMP_TOKEN_INVALID is thrown when the token is not found in Redis (already consumed or expired).
    it('should throw MFA_TEMP_TOKEN_INVALID when token is not in Redis', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'user-1',
        type: 'mfa_challenge',
        context: 'dashboard',
        tenantId: 'tenant-1',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.get.mockResolvedValue(null) // not found / already consumed

      await expect(service.verifyMfaTempToken(FIXED_JWT)).rejects.toThrow(AuthException)
    })

    // Verifies that MFA_TEMP_TOKEN_INVALID is thrown when storedUserId differs from the JWT sub claim.
    // This is a defence-in-depth check: requires a forged JWT but makes the binding between
    // the Redis record and the token claims explicit and auditable.
    it('should throw MFA_TEMP_TOKEN_INVALID when storedUserId does not match payload.sub', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'user-1',
        type: 'mfa_challenge',
        context: 'dashboard',
        tenantId: 'tenant-1',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.get.mockResolvedValue('different-user') // userId mismatch

      await expect(service.verifyMfaTempToken(FIXED_JWT)).rejects.toThrow(AuthException)
    })

    // Scenario: the JWT must be verified with the configured algorithm allowlist.
    // Expected: jwtService.verify called with { algorithms: ['HS256'] }. Why: kills the ObjectLiteral
    // mutant on line 730 (options → {}) and the ArrayDeclaration mutant on line 731 (algorithms → [])
    // which would disable algorithm pinning and allow algorithm-confusion attacks.
    it('verifies the MFA temp token with the configured algorithm allowlist', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'user-1',
        type: 'mfa_challenge',
        context: 'dashboard',
        tenantId: 'tenant-1',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.get.mockResolvedValue('user-1')

      await service.verifyMfaTempToken(FIXED_JWT)

      expect(mockJwtService.verify).toHaveBeenCalledWith(FIXED_JWT, {
        algorithms: ['HS256'],
        // Expiry IS checked here — only logout waives it, and only for the access token.
        ignoreExpiration: false
      })
    })

    // Scenario: Redis returns null (token consumed/expired) AND the JWT sub is also null.
    // Expected: throws AuthException (the storedUserId === null guard fires first). Why: kills the
    // ConditionalExpression `if (false)` and the empty-block mutants on line 737 — without the null
    // guard, `null !== null` is false so the sub-mismatch check is skipped and the method would
    // wrongly return `{ userId: null }` instead of throwing.
    it('throws when storedUserId is null even if it equals a null sub claim', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: null,
        type: 'mfa_challenge',
        context: 'dashboard',
        tenantId: 'tenant-1',
        iat: 0,
        exp: 9999999999
      } as unknown as { jti: string; sub: string; type: string; context: string })
      mockRedis.get.mockResolvedValue(null)

      await expect(service.verifyMfaTempToken(FIXED_JWT)).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // consumeMfaTempToken
  // ---------------------------------------------------------------------------

  describe('consumeMfaTempToken', () => {
    // Verifies that consumeMfaTempToken removes the Redis entry keyed by
    // mfa:{sha256(jti)} so the JWT cannot be reused after a successful
    // MFA challenge. Must be a `DEL` (not `GETDEL`) because the value
    // is already known by the caller and a GETDEL would be wasteful.
    it('deletes the mfa:{sha256(jti)} Redis entry', async () => {
      mockRedis.del.mockResolvedValue(undefined)

      await service.consumeMfaTempToken(FIXED_UUID)

      expect(mockRedis.del).toHaveBeenCalledWith(expect.stringMatching(/^mfa:/))
      expect(mockRedis.del).toHaveBeenCalledTimes(1)
    })

    // Verifies that consumeMfaTempToken hashes the jti before keying so
    // the raw jti is never persisted to Redis. Mirrors the `issueMfaTempToken`
    // and `verifyMfaTempToken` key derivation.
    it('hashes the jti via sha256 before keying the Redis entry', async () => {
      mockRedis.del.mockResolvedValue(undefined)

      await service.consumeMfaTempToken(FIXED_UUID)

      const calls = mockRedis.del.mock.calls
      const calledKey = (calls[0] as [string])[0]
      // The deleted key starts with `mfa:` and the suffix is a hex SHA-256
      // (64 lowercase hex chars). Confirms the jti is not present in the raw.
      expect(calledKey).toMatch(/^mfa:[0-9a-f]{64}$/)
      expect(calledKey).not.toContain(FIXED_UUID)
    })

    // Verifies idempotency: a second call (e.g. from a concurrent successful
    // submission that lost a race) is a benign no-op rather than an error.
    it('is idempotent — calling twice does not throw', async () => {
      mockRedis.del.mockResolvedValue(undefined)

      await service.consumeMfaTempToken(FIXED_UUID)
      await expect(service.consumeMfaTempToken(FIXED_UUID)).resolves.toBeUndefined()
    })
  })

  // ---------------------------------------------------------------------------
  // reissuePlatformTokens
  // ---------------------------------------------------------------------------

  describe('reissuePlatformAccessWithAuthority', () => {
    // Platform rotation builds its claims from the `prt:` record written at login, so a
    // demotion from `super_admin` to `support` had no effect on a live console session: it
    // kept minting tokens with the old role for the refresh token's whole lifetime, and every
    // role check reads that claim — on the highest-privilege identity in the system. The
    // dashboard plane closed this and the platform plane was left with the identical hole.
    it('re-signs the token with the role and MFA flag the admin holds now', async () => {
      mockJwtService.sign.mockReturnValue('restamped.platform.jwt')
      mockRedis.getUserTokenEpoch.mockResolvedValue(4)

      const token = await service.reissuePlatformAccessWithAuthority(
        {
          jti: FIXED_UUID,
          sub: 'admin-1',
          role: 'super_admin',
          type: 'platform',
          mfaEnabled: false,
          mfaVerified: true,
          iat: 0,
          exp: 9999999999
        },
        'support',
        true
      )

      expect(token).toBe('restamped.platform.jwt')
      // The epoch is read from the PLATFORM counter — the two planes are separate generations.
      expect(mockRedis.getUserTokenEpoch).toHaveBeenCalledWith('admin-1', 'platform')
      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          sub: 'admin-1',
          role: 'support',
          type: 'platform',
          mfaEnabled: true,
          // Carried across: a second factor already cleared on this session must not be
          // silently demanded again by a re-stamp of the authority.
          mfaVerified: true,
          epoch: 4
        }),
        expect.anything()
      )
    })
  })

  describe('reissuePlatformTokens', () => {
    const PLATFORM_FAMILY = 'pfam-old-1'
    /** Minimal valid platform session JSON — matches the RefreshSession shape used for platform admins. */
    const OLD_PLATFORM_SESSION = JSON.stringify({
      userId: 'admin-1',
      tenantId: '',
      role: 'super-admin',
      device: 'Browser',
      ip: '1.2.3.4',
      createdAt: '2026-01-01T00:00:00.000Z',
      mfaEnabled: false,
      familyId: PLATFORM_FAMILY
    })

    /** Arms the seed read + the rotation script for a live platform rotation. */
    function armLivePlatformRotation(sessionJson = OLD_PLATFORM_SESSION): void {
      mockRedis.get.mockResolvedValue(sessionJson)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'rotated', sessionJson })
      mockRedis.set.mockResolvedValue(undefined)
    }

    /** Arms a platform rotation served from the grace window. */
    function armPlatformGraceRotation(sessionJson = OLD_PLATFORM_SESSION): void {
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'grace', sessionJson })
      mockRedis.set.mockResolvedValue(undefined)
    }

    // Verifies the primary rotation path: the old prt: session was live, a new session is
    // issued, and a RotatedTokenResult is returned with the expected fields.
    it('should return new tokens when the primary prt: session is found', async () => {
      armLivePlatformRotation()

      const result = await service.reissuePlatformTokens(
        'old-platform-refresh',
        '1.2.3.4',
        'Browser'
      )

      expect(mockRedis.rotateRefreshSession).toHaveBeenCalled()
      expect(result.accessToken).toBe(FIXED_JWT)
      expect(result.rawRefreshToken).toBe(FIXED_REFRESH_TOKEN)
      expect(result.session.userId).toBe('admin-1')
      expect(result.session.tenantId).toBe('')
      expect(result.session.role).toBe('super-admin')
    })

    // Scenario: the platform rotation drives the platform keyspace, not the dashboard one.
    // Expected: the bundle names `kind: 'platform'` with the exact hashes, the inherited family,
    // and both TTLs. Why: the two planes are keyed by ids from different repositories that may
    // collide, so rotating a platform token through the dashboard prefixes would cross the planes.
    it('drives the rotation on the platform plane with the inherited family', async () => {
      const oldHash = sha256('old-platform-refresh')
      armLivePlatformRotation()

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      expect(mockRedis.get).toHaveBeenCalledWith(`prt:${oldHash}`)
      expect(mockRedis.rotateRefreshSession).toHaveBeenCalledWith({
        kind: 'platform',
        oldHash,
        newHash: NEW_HASH,
        newSessionJson: expect.stringContaining(`"familyId":"${PLATFORM_FAMILY}"`),
        familyId: PLATFORM_FAMILY,
        userId: 'admin-1',
        refreshTtl: 7 * 86_400,
        graceTtl: 30
      })
      // The rotated session carries its detail record along, so a listing describes the live
      // token rather than a hash that no longer exists.
      const keys = (mockRedis.set.mock.calls as unknown[][]).map((c) => String(c[0]))
      expect(keys.filter((k) => k.startsWith('psd:'))).toHaveLength(1)
    })

    // Verifies the grace-window path: the primary session is gone but the pointer is still
    // inside its window, so a new token pair is issued.
    it('should return new tokens from the prp: grace pointer when the primary session is gone', async () => {
      armPlatformGraceRotation()

      const result = await service.reissuePlatformTokens(
        'old-platform-refresh',
        '1.2.3.4',
        'Browser'
      )

      expect(result.accessToken).toBe(FIXED_JWT)
      expect(result.rawRefreshToken).toBe(FIXED_REFRESH_TOKEN)
      expect(result.session.userId).toBe('admin-1')
    })

    // Verifies that platform grace-window rotation writes ONLY a new prt: session — never a
    // new prp: grace pointer. Single-shot grace semantics prevent indefinite session extension
    // from a captured refresh token (matches dashboard-side `rt:` / `rp:` behavior).
    it('should write only a new prt: session (no new prp: pointer) on grace-window rotation', async () => {
      armPlatformGraceRotation()

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      expect(mockRedis.writeRecoveredSession).toHaveBeenCalledWith(
        expect.objectContaining({ kind: 'platform', newHash: NEW_HASH })
      )
      const keys = (mockRedis.set.mock.calls as unknown[][]).map((c) => String(c[0]))
      expect(keys.filter((k) => k.startsWith('prp:'))).toHaveLength(0)
      // The display-metadata record is still a loose write: it authenticates nothing, so a
      // revocation racing it costs a listing row and no access.
      expect(keys.filter((k) => k.startsWith('psd:'))).toHaveLength(1)
    })

    // Verifies that REFRESH_TOKEN_INVALID is thrown when the token was never issued.
    it('should throw REFRESH_TOKEN_INVALID when neither prt: session nor prp: grace pointer exists', async () => {
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'invalid' })

      await expect(
        service.reissuePlatformTokens('expired-token', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)

      try {
        await service.reissuePlatformTokens('expired-token-2', '1.2.3.4', 'Browser')
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID })
        })
      }
    })

    // Scenario: a consumed platform token replayed past its grace window is a theft signal.
    // Expected: the platform family is revoked and the request still fails. Why: #38 deferred
    // platform reuse detection entirely, so this is the gap the family design closes.
    it('revokes the platform family when a consumed platform token is replayed', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({
        kind: 'reused',
        familyId: PLATFORM_FAMILY
      })

      await expect(
        service.reissuePlatformTokens('stolen-platform-token', '9.9.9.9', 'Attacker')
      ).rejects.toThrow(AuthException)

      expect(mockRedis.revokeFamily).toHaveBeenCalledWith(PLATFORM_FAMILY, 'platform')
      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).toContain('reuse of a consumed refresh token detected')
      warnSpy.mockRestore()
    })

    // A replayed PLATFORM token is the same evidence of compromise as a dashboard one, against
    // an account that usually holds more authority. The hook has to fire on both planes, or an
    // operator watching for takeover is blind on the half that matters most.
    it('emits onRefreshTokenReuseDetected for a replayed platform token', async () => {
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({
        kind: 'reused',
        familyId: PLATFORM_FAMILY
      })
      mockRedis.revokeFamily.mockResolvedValue({ removed: 2, ownerId: 'admin-1' })

      await expect(
        service.reissuePlatformTokens('stolen-platform-token', '9.9.9.9', 'Attacker')
      ).rejects.toThrow(AuthException)
      await Promise.resolve()

      expect(mockHooks.onRefreshTokenReuseDetected).toHaveBeenCalledWith(
        { userId: 'admin-1', familyId: PLATFORM_FAMILY },
        expect.anything()
      )
    })

    // Scenario: platform primary rotation rewrites the per-admin SET — remove old prt:, add new
    // prt: and the prp: grace pointer, then expire the SET with the refresh TTL (days*86400).
    // Why: kills the StringLiteral mutants on each key/member and the `* 86_400` arithmetic mutant.
    it('updates the psess:{adminId} SET with exact keys and TTL on platform primary rotation', async () => {
      const oldHash = sha256('old-platform-refresh')
      armLivePlatformRotation()

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      // The `psess:` membership moved inside the rotation script, on this plane as on the
      // other: maintaining it out here left a window in which a concurrent revoke-all could
      // sweep past the session the rotation was minting. The script is given the plane and
      // the owner; the key-level assertions live in the redis service spec.
      expect(mockRedis.rotateRefreshSession).toHaveBeenCalledWith(
        expect.objectContaining({ kind: 'platform', userId: 'admin-1' })
      )
      // The dashboard index is a different plane with a colliding id space: a platform
      // rotation neither reads it nor writes it.
      const touched = [...mockRedis.sadd.mock.calls, ...mockRedis.srem.mock.calls].map(
        (call) => call[0] as string
      )
      expect(touched).not.toContain('sess:admin-1')
      expect(mockRedis.del).toHaveBeenCalledWith(`psd:${oldHash}`)
    })

    // Scenario: a zero-width grace window writes no `prp:` key, so indexing a `prp:` member for
    // it would leave the platform index pointing at nothing.
    it('indexes no platform grace member when the grace window is zero', async () => {
      const zeroGrace = await Test.createTestingModule({
        providers: [
          TokenManagerService,
          { provide: JwtService, useValue: mockJwtService },
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: {
              ...mockOptions,
              jwt: { ...mockOptions.jwt, refreshGraceWindowSeconds: 0 }
            }
          },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()
      armLivePlatformRotation()

      await zeroGrace
        .get(TokenManagerService)
        .reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      // The zero window is threaded to the script, which is where the guard that decides
      // whether a `prp:` member is indexed now lives.
      expect(mockRedis.rotateRefreshSession).toHaveBeenCalledWith(
        expect.objectContaining({ kind: 'platform', graceTtl: 0 })
      )
    })

    // Scenario: the new platform session record must store an empty tenantId on primary rotation.
    // Why: kills the StringLiteral mutant that passes "Stryker was here!" as the tenantId.
    it('stores an empty tenantId in the rotated platform session on primary rotation', async () => {
      armLivePlatformRotation()

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      const bundle = mockRedis.rotateRefreshSession.mock.calls[0]?.[0] as { newSessionJson: string }
      const session = JSON.parse(bundle.newSessionJson) as Record<string, unknown>
      expect(session['tenantId']).toBe('')
    })

    // Scenario: platform grace-window rotation removes the consumed prp: pointer, adds the new
    // prt:, and expires the SET with the refresh TTL.
    it('updates the psess:{adminId} SET with exact keys and TTL on platform grace-window rotation', async () => {
      const oldHash = sha256('old-platform-refresh')
      armPlatformGraceRotation()

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      expect(mockRedis.srem).toHaveBeenCalledWith('psess:admin-1', `prp:${oldHash}`)
      expect(mockRedis.srem).not.toHaveBeenCalledWith('sess:admin-1', `prp:${oldHash}`)
      // Session, index and family membership are one atomic step.
      expect(mockRedis.writeRecoveredSession).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: 'platform',
          userId: 'admin-1',
          newHash: NEW_HASH,
          familyId: PLATFORM_FAMILY,
          refreshTtl: 7 * 86_400
        })
      )
      // The superseded detail record is dropped by its exact key; a wrong key would leak
      // the old record until TTL and leave a listing describing a token that no longer exists.
      expect(mockRedis.del).toHaveBeenCalledWith(`psd:${oldHash}`)
    })

    // Scenario: the new platform session record must store an empty tenantId on grace-window
    // rotation. Why: kills the StringLiteral mutant on the grace-path buildSession tenantId.
    // The platform twin of the dashboard case, on the plane where the surviving session is
    // the highest-privilege identity in the system.
    it('refuses a platform grace recovery that a concurrent revoke-all swept', async () => {
      armPlatformGraceRotation()
      mockRedis.writeRecoveredSession.mockResolvedValueOnce(false)

      await expect(
        service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID } }
      })
    })

    it('stores an empty tenantId in the rotated platform session on grace-window rotation', async () => {
      armPlatformGraceRotation()

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      const call = mockRedis.writeRecoveredSession.mock.calls[0]?.[0] as {
        newSessionJson: string
      }
      const session = JSON.parse(call.newSessionJson) as Record<string, unknown>
      expect(session['tenantId']).toBe('')
    })

    // Scenario: a platform grace record carrying no family, so there is no index to join.
    it('writes no platform family index when the recovered session names no family', async () => {
      armPlatformGraceRotation(
        JSON.stringify({
          userId: 'admin-1',
          tenantId: '',
          role: 'super-admin',
          device: 'Browser',
          ip: '1.2.3.4',
          mfaEnabled: false,
          createdAt: '2026-01-01T00:00:00.000Z'
        })
      )

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      const addedKeys = (mockRedis.sadd.mock.calls as unknown[][]).map((c) => String(c[0]))
      expect(addedKeys.some((k) => k.startsWith('pfam:'))).toBe(false)
    })

    // Scenario: a rotated platform access token must always carry mfaVerified:false.
    it('issues the rotated platform access token with mfaVerified:false', async () => {
      armLivePlatformRotation()

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      const signCall = mockJwtService.sign.mock.calls[0] as [Record<string, unknown>]
      expect(signCall[0]['mfaVerified']).toBe(false)
    })

    // Scenario: when the token was never issued, a warning is logged before throwing.
    it('warns with the no-valid-session message before throwing on platform rotation', async () => {
      const warnSpy = jest.spyOn(service['logger'], 'warn').mockImplementation(() => undefined)
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({ kind: 'invalid' })

      await expect(
        service.reissuePlatformTokens('gone-platform-token', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
      expect(warnSpy).toHaveBeenCalledWith(
        'reissuePlatformTokens: no valid session or grace window found — REFRESH_TOKEN_INVALID'
      )
      warnSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // The MFA flag is required on a stored session
  // ---------------------------------------------------------------------------

  describe('stored session integrity', () => {
    // Scenario: a session record with no `mfaEnabled`. Expected: the rotation refuses it.
    // Why: defaulting the missing value to `false` would turn a truncated or corrupt record
    // into a silent second-factor bypass — the gate refuses only a token whose claims say
    // `mfaEnabled && !mfaVerified`, so an absent field reads as "no second factor here" and the
    // rotated token clears every MFA-gated route. Refusing costs the holder a login; defaulting
    // costs the account.
    //
    // The check reads the record where the rotation first touches it — the seed read of
    // `rt:{oldHash}`, which is the same key the script consumes. A record that fails here
    // never reaches the script, and a record the script consumed on the live path must have
    // passed here, because that path is unreachable unless this read found the session.
    // …and the same for the two fields the rotated token's CLAIMS are built from. A record
    // missing `userId` mints a token for nobody; one missing `role` mints a token whose
    // authorization claim is `undefined`, which every role check then compares against.
    it.each([
      ['userId', { tenantId: 't1', role: 'member', mfaEnabled: false }],
      ['role', { userId: 'user-1', tenantId: 't1', mfaEnabled: false }]
    ])('should refuse a session record with no %s', async (_field, record) => {
      mockRedis.get.mockResolvedValue(
        JSON.stringify({
          ...record,
          device: 'Browser',
          ip: '1.2.3.4',
          createdAt: '2026-01-01T00:00:00.000Z'
        })
      )

      await expect(
        service.reissueTokens('raw-refresh-token', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
      expect(mockRedis.rotateRefreshSession).not.toHaveBeenCalled()
    })

    it('should refuse a session record with no mfaEnabled flag', async () => {
      mockRedis.get.mockResolvedValue(
        JSON.stringify({
          userId: 'user-1',
          tenantId: 'tenant-1',
          role: 'member',
          device: 'Browser',
          ip: '1.2.3.4',
          createdAt: '2026-01-01T00:00:00.000Z'
        })
      )

      await expect(
        service.reissueTokens('raw-refresh-token', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
      // …and it refused before the rotation ran, so the token was never consumed.
      expect(mockRedis.rotateRefreshSession).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // verifyIgnoringExpiry / verifyPlatformIgnoringExpiry
  // ---------------------------------------------------------------------------

  describe('verifying while ignoring expiry', () => {
    // Exactly one caller wants this: logout. An access token that expired while the user was
    // away is the normal case there, and refusing would leave the refresh session — the
    // long-lived credential logout exists to kill — alive for its whole lifetime.
    //
    // But the SIGNATURE still has to hold. The payload's `jti` decides which token gets
    // blacklisted, so reading it unverified would let a caller revoke an access token they do
    // not own by naming its id. These assert both halves: expiry waived, verification not.
    it.each([
      ['dashboard', (svc: TokenManagerService, token: string) => svc.verifyIgnoringExpiry(token)],
      [
        'platform',
        (svc: TokenManagerService, token: string) => svc.verifyPlatformIgnoringExpiry(token)
      ]
    ])('waives expiry on the %s plane while still verifying the signature', (_plane, call) => {
      mockJwtService.verify.mockReturnValue({ sub: 'user-1', jti: 'jti-1' })

      expect(call(service, 'expired.but.signed')).toMatchObject({ jti: 'jti-1' })

      // The waiver is explicit and scoped to this call — every other verification in the
      // service keeps checking expiry, which is what makes this one safe to have at all.
      expect(mockJwtService.verify).toHaveBeenCalledWith(
        'expired.but.signed',
        expect.objectContaining({ ignoreExpiration: true })
      )
    })

    it.each([
      ['dashboard', (svc: TokenManagerService, token: string) => svc.verifyIgnoringExpiry(token)],
      [
        'platform',
        (svc: TokenManagerService, token: string) => svc.verifyPlatformIgnoringExpiry(token)
      ]
    ])('still refuses a %s token no configured secret accepts', (_plane, call) => {
      mockJwtService.verify.mockImplementation(() => {
        throw new Error('invalid signature')
      })

      expect(() => call(service, 'forged.token')).toThrow()
    })
  })

  // ---------------------------------------------------------------------------
  // iss / aud stamping
  // ---------------------------------------------------------------------------

  describe('issuer and audience stamping', () => {
    /** A service whose options bind the pair. */
    async function bindingService(binding: {
      issuer?: string
      audience?: string
    }): Promise<TokenManagerService> {
      const module = await Test.createTestingModule({
        providers: [
          TokenManagerService,
          { provide: JwtService, useValue: mockJwtService },
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: { ...mockOptions, jwt: { ...mockOptions.jwt, ...binding } }
          },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()
      return module.get(TokenManagerService)
    }

    // Absent by default, so an existing deployment mints exactly the tokens it did before.
    it('stamps neither when the deployment configured neither', async () => {
      await service.issueTokens(SAFE_USER, '1.2.3.4', 'Browser')

      const [, signOptions] = mockJwtService.sign.mock.calls[0] as [
        unknown,
        Record<string, unknown>
      ]
      // Key ABSENT, not present-and-undefined. `jsonwebtoken` validates sign options by type
      // and throws `"issuer" must be a string` on an explicit `undefined`, so an unbound
      // deployment that passed the key through would fail to mint any token at all — which is
      // exactly what the end-to-end suite caught when this was written the other way.
      expect(signOptions).not.toHaveProperty('issuer')
      expect(signOptions).not.toHaveProperty('audience')
    })

    // …and stamps both when it did. The claim has to be ON the token, or the verifier that
    // requires it rejects the backend's own output.
    it('stamps both on the access token when configured', async () => {
      const bound = await bindingService({ issuer: 'bymax', audience: 'dashboard' })

      await bound.issueTokens(SAFE_USER, '1.2.3.4', 'Browser')

      const [, signOptions] = mockJwtService.sign.mock.calls[0] as [
        unknown,
        Record<string, unknown>
      ]
      expect(signOptions).toMatchObject({ issuer: 'bymax', audience: 'dashboard' })
    })

    // The MFA challenge token is stamped like every other. It grants no resource access on its
    // own, but a shape the verifier exempted would be a shape an attacker aims at.
    it('stamps the MFA challenge token too', async () => {
      const bound = await bindingService({ issuer: 'bymax', audience: 'dashboard' })
      mockRedis.set.mockResolvedValue(undefined)

      await bound.issueMfaTempToken('user-1', 'dashboard', 'tenant-1')

      const [, signOptions] = mockJwtService.sign.mock.calls.at(-1) as [
        unknown,
        Record<string, unknown>
      ]
      expect(signOptions).toMatchObject({ issuer: 'bymax', audience: 'dashboard' })
    })

    // An empty value is read as unconfigured rather than as "stamp the empty issuer": a
    // consumer threading an unset environment variable through must not silently turn the
    // check on and start minting tokens their own verifier rejects.
    // The empty-value case is decided by `resolveOptions` and asserted there: by the time a
    // value reaches this service it is either a real binding or absent, and re-testing the
    // normalization here would pin it in a second place that could disagree with the first.
  })

  // ---------------------------------------------------------------------------
  // Reuse detection carries an identity into the log
  // ---------------------------------------------------------------------------

  describe('reuse-detection logging', () => {
    // Scenario: a consumed refresh token presented again. Expected: the log names the account
    // and the lineage, on both planes. Why: this is the strongest compromise signal the
    // library produces — a token that was already exchanged has been presented a second time,
    // so one of its two holders is not the owner — and it used to be logged as bare prose.
    // The account reached only a consumer who had wired `onRefreshTokenReuseDetected`, and the
    // shipped hooks are no-ops, so on a default deployment the one unambiguous theft signal
    // was anonymous in the log and absent everywhere else. An operator could tell that
    // something happened and not to whom (ASVS 16.2.1).
    it.each([
      ['dashboard', 'rt', 'reissueTokens'],
      ['platform', 'prt', 'reissuePlatformTokens']
    ])('names the owner and the family on the %s plane', async (plane, prefix, method) => {
      const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {})
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({
        kind: 'reused',
        familyId: 'fam-stolen'
      })
      mockRedis.revokeFamily.mockResolvedValue({ ownerId: 'user-compromised', count: 3 })

      try {
        const call =
          plane === 'dashboard'
            ? service.reissueTokens(FIXED_REFRESH_TOKEN, '1.2.3.4', 'Chrome')
            : service.reissuePlatformTokens(FIXED_REFRESH_TOKEN, '1.2.3.4', 'Chrome')
        await expect(call).rejects.toThrow(AuthException)

        const lines = warn.mock.calls.map((args) => String(args[0]))
        const named = lines.filter(
          (line) => line.includes('user-compromised') && line.includes('fam-stolen')
        )
        expect(named.length).toBeGreaterThan(0)
        expect(named.join(' ')).toContain(method)

        // The detection is logged BEFORE the revocation and the owner AFTER it, so a
        // `revokeFamily` that throws cannot take the finding down with it.
        expect(lines.filter((line) => line.includes('fam-stolen')).length).toBe(2)
      } finally {
        warn.mockRestore()
        expect(prefix).toBeTruthy()
      }
    })

    // The finding survives a failed response. Losing the log because the revocation could not
    // complete would leave an operator with no record of the one event they most need.
    it('still records the detection when the family revocation fails', async () => {
      const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {})
      mockRedis.get.mockResolvedValue(null)
      mockRedis.rotateRefreshSession.mockResolvedValue({
        kind: 'reused',
        familyId: 'fam-stolen'
      })
      mockRedis.revokeFamily.mockRejectedValue(new Error('redis down'))

      try {
        await expect(
          service.reissueTokens(FIXED_REFRESH_TOKEN, '1.2.3.4', 'Chrome')
        ).rejects.toThrow('redis down')

        const lines = warn.mock.calls.map((args) => String(args[0]))
        expect(lines.some((line) => line.includes('fam-stolen'))).toBe(true)
      } finally {
        warn.mockRestore()
      }
    })
  })
})
