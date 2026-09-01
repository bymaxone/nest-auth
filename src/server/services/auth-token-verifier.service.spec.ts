/**
 * @fileoverview Tests for AuthTokenVerifierService — the one call that performs the whole
 * identity chain a guarded HTTP route performs.
 *
 * Each check gets a test that fails ONLY that check while every other one passes, so a test
 * proves the step it names rather than passing because something earlier refused first. The
 * ordering tests are the other half: they pin which refusal wins when two apply at once, because
 * a caller branches on the code it receives.
 */

import { Test } from '@nestjs/testing'
import { JwtService } from '@nestjs/jwt'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AccountStatusService } from './account-status.service'
import { AuthRevocationService } from './auth-revocation.service'
import { AuthTokenVerifierService } from './auth-token-verifier.service'
import type { VerifyAccessTokenOptions } from './auth-token-verifier.service'

/** Extracts the canonical error code from a thrown AuthException response body. */
function errorCodeOf(err: unknown): string {
  const body = (err as AuthException).getResponse() as { error: { code: string } }
  return body.error.code
}

// A syntactically valid UUID v4, which `assertValidJti` requires.
const JTI = '3f2504e0-4f89-41d3-9a0c-0305e82c3301'

const DASHBOARD_PAYLOAD = {
  jti: JTI,
  sub: 'user-1',
  tenantId: 'tenant-1',
  role: 'member',
  type: 'dashboard',
  status: 'active',
  mfaEnabled: false,
  mfaVerified: false,
  epoch: 1,
  iat: 1,
  exp: 2
}

const PLATFORM_PAYLOAD = {
  jti: JTI,
  sub: 'admin-1',
  role: 'super_admin',
  type: 'platform',
  mfaEnabled: false,
  mfaVerified: false,
  epoch: 1,
  iat: 1,
  exp: 2
}

const mockJwt = { verify: jest.fn() }
const mockRevocation = { isAccessTokenRevoked: jest.fn() }
const mockAccountStatus = {
  assertDashboardAccountUsable: jest.fn(),
  assertPlatformAccountUsable: jest.fn()
}

const mockOptions = {
  jwt: { algorithm: 'HS256', issuer: 'iss', audience: 'aud', previousSecrets: [] }
}

/** Builds a verifier over the shared doubles. */
async function buildVerifier(): Promise<AuthTokenVerifierService> {
  const module = await Test.createTestingModule({
    providers: [
      AuthTokenVerifierService,
      { provide: JwtService, useValue: mockJwt },
      { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
      { provide: AuthRevocationService, useValue: mockRevocation },
      { provide: AccountStatusService, useValue: mockAccountStatus }
    ]
  }).compile()
  return module.get(AuthTokenVerifierService)
}

describe('AuthTokenVerifierService', () => {
  let verifier: AuthTokenVerifierService

  beforeEach(async () => {
    jest.clearAllMocks()
    // The default world is one where every check passes; each test breaks exactly one.
    mockJwt.verify.mockReturnValue({ ...DASHBOARD_PAYLOAD })
    mockRevocation.isAccessTokenRevoked.mockResolvedValue(false)
    mockAccountStatus.assertDashboardAccountUsable.mockResolvedValue(undefined)
    mockAccountStatus.assertPlatformAccountUsable.mockResolvedValue(undefined)
    verifier = await buildVerifier()
  })

  // -------------------------------------------------------------------------
  // The happy paths
  // -------------------------------------------------------------------------

  // A fully valid dashboard token returns its payload tagged with the plane, and every optional
  // check runs by default — a caller that passes only `plane` must get the strict behaviour.
  it('returns the dashboard payload tagged with its plane, running both optional checks', async () => {
    const result = await verifier.verifyAccessToken('tok', { plane: 'dashboard' })

    expect(result).toEqual({ plane: 'dashboard', payload: DASHBOARD_PAYLOAD })
    expect(mockRevocation.isAccessTokenRevoked).toHaveBeenCalledWith(DASHBOARD_PAYLOAD, 'dashboard')
    expect(mockAccountStatus.assertDashboardAccountUsable).toHaveBeenCalledWith({
      userId: 'user-1',
      tenantId: 'tenant-1'
    })
  })

  // The platform arm asks the revocation service for the PLATFORM epoch namespace and the platform
  // status gate. Passing the dashboard namespace would read an epoch nothing ever bumps.
  it('returns the platform payload and consults the platform namespace and status gate', async () => {
    mockJwt.verify.mockReturnValue({ ...PLATFORM_PAYLOAD })

    const result = await verifier.verifyAccessToken('tok', { plane: 'platform' })

    expect(result).toEqual({ plane: 'platform', payload: PLATFORM_PAYLOAD })
    expect(mockRevocation.isAccessTokenRevoked).toHaveBeenCalledWith(PLATFORM_PAYLOAD, 'platform')
    expect(mockAccountStatus.assertPlatformAccountUsable).toHaveBeenCalledWith('admin-1')
    expect(mockAccountStatus.assertDashboardAccountUsable).not.toHaveBeenCalled()
  })

  // The verification is delegated with the pinned algorithm and the configured binding claims —
  // this is what refuses `alg: none` and a token carrying no issuer.
  it('verifies under the pinned algorithm and the configured issuer and audience', async () => {
    await verifier.verifyAccessToken('tok', { plane: 'dashboard' })

    expect(mockJwt.verify).toHaveBeenCalledWith('tok', {
      algorithms: ['HS256'],
      ignoreExpiration: false,
      issuer: 'iss',
      audience: 'aud'
    })
  })

  // -------------------------------------------------------------------------
  // Each refusal, isolated
  // -------------------------------------------------------------------------

  // A signature, algorithm, binding-claim or expiry failure collapses to one opaque refusal:
  // naming which one failed tells a forger which part of the token to fix.
  it('answers TOKEN_INVALID when the signature or expiry is refused', async () => {
    mockJwt.verify.mockImplementation(() => {
      throw new Error('jwt expired')
    })
    const thrown = await verifier
      .verifyAccessToken('tok', { plane: 'dashboard' })
      .catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
  })

  // The claim-shape assertions run on a token that is otherwise entirely valid. These values
  // become Redis keys downstream, so a malformed one builds a key nobody intended.
  it.each([
    ['a malformed jti', { jti: 'not-a-uuid' }],
    ['an empty sub', { sub: '' }],
    ['a missing tenantId', { tenantId: undefined }]
  ])('answers TOKEN_INVALID for %s', async (_label, overlay) => {
    mockJwt.verify.mockReturnValue({ ...DASHBOARD_PAYLOAD, ...overlay })
    const thrown = await verifier
      .verifyAccessToken('tok', { plane: 'dashboard' })
      .catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
  })

  // The type check is what stops a half-credential being read as a session: an `mfa_challenge`
  // token is signed with the SAME secret and would otherwise pass every check above it.
  it.each(['platform', 'mfa_challenge'])(
    'refuses a %s token presented on the dashboard plane',
    async (type) => {
      mockJwt.verify.mockReturnValue({ ...DASHBOARD_PAYLOAD, type })
      const thrown = await verifier
        .verifyAccessToken('tok', { plane: 'dashboard' })
        .catch((e: unknown) => e)
      expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
      // Refused before the store is consulted — a token of the wrong type is not a lookup to make.
      expect(mockRevocation.isAccessTokenRevoked).not.toHaveBeenCalled()
    }
  )

  // The same shapes on the PLATFORM arm, which carries its own copies of the two assertions.
  // Without these the dashboard tests above prove nothing about it: deleting either call from the
  // platform arm leaves every dashboard test green, so a platform `jti` of any shape would reach
  // the `rv:{jti}` key untested. There is no tenant row here — a platform token carries none.
  it.each([
    ['a malformed jti', { jti: 'not-a-uuid' }],
    ['an empty sub', { sub: '' }]
  ])('answers TOKEN_INVALID for %s on the platform plane', async (_label, overlay) => {
    mockJwt.verify.mockReturnValue({ ...PLATFORM_PAYLOAD, ...overlay })
    const thrown = await verifier
      .verifyAccessToken('tok', { plane: 'platform' })
      .catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    // Refused before the store is consulted: a malformed claim is not a lookup to make.
    expect(mockRevocation.isAccessTokenRevoked).not.toHaveBeenCalled()
  })

  // The plane is the CALLER's claim, never the token's: a dashboard token must not open a platform
  // stream by being handed to the platform arm. The code is PLATFORM_AUTH_REQUIRED rather than
  // TOKEN_INVALID, matching what JwtPlatformGuard already answers for the same condition, so a
  // consumer moving a surface off that guard keeps branching on what it branched on before.
  it.each(['dashboard', 'mfa_challenge'])(
    'answers PLATFORM_AUTH_REQUIRED for a %s token on the platform plane',
    async (type) => {
      mockJwt.verify.mockReturnValue({ ...PLATFORM_PAYLOAD, type })
      const thrown = await verifier
        .verifyAccessToken('tok', { plane: 'platform' })
        .catch((e: unknown) => e)
      expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.PLATFORM_AUTH_REQUIRED)
      expect(mockRevocation.isAccessTokenRevoked).not.toHaveBeenCalled()
    }
  )

  // A plane that is neither must REFUSE, not fall through. TypeScript rules the value out; a
  // JavaScript consumer, or one deriving the plane from a namespace segment or an unnarrowed
  // config value, does not. The fall-through arm would be the PLATFORM one — the cross-tenant
  // path — so `'Dashboard'` would verify a real platform token for a connection meant to be
  // tenant-scoped. A TypeError rather than an AuthException: this is the caller's bug, not an
  // authentication outcome, and it must not read as one.
  it.each([['Dashboard'], ['dash'], [undefined]])(
    'throws a TypeError for the plane %p rather than running the platform arm',
    async (plane) => {
      const thrown = await verifier
        .verifyAccessToken('tok', { plane } as unknown as VerifyAccessTokenOptions)
        .catch((e: unknown) => e)
      expect(thrown).toBeInstanceOf(TypeError)
      expect((thrown as TypeError).message).toBe(
        "verifyAccessToken: plane must be 'dashboard' or 'platform'"
      )
      expect(mockRevocation.isAccessTokenRevoked).not.toHaveBeenCalled()
      expect(mockAccountStatus.assertPlatformAccountUsable).not.toHaveBeenCalled()
    }
  )

  // A revoked token is refused on both planes, and as TOKEN_INVALID rather than a distinct code:
  // telling "valid but logged out" from "never valid" is an oracle for no benefit.
  it.each([
    ['dashboard', DASHBOARD_PAYLOAD],
    ['platform', PLATFORM_PAYLOAD]
  ])('answers TOKEN_INVALID for a revoked %s token', async (plane, payload) => {
    mockJwt.verify.mockReturnValue({ ...payload })
    mockRevocation.isAccessTokenRevoked.mockResolvedValue(true)
    const thrown = await verifier
      .verifyAccessToken('tok', { plane: plane as 'dashboard' | 'platform' })
      .catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
  })

  // -------------------------------------------------------------------------
  // MFA policy
  // -------------------------------------------------------------------------

  // The case a reconnect actually hits: a refresh mints `mfaEnabled: true, mfaVerified: false`, so
  // a token that is otherwise entirely valid represents a session that never proved its second
  // factor. MFA_REQUIRED rather than TOKEN_INVALID — the client must complete the challenge, and
  // that is an action, not a dead end.
  it('answers MFA_REQUIRED when MFA is enabled and the token predates the challenge', async () => {
    mockJwt.verify.mockReturnValue({ ...DASHBOARD_PAYLOAD, mfaEnabled: true, mfaVerified: false })
    const thrown = await verifier
      .verifyAccessToken('tok', { plane: 'dashboard' })
      .catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.MFA_REQUIRED)
  })

  // A token issued AFTER the challenge passes.
  it('accepts an MFA-enabled token that was issued after the challenge', async () => {
    mockJwt.verify.mockReturnValue({ ...DASHBOARD_PAYLOAD, mfaEnabled: true, mfaVerified: true })
    await expect(verifier.verifyAccessToken('tok', { plane: 'dashboard' })).resolves.toMatchObject({
      plane: 'dashboard'
    })
  })

  // The policy applies on the platform plane too — a platform administrator's second factor is
  // not weaker than a tenant user's.
  it('applies the MFA policy on the platform plane', async () => {
    mockJwt.verify.mockReturnValue({ ...PLATFORM_PAYLOAD, mfaEnabled: true, mfaVerified: false })
    const thrown = await verifier
      .verifyAccessToken('tok', { plane: 'platform' })
      .catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.MFA_REQUIRED)
  })

  // A payload is cast from a token, so a signed token that simply OMITS `mfaEnabled` would compare
  // `undefined === true`, read as "MFA is off", and pass a gate it was never shown to.
  it('answers TOKEN_INVALID when the mfaEnabled claim is absent or not a boolean', async () => {
    mockJwt.verify.mockReturnValue({ ...DASHBOARD_PAYLOAD, mfaEnabled: undefined })
    const thrown = await verifier
      .verifyAccessToken('tok', { plane: 'dashboard' })
      .catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
  })

  // `requireMfa: false` skips the policy entirely, for a caller that established the fact by
  // another route. Covered on BOTH planes: the two arms carry their own copy of the branch, so a
  // dashboard-only test leaves the platform one free to stop honouring the flag.
  it.each([
    ['dashboard', DASHBOARD_PAYLOAD, 'assertDashboardAccountUsable'],
    ['platform', PLATFORM_PAYLOAD, 'assertPlatformAccountUsable']
  ] as const)(
    'skips the MFA policy on the %s plane when requireMfa is false, keeping every other check',
    async (plane, payload, method) => {
      mockJwt.verify.mockReturnValue({ ...payload, mfaEnabled: true, mfaVerified: false })

      await expect(
        verifier.verifyAccessToken('tok', { plane, requireMfa: false })
      ).resolves.toMatchObject({ plane })

      expect(mockRevocation.isAccessTokenRevoked).toHaveBeenCalledTimes(1)
      expect(mockAccountStatus[method]).toHaveBeenCalledTimes(1)
    }
  )

  // -------------------------------------------------------------------------
  // Account status
  // -------------------------------------------------------------------------

  // The one check whose answer changes while a stream is open: a suspension landing between two
  // reconnects. Its refusal propagates with the code that names it, not flattened to TOKEN_INVALID.
  it.each([
    ['dashboard', DASHBOARD_PAYLOAD, 'assertDashboardAccountUsable'],
    ['platform', PLATFORM_PAYLOAD, 'assertPlatformAccountUsable']
  ] as const)(
    'propagates a blocked-account refusal on the %s plane',
    async (plane, payload, method) => {
      mockJwt.verify.mockReturnValue({ ...payload })
      mockAccountStatus[method].mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.ACCOUNT_SUSPENDED)
      )
      const thrown = await verifier.verifyAccessToken('tok', { plane }).catch((e: unknown) => e)
      expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.ACCOUNT_SUSPENDED)
    }
  )

  // `checkStatus: false` is the only way to avoid the store read, and it must not disable anything
  // else — a caller trading freshness for cost still gets every token-level check.
  it.each([
    ['dashboard', DASHBOARD_PAYLOAD, 'assertDashboardAccountUsable'],
    ['platform', PLATFORM_PAYLOAD, 'assertPlatformAccountUsable']
  ] as const)(
    'skips the %s status read when checkStatus is false, keeping every other check',
    async (plane, payload, method) => {
      mockJwt.verify.mockReturnValue({ ...payload })

      await expect(
        verifier.verifyAccessToken('tok', { plane, checkStatus: false })
      ).resolves.toMatchObject({ plane })

      expect(mockAccountStatus[method]).not.toHaveBeenCalled()
      expect(mockRevocation.isAccessTokenRevoked).toHaveBeenCalledTimes(1)
    }
  )

  // -------------------------------------------------------------------------
  // Ordering — which refusal wins when two apply
  // -------------------------------------------------------------------------

  // Revocation is consulted before the account is. A revoked token answers TOKEN_INVALID even
  // though the account behind it is also blocked, and the status store is never read — the
  // cheaper, already-decided refusal comes first.
  it('refuses a revoked token before consulting the account status', async () => {
    mockRevocation.isAccessTokenRevoked.mockResolvedValue(true)
    mockAccountStatus.assertDashboardAccountUsable.mockRejectedValue(
      new AuthException(AUTH_ERROR_CODES.ACCOUNT_BANNED)
    )

    const thrown = await verifier
      .verifyAccessToken('tok', { plane: 'dashboard' })
      .catch((e: unknown) => e)

    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    expect(mockAccountStatus.assertDashboardAccountUsable).not.toHaveBeenCalled()
  })

  // MFA is decided before the account is read: the challenge is answerable from the payload alone,
  // so a token needing it costs no store round trip.
  it('answers MFA_REQUIRED before consulting the account status', async () => {
    mockJwt.verify.mockReturnValue({ ...DASHBOARD_PAYLOAD, mfaEnabled: true, mfaVerified: false })
    mockAccountStatus.assertDashboardAccountUsable.mockRejectedValue(
      new AuthException(AUTH_ERROR_CODES.ACCOUNT_BANNED)
    )

    const thrown = await verifier
      .verifyAccessToken('tok', { plane: 'dashboard' })
      .catch((e: unknown) => e)

    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.MFA_REQUIRED)
    expect(mockAccountStatus.assertDashboardAccountUsable).not.toHaveBeenCalled()
  })
})
