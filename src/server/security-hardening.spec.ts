/**
 * @fileoverview Adversarial suite — attacks the library the way an attacker would.
 *
 * Unlike the co-located unit specs, nothing here mocks the primitive under attack. Tokens
 * are forged with real `node:crypto` and pushed through the real guards, so a regression in
 * signature handling, algorithm pinning, or token-type separation fails here even if every
 * unit test still passes against its mocks.
 *
 * Each block names the attack it defends and states what a pass actually proves. These are
 * regression tests for security properties, not coverage filler: if one starts failing, the
 * library has an exploitable hole, not a stale assertion.
 */

import { createHmac } from 'node:crypto'

import { Reflector } from '@nestjs/core'
import { JwtService } from '@nestjs/jwt'

import { BYMAX_AUTH_OPTIONS } from './bymax-auth.constants'
import { hmacSha256 } from './crypto/secure-token'
import { AuthException } from './errors/auth-exception'
import { JwtAuthGuard } from './guards/jwt-auth.guard'
import { JwtPlatformGuard } from './guards/jwt-platform.guard'
import { AuthRedisService } from './redis/auth-redis.service'
import { TokenDeliveryService } from './services/token-delivery.service'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** TEST FIXTURE ONLY — never a real secret. */
const JWT_SECRET = 'adversarial-suite-jwt-secret-32ch'

const VALID_JTI = '11111111-1111-4111-8111-111111111111'

/** base64url without padding — the JWT segment encoding. */
function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url')
}

/**
 * Hand-assembles a JWT so a test can forge headers the library's own signer would never
 * emit (`alg: none`, a swapped algorithm, a stripped signature).
 */
function forgeJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signature: string
): string {
  return `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}.${signature}`
}

/** A well-formed dashboard payload; individual tests override the parts they attack. */
function dashboardPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000)
  return {
    sub: 'user-1',
    tenantId: 'tenant-1',
    role: 'member',
    type: 'dashboard',
    status: 'active',
    mfaEnabled: false,
    mfaVerified: false,
    jti: VALID_JTI,
    iat: now,
    exp: now + 900,
    ...overrides
  }
}

const options = {
  jwt: {
    secret: JWT_SECRET,
    algorithm: 'HS256' as const,
    accessExpiresIn: '15m',
    refreshExpiresInDays: 7,
    accessCookieMaxAgeMs: 900_000
  },
  hmacKey: hmacSha256('irrelevant', JWT_SECRET),
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED'],
  cookies: { accessTokenName: 'access_token', refreshTokenName: 'refresh_token' },
  tokenDelivery: 'bearer'
}

/** Redis double that reports nothing revoked and no cutoff — the permissive baseline. */
const permissiveRedis = {
  get: jest.fn().mockResolvedValue(null),
  getUserTokenCutoff: jest.fn().mockResolvedValue(null)
}

/** Stand-ins for the decorated route the Reflector reads metadata from. */
class AttackedController {}
function attackedHandler(): void {}

/** Builds an ExecutionContext carrying a bearer token. */
function contextWithToken(token: string) {
  const request = { headers: { authorization: `Bearer ${token}` }, cookies: {} }
  return {
    switchToHttp: () => ({ getRequest: () => request }),
    getHandler: () => attackedHandler,
    getClass: () => AttackedController
  } as never
}

/** Asserts the guard refuses the token rather than admitting the request. */
async function expectRefused(
  guard: { canActivate: (c: never) => Promise<boolean> },
  token: string
) {
  await expect(guard.canActivate(contextWithToken(token))).rejects.toBeInstanceOf(AuthException)
}

describe('security hardening — adversarial', () => {
  let jwtService: JwtService
  let dashboardGuard: JwtAuthGuard
  let platformGuard: JwtPlatformGuard

  beforeEach(() => {
    jest.clearAllMocks()
    permissiveRedis.get.mockResolvedValue(null)
    permissiveRedis.getUserTokenCutoff.mockResolvedValue(null)

    jwtService = new JwtService({ secret: JWT_SECRET })
    const delivery = new TokenDeliveryService(options as never)
    dashboardGuard = new JwtAuthGuard(
      jwtService,
      delivery,
      permissiveRedis as unknown as AuthRedisService,
      new Reflector(),
      options as never
    )
    platformGuard = new JwtPlatformGuard(
      jwtService,
      delivery,
      permissiveRedis as unknown as AuthRedisService,
      new Reflector(),
      options as never
    )
  })

  // -------------------------------------------------------------------------
  // Algorithm confusion (CVE-2015-9235)
  // -------------------------------------------------------------------------

  describe('signature forgery', () => {
    // The classic JWT break: declare `alg: none` and drop the signature. A verifier that
    // trusts the header's algorithm accepts it. Passing proves the algorithm is pinned by
    // the verifier, not chosen by the token.
    it('rejects an unsigned alg:none token whose claims are otherwise perfect', async () => {
      const forged = forgeJwt({ alg: 'none', typ: 'JWT' }, dashboardPayload(), '')

      await expectRefused(dashboardGuard, forged)
    })

    // The same attack with a signature-shaped suffix, in case a verifier only checks that
    // the third segment is non-empty.
    it('rejects alg:none even when a junk signature segment is attached', async () => {
      const forged = forgeJwt({ alg: 'none', typ: 'JWT' }, dashboardPayload(), 'not-a-signature')

      await expectRefused(dashboardGuard, forged)
    })

    // Algorithm substitution: sign with HS512 while the deployment pins HS256. Accepting it
    // would mean the header dictates verification, which is the same class of hole.
    it('rejects a token signed with an algorithm the deployment does not pin', async () => {
      const header = { alg: 'HS512', typ: 'JWT' }
      const payload = dashboardPayload()
      const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`
      const signature = createHmac('sha512', JWT_SECRET).update(signingInput).digest('base64url')

      await expectRefused(dashboardGuard, forgeJwt(header, payload, signature))
    })

    // A token signed with the wrong key must not verify. This is the baseline guarantee
    // every other check rests on.
    it('rejects a correctly-shaped token signed with a different secret', async () => {
      const attacker = new JwtService({ secret: 'a-completely-different-secret-32b' })

      await expectRefused(dashboardGuard, attacker.sign(dashboardPayload()))
    })

    // Claim tampering: take a legitimately signed token and rewrite a claim without
    // re-signing. The signature must fail over the mutated payload.
    it('rejects a valid token whose payload was edited in place', async () => {
      const legitimate = jwtService.sign(dashboardPayload({ role: 'member' }))
      const [header, , signature] = legitimate.split('.')
      const escalated = b64url(JSON.stringify(dashboardPayload({ role: 'admin' })))

      await expectRefused(dashboardGuard, `${header}.${escalated}.${signature}`)
    })
  })

  // -------------------------------------------------------------------------
  // Token-type confusion across identity planes
  // -------------------------------------------------------------------------

  describe('token-type confusion', () => {
    // A platform token is signed with the same secret as a dashboard token, so only the
    // `type` claim separates the planes. If the dashboard guard ignored it, an operator
    // token would authenticate as a tenant user and vice versa.
    it('rejects a platform token presented to the dashboard guard', async () => {
      const platformToken = jwtService.sign(
        dashboardPayload({ type: 'platform', role: 'super_admin' })
      )

      await expectRefused(dashboardGuard, platformToken)
    })

    // The mirror direction: a tenant user must not reach a platform-guarded route by
    // presenting their own perfectly valid token.
    it('rejects a dashboard token presented to the platform guard', async () => {
      await expectRefused(platformGuard, jwtService.sign(dashboardPayload()))
    })

    // The MFA temp token is issued BEFORE the second factor is proven. If it satisfied an
    // access guard, MFA would be optional: log in, ignore the challenge, use the temp token.
    it('rejects an MFA temp token used as an access token', async () => {
      const tempToken = jwtService.sign(
        dashboardPayload({ type: 'mfa_temp', context: 'dashboard' })
      )

      await expectRefused(dashboardGuard, tempToken)
      await expectRefused(platformGuard, tempToken)
    })

    // A token with no `type` at all must not default into either plane.
    it('rejects a token carrying no type claim', async () => {
      const payload = dashboardPayload()
      delete payload['type']

      await expectRefused(dashboardGuard, jwtService.sign(payload))
    })
  })

  // -------------------------------------------------------------------------
  // Revocation cannot be dodged by malforming the token
  // -------------------------------------------------------------------------

  describe('revocation evasion', () => {
    // Revocation is keyed by `jti`. A token with no jti has no revocation key, so accepting
    // one would hand out a session that logout can never kill.
    it('rejects a token with no jti, which would be unrevocable', async () => {
      const payload = dashboardPayload()
      delete payload['jti']

      await expectRefused(dashboardGuard, jwtService.sign(payload))
    })

    // A jti that is not a UUID would land outside the `rv:` key shape the revocation check
    // reads, so a crafted value could miss its own blacklist entry.
    it('rejects a token whose jti is not a well-formed UUID', async () => {
      await expectRefused(dashboardGuard, jwtService.sign(dashboardPayload({ jti: '../../etc' })))
    })

    // The bulk cutoff compares `iat` against a per-user timestamp. A token signed without
    // `iat` would make that comparison silently false and slip past a password reset.
    it('rejects a token with no iat when a bulk cutoff is active', async () => {
      permissiveRedis.getUserTokenCutoff.mockResolvedValue(Math.floor(Date.now() / 1000))
      const payload = dashboardPayload()
      delete payload['iat']

      await expectRefused(dashboardGuard, jwtService.sign(payload, { noTimestamp: true }))
    })

    // Same evasion with a non-numeric iat, which would also defeat the `<` comparison. This
    // one is hand-signed rather than produced by the library: its own signer refuses a
    // non-numeric `iat`, but the guard must not rely on that. Any other signer holding the
    // deployment secret — a sibling service, an older library version — could emit one, and
    // the guard is the component that has to refuse it.
    it('rejects a token whose iat is not a finite number when a cutoff is active', async () => {
      permissiveRedis.getUserTokenCutoff.mockResolvedValue(Math.floor(Date.now() / 1000))
      const header = { alg: 'HS256', typ: 'JWT' }
      const payload = dashboardPayload({ iat: 'not-a-number' })
      const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`
      const signature = createHmac('sha256', JWT_SECRET).update(signingInput).digest('base64url')

      await expectRefused(dashboardGuard, forgeJwt(header, payload, signature))
    })

    // An empty sub keys `sess:` and the HMAC pre-images. Admitting it would let one
    // degenerate token share a key space with every other empty-sub token.
    it('rejects a token with an empty sub', async () => {
      await expectRefused(dashboardGuard, jwtService.sign(dashboardPayload({ sub: '' })))
    })
  })

  // -------------------------------------------------------------------------
  // Redis key injection
  // -------------------------------------------------------------------------

  describe('key-space injection', () => {
    // Identifiers that reach Redis keys are HMAC'd, never interpolated raw. This proves an
    // address carrying the key separator or CRLF cannot escape its own key and collide with,
    // or overwrite, another account's — the derived value is fixed-width hex whatever goes in.
    it.each([
      'victim@example.com:extra',
      'a@b.com\r\nSET evil 1',
      '../../../etc/passwd',
      'x'.repeat(4096)
    ])('derives a fixed-width hex identifier for the hostile input %#', (hostile) => {
      const identifier = hmacSha256(`tenant-1:${hostile}`, JWT_SECRET)

      expect(identifier).toMatch(/^[0-9a-f]{64}$/)
    })

    // Two different hostile inputs must not collapse to the same identifier — otherwise one
    // account's lockout would apply to another's.
    it('never collides two distinct hostile identifiers', () => {
      const first = hmacSha256('tenant-1:a@b.com:x', JWT_SECRET)
      const second = hmacSha256('tenant-1:a@b.com', JWT_SECRET)

      expect(first).not.toBe(second)
    })

    // The tenant/email separator must bind: 'tenantAB' + 'c@x' and 'tenantA' + 'Bc@x' are
    // different accounts and must stay different keys, or a crafted tenant id would let one
    // tenant consume another's lockout budget.
    it('resists prefix-collision across the tenant separator', () => {
      const shifted = hmacSha256('tenantAB:c@x.com', JWT_SECRET)
      const original = hmacSha256('tenantA:Bc@x.com', JWT_SECRET)

      expect(shifted).not.toBe(original)
    })
  })
})
