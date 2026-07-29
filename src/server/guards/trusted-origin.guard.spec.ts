/**
 * @fileoverview Tests for TrustedOriginGuard — the CSRF check that only matters when the
 * deployment opts into `SameSite=None` and the browser therefore sends the session cookie on
 * cross-site requests.
 */

import { Test } from '@nestjs/testing'
import type { ExecutionContext } from '@nestjs/common'

import {
  AUTH_ACCESS_COOKIE_NAME,
  AUTH_HAS_SESSION_COOKIE_NAME,
  AUTH_REFRESH_COOKIE_NAME
} from '../../shared/constants/cookie-defaults'
import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { TrustedOriginGuard } from './trusted-origin.guard'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const TRUSTED = 'https://app.example.com'

const mockOptions = {
  cookies: {
    sameSite: 'none',
    trustedOrigins: [TRUSTED],
    accessTokenName: AUTH_ACCESS_COOKIE_NAME,
    refreshTokenName: AUTH_REFRESH_COOKIE_NAME
  }
}

/** A request shape carrying only what the guard reads. */
interface RequestShape {
  method?: string
  headers?: Record<string, string | undefined>
  cookies?: unknown
}

/** Wrap a request in the minimal ExecutionContext the guard touches. */
function contextFor(request: RequestShape): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => request })
  } as unknown as ExecutionContext
}

/** The context of a state-changing request that carries the session cookie. */
function cookieBearingPost(headers: Record<string, string | undefined> = {}): ExecutionContext {
  return contextFor({ method: 'POST', headers, cookies: { [AUTH_ACCESS_COOKIE_NAME]: 'a_1' } })
}

/** The error code the guard raises, read off a thrown AuthException. */
function codeOf(error: unknown): string {
  const body = (error as AuthException).getResponse() as { error: { code: string } }
  return body.error.code
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

/** A guard over the given options, for the cases that need a non-default cookie config. */
async function buildGuard(options: unknown): Promise<TrustedOriginGuard> {
  const module = await Test.createTestingModule({
    providers: [TrustedOriginGuard, { provide: BYMAX_AUTH_OPTIONS, useValue: options }]
  }).compile()
  return module.get(TrustedOriginGuard)
}

describe('TrustedOriginGuard', () => {
  let guard: TrustedOriginGuard

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      providers: [TrustedOriginGuard, { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions }]
    }).compile()

    guard = module.get(TrustedOriginGuard)
  })

  describe('requests it never blocks', () => {
    // A safe method changes nothing, so it is not a CSRF target. OPTIONS in particular must
    // pass: blocking the preflight would fail every cross-origin call before the real request.
    it.each(['GET', 'HEAD', 'OPTIONS'])('allows %s regardless of origin', (method) => {
      const context = contextFor({
        method,
        headers: { origin: 'https://evil.example.com', 'sec-fetch-site': 'cross-site' },
        cookies: { [AUTH_ACCESS_COOKIE_NAME]: 'a_1' }
      })

      expect(guard.canActivate(context)).toBe(true)
    })

    // A bearer-token client has no ambient credential for an attacker page to spend: the token
    // travels in a header the page cannot set on a cross-site request. Blocking it would break
    // every non-browser caller for no security gain.
    it('allows a cross-site POST that carries no auth cookie', () => {
      const context = contextFor({
        method: 'POST',
        headers: { origin: 'https://evil.example.com', 'sec-fetch-site': 'cross-site' },
        cookies: {}
      })

      expect(guard.canActivate(context)).toBe(true)
    })

    // The session-signal cookie is readable by JavaScript by design and authenticates nothing,
    // so a request carrying only that one still has no credential to abuse.
    it('does not count the session-signal cookie as a credential', () => {
      const context = contextFor({
        method: 'POST',
        headers: { origin: 'https://evil.example.com' },
        cookies: { [AUTH_HAS_SESSION_COOKIE_NAME]: '1' }
      })

      expect(guard.canActivate(context)).toBe(true)
    })

    // Scenario: no cookie jar at all — `cookie-parser` not mounted, or a framework that never
    // parsed cookies — on a cross-site request from a browser. Expected: refused. Why: the
    // guard cannot prove there is no ambient credential, and treating "unreadable" as "absent"
    // means a deployment that forgets the middleware silently loses the CSRF control on every
    // request. Demanding a trusted Origin is the recoverable direction; waving it through is
    // not. Non-browser callers are unaffected — see the test below.
    it.each([undefined, null, 'not-an-object'])(
      'refuses a cross-site browser request when the %s cookie jar cannot be read',
      (cookies) => {
        const context = contextFor({
          method: 'POST',
          headers: { origin: 'https://evil.example.com' },
          cookies
        })

        expect(() => guard.canActivate(context)).toThrow(AuthException)
      }
    )

    // Scenario: the same unreadable jar, but from a non-browser client — no `Origin`, no
    // `Sec-Fetch-Site` (curl, a mobile app, server-to-server). Expected: allowed. Why: those
    // headers are what a browser attaches; their absence means no browser attached an ambient
    // cookie, so there is no CSRF to prevent. This is what keeps the fail-closed choice above
    // from breaking every bearer-token deployment that never mounts `cookie-parser`.
    it.each([undefined, null, 'not-an-object'])(
      'still allows a non-browser request when the %s cookie jar cannot be read',
      (cookies) => {
        const context = contextFor({ method: 'POST', headers: {}, cookies })

        expect(guard.canActivate(context)).toBe(true)
      }
    )

    // Scenario: a deployment that RENAMED its auth cookies, cross-site from an untrusted
    // origin. Expected: refused. Why: the guard used to read the shipped default names, so a
    // renamed credential was invisible to it — it concluded "no ambient credential" and
    // allowed the request. That failed open on exactly the configuration the guard exists
    // for (`SameSite=None`), where the browser does attach the renamed cookie.
    it('sees a renamed auth cookie as a credential', async () => {
      const renamed = await buildGuard({
        cookies: {
          sameSite: 'none',
          trustedOrigins: [TRUSTED],
          accessTokenName: 'bm_at',
          refreshTokenName: 'bm_rt'
        }
      })
      const context = contextFor({
        method: 'POST',
        headers: { origin: 'https://evil.example.com' },
        cookies: { bm_at: 'a_1' }
      })

      expect(() => renamed.canActivate(context)).toThrow(AuthException)
    })

    // `same-origin` is the app calling itself; `none` is a user-initiated navigation. Neither
    // can be caused by another site, so both pass without consulting the allowlist — which is
    // what keeps a same-origin deployment working with an empty list.
    it.each(['same-origin', 'none'])('allows a %s fetch-site', (site) => {
      const context = cookieBearingPost({ 'sec-fetch-site': site })

      expect(guard.canActivate(context)).toBe(true)
    })

    // The refresh cookie is a credential too — the refresh endpoint is the single most
    // valuable CSRF target in the module, so it must be recognised.
    it('recognises the refresh cookie as a credential', () => {
      // Asserted from the refusing side: the refresh cookie mints access tokens, so a
      // cross-site write carrying only that one is as much a target as one carrying the
      // access cookie. Against a trusted origin the request passes either way, which would
      // have proved nothing.
      const context = {
        method: 'POST',
        headers: { origin: 'https://evil.example.com' },
        cookies: { [AUTH_REFRESH_COOKIE_NAME]: 'r_1' }
      }

      expect(() => guard.canActivate(contextFor(context))).toThrow(AuthException)
    })

    // A listed origin is exactly what the allowlist is for.
    it('allows a cross-site POST from a trusted origin', () => {
      const context = cookieBearingPost({ origin: TRUSTED, 'sec-fetch-site': 'cross-site' })

      expect(guard.canActivate(context)).toBe(true)
    })

    // Neither header at all means no browser is involved: an attacker's page cannot make a
    // browser OMIT `Origin` on a cross-site request, so the absence is evidence, not evasion.
    it('allows a request that carries no browser signals', () => {
      expect(guard.canActivate(cookieBearingPost({}))).toBe(true)
    })
  })

  describe('requests it blocks', () => {
    // The attack itself: a page on another origin POSTs to the API, the browser attaches the
    // SameSite=None session cookie, and without this check the request is authenticated.
    it('rejects a cross-site POST from an untrusted origin', () => {
      const context = cookieBearingPost({
        origin: 'https://evil.example.com',
        'sec-fetch-site': 'cross-site'
      })

      let thrown: unknown
      try {
        guard.canActivate(context)
      } catch (error) {
        thrown = error
      }

      expect(thrown).toBeInstanceOf(AuthException)
      expect(codeOf(thrown)).toBe(AUTH_ERROR_CODES.UNTRUSTED_ORIGIN)
      expect((thrown as AuthException).getStatus()).toBe(403)
    })

    // A sibling subdomain is a different origin and is not covered by a parent entry. This is
    // the case an allowlist matched by pattern would wave through.
    it('rejects a subdomain of a trusted origin', () => {
      const context = cookieBearingPost({ origin: 'https://evil.app.example.com' })

      expect(() => guard.canActivate(context)).toThrow(AuthException)
    })

    // Same host, different scheme — the origin comparison is verbatim, so http never satisfies
    // an https entry.
    it('rejects a scheme mismatch against a trusted origin', () => {
      const context = cookieBearingPost({ origin: 'http://app.example.com' })

      expect(() => guard.canActivate(context)).toThrow(AuthException)
    })

    // A browser that sends `Sec-Fetch-Site` sends `Origin` too on a state-changing request, so
    // this combination is malformed rather than legitimate.
    it('rejects a cross-site fetch-site with no origin header', () => {
      const context = cookieBearingPost({ 'sec-fetch-site': 'cross-site' })

      expect(() => guard.canActivate(context)).toThrow(AuthException)
    })

    // `same-site` is not `same-origin`: a sibling subdomain of the same registrable domain is
    // a different origin and still has to be listed.
    it('rejects a same-site fetch-site with no origin header', () => {
      const context = cookieBearingPost({ 'sec-fetch-site': 'same-site' })

      expect(() => guard.canActivate(context)).toThrow(AuthException)
    })
  })
})
