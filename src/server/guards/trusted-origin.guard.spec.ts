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
import { MFA_TEMP_COOKIE_NAME } from '../constants/mfa-temp-cookie'
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

    // These two used to be allowed, on the reasoning that a request carrying no auth cookie has
    // no ambient credential for an attacker page to spend. The reasoning missed the requests
    // that MINT one: `POST /auth/login` and `/auth/register` carry no cookie and answer with a
    // session, and this guard sits on that controller. Under `SameSite=None` an attacker's page
    // could therefore log a victim's browser into the ATTACKER's account, and then read
    // everything the victim did there believing it was their own.
    //
    // A non-browser bearer client is still unaffected: it sends neither `Origin` nor
    // `Sec-Fetch-Site`, and that shape is admitted below. What is refused here announces itself
    // as a browser on an origin nobody authorized.
    it.each([
      ['no cookies at all — the login/register shape', {}],
      ['only the session-signal cookie, which authenticates nothing', { has_session: '1' }]
    ])('refuses a cross-site POST carrying %s', (_label, cookies) => {
      const context = contextFor({
        method: 'POST',
        headers: { origin: 'https://evil.example.com', 'sec-fetch-site': 'cross-site' },
        cookies
      })

      expect(() => guard.canActivate(context)).toThrow(AuthException)
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

  // The default configuration ships an empty allowlist, so what the guard does with one decides
  // what it does on most deployments. It used to short-circuit to allowed, which made it inert
  // there — and inert on `POST /auth/login`, where a cross-site request needs no cookie and the
  // response mints a session. The cases below split that posture along the one axis that can
  // decide it.
  //
  // `Origin` alone cannot: it is sent on a SAME-origin POST too, and this module never learns
  // its own origin (reconstructing it from `Host` would trust the client). `Sec-Fetch-Site`
  // can, and is not forgeable by a page — so it is authoritative wherever it is present, and
  // the empty list only excuses the request that omits it.
  describe('a posture where no origin is authorized', () => {
    const noAllowlist = {
      cookies: {
        sameSite: 'lax',
        trustedOrigins: [],
        accessTokenName: AUTH_ACCESS_COOKIE_NAME,
        refreshTokenName: AUTH_REFRESH_COOKIE_NAME
      }
    }

    it('admits a same-origin POST from a browser that sends Origin and no Sec-Fetch-Site', async () => {
      const lax = await buildGuard(noAllowlist)
      const context = contextFor({
        method: 'POST',
        headers: { origin: 'https://app.internal' },
        cookies: { [AUTH_ACCESS_COOKIE_NAME]: 'a_1' }
      })

      expect(lax.canActivate(context)).toBe(true)
    })

    // The empty list used to short-circuit the whole guard, so THIS request — the browser
    // itself stating the POST came from another site — was admitted. That is a login CSRF:
    // `POST /auth/login` carries the attacker's credentials in its own body, needs no cookie,
    // and its response plants a session first-party because a form POST is a top-level
    // navigation. The victim then works inside the attacker's account. `Sec-Fetch-Site` is
    // unambiguous here and is not forgeable by a page, so the empty list no longer excuses it.
    it.each(['cross-site', 'same-site'])(
      'refuses a %s POST even with nothing allowlisted — the login-CSRF shape',
      async (fetchSite) => {
        const lax = await buildGuard(noAllowlist)
        const context = contextFor({
          method: 'POST',
          headers: { origin: 'https://evil.example', 'sec-fetch-site': fetchSite }
        })

        expect(() => lax.canActivate(context)).toThrow(AuthException)
      }
    )

    // No cookie at all, which is exactly what a login or register request looks like. The old
    // guard reached the same allow via two independent skips; both are gone.
    it('refuses a cross-site POST carrying no cookie whatsoever', async () => {
      const lax = await buildGuard(noAllowlist)
      const context = contextFor({
        method: 'POST',
        headers: { origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' },
        cookies: {}
      })

      expect(() => lax.canActivate(context)).toThrow(AuthException)
    })

    // `Sec-Fetch-Site` present and cross-site, `Origin` withheld. Refused before the change and
    // after it, but for a different reason — the empty-list short-circuit used to run first and
    // this branch was unreachable in that posture.
    it('refuses a cross-site POST with no Origin header', async () => {
      const lax = await buildGuard(noAllowlist)
      const context = contextFor({
        method: 'POST',
        headers: { 'sec-fetch-site': 'cross-site' }
      })

      expect(() => lax.canActivate(context)).toThrow(AuthException)
    })

    // The other half of the same coin: the browser vouching for the request still admits it
    // with nothing listed, so a normal same-origin deployment is untouched by the change.
    it.each(['same-origin', 'none'])('still admits a %s POST', async (fetchSite) => {
      const lax = await buildGuard(noAllowlist)
      const context = contextFor({
        method: 'POST',
        headers: { origin: 'https://app.internal', 'sec-fetch-site': fetchSite }
      })

      expect(lax.canActivate(context)).toBe(true)
    })

    // A non-browser client sends neither header, and no page can make a browser omit `Origin`
    // on a cross-site request — so the absence stays evidence of no browser, not a bypass.
    it('still admits a request with neither header', async () => {
      const lax = await buildGuard(noAllowlist)
      const context = contextFor({ method: 'POST', headers: {} })

      expect(lax.canActivate(context)).toBe(true)
    })

    // The same request under a configured allowlist is still refused — the gate is the empty
    // list, not the method or the headers.
    it('still refuses it once an origin has been authorized', () => {
      const context = contextFor({
        method: 'POST',
        headers: { origin: 'https://app.internal' },
        cookies: { [AUTH_ACCESS_COOKIE_NAME]: 'a_1' }
      })

      expect(() => guard.canActivate(context)).toThrow(AuthException)
    })
  })

  // The MFA challenge cookie is an ambient credential like any other: planted by the OAuth
  // callback with the configured `sameSite` — `none` on exactly the deployments this guard
  // exists for — and the sole credential for `POST /auth/mfa/challenge`. A victim mid-login
  // holds it and no session cookie yet, so enumerating only the two session names concluded
  // "nothing to spend" and skipped the Origin check. Each cross-site POST with a wrong code
  // then hit the MFA brute-force counter; five of them locked the account for the window.
  describe('the MFA challenge cookie counts as an ambient credential', () => {
    it('demands a trusted Origin for a request carrying only mfa_temp_token', () => {
      const context = contextFor({
        method: 'POST',
        headers: { origin: 'https://evil.example' },
        cookies: { [MFA_TEMP_COOKIE_NAME]: 'temp.jwt' }
      })

      expect(() => guard.canActivate(context)).toThrow(AuthException)
    })

    it('admits the same request from a trusted Origin', () => {
      const context = contextFor({
        method: 'POST',
        headers: { origin: TRUSTED },
        cookies: { [MFA_TEMP_COOKIE_NAME]: 'temp.jwt' }
      })

      expect(guard.canActivate(context)).toBe(true)
    })
  })
})
