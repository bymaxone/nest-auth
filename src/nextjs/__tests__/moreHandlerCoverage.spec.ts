/**
 * Additional coverage tests for the route handlers and JWT helpers
 * — hits edge cases the primary test suites do not naturally cover.
 */

import {
  createClientRefreshHandler,
  createLogoutHandler,
  createSilentRefreshHandler,
  decodeJwtToken,
  verifyJwtToken
} from '..'
import { makeMockRequest, base64UrlEncode } from './_testHelpers'

describe('createLogoutHandler — factory validation', () => {
  // Redirect mode requires loginPath. Missing loginPath → throw.
  it('throws in redirect mode when loginPath is missing', () => {
    expect(() =>
      createLogoutHandler({
        apiBase: 'https://api.example.com',
        cookieNames: {
          access: 'access_token',
          refresh: 'refresh_token',
          hasSession: 'has_session'
        },
        mode: 'redirect'
      } as never)
    ).toThrow(/loginPath/)
  })

  // Redirect mode rejects a protocol-relative loginPath.
  it('throws in redirect mode when loginPath is protocol-relative', () => {
    expect(() =>
      createLogoutHandler({
        apiBase: 'https://api.example.com',
        cookieNames: {
          access: 'access_token',
          refresh: 'refresh_token',
          hasSession: 'has_session'
        },
        mode: 'redirect',
        loginPath: '//evil.com'
      })
    ).toThrow(/loginPath/)
  })

  // Invalid cookie names are rejected.
  it('throws on invalid cookie names', () => {
    expect(() =>
      createLogoutHandler({
        apiBase: 'https://api.example.com',
        cookieNames: { access: 'bad name', refresh: 'r', hasSession: 'h' },
        mode: 'status'
      })
    ).toThrow(/cookie name/)
  })

  // Invalid apiBase is rejected.
  it('throws on a relative apiBase', () => {
    expect(() =>
      createLogoutHandler({
        apiBase: '/api',
        cookieNames: { access: 'a', refresh: 'r', hasSession: 'h' },
        mode: 'status'
      })
    ).toThrow(/apiBase/)
  })
})

describe('createClientRefreshHandler — fetch throw path', () => {
  // Fetch throw → 401. Complements the other cases by exercising the
  // catch branch of the handler.
  it('returns 401 when fetch throws a network error', async () => {
    const fetchSpy = jest
      .spyOn(globalThis, 'fetch' as never)
      .mockRejectedValueOnce(new Error('ECONNRESET') as never) as jest.SpyInstance

    const handler = createClientRefreshHandler({ apiBase: 'https://api.example.com' })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/client-refresh',
      method: 'POST'
    })

    const response = await handler(request as never)
    expect(response.status).toBe(401)
    expect(response.headers.get('cache-control')).toMatch(/no-store/)
    fetchSpy.mockRestore()
  })
})

describe('createSilentRefreshHandler — opaque-redirect and origin mismatch', () => {
  // Opaque-redirect (upstream issued a 3xx that fetch did not follow).
  it('treats an opaque-redirect response as failure', async () => {
    const fetchSpy = jest.spyOn(globalThis, 'fetch' as never).mockResolvedValueOnce({
      type: 'opaqueredirect',
      status: 0,
      ok: false,
      headers: { get: () => null, getSetCookie: () => [] }
    } as never) as jest.SpyInstance

    const handler = createSilentRefreshHandler({
      apiBase: 'https://api.example.com',
      loginPath: '/auth/login',
      cookieNames: { access: 'a', refresh: 'r', hasSession: 'h' }
    })
    const request = makeMockRequest({
      url: 'https://app.example.com/api/auth/silent-refresh?redirect=/dash'
    })

    const response = await handler(request as never)
    const url = new URL(response.headers.get('location') ?? '')
    expect(url.searchParams.get('reason')).toBe('expired')
    fetchSpy.mockRestore()
  })
})

describe('decodeJwtToken — invalid UTF-8 payload', () => {
  // Base64url that decodes to bytes the UTF-8 fatal decoder rejects
  // (e.g., a lone continuation byte).
  it('rejects a payload whose bytes are not valid UTF-8', () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    // 0x80 is a lone continuation byte — invalid UTF-8 start.
    const invalidBytes = new Uint8Array([0x80])
    const payload = base64UrlEncode(invalidBytes.buffer)
    const token = `${header}.${payload}.x`
    expect(decodeJwtToken(token).isValid).toBe(false)
  })

  // Empty header or payload segments → malformed, rejected early.
  it('rejects a token with an empty header segment', () => {
    expect(decodeJwtToken('.payload.sig').isValid).toBe(false)
  })

  it('rejects a token with an empty payload segment', async () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    const token = `${header}..sig`
    expect(decodeJwtToken(token).isValid).toBe(false)
    expect((await verifyJwtToken(token, 'any-secret')).isValid).toBe(false)
  })

  // Malformed header in verify mode → empty decoded (pre-signature).
  it('rejects a token whose header fails to parse in verify mode', async () => {
    const badHeader = base64UrlEncode('not-json')
    const payload = base64UrlEncode(JSON.stringify({ sub: 'u', exp: 9999999999 }))
    const token = `${badHeader}.${payload}.sig`
    expect((await verifyJwtToken(token, 'a-secret')).isValid).toBe(false)
  })

  // Malformed payload in verify mode.
  it('rejects a token whose payload fails to parse in verify mode', async () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    const badPayload = base64UrlEncode('not-json')
    const token = `${header}.${badPayload}.sig`
    expect((await verifyJwtToken(token, 'a-secret')).isValid).toBe(false)
  })

  // Invalid signature segment (non-base64url chars) in verify mode.
  it('rejects a token whose signature segment is not valid base64url', async () => {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    const payload = base64UrlEncode(JSON.stringify({ sub: 'u', exp: 9999999999 }))
    const token = `${header}.${payload}.@@@`
    expect((await verifyJwtToken(token, 'a-secret')).isValid).toBe(false)
  })
})

describe('verifyJwtToken — Web Crypto failure paths', () => {
  // `subtle.importKey` rejecting → verifier returns empty decoded.
  // We patch `crypto.subtle.importKey` to throw so the catch branch
  // executes. This exercises the defensive guard that would
  // otherwise surface as an unhandled rejection in the middleware
  // hot path.
  it('returns invalid when subtle.importKey throws', async () => {
    const originalImportKey = globalThis.crypto.subtle.importKey
    ;(globalThis.crypto.subtle as unknown as { importKey: unknown }).importKey = () => {
      throw new Error('forced importKey failure')
    }

    try {
      const { verifyJwtToken: verify } = jest.requireActual(
        '../helpers/jwt'
      ) as typeof import('../helpers/jwt')
      const { base64UrlEncode: encode } = jest.requireActual(
        './_testHelpers'
      ) as typeof import('./_testHelpers')
      const header = encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
      const payload = encode(JSON.stringify({ sub: 'u', exp: 9999999999 }))
      const token = `${header}.${payload}.sig`
      const decoded = await verify(token, 'secret')
      expect(decoded.isValid).toBe(false)
    } finally {
      ;(globalThis.crypto.subtle as unknown as { importKey: unknown }).importKey = originalImportKey
    }
  })

  // `subtle.verify` rejecting (post-import) → empty decoded. Same
  // pattern as above but for the verify step.
  it('returns invalid when subtle.verify throws', async () => {
    const originalVerify = globalThis.crypto.subtle.verify
    ;(globalThis.crypto.subtle as unknown as { verify: unknown }).verify = () => {
      throw new Error('forced verify failure')
    }

    try {
      const { verifyJwtToken: verify } = jest.requireActual(
        '../helpers/jwt'
      ) as typeof import('../helpers/jwt')
      const { base64UrlEncode: encode } = jest.requireActual(
        './_testHelpers'
      ) as typeof import('./_testHelpers')
      const header = encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
      const payload = encode(JSON.stringify({ sub: 'u', exp: 9999999999 }))
      const token = `${header}.${payload}.sig`
      const decoded = await verify(token, 'secret')
      expect(decoded.isValid).toBe(false)
    } finally {
      ;(globalThis.crypto.subtle as unknown as { verify: unknown }).verify = originalVerify
    }
  })
})

describe('createSilentRefreshHandler — origin drift after URL resolution', () => {
  // A resolved URL whose origin differs from the request's — the
  // common trigger is a crafted base URL in the `new URL()` resolver,
  // but for the happy-relative case we force it by monkey-patching
  // `URL` so the resolved instance reports a different origin.
  it('falls back to loginPath when resolved origin differs from request origin', () => {
    const { resolveSafeDestination } = jest.requireActual(
      '../createSilentRefreshHandler'
    ) as typeof import('../createSilentRefreshHandler')

    const realURL = globalThis.URL
    // Stub URL so that `new URL('/ok', origin).origin` differs.
    ;(globalThis as unknown as { URL: typeof URL }).URL = function (input: string) {
      if (input === '/ok') {
        return {
          origin: 'https://evil.com',
          pathname: '/ok',
          search: '',
          hash: ''
        } as unknown as URL
      }
      return new realURL(input)
    } as unknown as typeof URL

    try {
      expect(resolveSafeDestination('/ok', 'https://app.example.com', '/auth/login')).toBe(
        '/auth/login'
      )
    } finally {
      ;(globalThis as unknown as { URL: typeof URL }).URL = realURL
    }
  })
})

describe('buildSilentRefreshUrl — search as explicit undefined own-property', () => {
  // Ensures the hasOwnSearch branch with `search: undefined` as an
  // own property still returns the empty string fallback. This
  // branch is only reachable by a structural consumer that sets
  // `search` as an own property whose value is `undefined` —
  // `exactOptionalPropertyTypes` blocks the literal form, so we
  // construct the object dynamically.
  it('treats own-property `search: undefined` as empty search', () => {
    const { buildSilentRefreshUrl } = jest.requireActual(
      '../helpers/buildSilentRefreshUrl'
    ) as typeof import('../helpers/buildSilentRefreshUrl')
    const nextUrl: { pathname: string; search?: string } = { pathname: '/rewritten' }
    // Assign as an OWN property with value undefined — bypasses
    // exactOptionalPropertyTypes via runtime assignment.
    ;(nextUrl as Record<string, unknown>)['search'] = undefined

    const result = buildSilentRefreshUrl({
      url: 'https://app.example.com/raw',
      nextUrl
    })
    expect(new URL(result).searchParams.get('redirect')).toBe('/rewritten')
  })
})
