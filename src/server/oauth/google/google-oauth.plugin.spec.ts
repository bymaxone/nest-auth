/**
 * GoogleOAuthPlugin — unit tests
 *
 * Verifies the three methods of the Google OAuth 2.0 plugin:
 *  - authorizeUrl(state)  — constructs the authorization redirect URL
 *  - exchangeCode(code)   — exchanges an authorization code for an access token
 *  - fetchProfile(token)  — fetches and normalizes the user's profile
 *
 * Mocking strategy: global.fetch is replaced with a jest mock before each test
 * so no real network calls are made. The mock is reset in beforeEach to ensure
 * isolation between tests.
 *
 * All tests follow the AAA pattern. Comments above every it() block explain
 * what is being verified and why.
 */

import { GoogleOAuthPlugin } from './google-oauth.plugin'

// ---------------------------------------------------------------------------
// Global fetch mock — replaces the Node.js built-in fetch for all tests.
// ---------------------------------------------------------------------------

const mockFetch = jest.fn()
global.fetch = mockFetch as unknown as typeof fetch

// ---------------------------------------------------------------------------
// Shared helper — builds a minimal fetch Response-like object.
// ---------------------------------------------------------------------------

function makeFetchResponse(body: unknown, ok: boolean, status = 200): Response {
  return {
    ok,
    status,
    json: jest.fn().mockResolvedValue(body)
  } as unknown as Response
}

// ---------------------------------------------------------------------------
// GoogleOAuthPlugin
// ---------------------------------------------------------------------------

describe('GoogleOAuthPlugin', () => {
  let plugin: GoogleOAuthPlugin

  beforeEach(() => {
    jest.resetAllMocks()

    plugin = new GoogleOAuthPlugin({
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      callbackUrl: 'https://app.example.com/callback'
    })
  })

  // ---------------------------------------------------------------------------
  // authorizeUrl()
  // ---------------------------------------------------------------------------

  describe('authorizeUrl()', () => {
    // Verifies that the returned URL points to Google's authorization endpoint
    // — a wrong base URL would silently redirect users to a phishing page.
    it('should return a URL starting with the Google authorization endpoint', () => {
      const url = plugin.authorizeUrl('state-abc')

      expect(url).toMatch(/^https:\/\/accounts\.google\.com\/o\/oauth2\/v2\/auth/)
    })

    // Verifies that client_id, redirect_uri, response_type=code, and state are
    // all present in the query parameters — missing any of these causes a Google error.
    it('should include client_id, redirect_uri, response_type, and state in query params', () => {
      const url = plugin.authorizeUrl('my-state')
      const parsed = new URL(url)

      expect(parsed.searchParams.get('client_id')).toBe('test-client-id')
      expect(parsed.searchParams.get('redirect_uri')).toBe('https://app.example.com/callback')
      expect(parsed.searchParams.get('response_type')).toBe('code')
      expect(parsed.searchParams.get('state')).toBe('my-state')
    })

    // Verifies that the default scope 'openid email profile' is present when no
    // custom scope is specified in the constructor.
    it('should include the default scope "openid email profile"', () => {
      const url = plugin.authorizeUrl('state-xyz')
      const parsed = new URL(url)

      expect(parsed.searchParams.get('scope')).toBe('openid email profile')
    })

    // Verifies that custom scopes provided at construction time override the defaults
    // and appear correctly space-joined in the scope query parameter.
    it('should use custom scope when provided in constructor', () => {
      const customPlugin = new GoogleOAuthPlugin({
        clientId: 'cid',
        clientSecret: 'csec',
        callbackUrl: 'https://app.example.com/cb',
        scope: ['openid', 'email']
      })

      const url = customPlugin.authorizeUrl('state-123')
      const parsed = new URL(url)

      expect(parsed.searchParams.get('scope')).toBe('openid email')
    })

    // Verifies that the state value is URL-encoded in the returned URL so that
    // special characters in the nonce are preserved through the redirect round-trip.
    it('should URL-encode the state parameter', () => {
      const stateWithSpecialChars = 'state with spaces & symbols'
      const url = plugin.authorizeUrl(stateWithSpecialChars)
      const parsed = new URL(url)

      // URLSearchParams.get() decodes percent-encoding, so we get the original value back.
      expect(parsed.searchParams.get('state')).toBe(stateWithSpecialChars)
    })

    // Verifies that the PKCE code_challenge and code_challenge_method=S256 are added
    // when a challenge is provided — omitting PKCE would leave the flow vulnerable to
    // authorization-code interception attacks.
    it('should include PKCE code_challenge and S256 method when codeChallenge is supplied', () => {
      const url = plugin.authorizeUrl('s', 'challenge-value-abc')
      const parsed = new URL(url)

      expect(parsed.searchParams.get('code_challenge')).toBe('challenge-value-abc')
      expect(parsed.searchParams.get('code_challenge_method')).toBe('S256')
    })

    // Verifies that PKCE fields are omitted when no challenge is supplied — plugins
    // must remain usable by callers that do not yet opt in to PKCE.
    it('should omit PKCE parameters when no codeChallenge is supplied', () => {
      const url = plugin.authorizeUrl('s')
      const parsed = new URL(url)

      expect(parsed.searchParams.get('code_challenge')).toBeNull()
      expect(parsed.searchParams.get('code_challenge_method')).toBeNull()
    })

    // Verifies that an empty string for codeChallenge is treated as "no PKCE" rather
    // than producing a malformed code_challenge query value.
    it('should omit PKCE parameters when codeChallenge is an empty string', () => {
      const url = plugin.authorizeUrl('s', '')
      const parsed = new URL(url)

      expect(parsed.searchParams.get('code_challenge')).toBeNull()
    })
  })

  // ---------------------------------------------------------------------------
  // exchangeCode()
  // ---------------------------------------------------------------------------

  describe('exchangeCode()', () => {
    // Verifies the happy path: a successful token response with token_type 'Bearer'
    // is returned as-is to the caller.
    it('should return the token response when the exchange succeeds', async () => {
      const tokenData = { access_token: 'at-123', token_type: 'Bearer', expires_in: 3600 }
      mockFetch.mockResolvedValue(makeFetchResponse(tokenData, true))

      const result = await plugin.exchangeCode('auth-code')

      expect(result).toEqual(tokenData)
    })

    // Verifies that token_type comparison is case-insensitive — Google may return
    // 'bearer' in lowercase, and we must accept it as a valid Bearer token.
    it('should accept lowercase "bearer" as a valid token_type', async () => {
      const tokenData = { access_token: 'at-456', token_type: 'bearer' }
      mockFetch.mockResolvedValue(makeFetchResponse(tokenData, true))

      await expect(plugin.exchangeCode('code')).resolves.toEqual(tokenData)
    })

    // Verifies that an unexpected token_type like 'mac' throws an error — silently
    // treating a MAC token as a Bearer token would produce an invalid Authorization header.
    it("should throw when token_type is not 'bearer' (e.g. 'mac')", async () => {
      mockFetch.mockResolvedValue(
        makeFetchResponse({ access_token: 'at', token_type: 'mac' }, true)
      )

      await expect(plugin.exchangeCode('code')).rejects.toThrow('unexpected token_type')
    })

    // Verifies that a non-2xx response from Google throws with the HTTP status code
    // included in the message for easier debugging in production logs.
    it('should throw with the HTTP status when Google returns a non-ok response', async () => {
      mockFetch.mockResolvedValue(makeFetchResponse({}, false, 401))

      await expect(plugin.exchangeCode('bad-code')).rejects.toThrow(
        'Google token exchange failed: 401'
      )
    })

    // Verifies that the POST request is made to the correct Google token endpoint
    // with the Content-Type header set to 'application/x-www-form-urlencoded' as
    // required by RFC 6749.
    it('should POST to the Google token URL with application/x-www-form-urlencoded', async () => {
      mockFetch.mockResolvedValue(
        makeFetchResponse({ access_token: 'at', token_type: 'Bearer' }, true)
      )

      await plugin.exchangeCode('code-abc')

      const [url, init] = mockFetch.mock.calls[0] as [
        string,
        { method?: string; headers?: Record<string, string>; body?: string }
      ]
      expect(url).toBe('https://oauth2.googleapis.com/token')
      expect((init.headers ?? {})['Content-Type']).toBe('application/x-www-form-urlencoded')
      expect(init.method).toBe('POST')
    })

    // Verifies that all required OAuth parameters (code, client_id, client_secret,
    // redirect_uri, grant_type) are present in the POST body as URL-encoded form fields.
    it('should include all required fields in the POST body', async () => {
      mockFetch.mockResolvedValue(
        makeFetchResponse({ access_token: 'at', token_type: 'Bearer' }, true)
      )

      await plugin.exchangeCode('my-code')

      const [, init] = mockFetch.mock.calls[0] as [
        string,
        { method?: string; headers?: Record<string, string>; body?: string }
      ]
      const body = new URLSearchParams(init.body as string)

      expect(body.get('code')).toBe('my-code')
      expect(body.get('client_id')).toBe('test-client-id')
      expect(body.get('client_secret')).toBe('test-client-secret')
      expect(body.get('redirect_uri')).toBe('https://app.example.com/callback')
      expect(body.get('grant_type')).toBe('authorization_code')
    })

    // Verifies that the PKCE code_verifier is forwarded to the token endpoint when
    // supplied — this is what lets Google's token endpoint validate the challenge.
    it('should forward code_verifier to the token endpoint when supplied', async () => {
      mockFetch.mockResolvedValue(
        makeFetchResponse({ access_token: 'at', token_type: 'Bearer' }, true)
      )

      await plugin.exchangeCode('code', 'verifier-xyz')

      const [, init] = mockFetch.mock.calls[0] as [string, { body?: string }]
      const body = new URLSearchParams(init.body as string)
      expect(body.get('code_verifier')).toBe('verifier-xyz')
    })

    // Verifies that code_verifier is NOT added to the body when the caller does not
    // supply one — plugins must remain backward compatible for non-PKCE callers.
    it('should omit code_verifier from the body when not supplied', async () => {
      mockFetch.mockResolvedValue(
        makeFetchResponse({ access_token: 'at', token_type: 'Bearer' }, true)
      )

      await plugin.exchangeCode('code')

      const [, init] = mockFetch.mock.calls[0] as [string, { body?: string }]
      const body = new URLSearchParams(init.body as string)
      expect(body.get('code_verifier')).toBeNull()
    })

    // Verifies that an empty-string code_verifier is treated as absent — prevents
    // forwarding a malformed empty `code_verifier=` parameter to the provider.
    it('should omit code_verifier from the body when supplied as an empty string', async () => {
      mockFetch.mockResolvedValue(
        makeFetchResponse({ access_token: 'at', token_type: 'Bearer' }, true)
      )

      await plugin.exchangeCode('code', '')

      const [, init] = mockFetch.mock.calls[0] as [string, { body?: string }]
      const body = new URLSearchParams(init.body as string)
      expect(body.get('code_verifier')).toBeNull()
    })
  })

  // ---------------------------------------------------------------------------
  // fetchProfile()
  // ---------------------------------------------------------------------------

  describe('fetchProfile()', () => {
    // Verifies the happy path: a complete UserInfo response is mapped to the
    // normalized OAuthProfile shape with provider='google'.
    it('should return a normalized OAuthProfile for a complete UserInfo response', async () => {
      mockFetch.mockResolvedValue(
        makeFetchResponse(
          {
            id: 'g-sub-123',
            email: 'user@example.com',
            verified_email: true,
            name: 'Test User',
            picture: 'https://lh3.googleusercontent.com/photo.jpg'
          },
          true
        )
      )

      const profile = await plugin.fetchProfile('access-token')

      expect(profile).toEqual({
        provider: 'google',
        providerId: 'g-sub-123',
        email: 'user@example.com',
        name: 'Test User',
        avatar: 'https://lh3.googleusercontent.com/photo.jpg'
      })
    })

    // Verifies that verified_email === false causes the plugin to throw — we must
    // not issue auth tokens for accounts with unverified email addresses.
    it('should throw when verified_email is false', async () => {
      mockFetch.mockResolvedValue(
        makeFetchResponse({ id: 'g-123', email: 'user@example.com', verified_email: false }, true)
      )

      await expect(plugin.fetchProfile('at')).rejects.toThrow('email address is not verified')
    })

    // Verifies that verified_email === true passes without error — this is the
    // normal case for verified Google accounts.
    it('should succeed when verified_email is true', async () => {
      mockFetch.mockResolvedValue(
        makeFetchResponse({ id: 'g-123', email: 'user@example.com', verified_email: true }, true)
      )

      await expect(plugin.fetchProfile('at')).resolves.toBeDefined()
    })

    // Verifies the defence-in-depth default: when `verified_email` is absent from
    // the UserInfo response, the plugin rejects the profile. Standard Google
    // sign-in flows always emit `verified_email: true`; a missing field indicates
    // a non-standard or future-changed response, and an auth library must never
    // promote such a profile to a trusted subject.
    it('should throw when verified_email is absent (undefined)', async () => {
      mockFetch.mockResolvedValue(
        makeFetchResponse({ id: 'g-123', email: 'user@example.com' }, true)
      )

      await expect(plugin.fetchProfile('at')).rejects.toThrow(
        'Google OAuth: email address is not verified.'
      )
    })

    // Verifies that when the name field is absent from UserInfo, profile.name is
    // undefined (not a fallback string) — the caller decides how to handle missing names.
    it('should leave profile.name undefined when name is absent from UserInfo', async () => {
      mockFetch.mockResolvedValue(
        makeFetchResponse({ id: 'g-123', email: 'user@example.com', verified_email: true }, true)
      )

      const profile = await plugin.fetchProfile('at')

      expect(profile.name).toBeUndefined()
    })

    // Verifies that when the picture field is absent from UserInfo, profile.avatar
    // is undefined — the caller decides whether to use a default avatar.
    it('should leave profile.avatar undefined when picture is absent from UserInfo', async () => {
      mockFetch.mockResolvedValue(
        makeFetchResponse(
          { id: 'g-123', email: 'user@example.com', verified_email: true, name: 'Name' },
          true
        )
      )

      const profile = await plugin.fetchProfile('at')

      expect(profile.avatar).toBeUndefined()
    })

    // Verifies that a non-2xx response from the UserInfo endpoint throws with the
    // HTTP status code in the message — distinguishes from exchangeCode errors in logs.
    it('should throw with the HTTP status when the UserInfo endpoint returns a non-ok response', async () => {
      mockFetch.mockResolvedValue(makeFetchResponse({}, false, 403))

      await expect(plugin.fetchProfile('bad-token')).rejects.toThrow(
        'Google UserInfo fetch failed: 403'
      )
    })

    // Verifies that the GET request to the UserInfo endpoint includes the access token
    // as a Bearer Authorization header — omitting it returns a 401 from Google.
    it('should send a GET request to the UserInfo URL with the Bearer Authorization header', async () => {
      mockFetch.mockResolvedValue(
        makeFetchResponse({ id: 'g-1', email: 'u@e.com', verified_email: true }, true)
      )

      await plugin.fetchProfile('my-access-token')

      const [url, init] = mockFetch.mock.calls[0] as [
        string,
        { method?: string; headers?: Record<string, string>; body?: string }
      ]
      expect(url).toBe('https://www.googleapis.com/oauth2/v2/userinfo')
      expect((init.headers ?? {})['Authorization']).toBe('Bearer my-access-token')
    })
  })
})
