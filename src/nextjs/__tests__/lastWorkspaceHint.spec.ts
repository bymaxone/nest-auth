/**
 * Tests for the landing hint the proxy passes to `getDefaultDashboard`: which cookie values are read,
 * and that nothing that is not a UUID can reach a redirect path.
 */

import { NextRequest } from 'next/server'

import { dashboardHint } from '../internal/workspaceHint'
import { createAuthProxy } from '../createAuthProxy'
import type { AuthProxyConfig } from '../createAuthProxy'
import { DEFAULT_PROXY_CONFIG, makeMockRequest, signHs256Token } from './_testHelpers'

const COOKIE = 'last_workspace'
const WORKSPACE = '3f2504e0-4f89-41d3-9a0c-0305e82c3301'
const SECRET = DEFAULT_PROXY_CONFIG.jwtSecret ?? ''

/** A real request carrying `cookies` and `headers`, the way the proxy receives one. */
function requestTo(
  url: string,
  cookies: Record<string, string>,
  headers: Record<string, string> = {}
): NextRequest {
  const cookie = Object.entries(cookies)
    .map(([name, value]) => `${name}=${value}`)
    .join('; ')
  return new NextRequest(url, { headers: { ...headers, ...(cookie === '' ? {} : { cookie }) } })
}

/** What a hostile or stale cookie can hold, none of which may reach a path. */
const UNSAFE = [
  ['a protocol-relative URL', '//evil.example'],
  ['a path escape', '../x'],
  ['an encoded protocol-relative URL', '%2F%2Fevil'],
  ['a value with a query', `${WORKSPACE}?next=//evil.example`],
  ['a value with a fragment', `${WORKSPACE}#x`],
  ['a value with a path', `${WORKSPACE}/../../x`],
  ['a value with a trailing newline', `${WORKSPACE}\n`],
  ['a value with a control character', `${WORKSPACE}\u0000`],
  ['an over-long value', `${WORKSPACE}${'a'.repeat(200)}`],
  ['a UUID with a character outside hex', '3f2504e0-4f89-41d3-9a0c-0305e82c330g'],
  ['a UUID with no hyphens', '3f2504e04f8941d39a0c0305e82c3301'],
  ['an empty value', ''],
  ['an ordinary word', 'dashboard']
] as const

function resolved(extra: Partial<AuthProxyConfig> = {}) {
  return createAuthProxy({ ...DEFAULT_PROXY_CONFIG, ...extra }).config
}

describe('dashboardHint', () => {
  it('reads a UUID from the configured cookie', () => {
    const request = makeMockRequest({ cookies: { [COOKIE]: WORKSPACE } })

    expect(dashboardHint(request, resolved({ lastWorkspaceCookie: COOKIE }))).toEqual({
      lastActiveWorkspaceId: WORKSPACE
    })
  })

  it('reads an upper-case UUID as it is', () => {
    const upper = WORKSPACE.toUpperCase()
    const request = makeMockRequest({ cookies: { [COOKIE]: upper } })

    expect(dashboardHint(request, resolved({ lastWorkspaceCookie: COOKIE }))).toEqual({
      lastActiveWorkspaceId: upper
    })
  })

  it.each(UNSAFE)('treats %s as absent', (_name, value) => {
    const request = makeMockRequest({ cookies: { [COOKIE]: value } })

    expect(dashboardHint(request, resolved({ lastWorkspaceCookie: COOKIE }))).toEqual({})
  })

  it('is empty when the cookie is not there', () => {
    const request = makeMockRequest()

    expect(dashboardHint(request, resolved({ lastWorkspaceCookie: COOKIE }))).toEqual({})
  })

  it('reads nothing when no cookie name is configured, even if a cookie by that name exists', () => {
    const request = makeMockRequest({ cookies: { [COOKIE]: WORKSPACE } })

    expect(dashboardHint(request, resolved())).toEqual({})
  })
})

describe('createAuthProxy — lastWorkspaceCookie', () => {
  describe('validation', () => {
    it.each([
      ['a space', 'last workspace'],
      ['a semicolon', 'a;b'],
      ['an equals sign', 'a=b'],
      ['an empty name', '']
    ])('refuses a cookie name with %s', (_name, name) => {
      expect(() => createAuthProxy({ ...DEFAULT_PROXY_CONFIG, lastWorkspaceCookie: name })).toThrow(
        /invalid cookie name ".*" for lastWorkspaceCookie/
      )
    })

    it.each(['access_token', 'refresh_token', 'has_session'])(
      'refuses the name of the %s cookie',
      (name) => {
        expect(() =>
          createAuthProxy({ ...DEFAULT_PROXY_CONFIG, lastWorkspaceCookie: name })
        ).toThrow(/must differ from cookieNames/)
      }
    )

    it('accepts a plain name, and a config without one', () => {
      expect(() =>
        createAuthProxy({ ...DEFAULT_PROXY_CONFIG, lastWorkspaceCookie: 'last_workspace' })
      ).not.toThrow()
      expect(() => createAuthProxy(DEFAULT_PROXY_CONFIG)).not.toThrow()
    })
  })

  describe('what getDefaultDashboard receives', () => {
    const signedIn = async (): Promise<string> =>
      signHs256Token(
        {
          sub: 'u1',
          role: 'member',
          tenantId: 't1',
          type: 'dashboard',
          exp: Math.floor(Date.now() / 1000) + 600
        },
        SECRET
      )

    async function landing(cookies: Record<string, string>, extra: Partial<AuthProxyConfig> = {}) {
      const getDefaultDashboard = jest.fn(
        (_role: string, hint: { lastActiveWorkspaceId?: string }) =>
          hint.lastActiveWorkspaceId === undefined
            ? '/dashboard'
            : `/w/${encodeURIComponent(hint.lastActiveWorkspaceId)}`
      )
      const { proxy } = createAuthProxy({
        ...DEFAULT_PROXY_CONFIG,
        lastWorkspaceCookie: COOKIE,
        getDefaultDashboard,
        ...extra
      })
      const request = requestTo('https://app.example.com/auth/login', {
        access_token: await signedIn(),
        has_session: '1',
        ...cookies
      })
      const response = await proxy(request)
      return { getDefaultDashboard, location: response.headers.get('location') }
    }

    it('lands a signed-in caller on the last workspace when the cookie holds a UUID', async () => {
      const { getDefaultDashboard, location } = await landing({ [COOKIE]: WORKSPACE })

      expect(getDefaultDashboard).toHaveBeenCalledWith('member', {
        lastActiveWorkspaceId: WORKSPACE
      })
      expect(location).toBe(`https://app.example.com/w/${WORKSPACE}`)
    })

    it('lands on the default dashboard with an empty hint when there is no cookie', async () => {
      const { getDefaultDashboard, location } = await landing({})

      expect(getDefaultDashboard).toHaveBeenCalledWith('member', {})
      expect(location).toBe('https://app.example.com/dashboard')
    })

    // A control character cannot travel in a header, so those values are covered above, on the hint.
    it.each(UNSAFE.filter(([, value]) => ![...value].some((char) => char.charCodeAt(0) <= 0x1f)))(
      'lands on the default dashboard for %s',
      async (_name, value) => {
        const { getDefaultDashboard, location } = await landing({ [COOKIE]: value })

        expect(getDefaultDashboard).toHaveBeenCalledWith('member', {})
        expect(location).toBe('https://app.example.com/dashboard')
      }
    )

    it('hands the same hint to the role-refusal fallback', async () => {
      const getDefaultDashboard = jest.fn(
        (_role: string, hint: { lastActiveWorkspaceId?: string }) =>
          `/w/${hint.lastActiveWorkspaceId ?? 'none'}`
      )
      const { proxy } = createAuthProxy({
        ...DEFAULT_PROXY_CONFIG,
        lastWorkspaceCookie: COOKIE,
        getDefaultDashboard
      })
      const request = requestTo('https://app.example.com/admin/users', {
        access_token: await signedIn(),
        has_session: '1',
        [COOKIE]: WORKSPACE
      })

      const response = await proxy(request)

      expect(getDefaultDashboard).toHaveBeenCalledWith('member', {
        lastActiveWorkspaceId: WORKSPACE
      })
      expect(response.headers.get('location')).toContain(`/w/${WORKSPACE}`)
    })

    it('hands an empty hint when the feature is not configured', async () => {
      const getDefaultDashboard = jest.fn(() => '/dashboard')
      const { proxy } = createAuthProxy({ ...DEFAULT_PROXY_CONFIG, getDefaultDashboard })
      const request = requestTo('https://app.example.com/auth/login', {
        access_token: await signedIn(),
        has_session: '1',
        [COOKIE]: WORKSPACE
      })

      await proxy(request)

      expect(getDefaultDashboard).toHaveBeenCalledWith('member', {})
    })
  })
})

describe('createAuthProxy — x-workspace-id', () => {
  // The workspace a request acts in comes from the route. A browser-supplied header with this name
  // must not reach a server component looking like something the proxy vouched for.
  it.each(['/about', '/dashboard'])(
    'strips a client-supplied x-workspace-id on %s',
    async (path) => {
      const token = await signHs256Token(
        {
          type: 'dashboard',
          sub: 'u1',
          role: 'member',
          tenantId: 't1',
          exp: Math.floor(Date.now() / 1000) + 600
        },
        SECRET
      )
      const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
      const request = requestTo(
        `https://app.example.com${path}`,
        { access_token: token },
        { 'x-workspace-id': 'someone-elses-workspace' }
      )

      const response = await proxy(request)

      expect(response.headers.get('x-middleware-override-headers')).not.toBeNull()
      expect(response.headers.get('x-middleware-request-x-workspace-id')).toBeNull()
      expect(response.headers.get('x-middleware-override-headers') ?? '').not.toContain(
        'x-workspace-id'
      )
    }
  )

  it('never sets x-workspace-id itself', async () => {
    const token = await signHs256Token(
      {
        type: 'dashboard',
        sub: 'u1',
        role: 'member',
        tenantId: 't1',
        workspaceId: 'w-from-token',
        exp: Math.floor(Date.now() / 1000) + 600
      },
      SECRET
    )
    const { proxy } = createAuthProxy(DEFAULT_PROXY_CONFIG)
    const request = requestTo('https://app.example.com/dashboard', { access_token: token })

    const response = await proxy(request)

    expect(response.headers.get('x-middleware-request-x-workspace-id')).toBeNull()
  })
})
