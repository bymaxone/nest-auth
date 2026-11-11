/**
 * Tests for the server-side workspace access reader: the request it makes, what each answer becomes,
 * and that a URL-supplied workspace id can neither make a page fail nor change the route asked.
 */

import { AuthClientError } from '@bymax-one/nest-auth/shared'

import { cookies } from 'next/headers'
import { RequestCookiesAdapter } from 'next/dist/server/web/spec-extension/adapters/request-cookies'
import { RequestCookies } from 'next/dist/compiled/@edge-runtime/cookies'

import { createWorkspaceAccessReader } from '../helpers/workspaceAccess'

jest.mock('next/headers', () => ({ cookies: jest.fn() }))
// React's `cache` memoizes per request on the server and is a pass-through elsewhere; a Map stands in
// for one request so the wiring (the reader IS cached, by workspace id) can be observed.
jest.mock('react', () => ({
  ...jest.requireActual<typeof import('react')>('react'),
  cache: <A, R>(fn: (arg: A) => R) =>
    (() => {
      const seen = new Map<A, R>()
      return (arg: A): R => {
        if (!seen.has(arg)) seen.set(arg, fn(arg))
        return seen.get(arg) as R
      }
    })()
}))

const ACCESS = {
  workspace: {
    id: 'w1',
    name: 'Team',
    status: 'active',
    createdAt: '2026-01-01T00:00:00.000Z',
    deletionScheduledAt: null
  },
  role: 'editor'
}

/** The request cookies a server component sees, built the way Next builds them. */
const cookieJar = (header: string): Awaited<ReturnType<typeof cookies>> =>
  RequestCookiesAdapter.seal(new RequestCookies(new Headers({ cookie: header })))

const reply = (status: number, body: unknown = ACCESS): Response =>
  new Response(typeof body === 'string' ? body : JSON.stringify(body), { status })

function build(answer: () => Response | Promise<Response> = () => reply(200)) {
  jest.mocked(cookies).mockResolvedValue(cookieJar('access_token=abc; has_session=1'))
  const send = jest.fn<ReturnType<typeof fetch>, Parameters<typeof fetch>>(() =>
    Promise.resolve(answer())
  )
  const read = createWorkspaceAccessReader({ apiBase: 'https://api.example.test', fetch: send })
  return { read, send }
}

describe('createWorkspaceAccessReader', () => {
  it('reads the access of a workspace with the request cookies, and returns the answer', async () => {
    const { read, send } = build()

    await expect(read('w1')).resolves.toEqual(ACCESS)

    expect(send).toHaveBeenCalledTimes(1)
    const [url, init] = send.mock.calls[0] ?? []
    expect(url).toBe('https://api.example.test/auth/workspaces/w1/access')
    expect(init).toMatchObject({
      method: 'GET',
      cache: 'no-store',
      headers: { accept: 'application/json', cookie: 'access_token=abc; has_session=1' }
    })
    expect(init?.signal).toBeInstanceOf(AbortSignal)
  })

  it.each([
    ['a slash', 'a/b', 'a%2Fb'],
    ['a dot-dot path', '../admin', '..%2Fadmin'],
    ['a query and a fragment', 'x?y#z', 'x%3Fy%23z'],
    ['a space', 'a b', 'a%20b']
  ])('encodes a workspace id with %s into one path segment', async (_name, id, encoded) => {
    const { read, send } = build()

    await read(id)

    expect(send.mock.calls[0]?.[0]).toBe(
      `https://api.example.test/auth/workspaces/${encoded}/access`
    )
  })

  it.each([
    [
      'a trailing slash on the base',
      'https://api.example.test/',
      'auth',
      'https://api.example.test/auth'
    ],
    [
      'a custom prefix',
      'https://api.example.test',
      'identity',
      'https://api.example.test/identity'
    ],
    [
      'slashes around the prefix',
      'https://api.example.test',
      '/identity/',
      'https://api.example.test/identity'
    ],
    [
      'a base with a path',
      'https://api.example.test/v1',
      'auth',
      'https://api.example.test/v1/auth'
    ]
  ])('composes the URL with %s', async (_name, apiBase, routePrefix, expected) => {
    jest.mocked(cookies).mockResolvedValue(cookieJar(''))
    const send = jest.fn<ReturnType<typeof fetch>, Parameters<typeof fetch>>(() =>
      Promise.resolve(reply(200))
    )
    const read = createWorkspaceAccessReader({ apiBase, routePrefix, fetch: send })

    await read('w1')

    expect(send.mock.calls[0]?.[0]).toBe(`${expected}/workspaces/w1/access`)
  })

  it.each([403, 404, 409])(
    'answers null for a %i, a workspace the caller cannot use',
    async (status) => {
      const { read } = build(() => reply(status, { error: { code: 'x' } }))

      await expect(read('w1')).resolves.toBeNull()
    }
  )

  it.each([401, 429, 500, 502])('throws an AuthClientError for a %i', async (status) => {
    const { read } = build(() => reply(status, { error: { code: 'x' } }))

    await expect(read('w1')).rejects.toMatchObject({ name: 'AuthClientError', status })
  })

  it.each([
    ['a non-JSON body', 'not json'],
    ['an array', []],
    ['null', null],
    ['a body without a role', { workspace: ACCESS.workspace }],
    ['a body with a numeric role', { workspace: ACCESS.workspace, role: 1 }],
    ['a body without a workspace', { role: 'editor' }],
    ['a workspace that is not an object', { workspace: 'w1', role: 'editor' }],
    ['a workspace with no id', { workspace: { name: 'T', status: 'active' }, role: 'editor' }],
    ['a workspace with no name', { workspace: { id: 'w1', status: 'active' }, role: 'editor' }],
    ['a workspace with no status', { workspace: { id: 'w1', name: 'T' }, role: 'editor' }]
  ])('throws, rather than answering, for %s', async (_name, body) => {
    const { read } = build(() => reply(200, body))

    await expect(read('w1')).rejects.toBeInstanceOf(AuthClientError)
  })

  it.each([
    ['an empty id', ''],
    ['a number', 5],
    ['undefined', undefined]
  ])('answers null and asks nothing for %s', async (_name, id) => {
    const { read, send } = build()

    await expect(Reflect.apply(read, undefined, [id])).resolves.toBeNull()

    expect(send).not.toHaveBeenCalled()
  })

  it('uses the global fetch when none is given', async () => {
    jest.mocked(cookies).mockResolvedValue(cookieJar(''))
    const global = jest
      .spyOn(globalThis, 'fetch')
      .mockImplementation(() => Promise.resolve(reply(200)))
    try {
      const read = createWorkspaceAccessReader({ apiBase: 'https://api.example.test' })

      await expect(read('w1')).resolves.toEqual(ACCESS)
      expect(global).toHaveBeenCalledTimes(1)
    } finally {
      global.mockRestore()
    }
  })

  it('shares one upstream call between reads of the same workspace in a request', async () => {
    const { read, send } = build()

    await Promise.all([read('w1'), read('w1'), read('w1')])
    await read('w2')

    expect(send).toHaveBeenCalledTimes(2)
  })

  it('refuses a base that is not an absolute http(s) URL, when the reader is created', () => {
    expect(() => createWorkspaceAccessReader({ apiBase: '/api' })).toThrow(
      'createWorkspaceAccessReader: apiBase "/api" must be an absolute URL'
    )
    expect(() => createWorkspaceAccessReader({ apiBase: '' })).toThrow('non-empty string')
  })

  describe('the timeout', () => {
    it('abandons a request that outlasts it', async () => {
      jest.mocked(cookies).mockResolvedValue(cookieJar(''))
      const hang = (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(init.signal?.reason))
        })
      const read = createWorkspaceAccessReader({
        apiBase: 'https://api.example.test',
        timeoutMs: 5,
        fetch: hang
      })

      await expect(read('w1')).rejects.toMatchObject({ name: 'TimeoutError' })
    })

    it.each([
      [undefined, 5000],
      [250, 250]
    ])('uses %s as the setting, so the limit is %i ms', async (timeoutMs, expected) => {
      jest.mocked(cookies).mockResolvedValue(cookieJar(''))
      const timeout = jest.spyOn(AbortSignal, 'timeout')
      const read = createWorkspaceAccessReader({
        apiBase: 'https://api.example.test',
        ...(timeoutMs === undefined ? {} : { timeoutMs }),
        fetch: () => Promise.resolve(reply(200))
      })

      await read('w1')

      expect(timeout).toHaveBeenCalledWith(expected)
      timeout.mockRestore()
    })
  })
})
