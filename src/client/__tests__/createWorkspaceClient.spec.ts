/**
 * Tests for the workspace calls of the typed client: the verb, the URL and the body of every method,
 * the encoding of what lands in a path, and what a workspace refusal does to the refresh logic.
 *
 * The method cases inject a stub `authFetch`, so what is asserted is what the client composes. The
 * refusal cases run the real fetch wrapper over a stubbed `fetch`, because "never refreshed" is a
 * property of the wrapper and not of the methods.
 */

import { AuthClientError } from '@bymax-one/nest-auth/shared'

import { createAuthClient } from '../createAuthClient'
import type { AuthFetch } from '../createAuthFetch'
import { createWorkspaceClient } from '../createWorkspaceClient'

const BASE = 'https://api.example.test'

interface Sent {
  url: string
  method: string | undefined
  body: unknown
  hasBody: boolean
}

/** A client over a stub `authFetch` that answers `reply` and records what it was asked. */
function build(reply: () => Response = () => new Response(null, { status: 204 })) {
  const sent: Sent[] = []
  const authFetch = jest.fn<ReturnType<AuthFetch>, Parameters<AuthFetch>>((input, init) => {
    const raw = init?.body
    sent.push({
      url: String(input),
      method: init?.method,
      body: typeof raw === 'string' ? JSON.parse(raw) : undefined,
      hasBody: raw !== undefined
    })
    return Promise.resolve(reply())
  })
  const client = createWorkspaceClient({ baseUrl: BASE, authFetch })
  return { client, sent, authFetch }
}

const json = (status: number, body: unknown) => (): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

describe('workspace calls of the typed client', () => {
  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('reads', () => {
    it('lists the caller’s workspaces from the list route, with no query by default', async () => {
      const page = { items: [], nextCursor: null, lastActiveWorkspaceId: 'w1' }
      const { client, sent } = build(json(200, page))

      await expect(client.listWorkspaces()).resolves.toEqual(page)

      expect(sent).toEqual([
        { url: `${BASE}/auth/workspaces`, method: 'GET', body: undefined, hasBody: false }
      ])
    })

    it.each([
      [{ cursor: 'c1' }, '?cursor=c1'],
      [{ limit: 5 }, '?limit=5'],
      [{ cursor: 'c1', limit: 5 }, '?cursor=c1&limit=5'],
      [{ cursor: 'a b&c=d' }, '?cursor=a+b%26c%3Dd'],
      [{}, '']
    ])('puts the page %j on the query as %s', async (page, query) => {
      const { client, sent } = build(json(200, { items: [], nextCursor: null }))

      await client.listWorkspaceMembers('w1', page)

      expect(sent[0]).toMatchObject({
        url: `${BASE}/auth/workspaces/w1/members${query}`,
        method: 'GET'
      })
    })

    it('pages invitations the same way', async () => {
      const { client, sent } = build(json(200, { items: [], nextCursor: null }))

      await client.listWorkspaceInvitations('w1', { limit: 2 })

      expect(sent[0]).toMatchObject({
        url: `${BASE}/auth/workspaces/w1/invitations?limit=2`,
        method: 'GET'
      })
    })

    it('reads the access of one workspace', async () => {
      const access = { workspace: { id: 'w1' }, role: 'editor' }
      const { client, sent } = build(json(200, access))

      await expect(client.getWorkspaceAccess('w1')).resolves.toEqual(access)

      expect(sent[0]).toMatchObject({ url: `${BASE}/auth/workspaces/w1/access`, method: 'GET' })
    })
  })

  describe('writes without an answer body', () => {
    it.each([
      [
        'switchWorkspace',
        (c: ReturnType<typeof build>['client']) => c.switchWorkspace('w1'),
        'POST',
        'w1/switch',
        {}
      ],
      [
        'restoreWorkspace',
        (c: ReturnType<typeof build>['client']) => c.restoreWorkspace('w1'),
        'POST',
        'w1/restore',
        {}
      ],
      [
        'leaveWorkspace',
        (c: ReturnType<typeof build>['client']) => c.leaveWorkspace('w1'),
        'POST',
        'w1/leave',
        {}
      ],
      [
        'resendWorkspaceInvitation',
        (c: ReturnType<typeof build>['client']) => c.resendWorkspaceInvitation('w1', 'a@b.c'),
        'POST',
        'w1/invitations/resend',
        { email: 'a@b.c' }
      ],
      [
        'revokeWorkspaceInvitation',
        (c: ReturnType<typeof build>['client']) => c.revokeWorkspaceInvitation('w1', 'a@b.c'),
        'POST',
        'w1/invitations/revoke',
        { email: 'a@b.c' }
      ],
      [
        'inviteToWorkspace',
        (c: ReturnType<typeof build>['client']) =>
          c.inviteToWorkspace('w1', { email: 'a@b.c', role: 'viewer' }),
        'POST',
        'w1/invitations',
        { email: 'a@b.c', role: 'viewer' }
      ]
    ])('%s sends %s %s', async (_name, call, method, path, body) => {
      const { client, sent } = build()

      await expect(call(client)).resolves.toBeUndefined()

      expect(sent).toEqual([
        { url: `${BASE}/auth/workspaces/${path}`, method, body, hasBody: true }
      ])
    })

    it('removes a member with a DELETE and no body', async () => {
      const { client, sent } = build()

      await client.removeWorkspaceMember('w1', 'u1')

      expect(sent).toEqual([
        {
          url: `${BASE}/auth/workspaces/w1/members/u1`,
          method: 'DELETE',
          body: undefined,
          hasBody: false
        }
      ])
    })

    it('sends only the password, and only when there is one, to schedule a deletion', async () => {
      const { client, sent } = build()

      await client.scheduleWorkspaceDeletion('w1')
      await client.scheduleWorkspaceDeletion('w1', {})
      await client.scheduleWorkspaceDeletion('w1', { password: 'pw' })

      expect(sent.map((s) => s.body)).toEqual([{}, {}, { password: 'pw' }])
      expect(sent[0]).toMatchObject({
        url: `${BASE}/auth/workspaces/w1/schedule-deletion`,
        method: 'POST'
      })
    })

    it('sends the transfer target, and the optional fields only when set', async () => {
      const { client, sent } = build()

      await client.transferWorkspaceOwnership('w1', { userId: 'u2' })
      await client.transferWorkspaceOwnership('w1', {
        userId: 'u2',
        demoteSelfTo: 'editor',
        password: 'pw'
      })

      expect(sent.map((s) => s.body)).toEqual([
        { userId: 'u2' },
        { userId: 'u2', demoteSelfTo: 'editor', password: 'pw' }
      ])
      expect(sent[0]).toMatchObject({
        url: `${BASE}/auth/workspaces/w1/transfer-ownership`,
        method: 'POST'
      })
    })

    it('forwards nothing a caller smuggles in beside the fields it names', async () => {
      const { client, sent } = build()
      const extra = { email: 'a@b.c', role: 'viewer', workspaceId: 'other', tenantId: 'x' }

      await client.inviteToWorkspace('w1', extra)
      const smuggledTransfer = { userId: 'u2', tenantId: 'x' }
      await client.transferWorkspaceOwnership('w1', smuggledTransfer)

      expect(sent.map((s) => s.body)).toEqual([
        { email: 'a@b.c', role: 'viewer' },
        { userId: 'u2' }
      ])
    })
  })

  describe('writes with an answer body', () => {
    it('creates a workspace by name', async () => {
      const created = { id: 'w9', name: 'Team' }
      const { client, sent } = build(json(201, created))

      await expect(client.createWorkspace('Team')).resolves.toEqual(created)

      expect(sent).toEqual([
        { url: `${BASE}/auth/workspaces`, method: 'POST', body: { name: 'Team' }, hasBody: true }
      ])
    })

    it('renames a workspace with a PATCH', async () => {
      const { client, sent } = build(json(200, { id: 'w1', name: 'New' }))

      await client.renameWorkspace('w1', 'New')

      expect(sent).toEqual([
        { url: `${BASE}/auth/workspaces/w1`, method: 'PATCH', body: { name: 'New' }, hasBody: true }
      ])
    })

    it('changes a member’s role with a PATCH to the member route', async () => {
      const { client, sent } = build(json(200, { userId: 'u1', role: 'editor' }))

      await client.changeWorkspaceMemberRole('w1', 'u1', 'editor')

      expect(sent).toEqual([
        {
          url: `${BASE}/auth/workspaces/w1/members/u1`,
          method: 'PATCH',
          body: { role: 'editor' },
          hasBody: true
        }
      ])
    })

    it.each([
      ['previewWorkspaceInvitation', 'invitations/preview'],
      ['acceptWorkspaceInvitation', 'invitations/accept']
    ] as const)('%s posts the token to %s', async (method, path) => {
      const { client, sent } = build(json(200, { workspaceId: 'w1', role: 'viewer' }))

      await client[method]('tok')

      expect(sent).toEqual([
        {
          url: `${BASE}/auth/workspaces/${path}`,
          method: 'POST',
          body: { token: 'tok' },
          hasBody: true
        }
      ])
    })

    it('accepts by signup with exactly the three fields', async () => {
      const { client, sent } = build(json(201, { user: {}, accessToken: '', workspaceId: 'w1' }))

      const smuggledSignup = {
        token: 'tok',
        name: 'Ana',
        password: 'pw',
        email: 'smuggled@example.test'
      }
      await client.acceptWorkspaceInvitationSignup(smuggledSignup)

      expect(sent).toEqual([
        {
          url: `${BASE}/auth/workspaces/invitations/accept-signup`,
          method: 'POST',
          body: { token: 'tok', name: 'Ana', password: 'pw' },
          hasBody: true
        }
      ])
    })
  })

  describe('the signal of a read', () => {
    it("hands the caller's signal to the fetch, and none when there is none", async () => {
      const inits: Array<RequestInit | undefined> = []
      const authFetch = jest.fn<ReturnType<AuthFetch>, Parameters<AuthFetch>>((_input, init) => {
        inits.push(init)
        return Promise.resolve(json(200, { items: [], nextCursor: null })())
      })
      const client = createWorkspaceClient({ baseUrl: BASE, authFetch })
      const controller = new AbortController()

      await client.listWorkspaces(undefined, { signal: controller.signal })
      await client.listWorkspaces()
      await client.listWorkspaces({ limit: 1 }, {})
      await client.listWorkspaceMembers('w1')

      expect(inits[0]?.signal).toBe(controller.signal)
      expect(inits.slice(1).map((init) => init?.signal)).toEqual([null, null, null])
    })

    it('cancels the request when the signal aborts, through the real fetch wrapper', async () => {
      jest.spyOn(globalThis, 'fetch').mockImplementation(
        (_input, init) =>
          new Promise((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () => reject(init.signal?.reason))
          })
      )
      const client = createWorkspaceClient({ baseUrl: BASE })
      const controller = new AbortController()

      const pending = client.listWorkspaces(undefined, { signal: controller.signal })
      controller.abort()

      await expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    })
  })

  describe('what lands in a path', () => {
    it.each([
      ['a/b', 'a%2Fb'],
      ['a b', 'a%20b'],
      ['../x', '..%2Fx'],
      ['é?#', '%C3%A9%3F%23']
    ])('percent-encodes the workspace id %j as %s', async (id, encoded) => {
      const { client, sent } = build(json(200, {}))

      await client.getWorkspaceAccess(id)

      expect(sent[0]?.url).toBe(`${BASE}/auth/workspaces/${encoded}/access`)
    })

    it('encodes the member id as well', async () => {
      const { client, sent } = build()

      await client.removeWorkspaceMember('w1', 'u/1')

      expect(sent[0]?.url).toBe(`${BASE}/auth/workspaces/w1/members/u%2F1`)
    })

    // A URL parser collapses a '.' or '..' segment, encoded or not, so the id would address another
    // route: PATCH workspaces/w/members/.. is the rename route.
    it.each(['.', '..'])('refuses the id %j, which a URL parser would collapse', async (id) => {
      const { client, authFetch } = build()

      await expect(client.getWorkspaceAccess(id)).rejects.toThrow(TypeError)
      await expect(client.changeWorkspaceMemberRole('w1', id, 'editor')).rejects.toThrow(TypeError)
      await expect(client.removeWorkspaceMember(id, 'u1')).rejects.toThrow(TypeError)

      expect(authFetch).not.toHaveBeenCalled()
    })

    it.each(['...', 'a..', '.a', '..a'])(
      'accepts the id %j, which is not a dot segment',
      async (id) => {
        const { client, sent } = build(json(200, {}))

        await client.getWorkspaceAccess(id)

        expect(sent).toHaveLength(1)
      }
    )

    it.each([
      [
        'an empty workspace id',
        (c: ReturnType<typeof build>['client']) => c.getWorkspaceAccess(''),
        'workspaceId'
      ],
      [
        'an empty member id',
        (c: ReturnType<typeof build>['client']) => c.removeWorkspaceMember('w1', ''),
        'userId'
      ],
      [
        'a workspace id that is not a string',
        (c: ReturnType<typeof build>['client']) => c.leaveWorkspace(Reflect.get({}, 'id')),
        'workspaceId'
      ]
    ])('refuses %s before any request is made', async (_name, call, field) => {
      const { client, authFetch } = build()

      await expect(call(client)).rejects.toThrow(
        new TypeError(`${field} must be a non-empty string`)
      )

      expect(authFetch).not.toHaveBeenCalled()
    })
  })

  describe('answers', () => {
    it('throws the server’s error for a refused call', async () => {
      const refusal = {
        error: { code: 'auth.workspace_not_found', message: 'Workspace not found', details: null }
      }
      const { client } = build(json(404, refusal))

      const failure = await client.getWorkspaceAccess('w1').catch((error: unknown) => error)

      expect(failure).toBeInstanceOf(AuthClientError)
      expect(failure).toMatchObject({ status: 404 })
    })

    it('throws for a refused call that answers no body', async () => {
      const { client } = build(() => new Response(null, { status: 403 }))

      await expect(client.leaveWorkspace('w1')).rejects.toBeInstanceOf(AuthClientError)
    })
  })

  describe('workspace refusals and the refresh logic', () => {
    const refusal = (code: string, status: number): Response =>
      new Response(JSON.stringify({ error: { code, message: code, details: null } }), {
        status,
        headers: { 'Content-Type': 'application/json' }
      })

    it.each([
      ['auth.workspace_not_found', 404],
      ['auth.insufficient_workspace_role', 403],
      ['auth.workspace_pending_deletion', 409]
    ])('answers %s as it is, with no refresh and no retry', async (code, status) => {
      const calls: string[] = []
      jest.spyOn(globalThis, 'fetch').mockImplementation((input) => {
        calls.push(String(input))
        return Promise.resolve(refusal(code, status))
      })
      const client = createWorkspaceClient({ baseUrl: BASE })

      await expect(client.getWorkspaceAccess('w1')).rejects.toMatchObject({ status })

      expect(calls).toEqual([`${BASE}/auth/workspaces/w1/access`])
    })

    it('still refreshes once for an expired token, then retries the workspace call', async () => {
      const calls: string[] = []
      jest.spyOn(globalThis, 'fetch').mockImplementation((input) => {
        calls.push(String(input))
        const first = calls.filter((c) => c.endsWith('/access')).length === 1
        if (String(input).endsWith('/access')) {
          return Promise.resolve(
            first
              ? refusal('auth.token_invalid', 401)
              : new Response(JSON.stringify({ workspace: {}, role: 'viewer' }), { status: 200 })
          )
        }
        return Promise.resolve(new Response(JSON.stringify({ user: {} }), { status: 200 }))
      })
      const client = createWorkspaceClient({ baseUrl: BASE })

      await expect(client.getWorkspaceAccess('w1')).resolves.toEqual({
        workspace: {},
        role: 'viewer'
      })

      expect(calls.filter((c) => c.includes('refresh'))).toHaveLength(1)
      expect(calls.filter((c) => c.endsWith('/access'))).toHaveLength(2)
    })
  })

  it('composes the URL under a same-origin base and a custom route prefix', async () => {
    const { authFetch } = build(json(200, {}))
    const client = createWorkspaceClient({
      baseUrl: '/api/',
      routePrefix: '/identity/',
      authFetch
    })

    await client.getWorkspaceAccess('w1')

    expect(authFetch.mock.calls[0]?.[0]).toBe('/api/identity/workspaces/w1/access')
  })
})
