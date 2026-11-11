/**
 * @jest-environment @stryker-mutator/jest-runner/jest-env/jsdom
 */

/**
 * Tests for `useWorkspaces()` through the real `AuthProvider` and a mocked client: the opt-in, the
 * load after sign-in, the precedence that picks the active workspace, switching, the two callbacks
 * and the cross-tab channel.
 */

import { act, renderHook } from '@testing-library/react'
import { type ReactNode } from 'react'

import { AuthClientError } from '../../shared'
import type { WorkspaceAccessClient } from '../../shared'
import { AuthProvider } from '../AuthProvider'
import { WorkspaceProvider } from '../WorkspaceProvider'
import type { AuthWorkspacesOptions } from '../workspaceContext'
import { useAuth } from '../useAuth'
import { useSession } from '../useSession'
import { useWorkspaces } from '../useWorkspaces'

import { MOCK_USER } from './_testHelpers'
import {
  FakeChannel,
  mount,
  settle,
  signedIn,
  W1,
  W2,
  workspace,
  type TestClient
} from './_workspaceTestKit'

describe('useWorkspaces', () => {
  afterEach(() => {
    jest.restoreAllMocks()
    Reflect.deleteProperty(globalThis, 'BroadcastChannel')
    FakeChannel.instances = []
  })

  describe('without a WorkspaceProvider', () => {
    it('is inert, reports disabled, and makes no workspace request', async () => {
      const client = signedIn()
      const { result } = mount(client, { current: undefined })
      await settle()

      expect(result.current).toMatchObject({
        status: 'disabled',
        memberships: [],
        activeWorkspace: null,
        lastActiveWorkspaceId: null
      })
      expect(result.current.hasWorkspaceRole('editor')).toBe(false)
      expect(result.current.handleWorkspaceError('w1', new Error('x'))).toBe(false)
      await expect(result.current.refresh()).resolves.toBeUndefined()
      await expect(result.current.switchWorkspace('w1')).rejects.toThrow(
        'render a <WorkspaceProvider> inside <AuthProvider>'
      )
      expect(client.listWorkspaces).not.toHaveBeenCalled()
      expect(client.switchWorkspace).not.toHaveBeenCalled()
    })

    it('refuses a WorkspaceProvider rendered outside an AuthProvider', () => {
      jest.spyOn(console, 'error').mockImplementation(() => undefined)
      const wrapper = ({ children }: { children: ReactNode }): ReactNode => (
        <WorkspaceProvider client={signedIn()}>{children}</WorkspaceProvider>
      )

      expect(() => renderHook(() => useWorkspaces(), { wrapper })).toThrow(
        'WorkspaceProvider must be rendered within an <AuthProvider>'
      )
    })

    it('throws outside an AuthProvider', () => {
      jest.spyOn(console, 'error').mockImplementation(() => undefined)

      expect(() => renderHook(() => useWorkspaces())).toThrow(
        'useWorkspaces must be called within an <AuthProvider>'
      )
    })
  })

  describe('loading', () => {
    it('is idle and silent before sign-in is known, then loads once the caller is signed in', async () => {
      const client = signedIn()
      const { result } = mount(client)

      expect(result.current.status).toBe('idle')
      expect(client.listWorkspaces).not.toHaveBeenCalled()
      await settle()

      expect(result.current.status).toBe('ready')
      expect(result.current.memberships).toEqual([W1, W2])
      expect(result.current.lastActiveWorkspaceId).toBe('w2')
      expect(client.listWorkspaces).toHaveBeenCalledTimes(1)
      expect(client.listWorkspaces).toHaveBeenCalledWith(undefined, {
        signal: expect.any(AbortSignal)
      })
    })

    it('loads the list once, and only once, when the caller is signed in', async () => {
      const client = signedIn()
      mount(client)
      await settle()
      await settle()

      expect(client.listWorkspaces).toHaveBeenCalledTimes(1)
    })

    it('stays idle and makes no request for a caller who is not signed in', async () => {
      const client = signedIn()
      client.getMe.mockRejectedValue(new AuthClientError('no', 401))
      const { result } = mount(client)
      await settle()

      expect(result.current.status).toBe('idle')
      expect(client.listWorkspaces).not.toHaveBeenCalled()
    })

    it('makes no request when the host asks for a reload while signed out', async () => {
      const client = signedIn()
      client.getMe.mockRejectedValue(new AuthClientError('no', 401))
      const { result } = mount(client)
      await settle()

      await act(async () => {
        await result.current.refresh()
      })

      expect(client.listWorkspaces).not.toHaveBeenCalled()
      expect(result.current.status).toBe('idle')
    })

    it('follows the cursors and keeps the last active workspace of the first page', async () => {
      const client = signedIn()
      client.listWorkspaces
        .mockResolvedValueOnce({ items: [W1], nextCursor: 'c2', lastActiveWorkspaceId: 'w1' })
        .mockResolvedValueOnce({ items: [W2], nextCursor: null, lastActiveWorkspaceId: null })
      const { result } = mount(client)
      await settle()
      await settle()

      expect(client.listWorkspaces.mock.calls).toEqual([
        [undefined, { signal: expect.any(AbortSignal) }],
        [{ cursor: 'c2' }, { signal: expect.any(AbortSignal) }]
      ])
      expect(result.current.memberships).toEqual([W1, W2])
      expect(result.current.lastActiveWorkspaceId).toBe('w1')
    })

    it('stops following cursors after twenty pages', async () => {
      const client = signedIn()
      client.listWorkspaces.mockResolvedValue({
        items: [W1],
        nextCursor: 'again',
        lastActiveWorkspaceId: null
      })
      mount(client)
      for (let i = 0; i < 25; i += 1) await settle()

      expect(client.listWorkspaces).toHaveBeenCalledTimes(20)
    })

    it('reports an error, with nothing listed, when the list cannot be read', async () => {
      const client = signedIn()
      client.listWorkspaces.mockRejectedValue(new AuthClientError('down', 503))
      const { result } = mount(client)
      await settle()

      expect(result.current.status).toBe('error')
      expect(result.current.memberships).toEqual([])
    })

    it('ignores a list that arrives after the session changed, and a failure that does', async () => {
      const client = signedIn()
      let finish: (value: Awaited<ReturnType<TestClient['listWorkspaces']>>) => void = () =>
        undefined
      let fail: (reason: unknown) => void = () => undefined
      client.listWorkspaces
        .mockImplementationOnce(() => new Promise((resolve) => (finish = resolve)))
        .mockImplementationOnce(() => new Promise((_resolve, reject) => (fail = reject)))
      client.logout.mockResolvedValue(undefined)
      const wrapper = ({ children }: { children: ReactNode }): ReactNode => (
        <AuthProvider client={client}>
          <WorkspaceProvider client={client}>{children}</WorkspaceProvider>
        </AuthProvider>
      )
      const { result } = renderHook(() => ({ workspaces: useWorkspaces(), auth: useAuth() }), {
        wrapper
      })
      await settle()
      await act(async () => {
        await result.current.auth.logout()
      })

      await act(async () => {
        finish({ items: [W1], nextCursor: null, lastActiveWorkspaceId: 'w1' })
        await Promise.resolve()
      })

      expect(result.current.workspaces).toMatchObject({ status: 'idle', memberships: [] })

      client.login.mockResolvedValue({ user: MOCK_USER, accessToken: '' })
      await act(async () => {
        await result.current.auth.login('a@b.c', 'pw')
      })
      await act(async () => {
        await result.current.auth.logout()
      })
      await act(async () => {
        fail(new Error('late'))
        await Promise.resolve()
      })

      expect(result.current.workspaces.status).toBe('idle')
    })

    it('keeps what it has when the session revalidates without ending', async () => {
      const client = signedIn()
      let finish: (value: { user: typeof MOCK_USER; accessToken: string }) => void = () => undefined
      client.login.mockImplementation(() => new Promise((resolve) => (finish = resolve)))
      const wrapper = ({ children }: { children: ReactNode }): ReactNode => (
        <AuthProvider client={client}>
          <WorkspaceProvider client={client}>{children}</WorkspaceProvider>
        </AuthProvider>
      )
      const { result } = renderHook(
        () => ({ workspaces: useWorkspaces(), auth: useAuth(), session: useSession() }),
        {
          wrapper
        }
      )
      await settle()
      expect(result.current.workspaces.status).toBe('ready')

      // The session goes loading while the sign-in is in flight, then authenticated again.
      let signIn: Promise<unknown> = Promise.resolve()
      await act(async () => {
        signIn = result.current.auth.login('a@b.c', 'pw')
        await Promise.resolve()
      })
      expect(result.current.session.status).toBe('loading')
      expect(result.current.workspaces.status).toBe('ready')
      await act(async () => {
        finish({ user: MOCK_USER, accessToken: '' })
        await signIn
      })
      await settle()

      expect(result.current.workspaces.status).toBe('ready')
      expect(result.current.workspaces.memberships).toHaveLength(2)
    })

    it('empties and goes idle again when the caller signs out, and loads afresh on the next sign-in', async () => {
      const client = signedIn()
      client.logout.mockResolvedValue(undefined)
      client.login.mockResolvedValue({ user: MOCK_USER, accessToken: '' })
      const onWorkspaceChanged = jest.fn()
      const wrapper = ({ children }: { children: ReactNode }): ReactNode => (
        <AuthProvider client={client}>
          <WorkspaceProvider client={client} onWorkspaceChanged={onWorkspaceChanged}>
            {children}
          </WorkspaceProvider>
        </AuthProvider>
      )
      const { result } = renderHook(() => ({ workspaces: useWorkspaces(), auth: useAuth() }), {
        wrapper
      })
      await settle()
      expect(result.current.workspaces.memberships).toHaveLength(2)

      await act(async () => {
        await result.current.auth.logout()
      })

      expect(result.current.workspaces).toMatchObject({
        status: 'idle',
        memberships: [],
        activeWorkspace: null,
        lastActiveWorkspaceId: null
      })

      await act(async () => {
        await result.current.auth.login('a@b.c', 'pw')
      })
      await settle()

      expect(result.current.workspaces.status).toBe('ready')
      expect(client.listWorkspaces).toHaveBeenCalledTimes(2)
      expect(onWorkspaceChanged).not.toHaveBeenCalled()
    })
  })

  describe('the active workspace', () => {
    it('is the one the server remembers when nothing else names one', async () => {
      const { result } = mount(signedIn())
      await settle()

      expect(result.current.activeWorkspace).toEqual(W2)
    })

    it('is null when the remembered workspace is not among the memberships', async () => {
      const { result } = mount(signedIn([W1], 'gone'))
      await settle()

      expect(result.current.activeWorkspace).toBeNull()
    })

    it('is the one the URL names, over the remembered one', async () => {
      const { result } = mount(signedIn(), { current: { activeWorkspaceId: 'w1' } })
      await settle()

      expect(result.current.activeWorkspace).toEqual(W1)
    })

    it('is null for a URL workspace the caller does not belong to', async () => {
      const { result } = mount(signedIn(), { current: { activeWorkspaceId: 'stranger' } })
      await settle()

      expect(result.current.activeWorkspace).toBeNull()
    })

    it('follows the URL when it changes', async () => {
      const holder = { current: { activeWorkspaceId: 'w1' } as AuthWorkspacesOptions | undefined }
      const { result, rerender } = mount(signedIn(), holder)
      await settle()

      holder.current = { activeWorkspaceId: 'w2' }
      rerender()

      expect(result.current.activeWorkspace).toEqual(W2)
    })
  })

  describe('switchWorkspace', () => {
    it('records the switch, makes it the chosen workspace, and updates what the server remembers', async () => {
      const client = signedIn()
      const { result } = mount(client)
      await settle()

      await act(async () => {
        await result.current.switchWorkspace('w1')
      })

      expect(client.switchWorkspace).toHaveBeenCalledWith('w1')
      expect(result.current.activeWorkspace).toEqual(W1)
      expect(result.current.lastActiveWorkspaceId).toBe('w1')
    })

    it('rejects with the server’s refusal and changes nothing', async () => {
      const client = signedIn()
      client.switchWorkspace.mockRejectedValue(new AuthClientError('no', 404))
      const { result } = mount(client)
      await settle()

      await act(async () => {
        await expect(result.current.switchWorkspace('w1')).rejects.toBeInstanceOf(AuthClientError)
      })

      expect(result.current.activeWorkspace).toEqual(W2)
      expect(result.current.lastActiveWorkspaceId).toBe('w2')
    })

    it('lets the URL outrank the chosen workspace', async () => {
      const { result } = mount(signedIn(), { current: { activeWorkspaceId: 'w2' } })
      await settle()

      await act(async () => {
        await result.current.switchWorkspace('w1')
      })

      expect(result.current.activeWorkspace).toEqual(W2)
    })
  })

  describe('onWorkspaceChanged', () => {
    it('is not called by the first load', async () => {
      const onWorkspaceChanged = jest.fn()
      mount(signedIn(), { current: { onWorkspaceChanged } })
      await settle()

      expect(onWorkspaceChanged).not.toHaveBeenCalled()
    })

    it('is called once, with the one left and the one entered, when the caller switches', async () => {
      const onWorkspaceChanged = jest.fn()
      const { result } = mount(signedIn(), { current: { onWorkspaceChanged } })
      await settle()

      await act(async () => {
        await result.current.switchWorkspace('w1')
      })

      expect(onWorkspaceChanged.mock.calls).toEqual([[W2, W1]])
    })

    it('is called when the URL changes the active workspace', async () => {
      const onWorkspaceChanged = jest.fn()
      const holder = {
        current: { activeWorkspaceId: 'w1', onWorkspaceChanged } as
          AuthWorkspacesOptions | undefined
      }
      const { rerender } = mount(signedIn(), holder)
      await settle()

      holder.current = { activeWorkspaceId: 'w2', onWorkspaceChanged }
      rerender()

      expect(onWorkspaceChanged.mock.calls).toEqual([[W1, W2]])
    })

    it('is not called by a reload that leaves the same workspace active', async () => {
      const onWorkspaceChanged = jest.fn()
      const { result } = mount(signedIn(), { current: { onWorkspaceChanged } })
      await settle()

      await act(async () => {
        await result.current.refresh()
      })

      expect(onWorkspaceChanged).not.toHaveBeenCalled()
    })

    it('is called with null when a reload shows the active workspace is gone', async () => {
      const client = signedIn()
      const onWorkspaceChanged = jest.fn()
      const { result } = mount(client, { current: { onWorkspaceChanged } })
      await settle()
      client.listWorkspaces.mockResolvedValue({
        items: [W1],
        nextCursor: null,
        lastActiveWorkspaceId: 'w2'
      })

      await act(async () => {
        await result.current.refresh()
      })

      expect(onWorkspaceChanged.mock.calls).toEqual([[W2, null]])
    })

    it('warns and carries on when the callback throws', async () => {
      const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined)
      const onWorkspaceChanged = jest.fn(() => {
        throw new Error('host bug')
      })
      const { result } = mount(signedIn(), { current: { onWorkspaceChanged } })
      await settle()

      await act(async () => {
        await result.current.switchWorkspace('w1')
      })

      expect(result.current.activeWorkspace).toEqual(W1)
      expect(warn).toHaveBeenCalledWith(
        '[nest-auth] onWorkspaceChanged callback threw:',
        expect.any(Error)
      )
    })
  })

  describe('hasWorkspaceRole', () => {
    const HIERARCHY = { owner: ['editor', 'viewer'], editor: ['viewer'], viewer: [] }

    it('matches the exact role in the active workspace, and nothing else without a hierarchy', async () => {
      const { result } = mount(signedIn([W1, W2], 'w1'))
      await settle()

      expect(result.current.hasWorkspaceRole('editor')).toBe(true)
      expect(result.current.hasWorkspaceRole('viewer')).toBe(false)
    })

    it('counts a role the hierarchy includes', async () => {
      const { result } = mount(signedIn([W1, W2], 'w1'), { current: { hierarchy: HIERARCHY } })
      await settle()

      expect(result.current.hasWorkspaceRole('viewer')).toBe(true)
      expect(result.current.hasWorkspaceRole('owner')).toBe(false)
    })

    it('answers for another workspace when asked, and false for one the caller is not in', async () => {
      const { result } = mount(signedIn([W1, W2], 'w1'), { current: { hierarchy: HIERARCHY } })
      await settle()

      expect(result.current.hasWorkspaceRole('editor', 'w2')).toBe(false)
      expect(result.current.hasWorkspaceRole('viewer', 'w2')).toBe(true)
      expect(result.current.hasWorkspaceRole('viewer', 'stranger')).toBe(false)
    })

    it('is false when no workspace is active', async () => {
      const { result } = mount(signedIn([W1], null), { current: { hierarchy: HIERARCHY } })
      await settle()

      expect(result.current.hasWorkspaceRole('editor')).toBe(false)
    })

    it('does not read a role the hierarchy inherits from its prototype', async () => {
      const odd = workspace('w3', 'toString')
      const { result } = mount(signedIn([odd], 'w3'), { current: { hierarchy: HIERARCHY } })
      await settle()

      expect(result.current.hasWorkspaceRole('viewer')).toBe(false)
      expect(result.current.hasWorkspaceRole('toString')).toBe(true)
    })
  })

  describe('handleWorkspaceError and onWorkspaceAccessLost', () => {
    const refusal = (code: string): AuthClientError =>
      new AuthClientError('refused', 404, {
        message: 'refused',
        error: 'Not Found',
        statusCode: 404,
        code
      })

    it.each([
      'auth.workspace_not_found',
      'auth.insufficient_workspace_role',
      'auth.workspace_pending_deletion'
    ])('calls the callback and reloads for %s from the active workspace', async (code) => {
      const client = signedIn()
      const onWorkspaceAccessLost = jest.fn()
      const { result } = mount(client, { current: { onWorkspaceAccessLost } })
      await settle()

      let handled = false
      await act(async () => {
        handled = result.current.handleWorkspaceError('w2', refusal(code))
        await Promise.resolve()
      })

      expect(handled).toBe(true)
      expect(onWorkspaceAccessLost.mock.calls).toEqual([['w2', code]])
      expect(client.listWorkspaces).toHaveBeenCalledTimes(2)
    })

    // The user can cause a refusal in a workspace they are not working in, for example by opening a
    // link to another one; that must not throw them out of the one they are in.
    it('does not call the callback, nor reload, for a refusal on a workspace other than the active one', async () => {
      const client = signedIn()
      const onWorkspaceAccessLost = jest.fn()
      const { result } = mount(client, { current: { onWorkspaceAccessLost } })
      await settle()

      let handled = false
      await act(async () => {
        handled = result.current.handleWorkspaceError('w1', refusal('auth.workspace_not_found'))
        await Promise.resolve()
      })

      expect(handled).toBe(true)
      expect(onWorkspaceAccessLost).not.toHaveBeenCalled()
      expect(client.listWorkspaces).toHaveBeenCalledTimes(1)
    })

    it('does not call the callback when no workspace is active', async () => {
      const onWorkspaceAccessLost = jest.fn()
      const { result } = mount(signedIn([W1], null), { current: { onWorkspaceAccessLost } })
      await settle()

      act(() => {
        result.current.handleWorkspaceError('w1', refusal('auth.workspace_not_found'))
      })

      expect(onWorkspaceAccessLost).not.toHaveBeenCalled()
    })

    it.each([
      ['an error that is not an AuthClientError', new Error('boom')],
      ['a string', 'auth.workspace_not_found'],
      ['null', null],
      ['an AuthClientError with another code', refusal('auth.token_invalid')],
      ['an AuthClientError with no code', new AuthClientError('x', 500)],
      [
        'an object that only looks like one',
        { name: 'Error', code: 'auth.workspace_not_found', status: 404 }
      ]
    ])('leaves %s alone', async (_name, error) => {
      const onWorkspaceAccessLost = jest.fn()
      const { result } = mount(signedIn(), { current: { onWorkspaceAccessLost } })
      await settle()

      expect(result.current.handleWorkspaceError('w2', error)).toBe(false)
      expect(onWorkspaceAccessLost).not.toHaveBeenCalled()
    })

    it('warns and carries on when the callback throws', async () => {
      const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined)
      const onWorkspaceAccessLost = jest.fn(() => {
        throw new Error('host bug')
      })
      const { result } = mount(signedIn(), { current: { onWorkspaceAccessLost } })
      await settle()

      let handled = false
      await act(async () => {
        handled = result.current.handleWorkspaceError('w2', refusal('auth.workspace_not_found'))
        await Promise.resolve()
      })

      expect(handled).toBe(true)
      expect(warn).toHaveBeenCalledWith(
        '[nest-auth] onWorkspaceAccessLost callback threw:',
        expect.any(Error)
      )
    })
  })

  describe('the cross-tab channel', () => {
    beforeEach(() => {
      Object.assign(globalThis, { BroadcastChannel: FakeChannel })
    })

    it('tells the other tabs when the caller switches, and they reload their lists', async () => {
      const first = signedIn()
      const second = signedIn()
      const { result } = mount(first)
      mount(second)
      await settle()
      expect(second.listWorkspaces).toHaveBeenCalledTimes(1)

      await act(async () => {
        await result.current.switchWorkspace('w1')
      })
      await settle()

      expect(second.listWorkspaces).toHaveBeenCalledTimes(2)
      expect(first.listWorkspaces).toHaveBeenCalledTimes(1)
    })

    it('makes no request in a tab that is signed out, and stays idle when it hears a switch', async () => {
      const signedOut = signedIn()
      signedOut.getMe.mockRejectedValue(new AuthClientError('no', 401))
      const active = signedIn()
      const { result } = mount(active)
      mount(signedOut)
      await settle()

      await act(async () => {
        await result.current.switchWorkspace('w1')
      })
      await settle()

      expect(signedOut.listWorkspaces).not.toHaveBeenCalled()
      expect(signedOut.getMe).toHaveBeenCalledTimes(1)
    })

    it('makes no request in a tab whose session is not known yet when it hears a switch', async () => {
      const pending = signedIn()
      pending.getMe.mockImplementation(() => new Promise(() => undefined))
      const active = signedIn()
      const { result } = mount(active)
      const other = mount(pending)
      await settle()

      await act(async () => {
        await result.current.switchWorkspace('w1')
      })
      await settle()

      expect(pending.listWorkspaces).not.toHaveBeenCalled()
      expect(other.result.current.status).toBe('idle')
    })

    it('does not change the active workspace of the tab that hears it', async () => {
      const first = signedIn()
      const second = signedIn()
      const { result } = mount(first)
      const other = mount(second)
      await settle()

      await act(async () => {
        await result.current.switchWorkspace('w1')
      })
      await settle()

      expect(other.result.current.activeWorkspace).toEqual(W2)
    })

    it('uses one named channel and closes what it opens', async () => {
      const { result, unmount } = mount(signedIn())
      await settle()
      await act(async () => {
        await result.current.switchWorkspace('w1')
      })

      unmount()

      expect(new Set(FakeChannel.instances.map((c) => c.name))).toEqual(
        new Set(['nest-auth:workspaces'])
      )
      expect(FakeChannel.instances.every((c) => c.closed)).toBe(true)
    })

    it('works with no channel at all', async () => {
      Reflect.deleteProperty(globalThis, 'BroadcastChannel')
      const { result } = mount(signedIn())
      await settle()

      await act(async () => {
        await result.current.switchWorkspace('w1')
      })

      expect(result.current.activeWorkspace).toEqual(W1)
    })
  })
})
