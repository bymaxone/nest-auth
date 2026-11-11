/**
 * @jest-environment @stryker-mutator/jest-runner/jest-env/jsdom
 */

/**
 * The state `<WorkspaceProvider>` keeps across renders and sign-ins: the options it reads, the chosen
 * workspace, the loading and error states, the notice that the active workspace changed, and what is
 * posted to other tabs. Each case fails when the behaviour it names is removed.
 */

import { act, renderHook } from '@testing-library/react'
import { type ReactNode } from 'react'

import { AuthClientError } from '../../shared'
import { AuthProvider } from '../AuthProvider'
import { WorkspaceProvider } from '../WorkspaceProvider'
import type { AuthWorkspacesOptions } from '../workspaceContext'
import { useAuth } from '../useAuth'
import { useSession } from '../useSession'
import { useWorkspaces } from '../useWorkspaces'

import { MOCK_USER } from './_testHelpers'
import { FakeChannel, mount, settle, signedIn, W1, W2, type TestClient } from './_workspaceTestKit'

type List = Awaited<ReturnType<TestClient['listWorkspaces']>>

/** Mounts the workspace hook beside the auth hooks, so a test can sign out and in. */
function mountAuth(client: TestClient, options: AuthWorkspacesOptions = {}) {
  client.logout.mockResolvedValue(undefined)
  client.login.mockResolvedValue({ user: MOCK_USER, accessToken: '' })
  const wrapper = ({ children }: { children: ReactNode }): ReactNode => (
    <AuthProvider client={client}>
      <WorkspaceProvider client={client} {...options}>
        {children}
      </WorkspaceProvider>
    </AuthProvider>
  )
  return renderHook(
    () => ({ workspaces: useWorkspaces(), auth: useAuth(), session: useSession() }),
    { wrapper }
  )
}

const clone = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T

describe('WorkspaceProvider state', () => {
  afterEach(() => {
    jest.restoreAllMocks()
    Reflect.deleteProperty(globalThis, 'BroadcastChannel')
    FakeChannel.instances = []
    FakeChannel.posted = []
  })

  it('calls the callbacks of the latest render, not of the first', async () => {
    const first = jest.fn()
    const second = jest.fn()
    const holder = { current: { onWorkspaceChanged: first } as AuthWorkspacesOptions | undefined }
    const { result, rerender } = mount(signedIn(), holder)
    await settle()
    holder.current = { onWorkspaceChanged: second }
    rerender()

    await act(async () => {
      await result.current.switchWorkspace('w1')
    })

    expect(first).not.toHaveBeenCalled()
    expect(second).toHaveBeenCalledTimes(1)
  })

  it('uses the hierarchy of the latest render for the role hint', async () => {
    const holder = { current: {} as AuthWorkspacesOptions | undefined }
    const { result, rerender } = mount(signedIn([W1, W2], 'w1'), holder)
    await settle()
    expect(result.current.hasWorkspaceRole('viewer')).toBe(false)

    holder.current = { hierarchy: { editor: ['viewer'] } }
    rerender()

    expect(result.current.hasWorkspaceRole('viewer')).toBe(true)
  })

  describe('the chosen workspace', () => {
    it('is forgotten when the caller signs out, so the next session starts from the server', async () => {
      const { result } = mountAuth(signedIn())
      await settle()
      await act(async () => {
        await result.current.workspaces.switchWorkspace('w1')
      })
      expect(result.current.workspaces.activeWorkspace).toEqual(W1)

      await act(async () => {
        await result.current.auth.logout()
      })
      await act(async () => {
        await result.current.auth.login('a@b.c', 'pw')
      })
      await settle()

      expect(result.current.workspaces.activeWorkspace).toEqual(W2)
    })

    it('survives a failed reload and the reload after it', async () => {
      const client = signedIn()
      const { result } = mount(client)
      await settle()
      await act(async () => {
        await result.current.switchWorkspace('w1')
      })
      client.listWorkspaces.mockRejectedValueOnce(new AuthClientError('down', 503))

      await act(async () => {
        await result.current.refresh()
      })
      expect(result.current.status).toBe('error')
      await act(async () => {
        await result.current.refresh()
      })

      expect(result.current.status).toBe('ready')
      expect(result.current.activeWorkspace).toEqual(W1)
    })

    it('still outranks what the server remembers when the list is read again', async () => {
      const client = signedIn()
      const { result } = mount(client)
      await settle()
      await act(async () => {
        await result.current.switchWorkspace('w1')
      })

      await act(async () => {
        await result.current.refresh()
      })

      expect(client.listWorkspaces).toHaveBeenCalledTimes(2)
      expect(result.current.lastActiveWorkspaceId).toBe('w2')
      expect(result.current.activeWorkspace).toEqual(W1)
    })
  })

  describe('loading', () => {
    it('reports loading while the first list is on its way', async () => {
      const client = signedIn()
      let finish: (value: List) => void = () => undefined
      client.listWorkspaces.mockImplementationOnce(
        () => new Promise((resolve) => (finish = resolve))
      )
      const { result } = mount(client)

      await settle()
      expect(result.current.status).toBe('loading')
      expect(result.current.memberships).toEqual([])
      await act(async () => {
        finish({ items: [W1], nextCursor: null, lastActiveWorkspaceId: 'w1' })
        await Promise.resolve()
      })

      expect(result.current.status).toBe('ready')
    })

    it('reports loading, not the earlier error, while a revalidated session reloads', async () => {
      const client = signedIn()
      client.listWorkspaces.mockRejectedValueOnce(new AuthClientError('down', 503))
      const { result } = mountAuth(client)
      await settle()
      expect(result.current.workspaces.status).toBe('error')
      let finishList: (value: List) => void = () => undefined
      client.listWorkspaces.mockImplementationOnce(
        () => new Promise((resolve) => (finishList = resolve))
      )
      let finishLogin: (value: { user: typeof MOCK_USER; accessToken: string }) => void = () =>
        undefined
      client.login.mockImplementationOnce(() => new Promise((resolve) => (finishLogin = resolve)))
      let signIn: Promise<unknown> = Promise.resolve()
      await act(async () => {
        signIn = result.current.auth.login('a@b.c', 'pw')
        await Promise.resolve()
      })

      await act(async () => {
        finishLogin({ user: MOCK_USER, accessToken: '' })
        await signIn
      })

      expect(result.current.workspaces.status).toBe('loading')
      await act(async () => {
        finishList({ items: [W1, W2], nextCursor: null, lastActiveWorkspaceId: 'w2' })
        await Promise.resolve()
      })
      expect(result.current.workspaces.status).toBe('ready')
    })

    it('keeps the list in view while a revalidated session reloads it', async () => {
      const client = signedIn()
      const { result } = mountAuth(client)
      await settle()
      let finishList: (value: List) => void = () => undefined
      client.listWorkspaces.mockImplementationOnce(
        () => new Promise((resolve) => (finishList = resolve))
      )
      let finishLogin: (value: { user: typeof MOCK_USER; accessToken: string }) => void = () =>
        undefined
      client.login.mockImplementationOnce(() => new Promise((resolve) => (finishLogin = resolve)))
      let signIn: Promise<unknown> = Promise.resolve()
      await act(async () => {
        signIn = result.current.auth.login('a@b.c', 'pw')
        await Promise.resolve()
      })
      expect(result.current.session.status).toBe('loading')

      await act(async () => {
        finishLogin({ user: MOCK_USER, accessToken: '' })
        await signIn
      })

      expect(client.listWorkspaces).toHaveBeenCalledTimes(2)
      expect(result.current.workspaces.status).toBe('ready')
      expect(result.current.workspaces.memberships).toHaveLength(2)
      await act(async () => {
        finishList({ items: [W1, W2], nextCursor: null, lastActiveWorkspaceId: 'w2' })
        await Promise.resolve()
      })
    })
  })

  describe('onWorkspaceChanged', () => {
    it('does not treat the first load of a new session as a change', async () => {
      const onWorkspaceChanged = jest.fn()
      const client = signedIn()
      const { result } = mountAuth(client, { onWorkspaceChanged })
      await settle()
      await act(async () => {
        await result.current.auth.logout()
      })
      client.listWorkspaces.mockResolvedValue({
        items: [W1, W2],
        nextCursor: null,
        lastActiveWorkspaceId: 'w1'
      })

      await act(async () => {
        await result.current.auth.login('a@b.c', 'pw')
      })
      await settle()

      expect(result.current.workspaces.activeWorkspace).toEqual(W1)
      expect(onWorkspaceChanged).not.toHaveBeenCalled()
    })

    it('is not called when a reload returns the same workspace as new objects', async () => {
      const onWorkspaceChanged = jest.fn()
      const client = signedIn()
      const { result } = mount(client, { current: { onWorkspaceChanged } })
      await settle()
      client.listWorkspaces.mockResolvedValue({
        items: [clone(W1), clone(W2)],
        nextCursor: null,
        lastActiveWorkspaceId: 'w2'
      })

      await act(async () => {
        await result.current.refresh()
      })

      expect(result.current.activeWorkspace).toEqual(W2)
      expect(onWorkspaceChanged).not.toHaveBeenCalled()
    })
  })

  it.each([
    ['undefined', undefined],
    ['a number', 5],
    ['a boolean', true]
  ])('leaves %s alone in the refusal handler', async (_name, error) => {
    const { result } = mount(signedIn())
    await settle()

    expect(result.current.handleWorkspaceError('w2', error)).toBe(false)
  })

  it('posts what other tabs listen for, and nothing else, when the caller switches', async () => {
    Object.assign(globalThis, { BroadcastChannel: FakeChannel })
    const { result } = mount(signedIn())
    await settle()

    await act(async () => {
      await result.current.switchWorkspace('w1')
    })

    expect(FakeChannel.posted).toEqual([{ type: 'workspaces-changed' }])
  })

  describe('the account the workspaces belong to', () => {
    // Another tab can sign in as someone else: the session stays 'authenticated' and only the user
    // changes, so the list of the first account must not be shown under the second.
    it('reloads, and forgets the chosen workspace, when the signed-in account changes', async () => {
      const client = signedIn()
      const { result } = mountAuth(client)
      await settle()
      await act(async () => {
        await result.current.workspaces.switchWorkspace('w1')
      })
      client.getMe.mockResolvedValue({ ...MOCK_USER, id: 'bob' })
      client.listWorkspaces.mockResolvedValue({
        items: [W2],
        nextCursor: null,
        lastActiveWorkspaceId: 'w2'
      })

      await act(async () => {
        await result.current.session.refresh()
      })
      await settle()

      expect(client.listWorkspaces).toHaveBeenCalledTimes(2)
      expect(result.current.workspaces.memberships).toEqual([W2])
      expect(result.current.workspaces.activeWorkspace).toEqual(W2)
    })

    // The reset runs in an effect, so the render in which the account changes must already read as
    // empty: no render may pair one account's workspaces with another account.
    it("never renders the first account's workspaces under the second account", async () => {
      const client = signedIn()
      client.logout.mockResolvedValue(undefined)
      const renders: Array<{ user: string | undefined; ids: string[]; active: string | null }> = []
      const wrapper = ({ children }: { children: ReactNode }): ReactNode => (
        <AuthProvider client={client}>
          <WorkspaceProvider client={client}>{children}</WorkspaceProvider>
        </AuthProvider>
      )
      const { result } = renderHook(
        () => {
          const value = { workspaces: useWorkspaces(), session: useSession() }
          renders.push({
            user: value.session.user?.id,
            ids: value.workspaces.memberships.map((m) => m.workspace.id),
            active: value.workspaces.activeWorkspace?.workspace.id ?? null
          })
          return value
        },
        { wrapper }
      )
      await settle()
      client.getMe.mockResolvedValue({ ...MOCK_USER, id: 'bob' })
      client.listWorkspaces.mockResolvedValue({
        items: [W2],
        nextCursor: null,
        lastActiveWorkspaceId: 'w2'
      })

      await act(async () => {
        await result.current.session.refresh()
      })
      await settle()

      const underBob = renders.filter((render) => render.user === 'bob')
      expect(underBob.length).toBeGreaterThan(0)
      expect(underBob.flatMap((render) => render.ids).filter((id) => id === 'w1')).toEqual([])
      expect(underBob[0]?.ids).toEqual([])
      expect(underBob[0]?.active).toBeNull()
    })

    it('ignores a switch that resolves after the account changed', async () => {
      const client = signedIn()
      const { result } = mountAuth(client)
      await settle()
      let finishSwitch: () => void = () => undefined
      client.switchWorkspace.mockImplementationOnce(
        () => new Promise((resolve) => (finishSwitch = () => resolve(undefined)))
      )
      let switching: Promise<void> = Promise.resolve()
      await act(async () => {
        switching = result.current.workspaces.switchWorkspace('w1')
        await Promise.resolve()
      })
      client.getMe.mockResolvedValue({ ...MOCK_USER, id: 'bob' })
      client.listWorkspaces.mockResolvedValue({
        items: [W2],
        nextCursor: null,
        lastActiveWorkspaceId: 'w2'
      })
      await act(async () => {
        await result.current.session.refresh()
      })
      await settle()

      await act(async () => {
        finishSwitch()
        await switching
      })

      expect(result.current.workspaces.lastActiveWorkspaceId).toBe('w2')
      expect(result.current.workspaces.activeWorkspace).toEqual(W2)
    })

    it('keeps what it shows while a sign-in is in flight for the same session', async () => {
      const client = signedIn()
      client.listWorkspaces.mockRejectedValueOnce(new Error('down'))
      const { result } = mountAuth(client)
      await settle()
      expect(result.current.workspaces.status).toBe('error')
      const slow: { resolve: (value: { user: typeof MOCK_USER; accessToken: string }) => void } = {
        resolve: () => undefined
      }
      client.login.mockReturnValueOnce(new Promise((resolve) => (slow.resolve = resolve)))

      let signingIn: Promise<unknown> = Promise.resolve()
      await act(async () => {
        signingIn = result.current.auth.login('a@b.c', 'pw')
        await Promise.resolve()
      })

      expect(result.current.session.status).toBe('loading')
      expect(result.current.workspaces.status).toBe('error')
      await act(async () => {
        slow.resolve({ user: MOCK_USER, accessToken: '' })
        await signingIn
      })
    })

    it('does not show a failure of a load that a newer load replaced', async () => {
      const client = signedIn()
      const { result } = mountAuth(client)
      await settle()
      const failing: { reject: (error: Error) => void } = { reject: () => undefined }
      client.listWorkspaces.mockReturnValueOnce(
        new Promise((_resolve, reject) => (failing.reject = reject))
      )
      await act(async () => {
        void result.current.workspaces.refresh()
        await Promise.resolve()
      })
      await act(async () => {
        await result.current.workspaces.refresh()
      })
      expect(result.current.workspaces.status).toBe('ready')

      await act(async () => {
        failing.reject(new Error('late'))
        await Promise.resolve()
      })

      expect(result.current.workspaces.status).toBe('ready')
    })

    it('does not reload for the same account revalidating', async () => {
      const client = signedIn()
      const { result } = mountAuth(client)
      await settle()

      await act(async () => {
        await result.current.session.refresh()
      })
      await settle()

      expect(client.listWorkspaces).toHaveBeenCalledTimes(1)
    })

    it('shows nothing of the first account while the second account loads', async () => {
      const client = signedIn()
      const { result } = mountAuth(client)
      await settle()
      let finish: (value: List) => void = () => undefined
      client.getMe.mockResolvedValue({ ...MOCK_USER, id: 'bob' })
      client.listWorkspaces.mockImplementationOnce(
        () => new Promise((resolve) => (finish = resolve))
      )

      await act(async () => {
        await result.current.session.refresh()
      })

      expect(result.current.workspaces.status).toBe('loading')
      expect(result.current.workspaces.memberships).toEqual([])
      expect(result.current.workspaces.activeWorkspace).toBeNull()
      await act(async () => {
        finish({ items: [W2], nextCursor: null, lastActiveWorkspaceId: 'w2' })
        await Promise.resolve()
      })
      expect(result.current.workspaces.memberships).toEqual([W2])
    })

    it('treats the first load for another account as a new session, with no change notice', async () => {
      const onWorkspaceChanged = jest.fn()
      const client = signedIn()
      const { result } = mountAuth(client, { onWorkspaceChanged })
      await settle()
      let finish: (value: List) => void = () => undefined
      client.getMe.mockResolvedValue({ ...MOCK_USER, id: 'bob' })
      client.listWorkspaces.mockImplementationOnce(
        () => new Promise((resolve) => (finish = resolve))
      )

      await act(async () => {
        await result.current.session.refresh()
      })
      expect(result.current.workspaces.status).toBe('loading')
      await act(async () => {
        finish({ items: [W1, W2], nextCursor: null, lastActiveWorkspaceId: 'w1' })
        await Promise.resolve()
      })

      expect(result.current.workspaces.activeWorkspace).toEqual(W1)
      expect(onWorkspaceChanged).not.toHaveBeenCalled()
    })
  })

  describe('a newer load', () => {
    it('aborts the older one, which then follows no page and sets no state', async () => {
      const client = signedIn()
      const { result } = mount(client)
      await settle()
      let finishOlder: (value: List) => void = () => undefined
      let olderSignal: AbortSignal | undefined
      client.listWorkspaces.mockImplementationOnce((_page, init) => {
        olderSignal = init?.signal
        return new Promise((resolve) => (finishOlder = resolve))
      })
      let older: Promise<void> = Promise.resolve()
      await act(async () => {
        older = result.current.refresh()
        await Promise.resolve()
      })
      client.listWorkspaces.mockResolvedValue({
        items: [W1],
        nextCursor: null,
        lastActiveWorkspaceId: 'w1'
      })

      await act(async () => {
        await result.current.refresh()
      })
      expect(olderSignal?.aborted).toBe(true)
      await act(async () => {
        finishOlder({ items: [W2], nextCursor: 'more', lastActiveWorkspaceId: 'w2' })
        await older
      })

      expect(client.listWorkspaces).toHaveBeenCalledTimes(3)
      expect(result.current.memberships).toEqual([W1])
    })
  })

  describe('unmounting', () => {
    it('stops following pages and sets no state when the provider goes away mid-load', async () => {
      const client = signedIn()
      let finish: (value: List) => void = () => undefined
      client.listWorkspaces.mockImplementationOnce(
        () => new Promise((resolve) => (finish = resolve))
      )
      const { unmount } = mountAuth(client)
      await settle()
      expect(client.listWorkspaces).toHaveBeenCalledTimes(1)

      unmount()
      await act(async () => {
        finish({ items: [W1], nextCursor: 'more', lastActiveWorkspaceId: 'w1' })
        await Promise.resolve()
        await Promise.resolve()
      })

      expect(client.listWorkspaces).toHaveBeenCalledTimes(1)
    })

    it('passes a signal to the list call and aborts it on unmount', async () => {
      const client = signedIn()
      let seen: AbortSignal | undefined
      client.listWorkspaces.mockImplementationOnce((_page, init) => {
        seen = init?.signal
        return new Promise(() => undefined)
      })
      const { unmount } = mountAuth(client)
      await settle()
      expect(seen?.aborted).toBe(false)

      unmount()

      expect(seen?.aborted).toBe(true)
    })
  })
})
