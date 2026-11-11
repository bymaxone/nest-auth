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
})
