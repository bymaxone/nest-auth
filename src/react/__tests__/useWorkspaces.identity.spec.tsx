/**
 * @jest-environment @stryker-mutator/jest-runner/jest-env/jsdom
 */

/**
 * What `<WorkspaceProvider>` shows across an account change. Every render is recorded with the account
 * the session reports and what the workspace hook returns, and no render may pair one account with the
 * other's data, wherever in a load, a switch, a revalidation or a broadcast the change lands.
 */

import { act, renderHook } from '@testing-library/react'
import { type ReactNode } from 'react'

import { AuthProvider } from '../AuthProvider'
import { useSession } from '../useSession'
import { useWorkspaces } from '../useWorkspaces'
import { WorkspaceProvider } from '../WorkspaceProvider'

import { MOCK_USER } from './_testHelpers'
import { FakeChannel, settle, signedIn, W1, W2, type TestClient } from './_workspaceTestKit'

type List = Awaited<ReturnType<TestClient['listWorkspaces']>>

const OWN_DATA: Record<string, { id: string; last: string }> = {
  alice: { id: 'w1', last: 'w1' },
  bob: { id: 'w2', last: 'w2' }
}
const LIST: Record<string, List> = {
  alice: { items: [W1], nextCursor: null, lastActiveWorkspaceId: 'w1' },
  bob: { items: [W2], nextCursor: null, lastActiveWorkspaceId: 'w2' }
}

interface Seen {
  user: string | undefined
  ids: string[]
  last: string | null
  active: string | null
}

/** A deferred answer, so a test decides when a request resolves. */
function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve: (value: T) => void = () => undefined
  const promise = new Promise<T>((done) => (resolve = done))
  return { promise, resolve }
}

function mountRecording(client: TestClient) {
  Object.assign(globalThis, { BroadcastChannel: FakeChannel })
  const seen: Seen[] = []
  const wrapper = ({ children }: { children: ReactNode }): ReactNode => (
    <AuthProvider client={client}>
      <WorkspaceProvider client={client}>{children}</WorkspaceProvider>
    </AuthProvider>
  )
  const view = renderHook(
    () => {
      const value = { workspaces: useWorkspaces(), session: useSession() }
      seen.push({
        user: value.session.user?.id,
        ids: value.workspaces.memberships.map((member) => member.workspace.id),
        last: value.workspaces.lastActiveWorkspaceId,
        active: value.workspaces.activeWorkspace?.workspace.id ?? null
      })
      return value
    },
    { wrapper }
  )
  return { ...view, seen }
}

/** Every render under `user` that shows anything read for another account. */
function foreign(seen: Seen[], user: string): Seen[] {
  const own = OWN_DATA[user]
  return seen.filter(
    (render) =>
      render.user === user &&
      (render.ids.some((id) => id !== own?.id) ||
        (render.last !== null && render.last !== own?.last) ||
        (render.active !== null && render.active !== own?.id))
  )
}

const asBob = (client: TestClient): void => {
  client.getMe.mockResolvedValue({ ...MOCK_USER, id: 'bob' })
  client.listWorkspaces.mockResolvedValue(LIST.bob as List)
}

describe('WorkspaceProvider across an account change', () => {
  beforeEach(() => {
    FakeChannel.instances = []
    FakeChannel.posted = []
  })
  afterEach(() => {
    jest.restoreAllMocks()
    Reflect.deleteProperty(globalThis, 'BroadcastChannel')
  })

  const asAlice = (): TestClient => {
    const client = signedIn()
    client.getMe.mockResolvedValue({ ...MOCK_USER, id: 'alice' })
    client.listWorkspaces.mockResolvedValue(LIST.alice as List)
    return client
  }

  const changeAccount = async (
    result: { current: { session: { refresh: () => Promise<void> } } },
    client: TestClient
  ): Promise<void> => {
    asBob(client)
    await act(async () => {
      await result.current.session.refresh()
    })
    await settle()
  }

  it('shows nothing of the first account in the render where the second one appears', async () => {
    const client = asAlice()
    const { result, seen } = mountRecording(client)
    await settle()
    expect(result.current.workspaces.memberships).toEqual([W1])

    await changeAccount(result, client)

    expect(foreign(seen, 'bob')).toEqual([])
    expect(seen.find((render) => render.user === 'bob')?.ids).toEqual([])
    expect(result.current.workspaces.activeWorkspace).toEqual(W2)
  })

  it('shows nothing of the first account when its load answers after the change', async () => {
    const client = asAlice()
    const late = deferred<List>()
    client.listWorkspaces.mockReturnValueOnce(late.promise)
    const { result, seen } = mountRecording(client)
    await settle()

    await changeAccount(result, client)
    await act(async () => {
      late.resolve(LIST.alice as List)
      await late.promise
    })
    await settle()

    expect(foreign(seen, 'bob')).toEqual([])
    expect(result.current.workspaces.memberships).toEqual([W2])
  })

  it('shows nothing of the first account when its switch answers after the change', async () => {
    const client = asAlice()
    const { result, seen } = mountRecording(client)
    await settle()
    const answer = deferred<undefined>()
    client.switchWorkspace.mockReturnValueOnce(answer.promise)
    let switching: Promise<void> = Promise.resolve()
    await act(async () => {
      switching = result.current.workspaces.switchWorkspace('w1')
      await Promise.resolve()
    })

    await changeAccount(result, client)
    await act(async () => {
      answer.resolve(undefined)
      await switching
    })

    expect(foreign(seen, 'bob')).toEqual([])
    expect(result.current.workspaces.lastActiveWorkspaceId).toBe('w2')
    expect(FakeChannel.posted).toEqual([])
  })

  it('shows nothing of the first account when the change lands during a revalidation', async () => {
    const client = asAlice()
    const { result, seen } = mountRecording(client)
    await settle()
    const slow = deferred<typeof MOCK_USER>()
    client.getMe.mockReturnValueOnce(slow.promise)
    let revalidating: Promise<void> = Promise.resolve()
    await act(async () => {
      revalidating = result.current.session.refresh()
      await Promise.resolve()
    })

    client.listWorkspaces.mockResolvedValue(LIST.bob as List)
    await act(async () => {
      slow.resolve({ ...MOCK_USER, id: 'bob' })
      await revalidating
    })
    await settle()

    expect(foreign(seen, 'bob')).toEqual([])
    expect(foreign(seen, 'alice')).toEqual([])
  })

  it('shows nothing of the first account when another tab broadcasts during the change', async () => {
    const client = asAlice()
    const { result, seen } = mountRecording(client)
    await settle()
    const late = deferred<List>()
    client.listWorkspaces.mockReturnValueOnce(late.promise)
    act(() => {
      new FakeChannel('nest-auth:workspaces').postMessage({ type: 'workspaces-changed' })
    })

    await changeAccount(result, client)
    await act(async () => {
      late.resolve(LIST.alice as List)
      await late.promise
    })
    await settle()

    expect(foreign(seen, 'bob')).toEqual([])
    expect(result.current.workspaces.memberships).toEqual([W2])
  })
})
