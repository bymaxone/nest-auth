/**
 * Helpers shared by the `useWorkspaces` specs: a signed-in client with a workspace list, a mount under
 * the real providers, a settle, and a cross-tab channel double.
 */

import { act, renderHook, type RenderHookResult } from '@testing-library/react'
import { type ReactNode } from 'react'

import type { WorkspaceAccessClient } from '../../shared'
import { AuthProvider } from '../AuthProvider'
import { useWorkspaces } from '../useWorkspaces'
import type { AuthWorkspacesOptions, WorkspacesContextValue } from '../workspaceContext'
import { WorkspaceProvider } from '../WorkspaceProvider'
import { createMockClient, MOCK_USER, type MockAuthClient } from './_testHelpers'

export const workspace = (id: string, role: string): WorkspaceAccessClient => ({
  workspace: {
    id,
    name: `Workspace ${id}`,
    status: 'active',
    createdAt: '2026-01-01T00:00:00.000Z',
    deletionScheduledAt: null
  },
  role
})

export const W1 = workspace('w1', 'editor')
export const W2 = workspace('w2', 'viewer')

export type WorkspaceMocks = {
  listWorkspaces: jest.Mock<
    Promise<{
      items: WorkspaceAccessClient[]
      nextCursor: string | null
      lastActiveWorkspaceId: string | null
    }>,
    [({ cursor?: string } | undefined)?]
  >
  switchWorkspace: jest.Mock<Promise<void>, [string]>
}
export type TestClient = MockAuthClient & WorkspaceMocks

/** A client that is signed in and whose workspaces are `items`, last active `lastActive`. */
export function signedIn(items = [W1, W2], lastActive: string | null = 'w2'): TestClient {
  const client = Object.assign(createMockClient(), {
    listWorkspaces: jest.fn() as WorkspaceMocks['listWorkspaces'],
    switchWorkspace: jest.fn() as WorkspaceMocks['switchWorkspace']
  })
  client.getMe.mockResolvedValue(MOCK_USER)
  client.listWorkspaces.mockResolvedValue({
    items,
    nextCursor: null,
    lastActiveWorkspaceId: lastActive
  })
  client.switchWorkspace.mockResolvedValue(undefined)
  return client
}

/** Mounts the hook under a provider whose `workspaces` option is read fresh on every render. */
export function mount(
  client: TestClient,
  options?: { current: AuthWorkspacesOptions | undefined }
): RenderHookResult<WorkspacesContextValue, unknown> & {
  holder: { current: AuthWorkspacesOptions | undefined }
} {
  const holder = options ?? { current: {} }
  const wrapper = ({ children }: { children: ReactNode }): ReactNode => (
    <AuthProvider client={client}>
      {holder.current === undefined ? (
        children
      ) : (
        <WorkspaceProvider client={client} {...holder.current}>
          {children}
        </WorkspaceProvider>
      )}
    </AuthProvider>
  )
  const view = renderHook(() => useWorkspaces(), { wrapper })
  return { ...view, holder }
}

export const settle = async (): Promise<void> => {
  await act(async () => {
    await Promise.resolve()
    await Promise.resolve()
  })
}

/** A cross-tab channel double: every instance hears what any other posts. */
export class FakeChannel {
  static instances: FakeChannel[] = []
  static posted: unknown[] = []
  onmessage: ((event: { data: unknown }) => void) | null = null
  closed = false
  constructor(readonly name: string) {
    FakeChannel.instances.push(this)
  }
  postMessage(data: unknown): void {
    FakeChannel.posted.push(data)
    for (const other of FakeChannel.instances) {
      if (other !== this && !other.closed) other.onmessage?.({ data })
    }
  }
  close(): void {
    this.closed = true
  }
}
