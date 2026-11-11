/**
 * The state of `<WorkspaceProvider>`, as small hooks: the list of the caller's workspaces, the
 * notice that the active one changed, the cross-tab channel, the role hint and the refusal handler.
 * Each takes what it reads and nothing else, so `WorkspaceProvider` only assembles them.
 */

import {
  type Dispatch,
  type RefObject,
  type SetStateAction,
  useCallback,
  useEffect,
  useRef,
  useState
} from 'react'

import type { WorkspaceClientMethods } from '@bymax-one/nest-auth/client'
import type { WorkspaceAccessClient } from '@bymax-one/nest-auth/shared'

import type { AuthStatus } from './context'
import type {
  AuthWorkspacesOptions,
  WorkspaceRefusalCode,
  WorkspacesStatus
} from './workspaceContext'

/** The channel other tabs of this origin are told on when the caller's workspaces change. */
const CHANNEL_NAME = 'nest-auth:workspaces'

/** Most pages of memberships followed on one load, so a misbehaving server cannot loop forever. */
const MAX_PAGES = 20

const REFUSAL_CODES: ReadonlySet<string> = new Set<WorkspaceRefusalCode>([
  'auth.workspace_not_found',
  'auth.insufficient_workspace_role',
  'auth.workspace_pending_deletion'
])

/** What the state hooks read of the host's options, kept current by the provider. */
export type OptionsRef = { readonly current: AuthWorkspacesOptions }

/** The loaded list, and where loading stands. */
export interface Loaded {
  status: WorkspacesStatus
  items: readonly WorkspaceAccessClient[]
  lastActiveWorkspaceId: string | null
}

const IDLE: Loaded = { status: 'idle', items: [], lastActiveWorkspaceId: null }

/** What the provider needs of the workspace client: the list and the switch. */
export type WorkspaceProviderClient = Pick<
  WorkspaceClientMethods,
  'listWorkspaces' | 'switchWorkspace'
>

/** Follows the cursors of the caller's workspaces to the end, or to {@link MAX_PAGES}. */
async function loadAll(client: WorkspaceProviderClient): Promise<Omit<Loaded, 'status'>> {
  const items: WorkspaceAccessClient[] = []
  let lastActiveWorkspaceId: string | null = null
  let cursor: string | undefined
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const result = await client.listWorkspaces(cursor === undefined ? undefined : { cursor })
    if (page === 0) lastActiveWorkspaceId = result.lastActiveWorkspaceId
    items.push(...result.items)
    if (result.nextCursor === null) break
    cursor = result.nextCursor
  }
  return { items, lastActiveWorkspaceId }
}

/** The workspace refusal code an error carries, or `undefined` for any other error. */
function refusalCodeOf(error: unknown): WorkspaceRefusalCode | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const { name, code } = error as { name?: unknown; code?: unknown }
  if (name !== 'AuthClientError' || typeof code !== 'string') return undefined
  return REFUSAL_CODES.has(code) ? (code as WorkspaceRefusalCode) : undefined
}

/** Runs a host callback, logging and swallowing what it throws. */
function callHost(name: string, run: (() => void) | undefined): void {
  try {
    run?.()
  } catch (error) {
    console.warn(`[nest-auth] ${name} callback threw:`, error)
  }
}

/**
 * Loads the caller's workspaces once the session is known to be signed in, and empties them when it
 * ends. A load that finishes after the session changed is ignored, and a reload requested while the
 * session is not signed in does nothing, so a tab that hears a broadcast while signed out makes no
 * request.
 *
 * @param client - The workspace client.
 * @param authStatus - The session status the auth provider owns.
 * @returns The loaded list, its setter, and the reload.
 */
export function useWorkspaceList(
  client: WorkspaceProviderClient,
  authStatus: AuthStatus
): {
  loaded: Loaded
  setLoaded: Dispatch<SetStateAction<Loaded>>
  clientRef: RefObject<WorkspaceProviderClient>
  refresh: () => Promise<void>
} {
  const [loaded, setLoaded] = useState<Loaded>(IDLE)
  const clientRef = useRef(client)
  const statusRef = useRef(authStatus)
  const generationRef = useRef<object>({})

  // Kept current in an effect, declared before every effect that reads them, so a load never runs
  // against the client or the session status of an earlier render.
  useEffect(() => {
    clientRef.current = client
    statusRef.current = authStatus
  })

  const refresh = useCallback(async (): Promise<void> => {
    if (statusRef.current !== 'authenticated') return
    const generation = generationRef.current
    try {
      const result = await loadAll(clientRef.current)
      if (generationRef.current === generation) setLoaded({ status: 'ready', ...result })
    } catch {
      if (generationRef.current === generation) setLoaded({ ...IDLE, status: 'error' })
    }
  }, [])

  useEffect(() => {
    generationRef.current = {}
    if (authStatus === 'authenticated') {
      setLoaded((current) =>
        current.status === 'ready' ? current : { ...IDLE, status: 'loading' }
      )
      void refresh()
    } else if (authStatus === 'unauthenticated') {
      setLoaded(IDLE)
    }
  }, [authStatus, refresh])

  return { loaded, setLoaded, clientRef, refresh }
}

/**
 * Tells the host, through `onWorkspaceChanged`, when the active workspace changes after the first
 * load. A list that empties (sign-out) starts the next load as a first one.
 *
 * @param status - Where the list stands.
 * @param active - The active workspace.
 * @param optionsRef - The host's options, current.
 */
export function useChangeNotice(
  status: WorkspacesStatus,
  active: WorkspaceAccessClient | null,
  optionsRef: OptionsRef
): void {
  const previousRef = useRef<{ id: string | null; value: WorkspaceAccessClient | null } | null>(
    null
  )
  useEffect(() => {
    if (status === 'idle') previousRef.current = null
    if (status !== 'ready') return
    const previous = previousRef.current
    previousRef.current = { id: active?.workspace.id ?? null, value: active }
    if (previous === null || previous.id === (active?.workspace.id ?? null)) return
    callHost('onWorkspaceChanged', () =>
      optionsRef.current.onWorkspaceChanged?.(previous.value, active)
    )
  }, [status, active, optionsRef])
}

/**
 * Opens the cross-tab channel, when the runtime has one, and reloads the list when another tab
 * posts on it.
 *
 * @param refresh - The reload.
 * @returns A reference to the open channel, for posting.
 */
export function useWorkspaceChannel(
  refresh: () => Promise<void>
): RefObject<BroadcastChannel | null> {
  const channelRef = useRef<BroadcastChannel | null>(null)
  useEffect(() => {
    if (typeof BroadcastChannel === 'undefined') return undefined
    const channel = new BroadcastChannel(CHANNEL_NAME)
    channel.onmessage = (): void => {
      void refresh()
    }
    channelRef.current = channel
    return (): void => {
      channelRef.current = null
      channel.close()
    }
  }, [refresh])
  return channelRef
}

/**
 * Builds the role hint: whether the caller's role in a workspace is the given one, or includes it
 * through the host's `hierarchy`. A hint for what to render, never an authority.
 *
 * @param active - The active workspace.
 * @param items - The caller's workspaces.
 * @param optionsRef - The host's options, current.
 * @returns The hint function.
 */
export function useRoleHint(
  active: WorkspaceAccessClient | null,
  items: readonly WorkspaceAccessClient[],
  optionsRef: OptionsRef
): (role: string, workspaceId?: string) => boolean {
  return useCallback(
    (role: string, workspaceId?: string): boolean => {
      const target =
        workspaceId === undefined
          ? active
          : (items.find((item) => item.workspace.id === workspaceId) ?? null)
      if (target === null) return false
      if (target.role === role) return true
      const included = Object.entries(optionsRef.current.hierarchy ?? {})
      return included.some(([held, covers]) => held === target.role && covers.includes(role))
    },
    [active, items, optionsRef]
  )
}

/**
 * Builds the handler a host calls from its catch: a workspace refusal for the ACTIVE workspace
 * reloads the list and calls `onWorkspaceAccessLost`; any other error is left alone.
 *
 * @param activeId - The active workspace id.
 * @param optionsRef - The host's options, current.
 * @param refresh - The reload.
 * @returns The handler, which answers whether the error was a workspace refusal.
 */
export function useRefusalHandler(
  activeId: string | null,
  optionsRef: OptionsRef,
  refresh: () => Promise<void>
): (workspaceId: string, error: unknown) => boolean {
  return useCallback(
    (workspaceId: string, error: unknown): boolean => {
      const code = refusalCodeOf(error)
      if (code === undefined) return false
      if (workspaceId !== activeId) return true
      callHost('onWorkspaceAccessLost', () =>
        optionsRef.current.onWorkspaceAccessLost?.(workspaceId, code)
      )
      void refresh()
      return true
    },
    [activeId, optionsRef, refresh]
  )
}

/**
 * Builds the switch: records it on the server, then makes it the chosen workspace, updates what the
 * server remembers as last active, and tells the other tabs. A refusal rejects and changes nothing.
 *
 * @param clientRef - The current workspace client.
 * @param setChosen - Sets the chosen workspace.
 * @param setLoaded - Sets the loaded list.
 * @param channelRef - The open cross-tab channel, if any.
 * @returns The switch function.
 */
export function useSwitch(
  clientRef: RefObject<WorkspaceProviderClient>,
  setChosen: Dispatch<SetStateAction<string | null>>,
  setLoaded: Dispatch<SetStateAction<Loaded>>,
  channelRef: RefObject<BroadcastChannel | null>
): (workspaceId: string) => Promise<void> {
  return useCallback(
    async (workspaceId: string): Promise<void> => {
      await clientRef.current.switchWorkspace(workspaceId)
      setChosen(workspaceId)
      setLoaded((current) => ({ ...current, lastActiveWorkspaceId: workspaceId }))
      channelRef.current?.postMessage({ type: 'workspaces-changed' })
    },
    [clientRef, setChosen, setLoaded, channelRef]
  )
}
