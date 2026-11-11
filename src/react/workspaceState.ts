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

/**
 * The loaded list, the workspace the caller chose, and where loading stands, all for one account.
 * `owner` is that account (tenant and user together); state whose owner is not the current account
 * is never read.
 */
export interface Loaded {
  owner: string | null
  status: WorkspacesStatus
  items: readonly WorkspaceAccessClient[]
  lastActiveWorkspaceId: string | null
  chosen: string | null
}

const IDLE: Loaded = {
  owner: null,
  status: 'idle',
  items: [],
  lastActiveWorkspaceId: null,
  chosen: null
}

/** What an account reads before its own list has arrived. */
const loadingFor = (owner: string): Loaded => ({ ...IDLE, owner, status: 'loading' })

/** What the provider needs of the workspace client: the list and the switch. */
export type WorkspaceProviderClient = Pick<
  WorkspaceClientMethods,
  'listWorkspaces' | 'switchWorkspace'
>

/**
 * Follows the cursors of the caller's workspaces to the end, or to {@link MAX_PAGES}, and stops at the
 * next page once `signal` aborts.
 */
async function loadAll(
  client: WorkspaceProviderClient,
  signal: AbortSignal
): Promise<Pick<Loaded, 'items' | 'lastActiveWorkspaceId'>> {
  const items: WorkspaceAccessClient[] = []
  let lastActiveWorkspaceId: string | null = null
  let cursor: string | undefined
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const result = await client.listWorkspaces(cursor === undefined ? undefined : { cursor }, {
      signal
    })
    if (signal.aborted) break
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
 * Builds the reload: it aborts a load still on its way, starts one with its own controller for the
 * account that is current when it starts, and stores the result under that account only if the
 * controller was not aborted. Does nothing unless the session is signed in.
 *
 * @param clientRef - The current workspace client.
 * @param statusRef - The current session status.
 * @param identityRef - The current account.
 * @param setLoaded - Sets the loaded list.
 * @param controllerRef - Holds the controller of the load in flight, so an effect can abort it.
 * @returns The reload.
 */
function useReload(
  clientRef: RefObject<WorkspaceProviderClient>,
  statusRef: RefObject<AuthStatus>,
  identityRef: RefObject<string | null>,
  setLoaded: Dispatch<SetStateAction<Loaded>>,
  controllerRef: RefObject<AbortController | null>
): () => Promise<void> {
  // Stryker disable ArrayDeclaration: the dependencies are refs and a state setter, which are stable, so any constant array re-creates the callback exactly as often as `[]`
  return useCallback(async (): Promise<void> => {
    const owner = identityRef.current
    if (statusRef.current !== 'authenticated') return
    controllerRef.current?.abort()
    const controller = new AbortController()
    controllerRef.current = controller
    try {
      const result = await loadAll(clientRef.current, controller.signal)
      if (!controller.signal.aborted) {
        setLoaded((current) => ({
          ...result,
          owner,
          status: 'ready',
          chosen: current.chosen
        }))
      }
    } catch {
      if (!controller.signal.aborted) {
        setLoaded((current) => ({
          ...IDLE,
          owner,
          status: 'error',
          chosen: current.chosen
        }))
      }
    }
  }, [clientRef, statusRef, identityRef, setLoaded, controllerRef])
  // Stryker restore ArrayDeclaration
}

/**
 * Loads the caller's workspaces once the session is known to be signed in, and empties them when it
 * ends or the account changes. What is stored belongs to one account and is read only by it: in the
 * render where the account changes the list already reads as loading, whatever the effects have run
 * yet. A load is aborted when the provider unmounts, when the session or the account changes and when
 * a newer load starts, and an aborted load sets no state and follows no further page. A reload
 * requested while the session is not signed in does nothing, so a tab that hears a broadcast while
 * signed out makes no request.
 *
 * @param client - The workspace client.
 * @param authStatus - The session status the auth provider owns.
 * @param identity - Who is signed in, as tenant and user together, or `null`.
 * @returns What the current account reads, the setter and the refs the other hooks write through,
 *   and the reload.
 */
export function useWorkspaceList(
  client: WorkspaceProviderClient,
  authStatus: AuthStatus,
  identity: string | null
): {
  loaded: Loaded
  setLoaded: Dispatch<SetStateAction<Loaded>>
  clientRef: RefObject<WorkspaceProviderClient>
  identityRef: RefObject<string | null>
  refresh: () => Promise<void>
} {
  const [stored, setLoaded] = useState<Loaded>(IDLE)
  const clientRef = useRef(client)
  const statusRef = useRef(authStatus)
  const identityRef = useRef(identity)
  const controllerRef = useRef<AbortController | null>(null)

  // Kept current in an effect, declared before every effect that reads them, so a load never runs
  // against the client, the session status or the account of an earlier render.
  useEffect(() => {
    clientRef.current = client
    statusRef.current = authStatus
    identityRef.current = identity
  })

  const refresh = useReload(clientRef, statusRef, identityRef, setLoaded, controllerRef)

  useEffect(() => {
    if (authStatus === 'authenticated' && identity !== null) {
      setLoaded((current) =>
        current.owner === identity && current.status === 'ready' ? current : loadingFor(identity)
      )
      void refresh()
    } else if (authStatus === 'unauthenticated') {
      setLoaded(IDLE)
    }
    return (): void => {
      controllerRef.current?.abort()
    }
  }, [authStatus, identity, refresh])

  const loaded =
    stored.owner === identity ? stored : identity === null ? IDLE : loadingFor(identity)
  return { loaded, setLoaded, clientRef, identityRef, refresh }
}

/**
 * Tells the host, through `onWorkspaceChanged`, when the active workspace changes after the first
 * load. A list that starts loading, on a first sign-in, after a sign-out or for another account, makes
 * the load that follows a first one.
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
    if (status === 'loading') previousRef.current = null
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
  // Stryker disable ArrayDeclaration: `refresh` has no dependencies, so it is one function for the life of the provider and `[]` re-runs the effect exactly as often
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
  // Stryker restore ArrayDeclaration
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
 * Builds the switch: records it on the server, then, if the account that asked is still the current
 * one, makes it the chosen workspace, updates what the server remembers as last active, and tells the
 * other tabs. A refusal rejects and changes nothing, and so does an answer that arrives after the
 * account changed.
 *
 * @param clientRef - The current workspace client.
 * @param identityRef - The current account.
 * @param setLoaded - Sets the loaded list.
 * @param channelRef - The open cross-tab channel, if any.
 * @returns The switch function.
 */
export function useSwitch(
  clientRef: RefObject<WorkspaceProviderClient>,
  identityRef: RefObject<string | null>,
  setLoaded: Dispatch<SetStateAction<Loaded>>,
  channelRef: RefObject<BroadcastChannel | null>
): (workspaceId: string) => Promise<void> {
  return useCallback(
    async (workspaceId: string): Promise<void> => {
      const owner = identityRef.current
      await clientRef.current.switchWorkspace(workspaceId)
      if (identityRef.current !== owner) return
      setLoaded((current) => ({
        ...current,
        chosen: workspaceId,
        lastActiveWorkspaceId: workspaceId
      }))
      channelRef.current?.postMessage({ type: 'workspaces-changed' })
    },
    // Stryker disable next-line ArrayDeclaration: refs and a state setter are stable references, so `[]` re-creates the callback exactly as often
    [clientRef, identityRef, setLoaded, channelRef]
  )
}
