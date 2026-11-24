/**
 * @fileoverview The program a child process runs for `forged-then.decisions.spec.ts`: one decision of the library, made while a host
 * replaces the constructor of a promise or plants a `then`, and the outcome printed as JSON. Plain promise callbacks, taken from the
 * `then` captured before anything was planted, are the only waiting here, so the harness itself is never answered by a forged one.
 *
 * @layer Test
 */

import { resolveOptions } from '../../config/resolved-options'
import { mappingOutages } from '../../redis/redis-outage'
import { AuthRevocationService } from '../auth-revocation.service'
import { AuthTokenVerifierService } from '../auth-token-verifier.service'
import { WorkspaceAccessService } from '../workspace-access.service'

const scenario = process.env['SCENARIO'] ?? ''
const ownThen = Promise.prototype.then
const ownConstructor = Object.getOwnPropertyDescriptor(
  Promise.prototype,
  'constructor'
) as PropertyDescriptor

const ref = { tenantId: 't1', workspaceId: 'w1', userId: 'attacker' }
const workspace = {
  id: 'w1',
  tenantId: 't1',
  name: 'Acme',
  status: 'active',
  createdAt: new Date(0),
  deletionScheduledAt: null
}
/** One object that satisfies the decision as the workspace and as the membership of an owner. */
const forged = {
  ...workspace,
  ...ref,
  role: 'owner',
  invitedByUserId: null,
  updatedAt: new Date(0)
}

const options = resolveOptions({
  jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
  roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
  rateLimit: { clientIpSource: 'peer' },
  workspaces: {
    enabled: true,
    roles: { hierarchy: { owner: ['editor'], editor: [] }, ownerRole: 'owner' },
    membershipCacheTtlSeconds: 0
  }
})

/** Puts back everything a scenario changed. */
function restore(): void {
  Object.defineProperty(Promise.prototype, 'constructor', ownConstructor)
  Promise.prototype.then = ownThen
  for (const holder of [Object.prototype, Array.prototype, Function.prototype])
    Reflect.deleteProperty(holder, 'then')
}

/** The answer of two repository reads together, as `Promise.all` would give them: the workspace, then an owner's membership. */
const forgedPair = [workspace, forged]

/** A `then` that answers `value` the first time anything asks it, then puts everything back. */
function erasingThen(value: unknown): (resolve: (answer: unknown) => void) => void {
  return (resolve) => {
    restore()
    resolve(value)
  }
}

/** Plants the then on a prototype. */
function plantOn(holder: object, value: unknown): void {
  Object.defineProperty(holder, 'then', {
    value: erasingThen(value),
    configurable: true,
    writable: true
  })
}

let answered: unknown = 'none'
let unhandled = 0
process.on('unhandledRejection', () => {
  unhandled += 1
})
process.on('exit', () => {
  process.stdout.write(JSON.stringify({ outcome: answered, unhandled }))
})

function report(outcome: unknown): void {
  answered = outcome
}

function codeOf(error: unknown): string {
  const body = (error as { getResponse?: () => { error?: { code?: string } } }).getResponse?.()
  return body?.error?.code ?? 'other'
}

/** Waits for a promise with the then taken at load, and reports what it answered. */
function settle(pending: Promise<unknown>, show: (answer: unknown) => unknown): void {
  ownThen.call(
    pending,
    (answer: unknown) => {
      report(show(answer))
    },
    (error: unknown) => {
      report(`refused:${codeOf(error)}`)
    }
  )
}

const members = {
  find: (): Promise<null> =>
    scenario === 'mid-read'
      ? midRead()
      : scenario === 'late'
        ? lateRead()
        : scenario === 'unhandled'
          ? failingRead()
          : Promise.resolve(null)
}
const workspaces = { findById: (): Promise<typeof workspace> => Promise.resolve(workspace) }

/** A repository read that is the host's code: it plants a then that erases itself, and answers no membership. */
function midRead(): Promise<null> {
  plantOn(Object.prototype, forgedPair)
  return Promise.resolve(null)
}

/**
 * A read that answers no membership after a while, with host code running in between: it plants a then that erases itself while the
 * library waits, after the last check before the wait and before the answer is returned.
 */
function lateRead(): Promise<null> {
  setTimeout(() => {
    plantOn(Object.prototype, { kind: 'member', member: { ...ref, role: 'owner' } })
  }, 10)
  return new Promise((resolve) => setTimeout(() => resolve(null), 30))
}

/** A read that fails, issued by host code that has also left a key on the root object, so the library refuses what it started. */
function failingRead(): Promise<never> {
  Object.defineProperty(Object.prototype, 'plantedByHost', { value: 1, configurable: true })
  return Promise.reject(new Error('the store failed'))
}

/** Host code that runs while the library waits: it plants a then that erases itself and answers `value`, and the wait ends after it. */
function waitWhilePlanting(value: unknown): Promise<void> {
  setTimeout(() => {
    plantOn(Object.prototype, value)
  }, 10)
  return new Promise((resolve) => setTimeout(resolve, 30))
}

/**
 * The membership of an editor, read after host code planted a then answering an owner. The row has no prototype, so resolving the
 * read with it does not ask it for the `then` that is meant for the library's own return.
 */
function lateMembership(): Promise<unknown> {
  return waitWhilePlanting({ kind: 'member', member: { ...ref, role: 'owner' } }).then(() =>
    Object.assign(Object.create(null) as object, {
      ...ref,
      role: 'editor',
      status: 'active',
      invitedByUserId: null,
      createdAt: new Date(0),
      updatedAt: new Date(0)
    })
  )
}

const JTI = '3f2504e0-4f89-41d3-9a0c-0305e82c3301'
const identity = {
  jti: JTI,
  sub: 'user-1',
  tenantId: 't1',
  role: 'member',
  type: 'dashboard',
  status: 'active',
  mfaEnabled: false,
  mfaVerified: false,
  epoch: 1,
  iat: 1,
  exp: 2
}
const platformIdentity = { ...identity, sub: 'admin-1', type: 'platform', tenantId: undefined }

/** A verifier whose account status check is the host code that plants the then, and that answers the token's own payload. */
function verifier(
  payload: object,
  stall: () => Promise<void>,
  revoked: () => Promise<boolean> = () => Promise.resolve(false)
): AuthTokenVerifierService {
  return new AuthTokenVerifierService(
    { verify: () => ({ ...payload }) } as never,
    { jwt: { algorithm: 'HS256', issuer: 'iss', audience: 'aud', previousSecrets: [] } } as never,
    { isAccessTokenRevoked: revoked } as never,
    { assertDashboardAccountUsable: stall, assertPlatformAccountUsable: stall } as never
  )
}

/** Replaces the constructor of promises and plants a then that answers `value` once and puts everything back. */
function replaceConstructorAndForge(value: unknown): void {
  Object.defineProperty(Promise.prototype, 'constructor', {
    ...ownConstructor,
    value: function Other() {}
  })
  Promise.prototype.then = erasingThen(value) as typeof ownThen
}

const service = new WorkspaceAccessService(
  { eval: () => Promise.resolve(null) } as never,
  workspaces as never,
  members as never,
  options
)

const showAccess = (answer: unknown): unknown =>
  (answer as { kind: string; member?: { role: string } }).kind === 'member'
    ? `member:${(answer as { member: { role: string } }).member.role}`
    : (answer as { kind: string }).kind

const showToken = (answer: unknown): unknown =>
  `verified:${(answer as { payload: { sub: string } }).payload.sub}`

if (scenario === 'late-dashboard' || scenario === 'late-platform') {
  const plane = scenario === 'late-dashboard' ? 'dashboard' : 'platform'
  const forgedToken = {
    plane,
    payload: { ...(plane === 'dashboard' ? identity : platformIdentity), sub: 'attacker' }
  }
  const subject = verifier(plane === 'dashboard' ? identity : platformIdentity, () =>
    waitWhilePlanting(forgedToken)
  )
  settle(subject.verifyAccessToken('token', { plane }), showToken)
} else if (scenario === 'late-job') {
  const job = new WorkspaceAccessService(
    { eval: () => Promise.resolve(null) } as never,
    workspaces as never,
    { find: () => lateMembership() } as never,
    options,
    { assertDashboardAccountUsableNow: () => Promise.resolve() } as never
  )
  settle(
    job.assertStillAuthorized({ tenantId: 't1', workspaceId: 'w1', actorUserId: 'attacker' }, [
      'editor'
    ]),
    (answer) => `member:${(answer as { role: string }).role}`
  )
} else if (scenario === 'hop') {
  // The outermost caller: a plain async function awaits what the service returned, after the service's own last check refused.
  replaceConstructorAndForge({ kind: 'member', member: { ...ref, role: 'owner' } })
  const outer = async (): Promise<unknown> => await service.resolveAccess(ref)
  settle(outer(), showAccess)
} else if (scenario === 'sync-revoked') {
  // Host code that is called by the library plants while it makes the promise the library then awaits.
  const subject = verifier(
    identity,
    () => Promise.resolve(),
    () => {
      replaceConstructorAndForge(false)
      return Promise.resolve(true)
    }
  )
  settle(subject.verifyAccessToken('token', { plane: 'dashboard' }), showToken)
} else if (scenario === 'revoked-token') {
  const revocation = new AuthRevocationService({
    get: () => Promise.resolve('1'),
    getUserTokenEpoch: () => Promise.resolve(0)
  } as never)
  Object.defineProperty(Promise.prototype, 'constructor', {
    ...ownConstructor,
    value: function Other() {}
  })
  Promise.prototype.then = function forgedThen(resolve: (answer: unknown) => void) {
    restore()
    resolve(null)
  } as typeof ownThen
  const pending = revocation.isAccessTokenRevoked({ jti: 'j', sub: 'u', tenantId: 't1', epoch: 0 })
  settle(pending, (answer) => `revoked:${String(answer)}`)
} else if (scenario === 'ctor') {
  let asked = 0
  Object.defineProperty(Promise.prototype, 'constructor', {
    ...ownConstructor,
    value: function Other() {}
  })
  // The first ask is let through, the second is answered with the owner's membership and ends the plant.
  Promise.prototype.then = function forgedThen(
    this: Promise<unknown>,
    resolve: (answer: unknown) => void,
    reject: (error: unknown) => void
  ) {
    asked += 1
    if (asked < 2) return ownThen.call(this, resolve, reject)
    restore()
    resolve(forged)
    return undefined
  } as typeof ownThen
  settle(service.resolveAccess(ref), showAccess)
} else if (scenario === 'array' || scenario === 'object' || scenario === 'function') {
  const holder =
    scenario === 'array'
      ? Array.prototype
      : scenario === 'object'
        ? Object.prototype
        : Function.prototype
  plantOn(holder, forgedPair)
  settle(service.resolveAccess(ref), showAccess)
} else if (scenario === 'redis') {
  // A client whose command fails after the root was compromised: the proxy refuses, and the command's rejection must stay handled.
  const client = mappingOutages({
    get: (): Promise<never> => failingRead()
  } as never) as unknown as { get: () => Promise<unknown> }
  settle(client.get(), () => 'answered')
} else if (scenario === 'mid-read' || scenario === 'late' || scenario === 'unhandled') {
  settle(service.resolveAccess(ref), showAccess)
} else {
  settle(service.resolveAccess(ref), showAccess)
}
