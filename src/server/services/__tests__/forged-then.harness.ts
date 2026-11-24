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

/** A read that fails, issued by host code that has also left a key on the root object, so the library refuses what it started. */
function failingRead(): Promise<never> {
  Object.defineProperty(Object.prototype, 'plantedByHost', { value: 1, configurable: true })
  return Promise.reject(new Error('the store failed'))
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

if (scenario === 'revoked-token') {
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
} else if (scenario === 'mid-read' || scenario === 'unhandled') {
  settle(service.resolveAccess(ref), showAccess)
} else {
  settle(service.resolveAccess(ref), showAccess)
}
