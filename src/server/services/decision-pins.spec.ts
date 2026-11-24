/**
 * @fileoverview The decisions that wait on a promise a repository or a store handed back, when that promise carries a constructor
 * and a `then` of its own: the lockout read, the re-proof before a deletion or a hand-over of ownership, the release of a resend
 * cooldown, and the rejection `markHandled` must hear. A bare `await` or `return` of such a promise resolves from the forged `then`,
 * so a locked account reads open, a wrong password reads right, and a failed delete reads fine.
 *
 * @layer Test
 */

import type { ResolvedOptions } from '../config/resolved-options'
import type { HookContext } from '../interfaces/auth-hooks.interface'
import { isRefusal } from '../utils/object-prototype-guard'
import { markHandled } from '../utils/settle'
import type { BruteForceService } from './brute-force.service'
import type { MembershipService } from './membership.service'
import { MfaFlowLockoutService } from './mfa-flow-lockout.service'
import { releasingCooldownOnFailure } from './otp.service'
import { WorkspaceActionsService } from './workspace-actions.service'
import type { WorkspaceCallerService } from './workspace-caller.service'
import type { WorkspaceService } from './workspace.service'

/** The reads of `then` a forged promise answered, so a row can prove the library asked for none. */
interface Forged<T> {
  promise: Promise<T>
  reads: () => number
}

/**
 * A native promise as a host could hand one over: its own `constructor` is not the language's (so `await` does not take it as
 * native) and its `then` settles the opposite way, once. The constructor stays configurable, as it is when a host sets it by plain
 * assignment.
 */
function forged<T>(real: Promise<T>, settles: () => unknown): Forged<T> {
  let reads = 0
  real.catch(() => undefined)
  Object.defineProperty(real, 'constructor', { value: Object, configurable: true })
  Object.defineProperty(real, 'then', {
    configurable: true,
    get() {
      reads += 1
      return (resolve: (value: unknown) => void) => {
        resolve(settles())
      }
    }
  })
  return { promise: real, reads: () => reads }
}

const CALLER = { sub: 'u1', tenantId: 't1' }
const REF = { tenantId: 't1', workspaceId: 'w1' }
const ACTOR = { userId: 'u1', role: 'owner' }
const CONTEXT = { plane: 'dashboard' } as HookContext

describe('the lockout read of the MFA-adjacent flows', () => {
  function lockout(bruteForce: Partial<Record<keyof BruteForceService, jest.Mock>>) {
    return new MfaFlowLockoutService({ hmacKey: 'k' } as ResolvedOptions, bruteForce as never)
  }

  // Scenario: the counter is at its limit and the answer carries a `then` that says it is not. Expected: the account stays locked.
  // Why: a bare return resolved the method's own promise from that `then`, which opened a locked account to reauth and MFA.
  it('keeps an account locked when the answer carries a then that says it is not', async () => {
    const answer = forged(Promise.resolve(true), () => false)
    const service = lockout({ isLockedOut: jest.fn().mockReturnValue(answer.promise) })

    await expect(service.isLockedOut('challenge', 'dashboard', 'u1', 't1')).resolves.toBe(true)
    expect(answer.reads()).toBe(0)
  })

  // Scenario: the record of a failure and the reset of a counter, each answered by a promise with a forged `then`.
  // Expected: neither is asked for `then`.
  it.each([
    [
      'recordFailure',
      (s: MfaFlowLockoutService) => s.recordFailure('challenge', 'dashboard', 'u1', 't1')
    ],
    ['resetFailures', (s: MfaFlowLockoutService) => s.reset('challenge', 'dashboard', 'u1', 't1')]
  ])('does not read then of the answer of %s', async (name, call) => {
    const answer = forged(Promise.resolve(undefined), () => undefined)
    const service = lockout({ [name]: jest.fn().mockReturnValue(answer.promise) })

    await call(service)

    expect(answer.reads()).toBe(0)
  })
})

describe('the steps of the workspace actions', () => {
  function actions(over: {
    reauthenticate?: jest.Mock
    create?: jest.Mock
    getAccess?: jest.Mock
    getMember?: jest.Mock
  }) {
    const workspaces = {
      create: over.create ?? jest.fn().mockResolvedValue({ id: 'w1' }),
      rename: jest.fn().mockResolvedValue(undefined),
      getAccess: over.getAccess ?? jest.fn().mockResolvedValue({ workspace: { id: 'w1' } }),
      scheduleDeletion: jest.fn().mockResolvedValue(undefined)
    }
    const memberships = {
      changeRole: jest.fn().mockResolvedValue(undefined),
      getMember: over.getMember ?? jest.fn().mockResolvedValue({ userId: 'u2' }),
      assertMayTransfer: jest.fn(),
      assertTransferTarget: jest.fn().mockResolvedValue(undefined),
      transferOwnership: jest.fn().mockResolvedValue(undefined)
    }
    const callers = {
      load: jest.fn().mockResolvedValue({ id: 'u1', tenantId: 't1' }),
      reauthenticate: over.reauthenticate ?? jest.fn().mockResolvedValue(undefined)
    }
    const service = new WorkspaceActionsService(
      workspaces as never,
      memberships as never,
      callers as never
    )
    return { service, workspaces, memberships }
  }

  const wrongPassword = (): Forged<void> =>
    forged(Promise.reject(new Error('auth.invalid_credentials')), () => undefined)

  // Scenario: the re-proof rejects (a wrong password) and the rejected promise carries a `then` that resolves. Expected: the
  // deletion is refused and nothing is written. Why: a bare await resolved from that `then`, and SCHEDULED_DELETION was written.
  it('does not schedule a deletion after a re-proof that rejected', async () => {
    const proof = wrongPassword()
    const { service, workspaces } = actions({
      reauthenticate: jest.fn().mockReturnValue(proof.promise)
    })

    await expect(service.scheduleDeletion(REF, ACTOR, CALLER, 'wrong', CONTEXT)).rejects.toThrow(
      'auth.invalid_credentials'
    )
    expect(workspaces.scheduleDeletion).not.toHaveBeenCalled()
  })

  // Scenario: the same forged rejection before a hand-over of ownership. Expected: refused, ownership unchanged.
  it('does not transfer ownership after a re-proof that rejected', async () => {
    const proof = wrongPassword()
    const { service, memberships } = actions({
      reauthenticate: jest.fn().mockReturnValue(proof.promise)
    })

    await expect(
      service.transferOwnership(
        REF,
        ACTOR,
        CALLER,
        { toUserId: 'u2', keeps: null, password: 'wrong' },
        CONTEXT
      )
    ).rejects.toThrow('auth.invalid_credentials')
    expect(memberships.transferOwnership).not.toHaveBeenCalled()
  })

  // Scenario: a `then` is planted on the root while the action waits for the repository, and the object it returns is the answer.
  // Expected: refused with the runtime's own error, for every method that returns what a service answered.
  // Why: an async function resolving from an object reads its `then`, and the planted one would answer for the result.
  it.each([
    ['create', (s: WorkspaceActionsService) => s.create(CALLER, 'Acme', CONTEXT)],
    ['rename', (s: WorkspaceActionsService) => s.rename(REF, ACTOR, 'Acme', CONTEXT)],
    [
      'changeRole',
      (s: WorkspaceActionsService) => s.changeRole(REF, 'u2', 'editor', ACTOR, CONTEXT)
    ]
  ])('refuses the result of %s while a then is planted on the root', async (_name, call) => {
    // The answer is settled before `then` is planted: an async function returning the object after the plant would wait on it.
    const plant = jest.fn().mockImplementation(
      () =>
        new Promise((resolve) => {
          resolve({ id: 'w1', workspace: { id: 'w1' }, userId: 'u2' })
          Object.defineProperty(Object.prototype, 'then', {
            // Answers for every object that inherits from the root, as a forged one would; it never hangs the wait.
            value: (done: (answer: unknown) => void) => {
              done('FORGED')
            },
            configurable: true
          })
        })
    )
    const { service } = actions({ create: plant, getAccess: plant, getMember: plant })

    // Matchers wait on objects that inherit from the root, so the refusal is read out of the window before it is asserted.
    let refusal: unknown
    try {
      await call(service)
    } catch (error: unknown) {
      refusal = error
    } finally {
      delete (Object.prototype as { then?: unknown }).then
    }

    expect(isRefusal(refusal)).toBe(true)
  })
})

describe('the release of a resend cooldown', () => {
  // Scenario: the delete of the cooldown key rejects and the rejected promise carries a `then` that answers. Expected: the failed
  // release is logged. Why: a `.then` chain called the forged `then`, so the failure was never seen.
  it('logs a delete that failed though its promise carries a then', async () => {
    const del = forged(Promise.reject(new Error('redis down')), () => undefined)
    const logger = { log: jest.fn(), warn: jest.fn(), error: jest.fn() }

    await releasingCooldownOnFailure(
      { del: jest.fn().mockReturnValue(del.promise) },
      logger,
      'cooldown:key',
      () => Promise.resolve(false)
    )

    expect(
      logger.log.mock.calls.length + logger.warn.mock.calls.length + logger.error.mock.calls.length
    ).toBe(1)
    expect(del.reads()).toBe(0)
  })
})

describe('markHandled on a promise that cannot take the pinned constructor', () => {
  // Scenario: a rejected promise whose own constructor is permanent and not the language's, with a `then` that never calls back.
  // Expected: the rejection is heard, so the process is not ended by an unhandled rejection.
  // Why: the failed pin was swallowed and the rejection was then awaited bare, which resolved from the forged `then` and left no
  // handler on the original.
  it('hears the rejection instead of awaiting it bare', async () => {
    const heard: unknown[] = []
    const onUnhandled = (reason: unknown): void => void heard.push(reason)
    const real = Promise.reject(new Error('lost'))
    Object.defineProperty(real, 'constructor', { value: Object })
    Object.defineProperty(real, 'then', { value: () => undefined })
    process.on('unhandledRejection', onUnhandled)
    try {
      markHandled(real)
      await new Promise((resolve) => setTimeout(resolve, 20))
    } finally {
      process.off('unhandledRejection', onUnhandled)
    }

    expect(heard).toEqual([])
  })

  // Scenario: a rejected promise whose own constructor is a permanent getter that throws. Expected: markHandled returns without
  // throwing, as nothing can be attached to it; the wait that follows refuses it.
  it('returns quietly for a promise that refuses every read of its constructor', () => {
    const real = Promise.reject(new Error('lost'))
    real.catch(() => undefined)
    Object.defineProperty(real, 'constructor', {
      get() {
        throw new Error('no constructor')
      }
    })

    expect(() => {
      markHandled(real)
    }).not.toThrow()
  })
})
