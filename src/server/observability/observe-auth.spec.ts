/**
 * @fileoverview A route marked with `@ObserveAuth` is counted from what it returns or throws, run inside a
 * span, and answers exactly as it would unobserved.
 *
 * @layer Test
 */

import type { CallHandler, ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { lastValueFrom, of, throwError } from 'rxjs'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthErrorCode } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthMetricsTally } from './auth-metrics-tally'
import { AuthTracing } from './auth-tracing'
import { AuthObservabilityInterceptor, ObserveAuth, OBSERVE_AUTH_METADATA } from './observe-auth'
import type { ObservedOperation } from './observe-auth'
import { observed } from './observed-outcome'
import type { AuthPlane } from '../services/auth-token-verifier.service'

/** A handler decorated for the operation and plane, as a controller method would be. */
function handlerFor(operation: ObservedOperation, plane: AuthPlane): () => void {
  class Probe {
    handle(): void {
      // The decorated method.
    }
  }
  const descriptor = Object.getOwnPropertyDescriptor(Probe.prototype, 'handle')
  if (descriptor === undefined) throw new Error('no descriptor')
  ObserveAuth(operation, plane)(Probe.prototype, 'handle', descriptor)
  return Probe.prototype.handle
}

/** The interceptor over a real tally and a seam that is not loaded (the operation runs bare). */
function build(): { interceptor: AuthObservabilityInterceptor; tally: AuthMetricsTally } {
  const tally = new AuthMetricsTally()
  return {
    tally,
    interceptor: new AuthObservabilityInterceptor(new Reflector(), tally, new AuthTracing())
  }
}

/** A context whose handler is the given function. */
function contextOf(handler: () => void): ExecutionContext {
  return { getHandler: () => handler } as unknown as ExecutionContext
}

/** Runs the interceptor over a handler that returns `result`. */
function returning(
  interceptor: AuthObservabilityInterceptor,
  handler: () => void,
  result: unknown
): Promise<unknown> {
  const next: CallHandler = { handle: () => of(result) }
  return lastValueFrom(interceptor.intercept(contextOf(handler), next))
}

/** Runs the interceptor over a handler that throws `error`. */
function throwing(
  interceptor: AuthObservabilityInterceptor,
  handler: () => void,
  error: unknown
): Promise<unknown> {
  const next: CallHandler = { handle: () => throwError(() => error) }
  return lastValueFrom(interceptor.intercept(contextOf(handler), next))
}

const refused = (code: AuthErrorCode): AuthException => new AuthException(code)

describe('@ObserveAuth', () => {
  // Scenario: the decorator is applied. Expected: the operation and the plane are on the handler.
  it('records the operation and the plane on the handler', () => {
    const handler = handlerFor('refresh', 'platform')

    expect(Reflect.getMetadata(OBSERVE_AUTH_METADATA, handler)).toEqual({
      operation: 'refresh',
      plane: 'platform'
    })
  })
})

describe('AuthObservabilityInterceptor — logins', () => {
  // Scenario: a login that returns tokens and one that returns an MFA challenge. Expected: success and
  // mfa_required on the plane of the route, and the result unchanged.
  it('counts a login that returns tokens and one that asks for MFA', async () => {
    const { interceptor, tally } = build()
    const handler = handlerFor('login', 'dashboard')
    const tokens = { user: { id: 'u' }, accessToken: 'a' }
    const challenge = { mfaRequired: true, mfaTempToken: 't' }

    await expect(returning(interceptor, handler, tokens)).resolves.toBe(tokens)
    await expect(returning(interceptor, handler, challenge)).resolves.toBe(challenge)

    expect(tally.snapshot().logins.dashboard).toMatchObject({ success: 1, mfa_required: 1 })
    expect(tally.snapshot().logins.platform.success).toBe(0)
  })

  // Scenario: each refusal a login can end with. Expected: counted under its outcome, and rethrown as is.
  it.each([
    [AUTH_ERROR_CODES.INVALID_CREDENTIALS, 'invalid_credentials'],
    [AUTH_ERROR_CODES.ACCOUNT_LOCKED, 'locked'],
    [AUTH_ERROR_CODES.ACCOUNT_INACTIVE, 'blocked'],
    [AUTH_ERROR_CODES.ACCOUNT_SUSPENDED, 'blocked'],
    [AUTH_ERROR_CODES.ACCOUNT_BANNED, 'blocked'],
    [AUTH_ERROR_CODES.PENDING_APPROVAL, 'blocked']
  ] as const)('counts %s as %s and rethrows it', async (code, outcome) => {
    const { interceptor, tally } = build()
    const failure = refused(code)

    await expect(throwing(interceptor, handlerFor('login', 'platform'), failure)).rejects.toBe(
      failure
    )

    expect(tally.snapshot().logins.platform[outcome]).toBe(1)
  })

  // Scenario: an end that is not one of the counted outcomes (an unverified address, a plain error).
  // Expected: nothing is counted and the error passes through.
  it.each([
    [refused(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)],
    [new Error('boom')],
    ['a thrown string']
  ])('counts nothing for %p', async (failure) => {
    const { interceptor, tally } = build()

    await expect(throwing(interceptor, handlerFor('login', 'dashboard'), failure)).rejects.toBe(
      failure
    )

    expect(Object.values(tally.snapshot().logins.dashboard).every((count) => count === 0)).toBe(
      true
    )
  })
})

describe('AuthObservabilityInterceptor — refresh and MFA', () => {
  // Scenario: a rotation, then each refusal. Expected: rotated, invalid, expired and reuse_detected, the
  // last two only when the refusal was marked; an unmarked refusal is invalid.
  it('counts a rotation and each kind of refused refresh', async () => {
    const { interceptor, tally } = build()
    const handler = handlerFor('refresh', 'dashboard')
    const invalid = () => refused(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)

    await returning(interceptor, handler, { accessToken: 'a' })
    await throwing(interceptor, handler, invalid()).catch(() => undefined)
    await throwing(interceptor, handler, observed('expired', invalid())).catch(() => undefined)
    await throwing(interceptor, handler, observed('reuse_detected', invalid())).catch(
      () => undefined
    )
    await throwing(interceptor, handler, refused(AUTH_ERROR_CODES.FORBIDDEN)).catch(() => undefined)

    expect(tally.snapshot().refreshes.dashboard).toEqual({
      rotated: 1,
      reuse_detected: 1,
      expired: 1,
      invalid: 1
    })
  })

  // Scenario: an MFA challenge that succeeds, a wrong code, a locked account and another refusal.
  it('counts MFA verifications by outcome', async () => {
    const { interceptor, tally } = build()
    const handler = handlerFor('mfa_verify', 'platform')

    await returning(interceptor, handler, { accessToken: 'a' })
    await throwing(interceptor, handler, refused(AUTH_ERROR_CODES.MFA_INVALID_CODE)).catch(
      () => undefined
    )
    await throwing(interceptor, handler, refused(AUTH_ERROR_CODES.ACCOUNT_LOCKED)).catch(
      () => undefined
    )
    await throwing(interceptor, handler, refused(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)).catch(
      () => undefined
    )

    expect(tally.snapshot().mfa.platform).toEqual({ success: 1, invalid: 1, locked: 1 })
  })

  // Scenario: a password-reset route. Expected: traced but counted nowhere.
  it('counts nothing for a password reset', async () => {
    const { interceptor, tally } = build()

    await returning(interceptor, handlerFor('password_reset', 'dashboard'), {})

    expect(JSON.stringify(tally.snapshot())).not.toMatch(/[1-9]/)
  })

  // Scenario: a handler with no decoration reaches the interceptor. Expected: it is passed through untouched.
  it('passes an undecorated handler through', async () => {
    const { interceptor, tally } = build()
    const next: CallHandler = { handle: () => of('plain') }

    await expect(
      lastValueFrom(
        interceptor.intercept(
          contextOf(() => undefined),
          next
        )
      )
    ).resolves.toBe('plain')

    expect(tally.snapshot().logins.dashboard.success).toBe(0)
  })
})
