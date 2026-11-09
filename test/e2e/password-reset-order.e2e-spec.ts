/**
 * End-to-end order of the checks on `POST /password/reset-password`.
 *
 * The proof is classified first, without being spent: more than one, none, or one the configured
 * method does not accept is an invalid token whatever password the request carries. Only then is
 * the password judged, and only then is the proof consumed. The specs drive the real HTTP stack
 * under both methods and watch the breach checker, because the point of the order is that a caller
 * holding no usable proof cannot reach it.
 */

import request from 'supertest'

import { BYMAX_AUTH_BREACH_CHECKER } from '../../src/server/bymax-auth.constants'
import { bootstrapTestApp, expectAuthError, type BootstrappedTestApp } from './setup'

/** Ten characters: inside the DTO's 8 to 128, under the default policy floor of 15. */
const SHORT = 'Passw0rd12'
/** Past both floors. */
const LONG = 'Correct-Horse-Battery-9'
const TOKEN = 'a'.repeat(64)

/** A proof of the kind each method does NOT accept. */
const WRONG_KIND = { token: { otp: '123456' }, otp: { token: TOKEN } } as const

describe.each(['token', 'otp'] as const)('reset-password check order, method %s', (method) => {
  let boot: BootstrappedTestApp
  const isBreached = jest.fn().mockResolvedValue(false)

  beforeAll(async () => {
    boot = await bootstrapTestApp(
      { passwordReset: { method } },
      {
        extraModuleProviders: [{ provide: BYMAX_AUTH_BREACH_CHECKER, useValue: { isBreached } }]
      }
    )
  })

  afterAll(async () => {
    await boot.app.close()
  })

  beforeEach(() => {
    isBreached.mockClear()
  })

  function reset(body: Record<string, unknown>): request.Test {
    return request(boot.app.getHttpServer())
      .post('/password/reset-password')
      .send({ email: 'order@example.com', tenantId: 'tenant-1', ...body })
  }

  // Scenario: no proof and a password under the policy floor. Expected: an invalid token, and the
  // breach checker is never asked. Why: the answer must not depend on the password, and an
  // unproven caller must not drive the checker.
  it('answers no proof with an invalid token before judging a short password', async () => {
    const res = await reset({ newPassword: SHORT })

    expectAuthError(res, 'auth.password_reset_token_invalid')
    expect(isBreached).not.toHaveBeenCalled()
  })

  // Scenario: a proof of the kind the method does not accept, with a short password. Expected: the
  // same invalid-token answer and no breach lookup.
  it('answers a proof of the wrong kind with an invalid token before judging a short password', async () => {
    const res = await reset({ ...WRONG_KIND[method], newPassword: SHORT })

    expectAuthError(res, 'auth.password_reset_token_invalid')
    expect(isBreached).not.toHaveBeenCalled()
  })

  // Scenario: no proof and a password that would pass the policy. Expected: the breach checker is
  // still not asked. Why: this is the call an unproven caller could otherwise make at will.
  it('does not ask the breach checker for a request with no proof', async () => {
    const res = await reset({ newPassword: LONG })

    expectAuthError(res, 'auth.password_reset_token_invalid')
    expect(isBreached).not.toHaveBeenCalled()
  })

  // Scenario: a proof of the right kind, not yet spent, with a short password. Expected: the
  // password is judged first and refused with a validation error, so the proof is not consumed.
  it('judges the password of a well-formed proof before spending it', async () => {
    const proof = method === 'token' ? { token: TOKEN } : { otp: '123456' }

    const res = await reset({ ...proof, newPassword: SHORT })

    expectAuthError(res, 'auth.validation')
  })

  // Scenario: two proofs and a short password. Expected: an invalid token, as before.
  it('refuses two proofs before judging the password', async () => {
    const res = await reset({ token: TOKEN, otp: '123456', newPassword: SHORT })

    expectAuthError(res, 'auth.password_reset_token_invalid')
    expect(isBreached).not.toHaveBeenCalled()
  })
})
