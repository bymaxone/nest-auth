import request from 'supertest'

import { bootstrapTestApp, expectAuthError } from './setup'
import type { BootstrappedTestApp } from './setup'

/** Runs `body` with `key` planted on the root object of the process, as plain assignment plants it, and takes it away again. */
async function withPlanted<T>(key: string, body: () => Promise<T>): Promise<T> {
  Object.defineProperty(Object.prototype, key, {
    value: 'planted',
    configurable: true,
    enumerable: true,
    writable: true
  })
  try {
    return await body()
  } finally {
    Reflect.deleteProperty(Object.prototype, key)
  }
}

describe('a key planted on Object.prototype after the module started (E2E)', () => {
  let boot: BootstrappedTestApp

  beforeAll(async () => {
    boot = await bootstrapTestApp(
      { platform: { enabled: true } },
      {
        controllers: { auth: true, mfa: true, passwordReset: true, sessions: true, platform: true }
      }
    )
  })

  afterAll(async () => {
    await boot.app.close()
  })

  // Scenario: the challenge of the second factor with a temporary token that is not a JWT, first with nothing planted and then
  // with a key planted. Expected: the first is refused as an invalid temporary token and the second as the library's refusal.
  // Why: the same verification runs for the temporary token, and it is the same answer an operator has to be able to see.
  it('answers the challenge with auth.internal, not the temp-token refusal, while a key is planted', async () => {
    const call = (): Promise<{ status: number; body: unknown }> =>
      request(boot.app.getHttpServer())
        .post('/mfa/challenge')
        .send({ mfaTempToken: 'not-a-jwt', code: '123456' })

    expectAuthError(await call(), 'auth.mfa_temp_token_invalid')
    expectAuthError(await withPlanted('sessions', call), 'auth.internal')
  })

  // Scenario: a request with a token that is not a JWT, on a dashboard route and on a platform route, first with nothing planted
  // and then with a key planted. Expected: the first is refused as an invalid token (401) and the second as the library's own
  // refusal (500 `auth.internal`). Why: a polluted process must not look like every user being signed out; a 500 is something
  // an operator sees and a 401 is something a client acts on.
  it.each(['/me', '/platform/me'] as const)(
    'answers %s with auth.internal, not auth.token_invalid, while a key is planted',
    async (route) => {
      const call = (): Promise<{ status: number; body: unknown }> =>
        request(boot.app.getHttpServer()).get(route).set('Authorization', 'Bearer not-a-jwt')

      expectAuthError(await call(), 'auth.token_invalid')
      expectAuthError(await withPlanted('sessions', call), 'auth.internal')
    }
  )
})
