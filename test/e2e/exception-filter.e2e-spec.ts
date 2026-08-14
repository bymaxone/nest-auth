/**
 * @fileoverview Proves `AuthExceptionFilter` over HTTP — the half nothing exercised.
 *
 * E2E-only coverage of `src/server/filters` was **0%**, while three specs carried comments
 * crediting the filter for envelopes it was not producing: an `AuthException`'s response body IS
 * the envelope, so Nest's default serialization renders it identically and no assertion could
 * tell the two apart. The filter is now registered in the harness, which makes those comments
 * true and makes this suite possible.
 *
 * What only the filter does is give a **non-`AuthException`** failure the same envelope. That is
 * the whole reason it exists — a client parsing `error.code` otherwise needed a second parser for
 * exactly the responses it can do least about — and it is what these cases drive.
 *
 * Failures are injected by overriding the user repository so `findByEmail` throws, which is the
 * shortest real path: `POST /login` reaches it before anything catches.
 */

import { BadRequestException, HttpException, HttpStatus } from '@nestjs/common'
import request from 'supertest'

import { BYMAX_AUTH_USER_REPOSITORY } from '../../src/server/bymax-auth.constants'
import { bootstrapTestApp, createMockUserRepository } from './setup'
import type { BootstrappedTestApp } from './setup'

/** The message a leak would surface. Distinctive so a substring search cannot miss it. */
const SECRET_DETAIL = 'postgres://user:hunter2@db.internal:5432/prod'

/** Boots an app whose `findByEmail` throws `thrown`. */
async function bootWithFailingRepo(thrown: unknown): Promise<BootstrappedTestApp> {
  const repo = createMockUserRepository()
  repo.findByEmail = (): never => {
    throw thrown
  }

  return bootstrapTestApp(
    {},
    {
      mutateBuilder: (builder) =>
        builder.overrideProvider(BYMAX_AUTH_USER_REPOSITORY).useValue(repo) as typeof builder
    }
  )
}

describe('AuthExceptionFilter over HTTP (E2E)', () => {
  // Verifies an unexpected throw becomes the library's envelope rather than the framework's, and
  // that the thrown detail does not reach the body.
  //
  // The message is the security half: an internal failure's message is the one place a stack
  // detail or a connection string reaches a response. The filter answers the generic text and
  // logs the cause. Asserting the absence of the injected string is what makes that a check
  // rather than a claim — a filter that passed `exception.message` through would still produce a
  // well-formed envelope with the right code, and only this assertion would notice.
  it('answers auth.internal for an unexpected throw, and leaks nothing from it', async () => {
    const boot = await bootWithFailingRepo(new Error(SECRET_DETAIL))

    try {
      const res = await request(boot.app.getHttpServer())
        .post('/login')
        .send({ email: 'a@example.com', password: 'ProbePass123!-xyz', tenantId: 'tenant-1' })

      expect(res.status).toBe(500)
      expect(res.body).toEqual({
        error: { code: 'auth.internal', message: 'Internal server error', details: null }
      })
      expect(JSON.stringify(res.body)).not.toContain(SECRET_DETAIL)
      expect(JSON.stringify(res.body)).not.toContain('hunter2')
    } finally {
      await boot.app.close()
    }
  })

  // Verifies a foreign `HttpException` — one the surrounding application threw, not this library —
  // keeps the status the application chose and is re-shaped into the envelope.
  //
  // Status and body are asserted separately on purpose: re-shaping the body while silently
  // normalising the status to 500 would still produce `auth.internal` and pass a body-only check,
  // and it would override a deliberate decision the application made.
  it('re-shapes a foreign HttpException into the envelope, keeping its status', async () => {
    const boot = await bootWithFailingRepo(new BadRequestException('the application said no'))

    try {
      const res = await request(boot.app.getHttpServer())
        .post('/login')
        .send({ email: 'a@example.com', password: 'ProbePass123!-xyz', tenantId: 'tenant-1' })

      expect(res.status).toBe(400)
      expect(res.body).toEqual({
        error: { code: 'auth.internal', message: 'the application said no', details: null }
      })
    } finally {
      await boot.app.close()
    }
  })

  // Verifies a foreign `HttpException` whose body ALREADY carries the envelope is passed through
  // rather than rebuilt.
  //
  // Reachable in a real deployment: an application-level guard or interceptor that answers in this
  // library's shape without constructing an `AuthException`. Rebuilding it would replace a
  // deliberate code with `auth.internal` and drop the `details` — so the assertion is that the
  // specific code and payload survive, not merely that an envelope came back.
  it('passes a foreign HttpException through when its body is already the envelope', async () => {
    const envelope = {
      error: { code: 'auth.forbidden', message: 'the application refused', details: ['why'] }
    }
    const boot = await bootWithFailingRepo(new HttpException(envelope, HttpStatus.FORBIDDEN))

    try {
      const res = await request(boot.app.getHttpServer())
        .post('/login')
        .send({ email: 'a@example.com', password: 'ProbePass123!-xyz', tenantId: 'tenant-1' })

      expect(res.status).toBe(403)
      expect(res.body).toEqual(envelope)
    } finally {
      await boot.app.close()
    }
  })

  // Verifies a foreign `HttpException` carrying a bare STRING body takes its message from that
  // string rather than from `exception.message`.
  //
  // The two are not always the same value, and only a string body distinguishes the branches:
  // `new BadRequestException('x')` produces an object body, so the case above cannot reach this
  // one. Constructed with the string form, which is what `new HttpException('...', status)` does.
  it('takes the message from a string body', async () => {
    const boot = await bootWithFailingRepo(
      new HttpException('a bare string body', HttpStatus.BAD_GATEWAY)
    )

    try {
      const res = await request(boot.app.getHttpServer())
        .post('/login')
        .send({ email: 'a@example.com', password: 'ProbePass123!-xyz', tenantId: 'tenant-1' })

      expect(res.status).toBe(502)
      expect(res.body).toEqual({
        error: { code: 'auth.internal', message: 'a bare string body', details: null }
      })
    } finally {
      await boot.app.close()
    }
  })

  // Verifies the filter leaves an `AuthException` exactly as it was.
  //
  // This is the regression the other two make possible: registering a global filter is the kind
  // of change that quietly re-shapes everything, and the library's own errors must come through
  // untouched — including a `details` payload, which a rebuild would drop. The tenantId refusal is
  // the shortest route to an error that carries one.
  it('passes an AuthException through untouched, details included', async () => {
    const boot = await bootstrapTestApp({ tenantIdResolver: () => 'from-resolver' })

    try {
      const res = await request(boot.app.getHttpServer()).post('/login').send({
        email: 'a@example.com',
        password: 'ProbePass123!-xyz',
        tenantId: 'named-by-the-caller'
      })

      expect(res.status).toBe(400)
      expect(res.body).toEqual({
        error: {
          code: 'auth.validation',
          message: 'Validation failed',
          details: [
            {
              field: 'tenantId',
              message: 'tenantId is decided by this deployment and must not be sent'
            }
          ]
        }
      })
    } finally {
      await boot.app.close()
    }
  })
})
