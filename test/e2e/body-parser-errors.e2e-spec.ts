/**
 * @fileoverview Proves `AuthExceptionFilter` answers a request the body parser refused with a
 * client-error envelope rather than `auth.internal`.
 *
 * The parser runs before routing and before any handler, so these failures never touch the
 * library's own code: Nest turns a `SyntaxError` into a `BadRequestException` carrying the
 * parser's text, and hands every other parser failure to the filter as a raw `http-errors`
 * object with a `type`. Each case here drives a real HTTP request through the booted app, because
 * a unit test would have to invent exactly the objects whose shape is in question.
 */

import { BadRequestException } from '@nestjs/common'
import request from 'supertest'

import { BYMAX_AUTH_USER_REPOSITORY } from '../../src/server/bymax-auth.constants'
import { bootstrapTestApp, createMockUserRepository } from './setup'
import type { BootstrappedTestApp } from './setup'

const MALFORMED = {
  error: { code: 'auth.validation', message: 'Malformed request', details: null }
}

describe('Body-parser failures over HTTP (E2E)', () => {
  let boot: BootstrappedTestApp

  beforeAll(async () => {
    boot = await bootstrapTestApp({})
  })

  afterAll(async () => {
    await boot.app.close()
  })

  // Verifies bodies the JSON parser rejects answer 400 `auth.validation`, with a message that
  // does not repeat any of the body. A bare string and a bare number are rejected by the parser's
  // strict mode, so they take the same path as syntactically broken JSON.
  it.each([
    ['unparseable JSON', '{not json'],
    ['a bare JSON string', '"abc-secret-marker"'],
    ['a bare JSON number', '42']
  ])('answers 400 auth.validation for %s and echoes nothing', async (_name, body) => {
    const res = await request(boot.app.getHttpServer())
      .post('/login')
      .set('Content-Type', 'application/json')
      .send(body)

    expect(res.status).toBe(400)
    expect(res.body).toEqual(MALFORMED)
    expect(JSON.stringify(res.body)).not.toContain('secret-marker')
  })

  // Verifies a path the framework cannot decode takes the same generic answer, so the message
  // never claims the body was the problem when it was not.
  it('answers 400 auth.validation for an undecodable path', async () => {
    const res = await request(boot.app.getHttpServer()).delete('/sessions/%FF')

    expect(res.status).toBe(400)
    expect(res.body).toEqual(MALFORMED)
  })

  // Verifies a form body nested deeper than the urlencoded parser allows is a client error. The
  // parser reports it as a 400 http-error of its own type, which no other case reaches.
  it('answers 400 auth.validation for a form body nested past the parser depth limit', async () => {
    const res = await request(boot.app.getHttpServer())
      .post('/login')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`a${'[b]'.repeat(40)}=1`)

    expect(res.status).toBe(400)
    expect(res.body).toEqual(MALFORMED)
  })

  // Verifies an oversized body is a 413 client error, not a 500.
  it('answers 413 auth.validation for a body over the limit', async () => {
    const res = await request(boot.app.getHttpServer())
      .post('/login')
      .set('Content-Type', 'application/json')
      .send(JSON.stringify({ a: 'x'.repeat(200_000) }))

    expect(res.status).toBe(413)
    expect(res.body).toEqual({
      error: { code: 'auth.validation', message: 'Request entity too large', details: null }
    })
  })

  // Verifies a charset and a content-encoding the parser cannot read are 415 client errors.
  it.each([
    ['an unsupported charset', { 'Content-Type': 'application/json; charset=nope' }, '{}'],
    [
      'an unsupported content-encoding',
      { 'Content-Type': 'application/json', 'Content-Encoding': 'nope' },
      '{}'
    ]
  ])('answers 415 auth.validation for %s', async (_name, headers, body) => {
    const res = await request(boot.app.getHttpServer()).post('/login').set(headers).send(body)

    expect(res.status).toBe(415)
    expect(res.body).toEqual({
      error: { code: 'auth.validation', message: 'Unsupported media type', details: null }
    })
  })

  // Verifies the remap is limited to failures raised before routing: a 400 the application raises
  // from inside a handler's call path keeps its own message and `auth.internal`, which is the
  // behaviour the host chose.
  it('leaves a BadRequestException thrown from a routed handler untouched', async () => {
    const repo = createMockUserRepository()
    repo.findByEmail = (): never => {
      throw new BadRequestException('the application said no')
    }
    const routed = await bootstrapTestApp(
      {},
      {
        mutateBuilder: (builder) =>
          builder.overrideProvider(BYMAX_AUTH_USER_REPOSITORY).useValue(repo) as typeof builder
      }
    )
    try {
      const res = await request(routed.app.getHttpServer())
        .post('/login')
        .send({ email: 'a@example.com', password: 'ProbePass123!-xyz', tenantId: 'tenant-1' })

      expect(res.status).toBe(400)
      expect(res.body).toEqual({
        error: { code: 'auth.internal', message: 'the application said no', details: null }
      })
    } finally {
      await routed.app.close()
    }
  })
})
