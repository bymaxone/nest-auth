/**
 * End-to-end check of the body the two password-reset request routes acknowledge with.
 *
 * `POST /password/forgot-password` and `POST /password/resend-otp` answer 200 whether or not the
 * account exists. The wire contract pins the body they send as well: an empty JSON object, the
 * same for a known and an unknown account, so a body that differed by outcome cannot become the
 * enumeration oracle the status closes.
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { bootstrapTestApp } from './setup'

interface Acknowledgement {
  routes: string[]
  status: number
  body: unknown
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as { responseBodies: { passwordResetRequest: Acknowledgement } }
const acknowledgement = contract.responseBodies.passwordResetRequest

const EMAIL = 'known@example.com'
const TENANT = 'tenant-1'

describe('password-reset request routes acknowledge with the contract body (E2E)', () => {
  let app: INestApplication

  beforeAll(async () => {
    const bootstrap = await bootstrapTestApp({
      tokenDelivery: 'bearer',
      passwordReset: { method: 'otp', otpLength: 6, otpTtlSeconds: 600 }
    })
    app = bootstrap.app
    await request(app.getHttpServer()).post('/register').send({
      email: EMAIL,
      password: 'AckSecret123!-xyz',
      name: 'Known User',
      tenantId: TENANT
    })
  })

  afterAll(async () => {
    await app.close()
  })

  // Scenario: the contract names both routes. Expected: this suite exercises exactly those.
  it('covers every route the contract lists', () => {
    expect([...acknowledgement.routes].sort()).toEqual([
      'password/forgot-password',
      'password/resend-otp'
    ])
  })

  it.each(['password/forgot-password', 'password/resend-otp'])(
    'answers %s with the contract status and body for a known and an unknown account alike',
    async (route) => {
      const known = await request(app.getHttpServer())
        .post(`/${route}`)
        .send({ email: EMAIL, tenantId: TENANT })
      const unknown = await request(app.getHttpServer())
        .post(`/${route}`)
        .send({ email: 'nobody@example.com', tenantId: TENANT })

      expect(known.status).toBe(acknowledgement.status)
      expect(known.body).toEqual(acknowledgement.body)
      expect(known.text).toBe(JSON.stringify(acknowledgement.body))
      expect(unknown.status).toBe(known.status)
      expect(unknown.text).toBe(known.text)
    }
  )
})
