/**
 * @fileoverview A refresh keeps the second factor the session was established with.
 *
 * `MfaRequiredGuard` refuses a token whose claims say `mfaEnabled && !mfaVerified`. A session that
 * completed the MFA challenge carries `mfaVerified: true`, and a refresh rotation must keep that
 * claim: otherwise every MFA user is refused on every route behind the guard once the access token
 * rotates after `jwt.accessExpiresIn`, and the only way back is to sign in again.
 *
 * So the rule is a whole-pipeline test: a user with MFA signs in, completes the challenge, refreshes,
 * and reaches a route mounted behind the guard, on the host's own controller (the composition the
 * guard's documentation recommends) rather than on one the library mounts.
 */

import { createHmac } from 'node:crypto'

import { Controller, Get, UseGuards } from '@nestjs/common'
import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { JwtAuthGuard } from '../../src/server/guards/jwt-auth.guard'
import { MfaRequiredGuard } from '../../src/server/guards/mfa-required.guard'
import { UserStatusGuard } from '../../src/server/guards/user-status.guard'
import { bootstrapTestApp } from './setup'

/** A host route behind the documented composition `JwtAuthGuard` → `UserStatusGuard` → `MfaRequiredGuard`. */
@Controller('host')
class HostController {
  @Get('protected')
  @UseGuards(JwtAuthGuard, UserStatusGuard, MfaRequiredGuard)
  protected(): { admitted: true } {
    return { admitted: true }
  }
}

const PASSWORD = 'RefreshKeepsFactor-9!xyz'
const EMAIL = 'keeps-factor@example.com'
const TENANT = 'tenant-1'

/** TOTP step length in seconds (RFC 6238 default, the one the library uses). */
const STEP_SECONDS = 30

/** Decodes an RFC 4648 base32 string. */
function base32Decode(input: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const char of input.replace(/=+$/, '').toUpperCase()) {
    bits += alphabet.indexOf(char).toString(2).padStart(5, '0')
  }
  const bytes: number[] = []
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2))
  return Buffer.from(bytes)
}

/**
 * RFC 6238 TOTP (HMAC-SHA-1, 6 digits) for the step containing `time`.
 *
 * @param base32Secret - The shared secret from `/mfa/setup`.
 * @param time - Epoch milliseconds.
 * @returns The six-digit code.
 */
function totp(base32Secret: string, time: number): string {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(time / 1000 / STEP_SECONDS)))
  const digest = createHmac('sha1', base32Decode(base32Secret)).update(counter).digest()
  const offset = (digest[digest.length - 1] as number) & 0x0f
  const value = digest.readUInt32BE(offset) & 0x7fffffff
  return (value % 1_000_000).toString().padStart(6, '0')
}

describe('refresh keeps the second factor (E2E)', () => {
  let app: INestApplication
  let accessToken: string
  let refreshToken: string

  beforeAll(async () => {
    const boot = await bootstrapTestApp(
      { tokenDelivery: 'bearer' },
      { hostControllers: [HostController] }
    )
    app = boot.app

    const register = await request(app.getHttpServer())
      .post('/register')
      .send({ email: EMAIL, password: PASSWORD, name: 'Keeps Factor', tenantId: TENANT })
    const setup = await request(app.getHttpServer())
      .post('/mfa/setup')
      .set('Authorization', `Bearer ${register.body.accessToken as string}`)
      .send({ password: PASSWORD })
    const secret = setup.body.secret as string

    await request(app.getHttpServer())
      .post('/mfa/verify-enable')
      .set('Authorization', `Bearer ${register.body.accessToken as string}`)
      .send({ code: totp(secret, Date.now()) })

    // Signing in again asks for the second factor; the code is one step ahead of the one spent
    // enabling it, because that step's anti-replay marker is stored.
    const login = await request(app.getHttpServer())
      .post('/login')
      .send({ email: EMAIL, password: PASSWORD, tenantId: TENANT })
    const challenge = await request(app.getHttpServer())
      .post('/mfa/challenge')
      .send({
        mfaTempToken: login.body.mfaTempToken as string,
        code: totp(secret, Date.now() + STEP_SECONDS * 1000)
      })
    accessToken = challenge.body.accessToken as string
    refreshToken = challenge.body.refreshToken as string
  })

  afterAll(async () => {
    await app.close()
  })

  // The baseline: the token the challenge issued reaches the route. Without this, a failure after
  // the refresh could be a fixture that never worked.
  it('admits the token the challenge issued', async () => {
    const res = await request(app.getHttpServer())
      .get('/host/protected')
      .set('Authorization', `Bearer ${accessToken}`)

    expect(res.status).toBe(200)
  })

  // The property under test: the session was established with the second factor, so the rotated
  // token it produces is not asked for it again.
  it('admits the access token a refresh rotation issues', async () => {
    const refreshed = await request(app.getHttpServer()).post('/refresh').send({ refreshToken })
    expect(refreshed.status).toBe(200)

    const res = await request(app.getHttpServer())
      .get('/host/protected')
      .set('Authorization', `Bearer ${refreshed.body.accessToken as string}`)

    expect(res.status).toBe(200)
  })

  // Each rotation inherits from the one before, so the factor has to survive a chain of them and not
  // only the first: a second refresh is how a long-lived page behaves.
  it('keeps the factor across a second rotation', async () => {
    const first = await request(app.getHttpServer()).post('/refresh').send({ refreshToken })
    const second = await request(app.getHttpServer())
      .post('/refresh')
      .send({ refreshToken: first.body.refreshToken as string })
    expect(second.status).toBe(200)

    const res = await request(app.getHttpServer())
      .get('/host/protected')
      .set('Authorization', `Bearer ${second.body.accessToken as string}`)

    expect(res.status).toBe(200)
  })
})
