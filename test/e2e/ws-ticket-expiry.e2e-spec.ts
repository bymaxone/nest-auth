/**
 * @fileoverview A WebSocket ticket never outlives the access token that minted it.
 *
 * A logout blacklists the access token's `jti` for the token's REMAINING life, because nothing
 * later can present that token. A ticket minted from it is a separate credential with its own
 * lifetime, so a ticket given the full 30 seconds outlives the blacklist entry whenever the token
 * had less than that left: the entry expires with the token, the user's epoch is unchanged, and
 * the ticket redeems although its session ended.
 *
 * The scenario needs real time to pass, so the access token is made short-lived instead of the
 * clock being faked: Redis expiry (here `ioredis-mock`) runs on the same real clock the token's
 * `exp` does, which is the property under test.
 */

import request from 'supertest'

import { WsTicketService } from '../../src/server/services/ws-ticket.service'
import { bootstrapTestApp, JWT_SECRET } from './setup'
import type { BootstrappedTestApp } from './setup'

const PASSWORD = 'TicketExpiry-9!xyz'
const TOKEN_LIFE_SECONDS = 2

/** Waits real time; the Redis expiry under test cannot be advanced any other way here. */
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

describe('a WebSocket ticket against its minting token (E2E)', () => {
  let boot: BootstrappedTestApp

  beforeAll(async () => {
    boot = await bootstrapTestApp({
      jwt: { secret: JWT_SECRET, accessExpiresIn: `${TOKEN_LIFE_SECONDS}s` }
    })
  })

  afterAll(async () => {
    await boot.app.close()
  })

  /** Registers a user and returns the session it opened. */
  async function session(email: string): Promise<{ accessToken: string; refreshToken: string }> {
    const res = await request(boot.app.getHttpServer())
      .post('/register')
      .send({ email, password: PASSWORD, name: 'Short Lived', tenantId: 'tenant-1' })
    expect(res.status).toBe(201)
    return res.body as { accessToken: string; refreshToken: string }
  }

  // Scenario: a ticket minted from a token with TOKEN_LIFE_SECONDS left. Expected: the response
  // reports a lifetime no longer than the token's. Why: `expiresIn` is what a client schedules its
  // upgrade by, so it must be the capped value rather than the 30-second ceiling.
  it('reports a lifetime no longer than the minting token has left', async () => {
    const { accessToken } = await session('ws-expiry-reported@example.com')

    const res = await request(boot.app.getHttpServer())
      .post('/ws-ticket')
      .set('Authorization', `Bearer ${accessToken}`)

    expect(res.status).toBe(200)
    expect((res.body as { expiresIn: number }).expiresIn).toBeLessThanOrEqual(TOKEN_LIFE_SECONDS)
    expect((res.body as { expiresIn: number }).expiresIn).toBeGreaterThan(0)
  })

  // Scenario: mint with the token nearly spent, log out, then wait until the blacklist entry has
  // expired with the token. Expected: the ticket is refused. Why: with a fixed 30-second ticket
  // the blacklist entry is gone after the token's remaining life while the ticket is not, and
  // nothing else ends it.
  it('refuses a ticket after a logout once the blacklist entry has expired with the token', async () => {
    const { accessToken, refreshToken } = await session('ws-expiry-logout@example.com')
    const minted = await request(boot.app.getHttpServer())
      .post('/ws-ticket')
      .set('Authorization', `Bearer ${accessToken}`)
    expect(minted.status).toBe(200)

    await request(boot.app.getHttpServer())
      .post('/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ refreshToken })

    await sleep((TOKEN_LIFE_SECONDS + 1) * 1000)

    await expect(
      boot.app.get(WsTicketService).redeem((minted.body as { ticket: string }).ticket)
    ).rejects.toMatchObject({ response: { error: { code: 'auth.token_invalid' } } })
  })
})
