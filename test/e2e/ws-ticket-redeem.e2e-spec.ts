/**
 * @fileoverview Redeeming a WebSocket ticket after something changed since it was minted.
 *
 * @layer Test
 */

import { randomUUID } from 'node:crypto'

import request from 'supertest'

import { BYMAX_AUTH_USER_REPOSITORY } from '../../src/server/bymax-auth.constants'
import type { IUserRepository } from '../../src/server/interfaces/user-repository.interface'
import { AuthRedisService } from '../../src/server/redis/auth-redis.service'
import { AuthService } from '../../src/server/services/auth.service'
import { WsTicketService } from '../../src/server/services/ws-ticket.service'
import { bootstrapTestApp, createMockUserRepository, expectAuthError } from './setup'
import type { BootstrappedTestApp } from './setup'

const PASSWORD = 'TicketRedeem-9!xyz'
const TENANT = 'tenant-1'

const refusedAs = (code: string): object => ({ response: { error: { code } } })

describe('redeeming a WebSocket ticket (E2E)', () => {
  let boot: BootstrappedTestApp

  beforeAll(async () => {
    boot = await bootstrapTestApp()
  })

  afterAll(async () => {
    await boot.app.close()
  })

  /** Registers an account and mints a ticket from the session that opens. */
  async function ticketFor(email: string): Promise<{ userId: string; ticket: string }> {
    const registered = await request(boot.app.getHttpServer())
      .post('/register')
      .send({ email, password: PASSWORD, name: 'Redeem', tenantId: TENANT })
    const body = registered.body as { accessToken: string; user: { id: string } }
    const minted = await request(boot.app.getHttpServer())
      .post('/ws-ticket')
      .set('Authorization', `Bearer ${body.accessToken}`)
    expect(minted.status).toBe(200)
    return { userId: body.user.id, ticket: (minted.body as { ticket: string }).ticket }
  }

  it('hands back the expiry of the minting token', async () => {
    const { ticket } = await ticketFor('ws-redeem-exp@example.com')

    const identity = await boot.app.get(WsTicketService).redeem(ticket, TENANT)

    expect(identity.exp).toBeGreaterThan(Math.floor(Date.now() / 1000))
  })

  it('refuses an account suspended after the mint', async () => {
    const { userId, ticket } = await ticketFor('ws-redeem-suspended@example.com')
    const users = boot.app.get<IUserRepository>(BYMAX_AUTH_USER_REPOSITORY)
    await users.updateStatus({ id: userId, tenantId: TENANT, status: 'SUSPENDED' })

    await expect(boot.app.get(WsTicketService).redeem(ticket)).rejects.toMatchObject(
      refusedAs('auth.account_suspended')
    )
  })

  it('refuses a session revoked after the mint', async () => {
    const { userId, ticket } = await ticketFor('ws-redeem-revoked@example.com')
    await boot.app.get(AuthService).revokeAllSessions({ userId, tenantId: TENANT })

    await expect(boot.app.get(WsTicketService).redeem(ticket)).rejects.toMatchObject(
      refusedAs('auth.token_invalid')
    )
  })

  // Written by hand, as only another writer of the keyspace can: this application has no
  // platform repository to check such a ticket against.
  it('refuses a record that names no tenant', async () => {
    const ticket = await boot.app.get(AuthRedisService).mintWsTicket(
      {
        sub: 'admin-1',
        role: 'ADMIN',
        status: 'ACTIVE',
        mfaEnabled: false,
        mfaVerified: false,
        jti: randomUUID(),
        epoch: 0
      },
      30
    )

    await expect(boot.app.get(WsTicketService).redeem(ticket)).rejects.toMatchObject(
      refusedAs('auth.token_invalid')
    )
  })

  it('refuses a tenant other than the one the caller expects', async () => {
    const { ticket } = await ticketFor('ws-redeem-tenant@example.com')

    await expect(boot.app.get(WsTicketService).redeem(ticket, 'tenant-2')).rejects.toMatchObject(
      refusedAs('auth.token_invalid')
    )
  })
})

// Why a ticket without a tenant cannot come from this library: the mint takes the tenant from the
// repository's answer, and an answer without one is refused before anything is written.
describe('minting a WebSocket ticket for an answer without a tenant (E2E)', () => {
  it.each([
    ['absent', undefined],
    ['null', null],
    ['empty', '']
  ])('mints nothing when the tenant is %s', async (name, tenantId) => {
    const users = createMockUserRepository()
    const findById = users.findById.bind(users)
    users.findById = async (ref) => {
      const found = await findById(ref)
      return found === null
        ? null
        : Object.defineProperty({ ...found }, 'tenantId', { value: tenantId, enumerable: true })
    }
    const boot = await bootstrapTestApp(
      {},
      { mutateBuilder: (b) => b.overrideProvider(BYMAX_AUTH_USER_REPOSITORY).useValue(users) }
    )
    const registered = await request(boot.app.getHttpServer())
      .post('/register')
      .send({ email: `ws-${name}@example.com`, password: PASSWORD, name: 'Mint', tenantId: TENANT })

    const minted = await request(boot.app.getHttpServer())
      .post('/ws-ticket')
      .set('Authorization', `Bearer ${(registered.body as { accessToken: string }).accessToken}`)
    await boot.app.close()

    expectAuthError(minted, 'auth.internal')
    expect(minted.body).not.toHaveProperty('ticket')
  })
})
