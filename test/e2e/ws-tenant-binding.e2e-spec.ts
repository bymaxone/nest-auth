/**
 * @fileoverview `enforceTenantBinding` on the WebSocket transport.
 *
 * The HTTP guard re-resolves the request tenant and refuses a token minted for another one. The
 * socket guard is a second door to the same room, so a binding that holds on HTTP and not here is
 * a hole in the option rather than a missing feature. These cases drive a real Socket.IO
 * handshake through both credential channels — the bearer header and the single-use ticket — with
 * the tenant named by a header the way a host-per-tenant edge would name it.
 */

import type { INestApplication } from '@nestjs/common'
import { Inject, UseGuards } from '@nestjs/common'
import { ConnectedSocket, SubscribeMessage, WebSocketGateway } from '@nestjs/websockets'
import request from 'supertest'
import { io } from 'socket.io-client'
import type { Socket as ClientSocket } from 'socket.io-client'

import { WsJwtGuard } from '../../src/server/guards/ws-jwt.guard'
import { AuthTokenVerifierService } from '../../src/server/services/auth-token-verifier.service'
import { bootstrapTestApp } from './setup'

/** The identity the guard attached to the socket, as the handler sees it. */
interface WhoAmI {
  sub?: unknown
  tenantId?: unknown
}

/** Echoes the identity the guard attached, so an admission asserts something. */
@WebSocketGateway({ transports: ['websocket'] })
class ProbeGateway {
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('whoami')
  whoami(@ConnectedSocket() client: { data: { user?: WhoAmI } }) {
    return client.data.user ?? null
  }
}

/**
 * A gateway that authenticates with the verifier service instead of the guard — the consumer
 * shape for a long-lived stream — passing the handshake it received.
 */
@WebSocketGateway({ namespace: 'verified', transports: ['websocket'] })
class VerifierGateway {
  constructor(
    @Inject(AuthTokenVerifierService) private readonly verifier: AuthTokenVerifierService
  ) {}

  @SubscribeMessage('whoami')
  async whoami(
    @ConnectedSocket()
    client: {
      handshake: { headers: Record<string, string | undefined>; url?: string }
    }
  ): Promise<{ ok: boolean }> {
    const token = client.handshake.headers['authorization']?.slice('Bearer '.length) ?? ''
    try {
      await this.verifier.verifyAccessToken(token, {
        plane: 'dashboard',
        request: client.handshake
      })
      return { ok: true }
    } catch {
      return { ok: false }
    }
  }
}

const PASSWORD = 'Ws-Tenant-Binding-Passphrase'

/** The header a host-per-tenant edge would set; the resolver below reads nothing else. */
const TENANT_HEADER = 'x-tenant-id'

/** One round trip: connect naming `tenant`, send `whoami`, resolve with the answer or refusal. */
async function whoami(
  port: number,
  options: { tenant?: string; ticket?: string; token?: string; namespace?: string }
): Promise<{ ok: true; user: WhoAmI } | { ok: false; error: unknown }> {
  const headers: Record<string, string> = {}
  if (options.tenant !== undefined) headers[TENANT_HEADER] = options.tenant
  if (options.token !== undefined) headers['Authorization'] = `Bearer ${options.token}`

  const socket: ClientSocket = io(`http://127.0.0.1:${String(port)}${options.namespace ?? ''}`, {
    transports: ['websocket'],
    forceNew: true,
    reconnection: false,
    extraHeaders: headers,
    ...(options.ticket === undefined ? {} : { query: { ticket: options.ticket } })
  })

  try {
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error('the gateway answered neither the message nor an exception'))
      }, 5_000)
      const settle = (value: { ok: true; user: WhoAmI } | { ok: false; error: unknown }): void => {
        clearTimeout(timer)
        resolve(value)
      }
      socket.on('exception', (error: unknown) => settle({ ok: false, error }))
      socket.on('connect_error', (error: unknown) => settle({ ok: false, error }))
      socket.emit('whoami', {}, (user: WhoAmI) => settle({ ok: true, user }))
    })
  } finally {
    socket.disconnect()
  }
}

describe('enforceTenantBinding on the WebSocket guard (E2E)', () => {
  let app: INestApplication
  let port: number
  let accessToken: string
  let userId: string

  beforeAll(async () => {
    const boot = await bootstrapTestApp(
      {
        enforceTenantBinding: true,
        tenantIdResolver: (req) => {
          const id = req.headers[TENANT_HEADER]
          if (typeof id !== 'string' || id === '') throw new Error('no tenant named')
          return id
        }
      },
      { hostProviders: [ProbeGateway, VerifierGateway] }
    )
    app = boot.app
    await app.listen(0)
    port = (app.getHttpServer() as { address: () => { port: number } }).address().port

    const registered = await request(app.getHttpServer())
      .post('/register')
      .set(TENANT_HEADER, 'tenant-a')
      .send({ email: 'bound@example.com', password: PASSWORD, name: 'Bound Holder' })
    accessToken = registered.body.accessToken as string
    userId = (registered.body.user as { id: string }).id
  })

  afterAll(async () => {
    await app.close()
  })

  async function mintTicket(): Promise<string> {
    const res = await request(app.getHttpServer())
      .post('/ws-ticket')
      .set(TENANT_HEADER, 'tenant-a')
      .set('Authorization', `Bearer ${accessToken}`)
    expect(res.status).toBe(200)
    return (res.body as { ticket: string }).ticket
  }

  it('control: the HTTP guard refuses the tenant-a token presented under tenant-b', async () => {
    const res = await request(app.getHttpServer())
      .post('/ws-ticket')
      .set(TENANT_HEADER, 'tenant-b')
      .set('Authorization', `Bearer ${accessToken}`)

    expect(res.status).toBe(401)
  })

  it('admits a bearer handshake that names the token tenant', async () => {
    const result = await whoami(port, { tenant: 'tenant-a', token: accessToken })

    expect(result.ok && result.user).toEqual(expect.objectContaining({ sub: userId }))
  })

  it('admits a ticket upgrade that names the ticket tenant', async () => {
    const result = await whoami(port, { tenant: 'tenant-a', ticket: await mintTicket() })

    expect(result.ok && result.user).toEqual(expect.objectContaining({ sub: userId }))
  })

  it('refuses a bearer handshake that names another tenant', async () => {
    const result = await whoami(port, { tenant: 'tenant-b', token: accessToken })

    expect(result.ok).toBe(false)
  })

  it('refuses a ticket upgrade that names another tenant', async () => {
    const result = await whoami(port, { tenant: 'tenant-b', ticket: await mintTicket() })

    expect(result.ok).toBe(false)
  })

  it('refuses a bearer handshake that names no tenant', async () => {
    const result = await whoami(port, { token: accessToken })

    expect(result.ok).toBe(false)
  })

  // The verifier is the other door a stream can authenticate through, so it is bound the same way
  // once the host passes the handshake.
  it.each([
    ['tenant-a', true],
    ['tenant-b', false]
  ])('the verifier service, given the handshake naming %s, answers ok=%s', async (tenant, ok) => {
    const result = await whoami(port, { tenant, token: accessToken, namespace: '/verified' })

    expect(result.ok && result.user).toEqual({ ok })
  })
})
