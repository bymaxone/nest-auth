/**
 * @fileoverview The tenant binding on a WebSocket upgrade behind a Host-rewriting proxy.
 *
 * The tenant is decided by the host name. A proxy such as nginx with its default
 * `proxy_set_header Host $proxy_host` presents the UPSTREAM host in `Host` and the public one in
 * `X-Forwarded-Host`. Over HTTP, Express resolves `req.hostname` from the forwarded header when its
 * `trust proxy` setting trusts the peer; an upgrade has no Express request, so the binding has to
 * make the same decision from the TCP peer the transport reports. These cases drive a real
 * Socket.IO handshake from the loopback address the test client really connects from, and judge
 * that peer with the compiled `trust proxy` function of the Express instance behind the Nest
 * adapter, wired the way the README documents.
 */

import type { INestApplication } from '@nestjs/common'
import { UseGuards } from '@nestjs/common'
import { ConnectedSocket, SubscribeMessage, WebSocketGateway } from '@nestjs/websockets'
import type express from 'express'
import request from 'supertest'
import { io } from 'socket.io-client'
import type { Socket as ClientSocket } from 'socket.io-client'

import { WsJwtGuard } from '../../src/server/guards/ws-jwt.guard'
import type { BymaxAuthModuleOptions } from '../../src/server/interfaces/auth-module-options.interface'
import { bootstrapTestApp } from './setup'

/** The identity the guard attached to the socket, as the handler sees it. */
interface WhoAmI {
  sub?: unknown
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

const PASSWORD = 'Ws-Trusted-Proxy-Passphrase'

/** The host the public sees for the tenant, and the one the proxy presents to the upstream. */
const PUBLIC_HOST = 'tenant-a.example.com'
const OTHER_HOST = 'tenant-b.example.com'
const UPSTREAM_HOST = 'upstream.internal'

/** The tenant is the first label of the host name, which is what the template's resolver does. */
const tenantFromHost: NonNullable<BymaxAuthModuleOptions['tenantIdResolver']> = (req) => {
  const label = req.hostname.split('.')[0]
  if (label === undefined || label === '') throw new Error('no tenant in the host')
  return label
}

/**
 * The README's recipe: the module factory runs before the app exists, so it reads the policy per
 * connection from a holder that refuses every peer until the Express instance behind the adapter
 * has been configured. `app.get()` would resolve a provider and not read the setting.
 */
function proxyPolicy(): {
  trusts: (peer: string) => boolean
  configure: (app: INestApplication, setting: string) => void
} {
  const policy = {
    trusts: (_peer: string): boolean => false,
    configure: (app: INestApplication, setting: string): void => {
      const expressApp = app.getHttpAdapter().getInstance() as express.Express
      expressApp.set('trust proxy', setting)
      policy.trusts = (peer) =>
        (expressApp.get('trust proxy fn') as (address: string, hop: number) => boolean)(peer, 0)
    }
  }
  return policy
}

/** One round trip: connect with the given headers, send `whoami`, resolve with the answer or refusal. */
async function whoami(
  port: number,
  token: string,
  headers: Record<string, string>
): Promise<{ ok: true; user: WhoAmI } | { ok: false }> {
  const socket: ClientSocket = io(`http://127.0.0.1:${String(port)}`, {
    transports: ['websocket'],
    forceNew: true,
    reconnection: false,
    extraHeaders: { Authorization: `Bearer ${token}`, ...headers }
  })

  try {
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error('the gateway answered neither the message nor an exception'))
      }, 5_000)
      const settle = (value: { ok: true; user: WhoAmI } | { ok: false }): void => {
        clearTimeout(timer)
        resolve(value)
      }
      socket.on('exception', () => settle({ ok: false }))
      socket.on('connect_error', () => settle({ ok: false }))
      socket.emit('whoami', {}, (user: WhoAmI) => settle({ ok: true, user }))
    })
  } finally {
    socket.disconnect()
  }
}

/** Boots an application with the binding on and the given trust policy, and a tenant-a token. */
async function boot(
  isTrustedProxy: BymaxAuthModuleOptions['isTrustedProxy']
): Promise<{ app: INestApplication; port: number; token: string }> {
  const { app } = await bootstrapTestApp(
    {
      enforceTenantBinding: true,
      tenantIdResolver: tenantFromHost,
      ...(isTrustedProxy === undefined ? {} : { isTrustedProxy })
    },
    { hostProviders: [ProbeGateway] }
  )
  await app.listen(0)
  const port = (app.getHttpServer() as { address: () => { port: number } }).address().port

  const registered = await request(app.getHttpServer())
    .post('/register')
    .set('Host', PUBLIC_HOST)
    .send({ email: 'proxied@example.com', password: PASSWORD, name: 'Proxied Holder' })
  return { app, port, token: registered.body.accessToken as string }
}

describe('enforceTenantBinding behind a Host-rewriting proxy (E2E)', () => {
  describe('when the host trusts the loopback peer', () => {
    let app: INestApplication
    let port: number
    let token: string

    beforeAll(async () => {
      const policy = proxyPolicy()
      ;({ app, port, token } = await boot((peer) => policy.trusts(peer)))
      policy.configure(app, 'loopback')
    })

    afterAll(async () => {
      await app.close()
    })

    // The proxy presents the upstream host and forwards the public one. The peer is trusted, so the
    // forwarded host decides the tenant, exactly as it does for Express over HTTP.
    it('admits a tenant-a token when the forwarded host names tenant-a', async () => {
      const result = await whoami(port, token, {
        Host: UPSTREAM_HOST,
        'X-Forwarded-Host': PUBLIC_HOST
      })

      expect(result.ok).toBe(true)
    })

    // The binding still binds: the forwarded host names another tenant.
    it('refuses a tenant-a token when the forwarded host names tenant-b', async () => {
      const result = await whoami(port, token, {
        Host: UPSTREAM_HOST,
        'X-Forwarded-Host': OTHER_HOST
      })

      expect(result.ok).toBe(false)
    })

    // A trusted peer that forwarded nothing leaves the upstream host to decide, which names no tenant.
    it('refuses when the trusted peer forwarded no host and Host is the upstream', async () => {
      const result = await whoami(port, token, { Host: UPSTREAM_HOST })

      expect(result.ok).toBe(false)
    })
  })

  describe('when the host trusts no peer', () => {
    let app: INestApplication
    let port: number
    let token: string

    beforeAll(async () => {
      ;({ app, port, token } = await boot(() => false))
    })

    afterAll(async () => {
      await app.close()
    })

    // The same handshake, from a peer the policy does not trust: the forwarded host is a claim the
    // client made, so the upstream host stands and the binding refuses.
    it('refuses the proxied handshake and ignores the forwarded host', async () => {
      const result = await whoami(port, token, {
        Host: UPSTREAM_HOST,
        'X-Forwarded-Host': PUBLIC_HOST
      })

      expect(result.ok).toBe(false)
    })

    // The honest handshake still works: a direct client whose Host names its tenant.
    it('admits a direct client whose Host names its tenant', async () => {
      const result = await whoami(port, token, { Host: PUBLIC_HOST })

      expect(result.ok).toBe(true)
    })
  })

  describe('when no trust policy is configured', () => {
    let app: INestApplication
    let port: number
    let token: string

    beforeAll(async () => {
      ;({ app, port, token } = await boot(undefined))
    })

    afterAll(async () => {
      await app.close()
    })

    // The default: X-Forwarded-Host is never read, so a client cannot choose its own host.
    it('refuses a forged forwarded host', async () => {
      const result = await whoami(port, token, {
        Host: UPSTREAM_HOST,
        'X-Forwarded-Host': PUBLIC_HOST
      })

      expect(result.ok).toBe(false)
    })
  })
})
