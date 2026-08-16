/**
 * @fileoverview `WsJwtGuard` under a real WebSocket handshake.
 *
 * 228 lines at **0% e2e coverage**. Every other guard in this library is reached by an HTTP
 * request; this one is reached by a socket upgrade, and no suite here spoke that protocol — so
 * its only proof was unit tests handing it a hand-built `ExecutionContext` whose `switchToWs()`
 * returned an object literal. That proves the code runs. It cannot prove that a real
 * `@nestjs/platform-socket.io` handshake presents the credential where the guard looks for it,
 * which is the entire question about a guard whose input comes from a transport.
 *
 * The alternative was to exclude it from the rule with the risk written down. The devDependency
 * was taken instead: `@nestjs/platform-socket.io`, `socket.io` and `socket.io-client` are
 * dev-only, none of them reaches the published bundle, and the guard is now exercised by the
 * transport it exists for. What corrodes a rule is a layer that quietly stops counting because
 * covering it was inconvenient.
 *
 * The gateway below is the CONSUMER's, declared in the test module — the same stance
 * `host-mounted-guards.e2e-spec.ts` takes for the HTTP guards, and for the same reason: a guard
 * applied with `@UseGuards()` resolves its dependencies from the declaring module's injector, so
 * this is also a test that `BymaxAuthModule` exports everything `WsJwtGuard` needs.
 *
 * Three branches stay out of reach of this transport, and are stated rather than skipped:
 *
 *  - `onModuleInit`'s missing-`@nestjs/websockets` arm. Reaching it means uninstalling the
 *    package this suite needs to exist.
 *  - `assertDashboardSnapshot`'s non-string `sub`. `redeemWsTicket` already refuses a record
 *    whose `sub` is not a string — it never becomes a snapshot — so the check is defence against
 *    a future writer on the shared keyspace rather than against anything the current one emits.
 *    Its sibling check, the missing tenant, IS reachable and is driven below.
 *  - `readUpgradeTicket`'s unparseable-URL arm. Socket.IO builds the upgrade URL itself, so it
 *    is always parseable; a raw `ws` server handing over a malformed one is what that arm is for.
 *
 * All three are covered by the guard's unit spec.
 */

import { createHash, createHmac } from 'node:crypto'

import type { INestApplication } from '@nestjs/common'
import { UseFilters, UseGuards } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import {
  ConnectedSocket,
  MessageBody,
  SubscribeMessage,
  WebSocketGateway
} from '@nestjs/websockets'
import request from 'supertest'
import { io } from 'socket.io-client'
import type { Socket as ClientSocket } from 'socket.io-client'

import { sha256 } from '../../src/server/crypto/secure-token'
import { WsAdapter } from '@nestjs/platform-ws'
import WebSocket from 'ws'

import { WsAuthExceptionFilter } from '../../src/server/filters/ws-auth-exception.filter'
import { WsJwtGuard } from '../../src/server/guards/ws-jwt.guard'
import type { BootstrappedTestApp } from './setup'
import { bootstrapTestApp, JWT_SECRET } from './setup'

// ---------------------------------------------------------------------------
// The consumer's gateway
// ---------------------------------------------------------------------------

/** The identity the guard attached to the socket, as the handler sees it. */
interface WhoAmI {
  sub?: unknown
  tenantId?: unknown
  type?: unknown
}

/**
 * A gateway that answers with whatever the guard put on `client.data.user`.
 *
 * The guard is applied to the handler rather than the connection, which is where `@UseGuards()`
 * runs in Nest: the socket connects unauthenticated and the first message is what has to prove
 * itself. Echoing the identity back is what makes the admission cases assert something — a
 * handler returning a constant would pass against a guard that admitted everyone.
 */
@WebSocketGateway({ transports: ['websocket'] })
class ProbeGateway {
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('whoami')
  whoami(@ConnectedSocket() client: { data: { user?: WhoAmI } }, @MessageBody() _body: unknown) {
    return client.data.user ?? null
  }
}

/**
 * The same gateway with `WsAuthExceptionFilter` registered — the deployment the README
 * prescribes for a host that mounts WebSockets.
 *
 * It exists beside the unfiltered one on purpose: the filter's whole claim is that the two
 * answer a refused client DIFFERENTLY, and one gateway can only ever show one of the two
 * answers. Running both under the same application, the same guard and the same credential is
 * what isolates the filter as the variable.
 */
@WebSocketGateway({ namespace: 'filtered', transports: ['websocket'] })
@UseFilters(new WsAuthExceptionFilter())
class FilteredGateway {
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('whoami')
  whoami(@ConnectedSocket() client: { data: { user?: WhoAmI } }, @MessageBody() _body: unknown) {
    return client.data.user ?? null
  }
}

/**
 * The same gateway again, for the NATIVE `ws` adapter.
 *
 * A native client also extends `EventEmitter`, so a filter that only emits succeeds on it and
 * sends nothing — the peer is told nothing while the code path looks taken. That failure is
 * invisible from a Socket.IO suite, which is why this one exists.
 */
@WebSocketGateway({ path: '/native' })
@UseFilters(new WsAuthExceptionFilter())
class NativeGateway {
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('whoami')
  whoami(@ConnectedSocket() client: { data: { user?: WhoAmI } }, @MessageBody() _body: unknown) {
    return client.data.user ?? null
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PASSWORD = 'Ws-Guard-Flow-Passphrase'

/** One round trip: connect, send `whoami`, resolve with the answer or the refusal. */
async function whoami(
  port: number,
  options: { ticket?: string; token?: string; namespace?: string }
): Promise<{ ok: true; user: WhoAmI } | { ok: false; error: unknown }> {
  const socket: ClientSocket = io(`http://127.0.0.1:${String(port)}${options.namespace ?? ''}`, {
    transports: ['websocket'],
    forceNew: true,
    reconnection: false,
    ...(options.ticket === undefined ? {} : { query: { ticket: options.ticket } }),
    ...(options.token === undefined
      ? {}
      : { extraHeaders: { Authorization: `Bearer ${options.token}` } })
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

      // Nest's WS exception layer emits refusals on `exception` rather than closing the socket,
      // so both outcomes are ordinary events and the test must listen for either. Listening for
      // only the happy one is how a suite times out on a refusal it should have asserted.
      socket.on('exception', (error: unknown) => settle({ ok: false, error }))
      socket.on('connect_error', (error: unknown) => settle({ ok: false, error }))
      socket.emit('whoami', {}, (user: WhoAmI) => settle({ ok: true, user }))
    })
  } finally {
    socket.disconnect()
  }
}

/**
 * What a refused client actually receives.
 *
 * NOT the library's error code. `WsJwtGuard` throws `AuthException`, which is an `HttpException`,
 * and Nest's WebSocket exception layer understands only `WsException` — everything else becomes
 * the generic `{status: 'error', message: 'Internal server error'}` below. So the whole
 * `auth.*` catalogue stops at the socket boundary, and a client cannot tell a refused credential
 * from a crashed handler. Measured here rather than assumed, and reported to the maintainer as
 * its own decision: fixing it is either a new exported WS exception filter or a change to what
 * the guard throws, and both are public surface.
 *
 * This helper exists so the refusal cases assert the payload that IS delivered. Asserting the
 * code the guard names would have failed for the right reason and read as the guard being
 * broken, which it is not — every refusal below happens, at the right moment, for the right
 * input.
 */
function refusalStatus(error: unknown): unknown {
  return (error as { status?: unknown }).status
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

/**
 * The token-epoch key the library derives for a dashboard account, computed the way the library does.
 *
 * The HMAC key is derived from the JWT secret by the same label `resolveOptions` uses, so this
 * exercises the real derivation end to end rather than restating a hash. A key spelled out as a
 * literal would pass on a build that derived it differently.
 */
function tokenEpochFor(userId: string, tenantId: string): string {
  const hmacKey = createHash('sha256')
    .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
    .digest('hex')
  return `ep:${createHmac('sha256', hmacKey).update(`dashboard:${tenantId}:${userId}`).digest('hex')}`
}

describe('WsJwtGuard under a real handshake (E2E)', () => {
  let boot: BootstrappedTestApp
  let app: INestApplication
  let port: number
  let accessToken: string
  let refreshToken: string
  let userId: string

  beforeAll(async () => {
    boot = await bootstrapTestApp({}, { hostProviders: [ProbeGateway, FilteredGateway] })
    app = boot.app

    // A listening server, which no other e2e here needs: supertest drives the HTTP handler
    // directly, but a socket upgrade needs a real port to connect to.
    await app.listen(0)
    port = (app.getHttpServer() as { address: () => { port: number } }).address().port

    const registered = await request(app.getHttpServer()).post('/register').send({
      email: 'ws-client@example.com',
      password: PASSWORD,
      name: 'Socket Holder',
      tenantId: 'tenant-1'
    })

    accessToken = registered.body.accessToken as string
    refreshToken = registered.body.refreshToken as string
    userId = (registered.body.user as { id: string }).id
  })

  afterAll(async () => {
    await app.close()
  })

  /** Mints a single-use upgrade ticket the way a browser client has to. */
  async function mintTicket(token = accessToken): Promise<string> {
    const res = await request(app.getHttpServer())
      .post('/ws-ticket')
      .set('Authorization', `Bearer ${token}`)

    expect(res.status).toBe(200)
    return (res.body as { ticket: string }).ticket
  }

  // ---------------------------------------------------------------------------
  // Admissions
  // ---------------------------------------------------------------------------

  // The path a browser has to take: the `WebSocket` API cannot set handshake headers, so the
  // credential is a single-use ticket in the upgrade query. This is the only place this library
  // reads a credential from a query string, and the reason it is acceptable is that the value is
  // opaque, ~30 seconds old and dead on first redemption — properties the next case proves.
  it('admits an upgrade carrying a valid ticket, as the snapshot it was minted from', async () => {
    const result = await whoami(port, { ticket: await mintTicket() })

    expect(result.ok).toBe(true)
    expect(result.ok && result.user).toEqual(
      expect.objectContaining({ sub: userId, tenantId: 'tenant-1' })
    )
  })

  // The header path, which a server-side client can take. Same guard, different channel, and the
  // identity it attaches is the JWT payload rather than a ticket snapshot — so the two admissions
  // are not the same assertion twice.
  it('admits a handshake carrying a bearer access token', async () => {
    const result = await whoami(port, { token: accessToken })

    expect(result.ok).toBe(true)
    expect(result.ok && result.user).toEqual(
      expect.objectContaining({ sub: userId, tenantId: 'tenant-1', type: 'dashboard' })
    )
  })

  // ---------------------------------------------------------------------------
  // The native `ws` adapter
  // ---------------------------------------------------------------------------

  // Its own application, because the adapter is per-application: `useWebSocketAdapter` replaces
  // the Socket.IO one, and the two cannot serve the same process.
  //
  // The case is the one a Socket.IO suite structurally cannot reach. A native client extends
  // `EventEmitter`, so `emit('exception', …)` on it SUCCEEDS and delivers nothing — the filter
  // would look correct in code, pass every unit test written against an emitter, and tell the
  // peer nothing. `@nestjs/platform-ws` delivers with `send(JSON.stringify(...))`, and this
  // asserts the frame arrives.
  it('delivers the library code over the native ws adapter too', async () => {
    const native = await bootstrapTestApp(
      {},
      {
        hostProviders: [NativeGateway],
        // Before `init()`, which is where a host has to make this choice: an adapter installed
        // afterwards serves requests and then throws on shutdown, far from the mistake.
        beforeInit: (app) => app.useWebSocketAdapter(new WsAdapter(app))
      }
    )

    try {
      await native.app.listen(0)

      const nativePort = (
        native.app.getHttpServer() as { address: () => { port: number } }
      ).address().port

      const socket = new WebSocket(`ws://127.0.0.1:${String(nativePort)}/native`)

      const frame = await new Promise<{ event: string; data: { error?: { code?: string } } }>(
        (resolve, reject) => {
          const timer = setTimeout(() => {
            reject(new Error('the native gateway sent no frame'))
          }, 5_000)

          socket.on('open', () => {
            socket.send(JSON.stringify({ event: 'whoami', data: {} }))
          })
          socket.on('close', (code: number) => {
            clearTimeout(timer)
            reject(new Error(`socket closed with ${String(code)}`))
          })
          socket.on('message', (raw: Buffer) => {
            clearTimeout(timer)
            resolve(
              JSON.parse(raw.toString()) as { event: string; data: { error?: { code?: string } } }
            )
          })
          socket.on('error', reject)
        }
      )

      socket.close()

      expect(frame.event).toBe('exception')
      expect(frame.data.error?.code).toBe('auth.token_invalid')
    } finally {
      await native.app.close()
    }
  })

  // ---------------------------------------------------------------------------
  // Refusals
  // ---------------------------------------------------------------------------

  // A ticket is spent by the first redemption. Without this, the query-string channel would be a
  // long-lived credential in a URL — exactly what the header-only rule existed to prevent, and
  // what makes an upgrade URL in an access log harmless once it has been used.
  it('refuses a ticket that has already been redeemed', async () => {
    const ticket = await mintTicket()

    const first = await whoami(port, { ticket })
    expect(first.ok).toBe(true)

    const replay = await whoami(port, { ticket })
    expect(replay.ok).toBe(false)
    expect(!replay.ok && refusalStatus(replay.error)).toBe('error')
  })

  // No credential at all, and a token this deployment never signed, answer the same way — the
  // same rule the HTTP guard follows, so a caller cannot learn from a socket what the REST
  // surface refuses to tell them.
  it.each([
    ['an upgrade with no credential', {}],
    ['a token this deployment did not sign', { token: 'not-a-jwt' }],
    ['a ticket that was never minted', { ticket: 'f'.repeat(64) }]
  ])('refuses %s', async (_why, options) => {
    const result = await whoami(port, options)

    expect(result.ok).toBe(false)
    expect(!result.ok && refusalStatus(result.error)).toBe('error')
  })

  // The gap, asserted so it cannot be fixed by accident or broken further in silence: a refused
  // client is told `Internal server error`, and the handler still never ran. The second half is
  // the security property and it holds; the first half is a usability defect in this library's
  // WebSocket story, and it is measured here rather than described.
  //
  // Why it matters beyond tidiness: a consumer building a reconnect policy cannot distinguish
  // "your credential is dead, stop retrying and send the user to sign in" from "the server
  // fell over, retry with backoff" — and the sensible default for an unknown error is to retry,
  // which turns every expired token into a reconnect loop against an endpoint that will refuse
  // it forever.
  it('delivers a generic error on a gateway with no filter registered', async () => {
    const result = await whoami(port, { token: 'not-a-jwt' })

    expect(result.ok).toBe(false)
    expect(!result.ok && result.error).toEqual(
      expect.objectContaining({ status: 'error', message: 'Internal server error' })
    )
  })

  // The same refusal on the gateway that registers `WsAuthExceptionFilter`: same application,
  // same guard, same credential, and now the client can read `error.code`. The pair is the
  // filter's entire claim, and running it as a pair is what shows the filter is what changed —
  // a single assertion on the filtered gateway would also pass if the guard had started
  // answering differently.
  it('delivers the library code once the filter is registered', async () => {
    const result = await whoami(port, { token: 'not-a-jwt', namespace: '/filtered' })

    expect(result.ok).toBe(false)
    expect(!result.ok && result.error).toEqual({
      status: 'error',
      error: expect.objectContaining({ code: 'auth.token_invalid' })
    })
  })

  // The filter must not change who gets in — it is an answer-shaping layer, not an
  // authorisation one. A valid ticket is admitted on the filtered gateway exactly as it is on
  // the plain one, with the same identity attached.
  it('admits a valid credential on the filtered gateway too', async () => {
    const result = await whoami(port, { ticket: await mintTicket(), namespace: '/filtered' })

    expect(result.ok).toBe(true)
    expect(result.ok && result.user).toEqual(
      expect.objectContaining({ sub: userId, tenantId: 'tenant-1' })
    )
  })

  // A token whose payload carries no `jti`. The guard needs one to build the revocation key, so
  // it refuses rather than proceeding with a key it would have to invent — a socket authorised
  // by a token that cannot be revoked is a session with no off switch.
  //
  // Signed here because no flow in this library mints such a token: what is synthesised is the
  // claim set, not the pipeline. It arrives over a real handshake and is verified by the same
  // key the deployment signs with.
  it('refuses a token carrying no jti', async () => {
    const jtiless = app
      .get(JwtService)
      .sign(
        { sub: userId, tenantId: 'tenant-1', role: 'MEMBER', type: 'dashboard', epoch: 0 },
        { secret: JWT_SECRET, expiresIn: '5m' }
      )

    const result = await whoami(port, { token: jtiless })

    expect(result.ok).toBe(false)
  })

  // A ticket that redeems to a snapshot with no tenant. `wst:` is ONE keyspace shared with
  // rust-auth over one Redis, and `WsTicketSnapshot.tenantId` is optional precisely because a
  // platform ticket omits it — so this record is not a hypothetical, it is the shape the sibling
  // implementation is expected to write the moment either backend mints one.
  //
  // Seeded directly, because that is where it would come from: another writer on the shared
  // keyspace. Everything else is real — the guard redeems it through the same service, over the
  // same handshake. It must refuse: this guard authorises a socket as a DASHBOARD identity, and
  // a tenant-less authorisation is worse than a refusal, because the socket opens and every
  // downstream tenant check silently compares against `undefined`.
  it('refuses a ticket that redeems to a snapshot with no tenant', async () => {
    const ticket = 'a'.repeat(64)

    await boot.redis.set(
      `auth:wst:${sha256(ticket)}`,
      JSON.stringify({
        sub: 'platform-admin-1',
        role: 'SUPER_ADMIN',
        status: 'active',
        mfaEnabled: false,
        mfaVerified: true
      })
    )

    const result = await whoami(port, { ticket })

    expect(result.ok).toBe(false)
  })

  // Revocation reaches the socket. A logout kills the HTTP session, and a WebSocket opened with
  // the same token must not outlive it — this is the branch where the guard consults the same two
  // revocation channels `JwtAuthGuard` does, and the one that would make a "logged out" user's
  // stream keep flowing.
  it('refuses a token that was revoked by a logout', async () => {
    const registered = await request(app.getHttpServer()).post('/register').send({
      email: 'ws-logout@example.com',
      password: PASSWORD,
      name: 'Logging Out',
      tenantId: 'tenant-1'
    })

    const token = registered.body.accessToken as string
    const refresh = registered.body.refreshToken as string

    const before = await whoami(port, { token })
    expect(before.ok).toBe(true)

    await request(app.getHttpServer())
      .post('/logout')
      .set('Authorization', `Bearer ${token}`)
      .send({ refreshToken: refresh })

    const after = await whoami(port, { token })
    expect(after.ok).toBe(false)
    expect(!after.ok && refusalStatus(after.error)).toBe('error')
  })

  // The pair for the case above, on the OTHER revocation channel: a password reset bumps the
  // user's epoch, and every token stamped below it dies — including one already presented to a
  // socket. Asserted with `refreshToken` untouched, so what kills it is the epoch and not the
  // logout above.
  it('refuses a token whose epoch was bumped', async () => {
    expect(refreshToken).toEqual(expect.any(String))

    const before = await whoami(port, { token: accessToken })
    expect(before.ok).toBe(true)

    await boot.redis.set(`auth:${tokenEpochFor(userId, 'tenant-1')}`, '99')

    const after = await whoami(port, { token: accessToken })
    expect(after.ok).toBe(false)
    expect(!after.ok && refusalStatus(after.error)).toBe('error')
  })
})
