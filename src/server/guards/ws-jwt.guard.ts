import { Inject, Injectable } from '@nestjs/common'
import type { CanActivate, ExecutionContext, OnModuleInit } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import type { WsTicketSnapshot } from '../interfaces/ws-ticket.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { WsTicketService } from '../services/ws-ticket.service'
import { readStampedEpoch } from '../utils'
import { verifyWithRotation } from '../utils/verify-with-rotation'
import { assertTokenType, assertValidSub } from './utils/assert-token-type'

/** Minimal shape of a WebSocket client as seen during the handshake. */
type WsClient = {
  handshake: {
    headers: Record<string, string | undefined>
    /** Parsed upgrade query string, when the transport exposes one (Socket.IO does). */
    query?: Record<string, string | string[] | undefined>
    /** Raw upgrade URL, the fallback for transports that do not parse the query. */
    url?: string
  }
  data: Record<string, unknown>
}

/**
 * WebSocket authentication guard — the WS twin of {@link JwtAuthGuard}.
 *
 * Validates HS256-signed dashboard JWTs carried in the `Authorization` header
 * of the Socket.IO/ws handshake. Token type isolation (`type: 'dashboard'`) and
 * Redis revocation checks mirror the HTTP guard exactly.
 *
 * @remarks
 * **Two credential channels, and only two** — the handshake
 * `Authorization: Bearer <token>` header, or a single-use ticket in the upgrade
 * query string.
 *
 * An access **token** in the query string stays unsupported, and for the original
 * reason: it is trivially captured in access logs, browser history and proxy
 * caches, which makes it equivalent to sending the credential in plaintext. But
 * the browser `WebSocket` API cannot set handshake headers, so header-only left
 * browser clients with no supported path at all — and a library that offers none
 * gets the query-string token anyway, written by the consumer.
 *
 * A ticket is the answer to that: minted by `POST {prefix}/ws-ticket` from a
 * session that is already authenticated, in good standing and MFA-satisfied;
 * opaque; ~30 seconds; and consumed by the first redemption, so a captured
 * upgrade URL is worthless by the time it reaches a log. rust-auth authenticates
 * its upgrades the same way.
 *
 * **Algorithm pinning** — `algorithms: [this.options.jwt.algorithm]` is forwarded
 * to `JwtService.verify()` to prevent algorithm-confusion attacks (CVE-2015-9235).
 * An attacker cannot substitute `alg: none` or swap to an asymmetric algorithm.
 *
 * **Soft peer-dependency on `@nestjs/websockets`** — this guard does not import
 * `@nestjs/websockets` at module load time (which would create a hard dependency
 * breaking consumers that never use WebSockets). Instead, a dynamic `import()`
 * inside `onModuleInit` throws a descriptive error if the package is absent,
 * failing fast at application startup.
 *
 * **No `@Public()` support** — the `Reflector`-based public-route bypass used by
 * {@link JwtAuthGuard} has no meaningful equivalent in WebSocket contexts where
 * every gateway handler is implicitly protected. Unauthenticated WS namespaces
 * should simply not apply this guard.
 *
 * @example
 * ```typescript
 * @UseGuards(WsJwtGuard)
 * @SubscribeMessage('message')
 * handleMessage(@ConnectedSocket() client: Socket) { ... }
 * ```
 *
 * @layer Guard
 */
@Injectable()
export class WsJwtGuard implements CanActivate, OnModuleInit {
  constructor(
    private readonly jwtService: JwtService,
    private readonly redis: AuthRedisService,
    private readonly wsTickets: WsTicketService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  /**
   * Verifies that `@nestjs/websockets` is installed and throws a descriptive
   * error at application startup if the package is absent.
   */
  async onModuleInit(): Promise<void> {
    try {
      await import('@nestjs/websockets')
    } catch {
      throw new Error('WsJwtGuard requires @nestjs/websockets to be installed')
    }
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const client = context.switchToWs().getClient<WsClient>()

    // The ticket path first: a client that presents one has no header to fall back to, and a
    // client that presents both is authenticated by the stronger, single-use credential.
    const ticket = readUpgradeTicket(client)
    if (ticket !== undefined) {
      const snapshot = await this.wsTickets.redeem(ticket)
      assertDashboardSnapshot(snapshot)
      // The socket is authorized as the snapshot the ticket was minted from — a frozen copy of
      // what the access token proved at mint time. It is deliberately not a token: it carries
      // no `jti` to revoke and no signature to re-verify, and it cannot be presented to the
      // REST surface. Its authority ends when the socket closes.
      client.data.user = snapshot
      return true
    }

    const authHeader = client.handshake.headers['authorization']
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined
    if (!token) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // Algorithm is pinned from options — rejects alg:none and algorithm-confusion attacks.
    let payload: DashboardJwtPayload
    try {
      payload = verifyWithRotation<DashboardJwtPayload>(this.jwtService, this.options, token)
    } catch {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // jti must be a string — a missing or numeric jti cannot be used as a Redis key.
    if (typeof payload.jti !== 'string') {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    assertTokenType(payload, 'dashboard')

    // rv:{jti} is written on logout with the token's remaining TTL as expiry. A hit is
    // surfaced as TOKEN_INVALID, exactly as `JwtAuthGuard` does it: TOKEN_REVOKED would let a
    // caller distinguish "this token was valid until someone logged it out" from "this token
    // was never valid", and the upgrade handshake is a cheaper place to ask that question than
    // the REST surface, not a more private one.
    const revoked = await this.redis.get(`rv:${payload.jti}`)
    if (revoked !== null) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // Require a well-formed `sub` before it keys the epoch lookup (`ep:{sub}`) —
    // mirrors JwtAuthGuard; a missing/empty/oversized sub would otherwise build a
    // malformed Redis key.
    assertValidSub(payload.sub)

    // Bulk revocation: reject any access token stamped below the user's current token epoch
    // (advanced on password reset). Mirrors JwtAuthGuard so a dashboard revocation event kills
    // WebSocket access tokens too, not just HTTP ones. Surfaced as TOKEN_INVALID (not
    // TOKEN_REVOKED) so the response is indistinguishable from a malformed/expired token and
    // leaks no oracle for whether a given user has been bumped.
    const epoch = await this.redis.getUserTokenEpoch(payload.sub)
    if (readStampedEpoch(payload) < epoch) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    client.data.user = payload
    return true
  }
}

/**
 * Refuses a redeemed snapshot that is not a dashboard one.
 *
 * A redemption proves the ticket existed and had not been spent. It does not prove which
 * identity plane minted it: `wst:` is one keyspace, shared with rust-auth over one Redis, and
 * {@link WsTicketSnapshot.tenantId} is optional precisely because a platform ticket omits it.
 * This guard authorizes the socket as a dashboard identity, so redeeming whatever the keyspace
 * happens to hold would let a platform-plane credential open a dashboard connection the moment
 * either backend starts minting one — the shape is already reserved for it.
 *
 * Requiring the tenant costs nothing to the legitimate path: `AuthUser.tenantId` is not
 * optional, so every ticket this library mints carries one. A snapshot without it was written
 * by something else, and a socket is not the place to find out what.
 *
 * This also refuses a record that decoded but lost fields — an authorization whose scope is
 * `undefined` is worse than a refusal, because the socket opens and every downstream tenant
 * check silently compares against nothing.
 *
 * @param snapshot - The snapshot the ticket redeemed to.
 * @throws AuthException `TOKEN_INVALID` when the snapshot is not a dashboard identity, matching
 *   the refusal a bad ticket already produces so the two stay indistinguishable.
 */
function assertDashboardSnapshot(snapshot: WsTicketSnapshot): void {
  if (typeof snapshot.sub !== 'string' || snapshot.sub === '') {
    throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
  }
  if (typeof snapshot.tenantId !== 'string' || snapshot.tenantId === '') {
    throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
  }
}

/**
 * Reads the single-use `ticket` parameter from the upgrade request.
 *
 * This is the only place the library reads a credential from a query string, and what it reads
 * is a one-shot ~30-second opaque ticket, never a JWT. Two shapes are accepted because
 * transports differ: Socket.IO parses the query for you, a raw `ws` server hands over the URL.
 *
 * @param client - The connecting client as seen during the handshake.
 * @returns The ticket, or `undefined` when the upgrade carries none.
 */
function readUpgradeTicket(client: WsClient): string | undefined {
  const fromQuery = client.handshake.query?.['ticket']
  // A repeated parameter arrives as an array. Taking the first would let a caller smuggle a
  // second value past whatever inspected the first, so the whole request is treated as
  // ticketless and falls through to the header path.
  if (typeof fromQuery === 'string' && fromQuery !== '') return fromQuery
  if (fromQuery !== undefined) return undefined

  const url = client.handshake.url
  if (typeof url !== 'string' || url === '') return undefined
  // `URL` needs an absolute input; the base is a placeholder and never used for anything but
  // parsing the relative upgrade path.
  //
  // A base does not make every input parseable — `http://[` and friends still throw, and this
  // string comes off the wire from whatever opened the socket. Throwing here would turn "this
  // upgrade carried no usable ticket", an ordinary authentication outcome, into an exception
  // escaping the guard: unhandled, and reachable by anyone who can attempt a connection. An
  // unparseable URL carries no ticket, which is the same answer as a URL carrying none.
  let params: URLSearchParams
  try {
    params = new URL(url, 'http://ws.invalid').searchParams
  } catch {
    return undefined
  }
  const all = params.getAll('ticket')
  return all.length === 1 && all[0] !== '' ? all[0] : undefined
}
