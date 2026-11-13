# WebSocket upgrades

How a browser client authenticates a WebSocket upgrade with `WsJwtGuard`, and how a gateway resolves the tenant of a socket. Part of the [`@bymax-one/nest-auth` README](../README.md).

The browser `WebSocket` API cannot set handshake headers, so a browser client cannot send
`Authorization: Bearer <token>` at the upgrade. The usual workaround puts the access token in the
query string, where it lands in access logs, browser history and proxy caches — a long-lived
credential in plaintext. `WsJwtGuard` refuses it.

The supported path is a single-use ticket:

```typescript
// 1. Mint from an authenticated session (POST, cookies or bearer as usual).
const { ticket, expiresIn } = await fetch('/auth/ws-ticket', {
  method: 'POST',
  credentials: 'include'
}).then((r) => r.json())

// 2. Open the socket with it. The ticket is consumed by the first redemption.
const socket = new WebSocket(`wss://api.example.com/socket?ticket=${ticket}`)
```

The ticket is opaque, 32 bytes of CSPRNG output, and lives at most 30 seconds, ending a second before the access
token that minted it does at the latest: `expiresIn` in the response is that capped lifetime in seconds, so a client
schedules its upgrade by it, and a token with no life left mints nothing. Only `sha256(ticket)` is
ever a Redis key, and the stored value is a verified-identity **snapshot** — no signature, no
expiry of its own — so a redeemed ticket authorizes a socket and cannot be turned back into a
session. It carries the `jti` and `epoch` of the access token that minted it, the two keys the
revocation channels are read by, and redemption is refused when that token has been blacklisted by
a logout or stamped below the user's current epoch (sign-out-everywhere, password change, MFA
reset): a ticket does not outlive the session that asked for it. A logout blacklists only
the access token it was given and does not move the epoch, so a ticket minted from an access token
that a refresh had already replaced is not refused after that logout, as a bearer token of that
kind is not; it is refused only after a later epoch bump (a password reset or change, an MFA
enable, disable or reset, or revoking another session or all of them). Minting requires an authenticated session in good standing that has already
satisfied MFA, so a ticket never carries more authority than the request that asked for it.

Non-browser clients that can set headers keep using `Authorization: Bearer` at the handshake;
both channels are accepted, and a ticket wins when both are present. `WsJwtGuard` checks
signature, token type and revocation on the Bearer path but not account status or MFA; where the
socket must also refuse a blocked account or an unfinished second factor, authorize with
`AuthTokenVerifierService.verifyAccessToken` (see
[Authorising a long-lived transport](./server-services.md#authorising-a-long-lived-transport--authtokenverifierservice)).

**Tenant binding on the socket.** With `enforceTenantBinding` on, `WsJwtGuard` re-resolves the
tenant of the upgrade and refuses (`auth.token_invalid`, the same code HTTP answers) a ticket or
token minted for another tenant, as `JwtAuthGuard` does on a mismatch. An upgrade has no Express request,
so your `tenantIdResolver` is handed a request-like object with **only** these fields:

| Field      | Value                                                                                                                               |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `headers`  | The handshake headers, names lowercased                                                                                             |
| `url`      | The upgrade URL, `''` when the transport exposes none                                                                               |
| `hostname` | The `Host` header with the port cut (a bracketed IPv6 literal keeps its brackets), `''` if absent; see below for `X-Forwarded-Host` |

There is **no** `cookies` (the `Cookie` header is present in `headers`, but nothing parses it the way
`cookie-parser` does on HTTP) and no `ip` or `ips`. `hostname` is the `Host` as received unless you
set `isTrustedProxy` (below). The resolver's parameter is typed
`TenantResolverRequest` (exported), so a resolver that reads one of the absent fields does not
compile. If a resolver still throws at runtime, or returns anything other than the credential's
tenant, the connection is **refused**, never bound to the wrong tenant. Resolve from `headers` or
`hostname` so one resolver
serves both HTTP and sockets.

**Behind a proxy that rewrites `Host`.** nginx's default `proxy_set_header Host $proxy_host` presents
the upstream name in `Host` and the public one in `X-Forwarded-Host`. Over HTTP, Express resolves
`req.hostname` from the forwarded header when its `trust proxy` setting trusts the peer; a socket has
no Express request, so without more the resolver sees the upstream host and the binding refuses every
stream. Declare the same trust decision once with `isTrustedProxy`, a function that takes the TCP peer
address and answers a boolean:

```typescript
// The module factory runs before the app exists, so it reads the policy per connection.
// Until main.ts fills it in, no peer is trusted.
export const proxyPolicy = { trusts: (_peer: string): boolean => false }

BymaxAuthModule.registerAsync({
  useFactory: () => ({
    // ...
    enforceTenantBinding: true,
    tenantIdResolver: (req) => req.hostname.split('.')[0] ?? '',
    isTrustedProxy: (peer) => proxyPolicy.trusts(peer)
  })
})

// main.ts
import { proxyPolicy } from './app.module' // wherever the module is configured

const app = await NestFactory.create<NestExpressApplication>(AppModule)
const expressApp = app.getHttpAdapter().getInstance()
expressApp.set('trust proxy', 'loopback, 10.0.0.0/8')
proxyPolicy.trusts = (peer) => expressApp.get('trust proxy fn')(peer, 0)
```

Read the compiled policy from the **Express instance**, `app.getHttpAdapter().getInstance()`. On a
Nest application, `app.get()` resolves a provider from the container and does not read an Express
setting, so `app.get('trust proxy fn')` looks for a provider of that name and fails.

The predicate receives the peer **exactly as the transport reported it**, so an IPv4-mapped form such
as `::ffff:10.0.0.1` reaches it unchanged; Express's compiled setting understands that form, which
is why the recipe delegates to it. When it answers `true`, the first element of a single
`X-Forwarded-Host` is used, with the port cut like `Host`. Unset, which is the default,
`X-Forwarded-Host` is never read. Every other case falls back to `Host`: no peer address, a header handed
over as separate values, an empty first element, a predicate that throws or answers anything but
`true`. (Node joins a header repeated on the wire into one comma-separated string, and its first
element is used, as in Express.) Those cases can therefore only make the binding stricter, never
admit a tenant the client chose. The
peer address comes from `WsJwtGuard` itself (Socket.IO's `handshake.address`); a caller of
`AuthTokenVerifierService.verifyAccessToken` passes it as `request.remoteAddress`.

Both channels live on the client's `handshake`, and only a **Socket.IO** client has one — with
`@nestjs/platform-ws` the gateway receives the raw `ws` socket, which carries no `handshake` and
does not retain the upgrade request. `WsJwtGuard` refuses such a connection with
`auth.token_invalid` instead of crashing on it, but it cannot authenticate anyone on that
adapter. And because `AuthException` extends `HttpException`, which Nest's WebSocket layer does
not recognise, a gateway that applies the guard also needs `WsAuthExceptionFilter` for the
refusal to reach the client as anything but `Internal server error` — see
[On a WebSocket, the envelope needs its own filter](#on-a-websocket-the-envelope-needs-its-own-filter).

## On a WebSocket, the envelope needs its own filter

`WsJwtGuard` throws the same `AuthException` every HTTP guard throws — and `AuthException`
extends `HttpException`, which Nest's **WebSocket** exception layer does not recognise. It
understands `WsException` and nothing else, so without a filter a refused socket client receives:

```json
{ "status": "error", "message": "Internal server error" }
```

The refusal itself is correct: the handler never runs. What is lost is everything the client
could act on. A reconnect policy cannot tell a dead credential from a crashed handler, and the
sensible default for an unknown error is to retry — so an expired token becomes a reconnect loop
against an endpoint that will refuse it forever.

> **Socket.IO only.** `WsJwtGuard` reads both credential channels from the client's
> `handshake`, and only a Socket.IO client has one: with `@nestjs/platform-ws` the gateway
> receives the raw `ws` socket, which carries no `handshake` — and `ws` does not retain the
> upgrade request either, so there is nothing to read. Such a connection is **refused** with
> `auth.token_invalid` rather than crashing the socket, and the filter below delivers that
> refusal, but the guard cannot authenticate anyone on that adapter. Supporting it needs the
> gateway to stash the upgrade request in `handleConnection`, which is a contract this library
> does not have today.

Register the filter on any gateway that applies the guard:

```typescript
@UseFilters(new WsAuthExceptionFilter())
@UseGuards(WsJwtGuard)
@WebSocketGateway()
export class FeedGateway {}
```

```json
{ "status": "error", "error": { "code": "auth.token_invalid", "message": "...", "details": null } }
```

`status: 'error'` is kept — it is the field Nest itself sets and the one socket.io clients
already branch on — and the envelope is added beside it, so a client handling both shapes needs
no second listener. The `AuthException` travels whole, so a `details` payload survives.

The filter is scoped to `AuthException` on purpose. An argument-less `@Catch()` would claim
every exception the gateway raises, so a `WsException` an unrelated handler throws — a domain
error with its own contract — would be rewritten as an `auth.*` code, and following this README
would silently break errors a consumer already ships. Everything that is not this library's
refusal keeps travelling through Nest's own exception layer, untouched.

Both transports are answered. A Socket.IO client is dispatched to with `emit`; a native `ws`
client is written to with `send`, in the `{event, data}` envelope `@nestjs/platform-ws` uses for
every other message — emitting on one of those succeeds, dispatches a local event and sends the
peer nothing, which is the failure this ordering exists to prevent. Both paths are driven over a
real handshake in `test/e2e/ws-guard.e2e-spec.ts`.
