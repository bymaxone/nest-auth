/**
 * The loopback default for the end-to-end suite's listeners, and its installers.
 *
 * Layer: e2e support. `test/jest.loopback-listen.ts` installs both patches for every e2e file; this
 * module only defines them, so a suite can import it without installing anything.
 *
 * `server.listen(port)` with no host binds the unspecified IPv6 address `::`, and supertest then
 * dials `127.0.0.1:<port>`. Under BSD bind rules, which macOS follows, another process can bind
 * `127.0.0.1` on that same port while `::` holds it, and a connection to `127.0.0.1:<port>` then
 * reaches that more specific listener instead: a request meant for the application under test is
 * answered by whatever else runs on the machine. Binding the suite's listeners to `127.0.0.1`
 * makes each one the most specific listener on its port, and no other `127.0.0.1` listener can
 * take a port one of them holds.
 *
 * Only the `(port[, backlog][, callback])` form gains a host. A path, a handle, an options object
 * and a call that names a host keep their meaning. Node's `net` module is one instance per worker
 * while Jest loads this file once per test file, so the patch is installed once, behind a
 * registered symbol, and the original method stays reachable for a control.
 *
 * A listen that names a host binds after a lookup, so the address is not known when `listen`
 * returns. supertest reads it at once when it starts a server itself, so its `Test` is taught to
 * wait for `listening` and to build its URL from the bound port before the request is sent. The
 * listener it starts stays open for the server's owner to close, as `app.close()` does, instead
 * of one listener per request: a suite that sends thousands of requests would otherwise spend a
 * loopback port per request on the listener and another on the client, and run the range dry.
 */
import { Server } from 'node:net'
import { Server as TlsServer } from 'node:tls'

import { Test } from 'supertest'

/** The address a port-only `listen` binds under this suite. */
export const LOOPBACK_HOST = '127.0.0.1'

/** Where the unpatched `Server.prototype.listen` is kept once the patch is installed. */
export const ORIGINAL_LISTEN = Symbol.for('bymax-one.nest-auth.e2e.loopback-listen.original')

/** Marks a supertest `Test` prototype this file has already taught to wait for its listener. */
const SUPERTEST_PATCHED = Symbol.for('bymax-one.nest-auth.e2e.loopback-listen.supertest')

/** The listener a `Test` started itself, and where its request goes once it is bound. */
const PENDING = Symbol('pending listener')

/** The start of a server's listener, while it is under way or listening. */
const STARTING = Symbol('starting listener')

/** `Server.prototype.listen` as this file calls it. */
type Listen = (this: Server, ...args: unknown[]) => Server

/** The listener a `Test` is waiting on. */
interface PendingListener {
  readonly server: Server
  readonly protocol: 'http' | 'https'
  readonly path: string
  readonly ready: Promise<void>
}

/** The parts of supertest's `Test` this file replaces or reads. */
interface PatchableTest {
  url: string
  [PENDING]?: PendingListener
  serverAddress(app: Server, path: string): string
  end(callback?: (error: unknown, response?: unknown) => void): unknown
}

/**
 * The arguments a `listen` call should be made with: a host inserted after the port when the call
 * names a port and no host, and the arguments unchanged otherwise.
 *
 * @param args - The arguments the caller passed.
 * @returns The arguments to call the original method with.
 */
export function withLoopbackHost(args: readonly unknown[]): unknown[] {
  const [port, second, ...rest] = args
  if (typeof port !== 'number' || typeof second === 'string') return [...args]
  return args.length === 1 ? [port, LOOPBACK_HOST] : [port, LOOPBACK_HOST, second, ...rest]
}

/**
 * Installs the loopback default on `Server.prototype.listen`, once per process.
 *
 * @param prototype - The prototype to patch; the real `Server.prototype` outside of tests of this
 *   file.
 */
export function installLoopbackListen(prototype: object = Server.prototype): void {
  if (Object.hasOwn(prototype, ORIGINAL_LISTEN)) return
  const original = Reflect.get(prototype, 'listen') as Listen
  Object.defineProperty(prototype, ORIGINAL_LISTEN, { value: original })
  Object.defineProperty(prototype, 'listen', {
    configurable: true,
    writable: true,
    value: function listen(this: Server, ...args: unknown[]): Server {
      return original.apply(this, withLoopbackHost(args))
    }
  })
}

/**
 * Starts `server` listening on a port of its own, or joins the start already under way, so the
 * requests a suite sends together share one listener.
 *
 * @param server - The server to start.
 * @returns A promise that settles once the server is listening.
 */
function listenOnce(server: Server): Promise<void> {
  const holder = server as Server & { [STARTING]?: Promise<void> }
  const started = holder[STARTING]
  if (started !== undefined) return started
  const starting = new Promise<void>((resolve, reject) => {
    server.once('listening', () => resolve())
    server.once('error', reject)
  })
  holder[STARTING] = starting
  server.once('close', () => {
    delete holder[STARTING]
  })
  server.listen(0)
  return starting
}

/** The methods of supertest's `Test` the patch replaces; `serverAddress` is not published API. */
export const SUPERTEST_METHODS = ['serverAddress', 'end'] as const

/**
 * Teaches supertest's `Test` to wait for a listener it starts itself, once per module registry.
 *
 * `serverAddress` is a supertest internal, not published API, and `end` is replaced around it, so
 * a release that renames or reshapes either would leave the suite unpatched and the requests
 * misrouted again; the install refuses instead.
 *
 * @param prototype - The `Test` prototype to patch.
 * @throws Error when either method is missing or is not a function.
 */
export function installSupertestWait(prototype: object = Test.prototype): void {
  if (Object.hasOwn(prototype, SUPERTEST_PATCHED)) return
  for (const name of SUPERTEST_METHODS) {
    if (typeof Reflect.get(prototype, name) !== 'function') {
      throw new Error(
        `supertest's Test has no ${name}() to patch, so the e2e requests could reach another server; update test/support/loopback-listen.ts for this supertest release`
      )
    }
  }
  const target = prototype as PatchableTest
  const serverAddress = target.serverAddress
  const end = target.end
  Object.defineProperty(prototype, SUPERTEST_PATCHED, { value: true })
  target.serverAddress = function (this: PatchableTest, app: Server, path: string): string {
    if (app.address() !== null) return serverAddress.call(this, app, path)
    const protocol = app instanceof TlsServer ? 'https' : 'http'
    this[PENDING] = { server: app, protocol, path, ready: listenOnce(app) }
    return `${protocol}://${LOOPBACK_HOST}${path}`
  }
  target.end = function (this: PatchableTest, callback) {
    const pending = this[PENDING]
    if (pending === undefined) return end.call(this, callback)
    delete this[PENDING]
    pending.ready.then(
      () => {
        const bound = pending.server.address()
        const port = typeof bound === 'object' && bound !== null ? bound.port : 0
        this.url = `${pending.protocol}://${LOOPBACK_HOST}:${String(port)}${pending.path}`
        end.call(this, callback)
      },
      (error: unknown) => callback?.(error)
    )
    return this
  }
}
