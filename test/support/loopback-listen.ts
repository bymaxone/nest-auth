/**
 * The loopback default for the end-to-end suite's listeners, and its installer.
 *
 * Layer: e2e support. `test/jest.loopback-listen.ts` installs the patch for every e2e file; this
 * module only defines it, so a suite can import it without installing anything.
 *
 * `server.listen(port)` with no host binds the unspecified IPv6 address `::`, and a client dials
 * `127.0.0.1:<port>`. Under BSD bind rules, which macOS follows, another process can bind
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
 * supertest is not patched: from 7.3 it binds a server it starts itself to `127.0.0.1` and closes
 * that listener after the last request, which is why the devDependency range starts there. What
 * this file covers is every other `listen(port)`, such as Nest's `app.listen(0)`.
 */
import { Server } from 'node:net'

/** The address a port-only `listen` binds under this suite. */
export const LOOPBACK_HOST = '127.0.0.1'

/** Where the unpatched `Server.prototype.listen` is kept once the patch is installed. */
export const ORIGINAL_LISTEN = Symbol.for('bymax-one.nest-auth.e2e.loopback-listen.original')

/** `Server.prototype.listen` as this file calls it. */
type Listen = (this: Server, ...args: unknown[]) => Server

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
