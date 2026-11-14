/**
 * End-to-end proof that the suite's listeners are bound to the IPv4 loopback address.
 *
 * Layer: e2e.
 * Goal: prove that `test/jest.loopback-listen.ts`, loaded by the e2e configuration, binds a
 *   port-only `listen` to `127.0.0.1` and leaves every other `listen` signature as Node defines it;
 *   that a server bound this way cannot share its port with another `127.0.0.1` listener; and that
 *   a supertest request against a server that is not listening yet binds it there and reaches it.
 *   The unpatched method, kept by the setup file, is the control: a port-only call through it binds
 *   a wildcard address, the one another process's `127.0.0.1` listener could share under BSD bind
 *   rules.
 * Mocks: none. Plain `node:http` servers on ephemeral ports; no application is booted.
 */
import { createServer } from 'node:http'
import type { Server } from 'node:http'
import { Server as NetServer } from 'node:net'
import type { AddressInfo } from 'node:net'

import request from 'supertest'

import {
  installLoopbackListen,
  installSupertestWait,
  LOOPBACK_HOST,
  ORIGINAL_LISTEN,
  SUPERTEST_METHODS,
  withLoopbackHost
} from '../support/loopback-listen'

/** Waits until `server` is listening. */
function listening(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('listening', () => resolve())
    server.once('error', reject)
  })
}

/** Closes `server` if it is listening. */
function close(server: Server): Promise<void> {
  return new Promise((resolve) => {
    if (!server.listening) {
      resolve()
      return
    }
    server.close(() => resolve())
  })
}

/** The bound address of a listening TCP server. */
function addressOf(server: Server): AddressInfo {
  return server.address() as AddressInfo
}

describe('Loopback listen (e2e)', () => {
  const servers: Server[] = []

  /** A server that answers every request with the address it was reached on. */
  function server(): Server {
    const created = createServer((incoming, response) => {
      response.end(String(incoming.socket.localAddress))
    })
    servers.push(created)
    return created
  }

  afterEach(async () => {
    await Promise.all(servers.splice(0).map(close))
  })

  /**
   * Signature scenario.
   *
   * A host is inserted after the port only for the `(port[, backlog][, callback])` form; a call
   * with no port, a host, a path, an options object or a handle passes through unchanged.
   */
  it('adds the loopback host to a port-only call and to nothing else', () => {
    const callback = (): void => undefined
    const handle = { fd: 3 }

    expect(withLoopbackHost([0])).toEqual([0, LOOPBACK_HOST])
    expect(withLoopbackHost([0, callback])).toEqual([0, LOOPBACK_HOST, callback])
    expect(withLoopbackHost([0, 511, callback])).toEqual([0, LOOPBACK_HOST, 511, callback])
    for (const args of [
      [],
      [callback],
      [0, 'localhost'],
      [0, '::', callback],
      ['/tmp/bymax-one.sock'],
      [{ port: 0 }],
      [{ port: 0, host: '::' }],
      [handle]
    ]) {
      expect(withLoopbackHost(args)).toEqual(args)
    }
  })

  /**
   * Binding scenario.
   *
   * The e2e configuration has installed the patch before this file loads. A port-only `listen`
   * binds `127.0.0.1`; the same call through the unpatched method, the control, binds a wildcard
   * address; an options object without a host keeps Node's wildcard default, and an explicit host
   * is honoured.
   */
  it('binds a port-only listen to the loopback address and leaves the rest alone', async () => {
    expect(Object.hasOwn(NetServer.prototype, ORIGINAL_LISTEN)).toBe(true)

    const patched = server()
    patched.listen(0)
    await listening(patched)

    const control = server()
    ;(Reflect.get(NetServer.prototype, ORIGINAL_LISTEN) as (port: number) => Server).call(
      control,
      0
    )
    await listening(control)

    const options = server()
    options.listen({ port: 0 })
    await listening(options)

    const explicit = server()
    explicit.listen(0, '::')
    await listening(explicit)

    expect(addressOf(patched).address).toBe(LOOPBACK_HOST)
    expect(['::', '0.0.0.0']).toContain(addressOf(control).address)
    expect(['::', '0.0.0.0']).toContain(addressOf(options).address)
    expect(addressOf(explicit).address).toBe('::')
  })

  /**
   * Exclusive-port scenario.
   *
   * Once a suite's listener holds a loopback port, another listener cannot bind `127.0.0.1` on
   * it, so nothing else on the machine can answer a request dialled there.
   */
  it('refuses a second loopback listener on a port the suite holds', async () => {
    const held = server()
    held.listen(0)
    await listening(held)

    const intruder = server()
    const refused = new Promise<string | undefined>((resolve) => {
      intruder.once('error', (error: Error & { code?: string }) => resolve(error.code))
      intruder.once('listening', () => resolve(undefined))
    })
    intruder.listen(addressOf(held).port, LOOPBACK_HOST)

    expect(await refused).toBe('EADDRINUSE')
  })

  /**
   * supertest scenario.
   *
   * A request against a server that is not listening binds it to `127.0.0.1` and reaches it
   * there. Requests sent together, and the ones after, share that listener, which stays open for
   * the server's owner to close.
   */
  it('lets supertest start one loopback listener and reach it', async () => {
    const target = server()

    const together = await Promise.all([request(target).get('/a'), request(target).get('/b')])
    const port = addressOf(target).port
    const after = await request(target).get('/c')

    expect(together.map((response) => response.text)).toEqual([LOOPBACK_HOST, LOOPBACK_HOST])
    expect(after.text).toBe(LOOPBACK_HOST)
    expect(target.listening).toBe(true)
    expect(addressOf(target)).toEqual({ address: LOOPBACK_HOST, family: 'IPv4', port })
  })

  /**
   * Coupling scenario.
   *
   * The installed supertest still has both methods the patch replaces, and an install on a
   * prototype that lacks either one refuses rather than leaving the suite unpatched.
   */
  it('finds the supertest methods it patches and refuses without them', () => {
    for (const name of SUPERTEST_METHODS) {
      expect(typeof Reflect.get(request.Test.prototype, name)).toBe('function')
      const missing: Record<string, unknown> = { serverAddress() {}, end() {} }
      delete missing[name]
      expect(() => installSupertestWait(missing)).toThrow(`supertest's Test has no ${name}()`)
    }
  })

  /**
   * Single-install scenario.
   *
   * Installing either patch again changes nothing, so the per-file setup load never wraps the
   * method twice.
   */
  it('installs each patch once', () => {
    const prototype = request.Test.prototype
    const listen: unknown = Reflect.get(NetServer.prototype, 'listen')
    const serverAddress: unknown = Reflect.get(prototype, 'serverAddress')
    const end: unknown = Reflect.get(prototype, 'end')

    installLoopbackListen()
    installSupertestWait()

    expect(Reflect.get(NetServer.prototype, 'listen')).toBe(listen)
    expect(Reflect.get(prototype, 'serverAddress')).toBe(serverAddress)
    expect(Reflect.get(prototype, 'end')).toBe(end)
  })
})
