/**
 * @fileoverview Proves the library refuses a compressed request body, and answers a corrupt one as
 * a client error.
 *
 * The host's body parser decides whether a `Content-Encoding` is decompressed: Express's default
 * inflates `gzip`, `deflate` and `br`. The contract is the same on every host, so the library
 * refuses any encoding other than `identity` itself, before a handler runs, with a 415 in the
 * `auth.validation` envelope. A body that claims to be compressed and is not never reaches the
 * handler either: the parser fails it, and the filter answers 400.
 *
 * Requests go over real HTTP with the header and the bytes exactly as sent, because a client
 * library would serialise or compress the body itself.
 */

import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { brotliCompressSync, deflateSync, gzipSync } from 'node:zlib'

import { bootstrapTestApp } from './setup'
import type { BootstrappedTestApp } from './setup'

const UNSUPPORTED = {
  error: { code: 'auth.validation', message: 'Unsupported media type', details: null }
}
const MALFORMED = {
  error: { code: 'auth.validation', message: 'Malformed request', details: null }
}

const CREDENTIALS = JSON.stringify({
  email: 'compressed@example.com',
  password: 'CompressedSecret123!',
  tenantId: 'tenant-1'
})

describe('Compressed request bodies (E2E)', () => {
  let boot: BootstrappedTestApp
  let port: number

  beforeAll(async () => {
    boot = await bootstrapTestApp(
      { platform: { enabled: true } },
      {
        controllers: { auth: true, mfa: true, passwordReset: true, sessions: true, platform: true }
      }
    )
    port = (boot.app.getHttpServer().address() as AddressInfo).port
  })

  afterAll(async () => {
    await boot.app.close()
  })

  function post(
    path: string,
    encoding: string | undefined,
    payload: Buffer
  ): Promise<{ status: number; body: unknown }> {
    return new Promise((resolve, reject) => {
      const headers: Record<string, string | number> = {
        'Content-Type': 'application/json',
        'Content-Length': payload.length
      }
      if (encoding !== undefined) headers['Content-Encoding'] = encoding
      const req = http.request({ port, path, method: 'POST', headers }, (res) => {
        let text = ''
        res.on('data', (chunk: Buffer) => (text += chunk.toString()))
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, body: text.length > 0 ? JSON.parse(text) : null })
        )
      })
      req.on('error', reject)
      req.end(payload)
    })
  }

  // Verifies each encoding the host parser would decompress is refused with the contract's 415,
  // whatever the case of the header or the list around it.
  it.each([
    ['gzip', gzipSync(CREDENTIALS)],
    ['deflate', deflateSync(CREDENTIALS)],
    ['br', brotliCompressSync(CREDENTIALS)],
    ['GZIP', gzipSync(CREDENTIALS)],
    ['identity, gzip', gzipSync(CREDENTIALS)]
  ])('refuses Content-Encoding %s with 415 auth.validation', async (encoding, payload) => {
    const res = await post('/login', encoding, payload)

    expect(res.status).toBe(415)
    expect(res.body).toEqual(UNSUPPORTED)
  })

  // Verifies the refusal is the library's, not the parser's, by sending an encoding the parser
  // does not know: an unknown name is refused the same way and the same text.
  it('refuses an encoding no parser knows with the same answer', async () => {
    const res = await post('/login', 'x-unknown', Buffer.from(CREDENTIALS))

    expect(res.status).toBe(415)
    expect(res.body).toEqual(UNSUPPORTED)
  })

  // Verifies the refusal covers every controller, not only the login: one route of each plane
  // that takes a body.
  it.each(['/register', '/password/forgot-password', '/platform/login', '/mfa/challenge'])(
    'refuses a compressed body on %s',
    async (path) => {
      const res = await post(path, 'gzip', gzipSync(CREDENTIALS))

      expect(res.status).toBe(415)
      expect(res.body).toEqual(UNSUPPORTED)
    }
  )

  // Verifies the routes the contract leaves unchecked (refresh, logout) are not refused for the
  // header: the request reaches the handler, which answers for its own reasons.
  it.each(['/refresh', '/logout', '/platform/refresh', '/platform/logout'])(
    'does not refuse a compressed body on the unchecked route %s',
    async (path) => {
      const res = await post(path, 'gzip', gzipSync('{}'))

      expect(res.status).not.toBe(415)
    }
  )

  // Verifies the MFA setup routes, which accept an empty body, still refuse a compressed one. The
  // other half of their policy, an empty body passing, is the guard's unit test: Express's parser
  // fails an empty body that claims to be gzip before any guard runs.
  it.each(['/mfa/setup', '/platform/mfa/setup'])(
    'refuses a compressed body on %s when a body is present',
    async (path) => {
      const res = await post(path, 'gzip', gzipSync('{}'))

      expect(res.status).toBe(415)
      expect(res.body).toEqual(UNSUPPORTED)
    }
  )

  // Verifies the working paths are untouched: a body with no Content-Encoding, and one that says
  // `identity`, reach the handler (an unknown user answers 401 there).
  it.each([undefined, 'identity', 'IDENTITY'])(
    'lets a body with Content-Encoding %s through to the handler',
    async (encoding) => {
      const res = await post('/login', encoding, Buffer.from(CREDENTIALS))

      expect(res.status).toBe(401)
    }
  )

  // Verifies a body that claims to be compressed and is not fails in the host's parser, which runs
  // before any guard, and that failure is a client error in the contract's envelope. The parser
  // raises it as a 400 with no `type` of its own, so it is recognised by having happened before a
  // route matched.
  it.each([
    ['gzip', Buffer.from(CREDENTIALS)],
    ['deflate', Buffer.from(CREDENTIALS)],
    ['br', Buffer.from(CREDENTIALS)]
  ])('answers a corrupt %s body as 400 auth.validation', async (encoding, payload) => {
    const res = await post('/login', encoding, payload)

    expect(res.status).toBe(400)
    expect(res.body).toEqual(MALFORMED)
  })
})
