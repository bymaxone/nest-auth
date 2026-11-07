/**
 * @fileoverview Proves a request refused for its `Content-Encoding` consumes no rate-limit budget.
 *
 * The shared contract says the encoding refusal happens before authentication and rate limiting.
 * The authentication half shows in `compressed-bodies.e2e-spec.ts`: an unauthenticated compressed
 * body is answered 415, not 401. This suite shows the other half with the limiter on: refusals far
 * past the route's limit leave every attempt that follows its full allowance.
 */

import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { gzipSync } from 'node:zlib'

import { bootstrapTestApp } from './setup'
import type { BootstrappedTestApp } from './setup'

/** `login` allows five requests a minute per address. */
const LOGIN_LIMIT = 5

const BODY = JSON.stringify({
  email: 'budget@example.com',
  password: 'WrongPassword123!',
  tenantId: 'tenant-1'
})

describe('encoding refusal and the rate limit (E2E)', () => {
  let boot: BootstrappedTestApp
  let port: number

  beforeAll(async () => {
    boot = await bootstrapTestApp({
      tokenDelivery: 'bearer',
      rateLimit: { enabled: true, clientIpSource: 'peer' as const }
    })
    await boot.app.listen(0)
    port = (boot.app.getHttpServer().address() as AddressInfo).port
  })

  afterAll(async () => {
    await boot.app.close()
  })

  /** One login request, optionally declaring a gzip body, over raw HTTP. */
  function login(compressed: boolean): Promise<number> {
    const payload = compressed ? gzipSync(BODY) : Buffer.from(BODY)
    return new Promise((resolve, reject) => {
      const headers: Record<string, string | number> = {
        'Content-Type': 'application/json',
        'Content-Length': payload.length
      }
      if (compressed) headers['Content-Encoding'] = 'gzip'
      const req = http.request({ port, path: '/login', method: 'POST', headers }, (res) => {
        res.resume()
        res.on('end', () => resolve(res.statusCode ?? 0))
      })
      req.on('error', reject)
      req.end(payload)
    })
  }

  // Scenario: twice the login limit of compressed requests, then the full allowance of ordinary
  // ones. Expected: every compressed request is a 415, the first LOGIN_LIMIT ordinary requests are
  // refused on their merits (401), and only the next one is rate limited (429). Why: had the
  // refusals been counted, the ordinary requests would have started at 429.
  it('leaves the full allowance to the requests that follow the refusals', async () => {
    const refusals: number[] = []
    for (let i = 0; i < LOGIN_LIMIT * 2; i += 1) refusals.push(await login(true))

    const ordinary: number[] = []
    for (let i = 0; i < LOGIN_LIMIT + 1; i += 1) ordinary.push(await login(false))

    expect(refusals).toEqual(Array<number>(LOGIN_LIMIT * 2).fill(415))
    expect(ordinary).toEqual([...Array<number>(LOGIN_LIMIT).fill(401), 429])
  })
})
