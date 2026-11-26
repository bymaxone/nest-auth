/**
 * @fileoverview Which listed session is marked as the caller's, with and without a refresh token
 * reaching the route.
 *
 * @layer Test
 */

import { createHash } from 'node:crypto'

import request from 'supertest'

import type { BymaxAuthModuleOptions } from '../../src/server/interfaces/auth-module-options.interface'
import { bootstrapTestApp } from './setup'
import type { BootstrappedTestApp } from './setup'

const PASSWORD = 'CurrentSession-9!xyz'
const TENANT = 'tenant-1'

interface Listed {
  sessionHash: string
  isCurrent: boolean
}

interface Pair {
  accessToken: string
  refreshToken: string
}

/** The sessions a listing marks as the caller's own. */
const marked = (res: request.Response): string[] =>
  (res.body as Listed[]).filter((s) => s.isCurrent).map((s) => s.sessionHash)

const hashOf = (refreshToken: string): string =>
  createHash('sha256').update(refreshToken).digest('hex')

/** The refresh token a response put in its cookie. */
const cookieToken = (res: request.Response): string => {
  const set = [res.headers['set-cookie']].flat().map(String)
  const found = set.find((c) => c.startsWith('refresh_token='))
  return decodeURIComponent(String(found).split(';')[0]!.slice('refresh_token='.length))
}

const account = (email: string): object => ({
  email,
  password: PASSWORD,
  name: 'Current',
  tenantId: TENANT
})

describe('the current session of a listing, bearer delivery (E2E)', () => {
  let boot: BootstrappedTestApp

  beforeAll(async () => {
    boot = await bootstrapTestApp()
  })

  afterAll(async () => {
    await boot.app.close()
  })

  /** Two logins of one account. */
  async function twoDevices(email: string): Promise<[Pair, Pair]> {
    const server = boot.app.getHttpServer()
    const first = await request(server).post('/register').send(account(email))
    const second = await request(server)
      .post('/login')
      .send({ email, password: PASSWORD, tenantId: TENANT })
    return [first.body as Pair, second.body as Pair]
  }

  it('marks the session of the access token when no refresh token is sent', async () => {
    const [first] = await twoDevices('current-access@example.com')

    const res = await request(boot.app.getHttpServer())
      .get('/sessions')
      .set('Authorization', `Bearer ${first.accessToken}`)

    expect(res.body).toHaveLength(2)
    expect(marked(res)).toEqual([hashOf(first.refreshToken)])
  })

  it('keeps marking it after a rotation', async () => {
    const [first] = await twoDevices('current-rotated@example.com')
    const rotated = await request(boot.app.getHttpServer())
      .post('/refresh')
      .send({ refreshToken: first.refreshToken })

    const res = await request(boot.app.getHttpServer())
      .get('/sessions')
      .set('Authorization', `Bearer ${(rotated.body as Pair).accessToken}`)

    expect(marked(res)).toEqual([hashOf((rotated.body as Pair).refreshToken)])
  })

  it('lets a refresh token that is sent decide', async () => {
    const [first, second] = await twoDevices('current-refresh-wins@example.com')

    const res = await request(boot.app.getHttpServer())
      .get('/sessions')
      .set('Authorization', `Bearer ${first.accessToken}`)
      .send({ refreshToken: second.refreshToken })

    expect(marked(res)).toEqual([hashOf(second.refreshToken)])
  })
})

describe.each([
  ['the default refresh cookie path', undefined],
  ['a refresh cookie scoped to the refresh route', '/auth/refresh']
])('the current session of a listing, cookie delivery with %s (E2E)', (_name, path) => {
  it('marks the session of the caller', async () => {
    const cookies: BymaxAuthModuleOptions['cookies'] =
      path === undefined ? {} : { refreshCookiePath: path }
    const boot = await bootstrapTestApp(
      { tokenDelivery: 'cookie', cookies },
      { beforeInit: (app) => app.setGlobalPrefix('auth') }
    )
    const browser = request.agent(boot.app.getHttpServer())
    const other = request.agent(boot.app.getHttpServer())
    const email = 'current-cookie@example.com'
    const own = await browser.post('/auth/register').send(account(email))
    await other.post('/auth/login').send({ email, password: PASSWORD, tenantId: TENANT })

    const res = await browser.get('/auth/sessions')
    await boot.app.close()

    expect(res.body).toHaveLength(2)
    expect(marked(res)).toEqual([hashOf(cookieToken(own))])
  })
})
