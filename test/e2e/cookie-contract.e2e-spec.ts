/**
 * @fileoverview Pins the flags on every cookie this library sets.
 *
 * Cookie delivery exists for one guarantee: **the tokens are never readable from JavaScript**. A
 * token leaking into `localStorage`, `sessionStorage` or a JS-readable cookie is invisible from
 * every angle this repository has — the unit tests pass, the e2e passes, the API answers
 * identically, and the wire looks perfect. Only a browser can observe the leak, and this library
 * has no browser.
 *
 * So this suite proves **its half**: the `Set-Cookie` headers carry the flags the guarantee is
 * built on. That does not prove a browser honours them — nothing here can — but it fails loudly
 * if a flag is ever dropped, which is the realistic regression. The other half is stated as a
 * contract in the README so a consumer knows the browser assertion is theirs to make rather than
 * assuming this suite covers it.
 *
 * The `has_session` hint is the reason this is asserted per cookie rather than as a blanket rule.
 * It is **deliberately** JS-readable and carries no credential — it is what lets a SPA know a
 * session probably exists without touching a token. A naive "every cookie is HttpOnly" assertion
 * would fail on it, and "fixing" that by making it HttpOnly would silently remove the feature.
 */

import request from 'supertest'

import { bootstrapTestApp } from './setup'
import type { BootstrappedTestApp } from './setup'

/** One `Set-Cookie` header, parsed into its name and the attributes present on it. */
interface ParsedCookie {
  name: string
  attributes: string[]
}

function parseSetCookie(headers: string[]): ParsedCookie[] {
  return headers.map((header) => {
    const [pair, ...rest] = header.split(';')
    return {
      name: pair!.split('=')[0]!.trim(),
      attributes: rest.map((part) => part.trim().toLowerCase())
    }
  })
}

const has = (cookie: ParsedCookie, attribute: string): boolean =>
  cookie.attributes.some((entry) => entry === attribute || entry.startsWith(`${attribute}=`))

describe('cookie flags on the credential-bearing cookies (E2E)', () => {
  let boot: BootstrappedTestApp
  let cookies: ParsedCookie[]

  beforeAll(async () => {
    boot = await bootstrapTestApp({ tokenDelivery: 'cookie', secureCookies: true })

    const registered = await request(boot.app.getHttpServer()).post('/register').send({
      email: 'cookie-contract@example.com',
      password: 'ProbePass123!-xyz',
      name: 'Cookie Contract',
      tenantId: 'tenant-1'
    })
    expect(registered.status).toBe(201)

    cookies = parseSetCookie(registered.headers['set-cookie'] as unknown as string[])
  })

  afterAll(async () => {
    await boot.app.close()
  })

  // Verifies the two credential cookies carry the flags the guarantee rests on.
  //
  // `HttpOnly` is the one that matters and the one nothing else in this repository checks:
  // dropping it would leak both tokens to any script on the page — including an injected one —
  // while every existing assertion in the suite stayed green, because the API behaves identically
  // either way. `Secure` is asserted alongside it because the deployment declared
  // `secureCookies: true`, and a credential cookie without it travels in clear on the first
  // downgrade.
  it.each(['access_token', 'refresh_token'])('%s is HttpOnly and Secure', (name) => {
    const cookie = cookies.find((entry) => entry.name === name)

    expect(cookie).toBeDefined()
    expect(has(cookie!, 'httponly')).toBe(true)
    expect(has(cookie!, 'secure')).toBe(true)
  })

  // Verifies the refresh cookie is scoped to the auth prefix rather than the whole origin.
  //
  // Path scoping means the long-lived credential is not attached to every request the application
  // makes — it travels only where it is redeemed. Losing it would not break anything, which is
  // exactly why it needs an assertion: the failure is silent and the blast radius is the widest
  // credential in the system being sent everywhere.
  it('refresh_token is path-scoped, not origin-wide', () => {
    const refresh = cookies.find((entry) => entry.name === 'refresh_token')

    expect(refresh).toBeDefined()
    expect(refresh!.attributes).toContain('path=/auth')
  })

  // Verifies the session hint is NOT HttpOnly — the one cookie that must stay readable.
  //
  // Asserted as an inequality on purpose. The hint carries no credential and exists so a SPA can
  // tell a session probably exists without touching a token; making it HttpOnly would remove the
  // feature while every other assertion here passed. This is also why the flags are asserted per
  // cookie: a blanket "everything is HttpOnly" rule would have been wrong, and the wrong fix for
  // it is the one that breaks a consumer silently.
  it('has_session stays readable and carries no credential', () => {
    const hint = cookies.find((entry) => entry.name === 'has_session')

    expect(hint).toBeDefined()
    expect(has(hint!, 'httponly')).toBe(false)
    expect(has(hint!, 'secure')).toBe(true)
  })

  // Verifies nothing else was set. A new credential-bearing cookie added without flags would sit
  // outside every assertion above, which is the shape of an unpinned collection this project has
  // been removing all week.
  it('sets exactly the three cookies this suite pins', () => {
    expect(cookies.map((entry) => entry.name).sort()).toEqual([
      'access_token',
      'has_session',
      'refresh_token'
    ])
  })
})
