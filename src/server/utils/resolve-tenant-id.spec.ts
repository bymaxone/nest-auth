/**
 * The one rule every tenant-scoped flow resolves its scope through.
 *
 * Two things are under test and they protect different failures. A configured resolver must win
 * over the body, which is what stops a caller naming a tenant it does not belong to; and with no
 * resolver configured, a body that names no tenant must be refused rather than defaulted, because
 * inventing a name would gather into one scope every account a misconfigured deployment created.
 */

import type { Request } from 'express'

import { resolveTenantId } from './resolve-tenant-id'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/** A request carrying only what a resolver in these scenarios reads. */
const REQUEST = { hostname: 'acme.example.com' } as Request

describe('resolveTenantId', () => {
  // The anti-spoofing promise the option documents: configured, the resolver decides, and a
  // caller that names a different tenant in the body changes nothing.
  it('prefers the resolver over the tenant named in the body', async () => {
    await expect(resolveTenantId('attacker-chosen', REQUEST, () => 'resolved')).resolves.toBe(
      'resolved'
    )
  })

  // The same promise when the caller sends nothing, which is the shape the DTOs now permit.
  it('uses the resolver when the body names no tenant', async () => {
    await expect(resolveTenantId(undefined, REQUEST, () => 'resolved')).resolves.toBe('resolved')
  })

  // A resolver may be asynchronous, and the awaited value is what scopes the request.
  it('awaits an asynchronous resolver', async () => {
    await expect(
      resolveTenantId(undefined, REQUEST, () => Promise.resolve('resolved-async'))
    ).resolves.toBe('resolved-async')
  })

  // Without a resolver the body is the only thing that can name a tenant, and it is honoured —
  // this is the pre-existing behaviour, unchanged.
  it('falls back to the body when no resolver is configured', async () => {
    await expect(resolveTenantId('from-body', REQUEST)).resolves.toBe('from-body')
  })

  // The case the optional field introduces: nothing in the request can scope it. Refused with
  // the same `auth.validation` code and `{ field, message }[]` shape the validation pipe
  // produces, so a client already handling a field error sees no new shape.
  it('refuses a request that no resolver and no body value can scope', async () => {
    const failure = resolveTenantId(undefined, REQUEST)

    await expect(failure).rejects.toBeInstanceOf(AuthException)
    await expect(failure).rejects.toMatchObject({
      response: {
        error: {
          code: AUTH_ERROR_CODES.VALIDATION,
          details: [{ field: 'tenantId', message: expect.stringContaining('tenantIdResolver') }]
        }
      }
    })
  })

  // Refusal is a client error: the deployment is misconfigured, but the request is what cannot
  // be answered, and a 500 here would page whoever is on call for every such call.
  it('refuses with 400 rather than a server error', async () => {
    await expect(resolveTenantId(undefined, REQUEST)).rejects.toMatchObject({ status: 400 })
  })

  // An empty string is a value the caller sent, not an absent field, so it is not the refusal
  // path. The DTOs reject it before this point; here it must not be mistaken for `undefined`.
  it('does not treat an empty body value as an absent one', async () => {
    await expect(resolveTenantId('', REQUEST)).resolves.toBe('')
  })

  // `null` is absent, and reaching this state is ordinary rather than exotic: `@IsOptional()`
  // skips validation for `null` as well as for `undefined`, so a caller sending `tenantId: null`
  // arrives here past every DTO constraint. Admitting it would carry `null` into the
  // tenant-scoped lookups and into the Redis and HMAC keys built from it.
  it('refuses a null body value the same way as an absent one', async () => {
    const failure = resolveTenantId(null, REQUEST)

    await expect(failure).rejects.toBeInstanceOf(AuthException)
    await expect(failure).rejects.toMatchObject({ status: 400 })
  })

  // …and a resolver still decides, so `null` in the body changes nothing when one is configured.
  it('uses the resolver even when the body value is null', async () => {
    await expect(resolveTenantId(null, REQUEST, () => 'resolved')).resolves.toBe('resolved')
  })
})
