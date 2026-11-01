import { Logger } from '@nestjs/common'
import type { ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'

import { API_KEY_SCOPES_KEY, ApiKeyScopes } from '../decorators/api-key-scopes.decorator'
import { formatApiKey } from '../crypto/api-key'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { ApiKeyAccessEvent, HookContext, IAuthHooks } from '../interfaces/auth-hooks.interface'
import { ApiKeyVerifierService } from '../services/api-key-verifier.service'
import {
  FakeClock,
  KEY_ID,
  MemoryApiKeyRepository,
  SENTINEL_KEY,
  SENTINEL_SECRET,
  makeOptions,
  makeRow
} from '../services/__tests__/api-key-fixtures'
import { ApiKeyGuard } from './api-key.guard'

// ---------------------------------------------------------------------------
// Routes under test: the metadata is real, so the guard reads what Nest would give it.
// ---------------------------------------------------------------------------

@ApiKeyScopes('admin')
class ClassScoped {
  inherits(): void {}

  @ApiKeyScopes('read')
  narrows(): void {}

  @ApiKeyScopes()
  emptyHandler(): void {}
}

class Undeclared {
  bare(): void {}
}

@ApiKeyScopes()
class EmptyClass {
  bare(): void {}
}

class Mixed {
  mixed(): void {}

  allWrong(): void {}
}
Reflect.defineMetadata(API_KEY_SCOPES_KEY, ['read', 1], Mixed.prototype.mixed)
Reflect.defineMetadata(API_KEY_SCOPES_KEY, [1, 2], Mixed.prototype.allWrong)

class Plain {
  @ApiKeyScopes('read', 'operate')
  both(): void {}

  @ApiKeyScopes('read')
  read(): void {}
}

type Req = {
  method: string
  route?: { path?: unknown } | undefined
  ip?: string
  ips?: string[]
  socket?: { remoteAddress?: string }
  headers: Record<string, string | string[] | undefined>
  apiKey?: unknown
}

function request(header: string | string[] | undefined, extra: Partial<Req> = {}): Req {
  return {
    method: 'GET',
    route: { path: '/videos/:id' },
    ip: '10.0.0.7',
    headers: { 'x-api-key': header, 'user-agent': 'agent/1', 'x-trace': 'abc' },
    ...extra
  }
}

function contextFor(cls: new () => object, method: string, req: Req): ExecutionContext {
  return {
    getHandler: () => (cls.prototype as Record<string, () => void>)[method],
    getClass: () => cls,
    switchToHttp: () => ({ getRequest: () => req })
  } as unknown as ExecutionContext
}

interface Harness {
  guard: ApiKeyGuard
  repo: MemoryApiKeyRepository
  events: Array<{ event: ApiKeyAccessEvent; context: HookContext }>
  errors: string[]
}

function build(
  options: {
    auditMode?: 'best-effort' | 'required'
    hooks?: IAuthHooks | null
    rows?: ReturnType<typeof makeRow>[]
  } = {}
): Harness {
  const repo = new MemoryApiKeyRepository(options.rows ?? [makeRow()])
  const opts = makeOptions(options.auditMode === undefined ? {} : { auditMode: options.auditMode })
  const lastUsed = { record: jest.fn() } as never
  const verifier = new ApiKeyVerifierService(repo, new FakeClock(), opts, lastUsed)
  const events: Harness['events'] = []
  const hooks: IAuthHooks | null =
    options.hooks === undefined
      ? {
          onApiKeyRequest: (event, context) => {
            events.push({ event, context })
          }
        }
      : options.hooks
  const errors: string[] = []
  jest.spyOn(Logger.prototype, 'error').mockImplementation((m) => {
    errors.push(String(m))
  })
  return { guard: new ApiKeyGuard(new Reflector(), verifier, opts, hooks), repo, events, errors }
}

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise
  } catch (err) {
    return (err as { getResponse(): { error: { code: string } } }).getResponse().error.code
  }
  return undefined
}

afterEach(() => {
  jest.restoreAllMocks()
})

describe('ApiKeyGuard', () => {
  describe('admitting', () => {
    // A valid key holding every declared scope is admitted and the principal is attached.
    it('admits a key holding every required scope and attaches the principal', async () => {
      const { guard } = build()
      const req = request(SENTINEL_KEY)
      await expect(guard.canActivate(contextFor(Plain, 'both', req))).resolves.toBe(true)
      expect(req.apiKey).toEqual({ id: KEY_ID, label: 'automation', scopes: ['read', 'operate'] })
    })

    // The attached principal cannot be altered by the handler.
    it('freezes the principal and its scopes', async () => {
      const { guard } = build()
      const req = request(SENTINEL_KEY)
      await guard.canActivate(contextFor(Plain, 'read', req))
      const principal = req.apiKey as { scopes: string[] }
      expect(Object.isFrozen(principal)).toBe(true)
      expect(Object.isFrozen(principal.scopes)).toBe(true)
    })

    // The principal never carries the digest or the secret.
    it('attaches nothing secret', async () => {
      const { guard } = build()
      const req = request(SENTINEL_KEY)
      await guard.canActivate(contextFor(Plain, 'read', req))
      expect(JSON.stringify(req.apiKey)).not.toContain(SENTINEL_SECRET)
      expect(Object.keys(req.apiKey as object).sort()).toEqual(['id', 'label', 'scopes'])
    })

    // A key may be read from a differently configured header.
    it('reads the configured header', async () => {
      const repo = new MemoryApiKeyRepository([makeRow()])
      const opts = makeOptions({ header: 'x-machine-key' })
      const verifier = new ApiKeyVerifierService(repo, new FakeClock(), opts, {
        record: jest.fn()
      } as never)
      const guard = new ApiKeyGuard(new Reflector(), verifier, opts, null)
      const req = request(undefined, { headers: { 'x-machine-key': SENTINEL_KEY } })
      await expect(guard.canActivate(contextFor(Plain, 'read', req))).resolves.toBe(true)
    })
  })

  describe('scopes', () => {
    // The key must hold ALL declared scopes.
    it('refuses a valid key missing one of the declared scopes', async () => {
      const { guard } = build({ rows: [makeRow({ scopes: ['read'] })] })
      expect(
        await codeOf(guard.canActivate(contextFor(Plain, 'both', request(SENTINEL_KEY))))
      ).toBe(AUTH_ERROR_CODES.API_KEY_SCOPE_INSUFFICIENT)
    })

    // A handler-level declaration overrides the class-level one: the most specific wins.
    it('lets the handler narrow the class declaration', async () => {
      const { guard } = build({ rows: [makeRow({ scopes: ['read'] })] })
      await expect(
        guard.canActivate(contextFor(ClassScoped, 'narrows', request(SENTINEL_KEY)))
      ).resolves.toBe(true)
    })

    // A handler with no declaration inherits the class declaration.
    it('falls back to the class declaration', async () => {
      const { guard } = build({ rows: [makeRow({ scopes: ['read'] })] })
      expect(
        await codeOf(guard.canActivate(contextFor(ClassScoped, 'inherits', request(SENTINEL_KEY))))
      ).toBe(AUTH_ERROR_CODES.API_KEY_SCOPE_INSUFFICIENT)
    })

    // Scope names are matched exactly: no hierarchy, no wildcard, no prefix match.
    it('does not treat admin as implying read', async () => {
      const { guard } = build({ rows: [makeRow({ scopes: ['admin'] })] })
      expect(
        await codeOf(guard.canActivate(contextFor(Plain, 'read', request(SENTINEL_KEY))))
      ).toBe(AUTH_ERROR_CODES.API_KEY_SCOPE_INSUFFICIENT)
    })
  })

  describe('credentials', () => {
    it.each([
      ['missing', undefined],
      ['malformed', 'garbage'],
      ['unknown', formatApiKey('bak', '5a1d9e40-7b3c-4f6a-8c21-0e9d4b6a3f12', SENTINEL_SECRET)],
      ['wrong', formatApiKey('bak', KEY_ID, 'A'.repeat(43))],
      ['a repeated header', ['a', 'b']]
    ])('answers the same code for a %s key', async (_name, header) => {
      const { guard } = build()
      expect(await codeOf(guard.canActivate(contextFor(Plain, 'read', request(header))))).toBe(
        AUTH_ERROR_CODES.API_KEY_INVALID
      )
    })

    it.each([
      ['revoked', { revokedAt: new Date('2020-01-01') }],
      ['expired', { expiresAt: new Date('2020-01-01') }]
    ])('answers the same code for a %s key', async (_name, patch) => {
      const { guard } = build({ rows: [makeRow(patch)] })
      expect(
        await codeOf(guard.canActivate(contextFor(Plain, 'read', request(SENTINEL_KEY))))
      ).toBe(AUTH_ERROR_CODES.API_KEY_INVALID)
    })

    // The user-JWT bearer header is not a key source.
    it('ignores the Authorization header', async () => {
      const { guard } = build()
      const req = request(undefined, {
        headers: { authorization: `Bearer ${SENTINEL_KEY}` }
      })
      expect(await codeOf(guard.canActivate(contextFor(Plain, 'read', req)))).toBe(
        AUTH_ERROR_CODES.API_KEY_INVALID
      )
    })

    // A store fault fails closed with a generic answer, and says so to the operator.
    it('fails closed when the store faults', async () => {
      const { guard, repo, events, errors } = build()
      repo.failWith = new Error(`down ${SENTINEL_SECRET}`)
      expect(
        await codeOf(guard.canActivate(contextFor(Plain, 'read', request(SENTINEL_KEY))))
      ).toBe(AUTH_ERROR_CODES.INTERNAL)
      expect(events[0]?.event).toMatchObject({ outcome: 'denied', reason: 'store_error' })
      expect(errors.join('\n')).not.toContain(SENTINEL_SECRET)
      expect(errors[0]).toContain('api-key: key store unavailable cause=')
    })
  })

  describe('a route that declares no scopes', () => {
    it.each([
      ['no declaration', Undeclared, 'bare'],
      ['an empty class declaration', EmptyClass, 'bare'],
      ['an empty handler declaration', ClassScoped, 'emptyHandler'],
      ['a declaration mixing a string and a non-string', Mixed, 'mixed'],
      ['a declaration of only non-strings', Mixed, 'allWrong']
    ])('is refused with %s', async (_name, cls, method) => {
      const { guard } = build()
      expect(
        await codeOf(guard.canActivate(contextFor(cls as never, method, request(SENTINEL_KEY))))
      ).toBe(AUTH_ERROR_CODES.FORBIDDEN)
    })

    // The refusal depends on route configuration alone: no credential is read, no store call
    // is made, whatever the key is. This branch intentionally takes different steps from the
    // credential paths, which is why it is separate in the walker and in the README.
    it('does no credential work', async () => {
      const { guard, repo } = build()
      await codeOf(guard.canActivate(contextFor(Undeclared, 'bare', request(SENTINEL_KEY))))
      await codeOf(guard.canActivate(contextFor(Undeclared, 'bare', request(undefined))))
      expect(repo.calls).toEqual([])
    })

    // The verb is client-supplied and the pattern is host-authored; neither may break the line.
    it('keeps the log line to one line whatever the method and route contain', async () => {
      const { guard, errors } = build()
      const req = request(SENTINEL_KEY, {
        method: 'GET\nforged: entry',
        route: { path: '/a\r\nb' }
      })
      await codeOf(guard.canActivate(contextFor(Undeclared, 'bare', req)))
      expect(errors[0]).not.toMatch(/[\r\n]/)
    })

    // It is an event too, and the operator is told which route to fix.
    it('is audited and logged with the route', async () => {
      const { guard, events, errors } = build()
      await codeOf(guard.canActivate(contextFor(Undeclared, 'bare', request(SENTINEL_KEY))))
      expect(events[0]?.event).toMatchObject({
        outcome: 'denied',
        reason: 'route_undeclared',
        keyId: null,
        route: '/videos/:id',
        requiredScopes: []
      })
      expect(errors[0]).toContain('GET /videos/:id is guarded but declares no scopes; refused')
    })
  })

  describe('the audit hook', () => {
    // One event per request, for the admitted one and for every kind of refusal.
    it('fires exactly once for every outcome', async () => {
      const { guard, events } = build()
      await guard.canActivate(contextFor(Plain, 'read', request(SENTINEL_KEY)))
      await codeOf(guard.canActivate(contextFor(Plain, 'read', request('garbage'))))
      await codeOf(guard.canActivate(contextFor(Plain, 'read', request(undefined))))
      expect(events.map((e) => [e.event.outcome, e.event.reason])).toEqual([
        ['allowed', null],
        ['denied', 'malformed'],
        ['denied', 'missing']
      ])
    })

    // The event names the label, the route pattern, the method, the scopes and the address.
    it('carries label, route, method, scopes and address', async () => {
      const { guard, events } = build()
      await guard.canActivate(contextFor(Plain, 'both', request(SENTINEL_KEY)))
      expect(events[0]?.event).toEqual({
        outcome: 'allowed',
        reason: null,
        keyId: KEY_ID,
        label: 'automation',
        method: 'GET',
        route: '/videos/:id',
        requiredScopes: ['read', 'operate'],
        ip: '10.0.0.7'
      })
    })

    // Scenario: behind a trusted proxy `req.ip` is a string the caller wrote that is not an
    // address. Expected: the audit event and the hook context both carry the nearest address
    // instead. Why: both reach the consumer's audit sink, which trusts them.
    it('records an address, never a caller-written string, in the event and the context', async () => {
      const { guard, events } = build()
      const written = `junk-${'x'.repeat(300)}`
      await guard.canActivate(
        contextFor(
          Plain,
          'both',
          request(SENTINEL_KEY, {
            ip: written,
            ips: [written],
            socket: { remoteAddress: '10.0.0.1' }
          })
        )
      )
      expect(events[0]?.event.ip).toBe('10.0.0.1')
      expect(events[0]?.context.ip).toBe('10.0.0.1')
    })

    // A refusal for a wrong secret still names the label the attempt claimed.
    it('names the claimed key on a wrong secret and none on an unknown one', async () => {
      const { guard, events } = build()
      await codeOf(
        guard.canActivate(
          contextFor(Plain, 'read', request(formatApiKey('bak', KEY_ID, 'A'.repeat(43))))
        )
      )
      await codeOf(
        guard.canActivate(
          contextFor(
            Plain,
            'read',
            request(formatApiKey('bak', '5a1d9e40-7b3c-4f6a-8c21-0e9d4b6a3f12', SENTINEL_SECRET))
          )
        )
      )
      expect(events[0]?.event).toMatchObject({
        reason: 'wrong_secret',
        keyId: KEY_ID,
        label: 'automation'
      })
      expect(events[1]?.event).toMatchObject({ reason: 'unknown', keyId: null, label: null })
    })

    // A scope refusal reports who was refused, so an operator sees which machine is misconfigured.
    it('names the key on a scope refusal', async () => {
      const { guard, events } = build({ rows: [makeRow({ scopes: ['read'] })] })
      await codeOf(guard.canActivate(contextFor(Plain, 'both', request(SENTINEL_KEY))))
      expect(events[0]?.event).toMatchObject({
        reason: 'scope_insufficient',
        keyId: KEY_ID,
        label: 'automation'
      })
    })

    // A route with no matched pattern reports an empty route, never the raw URL.
    it('reports an empty route when the framework matched no pattern', async () => {
      const { guard, events } = build()
      await guard.canActivate(
        contextFor(Plain, 'read', request(SENTINEL_KEY, { route: undefined }))
      )
      await guard.canActivate(
        contextFor(Plain, 'read', request(SENTINEL_KEY, { route: { path: /raw/ } }))
      )
      expect(events.map((e) => e.event.route)).toEqual(['', ''])
    })

    // An absent client address becomes an empty string, as in every other hook context.
    it('uses an empty address when the request has none', async () => {
      const { guard, events } = build()
      const req = request(SENTINEL_KEY)
      delete req.ip
      await guard.canActivate(contextFor(Plain, 'read', req))
      expect(events[0]?.event.ip).toBe('')
      expect(events[0]?.context.ip).toBe('')
    })

    // The hook context never carries the key header, whatever it is named, nor the user agent
    // of a request that did not send one.
    it('strips the key header from the context and defaults the user agent', async () => {
      const { guard, events } = build()
      const req = request(SENTINEL_KEY)
      delete req.headers['user-agent']
      await guard.canActivate(contextFor(Plain, 'read', req))
      expect(events[0]?.context.userAgent).toBe('')
      expect(events[0]?.context.sanitizedHeaders).toEqual({ 'x-trace': 'abc' })
    })

    // A header configured under a name the generic sanitizer would not catch is still removed.
    it('removes a custom key header the sanitizer does not know', async () => {
      const repo = new MemoryApiKeyRepository([makeRow()])
      const opts = makeOptions({ header: 'machine-credential' })
      const events: HookContext[] = []
      const verifier = new ApiKeyVerifierService(repo, new FakeClock(), opts, {
        record: jest.fn()
      } as never)
      const guard = new ApiKeyGuard(new Reflector(), verifier, opts, {
        onApiKeyRequest: (_e, context) => {
          events.push(context)
        }
      })
      await guard.canActivate(
        contextFor(
          Plain,
          'read',
          request(undefined, { headers: { 'machine-credential': SENTINEL_KEY } })
        )
      )
      expect(JSON.stringify(events[0])).not.toContain(SENTINEL_SECRET)
    })

    // No hook implemented, or an implementation without this method, is not an error.
    it.each([
      ['no hooks provider', null],
      ['a hooks object without the method', {}]
    ])('works with %s', async (_name, hooks) => {
      const { guard } = build({ hooks })
      await expect(
        guard.canActivate(contextFor(Plain, 'read', request(SENTINEL_KEY)))
      ).resolves.toBe(true)
    })

    describe('in required mode without a hook to call', () => {
      // Auditing was demanded and nothing can write it: admitting the request would be the one
      // outcome with no audit record at all, so it is refused and the misconfiguration is loud.
      it.each([
        ['no hooks provider', null],
        ['a hooks object without the method', {}]
      ])('denies a valid request with %s', async (_name, hooks) => {
        const { guard, errors } = build({ auditMode: 'required', hooks })
        const req = request(SENTINEL_KEY)
        expect(await codeOf(guard.canActivate(contextFor(Plain, 'read', req)))).toBe(
          AUTH_ERROR_CODES.INTERNAL
        )
        expect(req.apiKey).toBeUndefined()
        expect(errors.join('\n')).toContain('auditMode is required but no onApiKeyRequest hook')
      })
    })

    describe('in best-effort mode', () => {
      // A failing hook never changes the answer, however it fails.
      it.each([
        ['rejects', () => Promise.reject(new Error('siem down'))],
        [
          'throws synchronously',
          () => {
            throw new Error('siem down')
          }
        ]
      ])('admits the request when the hook %s', async (_name, onApiKeyRequest) => {
        const { guard, errors } = build({ hooks: { onApiKeyRequest } })
        await expect(
          guard.canActivate(contextFor(Plain, 'read', request(SENTINEL_KEY)))
        ).resolves.toBe(true)
        await new Promise((resolve) => setImmediate(resolve))
        expect(errors.join('\n')).toContain('audit hook failed')
      })

      // The request does not wait for a slow hook.
      it('does not await the hook', async () => {
        let release: () => void = () => undefined
        const gate = new Promise<void>((resolve) => {
          release = resolve
        })
        const { guard } = build({ hooks: { onApiKeyRequest: () => gate } })
        await expect(
          guard.canActivate(contextFor(Plain, 'read', request(SENTINEL_KEY)))
        ).resolves.toBe(true)
        release()
      })
    })

    describe('in required mode', () => {
      // The hook is awaited: the request is admitted only after the audit row is accepted.
      it('awaits the hook before admitting', async () => {
        const order: string[] = []
        const { guard } = build({
          auditMode: 'required',
          hooks: {
            onApiKeyRequest: async () => {
              await new Promise((resolve) => setImmediate(resolve))
              order.push('hook')
            }
          }
        })
        await guard.canActivate(contextFor(Plain, 'read', request(SENTINEL_KEY)))
        order.push('admitted')
        expect(order).toEqual(['hook', 'admitted'])
      })

      // A failing hook DENIES an otherwise valid request: fail closed.
      it('denies a valid request when the hook fails', async () => {
        const { guard, errors } = build({
          auditMode: 'required',
          hooks: { onApiKeyRequest: () => Promise.reject(new Error('row not written')) }
        })
        const req = request(SENTINEL_KEY)
        expect(await codeOf(guard.canActivate(contextFor(Plain, 'read', req)))).toBe(
          AUTH_ERROR_CODES.INTERNAL
        )
        expect(req.apiKey).toBeUndefined()
        expect(errors.join('\n')).toContain('audit hook failed')
      })

      // A refusal stays the refusal it was even when its own audit row cannot be written.
      it('keeps the original refusal when the hook fails on a denial', async () => {
        const { guard } = build({
          auditMode: 'required',
          hooks: { onApiKeyRequest: () => Promise.reject(new Error('row not written')) }
        })
        expect(await codeOf(guard.canActivate(contextFor(Plain, 'read', request('garbage'))))).toBe(
          AUTH_ERROR_CODES.API_KEY_INVALID
        )
      })
    })
  })

  describe('the key never leaks', () => {
    // Every refusal path is driven with a recognisable key. Neither the full key nor its secret
    // may appear in a log line, an exception, the hook event, the hook context or the request.
    it.each([
      ['admitted', {}, Plain, 'read', undefined],
      [
        'wrong secret',
        {},
        Plain,
        'read',
        formatApiKey('bak', KEY_ID, `${SENTINEL_SECRET.slice(1)}Z`)
      ],
      [
        'unknown id',
        {},
        Plain,
        'read',
        formatApiKey('bak', '5a1d9e40-7b3c-4f6a-8c21-0e9d4b6a3f12', SENTINEL_SECRET)
      ],
      ['revoked', { revokedAt: new Date('2020-01-01') }, Plain, 'read', undefined],
      ['expired', { expiresAt: new Date('2020-01-01') }, Plain, 'read', undefined],
      ['missing scope', { scopes: ['read'] }, Plain, 'both', undefined],
      ['undeclared route', {}, Undeclared, 'bare', undefined],
      ['malformed', {}, Plain, 'read', `${SENTINEL_KEY}!`]
    ])('%s', async (_name, patch, cls, method, header) => {
      const capturedLogs: string[] = []
      jest.spyOn(Logger.prototype, 'warn').mockImplementation((m) => {
        capturedLogs.push(String(m))
      })
      const { guard, events, errors } = build({ rows: [makeRow(patch)] })
      const req = request(header ?? SENTINEL_KEY)
      let thrown: unknown
      try {
        await guard.canActivate(contextFor(cls as never, method, req))
      } catch (err) {
        thrown = err
      }
      const everything = JSON.stringify([
        events,
        errors,
        capturedLogs,
        thrown instanceof Error
          ? [
              thrown.message,
              thrown.stack,
              (thrown as unknown as { getResponse(): unknown }).getResponse()
            ]
          : [],
        req.apiKey ?? null
      ])
      expect(everything).not.toContain(SENTINEL_SECRET)
      expect(everything).not.toContain(SENTINEL_KEY)
      expect(everything).not.toContain(SENTINEL_SECRET.slice(1))
    })
  })
})
