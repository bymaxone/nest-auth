/**
 * @fileoverview The API key guard checks the built-ins its decisions are made with: before it reads the route's scopes, after
 * the verification of the key (a store lookup it waits for), and after the audit hook it waits for, so a replacement made while it
 * waits is refused before the key is admitted.
 *
 * @layer Test
 */

import type { ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'

import { formatApiKey } from '../crypto/api-key'
import { ApiKeyScopes } from '../decorators/api-key-scopes.decorator'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import { ApiKeyVerifierService } from '../services/api-key-verifier.service'
import {
  FakeClock,
  KEY_ID,
  MemoryApiKeyRepository,
  SENTINEL_KEY,
  makeOptions,
  makeRow
} from '../services/__tests__/api-key-fixtures'
import { ApiKeyGuard } from './api-key.guard'

// The test's own copies: the windows below replace built-ins, so nothing inside one may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor

class Route {
  @ApiKeyScopes('read')
  read(): void {}
}

/** Replaces `key` of `holder` and returns what puts it back. */
function replace(holder: object, key: string, stub: unknown): () => void {
  const held = getOwn(holder, key) as PropertyDescriptor
  define(holder, key, { ...held, value: stub })
  return (): void => void define(holder, key, held)
}

function context(): ExecutionContext {
  const request = {
    method: 'GET',
    route: { path: '/videos/:id' },
    ip: '10.0.0.7',
    headers: { 'x-api-key': SENTINEL_KEY, 'user-agent': 'agent/1' }
  }
  return Object.assign({} as ExecutionContext, {
    getClass: () => Route,
    switchToHttp: () => ({ getRequest: () => request })
  })
}

/** The status of the refusal, or `true` when the guard admitted, or `undefined` for any other failure. */
async function outcome(guard: ApiKeyGuard): Promise<number | true | undefined> {
  try {
    return (await guard.canActivate(context())) ? true : undefined
  } catch (error) {
    return (error as { getStatus?: () => number }).getStatus?.()
  }
}

describe('ApiKeyGuard while a built-in is replaced', () => {
  const build = (
    repository: MemoryApiKeyRepository,
    hooks: IAuthHooks | null,
    lastUsed: { record: () => void } = { record: jest.fn() }
  ): ApiKeyGuard => {
    const options = makeOptions({ auditMode: 'required' })
    const verifier = new ApiKeyVerifierService(
      repository,
      new FakeClock(),
      options,
      lastUsed as never
    )
    return new ApiKeyGuard(new Reflector(), verifier, options, hooks)
  }
  const repository = (): MemoryApiKeyRepository => new MemoryApiKeyRepository([makeRow()])
  const audit: IAuthHooks = { onApiKeyRequest: async (): Promise<void> => undefined }

  // Scenario: a legitimate key with nothing replaced. Expected: admitted. Why: the control for the rows below.
  it('admits a key holding the scope with nothing replaced', async () => {
    expect(formatApiKey).toBeDefined()
    expect(KEY_ID).toBeDefined()

    await expect(outcome(build(repository(), audit))).resolves.toBe(true)
  })

  // Scenario: `Array.prototype.every`, which the scope check is made with, replaced before the guard runs. Expected: the library's
  // refusal. Why: a replaced `every` answers true for any scope.
  it('is refused when every is replaced before it runs', async () => {
    const rows = repository()
    const lookup = jest.spyOn(rows, 'findById')
    const guard = build(rows, audit)
    const restore = replace(Array.prototype, 'every', () => true)
    let result: number | true | undefined
    try {
      result = await outcome(guard)
    } finally {
      restore()
    }

    expect(result).toBe(500)
    expect(lookup).not.toHaveBeenCalled()
  })

  // Scenario: the store lookup of the key replaces `Array.prototype.includes` while it is awaited. Expected: the library's refusal.
  // Why: the key is decided after the lookup, and the scope check after that.
  it('is refused when a built-in is replaced during the lookup of the key', async () => {
    let restore = (): void => undefined
    const rows = repository()
    const find = rows.findById.bind(rows)
    rows.findById = async (id: string): Promise<ReturnType<typeof makeRow> | null> => {
      await Promise.resolve()
      restore = replace(Array.prototype, 'includes', () => true)
      return find(id)
    }
    const lastUsed = { record: jest.fn() }
    let result: number | true | undefined
    try {
      result = await outcome(build(rows, audit, lastUsed))
    } finally {
      restore()
    }

    expect(result).toBe(500)
    expect(lastUsed.record).not.toHaveBeenCalled()
  })

  // Scenario: the audit hook the guard waits for replaces `Array.prototype.every` and answers. Expected: the library's refusal and
  // no admission. Why: the key is admitted after the audit, so a replacement made during it must be seen by a check after it.
  it('is refused when a built-in is replaced during the audit hook', async () => {
    let restore = (): void => undefined
    const hooks: IAuthHooks = {
      onApiKeyRequest: async (): Promise<void> => {
        await Promise.resolve()
        restore = replace(Array.prototype, 'every', () => true)
      }
    }
    let result: number | true | undefined
    try {
      result = await outcome(build(repository(), hooks))
    } finally {
      restore()
    }

    expect(result).toBe(500)
  })

  // Scenario: the step the verifier takes after it has decided, the record of the key's last use, replaces `Array.prototype.every`.
  // Expected: the library's refusal. Why: nothing the verifier checks follows that step, so only a check by the guard after the
  // verification, before it reads the scopes, refuses the replacement, and no audit event says the key was allowed.
  it('is refused when a built-in is replaced after the verifier decided', async () => {
    let restore = (): void => undefined
    const lastUsed = {
      record: (): void => {
        restore = replace(Array.prototype, 'every', () => true)
      }
    }
    const events: string[] = []
    const hooks: IAuthHooks = {
      onApiKeyRequest: (event): void => {
        events.push(event.outcome)
      }
    }
    let result: number | true | undefined
    try {
      result = await outcome(build(repository(), hooks, lastUsed))
    } finally {
      restore()
    }

    expect(result).toBe(500)
    expect(events).not.toContain('allowed')
  })
})
