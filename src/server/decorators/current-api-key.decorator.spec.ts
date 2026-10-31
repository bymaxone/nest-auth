import type { ExecutionContext } from '@nestjs/common'

import type { ApiKeyPrincipal } from '../interfaces/api-key-repository.interface'
import { CurrentApiKey } from './current-api-key.decorator'

const { ROUTE_ARGS_METADATA } = require('@nestjs/common/constants') as {
  ROUTE_ARGS_METADATA: string
}

function factory(): (data: unknown, ctx: ExecutionContext) => unknown {
  class Controller {
    handler(@CurrentApiKey() key: unknown): unknown {
      return key
    }
  }
  const args = Reflect.getMetadata(ROUTE_ARGS_METADATA, Controller, 'handler') as Record<
    string,
    { factory: (data: unknown, ctx: ExecutionContext) => unknown }
  >
  return args[Object.keys(args)[0] as string]!.factory
}

function contextWith(request: object): ExecutionContext {
  return { switchToHttp: () => ({ getRequest: () => request }) } as unknown as ExecutionContext
}

describe('CurrentApiKey decorator', () => {
  // It hands the handler the principal the guard attached.
  it('returns request.apiKey', () => {
    const principal: ApiKeyPrincipal = { id: 'k', label: 'l', scopes: ['read'] }
    expect(factory()(undefined, contextWith({ apiKey: principal }))).toBe(principal)
  })

  // On a route the guard did not admit there is nothing to return, and it must not invent a
  // principal or fall back to the user.
  it('returns undefined when the guard did not run', () => {
    expect(factory()(undefined, contextWith({ user: { sub: 'u' } }))).toBeUndefined()
  })
})
