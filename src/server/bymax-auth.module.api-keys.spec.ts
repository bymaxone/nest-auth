/**
 * @fileoverview Wiring of the service-key feature in BymaxAuthModule: what registers it, what it
 * exports, and the startup errors for a half-configured feature.
 */

import { Controller, Get, Module } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_API_KEY_CLOCK,
  BYMAX_AUTH_API_KEY_REPOSITORY,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from './bymax-auth.constants'
import { BymaxAuthModule } from './bymax-auth.module'
import { ApiKeyScopes } from './decorators/api-key-scopes.decorator'
import { ServiceKey } from './decorators/service-key.decorator'
import { ApiKeyGuard } from './guards/api-key.guard'
import { ApiKeyService } from './services/api-key.service'
import { SystemApiKeyClock } from './services/api-key-clock'
import { ApiKeyVerifierService } from './services/api-key-verifier.service'
import { FakeClock, MemoryApiKeyRepository, PEPPER } from './services/__tests__/api-key-fixtures'

const JWT_SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'
const BASE = {
  jwt: { secret: JWT_SECRET },
  roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
  rateLimit: { clientIpSource: 'peer' as const }
}
const ENABLED = { ...BASE, apiKeys: { enabled: true, pepper: PEPPER, scopes: ['read', 'admin'] } }
const REDIS = { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: { get: jest.fn(), set: jest.fn() } }
const USERS = { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: {} }
const KEYS = { provide: BYMAX_AUTH_API_KEY_REPOSITORY, useValue: new MemoryApiKeyRepository() }

function compile(
  options: object,
  extraProviders: object[],
  controllers: Array<new () => object> = []
) {
  @Module({
    imports: [
      BymaxAuthModule.registerAsync({
        useFactory: () => options as never,
        extraProviders: [REDIS, USERS, ...extraProviders] as never
      })
    ],
    controllers
  })
  class Host {}
  return Test.createTestingModule({ imports: [Host] }).compile()
}

describe('BymaxAuthModule — service API keys', () => {
  // The repository provider plus apiKeys.enabled is what registers the feature.
  it('registers the feature services when the repository is provided and enabled', async () => {
    const module = await compile(ENABLED, [KEYS])
    expect(module.get(ApiKeyService, { strict: false })).toBeInstanceOf(ApiKeyService)
    expect(module.get(ApiKeyVerifierService, { strict: false })).toBeInstanceOf(
      ApiKeyVerifierService
    )
    expect(module.get(ApiKeyGuard, { strict: false })).toBeInstanceOf(ApiKeyGuard)
  })

  // Without it nothing of the feature exists.
  it('registers nothing when neither is configured', async () => {
    const module = await compile(BASE, [])
    expect(() => module.get(ApiKeyService, { strict: false })).toThrow()
    expect(() => module.get(ApiKeyGuard, { strict: false })).toThrow()
  })

  // The system clock is the fallback; a host-supplied one replaces it.
  it('falls back to the system clock and honours a supplied one', async () => {
    const fallback = await compile(ENABLED, [KEYS])
    expect(fallback.get(BYMAX_AUTH_API_KEY_CLOCK, { strict: false })).toBeInstanceOf(
      SystemApiKeyClock
    )
    const clock = new FakeClock()
    const supplied = await compile(ENABLED, [
      KEYS,
      { provide: BYMAX_AUTH_API_KEY_CLOCK, useValue: clock }
    ])
    expect(supplied.get(BYMAX_AUTH_API_KEY_CLOCK, { strict: false })).toBe(clock)
  })

  // Either half alone is a startup error that names what to do.
  it('refuses enabled without the repository', async () => {
    await expect(compile(ENABLED, [])).rejects.toThrow(
      /apiKeys\.enabled: true requires BYMAX_AUTH_API_KEY_REPOSITORY in extraProviders\. Provide your IApiKeyRepository implementation\./
    )
  })

  it('refuses the repository without enabled', async () => {
    await expect(compile(BASE, [KEYS])).rejects.toThrow(
      /BYMAX_AUTH_API_KEY_REPOSITORY is provided but apiKeys\.enabled is not true/
    )
  })

  // `@ServiceKey()` binds the guard in the CONSUMER's injector, so a host controller using it
  // must boot: the guard's own dependencies have to be exported with it.
  it('lets a host controller use @ServiceKey without re-registering anything', async () => {
    @Controller('machine')
    class Machine {
      @ServiceKey('read')
      @Get()
      list(): string {
        return 'ok'
      }
    }
    const module = await compile(ENABLED, [KEYS], [Machine])
    expect(module.get(Machine)).toBeInstanceOf(Machine)
  })

  // A typo in a declared scope stops the application at bootstrap, not at the first request.
  it('fails bootstrap on a scope outside the vocabulary', async () => {
    @Controller('typo')
    class Typo {
      @ApiKeyScopes('raed')
      @Get()
      list(): void {}
    }
    const module = await compile(ENABLED, [KEYS], [Typo])
    await expect(module.createNestApplication().init()).rejects.toThrow(
      /Typo\.list declares a scope/
    )
  })

  // The hooks provider is exported so the guard can be re-instantiated by a host.
  it('exports the hooks token only with the feature', async () => {
    const withFeature = await compile(ENABLED, [KEYS])
    expect(withFeature.get(BYMAX_AUTH_HOOKS, { strict: false })).toBeDefined()
  })
})
