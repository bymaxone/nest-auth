import { Controller, Get } from '@nestjs/common'
import { DiscoveryService, MetadataScanner, Reflector } from '@nestjs/core'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { API_KEY_SCOPES_KEY, ApiKeyScopes } from '../decorators/api-key-scopes.decorator'
import { ApiKeyScopeAuditService } from './api-key-scope-audit.service'
import { makeOptions } from './__tests__/api-key-fixtures'

async function auditOf(...controllers: Array<new () => object>): Promise<() => void> {
  const module = await Test.createTestingModule({
    controllers,
    providers: [
      ApiKeyScopeAuditService,
      MetadataScanner,
      { provide: BYMAX_AUTH_OPTIONS, useValue: makeOptions() }
    ],
    imports: [(await import('@nestjs/core')).DiscoveryModule]
  }).compile()
  const service = module.get(ApiKeyScopeAuditService)
  return () => service.onApplicationBootstrap()
}

describe('ApiKeyScopeAuditService', () => {
  // A vocabulary-clean application boots.
  it('accepts declarations inside the vocabulary', async () => {
    @ApiKeyScopes('admin')
    @Controller('a')
    class Fine {
      @ApiKeyScopes('read', 'operate')
      @Get()
      list(): void {}

      @Get('plain')
      plain(): void {}
    }
    expect((await auditOf(Fine))()).toBeUndefined()
  })

  // A typo on a handler fails the boot and names where.
  it('rejects a handler scope outside the vocabulary and names the route', async () => {
    @Controller('b')
    class Typo {
      @ApiKeyScopes('raed')
      @Get()
      list(): void {}
    }
    const run = await auditOf(Typo)
    expect(run).toThrow(/Typo\.list declares a scope outside apiKeys\.scopes/)
  })

  // A typo on a class fails the boot too.
  it('rejects a class scope outside the vocabulary', async () => {
    @ApiKeyScopes('nope')
    @Controller('c')
    class ClassTypo {
      @Get()
      list(): void {}
    }
    const run = await auditOf(ClassTypo)
    expect(run).toThrow(/ClassTypo declares a scope outside apiKeys\.scopes/)
  })

  // Every offender is reported in one error, not only the first.
  it('reports every offender at once', async () => {
    @Controller('d')
    class Two {
      @ApiKeyScopes('x')
      @Get('a')
      a(): void {}

      @ApiKeyScopes('y')
      @Get('b')
      b(): void {}
    }
    const run = await auditOf(Two)
    expect(run).toThrow(
      /Two\.a declares a scope outside apiKeys\.scopes; Two\.b declares a scope outside apiKeys\.scopes\. Add the scope to apiKeys\.scopes or correct the declaration\./
    )
  })

  // A non-string entry is a declaration outside the vocabulary too.
  it('rejects a non-string scope', async () => {
    @Controller('e')
    class Odd {
      @ApiKeyScopes(1 as unknown as string)
      @Get('a')
      a(): void {}
    }
    expect(await auditOf(Odd)).toThrow(/Odd\.a/)
  })

  // A declaration that is not a list at all is ignored here; the guard already treats it as
  // undeclared and refuses the route per request.
  it('ignores a declaration that is not a list', async () => {
    @Controller('g')
    class NotAList {
      @Get('a')
      a(): void {}
    }
    Reflect.defineMetadata(API_KEY_SCOPES_KEY, 'read', NotAList.prototype.a)
    expect((await auditOf(NotAList))()).toBeUndefined()
  })

  // Declaring nothing is not this service's concern: that is the guard's fail-closed branch.
  it('does not complain about a controller that declares nothing', async () => {
    @Controller('f')
    class Nothing {
      @Get()
      list(): void {}
    }
    expect((await auditOf(Nothing))()).toBeUndefined()
  })

  // Providers that are not controllers, and wrappers without an instance, are skipped.
  it('skips wrappers it cannot inspect', () => {
    const service = new ApiKeyScopeAuditService(
      {
        getControllers: () => [
          { instance: null, metatype: null },
          { instance: {}, metatype: 'x' }
        ]
      } as unknown as DiscoveryService,
      new MetadataScanner(),
      new Reflector(),
      makeOptions()
    )
    expect(() => service.onApplicationBootstrap()).not.toThrow()
  })
})
