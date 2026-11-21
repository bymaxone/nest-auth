/**
 * @fileoverview The library's services read the host's repository through a guarded view, and the token the module
 * exports is still the host's own instance.
 *
 * @layer Test
 */

import { Inject, Injectable } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_REDIS_CLIENT, BYMAX_AUTH_USER_REPOSITORY } from './bymax-auth.constants'
import { BymaxAuthModule } from './bymax-auth.module'
import { AuthService } from './services/auth.service'

const OPTIONS = {
  jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
  roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
  rateLimit: { clientIpSource: 'peer' as const }
}

@Injectable()
class RepoProbe {
  constructor(@Inject(BYMAX_AUTH_USER_REPOSITORY) readonly repo: unknown) {}
}

describe('BymaxAuthModule guarded repository view', () => {
  // Scenario: a host registers its user repository. Expected: AuthService is not handed the host's instance, what it
  // reads back is a copy of the host's record (nested arrays included), and a module that injects the exported token
  // gets the host's own instance. Why: a failed read of a record must end in the library's error, while a host
  // that injects the token from this module keeps its own repository.
  it('gives the library services the guarded view and keeps the exported token the host instance', async () => {
    const record = { id: 'u1', scopes: ['a'] }
    const repository = { findByEmail: jest.fn().mockResolvedValue(record) }
    const module = await Test.createTestingModule({
      imports: [
        BymaxAuthModule.registerAsync({
          useFactory: () => OPTIONS,
          extraProviders: [
            { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: {} },
            { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: repository }
          ]
        })
      ],
      providers: [RepoProbe]
    }).compile()

    const seen = Reflect.get(module.get(AuthService), 'userRepo') as typeof repository
    const answered = (await seen.findByEmail()) as typeof record

    expect(seen).not.toBe(repository)
    expect(answered).toEqual(record)
    expect(answered).not.toBe(record)
    expect(answered.scopes).not.toBe(record.scopes)
    expect(module.get(RepoProbe).repo).toBe(repository)
  })

  // Scenario: a host repository with lifecycle hooks, in a module that is initialised and closed. Expected: each hook
  // runs once. Why: the guarded view is a second provider over the same repository, and Nest calls a hook on every
  // provider instance it finds.
  it('runs the lifecycle hooks of the host repository once', async () => {
    const repository = {
      onModuleInit: jest.fn(),
      onModuleDestroy: jest.fn(),
      findByEmail: jest.fn()
    }
    const module = await Test.createTestingModule({
      imports: [
        BymaxAuthModule.registerAsync({
          useFactory: () => OPTIONS,
          extraProviders: [
            {
              provide: BYMAX_AUTH_REDIS_CLIENT,
              useValue: { ping: jest.fn().mockResolvedValue('PONG') }
            },
            { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: repository }
          ]
        })
      ]
    }).compile()

    await module.init()
    await module.close()

    expect(repository.onModuleInit).toHaveBeenCalledTimes(1)
    expect(repository.onModuleDestroy).toHaveBeenCalledTimes(1)
  })
})
