/**
 * @fileoverview `OAuthModule.register` used on its own, without `BymaxAuthModule`: the consumer supplies the
 * repository, the redis, token and session services and the options, and the module wires everything else,
 * including the guarded view of the user repository that `OAuthService` reads.
 *
 * @layer Test
 */

import { Global, Module } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY,
  GUARDED_USER_REPOSITORY
} from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import type { IUserRepository } from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { SessionService } from '../services/session.service'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { TokenManagerService } from '../services/token-manager.service'
import { OAuthModule } from './oauth.module'
import { OAuthService } from './oauth.service'

/** What the host's repository holds: a record whose prototype getter a copy must keep readable by name. */
class HostUser {
  id = 'u1'
  get email(): string {
    return 'a@b.c'
  }
}

describe('OAuthModule.register on its own', () => {
  // Scenario: the consumer provides the host's repository and the other services, and registers the module
  // without BymaxAuthModule. Expected: the module boots, OAuthService resolves, and the user repository it reads is
  // the guarded view: it answers a copy of the host's record, not the record. Why: OAuthService injects an
  // internal token the package does not export, so the module has to provide it itself or a standalone consumer
  // could never satisfy it.
  it('boots and resolves a user through the guarded copy', async () => {
    const hostRecord = new HostUser()
    const hostRepository = { findById: async (): Promise<unknown> => hostRecord }

    @Global()
    @Module({
      providers: [
        { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: hostRepository },
        { provide: BYMAX_AUTH_OPTIONS, useValue: {} },
        { provide: BYMAX_AUTH_HOOKS, useValue: null },
        { provide: AuthRedisService, useValue: {} },
        { provide: TokenManagerService, useValue: {} },
        { provide: SessionService, useValue: {} },
        { provide: TokenDeliveryService, useValue: {} }
      ],
      exports: [
        BYMAX_AUTH_USER_REPOSITORY,
        BYMAX_AUTH_OPTIONS,
        BYMAX_AUTH_HOOKS,
        AuthRedisService,
        TokenManagerService,
        SessionService,
        TokenDeliveryService
      ]
    })
    class HostModule {}

    const moduleRef = await Test.createTestingModule({
      imports: [HostModule, OAuthModule.register({} as ResolvedOptions)]
    }).compile()
    const view = moduleRef.get<IUserRepository>(GUARDED_USER_REPOSITORY, { strict: false })

    const answered = (await view.findById({ id: 'u1', tenantId: 't1' })) as {
      id: string
      email: string
    }

    expect(moduleRef.get(OAuthService)).toBeInstanceOf(OAuthService)
    expect(answered).not.toBe(hostRecord)
    expect(answered.id).toBe('u1')
    expect(answered.email).toBe('a@b.c')
    await moduleRef.close()
  })
})
