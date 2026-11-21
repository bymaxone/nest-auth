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
    const record = { id: 'u1', tags: ['a'] }
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

    const seen = (module.get(AuthService) as unknown as { userRepo: typeof repository }).userRepo
    const answered = (await seen.findByEmail()) as typeof record

    expect(seen).not.toBe(repository)
    expect(answered).toEqual(record)
    expect(answered).not.toBe(record)
    expect(answered.tags).not.toBe(record.tags)
    expect(module.get(RepoProbe).repo).toBe(repository)
  })
})
