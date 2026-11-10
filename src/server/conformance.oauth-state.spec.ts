/**
 * @fileoverview Pins the OAuth state record the wire contract declares against what the real
 * `OAuthService` writes, in both directions: a declared field the producer omits is a reader that
 * rejects the record, and a field the contract never declared is a writer drifting off it.
 *
 * @layer Test
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { Test } from '@nestjs/testing'
import type { Request, Response } from 'express'

import { OAUTH_PLUGINS } from './oauth/oauth.constants'
import { OAuthService } from './oauth/oauth.service'
import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from './bymax-auth.constants'
import { AuthRedisService } from './redis/auth-redis.service'
import { SessionService } from './services/session.service'
import { TokenManagerService } from './services/token-manager.service'
import { WorkspaceInvitationAcceptService } from './services/workspace-invitation-accept.service'

interface OAuthStateContract {
  redisKeyPrefixes: Record<string, string>
  recordEncodings: { oauthState: { key: string; fields: string[]; optionalFields: string[] } }
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as OAuthStateContract

const TOKEN = 'ab'.repeat(32)

/** What the service hands Redis when it starts a flow with, or without, an invitation. */
async function written(withInvitation: boolean): Promise<{ key: string; record: string[] }> {
  const set = jest.fn().mockResolvedValue(undefined)
  const module = await Test.createTestingModule({
    providers: [
      OAuthService,
      {
        provide: OAUTH_PLUGINS,
        useValue: [{ name: 'google', authorizeUrl: () => 'https://idp.example/a' }]
      },
      { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: {} },
      { provide: BYMAX_AUTH_HOOKS, useValue: {} },
      { provide: AuthRedisService, useValue: { set } },
      { provide: TokenManagerService, useValue: {} },
      { provide: SessionService, useValue: {} },
      { provide: BYMAX_AUTH_OPTIONS, useValue: { secureCookies: true } },
      { provide: WorkspaceInvitationAcceptService, useValue: {} }
    ]
  }).compile()
  const res = { cookie: jest.fn(), redirect: jest.fn(), setHeader: jest.fn() }

  await module
    .get(OAuthService)
    .initiateOAuth(
      'google',
      't1',
      { headers: {} } as Partial<Request> as Request,
      res as Partial<Response> as Response,
      withInvitation ? TOKEN : undefined
    )

  const [key, value] = set.mock.calls[0] as [string, string]
  return { key, record: Object.keys(JSON.parse(value) as object).sort() }
}

describe('the OAuth state record against the wire contract', () => {
  const declared = contract.recordEncodings.oauthState

  it('writes exactly the declared fields for an ordinary sign-in', async () => {
    const { record } = await written(false)

    expect(record).toEqual([...declared.fields].sort())
  })

  it('adds only the declared optional field when the flow carries an invitation', async () => {
    const { record } = await written(true)

    expect(record).toEqual([...declared.fields, ...declared.optionalFields].sort())
  })

  it('keys the record under the declared prefix by the hash of the state', async () => {
    const { key } = await written(false)

    expect(declared.key).toBe(`${contract.redisKeyPrefixes['oauthState']}:{sha256(state)}`)
    expect(key).toMatch(new RegExp(`^${contract.redisKeyPrefixes['oauthState']}:[0-9a-f]{64}$`))
  })
})
