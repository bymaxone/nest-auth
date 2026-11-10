/**
 * OAuthService — accepting a workspace invitation through the provider, and the sign-up gate of
 * `registration: 'invitation-only'`.
 *
 * Kept apart from `oauth.service.spec.ts` because it is a separate responsibility and that file is
 * already over the size limit.
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import type { Request, Response } from 'express'

import { OAUTH_PLUGINS } from './oauth.constants'
import { OAuthService } from './oauth.service'
import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { SessionService } from '../services/session.service'
import { TokenManagerService } from '../services/token-manager.service'
import { WorkspaceInvitationAcceptService } from '../services/workspace-invitation-accept.service'

const RAW_TOKEN = 'ab'.repeat(32)
const HASH = sha256(RAW_TOKEN)
const STATE = 'c'.repeat(64)

const USER = {
  id: 'user-1',
  email: 'invitee@example.com',
  name: 'Invitee',
  role: 'member',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: false,
  passwordHash: null,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}

const PROFILE = {
  provider: 'google',
  providerId: 'g-1',
  email: 'invitee@example.com',
  emailVerified: true,
  name: 'Invitee'
}

const LOADED = { key: `winv:${HASH}`, record: { kind: 'member' } }

/** A stored state record as the initiating half writes it. */
function stored(extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ provider: 'google', tenantId: 'tenant-1', codeVerifier: 'v', ...extra })
}

/** The code a promise rejects with, or `undefined` when it resolves. */
async function code(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise
  } catch (error) {
    return ((error as AuthException).getResponse() as { error: { code: string } }).error.code
  }
  return undefined
}

const plugin = {
  name: 'google',
  authorizeUrl: jest.fn(),
  exchangeCode: jest.fn(),
  fetchProfile: jest.fn()
}
const users = {
  updateLastLogin: jest.fn(),
  findByOAuthId: jest.fn(),
  findByEmail: jest.fn(),
  createWithOAuth: jest.fn(),
  linkOAuth: jest.fn(),
  findById: jest.fn()
}
const hooks = { onOAuthLogin: jest.fn(), afterLogin: jest.fn() }
const redis = { set: jest.fn(), getdel: jest.fn() }
const tokens = { issueTokens: jest.fn(), issueMfaTempToken: jest.fn() }
const accepts = { prepareOAuth: jest.fn(), completeOAuth: jest.fn() }

/** The service under test, with the resolved options a case needs and the accept service or none. */
async function build(
  registration: 'open' | 'invitation-only' = 'open',
  withAccepts = true
): Promise<OAuthService> {
  const options = {
    sessions: { enabled: false },
    secureCookies: true,
    blockedStatuses: ['BANNED'],
    emailVerification: { required: false },
    registration
  }
  const module = await Test.createTestingModule({
    providers: [
      OAuthService,
      { provide: OAUTH_PLUGINS, useValue: [plugin] },
      { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: users },
      { provide: BYMAX_AUTH_HOOKS, useValue: hooks },
      { provide: AuthRedisService, useValue: redis },
      { provide: TokenManagerService, useValue: tokens },
      { provide: SessionService, useValue: { createSession: jest.fn() } },
      { provide: BYMAX_AUTH_OPTIONS, useValue: options },
      ...(withAccepts ? [{ provide: WorkspaceInvitationAcceptService, useValue: accepts }] : [])
    ]
  }).compile()
  return module.get(OAuthService)
}

/** Runs a callback whose state record is `record`, for an existing account or none. */
function callback(service: OAuthService, record: string): Promise<unknown> {
  redis.getdel.mockResolvedValue(record)
  return service.handleCallback('google', 'code', STATE, STATE, '1.2.3.4', 'jest', {})
}

describe('OAuthService with workspace invitations', () => {
  beforeEach(() => {
    jest.resetAllMocks()
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
    plugin.exchangeCode.mockResolvedValue({ access_token: 'at' })
    plugin.fetchProfile.mockResolvedValue(PROFILE)
    users.findByOAuthId.mockResolvedValue(null)
    users.findByEmail.mockResolvedValue(null)
    users.createWithOAuth.mockResolvedValue(USER)
    users.updateLastLogin.mockResolvedValue(undefined)
    hooks.onOAuthLogin.mockResolvedValue({ action: 'create' })
    tokens.issueTokens.mockResolvedValue({ user: USER, accessToken: 'a', rawRefreshToken: 'r' })
    accepts.prepareOAuth.mockResolvedValue(LOADED)
    accepts.completeOAuth.mockResolvedValue({ workspaceId: 'w1', role: 'viewer' })
  })

  describe('initiating a flow', () => {
    const res = { cookie: jest.fn(), redirect: jest.fn(), setHeader: jest.fn() }
    const req = { headers: {} } as Partial<Request> as Request

    beforeEach(() => {
      plugin.authorizeUrl.mockImplementation(
        (state: string) => `https://idp.example/a?state=${state}`
      )
      redis.set.mockResolvedValue(undefined)
    })

    it('stores only the sha256 of the token in the state record, never the token', async () => {
      const service = await build()

      await service.initiateOAuth(
        'google',
        'tenant-1',
        req,
        res as Partial<Response> as Response,
        RAW_TOKEN
      )

      const [key, value] = redis.set.mock.calls[0] as [string, string]
      expect(JSON.parse(value)).toMatchObject({ workspaceInvitation: HASH })
      expect(key + value).not.toContain(RAW_TOKEN)
    })

    it('writes no invitation field when the flow carries none', async () => {
      const service = await build()

      await service.initiateOAuth('google', 'tenant-1', req, res as Partial<Response> as Response)

      const [, value] = redis.set.mock.calls[0] as [string, string]
      expect(Object.keys(JSON.parse(value) as object)).not.toContain('workspaceInvitation')
    })

    it('answers with Referrer-Policy: no-referrer and still binds the flow to the browser', async () => {
      const service = await build()

      await service.initiateOAuth(
        'google',
        'tenant-1',
        req,
        res as Partial<Response> as Response,
        RAW_TOKEN
      )

      expect(res.setHeader).toHaveBeenCalledWith('Referrer-Policy', 'no-referrer')
      const state = (res.redirect.mock.calls[0] as [string])[0].split('state=')[1]
      expect(res.cookie).toHaveBeenCalledWith('oauth_state', state, expect.any(Object))
    })

    it('refuses a token when workspaces are not enabled, storing nothing', async () => {
      const service = await build('open', false)

      const refused = service.initiateOAuth(
        'google',
        'tenant-1',
        req,
        res as Partial<Response> as Response,
        RAW_TOKEN
      )

      expect(await code(refused)).toBe(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
      expect(redis.set).not.toHaveBeenCalled()
    })
  })

  describe('the invitation-only gate', () => {
    it('refuses to create an account without an invitation, creating nothing', async () => {
      const service = await build('invitation-only')

      expect(await code(callback(service, stored()))).toBe(AUTH_ERROR_CODES.REGISTRATION_CLOSED)

      expect(users.createWithOAuth).not.toHaveBeenCalled()
      expect(tokens.issueTokens).not.toHaveBeenCalled()
    })

    it('lets an existing linked account sign in', async () => {
      const service = await build('invitation-only')
      users.findByOAuthId.mockResolvedValue(USER)
      hooks.onOAuthLogin.mockResolvedValue({ action: 'link' })
      users.linkOAuth.mockResolvedValue(undefined)
      users.findById.mockResolvedValue(USER)

      await expect(callback(service, stored())).resolves.toMatchObject({ accessToken: 'a' })
    })

    it('lets an invitation create the account it was addressed to', async () => {
      const service = await build('invitation-only')

      await expect(callback(service, stored({ workspaceInvitation: HASH }))).resolves.toMatchObject(
        { accessToken: 'a' }
      )

      expect(users.createWithOAuth).toHaveBeenCalledTimes(1)
    })
  })

  describe('accepting through the callback', () => {
    it('vets the invitation against the profile before the hook runs, and completes it for the created account', async () => {
      const service = await build()

      await callback(service, stored({ workspaceInvitation: HASH }))

      expect(accepts.prepareOAuth).toHaveBeenCalledWith(HASH, 'tenant-1', {
        email: PROFILE.email,
        emailVerified: true
      })
      expect(accepts.prepareOAuth.mock.invocationCallOrder[0]).toBeLessThan(
        hooks.onOAuthLogin.mock.invocationCallOrder[0] as number
      )
      expect(accepts.completeOAuth).toHaveBeenCalledWith(
        LOADED,
        USER,
        true,
        expect.objectContaining({ tenantId: 'tenant-1', email: PROFILE.email, userId: USER.id })
      )
    })

    it('tells the vetting when the provider did not verify the address', async () => {
      const service = await build()
      plugin.fetchProfile.mockResolvedValue({ ...PROFILE, emailVerified: false })

      await callback(service, stored({ workspaceInvitation: HASH }))

      expect(accepts.prepareOAuth).toHaveBeenCalledWith(HASH, 'tenant-1', {
        email: PROFILE.email,
        emailVerified: false
      })
    })

    it('completes it for an existing account as one that was not created', async () => {
      const service = await build()
      users.findByOAuthId.mockResolvedValue(USER)
      hooks.onOAuthLogin.mockResolvedValue({ action: 'link' })
      users.linkOAuth.mockResolvedValue(undefined)
      users.findById.mockResolvedValue(USER)

      await callback(service, stored({ workspaceInvitation: HASH }))

      expect(accepts.completeOAuth).toHaveBeenCalledWith(LOADED, USER, false, expect.anything())
    })

    it('refuses before the hook or any account is touched when the invitation cannot be honoured', async () => {
      const service = await build()
      accepts.prepareOAuth.mockRejectedValue(
        Object.assign(new Error('x'), {
          getResponse: () => ({ error: { code: AUTH_ERROR_CODES.INVITATION_EMAIL_MISMATCH } })
        })
      )

      expect(await code(callback(service, stored({ workspaceInvitation: HASH })))).toBe(
        AUTH_ERROR_CODES.INVITATION_EMAIL_MISMATCH
      )

      expect(hooks.onOAuthLogin).not.toHaveBeenCalled()
      expect(users.createWithOAuth).not.toHaveBeenCalled()
    })

    it('issues no tokens when completing refuses', async () => {
      const service = await build()
      accepts.completeOAuth.mockRejectedValue(
        Object.assign(new Error('x'), {
          getResponse: () => ({ error: { code: AUTH_ERROR_CODES.WORKSPACE_LIMIT_REACHED } })
        })
      )

      expect(await code(callback(service, stored({ workspaceInvitation: HASH })))).toBe(
        AUTH_ERROR_CODES.WORKSPACE_LIMIT_REACHED
      )

      expect(tokens.issueTokens).not.toHaveBeenCalled()
    })

    it('does not complete for an account that has a second factor, leaving the token for the signed-in route', async () => {
      const service = await build()
      users.createWithOAuth.mockResolvedValue({ ...USER, mfaEnabled: true })
      tokens.issueMfaTempToken.mockResolvedValue('temp')

      await expect(callback(service, stored({ workspaceInvitation: HASH }))).resolves.toEqual({
        mfaRequired: true,
        mfaTempToken: 'temp'
      })

      expect(accepts.completeOAuth).not.toHaveBeenCalled()
    })

    it('does not complete for a blocked account', async () => {
      const service = await build()
      users.createWithOAuth.mockResolvedValue({ ...USER, status: 'BANNED' })

      expect(await code(callback(service, stored({ workspaceInvitation: HASH })))).toBeDefined()

      expect(accepts.completeOAuth).not.toHaveBeenCalled()
    })

    it.each([
      ['a hash of the wrong length', { workspaceInvitation: 'abc' }],
      ['a hash one character short', { workspaceInvitation: HASH.slice(1) }],
      ['a hash that is not a string', { workspaceInvitation: 5 }]
    ])('refuses a state record carrying %s', async (_n, extra) => {
      const service = await build()

      expect(await code(callback(service, stored(extra)))).toBe(AUTH_ERROR_CODES.OAUTH_FAILED)
    })

    it('refuses a record that names an invitation when workspaces are not enabled', async () => {
      const service = await build('open', false)

      expect(await code(callback(service, stored({ workspaceInvitation: HASH })))).toBe(
        AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN
      )
      expect(users.createWithOAuth).not.toHaveBeenCalled()
    })
  })

  describe('what the library logs', () => {
    it('never records the raw token across a flow that succeeds and one that fails', async () => {
      const sinks = (['log', 'warn', 'error', 'debug', 'verbose'] as const).map((level) =>
        jest.spyOn(Logger.prototype, level).mockImplementation(() => undefined)
      )
      const service = await build()
      plugin.authorizeUrl.mockImplementation((state: string) => `https://idp/a?state=${state}`)
      redis.set.mockResolvedValue(undefined)
      const res = { cookie: jest.fn(), redirect: jest.fn(), setHeader: jest.fn() }
      await service.initiateOAuth(
        'google',
        'tenant-1',
        { headers: {} } as Partial<Request> as Request,
        res as Partial<Response> as Response,
        RAW_TOKEN
      )
      await callback(service, stored({ workspaceInvitation: HASH }))
      accepts.prepareOAuth.mockRejectedValue(new Error('refused'))
      await callback(service, stored({ workspaceInvitation: HASH })).catch(() => undefined)

      const logged = JSON.stringify(sinks.flatMap((sink) => sink.mock.calls))
      expect(logged).not.toContain(RAW_TOKEN)
    })
  })
})
