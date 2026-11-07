/**
 * @fileoverview PasswordResetService — how a password-reset request answers when something fails.
 *
 * `forgot-password` and `resend-otp` acknowledge with 200 whether or not the account exists, so
 * a failure may reach the caller only if it cannot tell the caller whether the account exists:
 *
 *   - a failure BEFORE the account is known (the cooldown store, the account lookup) answers 500
 *     `auth.internal`, because it is the same for every address;
 *   - a failure AFTER the account is known (issuing or storing the code) is logged and still
 *     answers 200, because it happens only for a registered address;
 *   - the resend cooldown is released when the request itself observes a failure, so a retry is not
 *     locked out for a minute, and a send that fails after the response has left never releases it;
 *   - every path, the cooldown hit included, takes at least the anti-enumeration floor, so
 *     releasing the cooldown for registered accounts opens no timing difference.
 *
 * The real `sleep` runs here (no mock) so the floor is measured, not assumed. Kept apart from
 * `password-reset.service.spec.ts` because that file is over the size limit.
 */

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import type { Request } from 'express'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'
import { OtpService } from './otp.service'
import { PasswordResetService } from './password-reset.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'

/** The shared wire contract, read from disk so the floor and the 500 are checked against it. */
const CONTRACT = JSON.parse(
  readFileSync(join(__dirname, '../../../conformance/wire-contract.json'), 'utf8')
) as {
  responseBodies: { passwordResetRequest: { failures: { floorMs: number } } }
  errorCatalog: { statuses: Record<string, number> }
}

/** The anti-enumeration floor the contract states, less the slack a timer may fire early. */
const FLOOR_MS = CONTRACT.responseBodies.passwordResetRequest.failures.floorMs - 5

const JWT_SECRET = 'test-secret-32-characters-minimum'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const mockOptions = {
  passwordReset: {
    method: 'otp' as const,
    tokenTtlSeconds: 3600,
    otpLength: 6,
    otpTtlSeconds: 300
  },
  blockedStatuses: ['banned', 'suspended'],
  jwt: { secret: JWT_SECRET, accessCookieMaxAgeMs: 900_000 },
  hmacKey: HMAC_KEY,
  previousHmacKeys: []
}

const mockUserRepo = { findByEmail: jest.fn(), findById: jest.fn() }
const mockEmailProvider = { sendPasswordResetOtp: jest.fn(), sendPasswordResetToken: jest.fn() }
const mockOtpService = { generate: jest.fn(), store: jest.fn(), verify: jest.fn() }
const mockRedis = { setnx: jest.fn(), del: jest.fn(), set: jest.fn(), get: jest.fn() }

const mockReq = { ip: '1.2.3.4', headers: { 'user-agent': 'TestBrowser' } } as unknown as Request

const REGISTERED = { id: 'u1', status: 'active', tenantId: 'tenant1' }

type Entry = 'initiateReset' | 'resendOtp'
const ENTRIES: Entry[] = ['initiateReset', 'resendOtp']
const dto = { email: 'user@example.com', tenantId: 'tenant1' }

/** The error code a rejected call carried, or `undefined` when it carried none. */
function codeOf(err: unknown): string | undefined {
  if (!(err instanceof AuthException)) return undefined
  return (err.getResponse() as { error?: { code?: string } }).error?.code
}

/** Lets queued continuations and detached tasks run. */
async function flush(): Promise<void> {
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve))
}

/** A service configured for `method`, over the shared doubles. */
async function buildService(method: 'otp' | 'token'): Promise<PasswordResetService> {
  const module = await Test.createTestingModule({
    providers: [
      PasswordResetService,
      {
        provide: BYMAX_AUTH_OPTIONS,
        useValue: { ...mockOptions, passwordReset: { ...mockOptions.passwordReset, method } }
      },
      { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
      { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
      { provide: BYMAX_AUTH_HOOKS, useValue: null },
      { provide: OtpService, useValue: mockOtpService },
      { provide: PasswordService, useValue: {} },
      { provide: AuthRedisService, useValue: mockRedis },
      { provide: SessionService, useValue: {} },
      { provide: BruteForceService, useValue: {} }
    ]
  }).compile()
  return module.get(PasswordResetService)
}

describe('PasswordResetService — a password-reset request that fails', () => {
  let service: PasswordResetService
  let errorSpy: jest.SpyInstance

  /** Runs `entry` and reports how it ended and how long it took. */
  async function run(entry: Entry): Promise<{ elapsedMs: number; error: unknown }> {
    const started = performance.now()
    let error: unknown
    try {
      await service[entry](dto, mockReq)
    } catch (err) {
      error = err
    }
    return { elapsedMs: performance.now() - started, error }
  }

  beforeEach(async () => {
    jest.clearAllMocks()
    mockRedis.setnx.mockResolvedValue(true)
    mockRedis.del.mockResolvedValue(undefined)
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.get.mockResolvedValue(null)
    mockUserRepo.findByEmail.mockResolvedValue(null)
    mockOtpService.generate.mockReturnValue('123456')
    mockOtpService.store.mockResolvedValue(undefined)
    mockEmailProvider.sendPasswordResetOtp.mockResolvedValue(undefined)
    errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

    service = await buildService('otp')
  })

  afterEach(() => {
    errorSpy.mockRestore()
  })

  // Scenario: the cooldown store fails before anything about the account is known. Expected: 500
  // auth.internal after the floor, and nothing to release because no cooldown was taken. Why: the
  // failure is the same for every address, so surfacing it tells the caller nothing about one.
  it.each(ENTRIES)(
    '%s answers 500 after the floor when the cooldown store fails',
    async (entry) => {
      mockRedis.setnx.mockRejectedValue(new Error('redis down'))

      const { elapsedMs, error } = await run(entry)

      expect(codeOf(error)).toBe(AUTH_ERROR_CODES.INTERNAL)
      expect(elapsedMs).toBeGreaterThanOrEqual(FLOOR_MS)
      expect(mockRedis.del).not.toHaveBeenCalled()
      expect(mockUserRepo.findByEmail).not.toHaveBeenCalled()
      expect(errorSpy).toHaveBeenCalledWith(`${entry}: cooldown store failed: <error>`)
    }
  )

  // Scenario: the account lookup fails. Expected: 500 auth.internal after the floor and the
  // cooldown released. Why: the lookup fails the same way for every address; the cooldown taken a
  // moment earlier must not lock the caller out of the retry the 500 invites.
  it.each(ENTRIES)(
    '%s answers 500 after the floor and releases the cooldown when the lookup fails',
    async (entry) => {
      mockUserRepo.findByEmail.mockRejectedValue(new Error('db down'))

      const { elapsedMs, error } = await run(entry)

      expect(codeOf(error)).toBe(AUTH_ERROR_CODES.INTERNAL)
      expect(elapsedMs).toBeGreaterThanOrEqual(FLOOR_MS)
      const [key] = mockRedis.setnx.mock.calls[0] as [string]
      expect(mockRedis.del).toHaveBeenCalledWith(key)
    }
  )

  // Scenario: a cooldown that cannot be released while the lookup is failing. Expected: still the
  // 500, and the release failure is logged. Why: the original failure is the answer.
  it.each(ENTRIES)('%s keeps the 500 when releasing the cooldown also fails', async (entry) => {
    mockUserRepo.findByEmail.mockRejectedValue(new Error('db down'))
    mockRedis.del.mockRejectedValue(new Error('redis down'))

    const { error } = await run(entry)

    expect(codeOf(error)).toBe(AUTH_ERROR_CODES.INTERNAL)
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('cooldown'))
  })

  // Scenario: the account exists and storing the code fails. Expected: the 200 acknowledgement
  // after the floor, the failure logged and the cooldown released. Why: this failure happens only
  // for a registered address, so a 5xx here would answer the enumeration question.
  it.each(ENTRIES)(
    '%s acknowledges, logs and releases the cooldown when storing the code fails',
    async (entry) => {
      mockUserRepo.findByEmail.mockResolvedValue(REGISTERED)
      mockOtpService.store.mockRejectedValue(new Error('redis write failed'))

      const { elapsedMs, error } = await run(entry)

      expect(error).toBeUndefined()
      expect(elapsedMs).toBeGreaterThanOrEqual(FLOOR_MS)
      expect(errorSpy).toHaveBeenCalledWith(`${entry}: unexpected error: <error>`)
      const [key] = mockRedis.setnx.mock.calls[0] as [string]
      expect(mockRedis.del).toHaveBeenCalledWith(key)
    }
  )

  // Scenario: a cooldown hit. Expected: the 200 acknowledgement after the same floor, with no
  // lookup and no release. Why: releasing the cooldown for registered accounts means a retry runs
  // in full while an unregistered address keeps hitting the cooldown, so a cooldown hit must not
  // answer faster than a full run.
  it.each(ENTRIES)('%s takes the floor on a cooldown hit', async (entry) => {
    mockRedis.setnx.mockResolvedValue(false)

    const { elapsedMs, error } = await run(entry)

    expect(error).toBeUndefined()
    expect(elapsedMs).toBeGreaterThanOrEqual(FLOOR_MS)
    expect(mockUserRepo.findByEmail).not.toHaveBeenCalled()
    expect(mockRedis.del).not.toHaveBeenCalled()
  })

  // Scenario: the address is not registered, and the one where everything succeeds. Expected: the
  // 200 acknowledgement after the floor and the cooldown kept. Why: the cooldown is what limits
  // a mail bomb, and it is released only by a failure.
  it.each(ENTRIES)(
    '%s keeps the cooldown and takes the floor when nothing fails',
    async (entry) => {
      const unregistered = await run(entry)
      mockUserRepo.findByEmail.mockResolvedValue(REGISTERED)
      mockRedis.setnx.mockResolvedValue(true)
      const registered = await run(entry)

      expect(unregistered.error).toBeUndefined()
      expect(registered.error).toBeUndefined()
      expect(unregistered.elapsedMs).toBeGreaterThanOrEqual(FLOOR_MS)
      expect(registered.elapsedMs).toBeGreaterThanOrEqual(FLOOR_MS)
      expect(mockRedis.del).not.toHaveBeenCalled()
    }
  )

  // Scenario: the contract states the floor and the pre-existence failure. Expected: the floor is
  // the 300 ms the service waits, and `auth.internal` answers 500 in the shared catalog. Why: the
  // note in the contract is what rust-auth mirrors, so it has to describe what this code does.
  it('states in the shared contract the floor and the status the 500 carries', () => {
    expect(CONTRACT.responseBodies.passwordResetRequest.failures.floorMs).toBe(300)
    expect(CONTRACT.errorCatalog.statuses[AUTH_ERROR_CODES.INTERNAL]).toBe(500)
  })

  // Scenario: the account exists and the mail provider fails AFTER the response has left, however
  // late. Expected: the response does not wait for the send, the failure is logged, and the resend
  // cooldown is never touched. Why: the send is detached from the request, so nothing about it can
  // hold the response, and a release from there would delete the fresh cooldown of a LATER request
  // once the send fails after the cooldown's own lifetime.
  it.each([
    ['otp', 'initiateReset'],
    ['otp', 'resendOtp'],
    ['token', 'initiateReset']
  ] as const)(
    'leaves the cooldown alone when the %s send fails late, through %s',
    async (method, entry) => {
      const svc = await buildService(method)
      mockUserRepo.findByEmail.mockResolvedValue(REGISTERED)
      mockUserRepo.findById.mockResolvedValue({ ...REGISTERED, passwordHash: 'hash' })
      let rejectSend: (err: Error) => void = () => undefined
      const pending = new Promise<void>((_resolve, reject) => {
        rejectSend = reject
      })
      mockEmailProvider.sendPasswordResetOtp.mockReturnValue(pending)
      mockEmailProvider.sendPasswordResetToken.mockReturnValue(pending)

      await svc[entry](dto, mockReq)
      const [cooldownKey] = mockRedis.setnx.mock.calls[0] as [string]
      rejectSend(new Error('smtp down'))
      await flush()

      expect(errorSpy).toHaveBeenCalledWith(expect.stringMatching(/send\w+ failed for user/))
      expect(mockRedis.del.mock.calls.map((call) => call[0])).not.toContain(cooldownKey)
      expect(mockRedis.setnx).toHaveBeenCalledTimes(1)
    }
  )
})
