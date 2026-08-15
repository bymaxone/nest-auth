/**
 * Unit tests for {@link EmailChangeService}.
 *
 * The address is the account's recovery credential — whoever controls it can drive a password
 * reset to a mailbox the owner does not read. Every test here is about one of the three things
 * that makes moving it safe: the password is re-proved, the new address is proved before it is
 * adopted, and the old address is told.
 *
 * @layer Service
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { hmacSha256, sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { EmailChangeService } from './email-change.service'
import { BruteForceService } from './brute-force.service'
import { PasswordService } from './password.service'

const USER = {
  id: 'user-1',
  email: 'old@example.com',
  name: 'Test User',
  passwordHash: 'scrypt:salt:hash',
  role: 'member',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}

const TOKEN = 'a'.repeat(64)
const NEW_EMAIL = 'new@example.com'

const mockUserRepo = {
  findById: jest.fn(),
  findByEmail: jest.fn(),
  updateEmail: jest.fn()
}

const mockEmailProvider = {
  sendEmailChangeVerification: jest.fn(),
  sendEmailChangedNotification: jest.fn()
}

const mockPasswordService = {
  compare: jest.fn()
}

const mockRedis = {
  set: jest.fn(),
  getdel: jest.fn()
}

/** The password re-proof is counted like a login; unlocked and quiet unless a case says otherwise. */
const mockBruteForce = {
  isLockedOut: jest.fn().mockResolvedValue(false),
  recordFailure: jest.fn(),
  resetFailures: jest.fn()
}

const mockOptions = {
  // The re-proof counter keys on an HMAC of the account id, so the fixture needs the key.
  hmacKey: 'test-hmac-key',
  emailChange: { tokenTtlSeconds: 3600 },
  // The confirmation re-reads the account's standing, so the service needs the same blocked
  // set every other status gate reads.
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED']
}

/** The stored record a valid token resolves to. */
function storedContext(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    userId: 'user-1',
    newEmail: NEW_EMAIL,
    tenantId: 'tenant-1',
    passwordFingerprint: sha256(USER.passwordHash),
    ...overrides
  })
}

describe('EmailChangeService', () => {
  let service: EmailChangeService

  beforeEach(async () => {
    jest.resetAllMocks()
    mockUserRepo.findById.mockResolvedValue(USER)
    mockUserRepo.findByEmail.mockResolvedValue(null)
    mockUserRepo.updateEmail.mockResolvedValue(undefined)
    mockPasswordService.compare.mockResolvedValue(true)
    mockRedis.set.mockResolvedValue(undefined)
    mockEmailProvider.sendEmailChangeVerification.mockResolvedValue(undefined)
    mockEmailProvider.sendEmailChangedNotification.mockResolvedValue(undefined)

    const module = await Test.createTestingModule({
      providers: [
        EmailChangeService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
        { provide: PasswordService, useValue: mockPasswordService },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: BruteForceService, useValue: mockBruteForce }
      ]
    }).compile()

    service = module.get(EmailChangeService)
  })

  // ---------------------------------------------------------------------------
  // onModuleInit
  // ---------------------------------------------------------------------------

  describe('onModuleInit', () => {
    // A deployment that enables the flow without a way to deliver the token would mint `ec:`
    // keys nobody ever receives — a failure that looks like success from every side, and that
    // a user experiences as a verification email that simply never arrives.
    it('refuses to boot when the provider cannot deliver the verification', () => {
      const providerWithout = {} as never
      const withoutSender = new EmailChangeService(
        mockOptions as never,
        mockUserRepo as never,
        providerWithout,
        mockPasswordService as never,
        mockRedis as never,
        mockBruteForce as never
      )

      // Both halves of the message: it has to name the flag that turned the flow on AND the
      // method that is missing, or an operator reading a startup crash has to go and find out
      // which of the two the library meant.
      expect(() => withoutSender.onModuleInit()).toThrow(/controllers\.emailChange is enabled/)
      expect(() => withoutSender.onModuleInit()).toThrow(/sendEmailChangeVerification/)
      expect(() => withoutSender.onModuleInit()).toThrow(/cannot deliver/)
      // …including the closing half, which is the part that says the flow is dead rather than
      // degraded. Truncated to "cannot deliver" it reads as a warning about one address.
      expect(() => withoutSender.onModuleInit()).toThrow(/its token without it/)
    })

    it('boots when the provider can deliver it', () => {
      expect(() => service.onModuleInit()).not.toThrow()
    })
  })

  // ---------------------------------------------------------------------------
  // requestChange
  // ---------------------------------------------------------------------------

  describe('requestChange', () => {
    const dto = { newEmail: NEW_EMAIL, currentPassword: 'right' }

    // This send is AWAITED, so a rejection leaves the service and reaches `AuthExceptionFilter`,
    // which logs an unknown exception. A relay that rejects by quoting the body puts the raw
    // change token into that error — so propagating the provider's error unchanged would publish
    // the credential through this library's own filter, with no consumer able to intervene. What
    // escapes is redacted, and the assertion is that the token the provider was handed is absent.
    it('does not let a quoted token escape in the error it propagates', async () => {
      mockEmailProvider.sendEmailChangeVerification.mockImplementation(
        (_t: string, _e: string, token: string) =>
          Promise.reject(new Error(`550 rejected: "Confirm with ${token}."`))
      )

      // One call, and the error from THAT call — a second `requestChange` would mint a different
      // token, so comparing the first token against the second error could pass by accident.
      const thrown = (await service.requestChange('user-1', dto).catch((e: unknown) => e)) as Error
      const sent = mockEmailProvider.sendEmailChangeVerification.mock.calls[0]?.[2] as string

      expect(sent).toMatch(/^[0-9a-f]{64}$/)
      expect(thrown.message).not.toContain(sent)
      expect(thrown.message).toContain('<redacted>')
    })

    // The happy path, and every property of the stored record that the confirmation relies on.
    it('mails a token to the new address and stores the pending change', async () => {
      await service.requestChange('user-1', dto)

      expect(mockEmailProvider.sendEmailChangeVerification).toHaveBeenCalledTimes(1)
      const [tenant, addressed, token] = mockEmailProvider.sendEmailChangeVerification.mock
        .calls[0] as [string, string, string]
      expect(tenant).toBe('tenant-1')
      // The token goes to the NEW address and nowhere else — receiving it is the proof.
      expect(addressed).toBe(NEW_EMAIL)
      expect(token).toMatch(/^[0-9a-f]{64}$/)

      // …stored under the hash of that token, never the token itself.
      const [key, value, ttl] = mockRedis.set.mock.calls[0] as [string, string, number]
      expect(key).toBe(`ec:${sha256(token)}`)
      expect(ttl).toBe(3600)
      expect(JSON.parse(value)).toEqual({
        userId: 'user-1',
        newEmail: NEW_EMAIL,
        tenantId: 'tenant-1',
        // Bound to the password in force right now, so a planted request dies the moment the
        // victim changes their password.
        passwordFingerprint: sha256(USER.passwordHash)
      })
    })

    // Nothing about the account changes at request time. A flow that wrote the address here
    // and verified afterwards would hand an attacker the account for the length of the TTL.
    it('changes nothing about the account', async () => {
      await service.requestChange('user-1', dto)

      expect(mockUserRepo.updateEmail).not.toHaveBeenCalled()
    })

    // The password re-prove is the gate that stops a stolen access token from moving the
    // recovery address. Without it, a thief with a token takes the account outright.
    it('refuses a wrong current password and mints nothing', async () => {
      mockPasswordService.compare.mockResolvedValue(false)

      await expect(service.requestChange('user-1', dto)).rejects.toThrow(AuthException)
      expect(mockRedis.set).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendEmailChangeVerification).not.toHaveBeenCalled()
    })

    // `login` refuses an account after N wrong passwords. This door asks for the SAME secret
    // and used to refuse nothing, so a caller holding a stolen access token but not the
    // password could guess it here without limit — and winning it moves the address the account
    // recovers through, which is persistence rather than a single theft. The per-route IP limit
    // is not that control: a distributed caller sidesteps it, and it is not keyed to the
    // account under attack.
    it('refuses once the re-proof failure budget for this account is spent', async () => {
      mockBruteForce.isLockedOut.mockResolvedValueOnce(true)

      await expect(service.requestChange('user-1', dto)).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.ACCOUNT_LOCKED } }
      })
      // Refused before the KDF, so a locked account is not an amplifier either.
      expect(mockPasswordService.compare).not.toHaveBeenCalled()
      expect(mockRedis.set).not.toHaveBeenCalled()
    })

    // The budget is keyed to THIS account and THIS flow, which is the whole reason it is a
    // separate counter. Two failures are possible here and both are severe in opposite
    // directions: a key that drops the user id gives every account one shared counter, so any
    // caller's failures lock out every user in the deployment; a key that drops the flow prefix
    // merges this budget with `login`'s, so guessing here locks the owner out of signing in.
    it('keys the failure budget to the account and to this flow alone', async () => {
      await service.requestChange('user-1', dto)

      expect(mockBruteForce.isLockedOut).toHaveBeenCalledWith(
        hmacSha256('reauth:email-change:user-1', 'test-hmac-key')
      )
    })

    // The control for the test above: two accounts must not share one counter, or a single
    // caller's failures lock out every user in the deployment.
    it('gives two accounts two different budgets', async () => {
      await service.requestChange('user-1', dto)
      const first = mockBruteForce.isLockedOut.mock.calls[0]?.[0]
      mockBruteForce.isLockedOut.mockClear()
      mockUserRepo.findById.mockResolvedValue({ ...USER, id: 'user-2' })

      await service.requestChange('user-2', dto)

      expect(mockBruteForce.isLockedOut.mock.calls[0]?.[0]).not.toBe(first)
    })

    // The lockout is answered with `account_locked`, which says nothing about which account or
    // why, so this line is the only record naming the user whose re-proof budget ran out — the
    // signal that someone holding a token is guessing at the password behind it.
    it('names the account whose budget ran out', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockBruteForce.isLockedOut.mockResolvedValueOnce(true)

      await expect(service.requestChange('user-1', dto)).rejects.toThrow(AuthException)

      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('userId=user-1'))
      warnSpy.mockRestore()
    })

    it('counts a wrong current password against that budget', async () => {
      mockPasswordService.compare.mockResolvedValue(false)
      mockBruteForce.recordFailure.mockClear()

      await expect(service.requestChange('user-1', dto)).rejects.toBeDefined()

      expect(mockBruteForce.recordFailure).toHaveBeenCalledTimes(1)
    })

    it('clears the budget once the current password is proved', async () => {
      mockBruteForce.resetFailures.mockClear()

      await service.requestChange('user-1', dto)

      expect(mockBruteForce.resetFailures).toHaveBeenCalledTimes(1)
    })

    // An account that cannot prove a password it does not have, and a subject that no longer
    // exists, answer identically — the caller learns nothing either way.
    it.each([
      ['the account no longer exists', null],
      ['the account has no local password', { ...USER, passwordHash: null }]
    ])('refuses when %s', async (_label, found) => {
      mockUserRepo.findById.mockResolvedValue(found)

      await expect(service.requestChange('user-1', dto)).rejects.toThrow(AuthException)
      expect(mockRedis.set).not.toHaveBeenCalled()
    })

    // Moving to an address someone else holds would put two accounts on one recovery
    // credential; moving to the account's own is a change that changes nothing and would send
    // a verification for a move that is not happening.
    it.each([
      ['another account in the tenant holds it', { ...USER, id: 'someone-else' }, NEW_EMAIL],
      ['it is the account own address', null, USER.email]
    ])('refuses when %s', async (_label, existing, target) => {
      mockUserRepo.findByEmail.mockResolvedValue(existing)

      await expect(service.requestChange('user-1', { ...dto, newEmail: target })).rejects.toThrow(
        AuthException
      )
      expect(mockRedis.set).not.toHaveBeenCalled()
    })

    // The uniqueness check runs in the caller's own tenant. Checking globally would refuse an
    // address another tenant legitimately holds; checking the wrong tenant would let a
    // collision through.
    it('checks uniqueness within the caller tenant', async () => {
      await service.requestChange('user-1', dto)

      expect(mockUserRepo.findByEmail).toHaveBeenCalledWith(NEW_EMAIL, 'tenant-1')
    })

    // Normalized on the way in, so the address is stored, mailed and checked in the one form
    // login resolves an account by. A stored `New@Example.COM` would never match a lookup.
    it('normalizes the target address before doing anything with it', async () => {
      await service.requestChange('user-1', { ...dto, newEmail: '  NEW@Example.COM  ' })

      expect(mockUserRepo.findByEmail).toHaveBeenCalledWith(NEW_EMAIL, 'tenant-1')
      const [, addressed] = mockEmailProvider.sendEmailChangeVerification.mock.calls[0] as [
        string,
        string
      ]
      expect(addressed).toBe(NEW_EMAIL)
      expect(JSON.parse((mockRedis.set.mock.calls[0] as string[])[1] ?? '{}')).toMatchObject({
        newEmail: NEW_EMAIL
      })
    })

    // The refusal names the account, so an operator can tell a user fumbling their own password
    // from someone working through a stolen access token.
    it('logs which account had its password rejected', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockPasswordService.compare.mockResolvedValue(false)

      await expect(service.requestChange('user-1', dto)).rejects.toThrow(AuthException)

      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).toContain('current password rejected')
      expect(warned).toContain('userId=user-1')
      warnSpy.mockRestore()
    })

    // The address is masked in the log. An operator needs to see that a change was requested;
    // they do not need the address, and a log aggregator is not where it should end up.
    it('masks the address in the log', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      await service.requestChange('user-1', dto)

      const logged = logSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(logged).toContain('requestChange: verification sent')
      expect(logged).not.toContain(NEW_EMAIL)
      logSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // confirmChange
  // ---------------------------------------------------------------------------

  describe('confirmChange', () => {
    beforeEach(() => {
      mockRedis.getdel.mockResolvedValue(storedContext())
    })

    it('applies the change and notifies the old address', async () => {
      await service.confirmChange({ token: TOKEN })

      expect(mockRedis.getdel).toHaveBeenCalledWith(`ec:${sha256(TOKEN)}`)
      expect(mockUserRepo.updateEmail).toHaveBeenCalledWith('user-1', NEW_EMAIL)
      // The notice goes to the address the account is LEAVING — the last message the owner can
      // receive somewhere they still control, and what turns a silent takeover into a visible
      // one (NIST SP 800-63B §4.6).
      expect(mockEmailProvider.sendEmailChangedNotification).toHaveBeenCalledWith(
        'tenant-1',
        'old@example.com',
        NEW_EMAIL
      )
    })

    // A suspension landing between the request and the confirmation stops the change. The two
    // are separated by the whole token TTL, so a link minted while the account was in good
    // standing is still in a mailbox when the suspension happens — and the address it moves is
    // where a password reset is sent, which makes it the one field a blocked account most needs
    // to be unable to change, since changing it is how a suspension gets undone from outside.
    it('refuses the confirmation once the account has been blocked', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...USER, status: 'SUSPENDED' })

      await expect(service.confirmChange({ token: TOKEN })).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.ACCOUNT_SUSPENDED } }
      })
      expect(mockUserRepo.updateEmail).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendEmailChangedNotification).not.toHaveBeenCalled()
    })

    // The SECOND log line the same failure reaches. The provider strips the addresses from its
    // own line, but under `onDeliveryError: 'rethrow'` the original error arrives here and this
    // catch logs it too — and this notification renders the new address into its body, so a relay
    // that rejects by quoting it puts the address into this entry. Containing a value in one place
    // and not the other contains it nowhere.
    it('keeps the addresses out of the notification-failure log', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      try {
        mockEmailProvider.sendEmailChangedNotification.mockRejectedValue(
          new Error(`550 rejected: "... changed to ${NEW_EMAIL} ..."`)
        )

        await service.confirmChange({ token: TOKEN })

        const logged = loggerSpy.mock.calls.map((c) => String(c[0])).join(' | ')
        expect(logged).toContain('notification to the previous address failed')
        expect(logged).not.toContain(NEW_EMAIL)
        expect(logged).toContain('<redacted>')
      } finally {
        loggerSpy.mockRestore()
      }
    })

    // The old address is read from the ACCOUNT at confirm time, not from the token. A record
    // that outlived an intervening change still notifies wherever the account actually is.
    it('notifies the address the account currently holds, not one the token remembers', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...USER, email: 'moved-since@example.com' })

      await service.confirmChange({ token: TOKEN })

      expect(mockEmailProvider.sendEmailChangedNotification).toHaveBeenCalledWith(
        'tenant-1',
        'moved-since@example.com',
        NEW_EMAIL
      )
    })

    // Single-use: the read and the delete are one operation, so a link that is clicked twice
    // — or raced — applies once.
    it('consumes the token atomically', async () => {
      mockRedis.getdel.mockResolvedValue(null)

      await expect(service.confirmChange({ token: TOKEN })).rejects.toThrow(AuthException)
      expect(mockUserRepo.updateEmail).not.toHaveBeenCalled()
    })

    // A record that is not one, by every route it can fail: unparseable, the wrong shape, and
    // each field individually absent.
    it.each([
      ['unparseable JSON', 'not-json'],
      ['the wrong shape', '{"nope":true}'],
      ['no userId', JSON.stringify({ newEmail: NEW_EMAIL, tenantId: 't1' })],
      ['no newEmail', JSON.stringify({ userId: 'u', tenantId: 't1' })],
      ['no tenantId', JSON.stringify({ userId: 'u', newEmail: NEW_EMAIL })]
    ])('refuses a stored record with %s', async (_label, raw) => {
      mockRedis.getdel.mockResolvedValue(raw)

      await expect(service.confirmChange({ token: TOKEN })).rejects.toThrow(AuthException)
      expect(mockUserRepo.updateEmail).not.toHaveBeenCalled()
    })

    // The account was deleted between the request and the confirmation.
    it('refuses when the account named by the token is gone', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(service.confirmChange({ token: TOKEN })).rejects.toThrow(AuthException)
      expect(mockUserRepo.updateEmail).not.toHaveBeenCalled()
    })

    // The binding to the password. An attacker who plants a change request and waits loses it
    // the moment the victim changes their password — which is the first thing a victim does.
    it('refuses a token no longer bound to the account password', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...USER, passwordHash: 'scrypt:new:hash' })

      await expect(service.confirmChange({ token: TOKEN })).rejects.toThrow(AuthException)
      expect(mockUserRepo.updateEmail).not.toHaveBeenCalled()
    })

    // The mirror case: the token was minted against a password the account has since LOST —
    // converted to OAuth-only, say. The binding no longer matches, and it is refused rather
    // than treated as unbound: a token that outlives the credential it was tied to is exactly
    // what the binding exists to catch.
    it('refuses a token whose account no longer has a password at all', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...USER, passwordHash: null })

      await expect(service.confirmChange({ token: TOKEN })).rejects.toThrow(AuthException)
      expect(mockUserRepo.updateEmail).not.toHaveBeenCalled()
    })

    // …and the account that had no password when the token was minted and has one now.
    it('refuses when a password was set after the token was minted', async () => {
      mockRedis.getdel.mockResolvedValue(storedContext({ passwordFingerprint: '' }))
      mockUserRepo.findById.mockResolvedValue({ ...USER, passwordHash: 'scrypt:brand:new' })

      // An empty stored fingerprint is read as "no binding" and accepted, so this one goes
      // through: refusing it would break every change in flight across a rolling deploy.
      await expect(service.confirmChange({ token: TOKEN })).resolves.toBeUndefined()
    })

    // A fingerprint of the wrong TYPE is a corrupted record, not a legacy one. This used to be
    // read as "no binding" and accepted, on the reasoning that the field comes from a record
    // the engine did not necessarily write — but that reasoning inverts: a value of unknown
    // provenance is the last thing that should decide whether the binding is skipped, and the
    // wire contract makes the field a string in every case (the digest, or `''`). Absence is
    // the only shape that means "predates the binding", and it is spelled by the field being
    // gone, not by it holding something else.
    it.each([
      ['a number', 42],
      ['an object', { digest: 'x' }],
      ['null, which is a value and not an absence', null]
    ])('refuses a record whose fingerprint is %s', async (_label, fingerprint) => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockRedis.getdel.mockResolvedValue(storedContext({ passwordFingerprint: fingerprint }))

      await expect(service.confirmChange({ token: TOKEN })).rejects.toThrow(AuthException)
      expect(mockUserRepo.updateEmail).not.toHaveBeenCalled()

      // Refused as a MALFORMED RECORD, and the difference is not visible in the response —
      // both refusals answer the same `email_change_token_invalid`, deliberately. It is visible
      // here: `assertStillBound` announces "no longer bound to the account password", which
      // asserts something specific and false about a corrupted record — that the user changed
      // their password. A shape check that lets the value through reaches that line and files
      // the wrong diagnosis, sending whoever reads it after a password change that never
      // happened.
      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).not.toContain('no longer bound to the account password')
      warnSpy.mockRestore()
    })

    // A record with no fingerprint field at all — what a sibling implementation that has not
    // taken this change writes.
    it('accepts a record that predates the binding', async () => {
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ userId: 'user-1', newEmail: NEW_EMAIL, tenantId: 'tenant-1' })
      )

      await expect(service.confirmChange({ token: TOKEN })).resolves.toBeUndefined()
      expect(mockUserRepo.updateEmail).toHaveBeenCalledWith('user-1', NEW_EMAIL)
    })

    // Re-checked here and not only at request time: the two are separated by the whole TTL,
    // and whoever registered the address in between would otherwise lose it to this change.
    it('refuses when the address was taken between the request and the confirmation', async () => {
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, id: 'someone-else' })

      await expect(service.confirmChange({ token: TOKEN })).rejects.toThrow(AuthException)
      expect(mockUserRepo.updateEmail).not.toHaveBeenCalled()
    })

    // A delivery failure does not roll back a change the user asked for and has proven — but
    // it is logged, because that notice is the owner's last chance to see a takeover.
    it('still applies the change when the notification cannot be delivered', async () => {
      mockEmailProvider.sendEmailChangedNotification.mockRejectedValue(new Error('smtp down'))
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      await expect(service.confirmChange({ token: TOKEN })).resolves.toBeUndefined()

      expect(mockUserRepo.updateEmail).toHaveBeenCalled()
      expect(errorSpy.mock.calls.map((call) => String(call[0])).join(' ')).toContain(
        'notification to the previous address failed'
      )
      errorSpy.mockRestore()
    })

    // …and a provider that implements no notification at all is not an error either: the
    // method is optional on the interface, so the change still lands.
    it('applies the change when the provider implements no notification', async () => {
      const silent = new EmailChangeService(
        mockOptions as never,
        mockUserRepo as never,
        { sendEmailChangeVerification: jest.fn() } as never,
        mockPasswordService as never,
        mockRedis as never,
        mockBruteForce as never
      )

      await expect(silent.confirmChange({ token: TOKEN })).resolves.toBeUndefined()
      expect(mockUserRepo.updateEmail).toHaveBeenCalledWith('user-1', NEW_EMAIL)
    })

    // A stored `null` is the one non-object JSON value that reaches the type guard: it parses
    // fine and `typeof null === 'object'`, so without the explicit null test it would fall
    // through to a property read on nothing.
    it('refuses a stored record that is JSON null', async () => {
      mockRedis.getdel.mockResolvedValue('null')

      await expect(service.confirmChange({ token: TOKEN })).rejects.toThrow(AuthException)
      expect(mockUserRepo.updateEmail).not.toHaveBeenCalled()
    })

    // The refusal names the account whose token stopped matching, which is what an operator
    // needs to tell a stale link from a planted one.
    it('logs which account a rejected token belonged to', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockUserRepo.findById.mockResolvedValue({ ...USER, passwordHash: 'scrypt:new:hash' })

      await expect(service.confirmChange({ token: TOKEN })).rejects.toThrow(AuthException)

      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).toContain('token no longer bound to the account password')
      expect(warned).toContain('userId=user-1')
      warnSpy.mockRestore()
    })

    // Both addresses are masked in the log, for the same reason the request masks one.
    it('masks both addresses in the log', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      await service.confirmChange({ token: TOKEN })

      const logged = logSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(logged).toContain('confirmChange: address changed')
      expect(logged).toContain('userId=user-1')
      // Both endpoints of the move are named, masked — an operator reconstructing an incident
      // needs to see WHICH change happened, not just that one did.
      expect(logged).toMatch(/from=\S+ to=\S+/)
      expect(logged).not.toContain('old@example.com')
      expect(logged).not.toContain(NEW_EMAIL)
      logSpy.mockRestore()
    })
  })
})
