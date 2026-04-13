import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import { NoOpEmailProvider } from './no-op-email.provider'

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('NoOpEmailProvider', () => {
  let provider: NoOpEmailProvider
  let logSpy: jest.SpyInstance

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      providers: [NoOpEmailProvider]
    }).compile()

    provider = module.get(NoOpEmailProvider)
    logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  // ---------------------------------------------------------------------------
  // sendPasswordResetToken
  // ---------------------------------------------------------------------------

  describe('sendPasswordResetToken', () => {
    // Verifies that the no-op implementation resolves without throwing any error.
    it('should resolve without throwing', async () => {
      await expect(
        provider.sendPasswordResetToken('user@example.com', 'secret-token')
      ).resolves.toBeUndefined()
    })

    // Verifies that the no-op implementation logs the recipient email for observability.
    it('should log the recipient email', async () => {
      await provider.sendPasswordResetToken('user@example.com', 'token')
      expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('user@example.com'))
    })

    // Verifies that the actual token value is never logged to prevent accidental secret leakage.
    it('should NOT log the token value', async () => {
      await provider.sendPasswordResetToken('user@example.com', 'MY_SECRET_TOKEN')
      const logged = logSpy.mock.calls.map((c) => String(c[0])).join('')
      expect(logged).not.toContain('MY_SECRET_TOKEN')
    })
  })

  // ---------------------------------------------------------------------------
  // sendPasswordResetOtp
  // ---------------------------------------------------------------------------

  describe('sendPasswordResetOtp', () => {
    // Verifies that sendPasswordResetOtp resolves without throwing.
    it('should resolve without throwing', async () => {
      await expect(
        provider.sendPasswordResetOtp('user@example.com', '123456')
      ).resolves.toBeUndefined()
    })

    // Verifies that the recipient email is logged for observability during development.
    it('should log the recipient email', async () => {
      await provider.sendPasswordResetOtp('user@example.com', '123456')
      expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('user@example.com'))
    })
  })

  // ---------------------------------------------------------------------------
  // sendEmailVerificationOtp
  // ---------------------------------------------------------------------------

  describe('sendEmailVerificationOtp', () => {
    // Verifies that sendEmailVerificationOtp resolves without throwing.
    it('should resolve without throwing', async () => {
      await expect(
        provider.sendEmailVerificationOtp('user@example.com', '654321')
      ).resolves.toBeUndefined()
    })

    // Verifies that the recipient email is included in the log output.
    it('should log the recipient email', async () => {
      await provider.sendEmailVerificationOtp('user@example.com', '654321')
      expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('user@example.com'))
    })
  })

  // ---------------------------------------------------------------------------
  // sendMfaEnabledNotification
  // ---------------------------------------------------------------------------

  describe('sendMfaEnabledNotification', () => {
    // Verifies that sendMfaEnabledNotification resolves without throwing.
    it('should resolve without throwing', async () => {
      await expect(provider.sendMfaEnabledNotification('user@example.com')).resolves.toBeUndefined()
    })

    // Verifies that the recipient email appears in the log output for the MFA-enabled notification.
    it('should log the recipient email', async () => {
      await provider.sendMfaEnabledNotification('user@example.com')
      expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('user@example.com'))
    })
  })

  // ---------------------------------------------------------------------------
  // sendMfaDisabledNotification
  // ---------------------------------------------------------------------------

  describe('sendMfaDisabledNotification', () => {
    // Verifies that sendMfaDisabledNotification resolves without throwing.
    it('should resolve without throwing', async () => {
      await expect(
        provider.sendMfaDisabledNotification('user@example.com')
      ).resolves.toBeUndefined()
    })

    // Verifies that the recipient email appears in the log output for the MFA-disabled notification.
    it('should log the recipient email', async () => {
      await provider.sendMfaDisabledNotification('user@example.com')
      expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('user@example.com'))
    })
  })

  // ---------------------------------------------------------------------------
  // sendNewSessionAlert
  // ---------------------------------------------------------------------------

  describe('sendNewSessionAlert', () => {
    const sessionInfo = { device: 'Chrome on macOS', ip: '1.2.3.4', sessionHash: 'abc12345' }

    // Verifies that sendNewSessionAlert resolves without throwing.
    it('should resolve without throwing', async () => {
      await expect(
        provider.sendNewSessionAlert('user@example.com', sessionInfo)
      ).resolves.toBeUndefined()
    })

    // Verifies that the recipient email is logged when a new session alert is sent.
    it('should log the recipient email', async () => {
      await provider.sendNewSessionAlert('user@example.com', sessionInfo)
      expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('user@example.com'))
    })
  })

  // ---------------------------------------------------------------------------
  // sendInvitation
  // ---------------------------------------------------------------------------

  describe('sendInvitation', () => {
    const inviteData = {
      inviterName: 'Alice',
      tenantName: 'Acme Corp',
      inviteUrl: 'https://app.example.com/invite/token',
      expiresAt: new Date('2026-05-01T00:00:00Z')
    }

    // Verifies that sendInvitation resolves without throwing.
    it('should resolve without throwing', async () => {
      await expect(
        provider.sendInvitation('invitee@example.com', inviteData)
      ).resolves.toBeUndefined()
    })

    // Verifies that the invitee email is included in the log output when an invitation is sent.
    it('should log the recipient email', async () => {
      await provider.sendInvitation('invitee@example.com', inviteData)
      expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('invitee@example.com'))
    })
  })
})
