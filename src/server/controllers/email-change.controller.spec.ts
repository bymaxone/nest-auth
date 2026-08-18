/**
 * Unit tests for {@link EmailChangeController}.
 *
 * The controller's whole job is which account the change applies to, and that answer must
 * come from the verified token rather than the body.
 *
 * @layer Controller
 */

import { Test } from '@nestjs/testing'

import { EmailChangeController } from './email-change.controller'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'
import { UserStatusGuard } from '../guards/user-status.guard'
import type { ChangeEmailDto } from '../dto/change-email.dto'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import { EmailChangeService } from '../services/email-change.service'

const mockService = {
  requestChange: jest.fn(),
  confirmChange: jest.fn()
}

const JWT_PAYLOAD = { sub: 'user-1', tenantId: 'tenant-1' } as DashboardJwtPayload

describe('EmailChangeController', () => {
  let controller: EmailChangeController

  beforeEach(async () => {
    jest.resetAllMocks()
    mockService.requestChange.mockResolvedValue(undefined)
    mockService.confirmChange.mockResolvedValue(undefined)

    const module = await Test.createTestingModule({
      controllers: [EmailChangeController],
      providers: [{ provide: EmailChangeService, useValue: mockService }]
    })
      // The guards are exercised by their own specs; overriding them here keeps this one
      // about the controller's single decision — whose account the change applies to.
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(UserStatusGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(TrustedOriginGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(AuthRateLimitGuard)
      .useValue({ canActivate: () => true })
      .compile()

    controller = module.get(EmailChangeController)
  })

  describe('requestChange', () => {
    const dto: ChangeEmailDto = { newEmail: 'new@example.com', currentPassword: 'right' }

    // The account comes from the caller's own claims. A body that could name a user id would
    // let anyone holding any session move any account's recovery address.
    it('applies the change to the authenticated caller, not to anyone the body names', async () => {
      await controller.requestChange(dto, JWT_PAYLOAD)

      expect(mockService.requestChange).toHaveBeenCalledWith('user-1', JWT_PAYLOAD.tenantId, dto)
    })

    it('returns undefined (HTTP 204 No Content)', async () => {
      await expect(controller.requestChange(dto, JWT_PAYLOAD)).resolves.toBeUndefined()
    })
  })

  describe('confirmChange', () => {
    // The token is the whole payload: it already names the account, the target address and
    // the tenant, all fixed when it was minted.
    it('delegates the token unchanged', async () => {
      const dto = { token: 'a'.repeat(64) }

      await controller.confirmChange(dto)

      expect(mockService.confirmChange).toHaveBeenCalledWith(dto)
    })

    it('returns undefined (HTTP 204 No Content)', async () => {
      await expect(controller.confirmChange({ token: 'a'.repeat(64) })).resolves.toBeUndefined()
    })
  })
})
