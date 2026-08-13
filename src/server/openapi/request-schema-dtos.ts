/**
 * @fileoverview The DTO set the generated request-schema artifact covers.
 *
 * A hand-maintained list on purpose, rather than a directory scan: the conformance suite asserts
 * its length, so adding a DTO without adding it here fails a test instead of silently narrowing
 * what the artifact documents. A scan would have grown the set quietly and told nobody.
 *
 * Not exported from the package — nothing reachable from `src/server/index.ts` imports it, so it
 * never enters the published bundle.
 *
 * @layer OpenAPI
 */
import type { DtoClass } from './derive-request-schemas'
import { AcceptInvitationDto } from '../dto/accept-invitation.dto'
import { ChangeEmailDto } from '../dto/change-email.dto'
import { ChangePasswordDto } from '../dto/change-password.dto'
import { ConfirmEmailChangeDto } from '../dto/confirm-email-change.dto'
import { CreateInvitationDto } from '../dto/create-invitation.dto'
import { ForgotPasswordDto } from '../dto/forgot-password.dto'
import { LoginDto } from '../dto/login.dto'
import { MfaChallengeDto } from '../dto/mfa-challenge.dto'
import { MfaDisableDto } from '../dto/mfa-disable.dto'
import { MfaRegenerateRecoveryCodesDto } from '../dto/mfa-regenerate-recovery-codes.dto'
import { MfaSetupDto } from '../dto/mfa-setup.dto'
import { MfaVerifyDto } from '../dto/mfa-verify.dto'
import { OAuthCallbackQueryDto } from '../dto/oauth-callback-query.dto'
import { OAuthInitiateQueryDto } from '../dto/oauth-initiate-query.dto'
import { PlatformLoginDto } from '../dto/platform-login.dto'
import { RegisterDto } from '../dto/register.dto'
import { ResendOtpDto } from '../dto/resend-otp.dto'
import { ResendVerificationDto } from '../dto/resend-verification.dto'
import { ResetPasswordDto } from '../dto/reset-password.dto'
import { RevokeInvitationDto } from '../dto/revoke-invitation.dto'
import { VerifyEmailDto } from '../dto/verify-email.dto'
import { VerifyOtpDto } from '../dto/verify-otp.dto'

/** Every DTO whose request body the library documents. */
export const REQUEST_SCHEMA_DTOS: readonly DtoClass[] = [
  AcceptInvitationDto,
  ChangeEmailDto,
  ChangePasswordDto,
  ConfirmEmailChangeDto,
  CreateInvitationDto,
  ForgotPasswordDto,
  LoginDto,
  MfaChallengeDto,
  MfaDisableDto,
  MfaRegenerateRecoveryCodesDto,
  MfaSetupDto,
  MfaVerifyDto,
  OAuthCallbackQueryDto,
  OAuthInitiateQueryDto,
  PlatformLoginDto,
  RegisterDto,
  ResendOtpDto,
  ResendVerificationDto,
  ResetPasswordDto,
  RevokeInvitationDto,
  VerifyEmailDto,
  VerifyOtpDto
]
