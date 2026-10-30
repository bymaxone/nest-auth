/**
 * @fileoverview Which request schemas each mountable controller family takes.
 *
 * The fragment contributes only the schemas of the controllers a deployment mounted, for the same
 * reason it describes only their operations: a component nothing in the document references is
 * noise in a consumer's served spec and in the client generated from it. The names are the DTO
 * class names, which is the key `@nestjs/swagger` registers a schema under.
 *
 * Kept as data beside the fragment rather than derived at boot, so the published bundle needs no
 * reflection over controllers. `request-schema-mounts.spec.ts` derives the same table from the
 * controllers' own route metadata and fails on any difference, in either direction.
 *
 * @layer OpenAPI
 */
import type { RegisteredControllers } from './auth-openapi-fragment'

/**
 * The DTO class names each controller family takes as a request body, by registration switch.
 *
 * A family that takes none is listed with an empty array, so the table has exactly the keys of
 * {@link RegisteredControllers} and the compiler flags a switch added without an entry.
 */
export const REQUEST_SCHEMAS_BY_CONTROLLER: Readonly<
  Record<keyof RegisteredControllers, readonly string[]>
> = {
  auth: ['RegisterDto', 'LoginDto', 'VerifyEmailDto', 'ResendVerificationDto'],
  passwordReset: [
    'ForgotPasswordDto',
    'ResetPasswordDto',
    'ChangePasswordDto',
    'VerifyOtpDto',
    'ResendOtpDto'
  ],
  mfa: [
    'MfaSetupDto',
    'MfaVerifyDto',
    'MfaChallengeDto',
    'MfaDisableDto',
    'MfaRegenerateRecoveryCodesDto'
  ],
  sessions: [],
  platform: ['PlatformLoginDto', 'MfaChallengeDto'],
  platformMfa: ['MfaSetupDto', 'MfaVerifyDto', 'MfaDisableDto', 'MfaRegenerateRecoveryCodesDto'],
  invitations: ['CreateInvitationDto', 'RevokeInvitationDto', 'AcceptInvitationDto'],
  emailChange: ['ChangeEmailDto', 'ConfirmEmailChangeDto'],
  oauth: []
}
