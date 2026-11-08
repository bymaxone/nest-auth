/**
 * @fileoverview The services `MfaService` collaborates with, provided real in every MFA test
 * module. Test-only; excluded from coverage and from the build.
 */

import { MfaChallengeService } from '../mfa-challenge.service'
import { MfaFlowLockoutService } from '../mfa-flow-lockout.service'
import { MfaRecordService } from '../mfa-record.service'
import { ReauthenticationService } from '../reauthentication.service'

/** Provide these beside `MfaService` so its collaborators run for real over the suite's doubles. */
export const MFA_COLLABORATORS = [
  MfaChallengeService,
  MfaFlowLockoutService,
  MfaRecordService,
  ReauthenticationService
]
