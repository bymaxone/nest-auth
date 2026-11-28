/**
 * @fileoverview The source file that writes each Redis prefix the contract declares for ending a
 * session, for the prefix check in `conformance.spec.ts`.
 *
 * @layer Test
 */

export const SESSION_END_PREFIX_SOURCES: Readonly<Record<string, string>> = {
  dashboardLogoutPending: 'constants/logout-pending.ts',
  platformLogoutPending: 'constants/logout-pending.ts',
  dashboardSessionRevocation: 'utils/session-access.ts',
  platformSessionRevocation: 'utils/session-access.ts'
}
