/**
 * @fileoverview The context a password-reset token or verified token is stored with.
 *
 * @layer Utils
 */

import type { Logger } from '@nestjs/common'

import { parseJson } from './captured-builtins'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { logEvent } from '../observability/log-event'

/** Stored context for a password-reset token or verifiedToken. */
export interface ResetContext {
  userId: string
  email: string
  tenantId: string
  /**
   * A digest of the password hash this token was issued against, binding it to that password.
   *
   * Each `forgot-password` writes its own `pw_reset:` key, so several can be alive at once —
   * the 60-second cooldown against a 600-second TTL allows up to ten. Completing a reset with
   * one used to leave the others valid, which is the wrong end state precisely when it matters:
   * a victim who resets because an attacker read a link from their mailbox has not closed the
   * link the attacker read. Binding each token to the password in force when it was minted
   * means the first completed reset — or an authenticated change — invalidates every one of
   * them at once, with no per-user index to keep in step.
   *
   * Empty for an account that had no password (OAuth-only) at issue time.
   */
  passwordFingerprint: string
}

/**
 * Parses a {@link ResetContext} from a Redis JSON string.
 *
 * @param json - The stored record.
 * @param logger - The logger a corrupted record is reported to.
 * @throws {@link AuthException} `PASSWORD_RESET_TOKEN_INVALID` if the JSON is
 *   malformed or missing required fields.
 */
export function parseResetContext(json: string, logger: Logger): ResetContext {
  // Narrow try scope to JSON.parse only — so that future logic added after
  // parsing is not accidentally swallowed and re-wrapped as TOKEN_INVALID.
  let parsed: unknown
  try {
    parsed = parseJson(json)
  } catch {
    // Corrupted storage, not an expired or replayed token: indistinguishable to the caller
    // by design, and distinguishable to an operator only here.
    logEvent(logger, 'AUTH_RECORD_INVALID', { record: 'reset_context' })
    // Stryker disable next-line CallExpression: equivalent — the warn above is already emitted, and with this throw gone `parsed` stays undefined, so the shape check immediately below refuses the record with the identical code. Same log, same error, same order.
    throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
  }

  if (
    parsed === null ||
    typeof parsed !== 'object' ||
    !('userId' in parsed) ||
    !('email' in parsed) ||
    !('tenantId' in parsed) ||
    typeof (parsed as Record<string, unknown>)['userId'] !== 'string' ||
    typeof (parsed as Record<string, unknown>)['email'] !== 'string' ||
    typeof (parsed as Record<string, unknown>)['tenantId'] !== 'string'
  ) {
    throw new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
  }

  const record = parsed as Record<string, unknown>
  const fingerprint = record['passwordFingerprint']
  return {
    userId: record['userId'] as string,
    email: record['email'] as string,
    tenantId: record['tenantId'] as string,
    // Absent on a record written by an older build, or by a sibling that has not taken this
    // change yet. Treated as "no binding" rather than as a mismatch: refusing every such
    // token would break every reset in flight during a rolling deploy, which is a worse
    // outcome than the narrow window this closes.
    passwordFingerprint: typeof fingerprint === 'string' ? fingerprint : ''
  }
}
