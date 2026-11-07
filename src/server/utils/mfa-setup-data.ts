/**
 * @fileoverview The pending-setup record an MFA enrolment parks in Redis, and the two parsers that
 * refuse a corrupted one with the same opaque `MFA_SETUP_REQUIRED` an absent one gets.
 *
 * @layer Utility
 */

import type { Logger } from '@nestjs/common'

import { logSafe } from './log-safe'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/**
 * Shape stored in Redis during a pending MFA setup.
 *
 * `encryptedSecret` and `encryptedPlainCodes` are both AES-256-GCM encrypted so
 * that a Redis compromise during the 10-minute setup window does not expose the
 * TOTP secret or plain-text recovery codes.
 *
 * @internal
 */
export interface MfaSetupData {
  /** AES-256-GCM encrypted Base32 TOTP secret. */
  encryptedSecret: string
  /** Keyed HMAC-SHA-256 digests of the recovery codes (stored in the DB after enable). */
  hashedCodes: string[]
  /**
   * AES-256-GCM encrypted JSON array of plain-text recovery codes.
   * Stored only to support idempotent re-display within the setup window.
   */
  encryptedPlainCodes: string
}

/**
 * Whether an unknown value is a well-formed {@link MfaSetupData}.
 *
 * @param value - The `JSON.parse` result.
 * @returns `true` when every field is present and correctly typed.
 */
function isMfaSetupData(value: unknown): value is MfaSetupData {
  if (value === null) return false
  // Unobservable either way. A primitive answers `undefined` to every field read below, so the
  // conjunction returns false without this arm, and returning true from it hands the caller a
  // value whose fields are all `undefined` — refused a step later by the same MFA_SETUP_REQUIRED.
  // Only `null` has to be stopped before the reads, because taking a property off it throws.
  // Kept as a stated precondition rather than as behaviour.
  //
  // Stryker disable ConditionalExpression,BooleanLiteral: subsumed by the field reads below
  if (typeof value !== 'object') return false
  // Stryker restore ConditionalExpression,BooleanLiteral
  const v = value as Record<string, unknown>
  return (
    typeof v['encryptedSecret'] === 'string' &&
    typeof v['encryptedPlainCodes'] === 'string' &&
    Array.isArray(v['hashedCodes']) &&
    v['hashedCodes'].every((code) => typeof code === 'string')
  )
}

/**
 * Safely parses a Redis-stored {@link MfaSetupData} JSON payload.
 *
 * A corrupted or tampered Redis value would otherwise raise an unhandled
 * `SyntaxError` from the service boundary (uncaught 500). We translate the
 * failure into an opaque `MFA_SETUP_REQUIRED`, which mirrors the response
 * the caller would receive if the key were absent — preventing an attacker
 * with Redis write access from distinguishing "no setup pending" from
 * "setup payload corrupted".
 *
 * @param raw - The stored JSON.
 * @param userId - The account, for the log line.
 * @param logger - Where the refusal is recorded.
 * @returns The validated record.
 */
export function parseSetupData(raw: string, userId: string, logger: Logger): MfaSetupData {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    // Recorded, not just refused. The caller gets an opaque MFA_SETUP_REQUIRED — correct, since
    // it must learn nothing about the payload's structure — which leaves this line as the only
    // trace of an event the docstring above calls either a downgrade of the stored value or an
    // internal bug. Both are things an operator needs to see, and neither is visible anywhere
    // else.
    logger.warn(`parseSetupData: pending-setup payload is not valid JSON userId=${logSafe(userId)}`)
    // Stryker disable next-line CallExpression: equivalent — the warn above is already emitted, and with this throw gone `parsed` stays undefined, so `!isMfaSetupData(parsed)` on the next statement refuses the record with the identical MFA_SETUP_REQUIRED.
    throw new AuthException(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)
  }
  // The shape is checked, not asserted. `hashedCodes` missing would enable MFA on an
  // account with no recovery codes at all — a lockout waiting to happen that the user
  // discovers only when they lose their authenticator. `rust-auth` deserializes into a
  // struct with every field required, so a record like that is refused there too.
  if (!isMfaSetupData(parsed)) {
    throw new AuthException(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)
  }
  return parsed
}

/**
 * Safely parses the AES-decrypted JSON array of plain-text recovery codes.
 *
 * A decrypted value that fails JSON parsing indicates either a downgrade of
 * the stored payload (highly unlikely, since AES-GCM authenticates the
 * ciphertext) or an internal bug. Both cases are surfaced opaquely as
 * `MFA_SETUP_REQUIRED` so callers do not learn structural details of the
 * encrypted payload.
 *
 * @param raw - The decrypted JSON.
 * @param userId - The account, for the log line.
 * @param logger - Where the refusal is recorded.
 * @returns The plain recovery codes.
 */
export function parsePlainRecoveryCodes(raw: string, userId: string, logger: Logger): string[] {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    // Same reasoning as `parseSetupData`, and a stronger case: AES-GCM authenticates the
    // ciphertext, so a decrypted value that will not parse means the plaintext itself was
    // written wrong. That is an internal bug, and it is otherwise silent.
    logger.warn(
      `parsePlainRecoveryCodes: decrypted payload is not valid JSON userId=${logSafe(userId)}`
    )
    // Stryker disable next-line CallExpression: equivalent — the warn above is already emitted, and with this throw gone `parsed` stays undefined, so the `!Array.isArray(parsed)` check on the next statement refuses it with the identical MFA_SETUP_REQUIRED.
    throw new AuthException(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)
  }
  if (!Array.isArray(parsed) || parsed.some((code) => typeof code !== 'string')) {
    throw new AuthException(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)
  }
  return parsed as string[]
}
