/**
 * @fileoverview The shape check of a WebSocket ticket read back from the store.
 *
 * @layer Utils
 */

import type { WsTicketSnapshot } from '../interfaces/ws-ticket.interface'

/**
 * Whether an unknown value is a well-formed {@link WsTicketSnapshot}.
 *
 * The record is read back from Redis, which the sibling implementation also writes, so it is
 * parsed defensively rather than cast: a snapshot missing `mfaVerified` would otherwise
 * authorize a socket as MFA-satisfied through an `undefined` that reads as false only by luck
 * of the comparison used downstream.
 *
 * @param value - The parsed JSON read back from the store.
 * @returns `true` when every required field is present and correctly typed.
 */
export function isWsTicketSnapshot(value: unknown): value is WsTicketSnapshot {
  // Stryker disable next-line ConditionalExpression,LogicalOperator: defensive shape guard
  // masked by the field checks below — a scalar reads every field as `undefined` and fails the
  // first `typeof`, and the only caller parses JSON inside a try/catch, so the `null` deref
  // this would otherwise allow surfaces as the same refusal
  if (typeof value !== 'object' || value === null) return false
  const record = value as Record<string, unknown>
  return (
    typeof record['sub'] === 'string' &&
    typeof record['role'] === 'string' &&
    typeof record['status'] === 'string' &&
    typeof record['mfaEnabled'] === 'boolean' &&
    typeof record['mfaVerified'] === 'boolean' &&
    typeof record['jti'] === 'string' &&
    record['jti'] !== '' &&
    typeof record['epoch'] === 'number' &&
    Number.isSafeInteger(record['epoch']) &&
    record['epoch'] >= 0 &&
    (record['tenantId'] === undefined || typeof record['tenantId'] === 'string')
  )
}
