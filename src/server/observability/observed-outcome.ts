/**
 * @fileoverview Lets the code that refuses a request tell the metrics what it knows and the caller cannot.
 *
 * Every refused refresh answers the same `REFRESH_TOKEN_INVALID`, so that a holder of a stolen token learns
 * nothing from the code, and a refused MFA challenge on the shared route does not say which plane the token
 * belonged to. The metrics tell the cases apart, and they read the answer from here: the refusal and the
 * plane are marked on the exception object in side tables, never on the exception's body, so nothing that
 * reaches a caller changes.
 *
 * @layer Utility
 */

/** The refusals that are told apart from a plain invalid token. */
export type ObservedRefusal = 'reuse_detected' | 'expired'

import type { AuthPlane } from '../services/auth-token-verifier.service'

const REFUSALS = new WeakMap<object, ObservedRefusal>()

/**
 * Marks `error` as a refusal of the given kind and returns it, so it can be thrown in the same statement.
 *
 * @param refusal - The kind of refusal.
 * @param error - The exception about to be thrown.
 * @returns The same exception.
 */
export function observed<E extends Error>(refusal: ObservedRefusal, error: E): E {
  REFUSALS.set(error, refusal)
  return error
}

/**
 * The kind of refusal an exception was marked with.
 *
 * @param error - Whatever a handler threw.
 * @returns The kind, or `undefined` for an exception that was not marked.
 */
export function observedRefusal(error: unknown): ObservedRefusal | undefined {
  return typeof error === 'object' && error !== null ? REFUSALS.get(error) : undefined
}

const PLANES = new WeakMap<object, AuthPlane>()

/**
 * Marks `error` with the plane the refused request belonged to and returns it, so it can be thrown in the same
 * statement.
 *
 * @param plane - The plane of the verified token.
 * @param error - The exception about to be thrown.
 * @returns The same exception.
 */
export function onPlane<E extends Error>(plane: AuthPlane, error: E): E {
  PLANES.set(error, plane)
  return error
}

/**
 * The plane an exception was marked with.
 *
 * @param error - Whatever a handler threw.
 * @returns The plane, or `undefined` for an exception that was not marked.
 */
export function markedPlane(error: unknown): AuthPlane | undefined {
  return typeof error === 'object' && error !== null ? PLANES.get(error) : undefined
}
