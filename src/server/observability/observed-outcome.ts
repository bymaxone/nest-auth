/**
 * @fileoverview Lets the code that refuses a refresh say which kind of refusal it was.
 *
 * Every refused refresh answers the same `REFRESH_TOKEN_INVALID`, so that a holder of a stolen token learns
 * nothing from the code. The metrics tell the cases apart, and they read the answer from here: the refusal is
 * marked on the exception object in a side table, never on the exception's body, so nothing that reaches a
 * caller changes.
 *
 * @layer Utility
 */

/** The refusals that are told apart from a plain invalid token. */
export type ObservedRefusal = 'reuse_detected' | 'expired'

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
