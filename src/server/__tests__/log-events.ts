/**
 * @fileoverview Test helpers for the log events: the exact object a logger received, so a test checks the event
 * and every field it carried, and a negative assertion is made over the object form.
 *
 * @layer Test
 */

import { AUTH_LOG_EVENTS } from '../observability/log-events'
import type { AuthLogEvent } from '../observability/log-events'

/** The object a logger is called with for `event`: the code, the catalog's message and exactly these fields. */
export function eventOf(
  event: AuthLogEvent,
  fields: Readonly<Record<string, string | number | boolean>> = {}
): { event: AuthLogEvent; message: string } & Record<string, unknown> {
  return { ...fields, event, message: AUTH_LOG_EVENTS[event].message }
}

/** The events a logger spy received, in order, whatever their fields. */
export function eventsReceived(spy: jest.SpyInstance): string[] {
  return spy.mock.calls
    .map((call: unknown[]) => call[0])
    .filter((arg: unknown): arg is { event: string } => typeof arg === 'object' && arg !== null)
    .map((arg: { event: string }) => arg.event)
}

/** Every object a logger spy received, as one string, for a check that a value appears in none of them. */
export function serialized(spy: jest.SpyInstance): string {
  return JSON.stringify(spy.mock.calls.map((call: unknown[]) => call[0]))
}

/**
 * Asserts that a logger spy received the event with exactly these fields, and that none of the values appear
 * anywhere in what it received.
 *
 * @param spy - The logger spy.
 * @param event - The event code.
 * @param fields - The fields the event carries, and no others.
 * @param absent - Values that must not appear in any object the spy received.
 */
export function expectEvent(
  spy: jest.SpyInstance,
  event: AuthLogEvent,
  fields: Readonly<Record<string, string | number | boolean>> = {},
  absent: readonly string[] = []
): void {
  expect(spy).toHaveBeenCalledWith(eventOf(event, fields))
  for (const value of absent) expect(serialized(spy)).not.toContain(value)
}
