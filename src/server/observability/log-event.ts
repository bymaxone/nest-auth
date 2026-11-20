/**
 * @fileoverview The one way the library writes a log event: an object message through the Nest `Logger`.
 *
 * @layer Utility
 */

import type { LoggerService } from '@nestjs/common'

import { AUTH_LOG_EVENTS } from './log-events'
import type { AuthLogEvent } from './log-events'

/** A field value: a closed string, a number or a flag; never an object a host or a store built. */
export type LogFieldValue = string | number | boolean

/**
 * Writes the event as an object with `event`, `message` and the fields, at the level the catalog gives it. The
 * code and the message come last, so a field of that name cannot replace them.
 *
 * The message is the catalog's library text, so no caller can put a value in it. A host's logger that throws
 * synchronously has no say in the flow that logged: the throw is swallowed. A `Logger` of Nest does not return
 * what the host's `LoggerService` returns, so a host logger that is asynchronous and rejects is the host's own
 * unhandled rejection; this function neither sees it nor claims to absorb it.
 *
 * @param logger - The logger of the class that writes the event.
 * @param event - A code of the catalog.
 * @param fields - The fields the catalog names for the event, each a closed value.
 */
export function logEvent(
  logger: Pick<LoggerService, 'log' | 'warn' | 'error'>,
  event: AuthLogEvent,
  fields?: Readonly<Record<string, LogFieldValue>>
): void {
  const { level, message } = AUTH_LOG_EVENTS[event]
  try {
    logger[level]({ ...fields, event, message })
  } catch {
    // The host's logger has no say in what the flow that logged does next.
  }
}
