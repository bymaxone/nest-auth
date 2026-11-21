/**
 * @fileoverview The one way the library writes a log event: an object message through the Nest `Logger`.
 *
 * @layer Utility
 */

import type { LoggerService } from '@nestjs/common'

import { AUTH_LOG_EVENTS } from './log-events'
import type { AuthLogEvent } from './log-events'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { AuthEmailKind } from '../providers/default-auth-email.provider'
import { describeChannelStatus } from '../utils/describe-error'

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

/** What can fail beside a flow: a hook of the host, or a step the library runs without awaiting. */
export type HookStep =
  keyof IAuthHooks | 'updateLastLogin' | 'accessDenied' | 'maxSessionsResolver' | 'onApiKeyRequest'

/** The named steps whose failure is reported as a store or repository event; the set is closed. */
export type StoreOperation =
  | 'account_status_cache_write'
  | 'api_key_last_used_flush'
  | 'api_key_lookup'
  | 'cache_invalidation'
  | 'dead_member_prune'
  | 'grace_pointer_prune'
  | 'invitation_withdraw'
  | 'logout_marker_clear'
  | 'logout_owner_keep'
  | 'mfa_lock_release'
  | 'mfa_reencryption'
  | 'new_session_user_lookup'
  | 'rehash_on_verify'
  | 'resend_cooldown_release'
  | 'reset_account_lookup'
  | 'reset_cooldown_release'
  | 'reset_cooldown_store'
  | 'reset_issue'
  | 'session_cleanup'
  | 'session_detail_read'
  | 'session_detail_rotation'
  | 'workspace_cache_read'
  | 'workspace_cache_write'

/** Writes that a hook or a fire-and-forget step failed, by its name and how it failed. */
export function logHook(
  logger: Pick<LoggerService, 'log' | 'warn' | 'error'>,
  hook: HookStep,
  how: 'threw' | 'rejected'
): void {
  logEvent(logger, 'AUTH_HOOK_FAILED', { hook, how })
}

/**
 * Writes that a named store or repository step failed, with the library's description of the failure and never the
 * text of the error.
 *
 * @param event - `AUTH_STORE_FAILED` when the flow reports it, `AUTH_STORE_DEGRADED` when the flow goes on without it.
 */
export function logStore(
  logger: Pick<LoggerService, 'log' | 'warn' | 'error'>,
  event: 'AUTH_STORE_FAILED' | 'AUTH_STORE_DEGRADED',
  operation: StoreOperation,
  err: unknown
): void {
  logEvent(logger, event, { operation, detail: describeChannelStatus(err) })
}

/** The notifications whose failed delivery is reported: the flow's own, or a kind of the bundled email provider. */
export type DeliveryKind =
  | AuthEmailKind
  | 'email_verification_otp'
  | 'password_changed_notice'
  | 'password_reset_token'
  | 'password_reset_otp'
  | 'mfa_enabled_notice'
  | 'mfa_disabled_notice'
  | 'mfa_reset_notice'
  | 'email_change_notice'

/** Writes that a notification could not be delivered: which kind, and the description of the failure. */
export function logDelivery(
  logger: Pick<LoggerService, 'log' | 'warn' | 'error'>,
  kind: DeliveryKind,
  err: unknown
): void {
  logEvent(logger, 'AUTH_DELIVERY_FAILED', { kind, detail: describeChannelStatus(err) })
}

/** Writes that an exception reached a filter of the library, on which surface, with the description of it. */
export function logUnhandled(
  logger: Pick<LoggerService, 'log' | 'warn' | 'error'>,
  surface: 'http' | 'ws',
  err: unknown
): void {
  logEvent(logger, 'AUTH_UNHANDLED_EXCEPTION', { surface, detail: describeChannelStatus(err) })
}
