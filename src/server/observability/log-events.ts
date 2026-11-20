/**
 * @fileoverview The catalog of the log events the library writes: each code, its level, its message and the
 * names of its fields. The README "Log events" table is the same list, and a spec compares the two both ways.
 *
 * @layer Config
 */

/** The levels an event is written at. */
export type LogEventLevel = 'log' | 'warn' | 'error'

/** What the catalog records about an event. */
interface LogEventSpec {
  /** The level the event is written at. */
  readonly level: LogEventLevel
  /** The library's own text: no value a caller, a host or a store supplied is ever part of it. */
  readonly message: string
  /** The names of the fields the event may carry, each a value from a closed set or a number. */
  readonly fields: readonly string[]
  /** When the event is written, in a sentence for the README. */
  readonly when: string
}

/**
 * Every event the security-relevant flows write.
 *
 * A message is library text and a field is a closed value, a library-made id or a description of a failure the
 * library composed (`detail`), so no log line carries a user, a tenant, an address, a token or text a host or a
 * store wrote.
 */
export const AUTH_LOG_EVENTS = {
  AUTH_LOGIN_LOCKED: {
    level: 'warn',
    message: 'login: account locked',
    fields: ['plane'],
    when: 'a login is refused because the account is at its failure ceiling'
  },
  AUTH_LOGIN_INVALID_CREDENTIALS: {
    level: 'warn',
    message: 'login: invalid credentials',
    fields: ['plane'],
    when: 'a login is refused for an unknown account or a wrong password'
  },
  AUTH_MFA_CODE_INVALID: {
    level: 'warn',
    message: 'MFA: invalid code',
    fields: ['plane', 'flow'],
    when: 'an MFA code is refused (flow: challenge, enable, disable, recovery_codes)'
  },
  AUTH_MFA_LOCKED: {
    level: 'warn',
    message: 'MFA: account locked',
    fields: ['plane', 'flow'],
    when: 'an MFA step is refused because the account is at its failure ceiling (flow: challenge, disable, recovery_codes)'
  },
  AUTH_MFA_RESET: {
    level: 'warn',
    message: 'MFA: removed administratively',
    fields: ['plane'],
    when: 'an administrator removes the MFA factor of an account'
  },
  AUTH_PASSWORD_REJECTED: {
    level: 'warn',
    message: 'the current password was rejected',
    fields: ['flow'],
    when: 'a password re-proof is refused (flow: change_password, email_change)'
  },
  AUTH_ACCOUNT_LOCKED: {
    level: 'warn',
    message: 'account locked',
    fields: ['flow'],
    when: 'a password re-proof is refused because the account is at its failure ceiling (flow: change_password, email_change, reauthentication)'
  },
  AUTH_REAUTHENTICATION_REFUSED: {
    level: 'warn',
    message: 'reauthentication refused',
    fields: ['plane', 'reason'],
    when: 'a sensitive action is refused for lack of a recent authentication (reason: no_recent_authentication)'
  },
  AUTH_REFRESH_REUSE_DETECTED: {
    level: 'warn',
    message: 'refresh: reuse of a consumed token detected, revoking its family',
    fields: ['plane', 'familyId'],
    when: 'a refresh token that was already exchanged is presented again'
  },
  AUTH_REFRESH_FAMILY_REVOKED: {
    level: 'warn',
    message: 'refresh: token family revoked after reuse detection',
    fields: ['plane', 'familyId'],
    when: 'the family of a reused refresh token has been revoked'
  },
  AUTH_REFRESH_REFUSED: {
    level: 'warn',
    message: 'refresh: no valid session or grace window found',
    fields: ['plane'],
    when: 'a refresh token matches no live session and no grace window'
  },
  AUTH_SESSION_LIFETIME_EXCEEDED: {
    level: 'warn',
    message: 'refresh: the session has outlived the absolute lifetime cap',
    fields: [],
    when: 'a rotation is refused because the login it descends from is older than jwt.absoluteSessionLifetimeDays'
  },
  AUTH_TOKEN_REVOCATION_REFUSED: {
    level: 'warn',
    message: 'a dashboard token carrying no tenant is refused without a store read',
    fields: ['reason'],
    when: 'a revocation check cannot name the epoch key of a token (reason: missing_tenant)'
  },
  AUTH_WS_TICKET_REFUSED: {
    level: 'warn',
    message: 'ws-ticket: refused',
    fields: ['reason'],
    when: 'a WebSocket ticket is refused (reason: mfa_not_satisfied, no_life_left, unknown_or_used, session_revoked)'
  },
  AUTH_OAUTH_STATE_REFUSED: {
    level: 'warn',
    message: 'oauth: callback state refused',
    fields: ['reason'],
    when: 'an OAuth callback is refused (reason: not_bound, provider_mismatch, invalid_or_expired, unparseable)'
  },
  AUTH_OTP_STORE_FAILED: {
    level: 'error',
    message: 'email verification: the code could not be stored',
    fields: ['detail'],
    when: 'the store refuses the write of an email-verification code'
  },
  AUTH_IDENTIFIER_REFUSED: {
    level: 'error',
    message: 'brute-force: an identifier was refused',
    fields: ['reason'],
    when: 'an identifier passed to the lockout counter is not usable (reason: forbidden_characters, too_long)'
  }
} as const satisfies Record<string, LogEventSpec>

/** The code of an event the catalog lists. */
export type AuthLogEvent = keyof typeof AUTH_LOG_EVENTS
