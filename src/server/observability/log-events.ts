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
    fields: ['plane']
  },
  AUTH_LOGIN_INVALID_CREDENTIALS: {
    level: 'warn',
    message: 'login: invalid credentials',
    fields: ['plane']
  },
  AUTH_MFA_CODE_INVALID: {
    level: 'warn',
    message: 'MFA: invalid code',
    fields: ['plane', 'flow']
  },
  AUTH_MFA_LOCKED: {
    level: 'warn',
    message: 'MFA: account locked',
    fields: ['plane', 'flow']
  },
  AUTH_MFA_RESET: {
    level: 'warn',
    message: 'MFA: removed administratively',
    fields: ['plane']
  },
  AUTH_PASSWORD_REJECTED: {
    level: 'warn',
    message: 'the current password was rejected',
    fields: ['flow']
  },
  AUTH_ACCOUNT_LOCKED: {
    level: 'warn',
    message: 'account locked',
    fields: ['flow']
  },
  AUTH_REAUTHENTICATION_REFUSED: {
    level: 'warn',
    message: 'reauthentication refused',
    fields: ['plane', 'reason']
  },
  AUTH_REFRESH_REUSE_DETECTED: {
    level: 'warn',
    message: 'refresh: reuse of a consumed token detected, revoking its family',
    fields: ['plane', 'familyId']
  },
  AUTH_REFRESH_FAMILY_REVOKED: {
    level: 'warn',
    message: 'refresh: token family revoked after reuse detection',
    fields: ['plane', 'familyId']
  },
  AUTH_REFRESH_REFUSED: {
    level: 'warn',
    message: 'refresh: no valid session or grace window found',
    fields: ['plane']
  },
  AUTH_SESSION_LIFETIME_EXCEEDED: {
    level: 'warn',
    message: 'refresh: the session has outlived the absolute lifetime cap',
    fields: []
  },
  AUTH_TOKEN_REVOCATION_REFUSED: {
    level: 'warn',
    message: 'a dashboard token carrying no tenant is refused without a store read',
    fields: ['reason']
  },
  AUTH_WS_TICKET_REFUSED: {
    level: 'warn',
    message: 'ws-ticket: refused',
    fields: ['reason']
  },
  AUTH_OAUTH_STATE_REFUSED: {
    level: 'warn',
    message: 'oauth: callback state refused',
    fields: ['reason']
  },
  AUTH_OTP_STORE_FAILED: {
    level: 'error',
    message: 'email verification: the code could not be stored',
    fields: ['detail']
  },
  AUTH_IDENTIFIER_REFUSED: {
    level: 'error',
    message: 'brute-force: an identifier was refused',
    fields: ['reason']
  },
  AUTH_LOGIN_SUCCEEDED: {
    level: 'log',
    message: 'login: succeeded',
    fields: ['plane', 'userId', 'tenantId', 'via']
  },
  AUTH_LOGIN_MFA_CHALLENGED: {
    level: 'log',
    message: 'login: MFA challenge issued',
    fields: ['plane', 'userId', 'tenantId', 'via']
  },
  AUTH_LOGOUT: {
    level: 'log',
    message: 'logout',
    fields: ['plane', 'userId']
  },
  AUTH_USER_REGISTERED: {
    level: 'log',
    message: 'register: user registered',
    fields: ['userId', 'tenantId']
  },
  AUTH_TOKENS_ISSUED: {
    level: 'log',
    message: 'tokens issued for an existing user',
    fields: ['userId', 'tenantId']
  },
  AUTH_EMAIL_VERIFIED: {
    level: 'log',
    message: 'email verified',
    fields: ['userId', 'tenantId']
  },
  AUTH_ACCOUNT_UNLOCKED: {
    level: 'log',
    message: 'lockout cleared by an administrator',
    fields: ['tenantId']
  },
  AUTH_EMAIL_CHANGE_REQUESTED: {
    level: 'log',
    message: 'email change: verification sent',
    fields: ['userId']
  },
  AUTH_EMAIL_CHANGED: {
    level: 'log',
    message: 'email change: address changed',
    fields: ['userId']
  },
  AUTH_INVITATION_CREATED: {
    level: 'log',
    message: 'invitation created',
    fields: ['tenantId', 'actorUserId']
  },
  AUTH_INVITATION_REVOKED: {
    level: 'log',
    message: 'invitation withdrawn',
    fields: ['tenantId', 'actorUserId']
  },
  AUTH_INVITATION_ACCEPTED: {
    level: 'log',
    message: 'invitation accepted',
    fields: ['userId', 'tenantId']
  },
  AUTH_MFA_CHALLENGE_PASSED: {
    level: 'log',
    message: 'MFA: challenge passed',
    fields: ['plane', 'userId']
  },
  AUTH_MFA_SETUP_STARTED: {
    level: 'log',
    message: 'MFA: setup initiated',
    fields: ['plane', 'userId']
  },
  AUTH_MFA_ENABLED: {
    level: 'log',
    message: 'MFA: enabled',
    fields: ['plane', 'userId']
  },
  AUTH_MFA_DISABLED: {
    level: 'log',
    message: 'MFA: disabled',
    fields: ['plane', 'userId']
  },
  AUTH_MFA_RECOVERY_CODES_REGENERATED: {
    level: 'log',
    message: 'MFA: recovery codes regenerated',
    fields: ['plane', 'userId']
  },
  AUTH_MFA_NOTHING_TO_RESET: {
    level: 'log',
    message: 'MFA: no second factor to remove',
    fields: ['plane', 'userId']
  },
  AUTH_WS_TICKET_ISSUED: {
    level: 'log',
    message: 'ws-ticket: issued',
    fields: ['userId', 'tenantId']
  },
  AUTH_REHASH_SKIPPED: {
    level: 'log',
    message: 'rehash on verify skipped: the stored hash changed',
    fields: []
  },
  AUTH_LOCKOUT_STATE_UNREADABLE: {
    level: 'warn',
    message: 'login: lockout state unreadable for the onLockout hook',
    fields: ['detail']
  },
  AUTH_EMAIL_CHANGE_TOKEN_STALE: {
    level: 'warn',
    message: 'email change: the token is no longer bound to the account password',
    fields: []
  },
  AUTH_PASSWORD_RESET_TOKEN_STALE: {
    level: 'warn',
    message: 'password reset: the token was issued against a password that has since changed',
    fields: []
  },
  AUTH_MFA_SETUP_KEY_CONSUMED: {
    level: 'warn',
    message: 'MFA: the setup key was consumed by a concurrent request',
    fields: []
  },
  AUTH_INVITATION_REFUSED: {
    level: 'warn',
    message: 'invitation: refused',
    fields: ['reason']
  },
  AUTH_OAUTH_CREATE_REFUSED: {
    level: 'warn',
    message: 'oauth: create refused, the account already exists',
    fields: []
  },
  AUTH_OAUTH_PROVIDER_ERROR: {
    level: 'warn',
    message: 'oauth: the provider returned an error on the callback',
    fields: ['error']
  },
  AUTH_OAUTH_EXCHANGE_FAILED: {
    level: 'error',
    message: 'oauth: the code exchange or profile fetch failed',
    fields: ['detail']
  },
  AUTH_DELIVERY_FAILED: {
    level: 'error',
    message: 'delivery failed',
    fields: ['kind', 'detail']
  },
  AUTH_PASSWORD_RESET_ROLLBACK_FAILED: {
    level: 'error',
    message: 'password reset: the rollback delete failed',
    fields: ['detail']
  },
  AUTH_SESSION_EVICTION_SKIPPED: {
    level: 'error',
    message: 'session limit: eviction skipped',
    fields: ['detail']
  },
  AUTH_SESSION_EVICTION_FAILED: {
    level: 'error',
    message: 'session limit: eviction failed',
    fields: ['detail']
  },
  AUTH_SESSION_LIMIT_RESOLVER_INVALID: {
    level: 'error',
    message:
      'session limit: maxSessionsResolver returned a value that is not a positive whole number',
    fields: []
  },
  AUTH_EMAIL_NOT_SENT: {
    level: 'log',
    message: 'no-op email provider: nothing was sent',
    fields: ['kind']
  },
  AUTH_MFA_SETUP_PAYLOAD_INVALID: {
    level: 'warn',
    message: 'MFA: a stored payload is not valid JSON',
    fields: ['kind']
  }
} as const satisfies Record<string, LogEventSpec>

/** The code of an event the catalog lists. */
export type AuthLogEvent = keyof typeof AUTH_LOG_EVENTS
