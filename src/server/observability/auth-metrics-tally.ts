/**
 * @fileoverview The counts the auth flows keep for whoever publishes metrics, with every label set closed.
 *
 * @layer Service
 */

import { Injectable } from '@nestjs/common'

import type { AuthPlane } from '../services/auth-token-verifier.service'

/** The two planes an authentication flow runs on. */
export const AUTH_PLANES = ['dashboard', 'platform'] as const satisfies readonly AuthPlane[]

/** What a login attempt ended as. */
export const LOGIN_OUTCOMES = [
  'success',
  'invalid_credentials',
  'locked',
  'mfa_required',
  'blocked'
] as const

/** What a refresh attempt ended as. */
export const REFRESH_OUTCOMES = ['rotated', 'reuse_detected', 'expired', 'invalid'] as const

/** What an MFA verification ended as. */
export const MFA_OUTCOMES = ['success', 'invalid', 'locked'] as const

/** What a login attempt ended as, one of {@link LOGIN_OUTCOMES}. */
export type LoginOutcome = (typeof LOGIN_OUTCOMES)[number]
/** What a refresh attempt ended as, one of {@link REFRESH_OUTCOMES}. */
export type RefreshOutcome = (typeof REFRESH_OUTCOMES)[number]
/** What an MFA verification ended as, one of {@link MFA_OUTCOMES}. */
export type MfaOutcome = (typeof MFA_OUTCOMES)[number]

/** A count for each outcome on each plane. */
type PlaneCounts<K extends string> = Readonly<Record<AuthPlane, Readonly<Record<K, number>>>>

/** A zeroed count for each member of a closed set. */
function zeroed<K extends string>(keys: readonly K[]): Record<K, number> {
  return Object.fromEntries(keys.map((key) => [key, 0])) as Record<K, number>
}

/** A zeroed count for each outcome on each plane. */
function zeroedPlanes<K extends string>(keys: readonly K[]): Record<AuthPlane, Record<K, number>> {
  return { dashboard: zeroed(keys), platform: zeroed(keys) }
}

/**
 * Counts what the authentication flows do, in plain numbers.
 *
 * It exists so that the code that does the work never imports a metrics library: an application that
 * publishes nothing pays for a few integer increments, and the optional `observability` subpath reads
 * these numbers when it is scraped. Each count is keyed by a closed set, so no label can grow with the
 * traffic, and nothing a caller or a host supplied is ever a key.
 */
@Injectable()
export class AuthMetricsTally {
  readonly #logins = zeroedPlanes(LOGIN_OUTCOMES)
  readonly #refreshes = zeroedPlanes(REFRESH_OUTCOMES)
  readonly #mfa = zeroedPlanes(MFA_OUTCOMES)
  #lockouts = 0

  /** A login attempt on `plane` ended as `outcome`. */
  login(plane: AuthPlane, outcome: LoginOutcome): void {
    this.#logins[plane][outcome] += 1
  }

  /** A refresh attempt on `plane` ended as `outcome`. */
  refresh(plane: AuthPlane, outcome: RefreshOutcome): void {
    this.#refreshes[plane][outcome] += 1
  }

  /** An MFA verification on `plane` ended as `outcome`. */
  mfa(plane: AuthPlane, outcome: MfaOutcome): void {
    this.#mfa[plane][outcome] += 1
  }

  /** A run of failures reached the threshold and locked an identifier out. */
  lockout(): void {
    this.#lockouts += 1
  }

  /** The counts so far, as copies. */
  snapshot(): {
    readonly logins: PlaneCounts<LoginOutcome>
    readonly refreshes: PlaneCounts<RefreshOutcome>
    readonly mfa: PlaneCounts<MfaOutcome>
    readonly lockouts: number
  } {
    return {
      logins: structuredClone(this.#logins),
      refreshes: structuredClone(this.#refreshes),
      mfa: structuredClone(this.#mfa),
      lockouts: this.#lockouts
    }
  }
}
