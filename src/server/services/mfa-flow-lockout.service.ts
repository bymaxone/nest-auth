/**
 * @fileoverview The brute-force counters of the MFA-adjacent flows (`challenge`, `disable`,
 * `reauth`): which identifier each flow counts under, and the lockout read, failure record and
 * reset over it.
 *
 * @layer Service
 */

import { Inject, Injectable } from '@nestjs/common'

import { BruteForceService } from './brute-force.service'
import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { userSubject } from '../constants/user-subject'
import { hmacSha256 } from '../crypto/secure-token'

/** The flows that keep a failure counter of their own. */
export type MfaFlow = 'challenge' | 'disable' | 'reauth'

/** The authentication plane a counter belongs to. */
export type MfaFlowPlane = 'dashboard' | 'platform'

/** Failure counters for the MFA flows, keyed by flow, plane, account and tenant. */
@Injectable()
export class MfaFlowLockoutService {
  constructor(
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(BruteForceService) private readonly bruteForce: BruteForceService
  ) {}

  /**
   * The brute-force identifier for one MFA flow: the flow and the account's length-prefixed subject,
   * which carries the tenant on the dashboard plane. Two tenants' user `1` therefore count under
   * different identifiers, so one tenant's failures can neither lock the other's account out nor be
   * cleared by it. `{flow}` (`challenge` / `disable` / `reauth`) keeps the three counters isolated
   * from each other.
   */
  private counterId(
    flow: MfaFlow,
    context: MfaFlowPlane,
    userId: string,
    tenantId: string | undefined
  ): string {
    return hmacSha256(`${flow}:${userSubject(context, userId, tenantId)}`, this.options.hmacKey)
  }

  /** Whether the account's counter for this flow has reached the lockout threshold. */
  async isLockedOut(
    flow: MfaFlow,
    context: MfaFlowPlane,
    userId: string,
    tenantId: string | undefined
  ): Promise<boolean> {
    return this.bruteForce.isLockedOut(this.counterId(flow, context, userId, tenantId))
  }

  /** Records a failed attempt against the account's counter for this flow. */
  async recordFailure(
    flow: MfaFlow,
    context: MfaFlowPlane,
    userId: string,
    tenantId: string | undefined
  ): Promise<void> {
    await this.bruteForce.recordFailure(this.counterId(flow, context, userId, tenantId))
  }

  /** Clears the account's counter for this flow, on a success. */
  async reset(
    flow: MfaFlow,
    context: MfaFlowPlane,
    userId: string,
    tenantId: string | undefined
  ): Promise<void> {
    await this.bruteForce.resetFailures(this.counterId(flow, context, userId, tenantId))
  }
}
