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
   * The tenant-scoped brute-force identifier for one MFA flow, and the legacy plane-only one it
   * replaces — equal on the platform plane, where the subject never carried a tenant, and distinct
   * on the dashboard plane, where it now does.
   *
   * A rolling upgrade runs old and new code against one Redis at once: on the dashboard plane an
   * old pod counts a failure under `{flow}:{plane}:{userId}` while a new pod counts it under
   * `{flow}:{userSubject}`, and either alone leaves a hole — a lockout an old pod filled would not
   * stop a new pod, and a success on one would not clear the other. For one release every read
   * consults both and every write touches both, so the two move as one; a later release drops the
   * legacy arm. On the platform plane the two ids are identical (no tenant ever entered the
   * subject), so the legacy arm is skipped — operating it would just be the same key a second time,
   * double-counting a failure and locking a platform admin out at half the threshold. `{flow}`
   * (`challenge` / `disable` / `reauth`) keeps the three counters isolated, exactly as before.
   */
  private counterIds(
    flow: MfaFlow,
    context: MfaFlowPlane,
    userId: string,
    tenantId: string | undefined
  ): { legacy: string; scoped: string } {
    return {
      legacy: hmacSha256(`${flow}:${context}:${userId}`, this.options.hmacKey),
      scoped: hmacSha256(`${flow}:${userSubject(context, userId, tenantId)}`, this.options.hmacKey)
    }
  }

  /**
   * Locked out when EITHER the legacy or the tenant-scoped counter has reached the threshold, so
   * neither a lockout an old pod recorded nor one a new pod recorded can be bypassed mid-migration.
   */
  async isLockedOut(
    flow: MfaFlow,
    context: MfaFlowPlane,
    userId: string,
    tenantId: string | undefined
  ): Promise<boolean> {
    const { legacy, scoped } = this.counterIds(flow, context, userId, tenantId)
    if (await this.bruteForce.isLockedOut(scoped)) return true
    return legacy !== scoped ? this.bruteForce.isLockedOut(legacy) : false
  }

  /**
   * Records the failure under both counters so the budget an attacker spends is seen by old and
   * new code alike — but under the scoped id ONCE when the two coincide (platform plane).
   */
  async recordFailure(
    flow: MfaFlow,
    context: MfaFlowPlane,
    userId: string,
    tenantId: string | undefined
  ): Promise<void> {
    const { legacy, scoped } = this.counterIds(flow, context, userId, tenantId)
    await this.bruteForce.recordFailure(scoped)
    if (legacy !== scoped) await this.bruteForce.recordFailure(legacy)
  }

  /**
   * Clears both counters on success — resetting only one would leave the other to lock a
   * legitimately authenticated user out on the next attempt — collapsing to one when they coincide.
   */
  async reset(
    flow: MfaFlow,
    context: MfaFlowPlane,
    userId: string,
    tenantId: string | undefined
  ): Promise<void> {
    const { legacy, scoped } = this.counterIds(flow, context, userId, tenantId)
    await this.bruteForce.resetFailures(scoped)
    if (legacy !== scoped) await this.bruteForce.resetFailures(legacy)
  }
}
