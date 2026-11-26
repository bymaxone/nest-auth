/**
 * @fileoverview The records a refresh session is written, rotated and recovered with, built from the session they describe.
 *
 * The three calls that store a session take a bundle of eight or nine fields that differ between the dashboard and platform planes
 * only in the tenant, so the bundle is built here, once, from the plane and the session.
 *
 * @layer Utility
 */

import { serializeSession } from './serialize-session'
import type { SessionExtra } from '../redis/create-session-script'
import type { RefreshRotationParams } from '../redis/refresh-rotation'

/** The identity plane a session belongs to. */
type Plane = 'dashboard' | 'platform'

/** What a stored session says about its owner and lineage. */
interface Lineage {
  userId: string
  tenantId: string
  familyId: string
  familyCreatedAt: string
}

/** A platform session has no tenant: the index of its plane is keyed without one. */
function tenantOf(plane: Plane, tenantId: string): string | undefined {
  return plane === 'platform' ? undefined : tenantId
}

/**
 * The record that writes the first session of a login.
 *
 * @param plane - The plane the session belongs to.
 * @param session - The session to store.
 * @param tokenHash - SHA-256 of the raw refresh token.
 * @param ttl - Lifetime of the session in seconds.
 * @param extras - Records written in the same step.
 * @returns The bundle `writeNewSession` takes.
 */
export function newSessionRecord(
  plane: Plane,
  session: Lineage,
  tokenHash: string,
  ttl: number,
  extras: readonly SessionExtra[]
): {
  kind: Plane
  tenantId: string | undefined
  tokenHash: string
  sessionJson: string
  familyId: string
  userId: string
  refreshTtl: number
  extras: readonly SessionExtra[]
} {
  return {
    kind: plane,
    tenantId: tenantOf(plane, session.tenantId),
    tokenHash,
    sessionJson: serializeSession(session),
    familyId: session.familyId,
    userId: session.userId,
    refreshTtl: ttl,
    extras
  }
}

/**
 * The record that rotates a session.
 *
 * @param plane - The plane the session belongs to.
 * @param seed - The session being rotated.
 * @param hashes - SHA-256 of the presented token, then of the new one.
 * @param next - The session to store under the new hash.
 * @param ttls - Lifetime of the new session, then the grace window of the old one, in seconds.
 * @returns The bundle `rotateRefreshSession` takes.
 */
export function rotationRecord(
  plane: Plane,
  seed: Lineage,
  hashes: readonly [oldHash: string, newHash: string],
  next: Lineage,
  ttls: readonly [refreshTtl: number, graceTtl: number]
): RefreshRotationParams {
  return {
    kind: plane,
    tenantId: tenantOf(plane, seed.tenantId),
    oldHash: hashes[0],
    newHash: hashes[1],
    newSessionJson: serializeSession(next),
    familyId: seed.familyId,
    userId: seed.userId,
    refreshTtl: ttls[0],
    graceTtl: ttls[1]
  }
}

/**
 * The record that stores the session a grace hit re-issues.
 *
 * @param plane - The plane the session belongs to.
 * @param grace - The session found in its grace window.
 * @param newHash - SHA-256 of the new refresh token.
 * @param next - The session to store under the new hash.
 * @param refreshTtl - Lifetime of the new session in seconds.
 * @returns The bundle `writeRecoveredSession` takes.
 */
export function recoveredRecord(
  plane: Plane,
  grace: Lineage,
  newHash: string,
  next: Lineage,
  refreshTtl: number
): {
  kind: Plane
  tenantId: string | undefined
  newHash: string
  newSessionJson: string
  familyId: string
  userId: string
  refreshTtl: number
} {
  return {
    kind: plane,
    tenantId: tenantOf(plane, grace.tenantId),
    newHash,
    newSessionJson: serializeSession(next),
    familyId: grace.familyId,
    userId: grace.userId,
    refreshTtl
  }
}
