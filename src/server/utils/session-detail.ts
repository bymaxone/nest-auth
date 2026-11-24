/**
 * The per-session detail records stored beside a refresh session: `sd:{hash}` for the dashboard
 * and `psd:{hash}` for the platform.
 *
 * Both use the same four fields and Unix-millisecond timestamps, so either backend sharing the
 * Redis reads the same shape. The two planes describe the device differently, and that difference
 * is part of the bytes both sides read, so it is kept.
 *
 * @layer Utils
 */

import { stringifyJson } from './captured-builtins'
import type { SessionExtra } from '../redis/create-session-script'

/** The longest IP, and on the platform plane the longest device text, kept in a detail record. */
export const MAX_SESSION_FIELD_LENGTH = 45

/**
 * Parses a raw User-Agent string into a short human-readable description.
 *
 * Uses only regex — no external libraries. Detects the browser and OS
 * from the most common UA patterns and returns a string of the form
 * "BrowserName on OSName" (e.g. "Chrome on macOS").
 *
 * @param ua - Raw `User-Agent` header value.
 * @returns Human-readable device description.
 */
export function parseUserAgent(ua: string): string {
  // --- Browser detection (order matters: Edge > Opera > Chrome > Firefox > Safari) ---
  let browser = 'Unknown Browser'

  if (/Edg\//.test(ua)) {
    browser = 'Edge'
  } else if (/OPR\/|Opera/.test(ua)) {
    browser = 'Opera'
  } else if (/Chrome\//.test(ua)) {
    browser = 'Chrome'
  } else if (/Firefox\//.test(ua)) {
    browser = 'Firefox'
  } else if (/Safari\//.test(ua) && /Version\//.test(ua)) {
    browser = 'Safari'
  }

  // --- OS detection ---
  let os = 'Unknown OS'

  if (/Android/.test(ua)) {
    os = 'Android'
  } else if (/iPhone|iPad|iPod/.test(ua)) {
    os = 'iOS'
  } else if (/Windows/.test(ua)) {
    os = 'Windows'
  } else if (/Macintosh|Mac OS X/.test(ua)) {
    os = 'macOS'
  } else if (/Linux/.test(ua)) {
    os = 'Linux'
  }

  return `${browser} on ${os}`
}

/**
 * The `sd:{hash}` value for a dashboard session: the device as {@link parseUserAgent} describes
 * it, and the IP truncated against oversized forwarded values.
 *
 * @param ip - Client IP address.
 * @param userAgent - Raw User-Agent header value.
 * @param now - Creation time in Unix milliseconds.
 * @returns The JSON string stored under `sd:{hash}`.
 */
export function dashboardSessionDetail(ip: string, userAgent: string, now: number): string {
  return stringifyJson({
    device: parseUserAgent(userAgent),
    ip: ip.slice(0, MAX_SESSION_FIELD_LENGTH),
    createdAt: now,
    lastActivityAt: now
  })
}

/**
 * The `psd:{hash}` value for a platform session: the raw User-Agent as the device, truncated, and
 * the IP truncated the same way.
 *
 * @param ip - Client IP address.
 * @param userAgent - Raw User-Agent header value.
 * @param now - Creation time in Unix milliseconds.
 * @returns The JSON string stored under `psd:{hash}`.
 */
export function platformSessionDetail(ip: string, userAgent: string, now: number): string {
  return stringifyJson({
    device: userAgent.slice(0, MAX_SESSION_FIELD_LENGTH),
    ip: ip.slice(0, MAX_SESSION_FIELD_LENGTH),
    createdAt: now,
    lastActivityAt: now
  })
}

/**
 * The `psd:{hash}` record of a new platform session, ready to be written with it.
 *
 * @param tokenHash - SHA-256 of the raw refresh token; the key's `{hash}` segment.
 * @param ip - Client IP address.
 * @param userAgent - Raw User-Agent header value.
 * @param ttl - Record lifetime in seconds; matches the refresh session it describes.
 * @returns The record, stamped with the current time.
 */
export function platformSessionExtra(
  tokenHash: string,
  ip: string,
  userAgent: string,
  ttl: number
): SessionExtra {
  return {
    key: `psd:${tokenHash}`,
    value: platformSessionDetail(ip, userAgent, Date.now()),
    ttl
  }
}
