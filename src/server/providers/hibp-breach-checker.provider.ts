/**
 * @fileoverview Have I Been Pwned breach checker, queried by k-anonymity range.
 *
 * @layer Provider
 */
import { createHash } from 'node:crypto'

import { Injectable, Logger } from '@nestjs/common'

import type { IPasswordBreachChecker } from '../interfaces/password-breach-checker.interface'

/** The range endpoint. The last five characters of the path are the hash prefix. */
const HIBP_RANGE_URL = 'https://api.pwnedpasswords.com/range/'

/** Characters of the SHA-1 hex sent to the service. The rest never leaves the process. */
const PREFIX_LENGTH = 5

/** How long to wait before giving up and approving the password. */
const DEFAULT_TIMEOUT_MS = 1_500

/**
 * Checks a password against Have I Been Pwned without ever sending it.
 *
 * @remarks
 * The protocol is k-anonymity: the password is SHA-1'd locally, the **first five** hex
 * characters of the digest are sent, and the service answers with every suffix it holds under
 * that prefix — some hundreds of them. The comparison happens here. The service learns a
 * prefix shared by thousands of distinct passwords and nothing else.
 *
 * SHA-1 is not a security choice here and is not used as one: it is the corpus's index. The
 * password is still hashed for storage with scrypt.
 *
 * **Fails open, deliberately.** A timeout, a network error, a rate limit or a malformed
 * response all approve the password. The alternative is an outage in a third-party service
 * blocking password changes — including the password change someone is making *because* they
 * were breached. A breach check is a hardening measure; it is not an authorization decision,
 * and it must not become a dependency of the credential path.
 *
 * @example
 * ```typescript
 * BymaxAuthModule.registerAsync({
 *   useFactory: () => ({ ... }),
 *   extraProviders: [{ provide: BYMAX_AUTH_BREACH_CHECKER, useClass: HibpBreachChecker }]
 * })
 * ```
 *
 * @layer Provider
 */
@Injectable()
export class HibpBreachChecker implements IPasswordBreachChecker {
  private readonly logger = new Logger(HibpBreachChecker.name)

  /**
   * @param timeoutMs - How long to wait for the range response before approving the password.
   *   Defaults to 1500 ms — long enough for a healthy round trip, short enough that a
   *   degraded service does not become a visible delay on every registration.
   */
  constructor(private readonly timeoutMs: number = DEFAULT_TIMEOUT_MS) {}

  /** @inheritdoc */
  async isBreached(password: string): Promise<boolean> {
    const digest = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase()
    const prefix = digest.slice(0, PREFIX_LENGTH)
    const suffix = digest.slice(PREFIX_LENGTH)

    const body = await this.fetchRange(prefix)
    if (body === null) return false

    // Each line is `SUFFIX:COUNT`. A match at all means the password is in the corpus; the
    // count is not consulted, because "breached once" is already disqualifying.
    return body
      .split('\n')
      .some((line) => line.slice(0, line.indexOf(':')).trim().toUpperCase() === suffix)
  }

  /**
   * Fetch the suffix list for a prefix, or `null` when the service could not be consulted.
   *
   * @param prefix - The first five hex characters of the SHA-1 digest.
   * @returns The response body, or `null` on any failure — which approves the password.
   */
  private async fetchRange(prefix: string): Promise<string | null> {
    const abort = AbortSignal.timeout(this.timeoutMs)
    try {
      const response = await fetch(`${HIBP_RANGE_URL}${prefix}`, {
        headers: { 'Add-Padding': 'true' },
        signal: abort
      })
      if (!response.ok) {
        this.logger.warn(`breach check unavailable (status ${response.status}) — password allowed`)
        return null
      }
      return await response.text()
    } catch {
      // Timeout, DNS failure, TLS failure, offline — all the same decision. The message
      // carries no password material, only that the check did not happen.
      this.logger.warn('breach check unreachable — password allowed')
      return null
    }
  }
}

/**
 * The default breach checker: approves every password.
 *
 * @remarks
 * Registered when the consumer supplies no `BYMAX_AUTH_BREACH_CHECKER`, so the credential path
 * behaves exactly as it did before the check existed. Making the network call opt-in rather
 * than opt-out is deliberate: a library should not start talking to a third party because it
 * was upgraded.
 *
 * @layer Provider
 */
@Injectable()
export class AllowAllBreachChecker implements IPasswordBreachChecker {
  /** @inheritdoc */
  async isBreached(_password: string): Promise<boolean> {
    return false
  }
}
