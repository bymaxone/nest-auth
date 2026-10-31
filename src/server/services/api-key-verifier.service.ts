/**
 * @fileoverview Verifies a presented service key, taking the same steps for every key.
 *
 * @layer Service
 */

import { Inject, Injectable } from '@nestjs/common'

import {
  BYMAX_AUTH_API_KEY_CLOCK,
  BYMAX_AUTH_API_KEY_REPOSITORY,
  BYMAX_AUTH_OPTIONS
} from '../bymax-auth.constants'
import type { ApiKeyClock } from './api-key-clock'
import { ApiKeyLastUsedService } from './api-key-last-used.service'
import type { ResolvedOptions } from '../config/resolved-options'
import {
  API_KEY_DUMMY_DIGEST,
  API_KEY_DUMMY_KEY_ID,
  API_KEY_DUMMY_SECRET,
  apiKeyDigest,
  digestsMatch,
  parseApiKey
} from '../crypto/api-key'
import type { AuthApiKey, IApiKeyRepository } from '../interfaces/api-key-repository.interface'
import type { ApiKeyDenyReason } from '../interfaces/auth-hooks.interface'

/** Why a key was not accepted. */
export type ApiKeyRejection = Extract<
  ApiKeyDenyReason,
  'missing' | 'malformed' | 'unknown' | 'wrong_secret' | 'revoked' | 'expired'
>

/** The outcome of verifying one presented key. */
export type ApiKeyVerdict =
  | { readonly ok: true; readonly key: AuthApiKey }
  | { readonly ok: false; readonly reason: ApiKeyRejection; readonly key: AuthApiKey | null }

/**
 * Verifies a presented key against the store.
 *
 * Every call takes the same steps whatever the key is, in this order:
 * parse (substituting a dummy when it does not parse) → read the row (always) → compute the
 * digest → compare in constant time against the row's digest or a dummy → only then decide.
 * No branch leaves before the decision, so an unknown, malformed, wrong, revoked or expired key
 * cannot be told apart by what the library does.
 *
 * @remarks
 * What this does not hide: the store round trip differs in cost for a present and an absent
 * row, and no library can remove that. Pre-verification flood protection is a per-address
 * throttle in front of the guard, documented in the README.
 */
@Injectable()
export class ApiKeyVerifierService {
  constructor(
    @Inject(BYMAX_AUTH_API_KEY_REPOSITORY) private readonly repository: IApiKeyRepository,
    @Inject(BYMAX_AUTH_API_KEY_CLOCK) private readonly clock: ApiKeyClock,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(ApiKeyLastUsedService) private readonly lastUsed: ApiKeyLastUsedService
  ) {}

  /**
   * Verifies the value of the key header.
   *
   * @param header - The header value as the framework delivered it.
   * @returns The verdict. A store fault propagates: the caller fails closed.
   */
  async verify(header: unknown): Promise<ApiKeyVerdict> {
    // 1-2. Parse; a value that does not parse is replaced by a well-formed dummy so every later
    // step still runs on it.
    const parsed = parseApiKey(header, this.options.apiKeys.prefix)
    const keyId = parsed?.keyId ?? API_KEY_DUMMY_KEY_ID
    const secret = parsed?.secret ?? API_KEY_DUMMY_SECRET

    // 3. Always read a row.
    const row = await this.repository.findById(keyId)

    // 4-5. Always digest, always compare two 32-byte buffers.
    const computed = apiKeyDigest(secret, this.options.apiKeys.pepper)
    const equal = digestsMatch(computed, row?.digest ?? API_KEY_DUMMY_DIGEST)

    // 6. Only now decide.
    const now = this.clock.now()
    const reason = this.rejection(header, parsed !== null, row, equal, now.getTime())
    if (reason !== null) {
      return { ok: false, reason, key: parsed === null ? null : row }
    }
    // Reaching here means `row` is non-null: `rejection` answers 'unknown' for a null row.
    const key = row as AuthApiKey
    this.lastUsed.record(key.id, now)
    return { ok: true, key }
  }

  /**
   * The single decision, evaluated after every step above has run.
   *
   * A key is valid strictly before `expiresAt` and strictly before `revokedAt`: at the instant
   * itself it is not.
   */
  private rejection(
    header: unknown,
    parsed: boolean,
    row: AuthApiKey | null,
    equal: boolean,
    nowMs: number
  ): ApiKeyRejection | null {
    if (!parsed) return header === undefined ? 'missing' : 'malformed'
    if (row === null) return 'unknown'
    if (!equal) return 'wrong_secret'
    if (row.revokedAt !== null && row.revokedAt.getTime() <= nowMs) return 'revoked'
    if (row.expiresAt !== null && row.expiresAt.getTime() <= nowMs) return 'expired'
    return null
  }
}
