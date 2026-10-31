/**
 * @fileoverview Issues, revokes and rotates service API keys.
 *
 * @layer Service
 */

import { randomUUID } from 'node:crypto'

import { Inject, Injectable } from '@nestjs/common'

import {
  BYMAX_AUTH_API_KEY_CLOCK,
  BYMAX_AUTH_API_KEY_REPOSITORY,
  BYMAX_AUTH_OPTIONS
} from '../bymax-auth.constants'
import type { ApiKeyClock } from './api-key-clock'
import type { ResolvedOptions } from '../config/resolved-options'
import { apiKeyDigest, formatApiKey, generateApiKeySecret } from '../crypto/api-key'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type {
  AuthApiKey,
  AuthApiKeySummary,
  IApiKeyRepository
} from '../interfaces/api-key-repository.interface'

/** Longest label accepted, in characters. A label names a machine caller, it is not a payload. */
export const API_KEY_MAX_LABEL_LENGTH = 128

/** Longest rotation overlap accepted, in seconds: 30 days. */
export const API_KEY_MAX_OVERLAP_SECONDS = 2_592_000

/** Control characters, which would corrupt a log line or an audit row that carries the label. */
// eslint-disable-next-line no-control-regex -- the point of the pattern is to match control characters
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** What issuing a key asks for. */
export interface IssueApiKeyInput {
  /** Machine caller's name. Not unique. 1 to {@link API_KEY_MAX_LABEL_LENGTH} characters. */
  label: string
  /** Scopes to grant: non-empty, each from `apiKeys.scopes`. */
  scopes: readonly string[]
  /** When the key stops verifying. Must be in the future. Absent means it does not expire. */
  expiresAt?: Date
}

/** A newly issued key. */
export interface IssuedApiKey {
  /**
   * The plaintext key. Returned this once and never retrievable again: only its digest is
   * stored. Hand it to the machine caller and do not log it.
   */
  key: string
  /** The stored row without its digest. */
  record: AuthApiKeySummary
}

/** What rotating a key asks for. */
export interface RotateApiKeyInput {
  /**
   * Seconds the old key keeps verifying after the new one is issued. `0` retires it at once.
   * An integer from 0 to {@link API_KEY_MAX_OVERLAP_SECONDS}.
   */
  overlapSeconds: number
  /** Expiry for the NEW key. Absent means it does not expire; the old key's expiry is not inherited. */
  expiresAt?: Date
}

/**
 * Issues, revokes and rotates service keys.
 *
 * Rotation is not special-cased: it issues a second key with the same label and scopes, and
 * retires the first after the overlap. Several active keys sharing a label is the ordinary state.
 */
@Injectable()
export class ApiKeyService {
  constructor(
    @Inject(BYMAX_AUTH_API_KEY_REPOSITORY) private readonly repository: IApiKeyRepository,
    @Inject(BYMAX_AUTH_API_KEY_CLOCK) private readonly clock: ApiKeyClock,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  /**
   * Issues a new key.
   *
   * @param input - Label, scopes and optional expiry.
   * @returns The plaintext key (once) and the stored record.
   * @throws {AuthException} `auth.validation` for a bad label, scope list or expiry.
   */
  async issue(input: IssueApiKeyInput): Promise<IssuedApiKey> {
    const now = this.clock.now()
    const label = this.validatedLabel(input.label)
    const scopes = this.validatedScopes(input.scopes)
    const expiresAt = this.validatedExpiry('expiresAt', input.expiresAt, now)

    const id = randomUUID()
    const secret = generateApiKeySecret()
    const stored = await this.repository.create({
      id,
      label,
      digest: apiKeyDigest(secret, this.options.apiKeys.pepper),
      scopes,
      createdAt: now,
      expiresAt
    })
    return {
      key: formatApiKey(this.options.apiKeys.prefix, id, secret),
      record: summary(stored)
    }
  }

  /**
   * Revokes a key now. Revoking an already revoked key succeeds.
   *
   * @param id - The key's row id.
   * @throws {AuthException} `auth.api_key_not_found` when no such key exists.
   */
  async revoke(id: string): Promise<void> {
    if (!UUID_PATTERN.test(id) || !(await this.repository.markRevoked(id, this.clock.now()))) {
      throw new AuthException(AUTH_ERROR_CODES.API_KEY_NOT_FOUND)
    }
  }

  /**
   * Replaces a key with a new one carrying the same label and scopes.
   *
   * The new key is issued first and the old one retired second, so a failure between the two
   * leaves both valid — the safe direction — rather than neither.
   *
   * @param id - The active key to replace.
   * @param input - The overlap and an optional expiry for the new key.
   * @returns The new key, plaintext once.
   * @throws {AuthException} `auth.validation` for a bad overlap or expiry;
   *   `auth.api_key_not_found` when no ACTIVE key has this id (a revoked or expired key is not
   *   rotated: that would re-issue access nobody holds).
   */
  async rotate(id: string, input: RotateApiKeyInput): Promise<IssuedApiKey> {
    const now = this.clock.now()
    const overlap = input.overlapSeconds
    if (!Number.isInteger(overlap) || overlap < 0 || overlap > API_KEY_MAX_OVERLAP_SECONDS) {
      throw validation(
        'overlapSeconds',
        `overlapSeconds must be an integer from 0 to ${API_KEY_MAX_OVERLAP_SECONDS}`
      )
    }
    const newExpiry = this.validatedExpiry('expiresAt', input.expiresAt, now)

    const old = UUID_PATTERN.test(id) ? await this.repository.findById(id) : null
    if (old === null || !isActive(old, now)) {
      throw new AuthException(AUTH_ERROR_CODES.API_KEY_NOT_FOUND)
    }

    const issued = await this.issue({
      label: old.label,
      scopes: old.scopes,
      ...(newExpiry === null ? {} : { expiresAt: newExpiry })
    })

    if (overlap === 0) {
      await this.repository.markRevoked(old.id, now)
    } else {
      const retireAt = new Date(now.getTime() + overlap * 1000)
      const sooner =
        // Stryker disable next-line EqualityOperator: at equal instants both arms yield a Date of the same time, so `<` and `<=` store the same expiry
        old.expiresAt !== null && old.expiresAt.getTime() < retireAt.getTime()
          ? old.expiresAt
          : retireAt
      await this.repository.setExpiry(old.id, sooner)
    }
    return issued
  }

  private validatedLabel(label: unknown): string {
    if (
      typeof label !== 'string' ||
      label.trim().length === 0 ||
      label.length > API_KEY_MAX_LABEL_LENGTH ||
      CONTROL_CHARACTERS.test(label)
    ) {
      throw validation(
        'label',
        `label must be 1 to ${API_KEY_MAX_LABEL_LENGTH} characters with no control characters`
      )
    }
    return label
  }

  private validatedScopes(scopes: unknown): readonly string[] {
    if (!Array.isArray(scopes) || scopes.length === 0) {
      throw validation('scopes', 'scopes must be a non-empty list')
    }
    const vocabulary = new Set(this.options.apiKeys.scopes)
    const seen = new Set<unknown>()
    for (const scope of scopes) {
      // The vocabulary holds only strings, so `has` also refuses a non-string entry.
      if (!vocabulary.has(scope as string)) {
        throw validation('scopes', 'every scope must come from the configured vocabulary')
      }
      if (seen.has(scope)) throw validation('scopes', 'scopes must not repeat')
      seen.add(scope)
    }
    return [...(scopes as string[])]
  }

  private validatedExpiry(field: string, value: Date | undefined, now: Date): Date | null {
    if (value === undefined) return null
    if (
      !(value instanceof Date) ||
      Number.isNaN(value.getTime()) ||
      value.getTime() <= now.getTime()
    ) {
      throw validation(field, `${field} must be a valid date in the future`)
    }
    return value
  }
}

function isActive(key: AuthApiKey, now: Date): boolean {
  const nowMs = now.getTime()
  return (
    (key.revokedAt === null || key.revokedAt.getTime() > nowMs) &&
    (key.expiresAt === null || key.expiresAt.getTime() > nowMs)
  )
}

function summary(row: AuthApiKey): AuthApiKeySummary {
  const { digest: _digest, ...rest } = row
  return rest
}

function validation(field: string, message: string): AuthException {
  return new AuthException(AUTH_ERROR_CODES.VALIDATION, [{ field, message }])
}
