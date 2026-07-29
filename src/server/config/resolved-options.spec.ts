/**
 * @fileoverview Tests for resolveOptions(), which merges consumer-supplied options with
 * secure defaults and validates all security-critical invariants at module startup.
 * Covers success paths, every validation error branch, and the new refreshGraceWindow check.
 */

import { createHash } from 'node:crypto'

import type { Request } from 'express'

import { hmacSha256 } from '../crypto/secure-token'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'
import { resolveOptions } from './resolved-options'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/**
 * Produces a high-entropy string of the given length for use as a JWT secret
 * in tests. The string is deterministic (not random) — it cycles through a
 * large fixed charset. It is NOT suitable for production secrets.
 */
function makeTestableHighEntropyString(length = 40): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  let result = ''
  for (let i = 0; i < length; i++) {
    result += chars[i % chars.length]
  }
  return result
}

const VALID_SECRET = makeTestableHighEntropyString(48)

const MINIMAL_OPTIONS: BymaxAuthModuleOptions = {
  jwt: { secret: VALID_SECRET },
  roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } }
}

// ---------------------------------------------------------------------------
// Success paths
// ---------------------------------------------------------------------------

describe('resolveOptions — success', () => {
  // Verifies that minimal valid options produce a resolved object with expected JWT defaults.
  it('should resolve with minimal valid config', () => {
    const resolved = resolveOptions(MINIMAL_OPTIONS)

    expect(resolved.jwt.secret).toBe(VALID_SECRET)
    expect(resolved.jwt.accessExpiresIn).toBe('15m')
    expect(resolved.jwt.refreshExpiresInDays).toBe(7)
    expect(resolved.jwt.algorithm).toBe('HS256')
    expect(resolved.jwt.refreshGraceWindowSeconds).toBe(30)
  })

  // Verifies that the default tokenDelivery mode is 'cookie' when not specified.
  it('should apply default tokenDelivery', () => {
    const resolved = resolveOptions(MINIMAL_OPTIONS)
    expect(resolved.tokenDelivery).toBe('cookie')
  })

  // Verifies that default cookie names are applied when the consumer provides no cookie config.
  it('should apply default cookie names', () => {
    const resolved = resolveOptions(MINIMAL_OPTIONS)
    expect(resolved.cookies.accessTokenName).toBe('access_token')
    expect(resolved.cookies.refreshTokenName).toBe('refresh_token')
    expect(resolved.cookies.sessionSignalName).toBe('has_session')
    expect(resolved.cookies.refreshCookiePath).toBe('/auth')
  })

  // Verifies that default scrypt cost parameters are applied when password config is omitted.
  it('should apply default password scrypt parameters', () => {
    const resolved = resolveOptions(MINIMAL_OPTIONS)
    // OWASP's recommended minimum for scrypt at r=8, p=1. Pinned to the literal rather than
    // read from DEFAULT_OPTIONS: a default that changed by accident would round-trip through
    // its own constant and this assertion would never notice.
    expect(resolved.password.costFactor).toBe(131_072)
    expect(resolved.password.blockSize).toBe(8)
    expect(resolved.password.parallelization).toBe(1)
  })

  // Verifies that default brute-force window and attempt limits are applied.
  it('should apply default bruteForce config', () => {
    const resolved = resolveOptions(MINIMAL_OPTIONS)
    expect(resolved.bruteForce.maxAttempts).toBe(5)
    expect(resolved.bruteForce.windowSeconds).toBe(900)
  })

  // Verifies that default session config (disabled, FIFO eviction, max 5) is applied.
  it('should apply default sessions config', () => {
    const resolved = resolveOptions(MINIMAL_OPTIONS)
    expect(resolved.sessions.enabled).toBe(false)
    expect(resolved.sessions.defaultMaxSessions).toBe(5)
    expect(resolved.sessions.evictionStrategy).toBe('fifo')
  })

  // Verifies that email verification is required by default to protect new registrations.
  it('should apply default emailVerification.required = true', () => {
    const resolved = resolveOptions(MINIMAL_OPTIONS)
    expect(resolved.emailVerification.required).toBe(true)
  })

  // Verifies that the default blocked status list includes BANNED, INACTIVE, and SUSPENDED.
  it('should apply default blockedStatuses', () => {
    const resolved = resolveOptions(MINIMAL_OPTIONS)
    expect(resolved.blockedStatuses).toEqual(['BANNED', 'INACTIVE', 'SUSPENDED'])
  })

  // Verifies that the resolved blockedStatuses is a copy rather than the shared default reference.
  it('should return a fresh blockedStatuses array (not the default reference)', () => {
    const resolved = resolveOptions(MINIMAL_OPTIONS)
    expect(resolved.blockedStatuses).not.toBe(['BANNED', 'INACTIVE', 'SUSPENDED'])
  })

  // Verifies that mutating the caller's original array does not affect the resolved copy.
  it('should always spread caller-provided blockedStatuses (mutation isolation)', () => {
    const statuses = ['DISABLED']
    const resolved = resolveOptions({ ...MINIMAL_OPTIONS, blockedStatuses: statuses })
    expect(resolved.blockedStatuses).toEqual(['DISABLED'])
    // Mutation of the original array must not affect the resolved copy
    statuses.push('EXTRA')
    expect(resolved.blockedStatuses).toEqual(['DISABLED'])
  })

  // Verifies that the default Redis namespace and route prefix are 'auth' when not specified.
  it('should apply default redisNamespace and routePrefix', () => {
    const resolved = resolveOptions(MINIMAL_OPTIONS)
    expect(resolved.redisNamespace).toBe('auth')
    expect(resolved.routePrefix).toBe('auth')
  })

  // Verifies that the default user status cache TTL is 60 seconds.
  it('should apply default userStatusCacheTtlSeconds', () => {
    const resolved = resolveOptions(MINIMAL_OPTIONS)
    expect(resolved.userStatusCacheTtlSeconds).toBe(60)
  })

  // Verifies that `hmacKey` is a deterministic 64-char hex SHA-256 digest derived
  // from the JWT secret and a fixed domain-separation label, so HMAC operations
  // never share a key with JWT signing.
  it('should derive hmacKey as sha256("bymax-auth:hmac-key:v1:" + jwt.secret)', () => {
    const expected = createHash('sha256')
      .update(`bymax-auth:hmac-key:v1:${VALID_SECRET}`, 'utf8')
      .digest('hex')
    const resolved = resolveOptions(MINIMAL_OPTIONS)
    expect(resolved.hmacKey).toBe(expected)
    expect(resolved.hmacKey).not.toBe(VALID_SECRET)
    expect(resolved.hmacKey).toMatch(/^[0-9a-f]{64}$/)
  })

  // CROSS-IMPLEMENTATION KNOWN-ANSWER TEST. The sibling Rust port (bymax-auth) derives the
  // same key and both backends key the same Redis identifiers with it, so this derivation is
  // a wire contract rather than an internal detail: the separator, the hash, and the fact
  // that the HMAC is keyed with the hex TEXT (not the raw digest) all have to match.
  // rust-auth carries the identical vectors in
  // `crates/bymax-auth-core/src/config/validate.rs`. If either side drifts, exactly one of
  // the two suites goes red — instead of the split surfacing in production as lockouts and
  // OTPs that silently miss each other across backends.
  it('should match the rust-auth known-answer vectors for key and identifier', () => {
    const secret = '0123456789abcdef0123456789abcdef'
    const expectedKey = '0dd66555bd2d89e0eb4ce050f1fef427bea6799bec27fb8e313f69ab965048c1'
    const identifierMessage = 'tenant-a:user@example.com'
    const expectedIdentifier = '609a759522bd8b397748fad2dbde07957cea580fe4f4f1f0ce0f526485de2b6d'

    const resolved = resolveOptions({ ...MINIMAL_OPTIONS, jwt: { secret } })

    expect(resolved.hmacKey).toBe(expectedKey)
    expect(hmacSha256(identifierMessage, resolved.hmacKey)).toBe(expectedIdentifier)
  })

  // Verifies that changing the JWT secret produces a different hmacKey (deterministic
  // derivation, not a constant), confirming key separation works per deployment.
  it('should produce distinct hmacKey values for distinct JWT secrets', () => {
    const resolvedA = resolveOptions(MINIMAL_OPTIONS)
    const resolvedB = resolveOptions({
      ...MINIMAL_OPTIONS,
      jwt: { secret: makeTestableHighEntropyString(64) }
    })
    expect(resolvedA.hmacKey).not.toBe(resolvedB.hmacKey)
  })

  // Verifies that explicitly setting algorithm to HS256 does not throw.
  it('should accept jwt.algorithm HS256 explicitly', () => {
    expect(() =>
      resolveOptions({ ...MINIMAL_OPTIONS, jwt: { secret: VALID_SECRET, algorithm: 'HS256' } })
    ).not.toThrow()
  })

  // Verifies that function references (like maxSessionsResolver) survive the options merge without being cloned.
  it('should preserve function-valued properties after merge (no clone)', () => {
    const resolver = (_user: unknown): number => 3
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      sessions: { maxSessionsResolver: resolver }
    }
    const resolved = resolveOptions(options)
    expect(resolved.sessions.maxSessionsResolver).toBe(resolver)
    expect(typeof resolved.sessions.maxSessionsResolver).toBe('function')
  })

  // Verifies that the tenantIdResolver function reference is preserved in resolved options.
  it('should preserve tenantIdResolver function reference', () => {
    const fn = (_req: Request): string => 'tenant-1'
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      tenantIdResolver: fn
    }
    const resolved = resolveOptions(options)
    expect(resolved.tenantIdResolver).toBe(fn)
  })

  // Verifies that partial jwt options are merged over defaults, preserving unspecified defaults.
  it('should merge partial jwt options over defaults', () => {
    const resolved = resolveOptions({
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, accessExpiresIn: '30m' }
    })
    expect(resolved.jwt.accessExpiresIn).toBe('30m')
    expect(resolved.jwt.refreshExpiresInDays).toBe(7) // default preserved
  })

  // Verifies that a valid MFA config with a 32-byte base64 key is accepted and MFA defaults are applied.
  it('should accept valid MFA config with 32-byte base64 key and merge mfa defaults', () => {
    const key = Buffer.alloc(32).toString('base64')
    // All-zero key is the weakest valid AES-256 key — intentional in tests only.
    // Production keys must be generated with crypto.randomBytes(32).
    const resolved = resolveOptions({
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: key, issuer: 'TestApp' }
    })
    expect(resolved.mfa).toBeDefined()
    // Default sub-fields must be resolved even when consumer omits them
    expect(resolved.mfa?.recoveryCodeCount).toBe(8)
    expect(resolved.mfa?.totpWindow).toBe(1)
  })

  // Verifies that resolved.mfa is undefined when no MFA config is provided.
  it('should not set mfa on resolved when mfa is not provided', () => {
    const resolved = resolveOptions(MINIMAL_OPTIONS)
    expect(resolved.mfa).toBeUndefined()
  })

  // Verifies that platform.enabled is accepted when platformHierarchy is also configured.
  it('should accept platform.enabled with platformHierarchy', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        platform: { enabled: true },
        roles: {
          hierarchy: { ADMIN: [] },
          platformHierarchy: { SUPER_ADMIN: [] }
        }
      })
    ).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// secureCookies default — NODE_ENV-driven
// ---------------------------------------------------------------------------

describe('resolveOptions — secureCookies default', () => {
  // Helper: run resolveOptions with NODE_ENV temporarily forced to a value, then
  // restore the original so other suites are not contaminated.
  function withNodeEnv<T>(value: string | undefined, fn: () => T): T {
    const original = process.env['NODE_ENV']
    if (value === undefined) {
      delete process.env['NODE_ENV']
    } else {
      process.env['NODE_ENV'] = value
    }
    try {
      return fn()
    } finally {
      if (original === undefined) {
        delete process.env['NODE_ENV']
      } else {
        process.env['NODE_ENV'] = original
      }
    }
  }

  // Scenario: NODE_ENV is 'production' and the consumer did not set secureCookies.
  // Expected: secureCookies resolves to true. Why: the default is computed as
  // `NODE_ENV === 'production'`; this pins the production branch and kills the
  // `?? false`, env-key, and env-value string mutants which would force false.
  it('should default secureCookies to true when NODE_ENV is production', () => {
    const resolved = withNodeEnv('production', () => resolveOptions(MINIMAL_OPTIONS))
    expect(resolved.secureCookies).toBe(true)
  })

  // Scenario: NODE_ENV is a non-production value ('development') with no consumer override.
  // Expected: secureCookies resolves to false. Why: pins the non-production branch and
  // kills the `?? true` mutant (which would force true) and the `===`→`!==` equality mutant
  // (which would flip the result to true for non-production).
  it('should default secureCookies to false when NODE_ENV is not production', () => {
    const resolved = withNodeEnv('development', () => resolveOptions(MINIMAL_OPTIONS))
    expect(resolved.secureCookies).toBe(false)
  })

  // Scenario: consumer explicitly sets secureCookies: false while NODE_ENV is production.
  // Expected: the explicit false wins over the production default. Why: confirms the
  // `userOptions.secureCookies ??` short-circuit — distinguishes the user-value branch from
  // the NODE_ENV fallback branch.
  it('should let an explicit secureCookies: false override the production default', () => {
    const resolved = withNodeEnv('production', () =>
      resolveOptions({ ...MINIMAL_OPTIONS, secureCookies: false })
    )
    expect(resolved.secureCookies).toBe(false)
  })

  // Scenario: consumer explicitly sets secureCookies: true while NODE_ENV is development.
  // Expected: the explicit true wins over the non-production default of false. Why: pins the
  // other side of the `??` user-value branch so neither fallback constant can satisfy both cases.
  it('should let an explicit secureCookies: true override the non-production default', () => {
    const resolved = withNodeEnv('development', () =>
      resolveOptions({ ...MINIMAL_OPTIONS, secureCookies: true })
    )
    expect(resolved.secureCookies).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// cookies.sameSite default + validation
// ---------------------------------------------------------------------------

describe('resolveOptions — cookies.sameSite', () => {
  /**
   * Verifies that omitting `cookies.sameSite` resolves to `'lax'`. This is the
   * v1.0.5 default and is the difference between OAuth redirects working
   * out-of-the-box and breaking on the first cross-site navigation. A drift
   * back to `'strict'` would silently regress every OAuth-enabled consumer.
   */
  it('should default cookies.sameSite to "lax" when not specified', () => {
    const resolved = resolveOptions(MINIMAL_OPTIONS)
    expect(resolved.cookies.sameSite).toBe('lax')
  })

  /**
   * Verifies that a consumer-supplied `'strict'` wins over the default — the
   * stricter posture is still available for apps that do not need OAuth.
   */
  it('should let an explicit cookies.sameSite: "strict" override the default', () => {
    const resolved = resolveOptions({
      ...MINIMAL_OPTIONS,
      cookies: { sameSite: 'strict' }
    })
    expect(resolved.cookies.sameSite).toBe('strict')
  })

  /**
   * Verifies that `cookies.sameSite: 'none'` is accepted when paired with
   * `secureCookies: true` (the browser-spec requirement). Used by apps that
   * embed authenticated content in iframes or other third-party contexts.
   */
  it('should accept cookies.sameSite: "none" with secureCookies: true', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        secureCookies: true,
        cookies: { sameSite: 'none', trustedOrigins: ['https://app.example.com'] }
      })
    ).not.toThrow()
  })

  /**
   * Verifies that `SameSite=None` without an allowlist is refused. It is the one posture where
   * the browser sends the session cookie cross-site, so with no origin named every cross-site
   * state-changing call is rejected — a deployment that boots and then quietly fails.
   */
  it('should reject cookies.sameSite: "none" with an empty trustedOrigins', () => {
    const resolve = () =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        secureCookies: true,
        cookies: { sameSite: 'none' }
      })

    expect(resolve).toThrow(/cookies\.trustedOrigins is empty/)
    // The message has to carry the remedy, not just the diagnosis: it is the whole reason
    // this is refused at startup instead of at the first rejected request.
    expect(resolve).toThrow('sends the session cookie on every cross-site request')
    expect(resolve).toThrow('every cross-site call that changes state is rejected')
    expect(resolve).toThrow("Set cookies.trustedOrigins: ['https://app.example.com']")
  })

  /**
   * The inverse: an allowlist that can never be consulted, because under `lax` or `strict` the
   * browser does not send the cookie cross-site at all. Refusing it stops a deployment from
   * believing it authorized an origin that will never be asked about.
   */
  it('should reject trustedOrigins under a SameSite posture that never uses it', () => {
    const resolve = () =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        cookies: { trustedOrigins: ['https://app.example.com'] }
      })

    expect(resolve).toThrow(/cookies\.trustedOrigins is set but cookies\.sameSite is 'lax'/)
    expect(resolve).toThrow('does not send the session cookie cross-site under that posture')
    expect(resolve).toThrow('the allowlist is never consulted')
    expect(resolve).toThrow("Use cookies.sameSite: 'none' (with secureCookies: true)")
  })

  /**
   * Every entry is compared verbatim against the `Origin` header, which is always a bare
   * origin. A path, a trailing slash or a naked hostname parses fine but can never match, so
   * it is refused at startup rather than silently blocking the origin it was meant to allow.
   */
  it.each([
    'https://app.example.com/',
    'https://app.example.com/callback',
    'app.example.com',
    'not a url'
  ])('should reject the malformed trusted origin %s', (origin) => {
    const resolve = () =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        secureCookies: true,
        cookies: { sameSite: 'none', trustedOrigins: [origin] }
      })

    expect(resolve).toThrow(/not absolute origins/)
    // The offending entry is named, along with the shape that would have worked — with four
    // origins listed, "one of these is wrong" is not an actionable message.
    expect(resolve).toThrow(origin)
    expect(resolve).toThrow('compared verbatim against the')
    expect(resolve).toThrow("always 'scheme://host[:port]' with no path or trailing slash")
  })

  /**
   * With more than one bad entry the message has to keep them apart — a run-together list is
   * not a list, and the operator has to be able to read which origins to fix.
   */
  it('should name every malformed trusted origin, separated', () => {
    const resolve = () =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        secureCookies: true,
        cookies: {
          sameSite: 'none',
          trustedOrigins: ['app.example.com', 'https://app.example.com/']
        }
      })

    expect(resolve).toThrow('app.example.com, https://app.example.com/')
  })

  /**
   * A port is part of the origin and must survive the round trip, so a local development
   * front end can be listed.
   */
  it('should accept an origin carrying an explicit port', () => {
    const resolved = resolveOptions({
      ...MINIMAL_OPTIONS,
      secureCookies: true,
      cookies: { sameSite: 'none', trustedOrigins: ['http://localhost:3000'] }
    })

    expect(resolved.cookies.trustedOrigins).toEqual(['http://localhost:3000'])
  })

  /**
   * Verifies the startup gate: `'none'` without `Secure` is a misconfiguration
   * browsers silently drop. The validator catches it before the app boots so
   * the broken state is surfaced loud instead of as "auth doesn't work".
   * Forces the non-production NODE_ENV branch where `secureCookies` defaults
   * to `false`, so the consumer's missing override is what trips the check.
   */
  it('should throw when cookies.sameSite: "none" is set without secureCookies: true', () => {
    const original = process.env['NODE_ENV']
    process.env['NODE_ENV'] = 'development'
    try {
      const resolve = () =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          cookies: { sameSite: 'none' }
        })

      expect(resolve).toThrow(/cookies\.sameSite is 'none' but secureCookies is false/)
      expect(resolve).toThrow('Browsers reject SameSite=None cookies without the Secure attribute')
      expect(resolve).toThrow('the auth cookies would never be stored')
      expect(resolve).toThrow('Set secureCookies: true (and serve over HTTPS)')
      expect(resolve).toThrow("use cookies.sameSite: 'lax' / 'strict'")
    } finally {
      if (original === undefined) {
        delete process.env['NODE_ENV']
      } else {
        process.env['NODE_ENV'] = original
      }
    }
  })

  /**
   * Verifies that `cookies.sameSite: 'none'` is accepted in production without
   * an explicit `secureCookies: true` because the `NODE_ENV === 'production'`
   * default makes `secureCookies` true automatically. Pins the interaction
   * between the two defaults so a future refactor that decouples them is
   * forced to retain the spec-compliant outcome.
   */
  it('should accept cookies.sameSite: "none" in production without explicit secureCookies', () => {
    const original = process.env['NODE_ENV']
    process.env['NODE_ENV'] = 'production'
    try {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          cookies: { sameSite: 'none', trustedOrigins: ['https://app.example.com'] }
        })
      ).not.toThrow()
    } finally {
      if (original === undefined) {
        delete process.env['NODE_ENV']
      } else {
        process.env['NODE_ENV'] = original
      }
    }
  })

  /**
   * Verifies that `cookies.sameSite: 'lax'` and `'strict'` do not require
   * `secureCookies: true`. Only `'none'` triggers the spec-driven gate.
   */
  it('should not require secureCookies for cookies.sameSite: "lax" or "strict"', () => {
    const original = process.env['NODE_ENV']
    process.env['NODE_ENV'] = 'development'
    try {
      expect(() =>
        resolveOptions({ ...MINIMAL_OPTIONS, cookies: { sameSite: 'lax' } })
      ).not.toThrow()
      expect(() =>
        resolveOptions({ ...MINIMAL_OPTIONS, cookies: { sameSite: 'strict' } })
      ).not.toThrow()
    } finally {
      if (original === undefined) {
        delete process.env['NODE_ENV']
      } else {
        process.env['NODE_ENV'] = original
      }
    }
  })
})

// ---------------------------------------------------------------------------
// Validation failures — jwt missing entirely
// ---------------------------------------------------------------------------

describe('resolveOptions — jwt missing', () => {
  // Verifies that omitting the jwt group entirely throws a clear startup error.
  it('should throw when jwt configuration is entirely absent', () => {
    // Cast needed because TypeScript does not allow omitting a required field.
    const options = { roles: { hierarchy: { ADMIN: [] } } } as never
    expect(() => resolveOptions(options)).toThrow(/jwt configuration is required/)
  })

  // Scenario: jwt group omitted entirely. Expected: the actionable remediation hint
  // ('Provide at least jwt.secret.') appears in the message. Why: pins the second concatenated
  // string literal so the StringLiteral mutant emptying it is killed.
  it('should include the "Provide at least jwt.secret" remediation in the missing-jwt error', () => {
    const options = { roles: { hierarchy: { ADMIN: [] } } } as never
    expect(() => resolveOptions(options)).toThrow(/Provide at least jwt\.secret\./)
  })
})

// ---------------------------------------------------------------------------
// Validation failures — jwt.secret
// ---------------------------------------------------------------------------

describe('resolveOptions — jwt.secret validation', () => {
  // Verifies that a missing or empty jwt.secret produces a descriptive error rather than a raw
  // TypeError — covers ConfigService callers where config.get() returns undefined at runtime.
  it('should throw a descriptive error when jwt.secret is empty (not a raw TypeError)', () => {
    const options = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: '' }
    } as unknown as BymaxAuthModuleOptions
    expect(() => resolveOptions(options)).toThrow(/\[BymaxAuthModule\] jwt\.secret is required/)
  })

  // Scenario: empty jwt.secret. Expected: the message includes the `node -e ... randomBytes(32)`
  // generation hint. Why: pins the second concatenated literal of the empty-secret error so the
  // StringLiteral mutant emptying that remediation hint is killed.
  it('should include the randomBytes generation hint when jwt.secret is empty', () => {
    const options = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: '' }
    } as unknown as BymaxAuthModuleOptions
    expect(() => resolveOptions(options)).toThrow(/randomBytes\(32\)\.toString\('base64'\)/)
  })

  // Verifies that a secret shorter than 32 characters is rejected at startup.
  it('should throw when secret is shorter than 32 characters', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: 'short-secret' }
    }
    expect(() => resolveOptions(options)).toThrow(/at least 32 characters/)
  })

  // Scenario: secret shorter than 32 chars. Expected: the message includes the `node -e`
  // randomBytes generation hint. Why: pins the second concatenated literal so the StringLiteral
  // mutant emptying the remediation hint on the length error is killed.
  it('should include the randomBytes generation hint when secret is too short', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: 'short-secret' }
    }
    expect(() => resolveOptions(options)).toThrow(/randomBytes\(32\)\.toString\('base64'\)/)
  })

  // Scenario: secret whose Shannon entropy is exactly 3.5 bits/char (16 distinct chars once each
  // plus two chars eight times each over 32 chars). Expected: accepted (no throw). Why: the gate
  // is `entropy < 3.5`, so 3.5 must pass; this kills the EqualityOperator mutant `<`→`<=`, which
  // would reject this boundary value. (edge-case: exact boundary)
  it('should accept a secret with entropy exactly 3.5 bits/char (boundary)', () => {
    // 16 unique chars + 'Y'*8 + 'Z'*8 → length 32, Shannon entropy === 3.5 exactly.
    const boundarySecret = 'ABCDEFGHIJKLMNOP' + 'Y'.repeat(8) + 'Z'.repeat(8)
    expect(boundarySecret.length).toBe(32)
    expect(() =>
      resolveOptions({ ...MINIMAL_OPTIONS, jwt: { secret: boundarySecret } })
    ).not.toThrow()
  })

  // Scenario: low-entropy secret (all same character). Expected: the message includes both the
  // 'minimum: 3.5 bits/char' explanation and the randomBytes hint. Why: pins the two concatenated
  // literals (lines reporting the threshold and the generation hint) so emptying either is killed.
  it('should include the 3.5 bits/char threshold and randomBytes hint in the entropy error', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: 'a'.repeat(40) }
    }
    expect(() => resolveOptions(options)).toThrow(/minimum: 3\.5 bits\/char/)
    expect(() => resolveOptions(options)).toThrow(/randomBytes\(32\)\.toString\('base64'\)/)
  })

  // Verifies that a secret with all identical characters is rejected due to insufficient entropy.
  it('should throw when secret has low entropy (all same character)', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: 'a'.repeat(40) }
    }
    expect(() => resolveOptions(options)).toThrow(/insufficient entropy/)
  })

  // Verifies that a secret with a simple repeating pattern is rejected for low Shannon entropy.
  it('should throw when secret has low entropy (simple repeating pattern)', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: '1234'.repeat(10) }
    }
    expect(() => resolveOptions(options)).toThrow(/insufficient entropy/)
  })

  // Verifies that the error message does not leak the actual secret length as a metadata oracle.
  it('should not include the secret length in the error message', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: 'tooshort' }
    }
    // Length must not appear in the error to prevent metadata leakage to logs
    expect(() => resolveOptions(options)).not.toThrow(/current length/)
    expect(() => resolveOptions(options)).toThrow(/at least 32 characters/)
  })
})

// ---------------------------------------------------------------------------
// Validation failures — jwt.algorithm
// ---------------------------------------------------------------------------

describe('resolveOptions — jwt.algorithm validation', () => {
  // Verifies that asymmetric algorithms are rejected to prevent algorithm confusion attacks.
  it('should throw when algorithm is not HS256', () => {
    const options = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, algorithm: 'RS256' as unknown as 'HS256' }
    }
    expect(() => resolveOptions(options)).toThrow(/must be 'HS256'/)
  })

  // Scenario: a non-HS256 algorithm is supplied. Expected: the message explains the rationale
  // ('Asymmetric algorithms are intentionally unsupported ...'). Why: pins the second concatenated
  // literal so the StringLiteral mutant emptying that explanation is killed.
  it('should explain the algorithm-confusion rationale in the algorithm error', () => {
    const options = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, algorithm: 'RS256' as unknown as 'HS256' }
    }
    expect(() => resolveOptions(options)).toThrow(
      /Asymmetric algorithms are intentionally unsupported/
    )
  })
})

// ---------------------------------------------------------------------------
// Validation failures — mfa.encryptionKey
// ---------------------------------------------------------------------------

describe('resolveOptions — mfa.encryptionKey validation', () => {
  // Verifies that providing the mfa group without an encryptionKey throws a clear error.
  it('should throw when mfa group is provided without encryptionKey', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: '', issuer: 'App' }
    }
    expect(() => resolveOptions(options)).toThrow(/encryptionKey is required/)
  })

  // Scenario: mfa group without encryptionKey. Expected: the randomBytes generation hint is in the
  // message. Why: pins the second concatenated literal of the missing-encryptionKey error so the
  // StringLiteral mutant emptying the hint is killed.
  it('should include the randomBytes hint when encryptionKey is missing', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: '', issuer: 'App' }
    }
    expect(() => resolveOptions(options)).toThrow(/randomBytes\(32\)\.toString\('base64'\)/)
  })

  // Scenario: a standard-base64 key containing '+' and '/' that decodes to exactly 32 bytes.
  // Expected: accepted (no throw). Why: the value matches BASE64_STANDARD_RE but NOT the base64url
  // regex, exercising the `[A-Za-z0-9+/]+` class and `+` quantifier exclusively. Kills the Regex
  // mutants that drop the `+` quantifier or negate the class — both reject a valid standard key.
  it('should accept a standard-base64 encryptionKey containing + and / (32 bytes)', () => {
    // Buffer of 0xfb bytes → standard base64 begins with '+/...' and ends with single '=' padding.
    const stdKey = Buffer.alloc(32, 0xfb).toString('base64')
    expect(stdKey).toMatch(/[+/]/)
    expect(stdKey).not.toMatch(/[_-]/)
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: stdKey, issuer: 'App' }
    }
    expect(() => resolveOptions(options)).not.toThrow()
  })

  // Scenario: a standard-base64 string with two '=' padding chars (contains '/') decoding to 31
  // bytes. Expected: rejected with the 'exactly 32 bytes' byte-length error specifically. Why: under
  // the original BASE64_STANDARD_RE this passes the format check (isStandard=true) and is caught only
  // by the byte-length check; the Regex mutant `={0,2}`→`=` would reject it at the format check
  // (isStandard=false, isUrlSafe=false) and throw the 'must be valid base64' error instead. Asserting
  // the byte-length message and NOT the format message kills that mutant.
  it('should reject a 31-byte standard-base64 key with the byte-length error (not the format error)', () => {
    const key = Buffer.alloc(31, 0xff).toString('base64')
    expect(key).toMatch(/={2}$/)
    expect(key).toMatch(/\//)
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: key, issuer: 'App' }
    }
    expect(() => resolveOptions(options)).toThrow(/decode from base64 to exactly 32 bytes/)
    expect(() => resolveOptions(options)).not.toThrow(/must be valid base64/)
  })

  // Verifies that an encryptionKey with a non-base64 character (e.g. '!') fails the format check (line 261).
  it('should throw when encryptionKey contains characters outside the base64 alphabet', () => {
    // '!' is not a valid base64 character — this must fail the BASE64_RE format check.
    const key = 'AAAA'.repeat(7) + 'AAAA' + '!!!!'
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: key, issuer: 'App' }
    }
    expect(() => resolveOptions(options)).toThrow(/must be valid base64/)
  })

  // Scenario: encryptionKey with an out-of-alphabet character. Expected: the format error includes
  // the randomBytes generation hint. Why: pins the third concatenated literal of the format error so
  // the StringLiteral mutant emptying the hint is killed.
  it('should include the randomBytes hint in the base64 format error', () => {
    const key = 'AAAA'.repeat(7) + 'AAAA' + '!!!!'
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: key, issuer: 'App' }
    }
    expect(() => resolveOptions(options)).toThrow(/randomBytes\(32\)\.toString\('base64'\)/)
  })

  // Verifies that a non-base64 encryptionKey is rejected before key derivation.
  it('should throw when encryptionKey is not valid base64', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      // Hex string of sufficient length — not base64
      mfa: { encryptionKey: 'a'.repeat(64), issuer: 'App' }
    }
    // 'a'.repeat(64) has only 'a' chars — not valid base64 (not a multiple-of-4 group
    // with = padding), so it should fail format validation or byte-length check.
    // Either error is acceptable; what matters is that it does not silently accept garbage.
    expect(() => resolveOptions(options)).toThrow()
  })

  // Verifies that an encryptionKey that decodes to fewer than 32 bytes is rejected for AES-256 compliance.
  it('should throw when encryptionKey decodes to fewer than 32 bytes', () => {
    const key = Buffer.alloc(16).toString('base64') // 16 bytes, not 32
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: key, issuer: 'App' }
    }
    expect(() => resolveOptions(options)).toThrow(/exactly 32 bytes/)
  })

  // Scenario: a 16-byte (under-length) key. Expected: the byte-length error reports the AES-256-GCM
  // context with the actual decoded byte count and includes the randomBytes generation hint. Why:
  // pins the two concatenated literals on the byte-length error (the 'for AES-256-GCM (decoded: N
  // bytes)' fragment and the hint) so the StringLiteral mutants emptying either are killed.
  it('should report AES-256-GCM context and randomBytes hint in the byte-length error', () => {
    const key = Buffer.alloc(16).toString('base64')
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: key, issuer: 'App' }
    }
    expect(() => resolveOptions(options)).toThrow(/for AES-256-GCM \(decoded: 16 bytes\)/)
    expect(() => resolveOptions(options)).toThrow(/randomBytes\(32\)\.toString\('base64'\)/)
  })

  // Verifies that an encryptionKey that decodes to more than 32 bytes is rejected.
  it('should throw when encryptionKey decodes to more than 32 bytes', () => {
    const key = Buffer.alloc(48).toString('base64') // 48 bytes, not 32
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: key, issuer: 'App' }
    }
    expect(() => resolveOptions(options)).toThrow(/exactly 32 bytes/)
  })

  // Verifies that providing the mfa group without an issuer throws a descriptive error.
  it('should throw when mfa group is provided without issuer', () => {
    const key = Buffer.alloc(32).toString('base64')
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: key, issuer: '' }
    }
    expect(() => resolveOptions(options)).toThrow(/mfa.issuer is required/)
  })

  // Scenario: mfa group without issuer. Expected: the message explains the issuer is shown in
  // authenticator apps. Why: pins the second concatenated literal of the missing-issuer error so the
  // StringLiteral mutant emptying that explanation is killed.
  it('should explain that the issuer is displayed in authenticator apps', () => {
    const key = Buffer.alloc(32).toString('base64')
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: key, issuer: '' }
    }
    expect(() => resolveOptions(options)).toThrow(/displayed in authenticator apps/)
  })

  // Verifies that an encryptionKey produced via Node's `base64url` alphabet
  // (containing `-`/`_` instead of `+`/`/`) is accepted. Common consumer mistake:
  // copying `randomBytes(32).toString('base64url')` into the config — the previous
  // strict-base64-only regex rejected this with a confusing "must be valid base64"
  // error even though Node's Buffer decoder accepts it transparently.
  it('should accept a base64url-encoded encryptionKey (with `-`/`_` chars)', () => {
    // Use a buffer that, when std-base64-encoded, would produce both '+' and '/'.
    // Buffer.from([0xff, 0xfe, ..]) → 'std' has /+ chars → 'base64url' replaces them.
    const buf = Buffer.alloc(32, 0xfb)
    const stdKey = buf.toString('base64')
    const urlKey = buf.toString('base64url')
    // Sanity-check that the two encodings actually differ (so this test exercises the
    // base64url branch and not just the standard alphabet branch).
    expect(stdKey).not.toBe(urlKey)
    expect(urlKey).toMatch(/[-_]/)

    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: urlKey, issuer: 'App' }
    }
    expect(() => resolveOptions(options)).not.toThrow()
  })

  // Verifies the diagnostic message references both accepted alphabets so consumers
  // hitting the failure are pointed at the actual root cause (wrong character set).
  it('should mention both base64 and base64url alphabets in the format error', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: 'AAAA****AAAA', issuer: 'App' }
    }
    expect(() => resolveOptions(options)).toThrow(/standard.*base64url/i)
  })
})

// ---------------------------------------------------------------------------
// Validation failures — the bounds on the parameters that carry a control's strength
// ---------------------------------------------------------------------------

describe('resolveOptions — security-parameter bounds', () => {
  const KEY = Buffer.alloc(32, 1).toString('base64')

  /** Options with the given mfa overrides on top of a valid group. */
  function withMfa(overrides: Record<string, unknown>): BymaxAuthModuleOptions {
    return {
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: KEY, issuer: 'App', ...overrides } as NonNullable<
        BymaxAuthModuleOptions['mfa']
      >
    }
  }

  // Scenario: a TOTP window far past any clock skew. Expected: refused at startup. Why: the
  // window is counted in 30-second steps on both sides, so `2n + 1` codes are valid at once —
  // at 60 that is 121, and the six-digit code an attacker has to guess is a hundred times
  // weaker than its length suggests. Every sibling security parameter has a bound; this one
  // decides how much the second factor is worth and had none.
  it('should refuse a TOTP window past the ceiling', () => {
    expect(() => resolveOptions(withMfa({ totpWindow: 60 }))).toThrow(
      /totpWindow must be between 0 and 2/
    )
    expect(() => resolveOptions(withMfa({ totpWindow: 3 }))).toThrow(/totpWindow/)
    expect(() => resolveOptions(withMfa({ totpWindow: -1 }))).toThrow(/totpWindow/)
  })

  // Scenario: the boundary values and the default. Expected: accepted. Why: a bound that
  // rejects a legitimate tolerance is an outage, and 0 (no tolerance at all) is a valid
  // hardening choice, not an error.
  // The bound is the drift window the verifier actually applies, so a configured value always
  // means what it says. It used to be looser (10) than the verifier's clamp (2), which meant
  // `totpWindow: 10` read as "±5 minutes" in the config and behaved as ±1 minute — and behaved
  // differently again in `rust-auth`, which has always clamped.
  it('should accept every window inside the range', () => {
    for (const totpWindow of [0, 1, 2]) {
      expect(() => resolveOptions(withMfa({ totpWindow }))).not.toThrow()
    }
  })

  // Scenario: enrolment configured to mint zero recovery codes. Expected: refused. Why: the
  // account then has no way back if the authenticator is lost, and nothing in the flow reports
  // anything wrong — the user finds out at the worst moment.
  it('should refuse a recovery-code count outside the range', () => {
    expect(() => resolveOptions(withMfa({ recoveryCodeCount: 0 }))).toThrow(
      /recoveryCodeCount must be between 1 and 50/
    )
    expect(() => resolveOptions(withMfa({ recoveryCodeCount: 51 }))).toThrow(/recoveryCodeCount/)
    expect(() => resolveOptions(withMfa({ recoveryCodeCount: 1 }))).not.toThrow()
    expect(() => resolveOptions(withMfa({ recoveryCodeCount: 50 }))).not.toThrow()
  })

  // Scenario: a scrypt block size below 8. Expected: refused. Why: the memory cost is
  // 128 * N * r, so `costFactor`'s floor only guarantees what it claims while r holds. At
  // r = 1 the same N buys an eighth of the memory and the floor quietly stops meaning
  // anything — the weakening is invisible because the parameter that was bounded is intact.
  it('should refuse a block size that divides the memory hardness', () => {
    expect(() => resolveOptions({ ...MINIMAL_OPTIONS, password: { blockSize: 1 } })).toThrow(
      /blockSize must be at least 8/
    )
    expect(() => resolveOptions({ ...MINIMAL_OPTIONS, password: { blockSize: 8 } })).not.toThrow()
  })

  // Scenario: a non-positive parallelization. Expected: refused at startup rather than at the
  // first hash. Why: `crypto.scrypt` rejects it either way; the only question is whether the
  // deployment learns at boot or a user learns at login.
  it('should refuse a parallelization below one', () => {
    expect(() => resolveOptions({ ...MINIMAL_OPTIONS, password: { parallelization: 0 } })).toThrow(
      /parallelization must be at least 1/
    )
    expect(() =>
      resolveOptions({ ...MINIMAL_OPTIONS, password: { parallelization: 1 } })
    ).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// Validation failures — the grace window and the lockout knobs
// ---------------------------------------------------------------------------

describe('resolveOptions — grace window and brute-force bounds', () => {
  // Scenario: a 6-day grace window under a 7-day refresh lifetime. Expected: refused. Why: the
  // existing bound is relative ("< refresh lifetime"), which this passes — but the window is
  // the span in which an ALREADY-CONSUMED refresh token still recovers a session, so it is
  // precisely the replay window for a stolen one. It exists to cover a client that rotated and
  // never received the response: a network retry, measured in seconds.
  it('should refuse a grace window past the absolute ceiling', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        jwt: {
          ...MINIMAL_OPTIONS.jwt,
          refreshGraceWindowSeconds: 6 * 86_400,
          refreshExpiresInDays: 7
        }
      })
    ).toThrow(/refreshGraceWindowSeconds must be between 0 and 300/)
  })

  // Scenario: the boundary values. Expected: accepted. Why: 0 disables grace recovery outright
  // (a legitimate hardening choice) and 300 is the ceiling itself; a bound that rejects either
  // would be an outage rather than a guard.
  it('should accept every grace window inside the range', () => {
    for (const refreshGraceWindowSeconds of [0, 30, 300]) {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          jwt: { ...MINIMAL_OPTIONS.jwt, refreshGraceWindowSeconds }
        })
      ).not.toThrow()
    }
  })

  // Scenario: `bruteForce.windowSeconds: 0`. Expected: refused. Why: the value is handed
  // straight to Redis as the counter's EXPIRE, and Redis DELETES a key on `EXPIRE key 0` — so
  // every failure counter is destroyed at the moment it is created, the count never exceeds
  // one, `isLockedOut` is permanently false, and credential stuffing is bounded only by the
  // per-IP limiter a distributed caller sidesteps. Nothing about that is visible: the config
  // still reads as an enabled lockout.
  it('should refuse a zero or negative brute-force window', () => {
    for (const windowSeconds of [0, -1, 1.5]) {
      expect(() => resolveOptions({ ...MINIMAL_OPTIONS, bruteForce: { windowSeconds } })).toThrow(
        /windowSeconds must be a whole number of at least 1/
      )
    }
  })

  // Scenario: `maxAttempts` at both extremes. Expected: refused. Why: 0 locks out every account
  // permanently (a fresh counter already satisfies "attempts >= 0"), and a huge threshold
  // disables the lockout as effectively as switching it off.
  it('should refuse a brute-force threshold outside the range', () => {
    expect(() => resolveOptions({ ...MINIMAL_OPTIONS, bruteForce: { maxAttempts: 0 } })).toThrow(
      /maxAttempts must be a whole number of at least 1/
    )
    expect(() =>
      resolveOptions({ ...MINIMAL_OPTIONS, bruteForce: { maxAttempts: 1_000_000 } })
    ).toThrow(/maxAttempts must not exceed 100/)
    expect(() =>
      resolveOptions({ ...MINIMAL_OPTIONS, bruteForce: { maxAttempts: 5, windowSeconds: 900 } })
    ).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// Validation failures — mfa.previousEncryptionKeys
// ---------------------------------------------------------------------------

describe('resolveOptions — mfa.previousEncryptionKeys validation', () => {
  const CURRENT = Buffer.alloc(32, 1).toString('base64')
  const RETIRED = Buffer.alloc(32, 2).toString('base64')

  /** The options with the given retired keys, on top of a valid mfa group. */
  function withPrevious(previousEncryptionKeys: unknown): BymaxAuthModuleOptions {
    return {
      ...MINIMAL_OPTIONS,
      mfa: {
        encryptionKey: CURRENT,
        issuer: 'App',
        previousEncryptionKeys
      } as NonNullable<BymaxAuthModuleOptions['mfa']>
    }
  }

  // Scenario: a well-formed rotation. Expected: accepted, and the decoded keys are carried on
  // the resolved options. Why: this is the whole point — a stored secret written under the old
  // key has to keep opening while the rotation drains.
  it('should accept a well-formed rotation and decode every entry', () => {
    const resolved = resolveOptions(withPrevious([RETIRED]))

    expect(resolved.mfa?.previousEncryptionKeys).toEqual([RETIRED])
  })

  // Scenario: the option absent. Expected: accepted, with no retired keys. Why: the ordinary
  // deployment configures no rotation and must not pay for the feature.
  it('should accept the mfa group with no rotation configured', () => {
    const resolved = resolveOptions({
      ...MINIMAL_OPTIONS,
      mfa: { encryptionKey: CURRENT, issuer: 'App' }
    })

    expect(resolved.mfa?.previousEncryptionKeys).toBeUndefined()
  })

  // Scenario: a value that is not an array. Expected: refused at startup. Why: a single string
  // would iterate character by character and every character would fail the key check with a
  // message pointing at the wrong thing.
  it('should refuse a value that is not an array', () => {
    expect(() => resolveOptions(withPrevious(RETIRED))).toThrow(
      /previousEncryptionKeys must be an array/
    )
  })

  // Scenario: an entry that is not a string at all. Expected: refused with the same message the
  // current key gets. Why: `null` reaching the decoder is a crash at the first challenge.
  it('should refuse a non-string entry', () => {
    expect(() => resolveOptions(withPrevious([null]))).toThrow(
      /previousEncryptionKeys\[0\] must be a non-empty base64 string/
    )
  })

  // Scenario: an entry that decodes to 16 bytes. Expected: refused at startup, naming its
  // index. Why: a malformed retired key would otherwise throw at a user's first challenge —
  // during an incident, on the path they most need.
  it('should hold every entry to the 32-byte bar, naming the index', () => {
    const short = Buffer.alloc(16).toString('base64')

    expect(() => resolveOptions(withPrevious([RETIRED, short]))).toThrow(
      /previousEncryptionKeys\[1\].*exactly 32 bytes/s
    )
  })

  // Scenario: the current key listed as retired. Expected: refused. Why: a configuration that
  // reads as rotated while nothing changed is worse than one that never claimed to.
  it('should refuse an entry equal to the current key', () => {
    expect(() => resolveOptions(withPrevious([CURRENT]))).toThrow(
      /repeats mfa.encryptionKey or an earlier entry/
    )
  })

  // Scenario: the same retired key twice. Expected: refused. Why: same reason — a duplicate
  // describes a rotation that did not happen, and hides how many keys still open a secret.
  it('should refuse a duplicated entry', () => {
    expect(() => resolveOptions(withPrevious([RETIRED, RETIRED]))).toThrow(
      /previousEncryptionKeys\[1\].*repeats/s
    )
  })
})

// ---------------------------------------------------------------------------
// Validation failures — roles.hierarchy
// ---------------------------------------------------------------------------

describe('resolveOptions — roles.hierarchy validation', () => {
  // Scenario: roles object present but the hierarchy key omitted. Expected: throws the
  // 'roles.hierarchy is required' error including the example remediation with the `hierarchy:`
  // wrapper. Why: pins both concatenated literals of the missing-hierarchy branch so the
  // StringLiteral mutant emptying the remediation hint is killed.
  it('should throw with remediation when roles.hierarchy is missing', () => {
    const options = { ...MINIMAL_OPTIONS, roles: {} } as never
    expect(() => resolveOptions(options)).toThrow(/roles\.hierarchy is required/)
    expect(() => resolveOptions(options)).toThrow(
      /Define at least one role \(e\.g\. \{ hierarchy: \{ MEMBER: \[\] \} \}\)\./
    )
  })

  // Verifies that an empty hierarchy object is rejected to enforce at least one role.
  it('should throw when roles.hierarchy is an empty object', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      roles: { hierarchy: {} }
    }
    expect(() => resolveOptions(options)).toThrow(/hierarchy must not be an empty object/)
  })

  // Scenario: empty hierarchy object. Expected: the message includes the example remediation
  // ('Define at least one role (e.g. { MEMBER: [] }).'). Why: pins the second concatenated literal
  // of the empty-object error so the StringLiteral mutant emptying it is killed.
  it('should include the example role remediation in the empty-hierarchy error', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      roles: { hierarchy: {} }
    }
    expect(() => resolveOptions(options)).toThrow(
      /Define at least one role \(e\.g\. \{ MEMBER: \[\] \}\)\./
    )
  })

  // Verifies that a role referencing an undeclared child is rejected (referential integrity).
  it('should throw when a role references an undeclared child role', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      roles: { hierarchy: { ADMIN: ['GHOST_ROLE'] } }
    }
    expect(() => resolveOptions(options)).toThrow(/unknown role 'GHOST_ROLE'/)
  })

  // Scenario: a role references a child not declared as a key. Expected: the message includes the
  // referential-integrity explanation ('All roles referenced as children must be declared as
  // keys...'). Why: pins the second concatenated literal so the StringLiteral mutant emptying it is
  // killed.
  it('should explain the referential-integrity requirement in the unknown-child error', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      roles: { hierarchy: { ADMIN: ['GHOST_ROLE'] } }
    }
    expect(() => resolveOptions(options)).toThrow(
      /All roles referenced as children must be declared as keys in the hierarchy\./
    )
  })

  // Verifies that a well-formed multi-level hierarchy does not throw.
  it('should accept a valid multi-level hierarchy', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        roles: { hierarchy: { ADMIN: ['EDITOR', 'VIEWER'], EDITOR: ['VIEWER'], VIEWER: [] } }
      })
    ).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// Validation failures — platform
// ---------------------------------------------------------------------------

describe('resolveOptions — platform validation', () => {
  // Verifies that enabling platform without a platformHierarchy is rejected.
  it('should throw when platform.enabled is true without platformHierarchy', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      platform: { enabled: true }
    }
    expect(() => resolveOptions(options)).toThrow(/platformHierarchy is required/)
  })

  // Scenario: platform.enabled true without platformHierarchy. Expected: the message includes the
  // example platform hierarchy remediation. Why: pins the second concatenated literal of the
  // missing-platformHierarchy error so the StringLiteral mutant emptying it is killed.
  it('should include the example platform hierarchy remediation', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      platform: { enabled: true }
    }
    expect(() => resolveOptions(options)).toThrow(
      /Define the platform role hierarchy \(e\.g\. \{ SUPER_ADMIN: \['SUPPORT'\], SUPPORT: \[\] \}\)\./
    )
  })
})

// ---------------------------------------------------------------------------
// Validation failures — passwordReset.otpLength
// ---------------------------------------------------------------------------

describe('resolveOptions — passwordReset.otpLength validation', () => {
  // Verifies that an OTP length greater than 8 is rejected to prevent poor UX.
  it('should throw when otpLength is greater than 8', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      passwordReset: { otpLength: 9 }
    }
    expect(() => resolveOptions(options)).toThrow(/between 4 and 8/)
  })

  // Scenario: otpLength of 9 (too long). Expected: the message explains both the lower-bound
  // ('too easily guessable') and upper-bound ('degrade user experience') rationale and reports the
  // current value. Why: pins the two concatenated literals (lines describing the current value and
  // the upper-bound rationale) so the StringLiteral mutants emptying either are killed.
  it('should explain the otpLength rationale and report the current value', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      passwordReset: { otpLength: 9 }
    }
    expect(() => resolveOptions(options)).toThrow(
      /\(current: 9\)\. Values below 4 are too easily guessable/
    )
    expect(() => resolveOptions(options)).toThrow(/degrade user experience\./)
  })

  // Verifies that an OTP length less than 4 is rejected as too easily guessable.
  it('should throw when otpLength is less than 4', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      passwordReset: { otpLength: 3 }
    }
    expect(() => resolveOptions(options)).toThrow(/between 4 and 8/)
  })

  // Verifies that an OTP length of exactly 4 (the minimum) is accepted.
  it('should accept otpLength of exactly 4', () => {
    expect(() =>
      resolveOptions({ ...MINIMAL_OPTIONS, passwordReset: { otpLength: 4 } })
    ).not.toThrow()
  })

  // Verifies that an OTP length of exactly 8 (the maximum) is accepted.
  it('should accept otpLength of exactly 8', () => {
    expect(() =>
      resolveOptions({ ...MINIMAL_OPTIONS, passwordReset: { otpLength: 8 } })
    ).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// Validation failures — password.costFactor
// ---------------------------------------------------------------------------

describe('resolveOptions — password.costFactor validation', () => {
  // Verifies that a costFactor below 16384 is rejected as too weak for production.
  it('should throw when costFactor is below 16384', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      password: { costFactor: 8_192 }
    }
    expect(() => resolveOptions(options)).toThrow(/at least 16384/)
  })

  // Scenario: costFactor below the 16384 floor. Expected: the message reports the current value with
  // the brute-force rationale and recommends the production minimum of 32768. Why: pins the two
  // concatenated literals (the current-value/brute-force fragment and the recommended-minimum
  // sentence) so the StringLiteral mutants emptying either are killed.
  it('should report the current value, brute-force rationale, and recommended minimum', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      password: { costFactor: 8_192 }
    }
    expect(() => resolveOptions(options)).toThrow(
      /\(current: 8192\)\. Lower values produce hashes vulnerable to brute-force attacks\./
    )
    expect(() => resolveOptions(options)).toThrow(
      /The recommended minimum for production is 32768 \(2\^15\)\./
    )
  })

  // Verifies that a costFactor that is not a power of 2 is rejected (scrypt requirement).
  it('should throw when costFactor is not a power of 2', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      password: { costFactor: 20_000 }
    }
    expect(() => resolveOptions(options)).toThrow(/power of 2/)
  })

  // Verifies that a costFactor of 16384 (the minimum) is accepted without error.
  it('should accept costFactor of 16384 (minimum allowed)', () => {
    expect(() =>
      resolveOptions({ ...MINIMAL_OPTIONS, password: { costFactor: 16_384 } })
    ).not.toThrow()
  })

  // Verifies that the default costFactor of 32768 is accepted.
  it('should accept costFactor of 32768 (default)', () => {
    expect(() =>
      resolveOptions({ ...MINIMAL_OPTIONS, password: { costFactor: 32_768 } })
    ).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// Validation failures — oauth providers
// ---------------------------------------------------------------------------

describe('resolveOptions — oauth provider validation', () => {
  // Verifies that configuring an OAuth provider without a clientId throws a descriptive error.
  it('should throw when oauth.google is missing clientId', () => {
    const options = {
      ...MINIMAL_OPTIONS,
      oauth: {
        google: { clientId: '', clientSecret: 'secret', callbackUrl: 'https://app.com/cb' }
      }
    }
    expect(() => resolveOptions(options)).toThrow(/oauth\.google\.clientId is required/)
  })

  // Scenario: an OAuth provider missing a required field. Expected: the message ends with the
  // 'OAuth provider is configured.' clause naming the provider. Why: pins the second concatenated
  // literal of the required-field error so the StringLiteral mutant emptying it is killed.
  it('should name the configured provider in the required-field error', () => {
    const options = {
      ...MINIMAL_OPTIONS,
      oauth: {
        google: { clientId: '', clientSecret: 'secret', callbackUrl: 'https://app.com/cb' }
      }
    }
    expect(() => resolveOptions(options)).toThrow(/the 'google' OAuth provider is configured\./)
  })

  // Verifies that configuring an OAuth provider without a clientSecret throws.
  it('should throw when oauth.google is missing clientSecret', () => {
    const options = {
      ...MINIMAL_OPTIONS,
      oauth: {
        google: { clientId: 'id', clientSecret: '', callbackUrl: 'https://app.com/cb' }
      }
    }
    expect(() => resolveOptions(options)).toThrow(/oauth\.google\.clientSecret is required/)
  })

  // Verifies that configuring an OAuth provider without a callbackUrl throws.
  it('should throw when oauth.google is missing callbackUrl', () => {
    const options = {
      ...MINIMAL_OPTIONS,
      oauth: {
        google: { clientId: 'id', clientSecret: 'secret', callbackUrl: '' }
      }
    }
    expect(() => resolveOptions(options)).toThrow(/oauth\.google\.callbackUrl is required/)
  })

  // Verifies that a fully configured OAuth Google provider does not throw.
  it('should accept a fully configured oauth.google', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        oauth: {
          google: {
            clientId: 'client-id',
            clientSecret: 'client-secret',
            callbackUrl: 'https://app.com/callback'
          }
        }
      })
    ).not.toThrow()
  })

  // Verifies that omitting oauth entirely is valid (OAuth is an optional feature).
  it('should not throw when oauth is not configured', () => {
    expect(() => resolveOptions(MINIMAL_OPTIONS)).not.toThrow()
  })

  // Verifies that an HTTP callbackUrl is rejected when NODE_ENV is 'production' —
  // an unencrypted callback URL allows the authorization code to be intercepted in transit.
  it('should throw when oauth.google.callbackUrl uses HTTP in a production environment', () => {
    const originalNodeEnv = process.env['NODE_ENV']
    process.env['NODE_ENV'] = 'production'
    try {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            google: {
              clientId: 'client-id',
              clientSecret: 'client-secret',
              callbackUrl: 'http://app.com/callback'
            }
          }
        })
      ).toThrow(/callbackUrl must use HTTPS in production/)
    } finally {
      // Restore NODE_ENV to prevent contaminating other tests that rely on the default value.
      if (originalNodeEnv === undefined) {
        delete process.env['NODE_ENV']
      } else {
        process.env['NODE_ENV'] = originalNodeEnv
      }
    }
  })

  // Helper: run fn with NODE_ENV forced, then restore. Mirrors the inline pattern above.
  function withNodeEnv<T>(value: string | undefined, fn: () => T): T {
    const original = process.env['NODE_ENV']
    if (value === undefined) {
      delete process.env['NODE_ENV']
    } else {
      process.env['NODE_ENV'] = value
    }
    try {
      return fn()
    } finally {
      if (original === undefined) {
        delete process.env['NODE_ENV']
      } else {
        process.env['NODE_ENV'] = original
      }
    }
  }

  // Scenario: HTTP callbackUrl in production. Expected: the error reports the offending URL and the
  // interception rationale. Why: pins the second concatenated literal of the HTTPS error (line with
  // the got: '<url>' fragment) so the StringLiteral mutant emptying it is killed.
  it('should report the offending URL and interception rationale in the HTTPS error', () => {
    withNodeEnv('production', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'http://app.com/callback'
            }
          }
        })
      ).toThrow(
        /\(got: 'http:\/\/app\.com\/callback'\)\. Use an HTTPS URL to prevent authorization code interception\./
      )
    })
  })

  // Scenario: HTTPS callbackUrl in production. Expected: accepted (no throw). Why: in production an
  // HTTPS URL must pass — the `!callbackUrl.startsWith('https://')` term is false. Kills the
  // ConditionalExpression mutant that replaces `typeof... && !startsWith(...)` with `true` (which
  // would throw on a valid HTTPS URL) and the MethodExpression mutant `startsWith`→`endsWith` (a URL
  // that starts but does not end with 'https://' would then be wrongly rejected).
  it('should accept an HTTPS callbackUrl in production', () => {
    withNodeEnv('production', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'https://app.com/callback'
            }
          }
        })
      ).not.toThrow()
    })
  })

  // Scenario: a callbackUrl that ENDS with 'https://' but starts with 'http://', in production.
  // Expected: rejected (it is not an HTTPS URL). Why: distinguishes startsWith from endsWith — the
  // MethodExpression mutant `startsWith`→`endsWith` would treat this as HTTPS (endsWith true →
  // negation false) and NOT throw, so asserting it throws kills that mutant.
  it('should reject a callbackUrl that only ends with https:// in production', () => {
    withNodeEnv('production', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'http://app.com/redirect?to=https://'
            }
          }
        })
      ).toThrow(/callbackUrl must use HTTPS in production/)
    })
  })

  // Scenario: HTTP callbackUrl in a NON-production environment. Expected: accepted (no throw). Why:
  // the production gate `process.env['NODE_ENV'] === 'production'` is false outside production. Kills
  // the ConditionalExpression mutant replacing that gate with `true` (would throw everywhere) and the
  // LogicalOperator mutant `&&`→`||` (which would throw on any HTTP URL regardless of environment).
  it('should accept an HTTP callbackUrl outside production', () => {
    withNodeEnv('development', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'http://localhost:3000/callback'
            }
          }
        })
      ).not.toThrow()
    })
  })

  // ─── oauth.successRedirectUrl validation ─────────────────────────────────

  /**
   * Verifies the non-empty-string shape check. A misconfigured
   * `process.env.OAUTH_REDIRECT_URL` could surface as `''` in the options
   * object — silently allowing that would land the browser on the empty
   * string, which most servers interpret as `/`. Failing loud at boot is the
   * less-surprising posture.
   */
  it('should throw when oauth.successRedirectUrl is the empty string', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        oauth: {
          successRedirectUrl: '',
          google: {
            clientId: 'id',
            clientSecret: 'secret',
            callbackUrl: 'https://app.com/cb'
          }
        }
      })
    ).toThrow(/successRedirectUrl must be a non-empty string/)
  })

  /**
   * The same guard from its other side. `typeof url !== 'string'` is not
   * redundant with the emptiness check: the type says string, but the value
   * comes from a host's configuration — often straight out of env parsing or a
   * JSON file — and a number has no `.length` at all, so the emptiness half
   * alone would let it through to be redirected to.
   */
  it.each(['successRedirectUrl', 'mfaRedirectUrl', 'errorRedirectUrl'])(
    'should throw when oauth.%s is not a string at all',
    (key) => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            [key]: 8080 as unknown as string,
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'https://app.com/cb'
            }
          }
        })
      ).toThrow(new RegExp(`${key} must be a non-empty string`))
    }
  )

  /**
   * Verifies that an absolute HTTPS URL passes in production. Same security
   * posture as `callbackUrl` — TLS must protect both legs of the OAuth round-trip.
   */
  it('should accept an HTTPS successRedirectUrl in production', () => {
    withNodeEnv('production', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            successRedirectUrl: 'https://app.example.com/dashboard',
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'https://app.example.com/cb'
            }
          }
        })
      ).not.toThrow()
    })
  })

  /**
   * Verifies that a relative path passes in production. Same-origin redirects
   * inherit the protocol of the callback URL, so `/dashboard` is safe.
   */
  it('should accept a same-origin (leading-slash) successRedirectUrl in production', () => {
    withNodeEnv('production', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            successRedirectUrl: '/dashboard',
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'https://app.example.com/cb'
            }
          }
        })
      ).not.toThrow()
    })
  })

  /**
   * Verifies an HTTP successRedirectUrl is rejected in production. The redirect
   * must not downgrade the user from HTTPS to plain HTTP — that would expose
   * the freshly-set authentication cookies on the next request.
   */
  it('should throw when successRedirectUrl uses HTTP in production', () => {
    withNodeEnv('production', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            successRedirectUrl: 'http://app.example.com/dashboard',
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'https://app.example.com/cb'
            }
          }
        })
      ).toThrow(/successRedirectUrl must use HTTPS or be a same-origin path/)
      // The rejected value is echoed back — with several redirect URLs configured,
      // naming the rule without naming the offender is not actionable.
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            successRedirectUrl: 'http://app.example.com/dashboard',
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'https://app.example.com/cb'
            }
          }
        })
      ).toThrow("(starts with '/') in production (got: 'http://app.example.com/dashboard')")
    })
  })

  /**
   * Verifies an HTTP successRedirectUrl is accepted outside production. Local
   * development typically uses `http://localhost:3000/dashboard`, which must
   * remain valid — production gating is the only place HTTP is rejected.
   */
  it('should accept an HTTP successRedirectUrl outside production', () => {
    withNodeEnv('development', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            successRedirectUrl: 'http://localhost:3000/dashboard',
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'http://localhost:3000/cb'
            }
          }
        })
      ).not.toThrow()
    })
  })

  /**
   * Verifies the delivery-mode invariant. With `tokenDelivery: 'bearer'` the
   * lib returns the access token in the JSON body — a 302 replaces that body
   * with redirect headers, so the destination page would never see the token.
   * The startup error makes the misconfiguration loud.
   */
  it('should throw when successRedirectUrl is set together with tokenDelivery: bearer', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        tokenDelivery: 'bearer',
        oauth: {
          successRedirectUrl: '/dashboard',
          google: {
            clientId: 'id',
            clientSecret: 'secret',
            callbackUrl: 'https://app.com/cb'
          }
        }
      })
    ).toThrow(/tokenDelivery is 'bearer'/)
    // The remedy is the operator-facing half of this error, and the reason the pair is
    // refused at boot instead of at the first sign-in that silently drops its token.
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        tokenDelivery: 'bearer',
        oauth: {
          successRedirectUrl: 'https://app.example.com/dashboard',
          google: {
            clientId: 'id',
            clientSecret: 'secret',
            callbackUrl: 'https://app.example.com/cb'
          }
        }
      })
    ).toThrow('A redirect discards the JSON response body')
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        tokenDelivery: 'bearer',
        oauth: {
          successRedirectUrl: 'https://app.example.com/dashboard',
          google: {
            clientId: 'id',
            clientSecret: 'secret',
            callbackUrl: 'https://app.example.com/cb'
          }
        }
      })
    ).toThrow("Use tokenDelivery: 'cookie' or 'both'")
  })

  /**
   * Verifies that the validator does NOT trip on a fully omitted
   * `successRedirectUrl`. This guards the back-compatibility path — every
   * existing 1.0.x consumer relies on the JSON body response and must not
   * see a regression after upgrading.
   */
  it('should not throw when successRedirectUrl is absent', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        oauth: {
          google: {
            clientId: 'id',
            clientSecret: 'secret',
            callbackUrl: 'https://app.com/cb'
          }
        }
      })
    ).not.toThrow()
  })

  // ─── oauth.mfaRedirectUrl validation (1.0.7) ─────────────────────────────

  /**
   * Verifies the non-empty-string shape check for `mfaRedirectUrl`.
   * A misconfigured `process.env.OAUTH_MFA_REDIRECT_URL` could surface as
   * `''` in the options object — silently allowing that would land the
   * browser on the empty string. Failing loud at boot is the less-surprising
   * posture.
   */
  it('should throw when oauth.mfaRedirectUrl is the empty string', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        oauth: {
          mfaRedirectUrl: '',
          google: {
            clientId: 'id',
            clientSecret: 'secret',
            callbackUrl: 'https://app.com/cb'
          }
        }
      })
    ).toThrow(/mfaRedirectUrl must be a non-empty string/)
  })

  /**
   * Verifies an HTTPS URL passes in production for `mfaRedirectUrl`. Same
   * security posture as `successRedirectUrl` — TLS must protect both legs
   * of the OAuth → MFA challenge round-trip.
   */
  it('should accept an HTTPS mfaRedirectUrl in production', () => {
    withNodeEnv('production', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            mfaRedirectUrl: 'https://app.example.com/auth/mfa',
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'https://app.example.com/cb'
            }
          }
        })
      ).not.toThrow()
    })
  })

  /**
   * Verifies that a relative path passes in production for `mfaRedirectUrl`.
   */
  it('should accept a same-origin (leading-slash) mfaRedirectUrl in production', () => {
    withNodeEnv('production', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            mfaRedirectUrl: '/auth/mfa',
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'https://app.example.com/cb'
            }
          }
        })
      ).not.toThrow()
    })
  })

  /**
   * Verifies an HTTP `mfaRedirectUrl` is rejected in production. The
   * redirect must not downgrade the user from HTTPS to plain HTTP — that
   * would expose the freshly-set `mfa_temp_token` cookie on the next leg.
   */
  it('should throw when mfaRedirectUrl uses HTTP in production', () => {
    withNodeEnv('production', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            mfaRedirectUrl: 'http://app.example.com/auth/mfa',
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'https://app.example.com/cb'
            }
          }
        })
      ).toThrow(/mfaRedirectUrl must use HTTPS or be a same-origin path/)
      // The rejected value is echoed back — with several redirect URLs configured,
      // naming the rule without naming the offender is not actionable.
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            mfaRedirectUrl: 'http://app.example.com/mfa',
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'https://app.example.com/cb'
            }
          }
        })
      ).toThrow("(starts with '/') in production (got: 'http://app.example.com/mfa')")
    })
  })

  /**
   * Verifies an HTTP `mfaRedirectUrl` is accepted outside production. Local
   * development typically uses `http://localhost:3000/auth/mfa`, which must
   * remain valid.
   */
  it('should accept an HTTP mfaRedirectUrl outside production', () => {
    withNodeEnv('development', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            mfaRedirectUrl: 'http://localhost:3000/auth/mfa',
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'http://localhost:3000/cb'
            }
          }
        })
      ).not.toThrow()
    })
  })

  /**
   * Unlike `successRedirectUrl`, `mfaRedirectUrl` is compatible with every
   * `tokenDelivery` mode because no session token travels through the
   * redirect — only the dedicated `mfa_temp_token` cookie.
   */
  it('should accept mfaRedirectUrl together with tokenDelivery: bearer', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        tokenDelivery: 'bearer',
        oauth: {
          mfaRedirectUrl: '/auth/mfa',
          google: {
            clientId: 'id',
            clientSecret: 'secret',
            callbackUrl: 'https://app.com/cb'
          }
        }
      })
    ).not.toThrow()
  })

  /**
   * Back-compat guard: omitting `mfaRedirectUrl` must not trip the validator.
   */
  it('should not throw when mfaRedirectUrl is absent', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        oauth: {
          google: {
            clientId: 'id',
            clientSecret: 'secret',
            callbackUrl: 'https://app.com/cb'
          }
        }
      })
    ).not.toThrow()
  })

  // ─── oauth.errorRedirectUrl validation (1.0.7) ───────────────────────────

  /**
   * Verifies the non-empty-string shape check for `errorRedirectUrl`. The
   * same posture as `successRedirectUrl` / `mfaRedirectUrl` — empty values
   * are rejected at boot.
   */
  it('should throw when oauth.errorRedirectUrl is the empty string', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        oauth: {
          errorRedirectUrl: '',
          google: {
            clientId: 'id',
            clientSecret: 'secret',
            callbackUrl: 'https://app.com/cb'
          }
        }
      })
    ).toThrow(/errorRedirectUrl must be a non-empty string/)
  })

  /**
   * Verifies an HTTPS URL passes in production for `errorRedirectUrl`.
   */
  it('should accept an HTTPS errorRedirectUrl in production', () => {
    withNodeEnv('production', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            errorRedirectUrl: 'https://app.example.com/auth/error',
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'https://app.example.com/cb'
            }
          }
        })
      ).not.toThrow()
    })
  })

  /**
   * Verifies a same-origin path passes in production for `errorRedirectUrl`.
   */
  it('should accept a same-origin (leading-slash) errorRedirectUrl in production', () => {
    withNodeEnv('production', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            errorRedirectUrl: '/auth/error',
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'https://app.example.com/cb'
            }
          }
        })
      ).not.toThrow()
    })
  })

  /**
   * Verifies an HTTP `errorRedirectUrl` is rejected in production.
   */
  it('should throw when errorRedirectUrl uses HTTP in production', () => {
    withNodeEnv('production', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            errorRedirectUrl: 'http://app.example.com/auth/error',
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'https://app.example.com/cb'
            }
          }
        })
      ).toThrow(/errorRedirectUrl must use HTTPS or be a same-origin path/)
      // The rejected value is echoed back — with several redirect URLs configured,
      // naming the rule without naming the offender is not actionable.
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            errorRedirectUrl: 'http://app.example.com/error',
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'https://app.example.com/cb'
            }
          }
        })
      ).toThrow("(starts with '/') in production (got: 'http://app.example.com/error')")
    })
  })

  /**
   * Verifies HTTP outside production is allowed for `errorRedirectUrl`.
   */
  it('should accept an HTTP errorRedirectUrl outside production', () => {
    withNodeEnv('development', () => {
      expect(() =>
        resolveOptions({
          ...MINIMAL_OPTIONS,
          oauth: {
            errorRedirectUrl: 'http://localhost:3000/auth/error',
            google: {
              clientId: 'id',
              clientSecret: 'secret',
              callbackUrl: 'http://localhost:3000/cb'
            }
          }
        })
      ).not.toThrow()
    })
  })

  /**
   * Back-compat guard: omitting `errorRedirectUrl` must not trip the
   * validator — the lib still propagates the AuthException to NestJS's
   * exception filter in that case.
   */
  it('should not throw when errorRedirectUrl is absent', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        oauth: {
          google: {
            clientId: 'id',
            clientSecret: 'secret',
            callbackUrl: 'https://app.com/cb'
          }
        }
      })
    ).not.toThrow()
  })

  /**
   * Verifies all three redirect URLs can co-exist. Pins the interaction
   * between the three independent validators so a future refactor cannot
   * accidentally couple them.
   */
  it('should accept successRedirectUrl, mfaRedirectUrl, and errorRedirectUrl together', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        oauth: {
          successRedirectUrl: '/dashboard',
          mfaRedirectUrl: '/auth/mfa',
          errorRedirectUrl: '/auth/error',
          google: {
            clientId: 'id',
            clientSecret: 'secret',
            callbackUrl: 'https://app.com/cb'
          }
        }
      })
    ).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// Validation failures — jwt.refreshGraceWindowSeconds
// ---------------------------------------------------------------------------

describe('resolveOptions — jwt.refreshGraceWindowSeconds validation', () => {
  // Verifies that a grace window equal to the refresh token lifetime causes a startup error.
  it('should throw when refreshGraceWindowSeconds equals refreshExpiresInDays * 86400', () => {
    // refreshExpiresInDays=1 → lifetime = 86400s. Grace window of 86400s is not less than that.
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, refreshExpiresInDays: 1, refreshGraceWindowSeconds: 86_400 }
    }
    expect(() => resolveOptions(options)).toThrow(/refreshGraceWindowSeconds/)
  })

  // Verifies that a grace window greater than the refresh token lifetime causes a startup error.
  it('should throw when refreshGraceWindowSeconds exceeds refresh token lifetime', () => {
    // refreshExpiresInDays=1 → lifetime = 86400s. Grace window of 90000s exceeds that.
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, refreshExpiresInDays: 1, refreshGraceWindowSeconds: 90_000 }
    }
    expect(() => resolveOptions(options)).toThrow(/refreshGraceWindowSeconds/)
  })

  // Scenario: grace window equal to the refresh lifetime. Expected: the message reports the computed
  // lifetime via the `* 86400 (<N> s)` fragment and explains the grace-pointer rationale across both
  // following clauses. Why: pins the three concatenated literals of the grace-window error so the
  // StringLiteral mutants emptying any of them are killed.
  it('should report the computed lifetime and grace-pointer rationale in the error', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, refreshExpiresInDays: 1, refreshGraceWindowSeconds: 86_400 }
    }
    expect(() => resolveOptions(options)).toThrow(
      /jwt\.refreshExpiresInDays \* 86400 \(86400 s\)\./
    )
    expect(() => resolveOptions(options)).toThrow(
      /A grace window equal to or longer than the token lifetime would allow grace pointers/
    )
    expect(() => resolveOptions(options)).toThrow(/to outlive the refresh session they protect\./)
  })

  // Verifies that a grace window strictly less than the refresh token lifetime is accepted.
  it('should not throw when refreshGraceWindowSeconds is within the refresh token lifetime', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, refreshExpiresInDays: 7, refreshGraceWindowSeconds: 30 }
    }
    expect(() => resolveOptions(options)).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// Validation failures — jwt.accessExpiresIn vs the token-epoch retention window
// ---------------------------------------------------------------------------

describe('resolveOptions — jwt.accessExpiresIn validation', () => {
  // 30 days, the window the store guarantees a bumped token epoch stays readable for.
  const RETENTION_SECONDS = 30 * 24 * 60 * 60

  // Scenario: an access token configured to live exactly as long as the epoch record. Expected:
  // accepted. Why: the bound is the last value at which a pre-bump token is still covered, so an
  // off-by-one that rejected it (or that shifted the comparison) would be caught here.
  it('should accept an access lifetime exactly at the retention window', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, accessExpiresIn: `${RETENTION_SECONDS}s` }
    }
    expect(() => resolveOptions(options)).not.toThrow()
  })

  // Scenario: one second past the window. Expected: startup fails. Why: this is the fail-open the
  // rule exists to prevent — the epoch record can expire while the token it revokes is still
  // presentable, and the staleness check silently stops firing.
  it('should throw when the access lifetime outlives the retention window', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, accessExpiresIn: `${RETENTION_SECONDS + 1}s` }
    }
    expect(() => resolveOptions(options)).toThrow(
      new RegExp(`accessExpiresIn \\('${RETENTION_SECONDS + 1}s' = ${RETENTION_SECONDS + 1} s\\)`)
    )
    expect(() => resolveOptions(options)).toThrow(
      /must not exceed the token-epoch retention window \(2592000 s\)\./
    )
    expect(() => resolveOptions(options)).toThrow(
      /An access token that outlives the stored epoch would survive the password reset that revoked it/
    )
    expect(() => resolveOptions(options)).toThrow(
      /the epoch lookup falls back to 0 once the record expires, and the staleness check stops firing\./
    )
  })

  // Scenario: each unit `ms` accepts, long and short form, at a value inside the window. Expected:
  // all parse. Why: the unit table is what converts the configured string into the number the bound
  // is checked against — a unit read as the wrong magnitude would either reject a valid config or,
  // worse, let an over-long lifetime through.
  it.each([
    ['900ms', false],
    ['900 milliseconds', false],
    ['15m', false],
    ['15 minutes', false],
    ['1h', false],
    ['1 hour', false],
    ['1d', false],
    ['1 day', false],
    ['1w', false],
    ['1 week', false],
    ['31 days', true],
    ['1y', true],
    ['1 year', true]
  ])('should read %s and %s the retention bound', (accessExpiresIn, exceeds) => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, accessExpiresIn }
    }
    if (exceeds) {
      expect(() => resolveOptions(options)).toThrow(/token-epoch retention window/)
    } else {
      expect(() => resolveOptions(options)).not.toThrow()
    }
  })

  // Scenario: strings that are not a positive time span. Expected: startup fails with the parse
  // message. Why: a bare number is ambiguous (`ms` reads it as milliseconds, a reader means
  // seconds), an unknown unit leaves the bound unverifiable, and a zero or negative lifetime
  // mints a token that is expired on arrival — all configuration errors that would otherwise
  // surface at the first token issued.
  it.each(['900', '', 'soon', '15 fortnights', '15 m s', 'm15', '0m', '-5m'])(
    'should throw on the unreadable time span %p',
    (accessExpiresIn) => {
      const options: BymaxAuthModuleOptions = {
        ...MINIMAL_OPTIONS,
        jwt: { secret: VALID_SECRET, accessExpiresIn }
      }
      expect(() => resolveOptions(options)).toThrow(
        /accessExpiresIn must be a time span such as '15m', '1h' or '900s'/
      )
      expect(() => resolveOptions(options)).toThrow(
        /A value the signer cannot read would fail at the first token issued, and leaves the token-epoch retention bound unverifiable at startup\./
      )
    }
  )

  // Scenario: surrounding whitespace and mixed case, which a hand-written config picks up easily.
  // Expected: both are normalised rather than rejected.
  it('should tolerate surrounding whitespace and unit casing', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, accessExpiresIn: '  15 Minutes  ' }
    }
    expect(() => resolveOptions(options)).not.toThrow()
  })

  // Scenario: the option left unset. Expected: the default is validated, not skipped. Why: an
  // omitted value must be checked against the same bound, or the rule could be bypassed by
  // relying on a default that later changes.
  it('should validate the default access lifetime when the option is omitted', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET }
    }
    expect(() => resolveOptions(options)).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// Validation failures — jwt.previousSecrets
// ---------------------------------------------------------------------------

describe('resolveOptions — jwt.previousSecrets validation', () => {
  // A retired secret has to clear the same entropy bar as the current one, so it is a real
  // random-looking value rather than a padded placeholder.
  const OTHER_SECRET = 'kR7pQw9zTr4XmVn2PsB6yLdG3hJ8fCxZ5aNeU1oIqW0M'

  // Scenario: no rotation in progress. Expected: accepted, and no derived keys. Why: the field
  // is absent in every deployment that has never rotated, which is most of them.
  it('should accept an absent list and derive no previous keys', () => {
    const resolved = resolveOptions({ ...MINIMAL_OPTIONS, jwt: { secret: VALID_SECRET } })
    expect(resolved.previousHmacKeys).toEqual([])
  })

  // Scenario: a rotation in progress. Expected: one derived HMAC key per retired secret, in
  // order, and none equal to the current one. Why: those keys are what keep recovery-code
  // digests written before the rotation readable — the digests are keyed by an HMAC derived
  // from the secret, so without them a rotation silently invalidates every code a user filed.
  it('should derive one HMAC key per retired secret', () => {
    const resolved = resolveOptions({
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, previousSecrets: [OTHER_SECRET] }
    })

    expect(resolved.previousHmacKeys).toHaveLength(1)
    expect(resolved.previousHmacKeys[0]).toMatch(/^[0-9a-f]{64}$/)
    expect(resolved.previousHmacKeys[0]).not.toBe(resolved.hmacKey)
  })

  // Scenario: a retired secret that would not have been accepted as the current one. Expected:
  // rejected. Why: it still verifies tokens, so a weak entry is as forgeable as a weak current
  // secret — the rotation list is not a place where the bar drops.
  it.each([
    ['too short', 'short'],
    ['low entropy', 'a'.repeat(40)]
  ])('should reject a %s retired secret', (_label, secret) => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        jwt: { secret: VALID_SECRET, previousSecrets: [secret] }
      })
    ).toThrow(/jwt\.secret/)
  })

  // Scenario: a non-string entry, and a non-array value. Expected: rejected by shape.
  it('should reject a malformed list', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        jwt: { secret: VALID_SECRET, previousSecrets: [42 as unknown as string] }
      })
    ).toThrow(/previousSecrets\[0\] must be a string/)

    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        jwt: { secret: VALID_SECRET, previousSecrets: 'not-an-array' as unknown as string[] }
      })
    ).toThrow(/must be an array of strings/)
  })

  // Scenario: the current secret repeated in the retired list, and a duplicate entry. Expected:
  // rejected. Why: a configuration that reads as rotated while nothing changed is worse than
  // one that never claimed to — an operator would believe the old key was retired.
  it.each([
    ['the current secret', [VALID_SECRET]],
    ['a duplicate entry', [OTHER_SECRET, OTHER_SECRET]]
  ])('should reject %s in the list', (_label, previousSecrets) => {
    expect(() =>
      resolveOptions({ ...MINIMAL_OPTIONS, jwt: { secret: VALID_SECRET, previousSecrets } })
    ).toThrow(/repeats jwt\.secret or an earlier entry/)
  })
})

// ---------------------------------------------------------------------------
// Validation failures — refreshCookiePath (now throws instead of warns)
// ---------------------------------------------------------------------------

describe('resolveOptions — refreshCookiePath validation', () => {
  // Verifies that a custom routePrefix without refreshCookiePath throws to prevent misconfigured cookie path.
  it('should throw when routePrefix differs from auth and refreshCookiePath not set', () => {
    expect(() => resolveOptions({ ...MINIMAL_OPTIONS, routePrefix: 'api/auth' })).toThrow(
      /refreshCookiePath/
    )
  })

  // Scenario: custom routePrefix without refreshCookiePath. Expected: the message names the actual
  // prefix, explains the '/auth' default mismatch, the every-request consequence, and the precise
  // remediation `Set cookies.refreshCookiePath: '/<prefix>'`. Why: pins all four concatenated
  // literals (with the interpolated prefix) so the StringLiteral mutants emptying any of them are
  // killed — the prefix interpolation also pins it is `${prefix}`, not a constant.
  it('should produce the full refreshCookiePath remediation including the prefix', () => {
    const run = (): unknown => resolveOptions({ ...MINIMAL_OPTIONS, routePrefix: 'api/auth' })
    expect(run).toThrow(/routePrefix is 'api\/auth' but cookies\.refreshCookiePath is not set\./)
    expect(run).toThrow(
      /The refresh cookie path defaults to '\/auth', which will not match your routes/
    )
    expect(run).toThrow(
      /the refresh cookie will be sent on every request instead of only to the refresh endpoint\./
    )
    expect(run).toThrow(
      /Set cookies\.refreshCookiePath: '\/api\/auth' to restrict the refresh cookie correctly\./
    )
  })

  // Verifies that a custom routePrefix with partial cookie config but missing refreshCookiePath still throws.
  it('should throw when routePrefix differs, cookies provided but refreshCookiePath absent', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        routePrefix: 'api/auth',
        cookies: { accessTokenName: 'tok' }
      })
    ).toThrow(/refreshCookiePath/)
  })

  // Verifies that a custom routePrefix with refreshCookiePath explicitly set is accepted.
  it('should not throw when routePrefix differs but refreshCookiePath is explicitly set', () => {
    expect(() =>
      resolveOptions({
        ...MINIMAL_OPTIONS,
        routePrefix: 'api/auth',
        cookies: { refreshCookiePath: '/api/auth' }
      })
    ).not.toThrow()
  })

  // Verifies that using the default 'auth' routePrefix does not require refreshCookiePath.
  it('should not throw when routePrefix is the default auth', () => {
    expect(() => resolveOptions({ ...MINIMAL_OPTIONS, routePrefix: 'auth' })).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// Validation failures — jwt.refreshExpiresInDays
// ---------------------------------------------------------------------------

describe('resolveOptions — jwt.refreshExpiresInDays validation', () => {
  // Verifies that a zero value for refreshExpiresInDays throws a startup error.
  it('should throw when refreshExpiresInDays is 0', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, refreshExpiresInDays: 0 }
    }
    expect(() => resolveOptions(options)).toThrow(/refreshExpiresInDays/)
  })

  // Verifies that a negative value for refreshExpiresInDays throws a startup error.
  it('should throw when refreshExpiresInDays is negative', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, refreshExpiresInDays: -1 }
    }
    expect(() => resolveOptions(options)).toThrow(/refreshExpiresInDays/)
  })

  // Scenario: refreshExpiresInDays is 0 AND refreshGraceWindowSeconds is negative (-10), so the
  // grace-window check (graceSeconds >= lifetime → -10 >= 0 → false) cannot fire — only the
  // line-477 guard can throw. Expected: throws the 'must be a positive finite number' error
  // specifically. Why: the existing 0/negative tests assert only `/refreshExpiresInDays/`, which
  // ALSO appears in the grace-window error message, so the guard was not isolated. Pinning the
  // unique 'positive finite number' phrase here kills the BlockStatement-empty mutant, the
  // `if (false)` ConditionalExpression mutant, the `|| false` mutant, and the EqualityOperator
  // `<=`→`<` mutant — under each, 0 would no longer be rejected and resolveOptions would return.
  // (edge-case: boundary 0 with a non-firing grace check)
  it('should reject refreshExpiresInDays 0 with the positive-finite error in isolation', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, refreshExpiresInDays: 0, refreshGraceWindowSeconds: -10 }
    }
    expect(() => resolveOptions(options)).toThrow(
      /jwt\.refreshExpiresInDays must be a positive finite number\./
    )
  })

  // Scenario: refreshExpiresInDays is Infinity (grace window left at default). Expected: throws the
  // positive-finite error. Why: only the `!Number.isFinite(...)` term is true (Infinity <= 0 is
  // false), so this kills the LogicalOperator mutant `||`→`&&` — which would require BOTH terms true
  // and therefore NOT throw on Infinity — and the `if (false)` ConditionalExpression mutant. With
  // Infinity the computed lifetime is Infinity, so the grace check cannot mask the guard.
  it('should reject a non-finite refreshExpiresInDays (Infinity) with the positive-finite error', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: {
        secret: VALID_SECRET,
        refreshExpiresInDays: Number.POSITIVE_INFINITY,
        refreshGraceWindowSeconds: 30
      }
    }
    expect(() => resolveOptions(options)).toThrow(
      /jwt\.refreshExpiresInDays must be a positive finite number\./
    )
  })

  // Scenario: refreshExpiresInDays is 0 with a non-firing grace check (negative grace). Expected: the
  // message includes the 'Zero, negative, NaN, and Infinity are all rejected' explanation and the
  // 'invalid Redis TTL' consequence. Why: pins the two concatenated literals of the positive-finite
  // error so the StringLiteral mutants emptying either are killed.
  it('should explain why zero/negative/NaN/Infinity are rejected (Redis TTL consequence)', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, refreshExpiresInDays: 0, refreshGraceWindowSeconds: -10 }
    }
    expect(() => resolveOptions(options)).toThrow(
      /Zero, negative, NaN, and Infinity are all rejected/
    )
    expect(() => resolveOptions(options)).toThrow(
      /any of these would produce an invalid Redis TTL and cause all token rotations to fail at runtime\./
    )
  })
})
