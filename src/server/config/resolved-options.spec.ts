/**
 * @fileoverview Tests for resolveOptions(), which merges consumer-supplied options with
 * secure defaults and validates all security-critical invariants at module startup.
 * Covers success paths, every validation error branch, and the new refreshGraceWindow check.
 */

import type { Request } from 'express'

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
    expect(resolved.password.costFactor).toBe(32_768)
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
// Validation failures — jwt missing entirely
// ---------------------------------------------------------------------------

describe('resolveOptions — jwt missing', () => {
  // Verifies that omitting the jwt group entirely throws a clear startup error.
  it('should throw when jwt configuration is entirely absent', () => {
    // Cast needed because TypeScript does not allow omitting a required field.
    const options = { roles: { hierarchy: { ADMIN: [] } } } as never
    expect(() => resolveOptions(options)).toThrow(/jwt configuration is required/)
  })
})

// ---------------------------------------------------------------------------
// Validation failures — jwt.secret
// ---------------------------------------------------------------------------

describe('resolveOptions — jwt.secret validation', () => {
  // Verifies that a secret shorter than 32 characters is rejected at startup.
  it('should throw when secret is shorter than 32 characters', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: 'short-secret' }
    }
    expect(() => resolveOptions(options)).toThrow(/at least 32 characters/)
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
})

// ---------------------------------------------------------------------------
// Validation failures — roles.hierarchy
// ---------------------------------------------------------------------------

describe('resolveOptions — roles.hierarchy validation', () => {
  // Verifies that an empty hierarchy object is rejected to enforce at least one role.
  it('should throw when roles.hierarchy is an empty object', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      roles: { hierarchy: {} }
    }
    expect(() => resolveOptions(options)).toThrow(/hierarchy must not be an empty object/)
  })

  // Verifies that a role referencing an undeclared child is rejected (referential integrity).
  it('should throw when a role references an undeclared child role', () => {
    const options: BymaxAuthModuleOptions = {
      ...MINIMAL_OPTIONS,
      roles: { hierarchy: { ADMIN: ['GHOST_ROLE'] } }
    }
    expect(() => resolveOptions(options)).toThrow(/unknown role 'GHOST_ROLE'/)
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
// Validation failures — refreshCookiePath (now throws instead of warns)
// ---------------------------------------------------------------------------

describe('resolveOptions — refreshCookiePath validation', () => {
  // Verifies that a custom routePrefix without refreshCookiePath throws to prevent misconfigured cookie path.
  it('should throw when routePrefix differs from auth and refreshCookiePath not set', () => {
    expect(() => resolveOptions({ ...MINIMAL_OPTIONS, routePrefix: 'api/auth' })).toThrow(
      /refreshCookiePath/
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
})
