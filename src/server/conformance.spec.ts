/**
 * @fileoverview Cross-implementation conformance — asserts this library against the shared
 * wire contract in `conformance/wire-contract.json`.
 *
 * The sibling Rust library (`bymax-auth`) can back the same deployment and share one Redis,
 * so the key prefixes, index member shapes, record encodings, and credential formats are a
 * contract between the two rather than an internal detail of either. Both repos carry a
 * byte-identical copy of that file and a test like this one, so a change on either side turns
 * that side red immediately instead of surfacing later as sessions, lockouts, and reset links
 * that silently miss each other in production.
 *
 * A failure here means one of two things: the implementation drifted from the contract, or the
 * contract was changed without migrating the data already written in the old form. Neither is
 * fixed by editing the assertion.
 */

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import type { Redis } from 'ioredis'

import { encrypt } from './crypto/aes-gcm'
import { generateSecureToken, hmacSha256 } from './crypto/secure-token'
import { fromBase32, generateTotpSecret } from './crypto/totp'
import { resolveOptions } from './config/resolved-options'
import type { ResolvedOptions } from './config/resolved-options'
import { AUTH_THROTTLE_CONFIGS } from './constants/throttle-configs'
import { AUTH_ERROR_CODES } from './errors/auth-error-codes'
import { AuthException } from './errors/auth-exception'
import { WS_TICKET_TTL_SECONDS } from './interfaces/ws-ticket.interface'
import { AuthRedisService } from './redis/auth-redis.service'

interface WireContract {
  hmacKeyDerivation: {
    vectors: {
      secret: string
      derivedKeyHex: string
      identifierMessage: string
      identifierHex: string
    }[]
  }
  redisKeyPrefixes: Record<string, string>
  sessionIndexMembers: Record<string, string>
  familyIndexMembers: Record<string, string>
  rotationSemantics: Record<string, string>
  recordEncodings: Record<
    string,
    {
      key?: string
      fields?: string[]
      createdAt?: string
      familyId?: string
      familyCreatedAt?: string
      tenantId?: string
    }
  >
  credentialFormats: Record<string, string>
  accessTokenClaims: Record<string, unknown>
  rateLimits: Record<string, string>
  errorEnvelope: { shape: { error: Record<string, string> } }
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as WireContract

/** Minimal options accepted by resolveOptions; only the derivation is under test here. */
const MINIMAL_OPTIONS = {
  jwt: { secret: 'x'.repeat(40) },
  roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } }
}

describe('cross-implementation conformance', () => {
  // -------------------------------------------------------------------------
  // Identifier-key derivation
  // -------------------------------------------------------------------------

  describe('HMAC identifier key', () => {
    // Three things are pinned by one vector: the ':' separator, the SHA-256, and keying the
    // HMAC with the hex TEXT rather than the raw digest. Any one of them drifting gives every
    // lockout, OTP, cooldown, MFA-setup, and anti-replay record a different key on each
    // backend, so a lockout accrued through one is invisible to the other.
    it.each(contract.hmacKeyDerivation.vectors)(
      'derives the contract key and identifier for the pinned secret',
      (vector) => {
        const resolved = resolveOptions({
          ...MINIMAL_OPTIONS,
          jwt: { secret: vector.secret }
        } as never)

        expect(resolved.hmacKey).toBe(vector.derivedKeyHex)
        expect(hmacSha256(vector.identifierMessage, resolved.hmacKey)).toBe(vector.identifierHex)
      }
    )
  })

  // -------------------------------------------------------------------------
  // Redis keyspace
  // -------------------------------------------------------------------------

  describe('Redis key prefixes', () => {
    /**
     * Every prefix the contract names, paired with a source file that must mention it. Reading
     * the source is deliberate: these prefixes are assembled inline at their call sites rather
     * than centralized, so there is no runtime value to assert against.
     */
    const PREFIX_SOURCES: Record<string, string> = {
      dashboardRefreshSession: 'services/token-manager.service.ts',
      dashboardGracePointer: 'services/token-manager.service.ts',
      dashboardSessionIndex: 'services/token-manager.service.ts',
      dashboardSessionDetail: 'services/session.service.ts',
      platformRefreshSession: 'services/token-manager.service.ts',
      platformGracePointer: 'services/token-manager.service.ts',
      platformSessionIndex: 'services/token-manager.service.ts',
      platformSessionDetail: 'services/token-manager.service.ts',
      dashboardConsumedFamilyMarker: 'redis/auth-redis.service.ts',
      dashboardFamilyIndex: 'services/token-manager.service.ts',
      platformConsumedFamilyMarker: 'redis/auth-redis.service.ts',
      platformFamilyIndex: 'services/token-manager.service.ts',
      dashboardTokenEpoch: 'redis/auth-redis.service.ts',
      platformTokenEpoch: 'redis/auth-redis.service.ts',
      accessTokenBlacklist: 'guards/jwt-auth.guard.ts',
      totpReplayMarker: 'services/mfa.service.ts',
      passwordResetToken: 'services/password-reset.service.ts',
      passwordResetVerifiedToken: 'services/password-reset.service.ts'
    }

    // Verifies each contract prefix is the one the code actually writes. A rename that lands on
    // one side only splits the keyspace: a reset link emailed by one backend becomes invisible
    // to the other, and a session index written by one is never swept by the other.
    //
    // A prefix appears in the source either interpolated into a key (`rt:${hash}`) or named in
    // the prefix table the rotation scripts are driven by (`live: 'rt'`), so either form counts.
    it.each(Object.entries(PREFIX_SOURCES))(
      'writes the contract prefix for %s',
      (name, sourceFile) => {
        const prefix = contract.redisKeyPrefixes[name]
        const source = readFileSync(join(__dirname, sourceFile), 'utf8')

        expect(prefix).toBeDefined()
        expect(source.includes(`${prefix}:`) || source.includes(`'${prefix}'`)).toBe(true)
      }
    )

    // Verifies the two planes never share an index prefix. They are keyed by ids from
    // different consumer repositories, which may collide, so one shared index would let a
    // revoke on one plane log the other out.
    it('keeps the dashboard and platform keyspaces distinct', () => {
      const { dashboardSessionIndex, platformSessionIndex, dashboardSessionDetail } =
        contract.redisKeyPrefixes

      expect(platformSessionIndex).not.toBe(dashboardSessionIndex)
      expect(contract.redisKeyPrefixes['platformSessionDetail']).not.toBe(dashboardSessionDetail)
    })
  })

  // -------------------------------------------------------------------------
  // Index member shape
  // -------------------------------------------------------------------------

  describe('session index members', () => {
    // Verifies members carry their own keyspace prefix rather than a bare hash. An atomic
    // revoke rebuilds keys from members, and a bare hash cannot say whether it names a live
    // session or a rotation grace pointer — which is exactly how a rotated-away token can
    // survive a logout-all for its whole grace window.
    it.each(Object.entries({ dashboardLive: 'rt:', dashboardGrace: 'rp:', platformLive: 'prt:' }))(
      'declares a prefixed member shape for %s',
      (name, expectedPrefix) => {
        expect(contract.sessionIndexMembers[name]).toMatch(new RegExp(`^${expectedPrefix}`))
      }
    )

    // Verifies the source actually SADDs the prefixed form. The contract is only worth
    // anything if the code writes what it declares.
    it('adds prefixed members to the index', () => {
      const source = readFileSync(join(__dirname, 'services/token-manager.service.ts'), 'utf8')

      expect(source).toContain('`rt:${tokenHash}`')
      expect(source).toContain('`prt:${tokenHash}`')
    })
  })

  // -------------------------------------------------------------------------
  // Family index and rotation semantics
  // -------------------------------------------------------------------------

  describe('refresh-token families', () => {
    // Verifies the family index takes BARE hashes, unlike the session index. It only ever
    // tracks live refresh sessions, so the keyspace is implied — and the revocation script
    // rebuilds `rt:{hash}` from the member, which double-prefixing would break.
    // The member SHAPE is asserted here; that the code actually SADDs the bare hash under it is
    // pinned in the token-manager spec, which observes the call rather than the source text.
    it('declares bare-hash members for the family index', () => {
      expect(contract.familyIndexMembers['dashboardLive']).toBe('{sha256(refreshToken)}')
      expect(contract.familyIndexMembers['platformLive']).toBe('{sha256(refreshToken)}')
      // Distinct from the session index, whose members carry their own prefix.
      expect(contract.familyIndexMembers['dashboardLive']).not.toBe(
        contract.sessionIndexMembers['dashboardLive']
      )
    })

    // Verifies the record carries the family, omitted rather than emptied. rust-auth skips the
    // field when empty, so writing `"familyId":""` would make the same session serialize to
    // different bytes on each side.
    // That the serializer actually drops the empty key is pinned in the token-manager spec,
    // which reads the record handed to the rotation rather than the source text.
    it('carries familyId on the refresh session record, omitted when empty', () => {
      expect(contract.recordEncodings['refreshSession']?.fields).toContain('familyId')
      expect(contract.recordEncodings['refreshSession']?.['familyId']).toContain('omitted')
    })

    // The family's birth time is what the absolute-lifetime cap measures from, and it is
    // deliberately NOT `createdAt`: that one is this session's own and resets on every
    // rotation, which would make the cap unreachable while looking like it worked.
    it('carries the family birth time, distinct from the session createdAt', () => {
      expect(contract.recordEncodings['refreshSession']?.fields).toContain('familyCreatedAt')
      expect(contract.recordEncodings['refreshSession']?.['familyCreatedAt']).toContain(
        'carried unchanged through every rotation'
      )
    })

    // Verifies the reaction to a replay is the same on both sides. The two backends share the
    // consumed-family marker, so one treating a replay as recoverable while the other treats it
    // as theft would make the reaction depend on which backend the request happened to reach.
    it('pins the grace and reuse semantics both sides implement', () => {
      expect(contract.rotationSemantics['graceWindow']).toContain('single-shot')
      expect(contract.rotationSemantics['graceRequiresLiveFamily']).toContain('refused')
      expect(contract.rotationSemantics['reuseReaction']).toContain('revoke the whole family')

      const source = readFileSync(join(__dirname, 'redis/auth-redis.service.ts'), 'utf8')
      // The pointer is consumed on use, and a recovery is refused once its lineage is gone.
      expect(source).toContain("redis.call('DEL', KEYS[3])")
      expect(source).toContain('familyIsAlive')
    })
  })

  // -------------------------------------------------------------------------
  // Duplicated contracts
  // -------------------------------------------------------------------------

  describe('JWT payload contracts', () => {
    /**
     * Reads the field names of a TypeScript interface out of a source file.
     *
     * Comparing the two declarations structurally is only possible at build time; comparing the
     * declared field names is possible now, and catches the drift that actually happens — a
     * claim added to one copy and forgotten in the other.
     */
    function interfaceFields(relativePath: string, name: string): string[] {
      const source = readFileSync(join(__dirname, relativePath), 'utf8')
      const declaration = new RegExp(`export interface ${name} \\{([\\s\\S]*?)\\n\\}`).exec(source)
      const body = (declaration?.[1] ?? '')
        .replace(/\/\*\*[\s\S]*?\*\//g, '')
        .replace(/\/\/[^\n]*/g, '')
      return [...body.matchAll(/^\s*(\w+\??):/gm)].map((match) => match[1] ?? '')
    }

    // The same three payload contracts are declared twice — once in `shared` for consumers and
    // once in `server` for the guards — because the two subpaths must not import each other.
    // Nothing but this test stops them diverging, and a claim that exists on one side only is
    // exactly how a guard ends up checking something the issuer never stamps.
    it.each(['DashboardJwtPayload', 'PlatformJwtPayload', 'MfaTempPayload'])(
      'declares %s identically in shared and server',
      (name) => {
        const shared = interfaceFields('../shared/types/jwt-payload.types.ts', name)
        const server = interfaceFields('interfaces/jwt-payload.interface.ts', name)

        expect(shared.length).toBeGreaterThan(0)
        expect(server).toEqual(shared)
      }
    )
  })

  // -------------------------------------------------------------------------
  // Rate limits
  // -------------------------------------------------------------------------

  describe('per-route rate limits', () => {
    /** Render a throttle entry as the contract's `requests/windowSeconds` form. */
    function asContractValue(config: { default: { limit: number; ttl: number } }): string {
      return `${config.default.limit}/${config.default.ttl / 1000}`
    }

    // Both backends enforce these numbers, so a value changed on one side only means the same
    // client is throttled at different points depending on which one served the request.
    it.each(Object.keys(contract.rateLimits).filter((key) => !key.startsWith('$')))(
      'serves %s under the contract limit',
      (route) => {
        const catalog = AUTH_THROTTLE_CONFIGS as Record<
          string,
          { default: { limit: number; ttl: number } } | undefined
        >
        const config = catalog[route]

        expect(config).toBeDefined()
        expect(asContractValue(config ?? { default: { limit: 0, ttl: 0 } })).toBe(
          contract.rateLimits[route]
        )
      }
    )

    // The catalog and the contract must describe the same set of routes: an entry on one side
    // only is a route whose limit nobody agreed on.
    it('covers exactly the routes the contract names', () => {
      const contractRoutes = Object.keys(contract.rateLimits).filter((key) => !key.startsWith('$'))

      expect(Object.keys(AUTH_THROTTLE_CONFIGS).sort()).toEqual(contractRoutes.sort())
    })
  })

  // -------------------------------------------------------------------------
  // Access-token claims
  // -------------------------------------------------------------------------

  describe('access token claims', () => {
    // Verifies the bulk-revocation claim and its keyspace. Both sides stamp it and both sides
    // compare it, so a token issued by either backend is judged the same way — and a token that
    // predates the claim reads as generation 0 rather than being rejected outright.
    it('pins the epoch claim, its keyspace, and the rejection rule', () => {
      const epoch = contract.accessTokenClaims['epoch'] as Record<string, unknown>

      expect(epoch['claim']).toBe('epoch')
      expect(epoch['storedUnder']).toBe('{ep|pep}:{userId}')
      expect(epoch['absentReadsAs']).toBe(0)
      expect(epoch['rejectWhen']).toBe('stampedEpoch < storedEpoch')

      const guard = readFileSync(join(__dirname, 'guards/jwt-auth.guard.ts'), 'utf8')
      expect(guard).toContain('readStampedEpoch(payload) < epoch')
    })
  })

  // -------------------------------------------------------------------------
  // Record encodings
  // -------------------------------------------------------------------------

  describe('record encodings', () => {
    // Verifies the timestamp encoding is NOT uniform across records, which is the trap here.
    // The session detail must be epoch milliseconds because the reader guards on
    // `typeof === 'number'` and evicts a member whose detail fails to parse; the refresh
    // session and the invitation are ISO strings. Getting either backwards makes one backend
    // silently delete the other's sessions.
    it('pins epoch milliseconds for the session detail and ISO strings elsewhere', () => {
      expect(contract.recordEncodings['sessionDetail']?.createdAt).toBe('unix-milliseconds-number')
      expect(contract.recordEncodings['refreshSession']?.createdAt).toBe('iso8601-string')
      expect(contract.recordEncodings['invitation']?.createdAt).toBe('iso8601-string')
    })

    // Verifies the refresh-session record carries mfaEnabled. Without it a rotation mints
    // claims saying MFA is off, and since the gate refuses only when `mfaEnabled &&
    // !mfaVerified`, one routine refresh silently disables the second factor.
    it('requires mfaEnabled on the refresh session record', () => {
      expect(contract.recordEncodings['refreshSession']?.fields).toContain('mfaEnabled')
    })

    // Verifies the invitation record carries createdAt. Consumption is a single-use GETDEL, so
    // a record the reader rejects is destroyed rather than retried — a missing field does not
    // fail the acceptance, it loses the invitation.
    it('requires createdAt on the invitation record', () => {
      expect(contract.recordEncodings['invitation']?.fields).toContain('createdAt')
    })
  })

  // -------------------------------------------------------------------------
  // Credential formats
  // -------------------------------------------------------------------------

  describe('credential formats', () => {
    // Verifies the contract still describes the 256-bit refresh token this library mints, and
    // that the legacy UUID shape is documented as accepted rather than minted — the sibling
    // backend keeps a parsing allowance for it, which only makes sense while such tokens live.
    it('declares the 256-bit refresh token and the legacy allowance', () => {
      expect(contract.credentialFormats['refreshToken']).toContain('64 lowercase hex')
      expect(contract.credentialFormats['refreshTokenLegacy']).toContain('uuid-v4')
    })

    // Verifies the at-rest TOTP form is the Base32 text. Both backends read the same stored
    // secret, and decrypting one form as the other hands the wrong bytes to HMAC-SHA-1, which
    // rejects every code the user's authenticator produces.
    it('declares the TOTP secret at rest as encrypted Base32 text', () => {
      expect(contract.credentialFormats['totpSecretAtRest']).toContain('BASE32')
    })

    // Scenario: the token this library actually mints. Expected: 64 lowercase hex characters.
    // Why: the two assertions above read the contract's prose, which proves only that the
    // agreement still says what it said — a drift in the implementation would leave them green.
    // This one puts a real token next to the declaration.
    it('mints a refresh token in the declared shape', () => {
      for (let i = 0; i < 32; i++) {
        expect(generateSecureToken(32)).toMatch(/^[0-9a-f]{64}$/)
      }
    })

    // Scenario: a TOTP secret prepared the way `MfaService` prepares it. Expected: what goes
    // under AES-256-GCM is the Base32 TEXT, and decoding that text yields the bytes the HMAC
    // uses as its key. Why: this is the divergence that would make every code the user's
    // authenticator produces fail against one backend while working on the other — and it is
    // not visible in any type, only in what was encrypted.
    it('encrypts the Base32 text of the TOTP secret, not the raw bytes', () => {
      const key = Buffer.alloc(32, 7).toString('base64')
      const { raw, base32 } = generateTotpSecret()

      // The Base32 alphabet, and a round trip back to the HMAC key.
      expect(base32).toMatch(/^[A-Z2-7]+$/)
      expect(fromBase32(base32).equals(raw)).toBe(true)

      // The ciphertext is over the text: a stored record differs from one over the raw bytes.
      expect(encrypt(base32, key)).not.toBe(encrypt(raw.toString('binary'), key))
    })

    // Scenario: a stored recovery-code digest. Expected: 64 lowercase hex characters — a keyed
    // HMAC-SHA-256 — and never the legacy `scrypt:` form, which is verified but no longer
    // written. Why: the sibling backend verifies these digests directly.
    it('stores a recovery code as a hex HMAC-SHA-256 under the identifier key', () => {
      expect(contract.credentialFormats['recoveryCodeDigest']).toContain('hex hmac-sha256')
      expect(contract.credentialFormats['recoveryCodeDigestLegacy']).toContain('scrypt:')

      const digest = hmacSha256('A1B2-C3D4-E5F6', 'a'.repeat(64))
      expect(digest).toMatch(/^[0-9a-f]{64}$/)
      expect(digest.startsWith('scrypt:')).toBe(false)
    })
  })

  // -------------------------------------------------------------------------
  // WebSocket upgrade tickets
  // -------------------------------------------------------------------------

  describe('websocket upgrade ticket', () => {
    // Scenario: the prefix and record shape a ticket is stored under. Expected: `wst:` keyed by
    // the ticket's sha256, with the six snapshot fields. Why: a ticket minted by one backend is
    // redeemed by whichever one receives the upgrade, so the two must agree on both.
    it('declares the wst prefix and the snapshot shape', () => {
      expect(contract.redisKeyPrefixes['wsTicket']).toBe('wst')
      expect(contract.recordEncodings['wsTicket']?.key).toBe('wst:{sha256(ticket)}')
      expect(contract.recordEncodings['wsTicket']?.fields).toEqual([
        'sub',
        'tenantId',
        'role',
        'status',
        'mfaEnabled',
        'mfaVerified'
      ])
    })

    // Scenario: what this library actually mints and stores. Expected: the raw ticket is the
    // declared 64 hex characters, only its hash is a key, and the stored value carries exactly
    // the declared fields. Why: reading the contract's prose proves only that the agreement
    // still says what it said.
    it('mints and stores in the declared form', async () => {
      const redis = { set: jest.fn(), eval: jest.fn() }
      const service = new AuthRedisService(
        redis as unknown as Redis,
        { redisNamespace: 'auth' } as unknown as ResolvedOptions
      )
      const snapshot = {
        sub: 'u1',
        tenantId: 't1',
        role: 'MEMBER',
        status: 'ACTIVE',
        mfaEnabled: false,
        mfaVerified: false
      }

      const ticket = await service.mintWsTicket(snapshot, WS_TICKET_TTL_SECONDS)

      expect(ticket).toMatch(/^[0-9a-f]{64}$/)
      expect(contract.credentialFormats['wsTicket']).toContain('64 lowercase hex')
      const [key, value] = redis.set.mock.calls[0] as [string, string]
      expect(key).toBe(`auth:wst:${createHash('sha256').update(ticket).digest('hex')}`)
      expect(Object.keys(JSON.parse(value) as object).sort()).toEqual(
        [...(contract.recordEncodings['wsTicket']?.fields ?? [])].sort()
      )
    })

    // Scenario: a ticket with no tenant scope. Expected: `tenantId` absent from the record, not
    // null. Why: the contract says omitted, and the sibling backend omits it — a null would be
    // a field the other side's parser has to learn about.
    it('omits the tenant scope rather than writing null', async () => {
      const redis = { set: jest.fn(), eval: jest.fn() }
      const service = new AuthRedisService(
        redis as unknown as Redis,
        { redisNamespace: 'auth' } as unknown as ResolvedOptions
      )

      await service.mintWsTicket(
        { sub: 'a1', role: 'SUPER_ADMIN', status: 'ACTIVE', mfaEnabled: true, mfaVerified: true },
        WS_TICKET_TTL_SECONDS
      )

      const [, value] = redis.set.mock.calls[0] as [string, string]
      expect(contract.recordEncodings['wsTicket']?.tenantId).toContain('omitted')
      expect(value).not.toContain('tenantId')
    })
  })

  // -------------------------------------------------------------------------
  // Error envelope
  // -------------------------------------------------------------------------

  describe('error envelope', () => {
    // Scenario: an error thrown with no structured details. Expected: `details` is PRESENT and
    // null, not omitted. Why: one client library decodes both backends, and `undefined` is not
    // `null` to it — a key that is sometimes absent forces every reader to handle two shapes
    // for one meaning. The rust side omitted it until this assertion existed on both.
    it('serializes details as null rather than omitting the key', () => {
      const body = new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS).getResponse() as {
        error: Record<string, unknown>
      }

      expect(Object.keys(body.error).sort()).toEqual(
        Object.keys(contract.errorEnvelope.shape.error).sort()
      )
      expect(body.error).toHaveProperty('details', null)
      expect(typeof body.error['code']).toBe('string')
      expect(typeof body.error['message']).toBe('string')
      // `object|null`, not `object?` — the union the contract declares is what pins the key's
      // presence, so it is asserted rather than assumed.
      expect(contract.errorEnvelope.shape.error['details']).toBe('object|null')
    })

    // Scenario: an error that does carry details. Expected: an object under the same key, so
    // the declared union is pinned in both directions.
    it('serializes structured details as an object under the same key', () => {
      const body = new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED, 429, {
        retryAfterSeconds: 300
      }).getResponse() as { error: { details: unknown } }

      expect(body.error.details).toEqual({ retryAfterSeconds: 300 })
    })
  })
})
