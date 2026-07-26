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

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { hmacSha256 } from './crypto/secure-token'
import { resolveOptions } from './config/resolved-options'

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
  recordEncodings: Record<string, { fields?: string[]; createdAt?: string }>
  credentialFormats: Record<string, string>
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
      accessTokenBlacklist: 'guards/jwt-auth.guard.ts',
      totpReplayMarker: 'services/mfa.service.ts',
      passwordResetToken: 'services/password-reset.service.ts',
      passwordResetVerifiedToken: 'services/password-reset.service.ts'
    }

    // Verifies each contract prefix is the one the code actually writes. A rename that lands on
    // one side only splits the keyspace: a reset link emailed by one backend becomes invisible
    // to the other, and a session index written by one is never swept by the other.
    it.each(Object.entries(PREFIX_SOURCES))(
      'writes the contract prefix for %s',
      (name, sourceFile) => {
        const prefix = contract.redisKeyPrefixes[name]
        const source = readFileSync(join(__dirname, sourceFile), 'utf8')

        expect(prefix).toBeDefined()
        expect(source).toContain(`${prefix}:`)
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
  })
})
