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
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

import { sessionIndexKey } from './constants/user-keys'

import { plainToInstance } from 'class-transformer'
import { validate } from 'class-validator'
import type { Redis } from 'ioredis'

import { AuthController } from './controllers/auth.controller'
import { AcceptInvitationDto } from './dto/accept-invitation.dto'
import { LoginDto } from './dto/login.dto'
import { MfaVerifyDto } from './dto/mfa-verify.dto'
import { RegisterDto } from './dto/register.dto'
import { VerifyEmailDto } from './dto/verify-email.dto'
import { VerifyOtpDto } from './dto/verify-otp.dto'
import { encrypt } from './crypto/aes-gcm'
import { userSubject } from './constants/user-subject'
import { generateSecureToken, hmacSha256 } from './crypto/secure-token'
import { fromBase32, generateTotpSecret } from './crypto/totp'
import { resolveOptions } from './config/resolved-options'
import type { ResolvedOptions } from './config/resolved-options'
import { AUTH_THROTTLE_CONFIGS } from './constants/throttle-configs'
import { AUTH_ERROR_CODES, AUTH_ERROR_MESSAGES, AUTH_ERROR_STATUS } from './errors/auth-error-codes'
import { AuthException } from './errors/auth-exception'
import { WS_TICKET_TTL_SECONDS } from './interfaces/ws-ticket.interface'
import { PasswordService } from './services/password.service'
import { AuthRedisService } from './redis/auth-redis.service'
import { TokenDeliveryService } from './services/token-delivery.service'

import type { MfaChallengeResult, PlatformAuthResult } from './interfaces/auth-result.interface'

interface WireContract {
  hmacKeyDerivation: {
    vectors: {
      secret: string
      derivedKeyHex: string
      identifierMessage: string
      identifierHex: string
      otpCode: string
      otpRecordCodeHex: string
    }[]
  }
  redisKeyPrefixes: Record<string, string>
  identifierPreimages: Record<string, string>
  userSubjectPreimages: Record<string, string>
  userSubjectDerivedKeys: Record<string, string>
  requestFieldBounds: Record<string, { min?: number; max?: number }>
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
  passwordHashFormat: {
    encoding: string
    legacyEncoding: string
    vectors: { password: string; hash: string; writtenBy: string; needsRehash: boolean }[]
  }
  accessTokenClaims: Record<string, unknown>
  rateLimits: Record<string, string>
  errorCatalog: {
    codes: string[]
    internalOnly: string[]
    statuses: Record<string, number>
  }
  errorEnvelope: { shape: { error: Record<string, string> } }
  responseBodies: {
    login: { cookie: string[]; bearer: string[] }
    platformLogin: { bearer: string[] }
    me: { envelope: string }
    mfaChallenge: string[]
    wsTicket: string[]
  }
}

const CONTRACT_PATH = join(__dirname, '../../conformance/wire-contract.json')
const contractSource = readFileSync(CONTRACT_PATH, 'utf8')
const contract = JSON.parse(contractSource) as WireContract

/**
 * The SHA-256 of `conformance/wire-contract.json`, pinned so the file cannot change unnoticed.
 *
 * **What this catches, stated narrowly because the obvious wider claim is false.** It fails on an
 * *unaccompanied* byte change: an edit that forgets to advance the constant, a formatter
 * rewriting the file (`lint-staged` runs Prettier over `*.json` here), a merge resolving it
 * differently. That is a real class — the shared file must not move by accident on either side.
 *
 * **What it does NOT catch: cross-implementation divergence.** Changing the file *and* this
 * constant in one commit leaves this suite green, while rust-auth's untouched file and untouched
 * constant leave theirs green too. Both green, bytes divergent. Two independent local hashes
 * cannot enforce agreement between two repositories — nothing here reads the other side.
 *
 * That limitation is written down because the first version of this comment claimed the opposite
 * and named a *lesser* limitation ("would not catch both being advanced to the same wrong
 * value"), which read as thorough while missing the one that mattered. A limitations note that
 * gives false comfort is worse than none.
 *
 * Closing it for real needs a cross-repository comparison — one side fetching the other's
 * committed blob in CI, or both consuming one immutable versioned artifact. That is proposed and
 * unbuilt; until it exists, the contract's identity between repositories still rests on both
 * maintainers changing it deliberately and together.
 *
 * Hashed from the working tree, not `git show HEAD:`, which would be authoritative: `git` is
 * unavailable in the Stryker sandbox, and a check that skipped itself there would pass on the
 * broken state in the place the mutation gate runs.
 */
const CONTRACT_SHA256 = '80227c84725b1445388f1597350f7f8d8d2c61a3fdda11787c60a95e3c2dd474'

/** Minimal options accepted by resolveOptions; only the derivation is under test here. */
const MINIMAL_OPTIONS = {
  jwt: { secret: 'x'.repeat(40) },
  roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
  // Required whenever rate limiting is on; see `validateClientIpSource` for why there is no
  // default. Irrelevant to the derivation this suite pins, but a config that does not resolve
  // cannot be used to check anything.
  rateLimit: { clientIpSource: 'peer' as const }
}

describe('cross-implementation conformance', () => {
  // Verifies the shared contract has not changed without the change being declared here.
  //
  // Everything else in this suite checks that THIS library matches the contract; nothing checked
  // that the contract itself had not moved. This catches an unaccompanied byte change — a
  // forgotten constant, a reformat, a merge resolving it differently. It does NOT catch
  // divergence from rust-auth: see the constant's own doc comment for why two local hashes
  // cannot, and what would.
  it('holds the shared wire contract at its declared bytes', () => {
    expect(createHash('sha256').update(contractSource).digest('hex')).toBe(CONTRACT_SHA256)
  })

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
        // The OTP record's stored value continues the same vector: never the code, but the keyed
        // fingerprint `hmac(`{identifier}:{code}`, hmacKey)`. Pinned byte-for-byte because both
        // backends write and compare the SAME `otp:` record — a drift here is every code minted on
        // one failing to verify on the other. This is exactly `OtpService.fingerprint`'s derivation.
        expect(hmacSha256(`${vector.identifierHex}:${vector.otpCode}`, resolved.hmacKey)).toBe(
          vector.otpRecordCodeHex
        )
      }
    )
  })

  // -------------------------------------------------------------------------
  // Identifier preimages
  // -------------------------------------------------------------------------

  describe('identifier preimages', () => {
    /**
     * The single-source helper that derives each preimage. Every site that touches one of
     * these counters goes through the helper named here, so there is exactly one place per
     * preimage that has to agree with the contract.
     */
    const PREIMAGE_SOURCES: Record<string, string> = {
      dashboard: 'services/auth.service.ts',
      platform: 'services/platform-auth.service.ts',
      otpRecord: 'services/auth.service.ts',
      inviteeIndex: 'services/invitation.service.ts'
    }

    /**
     * Renders a contract preimage as the TypeScript template literal the source must contain.
     *
     * The contract writes them as `hmac_sha256(hmacKey, '<template>')` with `{placeholder}`
     * fields; the source writes the same template as a tagged literal with `${placeholder}`.
     * Deriving the expectation from the contract rather than repeating it is what makes this
     * bidirectional: a change on either side turns the test red.
     *
     * @param rendered - The contract value, e.g. `hmac_sha256(hmacKey, 'platform:{email}')`.
     * @returns The TypeScript literal, e.g. `` `platform:${email}` ``.
     */
    const asTemplateLiteral = (rendered: string): string =>
      '`' + (rendered.split("'")[1] ?? '').replace(/\{(\w+)\}/g, '${$1}') + '`'

    // Verifies each preimage is the one the code actually HMACs. These decide which records the
    // two backends share: the `dashboard:` segment is what keeps a tenant named `platform` out
    // of the platform lockout counter, and the invitee index is HMAC'd rather than plainly
    // digested because an address is too low-entropy for a bare SHA-256 to hide.
    it.each(Object.entries(PREIMAGE_SOURCES))(
      'builds the contract preimage for %s',
      (name, file) => {
        const rendered = contract.identifierPreimages[name]

        expect(rendered).toBeDefined()
        expect(readFileSync(join(__dirname, file), 'utf8')).toContain(asTemplateLiteral(rendered!))
      }
    )

    // Verifies the three planes cannot collide. `dashboard:` and `platform:` namespace their
    // own counters, and the OTP preimage stays bare only because its keyspace is already
    // purpose-scoped — so it must never equal either of the other two.
    it('keeps the login planes and the OTP records in separate keyspaces', () => {
      const { dashboard, platform, otpRecord, inviteeIndex } = contract.identifierPreimages

      expect(new Set([dashboard, platform, otpRecord, inviteeIndex]).size).toBe(4)
      expect(dashboard).toContain('dashboard:')
      expect(platform).toContain('platform:')
      expect(otpRecord).not.toContain('dashboard:')
    })
  })

  // -------------------------------------------------------------------------
  // MFA subject preimages
  // -------------------------------------------------------------------------

  describe('MFA subject preimages', () => {
    // Renders a contract preimage template (`dashboard:{tenantId}:{userId}`) against concrete
    // values, so the expectation is derived from the contract rather than repeated here — a change
    // on either side turns the test red.
    const render = (template: string): string =>
      template.replace('{tenantId}', 'T').replace('{userId}', 'U')

    // The subject every MFA store key and failure counter is HMAC'd over. `userSubject` is the one
    // place both libraries build it, so it must render exactly the two templates the contract pins.
    it('builds the tenant-scoped subject the contract pins', () => {
      const { dashboard, platform } = contract.userSubjectPreimages

      expect(userSubject('dashboard', 'U', 'T')).toBe(render(dashboard!))
      expect(userSubject('platform', 'U', undefined)).toBe(render(platform!))
    })

    // Driven by the plane, not by whether a tenant was supplied: a tenant passed on the platform
    // plane cannot move the preimage off `platform:{userId}`. This is the half of the cross-library
    // agreement that keeps a platform admin's keys where the contract says they are.
    it('derives the platform subject from the plane, ignoring any tenant', () => {
      const { platform } = contract.userSubjectPreimages

      expect(userSubject('platform', 'U', 'T')).toBe(render(platform!))
      expect(userSubject('platform', 'U', 'T')).toBe(userSubject('platform', 'U', undefined))
    })

    // The dashboard and platform subjects never collide for the same id, and two tenants never
    // collide — the properties the whole block exists to guarantee.
    it('keeps planes and tenants in separate subjects', () => {
      const { dashboard, platform } = contract.userSubjectPreimages

      expect(dashboard).toContain('{tenantId}')
      expect(platform).not.toContain('{tenantId}')
      expect(userSubject('dashboard', 'U', 'T')).not.toBe(userSubject('platform', 'U', undefined))
      expect(userSubject('dashboard', 'U', 'tenant-a')).not.toBe(
        userSubject('dashboard', 'U', 'tenant-b')
      )
    })

    // Every subject-derived key names `userSubject` in the contract, so the block cannot list a key
    // that silently derives from something else. Two of them share ONE preimage — the anti-replay
    // marker and the recovery-code claim — and are separated only by their prefix.
    //
    // Eight now, not six: the session index and the token epoch joined when they stopped being
    // keyed on the bare user id. The count is asserted rather than left open because the whole
    // value of this block is that a key deriving from the subject and NOT listed here is invisible
    // to the contract — which is exactly how those two spent so long tenant-blind.
    it('derives all eight named keys from the subject', () => {
      const derived = Object.entries(contract.userSubjectDerivedKeys).filter(
        ([name]) => name !== '$comment'
      )

      expect(derived.length).toBe(8)
      for (const [, formula] of derived) {
        expect(formula).toContain('userSubject')
      }
    })
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
      dashboardSessionIndex: 'constants/user-keys.ts',
      dashboardSessionDetail: 'services/session.service.ts',
      platformRefreshSession: 'services/token-manager.service.ts',
      platformGracePointer: 'services/token-manager.service.ts',
      platformSessionIndex: 'constants/user-keys.ts',
      platformSessionDetail: 'services/token-manager.service.ts',
      dashboardConsumedFamilyMarker: 'redis/auth-redis.service.ts',
      dashboardFamilyIndex: 'services/token-manager.service.ts',
      platformConsumedFamilyMarker: 'redis/auth-redis.service.ts',
      platformFamilyIndex: 'services/token-manager.service.ts',
      dashboardTokenEpoch: 'constants/user-keys.ts',
      platformTokenEpoch: 'constants/user-keys.ts',
      accessTokenBlacklist: 'guards/jwt-auth.guard.ts',
      totpReplayMarker: 'services/mfa.service.ts',
      passwordResetToken: 'services/password-reset.service.ts',
      passwordResetVerifiedToken: 'services/password-reset.service.ts',
      mfaTransitionLock: 'services/mfa.service.ts',
      failedLoginCounter: 'services/brute-force.service.ts',
      oneTimePassword: 'services/otp.service.ts',
      otpResendCooldown: 'services/password-reset.service.ts',
      oauthState: 'oauth/oauth.service.ts',
      wsTicket: 'redis/auth-redis.service.ts',
      invitation: 'services/invitation.service.ts',
      invitationIndex: 'services/invitation.service.ts',
      recoveryCodeClaim: 'services/mfa.service.ts',
      // Assembled in its own module rather than inline, because both the writer
      // (`TokenManagerService`) and the reader (`MfaService`) have to derive it identically.
      recentAuthMarker: 'constants/recent-auth.ts',
      emailChangeToken: 'services/email-change.service.ts',
      pendingMfaSetup: 'services/mfa.service.ts',
      mfaTempTokenMarker: 'services/token-manager.service.ts'
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

    // The map above is hand-maintained, so a prefix added to the contract and never added
    // here would be checked by nothing — which is how a contract entry becomes decoration.
    // This asserts the map covers the contract, so forgetting is a failing test rather than a
    // silent gap.
    it('checks every prefix the contract declares', () => {
      const declared = Object.keys(contract.redisKeyPrefixes)
        .filter((name) => name !== '$comment')
        .sort()
      const checked = Object.keys(PREFIX_SOURCES).sort()

      expect(checked).toEqual(declared)
    })

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
  // Error catalog
  // -------------------------------------------------------------------------

  describe('error catalog', () => {
    // Verifies both libraries name exactly the same set of codes. They can back the same
    // deployment, so a client switching on `error.code` must see one vocabulary: a code
    // present on one side only is a branch that never fires against the other, and a code
    // neither side emits is a branch that never fires at all — which is what five of them
    // were before this section existed.
    it('names exactly the codes the contract does, and no others', () => {
      expect(Object.values(AUTH_ERROR_CODES).sort()).toEqual(
        [...contract.errorCatalog.codes].sort()
      )
    })

    // Verifies the internal-only list is exactly these five, by name.
    //
    // Every other assertion about internal-only codes in this file lives inside a
    // `for (… of contract.errorCatalog.internalOnly)` loop, so an empty or shortened list does
    // not fail them — it stops them running, and they report success for having checked
    // nothing. Unlike `codes` and `statuses`, that array had nothing pinning its contents, and
    // nothing else could catch it: Stryker mutates `src/`, never the contract JSON.
    //
    // The general shape is worth naming, because it is the inverse of the one this whole change
    // was about. A range assertion accepts the wrong answer; this accepts the absence of the
    // question. Both report green.
    it('marks exactly the five internal-only codes the contract names', () => {
      expect([...contract.errorCatalog.internalOnly].sort()).toEqual([
        'auth.otp_expired',
        'auth.otp_max_attempts',
        'auth.token_expired',
        'auth.token_missing',
        'auth.token_revoked'
      ])
    })

    // Verifies every code carries a default end-user message. A code with no message would
    // answer with its own identifier, which is a developer string reaching a user.
    it('gives every code a default message', () => {
      for (const code of contract.errorCatalog.codes) {
        expect(AUTH_ERROR_MESSAGES[code as keyof typeof AUTH_ERROR_MESSAGES]).toBeTruthy()
      }
    })

    // Verifies every code answers the HTTP status the shared contract declares. This is the
    // assertion whose absence let thirteen codes drift: the contract pinned the code strings
    // and not their statuses, so nest-auth answering 401 where rust-auth answered 409, 404 or
    // 400 was invisible to both suites — each side was self-consistent and neither read the
    // other. Reading the shared file is what makes it a parity test rather than a restatement.
    it('answers the status the contract declares for every code', () => {
      expect(AUTH_ERROR_STATUS).toEqual(contract.errorCatalog.statuses)
    })

    // Verifies the table covers the catalog exactly — no code without a status (which would
    // reach `HttpException` as `undefined`), and no status for a code that no longer exists.
    it('declares a status for exactly the codes in the catalog', () => {
      expect(Object.keys(AUTH_ERROR_STATUS).sort()).toEqual([...contract.errorCatalog.codes].sort())
    })

    // Verifies each internal-only code carries the status of the public code it collapses onto.
    // The collapse hides which of the two happened; a differing status would give it back
    // through the status line, which is the same disclosure by another route.
    it('gives every internal-only code the status of the code it collapses onto', () => {
      const collapse: Record<string, string> = {
        'auth.token_expired': 'auth.token_invalid',
        'auth.token_revoked': 'auth.token_invalid',
        'auth.token_missing': 'auth.token_invalid',
        'auth.otp_expired': 'auth.otp_invalid',
        'auth.otp_max_attempts': 'auth.otp_invalid'
      }

      for (const internal of contract.errorCatalog.internalOnly) {
        const target = collapse[internal]

        // An explicit guard rather than `expect(target).toBeDefined()` plus `target!`. The
        // matcher does not narrow the type, so the assertion would need a non-null assertion
        // the project forbids — and a missing mapping would surface as a confusing lookup of
        // `statuses[undefined]` rather than as the real failure, which is that this collapse
        // map has fallen behind the contract's internal-only list.
        if (target === undefined) {
          throw new Error(`no collapse target declared for internal-only code ${internal}`)
        }

        expect(contract.errorCatalog.statuses[internal]).toBe(
          contract.errorCatalog.statuses[target]
        )
      }
    })

    // Verifies the internal-only codes are exactly the ones the contract names, and that this
    // library never throws one. They exist for logs; reaching a client, each would give back
    // the distinction the collapse exists to remove — "valid until revoked" from "never
    // valid", "no record was ever written here" from "wrong code".
    it('never throws a code the contract marks internal-only', () => {
      const sources = readdirSync(__dirname, { recursive: true, encoding: 'utf8' })
        .filter((f) => f.endsWith('.ts') && !f.endsWith('.spec.ts'))
        .map((f) => readFileSync(join(__dirname, f), 'utf8'))
        .join('\n')

      for (const wire of contract.errorCatalog.internalOnly) {
        const name = Object.entries(AUTH_ERROR_CODES).find(([, v]) => v === wire)?.[0]
        expect(name).toBeDefined()
        expect(sources).not.toContain(`new AuthException(AUTH_ERROR_CODES.${name!}`)
      }
    })
  })

  // -------------------------------------------------------------------------
  // Request field bounds
  // -------------------------------------------------------------------------

  describe('request field bounds', () => {
    /**
     * A value of exactly `n` characters that is otherwise valid for the field. Numeric fields
     * need digits and addresses need an `@`, so each bounded field says how to fill itself.
     */
    type Filler = (n: number) => string
    const text: Filler = (n) => 'a'.repeat(n)
    const digits: Filler = (n) => '1'.repeat(n)
    /** `a…a@e.com` — a well-formed address of exactly `n` characters. */
    const address: Filler = (n) => `${'a'.repeat(Math.max(1, n - 6))}@e.com`

    /**
     * One DTO field per contract bound: the DTO, the property, a payload that is otherwise
     * valid, and how to fill the field to a given length.
     *
     * Driven through class-validator rather than read out of the decorators: what matters is
     * the length the endpoint actually accepts, and a boundary test says that in a way a
     * decorator scan cannot.
     */
    const BOUNDED_FIELDS: [string, new () => object, string, Record<string, unknown>, Filler][] = [
      ['email', LoginDto, 'email', { password: 'x', tenantId: 't' }, address],
      [
        'newPassword',
        RegisterDto,
        'password',
        { email: 'a@e.com', name: 'Ok', tenantId: 't' },
        text
      ],
      ['provenPassword', LoginDto, 'password', { email: 'a@e.com', tenantId: 't' }, text],
      ['tenantId', LoginDto, 'tenantId', { email: 'a@e.com', password: 'x' }, text],
      [
        'displayName',
        RegisterDto,
        'name',
        { email: 'a@e.com', password: 'hunter2hunter2', tenantId: 't' },
        text
      ],
      [
        'invitationDisplayName',
        AcceptInvitationDto,
        'name',
        { token: 'a'.repeat(64), password: 'hunter2hunter2' },
        text
      ],
      [
        'singleUseToken',
        AcceptInvitationDto,
        'token',
        { name: 'Ok', password: 'hunter2hunter2' },
        text
      ],
      ['verificationOtp', VerifyEmailDto, 'otp', { email: 'a@e.com', tenantId: 't' }, digits],
      ['resetOtp', VerifyOtpDto, 'otp', { email: 'a@e.com', tenantId: 't' }, digits],
      ['totpCode', MfaVerifyDto, 'code', {}, digits]
    ]

    /** Whether `value` passes validation for `property` on `dto`. */
    async function accepts(
      Dto: new () => object,
      property: string,
      rest: Record<string, unknown>,
      value: string
    ): Promise<boolean> {
      const errors = await validate(plainToInstance(Dto, { ...rest, [property]: value }))
      return !errors.some((e) => e.property === property)
    }

    // Verifies each bound is the length the endpoint actually enforces, at both edges. A bound
    // that differs between the two implementations means the same request is accepted by one
    // backend and refused by the other, which for a deployment running both behind one address
    // is a difference nobody can explain from the outside.
    //
    // The address is the one field whose upper edge is not asserted from below: `@IsEmail`
    // already refuses an address near that length on its own grounds (the domain-label limits),
    // so "accepted at exactly 255" is not a property this DTO has. The half that matters — that
    // an oversized value is refused — is asserted for it like every other field.
    it.each(BOUNDED_FIELDS)(
      'enforces the contract bound for %s',
      async (name, Dto, property, rest, fill) => {
        const bound = contract.requestFieldBounds[name]
        expect(bound).toBeDefined()

        if (bound?.max !== undefined) {
          if (name !== 'email') {
            expect(await accepts(Dto, property, rest, fill(bound.max))).toBe(true)
          }
          expect(await accepts(Dto, property, rest, fill(bound.max + 1))).toBe(false)
        }
        if (bound?.min !== undefined && bound.min > 1) {
          expect(await accepts(Dto, property, rest, fill(bound.min - 1))).toBe(false)
        }
      }
    )
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

    // Verifies the code actually indexes the prefixed form. The contract is only worth
    // anything if the code writes what it declares.
    //
    // Asserted through the real service rather than by grepping the source for a template
    // literal: the member is composed inside the session-creation script now, and a text
    // search would have gone red for a refactor that changed nothing about the wire — or
    // stayed green for one that changed everything. Here the plane prefix and the hash are
    // read off the arguments the script is invoked with, and the concatenation is pinned
    // against the script itself.
    it.each([
      ['dashboard', 'rt', 'sess', 'fam'],
      ['platform', 'prt', 'psess', 'pfam']
    ])(
      'indexes a new %s session under its prefixed member',
      async (kind, prefix, index, family) => {
        const redis = { eval: jest.fn() }
        const service = new AuthRedisService(
          redis as unknown as Redis,
          { redisNamespace: 'auth', hmacKey: 'test-hmac-key' } as unknown as ResolvedOptions
        )

        await service.writeNewSession({
          kind: kind as 'dashboard' | 'platform',
          tenantId: kind === 'platform' ? undefined : 'tenant-1',
          tokenHash: 'a'.repeat(64),
          sessionJson: '{}',
          familyId: 'fam-1',
          userId: 'u1',
          refreshTtl: 60
        })

        const call = redis.eval.mock.calls[0] as unknown[]
        const script = call[0] as string
        // All three keys, in the arity the script declares: [script, numkeys, ...keys, ...argv].
        // The record and the family index are asserted alongside the session index because the
        // script writes all three under one TTL, and a key that arrived empty would silently
        // write the whole session under the namespace root.
        expect(call).toContain(`auth:${prefix}:${'a'.repeat(64)}`)
        // The index is derived, not interpolated: it names the ACCOUNT, so it carries the
        // tenant on the dashboard plane and is HMACed like every other subject-derived key.
        expect(call).toContain(
          `auth:${sessionIndexKey(kind as 'dashboard' | 'platform', 'u1', 'test-hmac-key', kind === 'platform' ? undefined : 'tenant-1')}`
        )
        expect(call).toContain(`auth:${family}:fam-1`)
        // The member is `{prefix}:{hash}`, built in the script from these two arguments.
        expect(call).toContain(prefix)
        expect(call).toContain('a'.repeat(64))
        expect(script).toContain("SADD', KEYS[2], ARGV[4] .. ':' .. ARGV[5]")
        // The index TTL is re-armed in the SAME step, which is the half a dropped connection
        // used to skip — leaving the set with no expiry at all.
        expect(script).toContain("EXPIRE', KEYS[2], ARGV[2]")
      }
    )
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

      // The rejection rule lives in AuthRevocationService, which the three JWT guards delegate to;
      // reading it here pins the same comparison the guards used to carry inline.
      const revocation = readFileSync(
        join(__dirname, 'services/auth-revocation.service.ts'),
        'utf8'
      )
      expect(revocation).toContain('readStampedEpoch(payload) < epoch')
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
    // Verifies the contract describes the 256-bit refresh token this library mints, and only
    // that: no second shape is declared, so neither backend keeps a parsing allowance.
    it('declares the 256-bit refresh token and no second accepted shape', () => {
      expect(contract.credentialFormats['refreshToken']).toContain('64 lowercase hex')
      // No legacy shape is declared, and none is accepted: the libraries are new, so a
      // parsing allowance for a corpus that does not exist is a widened input for nothing.
      expect(contract.credentialFormats['refreshTokenLegacy']).toBeUndefined()
    })

    // Verifies the at-rest TOTP form is the Base32 text. Both backends read the same stored
    // secret, and decrypting one form as the other hands the wrong bytes to HMAC-SHA-1, which
    // rejects every code the user's authenticator produces.
    it('declares the TOTP secret at rest as encrypted Base32 text', () => {
      expect(contract.credentialFormats['totpSecretAtRest']).toContain('BASE32')
    })

    // Scenario: a stored password hash. Expected: PHC, carrying the parameters it was written
    // under. Why: a hash that records nothing can only be verified by assuming the cost
    // configured today, which makes that cost unchangeable — raise it and every stored hash
    // becomes unreproducible, every user locked out, irreversibly.
    it('writes the stored password hash as a PHC string', async () => {
      const service = new PasswordService(
        { password: { costFactor: 16_384, blockSize: 8, parallelization: 1 } } as never,
        { isBreached: async () => false } as never
      )
      const stored = await service.hash('a-password')

      expect(stored).toMatch(/^\$scrypt\$ln=14,r=8,p=1\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/)
      // Its own output must round-trip and must not immediately want rewriting.
      expect(await service.compare('a-password', stored)).toBe(true)
      expect(service.needsRehash(stored)).toBe(false)
    }, 30_000)

    // Scenario: the two hashes the contract pins, one written by each implementation.
    // Expected: both verify here, and report the staleness the contract declares.
    //
    // Why this test rather than a prose assertion: the entry this replaces read
    // `toContain('self-describing')`, and it was green for the entire period during which the
    // two libraries could not read each other's hashes at all. Both encodings ARE
    // self-describing — that is exactly why the description could not catch the divergence.
    // A hash the sibling cannot verify does not surface as a parse error either, because
    // verification is total: it becomes `invalid_credentials`, and five of those trip the
    // brute-force counter the two backends SHARE, locking the owner out of both with their
    // own correct password.
    //
    // The vectors are real emitted output, so this fails the moment either side's encoder,
    // parser, B64 alphabet or parameter ordering drifts from the other's.
    it.each(
      contract.passwordHashFormat.vectors.map((vector) => [vector.writtenBy, vector] as const)
    )(
      'verifies the contract password-hash vector written by %s',
      async (_who, vector) => {
        const service = new PasswordService(
          { password: { costFactor: 16_384, blockSize: 8, parallelization: 1 } } as never,
          { isBreached: async () => false } as never
        )

        expect(await service.compare(vector.password, vector.hash)).toBe(true)
        expect(await service.compare(`${vector.password}-wrong`, vector.hash)).toBe(false)
        expect(service.needsRehash(vector.hash)).toBe(vector.needsRehash)
      },
      30_000
    )

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
    // HMAC-SHA-256 — and never a `scrypt:` KDF hash, a form neither library reads or writes.
    // Why: the sibling backend verifies these digests directly.
    it('stores a recovery code as a hex HMAC-SHA-256 under the identifier key', () => {
      expect(contract.credentialFormats['recoveryCodeDigest']).toContain('hex hmac-sha256')
      expect(contract.credentialFormats['recoveryCodeDigestLegacy']).toBeUndefined()

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
        { redisNamespace: 'auth', hmacKey: 'test-hmac-key' } as unknown as ResolvedOptions
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
        { redisNamespace: 'auth', hmacKey: 'test-hmac-key' } as unknown as ResolvedOptions
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
  // Response bodies
  // -------------------------------------------------------------------------

  describe('response bodies', () => {
    /** A delivery service over the given mode, with a response double that records nothing. */
    function delivery(mode: 'cookie' | 'bearer' | 'both'): TokenDeliveryService {
      return new TokenDeliveryService({
        tokenDelivery: mode,
        cookies: {
          accessTokenName: 'access_token',
          refreshTokenName: 'refresh_token',
          sessionSignalName: 'has_session',
          refreshCookiePath: '/auth/refresh',
          sameSite: 'lax',
          accessTokenMaxAgeMs: 900_000,
          refreshTokenMaxAgeMs: 604_800_000,
          trustedOrigins: []
        },
        secureCookies: true,
        jwt: { accessCookieMaxAgeMs: 900_000 }
      } as unknown as ResolvedOptions)
    }

    const authResult = {
      user: { id: 'u1', email: 'u@e.com' },
      accessToken: 'jwt',
      rawRefreshToken: 'opaque'
    }

    /** A minimal Express response: only the cookie/header calls the service makes. */
    function response(): { res: unknown } {
      return { res: { cookie: jest.fn(), clearCookie: jest.fn(), setHeader: jest.fn() } }
    }

    // Scenario: cookie mode, the default. Expected: the body carries the user and NOTHING else.
    // Why: the tokens are in `Set-Cookie` precisely so script cannot read them. Repeating a
    // refresh token in the JSON payload hands it to any XSS on the page and makes the HttpOnly
    // flag decorative.
    it('keeps the tokens out of the body in cookie mode', () => {
      const { res } = response()
      const body = delivery('cookie').deliverAuthResponse(res as never, authResult as never)

      expect(Object.keys(body as object)).toEqual(contract.responseBodies.login.cookie)
      expect(JSON.stringify(body)).not.toContain('opaque')
      expect(JSON.stringify(body)).not.toContain('jwt')
    })

    // Scenario: bearer mode. Expected: exactly the declared keys, with the internal
    // `rawRefreshToken` surfacing as `refreshToken` — the name the contract and the sibling
    // backend both use.
    it('returns the declared keys in bearer mode', () => {
      const { res } = response()
      const body = delivery('bearer').deliverAuthResponse(res as never, authResult as never)

      expect(Object.keys(body as object).sort()).toEqual(
        [...contract.responseBodies.login.bearer].sort()
      )
      expect((body as { refreshToken: string }).refreshToken).toBe('opaque')
    })

    // Scenario: `GET /auth/me`. Expected: the bare user, no envelope. Why: the contract had no
    // entry for this route, and that gap is what let the sibling backend change the shape while
    // its client kept unwrapping `.user` — the client returned `undefined` while every other
    // signal said authenticated, and the test that should have caught it mocked the old
    // envelope. Pinned here so neither side can move it alone again.
    it('answers /me with the bare user and no envelope', async () => {
      expect(contract.responseBodies.me.envelope).toBe('none')

      const authService = { getMe: jest.fn().mockResolvedValue({ id: 'u1', email: 'a@e.com' }) }
      const controller = new AuthController(authService as never, {} as never, {} as never)

      const body = await controller.me({ sub: 'u1' } as never)

      // A `{ user }` wrapper would show up as exactly one key named `user`.
      expect(Object.keys(body)).not.toEqual(['user'])
      expect(body).toEqual({ id: 'u1', email: 'a@e.com' })
    })

    // Scenario: the platform login body. Expected: the account under `admin`. Why: this is the
    // one payload where the two implementations name the same thing differently if nobody is
    // watching — rust-auth's own generated TypeScript said `user` while its adapter emitted
    // `admin`, so a consumer reading `result.user` got undefined at runtime.
    it('names the platform account admin, never user', () => {
      expect(contract.responseBodies.platformLogin.bearer).toContain('admin')
      expect(contract.responseBodies.platformLogin.bearer).not.toContain('user')

      const platformResult: PlatformAuthResult = {
        admin: { id: 'a1' } as never,
        accessToken: 'jwt',
        rawRefreshToken: 'opaque'
      }
      expect(Object.keys(platformResult).sort()).toEqual(
        ['accessToken', 'admin', 'rawRefreshToken'].sort()
      )
    })

    // Scenario: the MFA challenge and ws-ticket payloads. Expected: exactly the declared keys.
    it('returns the declared keys for the challenge and ticket payloads', () => {
      const challenge: MfaChallengeResult = { mfaRequired: true, mfaTempToken: 't' }
      expect(Object.keys(challenge).sort()).toEqual(
        [...contract.responseBodies.mfaChallenge].sort()
      )
      expect(contract.responseBodies.wsTicket.sort()).toEqual(['expiresIn', 'ticket'])
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
      const body = new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED, {
        retryAfterSeconds: 300
      }).getResponse() as { error: { details: unknown } }

      expect(body.error.details).toEqual({ retryAfterSeconds: 300 })
    })
  })
})
