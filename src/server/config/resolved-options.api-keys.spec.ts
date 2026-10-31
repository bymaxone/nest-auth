/**
 * @fileoverview Tests for the `apiKeys` option group: defaults, validation when enabled, and
 * the containment of the pepper.
 */

import { inspect } from 'node:util'

import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'
import { resolveOptions } from './resolved-options'

const JWT_SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'
const IDENTIFIER_KEY = 'Zt8#vB3@nM6$qL9%wE2^rY5&uI1*oP4(aS7)dF0!gH'
const PEPPER = 'pQ3$rT6&uW9*xZ2!aC5%dF8^gJ1(kM4)nP7+sV0-yB'

const BASE: BymaxAuthModuleOptions = {
  jwt: { secret: JWT_SECRET },
  roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
  rateLimit: { clientIpSource: 'peer' }
}

function withKeys(
  apiKeys: Partial<NonNullable<BymaxAuthModuleOptions['apiKeys']>>,
  extra: Partial<BymaxAuthModuleOptions> = {}
): BymaxAuthModuleOptions {
  return {
    ...BASE,
    ...extra,
    apiKeys: { enabled: true, pepper: PEPPER, scopes: ['read', 'admin'], ...apiKeys }
  }
}

describe('resolveOptions — apiKeys', () => {
  describe('defaults', () => {
    // A host that never opts in is neither asked for a pepper nor given a live feature.
    it('is disabled with documented defaults when absent', () => {
      const { apiKeys } = resolveOptions(BASE)
      // The pepper is non-enumerable by design, so it is read, not compared structurally.
      expect(apiKeys.pepper).toBe('')
      expect(apiKeys).toEqual({
        enabled: false,
        scopes: [],
        header: 'x-api-key',
        prefix: 'bak',
        lastUsedFlushSeconds: 60,
        auditMode: 'best-effort'
      })
    })

    // Nothing is validated while the feature is off, so a placeholder group does not fail boot.
    it('does not validate a disabled group', () => {
      expect(() =>
        resolveOptions({ ...BASE, apiKeys: { enabled: false, pepper: 'x', scopes: [] } })
      ).not.toThrow()
    })

    // Supplied values win over the defaults, field by field.
    it('keeps the values it was given', () => {
      const resolved = resolveOptions(
        withKeys({
          header: 'x-machine',
          prefix: 'svc',
          lastUsedFlushSeconds: 5,
          auditMode: 'required'
        })
      )
      expect(resolved.apiKeys).toMatchObject({
        enabled: true,
        pepper: PEPPER,
        scopes: ['read', 'admin'],
        header: 'x-machine',
        prefix: 'svc',
        lastUsedFlushSeconds: 5,
        auditMode: 'required'
      })
    })

    // A field a config object left `undefined` falls back to the default instead of erasing it.
    it('treats an undefined field as unset', () => {
      const resolved = resolveOptions({
        ...BASE,
        apiKeys: {
          enabled: undefined,
          pepper: PEPPER,
          scopes: ['read'],
          header: undefined,
          prefix: undefined,
          lastUsedFlushSeconds: undefined,
          auditMode: undefined
        } as unknown as NonNullable<BymaxAuthModuleOptions['apiKeys']>
      })
      expect(resolved.apiKeys).toMatchObject({
        enabled: false,
        header: 'x-api-key',
        prefix: 'bak',
        lastUsedFlushSeconds: 60,
        auditMode: 'best-effort'
      })
    })
  })

  describe('pepper', () => {
    it.each([
      ['empty', '', /apiKeys\.pepper is required/],
      ['short', 'short', /apiKeys\.pepper must be at least 32 characters/],
      ['repetitive', 'a'.repeat(40), /apiKeys\.pepper has insufficient entropy/]
    ])('refuses a %s pepper, naming the field', (_name, pepper, message) => {
      expect(() => resolveOptions(withKeys({ pepper }))).toThrow(message)
    })

    // A key shared across purposes is one leak away from all of them.
    it.each([
      ['jwt.secret', { jwt: { secret: PEPPER } }],
      ['a retired jwt secret', { jwt: { secret: JWT_SECRET, previousSecrets: [PEPPER] } }],
      ['identifierKey', { identifierKey: PEPPER }]
    ])('refuses a pepper equal to %s', (_name, extra) => {
      expect(() => resolveOptions(withKeys({}, extra as Partial<BymaxAuthModuleOptions>))).toThrow(
        /apiKeys\.pepper must not equal jwt\.secret, a retired jwt secret or identifierKey\. A key shared across purposes is one leak away from all of them\./
      )
    })

    // A distinct identifierKey and retired secrets are fine.
    it('accepts a pepper distinct from every other key', () => {
      expect(() =>
        resolveOptions(
          withKeys(
            {},
            {
              identifierKey: IDENTIFIER_KEY,
              jwt: { secret: JWT_SECRET, previousSecrets: [IDENTIFIER_KEY + 'x'] }
            }
          )
        )
      ).not.toThrow()
    })

    // The pepper never reaches a serialisation of the resolved options.
    it('is withheld from serialisation', () => {
      const resolved = resolveOptions(withKeys({}))
      expect(JSON.stringify(resolved)).not.toContain(PEPPER)
      expect(JSON.stringify(resolved.apiKeys)).not.toContain(PEPPER)
      expect(inspect(resolved, { depth: 6, showHidden: false })).not.toContain(PEPPER)
      expect(resolved.apiKeys.pepper).toBe(PEPPER)
    })
  })

  describe('scopes', () => {
    it.each([
      ['absent', undefined],
      ['empty', []],
      ['not a list', 'read'],
      ['a non-string entry', [1]],
      ['an empty entry', ['']],
      ['an entry starting with a symbol', ['-read']],
      ['an entry with a space', ['read it']],
      ['an over-long entry', ['a'.repeat(65)]]
    ])('refuses scopes that are %s', (_name, scopes) => {
      expect(() => resolveOptions(withKeys({ scopes: scopes as unknown as string[] }))).toThrow(
        /apiKeys\.scopes/
      )
    })

    // The messages say what to do, not only that something is wrong.
    it('explains the vocabulary and the scope grammar', () => {
      expect(() => resolveOptions(withKeys({ scopes: [] }))).toThrow(
        /closed vocabulary every route declaration and every issued key is checked against\./
      )
      expect(() => resolveOptions(withKeys({ scopes: ['no good'] }))).toThrow(
        /letters, digits and ':', '\.', '_', '-', starting with a letter or digit\./
      )
    })

    it('refuses a repeated scope', () => {
      expect(() => resolveOptions(withKeys({ scopes: ['read', 'read'] }))).toThrow(
        /apiKeys\.scopes\[1\] repeats/
      )
    })

    // The consumer's own vocabulary is accepted, including hyphens and a maximal entry.
    it('accepts hyphenated, dotted and maximal scope names', () => {
      expect(() =>
        resolveOptions(
          withKeys({ scopes: ['publish-claim', 'video:read', 'a.b_c', 'a'.repeat(64)] })
        )
      ).not.toThrow()
    })
  })

  describe('header, prefix, flush interval and audit mode', () => {
    it.each([
      ['uppercase', 'X-Api-Key'],
      ['with a space', 'x api'],
      ['empty', ''],
      ['over-long', 'a'.repeat(65)],
      ['authorization', 'authorization'],
      ['cookie', 'cookie'],
      ['set-cookie', 'set-cookie'],
      ['not a string', 7]
    ])('refuses a header that is %s', (_name, header) => {
      expect(() => resolveOptions(withKeys({ header: header as string }))).toThrow(
        /apiKeys\.header/
      )
    })

    it.each([
      ['with an underscore', 'my_key'],
      ['uppercase', 'BAK'],
      ['one character', 'b'],
      ['too long', 'a'.repeat(17)],
      ['starting with a digit', '1ab'],
      ['not a string', 3],
      // Coerces to the valid prefix 'ab' under a regex test: only the type check refuses it.
      ['an array that coerces to a valid prefix', ['ab']]
    ])('refuses a prefix that is %s', (_name, prefix) => {
      expect(() => resolveOptions(withKeys({ prefix: prefix as string }))).toThrow(
        /apiKeys\.prefix/
      )
    })

    // The messages say why.
    it('explains the header and prefix rules', () => {
      expect(() => resolveOptions(withKeys({ header: 'cookie' }))).toThrow(
        /authorization, cookie or set-cookie: those already carry a different credential\./
      )
      expect(() => resolveOptions(withKeys({ prefix: 'my_key' }))).toThrow(
        /starting with a letter\. An underscore is not allowed: it separates the parts of a key\./
      )
    })

    it('accepts both audit modes', () => {
      expect(() => resolveOptions(withKeys({ auditMode: 'best-effort' }))).not.toThrow()
      expect(() => resolveOptions(withKeys({ auditMode: 'required' }))).not.toThrow()
    })

    it('accepts prefixes at both length bounds', () => {
      expect(() => resolveOptions(withKeys({ prefix: 'ab' }))).not.toThrow()
      expect(() => resolveOptions(withKeys({ prefix: 'a'.repeat(16) }))).not.toThrow()
    })

    it.each([0, -1, 1.5, 3601, Number.NaN])('refuses a flush interval of %s', (seconds) => {
      expect(() => resolveOptions(withKeys({ lastUsedFlushSeconds: seconds }))).toThrow(
        /apiKeys\.lastUsedFlushSeconds/
      )
    })

    it('accepts both ends of the flush range', () => {
      expect(() => resolveOptions(withKeys({ lastUsedFlushSeconds: 1 }))).not.toThrow()
      expect(() => resolveOptions(withKeys({ lastUsedFlushSeconds: 3600 }))).not.toThrow()
    })

    it('refuses an unknown audit mode', () => {
      expect(() =>
        resolveOptions(withKeys({ auditMode: 'sometimes' as unknown as 'required' }))
      ).toThrow(/apiKeys\.auditMode/)
    })
  })
})
