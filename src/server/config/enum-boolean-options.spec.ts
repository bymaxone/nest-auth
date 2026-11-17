/**
 * @fileoverview Every flag is exactly `true` or `false` and every documented-set option is one of its
 * documented values, at boot. A flag read as `if (x)` in one place and `=== false` in another is
 * decided by whichever reader sees a value that is neither, and an option compared with `===` falls
 * through to its default branch on a typo; both are refused instead.
 *
 * @layer Test
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import * as ts from 'typescript'

import { resolveOptions } from './resolved-options'
import {
  BOOLEAN_OPTIONS,
  BOOLEAN_OR_FUNCTION_OPTIONS,
  CONTROLLER_FLAGS,
  ENUM_OPTIONS
} from './enum-boolean-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

const SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'

/** A value read back as the type a test needs it to be, for options a typed call would refuse. */
function untyped<T>(value: unknown): T {
  return value as T
}

/** Options with `value` at the dotted `path`, plus what the owning group needs to resolve. */
function optionsAt(path: string, value: unknown): BymaxAuthModuleOptions {
  const options: Record<string, unknown> = {
    jwt: { secret: SECRET },
    roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
    rateLimit: { clientIpSource: 'peer' }
  }
  const steps = path.split('.')
  const first = steps[0] as string
  if (first === 'workspaces') {
    options.workspaces = {
      enabled: true,
      roles: { hierarchy: { owner: ['editor'], editor: [] }, ownerRole: 'owner' }
    }
  }
  if (first === 'apiKeys') {
    options.apiKeys = {
      enabled: true,
      pepper: 'Zt8#vB3@nM6$qL9%wE2^rY5&uI1*oP4(aS7)dF0!gH',
      scopes: ['read']
    }
  }
  if (first === 'platform')
    options.roles = { hierarchy: { ADMIN: [] }, platformHierarchy: { P: [] } }
  if (path === 'enforceTenantBinding') options.tenantIdResolver = () => 't1'
  if (path === 'secureCookies' && value === false) options.environment = 'development'
  if (path === 'cookies.sameSite' && value === 'none') {
    options.cookies = { trustedOrigins: ['https://app.example.com'] }
  }
  let node = options
  for (const step of steps.slice(0, -1)) {
    node[step] = { ...((node[step] as Record<string, unknown> | undefined) ?? {}) }
    node = node[step] as Record<string, unknown>
  }
  node[steps[steps.length - 1] as string] = value
  if (!('jwt' in options && 'roles' in options && 'rateLimit' in options)) {
    throw new Error('the base options lost a required group')
  }
  return untyped<BymaxAuthModuleOptions>(options)
}

/** The values a flag can arrive as from an environment variable or untyped code, none of them a boolean. */
const NOT_A_BOOLEAN: [string, unknown][] = [
  ['an empty string', ''],
  ['zero', 0],
  ['one', 1],
  ["'false'", 'false'],
  ["'no'", 'no'],
  ['an object', {}],
  ['an array', []]
]

const FLAGS = [...BOOLEAN_OPTIONS, ...BOOLEAN_OR_FUNCTION_OPTIONS]

describe('flags at boot', () => {
  // Scenario: each flag given a value that is not a boolean. Expected: refused, naming the option, with
  // the type and never the content. Why: `rateLimit.enabled: ''` switched the rate-limit guard off
  // (`if (!enabled) return true`) while the boot check still read it as enabled.
  describe.each(FLAGS)('%s', (path) => {
    it.each(NOT_A_BOOLEAN)('refuses %s', (_label, value) => {
      expect(() => resolveOptions(optionsAt(path, value))).toThrow(
        new RegExp(
          `^\\[BymaxAuthModule\\] ${path.replace('.', '\\.')} must be true or false \\(received `
        )
      )
    })

    // Scenario: true and false. Expected: both resolve.
    it.each([true, false])('takes %s', (value) => {
      expect(() => resolveOptions(optionsAt(path, value))).not.toThrow()
    })
  })

  // Scenario: a flag that is a function or a boolean. Expected: a function resolves.
  it('takes a function for workspaces.allowCreate', () => {
    expect(() => resolveOptions(optionsAt('workspaces.allowCreate', () => true))).not.toThrow()
  })

  // Scenario: a secret passed to a flag by mistake. Expected: the refusal names the type and never the secret.
  it('never prints a string given to a flag', () => {
    const secret = 'hunter2-not-a-flag'
    let message = ''
    try {
      resolveOptions(optionsAt('rateLimit.enabled', secret))
    } catch (error) {
      message = error instanceof Error ? error.message : ''
    }

    expect(message).toContain('received a string')
    expect(message).not.toContain(secret)
  })

  // Scenario: the measured consequences. Expected: each is refused at boot instead of reaching its reader.
  it.each([
    ['rateLimit.enabled', ''],
    ['emailVerification.required', ''],
    ['secureCookies', 0],
    ['sessions.enabled', '']
  ])('refuses %s set to %p, which a reader would have taken for off', (path, value) => {
    expect(() => resolveOptions(optionsAt(path, value))).toThrow('must be true or false')
  })
})

describe('documented-set options at boot', () => {
  describe.each(Object.entries(ENUM_OPTIONS))('%s', (path, allowed) => {
    // Scenario: each documented value. Expected: resolves.
    it.each(allowed)('takes %s', (value) => {
      expect(() => resolveOptions(optionsAt(path, value))).not.toThrow()
    })

    // Scenario: a typo, a different case, an empty string, a number and a boolean. Expected: refused,
    // never folded to a documented value, naming the type and not the content.
    it.each([
      ['a typo', 'preupload'],
      ['a different case', allowed[0]?.toUpperCase()],
      ['an empty string', ''],
      ['a number', 5],
      ['a boolean', true]
    ])('refuses %s', (_label, value) => {
      let message = ''
      try {
        resolveOptions(optionsAt(path, value))
      } catch (error) {
        message = error instanceof Error ? error.message : ''
      }

      expect(message).toContain(`${path} must be one of`)
      expect(message).not.toContain('preupload')
    })
  })

  // Scenario: the typo that dropped the Secure flag from every cookie. Expected: refused, and the
  // documented value still makes cookies Secure.
  it('refuses environment "prodution" and keeps production secure', () => {
    expect(() => resolveOptions(optionsAt('environment', 'prodution'))).toThrow(
      "environment must be one of 'production', 'development', 'test'"
    )
    expect(resolveOptions(optionsAt('environment', 'production')).secureCookies).toBe(true)
  })
})

describe('controller flags', () => {
  // Scenario: each controller flag given a non-boolean. Expected: refused by the check registerAsync runs.
  it.each(CONTROLLER_FLAGS)('controllers.%s is true or false', async (name) => {
    const { validateControllerFlags } = await import('./enum-boolean-options')

    expect(() => validateControllerFlags({ [name]: 'false' })).toThrow(
      `controllers.${name} must be true or false (received a string)`
    )
    expect(() => validateControllerFlags({ [name]: true })).not.toThrow()
    expect(() => validateControllerFlags(undefined)).not.toThrow()
  })
})

describe('the option interfaces', () => {
  /** Every property typed `boolean`, or a union of string literals, in the option interfaces. */
  function declaredOptions(): { flags: string[]; sets: string[] } {
    const flags: string[] = []
    const sets: string[] = []
    const files = [
      'auth-module-options',
      'workspace-options',
      'api-key-options',
      'controller-flags'
    ].map((name) => join(__dirname, '..', 'interfaces', `${name}.interface.ts`))
    for (const file of files) {
      const source = ts.createSourceFile(
        file,
        readFileSync(file, 'utf8'),
        ts.ScriptTarget.Latest,
        true
      )
      const visit = (node: ts.Node, path: string[]): void => {
        if (ts.isPropertySignature(node) && node.type !== undefined) {
          const here = [...path, node.name.getText()]
          if (node.type.kind === ts.SyntaxKind.BooleanKeyword) flags.push(here.join('.'))
          else if (
            ts.isUnionTypeNode(node.type) &&
            node.type.types.every(
              (member) => ts.isLiteralTypeNode(member) && ts.isStringLiteral(member.literal)
            )
          ) {
            sets.push(here.join('.'))
          } else if (ts.isTypeLiteralNode(node.type)) {
            node.type.members.forEach((member) => visit(member, here))
          }
          return
        }
        ts.forEachChild(node, (child) => visit(child, path))
      }
      ts.forEachChild(source, (node) => {
        if (!ts.isInterfaceDeclaration(node)) return
        const root = node.name.text === 'BymaxAuthModuleOptions' ? [] : [node.name.text]
        node.members.forEach((member) => visit(member, root))
      })
    }
    return { flags, sets }
  }

  /** The options an interface declares as a set, that a dedicated validator already checks. */
  const CHECKED_ELSEWHERE = ['ApiKeyOptions.auditMode']

  /** The interface name that a dotted path starts with is the group it belongs to. */
  const asOptionPath = (declared: string): string =>
    declared
      .replace(/^ControllerFlags\./, 'controllers.')
      .replace(/^WorkspaceOptions\./, 'workspaces.')
      .replace(/^ApiKeyOptions\./, 'apiKeys.')

  // Scenario: every boolean and every set of string literals that an option interface declares.
  // Expected: each is in a table of this module, so a new option cannot be added without being checked.
  it('has every declared flag and documented set in a validator table', () => {
    const { flags, sets } = declaredOptions()
    const checkedFlags = new Set([
      ...BOOLEAN_OPTIONS,
      ...BOOLEAN_OR_FUNCTION_OPTIONS,
      ...CONTROLLER_FLAGS.map((name) => `controllers.${name}`)
    ])
    const checkedSets = new Set(Object.keys(ENUM_OPTIONS))

    const missingFlags = flags.map(asOptionPath).filter((path) => !checkedFlags.has(path))
    const missingSets = sets
      .filter((path) => !CHECKED_ELSEWHERE.includes(path))
      .map(asOptionPath)
      .filter((path) => !checkedSets.has(path))

    expect(missingFlags).toEqual([])
    expect(missingSets).toEqual([])
    expect(flags.length).toBeGreaterThan(15)
    expect(sets.length).toBeGreaterThan(4)
  })
})
