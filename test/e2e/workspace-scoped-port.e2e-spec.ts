/**
 * @fileoverview Fails when a method on a workspace port can name a workspace or a membership without
 * the whole key.
 *
 * A workspace id is unique only inside its tenant, and a user id only inside its tenant, so an
 * implementation that is handed less than the full key cannot scope the row it reads or writes,
 * however carefully it is written. The rule lives in the declaration, not in prose: this suite
 * reads the TypeScript AST of each port, so a method added tomorrow fails until somebody both
 * gives it the key it needs and lists it in the table below.
 *
 * The table is explicit because the required key differs by method, and a rule that guessed it
 * from the method's name would drift:
 * - a workspace method names `tenantId` and `workspaceId`;
 * - a membership method names the member as well;
 * - a listing by member needs the tenant and the member, since it spans workspaces;
 * - the last-active methods are keyed by tenant and member, since they span workspaces.
 *
 * It uses the same reader as `tenant-scoped-port.e2e-spec.ts`, and, like it, checks the TYPE of
 * each key and not merely its name, because `tenantId: string | undefined` is a required property
 * that still permits a call with no tenant.
 *
 * @layer Test
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { readPort } from './port-ast'

const INTERFACES = join(__dirname, '../../src/server/interfaces')
const WORKSPACE_PORT = join(INTERFACES, 'workspace-repository.interface.ts')
const MEMBERSHIP_PORT = join(INTERFACES, 'membership-repository.interface.ts')

/** The keys, each of which must be typed exactly `string`, a method's payload has to require. */
type KeyTable = Record<string, readonly string[]>

const WORKSPACE_KEYS: KeyTable = {
  createWithOwner: ['tenantId', 'workspaceId'],
  findById: ['tenantId', 'workspaceId'],
  rename: ['tenantId', 'workspaceId'],
  updateStatus: ['tenantId', 'workspaceId']
}

const MEMBERSHIP_KEYS: KeyTable = {
  find: ['tenantId', 'workspaceId', 'userId'],
  listForUser: ['tenantId', 'userId'],
  listForWorkspace: ['tenantId', 'workspaceId'],
  create: ['tenantId', 'workspaceId', 'userId'],
  changeRole: ['tenantId', 'workspaceId', 'userId'],
  remove: ['tenantId', 'workspaceId', 'userId'],
  transferOwnership: ['tenantId', 'workspaceId'],
  getLastActiveWorkspaceId: ['tenantId', 'userId'],
  setLastActiveWorkspaceId: ['tenantId', 'workspaceId', 'userId']
}

/** One method that breaks the rule, named with what is wrong. */
interface Violation {
  method: string
  problem: string
}

/**
 * Judges a parsed port against its key table.
 *
 * @param port - The parsed port.
 * @param table - The keys each method's payload has to require.
 * @returns Every method that is unlisted, takes other than one local payload object, or whose
 *   payload does not require a listed key typed exactly `string`; every table entry with no method
 *   behind it; and anything on the port a method-only reading would miss.
 */
function judge(port: ReturnType<typeof readPort>, table: KeyTable): Violation[] {
  const violations: Violation[] = []
  for (const method of port.methods) {
    const keys = table[method.name]
    if (keys === undefined) {
      violations.push({ method: method.name, problem: 'is not in the key table' })
      continue
    }
    const payload =
      method.params.length === 1 ? port.localTypes.get(method.params[0]?.type ?? '') : undefined
    if (payload === undefined) {
      violations.push({ method: method.name, problem: 'does not take one named payload object' })
      continue
    }
    for (const key of keys) {
      if (payload.get(key) !== 'string') {
        violations.push({ method: method.name, problem: `does not require ${key}: string` })
      }
    }
  }
  for (const member of port.otherMembers) {
    violations.push({ method: member, problem: 'is declared as something other than a method' })
  }
  for (const parent of port.inherits) {
    violations.push({
      method: parent,
      problem: 'is extended by the port, and its members are not read'
    })
  }
  const declared = new Set(port.methods.map((method) => method.name))
  for (const name of Object.keys(table)) {
    if (!declared.has(name))
      violations.push({ method: name, problem: 'is listed but not declared' })
  }
  return violations
}

describe('workspace-scoped ports', () => {
  const workspacePort = readPort(WORKSPACE_PORT, 'IWorkspaceRepository')
  const membershipPort = readPort(MEMBERSHIP_PORT, 'IMembershipRepository', [WORKSPACE_PORT])

  // Named, not counted: a port that parsed to some other interface with enough members would pass
  // a length check, and a deleted method would too.
  it('parses exactly the methods the tables list', () => {
    expect(workspacePort.methods.map((method) => method.name).sort()).toEqual(
      Object.keys(WORKSPACE_KEYS).sort()
    )
    expect(membershipPort.methods.map((method) => method.name).sort()).toEqual(
      Object.keys(MEMBERSHIP_KEYS).sort()
    )
  })

  it('has IWorkspaceRepository name every workspace through its full key', () => {
    expect(judge(workspacePort, WORKSPACE_KEYS)).toEqual([])
  })

  it('has IMembershipRepository name every membership through its full key', () => {
    expect(judge(membershipPort, MEMBERSHIP_KEYS)).toEqual([])
  })

  describe('the rule itself', () => {
    let dir: string

    beforeAll(() => {
      dir = mkdtempSync(join(tmpdir(), 'workspace-port-'))
    })

    afterAll(() => {
      rmSync(dir, { recursive: true, force: true })
    })

    /** Writes a port declaration to a temp file and parses it. */
    function parse(source: string): ReturnType<typeof readPort> {
      const file = join(dir, `port-${Math.random().toString(36).slice(2)}.ts`)
      writeFileSync(file, source)
      return readPort(file, 'IPort')
    }

    // The gate must be able to fail, or the two arms above prove nothing: each shape below is a
    // way a method could name a workspace without its whole key.
    it.each([
      [
        'a payload missing the workspace id',
        'interface P { tenantId: string }\ninterface IPort { rename(p: P): Promise<void> }',
        'does not require workspaceId: string'
      ],
      [
        'a tenant typed so that it may be absent',
        'interface P { tenantId: string | undefined; workspaceId: string }\ninterface IPort { rename(p: P): Promise<void> }',
        'does not require tenantId: string'
      ],
      [
        'positional strings instead of a payload object',
        'interface IPort { rename(tenantId: string, workspaceId: string): Promise<void> }',
        'does not take one named payload object'
      ],
      [
        'a key that is optional',
        'interface P { tenantId?: string; workspaceId: string }\ninterface IPort { rename(p: P): Promise<void> }',
        'does not require tenantId: string'
      ],
      [
        'an intersection payload the reader cannot resolve',
        'interface A { tenantId: string }\ninterface B { workspaceId: string }\ninterface IPort { rename(p: A & B): Promise<void> }',
        'does not take one named payload object'
      ],
      [
        'a member declared as a function-typed property',
        'interface P { tenantId: string; workspaceId: string }\ninterface IPort { rename(p: P): Promise<void>; archive: (p: P) => Promise<void> }',
        'is declared as something other than a method'
      ],
      [
        'a port that inherits members it does not declare',
        'interface P { tenantId: string; workspaceId: string }\ninterface Base { archive(p: P): Promise<void> }\ninterface IPort extends Base { rename(p: P): Promise<void> }',
        'is extended by the port, and its members are not read'
      ],
      [
        'a method the table does not list',
        'interface P { tenantId: string; workspaceId: string }\ninterface IPort { rename(p: P): Promise<void>; archive(p: P): Promise<void> }',
        'is not in the key table'
      ]
    ])('refuses %s', (_name, source, problem) => {
      const violations = judge(parse(source), { rename: ['tenantId', 'workspaceId'] })

      expect(violations.map((violation) => violation.problem)).toContain(problem)
    })

    it('refuses a table entry with no method behind it', () => {
      const port = parse(
        'interface P { tenantId: string }\ninterface IPort { find(p: P): Promise<void> }'
      )

      expect(judge(port, { find: ['tenantId'], gone: ['tenantId'] })).toEqual([
        { method: 'gone', problem: 'is listed but not declared' }
      ])
    })

    it('accepts a payload that extends a parent declared in the same file', () => {
      const port = parse(
        'interface Ref { tenantId: string; workspaceId: string }\n' +
          'interface P extends Ref { name: string }\n' +
          'interface IPort { rename(p: P): Promise<void> }'
      )

      expect(judge(port, { rename: ['tenantId', 'workspaceId'] })).toEqual([])
    })
  })
})
