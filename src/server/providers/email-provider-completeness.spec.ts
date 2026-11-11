/**
 * @fileoverview The bundled `DefaultAuthEmailProvider` implements every method a feature needs.
 *
 * A feature that needs an optional `IEmailProvider` method refuses to boot without it, so a default
 * provider that lacks one makes the feature unusable for every host that takes the default. Both
 * lists below are read from the sources, so a method added to a guard or to the interface is checked
 * without anyone remembering to list it.
 *
 * @layer Test
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

import ts from 'typescript'

import { DefaultAuthEmailProvider } from './default-auth-email.provider'

const SERVER = join(__dirname, '..')
const INTERFACE = join(SERVER, 'interfaces/email-provider.interface.ts')

/** Every non-spec source file under `dir`. */
function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === '__tests__' ? [] : sources(path)
    return name.endsWith('.ts') && !name.endsWith('.spec.ts') ? [path] : []
  })
}

/**
 * The provider methods a boot-time guard demands: the `onModuleInit` refusals written as
 * `if (!this.<provider>.<method>) { throw ... }`.
 *
 * @param source - The text of a source file.
 * @returns The method names the guards in it require.
 */
export function guardedMethods(source: string): string[] {
  return [...source.matchAll(/if \(!this\.\w+\.(send\w+)\) \{\s*throw new Error/g)].map(
    (match) => match[1] ?? ''
  )
}

/**
 * The optional methods of the `IEmailProvider` interface.
 *
 * @param source - The text of the file that declares it.
 * @returns The names of the interface's members declared with `?`.
 */
export function optionalMethods(source: string): string[] {
  const tree = ts.createSourceFile('email-provider.interface.ts', source, ts.ScriptTarget.Latest)
  const names: string[] = []
  tree.forEachChild((node) => {
    if (!ts.isInterfaceDeclaration(node) || node.name.text !== 'IEmailProvider') return
    for (const member of node.members) {
      if (ts.isMethodSignature(member) && member.questionToken !== undefined) {
        names.push(member.name.getText(tree))
      }
    }
  })
  return names
}

describe('the bundled email provider', () => {
  const implemented = (name: string): boolean =>
    typeof Reflect.get(DefaultAuthEmailProvider.prototype, name) === 'function'

  describe('reads what to check from the sources', () => {
    it('finds the method a boot-time guard demands', () => {
      const guard = `onModuleInit(): void {\n    if (!this.email.sendThing) {\n      throw new Error('x')\n    }\n  }`

      expect(guardedMethods(guard)).toEqual(['sendThing'])
    })

    it('finds the optional methods of the interface and no required one', () => {
      const fixture = `export interface IEmailProvider {\n  sendA(x: string): Promise<void>\n  sendB?(x: string): Promise<void>\n}\ninterface Other {\n  sendC?(): void\n}`

      expect(optionalMethods(fixture)).toEqual(['sendB'])
    })
  })

  it('implements every method a feature refuses to boot without', () => {
    const demanded = sources(SERVER).flatMap((file) => guardedMethods(readFileSync(file, 'utf8')))

    expect(demanded.length).toBeGreaterThan(0)
    expect(demanded.filter((name) => !implemented(name))).toEqual([])
  })

  it('implements every optional method of the provider port', () => {
    const optional = optionalMethods(readFileSync(INTERFACE, 'utf8'))

    expect(optional.length).toBeGreaterThan(0)
    expect(optional.filter((name) => !implemented(name))).toEqual([])
  })

  it('looks at the whole server source tree', () => {
    expect(sources(SERVER).map((file) => relative(SERVER, file))).toContain(
      'services/workspace-invitation.service.ts'
    )
  })
})
