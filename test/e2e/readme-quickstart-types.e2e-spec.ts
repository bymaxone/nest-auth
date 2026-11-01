/**
 * @fileoverview Type-checks the README Quick Start under `strict`, the way a reader's project does.
 * @layer test
 *
 * `check:published` compiles the README's snippets but ignores the diagnostic for a name nothing
 * declares, because a snippet may lean on the paragraph above it. That also lets an undeclared
 * type degrade to an error type that behaves like `any`, so a mismatch that depends on it never
 * surfaces. Here nothing is left undeclared. The blocks are taken from the README text, the
 * reader-owned names get typed stand-ins, `@bymax-one/nest-auth` resolves to this repository's
 * source, and the program must come back with no diagnostic at all.
 *
 * Stand-ins, and nothing else: the reader's database client, the mail transport, the cookie
 * parser, and the five names the module block uses without importing them. The blocks that are
 * not type-checked are the ones `readme-quickstart.e2e-spec.ts` lists as not executed.
 */
import { basename, join } from 'node:path'

import {
  createCompilerHost,
  createProgram,
  createSourceFile,
  getPreEmitDiagnostics,
  parseJsonConfigFileContent,
  readConfigFile,
  sys,
  type CompilerOptions
} from 'typescript'

import { block } from './readme-blocks'

const ROOT = join(__dirname, '../..')

/** Where the blocks pretend to live: beside the repository's `node_modules`, so imports resolve. */
const VIRTUAL_DIR = join(ROOT, 'test', 'e2e', '.quickstart-types')

/** The README blocks that are programs, by a marker only that block contains, and the file each is. */
const BLOCKS: [marker: string, file: string][] = [
  ['// user.repository.ts', 'user.repository.ts'],
  ['// email.provider.ts', 'email.provider.ts'],
  ['// app.module.ts', 'app.module.ts'],
  ["import cookieParser from 'cookie-parser'", 'main.ts'],
  ['// users.controller.ts', 'users.controller.ts']
]

/** Typed stand-ins for what the README leaves to the reader. */
const STAND_INS: Record<string, string> = {
  'prisma.service.ts': `
    import type { AuthUser } from '@bymax-one/nest-auth'
    type Where = Record<string, unknown>
    export declare class PrismaService {
      user: {
        findFirst(args: { where: Where }): Promise<AuthUser | null>
        findUnique(args: { where: Where }): Promise<AuthUser | null>
        create(args: { data: Record<string, unknown> }): Promise<AuthUser>
        updateMany(args: { where: Where; data: Record<string, unknown> }): Promise<{ count: number }>
      }
    }
  `,
  'reader-owned.d.ts': `
    import type { Type } from '@nestjs/common'
    import type { Redis } from 'ioredis'
    declare global {
      class ConfigService {
        get(key: string): string | undefined
        getOrThrow(key: string): string
      }
      const ConfigModule: Type<unknown>
      const DatabaseModule: Type<unknown>
      const RedisModule: Type<unknown>
      class RedisService {
        client: Redis
      }
    }
    export {}
  `,
  'ambient.d.ts': `
    declare module 'resend' {
      export class Resend {
        constructor(apiKey: string)
        emails: { send(message: Record<string, unknown>): Promise<unknown> }
      }
    }
    declare module 'cookie-parser' {
      const cookieParser: () => (req: unknown, res: unknown, next: () => void) => void
      export default cookieParser
    }
  `
}

/** The repository's own compiler settings, tightened to `strict` and pointed at this source. */
function compilerOptions(): CompilerOptions {
  const config = readConfigFile(join(ROOT, 'tsconfig.json'), sys.readFile)
  const parsed = parseJsonConfigFileContent(config.config, sys, ROOT)
  return {
    ...parsed.options,
    noEmit: true,
    strict: true,
    skipLibCheck: true,
    baseUrl: ROOT,
    rootDir: ROOT,
    paths: { '@bymax-one/nest-auth': [join(ROOT, 'src', 'server', 'index.ts')] },
    types: ['node']
  }
}

/** Compiles `files` as if they sat in {@link VIRTUAL_DIR}; answers `TS<code> <file>` per error. */
function diagnosticsOf(files: Record<string, string>): string[] {
  const virtual = new Map(
    Object.entries(files).map(([name, text]) => [join(VIRTUAL_DIR, name), text])
  )
  const options = compilerOptions()
  const host = createCompilerHost(options)
  const { fileExists, readFile, getSourceFile, directoryExists } = host
  host.directoryExists = (dir) => dir === VIRTUAL_DIR || (directoryExists?.call(host, dir) ?? false)
  host.fileExists = (file) => virtual.has(file) || fileExists.call(host, file)
  host.readFile = (file) => virtual.get(file) ?? readFile.call(host, file)
  host.getSourceFile = (file, languageVersion, ...rest) => {
    const text = virtual.get(file)
    return text === undefined
      ? getSourceFile.call(host, file, languageVersion, ...rest)
      : createSourceFile(file, text, languageVersion)
  }
  const program = createProgram([...virtual.keys()], options, host)
  return getPreEmitDiagnostics(program)
    .filter((diagnostic) => diagnostic.file !== undefined && virtual.has(diagnostic.file.fileName))
    .map((diagnostic) => `TS${diagnostic.code} ${basename(diagnostic.file?.fileName ?? '')}`)
}

/** The README blocks, optionally altered, beside the stand-ins. */
function quickStartFiles(
  alter: (marker: string, source: string) => string
): Record<string, string> {
  const blocks = Object.fromEntries(
    BLOCKS.map(([marker, file]) => [file, alter(marker, block(marker))])
  )
  return { ...STAND_INS, ...blocks }
}

const unaltered = (_marker: string, source: string): string => source

/**
 * Defects planted into the README text, each of which must come back as one specific diagnostic.
 * `from` must occur exactly once in its block, so a README edit that moves it fails here instead
 * of leaving a row that checks nothing.
 */
const PLANTED: { name: string; marker: string; from: string; to: string; reports: string }[] = [
  {
    name: 'the secret is read with get, which may answer undefined',
    marker: '// app.module.ts',
    from: "config.getOrThrow('JWT_SECRET')",
    to: "config.get('JWT_SECRET')",
    reports: 'TS2322 app.module.ts'
  },
  {
    name: 'the module block does not import the repository it uses',
    marker: '// app.module.ts',
    from: "import { PrismaUserRepository } from './user.repository'\n",
    to: '',
    reports: 'TS2304 app.module.ts'
  },
  {
    name: 'the module block does not import the email provider it uses',
    marker: '// app.module.ts',
    from: "import { ResendEmailProvider } from './email.provider'\n",
    to: '',
    reports: 'TS2304 app.module.ts'
  }
]

describe('README Quick Start type-checks under strict (E2E)', () => {
  // Scenario: the README's repository, email provider, module, main.ts and controller blocks,
  // compiled together with every reader-owned name declared. Expected: no diagnostic.
  it('compiles with no diagnostic', () => {
    expect(diagnosticsOf(quickStartFiles(unaltered))).toEqual([])
  })

  // Scenario: a defect planted into one block. Expected: the diagnostic named in the row, so the
  // check is shown to see the class of error it exists for and not merely to be quiet.
  it.each(PLANTED)('reports $reports when $name', ({ marker, from, to, reports }) => {
    expect(block(marker).split(from)).toHaveLength(2)
    const planted = (m: string, source: string): string =>
      m === marker ? source.replace(from, to) : source

    expect(diagnosticsOf(quickStartFiles(planted))).toContain(reports)
  })
})
