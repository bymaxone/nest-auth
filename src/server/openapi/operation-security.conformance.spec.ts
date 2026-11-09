/**
 * @fileoverview Binds `conformance/openapi-operation-security.json` to the table the OpenAPI
 * fragment is built from.
 *
 * The committed artifact is generated, never hand-edited: run `pnpm gen:openapi-security` and
 * review the diff. This suite regenerates it from the live table and the controllers' route
 * metadata and fails when the committed copy has fallen behind, so a route that gains, loses or
 * changes its credential is a red test in the repository that caused it. rust-auth asserts its own
 * OpenAPI security table against this file instead of copying it by hand.
 *
 * @layer Test
 */

import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { RequestMethod } from '@nestjs/common'
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants'

import { OPERATIONS } from './auth-openapi-fragment'
import type { Credential } from './auth-openapi-fragment'

const ARTIFACT = join(__dirname, '../../../conformance/openapi-operation-security.json')
/** Every directory a shipped controller lives in. */
const CONTROLLER_DIRECTORIES = [join(__dirname, '../controllers'), join(__dirname, '../oauth')]

type Constructor = abstract new (...args: never[]) => object

/**
 * What each credential kind asks of the caller. The record is exhaustive over {@link Credential},
 * so a new kind does not compile until it is described here, and therefore in the artifact.
 */
const KINDS: Readonly<Record<Credential, string>> = {
  none: 'Reachable unauthenticated; the operation requires no credential.',
  access: 'The access token is required.',
  refreshRequired: 'The refresh credential is required.',
  accessAndRefreshRequired:
    'Both the access token and the refresh credential are required: the first authorises the caller and the second names the session.',
  accessWithOptionalRefresh:
    'The access token is required and the refresh credential is read when present.',
  accessWithOptionalRefreshCookie:
    'The access token is required and the refresh credential is read when present, from the cookie only because the HTTP method carries no body.',
  optionalAccessAndRefresh:
    'Both credentials are read and neither is required; each one received does more of the job.',
  platform: 'The platform access token is required.',
  platformLogout: 'The platform access token is read and not required.',
  platformRefresh: 'No header credential; the platform refresh token travels in the request body.'
}

const ARTIFACT_COMMENT = [
  'The credential each operation this library mounts requires, shared with rust-auth so its OpenAPI',
  'security table is asserted against this one and not copied by hand.',
  '',
  'GENERATED from the table `OPERATIONS` in src/server/openapi/auth-openapi-fragment.ts and the',
  "controllers' route metadata. Do not edit by hand: run `pnpm gen:openapi-security` and review the",
  'diff. `operation-security.conformance.spec.ts` fails when this file differs from what the code',
  'produces.',
  '',
  'Keys are `METHOD /path`, the path relative to the route prefix the host applies, with `:name` for',
  'a parameter. Values are one of the kinds in `kinds`, whose meaning is the whole contract here:',
  'how a kind becomes an OpenAPI security requirement depends on the deployment (`tokenDelivery`',
  'and which schemes are registered) and is not in this file.'
]

/** Loads every controller class the library ships, by class name. */
async function loadControllers(): Promise<Map<string, Constructor>> {
  const byName = new Map<string, Constructor>()
  for (const directory of CONTROLLER_DIRECTORIES) {
    for (const file of readdirSync(directory).filter((name) => /\.controller\.ts$/.test(name))) {
      const loaded = (await import(join(directory, file))) as Record<string, unknown>
      for (const exported of Object.values(loaded)) {
        if (typeof exported === 'function') byName.set(exported.name, exported as Constructor)
      }
    }
  }
  return byName
}

/**
 * Joins route segments into `/a/b`, dropping empty segments and the slashes around each.
 *
 * @param parts - The controller path and the handler path.
 * @returns The path, `/` when both are empty.
 */
function joinPath(...parts: unknown[]): string {
  const segments = parts.flatMap((part) => {
    if (typeof part !== 'string')
      throw new Error(`a route path must be a single string, got ${String(part)}`)
    return part.split('/').filter((segment) => segment !== '')
  })
  return `/${segments.join('/')}`
}

/**
 * Derives the artifact's `operations` map from the table and the route metadata.
 *
 * @param controllers - The controller classes by name.
 * @returns `METHOD /path` to credential kind, sorted by key.
 */
function deriveOperations(controllers: Map<string, Constructor>): Record<string, Credential> {
  const derived: Record<string, Credential> = {}
  for (const handlers of Object.values(OPERATIONS)) {
    for (const [handler, credential] of Object.entries(handlers)) {
      const [className = '', methodName = ''] = handler.split('.')
      const controller = controllers.get(className)
      if (controller === undefined) throw new Error(`${handler} names no shipped controller`)
      const method = (controller.prototype as Record<string, unknown>)[methodName]
      if (typeof method !== 'function') throw new Error(`${handler} names no method`)

      const verb: unknown = Reflect.getMetadata(METHOD_METADATA, method)
      if (typeof verb !== 'number') throw new Error(`${handler} is not a route handler`)
      const path = joinPath(
        Reflect.getMetadata(PATH_METADATA, controller),
        Reflect.getMetadata(PATH_METADATA, method)
      )
      const key = `${RequestMethod[verb]} ${path}`
      if (key in derived) throw new Error(`${key} is declared twice`)
      derived[key] = credential
    }
  }
  return Object.fromEntries(Object.entries(derived).sort(([a], [b]) => a.localeCompare(b)))
}

describe('OpenAPI operation security — generated artifact', () => {
  // Verifies the committed artifact is exactly what the current table and routes produce. Set
  // UPDATE_OPENAPI_SECURITY=1 (via `pnpm gen:openapi-security`) to rewrite it instead of asserting.
  it('matches the committed conformance artifact', async () => {
    const operations = deriveOperations(await loadControllers())
    const expected = { $comment: ARTIFACT_COMMENT, kinds: KINDS, operations }

    if (process.env['UPDATE_OPENAPI_SECURITY'] === '1') {
      writeFileSync(ARTIFACT, `${JSON.stringify(expected, null, 2)}\n`, 'utf8')
    }

    expect(JSON.parse(readFileSync(ARTIFACT, 'utf8'))).toEqual(JSON.parse(JSON.stringify(expected)))
  })

  // Verifies the file is byte for byte the generator's output, so a hand edit that keeps the
  // parsed value equal (key order, formatting) is also a red test.
  it('is written exactly as the generator writes it', async () => {
    const operations = deriveOperations(await loadControllers())
    const expected = `${JSON.stringify({ $comment: ARTIFACT_COMMENT, kinds: KINDS, operations }, null, 2)}\n`

    expect(readFileSync(ARTIFACT, 'utf8')).toBe(expected)
  })

  it('uses only kinds the file defines, and defines no kind that nothing uses', async () => {
    const used = new Set(Object.values(deriveOperations(await loadControllers())))

    expect([...used].sort()).toEqual(Object.keys(KINDS).sort())
  })

  it('lists no operation twice and keeps its keys in order', async () => {
    const keys = Object.keys(deriveOperations(await loadControllers()))

    expect(keys).toEqual([...keys].sort((a, b) => a.localeCompare(b)))
    expect(new Set(keys).size).toBe(keys.length)
  })
})
