/**
 * @fileoverview The catalog of log events, the README "Log events" table and the code that writes the events
 * agree both ways: every event is documented and written somewhere, and every call names a documented event
 * with only the fields the catalog lists.
 *
 * @layer Test
 */

import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import { AUTH_LOG_EVENTS } from './log-events'
import type { AuthLogEvent } from './log-events'

const ROOT = join(__dirname, '..')
const README = readFileSync(join(__dirname, '../../../README.md'), 'utf8')
const CODES = Object.keys(AUTH_LOG_EVENTS) as AuthLogEvent[]

/** The rows of the README "Log events" table: code, level, message, when, and the field names. */
function documented(): Map<
  string,
  { level: string; message: string; when: string; fields: string[] }
> {
  const section = README.slice(README.indexOf('### Log events'))
  const body = section.slice(0, section.indexOf('\n---'))
  const rows = new Map<string, { level: string; message: string; when: string; fields: string[] }>()
  for (const line of body.split('\n')) {
    const cells = line.split('|').map((cell) => cell.trim())
    const code = /^`(AUTH_[A-Z_]+)`$/.exec(cells[1] ?? '')?.[1]
    if (code === undefined) continue
    const fields = [...(cells[5] ?? '').matchAll(/`(\w+)`/g)].map((m) => m[1] as string)
    rows.set(code, { level: cells[2] ?? '', message: cells[3] ?? '', when: cells[4] ?? '', fields })
  }
  return rows
}

/** Every non-test source file of the server. */
function sources(dir: string = ROOT): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) return entry.name === '__tests__' ? [] : sources(path)
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.spec.ts') ? [path] : []
  })
}

/** The events the code writes: each call's code and the field names it passes. */
function writtenCalls(): Array<{ code: string; fields: string[]; file: string }> {
  const calls: Array<{ code: string; fields: string[]; file: string }> = []
  const call = /logEvent\(\s*[\w.]+,\s*'(AUTH_[A-Z_]+)'(?:,\s*\{([^}]*)\})?/g
  for (const file of sources()) {
    if (file.endsWith('log-event.ts') || file.endsWith('log-events.ts')) continue
    for (const match of readFileSync(file, 'utf8').matchAll(call)) {
      const fields = [...(match[2] ?? '').matchAll(/(?:^|,)\s*(\w+)\s*(?::|(?=,|$))/g)].map(
        (m) => m[1] as string
      )
      calls.push({ code: match[1] as string, fields, file })
    }
  }
  return calls
}

describe('the log event catalog', () => {
  // Scenario: every event of the catalog. Expected: a level the logger has, library text with no placeholder or
  // assignment in it, and a list of field names. Why: a message with a `${}` or a `key=value` is where a value
  // a caller supplied would enter.
  it.each(CODES)('%s is library text at a real level', (code) => {
    const { level, message, fields } = AUTH_LOG_EVENTS[code]

    expect(['log', 'warn', 'error']).toContain(level)
    expect(message).toMatch(/^[a-zA-Z]/)
    expect(message).not.toMatch(/\$\{|=|userId=|tenantId/)
    expect(new Set(fields).size).toBe(fields.length)
  })

  // Scenario: the catalog and the README table. Expected: the same codes, and for each the same level, the same
  // sentence and the same field names.
  it('is the README table, row for row', () => {
    const rows = documented()

    expect([...rows.keys()].sort()).toEqual([...CODES].sort())
    for (const code of CODES) {
      const spec = AUTH_LOG_EVENTS[code]
      const row = rows.get(code)
      expect(row?.level).toBe(spec.level)
      expect(row?.message).toBe(spec.message)
      expect(row?.when).toBe(spec.when[0]?.toUpperCase() + spec.when.slice(1))
      expect(row?.fields).toEqual([...spec.fields])
    }
  })

  // Scenario: the code that writes events. Expected: every call names a catalog code and passes only the
  // fields the catalog lists for it, and every catalog code is written by at least one call.
  it('is what the code writes, and nothing else', () => {
    const calls = writtenCalls()

    expect(calls.length).toBeGreaterThan(0)
    for (const { code, fields } of calls) {
      expect(CODES).toContain(code)
      const allowed: readonly string[] = AUTH_LOG_EVENTS[code as AuthLogEvent].fields
      for (const field of fields) expect(allowed).toContain(field)
    }
    expect(new Set(calls.map((call) => call.code))).toEqual(new Set(CODES))
  })
})
