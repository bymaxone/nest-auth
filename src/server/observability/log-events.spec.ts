/**
 * @fileoverview The catalog of log events, the README "Log events" table and the code that writes the events
 * agree: every event is documented, in the same words.
 *
 * @layer Test
 */

import { readFileSync } from 'node:fs'
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
})
