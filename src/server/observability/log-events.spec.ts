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
  // message and the same field names, and a sentence saying when it is written.
  it('is the README table, row for row', () => {
    const rows = documented()

    expect([...rows.keys()].sort()).toEqual([...CODES].sort())
    for (const code of CODES) {
      const spec = AUTH_LOG_EVENTS[code]
      const row = rows.get(code)
      expect(row?.level).toBe(spec.level)
      expect(row?.message).toBe(spec.message)
      expect(row?.when).not.toBe('')
      expect(row?.fields).toEqual([...spec.fields])
    }
  })

  // Scenario: the fields an event may carry. Expected: only names from this list. Why: a field is where a value
  // a caller, a host or a store supplied would enter, so a new name is a decision this list makes visible.
  it.each(CODES)('%s carries only fields from the closed list', (code) => {
    const allowed = [
      'plane',
      'flow',
      'reason',
      'kind',
      'via',
      'error',
      'detail',
      'familyId',
      'userId',
      'tenantId',
      'actorUserId'
    ]

    for (const field of AUTH_LOG_EVENTS[code].fields) expect(allowed).toContain(field)
  })

  // Scenario: who may be named. Expected: only an event written at the `log` level, which is the success and
  // audit trail, carries a user or a tenant, and no event of any level carries an address, a provider, a token or
  // a code. Why: an audit trail without "who" is useless, while a refusal that names the account lets whoever
  // reads the log enumerate it; an address is never wanted.
  it.each(CODES)('%s names a user or a tenant only when it is a success or audit event', (code) => {
    const { level, fields } = AUTH_LOG_EVENTS[code]

    for (const field of fields) {
      if (/^(userId|tenantId|actorUserId)$/.test(field)) expect(level).toBe('log')
      expect(field).not.toMatch(/email|address|provider|token|otp|secret|password/i)
    }
  })
})
