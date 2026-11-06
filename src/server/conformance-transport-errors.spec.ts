/**
 * @fileoverview The transport-error answers, driven against the shared wire contract.
 *
 * `conformance.spec.ts` pins the contract's own bytes. These cases drive `AuthExceptionFilter`
 * against the `transportErrors` section: every body-parser type the filter matches has to sit in
 * exactly one row, and the filter has to answer that row's status and fixed message. A filter and
 * a contract that disagree raise nothing at runtime, and rust-auth reads the same rows, so this is
 * the only place the drift shows.
 *
 * @layer Conformance
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { BadRequestException } from '@nestjs/common'
import type { ArgumentsHost } from '@nestjs/common'

import { AUTH_ERROR_CODES, AUTH_ERROR_STATUS } from './errors/auth-error-codes'
import { AuthExceptionFilter } from './filters/auth-exception.filter'

interface TransportErrorsContract {
  transportErrors: {
    envelope: { code: string; details: null }
    rows: { condition: string; status: number | string; message: string }[]
    contentTypeMismatch: { status: number; code: string; message: string }
  }
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as TransportErrorsContract

describe('cross-implementation conformance: transport errors', () => {
  /** Runs the real filter over `exception` for a request that matched no route. */
  function answer(exception: unknown): { status: number; body: unknown } {
    let status = 0
    let body: unknown
    const res = {
      status: (code: number) => {
        status = code
        return {
          json: (payload: unknown) => {
            body = payload
          }
        }
      }
    }
    const host = {
      switchToHttp: () => ({ getResponse: () => res, getRequest: () => ({}) })
    } as unknown as ArgumentsHost
    new AuthExceptionFilter().catch(exception, host)
    return { status, body }
  }

  /** What a refused request from body-parser looks like at the filter. */
  function refused(type: string, status: number): Error {
    return Object.assign(new Error('parser text that must not be repeated'), { type, status })
  }

  const { envelope, rows, contentTypeMismatch } = contract.transportErrors

  // Verifies the filter's answer to EVERY body-parser type it matches is the contract row that
  // names that type: exactly one row, the row's fixed message, and the row's status or, for
  // the row that takes its status from the error, the status the parser reported. The types and
  // the statuses body-parser gives them are listed here rather than read from the filter, so a
  // type matched by the filter but named by no row fails this test, and so does one in two rows.
  it.each([
    ['entity.parse.failed', 400],
    ['entity.verify.failed', 403],
    ['request.aborted', 400],
    ['request.size.invalid', 400],
    ['querystring.parse.rangeError', 400],
    ['parameters.too.many', 413],
    ['entity.too.large', 413],
    ['charset.unsupported', 415],
    ['encoding.unsupported', 415]
  ])('answers the %s refusal as the one contract row naming it', (type, reported) => {
    const named = rows.filter((row) => row.condition.includes(type))
    expect(named).toHaveLength(1)
    const row = named[0] as (typeof rows)[number]

    expect(answer(refused(type, reported))).toEqual({
      status: typeof row.status === 'number' ? row.status : reported,
      body: { error: { code: envelope.code, message: row.message, details: envelope.details } }
    })
  })

  // Verifies a malformed body refused before routing is answered as the row that says so.
  it('answers a pre-routing BadRequestException as the malformed-body row', () => {
    const row = rows.find((candidate) => candidate.condition.includes('malformed JSON body'))

    expect(answer(new BadRequestException('x'))).toEqual({
      status: row?.status,
      body: { error: { code: envelope.code, message: row?.message, details: envelope.details } }
    })
  })

  // Verifies the row that takes its status from the error says so in the contract.
  it('declares that the verify-failure row takes the status from the error itself', () => {
    expect(rows[1]?.status).toBe("the error's own 4xx status")
  })

  // Verifies the content-type row names the library's own validation code and status.
  it('keeps the content-type mismatch on auth.validation at the catalog status', () => {
    expect(contentTypeMismatch.code).toBe(AUTH_ERROR_CODES.VALIDATION)
    expect(contentTypeMismatch.status).toBe(AUTH_ERROR_STATUS[AUTH_ERROR_CODES.VALIDATION])
  })
})
