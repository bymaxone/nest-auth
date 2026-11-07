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

import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import { BadRequestException, RequestMethod, type HttpException } from '@nestjs/common'
import type { ArgumentsHost, ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'

import { AUTH_ERROR_CODES, AUTH_ERROR_STATUS } from './errors/auth-error-codes'
import { AuthExceptionFilter } from './filters/auth-exception.filter'
import { REQUEST_ENCODING_KEY } from './decorators/request-encoding.decorator'
import type { RequestEncodingPolicy } from './decorators/request-encoding.decorator'
import { RequestEncodingGuard } from './guards/request-encoding.guard'

interface TransportErrorsContract {
  transportErrors: {
    envelope: { code: string; details: null }
    rows: { condition: string; status: number | string; message: string }[]
    contentTypeMismatch: { status: number; code: string; message: string }
  }
  requestEncoding: {
    methodsNeverChecked: string[]
    strict: string[]
    whenBody: string[]
    unchecked: string[]
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

  // Verifies each body-parser type listed here is named by exactly one contract row and answered
  // with that row's fixed message and status, or, for the row that takes its status from the
  // error, the status the parser reported. The list and the statuses body-parser gives the types
  // are written out here, not read from the filter, so a type added to the filter has to be added
  // here too; a listed type named by no row, or by two, fails.
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

  // Verifies a plain 400 from the body parser, which carries no `type` of its own, is answered as
  // the row that names that shape.
  it('answers an untyped parser 400 as the row that names it', () => {
    const row = rows.find((candidate) => candidate.condition.includes('no type of its own'))
    const untyped = Object.assign(new Error('incorrect header check'), {
      status: 400,
      statusCode: 400,
      expose: true
    })

    expect(answer(untyped)).toEqual({
      status: row?.status,
      body: { error: { code: envelope.code, message: row?.message, details: envelope.details } }
    })
  })

  // Verifies the library's own refusal of a compressed body is the row that names it: the status
  // and the envelope the guard throws are the ones the contract lists.
  it('refuses a compressed body as the row that names the Content-Encoding refusal', () => {
    const row = rows.find((candidate) =>
      candidate.condition.includes('Content-Encoding other than identity')
    )
    class Controller {
      handler(): void {}
    }
    const context = {
      getHandler: () => Controller.prototype.handler,
      switchToHttp: () => ({
        getRequest: () => ({ method: 'POST', headers: { 'content-encoding': 'gzip' } })
      })
    } as unknown as ExecutionContext

    let thrown: HttpException | undefined
    try {
      new RequestEncodingGuard(new Reflector()).canActivate(context)
    } catch (err) {
      thrown = err as HttpException
    }

    expect({ status: thrown?.getStatus(), body: thrown?.getResponse() }).toEqual({
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

describe('cross-implementation conformance: request encoding scope', () => {
  const { requestEncoding } = contract

  /** Every route a library controller declares, as `METHOD path` relative to the route prefix. */
  async function libraryRoutes(): Promise<{ label: string; method: string; policy?: string }[]> {
    const files = [
      ...readdirSync(join(__dirname, 'controllers'))
        .filter((file) => file.endsWith('.controller.ts'))
        .map((file) => join(__dirname, 'controllers', file)),
      join(__dirname, 'oauth/oauth.controller.ts')
    ]
    const routes: { label: string; method: string; policy?: string }[] = []
    for (const file of files) {
      const exported = (await import(file)) as Record<string, unknown>
      for (const controller of Object.values(exported)) {
        if (typeof controller !== 'function' || !Reflect.hasMetadata('path', controller)) continue
        const prefix = Reflect.getMetadata('path', controller) as string
        const proto = controller.prototype as Record<string, unknown>
        for (const name of Object.getOwnPropertyNames(proto)) {
          const handler = proto[name]
          if (typeof handler !== 'function' || !Reflect.hasMetadata('method', handler)) continue
          const method = RequestMethod[Reflect.getMetadata('method', handler) as number] as string
          const path = [prefix, Reflect.getMetadata('path', handler) as string]
            .join('/')
            .split('/')
            .filter((part) => part.length > 0 && part !== '/')
            .join('/')
          const policy = Reflect.getMetadata(REQUEST_ENCODING_KEY, handler) as
            RequestEncodingPolicy | undefined
          routes.push({ label: `${method} ${path}`, method, ...(policy ? { policy } : {}) })
        }
      }
    }
    return routes
  }

  // Verifies the scope the shared contract lists is the scope the controllers apply: every route
  // of a body-carrying method is strict, 'when-body' or 'unchecked' exactly as the contract says,
  // and the contract names no route that does not exist. A route added without a decision is
  // strict, and fails here until the contract lists it.
  it('applies to exactly the routes the contract lists, with the policy it lists', async () => {
    const routes = (await libraryRoutes()).filter(
      (route) => !requestEncoding.methodsNeverChecked.includes(route.method)
    )

    const labelsWith = (policy: string | undefined): string[] =>
      routes
        .filter((route) => route.policy === policy)
        .map((route) => route.label)
        .sort()

    expect(labelsWith(undefined)).toEqual([...requestEncoding.strict].sort())
    expect(labelsWith('when-body')).toEqual([...requestEncoding.whenBody].sort())
    expect(labelsWith('unchecked')).toEqual([...requestEncoding.unchecked].sort())
  })

  // Verifies the methods the contract never checks are the ones the guard skips.
  it('never checks the methods the contract lists', () => {
    expect([...requestEncoding.methodsNeverChecked].sort()).toEqual([
      'DELETE',
      'GET',
      'HEAD',
      'OPTIONS'
    ])
  })
})
