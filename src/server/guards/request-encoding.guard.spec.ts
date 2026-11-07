/**
 * @fileoverview Tests for RequestEncodingGuard — the refusal of a compressed request body that
 * holds the shared contract whatever the host's body parser does.
 */

import { readdirSync } from 'node:fs'
import { join } from 'node:path'

import { HttpException, HttpStatus } from '@nestjs/common'
import type { ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'

import { REQUEST_ENCODING_KEY } from '../decorators/request-encoding.decorator'
import type { RequestEncodingPolicy } from '../decorators/request-encoding.decorator'
import { RequestEncodingGuard } from './request-encoding.guard'

/** What the guard sees of a request. */
interface FakeRequest {
  method?: string
  headers: Record<string, string>
}

/** An execution context whose request is `request` and whose handler carries `policy`. */
function contextWith(request: FakeRequest, policy?: RequestEncodingPolicy): ExecutionContext {
  class Controller {
    handler(): void {}
  }
  if (policy !== undefined) {
    Reflect.defineMetadata(REQUEST_ENCODING_KEY, policy, Controller.prototype.handler)
  }
  return {
    getHandler: () => Controller.prototype.handler,
    switchToHttp: () => ({ getRequest: () => ({ method: 'POST', ...request }) })
  } as unknown as ExecutionContext
}

function guard(): RequestEncodingGuard {
  return new RequestEncodingGuard(new Reflector())
}

/** Runs the guard and returns what it threw, or `undefined` when it let the request through. */
function refusal(request: FakeRequest, policy?: RequestEncodingPolicy): HttpException | undefined {
  try {
    guard().canActivate(contextWith(request, policy))
  } catch (err) {
    return err as HttpException
  }
  return undefined
}

describe('RequestEncodingGuard', () => {
  // A request that declares no encoding, or only `identity`, is the working path and must pass in
  // every spelling a client can send.
  it.each([
    ['no header', {}],
    ['identity', { 'content-encoding': 'identity' }],
    ['IDENTITY', { 'content-encoding': 'IDENTITY' }],
    ['a list of identity', { 'content-encoding': 'identity, identity' }],
    ['an empty header', { 'content-encoding': '' }],
    ['only separators', { 'content-encoding': ' , ' }]
  ])('lets a request with %s through', (_name, headers) => {
    expect(guard().canActivate(contextWith({ headers }))).toBe(true)
  })

  // Any other encoding is refused on a strict route (one with no policy), with the contract's
  // status and the library's envelope, in any case and anywhere in a list. The envelope is the
  // body of the exception itself, which is how the optional filter and Nest's default
  // serialisation render the same answer.
  it.each([
    ['gzip', 'gzip'],
    ['deflate', 'deflate'],
    ['br', 'br'],
    ['zstd', 'zstd'],
    ['an unknown name', 'x-unknown'],
    ['upper case', 'GZIP'],
    ['padding around the name', '  gzip  '],
    ['a list that ends in an encoding', 'identity, gzip'],
    ['a list that starts with one', 'gzip, identity']
  ])('refuses %s with 415 in the auth.validation envelope', (_name, value) => {
    const thrown = refusal({ headers: { 'content-encoding': value } })

    expect(thrown).toBeInstanceOf(HttpException)
    expect(thrown?.getStatus()).toBe(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
    expect(thrown?.getResponse()).toEqual({
      error: { code: 'auth.validation', message: 'Unsupported media type', details: null }
    })
  })

  // A route that opted out is never refused, whatever the header says.
  it('lets an unchecked route through with a compressed body', () => {
    expect(refusal({ headers: { 'content-encoding': 'gzip' } }, 'unchecked')).toBeUndefined()
  })

  // The when-body policy: refused with a body, in either of the two ways a body is declared, and
  // let through without one.
  it.each([
    ['a Content-Length', { 'content-length': '42' }],
    ['a chunked transfer', { 'transfer-encoding': 'chunked' }]
  ])('refuses a when-body route that carries %s', (_name, extra) => {
    const thrown = refusal({ headers: { 'content-encoding': 'gzip', ...extra } }, 'when-body')

    expect(thrown?.getStatus()).toBe(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
  })

  it.each([
    ['no length header', {}],
    ['a zero Content-Length', { 'content-length': '0' }]
  ])('lets a when-body route through with %s', (_name, extra) => {
    expect(
      refusal({ headers: { 'content-encoding': 'gzip', ...extra } }, 'when-body')
    ).toBeUndefined()
  })

  // A path-only or query-only request has no body to decode; none of these methods is checked.
  it.each(['GET', 'HEAD', 'OPTIONS', 'DELETE'])('never checks a %s request', (method) => {
    expect(refusal({ method, headers: { 'content-encoding': 'gzip' } })).toBeUndefined()
  })

  // The body methods are checked.
  it.each(['POST', 'PUT', 'PATCH'])('checks a %s request', (method) => {
    expect(refusal({ method, headers: { 'content-encoding': 'gzip' } })).toBeInstanceOf(
      HttpException
    )
  })
})

describe('library controllers', () => {
  const controllerFiles = [
    ...readdirSync(join(__dirname, '../controllers'))
      .filter((file) => file.endsWith('.controller.ts'))
      .map((file) => join(__dirname, '../controllers', file)),
    join(__dirname, '../oauth/oauth.controller.ts')
  ]

  // The refusal only holds if every controller applies it, and a controller added later would not
  // unless something says so. Each file in the controllers directory, and the OAuth controller,
  // must apply the guard at class level, and there must be files to check.
  it('apply RequestEncodingGuard to every controller class', async () => {
    expect(controllerFiles.length).toBeGreaterThan(8)

    for (const file of controllerFiles) {
      const exported = (await import(file)) as Record<string, unknown>
      const controllers = Object.values(exported).filter(
        (value): value is new () => unknown =>
          typeof value === 'function' && Reflect.hasMetadata('path', value)
      )
      expect(controllers.length).toBeGreaterThan(0)
      for (const controller of controllers) {
        const guards = (Reflect.getMetadata('__guards__', controller) ?? []) as unknown[]
        expect({
          file,
          controller: controller.name,
          applied: guards.includes(RequestEncodingGuard)
        }).toEqual({
          file,
          controller: controller.name,
          applied: true
        })
      }
    }
  })
})
