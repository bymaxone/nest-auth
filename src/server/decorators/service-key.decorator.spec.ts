import { GUARDS_METADATA } from '@nestjs/common/constants'

import { ApiKeyGuard } from '../guards/api-key.guard'
import { API_KEY_SCOPES_KEY } from './api-key-scopes.decorator'
import { IS_PUBLIC_KEY } from './public.decorator'
import { ServiceKey } from './service-key.decorator'

describe('ServiceKey decorator', () => {
  class Controller {
    @ServiceKey('read', 'operate')
    handler(): void {}
  }

  // It declares the scopes the key must hold.
  it('declares the scopes', () => {
    expect(Reflect.getMetadata(API_KEY_SCOPES_KEY, Controller.prototype.handler)).toEqual([
      'read',
      'operate'
    ])
  })

  // It lets the route past the user JWT guards, which skip a route carrying the public marker.
  it('marks the route as skipping the user JWT guards', () => {
    expect(Reflect.getMetadata(IS_PUBLIC_KEY, Controller.prototype.handler)).toBe(true)
  })

  // It binds the key guard itself, so the JWT bypass can never be present without it.
  it('binds the key guard', () => {
    expect(Reflect.getMetadata(GUARDS_METADATA, Controller.prototype.handler)).toEqual([
      ApiKeyGuard
    ])
  })

  // It works at class level too, and then applies to every handler.
  it('applies to a class', () => {
    @ServiceKey('admin')
    class Whole {}
    expect(Reflect.getMetadata(API_KEY_SCOPES_KEY, Whole)).toEqual(['admin'])
    expect(Reflect.getMetadata(IS_PUBLIC_KEY, Whole)).toBe(true)
    expect(Reflect.getMetadata(GUARDS_METADATA, Whole)).toEqual([ApiKeyGuard])
  })
})
