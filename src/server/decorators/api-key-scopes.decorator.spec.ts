import { API_KEY_SCOPES_KEY, ApiKeyScopes } from './api-key-scopes.decorator'

describe('ApiKeyScopes decorator', () => {
  // The declared scopes are stored on the handler, in the order given.
  it('stores the scopes on a method', () => {
    class Controller {
      @ApiKeyScopes('read', 'operate')
      handler(): void {}
    }
    expect(Reflect.getMetadata(API_KEY_SCOPES_KEY, Controller.prototype.handler)).toEqual([
      'read',
      'operate'
    ])
  })

  // The same decorator declares a class-wide default.
  it('stores the scopes on a class', () => {
    @ApiKeyScopes('admin')
    class Controller {}
    expect(Reflect.getMetadata(API_KEY_SCOPES_KEY, Controller)).toEqual(['admin'])
  })

  // A Symbol, not a conventional string, so a host's own metadata can never collide with it and
  // quietly declare scopes.
  it('keys its metadata with a unique symbol', () => {
    expect(typeof API_KEY_SCOPES_KEY).toBe('symbol')
    expect(Symbol.keyFor(API_KEY_SCOPES_KEY)).toBeUndefined()
    expect(API_KEY_SCOPES_KEY.description).toBe('bymax:apiKeyScopes')
  })
})
