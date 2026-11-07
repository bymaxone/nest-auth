/**
 * @fileoverview The metadata a route sets to say how strictly {@link RequestEncodingGuard} checks
 * the `Content-Encoding` of its request: the policy type, the key it is stored under, and the
 * `@RequestEncoding()` decorator that sets it.
 *
 * @layer Decorator
 */
import { SetMetadata } from '@nestjs/common'

/**
 * Metadata key {@link RequestEncodingGuard} reads to learn how strictly a route checks the
 * `Content-Encoding` of its request.
 *
 * A `Symbol`, like the library's other metadata keys, so a host's own metadata can never collide
 * with it.
 */
export const REQUEST_ENCODING_KEY = Symbol('bymax:requestEncoding')

/**
 * How a route treats a request whose `Content-Encoding` is not `identity`.
 *
 * - `'unchecked'`: never refused. The routes that take no JSON body to decode (refresh, logout,
 *   revoke-all, a ticket request) and that the shared contract leaves unchecked.
 * - `'when-body'`: refused only when the request carries a body. The MFA setup routes take an
 *   optional body, and an empty one takes the default.
 *
 * A route with no policy is strict: every non-`identity` encoding is refused, so a route added
 * later is checked unless someone says it should not be.
 */
export type RequestEncodingPolicy = 'unchecked' | 'when-body'

/**
 * Sets how strictly {@link RequestEncodingGuard} checks the route's `Content-Encoding`.
 *
 * @param policy - See {@link RequestEncodingPolicy}.
 * @returns A method decorator.
 *
 * @example
 * ```typescript
 * @RequestEncoding('unchecked')
 * @Post('refresh')
 * refresh() { ... }
 * ```
 */
export const RequestEncoding = (policy: RequestEncodingPolicy): MethodDecorator =>
  SetMetadata(REQUEST_ENCODING_KEY, policy)
