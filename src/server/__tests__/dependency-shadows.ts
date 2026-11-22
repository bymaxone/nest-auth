/**
 * @fileoverview The options a spec expects a dependency to be called with: what the call sets, over the shadows every
 * call carries.
 *
 * @layer Test
 */

import { COOKIE_SHADOWS, JWT_VERIFY_SHADOWS } from '../utils/dependency-options'

/** The options of a cookie call that sets `chosen`. */
export const cookieOptions = (chosen: object): object => ({ ...COOKIE_SHADOWS, ...chosen })

/** The options of a verification that sets `chosen`. */
export const verifyOptions = (chosen: object): object => ({ ...JWT_VERIFY_SHADOWS, ...chosen })
