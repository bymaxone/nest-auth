/**
 * Binds every port-only `listen` of the end-to-end suite to the IPv4 loopback address.
 *
 * Layer: e2e support, loaded through `setupFiles` in `jest.e2e.config.ts` and in
 * `jest.coverage.config.ts`.
 *
 * The reasoning, the patch and its limits are in `test/support/loopback-listen.ts`.
 */
import { installLoopbackListen } from './support/loopback-listen'

installLoopbackListen()
