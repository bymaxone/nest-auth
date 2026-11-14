/**
 * Binds every port-only `listen` of the end-to-end suite to the IPv4 loopback address, and makes
 * supertest wait for a listener it starts itself.
 *
 * Layer: e2e support, loaded through `setupFiles` in `jest.e2e.config.ts` and in
 * `jest.coverage.config.ts`.
 *
 * The reasoning, the patches and their limits are in `test/support/loopback-listen.ts`.
 *
 * The coverage config runs the jsdom suites too, and loading supertest there fails before jsdom
 * has `TextEncoder`. A jsdom suite listens on nothing, so the patch is installed only where there
 * is no `window`.
 */
if (typeof window === 'undefined') {
  // A static import would load supertest in every environment, jsdom included.
  const { installLoopbackListen, installSupertestWait } =
    require('./support/loopback-listen') as typeof import('./support/loopback-listen')
  installLoopbackListen()
  installSupertestWait()
}
