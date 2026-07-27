/**
 * Test stub for the `server-only` marker package.
 *
 * The real package's default export throws on import outside a React Server Component, which is
 * exactly what makes it a useful build-time guard — and exactly what breaks a Jest run, where no
 * `react-server` condition is set. rust-auth's Next.js package aliases it the same way under
 * vitest. Empty on purpose: the guard is a build concern, and the module under test has nothing
 * to say to it at runtime.
 */
export {}
