/**
 * Fills the `:placeholders` of a route of `AUTH_ROUTES` with values a caller supplies.
 *
 * Every place a caller-supplied value becomes part of a request path goes through here: a value that
 * is put into a path by hand can leave its segment, and the library's own route constants carry
 * placeholders (`sessions/:id`, `oauth/:provider`, the workspace routes) that a consumer fills too.
 */

/**
 * Percent-encodes one value for use as a single path segment.
 *
 * @param name - What the value is, for the message.
 * @param value - The value.
 * @returns The encoded segment.
 * @throws {TypeError} For a value that is not a string, is empty, or is `.` or `..`. A URL parser
 *   collapses a dot segment even when it is percent-encoded, so encoding cannot keep it inside the
 *   segment, and an empty one would address another route (`workspaces//access`).
 */
export function pathSegment(name: string, value: unknown): string {
  if (typeof value !== 'string' || value === '') {
    throw new TypeError(`${name} must be a non-empty string`)
  }
  if (value === '.' || value === '..') throw new TypeError(`${name} must not be '.' or '..'`)
  return encodeURIComponent(value)
}

/**
 * Fills the placeholders of a route template with percent-encoded, single-segment values.
 *
 * @param template - A route such as `workspaces/:workspaceId/members/:userId`.
 * @param values - What each placeholder stands for.
 * @returns The path.
 * @throws {TypeError} When a placeholder has no value, or its value fails {@link pathSegment}.
 */
export function fillRoute(template: string, values: Readonly<Record<string, string>>): string {
  return template.replace(/:([A-Za-z]+)/g, (_match, name: string) =>
    pathSegment(name, Object.entries(values).find(([key]) => key === name)?.[1])
  )
}
