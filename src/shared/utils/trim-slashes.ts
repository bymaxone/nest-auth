/**
 * Strips `/` characters from the ends of a string without a regular expression.
 *
 * The one implementation for every place that normalizes a base URL or a route prefix, so the same
 * configuration resolves to the same path on the client, in the Next.js reader and in the shared
 * route helpers.
 */

/**
 * Strip trailing, and optionally leading, `/` characters without a regular expression.
 *
 * The obvious `replace(/^\/+|\/+$/g, '')` is quadratic on a run of slashes: the `$`-anchored
 * alternative backtracks over every prefix of the run, which CodeQL flags as a polynomial ReDoS. A
 * pair of scans is linear and says what it does.
 *
 * @param value - The string to trim.
 * @param leading - Whether to trim the leading run too. Default `true`. A base URL keeps its
 *   leading slash because a root-relative base (`/api`) is a legitimate value.
 * @returns `value` with the requested runs of `/` removed.
 */
export function trimSlashes(value: string, leading = true): string {
  let start = 0
  let end = value.length
  // Stryker disable ConditionalExpression,EqualityOperator
  // Both bounds are equivalent to `true` here, and both comparisons are equivalent one step
  // looser: the character test is what actually stops each loop, because an index past either
  // end reads `undefined`, which is never `'/'`. Verified by running all four mutants against
  // '', '/', '//', '///', '/a/', 'a', '/api/' and '////a////' in both `leading` modes: every one
  // returns what the guarded form returns. The bounds stay because a loop whose only terminator
  // is an out-of-range read is a worse thing to leave for the next reader.
  if (leading) {
    while (start < end && value[start] === '/') start += 1
  }
  while (end > start && value[end - 1] === '/') end -= 1
  // Stryker restore ConditionalExpression,EqualityOperator
  return value.slice(start, end)
}
