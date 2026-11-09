/**
 * @fileoverview The Lua scripts behind the workspace-membership cache.
 *
 * @layer Constants
 */

/**
 * Reads both version counters and the cache entry they name, in one round trip.
 *
 * `KEYS[1]` is the workspace version, `KEYS[2]` the membership version and `KEYS[3]` the
 * entry's key base. A counter that does not exist reads as `'0'`. Returns
 * `{ workspaceVersion, membershipVersion, entry }`, with `entry` the empty string on a miss, since
 * a Lua `false` inside a table would truncate the reply.
 *
 * The versions are returned so the caller can write a refill under THEM: they were read before the
 * repository, so a change that lands afterwards moves a counter and the refill is written under a
 * key nobody reads.
 */
export const READ_MEMBERSHIP_SCRIPT = `
local workspaceVersion = redis.call('GET', KEYS[1])
if not workspaceVersion then workspaceVersion = '0' end
local membershipVersion = redis.call('GET', KEYS[2])
if not membershipVersion then membershipVersion = '0' end
local entry = redis.call('GET', KEYS[3] .. ':' .. workspaceVersion .. ':' .. membershipVersion)
if not entry then entry = '' end
return { workspaceVersion, membershipVersion, entry }
`

/**
 * Bumps one version counter and refreshes its retention in a single step, so a counter never
 * outlives its retention window and never loses it either.
 *
 * `KEYS[1]` is the counter and `ARGV[1]` the retention in seconds.
 */
export const BUMP_VERSION_SCRIPT = `
local version = redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[1])
return version
`
