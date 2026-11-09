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
 *
 * One script is an optimisation: the wire contract requires the ORDER (workspace version,
 * membership version, entry, repositories), not the atomicity. The entry key is built inside the
 * script from the two values just read, so it is not a declared key; the script therefore needs a
 * standalone Redis or Sentinel, like every other multi-key script in this library.
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

/**
 * Writes a cache entry, only while both version counters still hold the values the reader saw, and
 * extends the retention of every counter that exists, in a single step.
 *
 * `KEYS[1]` is the workspace version, `KEYS[2]` the membership version and `KEYS[3]` the entry's
 * full key; `ARGV[1]` is the entry, `ARGV[2]` its lifetime, `ARGV[3]` the counters' retention in
 * seconds, and `ARGV[4]` and `ARGV[5]` the workspace and membership versions the reader saw. An
 * absent counter counts as `'0'`, as it does on a read. Returns `1` when the entry was written and
 * `0` when a counter had moved.
 *
 * A counter value must never be reused while an entry bearing it can live. A counter that expires
 * restarts at 1 on its next bump, so an entry written under the old value would be current again.
 * Extending the retention covers a counter that is alive; the comparison covers one that expired
 * between the read and this write, which reads as `'0'` here and no longer matches. An entry written
 * after a bump was never readable, so skipping it also saves the write.
 */
export const FILL_MEMBERSHIP_SCRIPT = `
local workspaceVersion = redis.call('GET', KEYS[1])
if not workspaceVersion then workspaceVersion = '0' end
local membershipVersion = redis.call('GET', KEYS[2])
if not membershipVersion then membershipVersion = '0' end
if workspaceVersion ~= ARGV[4] or membershipVersion ~= ARGV[5] then return 0 end
if redis.call('EXISTS', KEYS[1]) == 1 then redis.call('EXPIRE', KEYS[1], ARGV[3]) end
if redis.call('EXISTS', KEYS[2]) == 1 then redis.call('EXPIRE', KEYS[2], ARGV[3]) end
redis.call('SET', KEYS[3], ARGV[1], 'EX', ARGV[2])
return 1
`
