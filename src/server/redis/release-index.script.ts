/**
 * @fileoverview The Lua that drops an invitee index on behalf of whoever read it.
 *
 * @layer Redis
 */

/** Deletes the index in `KEYS[1]` only while it still holds `ARGV[1]`, the value the caller read. */
export const RELEASE_INDEX_SCRIPT = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0`
