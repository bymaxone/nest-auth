/**
 * How long the session store must keep a bumped token epoch readable, in seconds (30 days).
 *
 * The epoch record is what makes an already-issued access token verifiable as stale. If it can
 * lapse while a pre-bump token is still inside its own `exp` window, the epoch lookup falls back
 * to `0`, the `token.epoch < stored` test stops firing, and a token revoked by a password reset
 * becomes valid again — a fail-open. Startup validation therefore rejects a `jwt.accessExpiresIn`
 * longer than this bound, which lets the store expire the record rather than retain it forever.
 *
 * rust-auth pins the identical value (`TOKEN_EPOCH_RETENTION_SECS`), so a shared Redis ages the
 * two backends' epoch keys the same way and neither can outlive the other's guarantee.
 */
export const TOKEN_EPOCH_RETENTION_SECONDS = 30 * 24 * 60 * 60
