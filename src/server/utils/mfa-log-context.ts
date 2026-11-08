/**
 * @fileoverview The logger context every MFA service logs under.
 *
 * @layer Utility
 */

/**
 * The context name on every log line the MFA flows emit.
 *
 * The flows are split across several classes, but an operator filters and alerts on the line's
 * context, so they all log as `MfaService`, the public entry point, and a line keeps its context
 * wherever the code that writes it lives. A literal rather than `MfaService.name` because the
 * classes that use it are imported by `MfaService`.
 */
export const MFA_LOG_CONTEXT = 'MfaService'
