/**
 * @fileoverview The registration switches of the controllers a deployment mounts.
 *
 * @layer Interface
 */

/**
 * Granular control over which controllers are registered.
 * Allows disabling endpoints that are not needed for a specific application.
 */
export interface ControllerFlags {
  /** Enables `AuthController` (register, login, logout, refresh, me). Default: `true` */
  auth?: boolean

  /**
   * Enables `MfaController`, `MfaService`, and `MfaRequiredGuard`.
   *
   * **Opt-in** — must be set to `true` explicitly **on the `registerAsync()` call**,
   * not inside `useFactory`. The factory is evaluated asynchronously after the module
   * is built; this field is the synchronous activation switch.
   *
   * When set to `true`, the `mfa` group (`encryptionKey`, `issuer`) **must** also be
   * present in the `useFactory` return value — omitting it causes a startup error.
   *
   * Default: `false`
   */
  mfa?: boolean

  /** Enables `PasswordResetController`. Default: `true` */
  passwordReset?: boolean

  /**
   * Enables `SessionController`. **Opt-in** — `Default: false`. Also requires
   * `sessions.enabled: true`; setting one without the other is a startup error.
   */
  sessions?: boolean

  /**
   * Enables `PlatformAuthController`. **Opt-in** — `Default: false`. Also requires
   * `platform.enabled: true`; setting one without the other is a startup error.
   */
  platform?: boolean

  /**
   * Enables `OAuthController` and `OAuthService`.
   *
   * **Opt-in** — requires the `oauth` group to be configured in the `useFactory` return
   * value. Omitting the `oauth` group causes a startup error when this flag is `true`.
   *
   * Default: `false`
   */
  oauth?: boolean

  /**
   * Enables `InvitationController`. **Opt-in** — `Default: false`. Also requires
   * `invitations.enabled: true`; setting one without the other is a startup error.
   */
  invitations?: boolean

  /**
   * Enables `EmailChangeController` and `EmailChangeService`. **Opt-in** — `Default: false`.
   *
   * Requires the configured `IEmailProvider` to implement
   * `sendEmailChangeVerification`: the flow cannot deliver its token without it, and the
   * module refuses to boot rather than mint tokens nobody receives.
   */
  emailChange?: boolean

  /**
   * Enables `WorkspaceController`: the workspace routes. **Opt-in** — `Default: false`.
   *
   * Requires `workspaces.enabled: true` and both workspace repository providers in
   * `extraProviders`; the module refuses to boot without them.
   */
  workspaces?: boolean

  /**
   * Enables `WorkspaceInvitationController`: invite, list, resend, revoke and preview.
   * **Opt-in** — `Default: false`.
   *
   * Requires `workspaces.enabled: true`, both workspace repository providers, and an email
   * provider that implements `sendWorkspaceInvitation`; the module refuses to boot without them.
   */
  workspaceInvitations?: boolean
}
