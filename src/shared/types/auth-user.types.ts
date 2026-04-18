/**
 * Client-safe representation of an authenticated user for @bymax-one/nest-auth.
 *
 * This is a deliberately narrow projection of the server-side `AuthUser`
 * interface. It contains only the fields a frontend application needs to
 * render UI, gate features, and personalize the experience. Credential
 * material (`passwordHash`), MFA secrets (`mfaSecret`, `mfaRecoveryCodes`),
 * and OAuth bookkeeping fields are intentionally omitted so that a
 * misconfigured server endpoint cannot accidentally leak them through this
 * type.
 *
 * @remarks
 * The shape is structurally compatible with `Pick<AuthUser, ...>` from the
 * server subpath. The shared subpath redeclares the type (instead of
 * re-exporting from `../../server`) to keep this entry point free of any
 * server-side runtime dependencies — it must remain importable in browser
 * and edge runtimes.
 */
export interface AuthUserClient {
  /** Unique internal identifier for the user (UUID or similar). */
  id: string

  /** User's primary email address. */
  email: string

  /** Display name of the user. */
  name: string

  /** Authorization role within the tenant (application-defined). */
  role: string

  /** Tenant identifier that scopes the user to a specific organization. */
  tenantId: string

  /** Account lifecycle status (e.g. `'active'`, `'suspended'`). */
  status: string

  /** Whether Time-based One-Time Password (TOTP) MFA is currently enabled. */
  mfaEnabled: boolean

  /**
   * URL of the user's avatar image, when available.
   * Optional because not every consumer application stores avatars.
   */
  avatarUrl?: string
}

/**
 * Client-safe representation of an authenticated platform administrator.
 *
 * Mirrors `AuthUserClient` but reflects the differences in the platform
 * domain: there is no `tenantId` (platform admins live above tenants) and an
 * optional `platformId` for multi-platform deployments.
 */
export interface AuthPlatformUserClient {
  /** Unique internal identifier for the platform administrator. */
  id: string

  /** Platform administrator's primary email address. */
  email: string

  /** Display name of the platform administrator. */
  name: string

  /** Authorization role within the platform layer (application-defined). */
  role: string

  /** Account lifecycle status (e.g. `'active'`, `'suspended'`). */
  status: string

  /** Whether Time-based One-Time Password (TOTP) MFA is currently enabled. */
  mfaEnabled: boolean

  /**
   * URL of the administrator's avatar image, when available.
   * Optional because not every consumer application stores avatars.
   */
  avatarUrl?: string

  /**
   * Logical platform identifier for multi-platform deployments.
   * Absent in single-platform configurations.
   */
  platformId?: string
}
