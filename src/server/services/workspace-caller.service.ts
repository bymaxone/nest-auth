/**
 * @fileoverview The signed-in caller of a workspace route: loading the account behind the token and
 * re-proving who is at the keyboard before a destructive change.
 *
 * @layer Service
 */

import { Inject, Injectable } from '@nestjs/common'

import { ReauthenticationService } from './reauthentication.service'
import { BYMAX_AUTH_USER_REPOSITORY } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import type {
  AuthUser,
  IUserRepository,
  SafeAuthUser
} from '../interfaces/user-repository.interface'
import { toSafeUser } from '../utils/mfa-safe-user'

/** Loads the account behind a verified dashboard token, and re-proves it before a destructive change. */
@Injectable()
export class WorkspaceCallerService {
  constructor(
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly users: IUserRepository,
    @Inject(ReauthenticationService) private readonly reauthentication: ReauthenticationService
  ) {}

  /**
   * Loads the account the token names, without its credentials.
   *
   * @param caller - The verified token's subject and tenant.
   * @returns The account.
   * @throws {AuthException} `auth.token_invalid` when the account no longer exists.
   */
  async load(caller: Pick<DashboardJwtPayload, 'sub' | 'tenantId'>): Promise<SafeAuthUser> {
    return toSafeUser(await this.find(caller))
  }

  /**
   * Re-proves the caller by their password, or by a recent sign-in when the account has none.
   *
   * Counted by the same lockout as a login, so a stolen token cannot guess the password here
   * without limit. Run it AFTER the checks that decide whether the caller may act at all: a caller
   * who may not must be refused before they can spend a key derivation or a lockout attempt.
   *
   * @param caller - The verified token's subject and tenant.
   * @param password - The password the caller submitted, if any.
   * @throws {AuthException} `auth.token_invalid` when the account no longer exists,
   *   `auth.invalid_credentials` for a missing or wrong password, `auth.account_locked` at the
   *   lockout ceiling, `auth.reauthentication_required` for a passwordless account with no recent
   *   sign-in.
   */
  async reauthenticate(
    caller: Pick<DashboardJwtPayload, 'sub' | 'tenantId'>,
    password: string | undefined
  ): Promise<void> {
    const user = await this.find(caller)
    await this.reauthentication.assertReauthenticated(
      'dashboard',
      user.id,
      user.passwordHash,
      password,
      caller.tenantId
    )
  }

  private async find(caller: Pick<DashboardJwtPayload, 'sub' | 'tenantId'>): Promise<AuthUser> {
    const user = await this.users.findById({ id: caller.sub, tenantId: caller.tenantId })
    if (user === null) throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    return user
  }
}
