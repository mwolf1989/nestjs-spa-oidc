import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
  Inject,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { BaseDecodedAccessToken } from '../types/decoded-access-token.type';
import { OidcLogger, OidcSpaModuleOptions } from '../types/module-options.type';
import { OIDC_LOGGER, OIDC_SPA_MODULE_OPTIONS } from '../constants';

/**
 * Minimal request interface for platform-agnostic support
 */
interface RequestWithUser {
  user?: BaseDecodedAccessToken;
}

/**
 * Guard that checks if the authenticated user has the required roles.
 * This guard should be used after the AuthGuard to ensure the user is authenticated.
 * It reads the roles metadata set by the @Roles() decorator and checks if the user has any of those roles.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(OIDC_LOGGER) private readonly logger: OidcLogger,
    @Inject(OIDC_SPA_MODULE_OPTIONS)
    private readonly options: OidcSpaModuleOptions,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const handler = context.getHandler();
    const className = context.getClass().name;
    const handlerName = handler.name;

    // Get required roles from the @Roles() decorator
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // If no roles are required, allow access
    if (!requiredRoles || requiredRoles.length === 0) {
      this.logger.debug?.(
        `No roles required for ${className}.${handlerName}, allowing access`,
        RolesGuard.name,
      );
      return true;
    }

    this.logger.debug?.(
      `Checking roles for ${className}.${handlerName}, required: ${requiredRoles.join(', ')}`,
      RolesGuard.name,
    );

    const request = context.switchToHttp().getRequest<RequestWithUser>();
    const user = request.user;

    // If there's no user (shouldn't happen if AuthGuard is applied first), deny access
    if (!user) {
      this.logger.debug?.('User not authenticated', RolesGuard.name);
      throw new ForbiddenException('User not authenticated');
    }

    // Get user roles from the token using the configured function or default
    const userRoles = this.options.getRolesFromDecodedAccessToken
      ? this.options.getRolesFromDecodedAccessToken(user)
      : (user as any).realm_access?.roles || [];

    this.logger.debug?.(
      `User ${user.sub} has roles: ${userRoles.join(', ')}`,
      RolesGuard.name,
    );

    // Check if user has at least one of the required roles
    const hasRole = requiredRoles.some((role) => userRoles.includes(role));

    if (!hasRole) {
      this.logger.debug?.(
        `User ${user.sub} does not have required roles: ${requiredRoles.join(', ')}`,
        RolesGuard.name,
      );
      throw new ForbiddenException(
        `User does not have required role(s): ${requiredRoles.join(', ')}`,
      );
    }

    this.logger.debug?.(
      `User ${user.sub} has required role, allowing access`,
      RolesGuard.name,
    );

    return true;
  }
}

