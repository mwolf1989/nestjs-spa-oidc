import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  Inject,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { OidcService } from '../services/oidc.service';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { BaseDecodedAccessToken } from '../types/decoded-access-token.type';
import { OidcLogger } from '../types/module-options.type';
import { OIDC_LOGGER } from '../constants';

/**
 * Minimal request interface for platform-agnostic support
 */
interface RequestWithUser {
  headers: {
    authorization?: string;
  };
  user?: BaseDecodedAccessToken;
}

/**
 * Authentication guard that validates OIDC/JWT tokens.
 * This guard can be applied globally or to specific routes.
 * Routes marked with @Public() decorator will skip authentication.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly oidcService: OidcService,
    private readonly reflector: Reflector,
    @Inject(OIDC_LOGGER) private readonly logger: OidcLogger,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<RequestWithUser>();
    const handler = context.getHandler();
    const className = context.getClass().name;
    const handlerName = handler.name;

    this.logger.debug?.(
      `Checking authentication for ${className}.${handlerName}`,
      AuthGuard.name,
    );

    // Check if the route is marked as public
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      this.logger.debug?.(
        `Route ${className}.${handlerName} is public, skipping authentication`,
        AuthGuard.name,
      );
      return true;
    }

    const authorizationHeader = request.headers.authorization;

    if (!authorizationHeader) {
      this.logger.debug?.('No authorization header provided', AuthGuard.name);
      throw new UnauthorizedException('No authorization header provided');
    }

    this.logger.debug?.('Authorization header found, validating token', AuthGuard.name);

    try {
      // Decode and validate the access token
      const decodedToken = await this.oidcService.decodeAccessToken(authorizationHeader);

      this.logger.debug?.(
        `Token validated successfully for user: ${decodedToken.sub}`,
        AuthGuard.name,
      );

      // Attach the decoded token to the request object for use in controllers
      request.user = decodedToken as BaseDecodedAccessToken;

      return true;
    } catch (error) {
      this.logger.debug?.(
        `Token validation failed: ${(error as Error).message}`,
        AuthGuard.name,
      );
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('Invalid authentication token');
    }
  }
}

