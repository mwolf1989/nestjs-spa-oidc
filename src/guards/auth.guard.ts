import {
  CanActivate,
  ExecutionContext,
  HttpException,
  Injectable,
  UnauthorizedException,
  Inject,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { AnyRequest } from 'oidc-spa/server';
import { OidcService } from '../services/oidc.service';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { BaseDecodedAccessToken } from '../types/decoded-access-token.type';
import { OidcLogger } from '../types/module-options.type';
import { OIDC_LOGGER } from '../constants';

/**
 * Minimal request interface for platform-agnostic support
 */
type RequestWithUser = AnyRequest & {
  user?: BaseDecodedAccessToken;
};

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

    this.logger.debug?.(`Checking authentication for ${className}.${handlerName}`, AuthGuard.name);

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

    this.logger.debug?.('Validating request authentication context', AuthGuard.name);

    try {
      const decodedToken = await this.oidcService.decodeRequest(request);

      this.logger.debug?.(
        `Token validated successfully for user: ${decodedToken.sub}`,
        AuthGuard.name,
      );

      // Attach the decoded token to the request object for use in controllers
      request.user = decodedToken as BaseDecodedAccessToken;

      return true;
    } catch (error) {
      this.logger.debug?.(`Token validation failed: ${(error as Error).message}`, AuthGuard.name);
      if (error instanceof HttpException) {
        throw error;
      }
      throw new UnauthorizedException('Invalid authentication token');
    }
  }
}
