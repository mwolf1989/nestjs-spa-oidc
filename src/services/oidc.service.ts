import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  OnModuleInit,
  UnauthorizedException,
} from '@nestjs/common';
import {
  extractRequestAuthContext,
  oidcSpa,
  type AnyRequest,
  type ValidateAndDecodeAccessToken,
} from 'oidc-spa/server';
import {
  BaseDecodedAccessToken,
  DefaultDecodedAccessTokenSchema,
} from '../types/decoded-access-token.type';
import { OidcSpaModuleOptions, OidcLogger } from '../types/module-options.type';
import { OIDC_SPA_MODULE_OPTIONS, OIDC_LOGGER } from '../constants';

/**
 * Service responsible for OIDC token validation using the oidc-spa/server library.
 * This service initializes the OIDC backend and provides methods to decode and validate access tokens.
 */
@Injectable()
export class OidcService<
  T extends BaseDecodedAccessToken = BaseDecodedAccessToken,
> implements OnModuleInit {
  private validateAndDecodeAccessTokenFn: ValidateAndDecodeAccessToken<T> | null = null;

  constructor(
    @Inject(OIDC_SPA_MODULE_OPTIONS)
    private readonly options: OidcSpaModuleOptions<T>,
    @Inject(OIDC_LOGGER)
    private readonly logger: OidcLogger,
  ) {}

  /**
   * Initialize the OIDC backend on module initialization.
   * This fetches the OIDC configuration and sets up the token verification.
   */
  async onModuleInit() {
    if (!this.options.issuerUri || !this.options.audience) {
      this.logger.warn(
        'OIDC configuration is missing. Authentication will not work properly.',
        OidcService.name,
      );
      this.logger.warn(
        'Please provide issuerUri and audience in module configuration.',
        OidcService.name,
      );
      return;
    }

    this.logger.debug?.(
      `Initializing OIDC backend with issuer: ${this.options.issuerUri}`,
      OidcService.name,
    );

    try {
      const { bootstrapAuth, validateAndDecodeAccessToken } = oidcSpa
        .withExpectedDecodedAccessTokenShape<T>({
          decodedAccessTokenSchema: (this.options.decodedAccessTokenSchema ||
            DefaultDecodedAccessTokenSchema) as any,
        })
        .createUtils();

      await bootstrapAuth({
        implementation: 'real',
        issuerUri: this.options.issuerUri,
        expectedAudience: this.options.audience,
      });

      this.validateAndDecodeAccessTokenFn = validateAndDecodeAccessToken;

      this.logger.log(
        `OIDC backend initialized successfully with issuer: ${this.options.issuerUri}`,
        OidcService.name,
      );
    } catch (error) {
      this.logger.error(
        `Failed to initialize OIDC backend: ${error instanceof Error ? error.message : String(error)}`,
        error instanceof Error ? error.stack : undefined,
        OidcService.name,
      );
      throw error;
    }
  }

  /**
   * Decode and validate an access token from an Express, Fastify, Fetch, Hono,
   * or unified request. Passing the complete request enables DPoP validation.
   *
   * @param request - Request representation supported by oidc-spa/server
   * @param requiredRole - Optional role that the user must have
   * @returns The decoded access token
   */
  async decodeRequest(request: AnyRequest, requiredRole?: string): Promise<T> {
    const requestAuthContext = extractRequestAuthContext({
      request,
      trustProxy: this.options.trustProxy ?? true,
    });

    if (!requestAuthContext) {
      this.logger.debug?.('No authorization header provided', OidcService.name);
      throw new UnauthorizedException('No authorization header provided');
    }

    if (!requestAuthContext.isWellFormed) {
      this.logger.debug?.(requestAuthContext.debugErrorMessage, OidcService.name);
      throw new BadRequestException('Malformed authentication request');
    }

    return this.validateAccessToken(requestAuthContext.accessTokenAndMetadata, requiredRole);
  }

  /**
   * Decode and validate a Bearer token from the Authorization header.
   * Prefer decodeRequest() when the full request is available so DPoP proofs
   * and request metadata can be validated.
   *
   * @param authorizationHeaderValue - The value of the Authorization header (e.g., "Bearer <token>")
   * @param requiredRole - Optional role that the user must have
   * @returns The decoded access token
   * @throws UnauthorizedException if the token is invalid, expired, or missing
   */
  async decodeAccessToken(
    authorizationHeaderValue: string | undefined,
    requiredRole?: string,
  ): Promise<T> {
    if (!authorizationHeaderValue) {
      this.logger.debug?.('No authorization header provided', OidcService.name);
      throw new UnauthorizedException('No authorization header provided');
    }

    const [scheme, accessToken, ...additionalParts] = authorizationHeaderValue.split(' ');

    if (scheme.toLowerCase() !== 'bearer' || !accessToken || additionalParts.length > 0) {
      this.logger.debug?.('Invalid authorization header scheme', OidcService.name);
      throw new UnauthorizedException('Invalid authorization header');
    }

    return this.validateAccessToken(
      {
        scheme: 'Bearer',
        accessToken,
        rejectIfAccessTokenDPoPBound: true,
      },
      requiredRole,
    );
  }

  private async validateAccessToken(
    accessTokenAndMetadata: Parameters<ValidateAndDecodeAccessToken<T>>[0],
    requiredRole?: string,
  ): Promise<T> {
    if (!this.validateAndDecodeAccessTokenFn) {
      throw new Error('OIDC service not initialized');
    }

    this.logger.debug?.(
      `Validating ${accessTokenAndMetadata.scheme} access token`,
      OidcService.name,
    );

    const result = await this.validateAndDecodeAccessTokenFn(accessTokenAndMetadata);

    if (!result.isSuccess) {
      this.logger.debug?.(`Token validation failed: ${result.debugErrorMessage}`, OidcService.name);
      throw new UnauthorizedException('Invalid or expired token');
    }

    const { decodedAccessToken } = result;

    this.logger.debug?.(
      `Token decoded successfully for user: ${decodedAccessToken.sub}`,
      OidcService.name,
    );

    if (requiredRole !== undefined) {
      const roles = this.getUserRoles(decodedAccessToken);
      this.logger.debug?.(
        `Checking required role: ${requiredRole}, user roles: ${roles.join(', ')}`,
        OidcService.name,
      );

      if (!roles.includes(requiredRole)) {
        this.logger.debug?.(`User does not have required role: ${requiredRole}`, OidcService.name);
        throw new ForbiddenException(`User does not have required role: ${requiredRole}`);
      }
    }

    return decodedAccessToken;
  }

  /**
   * Extract user ID from the decoded token.
   *
   * @param token - The decoded access token
   * @returns The user ID (sub claim)
   */
  getUserId(token: T): string {
    return token.sub;
  }

  /**
   * Extract user roles from the decoded token.
   * Uses the custom getRolesFromDecodedAccessToken function if provided, otherwise uses the default.
   *
   * @param token - The decoded access token
   * @returns Array of user roles
   */
  getUserRoles(token: T): string[] {
    if (this.options.getRolesFromDecodedAccessToken) {
      return this.options.getRolesFromDecodedAccessToken(token);
    }
    // Default implementation for tokens with realm_access
    return (token as any).realm_access?.roles || [];
  }

  /**
   * Check if the user has a specific role.
   *
   * @param token - The decoded access token
   * @param role - The role to check
   * @returns True if the user has the role
   */
  hasRole(token: T, role: string): boolean {
    return this.getUserRoles(token).includes(role);
  }
}
