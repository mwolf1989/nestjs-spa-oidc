import { Injectable, UnauthorizedException, OnModuleInit, Inject } from '@nestjs/common';
import { createOidcBackend } from 'oidc-spa/backend';
import type { ResultOfAccessTokenVerify } from 'oidc-spa/backend';
import { BaseDecodedAccessToken, DefaultDecodedAccessTokenSchema } from '../types/decoded-access-token.type';
import { OidcSpaModuleOptions, OidcLogger } from '../types/module-options.type';
import { OIDC_SPA_MODULE_OPTIONS, OIDC_LOGGER } from '../constants';

/**
 * Service responsible for OIDC token validation using the oidc-spa/backend library.
 * This service initializes the OIDC backend and provides methods to decode and validate access tokens.
 */
@Injectable()
export class OidcService<T extends BaseDecodedAccessToken = BaseDecodedAccessToken>
  implements OnModuleInit
{
  private decodeAccessTokenFn:
    | ((params: {
        authorizationHeaderValue: string | undefined;
        requiredRole?: string;
      }) => Promise<T>)
    | null = null;

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
      const oidcBackend = await createOidcBackend({
        issuerUri: this.options.issuerUri,
        decodedAccessTokenSchema: (this.options.decodedAccessTokenSchema || DefaultDecodedAccessTokenSchema) as any,
      });

      const verifyAndDecodeAccessToken = oidcBackend.verifyAndDecodeAccessToken.bind(
        oidcBackend,
      ) as (params: { accessToken: string }) => Promise<ResultOfAccessTokenVerify<T>>;

      this.decodeAccessTokenFn = async (params: {
        authorizationHeaderValue: string | undefined;
        requiredRole?: string;
      }): Promise<T> => {
        const { authorizationHeaderValue, requiredRole } = params;

        this.logger.debug?.('Decoding access token', OidcService.name);

        if (!authorizationHeaderValue) {
          this.logger.debug?.('No authorization header provided', OidcService.name);
          throw new UnauthorizedException('No authorization header provided');
        }

        // Extract the token from "Bearer <token>"
        const accessToken = authorizationHeaderValue.replace(/^Bearer /, '');

        this.logger.debug?.('Verifying token signature and expiration', OidcService.name);

        const result: ResultOfAccessTokenVerify<T> = await verifyAndDecodeAccessToken({
          accessToken,
        });

        if (!result.isValid) {
          this.logger.debug?.(
            `Token validation failed: ${result.errorCase}`,
            OidcService.name,
          );

          switch (result.errorCase) {
            case 'does not respect schema':
              throw new Error(
                `The access token does not respect the schema: ${result.errorMessage}`,
              );
            case 'invalid signature':
            case 'expired':
              throw new UnauthorizedException('Invalid or expired token');
          }
        }

        const { decodedAccessToken } = result;

        this.logger.debug?.(
          `Token decoded successfully for user: ${decodedAccessToken.sub}`,
          OidcService.name,
        );

        // Check required role if specified
        if (requiredRole !== undefined) {
          const roles = this.getUserRoles(decodedAccessToken);
          this.logger.debug?.(
            `Checking required role: ${requiredRole}, user roles: ${roles.join(', ')}`,
            OidcService.name,
          );

          if (!roles.includes(requiredRole)) {
            this.logger.debug?.(
              `User does not have required role: ${requiredRole}`,
              OidcService.name,
            );
            throw new UnauthorizedException(`User does not have required role: ${requiredRole}`);
          }
        }

        // Validate audience
        const { aud } = decodedAccessToken;
        const audArray = typeof aud === 'string' ? [aud] : aud;

        this.logger.debug?.(
          `Validating token audience: ${audArray.join(', ')} against expected: ${this.options.audience}`,
          OidcService.name,
        );

        if (!audArray.includes(this.options.audience)) {
          this.logger.debug?.('Invalid token audience', OidcService.name);
          throw new UnauthorizedException('Invalid token audience');
        }

        return decodedAccessToken;
      };

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
   * Decode and validate an access token from the Authorization header.
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
    if (!this.decodeAccessTokenFn) {
      throw new Error('OIDC service not initialized');
    }

    return this.decodeAccessTokenFn({
      authorizationHeaderValue,
      requiredRole,
    });
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
   * Uses the custom getRolesFromToken function if provided, otherwise uses the default.
   *
   * @param token - The decoded access token
   * @returns Array of user roles
   */
  getUserRoles(token: T): string[] {
    if (this.options.getRolesFromToken) {
      return this.options.getRolesFromToken(token);
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

