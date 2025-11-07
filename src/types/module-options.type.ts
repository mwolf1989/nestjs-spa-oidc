import { ModuleMetadata, Type } from '@nestjs/common';
import { z } from 'zod';
import { BaseDecodedAccessToken } from './decoded-access-token.type';

/**
 * Logger interface that the module can use.
 * This allows consumers to provide their own logger implementation.
 */
export interface OidcLogger {
  log(message: string, context?: string): void;
  error(message: string, trace?: string, context?: string): void;
  warn(message: string, context?: string): void;
  debug?(message: string, context?: string): void;
}

/**
 * Configuration options for the OIDC SPA module.
 */
export interface OidcSpaModuleOptions<T extends BaseDecodedAccessToken = BaseDecodedAccessToken> {
  /**
   * The OIDC issuer URI (e.g., "https://auth.example.com/realms/myrealm")
   */
  issuerUri: string;

  /**
   * The expected audience for the access token
   */
  audience: string;

  /**
   * Zod schema for validating the decoded access token.
   * If not provided, the default schema will be used.
   */
  decodedAccessTokenSchema?: z.ZodType<T>;

  /**
   * Whether to apply the AuthGuard globally.
   * Default: true
   */
  globalGuard?: boolean;

  /**
   * Whether to apply the RolesGuard globally.
   * Default: true
   */
  globalRolesGuard?: boolean;

  /**
   * Custom logger instance.
   * If not provided, console will be used.
   */
  logger?: OidcLogger;

  /**
   * Function to extract roles from the decoded token.
   * Default: (token) => token.realm_access?.roles || []
   */
  getRolesFromToken?: (token: T) => string[];
}

/**
 * Factory for creating OIDC SPA module options.
 */
export interface OidcSpaModuleOptionsFactory<
  T extends BaseDecodedAccessToken = BaseDecodedAccessToken,
> {
  createOidcSpaModuleOptions(): Promise<OidcSpaModuleOptions<T>> | OidcSpaModuleOptions<T>;
}

/**
 * Async configuration options for the OIDC SPA module.
 */
export interface OidcSpaModuleAsyncOptions<
  T extends BaseDecodedAccessToken = BaseDecodedAccessToken,
> extends Pick<ModuleMetadata, 'imports'> {
  /**
   * Factory function to create the module options
   */
  useFactory?: (...args: any[]) => Promise<OidcSpaModuleOptions<T>> | OidcSpaModuleOptions<T>;

  /**
   * Dependencies to inject into the factory function
   */
  inject?: any[];

  /**
   * Use an existing options factory class
   */
  useExisting?: Type<OidcSpaModuleOptionsFactory<T>>;

  /**
   * Use a new instance of an options factory class
   */
  useClass?: Type<OidcSpaModuleOptionsFactory<T>>;
}

