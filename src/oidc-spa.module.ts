import {
  CanActivate,
  DynamicModule,
  ExecutionContext,
  Module,
  Provider,
  Type,
} from '@nestjs/common';
import { APP_GUARD, Reflector } from '@nestjs/core';
import {
  OidcSpaModuleOptions,
  OidcSpaModuleAsyncOptions,
  OidcSpaModuleOptionsFactory,
  OidcLogger,
} from './types/module-options.type';
import { BaseDecodedAccessToken } from './types/decoded-access-token.type';
import { OIDC_SPA_MODULE_OPTIONS, OIDC_LOGGER } from './constants';
import { OidcService } from './services/oidc.service';
import { AuthGuard } from './guards/auth.guard';
import { RolesGuard } from './guards/roles.guard';

/**
 * Default console logger implementation
 */
class ConsoleLogger implements OidcLogger {
  log(message: string, context?: string): void {
    console.log(`[${context || 'OidcSpa'}] ${message}`);
  }

  error(message: string, trace?: string, context?: string): void {
    console.error(`[${context || 'OidcSpa'}] ${message}`, trace || '');
  }

  warn(message: string, context?: string): void {
    console.warn(`[${context || 'OidcSpa'}] ${message}`);
  }

  debug(message: string, context?: string): void {
    // Only log debug messages if NODE_ENV is development
    if (process.env.NODE_ENV === 'development') {
      console.debug(`[${context || 'OidcSpa'}] ${message}`);
    }
  }
}

/**
 * No-op guard used when global guard registration is disabled via async options.
 */
class NoopGuard implements CanActivate {
  canActivate(_context: ExecutionContext): boolean {
    return true;
  }
}

/**
 * OIDC SPA Authentication Module for NestJS
 *
 * This module provides OIDC-based authentication for Single Page Applications.
 * It can be configured using forRoot() for synchronous configuration or
 * forRootAsync() for asynchronous configuration.
 *
 * @example
 * ```typescript
 * // Synchronous configuration
 * OidcSpaModule.forRoot({
 *   issuerUri: 'https://auth.example.com/realms/myrealm',
 *   audience: 'account',
 * })
 * ```
 *
 * @example
 * ```typescript
 * // Asynchronous configuration with ConfigService
 * OidcSpaModule.forRootAsync({
 *   imports: [ConfigModule],
 *   useFactory: (configService: ConfigService) => ({
 *     issuerUri: configService.get('OIDC_ISSUER_URI'),
 *     audience: configService.get('OIDC_AUDIENCE'),
 *   }),
 *   inject: [ConfigService],
 * })
 * ```
 */
@Module({})
export class OidcSpaModule {
  /**
   * Configure the module with synchronous options
   */
  static forRoot<T extends BaseDecodedAccessToken = BaseDecodedAccessToken>(
    options: OidcSpaModuleOptions<T>,
  ): DynamicModule {
    const providers: Provider[] = [
      {
        provide: OIDC_SPA_MODULE_OPTIONS,
        useValue: options,
      },
      {
        provide: OIDC_LOGGER,
        useValue: options.logger || new ConsoleLogger(),
      },
      OidcService,
    ];

    // Add global guards if enabled (default: true)
    if (options.globalGuard !== false) {
      providers.push({
        provide: APP_GUARD,
        useClass: AuthGuard,
      });
    }

    if (options.globalRolesGuard !== false) {
      providers.push({
        provide: APP_GUARD,
        useClass: RolesGuard,
      });
    }

    return {
      module: OidcSpaModule,
      providers,
      exports: [OidcService, OIDC_SPA_MODULE_OPTIONS, OIDC_LOGGER],
    };
  }

  /**
   * Configure the module with asynchronous options
   */
  static forRootAsync<T extends BaseDecodedAccessToken = BaseDecodedAccessToken>(
    options: OidcSpaModuleAsyncOptions<T>,
  ): DynamicModule {
    const providers: Provider[] = [
      ...this.createAsyncProviders(options),
      OidcService,
      {
        provide: APP_GUARD,
        useFactory: (
          moduleOptions: OidcSpaModuleOptions<T>,
          oidcService: OidcService,
          reflector: Reflector,
          logger: OidcLogger,
        ) =>
          moduleOptions.globalGuard === false
            ? new NoopGuard()
            : new AuthGuard(oidcService, reflector, logger),
        inject: [OIDC_SPA_MODULE_OPTIONS, OidcService, Reflector, OIDC_LOGGER],
      },
      {
        provide: APP_GUARD,
        useFactory: (
          moduleOptions: OidcSpaModuleOptions<T>,
          reflector: Reflector,
          logger: OidcLogger,
        ) =>
          moduleOptions.globalRolesGuard === false
            ? new NoopGuard()
            : new RolesGuard<T>(reflector, logger, moduleOptions),
        inject: [OIDC_SPA_MODULE_OPTIONS, Reflector, OIDC_LOGGER],
      },
    ];

    return {
      module: OidcSpaModule,
      imports: options.imports || [],
      providers,
      exports: [OidcService, OIDC_SPA_MODULE_OPTIONS, OIDC_LOGGER],
    };
  }

  /**
   * Create async providers for the module options
   */
  private static createAsyncProviders<T extends BaseDecodedAccessToken = BaseDecodedAccessToken>(
    options: OidcSpaModuleAsyncOptions<T>,
  ): Provider[] {
    if (options.useFactory) {
      return [
        {
          provide: OIDC_SPA_MODULE_OPTIONS,
          useFactory: options.useFactory,
          inject: options.inject || [],
        },
        {
          provide: OIDC_LOGGER,
          useFactory: async (...args: any[]) => {
            const moduleOptions = await options.useFactory!(...args);
            return moduleOptions.logger || new ConsoleLogger();
          },
          inject: options.inject || [],
        },
      ];
    }

    const inject = [
      (options.useClass || options.useExisting) as Type<OidcSpaModuleOptionsFactory<T>>,
    ];

    return [
      {
        provide: OIDC_SPA_MODULE_OPTIONS,
        useFactory: async (optionsFactory: OidcSpaModuleOptionsFactory<T>) =>
          await optionsFactory.createOidcSpaModuleOptions(),
        inject,
      },
      {
        provide: OIDC_LOGGER,
        useFactory: async (optionsFactory: OidcSpaModuleOptionsFactory<T>) => {
          const moduleOptions = await optionsFactory.createOidcSpaModuleOptions();
          return moduleOptions.logger || new ConsoleLogger();
        },
        inject,
      },
      ...(options.useClass
        ? [
            {
              provide: options.useClass,
              useClass: options.useClass,
            },
          ]
        : []),
    ];
  }
}
