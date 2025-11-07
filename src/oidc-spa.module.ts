import { DynamicModule, Module, Provider, Type } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
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
    ];

    // We need to determine if guards should be global after options are resolved
    // For async config, we'll add them conditionally in a factory
    providers.push({
      provide: 'OIDC_GUARDS_SETUP',
      useFactory: (moduleOptions: OidcSpaModuleOptions<T>) => {
        // This is just a marker to ensure guards are set up
        // The actual guards are added below
        return moduleOptions;
      },
      inject: [OIDC_SPA_MODULE_OPTIONS],
    });

    // Add guards - they will check the options internally
    // For async config, we always add them but they can be disabled via options
    providers.push(
      {
        provide: APP_GUARD,
        useClass: AuthGuard,
      },
      {
        provide: APP_GUARD,
        useClass: RolesGuard,
      },
    );

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

