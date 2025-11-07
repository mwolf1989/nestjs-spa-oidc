/**
 * Public API for the OIDC SPA NestJS module.
 * Export all decorators, guards, services, types, and the module itself.
 */

// Module
export { OidcSpaModule } from './oidc-spa.module';

// Decorators
export { Public } from './decorators/public.decorator';
export { User } from './decorators/user.decorator';
export { Roles } from './decorators/roles.decorator';

// Guards
export { AuthGuard } from './guards/auth.guard';
export { RolesGuard } from './guards/roles.guard';

// Services
export { OidcService } from './services/oidc.service';

// Types
export type {
  BaseDecodedAccessToken,
  DefaultDecodedAccessToken,
} from './types/decoded-access-token.type';
export { DefaultDecodedAccessTokenSchema } from './types/decoded-access-token.type';

export type {
  OidcSpaModuleOptions,
  OidcSpaModuleAsyncOptions,
  OidcSpaModuleOptionsFactory,
  OidcLogger,
} from './types/module-options.type';

// Constants
export { OIDC_SPA_MODULE_OPTIONS, OIDC_LOGGER } from './constants';

