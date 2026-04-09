import { strict as assert } from 'node:assert';
import test from 'node:test';
import { APP_GUARD, Reflector } from '@nestjs/core';
import { AuthGuard } from '../src/guards/auth.guard';
import { RolesGuard } from '../src/guards/roles.guard';
import { OidcSpaModule } from '../src/oidc-spa.module';
import type { OidcService } from '../src/services/oidc.service';
import type { OidcLogger, OidcSpaModuleOptions } from '../src/types/module-options.type';

type AppGuardProvider = {
  provide: unknown;
  useFactory?: (...args: any[]) => any;
  inject?: unknown[];
};

function getAppGuardProviders(): AppGuardProvider[] {
  const dynamicModule = OidcSpaModule.forRootAsync({
    useFactory: async () => ({
      issuerUri: 'https://auth.example.com/realms/test',
      audience: 'account',
    }),
  });

  return (dynamicModule.providers ?? []).filter((provider): provider is AppGuardProvider => {
    if (typeof provider !== 'object' || provider === null) {
      return false;
    }

    return 'provide' in provider && provider.provide === APP_GUARD;
  });
}

function getGuardFactories() {
  const appGuardProviders = getAppGuardProviders();

  const authGuardProvider = appGuardProviders.find((provider) => provider.inject?.length === 4);
  const rolesGuardProvider = appGuardProviders.find((provider) => provider.inject?.length === 3);

  assert.ok(authGuardProvider?.useFactory, 'AuthGuard APP_GUARD provider factory must exist');
  assert.ok(rolesGuardProvider?.useFactory, 'RolesGuard APP_GUARD provider factory must exist');

  return {
    authFactory: authGuardProvider.useFactory,
    rolesFactory: rolesGuardProvider.useFactory,
  };
}

function createLoggerMock(): OidcLogger {
  return {
    log: () => undefined,
    error: () => undefined,
    warn: () => undefined,
    debug: () => undefined,
  };
}

test('forRootAsync: global guard opt-outs produce no-op guards', () => {
  const { authFactory, rolesFactory } = getGuardFactories();

  const options: OidcSpaModuleOptions = {
    issuerUri: 'https://auth.example.com/realms/test',
    audience: 'account',
    globalGuard: false,
    globalRolesGuard: false,
  };

  const authGuard = authFactory(options, {} as OidcService, new Reflector(), createLoggerMock());
  const rolesGuard = rolesFactory(options, new Reflector(), createLoggerMock());

  assert.equal(authGuard.constructor.name, 'NoopGuard');
  assert.equal(rolesGuard.constructor.name, 'NoopGuard');
  assert.equal(authGuard.canActivate({} as any), true);
  assert.equal(rolesGuard.canActivate({} as any), true);
});

test('forRootAsync: guards are real when opt-outs are not disabled', () => {
  const { authFactory, rolesFactory } = getGuardFactories();

  const options: OidcSpaModuleOptions = {
    issuerUri: 'https://auth.example.com/realms/test',
    audience: 'account',
  };

  const authGuard = authFactory(options, {} as OidcService, new Reflector(), createLoggerMock());
  const rolesGuard = rolesFactory(options, new Reflector(), createLoggerMock());

  assert.ok(authGuard instanceof AuthGuard);
  assert.ok(rolesGuard instanceof RolesGuard);
});
