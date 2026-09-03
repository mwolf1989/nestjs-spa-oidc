import 'reflect-metadata';

import assert from 'node:assert/strict';
import test from 'node:test';
import { ExecutionContext, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  AuthGuard,
  OidcService,
  OidcSpaModule,
  Public,
  Roles,
  RolesGuard,
  type BaseDecodedAccessToken,
  type OidcLogger,
} from '../src';

const logger: OidcLogger = {
  log: () => undefined,
  error: () => undefined,
  warn: () => undefined,
};

function createExecutionContext(
  request: Record<string, unknown>,
  handler: () => void = () => undefined,
): ExecutionContext {
  class TestController {}

  return {
    getHandler: () => handler,
    getClass: () => TestController,
    switchToHttp: () => ({
      getRequest: () => request,
    }),
  } as unknown as ExecutionContext;
}

test('exports a Nest dynamic module with the configured providers', () => {
  const module = OidcSpaModule.forRoot({
    issuerUri: 'https://issuer.example.test',
    audience: 'api',
    globalGuard: false,
    globalRolesGuard: false,
  });

  assert.equal(module.module, OidcSpaModule);
  assert.equal(module.providers?.length, 3);
  assert.equal(module.exports?.length, 3);
});

test('AuthGuard skips public handlers', async () => {
  const handler = () => undefined;
  Public()(handler);

  const oidcService = {
    decodeAccessToken: () => {
      throw new Error('public handlers must not decode a token');
    },
  } as unknown as OidcService;
  const guard = new AuthGuard(oidcService, new Reflector(), logger);

  assert.equal(await guard.canActivate(createExecutionContext({ headers: {} }, handler)), true);
});

test('AuthGuard validates a bearer token and attaches the decoded user', async () => {
  const token: BaseDecodedAccessToken = {
    sub: 'user-1',
    aud: 'api',
  };
  const request: {
    headers: { authorization: string };
    user?: BaseDecodedAccessToken;
  } = {
    headers: { authorization: 'Bearer access-token' },
  };
  const oidcService = {
    decodeAccessToken: async (authorizationHeader: string) => {
      assert.equal(authorizationHeader, 'Bearer access-token');
      return token;
    },
  } as unknown as OidcService;
  const guard = new AuthGuard(oidcService, new Reflector(), logger);

  assert.equal(await guard.canActivate(createExecutionContext(request)), true);
  assert.equal(request.user, token);
});

test('AuthGuard rejects requests without an authorization header', async () => {
  const oidcService = {} as OidcService;
  const guard = new AuthGuard(oidcService, new Reflector(), logger);

  await assert.rejects(
    guard.canActivate(createExecutionContext({ headers: {} })),
    UnauthorizedException,
  );
});

test('RolesGuard enforces handler roles', () => {
  const handler = () => undefined;
  Roles('admin')(handler);

  const guard = new RolesGuard(new Reflector(), logger, {
    issuerUri: 'https://issuer.example.test',
    audience: 'api',
  });

  assert.equal(
    guard.canActivate(
      createExecutionContext(
        {
          user: {
            sub: 'admin-1',
            aud: 'api',
            realm_access: { roles: ['admin'] },
          },
        },
        handler,
      ),
    ),
    true,
  );

  assert.throws(
    () =>
      guard.canActivate(
        createExecutionContext(
          {
            user: {
              sub: 'user-1',
              aud: 'api',
              realm_access: { roles: ['viewer'] },
            },
          },
          handler,
        ),
      ),
    ForbiddenException,
  );
});
