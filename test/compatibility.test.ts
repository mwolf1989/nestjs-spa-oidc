import 'reflect-metadata';

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  BadRequestException,
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { AnyRequest, ValidateAndDecodeAccessToken } from 'oidc-spa/server';
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
    decodeRequest: () => {
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
    decodeRequest: async (requestToDecode: unknown) => {
      assert.equal(requestToDecode, request);
      return token;
    },
  } as unknown as OidcService;
  const guard = new AuthGuard(oidcService, new Reflector(), logger);

  assert.equal(await guard.canActivate(createExecutionContext(request)), true);
  assert.equal(request.user, token);
});

test('AuthGuard rejects requests without an authorization header', async () => {
  const oidcService = {
    decodeRequest: async () => {
      throw new UnauthorizedException('No authorization header provided');
    },
  } as unknown as OidcService;
  const guard = new AuthGuard(oidcService, new Reflector(), logger);

  await assert.rejects(
    guard.canActivate(createExecutionContext({ headers: {} })),
    UnauthorizedException,
  );
});

test('AuthGuard preserves malformed-request errors', async () => {
  const oidcService = {
    decodeRequest: async () => {
      throw new BadRequestException('Malformed authentication request');
    },
  } as unknown as OidcService;
  const guard = new AuthGuard(oidcService, new Reflector(), logger);

  await assert.rejects(
    guard.canActivate(createExecutionContext({ headers: {} })),
    BadRequestException,
  );
});

test('OidcService passes DPoP proof and request metadata to oidc-spa', async () => {
  const service = new OidcService(
    {
      issuerUri: 'https://issuer.example.test',
      audience: 'api',
      trustProxy: false,
    },
    logger,
  );
  let receivedParams: ValidateAndDecodeAccessToken.Params | undefined;
  const decodedAccessToken: BaseDecodedAccessToken = {
    sub: 'user-1',
    aud: 'api',
  };

  Object.assign(service, {
    validateAndDecodeAccessTokenFn: async (params: ValidateAndDecodeAccessToken.Params) => {
      receivedParams = params;
      return {
        isSuccess: true as const,
        decodedAccessToken,
        decodedAccessToken_original: {
          iss: 'https://issuer.example.test',
          sub: 'user-1',
          aud: 'api',
          exp: 2_000_000_000,
          iat: 1_900_000_000,
        },
        accessToken: params.accessToken,
      };
    },
  });

  const request: AnyRequest.Unified = {
    type: 'unified',
    method: 'GET',
    pseudoHeaders: {
      ':scheme': 'https',
      ':authority': 'api.example.test',
      ':path': '/todos?limit=10',
    },
    headers: {
      Authorization: 'DPoP access-token',
      DPoP: 'proof-token',
      Forwarded: undefined,
      'X-Forwarded-Proto': undefined,
      'X-Forwarded-Host': undefined,
    },
  };

  assert.equal(await service.decodeRequest(request), decodedAccessToken);
  assert.deepEqual(receivedParams, {
    scheme: 'DPoP',
    accessToken: 'access-token',
    dpopProof: 'proof-token',
    expectedHtu: 'https://api.example.test/todos',
    expectedHtm: 'GET',
  });
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
