# NestJS SPA OIDC

A reusable NestJS module for OIDC (OpenID Connect) authentication in Single Page Applications. This module provides seamless integration with OIDC providers using JWT tokens, with built-in support for authentication guards, role-based access control, and platform-agnostic request handling.

## Features

- ✅ **OIDC/JWT Token Validation** - Automatic token verification using `oidc-spa/backend`
- ✅ **Global Authentication Guard** - Protect all routes by default with opt-out via `@Public()` decorator
- ✅ **Role-Based Access Control (RBAC)** - Easy role checking with `@Roles()` decorator
- ✅ **Platform Agnostic** - Works with both Express and Fastify
- ✅ **TypeScript First** - Full type safety with customizable token schemas
- ✅ **Flexible Configuration** - Synchronous and asynchronous configuration options
- ✅ **Custom Logger Support** - Bring your own logger or use the built-in console logger
- ✅ **User Context Extraction** - Simple `@User()` decorator to access authenticated user

## Installation

```bash
pnpm add @mwolf1989/nestjs-spa-oidc
# or
npm install @mwolf1989/nestjs-spa-oidc
# or
yarn add @mwolf1989/nestjs-spa-oidc
```

## Quick Start

### 1. Basic Configuration

```typescript
import { Module } from '@nestjs/common';
import { OidcSpaModule } from '@mwolf1989/nestjs-spa-oidc';

@Module({
  imports: [
    OidcSpaModule.forRoot({
      issuerUri: 'https://auth.example.com/realms/myrealm',
      audience: 'account',
    }),
  ],
})
export class AppModule {}
```

### 2. Async Configuration with ConfigService

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { OidcSpaModule } from '@mwolf1989/nestjs-spa-oidc';

@Module({
  imports: [
    ConfigModule.forRoot(),
    OidcSpaModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        issuerUri: configService.get('OIDC_ISSUER_URI'),
        audience: configService.get('OIDC_AUDIENCE'),
      }),
      inject: [ConfigService],
    }),
  ],
})
export class AppModule {}
```

### 3. Using in Controllers

```typescript
import { Controller, Get } from '@nestjs/common';
import { Public, User, Roles } from '@mwolf1989/nestjs-spa-oidc';
import type { DefaultDecodedAccessToken } from '@mwolf1989/nestjs-spa-oidc';

@Controller('api')
export class ApiController {
  // Public route - no authentication required
  @Public()
  @Get('health')
  getHealth() {
    return { status: 'ok' };
  }

  // Protected route - requires authentication
  @Get('profile')
  getProfile(@User() user: DefaultDecodedAccessToken) {
    return {
      userId: user.sub,
      roles: user.realm_access?.roles || [],
    };
  }

  // Role-protected route - requires specific role
  @Roles('admin')
  @Get('admin')
  getAdminData(@User() user: DefaultDecodedAccessToken) {
    return { message: 'Admin only data' };
  }

  // Multiple roles - user needs at least one
  @Roles('admin', 'moderator')
  @Get('moderation')
  getModerationData() {
    return { message: 'Moderation data' };
  }

  // Extract specific user property
  @Get('user-id')
  getUserId(@User('sub') userId: string) {
    return { userId };
  }
}
```

## Advanced Configuration

### Custom Token Schema

Define your own token structure with Zod:

```typescript
import { z } from 'zod';
import { OidcSpaModule } from '@mwolf1989/nestjs-spa-oidc';

const CustomTokenSchema = z.object({
  sub: z.string(),
  aud: z.union([z.string(), z.array(z.string())]),
  email: z.string().email(),
  name: z.string(),
  roles: z.array(z.string()),
  organization: z.string().optional(),
});

type CustomToken = z.infer<typeof CustomTokenSchema>;

@Module({
  imports: [
    OidcSpaModule.forRoot<CustomToken>({
      issuerUri: 'https://auth.example.com',
      audience: 'my-api',
      decodedAccessTokenSchema: CustomTokenSchema,
      getRolesFromDecodedAccessToken: (token) => token.roles, // Custom role extraction
    }),
  ],
})
export class AppModule {}
```

### Custom Logger

Integrate with your existing logger (e.g., Pino, Winston):

```typescript
import { Logger } from 'nestjs-pino';
import { OidcSpaModule, OidcLogger } from '@mwolf1989/nestjs-spa-oidc';

class PinoOidcLogger implements OidcLogger {
  constructor(private readonly logger: Logger) {}

  log(message: string, context?: string): void {
    this.logger.log({ context }, message);
  }

  error(message: string, trace?: string, context?: string): void {
    this.logger.error({ context, trace }, message);
  }

  warn(message: string, context?: string): void {
    this.logger.warn({ context }, message);
  }

  debug(message: string, context?: string): void {
    this.logger.debug({ context }, message);
  }
}

@Module({
  imports: [
    OidcSpaModule.forRootAsync({
      imports: [LoggerModule],
      useFactory: (logger: Logger) => ({
        issuerUri: process.env.OIDC_ISSUER_URI,
        audience: process.env.OIDC_AUDIENCE,
        logger: new PinoOidcLogger(logger),
      }),
      inject: [Logger],
    }),
  ],
})
export class AppModule {}
```

### Disable Global Guards

If you prefer to apply guards manually:

```typescript
OidcSpaModule.forRoot({
  issuerUri: 'https://auth.example.com',
  audience: 'account',
  globalGuard: false,        // Disable global AuthGuard
  globalRolesGuard: false,   // Disable global RolesGuard
})
```

Then apply guards manually in controllers:

```typescript
import { Controller, UseGuards } from '@nestjs/common';
import { AuthGuard, RolesGuard } from '@mwolf1989/nestjs-spa-oidc';

@Controller('api')
@UseGuards(AuthGuard, RolesGuard)
export class ApiController {
  // Your routes here
}
```

## Configuration Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `issuerUri` | `string` | Yes | - | OIDC issuer URI (e.g., `https://auth.example.com/realms/myrealm`) |
| `audience` | `string` | Yes | - | Expected audience for the access token |
| `decodedAccessTokenSchema` | `ZodType` | No | `DefaultDecodedAccessTokenSchema` | Zod schema for token validation |
| `globalGuard` | `boolean` | No | `true` | Apply AuthGuard globally |
| `globalRolesGuard` | `boolean` | No | `true` | Apply RolesGuard globally |
| `logger` | `OidcLogger` | No | `ConsoleLogger` | Custom logger instance |
| `getRolesFromDecodedAccessToken` | `function` | No | `(token) => token.realm_access?.roles \|\| []` | Function to extract roles from token |

## API Reference

### Decorators

- **`@Public()`** - Mark a route as public (no authentication required)
- **`@User(property?)`** - Extract authenticated user from request
- **`@Roles(...roles)`** - Require specific roles for route access

### Guards

- **`AuthGuard`** - Validates JWT tokens and attaches user to request
- **`RolesGuard`** - Checks if user has required roles

### Services

- **`OidcService`** - Core service for token validation and user info extraction
  - `decodeAccessToken(authHeader, requiredRole?)` - Decode and validate token
  - `getUserId(token)` - Extract user ID from token
  - `getUserRoles(token)` - Extract roles from token
  - `hasRole(token, role)` - Check if user has specific role

## Environment Variables

```env
OIDC_ISSUER_URI=https://auth.example.com/realms/myrealm
OIDC_AUDIENCE=account
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

