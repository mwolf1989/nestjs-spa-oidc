import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { BaseDecodedAccessToken } from '../types/decoded-access-token.type';

/**
 * Decorator to extract the authenticated user from the request.
 * The user object is populated by the AuthGuard after successful token validation.
 *
 * @example
 * ```typescript
 * @Get('profile')
 * getProfile(@User() user: DecodedAccessToken) {
 *   return { userId: user.sub };
 * }
 * ```
 *
 * You can also extract specific properties:
 * @example
 * ```typescript
 * @Get('user-id')
 * getUserId(@User('sub') userId: string) {
 *   return { userId };
 * }
 * ```
 */
export const User = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest<{
      user?: BaseDecodedAccessToken;
    }>();
    const user = request.user;

    return data ? user?.[data as keyof BaseDecodedAccessToken] : user;
  },
);

