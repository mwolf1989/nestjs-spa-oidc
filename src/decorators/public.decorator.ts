import { SetMetadata } from '@nestjs/common';

/**
 * Metadata key for marking routes as public.
 */
export const IS_PUBLIC_KEY = 'isPublic';

/**
 * Decorator to mark a route as public (no authentication required).
 * Use this decorator on controller methods that should be accessible without authentication.
 *
 * @example
 * ```typescript
 * @Public()
 * @Get('health')
 * getHealth() {
 *   return { status: 'ok' };
 * }
 * ```
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

