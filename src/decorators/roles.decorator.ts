import { SetMetadata } from '@nestjs/common';

/**
 * Metadata key for required roles.
 */
export const ROLES_KEY = 'roles';

/**
 * Decorator to specify required roles for a route.
 * Use this decorator in combination with the RolesGuard to restrict access based on user roles.
 *
 * @param roles - One or more roles required to access the route
 *
 * @example
 * ```typescript
 * @Roles('admin')
 * @Delete('users/:id')
 * deleteUser(@Param('id') id: string) {
 *   // Only users with 'admin' role can access this
 * }
 * ```
 *
 * @example
 * ```typescript
 * @Roles('admin', 'moderator')
 * @Post('content/approve')
 * approveContent() {
 *   // Users with either 'admin' or 'moderator' role can access this
 * }
 * ```
 */
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);

