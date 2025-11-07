import { z } from 'zod';

/**
 * Default schema for the decoded access token.
 * This can be extended or replaced by consumers of the module.
 */
export const DefaultDecodedAccessTokenSchema = z.object({
  sub: z.string(),
  aud: z.union([z.string(), z.array(z.string())]),
  realm_access: z
    .object({
      roles: z.array(z.string()),
    })
    .optional(),
  // Add other common claims
  // preferred_username: z.string().optional(),
  // email: z.string().email().optional(),
  // name: z.string().optional(),
});

/**
 * Default type for the decoded access token.
 * This can be extended by consumers of the module.
 */
export type DefaultDecodedAccessToken = z.infer<typeof DefaultDecodedAccessTokenSchema>;

/**
 * Base interface that all decoded access tokens must implement.
 * Includes an index signature to be compatible with DecodedAccessToken_RFC9068.
 */
export interface BaseDecodedAccessToken {
  sub: string;
  aud: string | string[];
  [key: string]: unknown;
}

