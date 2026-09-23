export const AUTH_CODE_TTL_MS = 5 * 60_000;
export const ACCESS_TOKEN_TTL_SEC = 3600;
export const ID_TOKEN_TTL_SEC = 3600;
export const MAX_OIDC_PER_MINUTE = 30;
export const CODE_MIN_LEN = 32;
export const CODE_MAX_LEN = 128;
export const CLIENT_ID_LEN = 24;
export const CLIENT_SECRET_LEN = 40;

export const SUPPORTED_SCOPES = [
  "openid",
  "profile",
  "email",
  "phone",
] as const;

export type SupportedScope = (typeof SUPPORTED_SCOPES)[number];

export const OIDC_CLIENTS_COLLECTION = "oidcClients";
export const OIDC_AUTH_CODES_COLLECTION = "oidcAuthCodes";
export const OIDC_RATE_LIMIT_COLLECTION = "oidcRateLimit";
export const DEVELOPERS_COLLECTION = "developers";
