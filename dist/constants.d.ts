export declare const AUTH_CODE_TTL_MS: number;
export declare const ACCESS_TOKEN_TTL_SEC = 3600;
export declare const ID_TOKEN_TTL_SEC = 3600;
export declare const MAX_OIDC_PER_MINUTE = 30;
export declare const CODE_MIN_LEN = 32;
export declare const CODE_MAX_LEN = 128;
export declare const CLIENT_ID_LEN = 24;
export declare const CLIENT_SECRET_LEN = 40;
export declare const SUPPORTED_SCOPES: readonly ["openid", "profile", "email", "phone"];
export type SupportedScope = (typeof SUPPORTED_SCOPES)[number];
export declare const OIDC_CLIENTS_COLLECTION = "oidcClients";
export declare const OIDC_AUTH_CODES_COLLECTION = "oidcAuthCodes";
export declare const OIDC_RATE_LIMIT_COLLECTION = "oidcRateLimit";
export declare const DEVELOPERS_COLLECTION = "developers";
//# sourceMappingURL=constants.d.ts.map