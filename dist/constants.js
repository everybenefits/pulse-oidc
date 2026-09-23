"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEVELOPERS_COLLECTION = exports.OIDC_RATE_LIMIT_COLLECTION = exports.OIDC_AUTH_CODES_COLLECTION = exports.OIDC_CLIENTS_COLLECTION = exports.SUPPORTED_SCOPES = exports.CLIENT_SECRET_LEN = exports.CLIENT_ID_LEN = exports.CODE_MAX_LEN = exports.CODE_MIN_LEN = exports.MAX_OIDC_PER_MINUTE = exports.ID_TOKEN_TTL_SEC = exports.ACCESS_TOKEN_TTL_SEC = exports.AUTH_CODE_TTL_MS = void 0;
exports.AUTH_CODE_TTL_MS = 5 * 60_000;
exports.ACCESS_TOKEN_TTL_SEC = 3600;
exports.ID_TOKEN_TTL_SEC = 3600;
exports.MAX_OIDC_PER_MINUTE = 30;
exports.CODE_MIN_LEN = 32;
exports.CODE_MAX_LEN = 128;
exports.CLIENT_ID_LEN = 24;
exports.CLIENT_SECRET_LEN = 40;
exports.SUPPORTED_SCOPES = [
    "openid",
    "profile",
    "email",
    "phone",
];
exports.OIDC_CLIENTS_COLLECTION = "oidcClients";
exports.OIDC_AUTH_CODES_COLLECTION = "oidcAuthCodes";
exports.OIDC_RATE_LIMIT_COLLECTION = "oidcRateLimit";
exports.DEVELOPERS_COLLECTION = "developers";
