"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OidcHttpError = void 0;
exports.oauthErrorRedirect = oauthErrorRedirect;
class OidcHttpError extends Error {
    status;
    code;
    oauthError;
    constructor(status, code, message, oauthError) {
        super(message);
        this.status = status;
        this.code = code;
        this.oauthError = oauthError;
        this.name = "OidcHttpError";
    }
    toJsonResponse() {
        const body = {
            error: this.oauthError ?? mapOidcToOauthError(this.code),
            error_description: this.message,
            code: this.code,
        };
        return Response.json(body, {
            status: this.status,
            headers: {
                "Cache-Control": "no-store",
                Pragma: "no-cache",
            },
        });
    }
}
exports.OidcHttpError = OidcHttpError;
function mapOidcToOauthError(code) {
    switch (code) {
        case "invalid_client":
            return "invalid_client";
        case "invalid_grant":
            return "invalid_grant";
        case "unauthorized_client":
            return "unauthorized_client";
        case "unsupported_grant_type":
            return "unsupported_grant_type";
        case "invalid_scope":
            return "invalid_scope";
        case "access_denied":
            return "access_denied";
        case "rate_limited":
        case "temporarily_unavailable":
            return "temporarily_unavailable";
        case "server_error":
            return "server_error";
        default:
            return "invalid_request";
    }
}
/** Build an OAuth error redirect to the client's redirect_uri. */
function oauthErrorRedirect(redirectUri, error, description, state) {
    const url = new URL(redirectUri);
    url.searchParams.set("error", error);
    url.searchParams.set("error_description", description);
    if (state)
        url.searchParams.set("state", state);
    return url.toString();
}
