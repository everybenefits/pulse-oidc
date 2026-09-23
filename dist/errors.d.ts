import type { OidcErrorCode } from "./types";
export declare class OidcHttpError extends Error {
    readonly status: number;
    readonly code: OidcErrorCode;
    readonly oauthError?: string | undefined;
    constructor(status: number, code: OidcErrorCode, message: string, oauthError?: string | undefined);
    toJsonResponse(): Response;
}
/** Build an OAuth error redirect to the client's redirect_uri. */
export declare function oauthErrorRedirect(redirectUri: string, error: string, description: string, state: string | null): string;
//# sourceMappingURL=errors.d.ts.map