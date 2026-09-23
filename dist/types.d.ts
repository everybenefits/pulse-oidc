export type OidcErrorCode = "invalid_request" | "invalid_client" | "invalid_grant" | "unauthorized_client" | "unsupported_grant_type" | "invalid_scope" | "access_denied" | "server_error" | "temporarily_unavailable" | "account_disabled" | "developer_suspended" | "not_found" | "forbidden" | "rate_limited";
export type DeveloperStatus = "pending" | "active" | "suspended";
export type OidcClientRecord = {
    clientId: string;
    name: string;
    secretHash: string;
    redirectUris: string[];
    scopes: string[];
    enabled: boolean;
    trusted: boolean;
    ownerDeveloperId: string;
    createdAt?: unknown;
    updatedAt?: unknown;
};
export type DeveloperRecord = {
    uid: string;
    email: string | null;
    displayName: string | null;
    orgName: string | null;
    status: DeveloperStatus;
    /** Platform ops can manage IdP keys UI + oversight. */
    isPlatformAdmin?: boolean;
    createdAt?: unknown;
    updatedAt?: unknown;
};
export type AuthorizeRequest = {
    clientId: string;
    redirectUri: string;
    responseType: string;
    scope: string;
    state: string | null;
    nonce: string | null;
    codeChallenge: string | null;
    codeChallengeMethod: string | null;
};
export type TokenSuccess = {
    access_token: string;
    token_type: "Bearer";
    expires_in: number;
    id_token: string;
    scope: string;
};
export type UserProfileClaimsSource = {
    uid: string;
    email?: string | null;
    emailVerified?: boolean;
    displayName?: string | null;
    photoUrl?: string | null;
    phoneCountryCode?: string | null;
    phoneNumber?: string | null;
    locale?: string | null;
    accountStatus?: string | null;
};
//# sourceMappingURL=types.d.ts.map