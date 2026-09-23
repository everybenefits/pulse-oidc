import { type Firestore } from "firebase-admin/firestore";
import type { Auth } from "firebase-admin/auth";
import { OidcHttpError, oauthErrorRedirect } from "./errors";
import { type SigningKeyMaterial } from "./crypto";
import type { AuthorizeRequest, DeveloperRecord, OidcClientRecord, TokenSuccess, UserProfileClaimsSource } from "./types";
export type OidcServerDeps = {
    auth: () => Auth;
    db: () => Firestore;
    issuer: () => string;
    signingKey: () => Promise<SigningKeyMaterial>;
};
export type OidcRequestContext = {
    clientIp?: string;
};
export declare function contextFromRequest(request: Request): OidcRequestContext;
export declare function rateLimitDocId(bucket: string, identity: string): string;
export declare function parseAuthorizeQuery(searchParams: URLSearchParams): AuthorizeRequest;
export declare function createOidcServer(deps: OidcServerDeps): {
    getDiscovery: () => Promise<{
        issuer: string;
        authorization_endpoint: string;
        token_endpoint: string;
        userinfo_endpoint: string;
        jwks_uri: string;
        response_types_supported: string[];
        subject_types_supported: string[];
        id_token_signing_alg_values_supported: string[];
        scopes_supported: ("email" | "openid" | "profile" | "phone")[];
        token_endpoint_auth_methods_supported: string[];
        claims_supported: string[];
        code_challenge_methods_supported: string[];
        grant_types_supported: string[];
    }>;
    getJwks: () => Promise<{
        keys: import("jose").JWK[];
    }>;
    getPlatformKid: () => Promise<string>;
    parseAuthorizeQuery: typeof parseAuthorizeQuery;
    validateAuthorizeRequest: (req: AuthorizeRequest) => Promise<{
        ok: true;
        client: OidcClientRecord;
        scopes: string[];
    } | {
        ok: false;
        errorRedirect: string;
    }>;
    mintAuthorizationCode: (opts: {
        ctx: OidcRequestContext;
        uid: string;
        req: AuthorizeRequest;
        scopes: string[];
    }) => Promise<{
        code: string;
        redirectUrl: string;
    }>;
    exchangeAuthorizationCode: (ctx: OidcRequestContext, request: Request, body: URLSearchParams) => Promise<TokenSuccess>;
    userInfo: (accessToken: string) => Promise<Record<string, string | boolean | number>>;
    loadClient: (clientId: string) => Promise<OidcClientRecord | null>;
    loadConsumerClaims: (uid: string) => Promise<UserProfileClaimsSource>;
    getDeveloper: (uid: string) => Promise<DeveloperRecord | null>;
    createDeveloperAccount: (opts: {
        uid: string;
        email: string | null;
        displayName: string | null;
        orgName?: string | null;
    }) => Promise<DeveloperRecord>;
    assertActiveDeveloper: (uid: string) => Promise<DeveloperRecord>;
    createOidcClient: (opts: {
        ownerDeveloperId: string;
        name: string;
        redirectUris: string[];
        scopes?: string[];
    }) => Promise<{
        client: OidcClientRecord;
        clientSecret: string;
    }>;
    listOidcClientsForOwner: (ownerDeveloperId: string) => Promise<OidcClientRecord[]>;
    listAllOidcClients: () => Promise<OidcClientRecord[]>;
    updateOidcClient: (opts: {
        clientId: string;
        actorDeveloperId: string;
        asPlatformAdmin?: boolean;
        name?: string;
        redirectUris?: string[];
        scopes?: string[];
        enabled?: boolean;
        trusted?: boolean;
    }) => Promise<OidcClientRecord>;
    rotateClientSecret: (opts: {
        clientId: string;
        actorDeveloperId: string;
        asPlatformAdmin?: boolean;
    }) => Promise<{
        clientSecret: string;
    }>;
    setDeveloperStatus: (opts: {
        targetUid: string;
        status: DeveloperRecord["status"];
    }) => Promise<void>;
    listDevelopers: () => Promise<DeveloperRecord[]>;
    OidcHttpError: typeof OidcHttpError;
};
export type OidcServer = ReturnType<typeof createOidcServer>;
export { OidcHttpError, oauthErrorRedirect };
export { parseAuthorizeQuery as parseAuthorizeSearchParams };
export { loadSigningKeyFromEnv, generateOidcKeyPair, hashClientSecret, verifyClientSecret, verifyPkceS256, } from "./crypto";
export type { SigningKeyMaterial } from "./crypto";
export type { AuthorizeRequest, OidcClientRecord, DeveloperRecord } from "./types";
export { SUPPORTED_SCOPES, OIDC_CLIENTS_COLLECTION, DEVELOPERS_COLLECTION, } from "./constants";
export { buildOidcClaims, parseScopeString } from "./claims";
//# sourceMappingURL=server.d.ts.map