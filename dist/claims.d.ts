import type { UserProfileClaimsSource } from "./types";
export declare function splitDisplayName(displayName: string | null | undefined): {
    given_name: string;
    family_name: string;
    name: string;
};
export declare function buildPhoneNumber(countryCode: string | null | undefined, number: string | null | undefined): string | undefined;
/** Build ID token / userinfo claims from Firebase Auth + users/{uid}. */
export declare function buildOidcClaims(profile: UserProfileClaimsSource, scopes: string[]): Record<string, string | boolean | number>;
export declare function parseScopeString(scope: string | null | undefined): string[];
//# sourceMappingURL=claims.d.ts.map