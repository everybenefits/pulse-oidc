import { importJWK, type JWK } from "jose";
type JoseKey = Awaited<ReturnType<typeof importJWK>>;
import { ACCESS_TOKEN_TTL_SEC, ID_TOKEN_TTL_SEC } from "./constants";
export declare function generateClientId(): string;
export declare function generateClientSecret(): string;
export declare function generateAuthCode(): string;
export declare function hashClientSecret(secret: string): string;
export declare function verifyClientSecret(secret: string, storedHash: string): boolean;
export declare function verifyPkceS256(verifier: string, challenge: string): boolean;
export type SigningKeyMaterial = {
    privateKey: JoseKey;
    publicJwk: JWK;
    kid: string;
    alg: "RS256";
};
/** Load RSA private JWK from env JSON string. */
export declare function loadSigningKeyFromEnv(raw: string | undefined | null): Promise<SigningKeyMaterial | null>;
export declare function generateOidcKeyPair(): Promise<{
    privateJwk: JWK;
    publicJwk: JWK;
    kid: string;
}>;
export declare function signIdToken(opts: {
    key: SigningKeyMaterial;
    issuer: string;
    audience: string;
    claims: Record<string, string | boolean | number>;
    nonce?: string | null;
}): Promise<string>;
export declare function signAccessToken(opts: {
    key: SigningKeyMaterial;
    issuer: string;
    audience: string;
    uid: string;
    scope: string;
    clientId: string;
}): Promise<string>;
export declare function verifyAccessToken(token: string, key: SigningKeyMaterial, issuer: string): Promise<{
    uid: string;
    scope: string;
    clientId: string;
}>;
export { ACCESS_TOKEN_TTL_SEC, ID_TOKEN_TTL_SEC };
//# sourceMappingURL=crypto.d.ts.map