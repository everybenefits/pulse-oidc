import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import {
  exportJWK,
  generateKeyPair,
  importJWK,
  SignJWT,
  jwtVerify,
  type JWK,
} from "jose";

type JoseKey = Awaited<ReturnType<typeof importJWK>>;
import {
  ACCESS_TOKEN_TTL_SEC,
  CLIENT_ID_LEN,
  CLIENT_SECRET_LEN,
  ID_TOKEN_TTL_SEC,
} from "./constants";

const SCRYPT_KEYLEN = 64;

export function generateClientId(): string {
  return randomBytes(CLIENT_ID_LEN).toString("base64url").slice(0, CLIENT_ID_LEN);
}

export function generateClientSecret(): string {
  return randomBytes(CLIENT_SECRET_LEN).toString("base64url");
}

export function generateAuthCode(): string {
  return randomBytes(32).toString("base64url");
}

export function hashClientSecret(secret: string): string {
  const salt = randomBytes(16).toString("base64url");
  const hash = scryptSync(secret, salt, SCRYPT_KEYLEN).toString("base64url");
  return `scrypt$${salt}$${hash}`;
}

export function verifyClientSecret(
  secret: string,
  storedHash: string,
): boolean {
  const parts = storedHash.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  const salt = parts[1]!;
  const expected = parts[2]!;
  const actual = scryptSync(secret, salt, SCRYPT_KEYLEN).toString("base64url");
  try {
    return timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
  } catch {
    return false;
  }
}

export function verifyPkceS256(verifier: string, challenge: string): boolean {
  const computed = createHash("sha256").update(verifier).digest("base64url");
  try {
    return timingSafeEqual(Buffer.from(computed), Buffer.from(challenge));
  } catch {
    return false;
  }
}

export type SigningKeyMaterial = {
  privateKey: JoseKey;
  publicJwk: JWK;
  kid: string;
  alg: "RS256";
};

/** Load RSA private JWK from env JSON string. */
export async function loadSigningKeyFromEnv(
  raw: string | undefined | null,
): Promise<SigningKeyMaterial | null> {
  if (!raw?.trim()) return null;
  let jwk: JWK;
  try {
    jwk = JSON.parse(raw) as JWK;
  } catch {
    return null;
  }
  if (jwk.kty !== "RSA" || !jwk.d) return null;
  const kid =
    typeof jwk.kid === "string" && jwk.kid
      ? jwk.kid
      : createHash("sha256")
          .update(JSON.stringify({ n: jwk.n, e: jwk.e }))
          .digest("base64url")
          .slice(0, 16);
  const privateKey = await importJWK({ ...jwk, alg: "RS256" }, "RS256");
  const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...pub } = jwk;
  const publicJwk: JWK = {
    ...pub,
    kid,
    alg: "RS256",
    use: "sig",
  };
  return { privateKey, publicJwk, kid, alg: "RS256" };
}

export async function generateOidcKeyPair(): Promise<{
  privateJwk: JWK;
  publicJwk: JWK;
  kid: string;
}> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", {
    extractable: true,
  });
  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);
  const kid = createHash("sha256")
    .update(JSON.stringify({ n: publicJwk.n, e: publicJwk.e }))
    .digest("base64url")
    .slice(0, 16);
  return {
    privateJwk: { ...privateJwk, kid, alg: "RS256", use: "sig" },
    publicJwk: { ...publicJwk, kid, alg: "RS256", use: "sig" },
    kid,
  };
}

export async function signIdToken(opts: {
  key: SigningKeyMaterial;
  issuer: string;
  audience: string;
  claims: Record<string, string | boolean | number>;
  nonce?: string | null;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    ...opts.claims,
    ...(opts.nonce ? { nonce: opts.nonce } : {}),
  })
    .setProtectedHeader({ alg: "RS256", kid: opts.key.kid, typ: "JWT" })
    .setIssuer(opts.issuer)
    .setAudience(opts.audience)
    .setSubject(String(opts.claims.sub))
    .setIssuedAt(now)
    .setExpirationTime(now + ID_TOKEN_TTL_SEC)
    .sign(opts.key.privateKey);
}

export async function signAccessToken(opts: {
  key: SigningKeyMaterial;
  issuer: string;
  audience: string;
  uid: string;
  scope: string;
  clientId: string;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    scope: opts.scope,
    client_id: opts.clientId,
    token_use: "access",
  })
    .setProtectedHeader({ alg: "RS256", kid: opts.key.kid, typ: "at+JWT" })
    .setIssuer(opts.issuer)
    .setAudience(opts.audience)
    .setSubject(opts.uid)
    .setIssuedAt(now)
    .setExpirationTime(now + ACCESS_TOKEN_TTL_SEC)
    .sign(opts.key.privateKey);
}

export async function verifyAccessToken(
  token: string,
  key: SigningKeyMaterial,
  issuer: string,
): Promise<{ uid: string; scope: string; clientId: string }> {
  const pub = await importJWK(key.publicJwk, "RS256");
  const { payload } = await jwtVerify(token, pub, {
    issuer,
    algorithms: ["RS256"],
  });
  const uid = String(payload.sub ?? "");
  const scope = String(payload.scope ?? "");
  const clientId = String(payload.client_id ?? "");
  if (!uid) throw new Error("missing sub");
  return { uid, scope, clientId };
}

export { ACCESS_TOKEN_TTL_SEC, ID_TOKEN_TTL_SEC };
