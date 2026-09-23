"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ID_TOKEN_TTL_SEC = exports.ACCESS_TOKEN_TTL_SEC = void 0;
exports.generateClientId = generateClientId;
exports.generateClientSecret = generateClientSecret;
exports.generateAuthCode = generateAuthCode;
exports.hashClientSecret = hashClientSecret;
exports.verifyClientSecret = verifyClientSecret;
exports.verifyPkceS256 = verifyPkceS256;
exports.loadSigningKeyFromEnv = loadSigningKeyFromEnv;
exports.generateOidcKeyPair = generateOidcKeyPair;
exports.signIdToken = signIdToken;
exports.signAccessToken = signAccessToken;
exports.verifyAccessToken = verifyAccessToken;
const node_crypto_1 = require("node:crypto");
const jose_1 = require("jose");
const constants_1 = require("./constants");
Object.defineProperty(exports, "ACCESS_TOKEN_TTL_SEC", { enumerable: true, get: function () { return constants_1.ACCESS_TOKEN_TTL_SEC; } });
Object.defineProperty(exports, "ID_TOKEN_TTL_SEC", { enumerable: true, get: function () { return constants_1.ID_TOKEN_TTL_SEC; } });
const SCRYPT_KEYLEN = 64;
function generateClientId() {
    return (0, node_crypto_1.randomBytes)(constants_1.CLIENT_ID_LEN).toString("base64url").slice(0, constants_1.CLIENT_ID_LEN);
}
function generateClientSecret() {
    return (0, node_crypto_1.randomBytes)(constants_1.CLIENT_SECRET_LEN).toString("base64url");
}
function generateAuthCode() {
    return (0, node_crypto_1.randomBytes)(32).toString("base64url");
}
function hashClientSecret(secret) {
    const salt = (0, node_crypto_1.randomBytes)(16).toString("base64url");
    const hash = (0, node_crypto_1.scryptSync)(secret, salt, SCRYPT_KEYLEN).toString("base64url");
    return `scrypt$${salt}$${hash}`;
}
function verifyClientSecret(secret, storedHash) {
    const parts = storedHash.split("$");
    if (parts.length !== 3 || parts[0] !== "scrypt")
        return false;
    const salt = parts[1];
    const expected = parts[2];
    const actual = (0, node_crypto_1.scryptSync)(secret, salt, SCRYPT_KEYLEN).toString("base64url");
    try {
        return (0, node_crypto_1.timingSafeEqual)(Buffer.from(actual), Buffer.from(expected));
    }
    catch {
        return false;
    }
}
function verifyPkceS256(verifier, challenge) {
    const computed = (0, node_crypto_1.createHash)("sha256").update(verifier).digest("base64url");
    try {
        return (0, node_crypto_1.timingSafeEqual)(Buffer.from(computed), Buffer.from(challenge));
    }
    catch {
        return false;
    }
}
/** Load RSA private JWK from env JSON string. */
async function loadSigningKeyFromEnv(raw) {
    if (!raw?.trim())
        return null;
    let jwk;
    try {
        jwk = JSON.parse(raw);
    }
    catch {
        return null;
    }
    if (jwk.kty !== "RSA" || !jwk.d)
        return null;
    const kid = typeof jwk.kid === "string" && jwk.kid
        ? jwk.kid
        : (0, node_crypto_1.createHash)("sha256")
            .update(JSON.stringify({ n: jwk.n, e: jwk.e }))
            .digest("base64url")
            .slice(0, 16);
    const privateKey = await (0, jose_1.importJWK)({ ...jwk, alg: "RS256" }, "RS256");
    const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...pub } = jwk;
    const publicJwk = {
        ...pub,
        kid,
        alg: "RS256",
        use: "sig",
    };
    return { privateKey, publicJwk, kid, alg: "RS256" };
}
async function generateOidcKeyPair() {
    const { privateKey, publicKey } = await (0, jose_1.generateKeyPair)("RS256", {
        extractable: true,
    });
    const privateJwk = await (0, jose_1.exportJWK)(privateKey);
    const publicJwk = await (0, jose_1.exportJWK)(publicKey);
    const kid = (0, node_crypto_1.createHash)("sha256")
        .update(JSON.stringify({ n: publicJwk.n, e: publicJwk.e }))
        .digest("base64url")
        .slice(0, 16);
    return {
        privateJwk: { ...privateJwk, kid, alg: "RS256", use: "sig" },
        publicJwk: { ...publicJwk, kid, alg: "RS256", use: "sig" },
        kid,
    };
}
async function signIdToken(opts) {
    const now = Math.floor(Date.now() / 1000);
    return new jose_1.SignJWT({
        ...opts.claims,
        ...(opts.nonce ? { nonce: opts.nonce } : {}),
    })
        .setProtectedHeader({ alg: "RS256", kid: opts.key.kid, typ: "JWT" })
        .setIssuer(opts.issuer)
        .setAudience(opts.audience)
        .setSubject(String(opts.claims.sub))
        .setIssuedAt(now)
        .setExpirationTime(now + constants_1.ID_TOKEN_TTL_SEC)
        .sign(opts.key.privateKey);
}
async function signAccessToken(opts) {
    const now = Math.floor(Date.now() / 1000);
    return new jose_1.SignJWT({
        scope: opts.scope,
        client_id: opts.clientId,
        token_use: "access",
    })
        .setProtectedHeader({ alg: "RS256", kid: opts.key.kid, typ: "at+JWT" })
        .setIssuer(opts.issuer)
        .setAudience(opts.audience)
        .setSubject(opts.uid)
        .setIssuedAt(now)
        .setExpirationTime(now + constants_1.ACCESS_TOKEN_TTL_SEC)
        .sign(opts.key.privateKey);
}
async function verifyAccessToken(token, key, issuer) {
    const pub = await (0, jose_1.importJWK)(key.publicJwk, "RS256");
    const { payload } = await (0, jose_1.jwtVerify)(token, pub, {
        issuer,
        algorithms: ["RS256"],
    });
    const uid = String(payload.sub ?? "");
    const scope = String(payload.scope ?? "");
    const clientId = String(payload.client_id ?? "");
    if (!uid)
        throw new Error("missing sub");
    return { uid, scope, clientId };
}
