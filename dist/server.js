"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseScopeString = exports.buildOidcClaims = exports.DEVELOPERS_COLLECTION = exports.OIDC_CLIENTS_COLLECTION = exports.SUPPORTED_SCOPES = exports.verifyPkceS256 = exports.verifyClientSecret = exports.hashClientSecret = exports.generateOidcKeyPair = exports.loadSigningKeyFromEnv = exports.oauthErrorRedirect = exports.OidcHttpError = void 0;
exports.contextFromRequest = contextFromRequest;
exports.rateLimitDocId = rateLimitDocId;
exports.parseAuthorizeQuery = parseAuthorizeQuery;
exports.parseAuthorizeSearchParams = parseAuthorizeQuery;
exports.createOidcServer = createOidcServer;
const node_crypto_1 = require("node:crypto");
const firestore_1 = require("firebase-admin/firestore");
const constants_1 = require("./constants");
const claims_1 = require("./claims");
const errors_1 = require("./errors");
Object.defineProperty(exports, "OidcHttpError", { enumerable: true, get: function () { return errors_1.OidcHttpError; } });
Object.defineProperty(exports, "oauthErrorRedirect", { enumerable: true, get: function () { return errors_1.oauthErrorRedirect; } });
const crypto_1 = require("./crypto");
function clientIpFromRequest(request) {
    const forwarded = request.headers.get("x-forwarded-for");
    if (forwarded) {
        const first = forwarded.split(",")[0]?.trim();
        if (first)
            return first;
    }
    return request.headers.get("x-real-ip")?.trim() || "unknown";
}
function contextFromRequest(request) {
    return { clientIp: clientIpFromRequest(request) };
}
function rateLimitDocId(bucket, identity) {
    const hash = (0, node_crypto_1.createHash)("sha256").update(identity).digest("hex").slice(0, 32);
    const minute = Math.floor(Date.now() / 60_000);
    return `${bucket}_${hash}_${minute}`;
}
function parseAuthorizeQuery(searchParams) {
    return {
        clientId: String(searchParams.get("client_id") ?? "").trim(),
        redirectUri: String(searchParams.get("redirect_uri") ?? "").trim(),
        responseType: String(searchParams.get("response_type") ?? "").trim(),
        scope: String(searchParams.get("scope") ?? "").trim(),
        state: searchParams.get("state"),
        nonce: searchParams.get("nonce"),
        codeChallenge: searchParams.get("code_challenge"),
        codeChallengeMethod: searchParams.get("code_challenge_method"),
    };
}
function discoveryDocument(issuer) {
    const base = issuer.replace(/\/$/, "");
    return {
        issuer: base,
        authorization_endpoint: `${base}/oauth/authorize`,
        token_endpoint: `${base}/oauth/token`,
        userinfo_endpoint: `${base}/oauth/userinfo`,
        jwks_uri: `${base}/.well-known/jwks.json`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        scopes_supported: [...constants_1.SUPPORTED_SCOPES],
        token_endpoint_auth_methods_supported: [
            "client_secret_basic",
            "client_secret_post",
        ],
        claims_supported: [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "nonce",
            "email",
            "email_verified",
            "name",
            "given_name",
            "family_name",
            "picture",
            "phone_number",
            "locale",
        ],
        code_challenge_methods_supported: ["S256"],
        grant_types_supported: ["authorization_code"],
    };
}
function createOidcServer(deps) {
    async function consumeRateLimit(bucket, identity) {
        const minute = Math.floor(Date.now() / 60_000);
        const id = rateLimitDocId(bucket, identity);
        const ref = deps.db().doc(`${constants_1.OIDC_RATE_LIMIT_COLLECTION}/${id}`);
        await deps.db().runTransaction(async (tx) => {
            const snap = await tx.get(ref);
            const count = Number(snap.data()?.count ?? 0);
            if (count >= constants_1.MAX_OIDC_PER_MINUTE) {
                throw new errors_1.OidcHttpError(429, "rate_limited", "Too many OIDC requests.", "temporarily_unavailable");
            }
            tx.set(ref, {
                bucket,
                minute,
                count: count + 1,
                expiresAt: firestore_1.Timestamp.fromMillis((minute + 2) * 60_000),
            }, { merge: true });
        });
    }
    async function assertActiveConsumer(uid) {
        const snap = await deps.db().doc(`users/${uid}`).get();
        const status = String(snap.data()?.accountStatus ?? "active");
        if (status === "deactivated" || status === "pendingDeletion") {
            throw new errors_1.OidcHttpError(403, "account_disabled", "Account is deactivated or pending deletion.", "access_denied");
        }
    }
    async function loadClient(clientId) {
        const snap = await deps
            .db()
            .collection(constants_1.OIDC_CLIENTS_COLLECTION)
            .doc(clientId)
            .get();
        if (!snap.exists)
            return null;
        const data = snap.data() ?? {};
        return {
            clientId,
            name: String(data.name ?? ""),
            secretHash: String(data.secretHash ?? ""),
            redirectUris: Array.isArray(data.redirectUris)
                ? data.redirectUris.map(String)
                : [],
            scopes: Array.isArray(data.scopes)
                ? data.scopes.map(String)
                : [...constants_1.SUPPORTED_SCOPES],
            enabled: data.enabled !== false,
            trusted: data.trusted === true,
            ownerDeveloperId: String(data.ownerDeveloperId ?? ""),
            createdAt: data.createdAt,
            updatedAt: data.updatedAt,
        };
    }
    function assertRedirectUri(client, redirectUri) {
        if (!client.redirectUris.includes(redirectUri)) {
            throw new errors_1.OidcHttpError(400, "invalid_request", "redirect_uri is not registered for this client.");
        }
    }
    function normalizeScopes(requested, client) {
        if (!requested.includes("openid")) {
            throw new errors_1.OidcHttpError(400, "invalid_scope", "scope must include openid.", "invalid_scope");
        }
        const allowed = new Set(client.scopes);
        const supported = new Set(constants_1.SUPPORTED_SCOPES);
        for (const s of requested) {
            if (!supported.has(s) || !allowed.has(s)) {
                throw new errors_1.OidcHttpError(400, "invalid_scope", `Unsupported or disallowed scope: ${s}`, "invalid_scope");
            }
        }
        return requested;
    }
    /**
     * Validate authorize params. On client/redirect failure, throw (no redirect).
     * On other OAuth errors with a valid redirect, return errorRedirect URL.
     */
    async function validateAuthorizeRequest(req) {
        if (!req.clientId) {
            throw new errors_1.OidcHttpError(400, "invalid_request", "client_id is required.");
        }
        const client = await loadClient(req.clientId);
        if (!client || !client.enabled) {
            throw new errors_1.OidcHttpError(400, "invalid_client", "Unknown or disabled client.");
        }
        if (!req.redirectUri) {
            throw new errors_1.OidcHttpError(400, "invalid_request", "redirect_uri is required.");
        }
        try {
            assertRedirectUri(client, req.redirectUri);
        }
        catch (e) {
            throw e;
        }
        if (req.responseType !== "code") {
            return {
                ok: false,
                errorRedirect: (0, errors_1.oauthErrorRedirect)(req.redirectUri, "unsupported_response_type", "Only response_type=code is supported.", req.state),
            };
        }
        if (req.codeChallenge && req.codeChallengeMethod !== "S256") {
            return {
                ok: false,
                errorRedirect: (0, errors_1.oauthErrorRedirect)(req.redirectUri, "invalid_request", "Only code_challenge_method=S256 is supported.", req.state),
            };
        }
        try {
            const scopes = normalizeScopes((0, claims_1.parseScopeString)(req.scope), client);
            return { ok: true, client, scopes };
        }
        catch (e) {
            if (e instanceof errors_1.OidcHttpError) {
                return {
                    ok: false,
                    errorRedirect: (0, errors_1.oauthErrorRedirect)(req.redirectUri, e.oauthError ?? "invalid_scope", e.message, req.state),
                };
            }
            throw e;
        }
    }
    async function loadConsumerClaims(uid) {
        const [userRecord, snap] = await Promise.all([
            deps.auth().getUser(uid),
            deps.db().doc(`users/${uid}`).get(),
        ]);
        const data = snap.data() ?? {};
        return {
            uid,
            email: userRecord.email ?? data.email ?? null,
            emailVerified: Boolean(userRecord.emailVerified),
            displayName: data.displayName ?? userRecord.displayName ?? null,
            photoUrl: data.photoUrl ?? userRecord.photoURL ?? null,
            phoneCountryCode: data.phoneCountryCode ?? null,
            phoneNumber: data.phoneNumber ?? userRecord.phoneNumber ?? null,
            locale: data.locale ?? null,
            accountStatus: data.accountStatus ?? "active",
        };
    }
    async function mintAuthorizationCode(opts) {
        await consumeRateLimit("authorize_ip", opts.ctx.clientIp || "unknown");
        await consumeRateLimit("authorize_uid", opts.uid);
        await assertActiveConsumer(opts.uid);
        const code = (0, crypto_1.generateAuthCode)();
        const now = Date.now();
        await deps
            .db()
            .collection(constants_1.OIDC_AUTH_CODES_COLLECTION)
            .doc(code)
            .set({
            uid: opts.uid,
            clientId: opts.req.clientId,
            redirectUri: opts.req.redirectUri,
            scope: opts.scopes.join(" "),
            nonce: opts.req.nonce,
            codeChallenge: opts.req.codeChallenge,
            codeChallengeMethod: opts.req.codeChallengeMethod,
            used: false,
            createdAt: firestore_1.FieldValue.serverTimestamp(),
            expiresAt: firestore_1.Timestamp.fromMillis(now + constants_1.AUTH_CODE_TTL_MS),
        });
        const url = new URL(opts.req.redirectUri);
        url.searchParams.set("code", code);
        if (opts.req.state)
            url.searchParams.set("state", opts.req.state);
        return { code, redirectUrl: url.toString() };
    }
    function parseClientAuth(request, body) {
        const header = request.headers.get("authorization");
        if (header?.toLowerCase().startsWith("basic ")) {
            const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
            const idx = decoded.indexOf(":");
            if (idx < 0) {
                throw new errors_1.OidcHttpError(401, "invalid_client", "Invalid client authentication.", "invalid_client");
            }
            return {
                clientId: decodeURIComponent(decoded.slice(0, idx)),
                clientSecret: decodeURIComponent(decoded.slice(idx + 1)),
            };
        }
        return {
            clientId: String(body.get("client_id") ?? "").trim(),
            clientSecret: String(body.get("client_secret") ?? ""),
        };
    }
    async function exchangeAuthorizationCode(ctx, request, body) {
        await consumeRateLimit("token_ip", ctx.clientIp || "unknown");
        const grantType = String(body.get("grant_type") ?? "");
        if (grantType !== "authorization_code") {
            throw new errors_1.OidcHttpError(400, "unsupported_grant_type", "Only authorization_code is supported.", "unsupported_grant_type");
        }
        const { clientId, clientSecret } = parseClientAuth(request, body);
        if (!clientId || !clientSecret) {
            throw new errors_1.OidcHttpError(401, "invalid_client", "Client authentication required.", "invalid_client");
        }
        const client = await loadClient(clientId);
        if (!client || !client.enabled) {
            throw new errors_1.OidcHttpError(401, "invalid_client", "Unknown or disabled client.", "invalid_client");
        }
        if (!(0, crypto_1.verifyClientSecret)(clientSecret, client.secretHash)) {
            throw new errors_1.OidcHttpError(401, "invalid_client", "Invalid client credentials.", "invalid_client");
        }
        const code = String(body.get("code") ?? "").trim();
        const redirectUri = String(body.get("redirect_uri") ?? "").trim();
        const codeVerifier = body.get("code_verifier");
        if (code.length < constants_1.CODE_MIN_LEN ||
            code.length > constants_1.CODE_MAX_LEN ||
            !redirectUri) {
            throw new errors_1.OidcHttpError(400, "invalid_grant", "code and redirect_uri are required.", "invalid_grant");
        }
        await consumeRateLimit("token_code", code);
        const ref = deps.db().collection(constants_1.OIDC_AUTH_CODES_COLLECTION).doc(code);
        const snap = await ref.get();
        if (!snap.exists) {
            throw new errors_1.OidcHttpError(400, "invalid_grant", "Invalid or expired authorization code.", "invalid_grant");
        }
        const data = snap.data() ?? {};
        const expiresAt = data.expiresAt;
        if (data.used === true ||
            !expiresAt ||
            expiresAt.toMillis() < Date.now() ||
            String(data.clientId) !== clientId ||
            String(data.redirectUri) !== redirectUri) {
            throw new errors_1.OidcHttpError(400, "invalid_grant", "Invalid or expired authorization code.", "invalid_grant");
        }
        const storedChallenge = data.codeChallenge
            ? String(data.codeChallenge)
            : null;
        if (storedChallenge) {
            if (!codeVerifier || !(0, crypto_1.verifyPkceS256)(codeVerifier, storedChallenge)) {
                throw new errors_1.OidcHttpError(400, "invalid_grant", "PKCE verification failed.", "invalid_grant");
            }
        }
        const uid = String(data.uid ?? "");
        await assertActiveConsumer(uid);
        await deps.db().runTransaction(async (tx) => {
            const fresh = await tx.get(ref);
            if (!fresh.exists || fresh.data()?.used === true) {
                throw new errors_1.OidcHttpError(400, "invalid_grant", "Invalid or expired authorization code.", "invalid_grant");
            }
            tx.update(ref, {
                used: true,
                usedAt: firestore_1.FieldValue.serverTimestamp(),
            });
        });
        void ref.delete().catch(() => undefined);
        const scope = String(data.scope ?? "openid");
        const scopes = (0, claims_1.parseScopeString)(scope);
        const profile = await loadConsumerClaims(uid);
        const claims = (0, claims_1.buildOidcClaims)(profile, scopes);
        const key = await deps.signingKey();
        const issuer = deps.issuer().replace(/\/$/, "");
        const [id_token, access_token] = await Promise.all([
            (0, crypto_1.signIdToken)({
                key,
                issuer,
                audience: clientId,
                claims,
                nonce: data.nonce ? String(data.nonce) : null,
            }),
            (0, crypto_1.signAccessToken)({
                key,
                issuer,
                audience: clientId,
                uid,
                scope,
                clientId,
            }),
        ]);
        return {
            access_token,
            token_type: "Bearer",
            expires_in: constants_1.ACCESS_TOKEN_TTL_SEC,
            id_token,
            scope,
        };
    }
    async function userInfo(accessToken) {
        const key = await deps.signingKey();
        const issuer = deps.issuer().replace(/\/$/, "");
        let decoded;
        try {
            decoded = await (0, crypto_1.verifyAccessToken)(accessToken, key, issuer);
        }
        catch {
            throw new errors_1.OidcHttpError(401, "invalid_grant", "Invalid access token.", "invalid_token");
        }
        await assertActiveConsumer(decoded.uid);
        const profile = await loadConsumerClaims(decoded.uid);
        return (0, claims_1.buildOidcClaims)(profile, (0, claims_1.parseScopeString)(decoded.scope));
    }
    async function getDiscovery() {
        return discoveryDocument(deps.issuer());
    }
    async function getJwks() {
        const key = await deps.signingKey();
        return { keys: [key.publicJwk] };
    }
    async function getPlatformKid() {
        const key = await deps.signingKey();
        return key.kid;
    }
    // --- Developer + client management ---
    async function getDeveloper(uid) {
        const snap = await deps
            .db()
            .collection(constants_1.DEVELOPERS_COLLECTION)
            .doc(uid)
            .get();
        if (!snap.exists)
            return null;
        const data = snap.data() ?? {};
        return {
            uid,
            email: data.email ?? null,
            displayName: data.displayName ?? null,
            orgName: data.orgName ?? null,
            status: data.status ?? "pending",
            isPlatformAdmin: data.isPlatformAdmin === true,
            createdAt: data.createdAt,
            updatedAt: data.updatedAt,
        };
    }
    async function assertActiveDeveloper(uid) {
        const dev = await getDeveloper(uid);
        if (!dev) {
            throw new errors_1.OidcHttpError(403, "forbidden", "Not a registered developer.");
        }
        if (dev.status === "suspended") {
            throw new errors_1.OidcHttpError(403, "developer_suspended", "Developer account is suspended.");
        }
        if (dev.status !== "active" && dev.status !== "pending") {
            throw new errors_1.OidcHttpError(403, "forbidden", "Developer account not active.");
        }
        return dev;
    }
    async function createDeveloperAccount(opts) {
        const ref = deps.db().collection(constants_1.DEVELOPERS_COLLECTION).doc(opts.uid);
        const existing = await ref.get();
        if (existing.exists) {
            return (await getDeveloper(opts.uid));
        }
        const record = {
            email: opts.email,
            displayName: opts.displayName,
            orgName: opts.orgName ?? null,
            status: "active",
            isPlatformAdmin: false,
            createdAt: firestore_1.FieldValue.serverTimestamp(),
            updatedAt: firestore_1.FieldValue.serverTimestamp(),
        };
        await ref.set(record);
        return {
            uid: opts.uid,
            email: opts.email,
            displayName: opts.displayName,
            orgName: opts.orgName ?? null,
            status: "active",
            isPlatformAdmin: false,
        };
    }
    async function createOidcClient(opts) {
        await assertActiveDeveloper(opts.ownerDeveloperId);
        const name = opts.name.trim();
        if (!name) {
            throw new errors_1.OidcHttpError(400, "invalid_request", "name is required.");
        }
        const redirectUris = opts.redirectUris
            .map((u) => u.trim())
            .filter(Boolean);
        if (redirectUris.length === 0) {
            throw new errors_1.OidcHttpError(400, "invalid_request", "At least one redirect_uri is required.");
        }
        for (const uri of redirectUris) {
            try {
                // eslint-disable-next-line no-new
                new URL(uri);
            }
            catch {
                throw new errors_1.OidcHttpError(400, "invalid_request", `Invalid redirect_uri: ${uri}`);
            }
        }
        const scopes = opts.scopes?.length
            ? opts.scopes.filter((s) => constants_1.SUPPORTED_SCOPES.includes(s))
            : [...constants_1.SUPPORTED_SCOPES];
        if (!scopes.includes("openid"))
            scopes.unshift("openid");
        const clientId = (0, crypto_1.generateClientId)();
        const clientSecret = (0, crypto_1.generateClientSecret)();
        const secretHash = (0, crypto_1.hashClientSecret)(clientSecret);
        const doc = {
            name,
            secretHash,
            redirectUris,
            scopes,
            enabled: true,
            trusted: false,
            ownerDeveloperId: opts.ownerDeveloperId,
            createdAt: firestore_1.FieldValue.serverTimestamp(),
            updatedAt: firestore_1.FieldValue.serverTimestamp(),
        };
        await deps
            .db()
            .collection(constants_1.OIDC_CLIENTS_COLLECTION)
            .doc(clientId)
            .set(doc);
        return {
            client: {
                clientId,
                name,
                secretHash,
                redirectUris,
                scopes,
                enabled: true,
                trusted: false,
                ownerDeveloperId: opts.ownerDeveloperId,
            },
            clientSecret,
        };
    }
    async function listOidcClientsForOwner(ownerDeveloperId) {
        await assertActiveDeveloper(ownerDeveloperId);
        const snap = await deps
            .db()
            .collection(constants_1.OIDC_CLIENTS_COLLECTION)
            .where("ownerDeveloperId", "==", ownerDeveloperId)
            .get();
        return snap.docs.map((d) => {
            const data = d.data();
            return {
                clientId: d.id,
                name: String(data.name ?? ""),
                secretHash: String(data.secretHash ?? ""),
                redirectUris: Array.isArray(data.redirectUris)
                    ? data.redirectUris.map(String)
                    : [],
                scopes: Array.isArray(data.scopes) ? data.scopes.map(String) : [],
                enabled: data.enabled !== false,
                trusted: data.trusted === true,
                ownerDeveloperId: String(data.ownerDeveloperId ?? ""),
                createdAt: data.createdAt,
                updatedAt: data.updatedAt,
            };
        });
    }
    async function listAllOidcClients() {
        const snap = await deps.db().collection(constants_1.OIDC_CLIENTS_COLLECTION).get();
        return snap.docs.map((d) => {
            const data = d.data();
            return {
                clientId: d.id,
                name: String(data.name ?? ""),
                secretHash: String(data.secretHash ?? ""),
                redirectUris: Array.isArray(data.redirectUris)
                    ? data.redirectUris.map(String)
                    : [],
                scopes: Array.isArray(data.scopes) ? data.scopes.map(String) : [],
                enabled: data.enabled !== false,
                trusted: data.trusted === true,
                ownerDeveloperId: String(data.ownerDeveloperId ?? ""),
                createdAt: data.createdAt,
                updatedAt: data.updatedAt,
            };
        });
    }
    async function updateOidcClient(opts) {
        const client = await loadClient(opts.clientId);
        if (!client) {
            throw new errors_1.OidcHttpError(404, "not_found", "Client not found.");
        }
        if (!opts.asPlatformAdmin &&
            client.ownerDeveloperId !== opts.actorDeveloperId) {
            throw new errors_1.OidcHttpError(403, "forbidden", "Not the owner of this client.");
        }
        if (!opts.asPlatformAdmin) {
            await assertActiveDeveloper(opts.actorDeveloperId);
        }
        const patch = {
            updatedAt: firestore_1.FieldValue.serverTimestamp(),
        };
        if (opts.name !== undefined)
            patch.name = opts.name.trim();
        if (opts.redirectUris !== undefined) {
            patch.redirectUris = opts.redirectUris.map((u) => u.trim()).filter(Boolean);
        }
        if (opts.scopes !== undefined) {
            const scopes = opts.scopes.filter((s) => constants_1.SUPPORTED_SCOPES.includes(s));
            if (!scopes.includes("openid"))
                scopes.unshift("openid");
            patch.scopes = scopes;
        }
        if (opts.enabled !== undefined)
            patch.enabled = opts.enabled;
        if (opts.trusted !== undefined) {
            if (!opts.asPlatformAdmin) {
                throw new errors_1.OidcHttpError(403, "forbidden", "Only platform admins can set trusted.");
            }
            patch.trusted = opts.trusted;
        }
        await deps
            .db()
            .collection(constants_1.OIDC_CLIENTS_COLLECTION)
            .doc(opts.clientId)
            .update(patch);
        return (await loadClient(opts.clientId));
    }
    async function rotateClientSecret(opts) {
        const client = await loadClient(opts.clientId);
        if (!client) {
            throw new errors_1.OidcHttpError(404, "not_found", "Client not found.");
        }
        if (!opts.asPlatformAdmin &&
            client.ownerDeveloperId !== opts.actorDeveloperId) {
            throw new errors_1.OidcHttpError(403, "forbidden", "Not the owner of this client.");
        }
        if (!opts.asPlatformAdmin) {
            await assertActiveDeveloper(opts.actorDeveloperId);
        }
        const clientSecret = (0, crypto_1.generateClientSecret)();
        await deps
            .db()
            .collection(constants_1.OIDC_CLIENTS_COLLECTION)
            .doc(opts.clientId)
            .update({
            secretHash: (0, crypto_1.hashClientSecret)(clientSecret),
            updatedAt: firestore_1.FieldValue.serverTimestamp(),
        });
        return { clientSecret };
    }
    async function setDeveloperStatus(opts) {
        await deps
            .db()
            .collection(constants_1.DEVELOPERS_COLLECTION)
            .doc(opts.targetUid)
            .update({
            status: opts.status,
            updatedAt: firestore_1.FieldValue.serverTimestamp(),
        });
    }
    async function listDevelopers() {
        const snap = await deps.db().collection(constants_1.DEVELOPERS_COLLECTION).get();
        return snap.docs.map((d) => {
            const data = d.data();
            return {
                uid: d.id,
                email: data.email ?? null,
                displayName: data.displayName ?? null,
                orgName: data.orgName ?? null,
                status: data.status ?? "pending",
                isPlatformAdmin: data.isPlatformAdmin === true,
                createdAt: data.createdAt,
                updatedAt: data.updatedAt,
            };
        });
    }
    return {
        getDiscovery,
        getJwks,
        getPlatformKid,
        parseAuthorizeQuery,
        validateAuthorizeRequest,
        mintAuthorizationCode,
        exchangeAuthorizationCode,
        userInfo,
        loadClient,
        loadConsumerClaims,
        getDeveloper,
        createDeveloperAccount,
        assertActiveDeveloper,
        createOidcClient,
        listOidcClientsForOwner,
        listAllOidcClients,
        updateOidcClient,
        rotateClientSecret,
        setDeveloperStatus,
        listDevelopers,
        OidcHttpError: errors_1.OidcHttpError,
    };
}
var crypto_2 = require("./crypto");
Object.defineProperty(exports, "loadSigningKeyFromEnv", { enumerable: true, get: function () { return crypto_2.loadSigningKeyFromEnv; } });
Object.defineProperty(exports, "generateOidcKeyPair", { enumerable: true, get: function () { return crypto_2.generateOidcKeyPair; } });
Object.defineProperty(exports, "hashClientSecret", { enumerable: true, get: function () { return crypto_2.hashClientSecret; } });
Object.defineProperty(exports, "verifyClientSecret", { enumerable: true, get: function () { return crypto_2.verifyClientSecret; } });
Object.defineProperty(exports, "verifyPkceS256", { enumerable: true, get: function () { return crypto_2.verifyPkceS256; } });
var constants_2 = require("./constants");
Object.defineProperty(exports, "SUPPORTED_SCOPES", { enumerable: true, get: function () { return constants_2.SUPPORTED_SCOPES; } });
Object.defineProperty(exports, "OIDC_CLIENTS_COLLECTION", { enumerable: true, get: function () { return constants_2.OIDC_CLIENTS_COLLECTION; } });
Object.defineProperty(exports, "DEVELOPERS_COLLECTION", { enumerable: true, get: function () { return constants_2.DEVELOPERS_COLLECTION; } });
var claims_2 = require("./claims");
Object.defineProperty(exports, "buildOidcClaims", { enumerable: true, get: function () { return claims_2.buildOidcClaims; } });
Object.defineProperty(exports, "parseScopeString", { enumerable: true, get: function () { return claims_2.parseScopeString; } });
