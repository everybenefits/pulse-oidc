import { createHash } from "node:crypto";
import { FieldValue, Timestamp, type Firestore } from "firebase-admin/firestore";
import type { Auth } from "firebase-admin/auth";
import {
  AUTH_CODE_TTL_MS,
  CODE_MAX_LEN,
  CODE_MIN_LEN,
  DEVELOPERS_COLLECTION,
  MAX_OIDC_PER_MINUTE,
  OIDC_AUTH_CODES_COLLECTION,
  OIDC_CLIENTS_COLLECTION,
  OIDC_RATE_LIMIT_COLLECTION,
  SUPPORTED_SCOPES,
  ACCESS_TOKEN_TTL_SEC,
} from "./constants";
import { buildOidcClaims, parseScopeString } from "./claims";
import { OidcHttpError, oauthErrorRedirect } from "./errors";
import {
  generateAuthCode,
  generateClientId,
  generateClientSecret,
  hashClientSecret,
  signAccessToken,
  signIdToken,
  verifyAccessToken,
  verifyClientSecret,
  verifyPkceS256,
  type SigningKeyMaterial,
} from "./crypto";
import type {
  AuthorizeRequest,
  DeveloperRecord,
  OidcClientRecord,
  TokenSuccess,
  UserProfileClaimsSource,
} from "./types";

export type OidcServerDeps = {
  auth: () => Auth;
  db: () => Firestore;
  issuer: () => string;
  signingKey: () => Promise<SigningKeyMaterial>;
};

export type OidcRequestContext = {
  clientIp?: string;
};

function clientIpFromRequest(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) return first;
  }
  return request.headers.get("x-real-ip")?.trim() || "unknown";
}

export function contextFromRequest(request: Request): OidcRequestContext {
  return { clientIp: clientIpFromRequest(request) };
}

export function rateLimitDocId(bucket: string, identity: string): string {
  const hash = createHash("sha256").update(identity).digest("hex").slice(0, 32);
  const minute = Math.floor(Date.now() / 60_000);
  return `${bucket}_${hash}_${minute}`;
}

export function parseAuthorizeQuery(
  searchParams: URLSearchParams,
): AuthorizeRequest {
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

function discoveryDocument(issuer: string) {
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
    scopes_supported: [...SUPPORTED_SCOPES],
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

export function createOidcServer(deps: OidcServerDeps) {
  async function consumeRateLimit(
    bucket: string,
    identity: string,
  ): Promise<void> {
    const minute = Math.floor(Date.now() / 60_000);
    const id = rateLimitDocId(bucket, identity);
    const ref = deps.db().doc(`${OIDC_RATE_LIMIT_COLLECTION}/${id}`);
    await deps.db().runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      const count = Number(snap.data()?.count ?? 0);
      if (count >= MAX_OIDC_PER_MINUTE) {
        throw new OidcHttpError(
          429,
          "rate_limited",
          "Too many OIDC requests.",
          "temporarily_unavailable",
        );
      }
      tx.set(
        ref,
        {
          bucket,
          minute,
          count: count + 1,
          expiresAt: Timestamp.fromMillis((minute + 2) * 60_000),
        },
        { merge: true },
      );
    });
  }

  async function assertActiveConsumer(uid: string): Promise<void> {
    const snap = await deps.db().doc(`users/${uid}`).get();
    const status = String(snap.data()?.accountStatus ?? "active");
    if (status === "deactivated" || status === "pendingDeletion") {
      throw new OidcHttpError(
        403,
        "account_disabled",
        "Account is deactivated or pending deletion.",
        "access_denied",
      );
    }
  }

  async function loadClient(
    clientId: string,
  ): Promise<OidcClientRecord | null> {
    const snap = await deps
      .db()
      .collection(OIDC_CLIENTS_COLLECTION)
      .doc(clientId)
      .get();
    if (!snap.exists) return null;
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
        : [...SUPPORTED_SCOPES],
      enabled: data.enabled !== false,
      trusted: data.trusted === true,
      ownerDeveloperId: String(data.ownerDeveloperId ?? ""),
      createdAt: data.createdAt,
      updatedAt: data.updatedAt,
    };
  }

  function assertRedirectUri(
    client: OidcClientRecord,
    redirectUri: string,
  ): void {
    if (!client.redirectUris.includes(redirectUri)) {
      throw new OidcHttpError(
        400,
        "invalid_request",
        "redirect_uri is not registered for this client.",
      );
    }
  }

  function normalizeScopes(
    requested: string[],
    client: OidcClientRecord,
  ): string[] {
    if (!requested.includes("openid")) {
      throw new OidcHttpError(
        400,
        "invalid_scope",
        "scope must include openid.",
        "invalid_scope",
      );
    }
    const allowed = new Set(client.scopes);
    const supported = new Set<string>(SUPPORTED_SCOPES);
    for (const s of requested) {
      if (!supported.has(s) || !allowed.has(s)) {
        throw new OidcHttpError(
          400,
          "invalid_scope",
          `Unsupported or disallowed scope: ${s}`,
          "invalid_scope",
        );
      }
    }
    return requested;
  }

  /**
   * Validate authorize params. On client/redirect failure, throw (no redirect).
   * On other OAuth errors with a valid redirect, return errorRedirect URL.
   */
  async function validateAuthorizeRequest(req: AuthorizeRequest): Promise<
    | { ok: true; client: OidcClientRecord; scopes: string[] }
    | { ok: false; errorRedirect: string }
  > {
    if (!req.clientId) {
      throw new OidcHttpError(400, "invalid_request", "client_id is required.");
    }
    const client = await loadClient(req.clientId);
    if (!client || !client.enabled) {
      throw new OidcHttpError(400, "invalid_client", "Unknown or disabled client.");
    }
    if (!req.redirectUri) {
      throw new OidcHttpError(400, "invalid_request", "redirect_uri is required.");
    }
    try {
      assertRedirectUri(client, req.redirectUri);
    } catch (e) {
      throw e;
    }

    if (req.responseType !== "code") {
      return {
        ok: false,
        errorRedirect: oauthErrorRedirect(
          req.redirectUri,
          "unsupported_response_type",
          "Only response_type=code is supported.",
          req.state,
        ),
      };
    }

    if (req.codeChallenge && req.codeChallengeMethod !== "S256") {
      return {
        ok: false,
        errorRedirect: oauthErrorRedirect(
          req.redirectUri,
          "invalid_request",
          "Only code_challenge_method=S256 is supported.",
          req.state,
        ),
      };
    }

    try {
      const scopes = normalizeScopes(parseScopeString(req.scope), client);
      return { ok: true, client, scopes };
    } catch (e) {
      if (e instanceof OidcHttpError) {
        return {
          ok: false,
          errorRedirect: oauthErrorRedirect(
            req.redirectUri,
            e.oauthError ?? "invalid_scope",
            e.message,
            req.state,
          ),
        };
      }
      throw e;
    }
  }

  async function loadConsumerClaims(
    uid: string,
  ): Promise<UserProfileClaimsSource> {
    const [userRecord, snap] = await Promise.all([
      deps.auth().getUser(uid),
      deps.db().doc(`users/${uid}`).get(),
    ]);
    const data = snap.data() ?? {};
    return {
      uid,
      email: userRecord.email ?? (data.email as string | null) ?? null,
      emailVerified: Boolean(userRecord.emailVerified),
      displayName:
        (data.displayName as string | null) ?? userRecord.displayName ?? null,
      photoUrl:
        (data.photoUrl as string | null) ?? userRecord.photoURL ?? null,
      phoneCountryCode: (data.phoneCountryCode as string | null) ?? null,
      phoneNumber:
        (data.phoneNumber as string | null) ?? userRecord.phoneNumber ?? null,
      locale: (data.locale as string | null) ?? null,
      accountStatus: (data.accountStatus as string | null) ?? "active",
    };
  }

  async function mintAuthorizationCode(opts: {
    ctx: OidcRequestContext;
    uid: string;
    req: AuthorizeRequest;
    scopes: string[];
  }): Promise<{ code: string; redirectUrl: string }> {
    await consumeRateLimit("authorize_ip", opts.ctx.clientIp || "unknown");
    await consumeRateLimit("authorize_uid", opts.uid);
    await assertActiveConsumer(opts.uid);

    const code = generateAuthCode();
    const now = Date.now();
    await deps
      .db()
      .collection(OIDC_AUTH_CODES_COLLECTION)
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
        createdAt: FieldValue.serverTimestamp(),
        expiresAt: Timestamp.fromMillis(now + AUTH_CODE_TTL_MS),
      });

    const url = new URL(opts.req.redirectUri);
    url.searchParams.set("code", code);
    if (opts.req.state) url.searchParams.set("state", opts.req.state);
    return { code, redirectUrl: url.toString() };
  }

  function parseClientAuth(request: Request, body: URLSearchParams): {
    clientId: string;
    clientSecret: string;
  } {
    const header = request.headers.get("authorization");
    if (header?.toLowerCase().startsWith("basic ")) {
      const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
      const idx = decoded.indexOf(":");
      if (idx < 0) {
        throw new OidcHttpError(
          401,
          "invalid_client",
          "Invalid client authentication.",
          "invalid_client",
        );
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

  async function exchangeAuthorizationCode(
    ctx: OidcRequestContext,
    request: Request,
    body: URLSearchParams,
  ): Promise<TokenSuccess> {
    await consumeRateLimit("token_ip", ctx.clientIp || "unknown");

    const grantType = String(body.get("grant_type") ?? "");
    if (grantType !== "authorization_code") {
      throw new OidcHttpError(
        400,
        "unsupported_grant_type",
        "Only authorization_code is supported.",
        "unsupported_grant_type",
      );
    }

    const { clientId, clientSecret } = parseClientAuth(request, body);
    if (!clientId || !clientSecret) {
      throw new OidcHttpError(
        401,
        "invalid_client",
        "Client authentication required.",
        "invalid_client",
      );
    }

    const client = await loadClient(clientId);
    if (!client || !client.enabled) {
      throw new OidcHttpError(
        401,
        "invalid_client",
        "Unknown or disabled client.",
        "invalid_client",
      );
    }
    if (!verifyClientSecret(clientSecret, client.secretHash)) {
      throw new OidcHttpError(
        401,
        "invalid_client",
        "Invalid client credentials.",
        "invalid_client",
      );
    }

    const code = String(body.get("code") ?? "").trim();
    const redirectUri = String(body.get("redirect_uri") ?? "").trim();
    const codeVerifier = body.get("code_verifier");

    if (
      code.length < CODE_MIN_LEN ||
      code.length > CODE_MAX_LEN ||
      !redirectUri
    ) {
      throw new OidcHttpError(
        400,
        "invalid_grant",
        "code and redirect_uri are required.",
        "invalid_grant",
      );
    }

    await consumeRateLimit("token_code", code);

    const ref = deps.db().collection(OIDC_AUTH_CODES_COLLECTION).doc(code);
    const snap = await ref.get();
    if (!snap.exists) {
      throw new OidcHttpError(
        400,
        "invalid_grant",
        "Invalid or expired authorization code.",
        "invalid_grant",
      );
    }
    const data = snap.data() ?? {};
    const expiresAt = data.expiresAt as Timestamp | undefined;
    if (
      data.used === true ||
      !expiresAt ||
      expiresAt.toMillis() < Date.now() ||
      String(data.clientId) !== clientId ||
      String(data.redirectUri) !== redirectUri
    ) {
      throw new OidcHttpError(
        400,
        "invalid_grant",
        "Invalid or expired authorization code.",
        "invalid_grant",
      );
    }

    const storedChallenge = data.codeChallenge
      ? String(data.codeChallenge)
      : null;
    if (storedChallenge) {
      if (!codeVerifier || !verifyPkceS256(codeVerifier, storedChallenge)) {
        throw new OidcHttpError(
          400,
          "invalid_grant",
          "PKCE verification failed.",
          "invalid_grant",
        );
      }
    }

    const uid = String(data.uid ?? "");
    await assertActiveConsumer(uid);

    await deps.db().runTransaction(async (tx) => {
      const fresh = await tx.get(ref);
      if (!fresh.exists || fresh.data()?.used === true) {
        throw new OidcHttpError(
          400,
          "invalid_grant",
          "Invalid or expired authorization code.",
          "invalid_grant",
        );
      }
      tx.update(ref, {
        used: true,
        usedAt: FieldValue.serverTimestamp(),
      });
    });
    void ref.delete().catch(() => undefined);

    const scope = String(data.scope ?? "openid");
    const scopes = parseScopeString(scope);
    const profile = await loadConsumerClaims(uid);
    const claims = buildOidcClaims(profile, scopes);
    const key = await deps.signingKey();
    const issuer = deps.issuer().replace(/\/$/, "");

    const [id_token, access_token] = await Promise.all([
      signIdToken({
        key,
        issuer,
        audience: clientId,
        claims,
        nonce: data.nonce ? String(data.nonce) : null,
      }),
      signAccessToken({
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
      expires_in: ACCESS_TOKEN_TTL_SEC,
      id_token,
      scope,
    };
  }

  async function userInfo(
    accessToken: string,
  ): Promise<Record<string, string | boolean | number>> {
    const key = await deps.signingKey();
    const issuer = deps.issuer().replace(/\/$/, "");
    let decoded: { uid: string; scope: string; clientId: string };
    try {
      decoded = await verifyAccessToken(accessToken, key, issuer);
    } catch {
      throw new OidcHttpError(
        401,
        "invalid_grant",
        "Invalid access token.",
        "invalid_token",
      );
    }
    await assertActiveConsumer(decoded.uid);
    const profile = await loadConsumerClaims(decoded.uid);
    return buildOidcClaims(profile, parseScopeString(decoded.scope));
  }

  async function getDiscovery() {
    return discoveryDocument(deps.issuer());
  }

  async function getJwks() {
    const key = await deps.signingKey();
    return { keys: [key.publicJwk] };
  }

  async function getPlatformKid(): Promise<string> {
    const key = await deps.signingKey();
    return key.kid;
  }

  // --- Developer + client management ---

  async function getDeveloper(uid: string): Promise<DeveloperRecord | null> {
    const snap = await deps
      .db()
      .collection(DEVELOPERS_COLLECTION)
      .doc(uid)
      .get();
    if (!snap.exists) return null;
    const data = snap.data() ?? {};
    return {
      uid,
      email: (data.email as string | null) ?? null,
      displayName: (data.displayName as string | null) ?? null,
      orgName: (data.orgName as string | null) ?? null,
      status: (data.status as DeveloperRecord["status"]) ?? "pending",
      isPlatformAdmin: data.isPlatformAdmin === true,
      createdAt: data.createdAt,
      updatedAt: data.updatedAt,
    };
  }

  async function assertActiveDeveloper(uid: string): Promise<DeveloperRecord> {
    const dev = await getDeveloper(uid);
    if (!dev) {
      throw new OidcHttpError(403, "forbidden", "Not a registered developer.");
    }
    if (dev.status === "suspended") {
      throw new OidcHttpError(
        403,
        "developer_suspended",
        "Developer account is suspended.",
      );
    }
    if (dev.status !== "active" && dev.status !== "pending") {
      throw new OidcHttpError(403, "forbidden", "Developer account not active.");
    }
    return dev;
  }

  async function createDeveloperAccount(opts: {
    uid: string;
    email: string | null;
    displayName: string | null;
    orgName?: string | null;
  }): Promise<DeveloperRecord> {
    const ref = deps.db().collection(DEVELOPERS_COLLECTION).doc(opts.uid);
    const existing = await ref.get();
    if (existing.exists) {
      return (await getDeveloper(opts.uid))!;
    }
    const record = {
      email: opts.email,
      displayName: opts.displayName,
      orgName: opts.orgName ?? null,
      status: "active" as const,
      isPlatformAdmin: false,
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
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

  async function createOidcClient(opts: {
    ownerDeveloperId: string;
    name: string;
    redirectUris: string[];
    scopes?: string[];
  }): Promise<{ client: OidcClientRecord; clientSecret: string }> {
    await assertActiveDeveloper(opts.ownerDeveloperId);
    const name = opts.name.trim();
    if (!name) {
      throw new OidcHttpError(400, "invalid_request", "name is required.");
    }
    const redirectUris = opts.redirectUris
      .map((u) => u.trim())
      .filter(Boolean);
    if (redirectUris.length === 0) {
      throw new OidcHttpError(
        400,
        "invalid_request",
        "At least one redirect_uri is required.",
      );
    }
    for (const uri of redirectUris) {
      try {
        // eslint-disable-next-line no-new
        new URL(uri);
      } catch {
        throw new OidcHttpError(
          400,
          "invalid_request",
          `Invalid redirect_uri: ${uri}`,
        );
      }
    }

    const scopes = opts.scopes?.length
      ? opts.scopes.filter((s) =>
          (SUPPORTED_SCOPES as readonly string[]).includes(s),
        )
      : [...SUPPORTED_SCOPES];
    if (!scopes.includes("openid")) scopes.unshift("openid");

    const clientId = generateClientId();
    const clientSecret = generateClientSecret();
    const secretHash = hashClientSecret(clientSecret);
    const doc = {
      name,
      secretHash,
      redirectUris,
      scopes,
      enabled: true,
      trusted: false,
      ownerDeveloperId: opts.ownerDeveloperId,
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    };
    await deps
      .db()
      .collection(OIDC_CLIENTS_COLLECTION)
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

  async function listOidcClientsForOwner(
    ownerDeveloperId: string,
  ): Promise<OidcClientRecord[]> {
    await assertActiveDeveloper(ownerDeveloperId);
    const snap = await deps
      .db()
      .collection(OIDC_CLIENTS_COLLECTION)
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

  async function listAllOidcClients(): Promise<OidcClientRecord[]> {
    const snap = await deps.db().collection(OIDC_CLIENTS_COLLECTION).get();
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

  async function updateOidcClient(opts: {
    clientId: string;
    actorDeveloperId: string;
    asPlatformAdmin?: boolean;
    name?: string;
    redirectUris?: string[];
    scopes?: string[];
    enabled?: boolean;
    trusted?: boolean;
  }): Promise<OidcClientRecord> {
    const client = await loadClient(opts.clientId);
    if (!client) {
      throw new OidcHttpError(404, "not_found", "Client not found.");
    }
    if (
      !opts.asPlatformAdmin &&
      client.ownerDeveloperId !== opts.actorDeveloperId
    ) {
      throw new OidcHttpError(403, "forbidden", "Not the owner of this client.");
    }
    if (!opts.asPlatformAdmin) {
      await assertActiveDeveloper(opts.actorDeveloperId);
    }

    const patch: Record<string, unknown> = {
      updatedAt: FieldValue.serverTimestamp(),
    };
    if (opts.name !== undefined) patch.name = opts.name.trim();
    if (opts.redirectUris !== undefined) {
      patch.redirectUris = opts.redirectUris.map((u) => u.trim()).filter(Boolean);
    }
    if (opts.scopes !== undefined) {
      const scopes = opts.scopes.filter((s) =>
        (SUPPORTED_SCOPES as readonly string[]).includes(s),
      );
      if (!scopes.includes("openid")) scopes.unshift("openid");
      patch.scopes = scopes;
    }
    if (opts.enabled !== undefined) patch.enabled = opts.enabled;
    if (opts.trusted !== undefined) {
      if (!opts.asPlatformAdmin) {
        throw new OidcHttpError(
          403,
          "forbidden",
          "Only platform admins can set trusted.",
        );
      }
      patch.trusted = opts.trusted;
    }

    await deps
      .db()
      .collection(OIDC_CLIENTS_COLLECTION)
      .doc(opts.clientId)
      .update(patch);

    return (await loadClient(opts.clientId))!;
  }

  async function rotateClientSecret(opts: {
    clientId: string;
    actorDeveloperId: string;
    asPlatformAdmin?: boolean;
  }): Promise<{ clientSecret: string }> {
    const client = await loadClient(opts.clientId);
    if (!client) {
      throw new OidcHttpError(404, "not_found", "Client not found.");
    }
    if (
      !opts.asPlatformAdmin &&
      client.ownerDeveloperId !== opts.actorDeveloperId
    ) {
      throw new OidcHttpError(403, "forbidden", "Not the owner of this client.");
    }
    if (!opts.asPlatformAdmin) {
      await assertActiveDeveloper(opts.actorDeveloperId);
    }
    const clientSecret = generateClientSecret();
    await deps
      .db()
      .collection(OIDC_CLIENTS_COLLECTION)
      .doc(opts.clientId)
      .update({
        secretHash: hashClientSecret(clientSecret),
        updatedAt: FieldValue.serverTimestamp(),
      });
    return { clientSecret };
  }

  async function setDeveloperStatus(opts: {
    targetUid: string;
    status: DeveloperRecord["status"];
  }): Promise<void> {
    await deps
      .db()
      .collection(DEVELOPERS_COLLECTION)
      .doc(opts.targetUid)
      .update({
        status: opts.status,
        updatedAt: FieldValue.serverTimestamp(),
      });
  }

  async function listDevelopers(): Promise<DeveloperRecord[]> {
    const snap = await deps.db().collection(DEVELOPERS_COLLECTION).get();
    return snap.docs.map((d) => {
      const data = d.data();
      return {
        uid: d.id,
        email: (data.email as string | null) ?? null,
        displayName: (data.displayName as string | null) ?? null,
        orgName: (data.orgName as string | null) ?? null,
        status: (data.status as DeveloperRecord["status"]) ?? "pending",
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
    OidcHttpError,
  };
}

export type OidcServer = ReturnType<typeof createOidcServer>;

export { OidcHttpError, oauthErrorRedirect };
export { parseAuthorizeQuery as parseAuthorizeSearchParams };
export {
  loadSigningKeyFromEnv,
  generateOidcKeyPair,
  hashClientSecret,
  verifyClientSecret,
  verifyPkceS256,
} from "./crypto";
export type { SigningKeyMaterial } from "./crypto";
export type { AuthorizeRequest, OidcClientRecord, DeveloperRecord } from "./types";
export {
  SUPPORTED_SCOPES,
  OIDC_CLIENTS_COLLECTION,
  DEVELOPERS_COLLECTION,
} from "./constants";
export { buildOidcClaims, parseScopeString } from "./claims";
