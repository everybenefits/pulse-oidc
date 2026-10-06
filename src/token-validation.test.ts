import { beforeAll, describe, expect, it, vi } from "vitest";
import {
  generateOidcKeyPair, loadSigningKeyFromEnv, signAccessToken,
  signIdToken, verifyAccessToken, type SigningKeyMaterial,
} from "./crypto";
import { createOidcServer } from "./server";

describe("access token validation", () => {
  let key: SigningKeyMaterial;
  const issuer = "https://review.invalid";
  beforeAll(async () => {
    const pair = await generateOidcKeyPair();
    key = (await loadSigningKeyFromEnv(JSON.stringify(pair.privateJwk)))!;
  });
  it("accepts a platform access token", async () => {
    const token = await signAccessToken({ key, issuer, audience: "client-a", clientId: "client-a", uid: "user-a", scope: "openid profile" });
    await expect(verifyAccessToken(token, key, issuer)).resolves.toEqual({ uid: "user-a", scope: "openid profile", clientId: "client-a" });
  });
  it("rejects an ID token signed by the same platform key", async () => {
    const token = await signIdToken({ key, issuer, audience: "client-a", claims: { sub: "user-a" } });
    await expect(verifyAccessToken(token, key, issuer)).rejects.toThrow();
  });
  it("rejects an access token with a different audience", async () => {
    const token = await signAccessToken({ key, issuer, audience: "client-b", clientId: "client-a", uid: "user-a", scope: "openid" });
    await expect(verifyAccessToken(token, key, issuer)).rejects.toThrow();
  });
});

describe("untrusted Firestore IDs", () => {
  const db = vi.fn(() => { throw new Error("Firestore must not receive malformed IDs"); });
  const server = createOidcServer({ db, auth: () => ({}) as never, issuer: () => "https://review.invalid", signingKey: async () => ({}) as never });
  it.each(["a/b", ".", "..", "__reserved__", "x".repeat(1501)])("treats malformed client ID %s as unknown", async (clientId) => {
    await expect(server.loadClient(clientId)).resolves.toBeNull();
    expect(db).not.toHaveBeenCalled();
  });
});
