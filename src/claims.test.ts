import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  buildOidcClaims,
  buildPhoneNumber,
  parseScopeString,
  splitDisplayName,
} from "./claims";
import {
  generateOidcKeyPair,
  hashClientSecret,
  loadSigningKeyFromEnv,
  signAccessToken,
  signIdToken,
  verifyAccessToken,
  verifyClientSecret,
  verifyPkceS256,
} from "./crypto";

describe("splitDisplayName", () => {
  it("splits first and rest", () => {
    expect(splitDisplayName("Ada Lovelace")).toEqual({
      given_name: "Ada",
      family_name: "Lovelace",
      name: "Ada Lovelace",
    });
  });

  it("falls back when empty", () => {
    expect(splitDisplayName("")).toEqual({
      given_name: "User",
      family_name: "",
      name: "User",
    });
  });
});

describe("buildOidcClaims", () => {
  it("includes required Thinkific-style claims for profile+email", () => {
    const claims = buildOidcClaims(
      {
        uid: "u1",
        email: "a@example.com",
        emailVerified: true,
        displayName: "Jane Doe",
        photoUrl: "https://example.com/p.png",
      },
      ["openid", "profile", "email"],
    );
    expect(claims.sub).toBe("u1");
    expect(claims.email).toBe("a@example.com");
    expect(claims.email_verified).toBe(true);
    expect(claims.given_name).toBe("Jane");
    expect(claims.family_name).toBe("Doe");
  });

  it("builds phone when scope present", () => {
    expect(buildPhoneNumber("1", "5551234567")).toBe("+15551234567");
    const claims = buildOidcClaims(
      {
        uid: "u1",
        phoneCountryCode: "1",
        phoneNumber: "5551234567",
      },
      ["openid", "phone"],
    );
    expect(claims.phone_number).toBe("+15551234567");
  });
});

describe("parseScopeString", () => {
  it("dedupes and splits", () => {
    expect(parseScopeString("openid email openid")).toEqual([
      "openid",
      "email",
    ]);
  });
});

describe("client secret hashing", () => {
  it("verifies matching secrets", () => {
    const secret = "super-secret-value-1234567890";
    const hash = hashClientSecret(secret);
    expect(verifyClientSecret(secret, hash)).toBe(true);
    expect(verifyClientSecret("wrong", hash)).toBe(false);
  });
});

describe("PKCE S256", () => {
  it("verifies challenge", () => {
    const verifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
    const challenge = createHash("sha256")
      .update(verifier)
      .digest("base64url");
    expect(verifyPkceS256(verifier, challenge)).toBe(true);
    expect(verifyPkceS256("nope", challenge)).toBe(false);
  });
});

describe("JWT signing", () => {
  it("round-trips id and access tokens", async () => {
    const pair = await generateOidcKeyPair();
    const key = await loadSigningKeyFromEnv(JSON.stringify(pair.privateJwk));
    expect(key).not.toBeNull();
    const issuer = "https://pulse.example";
    const idToken = await signIdToken({
      key: key!,
      issuer,
      audience: "client1",
      claims: { sub: "uid1", email: "a@b.co", email_verified: true },
      nonce: "n1",
    });
    const access = await signAccessToken({
      key: key!,
      issuer,
      audience: "client1",
      uid: "uid1",
      scope: "openid email",
      clientId: "client1",
    });
    const decoded = await verifyAccessToken(access, key!, issuer);
    expect(decoded.uid).toBe("uid1");
    expect(decoded.scope).toBe("openid email");
    expect(idToken.split(".")).toHaveLength(3);
  });
});
