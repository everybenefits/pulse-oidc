import type { UserProfileClaimsSource } from "./types";

export function splitDisplayName(displayName: string | null | undefined): {
  given_name: string;
  family_name: string;
  name: string;
} {
  const trimmed = (displayName ?? "").trim();
  if (!trimmed) {
    return { given_name: "User", family_name: "", name: "User" };
  }
  const parts = trimmed.split(/\s+/);
  const given_name = parts[0] ?? "User";
  const family_name = parts.length > 1 ? parts.slice(1).join(" ") : "";
  return { given_name, family_name, name: trimmed };
}

export function buildPhoneNumber(
  countryCode: string | null | undefined,
  number: string | null | undefined,
): string | undefined {
  const n = (number ?? "").trim();
  if (!n) return undefined;
  const cc = (countryCode ?? "").trim().replace(/^\+/, "");
  if (!cc) return n.startsWith("+") ? n : undefined;
  return `+${cc}${n.replace(/^\+/, "")}`;
}

/** Build ID token / userinfo claims from Firebase Auth + users/{uid}. */
export function buildOidcClaims(
  profile: UserProfileClaimsSource,
  scopes: string[],
): Record<string, string | boolean | number> {
  const scopeSet = new Set(scopes);
  const claims: Record<string, string | boolean | number> = {
    sub: profile.uid,
  };

  if (scopeSet.has("email") || scopeSet.has("openid")) {
    if (profile.email) claims.email = profile.email;
    claims.email_verified = Boolean(profile.emailVerified);
  }

  if (scopeSet.has("profile")) {
    const names = splitDisplayName(profile.displayName);
    claims.name = names.name;
    claims.given_name = names.given_name;
    claims.family_name = names.family_name;
    if (profile.photoUrl) claims.picture = profile.photoUrl;
    if (profile.locale) claims.locale = profile.locale;
  }

  if (scopeSet.has("phone")) {
    const phone = buildPhoneNumber(
      profile.phoneCountryCode,
      profile.phoneNumber,
    );
    if (phone) claims.phone_number = phone;
  }

  return claims;
}

export function parseScopeString(scope: string | null | undefined): string[] {
  if (!scope?.trim()) return [];
  return [...new Set(scope.trim().split(/\s+/).filter(Boolean))];
}
