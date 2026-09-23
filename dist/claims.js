"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.splitDisplayName = splitDisplayName;
exports.buildPhoneNumber = buildPhoneNumber;
exports.buildOidcClaims = buildOidcClaims;
exports.parseScopeString = parseScopeString;
function splitDisplayName(displayName) {
    const trimmed = (displayName ?? "").trim();
    if (!trimmed) {
        return { given_name: "User", family_name: "", name: "User" };
    }
    const parts = trimmed.split(/\s+/);
    const given_name = parts[0] ?? "User";
    const family_name = parts.length > 1 ? parts.slice(1).join(" ") : "";
    return { given_name, family_name, name: trimmed };
}
function buildPhoneNumber(countryCode, number) {
    const n = (number ?? "").trim();
    if (!n)
        return undefined;
    const cc = (countryCode ?? "").trim().replace(/^\+/, "");
    if (!cc)
        return n.startsWith("+") ? n : undefined;
    return `+${cc}${n.replace(/^\+/, "")}`;
}
/** Build ID token / userinfo claims from Firebase Auth + users/{uid}. */
function buildOidcClaims(profile, scopes) {
    const scopeSet = new Set(scopes);
    const claims = {
        sub: profile.uid,
    };
    if (scopeSet.has("email") || scopeSet.has("openid")) {
        if (profile.email)
            claims.email = profile.email;
        claims.email_verified = Boolean(profile.emailVerified);
    }
    if (scopeSet.has("profile")) {
        const names = splitDisplayName(profile.displayName);
        claims.name = names.name;
        claims.given_name = names.given_name;
        claims.family_name = names.family_name;
        if (profile.photoUrl)
            claims.picture = profile.photoUrl;
        if (profile.locale)
            claims.locale = profile.locale;
    }
    if (scopeSet.has("phone")) {
        const phone = buildPhoneNumber(profile.phoneCountryCode, profile.phoneNumber);
        if (phone)
            claims.phone_number = phone;
    }
    return claims;
}
function parseScopeString(scope) {
    if (!scope?.trim())
        return [];
    return [...new Set(scope.trim().split(/\s+/).filter(Boolean))];
}
