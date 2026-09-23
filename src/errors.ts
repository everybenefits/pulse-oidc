import type { OidcErrorCode } from "./types";

export class OidcHttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: OidcErrorCode,
    message: string,
    readonly oauthError?: string,
  ) {
    super(message);
    this.name = "OidcHttpError";
  }

  toJsonResponse(): Response {
    const body: Record<string, string> = {
      error: this.oauthError ?? mapOidcToOauthError(this.code),
      error_description: this.message,
      code: this.code,
    };
    return Response.json(body, {
      status: this.status,
      headers: {
        "Cache-Control": "no-store",
        Pragma: "no-cache",
      },
    });
  }
}

function mapOidcToOauthError(code: OidcErrorCode): string {
  switch (code) {
    case "invalid_client":
      return "invalid_client";
    case "invalid_grant":
      return "invalid_grant";
    case "unauthorized_client":
      return "unauthorized_client";
    case "unsupported_grant_type":
      return "unsupported_grant_type";
    case "invalid_scope":
      return "invalid_scope";
    case "access_denied":
      return "access_denied";
    case "rate_limited":
    case "temporarily_unavailable":
      return "temporarily_unavailable";
    case "server_error":
      return "server_error";
    default:
      return "invalid_request";
  }
}

/** Build an OAuth error redirect to the client's redirect_uri. */
export function oauthErrorRedirect(
  redirectUri: string,
  error: string,
  description: string,
  state: string | null,
): string {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  url.searchParams.set("error_description", description);
  if (state) url.searchParams.set("state", state);
  return url.toString();
}
