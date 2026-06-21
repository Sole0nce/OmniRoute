/**
 * OIDC callback — validates state, exchanges the auth code (PKCE), verifies
 * the id_token via JWKS, mints an OmniRoute dashboard session JWT, and
 * redirects to /dashboard.
 *
 * Public-facing route — the IdP redirects the user's browser here.
 * Does NOT spawn any child process, so intentionally NOT in
 * `LOCAL_ONLY_API_PREFIXES`. The route's defense-in-depth comes from:
 *   - PKCE S256 (verifier in HttpOnly cookie),
 *   - state cookie match,
 *   - id_token JWKS signature, issuer, audience, AND nonce all enforced,
 *   - sanitized error responses (no stack/PII leak).
 *
 * DRAFT — needs live IdP validation before un-drafting (Hard Rule #18).
 */
import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { SignJWT } from "jose";
import {
  OIDC_COOKIE_NAMES,
  exchangeOidcCode,
  fetchOidcDiscovery,
  getPublicOrigin,
  pickOidcDisplayName,
  pickOidcEmail,
  resolveOidcRuntimeConfig,
  verifyOidcIdToken,
} from "@/lib/auth/oidc";
import { readOidcSettings } from "@/lib/db/oidcConfig";
import { sanitizeErrorMessage } from "@omniroute/open-sse/utils/error";

function clearOidcCookies(
  cookieStore: Awaited<ReturnType<typeof cookies>>
): void {
  for (const name of Object.values(OIDC_COOKIE_NAMES)) {
    cookieStore.delete(name);
  }
}

function shouldUseSecureCookie(request: Request): boolean {
  if (process.env.AUTH_COOKIE_SECURE === "true") return true;
  const forwardedProto = (request.headers.get("x-forwarded-proto") || "")
    .split(",")[0]
    .trim()
    .toLowerCase();
  if (forwardedProto === "https") return true;
  try {
    return new URL(request.url).protocol === "https:";
  } catch {
    return false;
  }
}

function redirectToLogin(origin: string, errorCode: string): NextResponse {
  const safe = sanitizeErrorMessage(errorCode);
  return NextResponse.redirect(
    new URL(
      `/login?error=${encodeURIComponent(safe)}`,
      origin || "http://localhost"
    )
  );
}

export async function GET(request: Request) {
  const origin = getPublicOrigin(request);
  const cookieStore = await cookies();

  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return redirectToLogin(origin, "oidc_invalid_request");
  }

  const errorParam = url.searchParams.get("error");
  if (errorParam) {
    clearOidcCookies(cookieStore);
    return redirectToLogin(origin, errorParam);
  }

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) {
    clearOidcCookies(cookieStore);
    return redirectToLogin(origin, "oidc_missing_code");
  }

  const storedState = cookieStore.get(OIDC_COOKIE_NAMES.state)?.value;
  const storedNonce = cookieStore.get(OIDC_COOKIE_NAMES.nonce)?.value;
  const codeVerifier = cookieStore.get(OIDC_COOKIE_NAMES.verifier)?.value;

  if (!storedState || !storedNonce || !codeVerifier || storedState !== state) {
    clearOidcCookies(cookieStore);
    return redirectToLogin(origin, "oidc_invalid_state");
  }

  try {
    const settings = await readOidcSettings();
    const config = resolveOidcRuntimeConfig(settings);
    if (!config) {
      clearOidcCookies(cookieStore);
      return redirectToLogin(origin, "oidc_not_configured");
    }

    const discovery = await fetchOidcDiscovery(config.issuerUrl);
    const redirectUri = `${origin}/api/auth/oidc/callback`;
    const token = await exchangeOidcCode({
      tokenEndpoint: discovery.token_endpoint,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      code,
      redirectUri,
      codeVerifier,
    });

    if (!token.id_token) {
      throw new Error("OIDC provider did not return an id_token");
    }

    const payload = await verifyOidcIdToken({
      idToken: token.id_token,
      issuer: discovery.issuer || config.issuerUrl,
      audience: config.clientId,
      jwksUri: discovery.jwks_uri,
      nonce: storedNonce,
    });

    const jwtSecret = process.env.JWT_SECRET?.trim();
    if (!jwtSecret) {
      throw new Error("Server misconfigured: JWT_SECRET not set");
    }

    const sessionToken = await new SignJWT({
      authenticated: true,
      oidc: true,
      oidcSub: payload.sub || null,
      oidcEmail: pickOidcEmail(payload) || null,
      oidcName: pickOidcDisplayName(payload),
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("30d")
      .sign(new TextEncoder().encode(jwtSecret));

    clearOidcCookies(cookieStore);
    cookieStore.set("auth_token", sessionToken, {
      httpOnly: true,
      secure: shouldUseSecureCookie(request),
      sameSite: "lax",
      path: "/",
    });

    return NextResponse.redirect(new URL("/dashboard", origin || "http://localhost"));
  } catch (error) {
    clearOidcCookies(cookieStore);
    const safe = sanitizeErrorMessage(
      error instanceof Error ? error.message : "oidc_callback_failed"
    );
    return redirectToLogin(origin, safe);
  }
}
