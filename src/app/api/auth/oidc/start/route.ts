/**
 * OIDC sign-in entry point — generates `state`, `nonce`, PKCE verifier
 * (cookies, HttpOnly, 10 min TTL) and redirects the browser to the IdP
 * authorization endpoint.
 *
 * Public-facing route — the IdP returns the user to /api/auth/oidc/callback,
 * which must be browser-reachable on the same host as the dashboard.
 * Does NOT spawn any child process, so it is intentionally NOT in
 * `LOCAL_ONLY_API_PREFIXES`.
 *
 * DRAFT — needs live IdP validation before un-drafting (Hard Rule #18).
 */
import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import {
  OIDC_COOKIE_NAMES,
  buildOidcAuthorizationUrl,
  createOidcNonce,
  createOidcState,
  createPkcePair,
  fetchOidcDiscovery,
  getPublicOrigin,
  resolveOidcRuntimeConfig,
} from "@/lib/auth/oidc";
import { readOidcSettings } from "@/lib/db/oidcConfig";
import { sanitizeErrorMessage } from "@omniroute/open-sse/utils/error";

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

export async function GET(request: Request) {
  const origin = getPublicOrigin(request);
  try {
    const settings = await readOidcSettings();
    const config = resolveOidcRuntimeConfig(settings);
    if (!config) {
      return NextResponse.redirect(
        new URL("/login?error=oidc_not_configured", origin || "http://localhost")
      );
    }

    const discovery = await fetchOidcDiscovery(config.issuerUrl);
    const state = createOidcState();
    const nonce = createOidcNonce();
    const { verifier, challenge } = createPkcePair();
    const redirectUri = `${origin}/api/auth/oidc/callback`;
    const authUrl = buildOidcAuthorizationUrl({
      authorizationEndpoint: discovery.authorization_endpoint,
      clientId: config.clientId,
      redirectUri,
      scopes: config.scopes,
      state,
      nonce,
      codeChallenge: challenge,
    });

    const cookieStore = await cookies();
    const baseOptions = {
      httpOnly: true,
      secure: shouldUseSecureCookie(request),
      sameSite: "lax" as const,
      path: "/",
      maxAge: 10 * 60,
    };
    cookieStore.set(OIDC_COOKIE_NAMES.state, state, baseOptions);
    cookieStore.set(OIDC_COOKIE_NAMES.nonce, nonce, baseOptions);
    cookieStore.set(OIDC_COOKIE_NAMES.verifier, verifier, baseOptions);

    return NextResponse.redirect(authUrl);
  } catch (error) {
    const safe = sanitizeErrorMessage(
      error instanceof Error ? error.message : "oidc_start_failed"
    );
    return NextResponse.redirect(
      new URL(
        `/login?error=${encodeURIComponent(safe)}`,
        origin || "http://localhost"
      )
    );
  }
}
