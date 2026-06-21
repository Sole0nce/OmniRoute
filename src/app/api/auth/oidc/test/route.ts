/**
 * OIDC discovery + secret probe — admin-only test endpoint. Requires a valid
 * dashboard session JWT in the `auth_token` cookie.
 *
 * Returns sanitized error bodies via `buildErrorBody()`.
 *
 * DRAFT — needs live IdP validation before un-drafting (Hard Rule #18).
 */
import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { jwtVerify } from "jose";
import { z } from "zod";
import {
  DEFAULT_OIDC_SCOPES,
  decryptOidcClientSecret,
  fetchOidcDiscovery,
  getPublicOrigin,
  probeOidcClientSecret,
} from "@/lib/auth/oidc";
import { readOidcSettings } from "@/lib/db/oidcConfig";
import { buildErrorBody } from "@omniroute/open-sse/utils/error";

const TestBodySchema = z.object({
  issuerUrl: z.string().trim().min(1).optional(),
  clientId: z.string().trim().min(1).optional(),
  scopes: z.string().trim().optional(),
  clientSecret: z.string().optional(),
});

async function isDashboardAuthenticated(): Promise<boolean> {
  try {
    const cookieStore = await cookies();
    const token = cookieStore.get("auth_token")?.value;
    const secret = process.env.JWT_SECRET?.trim();
    if (!token || !secret) return false;
    await jwtVerify(token, new TextEncoder().encode(secret));
    return true;
  } catch {
    return false;
  }
}

export async function POST(request: Request) {
  if (!(await isDashboardAuthenticated())) {
    return NextResponse.json(buildErrorBody(401, "Unauthorized"), { status: 401 });
  }

  let parsed: z.infer<typeof TestBodySchema>;
  try {
    const raw = await request.json().catch(() => ({}));
    parsed = TestBodySchema.parse(raw);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid body";
    return NextResponse.json(buildErrorBody(400, message), { status: 400 });
  }

  const settings = await readOidcSettings();
  const issuerUrl = (parsed.issuerUrl || settings.oidcIssuerUrl || "").trim();
  const clientId = (parsed.clientId || settings.oidcClientId || "").trim();
  const scopes = (parsed.scopes || settings.oidcScopes || DEFAULT_OIDC_SCOPES).trim();
  const clientSecret =
    parsed.clientSecret !== undefined
      ? parsed.clientSecret.trim()
      : decryptOidcClientSecret(settings.oidcClientSecret);

  if (!issuerUrl) {
    return NextResponse.json(buildErrorBody(400, "Issuer URL is required"), { status: 400 });
  }
  if (!clientId) {
    return NextResponse.json(buildErrorBody(400, "Client ID is required"), { status: 400 });
  }

  try {
    const discovery = await fetchOidcDiscovery(issuerUrl);
    const redirectUri = `${getPublicOrigin(request)}/api/auth/oidc/callback`;
    const probe = await probeOidcClientSecret({
      tokenEndpoint: discovery.token_endpoint,
      clientId,
      clientSecret,
      redirectUri,
    });

    return NextResponse.json({
      ok: probe.valid !== false,
      discoveryOk: true,
      clientSecretTested: probe.tested,
      clientSecretValid: probe.valid,
      issuerUrl,
      clientId,
      scopes: scopes || DEFAULT_OIDC_SCOPES,
      redirectUri,
      authorizationEndpoint: discovery.authorization_endpoint,
      tokenEndpoint: discovery.token_endpoint,
      jwksUri: discovery.jwks_uri,
      message: probe.message,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "OIDC test failed";
    return NextResponse.json(buildErrorBody(500, message), { status: 500 });
  }
}
