/**
 * OIDC config CRUD — admin-only. Plaintext `client_secret` arrives via PATCH
 * and is AES-256-GCM-encrypted before storage (`db/oidcConfig.ts`).
 *
 * GET returns the safe shape (no decrypted secret leaves the server; only a
 * boolean indicating whether one is stored).
 */
import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { jwtVerify } from "jose";
import { z } from "zod";
import {
  DEFAULT_OIDC_LOGIN_LABEL,
  DEFAULT_OIDC_SCOPES,
  isOidcConfigured,
} from "@/lib/auth/oidc";
import { readOidcSettings, saveOidcSettings } from "@/lib/db/oidcConfig";
import { buildErrorBody } from "@omniroute/open-sse/utils/error";

const PatchSchema = z.object({
  authMode: z.enum(["password", "oidc", "both"]).optional(),
  oidcIssuerUrl: z.string().trim().max(2048).optional(),
  oidcClientId: z.string().trim().max(512).optional(),
  oidcClientSecret: z.string().max(4096).optional(),
  oidcScopes: z.string().trim().max(512).optional(),
  oidcLoginLabel: z.string().trim().max(120).optional(),
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

export async function GET() {
  if (!(await isDashboardAuthenticated())) {
    return NextResponse.json(buildErrorBody(401, "Unauthorized"), { status: 401 });
  }
  const settings = await readOidcSettings();
  return NextResponse.json({
    authMode: settings.authMode || "password",
    oidcIssuerUrl: settings.oidcIssuerUrl || "",
    oidcClientId: settings.oidcClientId || "",
    oidcScopes: settings.oidcScopes || DEFAULT_OIDC_SCOPES,
    oidcLoginLabel: settings.oidcLoginLabel || DEFAULT_OIDC_LOGIN_LABEL,
    oidcConfigured: isOidcConfigured(settings),
    oidcClientSecretStored: !!(settings.oidcClientSecret || ""),
  });
}

export async function PATCH(request: Request) {
  if (!(await isDashboardAuthenticated())) {
    return NextResponse.json(buildErrorBody(401, "Unauthorized"), { status: 401 });
  }
  let body: z.infer<typeof PatchSchema>;
  try {
    const raw = await request.json().catch(() => ({}));
    body = PatchSchema.parse(raw);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid body";
    return NextResponse.json(buildErrorBody(400, message), { status: 400 });
  }

  try {
    await saveOidcSettings({
      authMode: body.authMode,
      oidcIssuerUrl: body.oidcIssuerUrl,
      oidcClientId: body.oidcClientId,
      oidcClientSecretPlaintext: body.oidcClientSecret,
      oidcScopes: body.oidcScopes,
      oidcLoginLabel: body.oidcLoginLabel,
    });
    const settings = await readOidcSettings();
    return NextResponse.json({
      authMode: settings.authMode || "password",
      oidcIssuerUrl: settings.oidcIssuerUrl || "",
      oidcClientId: settings.oidcClientId || "",
      oidcScopes: settings.oidcScopes || DEFAULT_OIDC_SCOPES,
      oidcLoginLabel: settings.oidcLoginLabel || DEFAULT_OIDC_LOGIN_LABEL,
      oidcConfigured: isOidcConfigured(settings),
      oidcClientSecretStored: !!(settings.oidcClientSecret || ""),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to save OIDC settings";
    return NextResponse.json(buildErrorBody(500, message), { status: 500 });
  }
}
