/**
 * Dashboard auth status — used by the login page + Header to decide which
 * sign-in flow(s) to surface.
 *
 * Backwards-compatible with the pre-OIDC shape (`{ authenticated: boolean }`)
 * and extended with OIDC availability info so the login page can render a
 * "Sign in with OIDC" button when the operator has configured it.
 *
 * No child-process spawning — public-facing endpoint by design.
 */
import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { jwtVerify } from "jose";
import {
  DEFAULT_OIDC_LOGIN_LABEL,
  isOidcConfigured,
  type OidcAuthMode,
} from "@/lib/auth/oidc";
import { readOidcSettings } from "@/lib/db/oidcConfig";

function getJwtSecret(): Uint8Array | null {
  const secret = process.env.JWT_SECRET?.trim();
  return secret ? new TextEncoder().encode(secret) : null;
}

export async function GET() {
  let authenticated = false;
  try {
    const cookieStore = await cookies();
    const token = cookieStore.get("auth_token")?.value;
    const secret = getJwtSecret();
    if (token && secret) {
      await jwtVerify(token, secret);
      authenticated = true;
    }
  } catch {
    authenticated = false;
  }

  let oidcSettings = {};
  try {
    oidcSettings = await readOidcSettings();
  } catch {
    // Never block status reads on a DB hiccup — fall back to OIDC-off shape.
    oidcSettings = {};
  }

  const stored = oidcSettings as {
    authMode?: OidcAuthMode;
    oidcLoginLabel?: string;
  };
  const authMode: OidcAuthMode = stored.authMode || "password";
  const oidcConfigured = isOidcConfigured(oidcSettings);
  const oidcLoginLabel =
    (stored.oidcLoginLabel || "").trim() || DEFAULT_OIDC_LOGIN_LABEL;

  return NextResponse.json({
    authenticated,
    authMode,
    oidcConfigured,
    oidcLoginLabel,
  });
}
