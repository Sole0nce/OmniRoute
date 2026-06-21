/**
 * OIDC dashboard SSO — typed config helpers + verification.
 *
 * Adapted (TS) from the upstream 9router PR #1020 (author Walter Cheng).
 *
 * Security notes
 * --------------
 * - `client_secret` is stored AES-256-GCM-encrypted via `src/lib/db/encryption.ts`
 *   (`encrypt`/`decrypt`). Plaintext never persists when `STORAGE_ENCRYPTION_KEY`
 *   is set. Plaintext fallback (passthrough mode) is the existing repo convention
 *   and is logged with a warning by the encryption helper.
 * - `id_token` is verified via `jose.createRemoteJWKSet` + `jwtVerify`, with
 *   issuer, audience, AND nonce all enforced (jose's `nonce` option matches the
 *   claim against the supplied value).
 * - PKCE S256 is mandatory: `code_challenge_method=S256` is hardcoded.
 * - `state` and `nonce` are 16 random bytes (base64url) per attempt; the
 *   callback rejects if either cookie is missing or mismatches.
 * - This module owns *no* I/O on cookies or Next.js request lifecycle — those
 *   live in the route handlers so this module is unit-testable with injected
 *   fetch + injected JWKS.
 *
 * **DRAFT** — needs live IdP validation (Authentik/Keycloak) on the production
 * VPS per Hard Rule #18 before un-drafting the PR.
 */

import crypto from "node:crypto";
import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
} from "jose";
import { encrypt, decrypt } from "@/lib/db/encryption";

export const OIDC_COOKIE_NAMES = {
  state: "oidc_state",
  nonce: "oidc_nonce",
  verifier: "oidc_code_verifier",
} as const;

export const DEFAULT_OIDC_SCOPES = "openid profile email";
export const DEFAULT_OIDC_LOGIN_LABEL = "Sign in with OIDC";

export type OidcAuthMode = "password" | "oidc" | "both";

export interface OidcStoredSettings {
  authMode?: OidcAuthMode;
  oidcIssuerUrl?: string;
  oidcClientId?: string;
  /** Encrypted (AES-256-GCM) at rest. Use `decryptOidcClientSecret`. */
  oidcClientSecret?: string;
  oidcScopes?: string;
  oidcLoginLabel?: string;
}

export interface OidcRuntimeConfig {
  issuerUrl: string;
  clientId: string;
  /** Plaintext, decrypted in-memory only. */
  clientSecret: string;
  scopes: string;
  loginLabel: string;
}

export interface OidcDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  [key: string]: unknown;
}

export interface OidcTokenResponse {
  id_token?: string;
  access_token?: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  [key: string]: unknown;
}

export interface PkcePair {
  verifier: string;
  challenge: string;
}

// ───────────────────── normalization ─────────────────────

function trimTrailingSlashes(value: string | undefined | null): string {
  return (value || "").trim().replace(/\/+$/, "");
}

function normalizeScopes(value: string | undefined | null): string {
  return ((value || "").trim() || DEFAULT_OIDC_SCOPES);
}

/** Encrypt for storage (passthrough if STORAGE_ENCRYPTION_KEY unset). */
export function encryptOidcClientSecret(plaintext: string): string {
  const out = encrypt(plaintext);
  return typeof out === "string" ? out : "";
}

/** Decrypt for in-memory use; returns "" on failure. */
export function decryptOidcClientSecret(ciphertext: string | undefined | null): string {
  if (!ciphertext) return "";
  const out = decrypt(ciphertext);
  return typeof out === "string" ? out : "";
}

export function isOidcConfigured(settings: OidcStoredSettings | null | undefined): boolean {
  if (!settings) return false;
  const decryptedSecret = decryptOidcClientSecret(settings.oidcClientSecret);
  return !!(
    trimTrailingSlashes(settings.oidcIssuerUrl) &&
    (settings.oidcClientId || "").trim() &&
    decryptedSecret
  );
}

export function resolveOidcRuntimeConfig(
  settings: OidcStoredSettings | null | undefined
): OidcRuntimeConfig | null {
  if (!settings) return null;
  const mode: OidcAuthMode = (settings.authMode as OidcAuthMode) || "password";
  if (mode !== "oidc" && mode !== "both") return null;
  if (!isOidcConfigured(settings)) return null;

  return {
    issuerUrl: trimTrailingSlashes(settings.oidcIssuerUrl),
    clientId: (settings.oidcClientId || "").trim(),
    clientSecret: decryptOidcClientSecret(settings.oidcClientSecret),
    scopes: normalizeScopes(settings.oidcScopes),
    loginLabel:
      ((settings.oidcLoginLabel || "").trim() || DEFAULT_OIDC_LOGIN_LABEL),
  };
}

// ───────────────────── public origin ─────────────────────

/**
 * Resolve the public origin used in `redirect_uri`. Honors the operator's
 * `BASE_URL` / `NEXT_PUBLIC_BASE_URL` first, then falls back to
 * x-forwarded-host / host headers. The callback URL must be browser-reachable
 * from the IdP redirect, which is the same host the dashboard is exposed on.
 */
export function getPublicOrigin(request: Request): string {
  const configured =
    process.env.BASE_URL || process.env.NEXT_PUBLIC_BASE_URL || "";
  if (configured) return trimTrailingSlashes(configured);

  const headers = request.headers;
  const forwardedProto = (headers.get("x-forwarded-proto") || "")
    .split(",")[0]
    .trim()
    .toLowerCase();
  const forwardedHost = headers.get("x-forwarded-host") || "";
  const host = forwardedHost || headers.get("host") || "";
  if (host) {
    let protocol = forwardedProto;
    if (!protocol) {
      try {
        protocol = new URL(request.url).protocol.replace(/:$/, "");
      } catch {
        protocol = "http";
      }
    }
    return `${protocol}://${host}`.replace(/\/+$/, "");
  }

  try {
    return trimTrailingSlashes(new URL(request.url).origin);
  } catch {
    return "";
  }
}

// ───────────────────── discovery + PKCE + URL ─────────────────────

export type FetchLike = (
  input: string,
  init?: RequestInit
) => Promise<Response>;

export async function fetchOidcDiscovery(
  issuerUrl: string,
  fetchImpl: FetchLike = fetch
): Promise<OidcDiscoveryDocument> {
  const discoveryUrl = `${trimTrailingSlashes(issuerUrl)}/.well-known/openid-configuration`;
  const res = await fetchImpl(discoveryUrl, { cache: "no-store" } as RequestInit);
  if (!res.ok) {
    throw new Error(
      `Failed to load OIDC discovery document (status ${res.status})`
    );
  }
  const json = (await res.json()) as OidcDiscoveryDocument;
  if (!json || typeof json !== "object") {
    throw new Error("OIDC discovery document is not a JSON object");
  }
  if (!json.authorization_endpoint || !json.token_endpoint || !json.jwks_uri) {
    throw new Error(
      "OIDC discovery document missing authorization_endpoint / token_endpoint / jwks_uri"
    );
  }
  return json;
}

export function createPkcePair(): PkcePair {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

export function createOidcState(): string {
  return crypto.randomBytes(16).toString("base64url");
}

export function createOidcNonce(): string {
  return crypto.randomBytes(16).toString("base64url");
}

export interface BuildAuthorizationUrlOptions {
  authorizationEndpoint: string;
  clientId: string;
  redirectUri: string;
  scopes?: string;
  state: string;
  nonce: string;
  codeChallenge: string;
}

export function buildOidcAuthorizationUrl(
  opts: BuildAuthorizationUrlOptions
): string {
  const url = new URL(opts.authorizationEndpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", opts.clientId);
  url.searchParams.set("redirect_uri", opts.redirectUri);
  url.searchParams.set("scope", normalizeScopes(opts.scopes));
  url.searchParams.set("state", opts.state);
  url.searchParams.set("nonce", opts.nonce);
  url.searchParams.set("code_challenge", opts.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

// ───────────────────── token exchange ─────────────────────

export interface ExchangeOidcCodeOptions {
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  code: string;
  redirectUri: string;
  codeVerifier: string;
}

export async function exchangeOidcCode(
  opts: ExchangeOidcCodeOptions,
  fetchImpl: FetchLike = fetch
): Promise<OidcTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: opts.clientId,
    code: opts.code,
    redirect_uri: opts.redirectUri,
    code_verifier: opts.codeVerifier,
  });
  if (opts.clientSecret) body.set("client_secret", opts.clientSecret);

  const res = await fetchImpl(opts.tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  } as RequestInit);

  const data = (await res.json().catch(() => ({}))) as OidcTokenResponse & {
    error?: string;
    error_description?: string;
  };
  if (!res.ok) {
    const message =
      data?.error_description ||
      data?.error ||
      `OIDC token exchange failed (${res.status})`;
    throw new Error(String(message));
  }
  return data;
}

// ───────────────────── id_token verification ─────────────────────

export interface VerifyOidcIdTokenOptions {
  idToken: string;
  issuer: string;
  audience: string;
  jwksUri: string;
  nonce: string;
  /** Test seam: inject a pre-built JWKS getter to avoid network in unit tests. */
  jwks?: JWTVerifyGetKey;
}

export async function verifyOidcIdToken(
  opts: VerifyOidcIdTokenOptions
): Promise<JWTPayload> {
  const jwks =
    opts.jwks || createRemoteJWKSet(new URL(opts.jwksUri));
  const { payload } = await jwtVerify(opts.idToken, jwks, {
    issuer: opts.issuer,
    audience: opts.audience,
  });
  // jose 6 dropped the `nonce` verify option — assert manually.
  if (typeof payload.nonce !== "string" || payload.nonce !== opts.nonce) {
    throw new Error("id_token nonce mismatch");
  }
  return payload;
}

// ───────────────────── probe (admin test endpoint) ─────────────────────

export interface ProbeOidcClientSecretOptions {
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export interface ProbeResult {
  tested: boolean;
  valid: boolean | null;
  message: string;
}

export async function probeOidcClientSecret(
  opts: ProbeOidcClientSecretOptions,
  fetchImpl: FetchLike = fetch
): Promise<ProbeResult> {
  if (!opts.clientSecret) {
    return {
      tested: false,
      valid: null,
      message: "No client secret was provided, so secret validation was skipped.",
    };
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: opts.clientId,
    client_secret: opts.clientSecret,
    code: "__oidc_test_invalid_code__",
    redirect_uri: opts.redirectUri,
    code_verifier: "__oidc_test_invalid_verifier__",
  });

  const res = await fetchImpl(opts.tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  } as RequestInit);

  const data = (await res.json().catch(() => ({}))) as {
    error?: string;
    error_description?: string;
  };
  const error = (data?.error || "").toLowerCase();
  const description = data?.error_description || data?.error || "";

  if (res.ok) {
    return { tested: true, valid: true, message: "Client secret accepted by the token endpoint." };
  }
  if (
    error === "invalid_client" ||
    error === "unauthorized_client" ||
    /client.*(invalid|failed|mismatch)/i.test(description)
  ) {
    return { tested: true, valid: false, message: description || "Client secret is not valid." };
  }
  if (
    error === "invalid_grant" ||
    error === "invalid_code" ||
    /grant|code/i.test(description)
  ) {
    return {
      tested: true,
      valid: true,
      message:
        "Client secret accepted; token exchange failed only because the probe authorization code is intentionally invalid.",
    };
  }
  return {
    tested: true,
    valid: null,
    message: description || `Token endpoint responded with ${res.status}`,
  };
}

// ───────────────────── payload helpers ─────────────────────

export function pickOidcDisplayName(payload: JWTPayload): string {
  const p = payload as Record<string, unknown>;
  return (
    (typeof p.preferred_username === "string" && p.preferred_username) ||
    (typeof p.email === "string" && p.email) ||
    (typeof p.name === "string" && p.name) ||
    (typeof p.given_name === "string" && p.given_name) ||
    (typeof payload.sub === "string" && payload.sub) ||
    "OIDC user"
  );
}

export function pickOidcEmail(payload: JWTPayload): string {
  const p = payload as Record<string, unknown>;
  return typeof p.email === "string" ? p.email : "";
}
