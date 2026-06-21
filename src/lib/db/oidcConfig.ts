/**
 * OIDC dashboard SSO configuration — typed CRUD on the shared `key_value`
 * settings namespace, encrypting `client_secret` at rest with AES-256-GCM
 * (`src/lib/db/encryption.ts`). No raw SQL in routes — go through this module.
 */

import { getSettings, updateSettings } from "@/lib/db/settings";
import {
  encryptOidcClientSecret,
  type OidcAuthMode,
  type OidcStoredSettings,
} from "@/lib/auth/oidc";

const OIDC_KEYS = [
  "authMode",
  "oidcIssuerUrl",
  "oidcClientId",
  "oidcClientSecret",
  "oidcScopes",
  "oidcLoginLabel",
] as const;

export type OidcConfigUpdate = {
  authMode?: OidcAuthMode;
  oidcIssuerUrl?: string;
  oidcClientId?: string;
  /** Plaintext input — will be AES-256-GCM-encrypted before storage. */
  oidcClientSecretPlaintext?: string;
  oidcScopes?: string;
  oidcLoginLabel?: string;
};

export async function readOidcSettings(): Promise<OidcStoredSettings> {
  const raw = (await getSettings()) as Record<string, unknown>;
  const out: OidcStoredSettings = {};
  for (const key of OIDC_KEYS) {
    const value = raw[key];
    if (typeof value === "string") {
      (out as Record<string, string>)[key] = value;
    }
  }
  return out;
}

/**
 * Save an OIDC config patch. Only provided fields are written. `client_secret`
 * is encrypted before storage; passing an empty string is treated as
 * "no change" (matches upstream UX: leave blank to keep the existing secret).
 */
export async function saveOidcSettings(patch: OidcConfigUpdate): Promise<void> {
  const updates: Record<string, unknown> = {};
  if (patch.authMode !== undefined) updates.authMode = patch.authMode;
  if (patch.oidcIssuerUrl !== undefined) updates.oidcIssuerUrl = patch.oidcIssuerUrl;
  if (patch.oidcClientId !== undefined) updates.oidcClientId = patch.oidcClientId;
  if (patch.oidcScopes !== undefined) updates.oidcScopes = patch.oidcScopes;
  if (patch.oidcLoginLabel !== undefined) updates.oidcLoginLabel = patch.oidcLoginLabel;
  if (
    patch.oidcClientSecretPlaintext !== undefined &&
    patch.oidcClientSecretPlaintext.length > 0
  ) {
    updates.oidcClientSecret = encryptOidcClientSecret(
      patch.oidcClientSecretPlaintext
    );
  }
  if (Object.keys(updates).length > 0) {
    await updateSettings(updates);
  }
}
