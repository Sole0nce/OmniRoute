/**
 * Unit tests for the OIDC dashboard SSO module.
 *
 * Uses jose's `generateKeyPair` + `createLocalJWKSet` so the verifier path is
 * exercised end-to-end without network or upstream IdP. `fetchImpl` is injected
 * for discovery + token-exchange + probe to avoid live HTTP.
 *
 * Encryption test re-uses the real `src/lib/db/encryption.ts` helper with a
 * deterministic `STORAGE_ENCRYPTION_KEY` set for the duration of the test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SignJWT,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type JWK,
  type KeyLike,
} from "jose";

// Ensure encryption is active for the encryption round-trip test BEFORE the
// module loads (the key is cached on first derivation).
process.env.STORAGE_ENCRYPTION_KEY =
  process.env.STORAGE_ENCRYPTION_KEY ||
  "test-storage-key-for-oidc-unit-tests-xxxxxxxxxxxxxxxxxxxxxxxx==";

const {
  buildOidcAuthorizationUrl,
  createOidcNonce,
  createOidcState,
  createPkcePair,
  encryptOidcClientSecret,
  decryptOidcClientSecret,
  exchangeOidcCode,
  fetchOidcDiscovery,
  isOidcConfigured,
  probeOidcClientSecret,
  resolveOidcRuntimeConfig,
  verifyOidcIdToken,
  DEFAULT_OIDC_SCOPES,
} = await import("@/lib/auth/oidc");

const ISSUER = "https://idp.example.com";
const CLIENT_ID = "test-client";
const AUDIENCE = CLIENT_ID;
const JWKS_URI = `${ISSUER}/jwks`;

interface KeyMaterial {
  privateKey: KeyLike;
  publicJwk: JWK;
  kid: string;
}

async function makeKeys(): Promise<KeyMaterial> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", {
    modulusLength: 2048,
    extractable: true,
  });
  const jwk = await exportJWK(publicKey);
  jwk.alg = "RS256";
  jwk.use = "sig";
  jwk.kid = "test-key-1";
  return { privateKey, publicJwk: jwk, kid: "test-key-1" };
}

async function signIdToken(
  privateKey: KeyLike,
  kid: string,
  claims: Record<string, unknown>
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

// ───────────────────────────────────────────────────────────

test("buildOidcAuthorizationUrl includes PKCE S256, state, nonce, scope", () => {
  const url = new URL(
    buildOidcAuthorizationUrl({
      authorizationEndpoint: `${ISSUER}/authorize`,
      clientId: CLIENT_ID,
      redirectUri: "https://omni.example.com/api/auth/oidc/callback",
      scopes: DEFAULT_OIDC_SCOPES,
      state: "STATE",
      nonce: "NONCE",
      codeChallenge: "CHALLENGE",
    })
  );
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("client_id"), CLIENT_ID);
  assert.equal(
    url.searchParams.get("redirect_uri"),
    "https://omni.example.com/api/auth/oidc/callback"
  );
  assert.equal(url.searchParams.get("scope"), "openid profile email");
  assert.equal(url.searchParams.get("state"), "STATE");
  assert.equal(url.searchParams.get("nonce"), "NONCE");
  assert.equal(url.searchParams.get("code_challenge"), "CHALLENGE");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
});

test("createPkcePair produces a valid base64url verifier + S256 challenge", () => {
  const { verifier, challenge } = createPkcePair();
  assert.match(verifier, /^[A-Za-z0-9_-]+$/);
  assert.match(challenge, /^[A-Za-z0-9_-]+$/);
  assert.notEqual(verifier, challenge);
  assert.ok(verifier.length >= 43, "verifier should be at least 43 chars (RFC 7636)");
});

// 1. State mismatch — this is enforced at the route level by comparing cookie
// vs query string, but we assert here that randomness produces independent
// values so a forger cannot guess one from the other.
test("state and nonce are independent random values", () => {
  const a = createOidcState();
  const b = createOidcState();
  const n = createOidcNonce();
  assert.notEqual(a, b);
  assert.notEqual(a, n);
});

// 2. Nonce mismatch in id_token → throws.
test("verifyOidcIdToken rejects when id_token nonce does not match expected", async () => {
  const { privateKey, publicJwk, kid } = await makeKeys();
  const jwks = createLocalJWKSet({ keys: [publicJwk] });
  const idToken = await signIdToken(privateKey, kid, { nonce: "WRONG_NONCE" });

  await assert.rejects(
    verifyOidcIdToken({
      idToken,
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKS_URI,
      nonce: "EXPECTED_NONCE",
      jwks,
    }),
    /nonce mismatch/i
  );
});

// 3. PKCE code_verifier mismatch — modeled as a token endpoint that rejects
// the exchange when the verifier is wrong. We assert exchangeOidcCode
// surfaces the IdP's `invalid_grant` error.
test("exchangeOidcCode surfaces invalid_grant when token endpoint rejects PKCE", async () => {
  const fakeFetch: typeof fetch = async () =>
    new Response(
      JSON.stringify({
        error: "invalid_grant",
        error_description: "PKCE verification failed",
      }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );

  await assert.rejects(
    exchangeOidcCode(
      {
        tokenEndpoint: `${ISSUER}/token`,
        clientId: CLIENT_ID,
        clientSecret: "secret",
        code: "any",
        redirectUri: "https://omni.example.com/api/auth/oidc/callback",
        codeVerifier: "wrong",
      },
      fakeFetch as unknown as typeof fetch
    ),
    /PKCE verification failed/
  );
});

// 4. id_token signature invalid (wrong key) → throws.
test("verifyOidcIdToken rejects an id_token signed by a different key", async () => {
  const signer = await makeKeys();
  const otherSigner = await makeKeys();
  // JWKS exposes only the OTHER key — signature will fail.
  const jwks = createLocalJWKSet({ keys: [otherSigner.publicJwk] });
  const idToken = await signIdToken(signer.privateKey, signer.kid, {
    nonce: "N",
  });

  await assert.rejects(
    verifyOidcIdToken({
      idToken,
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKS_URI,
      nonce: "N",
      jwks,
    })
  );
});

// 5. JWKS / discovery fetch failure → throws sanitizable error (no stack
// leak, just a clean message — the route layer routes it through
// sanitizeErrorMessage / buildErrorBody).
test("fetchOidcDiscovery throws a clean Error on non-OK responses", async () => {
  const fakeFetch: typeof fetch = async () =>
    new Response("nope", { status: 500 });
  await assert.rejects(
    fetchOidcDiscovery(`${ISSUER}/.well-known/openid-configuration`, fakeFetch),
    (err) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, /Failed to load OIDC discovery/);
      // Sanity: no stack-trace fragment.
      assert.ok(!err.message.includes("at /"));
      return true;
    }
  );
});

// 6. client_secret encryption round-trip.
test("client_secret is encrypted at rest and round-trips through decrypt", () => {
  const plaintext = "super-secret-client-secret-value-xyz";
  const ciphertext = encryptOidcClientSecret(plaintext);
  assert.ok(ciphertext.length > 0);
  assert.notEqual(ciphertext, plaintext);
  assert.ok(
    ciphertext.startsWith("enc:v1:"),
    "ciphertext should carry the AES-256-GCM envelope prefix"
  );
  const round = decryptOidcClientSecret(ciphertext);
  assert.equal(round, plaintext);
});

// 7. resolveOidcRuntimeConfig only returns a config when authMode + secret are present.
test("resolveOidcRuntimeConfig returns null unless mode + issuer + clientId + secret are present", () => {
  const encryptedSecret = encryptOidcClientSecret("secret");
  // password mode → null even if everything else is set
  assert.equal(
    resolveOidcRuntimeConfig({
      authMode: "password",
      oidcIssuerUrl: ISSUER,
      oidcClientId: CLIENT_ID,
      oidcClientSecret: encryptedSecret,
    }),
    null
  );
  // missing secret → null
  assert.equal(
    resolveOidcRuntimeConfig({
      authMode: "oidc",
      oidcIssuerUrl: ISSUER,
      oidcClientId: CLIENT_ID,
    }),
    null
  );
  // both mode → returns config
  const cfg = resolveOidcRuntimeConfig({
    authMode: "both",
    oidcIssuerUrl: `${ISSUER}/`,
    oidcClientId: CLIENT_ID,
    oidcClientSecret: encryptedSecret,
  });
  assert.ok(cfg);
  assert.equal(cfg.issuerUrl, ISSUER, "trailing slash should be stripped");
  assert.equal(cfg.clientSecret, "secret", "secret should be decrypted in-memory");
  assert.equal(cfg.scopes, "openid profile email");
});

// 8. isOidcConfigured mirrors resolution.
test("isOidcConfigured detects a complete config", () => {
  const encryptedSecret = encryptOidcClientSecret("secret");
  assert.equal(isOidcConfigured(null), false);
  assert.equal(isOidcConfigured({}), false);
  assert.equal(isOidcConfigured({ oidcIssuerUrl: ISSUER }), false);
  assert.equal(
    isOidcConfigured({
      oidcIssuerUrl: ISSUER,
      oidcClientId: CLIENT_ID,
      oidcClientSecret: encryptedSecret,
    }),
    true
  );
});

// 9. happy-path verification using the local JWKS test seam.
test("verifyOidcIdToken accepts a correctly-signed id_token with matching nonce", async () => {
  const { privateKey, publicJwk, kid } = await makeKeys();
  const jwks = createLocalJWKSet({ keys: [publicJwk] });
  const idToken = await signIdToken(privateKey, kid, {
    nonce: "NONCE",
    sub: "u1",
    email: "u1@example.com",
  });
  const payload = await verifyOidcIdToken({
    idToken,
    issuer: ISSUER,
    audience: AUDIENCE,
    jwksUri: JWKS_URI,
    nonce: "NONCE",
    jwks,
  });
  assert.equal(payload.sub, "u1");
  assert.equal(payload.email, "u1@example.com");
});

// 10. probeOidcClientSecret classification.
test("probeOidcClientSecret treats invalid_grant as 'secret accepted'", async () => {
  const fakeFetch: typeof fetch = async () =>
    new Response(
      JSON.stringify({
        error: "invalid_grant",
        error_description: "authorization code expired",
      }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  const result = await probeOidcClientSecret(
    {
      tokenEndpoint: `${ISSUER}/token`,
      clientId: CLIENT_ID,
      clientSecret: "secret",
      redirectUri: "https://omni.example.com/api/auth/oidc/callback",
    },
    fakeFetch as unknown as typeof fetch
  );
  assert.equal(result.tested, true);
  assert.equal(result.valid, true);
});

test("probeOidcClientSecret reports invalid_client as a bad secret", async () => {
  const fakeFetch: typeof fetch = async () =>
    new Response(
      JSON.stringify({ error: "invalid_client", error_description: "client not authorized" }),
      { status: 401, headers: { "Content-Type": "application/json" } }
    );
  const result = await probeOidcClientSecret(
    {
      tokenEndpoint: `${ISSUER}/token`,
      clientId: CLIENT_ID,
      clientSecret: "secret",
      redirectUri: "https://omni.example.com/api/auth/oidc/callback",
    },
    fakeFetch as unknown as typeof fetch
  );
  assert.equal(result.tested, true);
  assert.equal(result.valid, false);
});
