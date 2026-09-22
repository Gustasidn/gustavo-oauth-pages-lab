export async function onRequestGet(context) {
  const { request, env, params } = context;
  const provider = params.provider;

  if (provider !== "google" && provider !== "github") {
    return new Response("Not Found", { status: 404 });
  }

  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const txId = btoa(String.fromCharCode(...array)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  
  crypto.getRandomValues(array);
  const state = btoa(String.fromCharCode(...array)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  crypto.getRandomValues(array);
  const codeVerifier = btoa(String.fromCharCode(...array)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  let nonce = null;
  if (provider === "google") {
    crypto.getRandomValues(array);
    nonce = btoa(String.fromCharCode(...array)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  const encoder = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(codeVerifier));
  const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const txDigest = await crypto.subtle.digest("SHA-256", encoder.encode(txId));
  const idHash = Array.from(new Uint8Array(txDigest)).map(b => b.toString(16).padStart(2, "0")).join("");

  const stateDigest = await crypto.subtle.digest("SHA-256", encoder.encode(state));
  const stateHash = Array.from(new Uint8Array(stateDigest)).map(b => b.toString(16).padStart(2, "0")).join("");

  const expiresAt = Math.floor(Date.now() / 1000) + 600;

  try {
    await env.DB.prepare(
      "INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(idHash, provider, stateHash, nonce, codeVerifier, expiresAt).run();
  } catch (err) {
    return new Response("Erro interno ao gravar transação", { status: 500 });
  }

  let authUrl = "";
  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;

  if (provider === "google") {
    const clientId = env.GOOGLE_CLIENT_ID;
    authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent("openid email profile")}&state=${encodeURIComponent(state)}&nonce=${encodeURIComponent(nonce)}&code_challenge=${encodeURIComponent(codeChallenge)}&code_challenge_method=S256`;
  } else {
    const clientId = env.GITHUB_CLIENT_ID;
    authUrl = `https://github.com/login/oauth/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}&code_challenge=${encodeURIComponent(codeChallenge)}&code_challenge_method=S256`;
  }

  const cookieValue = `__Host-oauth-tx=${txId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;

  return new Response(null, {
    status: 302,
    headers: {
      "Location": authUrl,
      "Set-Cookie": cookieValue,
      "Cache-Control": "no-store"
    }
  });
}