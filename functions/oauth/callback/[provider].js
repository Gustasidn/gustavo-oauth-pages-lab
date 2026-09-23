export async function onRequestGet(context) {
  try {
    const { request, env, params } = context;
    const provider = params.provider;

    if (provider !== "google" && provider !== "github") {
      return new Response("Not Found", { status: 404 });
    }

    const url = new URL(request.url);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const error = url.searchParams.get("error");

    if (error || !code || !state) {
      return new Response("Parâmetros inválidos ou erro no provedor", { status: 400 });
    }

    const cookieHeader = request.headers.get("Cookie") || "";
    const cookies = Object.fromEntries(cookieHeader.split(";").map(c => {
      const [key, ...v] = c.trim().split("=");
      return [key, v.join("=")];
    }));

    const txId = cookies["__Host-oauth-tx"];
    if (!txId) {
      return new Response("Cookie temporário de transação ausente", { status: 400 });
    }

    const encoder = new TextEncoder();
    const txDigest = await crypto.subtle.digest("SHA-256", encoder.encode(txId));
    const idHash = Array.from(new Uint8Array(txDigest)).map(b => b.toString(16).padStart(2, "0")).join("");

    const tx = await env.DB.prepare("SELECT * FROM oauth_transactions WHERE id_hash = ?").bind(idHash).first();
    if (!tx || tx.expires_at < Math.floor(Date.now() / 1000) || tx.provider !== provider) {
      return new Response("Transação inválida ou expirada", { status: 400 });
    }

    const stateDigest = await crypto.subtle.digest("SHA-256", encoder.encode(state));
    const stateHash = Array.from(new Uint8Array(stateDigest)).map(b => b.toString(16).padStart(2, "0")).join("");

    if (stateHash !== tx.state_hash) {
      return new Response("State inválido", { status: 400 });
    }

    await env.DB.prepare("DELETE FROM oauth_transactions WHERE id_hash = ?").bind(idHash).run();

    const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
    let issuer = "";
    let subject = "";
    let email = null;
    let displayName = null;

    if (provider === "google") {
      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: env.GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri: redirectUri,
          grant_type: "authorization_code",
          code_verifier: tx.code_verifier
        })
      });

      const tokenData = await tokenRes.json();
      if (!tokenRes.ok || !tokenData.id_token) {
        return new Response(`Falha na troca de código do Google: ${JSON.stringify(tokenData)}`, { status: 400 });
      }

      const parts = tokenData.id_token.split(".");
      if (parts.length !== 3) return new Response("JWT inválido", { status: 400 });
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));

      if (payload.iss !== "https://accounts.google.com" && payload.iss !== "accounts.google.com") {
        return new Response("Emissor inválido", { status: 400 });
      }
      if (payload.aud !== env.GOOGLE_CLIENT_ID) {
        return new Response("Audiência inválida", { status: 400 });
      }
      if (payload.exp < Math.floor(Date.now() / 1000)) {
        return new Response("Token expirado", { status: 400 });
      }
      if (payload.nonce !== tx.nonce) {
        return new Response("Nonce inválido", { status: 400 });
      }

      issuer = "https://accounts.google.com";
      subject = payload.sub;
      email = payload.email || null;
      displayName = payload.name || payload.email;

    } else {
      const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept": "application/json"
        },
        body: new URLSearchParams({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: redirectUri,
          code_verifier: tx.code_verifier
        })
      });

      const tokenData = await tokenRes.json();
      if (!tokenRes.ok || !tokenData.access_token) {
        return new Response(`Falha na troca de código do GitHub: ${JSON.stringify(tokenData)}`, { status: 400 });
      }

      const accessToken = tokenData.access_token;

      const userRes = await fetch("https://api.github.com/user", {
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Accept": "application/vnd.github+json",
          "X-GitHub-Api-Version": "2026-03-10",
          "User-Agent": "Cloudflare-Pages-Lab"
        }
      });

      if (!userRes.ok) {
        return new Response("Falha ao consultar perfil do GitHub", { status: 400 });
      }

      const userData = await userRes.json();
      issuer = "https://github.com";
      subject = String(userData.id);
      email = userData.email || null;
      displayName = userData.name || userData.login;

      const basicAuth = btoa(`${env.GITHUB_CLIENT_ID}:${env.GITHUB_CLIENT_SECRET}`);
      await fetch(`https://api.github.com/applications/${env.GITHUB_CLIENT_ID}/grant`, {
        method: "DELETE",
        headers: {
          "Authorization": `Basic ${basicAuth}`,
          "Content-Type": "application/json",
          "User-Agent": "Cloudflare-Pages-Lab"
        },
        body: JSON.stringify({ access_token: accessToken })
      });
    }

    const sessionArray = new Uint8Array(32);
    crypto.getRandomValues(sessionArray);
    const sessionId = btoa(String.fromCharCode(...sessionArray)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    const sessionDigest = await crypto.subtle.digest("SHA-256", encoder.encode(sessionId));
    const sessionHash = Array.from(new Uint8Array(sessionDigest)).map(b => b.toString(16).padStart(2, "0")).join("");

    const now = Math.floor(Date.now() / 1000);
    const sessionExpiresAt = now + 28800;

    await env.DB.prepare(
      "INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).bind(sessionHash, issuer, subject, email, displayName, sessionExpiresAt, now).run();

    const sessionCookie = `__Host-session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`;
    const clearTempCookie = `__Host-oauth-tx=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

    // Uso correto da classe Headers para múltiplos Set-Cookie
    const responseHeaders = new Headers();
    responseHeaders.set("Location", env.PUBLIC_BASE_URL);
    responseHeaders.append("Set-Cookie", sessionCookie);
    responseHeaders.append("Set-Cookie", clearTempCookie);
    responseHeaders.set("Cache-Control", "no-store");

    return new Response(null, {
      status: 302,
      headers: responseHeaders
    });

  } catch (err) {
    return new Response(`Erro interno no callback: ${err.message}`, { status: 500 });
  }
}