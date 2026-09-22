export async function onRequestPost(context) {
  const { request, env } = context;

  const origin = request.headers.get("Origin");
  if (!origin || origin !== env.PUBLIC_BASE_URL) {
    return new Response("Origin inválida", { status: 403 });
  }

  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = Object.fromEntries(cookieHeader.split(";").map(c => {
    const [key, ...v] = c.trim().split("=");
    return [key, v.join("=")];
  }));

  const sessionId = cookies["__Host-session"];
  if (sessionId) {
    const encoder = new TextEncoder();
    const sessionDigest = await crypto.subtle.digest("SHA-256", encoder.encode(sessionId));
    const sessionHash = Array.from(new Uint8Array(sessionDigest)).map(b => b.toString(16).padStart(2, "0")).join("");

    await env.DB.prepare("DELETE FROM sessions WHERE id_hash = ?").bind(sessionHash).run();
  }

  const expireCookie = `__Host-session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

  return new Response(null, {
    status: 302,
    headers: {
      "Location": env.PUBLIC_BASE_URL,
      "Set-Cookie": expireCookie,
      "Cache-Control": "no-store"
    }
  });
}