export async function onRequestGet(context) {
  const { request, env } = context;
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = Object.fromEntries(
    cookieHeader.split(";").map(c => {
      const [key, ...v] = c.trim().split("=");
      return [key, v.join("=")];
    })
  );

  const sessionId = cookies["__Host-session"];
  if (!sessionId) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }

  const encoder = new TextEncoder();
  const sessionDigest = await crypto.subtle.digest("SHA-256", encoder.encode(sessionId));
  const sessionHash = Array.from(new Uint8Array(sessionDigest)).map(b => b.toString(16).padStart(2, "0")).join("");

  const session = await env.DB.prepare("SELECT * FROM sessions WHERE id_hash = ?").bind(sessionHash).first();
  const now = Math.floor(Date.now() / 1000);

  if (!session || session.expires_at < now) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }

  return new Response(JSON.stringify({
    issuer: session.issuer,
    subject: session.subject,
    email: session.email,
    displayName: session.display_name
  }), {
    status: 200,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
  });
}