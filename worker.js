const RTK_AUTHORIZE_URL = "https://routicket.com/oauth/authorize.php";
const RTK_TOKEN_URL = "https://routicket.com/oauth/token.php";
const RTK_USERINFO_URL = "https://routicket.com/oauth/userinfo.php";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/oauth/login") return oauthLogin(env);
    if (url.pathname === "/oauth/callback") return oauthCallback(url, env);
    if (url.pathname === "/oauth/status") return oauthStatus(env);
    if (url.pathname === "/oauth/logout" && request.method === "POST") return oauthLogout(env);

    return env.ASSETS.fetch(request);
  },
};

async function oauthLogin(env) {
  assertConfig(env);

  const state = randomBase64Url(32);
  const verifier = randomBase64Url(64);
  const challenge = await sha256Base64Url(verifier);

  await env.OAUTH_KV.put(`oauth_verifier:${state}`, verifier, {
    expirationTtl: 600,
  });

  const authorize = new URL(RTK_AUTHORIZE_URL);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("client_id", env.RTK_CLIENT_ID);
  authorize.searchParams.set("redirect_uri", env.RTK_REDIRECT_URI);
  authorize.searchParams.set("code_challenge", challenge);
  authorize.searchParams.set("code_challenge_method", "S256");
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("scope", env.RTK_SCOPE || "profile email");

  return Response.redirect(authorize.toString(), 302);
}

async function oauthCallback(url, env) {
  assertConfig(env);

  const error = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (error) {
    return Response.redirect(`${env.APP_URL}?oauth=cancelled&reason=${encodeURIComponent(error)}`, 302);
  }

  if (!code || !state) {
    return Response.redirect(`${env.APP_URL}?oauth=error&reason=missing_code_or_state`, 302);
  }

  const verifierKey = `oauth_verifier:${state}`;
  const verifier = await env.OAUTH_KV.get(verifierKey);

  if (!verifier) {
    return Response.redirect(`${env.APP_URL}?oauth=error&reason=invalid_or_expired_state`, 302);
  }

  const tokenBody = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: env.RTK_CLIENT_ID,
    code,
    redirect_uri: env.RTK_REDIRECT_URI,
    code_verifier: verifier,
  });

  const tokenResponse = await fetch(RTK_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: tokenBody,
  });

  const tokenResult = await safeJson(tokenResponse);

  if (!tokenResponse.ok || !tokenResult?.access_token) {
    return Response.redirect(`${env.APP_URL}?oauth=error&reason=token_rejected`, 302);
  }

  const profileResponse = await fetch(RTK_USERINFO_URL, {
    headers: {
      Authorization: `Bearer ${tokenResult.access_token}`,
      Accept: "application/json",
    },
  });

  const userinfo = await safeJson(profileResponse);
  const profile = normalizeProfile(userinfo);

  if (!profileResponse.ok || !profile) {
    return Response.redirect(`${env.APP_URL}?oauth=error&reason=profile_unavailable`, 302);
  }

  await Promise.all([
    env.OAUTH_KV.put("routicket_access_token", tokenResult.access_token),
    tokenResult.refresh_token
      ? env.OAUTH_KV.put("routicket_refresh_token", tokenResult.refresh_token)
      : Promise.resolve(),
    env.OAUTH_KV.put("routicket_profile", JSON.stringify(profile)),
    env.OAUTH_KV.put(
      "routicket_token_meta",
      JSON.stringify({
        connected_at: new Date().toISOString(),
        expires_in: tokenResult.expires_in ?? null,
        token_type: tokenResult.token_type || "Bearer",
        scope: tokenResult.scope || env.RTK_SCOPE || "profile email",
      }),
    ),
    env.OAUTH_KV.delete(verifierKey),
  ]);

  return Response.redirect(`${env.APP_URL}?oauth=success`, 302);
}

async function oauthStatus(env) {
  assertConfig(env);

  const [token, profile, meta] = await Promise.all([
    env.OAUTH_KV.get("routicket_access_token"),
    env.OAUTH_KV.get("routicket_profile", "json"),
    env.OAUTH_KV.get("routicket_token_meta", "json"),
  ]);

  return json({
    ok: true,
    connected: Boolean(token && profile),
    profile: profile || null,
    meta: meta || null,
  });
}

async function oauthLogout(env) {
  assertConfig(env);

  await Promise.all([
    env.OAUTH_KV.delete("routicket_access_token"),
    env.OAUTH_KV.delete("routicket_refresh_token"),
    env.OAUTH_KV.delete("routicket_profile"),
    env.OAUTH_KV.delete("routicket_token_meta"),
  ]);

  return json({ ok: true });
}

function normalizeProfile(payload) {
  if (!payload || typeof payload !== "object") return null;

  const source = payload.user || payload.profile || payload.data || payload;
  const id = source.id ?? source.user_id ?? source.id_usuario ?? source.usuario_id ?? null;
  const name = source.name ?? source.nombre ?? source.display_name ?? source.username ?? null;
  const email = source.email ?? source.correo ?? null;
  const photo = source.photo ?? source.foto ?? source.avatar ?? source.picture ?? null;

  if (!id) return null;

  return {
    id,
    name: name || "Usuario Routicket",
    email: email || null,
    photo: photo || null,
  };
}

function assertConfig(env) {
  const missing = [];
  if (!env.OAUTH_KV) missing.push("OAUTH_KV");
  if (!env.RTK_CLIENT_ID) missing.push("RTK_CLIENT_ID");
  if (!env.RTK_REDIRECT_URI) missing.push("RTK_REDIRECT_URI");
  if (!env.APP_URL) missing.push("APP_URL");

  if (missing.length) {
    throw new Error(`Missing OAuth configuration: ${missing.join(", ")}`);
  }
}

function randomBase64Url(bytes) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return bytesToBase64Url(data);
}

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToBase64Url(new Uint8Array(digest));
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function safeJson(response) {
  const text = await response.text();
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    return null;
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}
