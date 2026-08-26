const RTK_AUTHORIZE_URL = "https://routicket.com/oauth/authorize.php";
const RTK_TOKEN_URL = "https://routicket.com/oauth/token.php";
const RTK_USERINFO_URL = "https://routicket.com/oauth/userinfo.php";

const COOKIE_STATE = "rtk_oauth_state";
const COOKIE_VERIFIER = "rtk_oauth_verifier";
const COOKIE_TOKEN = "rtk_access_token";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/oauth/login") return oauthLogin(env);
    if (url.pathname === "/oauth/callback") return oauthCallback(request, url, env);
    if (url.pathname === "/oauth/status") return oauthStatus(request, env);
    if (url.pathname === "/oauth/logout" && request.method === "POST") return oauthLogout();

    return env.ASSETS.fetch(request);
  },
};

async function oauthLogin(env) {
  assertConfig(env);

  const state = randomBase64Url(32);
  const verifier = randomBase64Url(64);
  const challenge = await sha256Base64Url(verifier);

  const authorize = new URL(RTK_AUTHORIZE_URL);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("client_id", env.RTK_CLIENT_ID);
  authorize.searchParams.set("redirect_uri", env.RTK_REDIRECT_URI);
  authorize.searchParams.set("code_challenge", challenge);
  authorize.searchParams.set("code_challenge_method", "S256");
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("scope", env.RTK_SCOPE || "profile email");

  const headers = new Headers({ Location: authorize.toString() });
  headers.append("Set-Cookie", makeCookie(COOKIE_STATE, state, 600));
  headers.append("Set-Cookie", makeCookie(COOKIE_VERIFIER, verifier, 600));

  return new Response(null, { status: 302, headers });
}

async function oauthCallback(request, url, env) {
  assertConfig(env);

  const error = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const expectedState = cookies[COOKIE_STATE];
  const verifier = cookies[COOKIE_VERIFIER];

  if (error) return redirectWithClearedPkce(`${env.APP_URL}?oauth=cancelled&reason=${encodeURIComponent(error)}`);
  if (!code || !state) return redirectWithClearedPkce(`${env.APP_URL}?oauth=error&reason=missing_code_or_state`);
  if (!expectedState || !verifier || !safeEqual(state, expectedState)) {
    return redirectWithClearedPkce(`${env.APP_URL}?oauth=error&reason=invalid_or_expired_state`);
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
    return redirectWithClearedPkce(`${env.APP_URL}?oauth=error&reason=token_rejected`);
  }

  const profile = await fetchProfile(tokenResult.access_token);
  if (!profile) {
    return redirectWithClearedPkce(`${env.APP_URL}?oauth=error&reason=profile_unavailable`);
  }

  const maxAge = Math.max(60, Math.min(Number(tokenResult.expires_in) || 3600, 60 * 60 * 24 * 7));
  const headers = new Headers({ Location: `${env.APP_URL}?oauth=success` });
  headers.append("Set-Cookie", clearCookie(COOKIE_STATE));
  headers.append("Set-Cookie", clearCookie(COOKIE_VERIFIER));
  headers.append("Set-Cookie", makeCookie(COOKIE_TOKEN, tokenResult.access_token, maxAge));

  return new Response(null, { status: 302, headers });
}

async function oauthStatus(request, env) {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const token = cookies[COOKIE_TOKEN];

  if (!token) {
    return json({ ok: true, connected: false, profile: null });
  }

  const profile = await fetchProfile(token);
  if (!profile) {
    const response = json({ ok: true, connected: false, profile: null });
    response.headers.append("Set-Cookie", clearCookie(COOKIE_TOKEN));
    return response;
  }

  return json({ ok: true, connected: true, profile });
}

function oauthLogout() {
  const response = json({ ok: true });
  response.headers.append("Set-Cookie", clearCookie(COOKIE_TOKEN));
  response.headers.append("Set-Cookie", clearCookie(COOKIE_STATE));
  response.headers.append("Set-Cookie", clearCookie(COOKIE_VERIFIER));
  return response;
}

async function fetchProfile(accessToken) {
  try {
    const response = await fetch(RTK_USERINFO_URL, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
      },
    });
    const payload = await safeJson(response);
    if (!response.ok) return null;
    return normalizeProfile(payload);
  } catch {
    return null;
  }
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
  if (!env.RTK_CLIENT_ID) missing.push("RTK_CLIENT_ID");
  if (!env.RTK_REDIRECT_URI) missing.push("RTK_REDIRECT_URI");
  if (!env.APP_URL) missing.push("APP_URL");
  if (missing.length) throw new Error(`Missing OAuth configuration: ${missing.join(", ")}`);
}

function parseCookies(header) {
  return Object.fromEntries(
    header.split(";").map(v => v.trim()).filter(Boolean).map(pair => {
      const index = pair.indexOf("=");
      return index === -1 ? [pair, ""] : [pair.slice(0, index), decodeURIComponent(pair.slice(index + 1))];
    }),
  );
}

function makeCookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function clearCookie(name) {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function redirectWithClearedPkce(location) {
  const headers = new Headers({ Location: location });
  headers.append("Set-Cookie", clearCookie(COOKIE_STATE));
  headers.append("Set-Cookie", clearCookie(COOKIE_VERIFIER));
  return new Response(null, { status: 302, headers });
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
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
  try { return text ? JSON.parse(text) : {}; } catch { return null; }
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
