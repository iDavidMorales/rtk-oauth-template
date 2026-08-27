const RTK_AUTHORIZE_URL = "https://routicket.com/oauth/authorize.php";
const RTK_TOKEN_URL = "https://routicket.com/oauth/token.php";
const RTK_USERINFO_URL = "https://routicket.com/oauth/userinfo.php";
const RTK_APP_URL = "https://routicket.com/oauth/app.php";

const COOKIE_STATE = "rtk_oauth_state";
const COOKIE_VERIFIER = "rtk_oauth_verifier";
const COOKIE_TOKEN = "rtk_access_token";
const COOKIE_RETURN = "rtk_oauth_return";
const COOKIE_APP = "rtk_oauth_app";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/oauth/login") {
      try { return await oauthLogin(url, env); }
      catch (error) { return json({ ok: false, error: "oauth_login_unavailable", detail: error?.message || "configuration_error" }, 503); }
    }
    if (url.pathname === "/oauth/callback") return oauthCallback(request, url, env);
    if (url.pathname === "/oauth/status") return oauthStatus(request);
    if (url.pathname === "/oauth/logout" && request.method === "POST") return oauthLogout();

    return env.ASSETS.fetch(request);
  },
};

async function oauthLogin(url, env) {
  const app = await resolveApp(url, env);

  const state = randomBase64Url(32);
  const verifier = randomBase64Url(64);
  const challenge = await sha256Base64Url(verifier);
  const requestedReturn = normalizeReturnUrl(url.searchParams.get("return"));

  const authorize = new URL(RTK_AUTHORIZE_URL);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("client_id", app.client_id);
  authorize.searchParams.set("redirect_uri", app.redirect_uri);
  authorize.searchParams.set("code_challenge", challenge);
  authorize.searchParams.set("code_challenge_method", "S256");
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("scope", app.scopes.join(" "));

  const headers = new Headers({ Location: authorize.toString() });
  headers.append("Set-Cookie", makeCookie(COOKIE_STATE, state, 600));
  headers.append("Set-Cookie", makeCookie(COOKIE_VERIFIER, verifier, 600));
  headers.append("Set-Cookie", makeCookie(COOKIE_APP, JSON.stringify(app), 600));
  if (requestedReturn) headers.append("Set-Cookie", makeCookie(COOKIE_RETURN, requestedReturn, 600));
  else headers.append("Set-Cookie", clearCookie(COOKIE_RETURN));

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
  const gameReturn = normalizeReturnUrl(cookies[COOKIE_RETURN]);
  const app = parseJsonCookie(cookies[COOKIE_APP]);
  if (!app?.client_id || !app?.redirect_uri) return redirectWithClearedPkce(buildReturn(gameReturn, env.APP_URL, "error", "missing_app_context"));
  const fallback = env.APP_URL;

  if (error) return redirectWithClearedPkce(buildReturn(gameReturn, fallback, "cancelled", error));
  if (!code || !state) return redirectWithClearedPkce(buildReturn(gameReturn, fallback, "error", "missing_code_or_state"));
  if (!expectedState || !verifier || !safeEqual(state, expectedState)) {
    return redirectWithClearedPkce(buildReturn(gameReturn, fallback, "error", "invalid_or_expired_state"));
  }

  const tokenBody = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: app.client_id,
    code,
    redirect_uri: app.redirect_uri,
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
    return redirectWithClearedPkce(buildReturn(gameReturn, fallback, "error", "token_rejected"));
  }

  // userinfo is useful for showing the profile, but it must not block
  // wallet authentication. A valid access_token is enough for Royal Win.
  const profile = await fetchProfile(tokenResult.access_token);
  const maxAge = Math.max(60, Math.min(Number(tokenResult.expires_in) || 3600, 60 * 60 * 24 * 7));

  if (gameReturn) {
    const bridge = new URL("https://routicket.com/plugins/bank2/user/game_wallet.php");
    bridge.searchParams.set("action", "connect");
    bridge.searchParams.set("return", gameReturn);
    const headers = new Headers({ Location: bridge.toString() });
    headers.append("Set-Cookie", clearCookie(COOKIE_STATE));
    headers.append("Set-Cookie", clearCookie(COOKIE_VERIFIER));
    headers.append("Set-Cookie", clearCookie(COOKIE_RETURN));
    headers.append("Set-Cookie", makeCookie(COOKIE_TOKEN, tokenResult.access_token, maxAge));
    return new Response(null, { status: 302, headers });
  }

  const destination = new URL(fallback);
  destination.searchParams.set("oauth", "success");
  destination.searchParams.set("profile", profile ? "available" : "unavailable");
  const headers = successHeaders(destination.toString(), tokenResult.access_token, maxAge);
  return new Response(null, { status: 302, headers });
}

async function oauthStatus(request) {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const token = cookies[COOKIE_TOKEN];
  if (!token) return json({ ok: true, connected: false, profile: null });

  const profile = await fetchProfile(token);
  return json({
    ok: true,
    connected: true,
    profile: profile || null,
    profile_available: Boolean(profile),
  });
}

function oauthLogout() {
  const response = json({ ok: true });
  response.headers.append("Set-Cookie", clearCookie(COOKIE_TOKEN));
  response.headers.append("Set-Cookie", clearCookie(COOKIE_STATE));
  response.headers.append("Set-Cookie", clearCookie(COOKIE_VERIFIER));
  response.headers.append("Set-Cookie", clearCookie(COOKIE_RETURN));
  return response;
}

function successHeaders(location, accessToken, maxAge) {
  const headers = new Headers({ Location: location });
  headers.append("Set-Cookie", clearCookie(COOKIE_STATE));
  headers.append("Set-Cookie", clearCookie(COOKIE_VERIFIER));
  headers.append("Set-Cookie", clearCookie(COOKIE_RETURN));
  headers.append("Set-Cookie", makeCookie(COOKIE_TOKEN, accessToken, maxAge));
  return headers;
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
    if (!response.ok || !payload) return null;
    return normalizeProfile(payload);
  } catch {
    return null;
  }
}

function normalizeProfile(payload) {
  if (!payload || typeof payload !== "object") return null;

  const candidates = [
    payload,
    payload.user,
    payload.profile,
    payload.data,
    payload.data?.user,
    payload.data?.profile,
    payload.result,
  ].filter(v => v && typeof v === "object");

  for (const source of candidates) {
    const id = source.id ?? source.user_id ?? source.id_usuario ?? source.usuario_id ?? source.uid ?? source.sub ?? null;
    const name = source.name ?? source.nombre ?? source.display_name ?? source.username ?? source.user_name ?? null;
    const email = source.email ?? source.correo ?? source.mail ?? null;
    const photo = source.photo ?? source.foto ?? source.avatar ?? source.picture ?? source.image ?? source.profile_photo ?? null;

    if (id || email || name) {
      return {
        id: id || null,
        name: name || "Usuario Routicket",
        email: email || null,
        photo: photo || null,
      };
    }
  }

  return null;
}

function normalizeReturnUrl(value) {
  if (!value) return null;
  try {
    const url = new URL(value);
    const allowedOrigin = url.origin === "https://rtk-games.vercel.app";
    const allowedPath = url.pathname.startsWith("/game/05/") || url.pathname === "/game/05"
      || url.pathname.startsWith("/game/01/ruleta-riviera/") || url.pathname === "/game/01/ruleta-riviera";
    if (!allowedOrigin || !allowedPath) return null;
    url.hash = "";
    return url.toString();
  } catch {
    return null;
  }
}

async function resolveApp(url, env) {
  const id = url.searchParams.get('app_id');
  const slug = url.searchParams.get('slug');
  const query = id ? `app_id=${encodeURIComponent(id)}` : (slug ? `slug=${encodeURIComponent(slug)}` : '');
  if (!query) throw new Error('Missing app_id');
  const response = await fetch(`${RTK_APP_URL}?${query}`, { headers: { Accept: 'application/json' } });
  const payload = await safeJson(response);
  if (!response.ok || !payload?.app) throw new Error('App not registered');
  const app = payload.app;
  const redirects = Array.isArray(app.redirect_uris) ? app.redirect_uris : [];
  const scopes = Array.isArray(app.scopes) ? app.scopes : [];
  const redirect = redirects.find(value => {
    try { return new URL(value).pathname === '/oauth/callback'; }
    catch { return false; }
  });
  if (!redirect) throw new Error('Worker callback is not registered for this app');
  return { ...app, redirect_uri: redirect, scopes: scopes.length ? scopes : ['profile', 'email'] };
}

function parseJsonCookie(value) {
  try { return JSON.parse(value || ''); } catch { return null; }
}

function buildReturn(gameReturn, fallback, status, reason) {
  const destination = new URL(gameReturn || fallback);
  destination.searchParams.set("oauth", status);
  if (reason) destination.searchParams.set("reason", reason);
  return destination.toString();
}

function assertConfig(env) {
  const missing = [];
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
  headers.append("Set-Cookie", clearCookie(COOKIE_RETURN));
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
