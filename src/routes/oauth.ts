import { Hono } from "hono";
import { prisma } from "../lib/db.js";
import { generateIdToken, generateAccessToken, verifyToken, getPublicJWK } from "../lib/jwt.js";
import { v4 as uuidv4 } from "uuid";
import { baseUrl } from "../utils/baseUrl.js";

export const oauthRoutes = new Hono();

// Authorization endpoint
oauthRoutes.get("/authorize", async (c) => {
  const { client_id, redirect_uri, response_type, scope, state } = c.req.query();

  if (!client_id || !redirect_uri || !response_type) {
    return c.text("Missing required parameters", 400);
  }

  // Check if client exists
  const client = await prisma.oAuthClient.findUnique({
    where: { clientId: client_id },
  });

  if (!client) {
    return c.text("Invalid client", 400);
  }

  // Check if redirect_uri is registered
  if (!client.redirectUris.includes(redirect_uri)) {
    return c.text("Invalid redirect URI", 400);
  }

  // Validate requested scopes against allowed scopes
  const requestedScopes = scope ? scope.split(" ").filter((s) => s.trim()) : ["openid"];
  const allowedScopes = client.allowedScopes || [];

  // Check if all requested scopes are allowed
  const unauthorizedScopes = requestedScopes.filter((scope) => !allowedScopes.includes(scope));

  if (unauthorizedScopes.length > 0) {
    return c.text(
      `Client is not authorized to request the following scopes: ${unauthorizedScopes.join(", ")}. ` +
        `Allowed scopes: ${allowedScopes.join(", ")}`,
      400,
    );
  }

  // Check if user is already authenticated (basic session check)
  // In production, you'd use proper session management or JWT tokens
  const sessionCookie = c.req.header("Cookie")?.match(/session=([^;]+)/)?.[1];

  if (sessionCookie) {
    // User appears to be authenticated, redirect to consent page
    // For now, we'll redirect to login to get the authorization code
    const loginUrl = new URL("/user/login", `http://${c.req.header("host")}`);
    loginUrl.searchParams.set("client_id", client_id);
    loginUrl.searchParams.set("redirect_uri", redirect_uri);
    loginUrl.searchParams.set("response_type", response_type);
    if (scope) loginUrl.searchParams.set("scope", scope);
    if (state) loginUrl.searchParams.set("state", state);
    return c.redirect(loginUrl.toString());
  }

  // User not authenticated, redirect to login
  const loginUrl = new URL("/user/login", `http://${c.req.header("host")}`);
  loginUrl.searchParams.set("client_id", client_id);
  loginUrl.searchParams.set("redirect_uri", redirect_uri);
  loginUrl.searchParams.set("response_type", response_type);
  if (scope) loginUrl.searchParams.set("scope", scope);
  if (state) loginUrl.searchParams.set("state", state);

  return c.redirect(loginUrl.toString());
});

// Token endpoint - handles both authorization_code and refresh_token flows
oauthRoutes.post("/token", async (c) => {
  const body = await c.req.parseBody();
  const { grant_type, code, refresh_token, client_id, client_secret, redirect_uri } = body;

  // Handle refresh token flow
  if (grant_type === "refresh_token") {
    if (!refresh_token || !client_id || !client_secret) {
      return c.json({ error: "invalid_request" }, 400);
    }

    const client = await prisma.oAuthClient.findUnique({
      where: { clientId: client_id as string },
    });

    if (!client || client.clientSecret !== client_secret) {
      return c.json({ error: "invalid_client" }, 401);
    }

    const refreshTokenRecord = await prisma.refreshToken.findUnique({
      where: { token: refresh_token as string },
      include: { user: true },
    });

    if (!refreshTokenRecord || refreshTokenRecord.expiresAt < new Date()) {
      return c.json({ error: "invalid_grant" }, 400);
    }

    if (refreshTokenRecord.clientId !== client.id) {
      return c.json({ error: "invalid_grant" }, 400);
    }

    const user = refreshTokenRecord.user;

    // Generate new access token with same scopes (we'll need to store scopes in refresh token)
    const accessToken = await generateAccessToken(
      user.id,
      client.id,
      "openid", // Default scope, should be stored in refresh token
    );

    return c.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
    });
  }

  // Handle authorization code flow
  if (grant_type === "authorization_code") {
    if (!code || !client_id || !client_secret || !redirect_uri) {
      return c.json({ error: "invalid_request" }, 400);
    }

    const client = await prisma.oAuthClient.findUnique({
      where: { clientId: client_id as string },
    });

    if (!client || client.clientSecret !== client_secret) {
      return c.json({ error: "invalid_client" }, 401);
    }

    const authCode = await prisma.authorizationCode.findUnique({
      where: {
        code: code as string,
        clientId: client.id,
      },
      include: { user: true },
    });

    if (!authCode || authCode.expiresAt < new Date()) {
      return c.json({ error: "invalid_grant" }, 400);
    }

    if (authCode.redirectUri !== redirect_uri) {
      return c.json({ error: "invalid_grant" }, 400);
    }

    const user = authCode.user;
    const grantedScopes = authCode.scope || "openid";

    const [accessToken, idToken] = await Promise.all([
      generateAccessToken(user.id, client.id, grantedScopes, baseUrl(c)),
      generateIdToken(user, client.clientId, grantedScopes, baseUrl(c)),
    ]);

    await prisma.authorizationCode.delete({ where: { id: authCode.id } });

    // Create refresh token
    const refreshTokenValue = uuidv4();
    await prisma.refreshToken.create({
      data: {
        token: refreshTokenValue,
        clientId: client.id,
        userId: user.id,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      },
    });

    return c.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: refreshTokenValue,
      id_token: idToken,
    });
  }

  return c.json({ error: "unsupported_grant_type" }, 400);
});

// UserInfo endpoint
oauthRoutes.get("/userinfo", async (c) => {
  const auth = c.req.header("Authorization");
  if (!auth?.startsWith("Bearer ")) {
    return c.json({ error: "invalid_token" }, 401);
  }

  const token = auth.substring(7);

  try {
    const { payload } = await verifyToken(token);
    const userId = payload.sub;
    const grantedScopes = typeof payload.scope === "string" ? payload.scope.split(" ") : ["openid"];

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        name: true,
        about: true,
        website: true,
        twitter: true,
        github: true,
      },
    });

    if (!user) {
      return c.json({ error: "invalid_token" }, 401);
    }

    // Filter response based on granted scopes
    const response: any = {
      sub: user.id, // Always include sub (required by OpenID Connect)
    };

    // Add email scope data
    if (grantedScopes.includes("email")) {
      response.email = user.email;
    }

    // Add granular profile scope data
    if (grantedScopes.includes("name")) {
      response.name = user.name;
    }
    if (grantedScopes.includes("about")) {
      response.about = user.about;
    }
    if (grantedScopes.includes("website")) {
      response.website = user.website;
    }
    if (grantedScopes.includes("twitter")) {
      response.twitter = user.twitter;
    }
    if (grantedScopes.includes("github")) {
      response.github = user.github;
    }

    // Backward compatibility: if profile scope is granted, include all profile fields
    if (grantedScopes.includes("profile")) {
      response.name = user.name;
      response.about = user.about;
      response.website = user.website;
      response.twitter = user.twitter;
      response.github = user.github;
    }

    return c.json(response);
  } catch (_error) {
    return c.json({ error: "invalid_token" }, 401);
  }
});

// JWKS endpoint
oauthRoutes.get("/jwks", async (c) => {
  const jwk = await getPublicJWK();

  return c.json({
    keys: [
      {
        ...jwk,
        kty: "RSA",
        kid: "1",
        use: "sig",
        alg: "RS256",
      },
    ],
  });
});
