import { Hono } from "hono";
import "dotenv/config";

// Demo client configuration
const DEMO_CONFIG = {
  clientId: process.env.DEMO_CLIENT_KEY || "92bc7e9e-44b6-431d-9ff5-8d8fd4aa4041",
  clientSecret: process.env.DEMO_SECRET_KEY || "cc3cc342-4f1e-487d-91ab-d5525baf5905",
  redirectUri: "", // Will be set dynamically based on request
  authorizationEndpoint: "", // Will be set dynamically
  tokenEndpoint: "", // Will be set dynamically
  userinfoEndpoint: "", // Will be set dynamically
  scope: "openid, email, name, about, website, twitter, github",
};

const demoRoutes = new Hono();

// Demo page
demoRoutes.get("/", async (c) => {
  // Get the current host for dynamic URLs
  const host = c.req.header("host") || "localhost:3000";
  const protocol = host.includes("localhost") ? "http" : "https";
  const baseUrl = `${protocol}://${host}`;

  // Update config with current host
  const config = {
    ...DEMO_CONFIG,
    redirectUri: `${protocol}://${host}/demo`,
    authorizationEndpoint: `${baseUrl}/oauth/authorize`,
    tokenEndpoint: `${baseUrl}/oauth/token`,
    userinfoEndpoint: `${baseUrl}/oauth/userinfo`,
  };

  return (c as any).render("demo", { baseUrl, config });
});

// Demo configuration endpoint (without secret for client-side)
demoRoutes.get("/config", async (c) => {
  // Get the current host for dynamic URLs
  const host = c.req.header("host") || "localhost:3000";
  const protocol = host.includes("localhost") ? "http" : "https";
  const baseUrl = `${protocol}://${host}`;

  // Return config without secret (for client-side use)
  const clientConfig = {
    clientId: DEMO_CONFIG.clientId,
    redirectUri: `${protocol}://${host}/demo`,
    authorizationEndpoint: `${baseUrl}/oauth/authorize`,
    tokenEndpoint: `${baseUrl}/oauth/token`,
    userinfoEndpoint: `${baseUrl}/oauth/userinfo`,
    scope: DEMO_CONFIG.scope,
  };

  return c.json(clientConfig);
});

// Demo token exchange endpoint (server-side with secret)
demoRoutes.post("/token", async (c) => {
  try {
    const body = await c.req.parseBody();
    const { code, redirect_uri, grant_type, refresh_token } = body as any;

    // Get the current host for dynamic URLs
    const host = c.req.header("host") || "localhost:3000";
    const protocol = host.includes("localhost") ? "http" : "https";
    const baseUrl = `${protocol}://${host}`;

    let tokenParams: URLSearchParams;

    if (grant_type === "refresh_token") {
      // Handle refresh token request
      if (!refresh_token) {
        return c.json({ error: "Missing refresh token" }, 400);
      }

      tokenParams = new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refresh_token,
        client_id: DEMO_CONFIG.clientId,
        client_secret: DEMO_CONFIG.clientSecret,
      });
    } else {
      // Handle authorization code exchange
      if (!code) {
        return c.json({ error: "Missing authorization code" }, 400);
      }

      tokenParams = new URLSearchParams({
        grant_type: "authorization_code",
        code: code,
        client_id: DEMO_CONFIG.clientId,
        client_secret: DEMO_CONFIG.clientSecret,
        redirect_uri: redirect_uri || `${protocol}://${host}/demo`,
      });
    }

    // Exchange code/token using server-side secret
    const tokenResponse = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: tokenParams,
    });

    if (!tokenResponse.ok) {
      const error = await tokenResponse.text();
      console.error("Token exchange failed:", error);
      return c.json({ error: "Failed to exchange token" }, 500);
    }

    const tokenData = await tokenResponse.json();
    return c.json(tokenData);
  } catch (error) {
    console.error("Demo token exchange error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

export { demoRoutes };
