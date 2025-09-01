import { serve } from "@hono/node-server";
import { Hono } from "hono";
// import { logger } from "hono/logger";
import { cors } from "hono/cors";
import { prettyJSON } from "hono/pretty-json";
import pug from "pug";

// Import routes
import { userRoutes } from "./routes/user.js";
import { developerRoutes } from "./routes/developer.js";
import { oauthRoutes } from "./routes/oauth.js";

const app = new Hono();

// Middleware
// app.use("*", logger());
app.use("*", cors());
app.use("*", prettyJSON());

// Custom Pug renderer
app.use("*", async (c, next) => {
  (c as any).render = (template: string, props?: any) => {
    const templatePath = `./src/views/${template}.pug`;
    const html = pug.renderFile(templatePath, props || {});
    return c.html(html);
  };
  await next();
});

// Routes
app.route("/user", userRoutes); // User authentication (end users)
app.route("/dev", developerRoutes); // Developer dashboard (programmers)
app.route("/oauth", oauthRoutes); // OAuth endpoints

// Home page
app.get("/", (c) => {
  return c.render("home");
});

// OpenID Connect Discovery
app.get("/.well-known/openid_configuration", (c) => {
  const baseUrl = `http://${c.req.header("host")}`;
  return c.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
    jwks_uri: `${baseUrl}/oauth/jwks`,
    response_types_supported: ["code", "id_token", "token id_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: [
      "openid",
      "profile",
      "email",
      "name",
      "about",
      "website",
      "twitter",
      "github",
    ],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
  });
});

const port = 3000;
console.log(`🚀 OpenID Provider running on port ${port}`);
console.log(`🏠 Home: http://localhost:${port}`);
console.log(`👤 User Login: http://localhost:${port}/user/login`);
console.log(`👨‍💻 Developer Portal: http://localhost:${port}/dev/login`);
console.log(`🔐 OAuth: http://localhost:${port}/oauth`);

serve({
  fetch: app.fetch,
  port,
});
