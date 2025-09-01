import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { logger } from "hono/logger";
import { cors } from "hono/cors";
import { prettyJSON } from "hono/pretty-json";
import { authRoutes } from "./routes/auth.js";
import { clientRoutes } from "./routes/clients.js";
import { dashboardRoutes } from "./routes/dashboard.js";

// const app = new Hono();

// app.use("*", logger());
// app.use("*", cors());
// app.use("*", prettyJSON());

// // Routes
// app.route("/auth", authRoutes);
// app.route("/clients", clientRoutes);
// app.route("/", dashboardRoutes);

// // Discovery endpoint
// app.get("/.well-known/openid_configuration", (c) => {
// 	const baseUrl = `http://${c.req.header("host")}`;
// 	return c.json({
// 		issuer: baseUrl,
// 		authorization_endpoint: `${baseUrl}/auth/authorize`,
// 		token_endpoint: `${baseUrl}/auth/token`,
// 		userinfo_endpoint: `${baseUrl}/auth/userinfo`,
// 		jwks_uri: `${baseUrl}/auth/jwks`,
// 		response_types_supported: ["code", "id_token", "token id_token"],
// 		subject_types_supported: ["public"],
// 		id_token_signing_alg_values_supported: ["RS256"],
// 		scopes_supported: ["openid", "profile", "email"],
// 		token_endpoint_auth_methods_supported: [
// 			"client_secret_basic",
// 			"client_secret_post",
// 		],
// 	});
// });

// const port = 3000;
// console.log(`Server is running on port ${port}`);

// serve({
// 	fetch: app.fetch,
// 	port,
// });

// src/index.ts - Update routing
const app = new Hono();

app.use("*", logger());
app.use("*", cors());
app.use("*", prettyJSON());

// Static routes first
app.route("/", dashboardRoutes);
app.route("/login", dashboardRoutes);
app.route("/register", dashboardRoutes);

// Auth routes
app.route("/auth", authRoutes);

// API routes
app.route("/clients", clientRoutes);

// Discovery endpoint
app.get("/.well-known/openid_configuration", (c) => {
	const baseUrl = `http://${c.req.header("host")}`;
	return c.json({
		issuer: baseUrl,
		authorization_endpoint: `${baseUrl}/auth/authorize`,
		token_endpoint: `${baseUrl}/auth/token`,
		userinfo_endpoint: `${baseUrl}/auth/userinfo`,
		jwks_uri: `${baseUrl}/auth/jwks`,
		response_types_supported: ["code", "id_token", "token id_token"],
		subject_types_supported: ["public"],
		id_token_signing_alg_values_supported: ["HS256"],
		scopes_supported: ["openid", "profile", "email"],
		token_endpoint_auth_methods_supported: [
			"client_secret_basic",
			"client_secret_post",
		],
	});
});

// app.get("/.well-known/openid_configuration", (c) => {
// 	const baseUrl = `http://${c.req.header("host")}`;
// 	return c.json({
// 		issuer: baseUrl,
// 		authorization_endpoint: `${baseUrl}/auth/authorize`,
// 		token_endpoint: `${baseUrl}/auth/token`,
// 		userinfo_endpoint: `${baseUrl}/auth/userinfo`,
// 		jwks_uri: `${baseUrl}/auth/jwks`,
// 		response_types_supported: ["code", "id_token", "token id_token"],
// 		subject_types_supported: ["public"],
// 		id_token_signing_alg_values_supported: ["HS256"],
// 		scopes_supported: ["openid", "profile", "email"],
// 		token_endpoint_auth_methods_supported: [
// 			"client_secret_basic",
// 			"client_secret_post",
// 		],
// 	});
// });

const port = 3000;
console.log(`Server is running on port ${port}`);

serve({
	fetch: app.fetch,
	port,
});
