import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { prisma } from "../db/prisma.js";
import {
	generateIdToken,
	generateAccessToken,
	verifyToken,
	getPublicJWK,
} from "../lib/jwt.js";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
// import { privateKey, publicKey } from "../lib/jwt.js";

export const authRoutes = new Hono();

// Login page
authRoutes.get("/login", (c) => {
	return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Login - OpenID Provider</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        input { width: 100%; padding: 10px; margin: 10px 0; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
      </style>
    </head>
    <body>
      <h1>Login</h1>
      <form method="POST" action="/auth/login">
        <input type="email" name="email" placeholder="Email" required />
        <input type="password" name="password" placeholder="Password" required />
        <input type="hidden" name="redirect_uri" value="${c.req.query("redirect_uri")}" />
        <input type="hidden" name="client_id" value="${c.req.query("client_id")}" />
        <input type="hidden" name="state" value="${c.req.query("state")}" />
        <input type="hidden" name="scope" value="${c.req.query("scope")}" />
        <button type="submit">Login</button>
      </form>
      <p>Don't have an account? <a href="/register">Register here</a></p>
    </body>
    </html>
  `);
});

// src/routes/auth.ts - Update the login endpoint
authRoutes.post(
	"/login",
	zValidator(
		"form",
		z.object({
			email: z.string().email(),
			password: z.string(),
			redirect_uri: z.string().optional(),
			client_id: z.string().optional(),
			state: z.string().optional(),
			scope: z.string().optional(),
		}),
	),
	async (c) => {
		const { email, password, redirect_uri, client_id, state, scope } =
			c.req.valid("form");

		const user = await prisma.user.findUnique({ where: { email } });
		if (!user || !(await bcrypt.compare(password, user.password))) {
			return c.text("Invalid credentials", 401);
		}

		// Only create authorization code if client_id is provided and valid
		if (client_id && redirect_uri) {
			// Find the client by client_id
			const client = await prisma.oAuthClient.findUnique({
				where: { clientId: client_id },
			});

			if (!client) {
				return c.text("Invalid client ID", 400);
			}

			// Verify redirect_uri is registered for this client
			if (!client.redirectUris.includes(redirect_uri)) {
				return c.text("Invalid redirect URI", 400);
			}

			const code = uuidv4();

			await prisma.authorizationCode.create({
				data: {
					code,
					clientId: client.id, // Use the actual client.id, not client_id
					userId: user.id,
					redirectUri: redirect_uri,
					scope: scope || "openid",
					expiresAt: new Date(Date.now() + 10 * 60 * 1000),
				},
			});

			const redirectUrl = new URL(redirect_uri);
			redirectUrl.searchParams.set("code", code);
			if (state) redirectUrl.searchParams.set("state", state);

			return c.redirect(redirectUrl.toString());
		}

		// For regular login, create a session and redirect to dashboard
		const session = await prisma.session.create({
			data: {
				userId: user.id,
				expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
			},
		});

		// Set session cookie (simplified)
		c.header(
			"Set-Cookie",
			`session=${session.id}; HttpOnly; Path=/; Max-Age=86400`,
		);

		return c.redirect("/dashboard");
	},
);

// // Login endpoint
// authRoutes.post(
// 	"/login",
// 	zValidator(
// 		"form",
// 		z.object({
// 			email: z.string().email(),
// 			password: z.string(),
// 			redirect_uri: z.string().optional(),
// 			client_id: z.string().optional(),
// 			state: z.string().optional(),
// 			scope: z.string().optional(),
// 		}),
// 	),
// 	async (c) => {
// 		const { email, password, redirect_uri, client_id, state, scope } =
// 			c.req.valid("form");

// 		const user = await prisma.user.findUnique({ where: { email } });
// 		if (!user || !(await bcrypt.compare(password, user.password))) {
// 			return c.text("Invalid credentials", 401);
// 		}

// 		// Create session
// 		const session = await prisma.session.create({
// 			data: {
// 				userId: user.id,
// 				expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
// 			},
// 		});

// 		if (redirect_uri && client_id) {
// 			// OAuth flow - redirect back with authorization code
// 			const code = uuidv4();

// 			await prisma.authorizationCode.create({
// 				data: {
// 					code,
// 					clientId: client_id,
// 					userId: user.id,
// 					redirectUri: redirect_uri,
// 					scope: scope || "openid",
// 					expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
// 				},
// 			});

// 			const redirectUrl = new URL(redirect_uri);
// 			redirectUrl.searchParams.set("code", code);
// 			if (state) redirectUrl.searchParams.set("state", state);

// 			return c.redirect(redirectUrl.toString());
// 		}

// 		// Regular login - redirect to dashboard
// 		return c.redirect("/dashboard");
// 	},
// );

// Authorization endpoint
authRoutes.get("/authorize", (c) => {
	const { client_id, redirect_uri, response_type, scope, state } =
		c.req.query();

	if (!client_id || !redirect_uri || !response_type) {
		return c.text("Missing required parameters", 400);
	}

	const loginUrl = new URL("/auth/login", `http://${c.req.header("host")}`);
	loginUrl.searchParams.set("client_id", client_id);
	loginUrl.searchParams.set("redirect_uri", redirect_uri);
	loginUrl.searchParams.set("response_type", response_type);
	if (scope) loginUrl.searchParams.set("scope", scope);
	if (state) loginUrl.searchParams.set("state", state);

	return c.redirect(loginUrl.toString());
});

// src/routes/auth.ts - Update the token endpoint
// authRoutes.post("/token", async (c) => {
// 	const body = await c.req.parseBody();
// 	const { grant_type, code, client_id, client_secret, redirect_uri } = body;

// 	if (grant_type !== "authorization_code") {
// 		return c.json({ error: "unsupported_grant_type" }, 400);
// 	}

// 	if (!client_id || !client_secret || !code || !redirect_uri) {
// 		return c.json({ error: "invalid_request" }, 400);
// 	}

// 	const client = await prisma.oAuthClient.findUnique({
// 		where: { clientId: client_id as string },
// 	});

// 	if (!client || client.clientSecret !== client_secret) {
// 		return c.json({ error: "invalid_client" }, 401);
// 	}

// 	const authCode = await prisma.authorizationCode.findUnique({
// 		where: {
// 			code: code as string,
// 			clientId: client.id,
// 		},
// 		include: { user: true },
// 	});

// 	if (!authCode || authCode.expiresAt < new Date()) {
// 		return c.json({ error: "invalid_grant" }, 400);
// 	}

// 	if (authCode.redirectUri !== redirect_uri) {
// 		return c.json({ error: "invalid_grant" }, 400);
// 	}

// 	const user = authCode.user;

// 	// Generate proper tokens
// 	const accessToken = generateAccessToken(user.id, client.id);
// 	const idToken = generateIdToken(user, client.clientId);

// 	// Clean up authorization code
// 	await prisma.authorizationCode.delete({ where: { id: authCode.id } });

// 	// Create refresh token
// 	const refreshToken = uuidv4();
// 	await prisma.refreshToken.create({
// 		data: {
// 			token: refreshToken,
// 			clientId: client.id,
// 			userId: user.id,
// 			expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
// 		},
// 	});

// 	return c.json({
// 		access_token: accessToken,
// 		token_type: "Bearer",
// 		expires_in: 3600,
// 		refresh_token: refreshToken,
// 		id_token: idToken,
// 	});
// });

// // src/routes/auth.ts - Update the token endpoint validation
// authRoutes.post("/token", async (c) => {
// 	const body = await c.req.parseBody();
// 	const { grant_type, code, client_id, client_secret, redirect_uri } = body;

// 	if (grant_type !== "authorization_code") {
// 		return c.json({ error: "unsupported_grant_type" }, 400);
// 	}

// 	if (!client_id || !client_secret || !code || !redirect_uri) {
// 		return c.json({ error: "invalid_request" }, 400);
// 	}

// 	const client = await prisma.oAuthClient.findUnique({
// 		where: { clientId: client_id as string },
// 	});

// 	if (!client || client.clientSecret !== client_secret) {
// 		return c.json({ error: "invalid_client" }, 401);
// 	}

// 	const authCode = await prisma.authorizationCode.findUnique({
// 		where: {
// 			code: code as string,
// 			clientId: client.id,
// 		},
// 		include: { user: true },
// 	});

// 	if (!authCode || authCode.expiresAt < new Date()) {
// 		return c.json({ error: "invalid_grant" }, 400);
// 	}

// 	if (authCode.redirectUri !== redirect_uri) {
// 		return c.json({ error: "invalid_grant" }, 400);
// 	}

// 	const user = authCode.user;

// 	const accessToken = generateAccessToken(user.id, client.id);
// 	const idToken = generateIdToken(user, client.clientId);

// 	// Clean up authorization code
// 	await prisma.authorizationCode.delete({ where: { id: authCode.id } });

// 	// Create refresh token
// 	const refreshToken = uuidv4();
// 	await prisma.refreshToken.create({
// 		data: {
// 			token: refreshToken,
// 			clientId: client.id,
// 			userId: user.id,
// 			expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
// 		},
// 	});

// 	return c.json({
// 		access_token: accessToken,
// 		token_type: "Bearer",
// 		expires_in: 3600,
// 		refresh_token: refreshToken,
// 		id_token: idToken,
// 	});
// });

// // Token endpoint
// authRoutes.post("/token", async (c) => {
// 	const body = await c.req.parseBody();
// 	const { grant_type, code, client_id, client_secret, redirect_uri } = body;

// 	if (grant_type !== "authorization_code") {
// 		return c.json({ error: "unsupported_grant_type" }, 400);
// 	}

// 	const client = await prisma.oAuthClient.findUnique({
// 		where: { clientId: client_id as string },
// 	});

// 	if (!client || client.clientSecret !== client_secret) {
// 		return c.json({ error: "invalid_client" }, 401);
// 	}

// 	const authCode = await prisma.authorizationCode.findUnique({
// 		where: {
// 			code: code as string,
// 			clientId: client.id,
// 		},
// 	});

// 	if (!authCode || authCode.expiresAt < new Date()) {
// 		return c.json({ error: "invalid_grant" }, 400);
// 	}

// 	// Generate tokens
// 	const user = await prisma.user.findUnique({ where: { id: authCode.userId } });
// 	if (!user) return c.json({ error: "invalid_grant" }, 400);

// 	const accessToken = generateAccessToken(user.id, client.id);
// 	const idToken = generateIdToken(user, client.clientId);

// 	// Clean up authorization code
// 	await prisma.authorizationCode.delete({ where: { id: authCode.id } });

// 	// Create refresh token
// 	const refreshToken = uuidv4();
// 	await prisma.refreshToken.create({
// 		data: {
// 			token: refreshToken,
// 			clientId: client.id,
// 			userId: user.id,
// 			expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
// 		},
// 	});

// 	return c.json({
// 		access_token: accessToken,
// 		token_type: "Bearer",
// 		expires_in: 3600,
// 		refresh_token: refreshToken,
// 		id_token: idToken,
// 	});
// });

// // UserInfo endpoint
// authRoutes.get("/userinfo", async (c) => {
// 	const auth = c.req.header("Authorization");
// 	if (!auth?.startsWith("Bearer ")) {
// 		return c.json({ error: "invalid_token" }, 401);
// 	}

// 	console.log(auth);
// 	const token = auth.substring(7);
// 	// In a real app, verify the token and extract user info
// 	// This is simplified for the example

// 	return c.json({
// 		sub: "admin",
// 		email: "admin@example.com",
// 		name: "admin",
// 	});
// });

// src/routes/auth.ts - Replace the userinfo endpoint
// authRoutes.get("/userinfo", async (c) => {
// 	const auth = c.req.header("Authorization");
// 	if (!auth?.startsWith("Bearer ")) {
// 		return c.json({ error: "invalid_token" }, 401);
// 	}

// 	const token = auth.substring(7);

// 	try {
// 		// Verify the JWT token
// 		const { payload } = await jwtVerify(token, privateKey);

// 		// Extract user ID from token
// 		const userId = payload.sub;
// 		if (!userId) {
// 			return c.json({ error: "invalid_token" }, 401);
// 		}

// 		// Get actual user info from database
// 		const user = await prisma.user.findUnique({
// 			where: { id: userId },
// 			select: {
// 				id: true,
// 				email: true,
// 				name: true,
// 			},
// 		});

// 		if (!user) {
// 			return c.json({ error: "invalid_token" }, 401);
// 		}

// 		return c.json({
// 			sub: user.id,
// 			email: user.email,
// 			name: user.name,
// 		});
// 	} catch (error) {
// 		return c.json({ error: "invalid_token" }, 401);
// 	}
// });

// src/routes/auth.ts - Update endpoints to use async functions
authRoutes.get("/userinfo", async (c) => {
	const auth = c.req.header("Authorization");
	if (!auth?.startsWith("Bearer ")) {
		return c.json({ error: "invalid_token" }, 401);
	}

	const token = auth.substring(7);

	try {
		const { payload } = await verifyToken(token);
		const userId = payload.sub;

		if (!userId) {
			return c.json({ error: "invalid_token" }, 401);
		}

		const user = await prisma.user.findUnique({
			where: { id: userId },
			select: {
				id: true,
				email: true,
				name: true,
			},
		});

		if (!user) {
			return c.json({ error: "invalid_token" }, 401);
		}

		return c.json({
			sub: user.id,
			email: user.email,
			name: user.name,
		});
	} catch (error) {
		return c.json({ error: "invalid_token" }, 401);
	}
});

// Update token endpoint
authRoutes.post("/token", async (c) => {
	const body = await c.req.parseBody();
	const { grant_type, code, client_id, client_secret, redirect_uri } = body;

	if (grant_type !== "authorization_code") {
		return c.json({ error: "unsupported_grant_type" }, 400);
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

	const user = authCode.user;

	// Use async functions
	const [accessToken, idToken] = await Promise.all([
		generateAccessToken(user.id, client.id),
		generateIdToken(user, client.clientId),
	]);

	await prisma.authorizationCode.delete({ where: { id: authCode.id } });

	const refreshToken = uuidv4();
	await prisma.refreshToken.create({
		data: {
			token: refreshToken,
			clientId: client.id,
			userId: user.id,
			expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
		},
	});

	return c.json({
		access_token: accessToken,
		token_type: "Bearer",
		expires_in: 3600,
		refresh_token: refreshToken,
		id_token: idToken,
	});
});

// // JWKS endpoint
// authRoutes.get("/jwks", (c) => {
// 	return c.json({
// 		keys: [
// 			{
// 				kty: "RSA",
// 				kid: "1",
// 				use: "sig",
// 				alg: "RS256",
// 				n: "...public-key-here...",
// 				e: "AQAB",
// 			},
// 		],
// 	});
// });

// src/routes/auth.ts - Update the JWKS endpoint
// authRoutes.get("/jwks", async (c) => {
// 	const jwk = await getPublicJWK();

// 	return c.json({
// 		keys: [
// 			{
// 				...jwk,
// 				kty: "RSA",
// 				kid: "1",
// 				use: "sig",
// 				alg: "RS256",
// 			},
// 		],
// 	});
// });

authRoutes.get("/jwks", (c) => {
	return c.json({
		keys: [
			{
				kty: "oct",
				kid: "1",
				use: "sig",
				alg: "HS256",
			},
		],
	});
});
