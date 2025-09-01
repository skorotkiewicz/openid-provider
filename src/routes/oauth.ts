import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { prisma } from "../lib/db.js";
import {
	generateIdToken,
	generateAccessToken,
	verifyToken,
	getPublicJWK,
} from "../lib/jwt.js";
import { v4 as uuidv4 } from "uuid";

export const oauthRoutes = new Hono();

// Authorization endpoint
oauthRoutes.get("/authorize", async (c) => {
	const { client_id, redirect_uri, response_type, scope, state } =
		c.req.query();

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

// Token endpoint
oauthRoutes.post("/token", async (c) => {
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

	if (authCode.redirectUri !== redirect_uri) {
		return c.json({ error: "invalid_grant" }, 400);
	}

	const user = authCode.user;

	const [accessToken, idToken] = await Promise.all([
		generateAccessToken(user.id, client.id),
		generateIdToken(user, client.clientId),
	]);

	await prisma.authorizationCode.delete({ where: { id: authCode.id } });

	return c.json({
		access_token: accessToken,
		token_type: "Bearer",
		expires_in: 3600,
		id_token: idToken,
	});
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
