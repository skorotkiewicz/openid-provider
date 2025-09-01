import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { prisma } from "../lib/db.js";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { getScopeDetails } from "../utils/scope-details";

export const userRoutes = new Hono();

// Helper function to show consent screen
async function showConsentScreen(
	c: any,
	user: any,
	clientId: string,
	redirectUri: string,
	scope: string,
	state: string,
) {
	// Get client information
	const client = await prisma.oAuthClient.findUnique({
		where: { clientId },
	});

	if (!client) {
		return c.text("Invalid client", 400);
	}

	// Parse scopes and filter by allowed scopes
	const requestedScopes = scope.split(" ").filter((s) => s.trim());
	const allowedScopes = client.allowedScopes || [];

	// Only show scopes that are both requested and allowed
	const validScopes = requestedScopes.filter((scope) =>
		allowedScopes.includes(scope),
	);
	const scopeDetails = getScopeDetails(validScopes);

	return (c as any).render("user/consent", {
		client,
		user,
		clientId,
		redirectUri,
		scope: validScopes.join(" "), // Update scope to only include allowed scopes
		state,
		scopeDetails,
	});
}

// User login page
userRoutes.get("/login", async (c) => {
	const redirectUri = c.req.query("redirect_uri") || "";
	const clientId = c.req.query("client_id") || "";
	const state = c.req.query("state") || "";
	const scope = c.req.query("scope") || "";

	// Check if user is already logged in and this is an OAuth flow
	if (redirectUri && clientId) {
		const sessionCookie = getCookie(c, "session");
		if (sessionCookie) {
			const session = await prisma.session.findUnique({
				where: { id: sessionCookie },
				include: { user: true },
			});

			if (session && session.expiresAt > new Date()) {
				// User is logged in, show consent screen
				return showConsentScreen(
					c,
					session.user,
					clientId,
					redirectUri,
					scope,
					state,
				);
			}
		}
	}

	// User not logged in or not OAuth flow, show login form
	return (c as any).render("user/login", {
		redirectUri,
		clientId,
		state,
		scope,
	});
});

// User register page
userRoutes.get("/register", (c) => {
	return (c as any).render("user/register", {
		redirectUri: c.req.query("redirect_uri") || "",
		clientId: c.req.query("client_id") || "",
		state: c.req.query("state") || "",
		scope: c.req.query("scope") || "",
	});
});

// User login POST
userRoutes.post(
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
			return (c as any).render("user/login-error", {
				redirectUri: redirect_uri,
				clientId: client_id,
				state,
				scope,
			});
		}

		// Handle OAuth flow
		if (redirect_uri && client_id) {
			const client = await prisma.oAuthClient.findUnique({
				where: { clientId: client_id },
			});

			if (!client) {
				return c.text("Invalid client", 400);
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

		// Regular login - create session and redirect to profile
		const session = await prisma.session.create({
			data: {
				userId: user.id,
				expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
			},
		});

		setCookie(c, "session", session.id, {
			httpOnly: true,
			path: "/",
			maxAge: 24 * 60 * 60, // 24 hours
		});

		return c.redirect("/user/profile");
	},
);

// User profile page
userRoutes.get("/profile", async (c) => {
	// Get user from session
	const sessionCookie = getCookie(c, "session");
	if (!sessionCookie) {
		return c.redirect("/user/login");
	}

	const session = await prisma.session.findUnique({
		where: { id: sessionCookie },
		include: { user: true },
	});

	if (!session || session.expiresAt < new Date()) {
		return c.redirect("/user/login");
	}

	const user = session.user;
	const success = c.req.query("success") === "1";

	return (c as any).render("user/profile", {
		user,
		success,
	});
});

// Update user profile
userRoutes.post(
	"/profile",
	zValidator(
		"form",
		z.object({
			name: z.string().optional(),
			about: z.string().optional(),
			website: z.string().optional(),
			twitter: z.string().optional(),
			github: z.string().optional(),
		}),
	),
	async (c) => {
		// Get user from session
		const sessionCookie = getCookie(c, "session");
		if (!sessionCookie) {
			return c.redirect("/user/login");
		}

		const session = await prisma.session.findUnique({
			where: { id: sessionCookie },
			include: { user: true },
		});

		if (!session || session.expiresAt < new Date()) {
			return c.redirect("/user/login");
		}

		const { name, about, website, twitter, github } = c.req.valid("form");

		// Update user profile
		await prisma.user.update({
			where: { id: session.user.id },
			data: {
				name: name || null,
				about: about || null,
				website: website || null,
				twitter: twitter || null,
				github: github || null,
			},
		});

		return c.redirect("/user/profile?success=1");
	},
);

// Handle consent approval
userRoutes.post(
	"/consent/allow",
	zValidator(
		"form",
		z.object({
			client_id: z.string(),
			redirect_uri: z.string(),
			scope: z.string(),
			state: z.string().optional(),
		}),
	),
	async (c) => {
		const { client_id, redirect_uri, scope, state } = c.req.valid("form");

		// Get user from session
		const sessionCookie = getCookie(c, "session");
		if (!sessionCookie) {
			return c.redirect("/user/login");
		}

		const session = await prisma.session.findUnique({
			where: { id: sessionCookie },
			include: { user: true },
		});

		if (!session || session.expiresAt < new Date()) {
			return c.redirect("/user/login");
		}

		const user = session.user;

		// Get client information
		const client = await prisma.oAuthClient.findUnique({
			where: { clientId: client_id },
		});

		if (!client) {
			return c.text("Invalid client", 400);
		}

		// Verify redirect_uri is registered for this client
		if (!client.redirectUris.includes(redirect_uri)) {
			return c.text("Invalid redirect URI", 400);
		}

		// Create authorization code
		const code = uuidv4();
		await prisma.authorizationCode.create({
			data: {
				code,
				clientId: client.id,
				userId: user.id,
				redirectUri: redirect_uri,
				scope: scope || "openid",
				expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
			},
		});

		// Redirect back to client with authorization code
		const redirectUrl = new URL(redirect_uri);
		redirectUrl.searchParams.set("code", code);
		if (state) redirectUrl.searchParams.set("state", state);

		return c.redirect(redirectUrl.toString());
	},
);

// Handle consent denial
userRoutes.post(
	"/consent/deny",
	zValidator(
		"form",
		z.object({
			redirect_uri: z.string(),
			state: z.string().optional(),
		}),
	),
	async (c) => {
		const { redirect_uri, state } = c.req.valid("form");

		// Redirect back to client with error
		const redirectUrl = new URL(redirect_uri);
		redirectUrl.searchParams.set("error", "access_denied");
		redirectUrl.searchParams.set("error_description", "User denied access");
		if (state) redirectUrl.searchParams.set("state", state);

		return c.redirect(redirectUrl.toString());
	},
);

// Logout
userRoutes.get("/logout", async (c) => {
	const sessionCookie = getCookie(c, "session");
	if (sessionCookie) {
		await prisma.session.delete({ where: { id: sessionCookie } });
	}

	deleteCookie(c, "session");
	return c.redirect("/");
});

// User register POST
userRoutes.post(
	"/register",
	zValidator(
		"form",
		z.object({
			email: z.string().email(),
			password: z.string().min(6),
			name: z.string().optional(),
			redirect_uri: z.string().optional(),
			client_id: z.string().optional(),
			state: z.string().optional(),
			scope: z.string().optional(),
		}),
	),
	async (c) => {
		const { email, password, name, redirect_uri, client_id, state, scope } =
			c.req.valid("form");

		const existingUser = await prisma.user.findUnique({ where: { email } });
		if (existingUser) {
			return (c as any).render("user/register-error", {
				redirectUri: redirect_uri,
				clientId: client_id,
				state,
				scope,
			});
		}

		const hashedPassword = await bcrypt.hash(password, 10);
		const user = await prisma.user.create({
			data: {
				email,
				password: hashedPassword,
				name: name || null,
			},
		});

		if (redirect_uri && client_id) {
			return c.redirect(
				`/user/login?redirect_uri=${redirect_uri}&client_id=${client_id}&state=${state}&scope=${scope}`,
			);
		}

		// Regular registration - create session and redirect to profile
		const session = await prisma.session.create({
			data: {
				userId: user.id,
				expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
			},
		});

		setCookie(c, "session", session.id, {
			httpOnly: true,
			path: "/",
			maxAge: 24 * 60 * 60, // 24 hours
		});

		return c.redirect("/user/profile");
	},
);
