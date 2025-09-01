import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { prisma } from "../lib/db.js";
import { verifyToken, generateAccessToken } from "../lib/jwt.js";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";

export const developerRoutes = new Hono();

// Developer login page
developerRoutes.get("/login", (c) => {
	return (c as any).render("developer/login");
});

// Developer register page
developerRoutes.get("/register", (c) => {
	return (c as any).render("developer/register");
});

// Developer dashboard
developerRoutes.get("/dashboard", (c) => {
	return (c as any).render("developer/dashboard");
});

// Developer login POST
developerRoutes.post(
	"/login",
	zValidator(
		"form",
		z.object({
			email: z.string().email(),
			password: z.string(),
		}),
	),
	async (c) => {
		const { email, password } = c.req.valid("form");

		const user = await prisma.user.findUnique({ where: { email } });
		if (!user || !(await bcrypt.compare(password, user.password))) {
			return c.html(
				`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Login Error - Developer Portal</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; text-align: center; }
          .error { color: #e74c3c; margin: 20px 0; }
          a { color: #3498db; text-decoration: none; }
        </style>
      </head>
      <body>
        <h1>Login Failed</h1>
        <p class="error">Invalid email or password</p>
        <a href="/dev/login">Try again</a>
      </body>
      </html>
    `,
				401,
			);
		}

		// Generate JWT token for the developer
		const token = await generateAccessToken(user.id, "developer-portal");

		// Return HTML that sets the token in sessionStorage and redirects
		return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Login Success - Developer Portal</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; text-align: center; }
        .success { color: #27ae60; margin: 20px 0; }
      </style>
    </head>
    <body>
      <h1>Login Successful!</h1>
      <p class="success">Welcome back, ${user.email}</p>
      <p>Redirecting to dashboard...</p>

      <script>
        // Store the JWT token in sessionStorage
        sessionStorage.setItem('devToken', '${token}');

        // Redirect to dashboard after a short delay
        setTimeout(() => {
          window.location.href = '/dev/dashboard';
        }, 1000);
      </script>
    </body>
    </html>
  `);
	},
);

// Developer register POST
developerRoutes.post(
	"/register",
	zValidator(
		"form",
		z.object({
			email: z.string().email(),
			password: z.string().min(6),
			name: z.string().optional(),
		}),
	),
	async (c) => {
		const { email, password, name } = c.req.valid("form");

		const existingUser = await prisma.user.findUnique({ where: { email } });
		if (existingUser) {
			return c.html(
				`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Registration Error - Developer Portal</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; text-align: center; }
          .error { color: #e74c3c; margin: 20px 0; }
          a { color: #3498db; text-decoration: none; }
        </style>
      </head>
      <body>
        <h1>Registration Failed</h1>
        <p class="error">Email already registered</p>
        <a href="/dev/register">Try again</a>
      </body>
      </html>
    `,
				400,
			);
		}

		const hashedPassword = await bcrypt.hash(password, 10);
		const user = await prisma.user.create({
			data: {
				email,
				password: hashedPassword,
				name: name || null,
			},
		});

		// Generate JWT token for the new developer
		const token = await generateAccessToken(user.id, "developer-portal");

		// Return HTML that sets the token in sessionStorage and redirects
		return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Registration Success - Developer Portal</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; text-align: center; }
        .success { color: #27ae60; margin: 20px 0; }
      </style>
    </head>
    <body>
      <h1>Registration Successful!</h1>
      <p class="success">Welcome to the Developer Portal, ${user.email}</p>
      <p>Redirecting to dashboard...</p>

      <script>
        // Store the JWT token in sessionStorage
        sessionStorage.setItem('devToken', '${token}');

        // Redirect to dashboard after a short delay
        setTimeout(() => {
          window.location.href = '/dev/dashboard';
        }, 1000);
      </script>
    </body>
    </html>
  `);
	},
);

// API endpoints for developers
developerRoutes.get("/api/me", async (c) => {
	const auth = c.req.header("Authorization");
	if (!auth?.startsWith("Bearer ")) {
		return c.json({ error: "Unauthorized" }, 401);
	}

	const token = auth.substring(7);

	try {
		// Verify the JWT token
		const { payload } = await verifyToken(token);
		const userId = payload.sub;

		if (!userId) {
			return c.json({ error: "Invalid token" }, 401);
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
			return c.json({ error: "User not found" }, 404);
		}

		return c.json(user);
	} catch (error) {
		return c.json({ error: "Invalid token" }, 401);
	}
});

developerRoutes.get("/api/clients", async (c) => {
	const auth = c.req.header("Authorization");
	if (!auth?.startsWith("Bearer ")) {
		return c.json({ error: "Unauthorized" }, 401);
	}

	const token = auth.substring(7);

	try {
		// Verify the JWT token and get user ID
		const { payload } = await verifyToken(token);
		const userId = payload.sub;

		if (!userId) {
			return c.json({ error: "Invalid token" }, 401);
		}

		// Filter clients by authenticated user
		const clients = await prisma.oAuthClient.findMany({
			where: {
				userId: userId,
			},
			select: {
				id: true,
				name: true,
				clientId: true,
				clientSecret: true,
				redirectUris: true,
				allowedScopes: true,
				createdAt: true,
			},
			orderBy: { createdAt: "desc" },
		});

		return c.json(clients);
	} catch (error) {
		return c.json({ error: "Failed to fetch clients" }, 500);
	}
});

developerRoutes.post(
	"/api/clients",
	zValidator(
		"json",
		z.object({
			name: z.string().min(1),
			redirectUris: z.array(z.string().url()),
			allowedScopes: z.array(z.string()).min(1),
		}),
	),
	async (c) => {
		const auth = c.req.header("Authorization");
		if (!auth?.startsWith("Bearer ")) {
			return c.json({ error: "Unauthorized" }, 401);
		}

		const token = auth.substring(7);

		try {
			// Verify the JWT token and get user ID
			const { payload } = await verifyToken(token);
			const authenticatedUserId = payload.sub;

			if (!authenticatedUserId) {
				return c.json({ error: "Invalid token" }, 401);
			}

			const { name, redirectUris, allowedScopes } = c.req.valid("json");

			// Validate that allowedScopes contains valid scope names
			const validScopes = [
				"openid",
				"email",
				"name",
				"about",
				"website",
				"twitter",
				"github",
				"profile",
			];
			const invalidScopes = allowedScopes.filter(
				(scope) => !validScopes.includes(scope),
			);

			if (invalidScopes.length > 0) {
				return c.json(
					{
						error: "Invalid scopes",
						invalidScopes,
						validScopes,
					},
					400,
				);
			}

			const clientId = uuidv4();
			const clientSecret = uuidv4();

			const client = await prisma.oAuthClient.create({
				data: {
					clientId,
					clientSecret,
					name,
					redirectUris,
					allowedScopes,
					userId: authenticatedUserId, // Use authenticated user's ID
				},
			});

			return c.json({
				id: client.id,
				name: client.name,
				clientId: client.clientId,
				clientSecret: client.clientSecret,
				redirectUris: client.redirectUris,
				allowedScopes: client.allowedScopes,
				createdAt: client.createdAt,
			});
		} catch (error) {
			return c.json({ error: "Failed to create client" }, 500);
		}
	},
);

developerRoutes.delete("/api/clients/:id", async (c) => {
	const auth = c.req.header("Authorization");
	if (!auth?.startsWith("Bearer ")) {
		return c.json({ error: "Unauthorized" }, 401);
	}

	const token = auth.substring(7);

	try {
		// Verify the JWT token and get user ID
		const { payload } = await verifyToken(token);
		const authenticatedUserId = payload.sub;

		if (!authenticatedUserId) {
			return c.json({ error: "Invalid token" }, 401);
		}

		const clientId = c.req.param("id");

		// Check if the client belongs to the authenticated user
		const client = await prisma.oAuthClient.findUnique({
			where: { id: clientId },
			select: { userId: true },
		});

		if (!client) {
			return c.json({ error: "Client not found" }, 404);
		}

		if (client.userId !== authenticatedUserId) {
			return c.json({ error: "Forbidden" }, 403);
		}

		// Delete the client
		await prisma.oAuthClient.delete({
			where: { id: clientId },
		});

		return c.json({ success: true });
	} catch (error) {
		return c.json({ error: "Failed to delete client" }, 500);
	}
});
