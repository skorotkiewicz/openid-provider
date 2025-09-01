import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { prisma } from "../lib/db.js";
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

		return c.redirect("/dev/dashboard");
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
		await prisma.user.create({
			data: {
				email,
				password: hashedPassword,
				name: name || null,
			},
		});

		return c.redirect("/dev/login");
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
		// For demo purposes, we'll accept any token
		// In production, you'd verify the JWT token
		const user = await prisma.user.findFirst();
		if (!user) {
			return c.json({ error: "No users found" }, 404);
		}

		return c.json({
			id: user.id,
			email: user.email,
			name: user.name,
		});
	} catch (error) {
		return c.json({ error: "Invalid token" }, 401);
	}
});

developerRoutes.get("/api/clients", async (c) => {
	const auth = c.req.header("Authorization");
	if (!auth?.startsWith("Bearer ")) {
		return c.json({ error: "Unauthorized" }, 401);
	}

	try {
		// For demo purposes, return all clients
		// In production, you'd filter by the authenticated user
		const clients = await prisma.oAuthClient.findMany({
			select: {
				id: true,
				name: true,
				clientId: true,
				clientSecret: true,
				redirectUris: true,
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
			userId: z.string(),
		}),
	),
	async (c) => {
		const auth = c.req.header("Authorization");
		if (!auth?.startsWith("Bearer ")) {
			return c.json({ error: "Unauthorized" }, 401);
		}

		try {
			const { name, redirectUris, userId } = c.req.valid("json");

			const clientId = uuidv4();
			const clientSecret = uuidv4();

			const client = await prisma.oAuthClient.create({
				data: {
					clientId,
					clientSecret,
					name,
					redirectUris,
					userId,
				},
			});

			return c.json({
				id: client.id,
				name: client.name,
				clientId: client.clientId,
				clientSecret: client.clientSecret,
				redirectUris: client.redirectUris,
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

	try {
		const clientId = c.req.param("id");

		await prisma.oAuthClient.delete({
			where: { id: clientId },
		});

		return c.json({ success: true });
	} catch (error) {
		return c.json({ error: "Failed to delete client" }, 500);
	}
});
