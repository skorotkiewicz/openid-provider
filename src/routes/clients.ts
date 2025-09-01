import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { prisma } from "../db/prisma.js";
import { generateClientCredentials } from "../lib/crypto.js";
import bcrypt from "bcryptjs";
import { verifyToken } from "../lib/jwt.js";

export const clientRoutes = new Hono();

// src/routes/dashboard.ts - Add session validation
// Update the get clients endpoint
clientRoutes.get("/", async (c) => {
	const auth = c.req.header("Authorization");
	if (!auth?.startsWith("Bearer ")) {
		return c.json({ error: "Unauthorized" }, 401);
	}

	const token = auth.substring(7);

	try {
		const { payload } = await verifyToken(token);
		const userId = payload.sub;

		if (!userId) {
			return c.json({ error: "Invalid token" }, 401);
		}

		const clients = await prisma.oAuthClient.findMany({
			where: { userId },
			select: {
				id: true,
				name: true,
				clientId: true,
				redirectUris: true,
				createdAt: true,
			},
		});

		return c.json(clients);
	} catch (error) {
		return c.json({ error: "Invalid token" }, 401);
	}
});

// // Get user's clients
// clientRoutes.get("/", async (c) => {
// 	const userId = c.req.query("userId");
// 	if (!userId) return c.json({ error: "User ID required" }, 400);

// 	const clients = await prisma.oAuthClient.findMany({
// 		where: { userId },
// 		select: {
// 			id: true,
// 			name: true,
// 			clientId: true,
// 			redirectUris: true,
// 			createdAt: true,
// 		},
// 	});

// 	return c.json(clients);
// });

// Create new client
clientRoutes.post(
	"/",
	zValidator(
		"json",
		z.object({
			name: z.string(),
			redirectUris: z.array(z.string().url()),
			userId: z.string(),
		}),
	),
	async (c) => {
		const { name, redirectUris, userId } = c.req.valid("json");

		const { clientId, clientSecret } = generateClientCredentials();

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
			clientId,
			clientSecret,
			name: client.name,
			redirectUris: client.redirectUris,
		});
	},
);

// src/routes/clients.ts - Naprawiona funkcja /api/me
clientRoutes.get("/api/me", async (c) => {
	try {
		// Pobierz token z nagłówka
		const auth = c.req.header("Authorization");
		if (!auth?.startsWith("Bearer ")) {
			return c.json({ error: "Unauthorized" }, 401);
		}

		const token = auth.substring(7);

		// Weryfikuj token
		const { payload } = await verifyToken(token);
		const userId = payload.sub;

		if (!userId) {
			return c.json({ error: "Invalid token" }, 401);
		}

		// Pobierz dane użytkownika z bazy
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
		console.error("Error in /api/me:", error);
		return c.json({ error: "Invalid token" }, 401);
	}
});

clientRoutes.get("/api/clients", async (c) => {
	try {
		const userId = "demo-user"; // In real app, get from session

		const clients = await prisma.oAuthClient.findMany({
			where: { userId },
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
		console.error("Error fetching clients:", error);
		return c.json({ error: "Failed to fetch clients" }, 500);
	}
});

clientRoutes.post(
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
		try {
			const { name, redirectUris, userId } = c.req.valid("json");

			const { clientId, clientSecret } = generateClientCredentials();

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
			console.error("Error creating client:", error);
			return c.json({ error: "Failed to create client" }, 500);
		}
	},
);

clientRoutes.delete("/api/clients/:id", async (c) => {
	try {
		const id = c.req.param("id");

		await prisma.oAuthClient.delete({
			where: { id },
		});

		return c.json({ success: true });
	} catch (error) {
		console.error("Error deleting client:", error);
		return c.json({ error: "Failed to delete client" }, 500);
	}
});
