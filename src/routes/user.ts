import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { prisma } from "../lib/db.js";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";

export const userRoutes = new Hono();

// User login page
userRoutes.get("/login", (c) => {
	return (c as any).render("user/login", {
		redirectUri: c.req.query("redirect_uri") || "",
		clientId: c.req.query("client_id") || "",
		state: c.req.query("state") || "",
		scope: c.req.query("scope") || "",
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
			return c.html(
				`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Login Error - OpenID Provider</title>
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
        <a href="/user/login?redirect_uri=${redirect_uri}&client_id=${client_id}&state=${state}&scope=${scope}">Try again</a>
      </body>
      </html>
    `,
				401,
			);
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
					clientId: client.id,
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

		return c.redirect("/");
	},
);

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
			return c.html(
				`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Registration Error - OpenID Provider</title>
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
        <a href="/user/register?redirect_uri=${redirect_uri}&client_id=${client_id}&state=${state}&scope=${scope}">Try again</a>
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

		if (redirect_uri && client_id) {
			return c.redirect(
				`/user/login?redirect_uri=${redirect_uri}&client_id=${client_id}&state=${state}&scope=${scope}`,
			);
		}

		return c.redirect("/");
	},
);
