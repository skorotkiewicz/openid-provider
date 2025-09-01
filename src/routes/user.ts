import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { prisma } from "../lib/db.js";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";

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

	return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Profile - OpenID Provider</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          margin: 0;
          padding: 20px;
          min-height: 100vh;
        }
        .profile-container {
          background: white;
          padding: 40px;
          border-radius: 10px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.1);
          max-width: 600px;
          margin: 0 auto;
        }
        h1 {
          text-align: center;
          color: #333;
          margin-bottom: 30px;
        }
        .form-group {
          margin-bottom: 20px;
        }
        label {
          display: block;
          margin-bottom: 5px;
          color: #555;
          font-weight: 500;
        }
        input, textarea {
          width: 100%;
          padding: 12px;
          border: 1px solid #ddd;
          border-radius: 5px;
          font-size: 16px;
          box-sizing: border-box;
        }
        input:focus, textarea:focus {
          outline: none;
          border-color: #667eea;
          box-shadow: 0 0 0 2px rgba(102, 126, 234, 0.2);
        }
        textarea {
          resize: vertical;
          min-height: 100px;
        }
        button {
          width: 100%;
          padding: 14px;
          background: #667eea;
          color: white;
          border: none;
          border-radius: 5px;
          font-size: 16px;
          cursor: pointer;
          transition: background 0.3s;
        }
        button:hover {
          background: #5a6fd8;
        }
        .links {
          text-align: center;
          margin-top: 20px;
        }
        .links a {
          color: #667eea;
          text-decoration: none;
          margin: 0 10px;
        }
        .links a:hover {
          text-decoration: underline;
        }
        .success {
          background: #d4edda;
          color: #155724;
          padding: 10px;
          border-radius: 5px;
          margin-bottom: 20px;
          border: 1px solid #c3e6cb;
        }
      </style>
    </head>
    <body>
      <div class="profile-container">
        <h1>Edit Your Profile</h1>

        ${c.req.query("success") ? '<div class="success">Profile updated successfully!</div>' : ""}

        <form method="POST" action="/user/profile">
          <div class="form-group">
            <label for="name">Full Name</label>
            <input type="text" id="name" name="name" value="${user.name || ""}" placeholder="Your full name" />
          </div>

          <div class="form-group">
            <label for="about">About Me</label>
            <textarea id="about" name="about" placeholder="Tell us about yourself...">${user.about || ""}</textarea>
          </div>

          <div class="form-group">
            <label for="website">Website</label>
            <input type="url" id="website" name="website" value="${user.website || ""}" placeholder="https://yourwebsite.com" />
          </div>

          <div class="form-group">
            <label for="twitter">Twitter</label>
            <input type="text" id="twitter" name="twitter" value="${user.twitter || ""}" placeholder="@yourusername" />
          </div>

          <div class="form-group">
            <label for="github">GitHub</label>
            <input type="text" id="github" name="github" value="${user.github || ""}" placeholder="yourusername" />
          </div>

          <button type="submit">Update Profile</button>
        </form>

        <div class="links">
          <a href="/">Home</a>
          <a href="/user/logout">Logout</a>
        </div>
      </div>
    </body>
    </html>
  `);
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
