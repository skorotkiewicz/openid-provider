import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { prisma } from "../db/prisma.js";
import bcrypt from "bcryptjs";

export const dashboardRoutes = new Hono();

// Dashboard page
dashboardRoutes.get("/dashboard", (c) => {
	return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Dashboard - OpenID Provider</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .card { border: 1px solid #ddd; padding: 20px; margin: 10px 0; border-radius: 5px; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; margin: 5px; }
        input, textarea { width: 100%; padding: 10px; margin: 5px 0; }
        pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
      </style>
    </head>
    <body>
      <h1>OpenID Provider Dashboard</h1>
      
      <div class="card">
        <h2>Your Applications</h2>
        <div id="clients"></div>
        <button onclick="createClient()">Create New Application</button>
      </div>

      <div class="card">
        <h2>Integration Example</h2>
        <pre id="example"></pre>
      </div>

      <script>
        // Load clients
        async function loadClients() {
          const userId = localStorage.getItem('userId') || 'demo-user'
          const res = await fetch('/clients?userId=' + userId)
          const clients = await res.json()
          
          const container = document.getElementById('clients')
          container.innerHTML = clients.map(client => \`
            <div class="card">
              <h3>\${client.name}</h3>
              <p><strong>Client ID:</strong> \${client.clientId}</p>
              <p><strong>Client Secret:</strong> [hidden]</p>
              <p><strong>Redirect URIs:</strong> \${client.redirectUris.join(', ')}</p>
            </div>
          \`).join('')
          
          if (clients.length > 0) {
            updateExample(clients[0])
          }
        }

        function updateExample(client) {
          document.getElementById('example').textContent = \`
// Install: npm install @auth/core

import { Auth } from '@auth/core'

const auth = new Auth({
  providers: [{
    id: 'custom',
    name: 'Your OpenID Provider',
    type: 'oauth',
    wellKnown: 'http://localhost:3000/.well-known/openid_configuration',
    clientId: '\${client.clientId}',
    clientSecret: '\${client.clientSecret}',
    redirectUri: 'http://localhost:3001/auth/callback',
  }]
})

// Usage in your app:
// Redirect users to: http://localhost:3000/auth/authorize?client_id=\${client.clientId}&response_type=code&redirect_uri=http://localhost:3001/auth/callback&scope=openid profile email
          \`.trim()
        }

        async function createClient() {
          const name = prompt('Application name:')
          const redirectUri = prompt('Redirect URI (e.g., http://localhost:3001/auth/callback):')
          
          if (name && redirectUri) {
            const userId = localStorage.getItem('userId') || 'demo-user'
            const res = await fetch('/clients', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                name,
                redirectUris: [redirectUri],
                userId
              })
            })
            const client = await res.json()
            alert(\`Created! Client ID: \${client.clientId}\\nClient Secret: \${client.clientSecret}\\nSave the secret - it won't be shown again!\`)
            loadClients()
          }
        }

        loadClients()
      </script>
    </body>
    </html>
  `);
});

// Register page
dashboardRoutes.get("/register", (c) => {
	return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Register - OpenID Provider</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        input { width: 100%; padding: 10px; margin: 10px 0; }
        button { width: 100%; padding: 10px; background: #28a745; color: white; border: none; cursor: pointer; }
        button:hover { background: #1e7e34; }
      </style>
    </head>
    <body>
      <h1>Register</h1>
      <form method="POST" action="/register">
        <input type="email" name="email" placeholder="Email" required />
        <input type="password" name="password" placeholder="Password" required />
        <input type="text" name="name" placeholder="Your Name" />
        <button type="submit">Register</button>
      </form>
      <p>Already have an account? <a href="/auth/login">Login here</a></p>
    </body>
    </html>
  `);
});

// Register endpoint
dashboardRoutes.post(
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
			return c.text("User already exists", 400);
		}

		const hashedPassword = await bcrypt.hash(password, 10);
		const user = await prisma.user.create({
			data: {
				email,
				password: hashedPassword,
				name,
			},
		});

		// Store user ID in localStorage via redirect
		return c.html(`
    <script>
      localStorage.setItem('userId', '${user.id}')
      window.location = '/dashboard'
    </script>
  `);
	},
);

// Home page
dashboardRoutes.get("/", (c) => {
	return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>OpenID Provider</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
        .btn { display: inline-block; padding: 15px 30px; margin: 10px; color: white; text-decoration: none; border-radius: 5px; }
        .btn-primary { background: #007bff; }
        .btn-success { background: #28a745; }
      </style>
    </head>
    <body>
      <h1>OpenID Provider</h1>
      <p>Create your own OAuth2/OpenID Connect applications</p>
      <a href="/register" class="btn btn-success">Get Started</a>
      <a href="/dashboard" class="btn btn-primary">Dashboard</a>
    </body>
    </html>
  `);
});
