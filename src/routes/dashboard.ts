import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { prisma } from "../db/prisma.js";
import bcrypt from "bcryptjs";

export const dashboardRoutes = new Hono();

// Dashboard page
// dashboardRoutes.get("/dashboard", (c) => {
// 	return c.html(`
//     <!DOCTYPE html>
//     <html>
//     <head>
//       <title>Dashboard - OpenID Provider</title>
//       <meta name="viewport" content="width=device-width, initial-scale=1">
//       <style>
//         body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
//         .card { border: 1px solid #ddd; padding: 20px; margin: 10px 0; border-radius: 5px; }
//         button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; margin: 5px; }
//         input, textarea { width: 100%; padding: 10px; margin: 5px 0; }
//         pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
//       </style>
//     </head>
//     <body>
//       <h1>OpenID Provider Dashboard</h1>

//       <div class="card">
//         <h2>Your Applications</h2>
//         <div id="clients"></div>
//         <button onclick="createClient()">Create New Application</button>
//       </div>

//       <div class="card">
//         <h2>Integration Example</h2>
//         <pre id="example"></pre>
//       </div>

//       <script>
//         // Load clients
//         async function loadClients() {
//           const userId = localStorage.getItem('userId') || 'demo-user'
//           const res = await fetch('/clients?userId=' + userId)
//           const clients = await res.json()

//           const container = document.getElementById('clients')
//           container.innerHTML = clients.map(client => \`
//             <div class="card">
//               <h3>\${client.name}</h3>
//               <p><strong>Client ID:</strong> \${client.clientId}</p>
//               <p><strong>Client Secret:</strong> [hidden]</p>
//               <p><strong>Redirect URIs:</strong> \${client.redirectUris.join(', ')}</p>
//             </div>
//           \`).join('')

//           if (clients.length > 0) {
//             updateExample(clients[0])
//           }
//         }

//         function updateExample(client) {
//           document.getElementById('example').textContent = \`
// // Install: npm install @auth/core

// import { Auth } from '@auth/core'

// const auth = new Auth({
//   providers: [{
//     id: 'custom',
//     name: 'Your OpenID Provider',
//     type: 'oauth',
//     wellKnown: 'http://localhost:3000/.well-known/openid_configuration',
//     clientId: '\${client.clientId}',
//     clientSecret: '\${client.clientSecret}',
//     redirectUri: 'http://localhost:3001/auth/callback',
//   }]
// })

// // Usage in your app:
// // Redirect users to: http://localhost:3000/auth/authorize?client_id=\${client.clientId}&response_type=code&redirect_uri=http://localhost:3001/auth/callback&scope=openid profile email
//           \`.trim()
//         }

//         async function createClient() {
//           const name = prompt('Application name:')
//           const redirectUri = prompt('Redirect URI (e.g., http://localhost:3001/auth/callback):')

//           if (name && redirectUri) {
//             const userId = localStorage.getItem('userId') || 'demo-user'
//             const res = await fetch('/clients', {
//               method: 'POST',
//               headers: { 'Content-Type': 'application/json' },
//               body: JSON.stringify({
//                 name,
//                 redirectUris: [redirectUri],
//                 userId
//               })
//             })
//             const client = await res.json()
//             alert(\`Created! Client ID: \${client.clientId}\\nClient Secret: \${client.clientSecret}\\nSave the secret - it won't be shown again!\`)
//             loadClients()
//           }
//         }

//         loadClients()
//       </script>
//     </body>
//     </html>
//   `);
// });

// src/routes/dashboard.ts - Update dashboard route
dashboardRoutes.get("/dashboard", (c) => {
	return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Dashboard - OpenID Provider</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: #f5f5f5;
          margin: 0;
          padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { 
          background: white; 
          padding: 20px; 
          border-radius: 10px; 
          margin-bottom: 20px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .section {
          background: white;
          padding: 20px;
          border-radius: 10px;
          margin-bottom: 20px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .client-card {
          border: 1px solid #ddd;
          border-radius: 8px;
          padding: 20px;
          margin: 10px 0;
          background: #fafafa;
        }
        .client-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 15px;
        }
        .client-id {
          font-family: monospace;
          background: #f0f0f0;
          padding: 5px 10px;
          border-radius: 4px;
          font-size: 14px;
        }
        .client-secret {
          font-family: monospace;
          background: #fff3cd;
          padding: 5px 10px;
          border-radius: 4px;
          font-size: 14px;
        }
        .redirect-uris {
          background: #e8f4fd;
          padding: 10px;
          border-radius: 4px;
          margin: 10px 0;
        }
        button {
          background: #007bff;
          color: white;
          border: none;
          padding: 10px 20px;
          border-radius: 5px;
          cursor: pointer;
          margin: 5px;
        }
        button:hover { background: #0056b3; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .empty-state {
          text-align: center;
          padding: 40px;
          color: #666;
        }
        .integration-example {
          background: #f8f9fa;
          border: 1px solid #dee2e6;
          border-radius: 8px;
          padding: 20px;
          margin: 20px 0;
        }
        code {
          background: #f1f1f1;
          padding: 2px 4px;
          border-radius: 3px;
          font-family: monospace;
        }
        pre {
          background: #f8f9fa;
          padding: 15px;
          border-radius: 5px;
          overflow-x: auto;
          font-size: 14px;
        }
        .form-group {
          margin-bottom: 15px;
        }
        label {
          display: block;
          margin-bottom: 5px;
          font-weight: bold;
        }
        input, textarea {
          width: 100%;
          padding: 10px;
          border: 1px solid #ddd;
          border-radius: 4px;
          box-sizing: border-box;
        }
        textarea {
          resize: vertical;
          min-height: 60px;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Dashboard</h1>
          <div id="user-info">Loading...</div>
        </div>

        <div class="section">
          <h2>Your Applications</h2>
          <div id="clients-container">
            <div class="empty-state">
              <p>Loading your applications...</p>
            </div>
          </div>
          <button onclick="createClient()">Create New Application</button>
        </div>

        <div class="section">
          <h2>Integration Code</h2>
          <p>Copy this code to integrate with your application:</p>
          <div id="integration-example">
            <p>First, create an application to see integration code.</p>
          </div>
        </div>
      </div>

      <script>
        let currentUser = null;
        let clients = [];

        async function loadUserData() {
          try {
            // Get user ID from session or use demo
            const response = await fetch('/api/me');
            if (response.ok) {
              const user = await response.json();
              currentUser = user;
              document.getElementById('user-info').innerHTML = \`
                <strong>Welcome, \${user.email}</strong>
                <button onclick="logout()" style="margin-left: 10px;">Logout</button>
              \`;
            } else {
              // Demo mode
              currentUser = { id: 'demo-user', email: 'demo@example.com' };
              document.getElementById('user-info').innerHTML = \`
                <strong>Demo Mode</strong> 
                <button onclick="logout()">Logout</button>
              \`;
            }
            loadClients();
          } catch (error) {
            console.error('Failed to load user data:', error);
          }
        }

        async function loadClients() {
          try {
            const response = await fetch('/api/clients');
            if (!response.ok) {
              throw new Error('Failed to load clients');
            }
            
            clients = await response.json();
            displayClients();
          } catch (error) {
            console.error('Error loading clients:', error);
            document.getElementById('clients-container').innerHTML = \`
              <div class="empty-state">
                <p>Error loading applications. Please try again.</p>
              </div>
            \`;
          }
        }

        function displayClients() {
          const container = document.getElementById('clients-container');
          
          if (clients.length === 0) {
            container.innerHTML = \`
              <div class="empty-state">
                <h3>No applications yet</h3>
                <p>Create your first OAuth application to get started.</p>
              </div>
            \`;
            return;
          }

          container.innerHTML = clients.map(client => \`
            <div class="client-card">
              <div class="client-header">
                <h3>\${client.name}</h3>
                <div>
                  <button onclick="viewClient('${client.id}')">View Details</button>
                  <button onclick="deleteClient('${client.id}')" class="btn-danger">Delete</button>
                </div>
              </div>
              <div>
                <strong>Client ID:</strong>
                <div class="client-id">\${client.clientId}</div>
              </div>
              <div>
                <strong>Client Secret:</strong>
                <div class="client-secret" id="secret-${client.id}">
                  ••••••••
                  <button onclick="revealSecret('${client.id}')" style="margin-left: 10px;">Show</button>
                </div>
              </div>
              <div class="redirect-uris">
                <strong>Redirect URIs:</strong>
                <ul>
                  \${client.redirectUris.map(uri => \`<li>\${uri}</li>\`).join('')}
                </ul>
              </div>
            </div>
          \`).join('');
        }

        function createClient() {
          const name = prompt('Application name:');
          if (!name) return;

          const redirectUri = prompt('Redirect URI (e.g., http://localhost:3001/auth/callback):');
          if (!redirectUri) return;

          fetch('/api/clients', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              name,
              redirectUris: [redirectUri],
              userId: currentUser.id
            })
          })
          .then(res => res.json())
          .then(client => {
            clients.unshift(client);
            displayClients();
            updateIntegrationExample(client);
            alert(\`Application created!\\n\\nClient ID: \${client.clientId}\\nClient Secret: \${client.clientSecret}\\n\\nSave the client secret - it won't be shown again!\`);
          })
          .catch(error => {
            console.error('Error creating client:', error);
            alert('Failed to create application. Please try again.');
          });
        }

        function revealSecret(clientId) {
          const client = clients.find(c => c.id === clientId);
          if (client) {
            const secretDiv = document.getElementById(\`secret-\${clientId}\`);
            secretDiv.innerHTML = \`
              \${client.clientSecret}
              <button onclick="hideSecret('${clientId}')" style="margin-left: 10px;">Hide</button>
            \`;
          }
        }

        function hideSecret(clientId) {
          const secretDiv = document.getElementById(\`secret-\${clientId}\`);
          secretDiv.innerHTML = \`
            ••••••••
            <button onclick="revealSecret('${clientId}')" style="margin-left: 10px;">Show</button>
          \`;
        }

        function updateIntegrationExample(client) {
          const exampleDiv = document.getElementById('integration-example');
          exampleDiv.innerHTML = \`
            <h4>Client Application Integration</h4>
            <p><strong>Client ID:</strong> <code>\${client.clientId}</code></p>
            <p><strong>Client Secret:</strong> <code>\${client.clientSecret}</code></p>
            
            <h5>1. Redirect users to authorization:</h5>
            <pre>http://localhost:3000/auth/authorize?
  client_id=\${client.clientId}&
  response_type=code&
  redirect_uri=\${client.redirectUris[0]}&
  scope=openid profile email&
  state=random-string</pre>

            <h5>2. Exchange code for tokens:</h5>
            <pre>POST http://localhost:3000/auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTHORIZATION_CODE&
client_id=\${client.clientId}&
client_secret=\${client.clientSecret}&
redirect_uri=\${client.redirectUris[0]}</pre>

            <h5>3. Get user information:</h5>
            <pre>GET http://localhost:3000/auth/userinfo
Authorization: Bearer ACCESS_TOKEN</pre>
          \`;
        }

        function logout() {
          // In a real app, invalidate session
          window.location.href = '/';
        }

        // Load data on page load
        loadUserData();
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

//
//
//
//
//
//
//
//
//
//
//
//

// src/routes/dashboard.ts - Add login/register pages

// Login page with proper styling
dashboardRoutes.get("/login", (c) => {
	const redirectUri = c.req.query("redirect_uri") || "";
	const clientId = c.req.query("client_id") || "";
	const state = c.req.query("state") || "";
	const scope = c.req.query("scope") || "";

	return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Login - OpenID Provider</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          margin: 0;
          padding: 20px;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .login-container {
          background: white;
          padding: 40px;
          border-radius: 10px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.1);
          max-width: 400px;
          width: 100%;
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
        input {
          width: 100%;
          padding: 12px;
          border: 1px solid #ddd;
          border-radius: 5px;
          font-size: 16px;
          box-sizing: border-box;
        }
        input:focus {
          outline: none;
          border-color: #667eea;
          box-shadow: 0 0 0 2px rgba(102, 126, 234, 0.2);
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
        .register-link {
          text-align: center;
          margin-top: 20px;
        }
        .register-link a {
          color: #667eea;
          text-decoration: none;
        }
        .register-link a:hover {
          text-decoration: underline;
        }
      </style>
    </head>
    <body>
      <div class="login-container">
        <h1>Sign In</h1>
        <form method="POST" action="/login">
          <div class="form-group">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" required placeholder="your@email.com" />
          </div>
          <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required placeholder="••••••••" />
          </div>
          <input type="hidden" name="redirect_uri" value="${redirectUri}" />
          <input type="hidden" name="client_id" value="${clientId}" />
          <input type="hidden" name="state" value="${state}" />
          <input type="hidden" name="scope" value="${scope}" />
          <button type="submit">Sign In</button>
        </form>
        <div class="register-link">
          <p>Don't have an account? <a href="/register?redirect_uri=${redirectUri}&client_id=${clientId}&state=${state}&scope=${scope}">Sign up here</a></p>
        </div>
      </div>
    </body>
    </html>
  `);
});

// Register page with proper styling
dashboardRoutes.get("/register", (c) => {
	const redirectUri = c.req.query("redirect_uri") || "";
	const clientId = c.req.query("client_id") || "";
	const state = c.req.query("state") || "";
	const scope = c.req.query("scope") || "";

	return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Register - OpenID Provider</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
          margin: 0;
          padding: 20px;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .register-container {
          background: white;
          padding: 40px;
          border-radius: 10px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.1);
          max-width: 400px;
          width: 100%;
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
        input {
          width: 100%;
          padding: 12px;
          border: 1px solid #ddd;
          border-radius: 5px;
          font-size: 16px;
          box-sizing: border-box;
        }
        input:focus {
          outline: none;
          border-color: #667eea;
          box-shadow: 0 0 0 2px rgba(102, 126, 234, 0.2);
        }
        button {
          width: 100%;
          padding: 14px;
          background: #764ba2;
          color: white;
          border: none;
          border-radius: 5px;
          font-size: 16px;
          cursor: pointer;
          transition: background 0.3s;
        }
        button:hover {
          background: #6a4190;
        }
        .login-link {
          text-align: center;
          margin-top: 20px;
        }
        .login-link a {
          color: #764ba2;
          text-decoration: none;
        }
        .login-link a:hover {
          text-decoration: underline;
        }
      </style>
    </head>
    <body>
      <div class="register-container">
        <h1>Create Account</h1>
        <form method="POST" action="/register">
          <div class="form-group">
            <label for="name">Full Name</label>
            <input type="text" id="name" name="name" required placeholder="John Doe" />
          </div>
          <div class="form-group">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" required placeholder="your@email.com" />
          </div>
          <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required placeholder="Create a password" />
          </div>
          <input type="hidden" name="redirect_uri" value="${redirectUri}" />
          <input type="hidden" name="client_id" value="${clientId}" />
          <input type="hidden" name="state" value="${state}" />
          <input type="hidden" name="scope" value="${scope}" />
          <button type="submit">Create Account</button>
        </form>
        <div class="login-link">
          <p>Already have an account? <a href="/login?redirect_uri=${redirectUri}&client_id=${clientId}&state=${state}&scope=${scope}">Sign in here</a></p>
        </div>
      </div>
    </body>
    </html>
  `);
});

// Handle login POST
dashboardRoutes.post(
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
        <a href="/login${redirect_uri ? `?redirect_uri=${redirect_uri}&client_id=${client_id}&state=${state}&scope=${scope}` : ""}">Try again</a>
      </body>
      </html>
    `,
				401,
			);
		}

		// Create session
		const session = await prisma.session.create({
			data: {
				userId: user.id,
				expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
			},
		});

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

		return c.redirect("/dashboard");
	},
);

// Handle register POST
dashboardRoutes.post(
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
        <a href="/register${redirect_uri ? `?redirect_uri=${redirect_uri}&client_id=${client_id}&state=${state}&scope=${scope}` : ""}">Try again</a>
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

		// Create session
		await prisma.session.create({
			data: {
				userId: user.id,
				expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
			},
		});

		if (redirect_uri && client_id) {
			return c.redirect(
				`/login?redirect_uri=${redirect_uri}&client_id=${client_id}&state=${state}&scope=${scope}`,
			);
		}

		return c.redirect("/dashboard");
	},
);

//
//
//
//
//
//
//
//
//
//
//
//

// // Home page
// dashboardRoutes.get("/", (c) => {
// 	return c.html(`
//     <!DOCTYPE html>
//     <html>
//     <head>
//       <title>OpenID Provider</title>
//       <meta name="viewport" content="width=device-width, initial-scale=1">
//       <style>
//         body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
//         .btn { display: inline-block; padding: 15px 30px; margin: 10px; color: white; text-decoration: none; border-radius: 5px; }
//         .btn-primary { background: #007bff; }
//         .btn-success { background: #28a745; }
//       </style>
//     </head>
//     <body>
//       <h1>OpenID Provider</h1>
//       <p>Create your own OAuth2/OpenID Connect applications</p>
//       <a href="/register" class="btn btn-success">Get Started</a>
//       <a href="/dashboard" class="btn btn-primary">Dashboard</a>
//     </body>
//     </html>
//   `);
// });

// src/routes/dashboard.ts - Update home page
dashboardRoutes.get("/", (c) => {
	return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>OpenID Provider - Secure Authentication</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          margin: 0;
          padding: 20px;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .hero {
          text-align: center;
          color: white;
          max-width: 600px;
        }
        h1 { 
          font-size: 2.5em;
          margin-bottom: 20px;
        }
        p {
          font-size: 1.2em;
          margin-bottom: 40px;
          opacity: 0.9;
        }
        .buttons {
          display: flex;
          gap: 20px;
          justify-content: center;
          flex-wrap: wrap;
        }
        .btn { 
          display: inline-block;
          padding: 15px 30px;
          color: white;
          text-decoration: none;
          border-radius: 50px;
          font-size: 1.1em;
          transition: all 0.3s;
          min-width: 150px;
        }
        .btn-primary { 
          background: rgba(255,255,255,0.2);
          border: 2px solid white;
        }
        .btn-primary:hover {
          background: white;
          color: #667eea;
          transform: translateY(-2px);
        }
        .btn-secondary {
          background: rgba(255,255,255,0.1);
          border: 2px solid rgba(255,255,255,0.3);
        }
        .btn-secondary:hover {
          background: rgba(255,255,255,0.2);
          transform: translateY(-2px);
        }
      </style>
    </head>
    <body>
      <div class="hero">
        <h1>OpenID Provider</h1>
        <p>Secure authentication for your applications. Create your own OAuth2/OpenID Connect provider.</p>
        <div class="buttons">
          <a href="/login" class="btn btn-primary">Sign In</a>
          <a href="/register" class="btn btn-secondary">Create Account</a>
        </div>
      </div>
    </body>
    </html>
  `);
});
