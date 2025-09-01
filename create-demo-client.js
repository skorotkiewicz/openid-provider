import { PrismaClient } from "@prisma/client";
import { v4 as uuidv4 } from "uuid";
import bcrypt from "bcryptjs";
import { SignJWT } from "jose";

const prisma = new PrismaClient();

// Generate RSA key pair for JWT signing (simplified for demo)
let privateKey;
async function generateKey() {
	const keyPair = await crypto.subtle.generateKey(
		{
			name: "RSASSA-PKCS1-v1_5",
			modulusLength: 2048,
			publicExponent: new Uint8Array([1, 0, 1]),
			hash: "SHA-256",
		},
		true,
		["sign", "verify"],
	);
	privateKey = keyPair.privateKey;
	return keyPair.publicKey;
}

async function createDemoUser() {
	try {
		console.log("Creating demo user...");

		// Check if demo user already exists
		const existingUser = await prisma.user.findUnique({
			where: { email: "demo@example.com" },
		});

		if (existingUser) {
			console.log("Demo user already exists:", existingUser);
			return existingUser;
		}

		// Create demo user
		const hashedPassword = await bcrypt.hash("demo123", 10);
		const demoUser = await prisma.user.create({
			data: {
				email: "demo@example.com",
				password: hashedPassword,
				name: "Demo User",
				about: "This is a demo user for testing the OAuth provider",
				website: "https://example.com",
				twitter: "@demouser",
				github: "demouser",
			},
		});

		console.log("Demo user created successfully:", demoUser);
		return demoUser;
	} catch (error) {
		console.error("Error creating demo user:", error);
	}
}

async function createDemoClient(userId) {
	try {
		console.log("Creating demo OAuth client...");

		// Check if demo client already exists
		const existingClient = await prisma.oAuthClient.findUnique({
			where: { clientId: "demo-client-id" },
		});

		if (existingClient) {
			console.log("Demo client already exists:", existingClient);
			return existingClient;
		}

		// Create demo client
		const demoClient = await prisma.oAuthClient.create({
			data: {
				clientId: "demo-client-id",
				clientSecret: "demo-client-secret",
				name: "Demo Client Application",
				redirectUris: ["http://127.0.0.1:5500/demo.html"],
				allowedScopes: [
					"openid",
					"email",
					"name",
					"about",
					"website",
					"twitter",
					"github",
					"profile",
				],
				userId: userId,
			},
		});

		console.log("Demo client created successfully:", demoClient);
		return demoClient;
	} catch (error) {
		console.error("Error creating demo client:", error);
	}
}

async function generateDemoToken(userId) {
	try {
		console.log("Generating demo JWT token...");

		await generateKey();

		const token = await new SignJWT({
			sub: userId,
			email: "demo@example.com",
			name: "Demo User",
			iss: "http://localhost:3000",
			iat: Math.floor(Date.now() / 1000),
			exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
		})
			.setProtectedHeader({ alg: "RS256", kid: "1" })
			.sign(privateKey);

		console.log("Demo token generated:", token);
		console.log("\n=== DEMO SETUP COMPLETE ===");
		console.log("Demo User Email: demo@example.com");
		console.log("Demo User Password: demo123");
		console.log("Demo JWT Token (for developer dashboard):", token);
		console.log("Copy this token to use in the developer dashboard");
		console.log("===========================\n");

		return token;
	} catch (error) {
		console.error("Error generating demo token:", error);
	}
}

async function main() {
	try {
		const demoUser = await createDemoUser();
		if (demoUser) {
			await createDemoClient(demoUser.id);
			await generateDemoToken(demoUser.id);
		}
	} catch (error) {
		console.error("Error in main:", error);
	} finally {
		await prisma.$disconnect();
	}
}

main();
