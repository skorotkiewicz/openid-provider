import { PrismaClient } from "@prisma/client";
import { v4 as uuidv4 } from "uuid";

const prisma = new PrismaClient();

async function createDemoClient() {
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
				userId: "demo-user",
			},
		});

		console.log("Demo client created successfully:", demoClient);
		return demoClient;
	} catch (error) {
		console.error("Error creating demo client:", error);
	} finally {
		await prisma.$disconnect();
	}
}

createDemoClient();
