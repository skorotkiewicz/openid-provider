import { v4 as uuidv4 } from "uuid";
import crypto from "crypto";

export function generateClientCredentials() {
	const clientId = uuidv4();
	const clientSecret = crypto.randomBytes(32).toString("hex");
	return { clientId, clientSecret };
}
