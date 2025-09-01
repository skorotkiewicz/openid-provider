import { SignJWT, jwtVerify, exportJWK } from "jose";

// RSA Keys
let privateKey: CryptoKey;
let publicKey: CryptoKey;

async function generateKeys() {
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
	publicKey = keyPair.publicKey;
}

// Initialize keys
generateKeys().catch(console.error);

export async function generateIdToken(
	user: any,
	clientId: string,
	scope?: string,
) {
	const payload: any = {
		sub: user.id,
		aud: clientId,
		iss: "http://localhost:3000",
		iat: Math.floor(Date.now() / 1000),
		exp: Math.floor(Date.now() / 1000) + 3600,
		scope: scope || "openid",
	};

	const scopeList = (scope || "openid").split(" ");

	// Add email if email scope is granted
	if (scopeList.includes("email")) {
		payload.email = user.email;
	}

	// Add profile fields based on granular scopes
	if (scopeList.includes("name")) {
		payload.name = user.name;
	}
	if (scopeList.includes("about")) {
		payload.about = user.about;
	}
	if (scopeList.includes("website")) {
		payload.website = user.website;
	}
	if (scopeList.includes("twitter")) {
		payload.twitter = user.twitter;
	}
	if (scopeList.includes("github")) {
		payload.github = user.github;
	}

	// Backward compatibility: if profile scope is granted, include all profile fields
	if (scopeList.includes("profile")) {
		payload.name = user.name;
		payload.about = user.about;
		payload.website = user.website;
		payload.twitter = user.twitter;
		payload.github = user.github;
	}

	return new SignJWT(payload)
		.setProtectedHeader({ alg: "RS256", kid: "1" })
		.sign(privateKey);
}

export async function generateAccessToken(
	userId: string,
	clientId: string,
	scope?: string,
) {
	return new SignJWT({
		sub: userId,
		aud: clientId,
		iss: "http://localhost:3000",
		iat: Math.floor(Date.now() / 1000),
		exp: Math.floor(Date.now() / 1000) + 3600,
		scope: scope || "openid",
	})
		.setProtectedHeader({ alg: "RS256", kid: "1" })
		.sign(privateKey);
}

export async function verifyToken(token: string) {
	return await jwtVerify(token, publicKey);
}

export async function getPublicJWK() {
	return await exportJWK(publicKey);
}
