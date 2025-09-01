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
	return new SignJWT({
		sub: user.id,
		email: user.email,
		name: user.name,
		aud: clientId,
		iss: "http://localhost:3000",
		iat: Math.floor(Date.now() / 1000),
		exp: Math.floor(Date.now() / 1000) + 3600,
		scope: scope || "openid",
	})
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
