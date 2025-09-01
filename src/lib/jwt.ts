// src/lib/jwt.ts - Use correct algorithm name
import { SignJWT, jwtVerify, exportJWK } from "jose";

// Generate RSA key pair using correct algorithm name
let privateKey: CryptoKey;
let publicKey: CryptoKey;

async function generateKeys() {
	const keyPair = await crypto.subtle.generateKey(
		{
			name: "RSA-PSS",
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

// Generate keys on startup
generateKeys().catch(console.error);

export async function generateIdToken(user: any, clientId: string) {
	return new SignJWT({
		sub: user.id,
		email: user.email,
		name: user.name,
		aud: clientId,
		iss: "http://localhost:3000",
		iat: Math.floor(Date.now() / 1000),
		exp: Math.floor(Date.now() / 1000) + 3600,
	})
		.setProtectedHeader({ alg: "RS256", kid: "1" })
		.sign(privateKey);
}

export async function generateAccessToken(userId: string, clientId: string) {
	return new SignJWT({
		sub: userId,
		aud: clientId,
		iss: "http://localhost:3000",
		iat: Math.floor(Date.now() / 1000),
		exp: Math.floor(Date.now() / 1000) + 3600,
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

// Fallback to HS256 if RSA fails
let fallbackSecret: Uint8Array;

export function setFallbackSecret() {
	fallbackSecret = crypto.getRandomValues(new Uint8Array(32));
}

export async function generateIdTokenHS256(user: any, clientId: string) {
	const encoder = new TextEncoder();
	return new SignJWT({
		sub: user.id,
		email: user.email,
		name: user.name,
		aud: clientId,
		iss: "http://localhost:3000",
		iat: Math.floor(Date.now() / 1000),
		exp: Math.floor(Date.now() / 1000) + 3600,
	})
		.setProtectedHeader({ alg: "HS256" })
		.sign(fallbackSecret);
}

// Initialize fallback
setFallbackSecret();
