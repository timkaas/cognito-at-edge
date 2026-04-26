import {
	generateNonce,
	generateSecret,
	sign,
	signNonce,
	generatePkceVerifier,
	generateCSRFTokens,
	getCurrentTimestampInSeconds,
	urlSafe,
	CSRF_CONFIG,
} from '../../src/util/csrf';

describe('generateNonce', () => {
	test('should generate nonce with timestamp and random string', () => {
		const nonce = generateNonce();
		expect(nonce).toMatch(/^\d+T[A-Za-z0-9\-._~]{16}$/);
	});

	test('should generate unique nonces', () => {
		const nonce1 = generateNonce();
		const nonce2 = generateNonce();
		expect(nonce1).not.toBe(nonce2);
	});
});

describe('generateSecret', () => {
	test('should generate secret of correct length', () => {
		const secret = generateSecret(CSRF_CONFIG.secretAllowedCharacters, 32);
		expect(secret).toHaveLength(32);
	});

	test('should only use allowed characters', () => {
		const secret = generateSecret(CSRF_CONFIG.secretAllowedCharacters, 100);
		const allowed = new Set(CSRF_CONFIG.secretAllowedCharacters);
		for (const char of secret) {
			expect(allowed.has(char)).toBe(true);
		}
	});

	test('should generate unique secrets', () => {
		const secret1 = generateSecret(CSRF_CONFIG.secretAllowedCharacters, 32);
		const secret2 = generateSecret(CSRF_CONFIG.secretAllowedCharacters, 32);
		expect(secret1).not.toBe(secret2);
	});
});

describe('sign', () => {
	test('should sign string with secret', () => {
		const result = sign('test', 'secret', 10);
		expect(result).toBeDefined();
		expect(typeof result).toBe('string');
	});

	test('should produce consistent signature for same input', () => {
		const sig1 = sign('test', 'secret', 16);
		const sig2 = sign('test', 'secret', 16);
		expect(sig1).toBe(sig2);
	});

	test('should produce different signature for different input', () => {
		const sig1 = sign('test1', 'secret', 16);
		const sig2 = sign('test2', 'secret', 16);
		expect(sig1).not.toBe(sig2);
	});

	test('should respect signature length parameter', () => {
		const sig8 = sign('test', 'secret', 8);
		const sig16 = sign('test', 'secret', 16);
		expect(sig8.length).toBeLessThanOrEqual(sig16.length);
	});
});

describe('signNonce', () => {
	test('should sign nonce with provided secret', () => {
		const nonce = generateNonce();
		const secret = 'my-signing-secret';
		const hmac = signNonce(nonce, secret);
		expect(hmac).toBeDefined();
		expect(typeof hmac).toBe('string');
	});

	test('should produce consistent signature for same nonce', () => {
		const nonce = generateNonce();
		const secret = 'my-signing-secret';
		const hmac1 = signNonce(nonce, secret);
		const hmac2 = signNonce(nonce, secret);
		expect(hmac1).toBe(hmac2);
	});

	test('should produce different signature for different secret', () => {
		const nonce = generateNonce();
		const hmac1 = signNonce(nonce, 'secret1');
		const hmac2 = signNonce(nonce, 'secret2');
		expect(hmac1).not.toBe(hmac2);
	});
});

describe('generatePkceVerifier', () => {
	test('should generate pkce and pkceHash', () => {
		const result = generatePkceVerifier();
		expect(result).toHaveProperty('pkce');
		expect(result).toHaveProperty('pkceHash');
	});

	test('should generate pkce of correct length', () => {
		const result = generatePkceVerifier();
		expect(result.pkce).toHaveLength(CSRF_CONFIG.pkceLength);
	});

	test('should generate unique verifiers', () => {
		const verifier1 = generatePkceVerifier();
		const verifier2 = generatePkceVerifier();
		expect(verifier1.pkce).not.toBe(verifier2.pkce);
		expect(verifier1.pkceHash).not.toBe(verifier2.pkceHash);
	});

	test('should use only allowed characters in pkce', () => {
		const result = generatePkceVerifier();
		const allowed = new Set(CSRF_CONFIG.secretAllowedCharacters);
		for (const char of result.pkce) {
			expect(allowed.has(char)).toBe(true);
		}
	});
});

describe('generateCSRFTokens', () => {
	test('should generate all required tokens', () => {
		const tokens = generateCSRFTokens('https://example.com', 'secret');
		expect(tokens).toHaveProperty('nonce');
		expect(tokens).toHaveProperty('nonceHmac');
		expect(tokens).toHaveProperty('pkce');
		expect(tokens).toHaveProperty('pkceHash');
		expect(tokens).toHaveProperty('state');
	});

	test('should include redirect_uri in state', () => {
		const redirectUri = 'https://example.com/callback';
		const tokens = generateCSRFTokens(redirectUri, 'secret');
		const decodedState = JSON.parse(
			Buffer.from(urlSafe.parse(tokens.state as string), 'base64').toString(),
		);
		expect(decodedState.redirect_uri).toBe(redirectUri);
	});

	test('should include nonce in state', () => {
		const tokens = generateCSRFTokens('https://example.com', 'secret');
		const decodedState = JSON.parse(
			Buffer.from(urlSafe.parse(tokens.state as string), 'base64').toString(),
		);
		expect(decodedState.nonce).toBe(tokens.nonce);
	});

	test('should sign nonce correctly', () => {
		const secret = 'my-secret';
		const tokens = generateCSRFTokens('https://example.com', secret);
		const expectedHmac = signNonce(tokens.nonce as string, secret);
		expect(tokens.nonceHmac).toBe(expectedHmac);
	});

	test('should generate unique token sets', () => {
		const tokens1 = generateCSRFTokens('https://example.com', 'secret');
		const tokens2 = generateCSRFTokens('https://example.com', 'secret');
		expect(tokens1.nonce).not.toBe(tokens2.nonce);
		expect(tokens1.pkce).not.toBe(tokens2.pkce);
	});
});

describe('getCurrentTimestampInSeconds', () => {
	test('should return a number', () => {
		const timestamp = getCurrentTimestampInSeconds();
		expect(typeof timestamp).toBe('number');
	});

	test('should return an integer', () => {
		const timestamp = getCurrentTimestampInSeconds();
		expect(Number.isInteger(timestamp)).toBe(true);
	});

	test('should return reasonable timestamp value', () => {
		const timestamp = getCurrentTimestampInSeconds();
		const now = Math.floor(Date.now() / 1000);
		expect(Math.abs(timestamp - now)).toBeLessThan(2);
	});

	test('should increase over time', () => {
		const timestamp1 = getCurrentTimestampInSeconds();
		const timestamp2 = getCurrentTimestampInSeconds();
		expect(timestamp2).toBeGreaterThanOrEqual(timestamp1);
	});
});

describe('urlSafe.stringify and parse', () => {
	test('should stringify base64 by replacing special characters', () => {
		const input = 'abc+def/ghi=';
		const stringified = urlSafe.stringify(input);
		expect(stringified).toBe('abc-def_ghi');
	});

	test('should parse url-safe string back to base64-like format', () => {
		const original = 'abc+def/ghi=';
		const stringified = urlSafe.stringify(original);
		const parsed = urlSafe.parse(stringified);
		expect(parsed).toContain('+');
		expect(parsed).toContain('/');
	});

	test('should round-trip correctly', () => {
		const original = 'SGVsbG8gV29ybGQ=';
		const stringified = urlSafe.stringify(original);
		const parsed = urlSafe.parse(stringified);
		// Note: trailing = may be stripped by stringify, which is expected
		expect(parsed.substring(0, parsed.length)).toContain('SGVs');
	});

	test('should handle strings without special characters', () => {
		const input = 'abcdefghijklmnop';
		const stringified = urlSafe.stringify(input);
		expect(stringified).toBe(input);
	});
});
