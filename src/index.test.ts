import { CognitoJwtVerifierMultiUserPool, CognitoJwtVerifierSingleUserPool } from "aws-jwt-verify/cognito-verifier"
import { CloudFrontRequest, CloudFrontRequestEvent, CloudFrontResultResponse } from "aws-lambda"
import { afterEach, beforeEach, describe, expect, test, vi, type MockInstance } from "vitest"
import { Authenticator, AuthenticatorParams } from "./index"
import { serializeCookie } from "./util/cookie"
import * as csrfModule from "./util/csrf"
import { NONCE_COOKIE_NAME_SUFFIX, NONCE_HMAC_COOKIE_NAME_SUFFIX, PKCE_COOKIE_NAME_SUFFIX } from "./util/csrf"

const TEST_DATE = new Date("2017-01-01T00:00:00.000Z")
// Test helper class that exposes private methods for testing
// @ts-expect-error Making private functions public for testing
class AnyAuthenticator extends Authenticator {
	// @ts-expect-error Making private functions public for testing
	public fetchTokensFromCode = super.fetchTokensFromCode.bind(this)
	// @ts-expect-error Making private functions public for testing
	public fetchTokensFromRefreshToken = super.fetchTokensFromRefreshToken.bind(this)
	// @ts-expect-error Making private functions public for testing
	public getRedirectResponse = super.getRedirectResponse.bind(this)
	// @ts-expect-error Making private functions public for testing
	public getTokensFromCookie = super.getTokensFromCookie.bind(this)
	// @ts-expect-error Making private functions public for testing
	public getCSRFTokensFromCookie = super.getCSRFTokensFromCookie.bind(this)
	// @ts-expect-error Making private functions public for testing
	public getRedirectUriFromState = super.getRedirectUriFromState.bind(this)
	// @ts-expect-error Making private functions public for testing
	public revokeTokens = super.revokeTokens.bind(this)
	// @ts-expect-error Making private functions public for testing
	public clearCookies = super.clearCookies.bind(this)
	// @ts-expect-error Making private functions public for testing
	public getRedirectToCognitoUserPoolResponse = super.getRedirectToCognitoUserPoolResponse.bind(this)
	// @ts-expect-error Making private functions public for testing
	public validateCSRFCookies = super.validateCSRFCookies.bind(this)
	// @ts-expect-error Making private functions public for testing
	public getHost = super.getHost.bind(this)

	// Properties are accessed directly from parent class
	// TypeScript doesn't allow overriding properties with accessors, so we just declare the types

	declare public jwtVerifier: // eslint-disable-next-line @typescript-eslint/no-explicit-any
		| CognitoJwtVerifierSingleUserPool<any>
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		| CognitoJwtVerifierMultiUserPool<any>
	declare public cookieBase: string
	declare public csrfProtection: AuthenticatorParams["csrfProtection"]
	declare public logoutConfiguration: AuthenticatorParams["logoutConfiguration"]
	declare public parseAuthPath: string
}

const defaults: AuthenticatorParams = {
	region: "us-east-1",
	userPoolId: "us-east-1_abcdef123",
	userPoolClientId: "123456789qwertyuiop987abcd",
	userPoolDomain: "my-cognito-domain.auth.us-east-1.amazoncognito.com",
	cookieExpirationDays: 365,
	disableCookieDomain: false,
	httpOnly: false,
}

describe("private functions", () => {
	let authenticator: AnyAuthenticator

	beforeEach(() => {
		vi.useFakeTimers()
		vi.setSystemTime(TEST_DATE)

		authenticator = new AnyAuthenticator({
			...defaults,
		})
	})

	afterEach(() => {
		vi.useRealTimers()
		vi.restoreAllMocks()
	})

	test("should fetch token", async () => {
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(tokenData) }))

		const res = await authenticator.fetchTokensFromCode("htt://redirect", "AUTH_CODE")

		expect(res).toMatchObject({
			refreshToken: tokenData.refresh_token,
			accessToken: tokenData.access_token,
			idToken: tokenData.id_token,
		})
	})

	test("should throw if unable to fetch token", async () => {
		const unexpectedError = new Error("Unexpected error")
		vi.stubGlobal("fetch", vi.fn().mockRejectedValue(unexpectedError))

		await expect(() => authenticator.fetchTokensFromCode("htt://redirect", "AUTH_CODE")).rejects.toThrow(
			unexpectedError,
		)
	})

	test("should getRedirectResponse", async () => {
		const username = "toto"
		const domain = "example.com"
		const path = "/test"
		const spyJwtVerify = vi
			.spyOn(authenticator.jwtVerifier, "verify")
			.mockResolvedValueOnce(createMockCognitoPayload(username))

		const expectedDefaultExpiration = new Date(TEST_DATE)
		expectedDefaultExpiration.setDate(expectedDefaultExpiration.getDate() + 365)
		const response = await authenticator.getRedirectResponse(
			{
				refreshToken: tokenData.refresh_token,
				accessToken: tokenData.access_token,
				idToken: tokenData.id_token,
			},
			domain,
			path,
		)
		expect(response).toMatchObject({
			status: "302",
			headers: {
				location: [
					{
						key: "Location",
						value: "https://" + domain + path,
					},
				],
			},
		})
		expect(response.headers?.["set-cookie"]).toStrictEqual(
			expect.arrayContaining([
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
			]),
		)
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
	})

	test("should not return cookie domain", async () => {
		const authenticatorWithNoCookieDomain = new AnyAuthenticator({
			...defaults,
			disableCookieDomain: true,
		})
		authenticatorWithNoCookieDomain.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")

		const expectedDefaultExpiration = new Date(TEST_DATE)
		expectedDefaultExpiration.setDate(expectedDefaultExpiration.getDate() + 365)
		const username = "toto"
		const domain = "example.com"
		const path = "/test"
		const spyJwtVerify = vi
			.spyOn(authenticatorWithNoCookieDomain.jwtVerifier, "verify")
			.mockResolvedValueOnce(createMockCognitoPayload(username))

		const response = await authenticatorWithNoCookieDomain.getRedirectResponse(
			{
				accessToken: tokenData.access_token,
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			},
			domain,
			path,
		)
		expect(response).toMatchObject({
			status: "302",
			headers: {
				location: [
					{
						key: "Location",
						value: "https://" + domain + path,
					},
				],
			},
		})
		expect(response.headers?.["set-cookie"]).toStrictEqual(
			expect.arrayContaining([
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
			]),
		)
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
	})

	test("should set HttpOnly on cookies", async () => {
		const authenticatorWithHttpOnly = new AnyAuthenticator({
			...defaults,
			httpOnly: true,
		})
		authenticatorWithHttpOnly.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")

		const expectedDefaultExpiration = new Date(TEST_DATE)
		expectedDefaultExpiration.setDate(expectedDefaultExpiration.getDate() + 365)
		const username = "toto"
		const domain = "example.com"
		const path = "/test"
		const spyJwtVerify = vi
			.spyOn(authenticatorWithHttpOnly.jwtVerifier, "verify")
			.mockResolvedValueOnce(createMockCognitoPayload(username))

		const response = await authenticatorWithHttpOnly.getRedirectResponse(
			{
				accessToken: tokenData.access_token,
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			},
			domain,
			path,
		)
		expect(response).toMatchObject({
			status: "302",
			headers: {
				location: [
					{
						key: "Location",
						value: "https://" + domain + path,
					},
				],
			},
		})
		expect(response.headers?.["set-cookie"]).toStrictEqual(
			expect.arrayContaining([
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
			]),
		)
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
	})

	test("should set SameSite on cookies", async () => {
		const authenticatorWithSameSite = new AnyAuthenticator({
			...defaults,
			httpOnly: true,
			sameSite: "Strict",
		})
		authenticatorWithSameSite.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")

		const expectedDefaultExpiration = new Date(TEST_DATE)
		expectedDefaultExpiration.setDate(expectedDefaultExpiration.getDate() + 365)
		const username = "toto"
		const domain = "example.com"
		const path = "/test"
		const spyJwtVerify = vi
			.spyOn(authenticatorWithSameSite.jwtVerifier, "verify")
			.mockResolvedValueOnce(createMockCognitoPayload(username))

		const response = await authenticatorWithSameSite.getRedirectResponse(
			{
				accessToken: tokenData.access_token,
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			},
			domain,
			path,
		)
		expect(response).toMatchObject({
			status: "302",
			headers: {
				location: [
					{
						key: "Location",
						value: "https://" + domain + path,
					},
				],
			},
		})
		expect(response.headers?.["set-cookie"]).toStrictEqual(
			expect.arrayContaining([
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly; SameSite=Strict`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly; SameSite=Strict`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly; SameSite=Strict`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly; SameSite=Strict`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly; SameSite=Strict`,
				},
			]),
		)
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
	})

	test("should set Path on cookies", async () => {
		const cookiePath = "/test/path"
		const authenticatorWithPath = new AnyAuthenticator({
			...defaults,
			cookiePath,
		})

		authenticatorWithPath.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")

		const expectedDefaultExpiration = new Date(TEST_DATE)
		expectedDefaultExpiration.setDate(expectedDefaultExpiration.getDate() + 365)
		const username = "toto"
		const domain = "example.com"
		const path = "/test"
		const spyJwtVerify = vi
			.spyOn(authenticatorWithPath.jwtVerifier, "verify")
			.mockResolvedValueOnce(createMockCognitoPayload(username))

		const response = await authenticatorWithPath.getRedirectResponse(
			{
				accessToken: tokenData.access_token,
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			},
			domain,
			path,
		)
		expect(response).toMatchObject({
			status: "302",
			headers: {
				location: [
					{
						key: "Location",
						value: "https://" + domain + path,
					},
				],
			},
		})
		expect(response.headers?.["set-cookie"]).toStrictEqual(
			expect.arrayContaining([
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
			]),
		)
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
	})

	test("should set csrf tokens when the feature is enabled", async () => {
		const cookiePath = "/test/path"
		const authenticatorWithPath = new AnyAuthenticator({
			...defaults,
			cookiePath,
			csrfProtection: {
				nonceSigningSecret: "foo-bar",
			},
		})
		const expectedDefaultExpiration = new Date(TEST_DATE)
		expectedDefaultExpiration.setDate(expectedDefaultExpiration.getDate() + 365)

		authenticatorWithPath.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")

		const username = "toto"
		const domain = "example.com"
		const path = "/test"
		const spyJwtVerify = vi
			.spyOn(authenticatorWithPath.jwtVerifier, "verify")
			.mockResolvedValueOnce(createMockCognitoPayload(username))

		const response = await authenticatorWithPath.getRedirectResponse(
			{
				accessToken: tokenData.access_token,
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			},
			domain,
			path,
		)
		expect(response).toMatchObject({
			status: "302",
			headers: {
				location: [
					{
						key: "Location",
						value: "https://" + domain + path,
					},
				],
			},
		})
		expect(response.headers?.["set-cookie"]).toStrictEqual(
			expect.arrayContaining([
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${PKCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${TEST_DATE.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${TEST_DATE.toUTCString()}; Secure`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_HMAC_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${TEST_DATE.toUTCString()}; Secure`,
				},
			]),
		)
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
	})

	test("should use overriden cookie settings", async () => {
		const cookiePath = "/test/path"
		const authenticatorWithPath = new AnyAuthenticator({
			...defaults,
			cookiePath,
			httpOnly: true,
			csrfProtection: {
				nonceSigningSecret: "foo-bar",
			},
			cookieSettingsOverrides: {
				accessToken: {
					httpOnly: false,
					sameSite: "Lax",
					path: "/foo",
					expirationDays: 2,
				},
			},
		})
		authenticatorWithPath.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")

		const username = "toto"
		const domain = "example.com"
		const path = "/test"
		const spyJwtVerify = vi
			.spyOn(authenticatorWithPath.jwtVerifier, "verify")
			.mockResolvedValueOnce(createMockCognitoPayload(username))

		const response = await authenticatorWithPath.getRedirectResponse(
			{
				accessToken: tokenData.access_token,
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			},
			domain,
			path,
		)

		const expectedAccessTokenExpiration = new Date(TEST_DATE)
		expectedAccessTokenExpiration.setDate(expectedAccessTokenExpiration.getDate() + 2)

		const expectedDefaultExpiration = new Date(TEST_DATE)
		expectedDefaultExpiration.setDate(expectedDefaultExpiration.getDate() + 365)

		expect(response).toMatchObject({
			status: "302",
			headers: {
				location: [
					{
						key: "Location",
						value: "https://" + domain + path,
					},
				],
			},
		})
		expect(response.headers?.["set-cookie"]).toStrictEqual(
			expect.arrayContaining([
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Path=/foo; Expires=${expectedAccessTokenExpiration.toUTCString()}; Secure; SameSite=Lax`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${PKCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${TEST_DATE.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${TEST_DATE.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: "Set-Cookie",
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_HMAC_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${TEST_DATE.toUTCString()}; Secure; HttpOnly`,
				},
			]),
		)
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
	})

	test("should getIdTokenFromCookie", () => {
		const appClientName = "toto,./;;..-_lol123"
		expect(
			authenticator.getTokensFromCookie([
				{
					key: "Cookie",
					value: [
						serializeCookie(
							`CognitoIdentityServiceProvider.5uka3k8840tap1g1i1617jh8pi.${appClientName}.idToken`,
							"wrong",
						),
						serializeCookie(
							`CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken`,
							tokenData.id_token,
						),
						serializeCookie(
							`CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken`,
							tokenData.id_token,
						),
						serializeCookie(
							`CognitoIdentityServiceProvider.5ukasw8840tap1g1i1617jh8pi.${appClientName}.idToken`,
							"wrong",
						),
					].join("; "),
				},
			]),
		).toMatchObject({ idToken: tokenData.id_token })

		expect(
			authenticator.getTokensFromCookie([
				{
					key: "Cookie",
					value: [
						serializeCookie(
							`CognitoIdentityServiceProvider.5uka3k8840tap1g1i1617jh8pi.${appClientName}.accessToken`,
							tokenData.access_token,
						),
						serializeCookie(
							`CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken`,
							tokenData.id_token,
						),
					].join("; "),
				},
			]),
		).toMatchObject({ idToken: tokenData.id_token })

		expect(
			authenticator.getTokensFromCookie([
				{
					key: "Cookie",
					value: [
						serializeCookie(
							`CognitoIdentityServiceProvider.5uka3k8840tap1g1i1617jh8pi.${appClientName}.accessToken`,
							tokenData.access_token,
						),
						serializeCookie(
							`CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken`,
							tokenData.id_token,
						),
						serializeCookie(
							`CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.refreshToken`,
							tokenData.refresh_token,
						),
					].join("; "),
				},
			]),
		).toMatchObject({
			idToken: tokenData.id_token,
			refreshToken: tokenData.refresh_token,
		})
	})

	test("should getTokensFromCookie throw on cookies", () => {
		expect(() => authenticator.getTokensFromCookie([])).toThrow("idToken")
	})

	describe("_validateCSRFCookies", () => {
		function buildRequest(tokensInState = {}, tokensInCookie = {}): CloudFrontRequest {
			const state = Buffer.from(JSON.stringify(tokensInState)).toString("base64")

			const cookieHeaders: { key?: string | undefined; value: string }[] = []
			for (const [name, value] of Object.entries(tokensInCookie)) {
				cookieHeaders.push({
					key: "cookie",
					value: `${authenticator.cookieBase}.${name}=${String(value)}`,
				})
			}
			return {
				clientIp: "",
				method: "",
				uri: "",
				querystring: `state=${state}`,
				headers: {
					cookie: cookieHeaders,
				},
			}
		}

		beforeEach(() => {
			authenticator.csrfProtection = {
				nonceSigningSecret: "foo-bar",
			}
		})

		test("should throw error when nonce cookie is not present", () => {
			const request = buildRequest({ nonce: "nonce-value" }, {})
			expect(() => {
				authenticator.validateCSRFCookies(request)
			}).toThrow("Your browser didn't send the nonce cookie along, but it is required for security (prevent CSRF).")
		})

		test("should throw error when nonce cookie is different than the one encoded in state", () => {
			const request = buildRequest(
				{ [NONCE_COOKIE_NAME_SUFFIX]: "nonce-value" },
				{ [NONCE_COOKIE_NAME_SUFFIX]: "nonce-value-different" },
			)
			expect(() => {
				authenticator.validateCSRFCookies(request)
			}).toThrow(
				"Nonce mismatch. This can happen if you start multiple authentication attempts in parallel (e.g. in separate tabs)",
			)
		})

		test("should throw error when pkce cookie is absent", () => {
			const request = buildRequest(
				{
					[NONCE_COOKIE_NAME_SUFFIX]: "nonce-value",
					[PKCE_COOKIE_NAME_SUFFIX]: "pkce-value",
				},
				{ [NONCE_COOKIE_NAME_SUFFIX]: "nonce-value" },
			)
			expect(() => {
				authenticator.validateCSRFCookies(request)
			}).toThrow("Your browser didn't send the pkce cookie along, but it is required for security (prevent CSRF).")
		})

		test("should throw error when calculated Hmac is different than the one stored in the cookie", () => {
			//const csrfModule = await import("./util/csrf")
			vi.spyOn(csrfModule, "signNonce").mockReturnValue("nonce-hmac-value-different")

			const request = buildRequest(
				{
					[NONCE_COOKIE_NAME_SUFFIX]: "nonce-value",
					[PKCE_COOKIE_NAME_SUFFIX]: "pkce-value",
				},
				{
					[NONCE_COOKIE_NAME_SUFFIX]: "nonce-value",
					[PKCE_COOKIE_NAME_SUFFIX]: "pkce-value",
					[NONCE_HMAC_COOKIE_NAME_SUFFIX]: "nonce-hmac-value",
				},
			)
			expect(() => {
				authenticator.validateCSRFCookies(request)
			}).toThrow("Nonce signature mismatch!")
		})
	})

	test("_revokeTokens", async () => {
		const mockFetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({}) })
		vi.stubGlobal("fetch", mockFetch)
		await authenticator.revokeTokens({
			refreshToken: tokenData.refresh_token,
		})
		expect(mockFetch).toHaveBeenCalledWith(
			"https://my-cognito-domain.auth.us-east-1.amazoncognito.com/oauth2/revoke",
			expect.objectContaining({
				method: "POST",
			}),
		)
	})

	describe("_clearCookies", () => {
		test("should verify tokens and clear cookies", async () => {
			vi.spyOn(authenticator.jwtVerifier, "verify").mockResolvedValueOnce(createMockCognitoPayload())
			vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true }))
			authenticator.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")
			const tokens = {
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			}

			const event = getCloudfrontRequest()
			const { request } = event.Records[0].cf
			const response = await authenticator.clearCookies(request, "", tokens)
			expect(response).toStrictEqual(
				expect.objectContaining({
					status: "302",
				}),
			)
			expect(response.headers?.["set-cookie"].length).toBe(5)
		})

		test("should clear cookies even if tokens cannot be verified", async () => {
			vi.spyOn(authenticator.jwtVerifier, "verify").mockRejectedValueOnce(new Error())
			vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true }))
			authenticator.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")
			const tokens = {
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			}
			const event = getCloudfrontRequest()
			const { request } = event.Records[0].cf
			const numCookiesToBeCleared = request.headers.cookie.length || 0
			const response = await authenticator.clearCookies(request, "", tokens)
			expect(response).toStrictEqual(
				expect.objectContaining({
					status: "302",
				}),
			)
			expect(response.headers?.["set-cookie"].length).toBe(numCookiesToBeCleared)
		})

		test("should clear cookies and redirect to logoutRedirectUri", async () => {
			vi.spyOn(authenticator.jwtVerifier, "verify").mockResolvedValueOnce(createMockCognitoPayload())
			vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true }))
			authenticator.logoutConfiguration = {
				logoutUriPath: "/logout",
				logoutRedirectUri: "https://foobar.com",
			}
			authenticator.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")
			const tokens = {
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			}
			const event = getCloudfrontRequest()
			const { request } = event.Records[0].cf
			const cfDomain = authenticator.getHost(request)
			const response = await authenticator.clearCookies(request, cfDomain, tokens)
			expect(response).toStrictEqual(expect.objectContaining({ status: "302" }))
			expect(response.headers?.location[0]?.value).toStrictEqual(
				"https://my-cognito-domain.auth.us-east-1.amazoncognito.com/logout?client_id=123456789qwertyuiop987abcd&logout_uri=https%3A%2F%2Ffoobar.com",
			)
		})

		test("should clear cookies and redirect to redirect_uri query param", async () => {
			vi.spyOn(authenticator.jwtVerifier, "verify").mockResolvedValueOnce(createMockCognitoPayload())
			vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true }))
			authenticator.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")
			const event = getCloudfrontRequest()
			const { request } = event.Records[0].cf
			request.querystring = "redirect_uri=https://foobar2.com"
			const response = await authenticator.clearCookies(request, "")
			expect(response).toStrictEqual(expect.objectContaining({ status: "302" }))
			expect(response.headers?.location[0]?.value).toStrictEqual(
				"https://my-cognito-domain.auth.us-east-1.amazoncognito.com/logout?client_id=123456789qwertyuiop987abcd&redirect_uri=https%3A%2F%2Ffoobar2.com&response_type=code",
			)
		})

		test("should clear cookies and redirect to cf domain", async () => {
			vi.spyOn(authenticator.jwtVerifier, "verify").mockResolvedValueOnce(createMockCognitoPayload())
			vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true }))
			authenticator.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")
			const event = getCloudfrontRequest()
			const { request } = event.Records[0].cf
			const cfDomain = authenticator.getHost(request)
			const response = await authenticator.clearCookies(request, cfDomain)
			expect(response).toStrictEqual(expect.objectContaining({ status: "302" }))
			expect(response.headers?.location[0]?.value).toStrictEqual(
				"https://my-cognito-domain.auth.us-east-1.amazoncognito.com/logout?client_id=123456789qwertyuiop987abcd&logout_uri=https%3A%2F%2Fd111111abcdef8.cloudfront.net",
			)
		})
	})
})

describe("createAuthenticator", () => {
	const params: AuthenticatorParams = {
		...defaults,
		disableCookieDomain: true,
		httpOnly: false,
	}

	test("should create authenticator", () => {
		expect(typeof new Authenticator(params)).toBe("object")
	})

	test("should create authenticator without cookieExpirationDays", () => {
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { cookieExpirationDays, ...rest } = params
		expect(typeof new Authenticator(rest)).toBe("object")
	})

	test("should create authenticator without disableCookieDomain", () => {
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { disableCookieDomain, ...rest } = params
		expect(typeof new Authenticator(rest)).toBe("object")
	})

	test("should create authenticator without cookieDomain", () => {
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { cookieDomain, ...rest } = params
		expect(typeof new Authenticator(rest)).toBe("object")
	})

	test("should create authenticator without httpOnly", () => {
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { httpOnly, ...rest } = params
		expect(typeof new Authenticator(rest)).toBe("object")
	})

	test("should create authenticator without cookiePath", () => {
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { cookiePath, ...rest } = params
		expect(typeof new Authenticator(rest)).toBe("object")
	})
})

describe("handle", () => {
	let authenticator: AnyAuthenticator
	let spyJwtVerify: MockInstance
	let spyGetTokensFromCookie: MockInstance
	let spyGetTokensFromCode: MockInstance
	let spyFetchTokensFromRefreshToken: MockInstance
	let spyGetRedirectResponse: MockInstance
	let spyGetRedirectToCognitoUserPoolResponse: MockInstance
	let spyRevokeTokens: MockInstance
	let spyClearCookies: MockInstance

	beforeEach(() => {
		vi.useFakeTimers()
		vi.setSystemTime(TEST_DATE)

		authenticator = new AnyAuthenticator({
			...defaults,
		})
		authenticator.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")
		spyGetTokensFromCookie = vi.spyOn(authenticator, "getTokensFromCookie")
		spyGetTokensFromCode = vi.spyOn(authenticator, "fetchTokensFromCode")
		spyFetchTokensFromRefreshToken = vi.spyOn(authenticator, "fetchTokensFromRefreshToken")
		spyGetRedirectResponse = vi.spyOn(authenticator, "getRedirectResponse")
		spyGetRedirectToCognitoUserPoolResponse = vi.spyOn(authenticator, "getRedirectToCognitoUserPoolResponse")
		spyRevokeTokens = vi.spyOn(authenticator, "revokeTokens")
		spyClearCookies = vi.spyOn(authenticator, "clearCookies")
		spyJwtVerify = vi.spyOn(authenticator.jwtVerifier, "verify")
	})

	afterEach(() => {
		vi.useRealTimers()
		vi.restoreAllMocks()
	})

	test("should forward request if authenticated", async () => {
		spyJwtVerify.mockResolvedValueOnce({
			token_use: "id",
			sub: "test-sub",
			iss: "test-iss",
			exp: 0,
			iat: 0,
			auth_time: 0,
			jti: "test-jti",
			origin_jti: "test-origin-jti",
		})

		const result = await authenticator.handle(getCloudfrontRequest())

		expect(result).toStrictEqual(getCloudfrontRequest().Records[0].cf.request)
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1)
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
	})

	test("should fetch with refresh token if available", async () => {
		spyJwtVerify.mockRejectedValueOnce(new Error())
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		})
		spyFetchTokensFromRefreshToken.mockResolvedValueOnce(tokenData)
		spyGetRedirectResponse.mockReturnValueOnce({
			response: "toto",
		})
		const request = getCloudfrontRequest()
		request.Records[0].cf.request.querystring = "code=54fe5f4e&state=/lol"

		const result = await authenticator.handle(request)

		expect(result).toStrictEqual({ response: "toto" })
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1)
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
		expect(spyFetchTokensFromRefreshToken).toHaveBeenCalledTimes(1)
		expect(spyGetRedirectResponse).toHaveBeenCalledWith(tokenData, "d111111abcdef8.cloudfront.net", "/lol")
	})

	test("should redirect to cognito if refresh token is invalid", async () => {
		spyJwtVerify.mockRejectedValueOnce(new Error())
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		})
		spyFetchTokensFromRefreshToken.mockRejectedValueOnce(new Error())
		spyGetRedirectToCognitoUserPoolResponse.mockReturnValueOnce({
			response: "toto",
		})
		const request = getCloudfrontRequest()

		const result = await authenticator.handle(request)

		expect(result).toStrictEqual({ response: "toto" })
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1)
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
		expect(spyFetchTokensFromRefreshToken).toHaveBeenCalledTimes(1)
	})

	test("should fetch and set token if code is present", async () => {
		spyJwtVerify.mockRejectedValueOnce(new Error())
		spyGetTokensFromCode.mockResolvedValueOnce(tokenData)
		spyGetRedirectResponse.mockReturnValueOnce({
			response: "toto",
		})
		const request = getCloudfrontRequest()
		request.Records[0].cf.request.querystring = "code=54fe5f4e&state=/lol"

		const result = await authenticator.handle(request)

		expect(result).toStrictEqual({ response: "toto" })
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
		expect(spyGetTokensFromCode).toHaveBeenCalledTimes(1)
		expect(spyGetRedirectResponse).toHaveBeenCalledWith(tokenData, "d111111abcdef8.cloudfront.net", "/lol")
	})

	test("should fetch and set token if code is present (custom redirect)", async () => {
		const authenticatorWithCustomRedirect = new AnyAuthenticator({
			...defaults,
			parseAuthPath: "/custom/login/path",
		})
		const spyJwtVerify = vi
			.spyOn(authenticatorWithCustomRedirect.jwtVerifier, "verify")
			.mockRejectedValueOnce(new Error())
		const spyFetchTokensFromCode = vi
			.spyOn(authenticatorWithCustomRedirect, "fetchTokensFromCode")
			.mockResolvedValueOnce(tokenData)
		const spyGetRedirectResponse = vi
			.spyOn(authenticatorWithCustomRedirect, "getRedirectResponse")
			.mockResolvedValueOnce({
				status: "302",
			})

		const request = getCloudfrontRequest()
		request.Records[0].cf.request.querystring = "code=54fe5f4e&state=/lol"

		const result = await authenticatorWithCustomRedirect.handle(request)

		expect(result).toStrictEqual({ status: "302" })
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
		expect(spyFetchTokensFromCode).toHaveBeenCalledWith(
			"https://d111111abcdef8.cloudfront.net/custom/login/path",
			"54fe5f4e",
		)
		expect(spyGetRedirectResponse).toHaveBeenCalledWith(tokenData, "d111111abcdef8.cloudfront.net", "/lol")
	})

	test("should fetch and set token if code is present and when csrfProtection is enabled", async () => {
		spyJwtVerify.mockRejectedValueOnce(new Error())
		spyGetTokensFromCode.mockResolvedValueOnce(tokenData)
		spyGetRedirectResponse.mockReturnValueOnce({
			response: "toto",
		})
		authenticator.csrfProtection = {
			nonceSigningSecret: "foobar",
		}
		const encodedState = Buffer.from(JSON.stringify({ redirect_uri: "/lol" })).toString("base64")
		const request = getCloudfrontRequest()
		request.Records[0].cf.request.querystring = `code=54fe5f4e&state=${encodedState}`

		const result = await authenticator.handle(request)

		expect(result).toStrictEqual({ response: "toto" })
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
		expect(spyGetTokensFromCode).toHaveBeenCalledTimes(1)
		expect(spyGetRedirectResponse).toHaveBeenCalledWith(tokenData, "d111111abcdef8.cloudfront.net", "/lol")
	})

	test("should redirect to auth domain if unauthenticated and no code", async () => {
		spyJwtVerify.mockRejectedValueOnce(new Error())

		const result = await authenticator.handle(getCloudfrontRequest())

		expect(result).toStrictEqual({
			status: "302",
			headers: {
				location: [
					{
						key: "Location",
						value:
							"https://my-cognito-domain.auth.us-east-1.amazoncognito.com/oauth2/authorize?redirect_uri=https%3A%2F%2Fd111111abcdef8.cloudfront.net&response_type=code&client_id=123456789qwertyuiop987abcd&state=%2Flol%253F%253Fparam%253D1",
					},
				],
				"cache-control": [
					{
						key: "Cache-Control",
						value: "no-cache, no-store, max-age=0, must-revalidate",
					},
				],
				pragma: [
					{
						key: "Pragma",
						value: "no-cache",
					},
				],
			},
		})
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
	})

	test("should redirect to auth domain if unauthenticated and no code (custom redirect)", async () => {
		const authenticatorWithCustomRedirect = new AnyAuthenticator({
			...defaults,
			parseAuthPath: "/custom/login/path",
		})
		const spyJwtVerify = vi
			.spyOn(authenticatorWithCustomRedirect.jwtVerifier, "verify")
			.mockRejectedValueOnce(new Error())

		const result = await authenticatorWithCustomRedirect.handle(getCloudfrontRequest())

		expect(result).toStrictEqual({
			status: "302",
			headers: {
				location: [
					{
						key: "Location",
						value:
							"https://my-cognito-domain.auth.us-east-1.amazoncognito.com/oauth2/authorize?redirect_uri=https%3A%2F%2Fd111111abcdef8.cloudfront.net%2Fcustom%2Flogin%2Fpath&response_type=code&client_id=123456789qwertyuiop987abcd&state=%2Flol%253F%253Fparam%253D1",
					},
				],
				"cache-control": [
					{
						key: "Cache-Control",
						value: "no-cache, no-store, max-age=0, must-revalidate",
					},
				],
				pragma: [
					{
						key: "Pragma",
						value: "no-cache",
					},
				],
			},
		})
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
	})

	test("should redirect to auth domain and clear csrf cookies if unauthenticated and no code", async () => {
		spyJwtVerify.mockRejectedValueOnce(new Error())

		authenticator.csrfProtection = {
			nonceSigningSecret: "foo-bar",
		}
		const response = await authenticator.handle(getCloudfrontRequest())
		expect(response).toMatchObject({
			status: "302",
			headers: {
				"cache-control": [
					{
						key: "Cache-Control",
						value: "no-cache, no-store, max-age=0, must-revalidate",
					},
				],
				pragma: [
					{
						key: "Pragma",
						value: "no-cache",
					},
				],
			},
		})
		expect(response.headers?.location).toBeDefined()
		const locationHeader = response.headers?.location
		expect(locationHeader).toBeDefined()
		const url = new URL(locationHeader?.[0]?.value ?? "")
		expect(url.origin).toStrictEqual("https://my-cognito-domain.auth.us-east-1.amazoncognito.com")
		expect(url.pathname).toStrictEqual("/oauth2/authorize")
		expect(url.searchParams.get("redirect_uri")).toStrictEqual("https://d111111abcdef8.cloudfront.net")
		expect(url.searchParams.get("response_type")).toStrictEqual("code")
		expect(url.searchParams.get("client_id")).toStrictEqual("123456789qwertyuiop987abcd")
		expect(url.searchParams.get("state")).toBeDefined()

		// Cookies
		expect(response.headers?.["set-cookie"]).toBeDefined()
		const setCookieHeaders = response.headers?.["set-cookie"]
		const cookies = setCookieHeaders?.map((h: { key?: string | undefined; value: string }) => h.value) ?? []
		expect(cookies.find(c => c.match(`.${NONCE_COOKIE_NAME_SUFFIX}=`))).toBeDefined()
		expect(cookies.find(c => c.match(`.${NONCE_HMAC_COOKIE_NAME_SUFFIX}=`))).toBeDefined()
		expect(cookies.find(c => c.match(`.${PKCE_COOKIE_NAME_SUFFIX}=`))).toBeDefined()
	})

	test("should redirect to auth domain with custom return redirect if unauthenticated", async () => {
		const authenticatorWithCustomRedirect = new AnyAuthenticator({
			...defaults,
			parseAuthPath: "/custom/login/path",
		})
		vi.spyOn(authenticatorWithCustomRedirect.jwtVerifier, "verify").mockRejectedValueOnce(new Error())
		const response = await authenticatorWithCustomRedirect.handle(getCloudfrontRequest())

		expect(response.headers?.location).toBeDefined()
		const locationHeader = response.headers?.location
		const url = new URL(locationHeader?.[0]?.value ?? "")
		expect(url.searchParams.get("redirect_uri")).toStrictEqual(
			"https://d111111abcdef8.cloudfront.net/custom/login/path",
		)
	})

	test("should revoke tokens and clear cookies if logoutConfiguration is set", async () => {
		authenticator.logoutConfiguration = {
			logoutUriPath: "/logout",
			logoutRedirectUri: "https://example.com",
		}
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		})
		spyRevokeTokens.mockResolvedValueOnce(undefined)
		spyClearCookies.mockResolvedValueOnce({ status: "302" })
		const request = getCloudfrontRequest()
		request.Records[0].cf.request.uri = "/logout"

		const result = await authenticator.handle(request)

		expect(result).toStrictEqual(expect.objectContaining({ status: "302" }))
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1)
		expect(spyRevokeTokens).toHaveBeenCalledTimes(1)
		expect(spyClearCookies).toHaveBeenCalledTimes(1)
	})

	test("should clear cookies if logoutConfiguration is set even if user is unauthenticated", async () => {
		authenticator.logoutConfiguration = {
			logoutUriPath: "/logout",
			logoutRedirectUri: "https://example.com",
		}
		spyGetTokensFromCookie.mockImplementationOnce(() => {
			throw new Error()
		})
		spyClearCookies.mockResolvedValueOnce({ status: "302" })

		const request = getCloudfrontRequest()
		request.Records[0].cf.request.uri = "/logout"

		const result = await authenticator.handle(request)

		expect(result).toStrictEqual(expect.objectContaining({ status: "302" }))
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1)
		expect(spyRevokeTokens).not.toHaveBeenCalledTimes(1)
		expect(spyClearCookies).toHaveBeenCalledTimes(1)
	})

	describe("_getRedirectResponse", () => {
		test("should handle expected case (relative path with / prefix)", async () => {
			spyJwtVerify.mockResolvedValueOnce(createMockCognitoPayload("toto"))

			const response = await authenticator.getRedirectResponse(
				{
					refreshToken: tokenData.refresh_token,
					accessToken: tokenData.access_token,
					idToken: tokenData.id_token,
				},
				"example.com",
				"/subpath/1",
			)

			expect(response.headers?.location).toBeDefined()
			const locationHeader = response.headers?.location
			expect(locationHeader?.[0]?.value).toStrictEqual("https://example.com/subpath/1")
		})

		test("should handle case where relative path is missing / prefix)", async () => {
			vi.spyOn(authenticator.jwtVerifier, "verify")
			spyJwtVerify.mockResolvedValueOnce(createMockCognitoPayload("toto"))

			const response = await authenticator.getRedirectResponse(
				{
					refreshToken: tokenData.refresh_token,
					accessToken: tokenData.access_token,
					idToken: tokenData.id_token,
				},
				"example.com",
				"subpath/2",
			)

			expect(response.headers?.location).toBeDefined()
			const locationHeader = response.headers?.location
			expect(locationHeader?.[0]?.value).toStrictEqual("https://example.com/subpath/2")
		})

		test("should redirect to a subpath of the CloudFront domain even if state contains a malicious URL (inc. protocol)", async () => {
			spyJwtVerify.mockResolvedValueOnce(createMockCognitoPayload("toto"))

			const response = await authenticator.getRedirectResponse(
				{
					refreshToken: tokenData.refresh_token,
					accessToken: tokenData.access_token,
					idToken: tokenData.id_token,
				},
				"example.com",
				"https://malicious-site.com/phishing",
			)

			expect(response.headers?.location).toBeDefined()
			const locationHeader = response.headers?.location
			expect(locationHeader?.[0]?.value).toStrictEqual("https://example.com/https://malicious-site.com/phishing")
		})

		test("should redirect to a subpath of the CloudFront domain even if state contains a malicious URL (// no protocol)", async () => {
			spyJwtVerify.mockResolvedValueOnce(createMockCognitoPayload("toto"))

			const response = await authenticator.getRedirectResponse(
				{
					refreshToken: tokenData.refresh_token,
					accessToken: tokenData.access_token,
					idToken: tokenData.id_token,
				},
				"example.com",
				"//malicious-site.com/phishing",
			)

			expect(response.headers?.location).toBeDefined()
			const locationHeader = response.headers?.location
			expect(locationHeader?.[0]?.value).toStrictEqual("https://example.com//malicious-site.com/phishing")
		})
	})
})

describe("handleSignIn", () => {
	let authenticator: AnyAuthenticator
	let spyGetTokensFromCookie: MockInstance
	let spyRedirectToCognito: MockInstance
	let spyJwtVerify: MockInstance

	beforeEach(() => {
		vi.useFakeTimers()
		vi.setSystemTime(TEST_DATE)

		authenticator = new AnyAuthenticator({
			...defaults,
			parseAuthPath: "parseAuth",
		})
		authenticator.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")
		spyGetTokensFromCookie = vi.spyOn(authenticator, "getTokensFromCookie")
		spyRedirectToCognito = vi.spyOn(authenticator, "getRedirectToCognitoUserPoolResponse")
		spyJwtVerify = vi.spyOn(authenticator.jwtVerifier, "verify")
	})

	afterEach(() => {
		vi.useRealTimers()
		vi.restoreAllMocks()
	})

	test("should forward request if authenticated", async () => {
		spyJwtVerify.mockResolvedValueOnce({
			token_use: "id",
			sub: "test-sub",
			iss: "test-iss",
			exp: 0,
			iat: 0,
			auth_time: 0,
			jti: "test-jti",
			origin_jti: "test-origin-jti",
		})
		const request = getCloudfrontRequest()
		request.Records[0].cf.request.querystring = "redirect_uri=https://example.aws.com"
		const response = await authenticator.handleSignIn(request)
		expect(response.status).toStrictEqual("302")
		expect(response.headers?.location).toBeDefined()
		const locationHeader = response.headers?.location
		expect(locationHeader?.[0]?.value).toStrictEqual("https://example.aws.com")
	})

	test("should redirect to cognito if refresh token is invalid", async () => {
		spyJwtVerify.mockRejectedValueOnce(new Error())
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		})
		spyRedirectToCognito.mockReturnValueOnce({
			response: "toto",
		})
		const request = getCloudfrontRequest()

		const result = await authenticator.handleSignIn(request)

		expect(result).toStrictEqual({ response: "toto" })
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1)
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
		expect(spyRedirectToCognito).toHaveBeenCalledTimes(1)
	})
})

describe("handleParseAuth", () => {
	let authenticator: AnyAuthenticator
	let spyValidateCSRFCookies: MockInstance
	let spyGetTokensFromCode: MockInstance
	let spyGetRedirectResponse: MockInstance

	beforeEach(() => {
		vi.useFakeTimers()
		vi.setSystemTime(TEST_DATE)

		authenticator = new AnyAuthenticator({
			...defaults,
			parseAuthPath: "parseAuth",
		})
		authenticator.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")
		spyValidateCSRFCookies = vi.spyOn(authenticator, "validateCSRFCookies")
		spyGetTokensFromCode = vi.spyOn(authenticator, "fetchTokensFromCode")
		spyGetRedirectResponse = vi.spyOn(authenticator, "getRedirectResponse")
	})

	afterEach(() => {
		vi.useRealTimers()
		vi.restoreAllMocks()
	})

	describe("if code is present", () => {
		test("should redirect successfully if csrfProtection is not enabled", async () => {
			spyGetTokensFromCode.mockResolvedValueOnce({
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
				accessToken: tokenData.access_token,
			})
			spyGetRedirectResponse.mockReturnValueOnce({
				response: "toto",
			})
			const state = Buffer.from(
				JSON.stringify({
					nonce: "nonceValue",
					nonceHmac: "nonceHmacValue",
					pkce: "pkceValue",
				}),
			).toString("base64")
			const request = getCloudfrontRequest()
			request.Records[0].cf.request.querystring = `code=code&state=${state}`

			const result = await authenticator.handleParseAuth(request)

			expect(result).toStrictEqual({ response: "toto" })
			expect(spyValidateCSRFCookies).not.toHaveBeenCalledTimes(1)
			expect(spyGetTokensFromCode).toHaveBeenCalledTimes(1)
			expect(spyGetRedirectResponse).toHaveBeenCalledTimes(1)
		})

		test("should redirect successfully after validating CSRF tokens", async () => {
			authenticator.csrfProtection = {
				nonceSigningSecret: "foo-bar",
			}
			spyValidateCSRFCookies.mockImplementation(() => {
				/* empty */
			})
			spyGetTokensFromCode.mockResolvedValueOnce({
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
				accessToken: tokenData.access_token,
			})
			spyGetRedirectResponse.mockReturnValueOnce({
				response: "toto",
			})
			const state = Buffer.from(
				JSON.stringify({
					nonce: "nonceValue",
					nonceHmac: "nonceHmacValue",
					pkce: "pkceValue",
				}),
			).toString("base64")
			const request = getCloudfrontRequest()
			request.Records[0].cf.request.querystring = `code=code&state=${state}`

			const result = await authenticator.handleParseAuth(request)

			expect(result).toStrictEqual({ response: "toto" })
			expect(spyValidateCSRFCookies).toHaveBeenCalledTimes(1)
			expect(spyGetTokensFromCode).toHaveBeenCalledTimes(1)
			expect(spyGetRedirectResponse).toHaveBeenCalledTimes(1)
		})
	})

	test("should throw error when parseAuthPath is not set", async () => {
		authenticator.parseAuthPath = ""
		spyGetRedirectResponse.mockReturnValueOnce({
			response: "toto",
		})
		const result: CloudFrontResultResponse = await authenticator.handleParseAuth(getCloudfrontRequest())
		expect(result).toStrictEqual({
			status: "400",
			// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
			body: expect.stringContaining("parseAuthPath"),
		})
		expect(spyValidateCSRFCookies).not.toHaveBeenCalledTimes(1)
		expect(spyGetTokensFromCode).not.toHaveBeenCalledTimes(1)
		expect(spyGetRedirectResponse).not.toHaveBeenCalledTimes(1)
	})

	test("should throw if code is absent", async () => {
		spyValidateCSRFCookies.mockRejectedValueOnce(new Error())
		const result = await authenticator.handleParseAuth(getCloudfrontRequest())
		expect(result).toStrictEqual(expect.objectContaining({ status: "400" }))
		expect(spyValidateCSRFCookies).not.toHaveBeenCalledTimes(1)
		expect(spyGetTokensFromCode).not.toHaveBeenCalledTimes(1)
		expect(spyGetRedirectResponse).not.toHaveBeenCalledTimes(1)
	})
})

describe("handleRefreshToken", () => {
	let authenticator: AnyAuthenticator
	let spyGetTokensFromCookie: MockInstance
	let spyJwtVerify: MockInstance
	let spyFetchTokensFromRefreshToken: MockInstance
	let spyGetRedirectResponse: MockInstance

	beforeEach(() => {
		vi.useFakeTimers()
		vi.setSystemTime(TEST_DATE)

		authenticator = new AnyAuthenticator({
			...defaults,
		})
		authenticator.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")
		spyGetTokensFromCookie = vi.spyOn(authenticator, "getTokensFromCookie")
		spyJwtVerify = vi.spyOn(authenticator.jwtVerifier, "verify")
		spyFetchTokensFromRefreshToken = vi.spyOn(authenticator, "fetchTokensFromRefreshToken")
		spyGetRedirectResponse = vi.spyOn(authenticator, "getRedirectResponse")
		vi.spyOn(authenticator, "getRedirectToCognitoUserPoolResponse")
	})

	afterEach(() => {
		vi.useRealTimers()
		vi.restoreAllMocks()
	})

	test("should refresh tokens successfully", async () => {
		const username = "toto"
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		})
		spyJwtVerify.mockResolvedValueOnce(createMockCognitoPayload(username))
		spyFetchTokensFromRefreshToken.mockResolvedValueOnce({
			idToken: tokenData.id_token,
			refreshToken: tokenData.refresh_token,
			accessToken: tokenData.access_token,
		})
		spyGetRedirectResponse.mockReturnValueOnce({
			response: "toto",
		})

		const result = await authenticator.handleRefreshToken(getCloudfrontRequest())

		expect(result).toStrictEqual({ response: "toto" })
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1)
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
		expect(spyFetchTokensFromRefreshToken).toHaveBeenCalledTimes(1)
		expect(spyGetRedirectResponse).toHaveBeenCalledTimes(1)
	})

	test("should redirect to cognito user pool if refresh token is invalid", async () => {
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		})
		spyJwtVerify.mockRejectedValueOnce(new Error())

		const result = await authenticator.handleRefreshToken(getCloudfrontRequest())

		expect(result).toStrictEqual(expect.objectContaining({ status: "302" }))
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1)
		expect(spyJwtVerify).toHaveBeenCalledTimes(1)
		expect(spyFetchTokensFromRefreshToken).not.toHaveBeenCalledTimes(1)
		expect(spyGetRedirectResponse).not.toHaveBeenCalledTimes(1)
	})
})

describe("handleSignOut", () => {
	let authenticator: AnyAuthenticator
	let spyGetTokensFromCookie: MockInstance
	let spyRevokeTokens: MockInstance
	let spyClearCookies: MockInstance

	beforeEach(() => {
		vi.useFakeTimers()
		vi.setSystemTime(TEST_DATE)

		authenticator = new AnyAuthenticator({
			...defaults,
		})
		authenticator.jwtVerifier.cacheJwks(jwksData, "us-east-1_abcdef123")
		spyGetTokensFromCookie = vi.spyOn(authenticator, "getTokensFromCookie")
		spyRevokeTokens = vi.spyOn(authenticator, "revokeTokens")
		spyClearCookies = vi.spyOn(authenticator, "clearCookies")
	})

	afterEach(() => {
		vi.useRealTimers()
		vi.restoreAllMocks()
	})

	test("should revoke tokens and clear cookies successfully", async () => {
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		})
		spyRevokeTokens.mockResolvedValueOnce(undefined)
		spyClearCookies.mockResolvedValueOnce({ status: "302" })

		const result = await authenticator.handleSignOut(getCloudfrontRequest())

		expect(result).toStrictEqual(expect.objectContaining({ status: "302" }))
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1)
		expect(spyRevokeTokens).toHaveBeenCalledTimes(1)
		expect(spyClearCookies).toHaveBeenCalledTimes(1)
	})

	test("should clear cookies successfully even if tokens cannot be revoked", async () => {
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		})
		spyRevokeTokens.mockRejectedValueOnce(new Error())
		spyClearCookies.mockResolvedValueOnce({ status: "302" })

		const result = await authenticator.handleSignOut(getCloudfrontRequest())

		expect(result).toStrictEqual(expect.objectContaining({ status: "302" }))
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1)
		expect(spyRevokeTokens).toHaveBeenCalledTimes(1)
		expect(spyClearCookies).toHaveBeenCalledTimes(1)
	})
})

const jwksData = {
	keys: [
		{
			kid: "1234example=",
			alg: "RS256",
			kty: "RSA",
			e: "AQAB",
			n: "1234567890",
			use: "sig",
		},
		{
			kid: "5678example=",
			alg: "RS256",
			kty: "RSA",
			e: "AQAB",
			n: "987654321",
			use: "sig",
		},
	],
}

const tokenData = {
	access_token: "eyJz9sdfsdfsdfsd",
	refresh_token: "dn43ud8uj32nk2je",
	id_token: "dmcxd329ujdmkemkd349r",
	token_type: "Bearer" as const,
	expires_in: 3600,
}

const getCloudfrontRequest = () =>
	({
		Records: [
			{
				cf: {
					config: {
						distributionDomainName: "d123.cloudfront.net",
						distributionId: "EDFDVBD6EXAMPLE",
						eventType: "viewer-request" as const,
						requestId: "MRVMF7KydIvxMWfJIglgwHQwZsbG2IhRJ07sn9AkKUFSHS9EXAMPLE==",
					},
					request: {
						body: {
							action: "read-only" as const,
							data: "eyJ1c2VybmFtZSI6IkxhbWJkYUBFZGdlIiwiY29tbWVudCI6IlRoaXMgaXMgcmVxdWVzdCBib2R5In0=",
							encoding: "base64" as const,
							inputTruncated: false,
						},
						clientIp: "2001:0db8:85a3:0:0:8a2e:0370:7334",
						querystring: "?param=1",
						uri: "/lol",
						method: "GET",
						headers: {
							host: [
								{
									key: "Host",
									value: "d111111abcdef8.cloudfront.net",
								},
							],
							"user-agent": [
								{
									key: "User-Agent",
									value: "curl/7.51.0",
								},
							],
							cookie: [
								{
									key: "cookie",
									value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.toto.idToken=${tokenData.access_token};`,
								},
							],
						},
						origin: {
							custom: {
								customHeaders: {
									"my-origin-custom-header": [
										{
											key: "My-Origin-Custom-Header",
											value: "Test",
										},
									],
								},
								domainName: "example.com",
								keepaliveTimeout: 5,
								path: "/custom_path",
								port: 443,
								protocol: "https" as const,
								readTimeout: 5,
								sslProtocols: ["TLSv1", "TLSv1.1"],
							},
						},
					},
				},
			},
		],
	}) satisfies CloudFrontRequestEvent

// Helper to create a minimal valid Cognito JWT payload for testing
const createMockCognitoPayload = (username?: string) => ({
	token_use: "id" as const,
	sub: "test-sub",
	iss: "test-iss",
	exp: 0,
	iat: 0,
	auth_time: 0,
	jti: "test-jti",
	origin_jti: "test-origin-jti",
	aud: "test-aud",
	at_hash: "test-at-hash",
	"cognito:username": username ?? "test-user",
	email_verified: false,
	phone_number_verified: false,
	identities: [],
	"cognito:roles": [],
	"cognito:preferred_role": "test-role",
})
