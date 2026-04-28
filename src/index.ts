import { CognitoJwtVerifier } from "aws-jwt-verify"
import { CognitoIdTokenPayload } from "aws-jwt-verify/jwt-model"
import type { CloudFrontRequest, CloudFrontRequestEvent, CloudFrontResultResponse } from "aws-lambda"
import { parse } from "querystring"
import {
	CookieAttributes,
	CookieSettingsOverrides,
	CookieType,
	getCookieDomain,
	parseCookies,
	SameSite,
	serializeCookie,
} from "./util/cookie"
import {
	CSRFTokens,
	generateCSRFTokens,
	NONCE_COOKIE_NAME_SUFFIX,
	NONCE_HMAC_COOKIE_NAME_SUFFIX,
	PKCE_COOKIE_NAME_SUFFIX,
	signNonce,
	urlSafe,
} from "./util/csrf"

type LogLevel = "fatal" | "error" | "warn" | "info" | "debug" | "trace" | "silent"

interface Logger {
	debug(...args: unknown[]): void
	info(...args: unknown[]): void
	warn(...args: unknown[]): void
	error(...args: unknown[]): void
}

function createLogger(level: LogLevel = "silent"): Logger {
	const levels: Record<LogLevel, number> = {
		trace: 10,
		debug: 20,
		info: 30,
		warn: 40,
		error: 50,
		fatal: 60,
		silent: Infinity,
	}
	// eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
	const minLevel = levels[level] ?? Infinity
	const noop = () => {
		/* empty */
	}

	const formatArg = (arg: unknown) => (typeof arg === "object" && arg !== null ? JSON.stringify(arg) : arg)

	return {
		debug:
			minLevel <= 20
				? (...args: unknown[]) => {
						console.debug(...args.map(formatArg))
					}
				: noop,
		info:
			minLevel <= 30
				? (...args: unknown[]) => {
						console.info(...args.map(formatArg))
					}
				: noop,
		warn:
			minLevel <= 40
				? (...args: unknown[]) => {
						console.warn(...args.map(formatArg))
					}
				: noop,
		error:
			minLevel <= 50
				? (...args: unknown[]) => {
						console.error(...args.map(formatArg))
					}
				: noop,
	}
}

export interface AuthenticatorParams {
	region: string
	userPoolId: string
	userPoolClientId: string
	userPoolClientSecret?: string
	userPoolDomain: string
	cookieExpirationDays?: number
	disableCookieDomain?: boolean
	httpOnly?: boolean
	sameSite?: SameSite
	logLevel?: LogLevel
	cookiePath?: string
	cookieDomain?: string
	cookieSettingsOverrides?: CookieSettingsOverrides
	logoutConfiguration?: LogoutConfiguration
	parseAuthPath?: string
	tokenScopes?: string
	csrfProtection?: {
		nonceSigningSecret: string
	}
}

interface LogoutConfiguration {
	// Path on your CloudFront distribution that triggers the logout flow
	logoutUriPath: string
	// Must be a registered sign-out URL in the Cognito app client
	logoutRedirectUri: string
}

interface Tokens {
	accessToken?: string
	idToken?: string
	refreshToken?: string
	token_type?: "Bearer"
	expires_in?: number
}

const MS_PER_DAY = 24 * 60 * 60 * 1000
const CSRF_COOKIE_TTL_MS = 10 * 60 * 1000
const NO_CACHE_VALUE = "no-cache, no-store, max-age=0, must-revalidate"
const DEFAULT_TOKEN_SCOPES = "phone email profile openid aws.cognito.signin.user.admin"

export class Authenticator {
	private readonly userPoolClientId: string
	private readonly userPoolClientSecret: string | undefined
	private readonly userPoolDomain: string
	private readonly cookieExpirationDays: number
	private readonly disableCookieDomain: boolean
	private readonly httpOnly: boolean
	private readonly sameSite?: SameSite
	private readonly cookieBase: string
	private readonly cookiePath?: string
	private readonly cookieDomain?: string
	private readonly csrfProtection?: {
		nonceSigningSecret: string
	}
	private readonly logoutConfiguration?: LogoutConfiguration
	private readonly parseAuthPath: string
	private readonly cookieSettingsOverrides?: CookieSettingsOverrides
	private readonly tokenScopes: string
	private readonly logger: Logger
	private readonly jwtVerifier
	private readonly tokenCache: Map<string, { payload: CognitoIdTokenPayload; expSec: number }>

	constructor(params: AuthenticatorParams) {
		this.userPoolClientId = params.userPoolClientId
		this.userPoolClientSecret = params.userPoolClientSecret
		this.userPoolDomain = params.userPoolDomain
		this.cookieExpirationDays = params.cookieExpirationDays ?? 365
		this.disableCookieDomain = "disableCookieDomain" in params && params.disableCookieDomain === true
		this.cookieDomain = params.cookieDomain
		this.httpOnly = "httpOnly" in params && params.httpOnly === true
		this.sameSite = params.sameSite
		this.cookieBase = `CognitoIdentityServiceProvider.${params.userPoolClientId}`
		this.cookiePath = params.cookiePath
		this.cookieSettingsOverrides = params.cookieSettingsOverrides ?? {}
		this.tokenScopes = params.tokenScopes ?? DEFAULT_TOKEN_SCOPES
		this.logger = createLogger(params.logLevel)
		this.jwtVerifier = CognitoJwtVerifier.create({
			userPoolId: params.userPoolId,
			clientId: params.userPoolClientId,
			tokenUse: "id",
		})
		this.tokenCache = new Map()
		this.jwtVerifier.hydrate().catch(() => {
			// JWKS will be fetched on first verify() if this fails — no action needed
		})
		this.csrfProtection = params.csrfProtection
		this.logoutConfiguration = params.logoutConfiguration
		this.parseAuthPath = (params.parseAuthPath ?? "").replace(/^\//, "")
	}

	async hydrate(): Promise<void> {
		await this.jwtVerifier.hydrate()
	}

	private async verifyIdToken(idToken: string) {
		const nowSec = Math.floor(Date.now() / 1000)
		const cached = this.tokenCache.get(idToken)
		if (cached && nowSec < cached.expSec) {
			return cached.payload
		}
		const payload = await this.jwtVerifier.verify(idToken)
		this.tokenCache.set(idToken, {
			payload,
			// eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
			expSec: payload.exp ?? nowSec,
		})
		return payload
	}

	private async verifyIdTokenOnLogout(idToken: string) {
		const nowSec = Math.floor(Date.now() / 1000)
		const cached = this.tokenCache.get(idToken)
		this.tokenCache.delete(idToken)
		if (cached && nowSec < cached.expSec) {
			return cached.payload
		}
		return this.jwtVerifier.verify(idToken)
	}

	private async postToTokenEndpoint<T>(data: Record<string, string>, logCtx: Record<string, unknown>): Promise<T> {
		const url = `https://${this.userPoolDomain}/oauth2/token`
		this.logger.debug({ ...logCtx, url })
		try {
			const resp = await this.postFormData(url, data)
			const json = (await resp.json()) as T
			this.logger.debug({ ...logCtx, tokens: json })
			return json
		} catch (err) {
			this.logger.error({ ...logCtx, url })
			throw err
		}
	}

	/**
	 * Exchange authorization code for tokens.
	 * @param  {String} redirectUri Redirection URI.
	 * @param  {String} code        Authorization code.
	 * @return {Promise} Authenticated user tokens.
	 */
	private async fetchTokensFromCode(redirectUri: string, code: string): Promise<Tokens> {
		const resp = await this.postToTokenEndpoint<{
			id_token: string
			access_token: string
			refresh_token: string
		}>(
			{
				client_id: this.userPoolClientId,
				code,
				grant_type: "authorization_code",
				redirect_uri: redirectUri,
			},
			{ msg: "Fetching tokens from grant code...", code },
		)
		return {
			idToken: resp.id_token,
			accessToken: resp.access_token,
			refreshToken: resp.refresh_token,
		}
	}

	/**
	 * Fetch accessTokens from refreshToken.
	 * @param  {String} redirectUri Redirection URI.
	 * @param  {String} refreshToken Refresh token.
	 * @return {Promise<Tokens>} Refreshed user tokens.
	 */
	private async fetchTokensFromRefreshToken(redirectUri: string, refreshToken: string): Promise<Tokens> {
		const resp = await this.postToTokenEndpoint<{
			id_token: string
			access_token: string
		}>(
			{
				client_id: this.userPoolClientId,
				refresh_token: refreshToken,
				grant_type: "refresh_token",
				redirect_uri: redirectUri,
			},
			{ msg: "Fetching tokens from refreshToken...", refreshToken },
		)
		return {
			idToken: resp.id_token,
			accessToken: resp.access_token,
		}
	}

	private getAuthorization(): string | undefined {
		return (
			this.userPoolClientSecret &&
			Buffer.from(`${this.userPoolClientId}:${this.userPoolClientSecret}`).toString("base64")
		)
	}

	private getHost(request: CloudFrontRequest): string {
		return request.headers.host[0].value
	}

	private getRequestedRedirectUri(cfDomain: string, requestParams: ReturnType<typeof parse>): string {
		return (requestParams.redirect_uri as string) || `https://${cfDomain}`
	}

	private createCookieAttributes(domain?: string, expires?: Date): CookieAttributes {
		return {
			domain,
			expires,
			secure: true,
			httpOnly: this.httpOnly,
			sameSite: this.sameSite,
			path: this.cookiePath,
		}
	}

	private getCallbackUri(cfDomain: string, fallback: string): string {
		return this.parseAuthPath ? `https://${cfDomain}/${this.parseAuthPath}` : fallback
	}

	private createRedirectResponse(location: string, cookies?: string[]): CloudFrontResultResponse {
		return {
			status: "302",
			headers: {
				location: [{ key: "Location", value: location }],
				"cache-control": [{ key: "Cache-Control", value: NO_CACHE_VALUE }],
				pragma: [{ key: "Pragma", value: "no-cache" }],
				...(cookies && { "set-cookie": cookies.map(c => ({ key: "Set-Cookie", value: c })) }),
			},
		}
	}

	private validateCSRFCookies(request: CloudFrontRequest) {
		if (!this.csrfProtection) {
			throw new Error("validateCSRFCookies should not be called if CSRF protection is disabled.")
		}

		const requestParams = parse(request.querystring)
		const requestCookies = request.headers.cookie.flatMap(h => parseCookies(h.value))
		this.logger.debug({ msg: "Validating CSRF Cookies", requestCookies })

		const parsedState = JSON.parse(Buffer.from(urlSafe.parse(requestParams.state as string), "base64").toString()) as {
			nonce?: string
		}

		const { nonce: originalNonce, nonceHmac, pkce } = this.getCSRFTokensFromCookie(request.headers.cookie)

		if (!parsedState.nonce || !originalNonce || parsedState.nonce !== originalNonce) {
			if (!originalNonce) {
				throw new Error(
					"Your browser didn't send the nonce cookie along, but it is required for security (prevent CSRF).",
				)
			}
			throw new Error(
				"Nonce mismatch. This can happen if you start multiple authentication attempts in parallel (e.g. in separate tabs)",
			)
		}
		if (!pkce) {
			throw new Error("Your browser didn't send the pkce cookie along, but it is required for security (prevent CSRF).")
		}

		const calculatedHmac = signNonce(parsedState.nonce, this.csrfProtection.nonceSigningSecret)
		if (calculatedHmac !== nonceHmac) {
			// eslint-disable-next-line @typescript-eslint/restrict-template-expressions
			throw new Error(`Nonce signature mismatch! Expected ${calculatedHmac} but got ${nonceHmac}`)
		}
	}

	private applyCookieOverrides(cookieAttributes: CookieAttributes = {}, cookieType: CookieType): CookieAttributes {
		const res = { ...cookieAttributes }
		const overrides = this.cookieSettingsOverrides?.[cookieType]
		if (overrides) {
			if (overrides.httpOnly !== undefined) res.httpOnly = overrides.httpOnly
			if (overrides.sameSite !== undefined) res.sameSite = overrides.sameSite
			if (overrides.path !== undefined) res.path = overrides.path
			if (overrides.expirationDays !== undefined) {
				res.expires = new Date(Date.now() + overrides.expirationDays * MS_PER_DAY)
			}
		}
		this.logger.debug({
			msg: "Cookie settings overridden",
			cookieAttributes,
			cookieType,
			cookieSettingsOverrides: this.cookieSettingsOverrides,
		})
		return res
	}

	/**
	 * Create a Lambda@Edge redirection response to set the tokens on the user's browser cookies.
	 * @param  {Object} tokens   Cognito User Pool tokens.
	 * @param  {String} domain   Website domain.
	 * @param  {String} path     Relative path to the requested object.
	 * @return Lambda@Edge response.
	 */
	private async getRedirectResponse(tokens: Tokens, domain: string, path: string): Promise<CloudFrontResultResponse> {
		// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
		const decoded = await this.verifyIdToken(tokens.idToken!)
		const username = decoded["cognito:username"]
		const usernameBase = `${this.cookieBase}.${username}`
		const cookieDomain = getCookieDomain(domain, this.disableCookieDomain, this.cookieDomain)
		const cookieAttributes = this.createCookieAttributes(
			cookieDomain,
			new Date(Date.now() + this.cookieExpirationDays * MS_PER_DAY),
		)
		const cookies = [
			serializeCookie(
				`${usernameBase}.accessToken`,
				// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
				tokens.accessToken!,
				this.applyCookieOverrides(cookieAttributes, "accessToken"),
			),
			serializeCookie(
				`${usernameBase}.idToken`,
				// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
				tokens.idToken!,
				this.applyCookieOverrides(cookieAttributes, "idToken"),
			),
			...(tokens.refreshToken
				? [
						serializeCookie(
							`${usernameBase}.refreshToken`,
							tokens.refreshToken,
							this.applyCookieOverrides(cookieAttributes, "refreshToken"),
						),
					]
				: []),
			serializeCookie(`${usernameBase}.tokenScopesString`, this.tokenScopes, cookieAttributes),
			serializeCookie(`${this.cookieBase}.LastAuthUser`, username, cookieAttributes),
		]

		if (this.csrfProtection) {
			// Domain attribute is always not set here as CSRF cookies are used
			// exclusively by the CF distribution
			const csrfCookieAttributes = { ...cookieAttributes, domain: undefined, expires: new Date() }
			cookies.push(
				serializeCookie(`${this.cookieBase}.${PKCE_COOKIE_NAME_SUFFIX}`, "", csrfCookieAttributes),
				serializeCookie(`${this.cookieBase}.${NONCE_COOKIE_NAME_SUFFIX}`, "", csrfCookieAttributes),
				serializeCookie(`${this.cookieBase}.${NONCE_HMAC_COOKIE_NAME_SUFFIX}`, "", csrfCookieAttributes),
			)
		}

		const locationUrl = "https://" + domain + (path.startsWith("/") ? "" : "/") + path
		const response = this.createRedirectResponse(locationUrl, cookies)
		this.logger.debug({ msg: "Generated set-cookie response", response })
		return response
	}

	/**
	 * Extract value of the authentication token from the request cookies.
	 * @param  {Array}  cookieHeaders 'Cookie' request headers.
	 * @return {Tokens} Extracted id token or access token. Null if not found.
	 */
	private getTokensFromCookie(cookieHeaders: { key?: string | undefined; value: string }[] | undefined): Tokens {
		if (!cookieHeaders) {
			this.logger.debug("Cookies weren't present in the request")
			throw new Error("Cookies weren't present in the request")
		}

		this.logger.debug({ msg: "Extracting authentication token from request cookie", cookieHeaders })

		const prefix = `${this.cookieBase}.`
		const tokens: Tokens = {}

		for (const header of cookieHeaders) {
			for (const { name, value } of parseCookies(header.value)) {
				if (name.startsWith(prefix)) {
					if (name.endsWith(".idToken")) tokens.idToken = value
					else if (name.endsWith(".refreshToken")) tokens.refreshToken = value
				}
			}
		}

		if (!tokens.idToken && !tokens.refreshToken) {
			this.logger.debug("Neither idToken, nor refreshToken was present in request cookies")
			throw new Error("Neither idToken, nor refreshToken was present in request cookies")
		}

		this.logger.debug({ msg: "Found tokens in cookie", tokens })
		return tokens
	}

	/**
	 * Extract values of the CSRF tokens from the request cookies.
	 * @param  {Array}  cookieHeaders 'Cookie' request headers.
	 * @return {CSRFTokens} Extracted CSRF Tokens from cookie.
	 */
	private getCSRFTokensFromCookie(
		cookieHeaders: { key?: string | undefined; value: string }[] | undefined,
	): CSRFTokens {
		if (!cookieHeaders) {
			this.logger.debug("Cookies weren't present in the request")
			throw new Error("Cookies weren't present in the request")
		}

		this.logger.debug({ msg: "Extracting CSRF tokens from request cookie", cookieHeaders })

		const csrfTokens: CSRFTokens = {}
		for (const header of cookieHeaders) {
			for (const { name, value } of parseCookies(header.value)) {
				if (name.startsWith(this.cookieBase)) {
					for (const key of [NONCE_COOKIE_NAME_SUFFIX, NONCE_HMAC_COOKIE_NAME_SUFFIX, PKCE_COOKIE_NAME_SUFFIX]) {
						if (name.endsWith(`.${key}`)) csrfTokens[key] = value
					}
				}
			}
		}

		this.logger.debug({ msg: "Found CSRF tokens in cookie", csrfTokens })
		return csrfTokens
	}

	/**
	 * Extracts the redirect uri from the state param. When CSRF protection is
	 * enabled, redirect uri is encoded inside state along with other data. So, it
	 * needs to be base64 decoded. When CSRF is not enabled, state can be used
	 * directly.
	 * @param {string} state
	 * @returns {string}
	 */
	private getRedirectUriFromState(state: string): string {
		if (this.csrfProtection) {
			const parsedState = JSON.parse(Buffer.from(urlSafe.parse(state), "base64").toString()) as {
				redirect_uri: string
				nonce?: string
			}
			this.logger.debug({ msg: "Parsed state param to extract redirect uri", parsedState })
			return parsedState.redirect_uri
		}
		return state
	}

	private async postFormData(url: string, data: Record<string, string>): Promise<Response> {
		const authorization = this.getAuthorization()
		const init: RequestInit = {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				...(authorization && { Authorization: `Basic ${authorization}` }),
			},
			body: new URLSearchParams(data).toString(),
		}
		const resp = await fetch(url, init)
		if (!resp.ok) {
			// eslint-disable-next-line @typescript-eslint/restrict-template-expressions
			throw new Error(`HTTP ${resp.status}: ${resp.statusText}`)
		}
		return resp
	}

	private async revokeTokens(tokens: Tokens) {
		const url = `https://${this.userPoolDomain}/oauth2/revoke`
		const data = { client_id: this.userPoolClientId, token: tokens.refreshToken ?? "" }
		this.logger.debug({ msg: "Revoking refreshToken...", url, refreshToken: tokens.refreshToken })
		try {
			await this.postFormData(url, data)
		} catch (err) {
			this.logger.error({ msg: "Unable to revoke refreshToken", url, err: JSON.stringify(err) })
			throw err
		}
		this.logger.debug({ msg: "Revoked refreshToken", refreshToken: tokens.refreshToken })
	}

	private async clearCookies(
		request: CloudFrontRequest,
		cfDomain: string,
		tokens: Tokens = {},
	): Promise<CloudFrontResultResponse> {
		this.logger.info({ msg: "Clearing cookies...", request, tokens })
		const cookieDomain = getCookieDomain(cfDomain, this.disableCookieDomain, this.cookieDomain)
		const cookieAttributes = this.createCookieAttributes(cookieDomain, new Date())

		let responseCookies: string[] = []
		try {
			// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
			const decoded = await this.verifyIdTokenOnLogout(tokens.idToken!)
			const username = decoded["cognito:username"]
			this.logger.info({ msg: "Token verified. Clearing cookies...", idToken: tokens.idToken, username })

			const usernameBase = `${this.cookieBase}.${username}`
			responseCookies = [
				serializeCookie(`${usernameBase}.accessToken`, "", cookieAttributes),
				serializeCookie(`${usernameBase}.idToken`, "", cookieAttributes),
				...(tokens.refreshToken ? [serializeCookie(`${usernameBase}.refreshToken`, "", cookieAttributes)] : []),
				serializeCookie(`${usernameBase}.tokenScopesString`, "", cookieAttributes),
				serializeCookie(`${this.cookieBase}.LastAuthUser`, "", cookieAttributes),
			]
		} catch (err) {
			this.logger.error(err)
			this.logger.info({
				msg: "Unable to verify token. Inferring data from request cookies and clearing them...",
				idToken: tokens.idToken,
			})
			// eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
			const requestCookies = (request.headers.cookie ?? []).flatMap(h => parseCookies(h.value))
			for (const { name } of requestCookies) {
				if (name.startsWith(this.cookieBase)) {
					responseCookies.push(serializeCookie(name, "", cookieAttributes))
				}
			}
		}

		const requestParams = parse(request.querystring)
		const redirectUri = requestParams.redirect_uri

		const params = redirectUri
			? new URLSearchParams({
					client_id: this.userPoolClientId,
					redirect_uri: redirectUri as string,
					response_type: "code",
				})
			: new URLSearchParams({
					client_id: this.userPoolClientId,
					logout_uri: this.logoutConfiguration?.logoutRedirectUri ?? `https://${cfDomain}`,
				})

		const logoutUrl = `https://${this.userPoolDomain}/logout?${params}`
		const response = this.createRedirectResponse(logoutUrl, responseCookies)
		this.logger.debug({ msg: "Generated set-cookie response", response })
		return response
	}

	/**
	 * Get redirect to cognito userpool response
	 * @param  {CloudFrontRequest}  request The original request
	 * @param  {string}  redirectUri Redirection URI.
	 * @return {CloudFrontResultResponse} Redirect response.
	 */
	private getRedirectToCognitoUserPoolResponse(
		request: CloudFrontRequest,
		redirectUri: string,
	): CloudFrontResultResponse {
		let csrfTokens: CSRFTokens = {}
		let state: string | undefined
		if (this.csrfProtection) {
			csrfTokens = generateCSRFTokens(redirectUri, this.csrfProtection.nonceSigningSecret)
			state = csrfTokens.state
		} else {
			let redirectPath = request.uri
			if (request.querystring) {
				redirectPath += encodeURIComponent("?" + request.querystring)
			}
			state = redirectPath
		}

		const params = new URLSearchParams({
			redirect_uri: redirectUri,
			response_type: "code",
			client_id: this.userPoolClientId,
			...(state && { state }),
		})

		const userPoolUrl = `https://${this.userPoolDomain}/oauth2/authorize?${params}`
		this.logger.debug(`Redirecting user to Cognito User Pool URL ${userPoolUrl}`)

		let cookies: string[] | undefined
		if (this.csrfProtection) {
			const cookieAttributes = this.createCookieAttributes(undefined, new Date(Date.now() + CSRF_COOKIE_TTL_MS))
			cookies = [
				serializeCookie(`${this.cookieBase}.${PKCE_COOKIE_NAME_SUFFIX}`, csrfTokens.pkce ?? "", cookieAttributes),
				serializeCookie(`${this.cookieBase}.${NONCE_COOKIE_NAME_SUFFIX}`, csrfTokens.nonce ?? "", cookieAttributes),
				serializeCookie(
					`${this.cookieBase}.${NONCE_HMAC_COOKIE_NAME_SUFFIX}`,
					csrfTokens.nonceHmac ?? "",
					cookieAttributes,
				),
			]
		}

		return this.createRedirectResponse(userPoolUrl, cookies)
	}

	/**
	 * Handle Lambda@Edge event:
	 *   * if authentication cookie is present and valid: forward the request
	 *   * if authentication cookie is invalid, but refresh token is present: set cookies with refreshed tokens
	 *   * if ?code=<grant code> is present: set cookies with new tokens
	 *   * else redirect to the Cognito UserPool to authenticate the user
	 * @param  {Object}  event Lambda@Edge event.
	 * @return {Promise} CloudFront response.
	 */
	async handle(event: CloudFrontRequestEvent): Promise<CloudFrontResultResponse | CloudFrontRequest> {
		this.logger.debug({ msg: "Handling Lambda@Edge event", event })

		const { request } = event.Records[0].cf
		const cfDomain = this.getHost(request)
		const requestParams = parse(request.querystring)
		const isLogoutPath =
			this.logoutConfiguration != null && request.uri.startsWith(this.logoutConfiguration.logoutUriPath)

		try {
			const tokens = this.getTokensFromCookie(request.headers.cookie)

			if (isLogoutPath) {
				this.logger.info({ msg: "Revoking tokens", tokens })
				await this.revokeTokens(tokens)
				this.logger.info({ msg: "Revoked tokens. Clearing cookies", tokens })
				return await this.clearCookies(request, cfDomain, tokens)
			}

			try {
				this.logger.debug({ msg: "Verifying token...", tokens })
				// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
				const user = await this.verifyIdToken(tokens.idToken!)
				this.logger.info({ msg: "Forwarding request", path: request.uri, user })
				return request
			} catch (err) {
				this.logger.info({ msg: "Token verification failed", tokens, refreshToken: tokens.refreshToken })
				if (tokens.refreshToken) {
					this.logger.debug({ msg: "Verifying idToken failed, verifying refresh token instead...", tokens, err })
					const redirectUri = this.getCallbackUri(cfDomain, `https://${cfDomain}`)
					return await this.fetchTokensFromRefreshToken(redirectUri, tokens.refreshToken).then(tokens =>
						this.getRedirectResponse(tokens, cfDomain, request.uri),
					)
				} else {
					throw err
				}
			}
		} catch (err) {
			if (isLogoutPath) {
				this.logger.info({ msg: "Clearing cookies", path: cfDomain })
				return this.clearCookies(request, cfDomain)
			}
			this.logger.debug("User isn't authenticated: %s", err)

			const redirectUri = this.getCallbackUri(cfDomain, `https://${cfDomain}`)
			if (requestParams.code) {
				return this.fetchTokensFromCode(redirectUri, requestParams.code as string).then(tokens =>
					this.getRedirectResponse(tokens, cfDomain, this.getRedirectUriFromState(requestParams.state as string)),
				)
			} else {
				return this.getRedirectToCognitoUserPoolResponse(request, redirectUri)
			}
		}
	}

	/**
	 * Check if user is authenticated:
	 *   * if authentication cookie is present and valid: return true
	 *   * else return false
	 * @param  {Object}  event Lambda@Edge event.
	 * @return {Boolean} True if user is authenticated.
	 */
	async isAuthenticated(event: CloudFrontRequestEvent) {
		this.logger.debug({ msg: "Checking if Lambda@Edge event is authenticated", event })

		const { request } = event.Records[0].cf

		try {
			const { idToken } = this.getTokensFromCookie(request.headers.cookie)
			if (!idToken) return false
			this.logger.debug({ msg: "Verifying token...", idToken })
			await this.verifyIdToken(idToken)
			return true
		} catch {
			return false
		}
	}

	/**
	 * If the user is already authenticated, redirect to redirect_uri.
	 * Otherwise initiate the authentication flow.
	 */
	async handleSignIn(event: CloudFrontRequestEvent): Promise<CloudFrontResultResponse> {
		this.logger.debug({ msg: "Handling Lambda@Edge event", event })

		const { request } = event.Records[0].cf
		const requestParams = parse(request.querystring)
		const cfDomain = this.getHost(request)
		const redirectUri = this.getRequestedRedirectUri(cfDomain, requestParams)

		try {
			const tokens = this.getTokensFromCookie(request.headers.cookie)
			this.logger.debug({ msg: "Verifying token...", tokens })
			// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
			const user = await this.verifyIdToken(tokens.idToken!)
			this.logger.info({ msg: "Redirecting user to", path: redirectUri, user })
			return {
				status: "302",
				headers: {
					location: [{ key: "Location", value: redirectUri }],
				},
			}
		} catch (err) {
			this.logger.debug("User isn't authenticated: %s", err)
			return this.getRedirectToCognitoUserPoolResponse(request, this.getCallbackUri(cfDomain, redirectUri))
		}
	}

	/**
	 * Exchange the OAuth authorization code for tokens, validate CSRF if enabled,
	 * and set tokens as cookies.
	 */
	async handleParseAuth(event: CloudFrontRequestEvent): Promise<CloudFrontResultResponse> {
		this.logger.debug({ msg: "Handling Lambda@Edge event", event })

		const { request } = event.Records[0].cf
		const cfDomain = this.getHost(request)
		const requestParams = parse(request.querystring)

		try {
			if (!this.parseAuthPath) {
				throw new Error("parseAuthPath is not set")
			}
			const redirectUri = `https://${cfDomain}/${this.parseAuthPath}`
			if (requestParams.code) {
				if (this.csrfProtection) {
					this.validateCSRFCookies(request)
				}
				const tokens = await this.fetchTokensFromCode(redirectUri, requestParams.code as string)
				const location = this.getRedirectUriFromState(requestParams.state as string)
				return await this.getRedirectResponse(tokens, cfDomain, location)
			} else {
				this.logger.debug({ msg: "Code param not found", requestParams })
				throw new Error("OAuth code parameter not found")
			}
		} catch (err) {
			this.logger.debug({ msg: "Unable to exchange code for tokens", err })
			return {
				status: "400",
				body: String(err),
			}
		}
	}

	/**
	 * Use the refresh token from cookies to get a new set of tokens and set them as cookies.
	 */
	async handleRefreshToken(event: CloudFrontRequestEvent): Promise<CloudFrontResultResponse> {
		this.logger.debug({ msg: "Handling Lambda@Edge event", event })

		const { request } = event.Records[0].cf
		const cfDomain = this.getHost(request)
		const requestParams = parse(request.querystring)
		const redirectUri = this.getRequestedRedirectUri(cfDomain, requestParams)

		try {
			let tokens = this.getTokensFromCookie(request.headers.cookie)
			this.logger.debug({ msg: "Verifying token...", tokens })
			// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
			const user = await this.verifyIdToken(tokens.idToken!)
			this.logger.debug({ msg: "Refreshing tokens...", tokens, user })
			// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
			tokens = await this.fetchTokensFromRefreshToken(redirectUri, tokens.refreshToken!)
			this.logger.debug({ msg: "Refreshed tokens...", tokens, user })
			return await this.getRedirectResponse(tokens, cfDomain, redirectUri)
		} catch (err) {
			this.logger.debug("User isn't authenticated: %s", err)
			return this.getRedirectToCognitoUserPoolResponse(request, this.getCallbackUri(cfDomain, redirectUri))
		}
	}

	/**
	 * Revoke the refresh token and clear all auth cookies. Clears cookies even
	 * if token revocation fails.
	 */
	async handleSignOut(event: CloudFrontRequestEvent): Promise<CloudFrontResultResponse> {
		this.logger.debug({ msg: "Handling Lambda@Edge event", event })

		const { request } = event.Records[0].cf
		const requestParams = parse(request.querystring)
		const cfDomain = this.getHost(request)
		const redirectUri = this.getRequestedRedirectUri(cfDomain, requestParams)

		try {
			const tokens = this.getTokensFromCookie(request.headers.cookie)
			this.logger.info({ msg: "Revoking tokens", tokens })
			await this.revokeTokens(tokens)
			this.logger.info({ msg: "Revoked tokens. Clearing cookies...", tokens })
			return await this.clearCookies(request, cfDomain, tokens)
		} catch (_err) {
			this.logger.info({ msg: "Unable to revoke tokens. Clearing cookies...", path: redirectUri })
			return this.clearCookies(request, cfDomain)
		}
	}
}
