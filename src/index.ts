import { CognitoJwtVerifier } from 'aws-jwt-verify';
import type { CloudFrontRequest, CloudFrontRequestEvent, CloudFrontResultResponse } from 'aws-lambda';
import { parse } from 'querystring';
import {
	CookieAttributes,
	CookieSettingsOverrides,
	CookieType,
	getCookieDomain,
	parseCookies,
	SameSite,
	serializeCookie
} from './util/cookie';
import {
	CSRFTokens,
	generateCSRFTokens,
	NONCE_COOKIE_NAME_SUFFIX,
	NONCE_HMAC_COOKIE_NAME_SUFFIX,
	PKCE_COOKIE_NAME_SUFFIX,
	signNonce,
	urlSafe
} from './util/csrf';
import { CognitoIdTokenPayload } from 'aws-jwt-verify/jwt-model';

type LogLevel = 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';

interface Logger {
	debug(...args: unknown[]): void;
	info(...args: unknown[]): void;
	error(...args: unknown[]): void;
}

function createLogger(level: LogLevel = 'silent'): Logger {
	const levels: Record<LogLevel, number> = {
		trace: 10,
		debug: 20,
		info: 30,
		warn: 40,
		error: 50,
		fatal: 60,
		silent: Infinity,
	};
	const minLevel = levels[level] ?? Infinity;
	const noop = () => {};
	return {
		debug: minLevel <= 20 ? (console.debug.bind(console) as (...args: unknown[]) => void) : noop,
		info: minLevel <= 30 ? (console.info.bind(console) as (...args: unknown[]) => void) : noop,
		error: minLevel <= 50 ? (console.error.bind(console) as (...args: unknown[]) => void) : noop,
	};
}

export interface AuthenticatorParams {
	region: string;
	userPoolId: string;
	userPoolAppId: string;
	userPoolAppSecret?: string;
	userPoolDomain: string;
	cookieExpirationDays?: number;
	disableCookieDomain?: boolean;
	httpOnly?: boolean;
	sameSite?: SameSite;
	logLevel?: LogLevel;
	cookiePath?: string;
	cookieDomain?: string;
	cookieSettingsOverrides?: CookieSettingsOverrides;
	logoutConfiguration?: LogoutConfiguration;
	parseAuthPath?: string;
	csrfProtection?: {
		nonceSigningSecret: string;
	};
}

interface LogoutConfiguration {
	logoutUri: string;
	logoutRedirectUri: string;
}

interface Tokens {
	accessToken?: string;
	idToken?: string;
	refreshToken?: string;
	token_type?: 'Bearer';
	expires_in?: number;
}

const MS_PER_DAY = 864e5;
const CSRF_COOKIE_TTL_MS = 10 * 60 * 1000;
const NO_CACHE_VALUE = 'no-cache, no-store, max-age=0, must-revalidate';
const COGNITO_TOKEN_SCOPES = 'phone email profile openid aws.cognito.signin.user.admin';

export class Authenticator {
	private readonly _region: string;
	private readonly _userPoolId: string;
	private readonly _userPoolClientId: string;
	private readonly _userPoolClientSecret: string | undefined;
	private readonly _userPoolDomain: string;
	private readonly _cookieExpirationDays: number;
	private readonly _disableCookieDomain: boolean;
	private readonly _httpOnly: boolean;
	private readonly _sameSite?: SameSite;
	private readonly _cookieBase: string;
	private readonly _cookiePath?: string;
	private readonly _cookieDomain?: string;
	private readonly _csrfProtection?: {
		nonceSigningSecret: string;
	};
	private readonly _logoutConfiguration?: LogoutConfiguration;
	private readonly _parseAuthPath?: string;
	private readonly _cookieSettingsOverrides?: CookieSettingsOverrides;
	private readonly _logger: Logger;
	private readonly _jwtVerifier;
	private readonly _tokenCache: Map<string, { payload: CognitoIdTokenPayload; expSec: number }>;

	constructor(params: AuthenticatorParams) {
		if (!params) throw new Error('Expected params');
		if (typeof params.region !== 'string') throw new Error('Expected params.region to be a string');
		if (typeof params.userPoolId !== 'string') throw new Error('Expected params.userPoolId to be a string');
		if (typeof params.userPoolAppId !== 'string') throw new Error('Expected params.userPoolAppId to be a string');
		if (typeof params.userPoolDomain !== 'string') throw new Error('Expected params.userPoolDomain to be a string');
		if (params.sameSite && !Object.values(['Strict', 'Lax', 'None']).includes(params.sameSite)) {
			throw new Error('Expected params.sameSite to be Strict, Lax, or None');
		}
		if (params.cookieExpirationDays !== undefined && typeof params.cookieExpirationDays !== 'number') {
			throw new Error('Expected params.cookieExpirationDays to be a number');
		}
		if (params.disableCookieDomain !== undefined && typeof params.disableCookieDomain !== 'boolean') {
			throw new Error('Expected params.disableCookieDomain to be a boolean');
		}
		if (params.cookieDomain !== undefined && typeof params.cookieDomain !== 'string') {
			throw new Error('Expected params.cookieDomain to be a string');
		}
		if (params.httpOnly !== undefined && typeof params.httpOnly !== 'boolean') {
			throw new Error('Expected params.httpOnly to be a boolean');
		}
		if (params.cookiePath !== undefined && typeof params.cookiePath !== 'string') {
			throw new Error('Expected params.cookiePath to be a string');
		}
		if (params.logoutConfiguration?.logoutUri !== undefined) {
			if (typeof params.logoutConfiguration.logoutUri !== 'string' ||
				params.logoutConfiguration.logoutUri === '' ||
				params.logoutConfiguration.logoutUri === '/') {
				throw new Error('Expected params.logoutConfiguration.logoutUri to be a valid string');
			}
		}

		this._region = params.region;
		this._userPoolId = params.userPoolId;
		this._userPoolClientId = params.userPoolAppId;
		this._userPoolClientSecret = params.userPoolAppSecret;
		this._userPoolDomain = params.userPoolDomain;
		this._cookieExpirationDays = params.cookieExpirationDays || 365;
		this._disableCookieDomain =
			'disableCookieDomain' in params && params.disableCookieDomain === true;
		this._cookieDomain = params.cookieDomain;
		this._httpOnly = 'httpOnly' in params && params.httpOnly === true;
		this._sameSite = params.sameSite;
		this._cookieBase = `CognitoIdentityServiceProvider.${params.userPoolAppId}`;
		this._cookiePath = params.cookiePath;
		this._cookieSettingsOverrides = params.cookieSettingsOverrides || {};
		this._logger = createLogger(params.logLevel);
		this._jwtVerifier = CognitoJwtVerifier.create({
			userPoolId: params.userPoolId,
			clientId: params.userPoolAppId,
			tokenUse: 'id',
		});
		this._tokenCache = new Map();
		this._jwtVerifier.hydrate().catch(() => {
			// JWKS will be fetched on first verify() if this fails — no action needed
		});
		this._csrfProtection = params.csrfProtection;
		this._logoutConfiguration = params.logoutConfiguration;
		this._parseAuthPath = (params.parseAuthPath || '').replace(/^\//, '');
	}

	async hydrate(): Promise<void> {
		await this._jwtVerifier.hydrate();
	}

	private async _verifyIdToken(idToken: string) {
		const nowSec = Math.floor(Date.now() / 1000);
		const cached = this._tokenCache.get(idToken);
		if (cached && nowSec < cached.expSec) {
			return cached.payload;
		}
		const payload = await this._jwtVerifier.verify(idToken);
		this._tokenCache.set(idToken, {
			payload,
			expSec: (payload as Record<string, number>).exp ?? nowSec,
		});
		return payload;
	}

	private async _postToTokenEndpoint<T>(
		data: Record<string, string>,
		logCtx: Record<string, unknown>,
	): Promise<T> {
		const authorization = this._getAuthorization();
		const url = `https://${this._userPoolDomain}/oauth2/token`;
		const init: RequestInit = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				...(authorization && { Authorization: `Basic ${authorization}` }),
			},
			body: new URLSearchParams(data).toString(),
		};
		this._logger.debug({ ...logCtx, url });
		try {
			const resp = await fetch(url, init);
			if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
			const json = (await resp.json()) as T;
			this._logger.debug({ ...logCtx, tokens: json });
			return json;
		} catch (err) {
			this._logger.error({ ...logCtx, url });
			throw err;
		}
	}

	/**
	 * Exchange authorization code for tokens.
	 * @param  {String} redirectURI Redirection URI.
	 * @param  {String} code        Authorization code.
	 * @return {Promise} Authenticated user tokens.
	 */
	async _fetchTokensFromCode(
		redirectURI: string,
		code: string,
	): Promise<Tokens> {
		const resp = await this._postToTokenEndpoint<{
			id_token: string;
			access_token: string;
			refresh_token: string;
		}>(
			{
				client_id: this._userPoolClientId,
				code: code,
				grant_type: 'authorization_code',
				redirect_uri: redirectURI,
			},
			{ msg: 'Fetching tokens from grant code...', code },
		);
		return {
			idToken: resp.id_token,
			accessToken: resp.access_token,
			refreshToken: resp.refresh_token,
		};
	}

	/**
	 * Fetch accessTokens from refreshToken.
	 * @param  {String} redirectURI Redirection URI.
	 * @param  {String} refreshToken Refresh token.
	 * @return {Promise<Tokens>} Refreshed user tokens.
	 */
	async _fetchTokensFromRefreshToken(
		redirectURI: string,
		refreshToken: string,
	): Promise<Tokens> {
		const resp = await this._postToTokenEndpoint<{
			id_token: string;
			access_token: string;
		}>(
			{
				client_id: this._userPoolClientId,
				refresh_token: refreshToken,
				grant_type: 'refresh_token',
				redirect_uri: redirectURI,
			},
			{ msg: 'Fetching tokens from refreshToken...', refreshToken },
		);
		return {
			idToken: resp.id_token,
			accessToken: resp.access_token,
		};
	}

	_getAuthorization(): string | undefined {
		return (
			this._userPoolClientSecret &&
			Buffer.from(
				`${this._userPoolClientId}:${this._userPoolClientSecret}`,
			).toString('base64')
		);
	}

	private _getCFDomain(request: CloudFrontRequest): string {
		return request.headers.host[0].value;
	}

	private _getRedirectURI(cfDomain: string, requestParams: ReturnType<typeof parse>): string {
		return (requestParams.redirect_uri as string) || `https://${cfDomain}`;
	}

	private _buildBaseCookieAttributes(domain?: string, expires?: Date): CookieAttributes {
		return {
			domain,
			expires,
			secure: true,
			httpOnly: this._httpOnly,
			sameSite: this._sameSite,
			path: this._cookiePath,
		};
	}

	private _getParseAuthOrFallbackURI(cfDomain: string, fallback: string): string {
		return this._parseAuthPath
			? `https://${cfDomain}/${this._parseAuthPath}`
			: fallback;
	}

	private _buildRedirectResponse(location: string, cookies?: string[]): CloudFrontResultResponse {
		return {
			status: '302',
			headers: {
				location: [{ key: 'Location', value: location }],
				'cache-control': [{ key: 'Cache-Control', value: NO_CACHE_VALUE }],
				pragma: [{ key: 'Pragma', value: 'no-cache' }],
				...(cookies && { 'set-cookie': cookies.map((c) => ({ key: 'Set-Cookie', value: c })) }),
			},
		};
	}

	_validateCSRFCookies(request: CloudFrontRequest) {
		if (!this._csrfProtection) {
			throw new Error(
				'_validateCSRFCookies should not be called if CSRF protection is disabled.',
			);
		}

		const requestParams = parse(request.querystring);
		const requestCookies = request.headers.cookie.flatMap((h) =>
			parseCookies(h.value),
		);
		this._logger.debug({ msg: 'Validating CSRF Cookies', requestCookies });

		const parsedState = JSON.parse(
			Buffer.from(
				urlSafe.parse(requestParams.state as string),
				'base64',
			).toString(),
		) as { nonce?: string };

		const {
			nonce: originalNonce,
			nonceHmac,
			pkce,
		} = this._getCSRFTokensFromCookie(request.headers.cookie);

		if (
			!parsedState.nonce ||
			!originalNonce ||
			parsedState.nonce !== originalNonce
		) {
			if (!originalNonce) {
				throw new Error(
					"Your browser didn't send the nonce cookie along, but it is required for security (prevent CSRF).",
				);
			}
			throw new Error(
				'Nonce mismatch. This can happen if you start multiple authentication attempts in parallel (e.g. in separate tabs)',
			);
		}
		if (!pkce) {
			throw new Error(
				"Your browser didn't send the pkce cookie along, but it is required for security (prevent CSRF).",
			);
		}

		const calculatedHmac = signNonce(
			parsedState.nonce,
			this._csrfProtection.nonceSigningSecret,
		);

		if (calculatedHmac !== nonceHmac) {
			throw new Error(
				`Nonce signature mismatch! Expected ${calculatedHmac} but got ${nonceHmac}`,
			);
		}
	}

	_getOverridenCookieAttributes(
		cookieAttributes: CookieAttributes = {},
		cookieType: CookieType,
	): CookieAttributes {
		const res = { ...cookieAttributes };

		const overrides = this._cookieSettingsOverrides?.[cookieType];
		if (overrides) {
			if (overrides.httpOnly !== undefined) {
				res.httpOnly = overrides.httpOnly;
			}
			if (overrides.sameSite !== undefined) {
				res.sameSite = overrides.sameSite;
			}
			if (overrides.path !== undefined) {
				res.path = overrides.path;
			}
			if (overrides.expirationDays !== undefined) {
				res.expires = new Date(Date.now() + overrides.expirationDays * MS_PER_DAY);
			}
		}
		this._logger.debug({
			msg: 'Cookie settings overriden',
			cookieAttributes,
			cookieType,
			cookieSettingsOverrides: this._cookieSettingsOverrides,
		});
		return res;
	}

	/**
	 * Create a Lambda@Edge redirection response to set the tokens on the user's browser cookies.
	 * @param  {Object} tokens   Cognito User Pool tokens.
	 * @param  {String} domain   Website domain.
	 * @param  {String} path     Relative path to the requested object.
	 * @return Lambda@Edge response.
	 */
	async _getRedirectResponse(
		tokens: Tokens,
		domain: string,
		path: string,
	): Promise<CloudFrontResultResponse> {
		const decoded = await this._verifyIdToken(tokens.idToken as string);
		const username = decoded['cognito:username'];
		const usernameBase = `${this._cookieBase}.${username}`;
		const cookieDomain = getCookieDomain(
			domain,
			this._disableCookieDomain,
			this._cookieDomain,
		);
		const cookieAttributes = this._buildBaseCookieAttributes(
			cookieDomain,
			new Date(Date.now() + this._cookieExpirationDays * MS_PER_DAY),
		);
		const cookies = [
			serializeCookie(
				`${usernameBase}.accessToken`,
				tokens.accessToken as string,
				this._getOverridenCookieAttributes(cookieAttributes, 'accessToken'),
			),
			serializeCookie(
				`${usernameBase}.idToken`,
				tokens.idToken as string,
				this._getOverridenCookieAttributes(cookieAttributes, 'idToken'),
			),
			...(tokens.refreshToken
				? [
						serializeCookie(
							`${usernameBase}.refreshToken`,
							tokens.refreshToken,
							this._getOverridenCookieAttributes(
								cookieAttributes,
								'refreshToken',
							),
						),
					]
				: []),
			serializeCookie(
				`${usernameBase}.tokenScopesString`,
				COGNITO_TOKEN_SCOPES,
				cookieAttributes,
			),
			serializeCookie(
				`${this._cookieBase}.LastAuthUser`,
				username,
				cookieAttributes,
			),
		];

		// Clear CSRF Token Cookies
		if (this._csrfProtection) {
			// Domain attribute is always not set here as CSRF cookies are used
			// exclusively by the CF distribution
			const csrfCookieAttributes = {
				...cookieAttributes,
				domain: undefined,
				expires: new Date(),
			};
			cookies.push(
				serializeCookie(
					`${this._cookieBase}.${PKCE_COOKIE_NAME_SUFFIX}`,
					'',
					csrfCookieAttributes,
				),
				serializeCookie(
					`${this._cookieBase}.${NONCE_COOKIE_NAME_SUFFIX}`,
					'',
					csrfCookieAttributes,
				),
				serializeCookie(
					`${this._cookieBase}.${NONCE_HMAC_COOKIE_NAME_SUFFIX}`,
					'',
					csrfCookieAttributes,
				),
			);
		}

		const locationUrl = 'https://' + domain + (path.startsWith('/') ? '' : '/') + path;
		const response = this._buildRedirectResponse(locationUrl, cookies);

		this._logger.debug({ msg: 'Generated set-cookie response', response });

		return response;
	}

	/**
	 * Extract value of the authentication token from the request cookies.
	 * @param  {Array}  cookieHeaders 'Cookie' request headers.
	 * @return {Tokens} Extracted id token or access token. Null if not found.
	 */
	_getTokensFromCookie(
		cookieHeaders:
			| Array<{ key?: string | undefined; value: string }>
			| undefined,
	): Tokens {
		if (!cookieHeaders) {
			this._logger.debug("Cookies weren't present in the request");
			throw new Error("Cookies weren't present in the request");
		}

		this._logger.debug({
			msg: 'Extracting authentication token from request cookie',
			cookieHeaders,
		});

		const cookies = cookieHeaders.flatMap((h) => parseCookies(h.value));

		const tokenCookieNamePrefix = `${this._cookieBase}.`;
		const idTokenCookieNamePostfix = '.idToken';
		const refreshTokenCookieNamePostfix = '.refreshToken';

		const tokens: Tokens = {};
		for (const { name, value } of cookies) {
			if (
				name.startsWith(tokenCookieNamePrefix) &&
				name.endsWith(idTokenCookieNamePostfix)
			) {
				tokens.idToken = value;
			}
			if (
				name.startsWith(tokenCookieNamePrefix) &&
				name.endsWith(refreshTokenCookieNamePostfix)
			) {
				tokens.refreshToken = value;
			}
		}

		if (!tokens.idToken && !tokens.refreshToken) {
			this._logger.debug(
				'Neither idToken, nor refreshToken was present in request cookies',
			);
			throw new Error(
				'Neither idToken, nor refreshToken was present in request cookies',
			);
		}

		this._logger.debug({ msg: 'Found tokens in cookie', tokens });
		return tokens;
	}

	/**
	 * Extract values of the CSRF tokens from the request cookies.
	 * @param  {Array}  cookieHeaders 'Cookie' request headers.
	 * @return {CSRFTokens} Extracted CSRF Tokens from cookie.
	 */
	_getCSRFTokensFromCookie(
		cookieHeaders:
			| Array<{ key?: string | undefined; value: string }>
			| undefined,
	): CSRFTokens {
		if (!cookieHeaders) {
			this._logger.debug("Cookies weren't present in the request");
			throw new Error("Cookies weren't present in the request");
		}

		this._logger.debug({
			msg: 'Extracting CSRF tokens from request cookie',
			cookieHeaders,
		});

		const cookies = cookieHeaders.flatMap((h) => parseCookies(h.value));
		const csrfTokens = cookies.reduce<CSRFTokens>((tokens, { name, value }) => {
			if (name.startsWith(this._cookieBase)) {
				[
					NONCE_COOKIE_NAME_SUFFIX,
					NONCE_HMAC_COOKIE_NAME_SUFFIX,
					PKCE_COOKIE_NAME_SUFFIX,
				].forEach((key) => {
					if (name.endsWith(`.${key}`)) {
						tokens[key] = value;
					}
				});
			}
			return tokens;
		}, {});

		this._logger.debug({ msg: 'Found CSRF tokens in cookie', csrfTokens });
		return csrfTokens;
	}

	/**
	 * Extracts the redirect uri from the state param. When CSRF protection is
	 * enabled, redirect uri is encoded inside state along with other data. So, it
	 * needs to be base64 decoded. When CSRF is not enabled, state can be used
	 * directly.
	 * @param {string} state
	 * @returns {string}
	 */
	_getRedirectUriFromState(state: string): string {
		if (this._csrfProtection) {
			const parsedState = JSON.parse(
				Buffer.from(urlSafe.parse(state), 'base64').toString(),
			) as { redirect_uri: string; nonce?: string };
			this._logger.debug({
				msg: 'Parsed state param to extract redirect uri',
				parsedState,
			});
			return parsedState.redirect_uri;
		}
		return state;
	}

	async _revokeTokens(tokens: Tokens) {
		const authorization = this._getAuthorization();
		const url = `https://${this._userPoolDomain}/oauth2/revoke`;
		const init: RequestInit = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				...(authorization && { Authorization: `Basic ${authorization}` }),
			},
			body: new URLSearchParams({
				client_id: this._userPoolClientId,
				token: tokens.refreshToken ?? '',
			}).toString(),
		};
		this._logger.debug({
			msg: 'Revoking refreshToken...',
			url,
			refreshToken: tokens.refreshToken,
		});
		try {
			const resp = await fetch(url, init);
			if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
			this._logger.debug({
				msg: 'Revoked refreshToken',
				refreshToken: tokens.refreshToken,
			});
		} catch (err) {
			this._logger.error({
				msg: 'Unable to revoke refreshToken',
				url,
				err: JSON.stringify(err),
			});
			throw err;
		}
	}

	async _clearCookies(
		event: CloudFrontRequestEvent,
		tokens: Tokens = {},
	): Promise<CloudFrontResultResponse> {
		this._logger.info({ msg: 'Clearing cookies...', event, tokens });
		const { request } = event.Records[0].cf;
		const cfDomain = this._getCFDomain(request);
		const requestParams = parse(request.querystring);
		const redirectURI =
			this._logoutConfiguration?.logoutRedirectUri ||
			(requestParams.redirect_uri as string) ||
			`https://${cfDomain}`;

		const cookieDomain = getCookieDomain(
			cfDomain,
			this._disableCookieDomain,
			this._cookieDomain,
		);
		const cookieAttributes = this._buildBaseCookieAttributes(
			cookieDomain,
			new Date(),
		);

		let responseCookies: string[] = [];
		try {
			const decoded = await this._verifyIdToken(tokens.idToken as string);
			const username = decoded['cognito:username'];
			this._logger.info({
				msg: 'Token verified. Clearing cookies...',
				idToken: tokens.idToken,
				username,
			});

			const usernameBase = `${this._cookieBase}.${username}`;
			responseCookies = [
				serializeCookie(`${usernameBase}.accessToken`, '', cookieAttributes),
				serializeCookie(`${usernameBase}.idToken`, '', cookieAttributes),
				...(tokens.refreshToken
					? [
							serializeCookie(
								`${usernameBase}.refreshToken`,
								'',
								cookieAttributes,
							),
						]
					: []),
				serializeCookie(
					`${usernameBase}.tokenScopesString`,
					'',
					cookieAttributes,
				),
				serializeCookie(
					`${this._cookieBase}.LastAuthUser`,
					'',
					cookieAttributes,
				),
			];
		} catch (_err) {
			this._logger.info({
				msg: 'Unable to verify token. Inferring data from request cookies and clearing them...',
				idToken: tokens.idToken,
			});
			const requestCookies = request.headers.cookie.flatMap((h) =>
				parseCookies(h.value),
			);
			for (const { name } of requestCookies) {
				if (name.startsWith(this._cookieBase)) {
					responseCookies.push(serializeCookie(name, '', cookieAttributes));
				}
			}
		}

		const t = encodeURIComponent(redirectURI);

		const logoutUrl = `https://${this._userPoolDomain}/logout?client_id=${this._userPoolClientId}&logout_uri=${t}`;

		const response = this._buildRedirectResponse(logoutUrl, responseCookies);

		this._logger.debug({ msg: 'Generated set-cookie response', response });

		return response;
	}

	/**
	 * Get redirect to cognito userpool response
	 * @param  {CloudFrontRequest}  request The original request
	 * @param  {string}  redirectURI Redirection URI.
	 * @return {CloudFrontResultResponse} Redirect response.
	 */
	_getRedirectToCognitoUserPoolResponse(
		request: CloudFrontRequest,
		redirectURI: string,
	): CloudFrontResultResponse {
		let redirectPath = request.uri;
		if (request.querystring && request.querystring !== '') {
			redirectPath += encodeURIComponent('?' + request.querystring);
		}

		let csrfTokens: CSRFTokens = {};
		let state: string | undefined = redirectPath;
		if (this._csrfProtection) {
			csrfTokens = generateCSRFTokens(
				redirectURI,
				this._csrfProtection.nonceSigningSecret,
			);
			state = csrfTokens.state;
		}

		const params = new URLSearchParams({
			redirect_uri: redirectURI,
			response_type: 'code',
			client_id: this._userPoolClientId,
		});

		if (state) {
			params.append('state', state);
		}

		const userPoolUrl = `https://${this._userPoolDomain}/oauth2/authorize?${params}`;

		this._logger.debug(
			`Redirecting user to Cognito User Pool URL ${userPoolUrl}`,
		);

		let cookies: string[] | undefined;
		if (this._csrfProtection) {
			const cookieAttributes = this._buildBaseCookieAttributes(
				undefined,
				new Date(Date.now() + CSRF_COOKIE_TTL_MS),
			);
			cookies = [
				serializeCookie(
					`${this._cookieBase}.${PKCE_COOKIE_NAME_SUFFIX}`,
					csrfTokens.pkce || '',
					cookieAttributes,
				),
				serializeCookie(
					`${this._cookieBase}.${NONCE_COOKIE_NAME_SUFFIX}`,
					csrfTokens.nonce || '',
					cookieAttributes,
				),
				serializeCookie(
					`${this._cookieBase}.${NONCE_HMAC_COOKIE_NAME_SUFFIX}`,
					csrfTokens.nonceHmac || '',
					cookieAttributes,
				),
			];
		}

		return this._buildRedirectResponse(userPoolUrl, cookies);
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
	async handle(
		event: CloudFrontRequestEvent,
	): Promise<CloudFrontResultResponse | CloudFrontRequest> {
		this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

		const { request } = event.Records[0].cf;
		const cfDomain = this._getCFDomain(request);
		const redirectURI = this._getParseAuthOrFallbackURI(cfDomain, `https://${cfDomain}`);

		try {
			const tokens = this._getTokensFromCookie(request.headers.cookie);
			if (
				this._logoutConfiguration &&
				request.uri.startsWith(this._logoutConfiguration.logoutUri)
			) {
				this._logger.info({ msg: 'Revoking tokens', tokens });
				await this._revokeTokens(tokens);

				this._logger.info({ msg: 'Revoked tokens. Clearing cookies', tokens });
				return await this._clearCookies(event, tokens);
			}
			try {
				this._logger.debug({ msg: 'Verifying token...', tokens });
				const user = await this._verifyIdToken(tokens.idToken as string);
				this._logger.info({
					msg: 'Forwarding request',
					path: request.uri,
					user,
				});
				return request;
			} catch (err) {
				this._logger.info({
					msg: 'Token verification failed',
					tokens,
					refreshToken: tokens.refreshToken,
				});
				if (tokens.refreshToken) {
					this._logger.debug({
						msg: 'Verifying idToken failed, verifying refresh token instead...',
						tokens,
						err,
					});
					return await this._fetchTokensFromRefreshToken(
						redirectURI,
						tokens.refreshToken,
					).then((tokens) =>
						this._getRedirectResponse(tokens, cfDomain, request.uri),
					);
				} else {
					throw err;
				}
			}
		} catch (err) {
			if (
				this._logoutConfiguration &&
				request.uri.startsWith(this._logoutConfiguration.logoutUri)
			) {
				this._logger.info({ msg: 'Clearing cookies', path: cfDomain });
				return this._clearCookies(event);
			}
			this._logger.debug("User isn't authenticated: %s", err);

			const requestParams = parse(request.querystring);
			if (requestParams.code) {
				return this._fetchTokensFromCode(
					redirectURI,
					requestParams.code as string,
				).then((tokens) =>
					this._getRedirectResponse(
						tokens,
						cfDomain,
						this._getRedirectUriFromState(requestParams.state as string),
					),
				);
			} else {
				return this._getRedirectToCognitoUserPoolResponse(request, redirectURI);
			}
		}
	}

	/**
	 *
	 * 1. If the token cookies are present in the request, send users to the redirect_uri
	 * 2. If cookies are not present, initiate the authentication flow
	 *
	 * @param event Event that triggers this Lambda function
	 * @returns Lambda response
	 */
	async handleSignIn(
		event: CloudFrontRequestEvent,
	): Promise<CloudFrontResultResponse> {
		this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

		const { request } = event.Records[0].cf;
		const requestParams = parse(request.querystring);
		const cfDomain = this._getCFDomain(request);
		const redirectURI = this._getRedirectURI(cfDomain, requestParams);

		try {
			const tokens = this._getTokensFromCookie(request.headers.cookie);

			this._logger.debug({ msg: 'Verifying token...', tokens });
			const user = await this._verifyIdToken(tokens.idToken as string);

			this._logger.info({
				msg: 'Redirecting user to',
				path: redirectURI,
				user,
			});
			return {
				status: '302',
				headers: {
					location: [
						{
							key: 'Location',
							value: redirectURI,
						},
					],
				},
			};
		} catch (err) {
			this._logger.debug("User isn't authenticated: %s", err);
			return this._getRedirectToCognitoUserPoolResponse(
				request,
				this._getParseAuthOrFallbackURI(cfDomain, redirectURI),
			);
		}
	}

	/**
	 *
	 * Handler that performs OAuth token exchange -- exchanges the authorization
	 * code obtained from the query parameter from server for tokens -- and sets
	 * tokens as cookies. This is done after performing CSRF checks, by verifying
	 * that the information encoded in the state query parameter is related to the
	 * one stored in the cookies.
	 *
	 * @param event Event that triggers this Lambda function
	 * @returns Lambda response
	 */
	async handleParseAuth(
		event: CloudFrontRequestEvent,
	): Promise<CloudFrontResultResponse> {
		this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

		const { request } = event.Records[0].cf;
		const cfDomain = this._getCFDomain(request);
		const requestParams = parse(request.querystring);

		try {
			if (!this._parseAuthPath) {
				throw new Error('parseAuthPath is not set');
			}
			const redirectURI = `https://${cfDomain}/${this._parseAuthPath}`;
			if (requestParams.code) {
				if (this._csrfProtection) {
					this._validateCSRFCookies(request);
				}
				const tokens = await this._fetchTokensFromCode(
					redirectURI,
					requestParams.code as string,
				);
				const location = this._getRedirectUriFromState(
					requestParams.state as string,
				);

				return await this._getRedirectResponse(tokens, cfDomain, location);
			} else {
				this._logger.debug({ msg: 'Code param not found', requestParams });
				throw new Error('OAuth code parameter not found');
			}
		} catch (err) {
			this._logger.debug({ msg: 'Unable to exchange code for tokens', err });
			return {
				status: '400',
				body: String(err),
			};
		}
	}

	/**
	 *
	 * Uses the refreshToken present in the cookies to get a new set of tokens
	 * from the authorization server. After fetching the tokens, they are sent
	 * back to the client as cookies.
	 *
	 * @param event Event that triggers this Lambda function
	 * @returns Lambda response
	 */
	async handleRefreshToken(
		event: CloudFrontRequestEvent,
	): Promise<CloudFrontResultResponse> {
		this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

		const { request } = event.Records[0].cf;
		const cfDomain = this._getCFDomain(request);
		const requestParams = parse(request.querystring);
		const redirectURI = this._getRedirectURI(cfDomain, requestParams);

		try {
			let tokens = this._getTokensFromCookie(request.headers.cookie);

			this._logger.debug({ msg: 'Verifying token...', tokens });
			const user = await this._verifyIdToken(tokens.idToken as string);

			this._logger.debug({ msg: 'Refreshing tokens...', tokens, user });
			tokens = await this._fetchTokensFromRefreshToken(
				redirectURI,
				tokens.refreshToken as string,
			);

			this._logger.debug({ msg: 'Refreshed tokens...', tokens, user });
			return await this._getRedirectResponse(tokens, cfDomain, redirectURI);
		} catch (err) {
			this._logger.debug("User isn't authenticated: %s", err);
			return this._getRedirectToCognitoUserPoolResponse(
				request,
				this._getParseAuthOrFallbackURI(cfDomain, redirectURI),
			);
		}
	}

	/**
	 *
	 * Revokes the refreshToken (which also invalidates the accessToken obtained
	 * using that refreshToken) and clears the cookies. Even if the revoke
	 * operation fails, clear cookies based on the cookie names present in the
	 * request headers.
	 *
	 * @param event Event that triggers this Lambda function
	 * @returns Lambda response
	 */
	async handleSignOut(
		event: CloudFrontRequestEvent,
	): Promise<CloudFrontResultResponse> {
		this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

		const { request } = event.Records[0].cf;
		const requestParams = parse(request.querystring);
		const cfDomain = this._getCFDomain(request);
		const redirectURI = this._getRedirectURI(cfDomain, requestParams);

		try {
			const tokens = this._getTokensFromCookie(request.headers.cookie);

			this._logger.info({ msg: 'Revoking tokens', tokens });
			await this._revokeTokens(tokens);

			this._logger.info({ msg: 'Revoked tokens. Clearing cookies...', tokens });
			return await this._clearCookies(event, tokens);
		} catch (_err) {
			this._logger.info({
				msg: 'Unable to revoke tokens. Clearing cookies...',
				path: redirectURI,
			});
			return this._clearCookies(event);
		}
	}
}
