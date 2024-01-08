/*
 * SPDX-FileCopyrightText: syuilo and other misskey contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { fileURLToPath } from 'node:url';
import { Inject, Injectable, OnApplicationShutdown } from '@nestjs/common';
import oauth2orize, { type OAuth2, AuthorizationError, ValidateFunctionArity2, OAuth2Req, MiddlewareRequest } from 'oauth2orize';
import oauth2Pkce from 'oauth2orize-pkce';
import fastifyCors from '@fastify/cors';
import fastifyView from '@fastify/view';
import pug from 'pug';
import bodyParser from 'body-parser';
import fastifyExpress from '@fastify/express';
import { verifyChallenge } from 'pkce-challenge';
import { mf2 } from 'microformats-parser';
import { permissions as kinds } from 'misskey-js';
import { secureRndstr } from '@/misc/secure-rndstr.js';
import { HttpRequestService } from '@/core/HttpRequestService.js';
import type { Config } from '@/config.js';
import { DI } from '@/di-symbols.js';
import { bindThis } from '@/decorators.js';
import type { AccessTokensRepository, UsersRepository } from '@/models/_.js';
import { IdService } from '@/core/IdService.js';
import { CacheService } from '@/core/CacheService.js';
import type { MiLocalUser } from '@/models/User.js';
import { RedisKVCache } from '@/misc/cache.js';
import { LoggerService } from '@/core/LoggerService.js';
import Logger from '@/logger.js';
import type { ServerResponse } from 'node:http';
import type { FastifyInstance } from 'fastify';
import { Redis } from 'ioredis';

// TODO: Consider migrating to @node-oauth/oauth2-server once
// https://github.com/node-oauth/node-oauth2-server/issues/180 is figured out.
// Upstream the various validations and RFC9207 implementation in that case.

interface ClientInformation {
	id: string;
	redirectUri: string;
}

interface GrantCode {
	clientId: string;
	userId: string;
	redirectUri: string;
	codeChallenge: string;
	scopes: string[];

	// fields to prevent multiple code use
	grantedToken?: string;
	revoked?: boolean;
	used?: boolean;
}

type OmitFirstElement<T extends unknown[]> = T extends [unknown, ...(infer R)]
	? R
	: [];

interface OAuthParsedRequest extends OAuth2Req {
	codeChallenge: string;
	codeChallengeMethod: string;
}

interface OAuthHttpResponse extends ServerResponse {
	redirect(location: string): void;
}

interface OAuth2DecisionRequest extends MiddlewareRequest {
	body: {
		transaction_id: string;
		cancel: boolean;
		login_token: string;
	}
}

function getQueryMode(issuerUrl: string): oauth2orize.grant.Options['modes'] {
	return {
		query: (txn, res, params): void => {
			// https://datatracker.ietf.org/doc/html/rfc9207#name-response-parameter-iss
			// "In authorization responses to the client, including error responses,
			// an authorization server supporting this specification MUST indicate its
			// identity by including the iss parameter in the response."
			params.iss = issuerUrl;

			const parsed = new URL(txn.redirectURI);
			for (const [key, value] of Object.entries(params)) {
				parsed.searchParams.append(key, value as string);
			}

			return (res as OAuthHttpResponse).redirect(parsed.toString());
		},
	};
}

/**
 * Maps the transaction ID and the oauth/authorize parameters.
 *
 * Flow:
 * 1. oauth/authorize endpoint will call store() to store the parameters
 *    and puts the generated transaction ID to the dialog page
 * 2. oauth/decision will call load() to retrieve the parameters and then remove()
 */
class OAuth2Store {
	#cache: RedisKVCache<OAuth2 | undefined>;

	constructor(redisClient: Redis) {
		this.#cache = new RedisKVCache<OAuth2 | undefined>(
			redisClient,
			'OAuth2Store',
			{
				lifetime: 1000 * 60 * 60 * 1, // 1h
				memoryCacheLifetime: 1000 * 60 * 5, // 5m
				fetcher: async () => undefined,
				toRedisConverter: (value) => JSON.stringify(value),
				fromRedisConverter: (value) => JSON.parse(value),
			},
		);
	}

	@bindThis
	public dispose(): void {
		this.#cache.dispose();
	}

	async load(req: OAuth2DecisionRequest, cb: (err: Error | null, txn?: OAuth2) => void): Promise<void> {
		const { transaction_id } = req.body;
		if (!transaction_id) {
			cb(new AuthorizationError('Missing transaction ID', 'invalid_request'));
			return;
		}
		const loaded = await this.#cache.get(transaction_id);
		if (!loaded) {
			cb(new AuthorizationError('Invalid or expired transaction ID', 'access_denied'));
			return;
		}
		cb(null, loaded);
	}

	store(req: OAuth2DecisionRequest, oauth2: OAuth2, cb: (err: Error | null, transactionID?: string) => void): void {
		const transactionId = secureRndstr(128);
		this.#cache.set(transactionId, oauth2);
		cb(null, transactionId);
	}

	remove(req: OAuth2DecisionRequest, tid: string, cb: () => void): void {
		this.#cache.delete(tid);
		cb();
	}
}

@Injectable()
export class OAuth2ProviderService implements OnApplicationShutdown {
	store: OAuth2Store;
	#server: oauth2orize.OAuth2Server;
	#logger: Logger;

	private grantCodeCache: RedisKVCache<GrantCode | undefined>;

	constructor(
		@Inject(DI.config)
		private config: Config,
		private httpRequestService: HttpRequestService,
		@Inject(DI.accessTokensRepository)
		private accessTokensRepository: AccessTokensRepository,
		idService: IdService,
		@Inject(DI.usersRepository)
		private usersRepository: UsersRepository,
		private cacheService: CacheService,
		loggerService: LoggerService,
		@Inject(DI.redis)
		redisClient: Redis,
	) {
		this.store = new OAuth2Store(redisClient);
		this.#server = oauth2orize.createServer({ store: this.store });
		this.#logger = loggerService.getLogger('oauth');

		this.grantCodeCache = new RedisKVCache<GrantCode | undefined>(
			redisClient,
			'OAuth2ProviderServiceGrantCode',
			{
				lifetime: 1000 * 60 * 60 * 1, // 1h
				memoryCacheLifetime: 1000 * 60 * 5, // 5m
				fetcher: async () => undefined,
				toRedisConverter: (value) => JSON.stringify(value),
				fromRedisConverter: (value) => JSON.parse(value),
			}
		);

		// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
		// "Authorization servers MUST support PKCE [RFC7636]."
		this.#server.grant(oauth2Pkce.extensions());
		this.#server.grant(oauth2orize.grant.code({
			modes: getQueryMode(config.url),
		}, (client, redirectUri, token, ares, areq, locals, done) => {
			(async (): Promise<OmitFirstElement<Parameters<typeof done>>> => {
				this.#logger.info(`Checking the user before sending authorization code to ${client.id}`);

				if (!token) {
					throw new AuthorizationError('No user', 'invalid_request');
				}
				const user = await this.cacheService.localUserByNativeTokenCache.fetch(token,
					() => this.usersRepository.findOneBy({ token }) as Promise<MiLocalUser | null>);
				if (!user) {
					throw new AuthorizationError('No such user', 'invalid_request');
				}

				this.#logger.info(`Sending authorization code on behalf of user ${user.id} to ${client.id} through ${redirectUri}, with scope: [${areq.scope}]`);

				const code = secureRndstr(128);
				this.grantCodeCache.set(code, {
					clientId: client.id,
					userId: user.id,
					redirectUri,
					codeChallenge: (areq as OAuthParsedRequest).codeChallenge,
					scopes: areq.scope,
				});
				return [code];
			})().then(args => done(null, ...args), err => done(err));
		}));
		this.#server.exchange(oauth2orize.exchange.authorizationCode((client, code, redirectUri, body, authInfo, done) => {
			(async (): Promise<OmitFirstElement<Parameters<typeof done>> | undefined> => {
				this.#logger.info('Checking the received authorization code for the exchange');
				const granted = await this.grantCodeCache.get(code);
				if (!granted) {
					return;
				}

				// https://datatracker.ietf.org/doc/html/rfc6749.html#section-4.1.2
				// "If an authorization code is used more than once, the authorization server
				// MUST deny the request and SHOULD revoke (when possible) all tokens
				// previously issued based on that authorization code."
				if (granted.used) {
					this.#logger.info(`Detected multiple code use from ${granted.clientId} for user ${granted.userId}. Revoking the code.`);
					this.grantCodeCache.delete(code);
					granted.revoked = true;
					if (granted.grantedToken) {
						await accessTokensRepository.delete({ token: granted.grantedToken });
					}
					return;
				}
				granted.used = true;

				// https://datatracker.ietf.org/doc/html/rfc6749.html#section-4.1.3
				if (body.client_id !== granted.clientId) return;
				if (redirectUri !== granted.redirectUri) return;

				// https://datatracker.ietf.org/doc/html/rfc7636.html#section-4.6
				if (!body.code_verifier) return;
				if (!(await verifyChallenge(body.code_verifier as string, granted.codeChallenge))) return;

				const accessToken = secureRndstr(128);
				const now = new Date();

				// NOTE: we don't have a setup for automatic token expiration
				await accessTokensRepository.insert({
					id: idService.gen(now.getTime()),
					lastUsedAt: now,
					userId: granted.userId,
					token: accessToken,
					hash: accessToken,
					name: granted.clientId,
					permission: granted.scopes,
				});

				if (granted.revoked) {
					this.#logger.info('Canceling the token as the authorization code was revoked in parallel during the process.');
					await accessTokensRepository.delete({ token: accessToken });
					return;
				}

				granted.grantedToken = accessToken;
				this.#logger.info(`Generated access token for ${granted.clientId} for user ${granted.userId}, with scope: [${granted.scopes}]`);

				return [accessToken, undefined, { scope: granted.scopes.join(' ') }];
			})().then(args => done(null, ...args ?? []), err => done(err));
		}));
	}

	@bindThis
	public dispose(): void {
		this.store.dispose();
		this.grantCodeCache.dispose();
	}

	@bindThis
	public onApplicationShutdown(signal?: string | undefined) {
		this.dispose();
	}

	// https://datatracker.ietf.org/doc/html/rfc8414.html
	// https://indieauth.spec.indieweb.org/#indieauth-server-metadata
	public generateRFC8414() {
		return {
			issuer: this.config.url,
			authorization_endpoint: new URL('/oauth/authorize', this.config.url),
			token_endpoint: new URL('/oauth/token', this.config.url),
			scopes_supported: kinds,
			response_types_supported: ['code'],
			grant_types_supported: ['authorization_code'],
			service_documentation: 'https://misskey-hub.net',
			code_challenge_methods_supported: ['S256'],
			authorization_response_iss_parameter_supported: true,
		};
	}

	@bindThis
	public async createServer(fastify: FastifyInstance): Promise<void> {
		fastify.get('/authorize', async (request, reply) => {
			const oauth2 = (request.raw as MiddlewareRequest).oauth2;
			if (!oauth2) {
				throw new Error('Unexpected lack of authorization information');
			}

			this.#logger.info(`Rendering authorization page for "${oauth2.client.name}"`);

			reply.header('Cache-Control', 'no-store');
			return await reply.view('oauth', {
				transactionId: oauth2.transactionID,
				clientName: oauth2.client.name,
				scope: oauth2.req.scope.join(' '),
			});
		});
		fastify.post('/decision', async () => { });

		fastify.register(fastifyView, {
			root: fileURLToPath(new URL('../web/views', import.meta.url)),
			engine: { pug },
			defaultContext: {
				version: this.config.version,
				config: this.config,
			},
		});

		await fastify.register(fastifyExpress);
		fastify.use('/authorize', this.#server.authorize(((areq, done) => {
			(async (): Promise<Parameters<typeof done>> => {
				// This should return client/redirectURI AND the error, or
				// the handler can't send error to the redirection URI

				const { codeChallenge, codeChallengeMethod, clientID, redirectURI, scope } = areq as OAuthParsedRequest;

				this.#logger.info(`Validating authorization parameters, with client_id: ${clientID}, redirect_uri: ${redirectURI}, scope: ${scope}`);

				// Find client information from the remote.
				const clientInfo: ClientInformation = { id: clientID, redirectUri: redirectURI };

				try {
					const scopes = [...new Set(scope)].filter(s => (<readonly string[]>kinds).includes(s));
					if (!scopes.length) {
						throw new AuthorizationError('`scope` parameter has no known scope', 'invalid_scope');
					}
					areq.scope = scopes;

					// Require PKCE parameters.
					// Recommended by https://indieauth.spec.indieweb.org/#authorization-request, but also prevents downgrade attack:
					// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#name-pkce-downgrade-attack
					if (typeof codeChallenge !== 'string') {
						throw new AuthorizationError('`code_challenge` parameter is required', 'invalid_request');
					}
					if (codeChallengeMethod !== 'S256') {
						throw new AuthorizationError('`code_challenge_method` parameter must be set as S256', 'invalid_request');
					}
				} catch (err) {
					return [err as Error, clientInfo, redirectURI];
				}

				return [null, clientInfo, redirectURI];
			})().then(args => done(...args), err => done(err));
		}) as ValidateFunctionArity2));
		fastify.use('/authorize', this.#server.errorHandler({
			mode: 'indirect',
			modes: getQueryMode(this.config.url),
		}));
		fastify.use('/authorize', this.#server.errorHandler());

		fastify.use('/decision', bodyParser.urlencoded({ extended: false }));
		fastify.use('/decision', this.#server.decision((req, done) => {
			const { body } = req as OAuth2DecisionRequest;
			this.#logger.info(`Received the decision. Cancel: ${!!body.cancel}`);
			req.user = body.login_token;
			done(null, undefined);
		}));
		fastify.use('/decision', this.#server.errorHandler());

		fastify.get('/userinfo', async (request, reply) => {
			const token = request.headers.authorization?.startsWith('Bearer ') ? request.headers.authorization.slice(7) : undefined;
			if (token != null) {
				const accessToken = await this.accessTokensRepository.findOneBy({ token });
				if (accessToken != null) {
					this.accessTokensRepository.update(accessToken.id, { lastUsedAt: new Date() });

					const user = await this.cacheService.localUserByIdCache.fetch(
						accessToken.userId,
						() => this.usersRepository.findOneBy({ id: accessToken.userId }) as Promise<MiLocalUser>,
					);
					const profile = await this.cacheService.userProfileCache.fetch(user.id);

					reply.send({
						sub: user.id,
						preferred_username: user.name ?? user.username,
						email: profile.email,
						picture: user.avatarUrl,
					});
					return;
				}
			}

			reply.code(401);
			reply.send({
				error: {
					message: 'Unauthorized.',
					code: 'UNAUTHORIZED',
					id: 'f3034c73-8b51-4a69-85f8-423fb0bb2460',
					kind: 'client',
				}
			});
		})
		fastify.use('/userinfo', this.#server.errorHandler());

		// Return 404 for any unknown paths under /oauth so that clients can know
		// whether a certain endpoint is supported or not.
		fastify.all('/*', async (_request, reply) => {
			reply.code(404);
			reply.send({
				error: {
					message: 'Unknown OAuth endpoint.',
					code: 'UNKNOWN_OAUTH_ENDPOINT',
					id: 'aa49e620-26cb-4e28-aad6-8cbcb58db147',
					kind: 'client',
				},
			});
		});
	}

	@bindThis
	public async createTokenServer(fastify: FastifyInstance): Promise<void> {
		fastify.register(fastifyCors);
		fastify.post('', async () => { });

		await fastify.register(fastifyExpress);
		// Clients may use JSON or urlencoded
		fastify.use('', bodyParser.urlencoded({ extended: false }));
		fastify.use('', bodyParser.json({ strict: true }));
		fastify.use('', this.#server.token());
		fastify.use('', this.#server.errorHandler());
	}
}
