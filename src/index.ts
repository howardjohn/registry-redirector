/**
 * OCI Image Registry Redirector
 * 
 * Redirects/proxies Docker/OCI registry requests to a target registry.
 * Complies with OCI Distribution Specification.
 * 
 * Supported endpoints:
 * - GET /v2/ - API version check
 * - GET /v2/<name>/manifests/<reference> - Manifest requests (proxied to handle auth)
 * - GET /v2/<name>/blobs/<digest> - Blob requests (proxied when auth present, redirected otherwise)
 * - GET /v2/<name>/tags/list - Tags list (proxied to handle auth)
 * - GET /v2/auth - Token endpoint for authentication (proxied to target registry)
 */

interface Env {
	TARGET_REGISTRY: string;
}

/**
 * Parse WWW-Authenticate header
 * Format: Bearer realm="https://auth.example.com/token",service="registry.example.com"
 */
function parseAuthenticate(authenticateStr: string): { realm: string; service: string } {
	// Match strings after =" and before "
	const re = /(?<=\=")(?:\\.|[^"\\])*(?=")/g;
	const matches = authenticateStr.match(re);
	if (matches == null || matches.length < 2) {
		throw new Error(`invalid Www-Authenticate Header: ${authenticateStr}`);
	}
	return {
		realm: matches[0],
		service: matches[1],
	};
}

/**
 * Return 401 response with rewritten WWW-Authenticate header
 */
function responseUnauthorized(url: URL): Response {
	const headers = new Headers();
	const protocol = url.protocol === 'http' ? 'http' : 'https';
	// Use url.host (includes port) for realm, url.hostname for service
	const realmHost = url.host; // Includes port if present
	const serviceHost = url.hostname; // Just the hostname
	headers.set(
		'Www-Authenticate',
		`Bearer realm="${protocol}://${realmHost}/v2/auth",service="${serviceHost}"`
	);
	return new Response(JSON.stringify({ message: 'UNAUTHORIZED' }), {
		status: 401,
		headers: headers,
	});
}

/**
 * Fetch token from upstream registry
 */
async function fetchToken(
	wwwAuthenticate: { realm: string; service: string },
	scope: string | null,
	authorization: string | null
): Promise<Response> {
	const url = new URL(wwwAuthenticate.realm);
	if (wwwAuthenticate.service.length) {
		url.searchParams.set('service', wwwAuthenticate.service);
	}
	if (scope) {
		url.searchParams.set('scope', scope);
	}

	const headers = new Headers();
	if (authorization) {
		headers.set('Authorization', authorization);
	}

	return await fetch(url.toString(), { method: 'GET', headers: headers });
}


export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		// Validate required configuration
		if (!env.TARGET_REGISTRY) {
			return new Response(
				JSON.stringify({ error: 'TARGET_REGISTRY environment variable is required' }),
				{ status: 500, headers: { 'Content-Type': 'application/json' } }
			);
		}

		const url = new URL(request.url);
		const method = request.method;
		const pathname = url.pathname;
		const targetRegistry = env.TARGET_REGISTRY;
		const authorization = request.headers.get('Authorization');

		// Redirect root to /v2/
		if (pathname === '/') {
			return Response.redirect(url.protocol + '//' + url.host + '/v2/', 301);
		}

		// Handle API version check: /v2/
		if (pathname === '/v2/' || pathname === '/v2') {
			const upstreamUrl = `https://${targetRegistry}/v2/`;
			const headers = new Headers();
			if (authorization) {
				headers.set('Authorization', authorization);
			}

			const resp = await fetch(upstreamUrl, {
				method: 'GET',
				headers: headers,
				redirect: 'follow',
			});

			// If upstream requires auth, return 401 with our auth endpoint
			if (resp.status === 401) {
				return responseUnauthorized(url);
			}

			return resp;
		}

		// Handle token endpoint: /v2/auth
		if (pathname === '/v2/auth') {
			// First check if upstream requires auth
			const upstreamUrl = `https://${targetRegistry}/v2/`;
			const resp = await fetch(upstreamUrl, {
				method: 'GET',
				redirect: 'follow',
			});

			if (resp.status !== 401) {
				return resp;
			}

			const authenticateStr = resp.headers.get('WWW-Authenticate');
			if (authenticateStr === null) {
				return resp;
			}

			const wwwAuthenticate = parseAuthenticate(authenticateStr);
			const scope = url.searchParams.get('scope');

			return await fetchToken(wwwAuthenticate, scope, authorization);
		}

		// If request has authentication, we must proxy (auth token is for our domain, not upstream)
		// Otherwise, we can redirect for better performance
		if (authorization) {
			const upstreamUrl = `https://${targetRegistry}${pathname}${url.search}`;
			const newReq = new Request(upstreamUrl, {
				method: request.method,
				headers: request.headers,
				redirect: 'follow',
			});

			const resp = await fetch(newReq);

			// If upstream requires auth, return 401 with our auth endpoint
			if (resp.status === 401) {
				return responseUnauthorized(url);
			}

			return resp;
		} else {
			// No auth - safe to redirect
			const redirectUrl = `https://${targetRegistry}${pathname}${url.search}`;
			return Response.redirect(redirectUrl, 307);
		}
	},
} satisfies ExportedHandler<Env>;
