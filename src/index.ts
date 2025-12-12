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
	TARGET_REGISTRIES: TargetRegistries;
	IMAGE_PULLS: AnalyticsEngineDataset;
}

type RegistryMapping = {
	[repo: string]: string;
	base: string;
};

type TargetRegistries = {
	[domain: string]: RegistryMapping;
};

/**
 * Get registry configuration based on Host header
 * Falls back to '*' if no match is found
 */
function getRegistryConfig(host: string, registries: TargetRegistries): RegistryMapping {
	// Try exact match first
	if (registries[host]) {
		return registries[host];
	}
	// Fallback to wildcard
	if (registries['*']) {
		return registries['*'];
	}
	// If no wildcard, throw error
	throw new Error('No registry configuration found for host and no wildcard (*) fallback configured');
}

/**
 * Build upstream URL with optional repo prefix
 * If repo is specified, it's prepended to the path
 * Example: base="ghcr.io", repo="agentgateway", path="/v2/myimage/manifests/latest"
 *          -> "https://ghcr.io/v2/agentgateway/myimage/manifests/latest"
 */
function buildUpstreamUrl(config: RegistryMapping, pathname: string, search: string = ''): string {
	const base = config.base;
	let path = pathname;
	
	// If repo is specified and path starts with /v2, prepend repo
	if (config.repo && pathname.startsWith('/v2')) {
		if (pathname === '/v2' || pathname === '/v2/') {
			// For /v2 or /v2/, use the original path
			path = pathname;
		} else {
			// For /v2/..., replace /v2/ with /v2/{repo}/
			path = `/v2/${config.repo}${pathname.slice(3)}`; // slice(3) removes '/v2'
		}
	}
	
	return `https://${base}${path}${search}`;
}

function getMapping(config: RegistryMapping, repo: string): string {
	const spl = repo.split('/', 2);
	const base: string = spl[0];
	if (config.mappings[base]) {
		if (spl.length > 1) {
			return config.mappings[base] + "/" + spl[1];
		}
		return config.mappings[base];
	}
	return repo;
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

/**
 * Parse image information from OCI registry pathname
 * Examples:
 *   /v2/myorg/myimage/manifests/latest -> { image: "myorg/myimage", reference: "latest", type: "manifest" }
 *   /v2/myorg/myimage/blobs/sha256:abc -> { image: "myorg/myimage", reference: "sha256:abc", type: "blob" }
 *   /v2/myorg/myimage/tags/list -> { image: "myorg/myimage", reference: null, type: "tags" }
 */
function parseImagePath(pathname: string): { image: string; reference: string | null; type: 'manifest' | 'blob' | 'tags' | null } | null {
	// Match /v2/<image>/manifests/<reference>
	const manifestMatch = pathname.match(/^\/v2\/(.+)\/manifests\/(.+)$/);
	if (manifestMatch) {
		return {
			image: manifestMatch[1],
			reference: manifestMatch[2],
			type: 'manifest',
		};
	}

	// Match /v2/<image>/blobs/<digest>
	const blobMatch = pathname.match(/^\/v2\/(.+)\/blobs\/(.+)$/);
	if (blobMatch) {
		return {
			image: blobMatch[1],
			reference: blobMatch[2],
			type: 'blob',
		};
	}

	// Match /v2/<image>/tags/list
	const tagsMatch = pathname.match(/^\/v2\/(.+)\/tags\/list$/);
	if (tagsMatch) {
		return {
			image: tagsMatch[1],
			reference: null,
			type: 'tags',
		};
	}

	return null;
}

/**
 * Track image pull event in Analytics Engine
 */
function trackImagePull(
	analytics: AnalyticsEngineDataset,
	imageInfo: { image: string; reference: string | null; type: 'manifest' | 'blob' | 'tags' },
	request: Request,
	cf?: IncomingRequestCfProperties
): void {
	try {
		const userAgent = request.headers.get('User-Agent') || 'unknown';
		// Get client IP from CF properties or use 'unknown'
		const ip: string = request.headers.get('cf-connecting-ip') || 'unknown';
		const region = cf?.region || 'unknown';
		const country = cf?.country || 'unknown';
		const timestamp = Date.now();

		// Write data point to Analytics Engine
		// blobs: [image_name, reference/tag/digest, request_type, user_agent, client_ip]
		// doubles: [timestamp]
		// indexes: [image_name, request_type] for efficient querying
		const data = {
			blobs: [
				imageInfo.image,
				imageInfo.reference || null,
				imageInfo.type,
				userAgent,
				ip,
				region,
				country,
			],
			doubles: [timestamp],
			indexes: [imageInfo.image],
		};
		analytics.writeDataPoint(data);
	} catch (error) {
		// Silently fail analytics tracking to not break the request
		// In production, you might want to log this
		console.error('Failed to track image pull:', error);
	}
}


export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		// Validate required configuration
		if (!env.TARGET_REGISTRIES || typeof env.TARGET_REGISTRIES !== 'object') {
			return new Response(
				JSON.stringify({ error: 'TARGET_REGISTRIES environment variable is required' }),
				{ status: 500, headers: { 'Content-Type': 'application/json' } }
			);
		}

		const url = new URL(request.url);
		const method = request.method;
		const pathname = url.pathname;
		const hostHeader = request.headers.get('Host') || url.hostname;
		const host = hostHeader.split(':')[0];
		
		// Get registry configuration based on Host header
		let registryConfig: RegistryMapping;
		try {
			registryConfig = getRegistryConfig(host, env.TARGET_REGISTRIES);
		} catch (error) {
			return new Response(
				JSON.stringify({ error: error instanceof Error ? error.message : 'Failed to get registry configuration' }),
				{ status: 500, headers: { 'Content-Type': 'application/json' } }
			);
		}
		
		const authorization = request.headers.get('Authorization');

		// Track image pulls for manifest and blob requests
		const imageInfo = parseImagePath(pathname);
		if (imageInfo && imageInfo.type && (imageInfo.type === 'manifest' || imageInfo.type === 'blob')) {
			// Get Cloudflare properties if available
			const cf = (request as any).cf as IncomingRequestCfProperties | undefined;
			trackImagePull(env.IMAGE_PULLS, {
				image: imageInfo.image,
				reference: imageInfo.reference,
				type: imageInfo.type,
			}, request, cf);
		}

		// Redirect root to /v2/
		if (pathname === '/') {
			return Response.redirect(url.protocol + '//' + url.host + '/v2/', 301);
		}

		// Handle API version check: /v2/
		if (pathname === '/v2/' || pathname === '/v2') {
			const upstreamUrl = buildUpstreamUrl(registryConfig, '/v2/');
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
			const upstreamUrl = buildUpstreamUrl(registryConfig, '/v2/');
			let scope: string | null = url.searchParams.get('scope');
			if (!scope) {
				return new Response(JSON.stringify({ error: 'scope is required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
			}
			// We get a scope like `repository:my-image:pull.
			// We need to rewrite it to `repository:/my-image:pull`
			const parts = scope.split(':', 3);
			const newRepo = getMapping(registryConfig, parts[1]);
			scope = `repository:${newRepo}:${parts[2]}`;
			const newUrl = new URL(upstreamUrl);
			newUrl.searchParams.set('scope', scope);
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

			return await fetchToken(wwwAuthenticate, scope, authorization);
		}

		let upstreamUrl: string;
		if (pathname.startsWith('/v2/')) {
			const newPathname = pathname.replace(`/v2/${imageInfo.image}/`, "/v2/" + getMapping(registryConfig, imageInfo.image) + "/");
			upstreamUrl = buildUpstreamUrl(registryConfig, newPathname, url.search);
		} else {
			upstreamUrl = buildUpstreamUrl(registryConfig, pathname, url.search);
		}
		// If request has authentication, we must proxy (auth token is for our domain, not upstream)
		// Otherwise, we can redirect for better performance
		if (authorization) {
			const newReq = new Request(upstreamUrl, {
				method: request.method,
				headers: request.headers,
				redirect: 'manual',
			});

			const resp = await fetch(newReq);

			// If upstream requires auth, return 401 with our auth endpoint
			if (resp.status === 401) {
				return responseUnauthorized(url);
			}

			return resp;
		} else {
			// No auth - safe to redirect
			return Response.redirect(upstreamUrl, 307);
		}
	},
} satisfies ExportedHandler<Env>;
