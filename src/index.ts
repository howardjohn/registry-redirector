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

export interface Env {
	TARGET_REGISTRIES: TargetRegistries;
	IMAGE_PULLS: AnalyticsEngineDataset;
}

export type RegistryMapping = {
	mappings: {
		[repo: string]: string;
	};
	base: string;
};

export type TargetRegistries = {
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
export function buildUpstreamUrl(config: RegistryMapping, pathname: string, search: string = ''): string {
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

export function getMapping(config: RegistryMapping, repo: string): string | null {
	const spl = repo.split('/', 2);
	const base: string = spl[0];
	if (config.mappings[base]) {
		if (spl.length > 1) {
			return config.mappings[base] + "/" + spl[1];
		}
		const res = config.mappings[base];
		if (res !== null) {
			return res;
		}
	}

	// Check: does any value, not key, in mappings equal 'repo'
	if (Object.values(config.mappings).includes(repo)) {
		return repo;
	}
	return null;
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
	return new Response(JSON.stringify({message: 'UNAUTHORIZED'}), {
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

	return await fetchLog(url.toString(), {method: 'GET', headers: headers});
}

/**
 * Parse image information from OCI registry pathname
 * Examples:
 *   /v2/myorg/myimage/manifests/latest -> { image: "myorg/myimage", reference: "latest", type: "manifest" }
 *   /v2/myorg/myimage/blobs/sha256:abc -> { image: "myorg/myimage", reference: "sha256:abc", type: "blob" }
 *   /v2/myorg/myimage/tags/list -> { image: "myorg/myimage", reference: null, type: "tags" }
 */
// Define an enum for image path types
export enum ImagePathType {
	Manifest = "manifest",
	Blob = "blob",
	Tags = "tags",
	V2Root = "v2",
	Auth = "auth",
	Unknown = "unknown",
}

export type ParsedImagePath =
	| { type: ImagePathType.Manifest; image: string; reference: string }
	| { type: ImagePathType.Blob; image: string; digest: string }
	| { type: ImagePathType.Tags; image: string }
	| { type: ImagePathType.V2Root }
	| { type: ImagePathType.Auth }
	| { type: ImagePathType.Unknown };

function parseImagePath(pathname: string): ParsedImagePath {
	// Match /v2/<image>/manifests/<reference>
	const manifestMatch = pathname.match(/^\/v2\/(.+)\/manifests\/(.+)$/);
	if (manifestMatch) {
		return {
			type: ImagePathType.Manifest,
			image: manifestMatch[1],
			reference: manifestMatch[2],
		};
	}

	// Match /v2/<image>/blobs/<digest>
	const blobMatch = pathname.match(/^\/v2\/(.+)\/blobs\/(.+)$/);
	if (blobMatch) {
		return {
			type: ImagePathType.Blob,
			image: blobMatch[1],
			digest: blobMatch[2],
		};
	}

	// Match /v2/<image>/tags/list
	const tagsMatch = pathname.match(/^\/v2\/(.+)\/tags\/list$/);
	if (tagsMatch) {
		return {
			type: ImagePathType.Tags,
			image: tagsMatch[1],
		};
	}

	// Match exact /v2/ (root index)
	if (pathname === "/v2/" || pathname === "/v2") {
		return {type: ImagePathType.V2Root};
	}

	// Match /v2/auth
	if (pathname === "/v2/auth") {
		return {type: ImagePathType.Auth};
	}

	return {type: ImagePathType.Unknown};
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
		analytics?.writeDataPoint(data);
	} catch (error) {
		// Silently fail analytics tracking to not break the request
		// In production, you might want to log this
		console.error('Failed to track image pull:', error);
	}
}


async function handleManifest(cfg: RegistryMapping, request: Request, path: string, image: string, reference: string) {
	return await handleGeneric(cfg, request, path, image);
}

async function handleBlob(cfg: RegistryMapping, request: Request, path: string, image: string, digest: string) {
	return await handleGeneric(cfg, request, path, image);
}

async function handleGeneric(cfg: RegistryMapping, request: Request, path: string, image: string) {
	const newRepo = getMapping(cfg, image);
	if (newRepo === null) {
		return handleUnknown(cfg);
	}
	const newPathname = path.replace(`/v2/${image}/`, `/v2/${newRepo}/`);
	const newUrl = `https://${cfg.base}${newPathname}`
	const newReq = new Request(newUrl, {
		method: request.method,
		headers: request.headers,
		redirect: 'manual',
	});

	const resp = await fetchLog(newReq);

	// If upstream requires auth, return 401 with our auth endpoint
	if (resp.status === 401) {
		return responseUnauthorized(new URL(request.url));
	}
	const location = resp.headers.get('location');
	if (location && location.startsWith('/')) {
		// This is a relative redirect. Map it back to an absolute URL
		const newLocation = `https://${cfg.base}${location}`
		const newResponse = new Response(resp.body, resp);
		newResponse.headers.set('location', newLocation);
		return newResponse
	}
	return resp;
}

async function handleTags(cfg: RegistryMapping, request: Request, path: string, image: string) {
	const resp = await handleGeneric(cfg, request, path, image);
	const link = resp.headers.get('link');
	if (link) {
		const newRepo = getMapping(cfg, image);
		// The Link will link to the real repository. We need to map it back to our synthetic one
		const newResponse = new Response(resp.body, resp);
		newResponse.headers.set('link', link.replace(`/v2/${newRepo}/tags`, `/v2/${image}/tags`));
		return newResponse
	}

	return resp;
}

async function handleRoot(cfg: RegistryMapping, request: Request, authorization: string | null) {
	const upstreamUrl = `https://${cfg.base}/v2/`;
	const headers = new Headers();
	if (authorization) {
		headers.set('Authorization', authorization);
	}

	const resp = await fetchLog(upstreamUrl, {
		method: 'GET',
		headers: headers,
		redirect: 'follow',
	});

	// If upstream requires auth, return 401 with our auth endpoint
	if (resp.status === 401) {
		return responseUnauthorized(new URL(request.url));
	}

	return resp;
}

async function handleAuth(cfg: RegistryMapping, authorization: string | null, originalUrl: URL) {
	let scope: string | null = originalUrl.searchParams.get('scope');
	if (!scope) {
		return new Response(JSON.stringify({error: 'scope is required'}), {
			status: 400,
			headers: {'Content-Type': 'application/json'}
		});
	}
	// We get a scope like `repository:my-image:pull.
	// We need to rewrite it to `repository:/my-image:pull`
	const parts = scope.split(':', 3);
	const newRepo = getMapping(cfg, parts[1]);
	if (newRepo === null) {
		return handleUnknown(cfg);
	}
	scope = `repository:${newRepo}:${parts[2]}`;

	// Send a request to /v2/ to get the WWW-Authenticate header so we know where to send the token request to
	const newUrl = new URL(`https://${cfg.base}/v2/`);
	const resp = await fetchLog(newUrl, {
		method: 'GET',
		redirect: 'follow',
	});

	if (resp.status !== 401) {
		return resp;
	}

	const authenticate = resp.headers.get('WWW-Authenticate');
	if (authenticate === null) {
		return resp;
	}

	const wwwAuthenticate = parseAuthenticate(authenticate);

	return await fetchToken(wwwAuthenticate, scope, authorization);
}

function handleUnknown(cfg: RegistryMapping,) {
	return new Response(JSON.stringify({error: 'Not found'}), {
		status: 404,
		headers: {'Content-Type': 'application/json'}
	});
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		// Validate required configuration
		if (!env.TARGET_REGISTRIES || typeof env.TARGET_REGISTRIES !== 'object') {
			return new Response(
				JSON.stringify({error: 'TARGET_REGISTRIES environment variable is required'}),
				{status: 500, headers: {'Content-Type': 'application/json'}}
			);
		}

		const method = request.method;
		if (method != "GET" && method != "HEAD") {
			return new Response(JSON.stringify({error: 'Method not allowed'}), {
				status: 405,
				headers: {'Content-Type': 'application/json'}
			});
		}

		const url = new URL(request.url);
		const pathname = url.pathname;
		const parsed = parseImagePath(pathname);

		// Redirect root to /v2/
		if (pathname === '/') {
			return Response.redirect(url.protocol + '//' + url.host + '/v2/', 301);
		}

		const hostHeader = request.headers.get('Host') || url.hostname;
		const host = hostHeader.split(':')[0];
		// Get registry configuration based on Host header
		let registryConfig: RegistryMapping;
		try {
			registryConfig = getRegistryConfig(host, env.TARGET_REGISTRIES);
		} catch (error) {
			return new Response(
				JSON.stringify({error: error instanceof Error ? error.message : 'Failed to get registry configuration'}),
				{status: 500, headers: {'Content-Type': 'application/json'}}
			);
		}

		if (parsed.type === ImagePathType.Manifest || parsed.type === ImagePathType.Blob) {
			// Get Cloudflare properties if available
			const cf = (request as any).cf as IncomingRequestCfProperties | undefined;
			trackImagePull(env.IMAGE_PULLS, {
				image: parsed.image,
				reference: parsed.type === ImagePathType.Manifest ? parsed.reference : parsed.digest,
				type: parsed.type,
			}, request, cf);
		}

		const pathAndQuery = url.pathname + url.search;
		const authorization = request.headers.get('Authorization');
		switch (parsed.type) {
			case ImagePathType.Manifest:
				return await handleManifest(registryConfig, request, pathAndQuery, parsed.image, parsed.reference);
			case ImagePathType.Blob:
				return await handleBlob(registryConfig, request, pathAndQuery, parsed.image, parsed.digest);
			case ImagePathType.Tags:
				return await handleTags(registryConfig, request, pathAndQuery, parsed.image);
			case ImagePathType.V2Root:
				return await handleRoot(registryConfig, request, authorization);
			case ImagePathType.Auth:
				return await handleAuth(registryConfig, authorization, url);
			default:
				return handleUnknown(registryConfig);
		}
	},
} satisfies ExportedHandler<Env>;

function fetchLog(input: RequestInfo | URL, init?: RequestInit<RequestInitCfProperties>): Promise<Response> {
	let urlStr: string;
	if (typeof input === "string") {
		urlStr = input;
	} else if (input instanceof URL) {
		urlStr = input.toString();
	} else if (input instanceof Request) {
		urlStr = input.url;
	} else {
		urlStr = String(input);
	}
	console.log("fetch:", urlStr);
	return fetch(input, init);
}
