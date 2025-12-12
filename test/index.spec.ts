import {createExecutionContext, env, fetchMock, waitOnExecutionContext} from 'cloudflare:test';
import {beforeAll, afterEach, describe, expect, it} from 'vitest';
import worker, {buildUpstreamUrl, getMapping} from '../src/index';

beforeAll(() => {
	// Enable outbound request mocking...
	fetchMock.activate();
	// ...and throw errors if an outbound request isn't mocked
	fetchMock.disableNetConnect();
});
// Ensure we matched every mock we defined
afterEach(() => fetchMock.assertNoPendingInterceptors());

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

async function runFetch(url: string) {
	const request = new IncomingRequest(url);
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, env, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

function setupMock(url: string) {
	const parsed = new URL(url);
	fetchMock
		.get(parsed.protocol + '//' + parsed.host)
		.intercept({path: parsed.pathname + parsed.search})
		.reply(200, "body");
}

function setup401Mock(url: string) {
	const parsed = new URL(url);
	fetchMock
		.get(parsed.protocol + '//' + parsed.host)
		.intercept({path: parsed.pathname})
		.reply(401, "body", {
			headers: { 'WWW-Authenticate': 'Bearer realm="https://example.org/v2/token",service="example.com"' }
		});
}

describe('OCI Registry Redirector', () => {
	it('redirects root to /v2/', async () => {
		const response = await runFetch('https://cr.example.com/');
		expect(response.status).toBe(301);
		const location = response.headers.get('Location');
		expect(location).toBe('https://cr.example.com/v2/');
	});

	it('proxies /v2/ endpoint to target registry', async () => {
		setupMock("https://example.org/v2/");
		const response = await runFetch('https://cr.example.com/v2/');
		expect(response.status).toBe(200);
	});

	it('handles blobs', async () => {
		const digest = 'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
		setupMock(`https://example.org/v2/a/b/blobs/${digest}`);
		await runFetch(`https://cr.example.com/v2/image1/blobs/${digest}`);

		setupMock(`https://example.org/v2/c/bar/blobs/${digest}`);
		await runFetch(`https://cr.example.com/v2/image2/bar/blobs/${digest}`);
	});

	it('handles manifests', async () => {
		setupMock(`https://example.org/v2/a/b/manifests/latest`);
		await runFetch(`https://cr.example.com/v2/image1/manifests/latest`);
		setupMock(`https://example.org/v2/c/bar/manifests/latest`);
		await runFetch(`https://cr.example.com/v2/image2/bar/manifests/latest`);
	});

	it('handles tags', async () => {
		setupMock(`https://example.org/v2/a/b/tags/list`);
		await runFetch(`https://cr.example.com/v2/image1/tags/list`);
		setupMock(`https://example.org/v2/c/bar/tags/list`);
		await runFetch(`https://cr.example.com/v2/image2/bar/tags/list`);
	});

	it('handles auth for image1', async () => {
		setup401Mock(`https://example.org/v2/`);
		setupMock(`https://example.org/v2/token?service=example.com&scope=repository:a/b:pull`);
		await runFetch(`https://cr.example.com/v2/auth?scope=repository:image1:pull`);
	});

	it('handles auth for image2', async () => {
		setup401Mock(`https://example.org/v2/`);
		setupMock(`https://example.org/v2/token?service=example.com&scope=repository:c/bar:pull`);
		await runFetch(`https://cr.example.com/v2/auth?scope=repository:image2/bar:pull`);
	});
});

describe('buildUpstreamUrl', () => {
	it('builds URL with base and pathname', () => {
		const config = { base: 'ghcr.io', mappings: {} };
		const result = buildUpstreamUrl(config, '/v2/myorg/myimage/manifests/latest');
		expect(result).toBe('https://ghcr.io/v2/myorg/myimage/manifests/latest');
	});

	it('includes search parameters', () => {
		const config = { base: 'ghcr.io', mappings: {} };
		const result = buildUpstreamUrl(config, '/v2/myorg/myimage/manifests/latest', '?n=5');
		expect(result).toBe('https://ghcr.io/v2/myorg/myimage/manifests/latest?n=5');
	});

	it('handles /v2 path without repo', () => {
		const config = { base: 'ghcr.io', mappings: {} };
		const result = buildUpstreamUrl(config, '/v2');
		expect(result).toBe('https://ghcr.io/v2');
	});

	it('handles /v2/ path without repo', () => {
		const config = { base: 'ghcr.io', mappings: {} };
		const result = buildUpstreamUrl(config, '/v2/');
		expect(result).toBe('https://ghcr.io/v2/');
	});

	it('preserves /v2 path when repo is specified', () => {
		const config = { base: 'ghcr.io', mappings: {}, repo: 'agentgateway' };
		const result = buildUpstreamUrl(config, '/v2');
		expect(result).toBe('https://ghcr.io/v2');
	});

	it('preserves /v2/ path when repo is specified', () => {
		const config = { base: 'ghcr.io', mappings: {}, repo: 'agentgateway' };
		const result = buildUpstreamUrl(config, '/v2/');
		expect(result).toBe('https://ghcr.io/v2/');
	});

	it('prepends repo to /v2/... paths', () => {
		const config = { base: 'ghcr.io', mappings: {}, repo: 'agentgateway' };
		const result = buildUpstreamUrl(config, '/v2/myimage/manifests/latest');
		expect(result).toBe('https://ghcr.io/v2/agentgateway/myimage/manifests/latest');
	});

	it('prepends repo to /v2/... paths with search params', () => {
		const config = { base: 'ghcr.io', mappings: {}, repo: 'agentgateway' };
		const result = buildUpstreamUrl(config, '/v2/myimage/blobs/sha256:abc', '?n=5');
		expect(result).toBe('https://ghcr.io/v2/agentgateway/myimage/blobs/sha256:abc?n=5');
	});

	it('does not modify non-/v2 paths even with repo', () => {
		const config = { base: 'ghcr.io', mappings: {}, repo: 'agentgateway' };
		const result = buildUpstreamUrl(config, '/other/path');
		expect(result).toBe('https://ghcr.io/other/path');
	});

	it('handles empty search string', () => {
		const config = { base: 'ghcr.io', mappings: {} };
		const result = buildUpstreamUrl(config, '/v2/test', '');
		expect(result).toBe('https://ghcr.io/v2/test');
	});
});

describe('getMapping', () => {
	it('returns mapped repo for single-part repo with mapping', () => {
		const config = {
			base: 'ghcr.io',
			mappings: { 'repo1': 'flat' }
		};
		const result = getMapping(config, 'repo1');
		expect(result).toBe('flat');
	});

	it('returns mapped repo with subpath for two-part repo with mapping', () => {
		const config = {
			base: 'ghcr.io',
			mappings: { 'myorg': 'mappedorg' }
		};
		const result = getMapping(config, 'myorg/myimage');
		expect(result).toBe('mappedorg/myimage');
	});

	it('returns original repo when no mapping exists (single part)', () => {
		const config = {
			base: 'ghcr.io',
			mappings: { 'otherorg': 'mappedorg' }
		};
		const result = getMapping(config, 'myorg');
		expect(result).toBe(null);
	});

	it('handles multi', () => {
		const config = {
			base: 'ghcr.io',
			mappings: { 'myorg': 'a/b' }
		};
		const result = getMapping(config, 'myorg');
		expect(result).toBe('a/b');
	});

	it('handles multi with Link', () => {
		// On a paginated call, the Link header will trigger the user to call a/b on subsequent calls.
		// Perhaps we should modify the Link, but for now we just handle the request
		const config = {
			base: 'ghcr.io',
			mappings: { 'myorg': 'a/b' }
		};
		const result = getMapping(config, 'a/b');
		expect(result).toBe('a/b');
	});

});
