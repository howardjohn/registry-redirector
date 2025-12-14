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
			headers: { 'WWW-Authenticate': `Bearer realm="${url}token",service="example.com"` }
		});
}

describe('OCI Registry Redirector', () => {
	it('redirects root to /v2/', async () => {
		const response = await runFetch('https://cr.example.com/');
		expect(response.status).toBe(301);
		const location = response.headers.get('Location');
		expect(location).toBe('https://cr.example.com/v2/');
	});

	it('returns 401 on /v2/ endpoint', async () => {
		const response = await runFetch('https://cr.example.com/v2/');
		expect(response.status).toBe(401);
	});

	it('handles blobs', async () => {
		const digest = 'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
		setupMock(`https://example.org/v2/a/b/blobs/${digest}`);
		await runFetch(`https://cr.example.com/v2/image1/blobs/${digest}`);

		setupMock(`https://alt.example.org/v2/c/bar/blobs/${digest}`);
		await runFetch(`https://cr.example.com/v2/image2/bar/blobs/${digest}`);
	});

	it('handles manifests', async () => {
		setupMock(`https://example.org/v2/a/b/manifests/latest`);
		await runFetch(`https://cr.example.com/v2/image1/manifests/latest`);
		setupMock(`https://alt.example.org/v2/c/bar/manifests/latest`);
		await runFetch(`https://cr.example.com/v2/image2/bar/manifests/latest`);
	});

	it('handles tags', async () => {
		setupMock(`https://example.org/v2/a/b/tags/list`);
		await runFetch(`https://cr.example.com/v2/image1/tags/list`);
		setupMock(`https://alt.example.org/v2/c/bar/tags/list`);
		await runFetch(`https://cr.example.com/v2/image2/bar/tags/list`);
	});

	it('handles auth for image1', async () => {
		setup401Mock(`https://example.org/v2/`);
		setupMock(`https://example.org/v2/token?service=example.com&scope=repository:a/b:pull`);
		await runFetch(`https://cr.example.com/v2/auth?scope=repository:image1:pull`);
	});

	it('handles auth for image2', async () => {
		setup401Mock(`https://alt.example.org/v2/`);
		setupMock(`https://alt.example.org/v2/token?service=example.com&scope=repository:c/bar:pull`);
		await runFetch(`https://cr.example.com/v2/auth?scope=repository:image2/bar:pull`);
	});
});

describe('getMapping', () => {
	it('returns mapped repo for single-part repo with mapping', () => {
		const config = {
			mappings: { 'repo1': 'ghcr.io/flat' }
		};
		const result = getMapping(config, 'repo1');
		expect(result?.repo).toBe('flat');
	});

	it('returns mapped repo with subpath for two-part repo with mapping', () => {
		const config = {
			mappings: { 'myorg': 'ghcr.io/mappedorg' }
		};
		const result = getMapping(config, 'myorg/myimage');
		expect(result?.repo).toBe('mappedorg/myimage');
	});

	it('returns original repo when no mapping exists (single part)', () => {
		const config = {
			mappings: { 'otherorg': 'ghcr.io/mappedorg' }
		};
		const result = getMapping(config, 'myorg');
		expect(result).toBe(null);
	});

	it('handles multi', () => {
		const config = {
			mappings: { 'myorg': 'ghcr.io/a/b' }
		};
		const result = getMapping(config, 'myorg');
		expect(result?.repo).toBe('a/b');
		expect(result?.base).toBe('ghcr.io');
	});

	it('handles multi with Link', () => {
		// On a paginated call, the Link header will trigger the user to call a/b on subsequent calls.
		// Perhaps we should modify the Link, but for now we just handle the request
		const config = {
			mappings: { 'myorg': 'ghcr.io/a/b' }
		};
		const result = getMapping(config, 'a/b');
		expect(result?.repo).toBe('a/b');
		expect(result?.base).toBe('ghcr.io');
	});

});
