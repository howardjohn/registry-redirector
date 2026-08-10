import {createExecutionContext, env, fetchMock, waitOnExecutionContext} from 'cloudflare:test';
import {beforeAll, afterEach, describe, expect, it} from 'vitest';
import worker, {getMapping} from '../src/index';

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

async function runFetch(url: string, headers?: HeadersInit) {
	const request = new IncomingRequest(url, {headers});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, env, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

function setupMock(url: string, headers?: Record<string, string>) {
	const parsed = new URL(url);
	fetchMock
		.get(parsed.protocol + '//' + parsed.host)
		.intercept({path: parsed.pathname + parsed.search})
		.reply(200, "body", headers ? {headers} : undefined);
}

function setup401Mock(url: string, quoteRealm = true, quoteService = true) {
	const parsed = new URL(url);

	let realmValue = `${url}token`;
	if (quoteRealm) {
		realmValue = `"${realmValue}"`;
	}
	let serviceValue = `example.com`;
	if (quoteService) {
		serviceValue = `"${serviceValue}"`;
	}
	const wwwAuthenticate = `Bearer realm=${realmValue},service=${serviceValue}`;
	fetchMock
		.get(parsed.protocol + '//' + parsed.host)
		.intercept({path: parsed.pathname})
		.reply(401, "body", {
			headers: { 'WWW-Authenticate': wwwAuthenticate }
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
		expect(response.headers.get('Www-Authenticate')).toBe(
			'Bearer realm="https://cr.example.com/v2/auth",service="cr.example.com"'
		);
	});

	it('issues an unscoped proxy token that authenticates the /v2/ ping', async () => {
		const tokenResponse = await runFetch('https://cr.example.com/v2/auth?service=cr.example.com');
		expect(tokenResponse.status).toBe(200);
		expect(tokenResponse.headers.get('Content-Type')).toBe('application/json');
		const tokenBody = await tokenResponse.json<{token: string; access: []}>();
		expect(tokenBody.access).toEqual([]);

		const pingResponse = await runFetch('https://cr.example.com/v2/', {
			Authorization: `Bearer ${tokenBody.token}`,
		});
		expect(pingResponse.status).toBe(200);
		expect(pingResponse.headers.get('Docker-Distribution-Api-Version')).toBe('registry/2.0');
	});

	it('does not accept a different token for the /v2/ ping', async () => {
		const tokenResponse = await runFetch('https://cr.example.com/v2/auth?service=cr.example.com');
		const {token} = await tokenResponse.json<{token: string}>();

		const response = await runFetch('https://cr.example.com/v2/', {
			Authorization: `Bearer ${token}-different`,
		});
		expect(response.status).toBe(401);
	});

	it('does not grant repository access with the proxy ping token', async () => {
		const tokenResponse = await runFetch('https://cr.example.com/v2/auth?service=cr.example.com');
		const {token} = await tokenResponse.json<{token: string}>();
		setup401Mock('https://example.org/v2/a/b/manifests/latest');

		const response = await runFetch('https://cr.example.com/v2/image1/manifests/latest', {
			Authorization: `Bearer ${token}`,
		});
		expect(response.status).toBe(401);
		expect(response.headers.get('Www-Authenticate')).toContain('scope="repository:image1:pull"');
	});

	it('handles blobs', async () => {
		const digest = 'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
		setupMock(`https://example.org/v2/a/b/blobs/${digest}`);
		const response = await runFetch(`https://cr.example.com/v2/image1/blobs/${digest}`);
		expect(response.headers.get('Cache-Control')).toBe('no-transform');

		setupMock(`https://alt.example.org/v2/c/bar/blobs/${digest}`);
		await runFetch(`https://cr.example.com/v2/image2/bar/blobs/${digest}`);
	});

	it('returns repo scope on unauthorized blob requests', async () => {
		const digest = 'sha256:d865bf0feaaa03f1f4c2e70e420e1830e8cb4db80d259b7e18e6ee86ce3d3cb9';
		setup401Mock(`https://alt.example.org/v2/d/e/blobs/${digest}`);
		const response = await runFetch(`https://cr.example.com/v2/image3/subimage/blobs/${digest}`);

		expect(response.status).toBe(401);
		expect(response.headers.get('Www-Authenticate')).toBe(
			'Bearer realm="https://cr.example.com/v2/auth",service="cr.example.com",scope="repository:image3/subimage:pull"'
		);
	});

	it('handles manifests', async () => {
		setupMock(`https://example.org/v2/a/b/manifests/latest`);
		const response = await runFetch(`https://cr.example.com/v2/image1/manifests/latest`);
		expect(response.headers.get('Cache-Control')).toBe('no-transform');
		setupMock(`https://alt.example.org/v2/c/bar/manifests/latest`);
		await runFetch(`https://cr.example.com/v2/image2/bar/manifests/latest`);
	});

	it('handles tags', async () => {
		setupMock(`https://example.org/v2/a/b/tags/list`);
		const response = await runFetch(`https://cr.example.com/v2/image1/tags/list`);
		expect(response.headers.get('Cache-Control')).toBe('no-transform');
		setupMock(`https://alt.example.org/v2/c/bar/tags/list`);
		await runFetch(`https://cr.example.com/v2/image2/bar/tags/list`);
	});

	it('handles referrers', async () => {
		const digest = 'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
		setupMock(`https://example.org/v2/a/b/referrers/${digest}`);
		const response = await runFetch(`https://cr.example.com/v2/image1/referrers/${digest}`);
		expect(response.status).toBe(200);
		expect(response.headers.get('Cache-Control')).toBe('no-transform');

		setupMock(`https://alt.example.org/v2/c/bar/referrers/${digest}`);
		await runFetch(`https://cr.example.com/v2/image2/bar/referrers/${digest}`);
	});

	it('returns repo scope on unauthorized referrers requests', async () => {
		const digest = 'sha256:d865bf0feaaa03f1f4c2e70e420e1830e8cb4db80d259b7e18e6ee86ce3d3cb9';
		setup401Mock(`https://alt.example.org/v2/d/e/referrers/${digest}`);
		const response = await runFetch(`https://cr.example.com/v2/image3/subimage/referrers/${digest}`);

		expect(response.status).toBe(401);
		expect(response.headers.get('Www-Authenticate')).toBe(
			'Bearer realm="https://cr.example.com/v2/auth",service="cr.example.com",scope="repository:image3/subimage:pull"'
		);
	});

	it('handles auth for image1', async () => {
		for (const quoteRealm of [true, false]) {
			for (const quoteService of [true, false]) {
				setup401Mock(`https://example.org/v2/`, quoteRealm, quoteService);
				setupMock(`https://example.org/v2/token?service=example.com&scope=repository:a/b:pull`);
				await runFetch(`https://cr.example.com/v2/auth?scope=repository:image1:pull`);
			}
		}
	});

	it('handles auth for image2', async () => {
		for (const quoteRealm of [true, false]) {
			for (const quoteService of [true, false]) {
				setup401Mock(`https://alt.example.org/v2/`, quoteRealm, quoteService);
				setupMock(`https://alt.example.org/v2/token?service=example.com&scope=repository:c/bar:pull`);
				await runFetch(`https://cr.example.com/v2/auth?scope=repository:image2/bar:pull`);
			}
		}

	});

	it('rejects invalid repository scopes', async () => {
		for (const scope of ['registry:catalog:*', 'repository:image1', 'repository']) {
			const response = await runFetch(`https://cr.example.com/v2/auth?scope=${encodeURIComponent(scope)}`);
			expect(response.status).toBe(400);
			expect(await response.json()).toEqual({error: 'invalid scope'});
		}
	});

	it('appends no-transform to an existing Cache-Control header', async () => {
		setupMock(`https://example.org/v2/a/b/manifests/latest`, {'Cache-Control': 'max-age=3600'});
		const response = await runFetch(`https://cr.example.com/v2/image1/manifests/latest`);
		expect(response.headers.get('Cache-Control')).toBe('max-age=3600, no-transform');
	});

	it('does not duplicate an existing no-transform directive', async () => {
		setupMock(`https://example.org/v2/a/b/manifests/latest`, {'Cache-Control': 'No-Transform'});
		const response = await runFetch(`https://cr.example.com/v2/image1/manifests/latest`);
		expect(response.headers.get('Cache-Control')).toBe('No-Transform');
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

	it('handles multi map', () => {
		const config = {
			mappings: { 'x/y': 'ghcr.io/a/b' }
		};
		const result = getMapping(config, 'x/y');
		expect(result?.repo).toBe('a/b');
		expect(result?.base).toBe('ghcr.io');
	});


});
