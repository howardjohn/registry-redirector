import {createExecutionContext, env, fetchMock, waitOnExecutionContext} from 'cloudflare:test';
import {beforeAll, afterEach, describe, expect, it, vi} from 'vitest';
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

async function runFetch(url: string, headers?: HeadersInit, method = 'GET') {
	const request = new IncomingRequest(url, {headers, method});
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
		setupTagsMock(`https://example.org/v2/a/b/tags/list`, ['v1.0.0']);
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

function setupTagsMock(url: string, tags: string[], link?: string) {
	const parsed = new URL(url);
	const headers: Record<string, string> = {'Content-Type': 'application/json'};
	if (link) {
		headers['Link'] = link;
	}
	fetchMock
		.get(parsed.protocol + '//' + parsed.host)
		.intercept({path: parsed.pathname + parsed.search})
		.reply(200, JSON.stringify({name: 'a/b', tags}), {headers});
}

describe('blocked tags', () => {
	const blockedBody = {errors: [{code: 'MANIFEST_UNKNOWN', message: 'v2 tags are retired'}]};

	it('returns 404 for blocked manifest tags without contacting upstream', async () => {
		for (const tag of ['v2.0.0', '2.0.0']) {
			const response = await runFetch(`https://cr.example.com/v2/image1/manifests/${tag}`);
			expect(response.status).toBe(404);
			expect(response.headers.get('Content-Type')).toBe('application/json');
			expect(await response.json()).toEqual(blockedBody);
		}
	});

	it('returns 404 without body for blocked manifest HEAD requests', async () => {
		const response = await runFetch(`https://cr.example.com/v2/image1/manifests/v2.0.0`, undefined, 'HEAD');
		expect(response.status).toBe(404);
		expect(await response.text()).toBe('');
	});

	it('blocks the upstream repo name alias too', async () => {
		const response = await runFetch(`https://cr.example.com/v2/a/b/manifests/v2.0.0`);
		expect(response.status).toBe(404);
	});

	it('records blocked manifest requests in analytics', async () => {
		const spy = vi.spyOn(env.IMAGE_PULLS, 'writeDataPoint');
		await runFetch(`https://cr.example.com/v2/image1/manifests/v2.0.0`);
		expect(spy.mock.calls[0][0]?.blobs?.[7]).toBe('blocked');

		setupMock(`https://example.org/v2/a/b/manifests/v1.0.0`);
		await runFetch(`https://cr.example.com/v2/image1/manifests/v1.0.0`);
		expect(spy.mock.calls[1][0]?.blobs?.[7]).toBe('');
		spy.mockRestore();
	});

	it('proxies non-blocked tags, digests, and other repos', async () => {
		setupMock(`https://example.org/v2/a/b/manifests/v1.0.0`);
		expect((await runFetch(`https://cr.example.com/v2/image1/manifests/v1.0.0`)).status).toBe(200);

		// Exact match only
		setupMock(`https://example.org/v2/a/b/manifests/v2.0.0-amd64`);
		expect((await runFetch(`https://cr.example.com/v2/image1/manifests/v2.0.0-amd64`)).status).toBe(200);

		const digest = 'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
		setupMock(`https://example.org/v2/a/b/manifests/${digest}`);
		expect((await runFetch(`https://cr.example.com/v2/image1/manifests/${digest}`)).status).toBe(200);

		setupMock(`https://alt.example.org/v2/c/bar/manifests/v2.0.0`);
		expect((await runFetch(`https://cr.example.com/v2/image2/bar/manifests/v2.0.0`)).status).toBe(200);
	});

	it('filters blocked tags from each upstream page and passes Link through', async () => {
		setupTagsMock(`https://example.org/v2/a/b/tags/list?n=3`, ['1.0.0', 'v1.0.0', 'v2.0.0'],
			'</v2/a/b/tags/list?last=v2.0.0&n=3>; rel="next"');
		const page1 = await runFetch(`https://cr.example.com/v2/image1/tags/list?n=3`);
		expect(page1.status).toBe(200);
		expect(page1.headers.get('Cache-Control')).toBe('no-transform');
		expect(await page1.json()).toEqual({name: 'a/b', tags: ['1.0.0', 'v1.0.0']});
		expect(page1.headers.get('Link')).toBe('</v2/image1/tags/list?last=v2.0.0&n=3>; rel="next"');

		// A page of only blocked tags is returned empty, with Link still pointing onward
		setupTagsMock(`https://example.org/v2/a/b/tags/list?last=v2.0.0&n=3`, ['2.0.0', 'v2.0.0'],
			'</v2/a/b/tags/list?last=v2.0.0&n=3>; rel="next"');
		const page2 = await runFetch(`https://cr.example.com/v2/image1/tags/list?last=v2.0.0&n=3`);
		expect(await page2.json()).toEqual({name: 'a/b', tags: []});
		expect(page2.headers.get('Link')).toBe('</v2/image1/tags/list?last=v2.0.0&n=3>; rel="next"');
	});

	it('passes HEAD tags requests through', async () => {
		fetchMock.get('https://example.org').intercept({path: '/v2/a/b/tags/list', method: 'HEAD'}).reply(200, '');
		const response = await runFetch(`https://cr.example.com/v2/image1/tags/list`, undefined, 'HEAD');
		expect(response.status).toBe(200);
	});

	it('returns 401 when upstream requires auth for tags', async () => {
		setup401Mock(`https://example.org/v2/a/b/tags/list`);
		const response = await runFetch(`https://cr.example.com/v2/image1/tags/list`);
		expect(response.status).toBe(401);
		expect(response.headers.get('Www-Authenticate')).toContain('scope="repository:image1:pull"');
	});

	it('does not filter tags for other repos', async () => {
		setupTagsMock(`https://alt.example.org/v2/c/bar/tags/list?n=1`, ['v2.0.0'], '</v2/c/bar/tags/list?last=v2.0.0&n=1>; rel="next"');
		const response = await runFetch(`https://cr.example.com/v2/image2/bar/tags/list?n=1`);
		expect(await response.json()).toEqual({name: 'a/b', tags: ['v2.0.0']});
		expect(response.headers.get('Link')).toBe('</v2/image2/bar/tags/list?last=v2.0.0&n=1>; rel="next"');
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
