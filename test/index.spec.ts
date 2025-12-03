import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index';

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe('OCI Registry Redirector', () => {
	it('redirects root to /v2/', async () => {
		const request = new IncomingRequest('https://example.com/');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		
		expect(response.status).toBe(301);
		const location = response.headers.get('Location');
		expect(location).toBe('https://example.com/v2/');
	});

	it('proxies /v2/ endpoint to target registry', async () => {
		const request = new IncomingRequest('https://example.com/v2/');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		
		// This will actually proxy to ghcr.io, so we can't assert exact status
		// but we can verify it's not a redirect
		expect(response.status).not.toBe(307);
		expect(response.status).not.toBe(301);
	});

	it('redirects blob requests to target registry', async () => {
		const digest = 'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
		const request = new IncomingRequest(`https://example.com/v2/myorg/myimage/blobs/${digest}`);
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		
		expect(response.status).toBe(307);
		const location = response.headers.get('Location');
		expect(location).toBe(`https://ghcr.io/v2/myorg/myimage/blobs/${digest}`);
	});

	it('proxies manifest requests to target registry', async () => {
		const request = new IncomingRequest('https://example.com/v2/myorg/myimage/manifests/latest');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		
		// Manifest requests are proxied, not redirected
		expect(response.status).not.toBe(307);
		expect(response.status).not.toBe(301);
	});

	it('proxies tags list requests to target registry', async () => {
		const request = new IncomingRequest('https://example.com/v2/myorg/myimage/tags/list');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		
		// Tags requests are proxied, not redirected
		expect(response.status).not.toBe(307);
		expect(response.status).not.toBe(301);
	});

	it('handles /v2/auth token endpoint', async () => {
		const request = new IncomingRequest('https://example.com/v2/auth?scope=repository:myorg/myimage:pull');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		
		// Token endpoint proxies to upstream, so we can't assert exact status
		// but we can verify it's not a redirect or error
		expect(response.status).not.toBe(307);
		expect(response.status).not.toBe(301);
		expect(response.status).not.toBe(404);
	});

	it('preserves query parameters in blob redirects', async () => {
		const digest = 'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
		const request = new IncomingRequest(`https://example.com/v2/myorg/myimage/blobs/${digest}?n=5`);
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		
		expect(response.status).toBe(307);
		const location = response.headers.get('Location');
		expect(location).toBe(`https://ghcr.io/v2/myorg/myimage/blobs/${digest}?n=5`);
	});

	it('uses custom target registry from env', async () => {
		const customEnv = { ...env, TARGET_REGISTRY: 'registry.example.com' };
		const digest = 'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
		const request = new IncomingRequest(`https://example.com/v2/myorg/myimage/blobs/${digest}`);
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, customEnv, ctx);
		await waitOnExecutionContext(ctx);
		
		expect(response.status).toBe(307);
		const location = response.headers.get('Location');
		expect(location).toBe(`https://registry.example.com/v2/myorg/myimage/blobs/${digest}`);
	});

	it('returns 404 for unknown endpoints', async () => {
		const request = new IncomingRequest('https://example.com/v2/unknown/endpoint');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		
		expect(response.status).toBe(404);
	});
});
