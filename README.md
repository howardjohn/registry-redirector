# Registry Redirector

This project provides an OCI/Docker image registry mirror that redirects requests to a specified upstream registry.
The primary goals of this project are to provide an abstraction layer over the underlying registry, allowing moving between registries without user impact.
Additionally, analytics are available to track usage patterns.

## Deployment

To deploy, fork the `wrangler.jsonc` file and update the `account_id` and `TARGET_REGISTRIES`.

Then, you can run `npx wrangler deploy`.

## Configuration

Configuration is handled by `TARGET_REGISTRIES` variable.


Example:

```jsonc
{
  "domain.example.com": {
    "mappings": {
      "image1": "ghcr.io/foo/bar",
      "charts": "index.docker.io/my-helm-charts",
      "sub/image2": "ghcr.io/foo/bar/baz",
    }
  }
}
```

With this configuration:
* `domain.example.com/image1` will pull `ghcr.io/foo/bar`
* `domain.example.com/charts/a` will pull `my-helm-charts/a` (aka `docker.io/my-helm-charts/a` with explicit path)
* `domain.example.com/charts/b` will pull `my-helm-charts/b` (or any other subpath under charts)
* `domain.example.com/sub/image2` will pull `ghcr.io/foo/bar/baz`

### Blocking tags

Specific tags can be retired with `blockedTags`, keyed by the *upstream* repository and matched exactly:

```jsonc
{
  "domain.example.com": {
    "mappings": { "image1": "ghcr.io/foo/bar" },
    "blockedTags": {
      "ghcr.io/foo/bar": {
        "message": "v2 tags are retired; use 1.x",
        "tags": ["v2.0.0", "v2.0.1"]
      }
    }
  }
}
```

For a blocked repository:
* `GET`/`HEAD` of a manifest by a blocked tag returns `404` with `{"errors":[{"code":"MANIFEST_UNKNOWN","message":"<message>"}]}`, without contacting upstream. Pulls by digest are unaffected.
* `tags/list` is proxied as usual (one upstream request, `n`/`last` and `Link` passed through), with blocked tags removed from each page. Pages may therefore contain fewer than `n` tags.
* Blocked manifest requests are recorded in analytics with `blob8 = 'blocked'`.
