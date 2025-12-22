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
