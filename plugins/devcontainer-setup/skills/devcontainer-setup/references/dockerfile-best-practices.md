# Dockerfile Best Practices

## Quick Reference

| Practice | Why |
|----------|-----|
| Order by change frequency | Rarely-changing layers first (base, system packages), frequently-changing last |
| Combine related RUN commands | Reduces layers and ensures cache coherence |
| Clean up in same layer | Don't leave apt cache in a layer |
| Use multi-stage builds | Separate build dependencies from runtime, reduce final image size |
| Pin versions with digests | Supply chain security: `FROM alpine:3.21@sha256:abc123...` |
| Switch to non-root user last | Do root operations first, then `USER vscode` |
| Use COPY over ADD | ADD has extra features you usually don't need |
| Use .dockerignore | Exclude build-irrelevant files to reduce context size |

## Base Image Selection

Choose minimal, trusted base images:
- **Docker Official Images** - curated, documented, regularly updated
- **Alpine Linux** - under 6 MB, tightly controlled
- **Verified Publisher** or **Docker-Sponsored Open Source** images

Pin images to specific digests for reproducible builds:
```dockerfile
FROM alpine:3.21@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c
```

Avoid `latest` tag - it can change unexpectedly and cause breaking builds.

## apt-get Best Practices

Always combine `update` with `install` in the same RUN statement:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    vim \
    && rm -rf /var/lib/apt/lists/*
```

**Why combine?** Keeping them separate causes Docker to cache the `update` layer, potentially installing outdated packages on subsequent builds.

**Best practices:**
- Use `--no-install-recommends` to minimize installed packages
- Sort packages alphabetically within each section for easier maintenance and PR reviews
- Clean up with `rm -rf /var/lib/apt/lists/*` in the same layer

## Pipe Safety

When using pipes, prepend `set -o pipefail &&` to fail if any command fails:

```dockerfile
RUN set -o pipefail && curl -fsSL https://example.com/install.sh | bash
```

Without this, a failed `curl` would be masked by a successful `bash`.

## Environment Variables

Use `ENV` for paths, versions, and configuration:

```dockerfile
ENV PYTHON_VERSION=3.13
ENV PATH=/home/vscode/.local/bin:$PATH
```

Note: `ENV` instructions add metadata, not filesystem layers like `RUN`. Multiple separate `ENV` lines are fine and often more readable than combining them.

## WORKDIR

Always use absolute paths. Avoid `RUN cd ... && command` patterns:

```dockerfile
# Good
WORKDIR /app
RUN make install

# Bad
RUN cd /app && make install
```

## Architecture Support

The templates support both AMD64 and ARM64 (Apple Silicon) automatically. Use `TARGETARCH` build arg for architecture-specific downloads:

```dockerfile
ARG TARGETARCH
RUN curl -fsSL "https://example.com/tool-${TARGETARCH}.tar.gz" | tar xz
```

## Devcontainer-Specific Tips

**Resource allocation:** Docker Desktop has limited defaults. Increase CPU/Memory in Docker settings for resource-intensive builds.
**Windows/WSL2:** Use Docker Desktop's WSL 2 backend for better file sharing performance.

## Sources

- [Docker Build Best Practices](https://docs.docker.com/build/building/best-practices/)
- [VS Code Dev Containers Tips](https://code.visualstudio.com/docs/devcontainers/tips-and-tricks)
