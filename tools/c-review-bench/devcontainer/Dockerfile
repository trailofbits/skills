# Prototype only. Not wired into CI or the bench harness yet.
#
# Minimal hermetic image for running one c-review bench cell: no zsh/tmux/fzf/node22/
# ast-grep/git-delta from the reference trailofbits/claude-code-devcontainer image, none
# of which the plugin or the bench scripts touch. Kept deliberately small so the build
# loop for this prototype stays fast; a production version should probably start from the
# reference Dockerfile instead of re-deriving package list from scratch.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git jq build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash hermetic
USER hermetic
WORKDIR /home/hermetic
ENV PATH="/home/hermetic/.local/bin:$PATH"

# uv provides Python 3.11+ (enumerate_units.py requires-python >=3.11) without a system
# package; the c compiler above is for any tree-sitter grammar wheel uv has to build
# from sdist rather than pulling prebuilt.
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
RUN uv python install 3.11

# Same installer the reference devcontainer's Dockerfile uses. No Node.js step anywhere
# in this file — if this fails, that assumption (that the native installer is
# self-contained) was wrong and needs revisiting, not silently working around it.
RUN curl -fsSL https://claude.ai/install.sh | bash

# Copied verbatim from /Users/gros/c-review-bench-runs/guard/ — the same two hooks the
# host driver already uses, baked into the image so the settings.json below can
# reference a fixed in-container path instead of one more bind mount.
COPY --chown=hermetic:hermetic guard/ /opt/guard/
USER root
RUN chmod +x /opt/guard/*.sh
USER hermetic

# Pre-warm uv's package cache for enumerate_units.py's tree-sitter dependencies *while
# network still exists* (build time). Proven necessary empirically: a fresh container
# with --network none failed `uv run enumerate_units.py --help` with a DNS-resolution
# error hitting pypi.org — uv's own HTTP client resolves and downloads on a cold cache,
# and that traffic is invisible to the Bash-command-pattern PreToolUse guard (it isn't a
# curl/wget subprocess, it's inside the uv binary). This bakes a throwaway copy of the
# scripts dir purely to run the same `uv run <script>` invocation the real one triggers,
# so the resolution is cached under this image's ~/.cache/uv by content hash before the
# real (mounted, possibly newer) copy ever runs with --network none.
COPY --chown=hermetic:hermetic c-review-scripts-warm/ /tmp/c-review-scripts-warm/
RUN cd /tmp/c-review-scripts-warm && uv run warm_uv_cache.py >/dev/null

CMD ["/bin/bash"]
