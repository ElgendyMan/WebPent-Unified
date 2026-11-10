# syntax=docker/dockerfile:1
# =============================================================================
# Dockerfile — WebPent v60 App Image (Lightweight, Fast Rebuild)
# =============================================================================
# Builds ON TOP of webpent-base:latest which already contains:
#   - OS deps, Go tools, Playwright, torch, sentence-transformers, chromadb
#   - Framework pip dependencies
#
# V6 DX-Final: Optimised Docker layer caching. The pyproject.toml is
# copied and `pip install -e .` is run BEFORE the rest of the source
# code is copied. This way, dependency changes (a new package added to
# pyproject.toml) trigger a rebuild, but ordinary code changes do NOT
# invalidate the pip layer — the layer cache is reused and rebuild
# takes <5 seconds.
#
# Prerequisite: Build the base image first:
#   make build-base
#   (or: docker build -t webpent-base:latest -f Dockerfile.base .)
# =============================================================================

FROM webpent-base:latest

ARG WEBPENT_VERSION=0.39.0
LABEL org.opencontainers.image.title="WebPent v60" \
      org.opencontainers.image.version="${WEBPENT_VERSION}" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# ---------------------------------------------------------------------------
# V6 DX-Final: Dependency layer — cached separately from source code.
# ---------------------------------------------------------------------------
# Copy ONLY pyproject.toml (and README.md, which pyproject.toml references
# via ``readme = "README.md"``) so that ``pip install -e .`` can resolve
# the framework's dependencies without needing the full source tree.
# Any change to pyproject.toml will invalidate this layer; any change
# to .py source files will NOT invalidate it, making iterative dev
# rebuilds near-instant.
COPY pyproject.toml README.md ./

# Install the framework's dependencies from pyproject.toml. We use
# ``--no-cache-dir`` to keep the image small and ``-e .`` so the
# editable install is wired up (the actual source will be mounted on
# top via the COPY below).
#
# V6 DX-Final: Removed the ``2>/dev/null || true`` mask. If pip fails
# (e.g. a dep is unavailable, a typo in pyproject.toml, a network
# error), the build MUST fail immediately so the operator sees the
# real error instead of a silently broken image.
RUN pip install --no-cache-dir -e .

# ---------------------------------------------------------------------------
# Source layer — this is the only layer that changes frequently.
# ---------------------------------------------------------------------------
# Now copy the rest of the source code. Because pip already installed
# all deps from pyproject.toml above, this layer only adds the .py
# files; subsequent code edits only invalidate this thin layer.
COPY . .

# Re-run ``pip install -e .`` in editable mode to refresh the egg-link
# to point at the freshly-copied source. This is a no-op for deps
# (already satisfied) so it completes in <1 second.
#
# V6 DX-Final: No ``2>/dev/null || true`` — failures must surface.
RUN pip install --no-cache-dir -e .

# Ensure permissions on files baked into the image itself (this does
# NOT fix bind-mounted files, which don't exist yet at build time —
# entrypoint.sh below handles those at container startup, every time).
RUN chown -R webpent:webpent /app

# V7 Ready-For-Kali FIX (REGRESSION RESTORED — this exact fix existed
# in a previous round and was silently lost when this round's
# Dockerfile/docker-compose changes were applied against a stale
# starting point that predated it): the container now STARTS as root
# and uses entrypoint.sh to reconcile bind-mount file ownership at
# every startup before dropping privileges to the webpent user via
# gosu. Static `USER webpent` (what was reintroduced here) cannot fix
# files that end up owned by a different uid on the host side of a
# bind mount — see entrypoint.sh's header comment for the full
# root-cause analysis (in short: `${UID:-1000}` in docker-compose
# almost never resolves to the real host UID, since $UID is a bash
# shell parameter, not an exported env var, in most shell configs).
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV HOME=/home/webpent

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["python", "server.py"]
