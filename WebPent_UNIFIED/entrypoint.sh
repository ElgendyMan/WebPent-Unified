#!/bin/bash
# entrypoint.sh — Permanent fix for the SQLite bind-mount permission class of bug.
#
# ROOT CAUSE (found via reading the actual docker-compose.dev.yml, not
# guessed): both api and worker services already had
# `user: "${UID:-1000}:${GID:-1000}"`, which LOOKS like it unifies
# permissions across both containers. It doesn't reliably work: `$UID`
# is a bash-builtin shell PARAMETER, not an exported environment
# variable, in the vast majority of shell configurations -- `docker
# compose` reads its OWN process environment for `${UID}` substitution,
# which essentially never has UID actually exported into it, so this
# expression silently falls back to the hardcoded default "1000" on
# most machines regardless of the real host user's UID. If host-side
# files (webpent.db, webpent.db-wal, webpent.db-shm, or the memory/
# and output/ directories) end up owned by a DIFFERENT uid — e.g. root,
# if `make dev-init` or `docker-compose up` was ever run with sudo, or
# if Docker auto-created the bind-mount target itself (which happens as
# root, since dockerd runs as root) — then a container process running
# as uid 1000 has read-only access to files it doesn't own, producing
# exactly "sqlite3.OperationalError: attempt to write a readonly
# database" no matter what `user:` directive is configured.
#
# FIX: this script runs as root (the image's actual startup user —
# see the Dockerfile, which no longer sets `USER webpent` directly),
# unconditionally reconciles ownership of every bind-mounted,
# write-needed path to the CONTAINER'S configured runtime user (still
# controllable via docker-compose's `user:` directive, or defaults to
# the `webpent` user baked into the image), and then drops privileges
# via `gosu` before exec'ing the real command. This works correctly on
# every single container start, regardless of what UID owns the files
# on the host, without requiring the operator to get UID/GID env vars
# exported correctly, run any manual chmod/chown, or coordinate
# anything between machines.
#
# ROOTLESS MODE (D-1, v0.28.0 — docs/PRODUCTION_FIX_PLAN_0270.md):
# if the container was STARTED as a non-root user (docker-compose
# `user:` directive — see the optional docker-compose.rootless.yml
# override), the chown reconciliation is impossible AND unnecessary
# (a non-root process cannot chown, and by definition already owns
# whatever it can write), and gosu cannot be used at all. In that mode
# this script execs the command DIRECTLY as the starting uid — no
# silent fallback, no second privilege mechanism. The mode is announced
# on the container log so the operator can SEE which path ran.
#
# DROP VERIFICATION (D-1, v0.28.0): on the root path, the privilege
# drop is VERIFIED BEFORE exec'ing the real command: the entrypoint
# asks gosu to run `id -u` as the target and compares the answer to
# the requested uid. A gosu failure or a uid mismatch is FATAL
# (fail-closed, exit 1) — the container must never end up running the
# application under an identity other than the one it declared, even
# if a future base-image change breaks gosu silently.
set -euo pipefail

# Rootless branch first: a non-root startup IS the rootless mode.
CURRENT_UID="$(id -u)"
if [ "${CURRENT_UID}" -ne 0 ]; then
    echo "entrypoint.sh: ROOTLESS MODE — started as uid ${CURRENT_UID};" \
         "no chown reconciliation, no gosu, exec'ing command directly."
    exec "$@"
fi

# Target user/group to run the actual application as. Defaults to the
# webpent:webpent user baked into the base image (see Dockerfile.base).
# Can still be overridden via docker-compose's `user:` directive if an
# operator has a specific reason to (gosu will just use whatever numeric
# uid:gid docker itself resolved into $(id -u)/$(id -g) at that point —
# but since this script is now the ENTRYPOINT and runs as root
# regardless of any `user:` override in compose, we resolve the target
# explicitly here instead of relying on that mechanism at all).
TARGET_USER="${WEBPENT_RUN_AS_USER:-webpent}"
TARGET_UID="$(id -u "${TARGET_USER}" 2>/dev/null || echo 1000)"
TARGET_GID="$(id -g "${TARGET_USER}" 2>/dev/null || echo 1000)"

# Paths that need to be writable by the app process. Only chown paths
# that actually exist (bind mounts may or may not include all of these
# depending on which compose file/service is running) — this script is
# shared by both the api and worker entrypoints.
PATHS_TO_FIX=(
    "/app/webpent.db"
    "/app/webpent.db-wal"
    "/app/webpent.db-shm"
    "/app/memory"
    "/app/output"
)

for p in "${PATHS_TO_FIX[@]}"; do
    if [ -e "$p" ]; then
        # -R for directories is a no-op cost-wise for single files, and
        # correctly recurses into memory/ and output/ subdirectories.
        chown -R "${TARGET_UID}:${TARGET_GID}" "$p" 2>/dev/null || {
            echo "entrypoint.sh: WARNING — could not chown $p (continuing; " \
                 "the app itself will surface a clear error if this " \
                 "actually blocks a write)." >&2
        }
    fi
done

# DROP VERIFICATION (D-1, fail-closed): prove the drop actually lands
# before handing the process over. If gosu is missing/broken (base
# image drift) or resolves a different identity than requested, the
# container REFUSES to start the application rather than silently
# running it as the wrong user.
DROPPED_UID="$(gosu "${TARGET_UID}:${TARGET_GID}" id -u 2>/dev/null)" || {
    echo "entrypoint.sh: FATAL — privilege-drop probe failed (gosu could " \
         "not run 'id -u' as ${TARGET_UID}:${TARGET_GID}). Refusing to " \
         "start the application unverified." >&2
    exit 1
}
if [ "${DROPPED_UID}" != "${TARGET_UID}" ]; then
    echo "entrypoint.sh: FATAL — privilege drop did not land: requested " \
         "uid ${TARGET_UID} but gosu reports ${DROPPED_UID}. Refusing to " \
         "start the application under an unverified identity." >&2
    exit 1
fi
echo "entrypoint.sh: privilege drop VERIFIED (uid=${TARGET_UID}, gid=${TARGET_GID})."

# Drop privileges and exec the real command as the target user. `exec
# gosu` replaces this script's process (PID 1) with the target
# process running as the target uid — signals (SIGTERM on
# docker-compose down/stop) go directly to the real app, not to a
# shell wrapper that might not forward them correctly.
exec gosu "${TARGET_UID}:${TARGET_GID}" "$@"
