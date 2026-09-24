#!/bin/bash
set -e

# InfraScan Entrypoint Script
# Handles switching between Web App and CLI modes

# 1. Explicitly check for 'web' mode
if [ "$1" = "web" ]; then
    shift
    echo "Starting InfraScan Web Server..."
    if [ $# -eq 0 ]; then
        exec gunicorn --bind 0.0.0.0:5000 --timeout 600 --workers 2 app:app
    else
        exec gunicorn "$@"
    fi
fi

# 2. Check for 'cli' mode (legacy compatibility or explicit choice)
if [ "$1" = "cli" ]; then
    shift
    if [ $# -eq 0 ] && [ -n "$BITBUCKET_CLONE_DIR" ]; then
        # No argv, and BITBUCKET_CLONE_DIR is only ever set inside Bitbucket
        # Pipelines: this is how `pipe: docker://soldevelo/infrascan:TAG`
        # invokes the container -- Bitbucket runs the image's own default CMD
        # (["cli"], see Dockerfile) feeding the pipe's declared `variables:`
        # as env vars only, never argv. Build the cli.py call from those
        # instead of calling cli.py with bare argparse defaults, which would
        # ignore the variables entirely and scan the wrong path. Outside
        # Bitbucket (BITBUCKET_CLONE_DIR unset), a bare zero-arg invocation
        # behaves exactly as before.
        exec /opt/infrascan/pipe/pipe.sh
    fi
    exec python /opt/infrascan/cli.py "$@"
fi

# 2b. Explicit 'pipe' mode -- same env-var-to-argv translation as above, for
# local testing without needing BITBUCKET_CLONE_DIR set.
if [ "$1" = "pipe" ]; then
    shift
    exec /opt/infrascan/pipe/pipe.sh "$@"
fi

# 3. Check if the command is an existing system command (like bash, sh, ls)
if command -v "$1" >/dev/null 2>&1; then
    exec "$@"
fi

# 4. Default: Run as a CLI tool
# This handles cases like 'docker run ... --scanner ...' or just 'docker run ...'
# if CMD is set to something other than 'web' or 'cli' or a system command.
if [ $# -eq 0 ] && [ -n "$BITBUCKET_CLONE_DIR" ]; then
    exec /opt/infrascan/pipe/pipe.sh
fi
echo "Running InfraScan CLI..."
exec python /opt/infrascan/cli.py "$@"
