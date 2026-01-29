#!/bin/bash
set -e

# Force sync skills if explicitly requested (e.g., after image updates)
if [ "${FORCE_SKILLS_SYNC:-}" = "1" ]; then
    echo "[ENTRYPOINT] FORCE_SKILLS_SYNC=1 detected"
    if [ -d "/app/skills-default" ]; then
        echo "[ENTRYPOINT] Syncing built-in skills to /app/skills"
        cp -r /app/skills-default/* /app/skills/
        echo "[ENTRYPOINT] ✅ Skills sync completed"
        ls -la /app/skills/
    else
        echo "[ENTRYPOINT] ⚠️ No default skills found in image"
    fi

# Initialize skills directory if it's empty (first run or volume is empty)
elif [ "$(find /app/skills/foundation /app/skills/scenarios /app/skills/validation /app/skills/workflows -type f -name '*.md' 2>/dev/null | wc -l | tr -d ' ')" = "0" ]; then
    echo "[ENTRYPOINT] Skills directory is empty or new volume detected"
    echo "[ENTRYPOINT] Initializing with built-in skills..."

    # Copy built-in skills from the image to /app/skills
    # This assumes we copied skills to /app/skills-default during build
    if [ -d "/app/skills-default" ]; then
        cp -r /app/skills-default/* /app/skills/
        echo "[ENTRYPOINT] ✅ Skills initialized successfully"
        echo "[ENTRYPOINT] Skills directory contents:"
        ls -la /app/skills/
    else
        echo "[ENTRYPOINT] ⚠️ No default skills found in image"
    fi
else
    echo "[ENTRYPOINT] Skills directory already initialized"
    echo "[ENTRYPOINT] Found existing skills:"
    ls -la /app/skills/
fi

# Run the main application
exec python /app/src/main.py
