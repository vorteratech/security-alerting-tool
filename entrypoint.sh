#!/bin/bash
set -e

# Auto-generate encryption key if not provided
if [ -z "$MASTER_ENCRYPTION_KEY" ]; then
    if [ -f "/app/data/.encryption_key" ]; then
        export MASTER_ENCRYPTION_KEY=$(cat /app/data/.encryption_key)
        echo "Loaded encryption key from storage"
    else
        export MASTER_ENCRYPTION_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
        echo "$MASTER_ENCRYPTION_KEY" > /app/data/.encryption_key
        chmod 600 /app/data/.encryption_key
        echo ""
        echo "============================================"
        echo "NEW ENCRYPTION KEY GENERATED"
        echo "============================================"
        echo "Key: $MASTER_ENCRYPTION_KEY"
        echo ""
        echo "Save this key! Add to environment variables"
        echo "to persist across container recreation."
        echo "============================================"
        echo ""
    fi
fi

echo "Starting Security Alerting Tool..."
echo "Health: http://localhost:8000/health"
echo "Docs:   http://localhost:8000/docs"

exec "$@"
