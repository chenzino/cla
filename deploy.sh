#!/bin/bash
# deploy.sh - Safe deployment with syntax check and health verification
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_FILE="$SCRIPT_DIR/server.js"
HTML_FILE="$SCRIPT_DIR/public/index.html"
URL="http://localhost:3000"
MAX_RETRIES=5

echo "=== Deploy Check ==="

# 1. Syntax check server.js
echo "[1/5] Checking server.js syntax..."
node --check "$SERVER_FILE"
echo "  ✓ server.js syntax OK"

# 2. Check HTML isn't empty/broken (basic sanity)
echo "[2/5] Checking index.html size..."
HTML_SIZE=$(stat -c%s "$HTML_FILE")
if [ "$HTML_SIZE" -lt 10000 ]; then
  echo "  ✗ ERROR: index.html is suspiciously small ($HTML_SIZE bytes). Aborting."
  exit 1
fi
SCRIPT_OPENS=$(grep -c '<script' "$HTML_FILE" || true)
SCRIPT_CLOSES=$(grep -c '</script>' "$HTML_FILE" || true)
if [ "$SCRIPT_OPENS" -ne "$SCRIPT_CLOSES" ]; then
  echo "  ✗ WARNING: Mismatched script tags (open: $SCRIPT_OPENS, close: $SCRIPT_CLOSES)"
  exit 1
fi
echo "  ✓ index.html OK ($HTML_SIZE bytes)"

# 3. JS syntax check inside HTML script blocks
echo "[3/5] Checking embedded JS syntax..."
node "$SCRIPT_DIR/check-syntax.js"

# 4. Restart via pm2
echo "[4/5] Restarting via pm2..."
pm2 restart cla --update-env 2>/dev/null || pm2 start "$SCRIPT_DIR/ecosystem.config.js"
echo "  ✓ pm2 restarted"

# 5. Health check
echo "[5/5] Health check..."
for i in $(seq 1 $MAX_RETRIES); do
  sleep 1
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null || echo "000")
  if [ "$HTTP_CODE" = "200" ]; then
    echo "  ✓ Server responding 200 OK"
    echo ""
    echo "=== Deploy SUCCESS ==="
    exit 0
  fi
  echo "  Attempt $i/$MAX_RETRIES: HTTP $HTTP_CODE"
done

echo "  ✗ ERROR: Server not responding after $MAX_RETRIES attempts"
echo "  Checking logs..."
pm2 logs cla --nostream --lines 10
echo ""
echo "=== Deploy FAILED ==="
exit 1
