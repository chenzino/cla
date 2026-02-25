#!/bin/bash
# Auto-pull from GitHub and restart server if changes detected
cd /home/ubuntu/cla

# Fetch latest
git fetch origin main 2>/dev/null

# Check if there are changes
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" != "$REMOTE" ]; then
  echo "$(date): Changes detected, pulling..."
  git pull origin main --ff-only 2>&1

  # Reinstall deps if package.json changed
  if git diff HEAD~1 --name-only | grep -q "package.json"; then
    npm install 2>&1
  fi

  # Restart server
  pkill -f "node server.js" 2>/dev/null
  sleep 1
  cd /home/ubuntu/cla && node server.js > /tmp/server.log 2>&1 &
  disown
  echo "$(date): Server restarted with new changes"
fi
