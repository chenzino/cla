#!/bin/bash
# Helper to update the monitor status from Claude Code session
# Usage: ./update-status.sh "status" "notes" [limitHit] [limitResetTime]

STATUS_FILE="/home/ubuntu/cla/data/status.json"

STATUS=${1:-"active"}
NOTES=${2:-"Working..."}
LIMIT_HIT=${3:-false}
LIMIT_RESET=${4:-null}

# Read existing logs
EXISTING_LOGS=$(cat "$STATUS_FILE" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get('logs',[])))" 2>/dev/null || echo "[]")

# Create updated status
python3 -c "
import json, sys
from datetime import datetime

logs = json.loads('''$EXISTING_LOGS''')
logs.append({
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'type': 'system',
    'message': '''$NOTES'''
})

# Keep last 100 logs
logs = logs[-100:]

status = {
    'usage': {
        'status': '''$STATUS''',
        'limitHit': $LIMIT_HIT,
        'limitResetTime': $LIMIT_RESET,
        'lastUpdated': datetime.utcnow().isoformat() + 'Z',
        'sessionStarted': '$(cat $STATUS_FILE 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('usage',{}).get('sessionStarted',''))" 2>/dev/null || echo "")',
        'notes': '''$NOTES'''
    },
    'logs': logs
}
print(json.dumps(status, indent=2))
" > "$STATUS_FILE"
