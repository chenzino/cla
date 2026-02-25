#!/bin/bash
# Claude Code session monitor - runs in background, updates status.json
# Checks session health, tracks uptime, detects limit hits

STATUS_FILE="/home/ubuntu/cla/data/status.json"
MESSAGES_FILE="/home/ubuntu/cla/data/messages.json"
SESSION_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
METRICS_FILE="/home/ubuntu/cla/data/metrics.json"

# Init metrics
if [ ! -f "$METRICS_FILE" ]; then
  echo '{"totalSessions":0,"totalUptime":0,"limitHits":[],"history":[]}' > "$METRICS_FILE"
fi

update_status() {
  local status="$1"
  local notes="$2"
  local limit_hit="${3:-false}"
  local reset_time="${4:-null}"

  # Check if claude process is running
  local claude_pid=$(pgrep -f "claude" | head -1)
  local claude_running="false"
  if [ -n "$claude_pid" ]; then
    claude_running="true"
  fi

  # Calculate uptime
  local start_epoch=$(date -d "$SESSION_START" +%s 2>/dev/null || echo 0)
  local now_epoch=$(date +%s)
  local uptime_seconds=$((now_epoch - start_epoch))
  local uptime_hours=$((uptime_seconds / 3600))
  local uptime_mins=$(( (uptime_seconds % 3600) / 60 ))
  local uptime_str="${uptime_hours}h ${uptime_mins}m"

  # Check server health
  local server_status=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3000/ 2>/dev/null)

  # Check tunnel health
  local tunnel_pid=$(pgrep -f "cloudflared" | head -1)
  local tunnel_running="false"
  if [ -n "$tunnel_pid" ]; then
    tunnel_running="true"
  fi

  # Read existing logs
  local existing_logs="[]"
  if [ -f "$STATUS_FILE" ]; then
    existing_logs=$(python3 -c "
import json,sys
try:
    d=json.load(open('$STATUS_FILE'))
    print(json.dumps(d.get('logs',[])))
except:
    print('[]')
" 2>/dev/null)
  fi

  python3 -c "
import json
from datetime import datetime, timezone

logs = json.loads('''$existing_logs''')

# Keep last 200 logs
logs = logs[-200:]

status = {
    'usage': {
        'status': '$status',
        'limitHit': $limit_hit,
        'limitResetTime': $reset_time,
        'lastUpdated': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'sessionStarted': '$SESSION_START',
        'notes': '''$notes''',
        'uptime': '$uptime_str',
        'health': {
            'server': '$server_status' == '200',
            'tunnel': $tunnel_running,
            'claude': $claude_running
        }
    },
    'logs': logs
}
with open('$STATUS_FILE', 'w') as f:
    json.dump(status, f, indent=2)
" 2>/dev/null
}

add_log() {
  local log_type="$1"
  local message="$2"

  if [ -f "$STATUS_FILE" ]; then
    python3 -c "
import json
from datetime import datetime, timezone

with open('$STATUS_FILE') as f:
    data = json.load(f)

data['logs'].append({
    'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    'type': '$log_type',
    'message': '''$message'''
})
data['logs'] = data['logs'][-200:]

with open('$STATUS_FILE', 'w') as f:
    json.dump(data, f, indent=2)
" 2>/dev/null
  fi
}

check_for_messages() {
  if [ -f "$MESSAGES_FILE" ]; then
    local unread=$(python3 -c "
import json
msgs = json.load(open('$MESSAGES_FILE'))
unread = [m for m in msgs if not m.get('read', False)]
if unread:
    print(unread[-1]['message'])
" 2>/dev/null)
    if [ -n "$unread" ]; then
      echo "$unread"
    fi
  fi
}

# Initial status update
update_status "active" "Monitor daemon started. Tracking session health."
add_log "system" "Monitor daemon started - tracking uptime, health, and usage"

# Main loop
while true; do
  # Check Claude process
  claude_running=$(pgrep -f "claude" | grep -v "pgrep" | head -1)

  # Check for usage limit indicators in recent claude output
  # Claude Code prints warnings to stderr when approaching limits
  limit_indicator=""
  if [ -f /tmp/claude-session.log ]; then
    limit_indicator=$(tail -50 /tmp/claude-session.log 2>/dev/null | grep -i "rate limit\|usage limit\|limit reached\|try again" | tail -1)
  fi

  if [ -n "$limit_indicator" ]; then
    # Estimate reset time (typically 5 hours from limit hit)
    reset_time=$(date -u -d "+5 hours" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)
    update_status "limited" "Usage limit hit. Waiting for reset." "True" "\"$reset_time\""
    add_log "error" "Usage limit detected: $limit_indicator"
  elif [ -n "$claude_running" ]; then
    update_status "active" "Claude Code session active and running."
  else
    update_status "idle" "Claude Code process not detected. Session may be between prompts."
  fi

  # Check for unread messages every cycle
  msg=$(check_for_messages)
  if [ -n "$msg" ]; then
    add_log "system" "Unread message from user: $msg"
    # Mark messages as read
    python3 -c "
import json
msgs = json.load(open('$MESSAGES_FILE'))
for m in msgs:
    m['read'] = True
json.dump(msgs, open('$MESSAGES_FILE', 'w'), indent=2)
" 2>/dev/null
  fi

  sleep 30
done
