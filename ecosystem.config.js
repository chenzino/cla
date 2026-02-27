module.exports = {
  apps: [{
    name: 'cla',
    script: './server.js',
    cwd: '/home/ubuntu/cla',
    watch: ['server.js', 'public'],
    watch_delay: 1000,
    ignore_watch: ['node_modules', 'data', '.git', '*.log'],
    max_memory_restart: '300M',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    // Logging
    error_file: '/home/ubuntu/cla/logs/error.log',
    out_file: '/home/ubuntu/cla/logs/out.log',
    merge_logs: true,
    log_date_format: 'YYYY-MM-DD HH:mm:ss',
    // Auto-restart
    autorestart: true,
    max_restarts: 10,
    min_uptime: '5s',
    restart_delay: 1000,
  }]
};
