# gunicorn.conf.py
import multiprocessing

# Network binding
bind = "127.0.0.1:8000"

# Process management
# Formula: (2 x number of cores) + 1
workers = (multiprocessing.cpu_count() * 2) + 1
worker_class = "gevent"  # Recommended for handling concurrent long-polling or async crypto requests
worker_connections = 1000

# Logging
accesslog = "/var/log/veritas/access.log"
errorlog = "/var/log/veritas/error.log"
loglevel = "info"

# Security & Performance
timeout = 60  # Give cryptographic operations up to 60s to complete
keepalive = 2
max_requests = 1200  # Automatically restart workers after X requests to prevent memory leaks
max_requests_jitter = 50