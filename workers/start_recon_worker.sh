#!/bin/sh
set -eu
export PYTHONPATH="/app:${PYTHONPATH:-}"
python /app/workers/worker_heartbeat.py &
exec celery -A backend.tasks worker --loglevel=info --queues recon_queue --hostname=recon_worker@%h
