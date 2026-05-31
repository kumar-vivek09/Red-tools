#!/bin/sh
set -eu
export PYTHONPATH="/app:${PYTHONPATH:-}"
python /app/workers/worker_heartbeat.py &
exec celery -A backend.tasks worker --loglevel=info --queues ai_queue --hostname=ai_worker@%h
