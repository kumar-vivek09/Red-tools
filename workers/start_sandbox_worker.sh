#!/bin/sh
set -eu
export PYTHONPATH="/app:${PYTHONPATH:-}"
python /app/workers/worker_heartbeat.py &
exec celery -A backend.tasks worker --loglevel=info --queues sandbox_queue --hostname=sandbox_worker@%h
