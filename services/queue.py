"""Queue, registry, and telemetry support with Redis-backed persistence and in-memory fallback."""

import asyncio
import json
import logging
import os
import time
import uuid
from collections import defaultdict

logger = logging.getLogger(__name__)


class QueueManager:
    """Queue manager for recon, malware, sandbox, and AI tasks with Redis support."""

    def __init__(self, redis_url=None):
        self.redis_url = redis_url or os.getenv("REDIS_URL")
        self._memory = defaultdict(list)
        self._pubsub_memory = defaultdict(list)
        self._jobs = {}
        self._workers = {}

        self._redis_sync = None
        self._redis_async = None
        self._redis_enabled = False

        self._connect_redis()

    def _connect_redis(self):
        if not self.redis_url:
            logger.warning("REDIS_URL not configured; using in-memory fallback")
            self._redis_sync = None
            self._redis_async = None
            self._redis_enabled = False
            return

        self.reconnect_redis()

    def reconnect_redis(self):
        try:
            import redis
            import redis.asyncio as aioredis

            self._redis_sync = redis.Redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=3,
                retry_on_timeout=False,
                health_check_interval=30,
            )
            self._redis_async = aioredis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=3,
                retry_on_timeout=False,
                health_check_interval=30,
            )
            self._redis_sync.ping()
            self._redis_enabled = True
            logger.info("Redis connected at %s", self.redis_url)
            return True
        except Exception as exc:
            self._redis_sync = None
            self._redis_async = None
            self._redis_enabled = False
            logger.warning("Redis reconnect failed (%s); using in-memory fallback", exc)
            return False

    def ensure_redis_connection(self):
        if not self.redis_url:
            return False

        if self._redis_enabled and self._redis_sync is not None:
            try:
                self._redis_sync.ping()
                return True
            except Exception as exc:
                logger.warning("Redis ping failed, reconnecting (%s)", exc)
                self._redis_sync = None
                self._redis_async = None
                self._redis_enabled = False

        return self.reconnect_redis()

    def _backend(self):
        return "redis" if self._redis_enabled else "memory"

    def _now(self):
        return int(time.time())

    def _normalize_job(self, job_id, payload):
        if payload is None:
            return None

        if isinstance(payload, str):
            payload = json.loads(payload)

        job = dict(payload)
        job.setdefault("job_id", job_id)
        job.setdefault("status", "queued")
        job.setdefault("queue", job.get("queue") or "unknown")
        job.setdefault("created_at", self._now())
        job.setdefault("attempts", int(job.get("attempts", 0)))
        job.setdefault("retry_count", int(job.get("retry_count", 0)))
        job.setdefault("max_retries", int(job.get("max_retries", 3)))
        return job

    def enqueue(self, queue_name, payload):
        payload = self._normalize_job(payload.get("job_id") if isinstance(payload, dict) else None, payload)
        payload_json = json.dumps(payload)

        if self.ensure_redis_connection():
            self._redis_sync.rpush(queue_name, payload_json)
        else:
            self._memory[queue_name].append(payload_json)

        self.set_job(payload["job_id"], payload)
        return {"backend": self._backend(), "queue": queue_name}

    def enqueue_job(self, queue_name, payload):
        payload = dict(payload)
        payload.setdefault("job_id", uuid.uuid4().hex)
        payload.setdefault("queue", queue_name)
        payload.setdefault("status", "queued")
        payload.setdefault("attempts", 0)
        payload.setdefault("retry_count", 0)
        payload.setdefault("max_retries", 3)
        payload.setdefault("created_at", self._now())
        self.set_job(payload["job_id"], payload)
        self.enqueue(queue_name, payload)
        return payload

    async def enqueue_async(self, queue_name, payload):
        return self.enqueue_job(queue_name, payload)

    def dequeue(self, queue_name):
        if self.ensure_redis_connection():
            raw = self._redis_sync.lpop(queue_name)
            if raw is None:
                return None
            payload = self._normalize_job(None, raw)
        else:
            if not self._memory[queue_name]:
                return None
            payload = self._normalize_job(None, self._memory[queue_name].pop(0))

        if payload is None:
            return None

        payload["status"] = "running"
        payload["claimed_at"] = self._now()
        payload["worker_id"] = payload.get("worker_id")
        self.set_job(payload["job_id"], payload)
        return payload

    def claim_job(self, queue_name, worker_id):
        payload = self.dequeue(queue_name)
        if not payload:
            return None
        payload["worker_id"] = worker_id
        self.set_job(payload["job_id"], payload)
        return payload

    async def dequeue_async(self, queue_name):
        return self.dequeue(queue_name)

    def publish(self, channel, payload):
        payload_json = json.dumps(payload)

        if self.ensure_redis_connection():
            self._redis_sync.publish(channel, payload_json)
            return

        self._pubsub_memory[channel].append(payload_json)

    async def publish_async(self, channel, payload):
        self.publish(channel, payload)

    async def subscribe(self, channel):
        if self._redis_async is not None:
            while True:
                pubsub = self._redis_async.pubsub()
                await pubsub.subscribe(channel)
                try:
                    async for message in pubsub.listen():
                        if message.get("type") == "message":
                            yield json.loads(message.get("data"))
                except Exception:
                    await asyncio.sleep(1)
                    continue
            return

        while True:
            if self._pubsub_memory[channel]:
                payload = self._pubsub_memory[channel].pop(0)
                yield json.loads(payload)
            else:
                await asyncio.sleep(0.25)

    def queue_length(self, queue_name):
        if self.ensure_redis_connection():
            return self._redis_sync.llen(queue_name)
        return len(self._memory[queue_name])

    def register_worker(self, worker_id, capabilities=None, metadata=None):
        worker = {
            "worker_id": worker_id,
            "capabilities": capabilities or [],
            "metadata": metadata or {},
            "last_seen": self._now(),
        }
        self._workers[worker_id] = worker
        if self.ensure_redis_connection():
            self._redis_sync.hset("workers", mapping={worker_id: json.dumps(worker)})
        return worker

    def heartbeat(self, worker_id, metadata=None):
        worker = self._workers.get(worker_id)
        if worker is None:
            worker = self.register_worker(worker_id, metadata=metadata)

        worker["last_seen"] = self._now()
        if metadata:
            worker["metadata"] = metadata

        if self.ensure_redis_connection():
            self._redis_sync.hset("workers", mapping={worker_id: json.dumps(worker)})

        return worker

    def worker_heartbeat(self, worker_id, metadata=None):
        worker = self.heartbeat(worker_id, metadata=metadata)
        event = {
            "type": "worker_heartbeat",
            "worker_id": worker_id,
            "status": "online",
            "metadata": worker.get("metadata", {}),
            "last_seen": worker.get("last_seen"),
        }
        self.publish("telemetry", event)
        self.publish("worker.heartbeat", event)
        return worker

    def list_workers(self):
        if self.ensure_redis_connection():
            raw = self._redis_sync.hgetall("workers")
            workers = [json.loads(value) for value in raw.values()]
            return workers
        return list(self._workers.values())

    def set_job(self, job_id, payload):
        job = self._normalize_job(job_id, payload)
        self._jobs[job_id] = job
        if self.ensure_redis_connection():
            self._redis_sync.hset("jobs", mapping={job_id: json.dumps(job)})
        return job

    def get_job(self, job_id):
        if self.ensure_redis_connection():
            raw = self._redis_sync.hget("jobs", job_id)
            if raw is None:
                return self._jobs.get(job_id)
            return self._normalize_job(job_id, raw)
        return self._jobs.get(job_id)

    def persist_job_status(self, job_id, status=None, **updates):
        job = self.get_job(job_id) or {"job_id": job_id}
        if status is not None:
            job["status"] = status
        job.update(updates)
        job.setdefault("updated_at", self._now())
        return self.set_job(job_id, job)

    def update_job(self, job_id, **updates):
        job = self.get_job(job_id) or {}
        job.update(updates)
        return self.set_job(job_id, job)

    def retry_failed_job(self, queue_name, job_id, reason=None):
        job = self.get_job(job_id)
        if job is None:
            return None

        retry_count = int(job.get("retry_count", 0)) + 1
        job["retry_count"] = retry_count
        job["last_error"] = reason
        job["attempts"] = int(job.get("attempts", 0)) + 1

        if retry_count > int(job.get("max_retries", 3)):
            job["status"] = "failed"
            self.set_job(job_id, job)
            return job

        job["status"] = "queued"
        job["worker_id"] = None
        job["queued_at"] = self._now()
        self.set_job(job_id, job)
        self.enqueue(queue_name, job)
        return job

    def queue_metrics(self):
        return {
            "backend": self._backend(),
            "queues": {
                "recon_queue": self.queue_length("recon_queue"),
                "malware_queue": self.queue_length("malware_queue"),
                "sandbox_queue": self.queue_length("sandbox_queue"),
                "ai_queue": self.queue_length("ai_queue"),
            },
            "jobs": len(self._jobs),
            "workers": len(self.list_workers()),
        }
