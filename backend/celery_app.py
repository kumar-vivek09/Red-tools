import os

from celery import Celery
from kombu import Queue

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "archai",
    broker=redis_url,
    backend=redis_url,
    include=["backend.tasks"],
)

celery_app.conf.task_default_queue = "default"
celery_app.conf.task_queues = (
    Queue("recon_queue"),
    Queue("malware_queue"),
    Queue("sandbox_queue"),
    Queue("ai_queue"),
)
celery_app.conf.task_routes = {
    "backend.tasks.dispatch_malware_analysis": {"queue": "malware_queue"},
    "backend.tasks.dispatch_sandbox_execution": {"queue": "sandbox_queue"},
    "backend.tasks.dispatch_ai_summary": {"queue": "ai_queue"},
}
celery_app.conf.worker_prefetch_multiplier = 1
celery_app.conf.task_acks_late = True
celery_app.conf.broker_transport_options = {"visibility_timeout": 3600}
