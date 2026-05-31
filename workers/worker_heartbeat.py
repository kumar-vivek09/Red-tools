import os
import time

from services.queue import QueueManager


def main():
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    worker_id = os.getenv("WORKER_ID") or os.getenv("ARCHAI_WORKER_ID") or "remote-worker"
    worker_role = os.getenv("WORKER_ROLE") or os.getenv("ARCHAI_WORKER_ROLE") or "recon"
    capabilities = os.getenv("ARCHAI_WORKER_CAPABILITIES", worker_role).split(",")
    capabilities = [cap.strip() for cap in capabilities if cap.strip()]

    queue_manager = QueueManager(redis_url=redis_url)
    queue_manager.register_worker(
        worker_id,
        capabilities=capabilities,
        metadata={
            "pid": os.getpid(),
            "worker_role": worker_role,
            "status": "online",
            "redis_url": redis_url,
        },
    )

    heartbeat_interval = int(os.getenv("WORKER_HEARTBEAT_INTERVAL", "15"))
    while True:
        queue_manager.worker_heartbeat(
            worker_id,
            metadata={
                "capabilities": capabilities,
                "worker_role": worker_role,
                "status": "online",
                "redis_url": redis_url,
            },
        )
        print(f"[heartbeat] worker={worker_id} role={worker_role} backend={queue_manager._backend()}")
        time.sleep(heartbeat_interval)


if __name__ == "__main__":
    main()
