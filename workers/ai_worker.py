import asyncio
import os

from workers.worker import DistributedWorker


async def main():
    worker = DistributedWorker(
        worker_id=os.getenv("ARCHAI_WORKER_ID", "ai-worker"),
        capabilities=["ai"],
    )
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
