import asyncio

from backend.pubsub import PubSubBridge


class TelemetryRouter:
    def __init__(self, queue_manager, websocket_manager):
        self.pubsub = PubSubBridge(queue_manager)
        self.websocket_manager = websocket_manager
        self.channels = ["telemetry", "telemetry.recon", "worker.heartbeat", "graph.events"]
        self._tasks = []

    async def start(self):
        if self._tasks:
            return
        for channel in self.channels:
            self._tasks.append(asyncio.create_task(self._listen_channel(channel)))

    async def _listen_channel(self, channel):
        while True:
            try:
                async for event in self.pubsub.subscribe(channel):
                    await self._dispatch(event)
            except Exception:
                await asyncio.sleep(1)

    async def _dispatch(self, event):
        if not event:
            return

        event = dict(event)
        event.setdefault("source", "redis")

        try:
            await self.websocket_manager.broadcast(event)
        except Exception:
            pass


# Expose a simple factory for the FastAPI backend to avoid direct pubsub wiring.

def create_telemetry_router(queue_manager, websocket_manager):
    return TelemetryRouter(queue_manager, websocket_manager)
