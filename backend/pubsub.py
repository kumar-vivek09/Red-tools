"""Pub/sub helpers for Redis-backed telemetry and graph streaming."""

import asyncio


class PubSubBridge:
    def __init__(self, queue_manager):
        self.queue_manager = queue_manager

    async def publish(self, channel, payload):
        await self.queue_manager.publish_async(channel, payload)

    async def subscribe(self, channel):
        async for event in self.queue_manager.subscribe(channel):
            yield event

    async def publish_with_retry(self, channel, payload, retries=3):
        last_error = None
        for _ in range(retries):
            try:
                await self.publish(channel, payload)
                return True
            except Exception as exc:
                last_error = exc
                await asyncio.sleep(0.5)
        if last_error:
            raise last_error
        return False
