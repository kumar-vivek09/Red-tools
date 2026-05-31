"""Async recon service wrappers preserving existing engine behavior."""

import asyncio

from core.orchestrator import Orchestrator


class ReconService:
    """Preserve existing orchestration flow while exposing a modular service API."""

    def __init__(self, scan_level=1):
        self.scan_level = scan_level

    async def scan_async(self, target):
        orchestrator = Orchestrator(self.scan_level)
        return await orchestrator.run(target)

    def scan_sync(self, target):
        try:
            return asyncio.run(self.scan_async(target))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(self.scan_async(target))
            finally:
                loop.close()
