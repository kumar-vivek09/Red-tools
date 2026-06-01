#!/usr/bin/env python
"""Test QueueManager fix for redis hset() compatibility."""

import json
from services.queue import QueueManager

# Test 1: Import and instantiate
qm = QueueManager()
print("✓ QueueManager imported and instantiated successfully")

# Test 2: Verify _normalize_job works
job = qm._normalize_job("test-job-1", {"queue": "test"})
print(f"✓ _normalize_job works: {job['job_id']}")

# Test 3: Verify set_job accepts correct parameters
result = qm.set_job("test-job-1", {"queue": "test"})
print(f"✓ set_job works: stored job {result['job_id']}")

# Test 4: Verify get_job retrieves the job
retrieved = qm.get_job("test-job-1")
print(f"✓ get_job works: retrieved job {retrieved['job_id']}")

# Test 5: Verify register_worker works
worker = qm.register_worker("test-worker", capabilities=["recon"])
print(f"✓ register_worker works: registered {worker['worker_id']}")

# Test 6: Verify heartbeat works
hb = qm.worker_heartbeat("test-worker")
print(f"✓ worker_heartbeat works: heartbeat for {hb['worker_id']}")

# Test 7: Verify list_workers works
workers = qm.list_workers()
print(f"✓ list_workers works: found {len(workers)} workers")

print("\n✅ All validation tests passed!")
