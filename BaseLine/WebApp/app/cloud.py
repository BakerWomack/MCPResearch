import os
import time

import httpx

BLOB_URL = os.environ.get("BLOB_STORAGE_URL", "http://cloud:9000").rstrip("/")

_client = httpx.AsyncClient(base_url=BLOB_URL, timeout=30.0)


async def get_blob(key: str) -> bytes:
    t0 = time.perf_counter()
    r = await _client.get(f"/object/{key}")
    r.raise_for_status()
    elapsed = time.perf_counter() - t0
    print(f"  [cloud] GET /object/{key}: {elapsed:.3f}s  status={r.status_code}")
    return r.content
