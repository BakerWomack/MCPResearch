import os
import time

import httpx

BLOB_URL = os.environ.get("BLOB_STORAGE_URL", "http://cloud:9000").rstrip("/")

_client = httpx.AsyncClient(base_url=BLOB_URL, timeout=30.0)


async def put_blob(key: str, data: bytes) -> float:
    """Store blob; return object mtime from storage (for secure-timestamp sealing)."""
    t0 = time.perf_counter()
    r = await _client.put(f"/object/{key}", content=data)
    r.raise_for_status()
    j = r.json()
    mtime = float(j.get("mtime", 0))
    elapsed = time.perf_counter() - t0
    print(
        f"  [cloud] PUT /object/{key}: {elapsed:.3f}s  status={r.status_code}  mtime={mtime}"
    )
    return mtime


async def head_blob_mtime(key: str) -> float:
    """Current blob mtime from storage (HEAD)."""
    t0 = time.perf_counter()
    r = await _client.head(f"/object/{key}")
    r.raise_for_status()
    mt = float(r.headers.get("X-Blob-Mtime", "0"))
    elapsed = time.perf_counter() - t0
    print(f"  [cloud] HEAD /object/{key}: {elapsed:.3f}s  mtime={mt}")
    return mt


async def get_blob(key: str) -> bytes:
    t0 = time.perf_counter()
    r = await _client.get(f"/object/{key}")
    r.raise_for_status()
    elapsed = time.perf_counter() - t0
    print(f"  [cloud] GET /object/{key}: {elapsed:.3f}s  status={r.status_code}")
    return r.content
