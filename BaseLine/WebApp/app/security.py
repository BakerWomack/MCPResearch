import os
import time

import httpx

SECURITY_URL = os.environ.get("SECURITY_CHECK_URL", "http://security-check:9001").rstrip("/")

_client = httpx.AsyncClient(base_url=SECURITY_URL, timeout=15.0)


async def check_content(text: str) -> tuple[bool, str]:
    t0 = time.perf_counter()
    try:
        print(f"  [security] POST /check  content_len={len(text)}")
        r = await _client.post("/check", json={"content": text})
        r.raise_for_status()
        data = r.json()
        elapsed = time.perf_counter() - t0
        allowed = data.get("allowed", False)
        print(
            f"  [security] response: {elapsed:.3f}s  status={r.status_code}  allowed={allowed}"
        )
        return allowed, data.get("reason", "")
    except Exception as e:
        elapsed = time.perf_counter() - t0
        print(f"  [security] ERROR after {elapsed:.3f}s: {e}")
        return False, str(e)
