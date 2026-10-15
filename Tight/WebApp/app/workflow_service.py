import time
from datetime import datetime, timezone

from fastapi import HTTPException

from database import SessionLocal
from models import Document
from app.cloud import get_blob
from app.security import check_content
from app import mcp_client
from app.util import db_span, wall_clock_ms


def _load_blob_key(doc_id: int) -> str:
    db = SessionLocal()
    try:
        with db_span(doc_id, "doc_lookup"):
            doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            raise HTTPException(404, "not found")
        return doc.blob_key
    finally:
        db.close()


async def _scan_and_mark_safe(doc_id: int, content: str, t0: float) -> None:
    w = wall_clock_ms
    t2 = time.perf_counter()
    allowed, reason = await check_content(content)
    print(
        f"[WORKFLOW {w()}] doc={doc_id} event=security_check_done  "
        f"elapsed={time.perf_counter()-t0:.4f}s  check_time={time.perf_counter()-t2:.4f}s  allowed={allowed}"
    )
    if not allowed:
        print(f"[WORKFLOW {w()}] doc={doc_id} event=blocked  elapsed={time.perf_counter()-t0:.4f}s")
        raise HTTPException(403, reason or "blocked")

    t3 = time.perf_counter()
    db = SessionLocal()
    try:
        with db_span(doc_id, "mark_safe"):
            d = db.query(Document).filter(Document.id == doc_id).first()
            if d:
                d.safe = True
                d.checked_at = datetime.now(timezone.utc)
                db.commit()
    finally:
        db.close()
    print(
        f"[WORKFLOW {w()}] doc={doc_id} event=marked_safe_in_db  "
        f"elapsed={time.perf_counter()-t0:.4f}s  db_write_time={time.perf_counter()-t3:.4f}s"
    )
    print(f"[WORKFLOW {w()}] doc={doc_id} event=vulnerability_window_open  elapsed={time.perf_counter()-t0:.4f}s")


async def run_document_workflow(document_id: int, user_prompt: str, history_json: str = "[]") -> str:
    t0 = time.perf_counter()
    w = wall_clock_ms
    print(f"[WORKFLOW {w()}] doc={document_id} event=workflow_start")

    blob_key = _load_blob_key(document_id)
    print(
        f"[WORKFLOW {w()}] doc={document_id} event=db_lookup_done  "
        f"elapsed={time.perf_counter()-t0:.4f}s  blob_key={blob_key}"
    )

    t1 = time.perf_counter()
    raw_blob = await get_blob(blob_key)
    content = raw_blob.decode("utf-8", errors="replace")[:100_000]
    print(
        f"[WORKFLOW {w()}] doc={document_id} event=blob_fetched_for_security_check  "
        f"elapsed={time.perf_counter()-t0:.4f}s  fetch_time={time.perf_counter()-t1:.4f}s  content_len={len(content)}"
    )

    await _scan_and_mark_safe(document_id, content, t0)

    t4 = time.perf_counter()
    print(f"[WORKFLOW {w()}] doc={document_id} event=mcp_call_start  elapsed={time.perf_counter()-t0:.4f}s")
    reply = await mcp_client.run_workflow(document_id, user_prompt, history_json)
    print(
        f"[WORKFLOW {w()}] doc={document_id} event=mcp_call_done  "
        f"elapsed={time.perf_counter()-t0:.4f}s  mcp_time={time.perf_counter()-t4:.4f}s"
    )
    if reply.startswith("Error calling MCP"):
        raise HTTPException(502, reply)
    return reply
