"""
Document workflow: load blob, run security / integrity checks, then call MCP.
Separated from route definitions for easier reading.
"""

import time
from datetime import datetime, timezone

from fastapi import HTTPException

from database import SessionLocal
from models import Document
from app.cloud import get_blob
from app.security import check_content
from app import mcp_client
from app.util import wall_clock_ms


def upload_kind_lower(doc: Document) -> str:
    return (doc.upload_kind or "vulnerable").lower()



def _load_document_row(doc_id: int) -> tuple[Document, str, str, bool, str | None, float | None]:
    """Return doc row and fields needed for the workflow."""
    db = SessionLocal()
    try:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            raise HTTPException(404, "not found")
        kind = upload_kind_lower(doc)
        return (
            doc,
            doc.blob_key,
            kind,
            doc.safe,
            doc.sechash,
            doc.seal_mtime,
        )
    finally:
        db.close()


async def _scan_and_seal(
    doc_id: int,
    content: str,
    t0: float,
) -> None:
    """Scan content, then record the scanner's hash as the seal."""
    w = wall_clock_ms
    t2 = time.perf_counter()
    allowed, reason, sechash = await check_content(content)
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
        d = db.query(Document).filter(Document.id == doc_id).first()
        if d:
            d.safe = True
            d.checked_at = datetime.now(timezone.utc)
            d.sechash = sechash
            db.commit()
    finally:
        db.close()
    print(
        f"[WORKFLOW {w()}] doc={doc_id} event=marked_safe_in_db  "
        f"elapsed={time.perf_counter()-t0:.4f}s  db_write_time={time.perf_counter()-t3:.4f}s"
    )
    print(f"[WORKFLOW {w()}] doc={doc_id} event=vulnerability_window_open  elapsed={time.perf_counter()-t0:.4f}s")


async def run_document_workflow(document_id: int, user_prompt: str) -> str:
    """
    Full pipeline for POST /api/workflow.
    Returns assistant reply text. Raises HTTPException on HTTP-style errors.
    """
    t0 = time.perf_counter()
    w = wall_clock_ms
    print(f"[WORKFLOW {w()}] doc={document_id} event=workflow_start")

    _doc, blob_key, kind, _safe, _hash, _mtime = _load_document_row(document_id)
    print(
        f"[WORKFLOW {w()}] doc={document_id} event=db_lookup_done  "
        f"elapsed={time.perf_counter()-t0:.4f}s  kind={kind}  blob_key={blob_key}"
    )

    t1 = time.perf_counter()
    raw_blob = await get_blob(blob_key)
    content = raw_blob.decode("utf-8", errors="replace")[:100_000]
    print(
        f"[WORKFLOW {w()}] doc={document_id} event=blob_fetched_for_security_check  "
        f"elapsed={time.perf_counter()-t0:.4f}s  fetch_time={time.perf_counter()-t1:.4f}s  content_len={len(content)}"
    )

    await _scan_and_seal(document_id, content, t0)

    t4 = time.perf_counter()
    print(f"[WORKFLOW {w()}] doc={document_id} event=mcp_call_start  elapsed={time.perf_counter()-t0:.4f}s")
    reply = await mcp_client.run_workflow(document_id, user_prompt)
    print(
        f"[WORKFLOW {w()}] doc={document_id} event=mcp_call_done  "
        f"elapsed={time.perf_counter()-t0:.4f}s  mcp_time={time.perf_counter()-t4:.4f}s"
    )
    if reply.startswith("Error calling MCP"):
        raise HTTPException(502, reply)
    return reply
