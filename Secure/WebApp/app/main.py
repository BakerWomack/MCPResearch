import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from database import Base, SessionLocal, engine
from models import Client, Document
from app.cloud import get_blob, head_blob_mtime, put_blob
from app import mcp_client
from app.util import wall_clock_ms
from app.workflow_service import run_document_workflow, upload_kind_lower

app = FastAPI()

Base.metadata.create_all(bind=engine)


def _migrate_documents():
    """Add columns to existing SQLite documents table (idempotent)."""
    stmts = [
        "ALTER TABLE documents ADD COLUMN upload_kind VARCHAR",
        "ALTER TABLE documents ADD COLUMN seal_mtime REAL",
    ]
    with engine.begin() as conn:
        for sql in stmts:
            try:
                conn.execute(text(sql))
            except OperationalError:
                pass


_migrate_documents()


def _create_document_record(
    *,
    key: str,
    safe: bool,
    sechash: str | None,
    upload_kind: str,
    seal_mtime: float | None,
):
    db = SessionLocal()
    try:
        doc = Document(
            blob_key=key,
            safe=safe,
            sechash=sechash,
            upload_kind=upload_kind,
            seal_mtime=seal_mtime,
            checked_at=datetime.now(timezone.utc) if safe else None,
        )
        db.add(doc)
        db.commit()
        db.refresh(doc)
        return doc
    finally:
        db.close()


@app.post("/api/upload/vulnerable")
async def upload_document(file: UploadFile = File(...)):
    """Store blob only; scan and hash-seal run at workflow time, same as baseline."""
    data = await file.read()
    key = uuid.uuid4().hex + Path(file.filename or "").suffix
    await put_blob(key, data)
    doc = _create_document_record(
        key=key,
        safe=False,
        sechash=None,
        upload_kind="secure",
        seal_mtime=None,
    )
    return {
        "filename": file.filename,
        "saved_as": key,
        "document_id": doc.id,
        "upload_kind": "secure",
    }


@app.get("/api/documents/{doc_id}/safety")
def get_safety(doc_id: int):
    db = SessionLocal()
    try:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            raise HTTPException(404, "not found")
        return {
            "safe": doc.safe,
            "sechash": doc.sechash,
            "upload_kind": upload_kind_lower(doc),
            "seal_mtime": doc.seal_mtime,
        }
    finally:
        db.close()


@app.get("/api/documents/{doc_id}/blob-mtime")
async def get_blob_mtime(doc_id: int):
    """Current blob object mtime in storage (for secure-timestamp verification)."""
    db = SessionLocal()
    try:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            raise HTTPException(404, "not found")
        mt = await head_blob_mtime(doc.blob_key)
        return {"mtime": mt}
    finally:
        db.close()


@app.get("/api/documents/{doc_id}/content")
async def get_content(doc_id: int):
    db = SessionLocal()
    try:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            raise HTTPException(404, "not found")
        raw = await get_blob(doc.blob_key)
        content = raw.decode("utf-8", errors="replace")
        w = wall_clock_ms()
        print(
            f"[WORKFLOW {w}] doc={doc_id} event=mcp_content_read  "
            f"content_len={len(content)}  blob={doc.blob_key}"
        )
        return {"content": content}
    finally:
        db.close()


class WorkflowBody(BaseModel):
    document_id: int
    user_prompt: str


class ChatBody(BaseModel):
    user_prompt: str


@app.get("/api/clients")
def list_clients():
    """List CRM clients (same database as the MCP server when DATABASE_URL is shared)."""
    db = SessionLocal()
    try:
        rows = db.query(Client).order_by(Client.id).all()
        return [
            {"id": c.id, "name": c.name, "contact": c.contact}
            for c in rows
        ]
    finally:
        db.close()


@app.get("/")
def portal_index():
    portal = Path(__file__).with_name("static") / "portal.html"
    if not portal.exists():
        raise HTTPException(500, "portal page missing")
    return FileResponse(portal)


@app.post("/api/chat")
async def direct_chat(body: ChatBody):
    prompt = (body.user_prompt or "").strip()
    if not prompt:
        raise HTTPException(400, "user_prompt is required")

    reply = await mcp_client.run_chat(prompt)
    if reply.startswith("Error calling MCP"):
        raise HTTPException(502, reply)
    return {"reply": reply}


@app.post("/api/workflow")
async def workflow(body: WorkflowBody):
    reply = await run_document_workflow(body.document_id, body.user_prompt)
    return {"reply": reply}
