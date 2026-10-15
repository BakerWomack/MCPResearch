import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from database import SessionLocal
from models import Client, Document
from app import mcp_client
from app.auth import (BLOB_PUBLIC_URL, UPLOAD_TOKEN_TTL_SECONDS,
                      check_password, issue_token, issue_upload_token,
                      require_auth)
from app.util import db_span
from app.workflow_service import run_document_workflow

app = FastAPI()


def _create_document_record(*, key: str, safe: bool, sechash: str | None):
    db = SessionLocal()
    try:
        doc = Document(
            blob_key=key,
            safe=safe,
            sechash=sechash,
            checked_at=datetime.now(timezone.utc) if safe else None,
        )
        with db_span(lambda: doc.id, "upload_insert"):
            db.add(doc)
            db.commit()
            db.refresh(doc)
        return doc
    finally:
        db.close()


class LoginBody(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def login(body: LoginBody):
    if not check_password(body.username, body.password):
        raise HTTPException(401, "invalid username or password")
    return {"access_token": issue_token(body.username), "token_type": "bearer"}


class UploadRequest(BaseModel):
    filename: str = "upload.csv"


@app.post("/api/upload/vulnerable", dependencies=[Depends(require_auth)])
def upload_document(body: UploadRequest):
    key = uuid.uuid4().hex + Path(body.filename or "").suffix
    doc = _create_document_record(key=key, safe=False, sechash=None)
    return {
        "filename": body.filename,
        "saved_as": key,
        "document_id": doc.id,
        "upload_url": f"{BLOB_PUBLIC_URL}/object/{key}",
        "upload_token": issue_upload_token(key),
        "expires_in": UPLOAD_TOKEN_TTL_SECONDS,
    }


def get_safety(doc_id: int):
    db = SessionLocal()
    try:
        with db_span(doc_id, "safety_lookup"):
            doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            raise HTTPException(404, "not found")
        return {"safe": doc.safe, "sechash": doc.sechash}
    finally:
        db.close()


def _history_json(turns) -> str:
    return json.dumps([{"role": t.role, "content": t.content} for t in turns])


class Turn(BaseModel):
    role: str
    content: str


class WorkflowBody(BaseModel):
    document_id: int
    user_prompt: str
    history: list[Turn] = Field(default_factory=list)


class ChatBody(BaseModel):
    user_prompt: str
    history: list[Turn] = Field(default_factory=list)


@app.get("/api/clients", dependencies=[Depends(require_auth)])
def list_clients():
    db = SessionLocal()
    try:
        with db_span(0, "clients_list"):
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


@app.post("/api/chat", dependencies=[Depends(require_auth)])
async def direct_chat(body: ChatBody):
    prompt = (body.user_prompt or "").strip()
    if not prompt:
        raise HTTPException(400, "user_prompt is required")

    reply = await mcp_client.run_chat(prompt, _history_json(body.history))
    if reply.startswith("Error calling MCP"):
        raise HTTPException(502, reply)
    return {"reply": reply}


@app.post("/api/workflow", dependencies=[Depends(require_auth)])
async def workflow(body: WorkflowBody):
    reply = await run_document_workflow(
        body.document_id, body.user_prompt, _history_json(body.history)
    )
    return {"reply": reply}
