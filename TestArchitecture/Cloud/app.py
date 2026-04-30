import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import Response

app = FastAPI()

ROOT = Path(os.environ["BLOB_ROOT"])
ROOT.mkdir(parents=True, exist_ok=True)


def _wall():
    """UTC time HH:MM:SS.mmm for cross-container logs."""
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]


def _safe_object_path(key: str) -> Path:
    safe = "".join(c for c in key if c.isalnum() or c in "-_.")
    if not safe or safe != key:
        raise HTTPException(status_code=400, detail="invalid key")
    return ROOT / safe


def _preview(data: bytes) -> str:
    return data[:80].decode("utf-8", errors="replace").replace("\n", "\\n")


# --- object API ---


@app.put("/object/{key}")
async def put_object(key: str, request: Request):
    body = await request.body()
    path = _safe_object_path(key)
    path.write_bytes(body)
    mtime = path.stat().st_mtime
    src = request.client.host if request.client else "?"
    pv = _preview(body)
    print(f"[BLOB {_wall()}] PUT {key}  src={src}  size={len(body)}  preview={pv!r}")
    return {"key": key, "size": len(body), "mtime": mtime}


@app.head("/object/{key}")
async def head_object(key: str, request: Request):
    """Return blob metadata without body (for timestamp sealing)."""
    path = _safe_object_path(key)
    if not path.exists():
        raise HTTPException(status_code=404, detail="not found")
    mtime = path.stat().st_mtime
    src = request.client.host if request.client else "?"
    print(f"[BLOB {_wall()}] HEAD {key}  src={src}  mtime={mtime}")
    return Response(headers={"X-Blob-Mtime": str(mtime)})


@app.get("/object/{key}")
async def get_object(key: str, request: Request):
    path = _safe_object_path(key)
    if not path.exists():
        raise HTTPException(status_code=404, detail="not found")
    data = path.read_bytes()
    src = request.client.host if request.client else "?"
    pv = _preview(data)
    print(f"[BLOB {_wall()}] GET {key}  src={src}  size={len(data)}  preview={pv!r}")
    return Response(content=data, media_type="application/octet-stream")


@app.delete("/object/{key}")
async def delete_object(key: str):
    path = _safe_object_path(key)
    if path.exists():
        path.unlink()
    return {"key": key, "deleted": True}
