import hashlib
from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="SecurityCheck")


class CheckRequest(BaseModel):
    content: str


class CheckResponse(BaseModel):
    allowed: bool
    reason: str = ""
    sechash: str = ""


def _wall():
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")


MALICIOUS_MARKER = "1234123423123412342134324"


@app.post("/check", response_model=CheckResponse)
def check(req: CheckRequest):
    if MALICIOUS_MARKER in req.content:
        print(f"[SCANNER {_wall()}] event=scan_rejected  content_len={len(req.content)}")
        return CheckResponse(allowed=False, reason="malicious content detected")
    sechash = hashlib.sha256(req.content.encode("utf-8")).hexdigest()
    print(f"[SCANNER {_wall()}] event=seal_computed  content_len={len(req.content)}  sechash={sechash[:16]}")
    return CheckResponse(allowed=True, sechash=sechash)
