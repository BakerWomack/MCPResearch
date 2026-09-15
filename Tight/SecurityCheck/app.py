from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="SecurityCheck")


class CheckRequest(BaseModel):
    content: str


class CheckResponse(BaseModel):
    allowed: bool
    reason: str = ""


MALICIOUS_MARKER = "1234123423123412342134324"


@app.post("/check", response_model=CheckResponse)
def check(req: CheckRequest):
    print(req.content)
    if MALICIOUS_MARKER in req.content:
        return CheckResponse(allowed=False, reason="malicious content detected")
    return CheckResponse(allowed=True)
