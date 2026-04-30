"""
HTTP client for the MCP server (FastMCP over SSE).
"""

import ast
import json
import os
import re
import time

from app.util import wall_clock_ms

# --- MCP base URL ---

MCP_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:3000/sse")
if "/sse" not in MCP_URL:
    MCP_URL = MCP_URL.rstrip("/") + "/sse"


# --- unwrap FastMCP / tool result strings ---


def _unwrap_tool_output_repr(s: str) -> str:
    """
    FastMCP sometimes exposes tool results as str() like:
    chat_directOutput(result='Hello\\nWorld')
    Return only the inner string literal.
    """
    if not s or "result=" not in s:
        return s
    t = s.strip().rstrip(",").strip()
    m = re.match(r"^[\w]+\s*\(\s*result\s*=\s*(.+)\)\s*$", t, re.DOTALL)
    if not m:
        return s
    raw = m.group(1).strip()
    try:
        out = ast.literal_eval(raw)
        if isinstance(out, str):
            return out
    except (ValueError, SyntaxError):
        pass
    return s


def _text_from_dict(d: dict) -> str:
    for key in ("result", "text", "content", "message"):
        v = d.get(key)
        if isinstance(v, str):
            return _unwrap_tool_output_repr(v)
    try:
        return _unwrap_tool_output_repr(json.dumps(d))
    except (TypeError, ValueError):
        return _unwrap_tool_output_repr(str(d))


def _text_from_result(result) -> str:
    if hasattr(result, "data") and result.data is not None:
        d = result.data
        if isinstance(d, str):
            return _unwrap_tool_output_repr(d)
        if isinstance(d, dict):
            return _text_from_dict(d)
        try:
            return _unwrap_tool_output_repr(json.dumps(d))
        except (TypeError, ValueError):
            return _unwrap_tool_output_repr(str(d))

    if getattr(result, "content", None):
        parts = [getattr(b, "text", "") for b in result.content if hasattr(b, "text")]
        joined = "\n".join(parts)
        if joined:
            return _unwrap_tool_output_repr(joined)

    return _unwrap_tool_output_repr(str(result))


# --- one MCP tool call over SSE ---


async def _call(tool: str, args: dict) -> str:
    from fastmcp import Client

    doc_id = args.get("document_id", "?")
    t0 = time.perf_counter()
    w = wall_clock_ms()
    print(f"[WORKFLOW {w}] doc={doc_id} event=mcp_sse_connect_start")

    async with Client(MCP_URL) as client:
        connect_time = time.perf_counter() - t0
        w = wall_clock_ms()
        print(f"[WORKFLOW {w}] doc={doc_id} event=mcp_sse_connected  connect_time={connect_time:.4f}s")

        t1 = time.perf_counter()
        res = await client.call_tool(tool, args, raise_on_error=False)
        w = wall_clock_ms()
        tool_time = time.perf_counter() - t1
        total = time.perf_counter() - t0
        print(
            f"[WORKFLOW {w}] doc={doc_id} event=mcp_tool_call_done  tool={tool}  "
            f"tool_time={tool_time:.4f}s  total={total:.4f}s"
        )
        return _text_from_result(res)


async def run_workflow(document_id: int, user_prompt: str) -> str:
    try:
        text = await _call("run_workflow", {"document_id": document_id, "user_prompt": user_prompt})
        return text or "(No response)"
    except Exception as e:
        return f"Error calling MCP server: {e}"


async def run_chat(user_prompt: str) -> str:
    try:
        text = await _call("chat_direct", {"user_prompt": user_prompt})
        return text or "(No response)"
    except Exception as e:
        return f"Error calling MCP server: {e}"
