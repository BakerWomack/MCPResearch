import time
from contextlib import contextmanager
from datetime import datetime, timezone


def wall_clock_ms() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")


@contextmanager
def db_span(doc_id, op: str):
    start_stamp = wall_clock_ms()
    deferred = callable(doc_id)
    if not deferred:
        print(f"[WORKFLOW {start_stamp}] doc={doc_id} event=db_{op}_start")
    t0 = time.perf_counter()
    try:
        yield
    finally:
        elapsed = time.perf_counter() - t0
        end_stamp = wall_clock_ms()
        resolved = doc_id() if deferred else doc_id
        if deferred:
            print(f"[WORKFLOW {start_stamp}] doc={resolved} event=db_{op}_start")
        print(
            f"[WORKFLOW {end_stamp}] doc={resolved} event=db_{op}_done  "
            f"db_time={elapsed:.4f}s"
        )
