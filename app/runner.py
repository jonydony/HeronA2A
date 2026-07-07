"""Execute a probe battery's HTTP call specs against a live agent.

Reads a probe-set JSON ({agent_name, base_url, probes:[{name, kind, capability,
call:{method,url,params,json,headers}, expected}]}) on stdin, executes each call,
and prints the same structure enriched with {status, response} per probe. This is
the SKILL.md-driven caller: each probe carries the exact shape derived from the
target's own SKILL.md, so Heron can exercise ANY agent, not just /api/send.
"""
from __future__ import annotations

import json
import sys

import httpx


def execute(probeset: dict, timeout: float = 30.0) -> dict:
    results = []
    with httpx.Client(timeout=timeout, follow_redirects=True) as c:
        for p in probeset.get("probes", []):
            call = p.get("call", {})
            method = (call.get("method") or "GET").upper()
            url = call.get("url")
            try:
                if method == "GET":
                    r = c.get(url, params=call.get("params"), headers=call.get("headers"))
                else:
                    r = c.request(method, url, params=call.get("params"),
                                  json=call.get("json"), headers=call.get("headers"))
                status, body = r.status_code, r.text[:600]
            except Exception as e:
                status, body = 0, f"error: {e}"
            results.append({**p, "status": status, "response": body})
    return {**probeset, "probes": results}


if __name__ == "__main__":
    print(json.dumps(execute(json.load(sys.stdin)), indent=2, ensure_ascii=False))
