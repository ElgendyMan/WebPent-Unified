"""Minimal deterministic OpenAI-compatible chat endpoint for local reproduction.

WP-J (Dispatch #009-A): the lab P7 ran with a configured LLM. This server
stands in for that endpoint so the exact CLI command shape can be replayed
locally without external services or credentials. It returns a fixed,
valid chat-completion envelope with deterministic content; the hunter's
planner treats unusable plans as an advisory failure and falls back to the
governed candidate catalog — itself a documented, audited path.
"""
from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PORT = 11434
HITS = {"chat": 0}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:  # quiet
        pass

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"models": [{"name": "repro-fake"}]}).encode())

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b"{}"
        try:
            json.loads(body or b"{}")
        except Exception:
            pass
        HITS["chat"] += 1
        payload = {
            "id": "chatcmpl-repro-%d" % HITS["chat"],
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "repro-fake",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "{}"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 1,
                "total_tokens": 11,
            },
        }
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"fake llm on 127.0.0.1:{PORT}", flush=True)
    server.serve_forever()
