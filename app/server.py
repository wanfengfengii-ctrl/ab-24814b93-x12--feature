"""HTTP API for X12 envelope auditing.

Endpoints
---------
POST /api/x12/audit
    Accepts an ``application/octet-stream`` body of up to 2 MiB containing a
    raw ASCII X12 message.

    Success (200)::

        {
          "interchange_control_number": "000000001",
          "group_count": 1,
          "transaction_count": 2,
          "sha256": "..."
        }

    Failure (4xx)::

        {
          "error": {
            "code": "SEGMENT_COUNT_MISMATCH",
            "message": "...",
            "segment": 7
          }
        }

GET /health
    Liveness/readiness probe.  Returns ``{"status": "ok"}`` with 200 once the
    HTTP server is accepting connections.
"""

from __future__ import annotations

import json
import logging
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .audit import MAX_MESSAGE_BYTES, EnvelopeError, audit

AUDIT_PATH = "/api/x12/audit"
HEALTH_PATH = "/health"

logger = logging.getLogger("x12-audit")

# Error codes that describe transport-level problems rather than an
# (otherwise readable) envelope; these map to 400.  Every other envelope
# violation maps to 422 Unprocessable Entity.
_BAD_REQUEST_CODES = frozenset({"EMPTY_MESSAGE", "NON_ASCII"})


def _status_for(code: str) -> int:
    if code == "MESSAGE_TOO_LARGE":
        return HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    if code in _BAD_REQUEST_CODES:
        return HTTPStatus.BAD_REQUEST
    return HTTPStatus.UNPROCESSABLE_ENTITY


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "X12Audit/1.0"
    protocol_version = "HTTP/1.1"

    # Maximum amount of an over-long request body to drain so that the
    # error response can still be delivered (bounds memory/CPU abuse from
    # a huge Content-Length).
    _DRAIN_CAP = MAX_MESSAGE_BYTES + 64 * 1024

    def _drain(self, length: int) -> bool:
        """Consume and discard up to ``length`` bytes of the request body.

        Returns True when the entire declared body was consumed, in which
        case the connection can be kept alive.
        """
        remaining = min(length, self._DRAIN_CAP)
        while remaining:
            chunk = self.rfile.read(min(64 * 1024, remaining))
            if not chunk:
                return False
            remaining -= len(chunk)
        return length <= self._DRAIN_CAP

    def _send_json(
        self, status: int, payload: dict, *, close: bool = False
    ) -> None:
        body = json.dumps(payload).encode("ascii")
        if close:
            self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        if self.path.split("?", 1)[0] == HEALTH_PATH:
            self._send_json(HTTPStatus.OK, {"status": "ok"})
        else:
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"error": {"code": "NOT_FOUND", "message": "unknown path"}},
            )

    def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
        if self.path.split("?", 1)[0] != AUDIT_PATH:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            keep_alive = length >= 0 and self._drain(length)
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"error": {"code": "NOT_FOUND", "message": "unknown path"}},
                close=not keep_alive,
            )
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0:
            self._send_json(
                HTTPStatus.LENGTH_REQUIRED,
                {
                    "error": {
                        "code": "BAD_CONTENT_LENGTH",
                        "message": "a valid Content-Length header is required",
                    }
                },
                close=True,
            )
            return

        content_type = self.headers.get("Content-Type", "")
        if content_type.split(";", 1)[0].strip().lower() != (
            "application/octet-stream"
        ):
            keep_alive = self._drain(length)
            self._send_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {
                    "error": {
                        "code": "UNSUPPORTED_MEDIA_TYPE",
                        "message": "Content-Type must be application/octet-stream",
                    }
                },
                close=not keep_alive,
            )
            return

        if length > MAX_MESSAGE_BYTES:
            # Drain what we are willing to read so the client receives the
            # 413; anything beyond the drain cap forces connection teardown.
            keep_alive = self._drain(length)
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {
                    "error": {
                        "code": "MESSAGE_TOO_LARGE",
                        "message": f"message exceeds {MAX_MESSAGE_BYTES} bytes",
                        "segment": 1,
                    }
                },
                close=not keep_alive,
            )
            return

        raw = self.rfile.read(length) if length else b""
        try:
            result = audit(raw)
        except EnvelopeError as exc:
            logger.info("audit failed: %s at segment %s", exc.code, exc.segment)
            self._send_json(
                _status_for(exc.code),
                {
                    "error": {
                        "code": exc.code,
                        "message": str(exc),
                        "segment": exc.segment,
                    }
                },
            )
            return

        self._send_json(
            HTTPStatus.OK,
            {
                "interchange_control_number": result.interchange_control_number,
                "group_count": result.group_count,
                "transaction_count": result.transaction_count,
                "sha256": result.sha256,
            },
        )

    def log_message(self, fmt: str, *args: object) -> None:
        logger.debug(fmt, *args)


def create_server(host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), AuditHandler)
    logger.info("listening on http://%s:%s", host, port)
    return server


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    server = create_server(host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
