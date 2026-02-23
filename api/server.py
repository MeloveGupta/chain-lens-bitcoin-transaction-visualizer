"""Bitcoin analyzer web server.

Pure Python HTTP server using http.server — no external dependencies.
Serves both the API endpoints and the frontend static files.
"""

import json
import os
import sys
import tempfile
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.analyzer import analyze_transaction
from core.block_parser import parse_blocks
from core.errors import AnalyzerError


FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}


class AnalyzerHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Bitcoin analyzer."""

    def log_message(self, format, *args):
        """Suppress default logging to stderr."""
        pass

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _send_file(self, filepath, content_type):
        try:
            with open(filepath, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404, "File not found")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # API endpoints
        if path == "/api/health":
            self._send_json({"ok": True})
            return

        # Serve frontend
        if path == "/" or path == "":
            path = "/index.html"

        filepath = os.path.join(FRONTEND_DIR, path.lstrip("/"))
        filepath = os.path.normpath(filepath)

        # Security: ensure we're within frontend dir
        if not filepath.startswith(os.path.normpath(FRONTEND_DIR)):
            self.send_error(403, "Forbidden")
            return

        ext = os.path.splitext(filepath)[1]
        content_type = CONTENT_TYPES.get(ext, "application/octet-stream")
        self._send_file(filepath, content_type)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        if path == "/api/analyze":
            self._handle_analyze(body)
        elif path == "/api/analyze_block":
            self._handle_analyze_block(body, self.headers)
        else:
            self.send_error(404, "Not found")

    def _handle_analyze(self, body):
        try:
            fixture = json.loads(body)
            result = analyze_transaction(fixture)
            self._send_json(result)
        except AnalyzerError as e:
            self._send_json(e.to_dict(), status=400)
        except json.JSONDecodeError as e:
            self._send_json({
                "ok": False,
                "error": {"code": "INVALID_JSON", "message": str(e)}
            }, status=400)
        except Exception as e:
            self._send_json({
                "ok": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)}
            }, status=500)

    def _parse_multipart(self, body, boundary):
        """Parse multipart form data and return dict of field_name -> bytes."""
        import email.parser
        parts = {}
        boundary_bytes = boundary.encode()
        chunks = body.split(b"--" + boundary_bytes)
        for chunk in chunks:
            if chunk in (b"", b"--\r\n", b"--\r\n", b"--"):
                continue
            chunk = chunk.strip(b"\r\n")
            if chunk == b"--":
                continue
            header_end = chunk.find(b"\r\n\r\n")
            if header_end == -1:
                continue
            header_part = chunk[:header_end].decode("utf-8", errors="replace")
            file_data = chunk[header_end + 4:]
            if file_data.endswith(b"\r\n"):
                file_data = file_data[:-2]
            # Extract field name
            for line in header_part.split("\r\n"):
                if "name=" in line.lower():
                    import re
                    m = re.search(r'name="([^"]*)"', line)
                    if m:
                        parts[m.group(1)] = file_data
                        break
        return parts

    def _handle_analyze_block(self, body, headers):
        """Handle block analysis via multipart form data or JSON with base64 data."""
        try:
            content_type = headers.get("Content-Type", "")

            if "multipart/form-data" in content_type:
                # Extract boundary
                boundary = None
                for part in content_type.split(";"):
                    part = part.strip()
                    if part.startswith("boundary="):
                        boundary = part[len("boundary="):]
                        break
                if not boundary:
                    raise ValueError("Missing multipart boundary")
                parts = self._parse_multipart(body, boundary)
                blk_data = parts.get("blk", b"")
                rev_data = parts.get("rev", b"")
                xor_data = parts.get("xor", b"")
            else:
                import base64
                data = json.loads(body)
                blk_data = base64.b64decode(data.get("blk_data", ""))
                rev_data = base64.b64decode(data.get("rev_data", ""))
                xor_data = base64.b64decode(data.get("xor_data", ""))

            blocks = parse_blocks(blk_data, rev_data, xor_data)
            self._send_json({"ok": True, "blocks": blocks})
        except AnalyzerError as e:
            self._send_json(e.to_dict(), status=400)
        except json.JSONDecodeError as e:
            self._send_json({
                "ok": False,
                "error": {"code": "INVALID_JSON", "message": str(e)}
            }, status=400)
        except Exception as e:
            self._send_json({
                "ok": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)}
            }, status=500)


def main():
    port = int(os.environ.get("PORT", 3000))
    server = HTTPServer(("0.0.0.0", port), AnalyzerHandler)
    url = f"http://127.0.0.1:{port}"
    print(url, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":
    main()
