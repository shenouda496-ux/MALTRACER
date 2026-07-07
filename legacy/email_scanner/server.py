"""
email_scanner/server.py
────────────────────────
GET  /events  → بيرجع الإيميلات + الـ contained IDs
POST /action  → بيعمل contain على إيميل
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

_email_events:  list = []
_email_lock     = threading.Lock()
_contained_ids: set  = set()
_gmail_service  = None

PORT = 7475


def set_service(service):
    global _gmail_service
    _gmail_service = service


def push_event(event: dict):
    with _email_lock:
        _email_events.append(event)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def do_GET(self):
        if self.path == "/events":
            with _email_lock:
                payload = json.dumps({
                    "events":    _email_events,
                    "contained": list(_contained_ids)
                }, default=str)
            data = payload.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path == "/action":
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
            msg_id = body.get("message_id")
            level  = body.get("level", "MEDIUM")

            result = {"ok": False, "msg": "No service"}

            if _gmail_service and msg_id:
                from email_scanner.actions import contain_email
                with _email_lock:
                    ev = next((e for e in _email_events if e.get("gmail_id") == msg_id), {})
                actions = contain_email(_gmail_service, msg_id, ev, level)
                _contained_ids.add(msg_id)
                result = {"ok": True, "actions": actions}
                print(f"[EmailServer] Action executed: {actions}")

            data = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404); self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


def start_server():
    server = HTTPServer(("127.0.0.1", PORT), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True, name="email-server")
    t.start()
    print(f"[EmailServer] http://127.0.0.1:{PORT}/events")
    return server
