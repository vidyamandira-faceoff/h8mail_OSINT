#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BreachHunter OSINT Web Application Server
Serves the modern frontend and provides REST API endpoints for OSINT breach hunting.
"""

import os
import sys
import json
import argparse
import mimetypes
import warnings
from urllib.parse import urlparse, parse_qs
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

# Suppress unverified TLS warnings from third-party APIs
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Ensure backend directory is in python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")

if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from services.hunter_service import HunterService
from h8mail.utils.version import __version__
from h8mail.utils.helpers import check_scylla_online

# Global service instance
hunter_service = HunterService()
CONFIG_FILE = os.path.join(CURRENT_DIR, "web_config.json")
HISTORY_FILE = os.path.join(CURRENT_DIR, "web_history.json")

# Load existing config if available
if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, "r") as f:
            saved_keys = json.load(f)
            hunter_service.set_api_keys(saved_keys)
    except Exception as e:
        print(f"[!] Warning: Could not read {CONFIG_FILE}: {e}")

# Session search history in-memory & persistent
search_history = []
if os.path.exists(HISTORY_FILE):
    try:
        with open(HISTORY_FILE, "r") as f:
            search_history = json.load(f)
    except Exception as e:
        print(f"[!] Warning: Could not read {HISTORY_FILE}: {e}")

def save_history():
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(search_history[-100:], f, indent=2)
    except Exception as e:
        print(f"[!] Warning: Could not save {HISTORY_FILE}: {e}")


class H8MailWebHandler(BaseHTTPRequestHandler):
    server_version = f"BreachHunter-Web/{__version__}"

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _send_json_response(self, data, status_code=200):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # --- API Routes ---
        if path == "/api/status":
            scylla_status = False
            try:
                scylla_status = check_scylla_online()
            except Exception:
                pass

            data = {
                "status": "online",
                "application": "BreachHunter OSINT",
                "version": __version__,
                "python_version": sys.version.split(" ")[0],
                "scylla_online": scylla_status,
                "endpoints": [
                    "/api/status",
                    "/api/search",
                    "/api/config",
                    "/api/history",
                    "/api/sample",
                ]
            }
            return self._send_json_response(data)

        elif path == "/api/config":
            # Mask keys for security
            masked = {}
            for k, v in hunter_service.api_keys.items():
                if v and len(str(v)) > 6:
                    masked[k] = str(v)[:3] + "..." + str(v)[-3:]
                elif v:
                    masked[k] = "******"
                else:
                    masked[k] = ""
            return self._send_json_response({"keys": masked})

        elif path == "/api/history":
            return self._send_json_response({"history": search_history[-100:]})

        elif path == "/api/sample":
            samples = {
                "emails": "test@example.com\nadmin@evilcorp.com\njohn.smith@gmail.com",
                "usernames": "admin\njohnsmith\ntestuser",
                "domains": "example.com\nevilcorp.com"
            }
            return self._send_json_response(samples)

        # --- Frontend Static Files ---
        if path == "/" or path == "/index.html":
            file_path = os.path.join(FRONTEND_DIR, "index.html")
        else:
            rel_path = path.lstrip("/")
            file_path = os.path.join(FRONTEND_DIR, rel_path)

        # Security check: ensure path is inside FRONTEND_DIR
        norm_file_path = os.path.abspath(file_path)
        norm_frontend = os.path.abspath(FRONTEND_DIR)
        if not norm_file_path.startswith(norm_frontend):
            self.send_error(403, "Forbidden")
            return

        if os.path.isfile(norm_file_path):
            mime_type, _ = mimetypes.guess_type(norm_file_path)
            if not mime_type:
                mime_type = "application/octet-stream"

            self.send_response(200)
            self.send_header("Content-Type", f"{mime_type}; charset=utf-8")
            self._send_cors_headers()
            self.end_headers()

            with open(norm_file_path, "rb") as f:
                self.wfile.write(f.read())
        else:
            # Fallback to index.html for SPA if file doesn't exist
            index_path = os.path.join(FRONTEND_DIR, "index.html")
            if os.path.exists(index_path):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self._send_cors_headers()
                self.end_headers()
                with open(index_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, f"File not found: {path}")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length)

        try:
            req_data = json.loads(post_body.decode("utf-8")) if post_body else {}
        except Exception:
            return self._send_json_response({"error": "Invalid JSON payload"}, 400)

        # --- POST /api/search ---
        if path == "/api/search":
            raw_input = req_data.get("raw_targets", "")
            query_type = req_data.get("query_type", "email")
            skip_defaults = bool(req_data.get("skip_defaults", False))
            include_sample_db = bool(req_data.get("include_sample_db", True))
            hide_passwords = bool(req_data.get("hide_passwords", False))
            custom_keys = req_data.get("api_keys", {})
            local_breach_files = req_data.get("local_breach_files", [])
            local_gzip_files = req_data.get("local_gzip_files", [])
            debug = bool(req_data.get("debug", False))

            targets = req_data.get("targets")
            if not targets:
                targets = hunter_service.extract_targets(raw_input, query_type=query_type)

            if not targets:
                return self._send_json_response(
                    {"error": "No valid targets provided. Enter at least one target."},
                    400
                )

            try:
                res = hunter_service.run_search(
                    targets=targets,
                    query_type=query_type,
                    skip_defaults=skip_defaults,
                    api_keys=custom_keys,
                    local_breach_files=local_breach_files,
                    local_gzip_files=local_gzip_files,
                    include_sample_db=include_sample_db,
                    hide_passwords=hide_passwords,
                    debug=debug,
                )

                # Append rich search history record
                import time
                from datetime import datetime
                scan_id = f"SCN-{int(time.time() * 1000) % 100000:05d}"
                breach_highlights = []
                for r in res.get("results", []):
                    for f in r.get("findings", []):
                        det = str(f.get("detail", ""))
                        src = str(f.get("source", ""))
                        if "Breach Exposure:" in det:
                            name = det.replace("Breach Exposure:", "").strip()
                            if name and name not in breach_highlights:
                                breach_highlights.append(name)
                        elif src == "LEAKLOOKUP_PUB":
                            if det and det not in breach_highlights:
                                breach_highlights.append(det)
                        elif src == "LOCALSEARCH":
                            if "Line" in det and "Local Dump Match" not in breach_highlights:
                                breach_highlights.append("Local Dump Match")

                history_entry = {
                    "id": scan_id,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "execution_time_seconds": res.get("execution_time_seconds", 0),
                    "query_type": query_type,
                    "targets": targets,
                    "targets_count": len(targets),
                    "breached_count": res.get("breached_targets", 0),
                    "safe_count": res.get("safe_targets", 0),
                    "total_findings": sum(len(r.get("findings", [])) for r in res.get("results", [])),
                    "breach_highlights": breach_highlights[:25],
                    "results": res.get("results", [])
                }
                search_history.append(history_entry)
                save_history()

                return self._send_json_response(res)
            except Exception as e:
                return self._send_json_response({"error": f"Search execution failed: {str(e)}"}, 500)

        # --- POST /api/history/clear ---
        elif path == "/api/history/clear":
            search_history.clear()
            save_history()
            return self._send_json_response({"message": "History cleared successfully"})

        # --- POST /api/config ---
        elif path == "/api/config":
            keys = req_data.get("keys", {})
            # Filter out empty or unchanged masked values
            updated = {}
            for k, v in keys.items():
                if v and "..." not in v and "******" not in v:
                    updated[k] = v.strip()
            
            hunter_service.set_api_keys(updated)

            # Save to config file
            try:
                with open(CONFIG_FILE, "w") as f:
                    json.dump(hunter_service.api_keys, f, indent=2)
            except Exception as e:
                print(f"[!] Warning: Could not save config file: {e}")

            return self._send_json_response({
                "message": "API keys updated successfully",
                "saved_keys": list(hunter_service.api_keys.keys())
            })

        else:
            return self._send_json_response({"error": f"Endpoint not found: {path}"}, 404)


def run_server(host="127.0.0.1", port=5000):
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, H8MailWebHandler)
    url = f"http://{host}:{port}"
    
    print("=" * 60)
    print("      BreachHunter OSINT Web Application Server")
    print(f"      Version: {__version__}")
    print("=" * 60)
    print(f"[*] Serving at:  {url}")
    print(f"[*] Frontend:    {FRONTEND_DIR}")
    print(f"[*] Backend:     {CURRENT_DIR}")
    print(f"[*] API Base:    {url}/api/status")
    print("=" * 60)
    print("Ready to accept connections. Press Ctrl+C to stop.")
    print("=" * 60)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down server gracefully...")
        httpd.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run BreachHunter Web Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind (default: 5000)")
    args = parser.parse_args()

    run_server(host=args.host, port=args.port)

