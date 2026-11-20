#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main launcher for BreachHunter Web Application.
Usage:
    python run_app.py
    python run_app.py --port 5000
"""

import sys
import os

# Add backend directory to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from server import run_server

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="BreachHunter Web App")
    parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    args = parser.parse_args()

    run_server(host=args.host, port=args.port)

