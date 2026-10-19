"""
Филин — self-hosted monitoring for a small office (formerly Server Signal Desk).

Pure Python standard library — no pip install, no external dependencies.
Everything is configured from the web UI: hosts, subnets, Telegram, intervals.

Run:   python monitor.py
Open:  http://localhost:8081
"""

import sys

if __name__ == "__main__":
    if "--version" in sys.argv:
        # the update smoke test: answer without opening config, DB or logs
        from ssd import core
        print(core.__version__)
        sys.exit(0)
    from ssd import app
    app.run_cli()
