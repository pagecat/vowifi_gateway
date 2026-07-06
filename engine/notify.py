#!/usr/bin/env python3
"""
notify.py - Best-effort event hook: POST engine events to the manager.

Usage (from the Asterisk dialplan / ims.updown):
  notify.py <event> [arg1] [arg2] ...

Events: call_in <from>, call_out <to>, sms_in <from> <body_b64>,
        sms_out <to> <body_b64>, tunnel_up, tunnel_down, registered, unregistered

Reads MANAGER_URL and VOWIFI_ID from /run/vowifi/engine.env (written by render.py).
Never fails the caller (all exceptions swallowed).
"""
import os
import sys
import json


def load_env():
    env = {}
    path = os.environ.get("VOWIFI_ENV", "/run/vowifi/engine.env")
    try:
        with open(path) as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    env[k] = v
    except Exception:
        pass
    return env


def main():
    if len(sys.argv) < 2:
        return
    event = sys.argv[1]
    args = sys.argv[2:]
    env = load_env()
    manager_url = os.environ.get("MANAGER_URL") or env.get("MANAGER_URL", "")
    inst_id = os.environ.get("VOWIFI_ID") or env.get("VOWIFI_ID", "1")
    payload = {"instance": inst_id, "event": event, "args": args}
    # Always append to a local event log so nothing is lost if the manager is down.
    try:
        os.makedirs("/logs", exist_ok=True)
        with open("/logs/events.jsonl", "a") as f:
            f.write(json.dumps(payload) + "\n")
    except Exception:
        pass
    if not manager_url:
        return
    try:
        import requests
        import urllib3
        urllib3.disable_warnings()
        requests.post(f"{manager_url.rstrip('/')}/api/engine/event",
                      json=payload, timeout=3, verify=False)
    except Exception:
        pass


if __name__ == "__main__":
    main()
