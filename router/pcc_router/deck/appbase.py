"""The base for Probe Deck's add-on pages (Switch logs, Capture, Configs…).

Each one is a class with a `name`. The server sends it:
  GET  /api/x/<name>[/<sub>[/<arg>]]  ->  app.get(sub, arg, query, user)
  POST /api/x/<name>/<action>         ->  app.post(action, body, user)
Its settings live in /etc/probe-deck/<name>.json (root-only), its data in /var/lib/probe-deck/<name>/.
"""
import json
import os
import threading
from pathlib import Path


def load_json(path, default):
    try:
        with open(path) as f:
            v = json.load(f)
        return v if isinstance(v, type(default)) else default
    except (OSError, ValueError):
        return default


def save_json(path, obj, private=False):
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)


class Reply:
    """A GET answer that isn't JSON: a download or plain text."""

    def __init__(self, body, ctype="application/octet-stream", filename=None, code=200):
        self.body, self.ctype, self.code = body, ctype, code
        self.headers = [("Content-Disposition", f'attachment; filename="{filename}"')] if filename else []


class App:
    name = ""
    VIEWER_POST = ()      # actions viewers may run too
    RAW_POST = ()         # actions that take a raw request body (uploads)
    SETTINGS = {}         # key -> default
    LIMITS = {}           # int key -> (lo, hi)

    def __init__(self, probe, conf_dir, data_dir):
        self.p = probe
        self.lock = threading.RLock()
        self.dir = Path(data_dir) / self.name
        self.dir.mkdir(parents=True, exist_ok=True)
        self.conf_file = Path(conf_dir) / f"{self.name}.json"
        self.conf = dict(self.SETTINGS)
        self.conf.update({k: v for k, v in load_json(self.conf_file, {}).items() if k in self.SETTINGS})

    def check(self, k, v):
        d = self.SETTINGS[k]
        if isinstance(d, bool):
            return bool(v)
        if isinstance(d, (int, float)):
            v = type(d)(v)
            lo, hi = self.LIMITS.get(k, (0, 10 ** 9))
            if not lo <= v <= hi:
                raise ValueError(f"{k} must be {lo}-{hi}")
            return v
        return str(v or "")[:2000]

    def save_conf(self, new):
        c = dict(self.conf)
        for k, v in new.items():
            if k in self.SETTINGS:
                c[k] = self.check(k, v)
        with self.lock:
            self.conf = c
        self.conf_file.parent.mkdir(parents=True, exist_ok=True)
        save_json(self.conf_file, c, private=True)
        self.on_conf()

    def on_conf(self):
        pass

    def start(self):
        pass

    def status(self):
        """For the sidebar light: {"dot": "on"|"warn"|"err"|"", "badge": n}."""
        return None

    def get(self, sub, arg, query, user):
        raise ValueError("not found")

    def post(self, action, body, user):
        if action == "settings":
            self.save_conf(body)
            return {}
        raise ValueError("Unknown action")

    def raw(self, action, stream, length, query, user):
        raise ValueError("Unknown action")
