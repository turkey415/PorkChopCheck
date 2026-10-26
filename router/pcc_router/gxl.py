"""Send to GXL: the port log's labelled rows go to a GXL Event Server, like Probe Deck's jack survey.

GXL's /agent/survey takes {"records": [{label, switch, port, vlan, speed, level, why}], "source"} with
the event's agent key, and updates the seats it already has (label = the seat, e.g. "A1"). The key
is kept in /etc/pcc-router/config.json (root-only) and never sent to the page.
"""

import json
import re
import time
import urllib.error
import urllib.request

LEVEL = {"good": "good", "warn": "check", "bad": "bad"}


def check_url(v):
    v = str(v or "").strip().rstrip("/")
    if v and not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d{1,5})?", v):
        raise ValueError("The GXL address looks like http://10.2.1.143:8000")
    return v


def check_key(v):
    v = str(v or "").strip()
    if v and not re.fullmatch(r"[A-Za-z0-9_\-]{8,128}", v):
        raise ValueError("That doesn't look like a GXL agent key")
    return v


class Gxl:
    def __init__(self, service, opener=urllib.request.urlopen):
        self.s = service
        self.open = opener
        self.sent = None  # the last send: when, how many GXL updated, labels it didn't know

    def state(self):
        c = self.s.config
        return {"url": c.get("gxl_url", ""), "key_set": bool(c.get("gxl_key")), "sent": self.sent}

    def settings(self, body):
        if "url" in body:
            self.s.set_option("gxl_url", check_url(body["url"]))
        if body.get("key"):  # left empty: keep the saved key
            self.s.set_option("gxl_key", check_key(body["key"]))
        return self.state()

    def records(self):
        out = []
        for r in self.s.log.list():
            if not r.get("label"):
                continue  # only rows saved with a seat label
            why = [] if r.get("verdict") == "good" else [f.strip() for f in str(r.get("findings") or "").split(";") if f.strip()]
            out.append({"label": r["label"][:30], "switch": r.get("switch") or None, "port": r.get("port") or None,
                        "vlan": r.get("vlan") or None, "speed": str(r.get("speed") or "") or None,
                        "level": LEVEL.get(r.get("verdict"), "check"), "why": why[:10]})  # fmt: skip
        return out

    def send(self):
        url, key = self.s.config.get("gxl_url"), self.s.config.get("gxl_key")
        if not url or not key:
            raise ValueError("Set the GXL address and the event's agent key first")
        records = self.records()
        if not records:
            raise ValueError("No labelled ports yet: save some in the port log with the seat as the label (e.g. A1)")
        body = json.dumps({"records": records, "source": "PorkChopCheck router"}).encode()
        req = urllib.request.Request(f"{url}/agent/survey", data=body, method="POST",
                                     headers={"Content-Type": "application/json", "Authorization": f"Agent {key}"})  # fmt: skip
        try:
            with self.open(req, timeout=10) as res:
                out = json.loads(res.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise ValueError("GXL doesn't know that agent key" if e.code == 401 else f"GXL said {e.code}") from None
        except (urllib.error.URLError, OSError) as e:
            raise ValueError(f"Couldn't reach GXL at {url}: {getattr(e, 'reason', e)}") from None
        self.sent = {"t": time.time(), "count": len(records), "updated": len(out.get("updated", [])), "unknown": out.get("unknown", [])[:50]}
        return self.sent
