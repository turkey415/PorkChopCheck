"""Wi-Fi name and password, changed the way GL.iNet's own Wireless page changes them, so its admin
page shows the same settings afterwards.

GL.iNet's calls go through `ubus call gl-session call` (module "wifi"): get_config / set_config for
the 2.4 and 5 GHz networks, get_mlo_config / set_mlo_config for the Wi-Fi 7 MLO network (one name
across both bands). Guest and IoT networks are left alone.

Passwords are never sent to the page. Saving needs the router's admin (root) password, checked
against /etc/shadow: in Access point mode the phone page is open to the whole network on WAN.
"""

import hmac
import json
import subprocess
import threading
import time
import warnings

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    try:
        import crypt  # Python 3.11 on the router still has it
    except ImportError:  # pragma: no cover - newer Pythons (the tests fake it)
        crypt = None

SHADOW = "/etc/shadow"
TRIES, LOCK_SECS = 5, 300  # wrong admin passwords before saving is locked for a while
BANDS = {"2G": "2.4 GHz", "5G": "5 GHz", "6G": "6 GHz"}


def gl(module, func, params=None, timeout=10):
    """One GL.iNet call; returns its result, or raises ValueError with GL.iNet's message."""
    req = json.dumps({"module": module, "func": func, "params": params or {}})
    try:
        out = subprocess.run(["ubus", "-t", str(timeout), "call", "gl-session", "call", req],
                             capture_output=True, text=True, timeout=timeout + 5).stdout  # fmt: skip
        reply = json.loads(out or "{}")
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        raise ValueError(f"GL.iNet did not answer ({e})") from None
    res = reply.get("result", reply)
    if isinstance(res, dict) and res.get("err_code"):
        raise ValueError(f"GL.iNet: {res.get('err_msg') or 'error'} ({res['err_code']})")
    return res.get("res", res) if isinstance(res, dict) else res


def check_ssid(ssid):
    ssid = (ssid or "").strip()
    if not 1 <= len(ssid.encode()) <= 32:
        raise ValueError("The Wi-Fi name must be 1 to 32 characters")
    return ssid


def check_key(key):
    if not 8 <= len(key) <= 63 or any(not 0x20 <= ord(c) <= 0x7E for c in key):
        raise ValueError("The password must be 8 to 63 letters, numbers or symbols (no accents or emoji)")
    return key


class Wifi:
    def __init__(self, call=gl, shadow=SHADOW, clock=time.monotonic, sleep=time.sleep):
        self.call, self.shadow, self.clock, self.sleep = call, shadow, clock, sleep
        self.fails, self.locked_until = 0, 0
        self.state = {"state": None}  # the last save: saving / done / error
        self.lock = threading.Lock()

    # ---------- reading ----------
    def _raw(self):
        mlo, bands = [], []
        try:
            for i in (self.call("wifi", "get_mlo_config") or {}).get("ifaces", []):
                if not i.get("guest"):
                    mlo.append(i)
        except ValueError:
            pass  # no MLO on this router
        for dev in self.call("wifi", "get_config") or []:
            for i in dev.get("ifaces", []):
                if not i.get("guest") and "iot" not in (i.get("name") or "") and i.get("name"):
                    bands.append((dev, i))
        return mlo, bands

    def networks(self):
        """The router's own networks (not guest or IoT), without passwords."""
        mlo, bands = self._raw()
        out = []
        for i in mlo:
            out.append({"id": i["name"], "kind": "mlo", "label": "Wi-Fi 7 MLO (" + " + ".join(BANDS.get(b.upper(), b) for b in i.get("mlo_band") or []) + ")",
                        "ssid": i.get("ssid"), "on": bool(i.get("mlo_enable")), "hidden": bool(i.get("hidden")),
                        "secured": (i.get("encryption") or "none") != "none"})  # fmt: skip
        for dev, i in bands:
            out.append({"id": i["name"], "kind": "band", "label": BANDS.get((dev.get("band") or "").upper(), dev.get("band")),
                        "ssid": i.get("ssid"), "on": bool(i.get("enabled")), "hidden": bool(i.get("hidden")),
                        "secured": (i.get("encryption") or "none") != "none"})  # fmt: skip
        # the ones people can see and join first
        out.sort(key=lambda n: (not n["on"], n["hidden"], n["kind"] != "mlo"))
        return out

    # ---------- the admin password ----------
    def check_admin(self, password):
        now = self.clock()
        if now < self.locked_until:
            raise PermissionError(f"Too many wrong passwords: try again in {int(self.locked_until - now) // 60 + 1} min")
        stored = ""
        try:
            with open(self.shadow) as f:
                for line in f:
                    if line.startswith("root:"):
                        stored = line.split(":")[1]
        except OSError:
            pass
        good = bool(stored) and crypt is not None and hmac.compare_digest(crypt.crypt(password or "", stored) or "", stored)
        if not good:
            self.fails += 1
            if self.fails >= TRIES:
                self.fails, self.locked_until = 0, now + LOCK_SECS
            self.sleep(1)  # slow down guessing
            raise PermissionError("Wrong admin password (the one for GL.iNet's admin page)")
        self.fails = 0

    # ---------- saving ----------
    def change(self, net_id, ssid, key, admin_password):
        """Checks everything, then saves in the background: Wi-Fi restarts, so the phone may drop."""
        self.check_admin(admin_password)
        ssid = check_ssid(ssid)
        key = check_key(key) if key else None
        mlo, bands = self._raw()
        params, func = None, None
        for i in mlo:
            if i["name"] == net_id:
                func = "set_mlo_config"
                params = {"name": i["name"], "ssid": ssid, "key": key if key is not None else i.get("key"),
                          "encryption": i.get("encryption"), "hidden": i.get("hidden", False),
                          "random_bssid": i.get("random_bssid", True), "mlo_enable": i.get("mlo_enable", True),
                          "mlo_band": i.get("mlo_band")}  # fmt: skip
        for dev, i in bands:
            if i["name"] == net_id:
                func = "set_config"
                params = {"iface_name": i["name"], "ssid": ssid, "key": key if key is not None else i.get("key"),
                          "encryption": i.get("encryption"), "hidden": i.get("hidden", False),
                          "random_bssid": i.get("random_bssid", True), "device": dev.get("device"),
                          "txpower": dev.get("txpower"), "hwmode": dev.get("hwmode"), "htmode": dev.get("htmode"),
                          "channel": dev.get("channel")}  # fmt: skip
        if not func:
            raise ValueError("No such network")
        if (params.get("encryption") or "none") == "none" and key:
            raise ValueError("That network has no password (open). Set one in GL.iNet's admin page first.")
        params = {k: v for k, v in params.items() if v is not None}
        with self.lock:
            if self.state.get("state") == "saving":
                raise ValueError("Still saving the last change")
            self.state = {"state": "saving", "id": net_id, "ssid": ssid, "t": time.time()}
        threading.Thread(target=self._save, args=(func, params, net_id, ssid), daemon=True).start()

    def _save(self, func, params, net_id, ssid):
        try:
            self.call("wifi", func, params, 60)
            self.state = {"state": "done", "id": net_id, "ssid": ssid, "t": time.time()}
        except ValueError as e:
            self.state = {"state": "error", "id": net_id, "error": str(e), "t": time.time()}
