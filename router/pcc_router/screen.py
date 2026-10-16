"""The router's little screen: a 284 x 76 landscape strip (on the GL-BE3600, a 76 x 284 framebuffer
turned a quarter turn, the way GL.iNet's own screen program draws it), RGB565, with touch.

Pages: Summary, Switch, Port, Layer 2. Tap for the next page; hold for 1.5 s to hand the screen back
to GL.iNet's screen program.
"""

import base64
import os
import struct
import time

from .font import FONTS

W, H = 284, 76  # as seen: landscape
FB_W, FB_H = 76, 284  # as stored
HOLD = 1.5  # seconds of touch that mean "give the screen back"

BG, FG, DIM = 0x0000, 0xFFFF, 0x8410
GOOD, WARN, BAD, ACC = 0x07E0, 0xFE60, 0xF800, 0x5DDF
LEVEL = {"good": GOOD, "warn": WARN, "bad": BAD}


def _glyphs(name):
    f = FONTS[name]
    out = {}
    for ch, data in f["glyphs"].items():
        raw = base64.b64decode(data)
        per = (f["w"] + 7) // 8
        rows = [int.from_bytes(raw[y * per:(y + 1) * per], "big") for y in range(f["h"])]
        # each row's bits are packed right-aligned: the leftmost pixel is bit w-1
        out[ch] = [[x for x in range(f["w"]) if rows[y] >> (f["w"] - 1 - x) & 1] for y in range(f["h"])]
    return f["w"], f["h"], out


class Canvas:
    """Draws in landscape coordinates (x right, y down) straight into framebuffer layout."""

    def __init__(self):
        self.buf = bytearray(FB_W * FB_H * 2)
        self.fonts = {name: _glyphs(name) for name in FONTS}

    def clear(self, color=BG):
        self.buf[:] = struct.pack("<H", color) * (FB_W * FB_H)

    def _px(self, x, y, color):
        if 0 <= x < W and 0 <= y < H:
            i = ((FB_H - 1 - x) * FB_W + y) * 2  # landscape (x, y) -> framebuffer, as GL.iNet draws it
            self.buf[i] = color & 0xFF
            self.buf[i + 1] = color >> 8

    def rect(self, x, y, w, h, color):
        lo, hi = color & 0xFF, color >> 8
        for yy in range(max(0, y), min(H, y + h)):
            for xx in range(max(0, x), min(W, x + w)):
                i = ((FB_H - 1 - xx) * FB_W + yy) * 2
                self.buf[i], self.buf[i + 1] = lo, hi

    def text_width(self, text, size):
        return len(text) * self.fonts[size][0]

    def text(self, x, y, text, size="small", color=FG, right=False, center=False, max_w=None):
        w, h, glyphs = self.fonts[size]
        if max_w is not None and len(text) * w > max_w:  # cut to fit, with an ellipsis
            n = max(1, max_w // w - 1)
            text = text[:n] + "…" if "…" in glyphs else text[:n + 1]
        if right:
            x -= len(text) * w
        elif center:
            x -= len(text) * w // 2
        for i, ch in enumerate(text):
            rows = glyphs.get(ch) or glyphs.get("?")
            gx = x + i * w
            for yy, cols in enumerate(rows):
                for xx in cols:
                    self._px(gx + xx, y + yy, color)
        return x + len(text) * w

    def frame(self):
        return bytes(self.buf)


# ---------- pages ----------
PAGES = ["summary", "switch", "port", "l2"]


def short_port(name):
    """'GigabitEthernet1/0/14' -> 'Gi1/0/14', as the switch's own CLI shows it."""
    if not name:
        return "?"
    for long, short in (("TwentyFiveGigE", "Twe"), ("TenGigabitEthernet", "Te"), ("GigabitEthernet", "Gi"),
                        ("FastEthernet", "Fa"), ("Ethernet", "Eth")):  # fmt: skip
        if name.startswith(long):
            return short + name[len(long):]
    return name


def speed_text(link):
    if not link.get("up"):
        return "no link"
    sp = link.get("speed")
    dup = (link.get("duplex") or "").lower()
    s = f"{sp // 1000}G" if sp and sp >= 1000 else f"{sp}M" if sp else "?"
    return s + (" half" if dup.startswith("half") else "")


def draw(c, snap, page):
    c.clear()
    level = snap["verdict"]
    color = LEVEL[level]
    c.rect(0, 0, 4, H, color)  # a stripe in the verdict's colour down the left edge
    name = PAGES[page % len(PAGES)]
    c.text(W - 2, 1, f"{page % len(PAGES) + 1}/{len(PAGES)}", "small", DIM, right=True)
    {"summary": _summary, "switch": _switch, "port": _port, "l2": _l2}[name](c, snap, color)


def _summary(c, s, color):
    sw, link, wan = s["switch"], s["link"], s["wan"]
    top = s["findings"][0][1]
    c.text(8, 1, top, "medium", color, max_w=W - 40)
    if sw["heard"]:
        c.text(8, 21, short_port(sw["port"]), "large", FG)
        vlan = f"VLAN {sw['vlan']}" if sw.get("vlan") is not None else ""
        c.text(W - 4, 26, vlan, "medium", ACC, right=True)
        c.text(8, 52, sw["name"] or "", "small", DIM, max_w=170)
    else:
        c.text(8, 24, speed_text(link) if link["up"] else "NO LINK", "large", FG if link["up"] else color)
    c.text(W - 4, 52, speed_text(link), "small", FG, right=True)
    c.text(8, 63, wan.get("address") or "no address", "small", FG if wan.get("address") else BAD)
    more = len([f for f in s["findings"] if f[0] != "good"]) - 1
    if more > 0:
        c.text(W - 4, 63, f"+{more} more", "small", WARN, right=True)


def _rows(c, rows):
    y = 15
    for key, value, col in rows:
        c.text(8, y, key, "small", DIM)
        c.text(78, y, str(value), "small", col or FG, max_w=W - 82)
        y += 12


def _switch(c, s, color):
    sw = s["switch"]
    c.text(8, 1, "SWITCH", "small", ACC)
    if not sw["heard"]:
        c.text(8, 30, "No CDP/LLDP yet", "medium", DIM)
        return
    _rows(c, [
        ("Switch", sw["name"] or "?", None),
        ("Port", short_port(sw["port"]), None),
        ("VLAN", f"{sw.get('vlan', '-')}" + (f"  voice {sw['voice_vlan']}" if sw.get("voice_vlan") else ""), ACC),
        ("Model", sw.get("platform") or "-", None),
        ("PoE", sw.get("poe") or "-", None),
    ])


def _port(c, s, color):
    link, wan, chk, t = s["link"], s["wan"], s["checks"], s["timing"]

    def check(name):
        r = chk.get(name)
        if not r:
            return "…", DIM
        ms = r.get("ms")
        text = ("<1 ms" if ms < 1 else f"{ms:.0f} ms") if r["ok"] and ms is not None else "ok" if r["ok"] else "no answer"
        return (text,
                GOOD if r["ok"] else BAD)

    c.text(8, 1, "PORT", "small", ACC)
    gw, gwc = check("gateway")
    inet, inc = check("internet")
    online = f"{t['gateway']:.0f} s" if t.get("gateway") is not None else "-"
    _rows(c, [
        ("Link", speed_text(link) + (f"  (could do {link['downshift'] // 1000}G)" if link.get("downshift") else ""), None),
        ("Address", f"{wan.get('address') or '-'}" + (f"/{wan['mask']}" if wan.get("mask") else ""), None),
        ("Gateway", f"{wan.get('gateway') or '-'}  {gw}", gwc),
        ("Internet", inet, inc),
        ("Online in", online, WARN if t.get("gateway") and t["gateway"] > 25 else None),
    ])


def _l2(c, s, color):
    l2, dhcp = s["l2"], s["dhcp"]
    stp = l2.get("stp") or {}
    c.text(8, 1, "LAYER 2", "small", ACC)
    servers = dhcp["servers"]
    _rows(c, [
        ("DHCP", ", ".join(servers) or "-", BAD if len(servers) > 1 else None),
        ("802.1X", "login asked" if l2.get("dot1x") else "none seen", WARN if l2.get("dot1x") else None),
        ("STP", f"{stp.get('proto', '-')} root {stp.get('root_mac', '-')}" if stp else "none seen", None),
        ("Trunk", (l2.get("dtp") or {}).get("oper", "-") + (f"  tags {l2['vlans_tagged']}" if l2["vlans_tagged"] else ""), None),
        ("Bcast/s", l2["broadcasts_per_s"], WARN if l2["broadcasts_per_s"] > 50 else None),
    ])


# ---------- the device ----------
class Display:
    def __init__(self, fb="/dev/fb0", backlight="/sys/class/backlight/soc:backlight"):
        self.fb, self.backlight = fb, backlight
        self.canvas = Canvas()

    def show(self, snap, page):
        draw(self.canvas, snap, page)
        with open(self.fb, "wb") as f:
            f.write(self.canvas.frame())

    def light(self, on=True):
        try:
            with open(os.path.join(self.backlight, "max_brightness")) as f:
                top = f.read().strip()
            with open(os.path.join(self.backlight, "brightness"), "w") as f:
                f.write(top if on else "0")
        except OSError:
            pass


class Touch:
    """Taps and long presses from the touchscreen (evdev: BTN_TOUCH down and up)."""

    EVENT = struct.Struct("llHHi")  # struct input_event on 64-bit Linux
    BTN_TOUCH = 0x14A

    def __init__(self, path="/dev/input/event0"):
        self.path = path

    def presses(self, stop):
        """Yields "tap" or "hold" until stop() is true."""
        try:
            f = open(self.path, "rb", buffering=0)
        except OSError:
            return
        os.set_blocking(f.fileno(), False)
        down_at = None
        with f:
            while not stop():
                data = f.read(self.EVENT.size * 16)
                if not data:
                    if down_at and time.monotonic() - down_at >= HOLD:
                        down_at = None
                        yield "hold"
                    time.sleep(0.05)
                    continue
                for i in range(0, len(data) - self.EVENT.size + 1, self.EVENT.size):
                    _, _, typ, code, value = self.EVENT.unpack_from(data, i)
                    if typ == 1 and code == self.BTN_TOUCH:
                        if value == 1:
                            down_at = time.monotonic()
                        elif value == 0 and down_at:
                            held = time.monotonic() - down_at
                            down_at = None
                            yield "hold" if held >= HOLD else "tap"
