"""
pc_smart - smart-home device discovery for PorkChopCheck.

How devices are found (all local, no cloud accounts):
  * Every host on the subnet: an ARP sweep through the OS, reverse DNS, a light port probe.
  * SSDP / UPnP: Sonos, Philips Hue, Belkin WeMo, Roku, smart TVs, many others. The UPnP
    description XML usually carries manufacturer, model and serial number.
  * mDNS: Chromecast / Google Nest, HomeKit, AirPlay, ESPHome, Matter, printers... (results come
    from pc_net.MdnsBrowser).
  * Vendor discovery protocols: TP-Link Kasa / Tapo (UDP 9999 + 20002), LIFX (UDP 56700),
    Govee (UDP 4001/4002, needs "LAN Control" on), WiZ (UDP 38899, needs "Allow local
    communication" on), Yeelight (UDP 1982), Tuya / Smart Life (UDP 6666/6667 broadcasts).
  * HTTP device info: Roku (:8060/query/device-info), Hue (/api/config), Shelly (/shelly),
    Google Cast (:8008/setup/eureka_info, best effort).

Serial numbers only appear when a device publishes one locally. Everything else is labelled
with where it came from. Pure Python; no extra packages.
"""

import concurrent.futures as cf
import csv
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import struct
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET

import pc_net as N

# ====================================================================== categories & brands
CATEGORIES = {
    "light": "Light", "plug": "Plug / switch", "speaker": "Speaker", "tv": "TV / streamer",
    "camera": "Camera / doorbell", "thermostat": "Climate", "hub": "Hub / bridge", "lock": "Lock / garage",
    "sensor": "Sensor", "appliance": "Appliance", "iot": "Smart device", "printer": "Printer",
    "console": "Game console", "computer": "Computer", "phone": "Phone / tablet",
    "network": "Network gear", "unknown": "Unknown",
}
SMART_CATS = {"light", "plug", "speaker", "tv", "camera", "thermostat", "hub", "lock", "sensor",
              "appliance", "iot"}

# (regex on vendor / manufacturer / hostname / model / mDNS text, brand, default category)
# Most specific first. Matching is case-insensitive.
BRANDS = [
    (r"\beero\b", "eero", "network"),
    (r"\bring\b|ring llc", "Ring", "camera"),
    (r"\bblink\b", "Blink", "camera"),
    (r"amazon|\becho\b|fire ?tv|kindle", "Amazon", "speaker"),
    (r"nest labs|\bnest\b", "Google Nest", "thermostat"),
    (r"google|chromecast", "Google", "tv"),
    (r"sonos", "Sonos", "speaker"),
    (r"\broku\b", "Roku", "tv"),
    (r"signify|philips light|philips hue|hue bridge|\bhue\b", "Philips Hue", "light"),
    (r"\bwiz\b|wiz connected", "WiZ", "light"),
    (r"kasa|tapo", "TP-Link Kasa / Tapo", "plug"),
    (r"shelly|allterco", "Shelly", "plug"),
    (r"tuya|smart ?life", "Tuya / Smart Life", "plug"),
    (r"lifx|lifi labs", "LIFX", "light"),
    (r"govee|intellirocks", "Govee", "light"),
    (r"yeelight|yeelink", "Yeelight", "light"),
    (r"nanoleaf", "Nanoleaf", "light"),
    (r"sengled", "Sengled", "light"),
    (r"\bwled\b", "WLED", "light"),
    (r"elgato", "Elgato", "light"),
    (r"lutron", "Lutron", "hub"),
    (r"leviton", "Leviton", "plug"),
    (r"belkin|wemo", "Belkin WeMo", "plug"),
    (r"meross", "Meross", "plug"),
    (r"ecobee", "ecobee", "thermostat"),
    (r"honeywell|resideo", "Honeywell", "thermostat"),
    (r"emerson|\bsensi\b", "Sensi", "thermostat"),
    (r"rachio", "Rachio", "appliance"),
    (r"irobot|roomba", "iRobot", "appliance"),
    (r"roborock", "Roborock", "appliance"),
    (r"ecovacs", "Ecovacs", "appliance"),
    (r"wyze", "Wyze", "camera"),
    (r"\barlo\b", "Arlo", "camera"),
    (r"\beufy\b|anker", "eufy", "camera"),
    (r"reolink", "Reolink", "camera"),
    (r"hikvision", "Hikvision", "camera"),
    (r"dahua", "Dahua", "camera"),
    (r"amcrest", "Amcrest", "camera"),
    (r"axis comm", "Axis", "camera"),
    (r"simplisafe", "SimpliSafe", "camera"),
    (r"chamberlain|\bmyq\b|liftmaster", "Chamberlain myQ", "lock"),
    (r"august home|\byale\b|assa abloy", "Yale / August", "lock"),
    (r"schlage|allegion", "Schlage", "lock"),
    (r"aqara|lumi united", "Aqara", "hub"),
    (r"xiaomi|mijia", "Xiaomi", "appliance"),
    (r"smartthings", "SmartThings", "hub"),
    (r"samsung", "Samsung", "tv"),
    (r"lg electronics|lg innotek|webos|\blgtv\b|\blg\b", "LG", "tv"),
    (r"vizio", "Vizio", "tv"),
    (r"hisense", "Hisense", "tv"),
    (r"\btcl\b", "TCL", "tv"),
    (r"sony interactive|playstation", "PlayStation", "console"),
    (r"nintendo", "Nintendo", "console"),
    (r"xbox", "Xbox", "console"),
    (r"\bsony\b|bravia", "Sony", "tv"),
    (r"\bbose\b", "Bose", "speaker"),
    (r"denon|marantz|\bheos\b|d&m holdings", "Denon / HEOS", "speaker"),
    (r"yamaha", "Yamaha", "speaker"),
    (r"hubitat", "Hubitat", "hub"),
    (r"homey|athom", "Homey", "hub"),
    (r"home ?assistant|nabu casa", "Home Assistant", "hub"),
    (r"esphome", "ESPHome", "sensor"),
    (r"ikea|dirigera|tradfri", "IKEA", "hub"),
    (r"\bapple\b|homepod|appletv|apple tv", "Apple", "phone"),
    (r"raspberry", "Raspberry Pi", "computer"),
    (r"espressif", "ESP-based device", "iot"),
    (r"hewlett|\bhp\b|laserjet|officejet|deskjet", "HP", "printer"),
    (r"brother", "Brother", "printer"),
    (r"\bcanon\b", "Canon", "printer"),
    (r"epson|seiko epson", "Epson", "printer"),
    (r"ubiquiti|unifi", "Ubiquiti", "network"),
    (r"netgear", "Netgear", "network"),
    (r"cisco|meraki", "Cisco", "network"),
    (r"tp-?link", "TP-Link", "network"),
]
_BRAND_RX = [(re.compile(rx, re.I), b, c) for rx, b, c in BRANDS]

# keywords in model / name / hostname that pin the category down
CATEGORY_WORDS = [
    (r"bulb|lamp|light|strip|\bled\b|lightstrip|wled|nanoleaf", "light"),
    (r"doorbell|\bcam\b|camera|cam[-_ ]|\bnvr\b|ipc\b", "camera"),
    (r"thermostat|\bhvac\b|purifier|heater|humidifier|\bfan\b|air ?con", "thermostat"),
    (r"speaker|\becho\b|homepod|soundbar|nest mini|nest audio|google home|audioaccessory|sonos", "speaker"),
    (r"\btv\b|roku|chromecast|fire ?tv|appletv|apple tv|shield|bravia|streaming", "tv"),
    (r"\block\b|garage|deadbolt", "lock"),
    (r"\bhub\b|bridge|gateway|smartthings|hubitat|dirigera", "hub"),
    (r"plug|outlet|socket|switch|dimmer|relay|smartplug", "plug"),
    (r"sensor|motion|contact|leak|temperature", "sensor"),
    (r"vacuum|roomba|robot|washer|dryer|fridge|oven|dishwasher|sprinkler", "appliance"),
    (r"printer|laserjet|officejet|deskjet|\bmfc\b", "printer"),
    (r"iphone|ipad|android|galaxy|pixel", "phone"),
    (r"macbook|imac|desktop|laptop|\bpc\b|windows", "computer"),
]
_CAT_RX = [(re.compile(rx, re.I), c) for rx, c in CATEGORY_WORDS]

MDNS_CATEGORY = {
    "_googlecast._tcp.local": "tv", "_airplay._tcp.local": "tv", "_raop._tcp.local": "speaker",
    "_sonos._tcp.local": "speaker", "_spotify-connect._tcp.local": "speaker",
    "_hue._tcp.local": "hub", "_hap._tcp.local": "iot", "_homekit._tcp.local": "iot",
    "_matter._tcp.local": "iot", "_matterc._udp.local": "iot", "_esphomelib._tcp.local": "sensor",
    "_wled._tcp.local": "light", "_nanoleafapi._tcp.local": "light", "_elg._tcp.local": "light",
    "_shelly._tcp.local": "plug", "_amzn-wplay._tcp.local": "tv", "_androidtvremote2._tcp.local": "tv",
    "_ipp._tcp.local": "printer", "_ipps._tcp.local": "printer", "_printer._tcp.local": "printer",
    "_pdl-datastream._tcp.local": "printer",
}
PORT_CATEGORY = {554: "camera", 1400: "speaker", 8060: "tv", 9100: "printer", 6668: "plug",
                 9999: "plug", 55443: "light"}
PROBE_PORTS = [80, 554, 1400, 8008, 8060, 9100, 6668, 9999, 55443]

# The fuller list for documenting a device: common services, with the name a person would use.
SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "Web interface",
    139: "Windows file sharing", 443: "Web interface (HTTPS)", 445: "Windows file sharing",
    515: "Printing (LPD)", 548: "Mac file sharing", 554: "Video stream (RTSP)",
    631: "Printing (IPP)", 1400: "Sonos control", 1883: "MQTT", 2049: "NFS file sharing",
    3389: "Remote Desktop", 5000: "AirPlay / UPnP", 5357: "Windows device discovery",
    5900: "Screen sharing (VNC)", 6668: "Tuya local control", 7000: "AirPlay",
    8008: "Chromecast", 8009: "Chromecast", 8060: "Roku control", 8080: "Web interface (alt)",
    8123: "Home Assistant", 8443: "Web interface (HTTPS alt)", 8554: "Video stream (RTSP alt)",
    8883: "MQTT (TLS)", 9100: "Printing (raw)", 9999: "TP-Link Kasa control", 32400: "Plex",
    49152: "UPnP", 55443: "Yeelight control", 62078: "iPhone / iPad sync",
}
ALL_PORTS = sorted(set(PROBE_PORTS) | set(SERVICE_PORTS))


def describe_ports(ports):
    """["80  Web interface", "554  Video stream (RTSP)", "12345"] for a list of port numbers."""
    return [f"{p}  {SERVICE_PORTS[p]}" if p in SERVICE_PORTS else str(p) for p in sorted(set(ports))]


def service_names(ports):
    """Distinct service names for the open ports, in port order: "Web interface, Chromecast"."""
    seen = []
    for p in sorted(set(ports)):
        n = SERVICE_PORTS.get(p)
        if n and n not in seen:
            seen.append(n)
    return ", ".join(seen)


def port_open(ip, port, src=None, timeout=0.4):
    """One TCP connect. True only if the device accepted it; the connection is closed at once."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if src:
            s.bind((src, 0))
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def probe_ports(ip, ports, src=None, timeout=0.6, workers=32, stop=None):
    """Which of `ports` one device answers on, sorted."""
    found = []
    ex = cf.ThreadPoolExecutor(workers)
    try:
        futs = {ex.submit(port_open, ip, p, src, timeout): p for p in ports}
        try:
            for f in cf.as_completed(futs, timeout=timeout * len(futs) / workers + 10):
                if stop and stop.is_set():
                    break
                if f.result():
                    found.append(futs[f])
        except cf.TimeoutError:
            pass
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return sorted(found)

# Where a fact came from; higher wins when two sources disagree.
PRIO = {"oui": 1, "dns": 2, "ports": 2, "mdns": 4, "upnp": 5, "http": 6, "protocol": 7}


# ====================================================================== small helpers
def _udp(src=None, broadcast=False, port=0, any_addr=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if broadcast:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("" if (any_addr or not src) else src, port))
    if src:
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(src))
        except OSError:
            pass
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    return s


def _collect(socks, seconds, handler, stop=None):
    """Read from one or more UDP sockets for `seconds`, calling handler(data, ip, port, local_port)."""
    socks = socks if isinstance(socks, list) else [socks]
    end = time.time() + seconds
    for s in socks:
        s.settimeout(0.2)
    while time.time() < end and not (stop and stop.is_set()):
        for s in socks:
            try:
                data, (ip, port) = s.recvfrom(65535)
            except (socket.timeout, BlockingIOError):
                continue
            except OSError:
                continue
            try:
                handler(data, ip, port, s.getsockname()[1])
            except Exception:  # noqa: BLE001
                pass


def _json(b):
    try:
        if isinstance(b, (bytes, bytearray)):
            b = b.decode("utf-8", "replace")
        b = b.strip().strip("\x00")
        return json.loads(b) if b[:1] in "{[" else None
    except ValueError:
        return None


def url_is_on(url, ip):
    """True if a plain-http URL points at this exact IP address. A device's SSDP reply names the
    URL of its description; without this check any device could have us fetch a page from
    another host, including this machine."""
    try:
        u = urllib.parse.urlsplit(url)
        return u.scheme == "http" and ipaddress.ip_address(u.hostname or "") == ipaddress.ip_address(ip)
    except ValueError:
        return False


def http_get(url, src=None, timeout=2.0, limit=131072):
    """Small plain-HTTP GET (LAN devices only). Returns text or None."""
    try:
        u = urllib.parse.urlsplit(url)
        if u.scheme != "http" or not u.hostname:
            return None
        c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout,
                                       source_address=(src, 0) if src else None)
        try:
            c.request("GET", (u.path or "/") + (f"?{u.query}" if u.query else ""),
                      headers={"User-Agent": "PorkChopCheck"})
            r = c.getresponse()
            if r.status != 200:
                return None
            return r.read(limit).decode("utf-8", "replace")
        finally:
            c.close()
    except (OSError, http.client.HTTPException, ValueError):
        return None


def fmt_mac(m):
    """Accepts aa:bb.., AA-BB.., aabbccddeeff; returns aa:bb:cc:dd:ee:ff or ''."""
    h = re.sub(r"[^0-9a-fA-F]", "", m or "")
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)).lower() if len(h) == 12 else ""


def _xml_fields(text):
    """Flatten an XML document into {tag: first text}, namespaces stripped."""
    out = {}
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag not in out and el.text and el.text.strip():
            out[tag] = el.text.strip()
    return out


# ====================================================================== AES-128 (decrypt) for Tuya
def _rotl8(x, s):
    return ((x << s) | (x >> (8 - s))) & 0xFF


def _build_sbox():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        sbox[p] = (q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4) ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


_SBOX, _INV_SBOX = _build_sbox()


def _xt(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xt(a)
        b >>= 1
    return r


def _expand_key(key):
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xt(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(11)]


def aes128_decrypt_block(round_keys, block):
    s = [b ^ k for b, k in zip(block, round_keys[10])]
    for rnd in range(9, -1, -1):
        s = [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]   # InvShiftRows
        s = [_INV_SBOX[b] for b in s]                                     # InvSubBytes
        s = [b ^ k for b, k in zip(s, round_keys[rnd])]                   # AddRoundKey
        if rnd:
            out = []
            for c in range(4):                                            # InvMixColumns
                a = s[4 * c:4 * c + 4]
                out += [_mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9),
                        _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13),
                        _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11),
                        _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)]
            s = out
    return bytes(s)


def aes128_ecb_decrypt(key, data):
    if len(data) % 16:
        return b""
    rk = _expand_key(key)
    out = b"".join(aes128_decrypt_block(rk, data[i:i + 16]) for i in range(0, len(data), 16))
    pad = out[-1] if out else 0
    return out[:-pad] if 0 < pad <= 16 and out.endswith(bytes([pad]) * pad) else out


# ====================================================================== protocol parsers
def parse_ssdp(data):
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].upper().startswith(("HTTP/1.1 200", "NOTIFY")):
        return None
    hd = {}
    for line in lines[1:]:
        k, sep, v = line.partition(":")
        if sep:
            hd[k.strip().lower()] = v.strip()
    return hd


def parse_upnp_xml(text):
    f = _xml_fields(text)
    if not f:
        return None
    serial = f.get("serialNumber") or f.get("serialNum") or ""
    model = f.get("modelName", "")
    number = f.get("modelNumber", "")
    if number and number not in model:
        model = f"{model} {number}".strip()
    return {"name": f.get("roomName") or f.get("friendlyName", ""),
            "brand_hint": f.get("manufacturer", ""),
            "model": model,
            "serial": serial, "serial_source": "UPnP" if serial else "",
            "udn": f.get("UDN", ""), "desc": f.get("modelDescription", "")}


def parse_roku(text):
    f = _xml_fields(text)
    if not f.get("serial-number") and not f.get("model-name"):
        return None
    return {"name": f.get("user-device-name") or f.get("friendly-device-name", ""),
            "model": f.get("friendly-model-name") or f.get("model-name", ""),
            "serial": f.get("serial-number", ""), "serial_source": "Roku ECP",
            "brand_hint": f.get("vendor-name", "Roku"), "category": "tv",
            "mac": fmt_mac(f.get("wifi-mac") or f.get("ethernet-mac", "")),
            "fw": f.get("software-version", "")}


def parse_hue_config(text):
    j = _json(text)
    if not isinstance(j, dict) or "bridgeid" not in j:
        return None
    return {"name": j.get("name", ""), "model": f"Hue Bridge {j.get('modelid', '')}".strip(),
            "serial": j.get("bridgeid", ""), "serial_source": "Hue bridge ID", "brand": "Philips Hue",
            "category": "hub", "mac": fmt_mac(j.get("mac", "")), "fw": j.get("swversion", "")}


def parse_shelly(text):
    j = _json(text)
    if not isinstance(j, dict) or "mac" not in j or not ("type" in j or "gen" in j):
        return None
    model = j.get("model") or j.get("type", "")
    app = j.get("app", "")
    return {"name": j.get("name") or "", "model": f"Shelly {app or model}".strip(),
            "serial": j.get("id") or fmt_mac(j["mac"]), "serial_source": "Shelly ID",
            "brand": "Shelly", "category": "plug", "mac": fmt_mac(j["mac"]),
            "fw": j.get("ver") or j.get("fw", "")}


def parse_cast(text):
    j = _json(text)
    if not isinstance(j, dict) or not ("name" in j or "device_info" in j):
        return None
    di = j.get("device_info") or {}
    return {"name": j.get("name", ""), "model": di.get("model_name", ""),
            "brand_hint": di.get("manufacturer", "Google"), "mac": fmt_mac(di.get("mac_address", ""))}


def xor_encrypt(b):
    key, out = 171, bytearray()
    for c in b:
        key ^= c
        out.append(key)
    return bytes(out)


def xor_decrypt(b):
    key, out = 171, bytearray()
    for c in b:
        out.append(key ^ c)
        key = c
    return bytes(out)


KASA_QUERY = xor_encrypt(b'{"system":{"get_sysinfo":null}}')
KASA_QUERY2 = bytes.fromhex("020000010000000000000000463cb5d3")


def _kasa_cat(t):
    t = (t or "").upper()
    for key, cat in (("BULB", "light"), ("STRIP", "light"), ("LIGHT", "light"), ("PLUG", "plug"),
                     ("SWITCH", "plug"), ("CAMERA", "camera"), ("HUB", "hub"), ("ROBOVAC", "appliance")):
        if key in t:
            return cat
    return "plug"


def parse_kasa_legacy(data):
    j = _json(xor_decrypt(data))
    si = (((j or {}).get("system") or {}).get("get_sysinfo")) if isinstance(j, dict) else None
    if not isinstance(si, dict):
        return None
    return {"name": si.get("alias", ""), "model": si.get("model", ""),
            "serial": si.get("deviceId", ""), "serial_source": "Kasa device ID",
            "brand": "TP-Link Kasa / Tapo", "category": _kasa_cat(si.get("type") or si.get("mic_type")),
            "mac": fmt_mac(si.get("mac") or si.get("mic_mac", "")), "fw": si.get("sw_ver", "")}


def parse_kasa_new(data):
    j = _json(data[16:]) if len(data) > 16 else None
    r = (j or {}).get("result") if isinstance(j, dict) else None
    if not isinstance(r, dict):
        return None
    return {"ip": r.get("ip", ""), "model": r.get("device_model", ""),
            "serial": r.get("device_id", ""), "serial_source": "TP-Link device ID",
            "brand": "TP-Link Kasa / Tapo", "category": _kasa_cat(r.get("device_type")),
            "mac": fmt_mac(r.get("mac", ""))}


def lifx_packet(msg_type, source=0x50434b31, seq=1):
    proto = 1024 | (1 << 12) | (1 << 13)              # protocol 1024, addressable, tagged
    return (struct.pack("<HHI", 36, proto, source) + bytes(8) + bytes(6) + bytes([0, seq])
            + bytes(8) + struct.pack("<HH", msg_type, 0))


def parse_lifx(data):
    if len(data) < 36:
        return None
    _size, proto, _src = struct.unpack_from("<HHI", data, 0)
    if proto & 0x0FFF != 1024 or struct.unpack_from("<H", data, 32)[0] != 3:   # StateService
        return None
    mac = N.mac_str(data[8:14])
    return {"model": "LIFX light", "serial": mac.replace(":", ""), "serial_source": "LIFX serial",
            "brand": "LIFX", "category": "light", "mac": mac}


GOVEE_SCAN = b'{"msg":{"cmd":"scan","data":{"account_topic":"reserve"}}}'


def parse_govee(data, ip):
    j = _json(data)
    msg = (j or {}).get("msg") if isinstance(j, dict) else None
    if not isinstance(msg, dict) or msg.get("cmd") != "scan":
        return None
    d = msg.get("data") or {}
    return {"ip": d.get("ip") or ip, "model": f"Govee {d.get('sku', '')}".strip(),
            "serial": d.get("device", ""), "serial_source": "Govee device ID",
            "brand": "Govee", "category": "light", "fw": d.get("wifiVersionSoft", "")}


WIZ_QUERY = b'{"method":"getSystemConfig","params":{}}'


def parse_wiz(data):
    j = _json(data)
    r = (j or {}).get("result") if isinstance(j, dict) else None
    if not isinstance(r, dict) or "mac" not in r:
        return None
    module = r.get("moduleName", "")
    mac = fmt_mac(r["mac"])
    return {"model": f"WiZ {module}".strip(), "serial": r["mac"], "serial_source": "WiZ MAC",
            "brand": "WiZ", "category": "plug" if "SOCKET" in module.upper() else "light",
            "mac": mac, "fw": r.get("fwVersion", "")}


YEELIGHT_QUERY = (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1982\r\n'
                  b'MAN: "ssdp:discover"\r\nST: wifi_bulb\r\n\r\n')


def parse_yeelight(data):
    hd = parse_ssdp(data)
    if not hd or not hd.get("location", "").startswith("yeelight://"):
        return None
    host = hd["location"][len("yeelight://"):].split(":")[0]
    return {"ip": host, "name": hd.get("name", ""), "model": f"Yeelight {hd.get('model', '')}".strip(),
            "serial": hd.get("id", ""), "serial_source": "Yeelight ID", "brand": "Yeelight",
            "category": "light", "fw": hd.get("fw_ver", "")}


TUYA_UDP_KEY = hashlib.md5(b"yGAdlopoPVldABfn").digest()


def parse_tuya(data):
    if len(data) < 28 or data[:4] != b"\x00\x00\x55\xaa":
        return None
    for start in (20, 24):
        body = data[start:-8]
        j = _json(body)
        if j is None and body and len(body) % 16 == 0:
            j = _json(aes128_ecb_decrypt(TUYA_UDP_KEY, body))
        if isinstance(j, dict) and "gwId" in j:
            return {"ip": j.get("ip", ""), "model": "Tuya device" + (f" ({j['productKey']})" if j.get("productKey") else ""),
                    "serial": j["gwId"], "serial_source": "Tuya device ID", "brand": "Tuya / Smart Life",
                    "category": "plug", "fw": f"protocol {j.get('version', '')}".strip()}
    return None


def parse_mdns_txt(stype, txt):
    """Pull model / name / MAC out of a service's TXT record."""
    kv = {}
    for t in txt or []:
        k, _, v = t.partition("=")
        kv[k.lower()] = v
    out = {}
    if stype.startswith("_googlecast"):
        out = {"model": kv.get("md", ""), "name": kv.get("fn", ""), "brand_hint": "Google"}
    elif stype.startswith(("_hap", "_homekit")):
        out = {"model": kv.get("md", "")}
    elif stype.startswith(("_airplay", "_raop", "_device-info")):
        out = {"model": kv.get("model") or kv.get("am", ""), "brand_hint": "Apple" if
               re.match(r"(AppleTV|AudioAccessory|HomePod|Mac|iPhone|iPad)", kv.get("model") or kv.get("am", "")) else ""}
    elif stype.startswith("_esphomelib"):
        out = {"model": kv.get("project_name") or kv.get("board", ""), "mac": fmt_mac(kv.get("mac", "")),
               "brand_hint": "ESPHome"}
    elif stype.startswith("_wled"):
        out = {"mac": fmt_mac(kv.get("mac", "")), "brand_hint": "WLED", "model": "WLED"}
    elif stype.startswith(("_ipp", "_printer", "_pdl")):
        out = {"model": kv.get("ty") or kv.get("product", "").strip("()"),
               "brand_hint": kv.get("usb_mfg", "")}
    elif stype.startswith("_nanoleaf"):
        out = {"model": kv.get("md", ""), "brand_hint": "Nanoleaf"}
    elif stype.startswith("_shelly"):
        out = {"model": f"Shelly {kv.get('app', '')}".strip(), "brand_hint": "Shelly"}
    elif stype.startswith(("_matter", "_matterc")):
        out = {"model": "Matter device"}
    return {k: v for k, v in out.items() if v}


# ====================================================================== classification
def classify(dev):
    """Fill in brand / category / smart from everything we know about a device."""
    text = " ".join(str(dev.get(k, "")) for k in ("brand_hint", "vendor", "hostname", "name", "model",
                                                     "desc")) + " " + " ".join(dev.get("mdns_types", []))
    if not dev.get("brand"):
        for rx, brand, cat in _BRAND_RX:
            if rx.search(text):
                dev["brand"] = brand
                dev.setdefault("_brand_cat", cat)
                break
    if not dev.get("brand"):
        dev["brand"] = dev.get("brand_hint") or (dev.get("vendor") or "").split(",")[0][:28]
    if not dev.get("category"):
        words = " ".join(str(dev.get(k, "")) for k in ("model", "name", "hostname", "desc"))
        for rx, cat in _CAT_RX:
            if rx.search(words):
                dev["category"] = cat
                break
    if not dev.get("category"):
        for t in dev.get("mdns_types", []):
            if t in MDNS_CATEGORY:
                dev["category"] = MDNS_CATEGORY[t]
                break
    if not dev.get("category"):
        for p in dev.get("ports", []):
            if p in PORT_CATEGORY:
                dev["category"] = PORT_CATEGORY[p]
                break
    if not dev.get("category"):
        dev["category"] = dev.get("_brand_cat") or "unknown"
    dev.pop("_brand_cat", None)
    dev["smart"] = dev["category"] in SMART_CATS or bool(set(dev.get("sources", [])) & PROTOCOL_SOURCES)
    return dev


PROTOCOL_SOURCES = {"Kasa", "LIFX", "Govee", "WiZ", "Yeelight", "Tuya", "Roku", "Hue", "Shelly"}


# ====================================================================== the scanner
class SmartScan:
    """
    Runs every discovery method in parallel and merges the results by IP.
      arp_table_fn()  -> [(ip, mac, state)]   the OS neighbor table (backend supplies it)
      mdns_scan_fn()  -> MdnsBrowser.snapshot() after running a scan
      progress(text)  -> status line updates
    """

    def __init__(self, src_ip, mask, my_mac, oui, arp_table_fn, mdns_scan_fn, progress=None,
                 services=False):
        self.services = services           # also check the common-services ports on every host
        self.src, self.mask, self.my_mac = src_ip, mask, N.norm_mac(my_mac)
        self.oui, self.arp_table_fn, self.mdns_scan_fn = oui, arp_table_fn, mdns_scan_fn
        self.progress = progress or (lambda t: None)
        self.lock = threading.Lock()
        self.devs = {}                     # ip -> dict
        self.counts = {}
        net, self.hosts, _ = N.scan_hosts(src_ip, mask)
        self.bcast = str(net.broadcast_address)

    # -- merge a finding into the device table
    def add(self, ip, finding, source, prio):
        if not N.is_ipv4(ip) or ip == self.src:
            return
        with self.lock:
            d = self.devs.setdefault(ip, {"ip": ip, "sources": [], "mdns_types": [], "ports": [],
                                          "_prio": {}})
            if source not in d["sources"]:
                d["sources"].append(source)
                self.counts[source] = self.counts.get(source, 0) + 1
            for k, v in finding.items():
                if v in (None, "", [], {}) or k == "ip":
                    continue
                if k in ("mdns_types", "ports"):
                    d[k] = sorted(set(d[k]) | set(v))
                    continue
                if k == "mac":
                    v = N.norm_mac(v)
                if not d.get(k) or prio > d["_prio"].get(k, 0):
                    d[k] = v
                    d["_prio"][k] = prio

    def run(self, stop=None):
        t0 = time.time()
        self.progress("Waking up every host on the subnet…")
        self._touch_sweep()
        jobs = [self._ssdp, self._kasa, self._lifx, self._govee, self._wiz, self._yeelight,
                self._tuya, self._mdns]
        with cf.ThreadPoolExecutor(len(jobs)) as ex:
            futs = [ex.submit(j, stop) for j in jobs]
            self.progress("Asking devices to identify themselves…")
            cf.wait(futs, timeout=20)
        if stop and stop.is_set():
            return self.finish()
        self.progress("Reading the ARP table…")
        self._arp()
        self.progress("Checking hostnames and common services…" if self.services
                      else "Checking hostnames and open ports…")
        self._rdns_and_ports(stop)
        self.progress("Fetching device details (Roku, Hue, Shelly, Cast)…")
        self._http_enrich(stop)
        self.progress(f"Done in {time.time() - t0:.0f}s")
        return self.finish()

    def finish(self):
        out = []
        with self.lock:
            for d in self.devs.values():
                d = {k: v for k, v in d.items() if not k.startswith("_")}
                d["services_checked"] = self.services
                if d.get("mac") and self.oui:
                    d["vendor"] = self.oui.vendor_long(d["mac"])
                out.append(classify(d))
        out.sort(key=lambda d: N.u32(socket.inet_aton(d["ip"]), 0))
        return out

    # -- 1. make the OS ARP every address so the neighbor table fills up (works without Npcap)
    def _touch_sweep(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((self.src, 0))
            for h in self.hosts:
                try:
                    s.sendto(b"", (h, 9))
                except OSError:
                    pass
            s.close()
        except OSError:
            pass
        time.sleep(1.5)

    def _arp(self):
        try:
            rows = self.arp_table_fn() or []
        except Exception:  # noqa: BLE001
            rows = []
        net = (N.u32(socket.inet_aton(self.src), 0), N.u32(socket.inet_aton(self.mask), 0))
        for ip, mac, _state in rows:
            try:
                if N.u32(socket.inet_aton(ip), 0) & net[1] != net[0] & net[1]:
                    continue
            except OSError:
                continue
            if mac and mac != self.my_mac:
                self.add(ip, {"mac": mac}, "ARP", PRIO["oui"])

    # -- 2. SSDP / UPnP
    def _ssdp(self, stop):
        locs = {}
        try:
            s = _udp(self.src)
        except OSError:
            return
        for st in ("ssdp:all", "upnp:rootdevice", "roku:ecp"):
            msg = (f'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
                   f"MX: 2\r\nST: {st}\r\n\r\n").encode()
            try:
                s.sendto(msg, ("239.255.255.250", 1900))
            except OSError:
                pass

        def h(data, ip, port, _lp):
            hd = parse_ssdp(data)
            if not hd:
                return
            f = {}
            server = hd.get("server", "")
            if "roku" in (hd.get("st", "") + server).lower():
                f["brand_hint"] = "Roku"
            if hd.get("hue-bridgeid"):
                f.update(brand="Philips Hue", category="hub", serial=hd["hue-bridgeid"],
                         serial_source="Hue bridge ID")
            if server:
                f["desc"] = server[:80]
            self.add(ip, f, "SSDP", PRIO["upnp"] - 1)
            loc = hd.get("location", "")
            if url_is_on(loc, ip):
                locs.setdefault(ip, set()).add(loc)
        _collect(s, 3.0, h, stop)
        s.close()
        for ip, urls in list(locs.items())[:96]:
            for url in sorted(urls)[:2]:
                xml = http_get(url, self.src)
                f = parse_upnp_xml(xml) if xml else None
                if f:
                    self.add(ip, f, "UPnP", PRIO["upnp"])
                    break

    # -- 3. vendor protocols
    def _kasa(self, stop):
        try:
            s = _udp(self.src, broadcast=True)
        except OSError:
            return
        for _ in range(2):
            for payload, port in ((KASA_QUERY, 9999), (KASA_QUERY2, 20002)):
                try:
                    s.sendto(payload, (self.bcast, port))
                except OSError:
                    pass

        def h(data, ip, port, _lp):
            f = parse_kasa_legacy(data) if port == 9999 else parse_kasa_new(data) if port == 20002 else None
            if f:
                self.add(f.get("ip") or ip, f, "Kasa", PRIO["protocol"])
        _collect(s, 3.0, h, stop)
        s.close()

    def _lifx(self, stop):
        try:
            s = _udp(self.src, broadcast=True)
            s.sendto(lifx_packet(2), (self.bcast, 56700))
        except OSError:
            return

        def h(data, ip, port, _lp):
            f = parse_lifx(data)
            if f:
                self.add(ip, f, "LIFX", PRIO["protocol"])
        _collect(s, 2.5, h, stop)
        s.close()

    def _govee(self, stop):
        try:
            recv = _udp(self.src, port=4002, any_addr=True)
        except OSError:
            return
        try:
            send = _udp(self.src)
            send.sendto(GOVEE_SCAN, ("239.255.255.250", 4001))
            send.close()
        except OSError:
            pass

        def h(data, ip, port, _lp):
            f = parse_govee(data, ip)
            if f:
                self.add(f["ip"], f, "Govee", PRIO["protocol"])
        _collect(recv, 3.0, h, stop)
        recv.close()

    def _wiz(self, stop):
        try:
            s = _udp(self.src, broadcast=True)
            for _ in range(2):
                s.sendto(WIZ_QUERY, (self.bcast, 38899))
        except OSError:
            return

        def h(data, ip, port, _lp):
            f = parse_wiz(data)
            if f:
                self.add(ip, f, "WiZ", PRIO["protocol"])
        _collect(s, 2.5, h, stop)
        s.close()

    def _yeelight(self, stop):
        try:
            s = _udp(self.src)
            s.sendto(YEELIGHT_QUERY, ("239.255.255.250", 1982))
        except OSError:
            return

        def h(data, ip, port, _lp):
            f = parse_yeelight(data)
            if f:
                self.add(f.get("ip") or ip, f, "Yeelight", PRIO["protocol"])
        _collect(s, 2.5, h, stop)
        s.close()

    def _tuya(self, stop):
        """Tuya devices broadcast themselves every few seconds on 6666 / 6667."""
        socks = []
        for port in (6666, 6667):
            try:
                socks.append(_udp(None, broadcast=True, port=port, any_addr=True))
            except OSError:
                pass
        if not socks:
            return

        def h(data, ip, port, _lp):
            f = parse_tuya(data)
            if f:
                self.add(f.get("ip") or ip, f, "Tuya", PRIO["protocol"])
        _collect(socks, 7.0, h, stop)
        for s in socks:
            s.close()

    # -- 4. mDNS (uses the shared browser)
    def _mdns(self, stop):
        try:
            snap = self.mdns_scan_fn()
        except Exception:  # noqa: BLE001
            return
        for (label, stype), e in snap["inst"].items():
            ips = [ip for ip in snap["hosts"].get(e.get("host", ""), ()) if N.is_ipv4(ip)]
            if not ips:
                continue
            f = parse_mdns_txt(stype, e.get("txt"))
            f.setdefault("name", label)
            f["mdns_types"] = [stype]
            host = e.get("host", "").replace(".local", "")
            if host:
                f["hostname"] = host
            self.add(ips[0], f, "mDNS", PRIO["mdns"])

    # -- 5. reverse DNS + quick port probe
    def _rdns_and_ports(self, stop):
        with self.lock:
            ips = list(self.devs)
        if not ips:
            return

        def rdns(ip):
            try:
                name = socket.gethostbyaddr(ip)[0]
                return ip, name if name != ip else ""
            except (OSError, UnicodeError):
                return ip, ""

        def probe(ip, port):
            return ip, port, port_open(ip, port, self.src)

        ports = ALL_PORTS if self.services else PROBE_PORTS
        workers = 96
        # Every probe that gets no answer costs its full 0.4 s, so allow for a quiet subnet.
        budget = max(40, min(300, 0.4 * len(ips) * len(ports) / workers + 20))
        ex = cf.ThreadPoolExecutor(workers)
        try:
            rd = [ex.submit(rdns, ip) for ip in ips]
            pr = [ex.submit(probe, ip, p) for ip in ips for p in ports]
            try:
                for f in cf.as_completed(rd + pr, timeout=budget):
                    if stop and stop.is_set():
                        break
                    try:
                        r = f.result()
                    except Exception:  # noqa: BLE001
                        continue
                    if len(r) == 2 and r[1]:
                        self.add(r[0], {"hostname": r[1].split(".")[0]}, "DNS", PRIO["dns"])
                    elif len(r) == 3 and r[2]:
                        self.add(r[0], {"ports": [r[1]]}, "Ports", PRIO["ports"])
            except cf.TimeoutError:
                pass                       # keep what we have; the rest of the scan still runs
        finally:
            ex.shutdown(wait=False, cancel_futures=True)

    # -- 6. HTTP device info
    def _http_enrich(self, stop):
        with self.lock:
            devs = {ip: dict(d) for ip, d in self.devs.items()}
        tasks = []
        for ip, d in devs.items():
            text = " ".join(str(d.get(k, "")) for k in ("brand", "brand_hint", "hostname", "name", "desc")).lower()
            ports = set(d.get("ports", []))
            if 8060 in ports or "roku" in text:
                tasks.append((ip, f"http://{ip}:8060/query/device-info", parse_roku, "Roku"))
            if "hue" in text or "philips" in text or "signify" in text:
                tasks.append((ip, f"http://{ip}/api/config", parse_hue_config, "Hue"))
            if 80 in ports and not set(d.get("sources", [])) & PROTOCOL_SOURCES:
                tasks.append((ip, f"http://{ip}/shelly", parse_shelly, "Shelly"))
            if 8008 in ports or "_googlecast._tcp.local" in d.get("mdns_types", []):
                tasks.append((ip, f"http://{ip}:8008/setup/eureka_info?params=name,device_info",
                              parse_cast, "Cast"))

        def go(t):
            ip, url, parser, source = t
            if stop and stop.is_set():
                return
            text = http_get(url, self.src, timeout=1.5)
            f = parser(text) if text else None
            if f:
                self.add(ip, f, source, PRIO["http"])
        with cf.ThreadPoolExecutor(32) as ex:
            list(ex.map(go, tasks))


# ====================================================================== inventory (devices.csv)
INV_FIELDS = ["label", "brand", "category", "name", "model", "serial", "serial_source", "ip", "mac",
              "vendor", "hostname", "fw", "smart", "discovered_by", "open_ports", "services",
              "first_seen", "last_seen"]


def kept_ports(old_ports, new_ports, services_checked):
    """The ports to record after a scan. A quick scan only tests PROBE_PORTS, so anything an
    earlier full check found outside that list was not retested and is kept."""
    old = {int(p) for p in str(old_ports or "").split() if p.isdigit()}
    new = {int(p) for p in new_ports}
    return sorted(new if services_checked else new | (old - set(PROBE_PORTS)))


class DeviceStore:
    """devices.json keeps every device ever seen (keyed by MAC, else IP); devices.csv mirrors it."""

    def __init__(self, folder):
        self.json_path = os.path.join(folder, "devices.json")
        self.csv_path = os.path.join(folder, "devices.csv")
        self.lock = threading.Lock()
        try:
            with open(self.json_path, encoding="utf-8") as f:
                self.items = json.load(f)
        except (OSError, ValueError):
            self.items = {}

    @staticmethod
    def key(d):
        return d.get("mac") or f"ip:{d.get('ip')}"

    def merge(self, devices):
        """Record a scan. Returns (new_count, error_or_None)."""
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        new = 0
        with self.lock:
            for d in devices:
                k = self.key(d)
                old = self.items.get(k, {})
                if not old:
                    new += 1
                rec = {f: old.get(f, "") for f in INV_FIELDS}
                rec.update({f: d.get(f, "") for f in ("brand", "category", "name", "model", "serial",
                                                     "serial_source", "ip", "mac", "vendor", "hostname", "fw")
                            if d.get(f)})
                rec["smart"] = "yes" if d.get("smart") else "no"
                rec["discovered_by"] = ", ".join(d.get("sources", []))
                ports = kept_ports(old.get("open_ports"), d.get("ports", []), d.get("services_checked"))
                rec["open_ports"] = " ".join(map(str, ports))
                rec["services"] = service_names(ports)
                rec["first_seen"] = old.get("first_seen") or now
                rec["last_seen"] = now
                self.items[k] = rec
            return new, self._save()

    def set_label(self, key, label):
        with self.lock:
            if key in self.items:
                self.items[key]["label"] = label
                return self._save()
        return None

    def label(self, key):
        with self.lock:
            return self.items.get(key, {}).get("label", "")

    def set_ports(self, key, ports):
        """Record a full service check of one device."""
        with self.lock:
            if key in self.items:
                self.items[key]["open_ports"] = " ".join(map(str, sorted(set(ports))))
                self.items[key]["services"] = service_names(ports)
                return self._save()
        return None

    def ports(self, key):
        with self.lock:
            return [int(p) for p in str(self.items.get(key, {}).get("open_ports", "")).split() if p.isdigit()]

    def _save(self):
        try:
            tmp = self.json_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.items, f, indent=1)
            os.replace(tmp, self.json_path)
        except OSError as e:
            return f"Couldn't save devices: {e}"
        rows = sorted(self.items.values(), key=lambda r: (r.get("smart") != "yes", r.get("brand", "").lower(),
                                                          r.get("name", "").lower()))
        try:
            tmp = self.csv_path + ".tmp"
            with open(tmp, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.DictWriter(f, fieldnames=INV_FIELDS, extrasaction="ignore")
                w.writeheader()
                w.writerows(N.csv_safe(r) for r in rows)
            os.replace(tmp, self.csv_path)
        except PermissionError:
            return "devices.csv is open (Excel?) — will update next scan"
        except OSError as e:
            return f"Couldn't write devices.csv: {e}"
        return None
