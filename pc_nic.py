"""
pc_nic - read a network card's advanced settings and say which ones matter for Counter-Strike.

Windows: the adapter's Advanced tab and power management, through PowerShell. Linux: ethtool.
Both are turned into the same list of items, and grade() decides what each one should be.
Reading only: nothing here changes a setting.
"""
import datetime
import os
import re
import shutil

import pc_net as N

# What a setting is, whatever the driver calls it. Windows drivers share the registry keywords that
# start with "*"; the rest are each vendor's own, so the name on screen is the fallback.
WIN_KINDS = [
    ("eee", r"^\*eee$|^eee$|^eeelinkadvertisement$|^advancedeee$|^enableeee$",
     r"energy.efficient ethernet|^eee$|advanced eee"),
    ("power", r"greenethernet|^autodisablegigabit$|^sipsenabled$|^\*selectivesuspend$",
     r"green ethernet|auto disable gigabit|selective suspend|idle power saver"),
    ("lowpower", r"^ulpmode$|^powersavingmode$|^reducespeedonpowerdown$|^autopowersavemodeenabled$|"
                 r"^enablesavepowernow$", r"ultra low power|power saving mode|reduce (link )?speed"),
    ("intmod", r"^\*interruptmoderation$", r"^interrupt moderation$"),
    ("flow", r"^\*flowcontrol$", r"^flow control$"),
    ("rss", r"^\*rss$", r"^receive side scaling$"),
    ("jumbo", r"^\*jumbopacket$", r"jumbo"),
    ("speedcfg", r"^\*speedduplex$", r"speed\s*(&|and)\s*duplex"),
    ("buffers", r"^\*(receive|transmit)buffers$", r"^(receive|transmit) buffers$"),
    ("sum", r"^\*(udp|ip)checksum", r"(udp|ipv4) checksum"),
    ("tcp", r"^\*lso|^\*rsc|^\*tcp|^\*ipsec|^\*uso", r"large send|segment coalescing|tcp checksum"),
    ("wake", r"wake|wol|^\*pmarp|^\*pmns|pme$", r"wake|arp offload|ns offload"),
]

# kind: (level when wrong, the state that is wrong, what it should be, why)
ONOFF = {
    "power": ("bad", True, "Off", "Power saving slows the link down or puts it to sleep between packets."),
    "sleep": ("bad", True, "Off", "Windows can put the card to sleep in the middle of a session."),
    "lowpower": ("warn", True, "Off", "Meant to act only while the cable is out or the PC sleeps. Off rules it out."),
    "intmod": ("warn", True, "Off", "The card holds packets back to hand them over in batches. "
                                    "Off trades a little CPU for less delay."),
    "flow": ("warn", True, "Off", "Lets this PC and the switch pause each other's traffic."),
    "rss": ("warn", False, "On", "Spreads network work across CPU cores. Off puts all of it on one core."),
    "jumbo": ("warn", True, "Off", "Only works when every device on the LAN matches, and at a LAN party it won't."),
}
NOTES = {
    "tcp": "only for TCP or large sends; game packets are small UDP",
    "sum": "leave on; turning it off only costs CPU",
    "wake": "a wake-up feature; nothing happens while playing",
}
OLD_DRIVER_YEARS = 4
SECTIONS = (("bad", "Fix these"), ("warn", "Worth changing"), ("ok", "Set right"),
            ("note", "No effect on Counter-Strike"), ("info", "Other settings"))


def item(kind, name, value, state=None):
    return {"kind": kind, "name": name, "value": str(value), "state": state}


def grade(it):
    """(level, what it should be, why) for one item. Level is bad, warn, ok or info."""
    kind, state = it["kind"], it["state"]
    if kind in ONOFF:
        level, wrong, want, why = ONOFF[kind]
        return (level, want, why) if state == wrong else ("ok", "", "")
    if kind == "eee":
        if state == "on":
            return "bad", "Off", "The link naps between packets and adds a delay each time it wakes."
        if state == "idle":
            return "warn", "Off", "This switch port isn't using it, but another one may."
        return "ok", "", ""
    if kind in ("speedcfg", "link"):
        forced = kind == "speedcfg"
        if forced and state.get("auto"):
            return "ok", "", ""
        mbps, want = state.get("mbps"), "Auto" if forced else "1 Gb full duplex or better"
        if state.get("half"):
            return "bad", want, "Half duplex means collisions and lost packets."
        if mbps and mbps < 100:
            return "bad", want, "10 Mb is a bad cable or a bad setting."
        if mbps and mbps < 1000:
            return "warn", want, "100 Mb on a gigabit card usually means a bad cable or an old switch port."
        return ("warn", want, "A forced speed can mismatch the switch.") if forced else ("ok", "", "")
    if kind == "buffers":
        return ("warn", "Larger", "At its smallest the card drops packets in a burst.") if state == "min" \
            else ("ok", "", "")
    if kind == "wifi":
        return "bad", "Off", "With Wi-Fi connected as well, traffic can leave by the wrong card."
    if kind == "driver":
        if state is not None and state >= OLD_DRIVER_YEARS:
            return "warn", "Newer", "Check the card maker's site for a newer driver."
        return "info", "", ""
    return "info", "", ""


def rows(report, advice=True):
    """[(section, level, text)] in the order the page shows them."""
    out = []
    if not advice:
        return [("Settings", "info", f"{it['name']}: {it['value']}")
                for it in sorted(report["items"], key=lambda i: i["name"].lower())]
    graded = []
    for it in report["items"]:
        level, want, why = grade(it)
        text = f"{it['name']}: {it['value']}"
        if level in ("bad", "warn"):
            text += f"  →  {want}. {why}"
        elif level == "info" and it["kind"] in NOTES:
            level, text = "note", f"{text}  ({NOTES[it['kind']]})"
        graded.append((level, text))
    for level, title in SECTIONS:
        out += [(title, level, text) for lv, text in graded if lv == level]
    return out


def headline(report):
    """(text, level) for the top of the page."""
    levels = [grade(it)[0] for it in report["items"]]
    bad, warn = levels.count("bad"), levels.count("warn")
    if not levels:
        return "No settings read", "info"
    parts = ([f"{bad} to fix"] if bad else []) + ([f"{warn} worth changing"] if warn else [])
    if not parts:
        return "Set up well for Counter-Strike", "ok"
    return ", ".join(parts), "bad" if bad else "warn"


# ---------------------------------------------------------------- Windows
NIC_PS = r"""$ErrorActionPreference='SilentlyContinue'
$a = Get-NetAdapter -Name __NAME__
$pm = Get-NetAdapterPowerManagement -Name __NAME__
[pscustomobject]@{
  Description = $a.InterfaceDescription
  Provider = $a.DriverProvider
  Driver = $a.DriverVersion
  DriverDate = [string]$a.DriverDate
  Speed = [int64]$a.Speed
  FullDuplex = $a.FullDuplex
  TurnOff = [string]$pm.AllowComputerToTurnOffDevice
  SelectiveSuspend = [string]$pm.SelectiveSuspend
  Props = @(Get-NetAdapterAdvancedProperty -Name __NAME__ | Select-Object DisplayName, DisplayValue,
            RegistryKeyword, @{n='RegistryValue';e={[string](@($_.RegistryValue)[0])}},
            @{n='Min';e={$_.NumericParameterMinValue}}, @{n='Max';e={$_.NumericParameterMaxValue}})
  Others = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $_.Name -ne $a.Name } |
             Select-Object Name, @{n='Media';e={[string]$_.PhysicalMediaType}})
} | ConvertTo-Json -Compress -Depth 4"""


def win_kind(keyword, name):
    keyword, name = (keyword or "").strip().lower(), (name or "").strip().lower()
    for kind, kw, nm in WIN_KINDS:
        if (keyword and re.search(kw, keyword)) or (not keyword and re.search(nm, name)):
            return kind
    for kind, _, nm in WIN_KINDS:              # a vendor keyword nobody listed: go by the name on screen
        if re.search(nm, name):
            return kind
    return "other"


def win_on(reg, shown):
    """Whether an on/off style setting is on, from its registry value and the text on screen."""
    shown = (shown or "").strip().lower()
    if re.match(r"(disabled|off|no|none)\b", shown):
        return False
    if re.match(r"(enabled|on|yes)\b", shown):
        return True
    return str(reg if reg is not None else "").strip() not in ("", "0")


def parse_speed(shown):
    """'100 Mbps Half Duplex' as {"auto", "mbps", "half"}."""
    shown = (shown or "").lower()
    m = re.search(r"(\d+(?:\.\d+)?)\s*(g|m)", shown)
    mbps = int(float(m.group(1)) * (1000 if m.group(2) == "g" else 1)) if m else None
    return {"auto": "auto" in shown and mbps is None, "mbps": mbps, "half": "half" in shown}


def _num(v):
    m = re.search(r"\d+", str(v if v is not None else ""))
    return int(m.group()) if m else None


def _win_state(kind, p):
    reg, shown = p.get("RegistryValue"), p.get("DisplayValue")
    if kind == "eee":
        return "on" if win_on(reg, shown) else "off"
    if kind == "speedcfg":
        return parse_speed(shown)
    if kind == "jumbo":
        n = _num(reg) if _num(reg) is not None else _num(shown)
        if n is not None and n >= 1000 and not re.match(r"\s*(disabled|off)", (shown or "").lower()):
            return n > 1600                     # a frame size in bytes; 1514 is the ordinary one
        return win_on(reg, shown)
    if kind == "buffers":
        cur, lo, hi = _num(reg), _num(p.get("Min")), _num(p.get("Max"))
        return "min" if None not in (cur, lo, hi) and hi > lo and cur <= lo else "ok"
    if kind in ONOFF:
        return win_on(reg, shown)
    return None


def driver_age(date_text, today=None):
    """Whole years since a driver date like 2021-03-09, or None."""
    date_text = date_text or ""
    m = re.search(r"(\d{4})-(\d{1,2})-(\d{1,2})", date_text)
    us = re.search(r"(\d{1,2})/(\d{1,2})/(\d{4})", date_text)
    if not m and not us:
        return None
    y, mo, d = m.groups() if m else (us.group(3), us.group(1), us.group(2))
    try:
        then = datetime.date(int(y), int(mo), int(d))
    except ValueError:
        return None
    today = today or datetime.date.today()
    return max(0, today.year - then.year - ((today.month, today.day) < (then.month, then.day)))


def windows_report(js, today=None):
    """The PowerShell answer as a report: {"adapter": text, "items": [...]}."""
    js = js or {}
    items = []
    mbps = (js.get("Speed") or 0) // 1_000_000
    if mbps:
        half = js.get("FullDuplex") is False
        items.append(item("link", "Linked at", N.fmt_speed(mbps) + (" half duplex" if half else " full duplex"),
                          {"mbps": mbps, "half": half}))
    for p in N.as_list(js.get("Props")):
        if not isinstance(p, dict) or not p.get("DisplayName"):
            continue
        kind = win_kind(p.get("RegistryKeyword"), p.get("DisplayName"))
        items.append(item(kind, p["DisplayName"].strip(), p.get("DisplayValue") or "", _win_state(kind, p)))
    for key, kind, name in (("TurnOff", "sleep", "Allow the computer to turn off this device"),
                            ("SelectiveSuspend", "power", "Selective suspend")):
        v = (js.get(key) or "").strip()
        if v in ("Enabled", "Disabled"):
            items.append(item(kind, name, "On" if v == "Enabled" else "Off", v == "Enabled"))
    for o in N.as_list(js.get("Others")):
        if isinstance(o, dict) and re.search(r"802\.11|wireless", o.get("Media") or "", re.I):
            items.append(item("wifi", "Wi-Fi also connected", o.get("Name") or "", True))
    if js.get("Driver"):
        date = (js.get("DriverDate") or "").split(" ")[0].split("T")[0]
        inbox = (js.get("Provider") or "").strip().lower() == "microsoft"      # Windows' own drivers carry a fixed old date
        items.append(item("driver", "Driver", " ".join(x for x in (js.get("Provider"), js["Driver"], date) if x),
                          None if inbox else driver_age(date, today)))
    return {"adapter": js.get("Description") or "", "items": items}


def read_windows(name):
    return windows_report(N.ps_json(NIC_PS.replace("__NAME__", N.psq(name)), 25))


# ---------------------------------------------------------------- Linux
FEATURES = (("tcp-segmentation-offload", "tcp", "TCP segmentation offload"),
            ("generic-segmentation-offload", "tcp", "Generic segmentation offload"),
            ("generic-receive-offload", "tcp", "Generic receive offload"),
            ("large-receive-offload", "tcp", "Large receive offload"),
            ("rx-checksumming", "sum", "Receive checksum offload"),
            ("tx-checksumming", "sum", "Transmit checksum offload"))


def parse_coalesce(text):
    """`ethtool -c`: {"adaptive": bool, "usecs": int}, or {} when the driver doesn't say."""
    text = text or ""
    us = re.search(r"^rx-usecs:\s*(\d+)", text, re.M)
    ad = re.search(r"Adaptive RX:\s*(on|off)", text)
    if not us and not ad:
        return {}
    return {"adaptive": bool(ad and ad.group(1) == "on"), "usecs": int(us.group(1)) if us else 0}


def parse_rings(text):
    """`ethtool -g`: {"rx": (now, max), "tx": (now, max)} for the ones reported."""
    parts = re.split(r"Current hardware settings:", text or "")
    if len(parts) != 2:
        return {}
    out = {}
    for key in ("RX", "TX"):
        hi = re.search(rf"^{key}:\s*(\d+)", parts[0], re.M)
        cur = re.search(rf"^{key}:\s*(\d+)", parts[1], re.M)
        if hi and cur:
            out[key.lower()] = (int(cur.group(1)), int(hi.group(1)))
    return out


def parse_features(text):
    """`ethtool -k`: {feature: bool} for the top-level lines."""
    return {m.group(1): m.group(2) == "on"
            for m in re.finditer(r"^([a-z0-9-]+):\s*(on|off)", text or "", re.M)}


def linux_report(t):
    """ethtool's answers (a dict of command output by name) as a report."""
    items = []
    link = N.parse_ethtool_link(t.get("link"))
    if link["speed"]:
        half = (link["duplex"] or "").lower() == "half"
        items.append(item("link", "Linked at", N.fmt_speed(link["speed"]) + (" half duplex" if half else " full duplex"),
                          {"mbps": link["speed"], "half": half}))
    auto = re.search(r"Auto-negotiation:\s*(on|off)", t.get("link") or "")
    if auto:
        on = auto.group(1) == "on"
        items.append(item("speedcfg", "Speed and duplex", "Auto" if on else "Forced",
                          {"auto": on, "mbps": link["speed"], "half": (link["duplex"] or "").lower() == "half"}))
    eee = N.parse_ethtool_eee(t.get("eee"))
    if eee.get("supported"):
        state = "on" if eee["active"] else "idle" if eee["enabled"] else "off"
        items.append(item("eee", "Energy Efficient Ethernet",
                          {"on": "On and in use", "idle": "On, not in use on this port", "off": "Off"}[state], state))
    pause = N.parse_ethtool_pause(t.get("pause"))
    if "rx" in pause or "tx" in pause:
        which = [k.upper() for k in ("rx", "tx") if pause.get(k)]
        items.append(item("flow", "Flow control", " and ".join(which) + " on" if which else "Off", bool(which)))
    co = parse_coalesce(t.get("coalesce"))
    if co:
        on = co["adaptive"] or co["usecs"] > 0
        items.append(item("intmod", "Interrupt moderation",
                          "Adaptive" if co["adaptive"] else f"{co['usecs']} µs" if on else "Off", on))
    mtu = _num(t.get("mtu"))
    if mtu:
        items.append(item("jumbo", "Largest packet (MTU)", mtu, mtu > 1500))
    for key, (cur, hi) in sorted(parse_rings(t.get("rings")).items()):
        items.append(item("buffers", "Receive buffers" if key == "rx" else "Transmit buffers", f"{cur} of {hi}",
                          "min" if cur < 256 and hi > cur else "ok"))
    feats = parse_features(t.get("features"))
    for key, kind, name in FEATURES:
        if key in feats:
            items.append(item(kind, name, "On" if feats[key] else "Off"))
    for w in t.get("wifi") or []:
        items.append(item("wifi", "Wi-Fi also connected", w, True))
    drv = dict(re.findall(r"^([\w-]+):\s*(.+)$", t.get("driver") or "", re.M))
    if drv.get("driver"):
        fw = drv.get("firmware-version", "").strip()
        items.append(item("driver", "Driver", drv["driver"] + (f", kernel {drv['version']}" if drv.get("version") else "")
                          + (f", firmware {fw}" if fw and fw != "N/A" else "")))
    return {"adapter": t.get("desc") or "", "items": items}


def linux_wifi_up(skip):
    """Other network cards that are Wi-Fi and connected."""
    found = []
    try:
        names = sorted(os.listdir(N.SYS_NET))
    except OSError:
        return found
    for n in names:
        if n != skip and os.path.isdir(os.path.join(N.SYS_NET, n, "wireless")) \
                and N._read(os.path.join(N.SYS_NET, n, "operstate")) == "up":
            found.append(n)
    return found


def read_linux(name):
    if not shutil.which("ethtool"):
        return None

    def et(*args):
        return N.run(["ethtool", *args, name], 5)[1]
    return linux_report({"link": et(), "eee": et("--show-eee"), "pause": et("-a"), "coalesce": et("-c"),
                         "rings": et("-g"), "features": et("-k"), "driver": et("-i"),
                         "mtu": N._read(os.path.join(N.SYS_NET, name, "mtu")),
                         "wifi": linux_wifi_up(name), "desc": N.linux_describe(name)})


def read(name):
    """This adapter's settings as a report, or None when they can't be read here."""
    if N.IS_WIN:
        return read_windows(name)
    if N.IS_LINUX:
        return read_linux(name)
    return None
