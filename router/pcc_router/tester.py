"""What the router has learned about the port its WAN is plugged into, and the verdict on it.

Pure logic: frames, link changes, the WAN's DHCP status and check results are handed in by the
service (service.py), and snapshot() gives everything for the screen and the phone page. Nothing
here touches the network, so it is tested on a PC (tests/test_router.py).

Frames are decoded by PorkChopCheck's own pc_net.classify, the same decoders the desktop app uses.
"""

import threading
import time

import pc_net as N

NEIGHBOR_WAIT = 70  # CDP comes every 60 s: after this long with nothing, say so
PORTFAST_SLOW = 25  # seconds from link up to the gateway answering that suggests portfast is off
BCAST_WINDOW = 10  # seconds the broadcast rate is averaged over
EVENTS = 40  # kept for the event list


class Tester:
    def __init__(self, iface="eth0", clock=time.time):
        self.iface, self.clock = iface, clock
        self.lock = threading.Lock()
        self.events = []
        self.link = {"up": False, "speed": None, "duplex": None, "since": None, "ours": [], "partner": [],
                     "downshift": None, "drops": 0}
        self.wan = {}  # address, gateway, dns from the router's own DHCP client
        self.checks = {}  # gateway / dns / internet results
        self.public_ip = None
        self.blinking = False  # the port finder is bouncing the link on purpose: not a new port
        self.new_port(self.clock())

    # ---------- a new port: everything learned from the last one is forgotten ----------
    def new_port(self, now):
        self.neighbors = {}  # "CDP"/"LLDP" -> (info, time)
        self.stp = None
        self.stp_tcn = 0
        self.dtp = None
        self.eapol = None
        self.dhcp_servers = {}  # server ip -> {"mac", "offer", "time"}
        self.dhcp_options = {}
        self.vlans_seen = set()
        self.gateway_mac = None
        self.ipv6_routers = {}
        self.bcast = []  # times of broadcast frames, for a rate
        self.timing = {"link": now, "address": None, "gateway": None, "internet": None}
        self.probe = {"done": False, "time": None}

    def event(self, text, sev="info"):
        self.events.append({"t": self.clock(), "text": text, "sev": sev})
        del self.events[:-EVENTS]

    # ---------- inputs ----------
    def on_link(self, up, speed=None, duplex=None, ethtool_text=None):
        if self.blinking:
            return
        now = self.clock()
        with self.lock:
            was = self.link["up"]
            if up and not was:
                self.new_port(now)
                self.link["since"] = now
                self.event(f"Link up {N.fmt_speed(speed) if speed else ''} {duplex or ''}".strip())
            elif was and not up:
                self.link["drops"] += 1
                self.link["since"] = now
                self.event("Link down", "bad")
            elif up and speed and self.link["speed"] and speed != self.link["speed"]:
                self.event(f"Link speed changed to {N.fmt_speed(speed)}", "warn")
            self.link.update(up=up, speed=speed if up else None, duplex=duplex if up else None)
            if ethtool_text is not None and up:
                info = N.parse_ethtool_link(ethtool_text)
                self.link.update(ours=info["ours"], partner=info["partner"], downshift=N.downshift(info))

    def on_frame(self, raw):
        now = self.clock()
        if raw[:6] == N.BCAST:
            self.bcast.append(now)
        for kind, info in N.classify(raw):
            with self.lock:
                self._take(kind, info, now)

    def _take(self, kind, info, now):
        if kind == "VLAN":
            self.vlans_seen.add(info["vlan"])
        elif kind in ("CDP", "LLDP"):
            if kind not in self.neighbors:
                self.event(f"{kind} from {info.get('name') or info.get('chassis') or 'the switch'}")
            self.neighbors[kind] = (info, now)
        elif kind == "STP":
            if info.get("tcn") or info.get("tc"):
                self.stp_tcn += 1
                if self.stp_tcn == 1 or self.stp_tcn % 10 == 0:
                    self.event("Spanning tree topology change", "warn")
            if not info.get("tcn"):
                self.stp = info
        elif kind == "DTP":
            self.dtp = info
        elif kind == "EAPOL":
            if not self.eapol:
                self.event("802.1X: the switch asks for a login", "warn")
            self.eapol = info
        elif kind == "DHCP" and info.get("msg") in ("OFFER", "ACK") and info.get("server"):
            server = info["server"]
            if server not in self.dhcp_servers:
                if self.dhcp_servers:
                    self.event(f"A second DHCP server answered: {server}", "bad")
                self.dhcp_servers[server] = {"mac": info.get("src"), "time": now}
            self.dhcp_servers[server]["time"] = now
            for key in ("lease", "domain", "tftp_name", "tftp_ips", "opt43", "ntp", "mask", "routers", "dns"):
                if key in info:
                    self.dhcp_options[key] = info[key]
        elif kind == "ARP" and info.get("op") == 2 and info.get("spa") == self.wan.get("gateway"):
            if self.gateway_mac and self.gateway_mac != info.get("sha"):
                self.event(f"The gateway answered from another MAC: {info.get('sha')}", "warn")
            self.gateway_mac = info.get("sha")
        elif kind == "RA":
            src = info.get("router") or info.get("src")
            if src and src not in self.ipv6_routers:
                if self.ipv6_routers:
                    self.event(f"Another IPv6 router: {src}", "warn")
                self.ipv6_routers[src] = info

    def on_wan(self, status):
        """The router's own DHCP client's view (ubus network.interface.wan status)."""
        now = self.clock()
        addrs = status.get("ipv4-address") or []
        route = next((r for r in status.get("route") or [] if r.get("target") == "0.0.0.0"), {})
        wan = {
            "address": addrs[0]["address"] if addrs else None,
            "mask": addrs[0].get("mask") if addrs else None,
            "gateway": route.get("nexthop"),
            "dns": status.get("dns-server") or [],
            "domain": (status.get("dns-search") or [None])[0],
        }
        with self.lock:
            if wan["address"] and not self.wan.get("address"):
                self.event(f"Address {wan['address']}/{wan['mask']}")
                if self.link["up"] and self.timing["address"] is None:
                    self.timing["address"] = now
            elif self.wan.get("address") and not wan["address"]:
                self.event("Lost the address", "bad")
            self.wan = wan

    def on_check(self, name, ok, ms=None, detail=""):
        """gateway / dns / internet: ok, round trip in ms."""
        now = self.clock()
        with self.lock:
            before = self.checks.get(name, {}).get("ok")
            self.checks[name] = {"ok": ok, "ms": ms, "detail": detail, "time": now}
            if ok and name in ("gateway", "internet") and self.link["up"] and self.timing[name] is None:
                self.timing[name] = now
            if before is not None and before != ok:
                self.event(f"{name.capitalize()} {'answers again' if ok else 'stopped answering'}", "info" if ok else "bad")

    def on_probe(self):
        """A DHCP DISCOVER of our own went out: every server that answers it shows up in dhcp_servers."""
        with self.lock:
            self.probe = {"done": False, "time": self.clock()}

    def probe_done(self):
        with self.lock:
            self.probe["done"] = True

    def set_gateway_mac(self, mac):
        """From the router's neighbor table, for when no ARP reply has been seen on the wire."""
        with self.lock:
            if mac and not self.gateway_mac:
                self.gateway_mac = mac

    # ---------- out ----------
    def snapshot(self):
        now = self.clock()
        with self.lock:
            nb = N.merge_neighbors(self.neighbors) if self.neighbors else {}
            self.bcast = [t for t in self.bcast if now - t < BCAST_WINDOW]
            link_age = now - self.link["since"] if self.link["since"] else None
            t0 = self.timing["link"]

            def after(key):
                t = self.timing.get(key)
                return round(t - t0, 1) if t and t0 else None

            snap = {
                "time": now,
                "iface": self.iface,
                "link": {**self.link, "age": link_age},
                "switch": {
                    "name": nb.get("name") or nb.get("chassis"), "port": nb.get("port"),
                    "vlan": nb.get("vlan"), "vlan_name": nb.get("vlan_name"), "voice_vlan": nb.get("voice_vlan"),
                    "mgmt_ip": nb.get("mgmt_ip"), "platform": nb.get("platform"), "poe": nb.get("poe"),
                    "duplex": nb.get("duplex"), "mau": nb.get("mau"), "vtp": nb.get("vtp"),
                    "protocols": sorted(self.neighbors), "heard": bool(nb),
                },
                "wan": dict(self.wan),
                "dhcp": {"servers": sorted(self.dhcp_servers), "options": dict(self.dhcp_options),
                         "probe": dict(self.probe)},
                "checks": {k: dict(v) for k, v in self.checks.items()},
                "public_ip": self.public_ip,
                "timing": {"address": after("address"), "gateway": after("gateway"), "internet": after("internet")},
                "l2": {
                    "dot1x": self.eapol, "stp": self.stp, "stp_changes": self.stp_tcn, "dtp": self.dtp,
                    "vlans_tagged": sorted(self.vlans_seen), "gateway_mac": self.gateway_mac,
                    "gateway_kind": N.mac_kind(self.gateway_mac) if self.gateway_mac else None,
                    "ipv6_routers": sorted(self.ipv6_routers), "broadcasts_per_s": round(len(self.bcast) / BCAST_WINDOW, 1),
                },
                "events": list(self.events),
            }  # fmt: skip
        snap["findings"] = findings(snap)
        snap["verdict"] = worst(snap["findings"])
        return snap


# ---------- the verdict ----------
def findings(s):
    """[(level, text)] worst first: bad (red), warn (amber), good (green)."""
    out = []
    link, wan, sw, l2, checks = s["link"], s["wan"], s["switch"], s["l2"], s["checks"]
    if not link["up"]:
        return [("bad", "No link")]
    if l2["dot1x"] and not wan.get("address"):
        out.append(("bad", "802.1X: needs a login"))
    if not wan.get("address"):
        out.append(("bad", "No DHCP address" if (link["age"] or 0) > 15 else "Waiting for an address"))
    if len(s["dhcp"]["servers"]) > 1:
        out.append(("bad", f"{len(s['dhcp']['servers'])} DHCP servers (rogue?)"))
    gw = checks.get("gateway")
    if wan.get("address") and gw and not gw["ok"]:
        out.append(("bad", "Gateway not answering"))
    if link.get("duplex") and link["duplex"].lower().startswith("half"):
        out.append(("warn", "Half duplex"))
    if link.get("downshift"):
        out.append(("warn", f"Linked at {N.fmt_speed(link['speed'])}, both ends can do {N.fmt_speed(link['downshift'])}: cable?"))
    inet = checks.get("internet")
    if inet and not inet["ok"] and wan.get("address"):
        out.append(("warn", "No internet"))
    t = s["timing"].get("gateway")
    if t is not None and t > PORTFAST_SLOW:
        out.append(("warn", f"Took {t:.0f} s to pass traffic: portfast off?"))
    if l2["stp_changes"] > 5:
        out.append(("warn", f"{l2['stp_changes']} spanning tree changes"))
    if len(l2["ipv6_routers"]) > 1:
        out.append(("warn", f"{len(l2['ipv6_routers'])} IPv6 routers"))
    if not sw["heard"] and (link["age"] or 0) > NEIGHBOR_WAIT:
        out.append(("warn", "No CDP or LLDP from the switch"))
    if not out:
        out.append(("good", "Port looks good"))
    order = {"bad": 0, "warn": 1, "good": 2}
    return sorted(out, key=lambda f: order[f[0]])


def worst(found):
    return found[0][0] if found else "good"
