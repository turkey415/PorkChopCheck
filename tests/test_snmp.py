"""Switch readout: the SNMP client against a pretend switch on this machine, then port grading
and the front-panel layout. No real switch needed."""
import bisect
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import pc_snmp as SN  # noqa: E402

ok = 0


def check(name, cond, extra=""):
    global ok
    assert cond, f"FAIL {name} {extra}"
    ok += 1
    print("ok ", name)


def raises(fn, kind=SN.SnmpError):
    try:
        fn()
    except kind:
        return True
    return False


# --- encoding, against packets other SNMP software produces
# snmpget -v2c -c public, request id 1, sysDescr.0 (matches Scapy's SNMP layer byte for byte)
GET_SYSDESCR = bytes.fromhex("302602010104067075626c6963a019020101020100020100300e300c06082b060102010101000500")
check("get request bytes", SN.build_request(2, "public", SN.PDU_GET, 1, [SN.SYS_DESCR]) == GET_SYSDESCR)
check("v1 carries version 0", SN.build_request(1, "public", SN.PDU_GET, 1, [SN.SYS_DESCR])[4] == 0)
bulk = SN.build_request(2, "public", SN.PDU_BULK, 7, [SN.IF], max_rep=20)
check("bulk asks for repetitions", SN.parse_message(bulk)[2:6] == (SN.PDU_BULK, 7, 0, 20))
check("oid text", SN.oid("1.3.6.1.2.1.1.5.0") == (1, 3, 6, 1, 2, 1, 1, 5, 0) and SN.oid_str((1, 3, 6)) == "1.3.6")
check("big oid numbers", SN._dec_oid(SN._enc_oid((1, 3, 6, 1, 4, 1, 9, 9, 23, 16383, 16384, 4294967295))[2:])
      == (1, 3, 6, 1, 4, 1, 9, 9, 23, 16383, 16384, 4294967295))
check("oid under 2.x", SN._dec_oid(SN._enc_oid((2, 39, 5))[2:]) == (2, 39, 5))
for n in (0, 1, 127, 128, 255, 256, 65535, 2 ** 31 - 1):
    check(f"integer {n}", SN._dec_int(SN._enc_int(n)[2:]) == n)
check("negative integer", SN._dec_int(SN._enc_int(-1)[2:]) == -1)
check("counter above 2^31", SN._dec_value(SN.T_COUNTER, SN.encode_value(SN.T_COUNTER, 4000000000)[2:]) == 4000000000)
check("counter64", SN._dec_value(SN.T_COUNTER64, SN.encode_value(SN.T_COUNTER64, 2 ** 40)[2:]) == 2 ** 40)
check("long length form", SN._read_tlv(SN._tlv(SN.T_STR, b"x" * 300), 0) == (SN.T_STR, 4, 304))
check("ip address", SN._dec_value(SN.T_IP, bytes([10, 2, 1, 5])) == "10.2.1.5")
check("text cleans up", SN.text(b"  SW-1\x00 ") == "SW-1" and SN.text(None) == "" and SN.text(SN.END) == "")

v, comm, pdu, rid, a, b, binds = SN.parse_message(GET_SYSDESCR)
check("parse request", (v, comm, pdu, rid, binds) == (2, b"public", SN.PDU_GET, 1, [(SN.SYS_DESCR, None)]))

# --- packets that are not SNMP must be refused, not crash
for name, junk in (("empty", b""), ("text", b"hello there"), ("cut short", GET_SYSDESCR[:20]),
                   ("length past the end", b"\x30\x82\xff\xff\x02\x01\x01"), ("endless length", b"\x30\x85" + b"\x01" * 9),
                   ("wrong outer type", b"\x04" + GET_SYSDESCR[1:]), ("not a pdu", GET_SYSDESCR.replace(b"\xa0\x19", b"\x30\x19")),
                   ("oid never ends", b"\x30\x0b\x02\x01\x01\x04\x00\xa2\x04\x06\x02\x81\x81")):
    check(f"refuses {name}", raises(lambda j=junk: SN.parse_message(j)))
for i in range(len(GET_SYSDESCR)):
    for bad in (0x00, 0x7F, 0xFF):                  # flip every byte: an error is fine, a crash is not
        try:
            SN.parse_message(GET_SYSDESCR[:i] + bytes([bad]) + GET_SYSDESCR[i + 1:])
        except SN.SnmpError:
            pass
check("survives every corrupted byte", True)


# --- a pretend switch
class Agent(threading.Thread):
    """Answers get, get-next and get-bulk from a dict of {oid: (type, value)} like a real agent."""

    def __init__(self, mib, community="public"):
        super().__init__(daemon=True)
        self.mib, self.community, self.seen = mib, community.encode(), 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.start()

    def after(self, o, version):
        keys = sorted(k for k, (t, _) in self.mib.items() if version == 2 or t != SN.T_COUNTER64)
        i = bisect.bisect_right(keys, o)
        return keys[i] if i < len(keys) else None

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            try:
                version, comm, pdu, rid, _, reps, binds = SN.parse_message(data)
            except SN.SnmpError:
                continue
            self.seen += 1
            if comm != self.community:
                continue                            # a real agent stays silent for a wrong community
            out, status, index = [], 0, 0
            if pdu == SN.PDU_GET:
                for i, (o, _) in enumerate(binds):
                    if o in self.mib:
                        out.append((o, SN.encode_value(*self.mib[o])))
                    elif version == 1:
                        status, index, out = 2, i + 1, [(o, SN.encode_value(SN.T_NULL)) for o, _ in binds]
                        break
                    else:
                        out.append((o, SN.encode_value(SN.T_NO_OBJECT)))
            else:
                o = binds[0][0]
                for _ in range(max(1, reps) if pdu == SN.PDU_BULK else 1):
                    nxt = self.after(o, version)
                    if nxt is None:
                        if version == 1:
                            status, index, out = 2, 1, [(o, SN.encode_value(SN.T_NULL))]
                        else:
                            out.append((o, SN.encode_value(SN.T_END)))
                        break
                    out.append((nxt, SN.encode_value(*self.mib[nxt])))
                    o = nxt
            self.sock.sendto(SN.build_message(version, comm.decode(), SN.PDU_RESPONSE, rid, out, status, index), addr)

    def close(self):
        self.sock.close()


def switch_mib(name="SW-TABLE-1", fa=24, gi=2):
    """A Catalyst 3560-24 as its SNMP agent would describe it."""
    mib = {SN.SYS_DESCR: (SN.T_STR, "Cisco IOS Software, C3560 Software (C3560-IPSERVICESK9-M), Version 12.2(55)SE"),
           SN.SYS_OBJECT: (SN.T_OID, SN.oid("1.3.6.1.4.1.9.1.633")), SN.SYS_UPTIME: (SN.T_TICKS, 8640000),
           SN.SYS_NAME: (SN.T_STR, name), SN.BRIDGE_PORTS: (SN.T_INT, fa + gi),
           SN.CDP_ADDRESS + (10101, 1): (SN.T_STR, bytes([10, 2, 1, 3])),
           SN.CDP_ADDRESS + (10102, 2): (SN.T_STR, bytes([10, 2, 1, 4])),
           SN.CDP_ADDRESS + (10005, 3): (SN.T_STR, bytes([10, 2, 1, 3]))}

    def port(idx, full, short, kind, speed, up=True):
        rows = {(SN.IF, 2): (SN.T_STR, full), (SN.IF, 3): (SN.T_INT, kind), (SN.IF, 5): (SN.T_GAUGE, speed * 1000000),
                (SN.IF, 7): (SN.T_INT, 1), (SN.IF, 8): (SN.T_INT, 1 if up else 2), (SN.IF, 9): (SN.T_TICKS, 4000),
                (SN.IF, 10): (SN.T_COUNTER, 1000), (SN.IF, 13): (SN.T_COUNTER, 0), (SN.IF, 14): (SN.T_COUNTER, 0),
                (SN.IF, 16): (SN.T_COUNTER, 2000), (SN.IF, 19): (SN.T_COUNTER, 0), (SN.IF, 20): (SN.T_COUNTER, 0),
                (SN.IFX, 1): (SN.T_STR, short), (SN.IFX, 6): (SN.T_COUNTER64, 2 ** 33), (SN.IFX, 10): (SN.T_COUNTER64, 2 ** 34),
                (SN.IFX, 15): (SN.T_GAUGE, speed), (SN.IFX, 18): (SN.T_STR, "")}
        if kind == 6:
            rows.update({(SN.DOT3, 2): (SN.T_COUNTER, 0), (SN.DOT3, 3): (SN.T_COUNTER, 0), (SN.DOT3, 8): (SN.T_COUNTER, 0),
                         (SN.DOT3, 9): (SN.T_COUNTER, 0), (SN.DOT3, 19): (SN.T_INT, 3)})
        for (table, col), val in rows.items():
            mib[table + (col, idx)] = val
    port(1, "Vlan1", "Vl1", 53, 1000)
    for n in range(1, fa + 1):
        port(10000 + n, f"FastEthernet0/{n}", f"Fa0/{n}", 6, 100, up=n <= 20)
    for n in range(1, gi + 1):
        port(10100 + n, f"GigabitEthernet0/{n}", f"Gi0/{n}", 6, 1000)
    port(10501, "Null0", "Nu0", 1, 0)
    return mib


mib = switch_mib()
mib[SN.IFX + (18, 10005)] = (SN.T_STR, "Seat A-05")
mib[SN.DOT3 + (19, 10007)] = (SN.T_INT, 2)             # Fa0/7 is at half duplex
mib[SN.IF + (7, 10024)] = (SN.T_INT, 2)                # Fa0/24 is shut down
del mib[SN.IFX + (6, 10102)]                           # Gi0/2 has no 64-bit traffic counter
mib[SN.oid("1.3.6.1.2.1.47.1.1.1.1.13.1")] = (SN.T_STR, "")
mib[SN.oid("1.3.6.1.2.1.47.1.1.1.1.13.1001")] = (SN.T_STR, "WS-C3560-24TS-S")
agent = Agent(mib)


def client(version=2, community="public", **kw):
    return SN.Client("127.0.0.1", community, version, timeout=kw.pop("timeout", 0.5), port=agent.port, **kw)


# --- get
for version in (1, 2):
    with client(version) as c:
        got = c.get([SN.SYS_NAME, SN.SYS_DESCR, SN.SYS_UPTIME])
        check(f"v{version} get", SN.text(got[SN.SYS_NAME]) == "SW-TABLE-1" and got[SN.SYS_UPTIME] == 8640000)
        missing = SN.oid("1.3.6.1.2.1.1.99.0")
        got = c.get([SN.SYS_NAME, missing, SN.SYS_UPTIME])
        check(f"v{version} missing value is None, the rest still come back",
              got[missing] is None and SN.text(got[SN.SYS_NAME]) == "SW-TABLE-1" and got[SN.SYS_UPTIME] == 8640000, got)
        many = [SN.IF + (2, 10000 + n) for n in range(1, 25)] + [SN.IF + (2, 10100 + n) for n in (1, 2)]
        got = c.get(many)
        check(f"v{version} more values than fit in one request", len(got) == 26
              and SN.text(got[many[-1]]) == "GigabitEthernet0/2")

# --- walk
for version in (1, 2):
    with client(version) as c:
        col = c.column(SN.IF + (2,))
        check(f"v{version} walks a whole column", len(col) == 28 and SN.text(col[(10024,)]) == "FastEthernet0/24", len(col))
        check(f"v{version} walk stops at the column's end", all(len(k) == 1 for k in col))
        check(f"v{version} walk of nothing", c.walk(SN.oid("1.3.6.1.2.1.99")) == [])
        last = c.walk(SN.CDP_ADDRESS)
        check(f"v{version} walk to the end of the device", len(last) == 3)
with client(2) as c:
    check("v2 reads 64-bit counters", c.column(SN.IFX + (6,))[(10001,)] == 2 ** 33)
with client(1) as c:
    check("v1 never sees 64-bit counters", c.column(SN.IFX + (6,)) == {})

# --- no answer
with client(2, community="wrong", timeout=0.15) as c:
    check("wrong community times out", raises(lambda: c.get([SN.SYS_NAME]), SN.SnmpTimeout))
before = agent.seen
with client(2, community="wrong", timeout=0.1, retries=2) as c:
    raises(lambda: c.get([SN.SYS_NAME]))
check("retries the request", agent.seen - before == 3, agent.seen - before)
dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dead.bind(("127.0.0.1", 0))
with SN.Client("127.0.0.1", timeout=0.15, port=dead.getsockname()[1]) as c:
    check("silent device times out", raises(lambda: c.get([SN.SYS_NAME]), SN.SnmpTimeout))
port_closed = dead.getsockname()[1]
dead.close()
with SN.Client("127.0.0.1", timeout=0.3, port=port_closed) as c:
    check("nothing listening is reported as no answer", raises(lambda: c.get([SN.SYS_NAME]), SN.SnmpTimeout))


class Liar(threading.Thread):
    """Answers every request with junk, then with a reply to some other request."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.start()

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            rid = SN.parse_message(data)[3]
            self.sock.sendto(b"\x30\x03junk", addr)
            self.sock.sendto(SN.build_message(2, "public", SN.PDU_RESPONSE, rid + 1,
                                              [(SN.SYS_NAME, SN.encode_value(SN.T_STR, "impostor"))]), addr)


liar = Liar()
with SN.Client("127.0.0.1", timeout=0.2, retries=0, port=liar.port) as c:
    check("junk and mismatched replies are ignored", raises(lambda: c.get([SN.SYS_NAME]), SN.SnmpTimeout))
liar.sock.close()

# --- finding switches
found = SN.sweep(["127.0.0.1"], "public", timeout=0.3, port=agent.port)
check("sweep finds the switch", SN.text(found.get("127.0.0.1", {}).get("name")) == "SW-TABLE-1", found)
check("sweep with v1", "127.0.0.1" in SN.sweep(["127.0.0.1"], "public", version=1, timeout=0.3, port=agent.port))
check("sweep with the wrong community finds nothing", SN.sweep(["127.0.0.1"], "nope", timeout=0.15, port=agent.port) == {})
stop = threading.Event()
stop.set()
check("sweep can be stopped", SN.sweep(["127.0.0.1"], "public", timeout=0.3, stop=stop, port=agent.port) == {})
with client() as c:
    info = SN.identify(c)
    check("identify", info["name"] == "SW-TABLE-1" and info["bridge_ports"] == 26 and info["uptime"] == 8640000)
    check("cisco by its object id", SN.is_cisco(info) and SN.is_switch(info))
    check("model number read from the switch", SN.model_of(info) == "WS-C3560-24TS-S", SN.model_of(info))
    check("model from the description", SN.model_of({"descr": info["descr"]}) == "C3560")
    check("cdp neighbors, each once", SN.cdp_neighbors(c) == ["10.2.1.3", "10.2.1.4"])
check("model number from the switch itself wins", SN.model_of({"model": "WS-C3560-24TS-S", "descr": "C3560 Software"})
      == "WS-C3560-24TS-S")
check("no model out of a generic description", SN.model_of({"descr": "Cisco IOS Software [Fuji], Catalyst L3 Switch Software"}) == "")
check("a printer is not a switch", not SN.is_switch({"descr": "HP LaserJet", "object": SN.oid("1.3.6.1.4.1.11.2"), "bridge_ports": 0}))
check("another make of switch is one", SN.is_switch({"descr": "ProCurve", "object": SN.oid("1.3.6.1.4.1.11.2"), "bridge_ports": 24}))

# --- reading ports
for version in (1, 2):
    with client(version) as c:
        ports = SN.read_ports(c)
    by = {p["name"]: p for p in ports}
    check(f"v{version} only the ethernet ports", len(ports) == 26 and "Vl1" not in by and "Nu0" not in by, len(ports))
    check(f"v{version} in port order", [p["name"] for p in ports[:3]] == ["Fa0/1", "Fa0/2", "Fa0/3"] and ports[-1]["name"] == "Gi0/2")
    check(f"v{version} speed and duplex", (by["Fa0/1"]["speed"], by["Fa0/1"]["duplex"], by["Gi0/1"]["speed"]) == (100, "full", 1000))
    check(f"v{version} half duplex seen", by["Fa0/7"]["duplex"] == "half")
    check(f"v{version} link and shut", by["Fa0/20"]["oper"] and not by["Fa0/21"]["oper"] and not by["Fa0/24"]["admin"])
    check(f"v{version} description", by["Fa0/5"]["alias"] == "Seat A-05" and by["Fa0/5"]["descr"] == "FastEthernet0/5")
    check(f"v{version} counters", by["Fa0/1"]["c"]["fcs"] == 0 and by["Fa0/1"]["c"]["in_err"] == 0)
    check(f"v{version} traffic counter width", by["Fa0/1"]["wide"] == (version == 2)
          and by["Fa0/1"]["c"]["in_oct"] == (2 ** 33 if version == 2 else 1000))
    check(f"v{version} port without a 64-bit counter uses the 32-bit one",
          not by["Gi0/2"]["wide"] and by["Gi0/2"]["c"]["in_oct"] == 1000)
agent.close()


# --- grading
def port(name="Gi0/1", **kw):
    c = dict(in_err=0, out_err=0, in_disc=0, out_disc=0, fcs=0, align=0, late=0, excess=0, in_oct=0, out_oct=0)
    c.update({k: kw.pop(k) for k in list(kw) if k in c})
    p = dict(index=kw.pop("index", 1), name=name, descr=name, alias="", admin=True, oper=True, speed=1000,
             duplex="full", last_change=4000, wide=True, c=c)
    p.update(kw)
    return p


def grade(readings, uptime=8640000, step=15.0):
    """Feed a list of readings of one port, 15 seconds apart, and return the last one graded."""
    w, t, out = SN.SwitchWatch(), 1000.0, None
    for r in readings:
        out = w.update([r], uptime, t)[0]
        t += step
        uptime += int(step * 100)
    return out


p = grade([port()])
check("clean port is green", (p["level"], p["reasons"]) == (SN.GOOD, []))
check("no traffic figure on the first look", p["in_mbps"] is None and p["busy"] is None)
p = grade([port(fcs=900, in_err=900)])
check("old errors do not count on the first look", p["level"] == SN.GOOD and p["errors"] == 0)
p = grade([port(fcs=900, in_err=900), port(fcs=900, in_err=900)])
check("old errors that are not rising stay green", p["level"] == SN.GOOD)
p = grade([port(), port(fcs=12, in_err=12)])
check("rising CRC errors are red", p["level"] == SN.BAD and "12 receive errors" in p["reasons"][0] and "CRC" in p["reasons"][0], p["reasons"])
check("CRC is not counted twice", p["errors"] == 12)
p = grade([port(), port(in_err=5)])
check("receive errors without CRC", p["level"] == SN.BAD and "CRC" not in p["reasons"][0])
p = grade([port(), port(out_err=3, late=3)])
check("send errors are red", p["level"] == SN.BAD and "3 send errors" in p["reasons"][0])
p = grade([port(), port(fcs=4, in_err=4)] + [port(fcs=4, in_err=4)] * 3)
check("still red inside a minute", p["level"] == SN.BAD)
p = grade([port(), port(fcs=4, in_err=4)] + [port(fcs=4, in_err=4)] * 6)
check("yellow once the errors stop", p["level"] == SN.WARN and "4 errors earlier" in p["reasons"][0], p["reasons"])
p = grade([port(), port(out_disc=40)])
check("dropped packets are yellow", p["level"] == SN.WARN and "Dropped 40" in p["reasons"][0])
p = grade([port(), port(out_disc=40)] + [port(out_disc=40)] * 6)
check("drops clear after a minute", p["level"] == SN.GOOD)
p = grade([port(fcs=500, in_err=500), port(fcs=3, in_err=3)])
check("cleared counters are not errors", p["level"] == SN.GOOD)
p = grade([port(in_err=4294967290, wide=False), port(in_err=4, wide=False)])
check("a counter rolling over still counts", p["level"] == SN.BAD and "10 receive errors" in p["reasons"][0], p["reasons"])

check("half duplex is red", grade([port(duplex="half")])["level"] == SN.BAD)
check("10 Mb is red", grade([port(speed=10)])["level"] == SN.BAD)
p = grade([port(speed=100)])
check("100 Mb on a gigabit port is yellow", p["level"] == SN.WARN and "100 Mb" in p["reasons"][0])
check("100 Mb on a fast ethernet port is fine", grade([port("Fa0/3", speed=100)])["level"] == SN.GOOD)
check("long gigabit name", grade([port("GigabitEthernet0/1", speed=100)])["level"] == SN.WARN)

p = grade([port(oper=False)])
check("empty port is grey", (p["level"], p["reasons"]) == (SN.DOWN, ["Nothing plugged in"]))
check("shut port", grade([port(admin=False, oper=False)])["level"] == SN.OFF)
check("shut port ignores its errors", grade([port(admin=False), port(admin=False, fcs=50, in_err=50)])["level"] == SN.OFF)
p = grade([port(), port(oper=False)])
check("link that just dropped is yellow", p["level"] == SN.WARN and "went down" in p["reasons"][0], p["reasons"])
p = grade([port(), port(oper=False), port()])
check("link that dropped and came back is red", p["level"] == SN.BAD and "2 times" in p["reasons"][0], p["reasons"])
p = grade([port(last_change=4000), port(last_change=8640900)])
check("a bounce between readings is caught", p["level"] == SN.WARN and "came up" in p["reasons"][0], p["reasons"])
p = grade([port(), port(oper=False), port()] + [port()] * 45)
check("link trouble clears after ten minutes", p["level"] == SN.GOOD)
p = grade([port(last_change=8640000 - 12000)])
check("first look: came up two minutes ago", p["level"] == SN.WARN and "2 min ago" in p["reasons"][0], p["reasons"])
check("first look: up for a day", grade([port(last_change=50000)])["level"] == SN.GOOD)
check("first look: a switch that just booted", grade([port(last_change=3000)], uptime=9000)["level"] == SN.GOOD)

mb = 1000000 // 8
p = grade([port(), port(out_oct=15 * 500 * mb, in_oct=15 * 100 * mb)])
check("traffic in megabits", round(p["out_mbps"]) == 500 and round(p["in_mbps"]) == 100 and p["busy"] == 50)
check("half full is green", p["level"] == SN.GOOD)
check("75% busy is yellow", grade([port(), port(out_oct=15 * 750 * mb)])["level"] == SN.WARN)
p = grade([port(), port(in_oct=15 * 950 * mb)])
check("95% busy is red", p["level"] == SN.BAD and "95% busy" in p["reasons"][0])
p = grade([port("Fa0/1", speed=100, wide=False, out_oct=4294967000), port("Fa0/1", speed=100, wide=False, out_oct=15 * 10 * mb - 296)])
check("32-bit traffic counter rolling over", round(p["out_mbps"]) == 10, p["out_mbps"])

w = SN.SwitchWatch()
w.update([port(), port(index=2)], 8640000, 1000.0)
w.update([port(fcs=5, in_err=5), port(index=2)], 8641500, 1015.0)
after = w.update([port(fcs=0, in_err=0), port(index=2)], 3000, 1030.0)
check("a restarted switch starts clean", after[0]["level"] == SN.GOOD and after[0]["errors"] == 0 and w.restarted_at == 1030.0)
both = w.update([port(fcs=2, in_err=2), port(index=2)], 4500, 1045.0)
check("ports are remembered separately", [x["level"] for x in both] == [SN.BAD, SN.GOOD])

# --- clear a port and see if the errors come back
w = SN.SwitchWatch()
w.update([port(), port(index=2)], 8640000, 1000.0)
w.update([port(fcs=9, in_err=9, out_disc=4), port(index=2, fcs=1, in_err=1)], 8641500, 1015.0)
check("nothing cleared yet", w.update([port(fcs=9, in_err=9, out_disc=4), port(index=2, fcs=1, in_err=1)],
                                      8643000, 1030.0)[0]["since_clear"] is None)
w.clear(1)
after = w.update([port(fcs=9, in_err=9, out_disc=4), port(index=2, fcs=1, in_err=1)], 8644500, 1045.0)
check("a cleared port goes green", after[0]["level"] == SN.GOOD and after[0]["errors"] == 0, after[0]["reasons"])
check("only that port is cleared", after[1]["level"] == SN.BAD)
check("counts restart from zero", after[0]["since_clear"] == dict(in_err=0, out_err=0, in_disc=0, out_disc=0,
                                                                  fcs=0, align=0, late=0, excess=0))
after = w.update([port(fcs=12, in_err=12, out_disc=4), port(index=2, fcs=1, in_err=1)], 8646000, 1060.0)
check("errors that come back turn it red again", after[0]["level"] == SN.BAD and after[0]["errors"] == 3
      and after[0]["since_clear"]["fcs"] == 3 and after[0]["since_clear"]["out_disc"] == 0, after[0])
w.clear()
after = w.update([port(fcs=12, in_err=12, out_disc=4), port(index=2, fcs=1, in_err=1)], 8647500, 1075.0)
check("clear all", [x["level"] for x in after] == [SN.GOOD, SN.GOOD])
w.update([port(fcs=40, in_err=40, out_disc=4), port(index=2, fcs=1, in_err=1)], 8649000, 1090.0)
w.clear(1)                                          # 30 more errors arrive before the tap is acted on
after = w.update([port(fcs=70, in_err=70, out_disc=9), port(index=2, fcs=1, in_err=1)], 8649100, 1091.0)
check("one clear is enough: errors from before the tap never count", after[0]["level"] == SN.GOOD
      and after[0]["errors"] == 0 and after[0]["since_clear"]["fcs"] == 0, after[0]["reasons"])
after = w.update([port(fcs=70, in_err=70, out_disc=9), port(index=2, fcs=1, in_err=1)], 8650600, 1106.0)
check("and it stays green while nothing new arrives", after[0]["level"] == SN.GOOD)
w = SN.SwitchWatch()
w.update([port()], 8640000, 1000.0)
w.update([port(oper=False)], 8641500, 1015.0)
w.clear(1)
check("clearing forgets a link drop too", w.update([port(oper=False)], 8643000, 1030.0)[0]["level"] == SN.DOWN)
SN.SwitchWatch().clear()
check("clearing before any reading is harmless", True)

# --- the icon's summary
s = SN.summarize([{"level": SN.BAD, "oper": True}, {"level": SN.WARN, "oper": True}, {"level": SN.GOOD, "oper": True},
                  {"level": SN.DOWN, "oper": False}])
check("summary counts", (s["bad"], s["warn"], s["up"], s["total"], s["level"]) == (1, 1, 3, 4, SN.BAD))
check("summary yellow", SN.summarize([{"level": SN.WARN, "oper": True}, {"level": SN.GOOD, "oper": True}])["level"] == SN.WARN)
check("summary green", SN.summarize([{"level": SN.GOOD, "oper": True}, {"level": SN.DOWN}])["level"] == SN.GOOD)
check("badge threshold", SN.BADGE_OVER == 2)

# --- the front panel
rows = SN.layout([{"name": f"Fa0/{n}"} for n in range(1, 25)] + [{"name": "Gi0/1"}, {"name": "Gi0/2"}])
check("one chassis, two blocks", len(rows) == 1 and [b["label"] for b in rows[0]] == ["Fa0/", "Gi0/"])
fa = rows[0][0]
check("odd ports on top, even below", [SN.short_name(p["name"]) for p in fa["top"]] == [str(n) for n in range(1, 25, 2)]
      and [SN.short_name(p["name"]) for p in fa["bottom"]] == [str(n) for n in range(2, 25, 2)])
check("two uplinks sit in one row", [p["name"] for p in rows[0][1]["top"]] == ["Gi0/1", "Gi0/2"] and rows[0][1]["bottom"] == [])
rows = SN.layout([{"name": f"GigabitEthernet{m}/0/{n}"} for m in (2, 1) for n in range(1, 5)]
                 + [{"name": "TenGigabitEthernet1/1/1"}])
check("a stack gets a row per member", len(rows) == 2 and [b["label"] for b in rows[0]] == ["Gi1/0/", "Te1/1/"]
      and [b["label"] for b in rows[1]] == ["Gi2/0/"], [[b["label"] for b in r] for r in rows])
rows = SN.layout([{"name": "Gi0/10"}, {"name": "Gi0/2"}, {"name": "Gi0/9"}, {"name": "Gi0/1"}])
check("sorted by number, not by text", [p["name"] for p in rows[0][0]["top"]] == ["Gi0/1", "Gi0/9"]
      and [p["name"] for p in rows[0][0]["bottom"]] == ["Gi0/2", "Gi0/10"])
rows = SN.layout([{"name": "uplink"}, {"name": ""}, {"name": "Port 7"}])
check("odd names still get a place", sum(len(b["top"]) + len(b["bottom"]) for r in rows for b in r) == 3)
check("empty switch", SN.layout([]) == [])
rows = SN.layout([{"name": "Gi0/0"}] + [{"name": f"Gi1/0/{n}"} for n in range(1, 37)]
                 + [{"name": f"Te1/0/{n}"} for n in range(37, 49)] + [{"name": f"Gi1/1/{n}"} for n in range(1, 5)]
                 + [{"name": f"Te1/1/{n}"} for n in range(1, 5)])
check("a lone management port joins the chassis, and ports stay in faceplate order",
      len(rows) == 1 and [b["label"] for b in rows[0]] == ["Gi1/0/", "Te1/0/", "Gi1/1/", "Te1/1/", "Gi0/"],
      [[b["label"] for b in r] for r in rows])
check("short names", (SN.short_name("GigabitEthernet0/14"), SN.short_name("Fa0/3"), SN.short_name("uplink")) == ("14", "3", "ink"))

print(f"\nALL {ok} SNMP CHECKS PASSED")
