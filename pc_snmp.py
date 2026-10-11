"""
pc_snmp - read switches over SNMP for PorkChopCheck.

A small SNMP v1/v2c client (get, walk, subnet sweep), the port model built from the standard
interface tables, and the grading that turns a port's counters into green, yellow or red.

No UI and no dependencies beyond the standard library, so all of it can be tested without a
switch (see tests/test_snmp.py).
"""
import collections
import ipaddress
import random
import re
import select
import socket
import time


class SnmpError(Exception):
    """The switch answered with an error, or with something that is not SNMP."""


class SnmpTimeout(SnmpError):
    """Nothing answered. Wrong address, wrong community, or SNMP is not turned on."""


# ====================================================================== BER encoding
T_INT, T_STR, T_NULL, T_OID, T_SEQ = 0x02, 0x04, 0x05, 0x06, 0x30
T_IP, T_COUNTER, T_GAUGE, T_TICKS, T_OPAQUE, T_COUNTER64 = 0x40, 0x41, 0x42, 0x43, 0x44, 0x46
T_NO_OBJECT, T_NO_INSTANCE, T_END = 0x80, 0x81, 0x82
PDU_GET, PDU_NEXT, PDU_RESPONSE, PDU_BULK = 0xA0, 0xA1, 0xA2, 0xA5
END = object()                      # walked off the end of what the switch has
MAX_OIDS = 20                       # per request, to keep replies inside one packet


def oid(text):
    """'1.3.6.1.2.1.1.5.0' as a tuple of numbers."""
    return tuple(int(p) for p in text.strip(".").split("."))


def oid_str(o):
    return ".".join(str(p) for p in o)


def _enc_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, body):
    return bytes([tag]) + _enc_len(len(body)) + body


def _enc_int(v, tag=T_INT):
    return _tlv(tag, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def _enc_oid(o):
    if len(o) < 2 or o[0] > 2 or o[1] > 39:
        raise SnmpError("bad OID")
    out = bytearray([o[0] * 40 + o[1]])
    for arc in o[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out += bytes(reversed(chunk))
    return _tlv(T_OID, bytes(out))


def encode_value(tag, value=None):
    """One value with its type tag. Only the test agent and the demo need more than NULL."""
    if tag == T_OID:
        return _enc_oid(value)
    if tag in (T_INT, T_COUNTER, T_GAUGE, T_TICKS, T_COUNTER64):
        return _enc_int(value, tag)
    if tag == T_IP:
        return _tlv(tag, socket.inet_aton(value))
    if tag in (T_STR, T_OPAQUE):
        return _tlv(tag, value if isinstance(value, bytes) else str(value).encode("utf-8"))
    return _tlv(tag, b"")


def build_message(version, community, pdu, req_id, binds, a=0, b=0):
    """A whole SNMP packet. `binds` is a list of (oid, encoded value); a and b are error status and
    index, or non-repeaters and max-repetitions for a bulk request. version is 1 or 2."""
    body = b"".join(_tlv(T_SEQ, _enc_oid(o) + v) for o, v in binds)
    inner = _enc_int(req_id) + _enc_int(a) + _enc_int(b) + _tlv(T_SEQ, body)
    return _tlv(T_SEQ, _enc_int(version - 1) + _tlv(T_STR, community.encode("utf-8", "replace"))
                + _tlv(pdu, inner))


def build_request(version, community, pdu, req_id, oids, max_rep=0):
    null = _tlv(T_NULL, b"")
    return build_message(version, community, pdu, req_id, [(o, null) for o in oids], 0, max_rep)


def _read_tlv(data, pos):
    """(tag, start, end) of the value at pos."""
    if pos + 2 > len(data):
        raise SnmpError("packet ends early")
    tag, first = data[pos], data[pos + 1]
    pos += 2
    if first & 0x80:
        n = first & 0x7F
        if not 1 <= n <= 4 or pos + n > len(data):
            raise SnmpError("bad length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    else:
        length = first
    if pos + length > len(data):
        raise SnmpError("packet ends early")
    return tag, pos, pos + length


def _expect(data, pos, tag):
    got, start, end = _read_tlv(data, pos)
    if got != tag:
        raise SnmpError("not the SNMP layout")
    return start, end


def _dec_int(body, signed=True):
    if not body or len(body) > 9:
        raise SnmpError("bad number")
    return int.from_bytes(body, "big", signed=signed)


def _dec_oid(body):
    if not body:
        raise SnmpError("empty OID")
    first, rest = 0, 0
    for i, byte in enumerate(body):                 # the first number can itself be multi-byte
        first = (first << 7) | (byte & 0x7F)
        if not byte & 0x80:
            rest = i + 1
            break
    else:
        raise SnmpError("bad OID")
    out = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    arc = 0
    for byte in body[rest:]:
        arc = (arc << 7) | (byte & 0x7F)
        if arc > 0xFFFFFFFF:
            raise SnmpError("bad OID")
        if not byte & 0x80:
            out.append(arc)
            arc = 0
    return tuple(out)


def _dec_value(tag, body):
    if tag == T_INT:
        return _dec_int(body)
    if tag in (T_COUNTER, T_GAUGE, T_TICKS, T_COUNTER64):
        return _dec_int(body, signed=False)
    if tag == T_OID:
        return _dec_oid(body)
    if tag == T_IP and len(body) == 4:
        return socket.inet_ntoa(body)
    if tag in (T_STR, T_OPAQUE, T_IP):
        return bytes(body)
    if tag == T_END:
        return END
    return None                                     # NULL, noSuchObject, noSuchInstance


def parse_message(data):
    """Take a packet apart: (version, community, pdu tag, request id, a, b, [(oid, value)])."""
    start, end = _expect(data, 0, T_SEQ)
    s, e = _expect(data, start, T_INT)
    version = _dec_int(data[s:e]) + 1
    s, e2 = _expect(data, e, T_STR)
    community = bytes(data[s:e2])
    pdu, pos, pend = _read_tlv(data, e2)
    if pdu & 0xE0 != 0xA0:
        raise SnmpError("not the SNMP layout")
    nums = []
    for _ in range(3):
        s, pos2 = _expect(data, pos, T_INT)
        nums.append(_dec_int(data[s:pos2]))
        pos = pos2
    pos, vend = _expect(data, pos, T_SEQ)
    binds = []
    while pos < vend:
        s, bend = _expect(data, pos, T_SEQ)
        os_, oe = _expect(data, s, T_OID)
        tag, vs, ve = _read_tlv(data, oe)
        binds.append((_dec_oid(data[os_:oe]), _dec_value(tag, data[vs:ve])))
        pos = bend
    return version, community, pdu, nums[0], nums[1], nums[2], binds


def text(value):
    """A string value as readable text."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").replace("\x00", "").strip()
    return "" if value is None or value is END else str(value)


# ====================================================================== client
class Client:
    """SNMP v1 or v2c to one device. Not for sharing between threads."""

    def __init__(self, host, community="public", version=2, timeout=1.5, retries=1, port=161):
        self.host, self.community, self.version = host, community, 1 if version == 1 else 2
        self.timeout, self.retries, self.port = timeout, retries, port
        self.sock = None
        self.req_id = random.randint(1, 0x3FFFFFFF)

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _exchange(self, pdu, oids, max_rep=0):
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.connect((self.host, self.port))
        self.req_id = self.req_id % 0x7FFFFFFF + 1
        packet = build_request(self.version, self.community, pdu, self.req_id, oids, max_rep)
        for _ in range(self.retries + 1):
            try:
                self.sock.send(packet)
            except OSError as e:
                raise SnmpTimeout(f"cannot reach {self.host}: {e}") from None
            deadline = time.monotonic() + self.timeout
            while True:
                wait = deadline - time.monotonic()
                if wait <= 0:
                    break
                self.sock.settimeout(wait)
                try:
                    data = self.sock.recv(65535)
                except socket.timeout:
                    break
                except OSError:                     # the host says nothing listens on that port
                    raise SnmpTimeout(f"{self.host} is not running SNMP") from None
                try:
                    _, _, kind, rid, status, index, binds = parse_message(data)
                except SnmpError:
                    continue
                if kind == PDU_RESPONSE and rid == self.req_id:
                    return status, index, binds
        raise SnmpTimeout(f"no SNMP answer from {self.host}")

    def get(self, oids):
        """{oid: value} for each OID asked for. A value the device does not have comes back None."""
        out = {}
        oids = list(oids)
        for i in range(0, len(oids), MAX_OIDS):
            chunk = oids[i:i + MAX_OIDS]
            while chunk:
                status, index, binds = self._exchange(PDU_GET, chunk)
                if status == 2 and 1 <= index <= len(chunk):    # v1: one missing OID fails them all
                    out[chunk.pop(index - 1)] = None
                    continue
                if status:
                    raise SnmpError(f"{self.host} answered with error {status}")
                for asked, (_, value) in zip(chunk, binds):
                    out[asked] = None if value is END else value
                break
        return out

    def walk(self, base, limit=5000):
        """Every (oid, value) under base, in order."""
        out, cur = [], base
        while len(out) < limit:
            if self.version == 1:
                status, _, binds = self._exchange(PDU_NEXT, [cur])
                if status == 2:                     # v1's way of saying there is nothing after this
                    break
            else:
                status, _, binds = self._exchange(PDU_BULK, [cur], MAX_OIDS)
            if status:
                raise SnmpError(f"{self.host} answered with error {status}")
            if not binds:
                break
            for o, value in binds:
                if value is END or o[:len(base)] != base or o <= cur:
                    return out
                out.append((o, value))
                cur = o
        return out

    def column(self, base):
        """A table column as {row index: value}. The index is whatever follows base in the OID."""
        return {o[len(base):]: v for o, v in self.walk(base)}


# ====================================================================== finding switches
SYS_DESCR, SYS_OBJECT, SYS_UPTIME, SYS_NAME = (oid("1.3.6.1.2.1.1.%d.0" % n) for n in (1, 2, 3, 5))
BRIDGE_PORTS = oid("1.3.6.1.2.1.17.1.2.0")          # how many ports it switches between
CISCO = oid("1.3.6.1.4.1.9")
CDP_ADDRESS = oid("1.3.6.1.4.1.9.9.23.1.2.1.1.4")   # each CDP neighbor's management address
MODEL_NAME = oid("1.3.6.1.2.1.47.1.1.1.1.13")       # the model number printed on each part of the device


def _system(binds):
    got = dict(binds)
    obj = got.get(SYS_OBJECT)
    return {"name": text(got.get(SYS_NAME)), "descr": " ".join(text(got.get(SYS_DESCR)).split()),
            "object": obj if isinstance(obj, tuple) else (), "uptime": got.get(SYS_UPTIME)}


def is_cisco(info):
    return info.get("object", ())[:len(CISCO)] == CISCO or "cisco" in info.get("descr", "").lower()


def model_of(info):
    """The model number the switch reports, else a short one out of its long system description."""
    if info.get("model"):
        return info["model"]
    m = re.search(r"\b(C\d{4}[A-Z0-9]*|WS-C[\w-]+|Catalyst (?!L3\b)[\w-]+)", info.get("descr", ""))
    return m.group(1) if m else ""


def sweep(hosts, community, version=2, timeout=1.0, rounds=2, stop=None, port=161):
    """Ask every address who it is. Returns {ip: system info} for the ones that answer."""
    hosts = list(hosts)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    base = random.randint(1, 0x3FFF0000)
    ids = {ip: base + i for i, ip in enumerate(hosts)}
    found = {}
    try:
        for _ in range(rounds):
            for i, ip in enumerate(hosts):
                if stop is not None and stop.is_set():
                    return found
                if ip in found:
                    continue
                try:
                    sock.sendto(build_request(version, community, PDU_GET, ids[ip],
                                              [SYS_DESCR, SYS_OBJECT, SYS_UPTIME, SYS_NAME]), (ip, port))
                except OSError:
                    pass
                if i % 16 == 15:
                    _collect(sock, ids, found, 0.004)       # pace it, and read as we go
            _collect(sock, ids, found, timeout)
    finally:
        sock.close()
    return found


def _collect(sock, ids, found, wait):
    deadline = time.monotonic() + wait
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return
        if not select.select([sock], [], [], left)[0]:
            return
        try:
            data, addr = sock.recvfrom(65535)
            _, _, kind, rid, status, _, binds = parse_message(data)
        except (OSError, SnmpError):
            continue
        if kind == PDU_RESPONSE and ids.get(addr[0]) == rid and not status:
            found[addr[0]] = _system(binds)


def identify(client):
    """System info for one device, plus how many ports it switches between (0 if it is not a switch)."""
    got = client.get([SYS_DESCR, SYS_OBJECT, SYS_UPTIME, SYS_NAME])
    info = _system(got.items())
    try:
        n = client.get([BRIDGE_PORTS]).get(BRIDGE_PORTS)
    except SnmpError:
        n = None
    info["bridge_ports"] = n if isinstance(n, int) else 0
    try:                                            # the chassis is listed first, so a few rows are enough
        info["model"] = next((text(v) for _, v in client.walk(MODEL_NAME, limit=12) if text(v)), "")
    except SnmpError:
        info["model"] = ""
    return info


def is_switch(info):
    return is_cisco(info) or info.get("bridge_ports", 0) > 1


def private_ip(ip):
    """True for an address on a local network. A scan only follows these, so a device cannot point
    it (and the community string) at an address out on the internet."""
    try:
        a = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return a.is_private and not (a.is_loopback or a.is_unspecified or a.is_multicast)


def cdp_neighbors(client):
    """Management addresses of the Cisco devices plugged into this one."""
    out = []
    for _, value in client.walk(CDP_ADDRESS):
        if isinstance(value, bytes) and len(value) == 4:
            value = socket.inet_ntoa(value)
        if isinstance(value, str) and value not in out and private_ip(value):
            out.append(value)
    return out


# ====================================================================== reading ports
IF = oid("1.3.6.1.2.1.2.2.1")
IFX = oid("1.3.6.1.2.1.31.1.1.1")
DOT3 = oid("1.3.6.1.2.1.10.7.2.1")
ETHERNET_TYPES = (6, 62, 69, 117)       # ethernet, and the older fast and gigabit ethernet types
# column name -> (table, column number)
COLUMNS = {"descr": (IF, 2), "type": (IF, 3), "speed": (IF, 5), "admin": (IF, 7), "oper": (IF, 8),
           "last_change": (IF, 9), "in_oct": (IF, 10), "in_disc": (IF, 13), "in_err": (IF, 14),
           "out_oct": (IF, 16), "out_disc": (IF, 19), "out_err": (IF, 20),
           "name": (IFX, 1), "high_speed": (IFX, 15), "alias": (IFX, 18),
           "align": (DOT3, 2), "fcs": (DOT3, 3), "late": (DOT3, 8), "excess": (DOT3, 9), "duplex": (DOT3, 19)}
WIDE = {"in_oct": (IFX, 6), "out_oct": (IFX, 10)}   # 64-bit traffic counters, SNMP v2c only
COUNTERS = ("in_err", "out_err", "in_disc", "out_disc", "fcs", "align", "late", "excess", "in_oct", "out_oct")


def read_ports(client):
    """Every Ethernet port on the switch, as a list of dicts in port order."""
    cols = {}
    for name, (table, n) in COLUMNS.items():
        cols[name] = client.column(table + (n,))
    hc = {name: {} for name in WIDE}
    if client.version == 2:
        hc = {name: client.column(table + (n,)) for name, (table, n) in WIDE.items()}
    ports = []
    for idx in sorted(cols["type"]):
        if cols["type"][idx] not in ETHERNET_TYPES:
            continue

        def num(name, default=None):
            v = cols[name].get(idx)
            return v if isinstance(v, int) else default
        high = num("high_speed", 0)
        wide = all(isinstance(hc[k].get(idx), int) for k in WIDE)
        counters = {k: num(k) for k in COUNTERS}
        if wide:
            counters.update({k: hc[k][idx] for k in WIDE})
        ports.append({
            "index": idx[0] if idx else 0,
            "name": text(cols["name"].get(idx)) or text(cols["descr"].get(idx)),
            "descr": text(cols["descr"].get(idx)), "alias": text(cols["alias"].get(idx)),
            "admin": num("admin") == 1, "oper": num("oper") == 1,
            "speed": high if high else num("speed", 0) // 1000000,
            "duplex": {2: "half", 3: "full"}.get(num("duplex"), ""),
            "last_change": num("last_change"), "wide": wide,
            "c": counters})
    return ports


# ====================================================================== grading
OFF, DOWN, GOOD, WARN, BAD = "off", "down", "ok", "warn", "bad"
RANK = {OFF: 0, DOWN: 0, GOOD: 1, WARN: 2, BAD: 3}
RECENT = 60.0           # seconds a port stays red after its last error
FLAP_WINDOW = 600.0     # link changes inside this many seconds count against a port
BUSY_WARN, BUSY_BAD = 70, 90        # percent of the port's speed
BADGE_OVER = 2          # a switch shows its count of red ports when there are more than this many


def _delta(cur, prev, wide=False):
    """How far a counter moved. 0 when it went backwards because it was cleared."""
    if cur is None or prev is None:
        return 0
    if cur >= prev:
        return cur - prev
    if not wide and prev > 0xC0000000:              # a 32-bit counter rolling over
        return cur + 0x100000000 - prev
    return 0


def _ago(secs):
    return f"{int(secs)} s ago" if secs < 90 else f"{int(secs // 60)} min ago"


class SwitchWatch:
    """Remembers one switch's ports between readings, so rising counters and link drops can be told
    from old history. Feed it each reading with update()."""

    def __init__(self):
        self.mem = {}
        self.uptime = None
        self.restarted_at = None

    def update(self, ports, uptime, now):
        """Grade a fresh reading. Adds level, reasons, traffic and error totals to each port."""
        if uptime is not None and self.uptime is not None and uptime + 6000 < self.uptime:
            self.mem.clear()                        # the switch restarted: its counters started over
            self.restarted_at = now
        self.uptime = uptime
        for p in ports:
            self._grade(p, uptime, now)
        return ports

    def clear(self, index=None):
        """Forget what has been seen on one port (or all of them) and start watching again from now.
        The switch's own totals cannot be cleared over SNMP, so this is where "clear and see if the
        errors come back" happens."""
        for idx, m in self.mem.items():
            if index is None or idx == index:
                m.update(errors=0, fresh=True)      # the next reading becomes the new starting point
                for q in (m["hits"], m["drops"], m["changes"]):
                    q.clear()

    def _grade(self, p, uptime, now):
        m = self.mem.setdefault(p["index"], {"c": None, "t": None, "oper": None, "lc": None, "base": None,
                                             "errors": 0, "hits": collections.deque(), "drops": collections.deque(),
                                             "changes": collections.deque()})
        c, prev = p["c"], m["c"]
        dt = now - m["t"] if m["t"] else 0
        rx = tx = crc = disc = 0
        p["in_mbps"] = p["out_mbps"] = None
        if prev is not None and dt > 0:
            crc = _delta(c["fcs"], prev["fcs"]) + _delta(c["align"], prev["align"])
            rx = max(_delta(c["in_err"], prev["in_err"]), crc)
            tx = max(_delta(c["out_err"], prev["out_err"]),
                     _delta(c["late"], prev["late"]) + _delta(c["excess"], prev["excess"]))
            disc = _delta(c["out_disc"], prev["out_disc"]) + _delta(c["in_disc"], prev["in_disc"])
            p["in_mbps"] = _delta(c["in_oct"], prev["in_oct"], p["wide"]) * 8 / dt / 1e6
            p["out_mbps"] = _delta(c["out_oct"], prev["out_oct"], p["wide"]) * 8 / dt / 1e6
            if m["oper"] != p["oper"] or (p["last_change"] is not None and p["last_change"] != m["lc"]):
                m["changes"].append(now)
            if m.pop("fresh", False):               # just cleared: whatever built up before the tap is not new
                rx = tx = crc = disc = 0
                m["changes"].clear()
                m["base"] = dict(c)
        elif prev is None and p["oper"] and uptime and p["last_change"] and p["last_change"] > 30000:
            age = (uptime - p["last_change"]) / 100         # first look: the switch says when it last changed
            if 0 <= age < FLAP_WINDOW:
                m["changes"].append(now - age)
        if rx or tx:
            m["hits"].append((now, rx, tx, crc))
            m["errors"] += rx + tx
        if disc:
            m["drops"].append((now, disc))
        for q, keep in ((m["hits"], RECENT), (m["drops"], RECENT), (m["changes"], FLAP_WINDOW)):
            while q and now - (q[0][0] if isinstance(q[0], tuple) else q[0]) > keep:
                q.popleft()
        m.update(c=dict(c), t=now, oper=p["oper"], lc=p["last_change"])

        busy = None
        if p["speed"] and p["out_mbps"] is not None:
            busy = int(max(p["in_mbps"], p["out_mbps"]) / p["speed"] * 100)
        p["busy"], p["errors"] = busy, m["errors"]
        base = m["base"]                            # what the counters have added since Clear was tapped
        p["since_clear"] = None if base is None else {k: _delta(c[k], base.get(k)) for k in c if "oct" not in k}
        bad, warn = [], []
        if not p["admin"]:
            p["level"], p["reasons"] = OFF, ["Shut down on the switch"]
            return
        n = len(m["changes"])
        if n >= 2:
            bad.append(f"Link changed {n} times in the last {int(FLAP_WINDOW // 60)} minutes")
        elif n == 1:
            warn.append(f"Link {'came up' if p['oper'] else 'went down'} {_ago(now - m['changes'][0])}")
        if p["oper"]:
            if p["duplex"] == "half":
                bad.append("Half duplex: one end is not negotiating")
            if p["speed"] == 10:
                bad.append("Linked at only 10 Mb")
            elif p["speed"] == 100 and p["name"][:2].lower() in ("gi", "te", "tw", "fo"):
                warn.append("Linked at 100 Mb on a gigabit port: check the cable")
            r_rx, r_tx, r_crc = (sum(h[i] for h in m["hits"]) for i in (1, 2, 3))
            if r_rx:
                bad.append(f"{r_rx} receive errors in the last minute"
                           + (f", {r_crc} of them CRC: bad cable or connector" if r_crc else ""))
            if r_tx:
                bad.append(f"{r_tx} send errors in the last minute")
            if not (r_rx or r_tx) and m["errors"]:
                warn.append(f"{m['errors']} errors earlier, none in the last minute")
            dropped = sum(d[1] for d in m["drops"])
            if dropped:
                warn.append(f"Dropped {dropped} packets in the last minute: the port is congested")
            if busy is not None and busy >= BUSY_BAD:
                bad.append(f"{busy}% busy: traffic is at the port's limit")
            elif busy is not None and busy >= BUSY_WARN:
                warn.append(f"{busy}% busy")
        if bad:
            p["level"], p["reasons"] = BAD, bad + warn
        elif warn:
            p["level"], p["reasons"] = WARN, warn
        else:
            p["level"], p["reasons"] = (GOOD, []) if p["oper"] else (DOWN, ["Nothing plugged in"])


def summarize(ports):
    """Counts for a switch's icon: how many ports are red, yellow and linked, and the worst level."""
    bad = sum(1 for p in ports if p.get("level") == BAD)
    warn = sum(1 for p in ports if p.get("level") == WARN)
    return {"bad": bad, "warn": warn, "up": sum(1 for p in ports if p.get("oper")), "total": len(ports),
            "level": BAD if bad else WARN if warn else GOOD}


# ====================================================================== front panel layout
_PORT_NAME = re.compile(r"^([A-Za-z][A-Za-z -]*?)\s*((?:\d+/)*)(\d+)$")
_KINDS = ("et", "fa", "gi", "tw", "te", "fo", "hu")    # slowest first, the order they sit on a switch


def layout(ports):
    """Arrange ports the way they sit on the front of a switch: odd numbers on top, even below,
    one block per kind of port. Returns a list of chassis rows (one per stack member), each a list
    of blocks {"label", "top", "bottom"} holding ports."""
    groups = {}
    for seq, p in enumerate(ports):
        m = _PORT_NAME.match(p.get("name", ""))
        if m:
            kind, path, num = m.group(1).strip().lower()[:2], m.group(2), int(m.group(3))
            parts = [int(x) for x in path.split("/") if x]
            member = parts[0] if len(parts) >= 2 else 0     # Gi2/0/5 is stack member 2
            label = f"{m.group(1).strip()[:2]}{path}"
        else:
            kind, parts, member, num, label = "", [], 0, seq + 1, ""
        order = _KINDS.index(kind) if kind in _KINDS else len(_KINDS)
        groups.setdefault((member, order, tuple(parts), label), []).append((num, p))
    rows = {}
    for (member, _, _, label), items in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][2], kv[0][1])):
        items.sort(key=lambda it: it[0])
        if all(n % 2 for n, _ in items) or not any(n % 2 for n, _ in items) or len(items) < 4:
            top, bottom = [p for _, p in items], []         # too few to pair up: a single row
        else:
            top = [p for n, p in items if n % 2]
            bottom = [p for n, p in items if not n % 2]
        rows.setdefault(member, []).append({"label": label, "top": top, "bottom": bottom})
    out = [rows[k] for k in sorted(rows)]
    small = [r for r in out if sum(len(b["top"]) + len(b["bottom"]) for b in r) <= 2]
    if small and len(small) < len(out):             # a lone management port is not a chassis of its own
        out = [r for r in out if r not in small]
        for r in small:
            out[0].extend(r)
    return out


def short_name(name):
    """The number printed next to the port on the switch: 'GigabitEthernet0/14' -> '14'."""
    m = _PORT_NAME.match(name or "")
    return m.group(3) if m else (name or "")[-3:]
