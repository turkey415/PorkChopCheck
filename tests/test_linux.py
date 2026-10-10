"""Linux platform-layer parsers, fed with real output formats from ip/nmcli/ethtool/ping."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import pc_net as N

ok = 0
def check(name, cond, extra=""):
    global ok
    assert cond, f"FAIL {name} {extra}"
    ok += 1
    print("ok ", name)

NMCLI = """GENERAL.CONNECTION:Wired connection 1
IP4.GATEWAY:10.20.30.1
IP4.DNS[1]:10.20.1.10
IP4.DNS[2]:10.20.1.11
IP4.DOMAIN[1]:lab.local
DHCP4.OPTION[1]:broadcast_address = 10.20.30.255
DHCP4.OPTION[2]:dhcp_lease_time = 86400
DHCP4.OPTION[3]:dhcp_server_identifier = 10.20.1.10
DHCP4.OPTION[4]:domain_name_servers = 10.20.1.10 10.20.1.11
DHCP4.OPTION[5]:expiry = 1760140320
DHCP4.OPTION[6]:requested_ms_classless_static_routes = 1"""
d = N.parse_nmcli(NMCLI)
check("nmcli dns/gw/domain", d["dns"] == ["10.20.1.10", "10.20.1.11"] and d["gateway"] == "10.20.30.1" and d["domain"] == ["lab.local"])
check("nmcli dhcp options", d["dhcp"]["dhcp_server_identifier"] == "10.20.1.10" and d["dhcp"]["expiry"] == "1760140320")
check("nmcli connection name", d["connection"] == "Wired connection 1")
d6 = N.parse_nmcli("IP6.ADDRESS[1]:2001\\:db8\\:\\:1/64\nIP4.GATEWAY:--")
check("nmcli escaped colons + empty gw", "gateway" not in d6)

ROUTES = '[{"dst":"default","gateway":"10.20.30.1","dev":"enp3s0","protocol":"dhcp","prefsrc":"10.20.30.147","metric":100,"flags":[]}]'
check("ip route default gw", N.parse_ip_gateways(__import__("json").loads(ROUTES)) == ["10.20.30.1"])
NEIGH = '[{"dst":"10.20.30.1","dev":"enp3s0","lladdr":"00:00:0c:07:ac:1e","state":["REACHABLE"]},{"dst":"10.20.30.9","dev":"enp3s0","state":["FAILED"]},{"dst":"10.20.30.55","dev":"enp3s0","lladdr":"F0:B3:EC:12:9A:01","state":["STALE"]}]'
rows = N.parse_ip_neigh(__import__("json").loads(NEIGH))
check("ip neigh (skips FAILED, normalizes MAC)", rows == [("10.20.30.1", "00:00:0c:07:ac:1e", "Reachable"), ("10.20.30.55", "f0:b3:ec:12:9a:01", "Stale")], rows)
ADDR6 = '[{"ifindex":2,"ifname":"enp3s0","addr_info":[{"family":"inet6","local":"2001:db8:30::5a2f:1","prefixlen":64,"scope":"global","dynamic":true,"mngtmpaddr":true},{"family":"inet6","local":"2001:db8:30::dead:beef","prefixlen":64,"scope":"global","temporary":true,"dynamic":true},{"family":"inet6","local":"fe80::1c4a:9e2f","prefixlen":64,"scope":"link"}]}]'
v6 = N.parse_ip6(__import__("json").loads(ADDR6))
check("ip -6 addr (drops privacy addr, SLAAC origin)", v6 == [{"IPAddress": "2001:db8:30::5a2f:1", "Origin": "RouterAdvertisement"}, {"IPAddress": "fe80::1c4a:9e2f", "Origin": "WellKnown"}], v6)
ETH = "NIC statistics:\n     rx_packets: 99120\n     rx_broadcast: 4211\n     rx_multicast: 812\n"
check("ethtool -S broadcast", N.parse_ethtool_bcast(ETH) == 4211)
check("ethtool -S missing", N.parse_ethtool_bcast("NIC statistics:\n  rx_packets: 5\n") is None)
check("resolvectl dns", N.parse_resolvectl("Link 2 (enp3s0): 10.20.1.10 10.20.1.11 fe80::1\n") == ["10.20.1.10", "10.20.1.11"])
check("lease time formatting", N.fmt_epoch(1760140320)[:3].isalpha())

LP_OK = "PING 1.1.1.1 (1.1.1.1) from 10.20.30.147 : 56(84) bytes of data.\n64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms\n"
LP_TTL = "PING 1.1.1.1 (1.1.1.1) from 10.20.30.147 : 56(84) bytes of data.\nFrom 10.20.30.2 icmp_seq=1 Time to live exceeded\n"
LP_UNR = "From 10.20.30.147 icmp_seq=1 Destination Host Unreachable\n"
WP_TTL = "Pinging 1.1.1.1 with 32 bytes of data:\nReply from 10.20.0.1: TTL expired in transit.\n"
WP_OK = "Reply from 1.1.1.1: bytes=32 time<1ms TTL=57\n"
check("linux ping ok", N.parse_ping_output(LP_OK, "1.1.1.1") == ("ok", "1.1.1.1", 12.3))
check("linux ping ttl exceeded", N.parse_ping_output(LP_TTL, "1.1.1.1", 4.0) == ("ttl", "10.20.30.2", 4.0))
check("linux ping unreachable", N.parse_ping_output(LP_UNR, "10.20.30.200")[0] == "unreach")
check("windows ping ttl expired", N.parse_ping_output(WP_TTL, "1.1.1.1", 5.0) == ("ttl", "10.20.0.1", 5.0))
check("windows ping <1ms", N.parse_ping_output(WP_OK, "1.1.1.1") == ("ok", "1.1.1.1", 1.0))
check("ping timeout", N.parse_ping_output("1 packets transmitted, 0 received", "1.1.1.1") == ("timeout", None, None))

# real /sys on this machine
if N.IS_LINUX:
    ads = N.linux_adapters()
    check("linux_adapters finds wired NICs only", all(a["name"] != "lo" for a in ads), ads)
    if ads:
        up, spd = N.linux_link(ads[0]["name"])
        check("linux_link reads carrier", isinstance(up, bool) and spd >= 0, (up, spd))
    check("has_net_caps returns bool", isinstance(N.has_net_caps(), bool))

# --- a bridged NIC, laid out exactly like a Nobara box running VMs (enp14s0 enslaved to br0)
import tempfile
root = tempfile.mkdtemp()
def mk(name, type_="1", device=True, carrier="1", master=None, wireless=False):
    p = os.path.join(root, name)
    os.makedirs(p)
    open(os.path.join(p, "type"), "w").write(type_ + "\n")
    open(os.path.join(p, "carrier"), "w").write(carrier + "\n")
    open(os.path.join(p, "speed"), "w").write("1000\n")
    open(os.path.join(p, "address"), "w").write("fc:9d:05:07:ad:e3\n")
    if device:
        os.makedirs(os.path.join(p, "device"))
    if wireless:
        os.makedirs(os.path.join(p, "wireless"))
    if master:
        os.symlink(os.path.join(root, master), os.path.join(p, "master"))
mk("lo", type_="772", device=False)
mk("br0", device=False)
mk("enp14s0", master="br0")
mk("wlp15s0", carrier="0", wireless=True)
mk("tailscale0", type_="65534", device=False)
mk("virbr0", device=False, carrier="0")
mk("vnet0", device=False, master="br0")
real = N.SYS_NET
N.SYS_NET = root
try:
    ads = N.linux_adapters()
    check("bridged box: only the physical NIC is offered", [a["name"] for a in ads] == ["enp14s0"], ads)
    check("bridged box: IP interface is br0", N.linux_l3_iface("enp14s0") == "br0")
    check("bridged box: adapter says where the IP is", ads[0]["desc"].endswith("IP on br0"), ads[0]["desc"])
    check("bridged box: link read from the port", N.linux_link("enp14s0") == (True, 1000))
    check("non-bridged NIC maps to itself", N.linux_l3_iface("wlp15s0") == "wlp15s0")
finally:
    N.SYS_NET = real
print(f"\nALL {ok} LINUX CHECKS PASSED")
