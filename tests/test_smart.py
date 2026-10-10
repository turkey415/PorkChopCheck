"""Smart-home discovery: protocol parsers, AES, classification, merging and the inventory."""
import json
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import pc_smart as S  # noqa: E402

ok = 0


def check(name, cond, extra=""):
    global ok
    assert cond, f"FAIL {name} {extra}"
    ok += 1
    print("ok ", name)


# --- AES-128 against official test vectors (FIPS-197 C.1 and NIST SP 800-38A F.1.2)
rk = S._expand_key(bytes(range(16)))
check("AES FIPS-197 vector", S.aes128_decrypt_block(rk, bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"))
      == bytes.fromhex("00112233445566778899aabbccddeeff"))
rk = S._expand_key(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
check("AES SP800-38A vector", S.aes128_decrypt_block(rk, bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97"))
      == bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"))
check("S-box spot check", S._SBOX[0x00] == 0x63 and S._SBOX[0x53] == 0xED and S._INV_SBOX[0x63] == 0x00)

# --- SSDP + UPnP
resp = (b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age = 1800\r\nLOCATION: http://10.20.30.70:1400/xml/device_description.xml\r\n"
        b"SERVER: Linux UPnP/1.0 Sonos/80.1-55014 (ZPS27)\r\nST: upnp:rootdevice\r\nUSN: uuid:RINCON_48A6B8C1D2E301400::upnp:rootdevice\r\n\r\n")
hd = S.parse_ssdp(resp)
check("ssdp headers", hd["location"].endswith("device_description.xml") and "sonos" in hd["server"].lower())
check("ssdp ignores M-SEARCH echoes", S.parse_ssdp(b"M-SEARCH * HTTP/1.1\r\n\r\n") is None)
SONOS = """<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:ZonePlayer:1</deviceType><friendlyName>10.20.30.70 - Sonos Era 100</friendlyName>
<manufacturer>Sonos, Inc.</manufacturer><modelNumber>S39</modelNumber><modelName>Sonos Era 100</modelName>
<serialNum>48-A6-B8-C1-D2-E3:A</serialNum><roomName>Lobby</roomName><UDN>uuid:RINCON_48A6B8C1D2E301400</UDN>
<deviceList><device><modelName>Inner</modelName></device></deviceList></device></root>"""
u = S.parse_upnp_xml(SONOS)
check("upnp: sonos room/model/serial", u["name"] == "Lobby" and u["model"] == "Sonos Era 100 S39"
      and u["serial"] == "48-A6-B8-C1-D2-E3:A" and u["brand_hint"] == "Sonos, Inc.", u)
WEMO = """<root xmlns="urn:Belkin:device-1-0"><device><friendlyName>Porch Light</friendlyName><manufacturer>Belkin International Inc.</manufacturer>
<modelName>Socket</modelName><modelNumber>1.0</modelNumber><serialNumber>221517K0101769</serialNumber></device></root>"""
check("upnp: wemo serialNumber", S.parse_upnp_xml(WEMO)["serial"] == "221517K0101769")
check("upnp: junk xml", S.parse_upnp_xml("<html><body>nope") is None)

# --- Roku, Hue, Shelly, Cast
ROKU = """<device-info><udn>29600009-1234</udn><serial-number>YH00AB123456</serial-number><device-id>S0A1234</device-id>
<vendor-name>Roku</vendor-name><model-name>4850X</model-name><friendly-model-name>Roku Ultra</friendly-model-name>
<user-device-name>Den TV</user-device-name><wifi-mac>d8:31:34:aa:bb:cc</wifi-mac><software-version>12.5.0</software-version></device-info>"""
r = S.parse_roku(ROKU)
check("roku device-info", r["serial"] == "YH00AB123456" and r["model"] == "Roku Ultra" and r["name"] == "Den TV"
      and r["mac"] == "d8:31:34:aa:bb:cc", r)
hue = S.parse_hue_config(json.dumps({"name": "Hue Bridge", "swversion": "1967054020", "mac": "ec:b5:fa:12:34:56",
                                     "bridgeid": "ECB5FAFFFE123456", "modelid": "BSB002"}))
check("hue /api/config", hue["serial"] == "ECB5FAFFFE123456" and hue["mac"] == "ec:b5:fa:12:34:56" and hue["category"] == "hub")
sh1 = S.parse_shelly('{"type":"SHSW-1","mac":"A4CF12F3B2C1","auth":false,"fw":"20230913-112003/v1.14.0"}')
sh2 = S.parse_shelly('{"name":null,"id":"shellyplus1pm-441793a1b2c3","mac":"441793A1B2C3","model":"SNSW-001P16EU","gen":2,"app":"Plus1PM","ver":"1.4.4"}')
check("shelly gen1", sh1["mac"] == "a4:cf:12:f3:b2:c1" and sh1["model"] == "Shelly SHSW-1")
check("shelly gen2", sh2["serial"] == "shellyplus1pm-441793a1b2c3" and sh2["model"] == "Shelly Plus1PM")
check("shelly rejects other json", S.parse_shelly('{"mac":"x"}') is None)
cast = S.parse_cast('{"name":"Kitchen display","device_info":{"manufacturer":"Google Inc.","model_name":"Google Nest Hub","mac_address":"F4:F5:D8:01:02:03"}}')
check("cast eureka_info", cast["model"] == "Google Nest Hub" and cast["mac"] == "f4:f5:d8:01:02:03")

# --- TP-Link Kasa / Tapo
sysinfo = {"system": {"get_sysinfo": {"alias": "Coffee maker", "model": "HS103(US)", "deviceId": "8006ABCDEF0123456789",
                                      "type": "IOT.SMARTPLUGSWITCH", "mac": "1C:3B:F3:11:22:33", "sw_ver": "1.0.5"}}}
check("kasa xor round-trip", S.xor_decrypt(S.xor_encrypt(b"hello kasa")) == b"hello kasa")
k = S.parse_kasa_legacy(S.xor_encrypt(json.dumps(sysinfo).encode()))
check("kasa legacy 9999", k["name"] == "Coffee maker" and k["serial"] == "8006ABCDEF0123456789"
      and k["category"] == "plug" and k["mac"] == "1c:3b:f3:11:22:33", k)
newresp = bytes(16) + json.dumps({"result": {"device_type": "SMART.TAPOBULB", "device_model": "L530E(US)",
                                             "ip": "10.20.30.81", "mac": "5C-62-8B-AA-BB-CC", "device_id": "802A1B2C"},
                                  "error_code": 0}).encode()
k2 = S.parse_kasa_new(newresp)
check("tapo 20002", k2["model"] == "L530E(US)" and k2["category"] == "light" and k2["mac"] == "5c:62:8b:aa:bb:cc"
      and k2["ip"] == "10.20.30.81", k2)
check("kasa probe is the documented 16 bytes", S.KASA_QUERY2.hex() == "020000010000000000000000463cb5d3")

# --- LIFX
pkt = S.lifx_packet(2)
check("lifx GetService is 36 bytes, protocol 1024, tagged", len(pkt) == 36
      and struct.unpack_from("<H", pkt, 2)[0] & 0x0FFF == 1024 and struct.unpack_from("<H", pkt, 2)[0] & (1 << 13)
      and struct.unpack_from("<H", pkt, 32)[0] == 2)
reply = bytearray(S.lifx_packet(3)) + bytes([1]) + struct.pack("<I", 56700)
reply[8:14] = bytes.fromhex("d073d5112233")
lf = S.parse_lifx(bytes(reply))
check("lifx StateService -> serial = MAC", lf["mac"] == "d0:73:d5:11:22:33" and lf["serial"] == "d073d5112233")
check("lifx ignores GetService echo", S.parse_lifx(pkt) is None)

# --- Govee, WiZ, Yeelight
gv = S.parse_govee(b'{"msg":{"cmd":"scan","data":{"ip":"10.20.30.90","device":"1F:80:C5:32:32:36:72:4E","sku":"H6163",'
                   b'"bleVersionHard":"3.01.01","wifiVersionSoft":"1.02.03"}}}', "10.20.30.90")
check("govee scan reply", gv["model"] == "Govee H6163" and gv["serial"].startswith("1F:80") and gv["fw"] == "1.02.03")
wz = S.parse_wiz(b'{"method":"getSystemConfig","env":"pro","result":{"mac":"a8bb50a1b2c3","homeId":123,"moduleName":"ESP25_SOCKET_01","fwVersion":"1.26.0"}}')
check("wiz getSystemConfig", wz["mac"] == "a8:bb:50:a1:b2:c3" and wz["category"] == "plug" and wz["fw"] == "1.26.0")
yl = S.parse_yeelight(b"HTTP/1.1 200 OK\r\nLocation: yeelight://10.20.30.95:55443\r\nid: 0x000000000015243f\r\n"
                      b"model: color\r\nfw_ver: 18\r\nname: desk\r\n\r\n")
check("yeelight", yl["ip"] == "10.20.30.95" and yl["serial"] == "0x000000000015243f" and yl["name"] == "desk")

# --- Tuya (protocol 3.1 broadcasts are plaintext on 6666)
body = json.dumps({"ip": "10.20.30.120", "gwId": "bf1234567890abcdef", "active": 2, "productKey": "keyabc123",
                   "version": "3.1"}).encode()
frame = b"\x00\x00\x55\xaa" + struct.pack(">III", 0, 0x13, len(body) + 8) + b"\x00\x00\x00\x00" + body + b"\x00" * 4 + b"\x00\x00\xaa\x55"
tu = S.parse_tuya(frame)
check("tuya 6666 plaintext", tu and tu["serial"] == "bf1234567890abcdef" and tu["ip"] == "10.20.30.120", tu)
check("tuya rejects junk", S.parse_tuya(b"\x00" * 40) is None)

# --- mDNS TXT
check("cast TXT", S.parse_mdns_txt("_googlecast._tcp.local", ["id=abc", "md=Google Nest Mini", "fn=Bedroom speaker"])
      == {"model": "Google Nest Mini", "name": "Bedroom speaker", "brand_hint": "Google"})
check("esphome TXT", S.parse_mdns_txt("_esphomelib._tcp.local", ["mac=24a160112233", "project_name=garage.door"])["mac"]
      == "24:a1:60:11:22:33")
check("homepod TXT", S.parse_mdns_txt("_airplay._tcp.local", ["model=AudioAccessory5,1"])["brand_hint"] == "Apple")

# --- classification
c = S.classify({"vendor": "Amazon Technologies Inc.", "hostname": "echo-dot-kitchen"})
check("classify Echo", c["brand"] == "Amazon" and c["category"] == "speaker" and c["smart"])
c = S.classify({"vendor": "Ring LLC"})
check("classify Ring", c["brand"] == "Ring" and c["category"] == "camera")
c = S.classify({"brand_hint": "Google", "model": "Chromecast", "mdns_types": ["_googlecast._tcp.local"]})
check("classify Chromecast", c["brand"] == "Google" and c["category"] == "tv")
c = S.classify({"brand_hint": "Google", "model": "Google Nest Mini"})
check("classify Nest Mini as speaker", c["category"] == "speaker")
c = S.classify({"vendor": "Espressif Inc.", "ports": [6668]})
check("classify ESP + tuya port", c["brand"] == "ESP-based device" and c["smart"])
c = S.classify({"vendor": "Hewlett Packard", "mdns_types": ["_ipp._tcp.local"], "model": "HP LaserJet M404"})
check("printer is not 'smart home'", c["category"] == "printer" and not c["smart"])
c = S.classify({"vendor": "Dell Inc."})
check("unknown PC stays unknown", c["category"] == "unknown" and not c["smart"])
c = S.classify({"brand": "LIFX", "category": "light", "sources": ["LIFX"]})
check("protocol-identified is smart", c["smart"])

# --- merging priorities
sc = S.SmartScan.__new__(S.SmartScan)
sc.src, sc.lock, sc.devs, sc.counts = "10.20.30.147", __import__("threading").Lock(), {}, {}
sc.add("10.20.30.70", {"name": "sonos-lobby", "mac": "48:A6:B8:C1:D2:E3"}, "DNS", S.PRIO["dns"])
sc.add("10.20.30.70", {"name": "Lobby", "serial": "X1"}, "UPnP", S.PRIO["upnp"])
sc.add("10.20.30.70", {"name": "low-prio"}, "DNS", S.PRIO["dns"])
sc.add("10.20.30.70", {"ports": [1400]}, "Ports", 2)
sc.add("10.20.30.70", {"ports": [80]}, "Ports", 2)
sc.add("10.20.30.147", {"name": "me"}, "DNS", 2)
d = sc.devs["10.20.30.70"]
check("merge: higher priority wins, lower can't overwrite", d["name"] == "Lobby" and d["serial"] == "X1")
check("merge: ports union, mac normalized, own IP skipped",
      d["ports"] == [80, 1400] and d["mac"] == "48:a6:b8:c1:d2:e3" and "10.20.30.147" not in sc.devs)

# --- inventory
tmp = tempfile.mkdtemp()
st = S.DeviceStore(tmp)
devs = [S.classify({"ip": "10.20.30.70", "mac": "48:a6:b8:c1:d2:e3", "name": "Lobby", "brand_hint": "Sonos, Inc.",
                    "serial": "X1", "sources": ["UPnP"], "ports": [1400]}),
        S.classify({"ip": "10.20.30.9", "vendor": "Dell Inc.", "sources": ["ARP"]})]
new, err = st.merge(devs)
check("inventory first scan", new == 2 and err is None)
st.set_label("48:a6:b8:c1:d2:e3", "Front lobby speaker")
new, err = st.merge(devs)
check("inventory rescan keeps label", new == 0 and st.label("48:a6:b8:c1:d2:e3") == "Front lobby speaker")
rows = open(os.path.join(tmp, "devices.csv"), encoding="utf-8-sig").read().splitlines()
check("devices.csv: smart first, labelled", rows[1].startswith("Front lobby speaker,Sonos") and len(rows) == 3, rows[1])
check("inventory reloads", len(S.DeviceStore(tmp).items) == 2)
st.merge([S.classify({"ip": "10.20.30.80", "mac": "48:a6:b8:00:00:01", "name": "=cmd|' /C calc'!A0", "sources": ["UPnP"]})])
import csv as _csv
cells = [c for row in _csv.reader(open(os.path.join(tmp, "devices.csv"), encoding="utf-8-sig")) for c in row]
check("devices.csv: a device name can't start a formula", not any(c and c[0] in "=+-@" for c in cells) and "'" not in cells and "'=cmd|' /C calc'!A0" in cells)

# --- SSDP: a device may only point us at its own address
check("ssdp location on the sender is fetched", S.url_is_on("http://10.20.30.70:1400/xml/device_description.xml", "10.20.30.70"))
for bad in ("http://127.0.0.1:8080/admin", "http://10.20.30.71/desc.xml", "http://localhost/x", "https://10.20.30.70/x",
            "http://10.20.30.70.evil.example/x", "http://[::1]/x", "file:///etc/passwd", "http:///x", ""):
    check(f"ssdp location elsewhere is refused: {bad or '(empty)'}", not S.url_is_on(bad, "10.20.30.70"))

print(f"\nALL {ok} SMART CHECKS PASSED")
