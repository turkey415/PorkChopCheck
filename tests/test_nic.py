"""NIC settings: what each setting is, what state it is in, and how it is graded, from saved
Windows and ethtool answers. No network card needed."""
import datetime
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import pc_nic as NC  # noqa: E402

ok = 0


def check(name, cond, extra=""):
    global ok
    assert cond, f"FAIL {name} {extra}"
    ok += 1
    print("ok ", name)


def P(name, shown, keyword, reg, lo=None, hi=None):
    return {"DisplayName": name, "DisplayValue": shown, "RegistryKeyword": keyword, "RegistryValue": reg,
            "Min": lo, "Max": hi}


def level(report, name):
    it = next(i for i in report["items"] if i["name"] == name)
    return NC.grade(it)[0]


TODAY = datetime.date(2026, 10, 11)

# --- which setting is which, across vendors
for keyword, name, kind in [
        ("*EEE", "Energy-Efficient Ethernet", "eee"), ("EEELinkAdvertisement", "Energy Efficient Ethernet", "eee"),
        ("AdvancedEEE", "Advanced EEE", "eee"), ("EnableGreenEthernet", "Green Ethernet", "power"),
        ("AutoDisableGigabit", "Auto Disable Gigabit", "power"), ("SipsEnabled", "System Idle Power Saver", "power"),
        ("ULPMode", "Ultra Low Power Mode", "lowpower"), ("ReduceSpeedOnPowerDown", "Reduce Speed On Power Down", "lowpower"),
        ("*InterruptModeration", "Interrupt Moderation", "intmod"), ("ITR", "Interrupt Moderation Rate", "other"),
        ("*FlowControl", "Flow Control", "flow"), ("*RSS", "Receive Side Scaling", "rss"),
        ("*NumRssQueues", "Maximum Number of RSS Queues", "other"), ("*JumboPacket", "Jumbo Packet", "jumbo"),
        ("*SpeedDuplex", "Speed & Duplex", "speedcfg"), ("*ReceiveBuffers", "Receive Buffers", "buffers"),
        ("*TransmitBuffers", "Transmit Buffers", "buffers"), ("*LsoV2IPv4", "Large Send Offload V2 (IPv4)", "tcp"),
        ("*RscIPv4", "Recv Segment Coalescing (IPv4)", "tcp"), ("*TCPChecksumOffloadIPv6", "TCP Checksum Offload (IPv6)", "tcp"),
        ("*UDPChecksumOffloadIPv4", "UDP Checksum Offload (IPv4)", "sum"), ("*IPChecksumOffloadIPv4", "IPv4 Checksum Offload", "sum"),
        ("*WakeOnMagicPacket", "Wake on Magic Packet", "wake"), ("*PMARPOffload", "ARP Offload", "wake"),
        ("S5WakeOnLan", "Shutdown Wake-On-Lan", "wake"), ("GigaLite", "Gigabit Lite", "other"),
        ("NetworkAddress", "Network Address", "other"), ("*PriorityVLANTag", "Priority & VLAN", "other")]:
    check(f"kind of {keyword}", NC.win_kind(keyword, name) == kind, NC.win_kind(keyword, name))
check("an unlisted vendor keyword falls back to the name", NC.win_kind("VendorGreenThing", "Green Ethernet") == "power")
check("no keyword at all uses the name", NC.win_kind("", "Flow Control") == "flow"
      and NC.win_kind(None, "Something Else") == "other")

# --- on or off
check("on by text", NC.win_on("0", "Enabled") and NC.win_on(None, "On"))
check("off by text", not NC.win_on("1", "Disabled") and not NC.win_on("3", "Off"))
check("on by number when the text says neither", NC.win_on("3", "Rx & Tx Enabled") and not NC.win_on("0", "Auto"))
check("missing value is off", not NC.win_on(None, None) and not NC.win_on("", ""))
check("speed text", NC.parse_speed("Auto Negotiation") == {"auto": True, "mbps": None, "half": False}
      and NC.parse_speed("100 Mbps Half Duplex") == {"auto": False, "mbps": 100, "half": True}
      and NC.parse_speed("1.0 Gbps Full Duplex") == {"auto": False, "mbps": 1000, "half": False}
      and NC.parse_speed("2.5 Gbps Full Duplex")["mbps"] == 2500)

# --- a Realtek card on factory settings
factory = NC.windows_report({
    "Description": "Realtek PCIe GbE Family Controller", "Provider": "Realtek", "Driver": "10.50.511.2021",
    "DriverDate": "2021-05-11", "Speed": 1_000_000_000, "FullDuplex": True, "TurnOff": "Enabled",
    "SelectiveSuspend": "Unsupported", "Others": [{"Name": "Wi-Fi", "Media": "Native 802.11"},
                                                  {"Name": "Ethernet 2", "Media": "802.3"}],
    "Props": [P("Energy-Efficient Ethernet", "Enabled", "*EEE", "1"),
              P("Green Ethernet", "Enabled", "EnableGreenEthernet", "1"),
              P("Interrupt Moderation", "Enabled", "*InterruptModeration", "1"),
              P("Flow Control", "Rx & Tx Enabled", "*FlowControl", "3"),
              P("Receive Side Scaling", "Enabled", "*RSS", "1"),
              P("Jumbo Frame", "Disabled", "*JumboPacket", "1514"),
              P("Speed & Duplex", "Auto Negotiation", "*SpeedDuplex", "0"),
              P("Receive Buffers", "512", "*ReceiveBuffers", "512", 64, 2048),
              P("Transmit Buffers", "64", "*TransmitBuffers", "64", 64, 2048),
              P("Large Send Offload v2 (IPv4)", "Enabled", "*LsoV2IPv4", "1"),
              P("UDP Checksum Offload (IPv4)", "Rx & Tx Enabled", "*UDPChecksumOffloadIPv4", "3"),
              P("Wake on Magic Packet", "Enabled", "*WakeOnMagicPacket", "1"),
              P("Gigabit Lite", "Enabled", "GigaLite", "1"), {"DisplayName": None}, "junk"]}, TODAY)
check("adapter name", factory["adapter"] == "Realtek PCIe GbE Family Controller")
check("junk rows are skipped", len(factory["items"]) == 17, len(factory["items"]))
for name, want in [("Energy-Efficient Ethernet", "bad"), ("Green Ethernet", "bad"),
                   ("Allow the computer to turn off this device", "bad"), ("Wi-Fi also connected", "bad"),
                   ("Interrupt Moderation", "warn"), ("Flow Control", "warn"), ("Transmit Buffers", "warn"),
                   ("Driver", "warn"), ("Receive Side Scaling", "ok"), ("Jumbo Frame", "ok"),
                   ("Speed & Duplex", "ok"), ("Receive Buffers", "ok"), ("Linked at", "ok"),
                   ("Large Send Offload v2 (IPv4)", "info"), ("UDP Checksum Offload (IPv4)", "info"),
                   ("Wake on Magic Packet", "info"), ("Gigabit Lite", "info")]:
    check(f"factory: {name} is {want}", level(factory, name) == want, level(factory, name))
check("a second wired card is not Wi-Fi", sum(i["kind"] == "wifi" for i in factory["items"]) == 1)
check("unsupported power setting is left out", not any(i["name"] == "Selective suspend" for i in factory["items"]))
check("headline counts", NC.headline(factory) == ("4 to fix, 4 worth changing", "bad"), NC.headline(factory))
rows = NC.rows(factory)
check("worst first", [r[0] for r in rows][:5] == ["Fix these"] * 4 + ["Worth changing"])
check("sections in order", list(dict.fromkeys(r[0] for r in rows))
      == ["Fix these", "Worth changing", "Set right", "No effect on Counter-Strike", "Other settings"])
eee = next(r for r in rows if r[2].startswith("Energy-Efficient"))
check("a red row says what to set and why", "→  Off." in eee[2] and "naps" in eee[2] and eee[1] == "bad")
lso = next(r for r in rows if r[2].startswith("Large Send"))
check("a TCP-only row says it doesn't matter", lso[1] == "note" and "small UDP" in lso[2])
plain = NC.rows(factory, advice=False)
check("advice off: every setting, no grades", len(plain) == 17 and {r[1] for r in plain} == {"info"}
      and not any("→" in r[2] for r in plain))
check("advice off: sorted by name", [r[2] for r in plain] == sorted((r[2] for r in plain), key=str.lower))

# --- the same card after tuning
tuned = NC.windows_report({
    "Description": "Intel(R) Ethernet Controller I226-V", "Provider": "Intel", "Driver": "2.1.4.3",
    "DriverDate": "2025-02-18", "Speed": 2_500_000_000, "FullDuplex": True, "TurnOff": "Disabled", "Others": [],
    "Props": [P("Energy Efficient Ethernet", "Off", "EEELinkAdvertisement", "0"),
              P("Interrupt Moderation", "Disabled", "*InterruptModeration", "0"),
              P("Flow Control", "Disabled", "*FlowControl", "0"),
              P("Receive Side Scaling", "Enabled", "*RSS", "1"),
              P("Jumbo Packet", "Disabled", "*JumboPacket", "1514"),
              P("Speed & Duplex", "Auto Negotiation", "*SpeedDuplex", "0"),
              P("Ultra Low Power Mode", "Disabled", "ULPMode", "0")]}, TODAY)
check("tuned card is all clear", NC.headline(tuned) == ("Set up well for Counter-Strike", "ok"), NC.headline(tuned))
check("a recent driver is not flagged", level(tuned, "Driver") == "info")

# --- single settings gone wrong
def one(prop, **extra):
    r = NC.windows_report(dict({"Props": [prop]}, **extra), TODAY)
    return NC.grade(r["items"][-1])


check("RSS off is yellow, and should be on", one(P("Receive Side Scaling", "Disabled", "*RSS", "0"))[:2] == ("warn", "On"))
check("jumbo 9014 is yellow", one(P("Jumbo Packet", "9014 Bytes", "*JumboPacket", "9014"))[0] == "warn")
check("jumbo as a plain switch", one(P("Jumbo Frame", "Enabled", "*JumboPacket", "1"))[0] == "warn"
      and one(P("Jumbo Frame", "Disabled", "*JumboPacket", "0"))[0] == "ok")
check("forced 100 half is red", one(P("Speed & Duplex", "100 Mbps Half Duplex", "*SpeedDuplex", "3"))[0] == "bad")
check("forced 10 full is red", one(P("Speed & Duplex", "10 Mbps Full Duplex", "*SpeedDuplex", "2"))[0] == "bad")
check("forced 100 full is yellow", one(P("Speed & Duplex", "100 Mbps Full Duplex", "*SpeedDuplex", "4"))[0] == "warn")
check("forced gigabit is yellow, set Auto", one(P("Speed & Duplex", "1.0 Gbps Full Duplex", "*SpeedDuplex", "6"))[:2]
      == ("warn", "Auto"))
check("ultra low power on is yellow", one(P("Ultra Low Power Mode", "Enabled", "ULPMode", "1"))[0] == "warn")
check("buffers with no range are not judged", one(P("Receive Buffers", "64", "*ReceiveBuffers", "64"))[0] == "ok")
check("selective suspend on is red", NC.grade(NC.windows_report({"SelectiveSuspend": "Enabled"})["items"][0])[0] == "bad")
slow = NC.windows_report({"Speed": 100_000_000, "FullDuplex": True})
check("linked at 100 Mb is yellow", level(slow, "Linked at") == "warn" and "100 Mbps" in slow["items"][0]["value"])
half = NC.windows_report({"Speed": 100_000_000, "FullDuplex": False})
check("linked at half duplex is red", level(half, "Linked at") == "bad")
check("nothing read", NC.windows_report(None) == {"adapter": "", "items": []}
      and NC.headline(NC.windows_report(None)) == ("No settings read", "info"))

# --- driver dates
check("driver age in whole years", NC.driver_age("2021-05-11", TODAY) == 5 and NC.driver_age("2021-10-12", TODAY) == 4)
check("US style date", NC.driver_age("5/11/2021", TODAY) == 5)
check("no date", NC.driver_age("", TODAY) is None and NC.driver_age("2021-13-45", TODAY) is None)
inbox = NC.windows_report({"Driver": "10.0.26100.1", "DriverDate": "2006-06-21", "Provider": "Microsoft"}, TODAY)
check("Windows' own driver date is not held against it", level(inbox, "Driver") == "info")

# --- Linux, from saved ethtool output
LINK = """Settings for enp14s0:
\tSupported link modes:   10baseT/Half 10baseT/Full
\t                        1000baseT/Full
\tAdvertised link modes:  10baseT/Half 10baseT/Full
\t                        1000baseT/Full
\tLink partner advertised link modes:  100baseT/Full
\t                                     1000baseT/Full
\tSpeed: 1000Mb/s
\tDuplex: Full
\tAuto-negotiation: on
\tLink detected: yes
"""
EEE_IDLE = "EEE settings for enp14s0:\n\tEEE status: enabled - inactive\n\tLink partner advertised EEE link modes:  Not reported\n"
EEE_ON = "EEE settings for eth0:\n\tEEE status: enabled - active\n\tLink partner advertised EEE link modes:  1000baseT/Full\n"
PAUSE = "Pause parameters for enp14s0:\nAutonegotiate:\ton\nRX:\t\ton\nTX:\t\toff\n"
COAL = "Coalesce parameters for eth0:\nAdaptive RX: off  TX: off\nrx-usecs: 50\nrx-frames: 0\ntx-usecs: 50\n"
RINGS = ("Ring parameters for eth0:\nPre-set maximums:\nRX:\t\t4096\nRX Mini:\tn/a\nTX:\t\t4096\n"
         "Current hardware settings:\nRX:\t\t128\nRX Mini:\tn/a\nTX:\t\t256\n")
FEAT = ("Features for eth0:\nrx-checksumming: on\ntx-checksumming: on\n\ttx-checksum-ipv4: on\n"
        "tcp-segmentation-offload: on\n\ttx-tcp-segmentation: on\ngeneric-receive-offload: on\n"
        "large-receive-offload: off [fixed]\nrx-vlan-offload: on\n")
DRV = "driver: r8169\nversion: 7.2.9-200.nobara.fc44.x86_64\nfirmware-version: rtl8126a-3_0.0.5 08/30/24\nbus-info: 0000:0e:00.0\n"

check("coalesce", NC.parse_coalesce(COAL) == {"adaptive": False, "usecs": 50}
      and NC.parse_coalesce("netlink error: Operation not supported") == {}
      and NC.parse_coalesce("Adaptive RX: on  TX: on\nrx-usecs: 0\n")["adaptive"])
check("rings", NC.parse_rings(RINGS) == {"rx": (128, 4096), "tx": (256, 4096)} and NC.parse_rings("") == {})
check("features keep top-level lines only", NC.parse_features(FEAT) == {
    "rx-checksumming": True, "tx-checksumming": True, "tcp-segmentation-offload": True,
    "generic-receive-offload": True, "large-receive-offload": False, "rx-vlan-offload": True})

lin = NC.linux_report({"link": LINK, "eee": EEE_ON, "pause": PAUSE, "coalesce": COAL, "rings": RINGS,
                       "features": FEAT, "driver": DRV, "mtu": "9000", "wifi": ["wlp15s0"], "desc": "Realtek RTL8126"})
for name, want in [("Energy Efficient Ethernet", "bad"), ("Wi-Fi also connected", "bad"), ("Flow control", "warn"),
                   ("Interrupt moderation", "warn"), ("Largest packet (MTU)", "warn"), ("Receive buffers", "warn"),
                   ("Transmit buffers", "ok"), ("Linked at", "ok"), ("Speed and duplex", "ok"),
                   ("TCP segmentation offload", "info"), ("Receive checksum offload", "info"), ("Driver", "info")]:
    check(f"linux: {name} is {want}", level(lin, name) == want, level(lin, name))
check("linux values read well", {i["name"]: i["value"] for i in lin["items"]}["Flow control"] == "RX on"
      and {i["name"]: i["value"] for i in lin["items"]}["Interrupt moderation"] == "50 µs"
      and "firmware rtl8126a" in lin["items"][-1]["value"])
check("linux headline", NC.headline(lin) == ("2 to fix, 4 worth changing", "bad"), NC.headline(lin))

quiet = NC.linux_report({"link": LINK, "eee": EEE_IDLE, "pause": PAUSE.replace("RX:\t\ton", "RX:\t\toff"),
                         "coalesce": "netlink error: Operation not supported", "mtu": "1500"})
check("EEE on but unused by the switch is yellow", level(quiet, "Energy Efficient Ethernet") == "warn")
check("a card that won't report a setting leaves it out",
      not any(i["kind"] in ("intmod", "buffers", "driver") for i in quiet["items"]))
check("linux: only the idle EEE to change", NC.headline(quiet) == ("1 worth changing", "warn"), NC.headline(quiet))
check("nothing from ethtool", NC.linux_report({}) == {"adapter": "", "items": []})
forced = NC.linux_report({"link": LINK.replace("1000Mb/s", "100Mb/s").replace("Duplex: Full", "Duplex: Half")
                          .replace("negotiation: on", "negotiation: off")})
check("linux: forced 100 half is red twice", level(forced, "Linked at") == "bad" and level(forced, "Speed and duplex") == "bad")

print(f"\nALL {ok} NIC CHECKS PASSED")
