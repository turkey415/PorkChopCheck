"""HTTPS for the phone page, from Probe Deck's tls.py: a certificate made on the router with openssl,
or one you upload (for example signed by your own CA), and an SSL context the server swaps live.

Files: /etc/pcc-router/tls/cert.pem and key.pem (plain PEM, root-only).
"""

import ipaddress
import os
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path

NAME_RE = re.compile(r"(?=.{1,253}$)[A-Za-z0-9*]([A-Za-z0-9\-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,62}))*\.?")
MAX_PEM = 64 * 1024


def parse_names(text):
    """'GL-BE3600, 192.168.8.1' -> (dns names, ips)."""
    dns, ips = [], []
    for part in re.split(r"[,\s]+", str(text)):
        part = part.strip()
        if not part:
            continue
        try:
            ips.append(str(ipaddress.ip_address(part)))
            continue
        except ValueError:
            pass
        if not NAME_RE.fullmatch(part):
            raise ValueError(f"Not a host name or IP: {part[:40]}")
        dns.append(part.rstrip(".").lower())
    if not dns and not ips:
        raise ValueError("Give the certificate at least one name or IP")
    if len(dns) + len(ips) > 20:
        raise ValueError("At most 20 names")
    return list(dict.fromkeys(dns)), list(dict.fromkeys(ips))


class TLS:
    def __init__(self, conf_dir, addresses=lambda: []):
        """addresses(): the router's addresses now (192.168.8.1, the WAN or Access point address)."""
        self.addresses = addresses
        self.dir = Path(conf_dir) / "tls"
        self.cert = self.dir / "cert.pem"
        self.key = self.dir / "key.pem"
        self.ctx = None
        self.error = None
        self.fresh = False  # made on this start, before the router knew all its addresses
        self.lock = threading.Lock()

    def default_names(self):
        host = socket.gethostname()
        return list(dict.fromkeys([host, f"{host}.lan", "192.168.8.1", *[a for a in self.addresses() if a]]))

    def ensure(self):
        """Make a certificate on first start, then load it."""
        if not (self.cert.exists() and self.key.exists()):
            try:
                self.generate(", ".join(self.default_names()))
                self.fresh = True
                return
            except (OSError, ValueError, subprocess.SubprocessError) as e:
                self.error = f"couldn't make a certificate: {e}"
                return
        self.load()

    def cover_addresses(self, wait=90, step=3, sleep=time.sleep):
        """A certificate made on first start is remade once the router has its addresses (the WAN or
        Access point one comes from DHCP a little later), so it names them too."""
        for _ in range(int(wait / step)):
            if not self.fresh:
                return
            info = self.info() or {}
            if self.addresses() and info.get("missing"):
                try:
                    self.generate(", ".join(self.default_names()))
                except (OSError, ValueError, subprocess.SubprocessError) as e:
                    self.error = f"couldn't remake the certificate: {e}"
                break
            if self.addresses() and not info.get("missing"):
                break
            sleep(step)
        self.fresh = False

    def _context(self, cert, key):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        return ctx

    def load(self):
        try:
            self.ctx, self.error = self._context(self.cert, self.key), None
        except (OSError, ssl.SSLError) as e:
            self.ctx, self.error = None, f"couldn't load the certificate: {e}"

    def _install(self, tmp_cert, tmp_key):
        os.chmod(tmp_key, 0o600)
        os.replace(tmp_key, self.key)
        os.replace(tmp_cert, self.cert)
        self.load()

    def generate(self, names, days=3650):
        days = int(days)
        if not 1 <= days <= 3650:
            raise ValueError("Days must be 1-3650")
        dns, ips = parse_names(names)
        cn = (dns or ips)[0]
        san = ",".join([f"DNS:{d}" for d in dns] + [f"IP:{i}" for i in ips])
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        with self.lock, tempfile.TemporaryDirectory(dir=self.dir) as tmp:
            key, cert = Path(tmp) / "key.pem", Path(tmp) / "cert.pem"
            r = subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                 "-sha256", "-days", str(days), "-keyout", str(key), "-out", str(cert),
                 "-subj", f"/CN={cn}/O=PorkChopCheck", "-addext", f"subjectAltName={san}",
                 "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=serverAuth",
                 "-addext", "basicConstraints=critical,CA:FALSE"],
                capture_output=True, text=True, timeout=60)  # fmt: skip
            if r.returncode:
                raise ValueError("openssl: " + (r.stderr.strip().splitlines() or ["failed"])[-1][:200])
            self._install(cert, key)

    def upload(self, cert_pem, key_pem):
        """Your own certificate (with its chain, if any) and its private key, as PEM text."""
        cert_pem, key_pem = str(cert_pem or "").strip(), str(key_pem or "").strip()
        if "-----BEGIN CERTIFICATE-----" not in cert_pem:
            raise ValueError("The certificate must be PEM text starting with -----BEGIN CERTIFICATE-----")
        if "PRIVATE KEY-----" not in key_pem:
            raise ValueError("The key must be PEM text with -----BEGIN … PRIVATE KEY----- (not encrypted)")
        if "ENCRYPTED" in key_pem:
            raise ValueError("The key is password-protected: export it without a password")
        if len(cert_pem) > MAX_PEM or len(key_pem) > MAX_PEM:
            raise ValueError("That is too big for a certificate")
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        with self.lock, tempfile.TemporaryDirectory(dir=self.dir) as tmp:
            cert, key = Path(tmp) / "cert.pem", Path(tmp) / "key.pem"
            cert.write_text(cert_pem + "\n")
            fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(key_pem + "\n")
            try:
                self._context(cert, key)  # proves the key matches the certificate
            except ssl.SSLError as e:
                raise ValueError("The key doesn't match the certificate, or one of them is damaged") from e
            self._install(cert, key)

    def info(self):
        if not self.cert.exists():
            return None
        try:
            d = ssl._ssl._test_decode_cert(str(self.cert))
        except (ssl.SSLError, OSError, AttributeError):
            return None
        flat = lambda seq: {k: v for rdn in seq for k, v in rdn}  # noqa: E731
        subj, iss = flat(d.get("subject", ())), flat(d.get("issuer", ()))
        names = [v for k, v in d.get("subjectAltName", ())]
        fp = subprocess.run(["openssl", "x509", "-in", str(self.cert), "-noout", "-fingerprint", "-sha256"],
                            capture_output=True, text=True).stdout.strip().partition("=")[2]  # fmt: skip
        text = subprocess.run(["openssl", "x509", "-in", str(self.cert), "-noout", "-text"], capture_output=True, text=True).stdout
        m = re.search(r"Public Key Algorithm: (\S+).*?\((\d+) bit\)", text, re.S)
        missing = [a for a in self.addresses() if a and a not in names]
        return {
            "cn": subj.get("commonName"), "issuer": iss.get("commonName") or iss.get("organizationName"),
            "self_signed": d.get("subject") == d.get("issuer"), "names": names,
            "from": ssl.cert_time_to_seconds(d["notBefore"]), "to": ssl.cert_time_to_seconds(d["notAfter"]),
            "sha256": fp, "key": f"{'ECDSA' if m and 'ec' in m.group(1).lower() else 'RSA' if m else '?'} {m.group(2) if m else ''}".strip(),
            "missing": missing, "suggest": ", ".join(self.default_names()), "now": time.time(), "error": self.error,
        }  # fmt: skip
