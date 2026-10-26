"""Logins for the phone page: user accounts (admin or viewer), from Probe Deck's auth.py.

The first visit creates the first admin, and proves it's the router's owner with the router's own
admin password (the one for GL.iNet's admin page, root's in /etc/shadow). Users are kept in
/etc/pcc-router/users.json and logins in /etc/pcc-router/sessions.json, both root-only.

Admin: everything. Viewer: can look, and re-check the port, but not change anything.

Locked out? Over SSH:  python3 -m pcc_router.auth passwd|add|del|list  (PYTHONPATH=/usr/share/pcc-router)
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import warnings
from http.cookies import SimpleCookie
from pathlib import Path

COOKIE = "pcc_session"
SHADOW = "/etc/shadow"
SESSION_SECS = 30 * 86400   # a login lasts a month
ROLES = ("admin", "viewer")
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._\-]{0,31}")
FAIL_WINDOW, FAIL_MAX, LOCK_SECS = 300, 10, 300


def hash_pw(pw, salt=None, iters=120_000):
    salt = salt or secrets.token_bytes(16)
    return f"pbkdf2${iters}${salt.hex()}${hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, iters).hex()}"


def check_hash(pw, stored):
    try:
        _, iters, salt, _ = stored.split("$")
        return hmac.compare_digest(hash_pw(pw, bytes.fromhex(salt), int(iters)), stored)
    except (ValueError, AttributeError):
        return False


def root_password_ok(pw, shadow=SHADOW):
    """True if pw is the router's admin password (root's, the one GL.iNet's admin page uses)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            import crypt  # Python 3.11 on the router still has it
        except ImportError:
            return False
    try:
        with open(shadow) as f:
            stored = next((line.split(":")[1] for line in f if line.startswith("root:")), "")
    except OSError:
        return False
    return bool(stored) and len(stored) > 3 and hmac.compare_digest(crypt.crypt(str(pw or ""), stored) or "", stored)


def norm_name(name):
    n = str(name or "").strip().lower()
    if not NAME_RE.fullmatch(n):
        raise ValueError("User names are 1-32 letters, digits, dots, dashes or underscores")
    return n


def check_new_pw(pw):
    pw = str(pw or "")
    if len(pw) < 8:
        raise ValueError("Use at least 8 characters")
    if len(pw) > 200:
        raise ValueError("That password is too long")
    return pw


class Auth:
    def __init__(self, conf_dir, owner_check=root_password_ok):
        self.users_file = Path(conf_dir) / "users.json"
        self.sess_file = Path(conf_dir) / "sessions.json"
        self.owner_check = owner_check  # the router's admin password: proof of ownership for the first setup
        self.lock = threading.Lock()
        self.users, self.mtime = {}, None
        self.sessions = {}             # sha256(token) -> {"user", "exp"}
        self.fails = {}                # ip -> [times]
        self.load_users()
        try:
            now = time.time()
            self.sessions = {k: v for k, v in json.loads(self.sess_file.read_text()).items() if v["exp"] > now}
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            pass

    # ---------- storage ----------
    def load_users(self):
        try:
            m = self.users_file.stat().st_mtime
        except OSError:
            self.users, self.mtime = {}, None
            return
        if m == self.mtime:
            return
        try:
            self.users = {u["name"]: u for u in json.loads(self.users_file.read_text()) if u.get("role") in ROLES}
        except (OSError, ValueError, KeyError, TypeError):
            self.users = {}
        changed_outside = self.mtime is not None
        self.mtime = m
        if changed_outside:
            # Changed by the command line (it drops sessions on disk too): take its session list.
            try:
                self.sessions = json.loads(self.sess_file.read_text())
            except (OSError, ValueError):
                pass
        self.sessions = {k: v for k, v in self.sessions.items() if v["user"] in self.users}

    def save_users(self):
        self.users_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.users_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(sorted(self.users.values(), key=lambda u: u["name"]), indent=1))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.users_file)
        self.mtime = self.users_file.stat().st_mtime

    def save_sessions(self):
        try:
            self.sess_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.sess_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.sessions))
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.sess_file)
        except OSError:
            pass

    # ---------- guessing ----------
    def check_rate(self, ip):
        now = time.time()
        f = [t for t in self.fails.get(ip, []) if now - t < FAIL_WINDOW]
        self.fails[ip] = f
        if len(f) >= FAIL_MAX:
            raise ValueError(f"Too many wrong passwords. Try again in {int(LOCK_SECS - (now - f[-FAIL_MAX]))} s")

    def failed(self, ip):
        self.fails.setdefault(ip, []).append(time.time())
        time.sleep(1)

    # ---------- setup, login, sessions ----------
    def needs_setup(self):
        with self.lock:
            self.load_users()
            return not self.users

    def setup(self, name, pw, owner_pw, ip):
        """Create the first admin. Only while there are no users, and only with the router's admin password."""
        self.check_rate(ip)
        with self.lock:
            self.load_users()
            if self.users:
                raise ValueError("Setup is already done")
            if self.owner_check and not self.owner_check(owner_pw):
                self.failed(ip)
                raise ValueError("The router's admin password is wrong (the one for GL.iNet's admin page)")
            name, pw = norm_name(name), check_new_pw(pw)
            self.users[name] = {"name": name, "role": "admin", "pw": hash_pw(pw), "created": time.time(), "last": None}
            self.save_users()
        return self.start(name)

    def login(self, name, pw, ip):
        self.check_rate(ip)
        with self.lock:
            self.load_users()
            u = self.users.get(str(name or "").strip().lower())
        if not u or not check_hash(str(pw or ""), u["pw"]):
            self.failed(ip)
            raise ValueError("Wrong user name or password")
        self.fails.pop(ip, None)
        return self.start(u["name"])

    def start(self, name):
        tok = secrets.token_urlsafe(32)
        now = time.time()
        with self.lock:
            self.sessions = {k: v for k, v in self.sessions.items() if v["exp"] > now}
            self.sessions[hashlib.sha256(tok.encode()).hexdigest()] = {"user": name, "exp": now + SESSION_SECS}
            if name in self.users:
                self.users[name]["last"] = now
                self.save_users()
            self.save_sessions()
        return tok

    @staticmethod
    def token(headers):
        try:
            c = SimpleCookie(headers.get("Cookie") or "").get(COOKIE)
        except Exception:
            return None
        return c.value if c else None

    def user(self, headers):
        """{"name", "role"} for this request's session, or None."""
        tok = self.token(headers)
        if not tok:
            return None
        with self.lock:
            self.load_users()
            s = self.sessions.get(hashlib.sha256(tok.encode()).hexdigest())
            if not s or s["exp"] < time.time():
                return None
            u = self.users.get(s["user"])
        return {"name": u["name"], "role": u["role"]} if u else None

    def logout(self, headers):
        tok = self.token(headers)
        if tok:
            with self.lock:
                self.sessions.pop(hashlib.sha256(tok.encode()).hexdigest(), None)
                self.save_sessions()

    def drop_sessions(self, name, keep=None):
        keep_h = hashlib.sha256(keep.encode()).hexdigest() if keep else None
        self.sessions = {k: v for k, v in self.sessions.items() if v["user"] != name or k == keep_h}
        self.save_sessions()

    @staticmethod
    def cookie(tok, secure=False):
        sec = "; Secure" if secure else ""
        if tok is None:
            return f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict{sec}"
        return f"{COOKIE}={tok}; Path=/; Max-Age={SESSION_SECS}; HttpOnly; SameSite=Strict{sec}"

    # ---------- managing users (admins) ----------
    def admins(self):
        return [u for u in self.users.values() if u["role"] == "admin"]

    def add(self, name, role, pw):
        name, pw = norm_name(name), check_new_pw(pw)
        if role not in ROLES:
            raise ValueError("Role must be admin or viewer")
        with self.lock:
            self.load_users()
            if name in self.users:
                raise ValueError(f"{name} already exists")
            if len(self.users) >= 50:
                raise ValueError("At most 50 users")
            self.users[name] = {"name": name, "role": role, "pw": hash_pw(pw), "created": time.time(), "last": None}
            self.save_users()

    def update(self, name, role=None, pw=None):
        with self.lock:
            self.load_users()
            u = self.users.get(name)
            if not u:
                raise ValueError("No such user")
            if role is not None:
                if role not in ROLES:
                    raise ValueError("Role must be admin or viewer")
                if u["role"] == "admin" and role != "admin" and len(self.admins()) == 1:
                    raise ValueError("That's the last admin. Make someone else admin first")
                u["role"] = role
            if pw is not None:
                u["pw"] = hash_pw(check_new_pw(pw))
                self.drop_sessions(name)  # they log in again with the new password
            self.save_users()

    def delete(self, name, me):
        with self.lock:
            self.load_users()
            u = self.users.get(name)
            if not u:
                raise ValueError("No such user")
            if name == me:
                raise ValueError("You can't delete yourself")
            if u["role"] == "admin" and len(self.admins()) == 1:
                raise ValueError("That's the last admin")
            del self.users[name]
            self.save_users()
            self.drop_sessions(name)

    def change_own(self, name, current, new, keep_token):
        with self.lock:
            self.load_users()
            u = self.users.get(name)
            if not u or not check_hash(str(current or ""), u["pw"]):
                time.sleep(1)
                raise ValueError("Current password is wrong")
            u["pw"] = hash_pw(check_new_pw(new))
            self.save_users()
            self.drop_sessions(name, keep=keep_token)  # log out their other browsers

    def listing(self):
        with self.lock:
            self.load_users()
            now = time.time()
            active = {}
            for s in self.sessions.values():
                if s["exp"] > now:
                    active[s["user"]] = active.get(s["user"], 0) + 1
            return [{"name": u["name"], "role": u["role"], "created": u.get("created"), "last": u.get("last"),
                     "sessions": active.get(u["name"], 0)} for u in sorted(self.users.values(), key=lambda u: u["name"])]


def cli():
    """Manage users over SSH, e.g. when locked out. The running page picks the change up by itself."""
    import argparse
    import getpass
    ap = argparse.ArgumentParser(description="PorkChopCheck router users")
    ap.add_argument("--conf-dir", default="/etc/pcc-router")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    for c in ("passwd", "add", "del"):
        p = sub.add_parser(c)
        p.add_argument("name")
        if c == "add":
            p.add_argument("role", choices=ROLES)
    a = ap.parse_args()
    au = Auth(a.conf_dir)
    if a.cmd == "list":
        for u in au.listing():
            print(f"{u['name']:20} {u['role']}")
        return
    if a.cmd == "del":
        with au.lock:
            au.users.pop(norm_name(a.name), None)
            au.save_users()
        print("deleted")
        return
    pw = getpass.getpass("New password: ")
    if pw != getpass.getpass("Again: "):
        sys.exit("Passwords don't match")
    if a.cmd == "add":
        au.add(a.name, a.role, pw)
    else:
        name = norm_name(a.name)
        if name not in au.users:
            sys.exit(f"No user {name}. Use: add {name} admin")
        au.update(name, pw=pw)
    print("saved")


if __name__ == "__main__":
    cli()
