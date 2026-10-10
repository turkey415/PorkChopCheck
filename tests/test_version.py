"""The version the app reports, and the release step that writes it."""
import os, re, shutil, subprocess, sys, tempfile

ok = 0
def check(name, cond, extra=""):
    global ok
    assert cond, f"FAIL {name} {extra}"
    ok += 1
    print("ok ", name)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import stamp_version as SV

src = open(os.path.join(ROOT, "porkchopcheck.py"), encoding="utf-8").read()
lines = SV.LINE_RE.findall(src)
check("porkchopcheck.py has exactly one VERSION line", len(lines) == 1, lines)
current = re.search(r'"(.*)"', lines[0]).group(1)
check("the source carries a dev version, never a release one", current.endswith("-dev"), current)

tmp = tempfile.mkdtemp()
copy = os.path.join(tmp, "porkchopcheck.py")
shutil.copy(os.path.join(ROOT, "porkchopcheck.py"), copy)
check("a tag is stamped without its v", SV.stamp("v2.0.0-beta.5", copy) == "2.0.0-beta.5")
out = open(copy, encoding="utf-8").read()
check("the line is rewritten", 'VERSION = "2.0.0-beta.5"' in out and current not in SV.LINE_RE.findall(out)[0])
check("nothing else in the file changes", out.replace('VERSION = "2.0.0-beta.5"', lines[0]) == src)
check("a plain release version works", SV.stamp("v2.1.0", copy) == "2.1.0")
for bad in ("main", "security-hardening", "v2.1", "2.1.0; rm -rf /", 'v2.1.0"\nimport os', ""):
    before = open(copy, encoding="utf-8").read()
    check(f"not a version, file untouched: {bad!r}", SV.stamp(bad, copy) is None and open(copy, encoding="utf-8").read() == before)

r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "stamp_version.py"), "v3.4.5-rc.1", copy],
                   capture_output=True, text=True)
check("command line form", r.returncode == 0 and "stamped 3.4.5-rc.1" in r.stdout and 'VERSION = "3.4.5-rc.1"' in open(copy).read(), r.stdout + r.stderr)
shutil.rmtree(tmp)
print(f"\nALL {ok} VERSION CHECKS PASSED")
