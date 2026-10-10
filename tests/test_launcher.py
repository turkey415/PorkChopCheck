"""pcc-launch: builds it against a throwaway prefix and checks what it hands to Python.
The capabilities themselves need root to grant, so this covers everything around them."""
import os, shutil, subprocess, sys, tempfile

ok = 0
def check(name, cond, extra=""):
    global ok
    assert cond, f"FAIL {name} {extra}"
    ok += 1
    print("ok ", name)

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "linux", "pcc-launch.c")
cc = shutil.which("cc") or shutil.which("gcc")
if not sys.platform.startswith("linux") or not cc:
    print("skipped: needs Linux and a C compiler")
    sys.exit(0)

prefix = tempfile.mkdtemp()
os.makedirs(os.path.join(prefix, ".venv", "bin"))
os.symlink(sys.executable, os.path.join(prefix, ".venv", "bin", "python3"))
with open(os.path.join(prefix, "porkchopcheck.py"), "w") as f:
    f.write("import json, os, sys\n"
            "print(json.dumps({'argv': sys.argv[1:], 'env': dict(os.environ),\n"
            "                  'E': sys.flags.ignore_environment, 's': sys.flags.no_user_site,\n"
            "                  'amb': [l for l in open('/proc/self/status') if l.startswith('CapAmb')][0].split()[1]}))\n")
exe = os.path.join(prefix, "pcc-launch")
r = subprocess.run([cc, "-O2", "-Wall", "-Wextra", "-Werror", f'-DPREFIX="{prefix}"', "-o", exe, SRC],
                   capture_output=True, text=True)
check("builds with no warnings", r.returncode == 0, r.stderr)

import json
env = dict(os.environ, LD_PRELOAD="/nonexistent/evil.so", LD_LIBRARY_PATH="/evil", PYTHONPATH="/evil",
           PYTHONSTARTUP="/evil.py", PYTHONHOME="/evil", TCLLIBPATH="/evil", TK_LIBRARY="/evil",
           PATH="/evil:" + os.environ.get("PATH", ""), HOME="/home/someone", DISPLAY=":7", LANG="C.UTF-8")
r = subprocess.run([exe, "--demo", "--size", "800x480", "it's; $(odd) arg"], capture_output=True, text=True, env=env)
check("starts the app's script with the app's Python", r.returncode == 0, r.stderr)
got = json.loads(r.stdout)
check("arguments pass through untouched", got["argv"] == ["--demo", "--size", "800x480", "it's; $(odd) arg"], got["argv"])
check("python runs with -E and -s", got["E"] == 1 and got["s"] == 1)
for bad in ("LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "TCLLIBPATH", "TK_LIBRARY"):
    check(f"{bad} is not passed on", bad not in got["env"])
check("PATH is replaced, not inherited", "/evil" not in got["env"]["PATH"] and got["env"]["PATH"].startswith("/usr/local/sbin:"))
check("display, home and locale are kept", (got["env"].get("DISPLAY"), got["env"].get("HOME"), got["env"].get("LANG")) == (":7", "/home/someone", "C.UTF-8"))
check("the app is told it came through the launcher", got["env"].get("PCC_LAUNCHED") in ("caps", "nocaps"))
if os.geteuid() != 0:
    check("without file capabilities it grants none", got["env"]["PCC_LAUNCHED"] == "nocaps" and int(got["amb"], 16) == 0, got["amb"])

shutil.rmtree(prefix)
print(f"\nALL {ok} LAUNCHER CHECKS PASSED")
