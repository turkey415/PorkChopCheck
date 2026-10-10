"""Write a release version into porkchopcheck.py, so the app can say which build it is.

    python tools/stamp_version.py v2.0.0-beta.5 [path/to/porkchopcheck.py]

The release workflow runs this before it builds the .exe and packs the archives. A name that is
not a version, such as a branch name on a test build, leaves the file alone.
"""
import os
import re
import sys

VERSION_RE = re.compile(r"^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)$")
LINE_RE = re.compile(r'^VERSION = "[^"\n]*"', re.M)


def stamp(version, path):
    """Returns the version written, or None if `version` is not a version number."""
    m = VERSION_RE.match(version)
    if not m:
        return None
    with open(path, encoding="utf-8") as f:
        src = f.read()
    if len(LINE_RE.findall(src)) != 1:
        raise SystemExit(f'{path}: expected exactly one line like VERSION = "..."')
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(LINE_RE.sub(f'VERSION = "{m.group(1)}"', src))
    return m.group(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    target = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "porkchopcheck.py")
    done = stamp(sys.argv[1], target)
    print(f"stamped {done}" if done else f"not a version, left as it is: {sys.argv[1]}")
