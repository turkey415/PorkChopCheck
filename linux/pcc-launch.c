/*
 * pcc-launch: start PorkChopCheck with packet capture and link control, and nothing else.
 *
 * install-linux.sh builds this, installs it root-owned next to the app and gives it two file
 * capabilities: cap_net_raw (capture) and cap_net_admin (link up/down). It hands them to exactly
 * one program: the app's own Python running the app's own script, both at fixed root-owned paths.
 *
 * The Python interpreter itself carries no capabilities, so nothing else on the machine can borrow
 * them by running it. Python is started with -E -s and a rebuilt environment, because a process
 * that gets its capabilities this way is not protected by the loader the way a setuid one is:
 * LD_PRELOAD, PYTHONPATH, TCLLIBPATH and friends would all be honoured.
 *
 * The app drops the ambient set as soon as it starts, so the programs it runs (ip, nmcli, ping,
 * iperf3, the file manager) get no capabilities at all.
 *
 * Build:  cc -O2 -Wall -Wextra -DPREFIX='"/opt/porkchopcheck"' -o pcc-launch pcc-launch.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/capability.h>

#ifndef PREFIX
#define PREFIX "/opt/porkchopcheck"
#endif
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_RAISE 2
#endif

#define PYTHON PREFIX "/.venv/bin/python3"
#define SCRIPT PREFIX "/porkchopcheck.py"
#define SAFE_PATH "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

/* What a desktop program needs to find its display, session bus, home and locale. */
static const char *const KEEP[] = {
    "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP", "XDG_DATA_DIRS", "XDG_CONFIG_DIRS", "DBUS_SESSION_BUS_ADDRESS",
    "HOME", "USER", "LOGNAME", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
    "LC_NUMERIC", "LC_TIME", "TZ", "TERM", "XCURSOR_THEME", "XCURSOR_SIZE",
};
#define NKEEP (sizeof(KEEP) / sizeof(KEEP[0]))

static const int CAPS[] = { CAP_NET_ADMIN, CAP_NET_RAW };
#define NCAPS (sizeof(CAPS) / sizeof(CAPS[0]))

/* Make our permitted capabilities inheritable, then ambient, so they survive the exec into a
 * Python that has no file capabilities of its own. Returns 0 if both made it. */
static int raise_ambient(void)
{
    struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
    size_t i;

    if (syscall(SYS_capget, &hdr, data) != 0)
        return -1;
    for (i = 0; i < NCAPS; i++)
        data[CAP_TO_INDEX(CAPS[i])].inheritable |= CAP_TO_MASK(CAPS[i]);
    if (syscall(SYS_capset, &hdr, data) != 0)
        return -1;
    for (i = 0; i < NCAPS; i++)
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAPS[i], 0, 0) != 0)
            return -1;
    return 0;
}

int main(int argc, char **argv)
{
    static char *env[NKEEP + 3];
    char **args;
    size_t n = 0, i;
    int a;

    for (i = 0; i < NKEEP; i++) {
        const char *v = getenv(KEEP[i]);
        char *kv;
        if (!v)
            continue;
        if (asprintf(&kv, "%s=%s", KEEP[i], v) < 0)
            return 111;
        env[n++] = kv;
    }
    env[n++] = SAFE_PATH;
    /* Tells the app it came through here; without capabilities it still runs, just without
     * capture, and says so on screen. */
    env[n++] = raise_ambient() == 0 ? "PCC_LAUNCHED=caps" : "PCC_LAUNCHED=nocaps";
    env[n] = NULL;

    args = calloc((size_t)argc + 4, sizeof(*args));
    if (!args)
        return 111;
    args[0] = PYTHON;
    args[1] = "-E";             /* ignore every PYTHON* variable */
    args[2] = "-s";             /* no per-user site-packages */
    args[3] = SCRIPT;
    for (a = 1; a < argc; a++)
        args[3 + a] = argv[a];

    execve(PYTHON, args, env);
    fprintf(stderr, "pcc-launch: cannot start %s: %s\n", PYTHON, strerror(errno));
    return 111;
}
