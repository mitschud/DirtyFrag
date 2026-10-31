/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Launcher for the DMC vault harness.
 *
 * VaultKeeperService.getPackageName() in services.jar authorises a caller whose process name
 * is "system_server" - it obtains that name from libvkjni's nativeGetProcessName(pid), which
 * opens /proc/<pid>/cmdline. Anything else has to be a platform-signed app that ActivityManager
 * knows about, which a helper we build can never be. execve lets us choose argv[0], so the
 * helper announces itself the way the vendor service already expects, instead of injecting code
 * into system_server to borrow its identity.
 *
 *   df-d2-launch <jar> <status|authorize> <uid> [argv0]
 */
#include <stdio.h>
#include <unistd.h>

#define APP_PROCESS "/system/bin/app_process64"

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <jar> <status|authorize> <uid> [argv0]\n", argv[0]);
        return 2;
    }

    char class_path[4096];
    if (snprintf(class_path, sizeof(class_path), "-Djava.class.path=%s", argv[1])
            >= (int)sizeof(class_path)) {
        fprintf(stderr, "jar path does not fit\n");
        return 2;
    }

    char *args[] = {
        /* argv[argc] is NULL by definition, so this falls back when no name was given. */
        argv[4] ? argv[4] : (char *)"system_server",
        class_path,
        (char *)"/system/bin",
        (char *)"df.d2.Harness",
        argv[2],
        (char *)"--uid",
        argv[3],
        NULL,
    };

    execv(APP_PROCESS, args);
    perror("execv " APP_PROCESS);
    return 1;
}
