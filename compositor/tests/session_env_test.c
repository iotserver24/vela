// SPDX-FileCopyrightText: 2026 Brando Giuffrida
// SPDX-License-Identifier: GPL-3.0-or-later

// Which secret store the session selects, with a private HOME. No compositor.

#include "session.h"
#include "supervisor.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

bool vela_session_hook_path(char *out, size_t size)
{
    (void)out;
    (void)size;
    return false;
}

static void expect(const char *name, const char *want)
{
    const char *got = getenv(name);
    if (!got) {
        got = "";
    }
    if (strcmp(got, want) != 0) {
        fprintf(stderr, "%s is \"%s\", expected \"%s\"\n", name, got, want);
        failures++;
    }
}

static void write_file(const char *path, size_t bytes)
{
    // 0600: these stand in for keyring files, which are not world-writable.
    const int fd = open(path, O_CLOEXEC | O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) {
        perror(path);
        exit(1);
    }
    const char block[4096] = { 0 };
    while (bytes > 0) {
        const size_t chunk = bytes < sizeof(block) ? bytes : sizeof(block);
        if (write(fd, block, chunk) != (ssize_t)chunk) {
            perror(path);
            close(fd);
            exit(1);
        }
        bytes -= chunk;
    }
    if (close(fd) != 0) {
        perror(path);
        exit(1);
    }
}

static int join(char *out, size_t size, const char *home, const char *child)
{
    const size_t home_len = strlen(home);
    const size_t child_len = strlen(child);
    if (home_len + 1 + child_len + 1 > size) {
        return 0;
    }
    memcpy(out, home, home_len);
    out[home_len] = '/';
    memcpy(out + home_len + 1, child, child_len + 1);
    return 1;
}

static void remove_child(const char *home, const char *child)
{
    char path[512];
    if (!join(path, sizeof(path), home, child)) {
        return;
    }
    if (unlink(path) != 0) {
        rmdir(path);
    }
}

static int make_dir(const char *home, const char *child)
{
    char path[512];
    if (!join(path, sizeof(path), home, child)) {
        return 0;
    }
    return mkdir(path, 0700) == 0 || errno == EEXIST;
}

int main(void)
{
    // The home has to be a private directory. A literal /tmp path is a
    // world-writable location, which the security scan rejects.
    char cwd[240];
    char home[256];
    if (!getcwd(cwd, sizeof(cwd))) {
        return 1;
    }
    if (snprintf(home, sizeof(home), "%s/vela-session-env-XXXXXX", cwd) >= (int)sizeof(home)) {
        return 1;
    }
    if (!mkdtemp(home)) {
        return 1;
    }
    setenv("HOME", home, 1);
    setenv("XDG_RUNTIME_DIR", "/run/user/1000", 1);

    vela_session_set_environment();
    expect("XDG_CURRENT_DESKTOP", "Vela:KDE");
    expect("KDE_SESSION_VERSION", "6");

    char path[512];
    if (!make_dir(home, ".local")
        || !make_dir(home, ".local/share")
        || !make_dir(home, ".local/share/kwalletd")
        || !make_dir(home, ".local/share/keyrings")
        || !join(path, sizeof(path), home, ".local/share/kwalletd/Default.kwl")) {
        return 1;
    }
    write_file(path, 40000);
    vela_session_set_environment();
    expect("XDG_CURRENT_DESKTOP", "Vela:KDE");

    if (!join(path, sizeof(path), home, ".local/share/keyrings/login.keyring")) {
        return 1;
    }
    write_file(path, 56000);
    unsetenv("KDE_SESSION_VERSION");
    unsetenv("SSH_AUTH_SOCK");
    vela_session_set_environment();
    expect("XDG_CURRENT_DESKTOP", "Vela:GNOME");
    expect("KDE_SESSION_VERSION", "");
    expect("SSH_AUTH_SOCK", "/run/user/1000/keyring/ssh");
    expect("GNOME_KEYRING_CONTROL", "/run/user/1000/keyring");

    remove_child(home, ".local/share/kwalletd/Default.kwl");
    remove_child(home, ".local/share/keyrings/login.keyring");
    remove_child(home, ".local/share/kwalletd");
    remove_child(home, ".local/share/keyrings");
    remove_child(home, ".local/share");
    remove_child(home, ".local");
    rmdir(home);
    return failures == 0 ? 0 : 1;
}
