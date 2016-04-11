////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2016 Jun Wu <quark@zju.edu.cn>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
////////////////////////////////////////////////////////////////////////////////

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define FATAL(msg) { perror(msg); exit(EXIT_FAILURE); }
#define STACK_SIZE (1024 * 8)

static const char NETNS_DEST[] = "/var/run/netns/lrun-empty";
static const char NETNS_DIR[] = "/var/run/netns";
static const char NETNS_SELF[] = "/proc/self/ns/net";

static void become_root(void) {
    int r = setuid(0);
    if (r == -1)
        FATAL("setuid");
}

static const int STATE_EXIST = 1;
static const int STATE_NETNS = 2;

static int get_netns_state(void) {
    become_root();

    int state = 0;
    int fd = open(NETNS_DEST, O_RDONLY);
    if (fd != -1) {
        state |= STATE_EXIST;
        int r = setns(fd, CLONE_NEWNET);
        if (r == 0)
            state |= STATE_NETNS;
        close(fd);
    }
    return state;
}

static int child_func(void *arg) {
    assert(getuid() == 0);

    if (access(NETNS_DIR, F_OK) == -1)
        mkdir(NETNS_DIR, 0755);
    int fd = open(NETNS_DEST, O_CREAT, 0444);
    close(fd);

    int r = mount(NETNS_SELF, NETNS_DEST, NULL, MS_BIND, NULL);
    if (r == -1)
        FATAL("mount");
    return 0;
}

static void create_netns(void) {
    become_root();

    int state = get_netns_state();
    if ((state & STATE_NETNS) != 0)
        return;

    char stack[STACK_SIZE];
    pid_t pid = clone(child_func, stack + STACK_SIZE, CLONE_NEWNET | SIGCHLD, 0);
    if (pid == -1)
        FATAL("clone");

    int stat = 0;
    int r = waitpid(pid, &stat, 0);
    if (r == -1)
        FATAL("waitpid");

    if (WEXITSTATUS(stat) != 0)
        exit(WEXITSTATUS(stat));
}

static void remove_netns(void) {
    become_root();

    int state = get_netns_state();
    if (state == 0)
        return;

    umount(NETNS_DEST);
    int r = unlink(NETNS_DEST);
    if (r == -1)
        FATAL("unlink");
}

static void show_state(void) {
    static const char state_strs[][8] = {
        /* 0 */ "missing",
        /* 1 = STATE_EXIST */ "bad",
        /* 2 = STATE_NETNS */ "?",
        /* 3 = STATE_NETNS | STATE_EXIST */ "okay"
    };
    int state = get_netns_state();
    assert(state >= 0 && state <= 3);
    printf("%s: %s\n", NETNS_DEST, state_strs[state]);
}

static void show_help(void) {
    fprintf(stderr,
            "Usage:\n\n"
            "  --create   create the empty net namespace\n"
            "  --destroy  destroy the empty namespace\n"
            "  --status   show the status of the empty namespace\n"
            "  --help     print this help\n");
}

typedef void void_func_t();

int main(int argc, const char *argv[]) {
    void_func_t *func= show_state;
    if (argc >= 2) {
        if (strchr(argv[1], 'h') || strchr(argv[1], '?'))
            func = show_help;
        else if (strchr(argv[1], 'c'))
            func = create_netns;
        else if (strchr(argv[1], 'd'))
            func = remove_netns;
    }
    func();
}
