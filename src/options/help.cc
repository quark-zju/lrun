////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2012-2015 Jun Wu <quark@zju.edu.cn>
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

#include <sys/ioctl.h>
#include <unistd.h>
#include <string>
#include "options.h"
#include "../seccomp.h"
#include "../version.h"


using std::string;
using namespace lrun;


static int get_terminal_width() {
    struct winsize ts;
    ioctl(0, TIOCGWINSZ, &ts);
    return ts.ws_col;
}

static string line_wrap(const string& content, size_t width, int indent, const string& join = "") {
    if (width <= 0) return content;

    string result;
    int line_size = 0;
    for (size_t i = 0; i < content.length(); ++i) {
        char c = content[i];
        if (c == ' ') {
            // should we break here?
            bool should_break = true;
            // look ahead for the next space char
            for (size_t j = i + 1; j <= content.length(); ++j) {
                char d = (j == content.length() ? ' ' : content[j]);
                if (d == ' ' && j - i + join.length() + line_size < width) {
                    should_break = false;
                    break;
                }
            }
            if (should_break) {
                result += join + "\n";
                for (int i = 0; i < indent; ++i) result += ' ';
                line_size = indent;
            } else {
                result += c;
                ++line_size;
            }
        } else {
            // can not split from here
            result += c;
            if (c == '\n') line_size = 0; else ++line_size;
        }
    }
    return result;
}

static string help_content(int width) {
    string content;
    content =
        "Run program with resources limited.\n"
        "\n"
        "Usage: lrun [options] [--] command-args [3>stat]\n"
        "\n";
    string options =
        "Options:\n"
        "  --max-cpu-time    seconds     Limit cpu time. `seconds` can be a floating-point number\n"
        "  --max-real-time   seconds     Limit physical time\n"
        "  --max-memory      bytes       Limit memory (+swap) usage. `bytes` supports common suffix like `k`, `m`, `g`\n"
        "  --max-output      bytes       Limit output. Note: lrun will make a \"best  effort\" to enforce the limit but it is NOT accurate\n"
        "  --max-rtprio      n           Set max realtime priority\n"
        "  --max-nfile       n           Set max number of file descriptors\n"
        "  --max-stack       bytes       Set max stack size per process\n"
        "  --max-nprocess    n           Set RLIMIT_NPROC. Note: user namespace is not separated, current processes are counted\n"
        "  --isolate-process bool        Isolate PID, IPC namespace\n"
        "  --basic-devices   bool        Enable device whitelist: null, zero, full, random, urandom\n"
        "  --remount-dev     bool        Remount /dev and create only basic device files in it (see --basic-device)\n"
        "  --reset-env       bool        Clean environment variables\n"
        "  --network         bool        Whether network access is permitted\n"
        "  --pass-exitcode   bool        Discard lrun exit code, pass child process's exit code\n"
        "  --chroot          path        Chroot to specified `path` before exec\n"
        "  --umount-outside  bool        Umount everything outside the chroot path. This is not necessary but can help to hide mount information. Note: umount is SLOW\n"
        "  --chdir           path        Chdir to specified `path` after chroot\n"
        "  --nice            value       Add nice with specified `value`. Only root can use a negative value\n"
        "  --umask           int         Set umask\n"
        "  --uid             uid         Set uid (`uid` must > 0). Only root can use this\n"
        "  --gid             gid         Set gid (`gid` must > 0). Only root can use this\n"
        "  --no-new-privs    bool        Do not allow getting higher privileges using exec. This disables things like sudo, ping, etc. Only root can set it to false. Require Linux >= 3.5\n"
        "  --stdout-fd       int         Redirect child process stdout to specified fd\n"
        "  --stderr-fd       int         Redirect child process stderr to specified fd\n";
    if (seccomp::supported()) options +=
        "  --syscalls        syscalls    Apply a syscall filter. "
        " `syscalls` is basically a list of syscall names separated by ',' with an optional prefix '!'. If prefix '!' exists, it's a blacklist otherwise a whitelist."
        " For full syntax of `syscalls`, see `--help-syscalls`. Conflicts with `--no-new-privs false`\n";
    options +=
        "  --cgname          string      Specify cgroup name to use. The specified cgroup will be created on demand, and will not be deleted. If this option is not set, lrun will pick"
        " an unique cgroup name and destroy it upon exit.\n"
        "  --hostname        string      Specify a new hostname\n"
        "  --interval        seconds     Set interval status update interval\n"
#ifndef NDEBUG
        "  --debug                       Print debug messages\n"
        "  --status                      Show realtime resource usage status\n"
#endif
        "  --help                        Show this help\n";
    if (seccomp::supported()) options +=
        "  --help-syscalls               Show full syntax of `syscalls`\n";
    options +=
        "  --help-fopen-filter           Show detailed help about fopen filter\n"
        "  --version                     Show version information\n"
        "\n"
        "Options that could be used multiple times:\n"
        "  --bindfs          dest src    Bind `src` to `dest`. This is performed before chroot. You should have read permission on `src`\n"
        "  --bindfs-ro       dest src    Like `--bindfs` but also make `dest` read-only\n"
        "  --tmpfs           path bytes  Mount writable tmpfs to specified `path` to hide filesystem subtree. `size` is in bytes. If it is 0, mount read-only."
        " This is performed after chroot. You should have write permission on `path`\n"
        "  --fopen-filter    cond action Do something when a file is opened. For details, see `--help-fopen-filter`.\n"
        "  --env             key value   Set environment variable before exec\n"
        "  --cgroup-option   subsys k v  Apply cgroup setting before exec. Only root can use this\n"
        "  --fd              n           Do not close fd `n`\n"
        "  --cmd             cmd         Execute system command after tmpfs mounted. Only root can use this\n"
        "  --group           gid         Set additional groups. Applied to lrun itself. Only root can use this\n"
        "\n";
    content += line_wrap(options, width, 32);
    content += line_wrap(
        "Return value:\n"
        "  - If lrun is unable to execute specified command, non-zero is returned and nothing will be written to fd 3\n"
        "  - Otherwise, lrun will return 0 and output time, memory usage, exit status of executed command to fd 3\n"
        "  - If `--pass-exitcode` is set to true, lrun will just pass exit code of the child process\n"
        "\n"
        , width, 4);
    content += line_wrap(
        "Option processing order:\n"
        "  --hostname, --fd, --umount-outside, (mount /proc), --bindfs, --bindfs-ro, --chroot, --tmpfs,"
        " --remount-dev, --fopen-filter, --chdir, --cmd, --umask, --gid, --uid, (rlimit options), --env, --nice,"
        " (cgroup limits), --syscalls\n"
        "\n"
        , width, 2);
    content += line_wrap(
        "Default options:\n"
        "  lrun --network true --basic-devices false --isolate-process true"
        " --remount-dev false --reset-env false --interval 0.02"
        " --pass-exitcode false --no-new-privs true --umount-outside false"
        " --max-nprocess 2048 --max-nfile 256"
        " --max-rtprio 0 --nice 0\n"
        , width, 7, " \\");
    return content;
}

static string help_syscalls_content(int width) {
    string content;
    content = line_wrap(
        "--syscalls FILTER_STRING\n"
        "  Default action for unlisted syscalls is to return EPERM.\n"
        "\n"
        "--syscalls !FILTER_STRING\n"
        "  Default action for unlisted syscalls is to allow.\n"
        "\n"
        , width, 2);
    content += line_wrap(
        "Format:\n"
        "  FILTER_STRING  := SYSCALL_RULE | FILTER_STRING + ',' + SYSCALL_RULE\n"
        "  SYSCALL_RULE   := SYSCALL_NAME + EXTRA_ARG_RULE + EXTRA_ACTION\n"
        "  EXTRA_ARG_RULE := '' | '[' + ARG_RULES + ']'\n"
        "  ARG_RULES      := ARG_RULE | ARG_RULES + ',' + ARG_RULE\n"
        "  ARG_RULE       := ARG_NAME + ARG_OP1 + NUMBER | ARG_NAME + ARG_OP2 + '=' + NUMBER\n"
        "  ARG_NAME       := 'a' | 'b' | 'c' | 'd' | 'e' | 'f'\n"
        "  ARG_OP1        := '==' | '=' | '!=' | '!' | '>' | '<' | '>=' | '<='\n"
        "  ARG_OP2        := '&'\n"
        "  EXTRA_ACTION   := '' | ':k' | ':e' | ':a'\n"
        "\n"
        , width, 20);
    content += line_wrap(
        "Notes:\n"
        "  ARG_NAME:     `a` for the first arg, `b` for the second, ...\n"
        "  ARG_OP1:      `=` is short for `==`, `!` is short for `!=`\n"
        "  ARG_OP2:      `&`: bitwise and\n"
        "  EXTRA_ACTION: `k` is to kill, `e` is to return EPERM, `a` is to allow\n"
        "  SYSCALL_NAME: syscall name or syscall number, ex: `read`, `0`, ...\n"
        "  NUMBER:       a decimal number containing only `0` to `9`\n"
        "\n"
        , width, 16);
    content += line_wrap(
        "Examples:\n"
        "  --syscalls 'read,write,open,exit'\n"
        "    Only read, write, open, exit are allowed\n"
        "  --syscalls '!write[a=2]'\n"
        "    Disallow write to fd 2 (stderr)\n"
        "  --syscalls '!sethostname:k'\n"
        "    Whoever calls sethostname will get killed\n"
        "  --syscalls '!clone[a&268435456==268435456]'\n"
        "    Do not allow a new user namespace to be created (CLONE_NEWUSER = 0x10000000)\n"
        , width, 4);
    return content;
}

static string help_fopen_filter_content(int width) {
    string content;
    content += line_wrap(
        "--fopen-filter CONDITION ACTION\n"
        "  Trigger an action when a file open condition is met\n"
        "\n"
        , width, 2);
    content += line_wrap(
        "Format:\n"
        "  CONDITION             := CONDITION_MOUNTPOINT | CONDITION_FILE\n"
        "  CONDITION_MOUNTPOINT  := 'm:' + PATH + ':' + REGEXP\n"
        "  CONDITION_FILE        := 'f:' + PATH\n"
        "  ACTION                := ACTION_ACCEPT | ACTION_REJECT | ACTION_RESET_TIMER\n"
        "  ACTION_ACCEPT         := 'a'\n"
        "  ACTION_DENY           := 'd'\n"
        "  ACTION_RESET_USAGE    := 'r' | 'R'\n"
        "  ACTION_LOG            := 'l' | 'l:' + LOG_FD\n"
        "\n"
        , width, 27);
    content += line_wrap(
        "Notes:\n"
        "  - PATH will be prepended with chroot path\n"
        "  - PATH and REGEXP in CONDITION_MOUNTPOINT should be escaped using '\\'. For example, replace ':' with '\\:'.\n"
        "  - ACTION_RESET_USAGE means reset CPU time counter. If 'R' is used, it is only effective for the 1st time, otherwise multiple times\n"
        "  - CONDITION_FILE does not work in /proc. Use CONDITION_MOUNTPOINT instead\n"
        "  - ACTION_LOG will log full paths, one per line, to stderr\n"
        "  - Mount point can be any sub path inside a real mount point. For example, /home/foo will be parsed as /home if /home/foo is not a mount point but /home is.\n"
        "  - If multiple conditions are met, the first one takes effect\n"
        "  - Filters have performance impact on all (including ones outside lrun) processes\n"
        "\n"
        , width, 4);
    content += line_wrap(
        "Examples:\n"
        "  --fopen-filter f:/usr/bin/cat R\n"
        "    If /usr/bin/cat is opened for the first time, lrun CPU time counter will be reset to zero.\n"
        "  --fopen-filter 'm:/etc:(\\.conf$|passwd|shadow)' l:5 5>/tmp/faccess.log\n"
        "    Log access to sensitive config files to /tmp/faccess.log\n"
        "  --fopen-filter 'm:/bin:/zsh$' d\n"
        "    Deny access to files with basename zsh. Effective on mountpoint /bin or / (if /bin is not a mountpoint but / is)\n"
        "  --fopen-filter 'm:/proc:/status$' a --fopen-filter 'm:/proc:/sta[^/]*$' d\n"
        "    Deny access to /proc/**/sta*, but allow /proc/**/status\n"
        , width, 4);
    return content;
}

string version_content(int) {
    string content;
    content = "lrun " VERSION "\n"
              "Copyright (C) 2012-2014 Jun Wu <quark@zju.edu.cn>\n"
              "\n"
              "libseccomp support: ";
    content += seccomp::supported() ? "yes" : "no";
    content += "\ndebug support: ";
    content +=
#ifdef NDEBUG
           "no"
#else
           "yes"
#endif
           ;
    content += "\n";
    return content;
}

typedef string gen_help_content_func(int);

static void print_help(gen_help_content_func f, FILE *fout = stderr) {
    int width = isatty(STDERR_FILENO) ? (get_terminal_width() - 1) : -1;
    const int MIN_WIDTH = 60;
    if (width < MIN_WIDTH && width >= 0) width = MIN_WIDTH;

    string content = f(width);

    fprintf(fout, "%s\n", content.c_str());
    exit(0);
}


void lrun::options::help() {
    print_help(help_content);
}

void lrun::options::help_syscalls() {
    print_help(help_syscalls_content);
}

void lrun::options::help_fopen_filter() {
    print_help(help_fopen_filter_content);
}

void lrun::options::version() {
    print_help(version_content, stdout);
}
