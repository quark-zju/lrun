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

#include <string>
#include "../utils/strconv.h"
#include "../utils/fs.h"
#include "options.h"

using std::string;


static int check_fd(int fd) {
    if (fs::is_fd_valid(fd)) {
        return fd;
    } else {
        FATAL("fd %d is not accessible", fd)
    };
}

void lrun::options::parse(int argc, char * argv[], lrun::MainConfig& config) {
    config.arg.args = argv + 1;
    config.arg.argc = argc - 1;

#define REQUIRE_NARGV(n) \
    if (i + n >= argc) { \
        fprintf(stderr, "Option '%s' requires %d argument%s.\n", option.c_str(), n, n > 1 ? "s" : ""); \
        exit(1); \
    } else { \
        config.arg.argc -= n; \
        config.arg.args += n; \
    }
#define NEXT_STRING_ARG string(argv[++i])
#define NEXT_LONG_LONG_ARG (strconv::to_longlong(NEXT_STRING_ARG))
#define NEXT_DOUBLE_ARG (strconv::to_double(NEXT_STRING_ARG))
#define NEXT_BOOL_ARG (strconv::to_bool(NEXT_STRING_ARG))
    for (int i = 1; i < argc; ++i) {
        // break if it is not option
        if (strncmp("--", argv[i], 2) != 0) {
            config.arg.args = argv + i;
            config.arg.argc = argc - i;
            break;
        } else {
            config.arg.args = argv + i + 1;
            config.arg.argc = argc - i - 1;
        }

        string option = argv[i] + 2;

        if (option == "max-cpu-time") {
            REQUIRE_NARGV(1);
            config.cpu_time_limit = NEXT_DOUBLE_ARG;
        } else if (option == "max-real-time") {
            REQUIRE_NARGV(1);
            config.real_time_limit = NEXT_DOUBLE_ARG;
        } else if (option == "max-memory") {
            REQUIRE_NARGV(1);
            long long max_memory = strconv::to_bytes(NEXT_STRING_ARG);
            static const long long MIN_MEMORY_LIMIT = 500000LL;
            if (max_memory > 0 && max_memory < MIN_MEMORY_LIMIT) {
                WARNING("max-memory too small, changed to %lld.", MIN_MEMORY_LIMIT);
                max_memory = MIN_MEMORY_LIMIT;
            }
            config.memory_limit = max_memory;
        } else if (option == "max-output") {
            REQUIRE_NARGV(1);
            config.output_limit = strconv::to_bytes(NEXT_STRING_ARG);
            config.arg.rlimits[RLIMIT_FSIZE] = config.output_limit;
        } else if (option == "max-nprocess") {
            REQUIRE_NARGV(1);
            config.arg.rlimits[RLIMIT_NPROC] = NEXT_LONG_LONG_ARG;
        } else if (option == "min-nice") {
            // deprecated
            REQUIRE_NARGV(1);
            config.arg.rlimits[RLIMIT_NICE] = 20 - NEXT_LONG_LONG_ARG;
        } else if (option == "max-rtprio") {
            REQUIRE_NARGV(1);
            config.arg.rlimits[RLIMIT_RTPRIO] = NEXT_LONG_LONG_ARG;
        } else if (option == "max-nfile") {
            REQUIRE_NARGV(1);
            config.arg.rlimits[RLIMIT_NOFILE] = NEXT_LONG_LONG_ARG;
        } else if (option == "max-stack") {
            REQUIRE_NARGV(1);
            config.arg.rlimits[RLIMIT_STACK] = NEXT_LONG_LONG_ARG;
        } else if (option == "isolate-process") {
            REQUIRE_NARGV(1);
            config.enable_pidns = NEXT_BOOL_ARG;
        } else if (option == "basic-devices") {
            REQUIRE_NARGV(1);
            config.enable_devices_whitelist = NEXT_BOOL_ARG;
        } else if (option == "remount-dev") {
            REQUIRE_NARGV(1);
            config.arg.remount_dev = NEXT_BOOL_ARG;
        } else if (option == "reset-env") {
            REQUIRE_NARGV(1);
            config.arg.reset_env = (int)NEXT_BOOL_ARG;
        } else if (option == "network") {
            REQUIRE_NARGV(1);
            config.enable_network = NEXT_BOOL_ARG;
        } else if (option == "pass-exitcode") {
            REQUIRE_NARGV(1);
            config.pass_exitcode = NEXT_BOOL_ARG;
        } else if (option == "chroot") {
            REQUIRE_NARGV(1);
            config.arg.chroot_path = NEXT_STRING_ARG;
        } else if (option == "chdir") {
            REQUIRE_NARGV(1);
            config.arg.chdir_path = NEXT_STRING_ARG;
        } else if (option == "nice") {
            REQUIRE_NARGV(1);
            config.arg.nice = (int)NEXT_LONG_LONG_ARG;
        } else if (option == "umask") {
            REQUIRE_NARGV(1);
            config.arg.umask = (mode_t)NEXT_LONG_LONG_ARG;
        } else if (option == "uid") {
            REQUIRE_NARGV(1);
            config.arg.uid = (uid_t)NEXT_LONG_LONG_ARG;
        } else if (option == "gid") {
            REQUIRE_NARGV(1);
            config.arg.gid = (gid_t)NEXT_LONG_LONG_ARG;
        } else if (option == "no-new-privs") {
            REQUIRE_NARGV(1);
            config.arg.no_new_privs = NEXT_BOOL_ARG;
        } else if (option == "stdout-fd") {
            REQUIRE_NARGV(1);
            config.arg.stdout_fd = check_fd(NEXT_LONG_LONG_ARG);
        } else if (option == "stderr-fd") {
            REQUIRE_NARGV(1);
            config.arg.stderr_fd = check_fd(NEXT_LONG_LONG_ARG);
        } else if (option == "umount-outside") {
            REQUIRE_NARGV(1);
            config.arg.umount_outside = NEXT_BOOL_ARG;
        } else if (option == "syscalls" && seccomp::supported()) {
            REQUIRE_NARGV(1);
            string syscalls = NEXT_STRING_ARG;

            config.arg.syscall_action = seccomp::action_t::DEFAULT_EPERM;
            switch (syscalls.data()[0]) {
                case '!': case '-':
                    config.arg.syscall_action = seccomp::action_t::OTHERS_EPERM;
                    /* fallthrough */
                case '=':
                    /* fallthrough */
                case '+':
                    config.arg.syscall_list = string(syscalls.data() + 1);
                    break;
                default:
                    config.arg.syscall_list = syscalls;
            }
        } else if (option == "fopen-filter") {
            REQUIRE_NARGV(2);
            string condition = NEXT_STRING_ARG;
            string action = NEXT_STRING_ARG;
            options::fopen_filter(condition, action);
        } else if (option == "group") {
            REQUIRE_NARGV(1);
            gid_t gid = (gid_t)NEXT_LONG_LONG_ARG;
            if (gid != 0) config.groups.push_back(gid);
        } else if (option == "interval") {
            REQUIRE_NARGV(1);
            useconds_t interval = (useconds_t)(NEXT_DOUBLE_ARG * 1000000);
            if (interval > 0) config.interval = interval;
        } else if (option == "cgname") {
            REQUIRE_NARGV(1);
            config.cgname = NEXT_STRING_ARG;
        } else if (option == "hostname") {
            REQUIRE_NARGV(1);
            config.arg.uts.nodename = NEXT_STRING_ARG;
            config.arg.clone_flags |= CLONE_NEWUTS;
        } else if (option == "domainname") {
            REQUIRE_NARGV(1);
            config.arg.uts.domainname = NEXT_STRING_ARG;
            config.arg.clone_flags |= CLONE_NEWUTS;
        // these 3 ones are undocumented, only available with utsmod.ko loaded
        // see https://github.com/quark-zju/mod_utsmod
        } else if (option == "ostype") {
            REQUIRE_NARGV(1);
            config.arg.uts.sysname = NEXT_STRING_ARG;
            config.arg.clone_flags |= CLONE_NEWUTS;
        } else if (option == "osrelease") {
            REQUIRE_NARGV(1);
            config.arg.uts.release = NEXT_STRING_ARG;
            config.arg.clone_flags |= CLONE_NEWUTS;
        } else if (option == "osversion") {
            REQUIRE_NARGV(1);
            config.arg.uts.version = NEXT_STRING_ARG;
            config.arg.clone_flags |= CLONE_NEWUTS;
        } else if (option == "remount-ro") {
            REQUIRE_NARGV(1);
            string dest = NEXT_STRING_ARG;
            config.arg.remount_list[dest] |= MS_RDONLY;
        } else if (option == "bindfs") {
            REQUIRE_NARGV(2);
            string dest = NEXT_STRING_ARG;
            string src = NEXT_STRING_ARG;
            config.arg.bindfs_list.push_back(make_pair(dest, src));
            config.arg.bindfs_dest_set.insert(dest);
        } else if (option == "bindfs-ro") {
            // bindfs + remount-ro
            REQUIRE_NARGV(2);
            string dest = NEXT_STRING_ARG;
            string src = NEXT_STRING_ARG;
            config.arg.bindfs_list.push_back(make_pair(dest, src));
            config.arg.bindfs_dest_set.insert(dest);
            config.arg.remount_list[dest] |= MS_RDONLY;
        } else if (option == "tmpfs") {
            REQUIRE_NARGV(2);
            string path = NEXT_STRING_ARG;
            long long bytes = strconv::to_bytes(NEXT_STRING_ARG);
            config.arg.tmpfs_list.push_back(make_pair(path, bytes));
        } else if (option == "cgroup-option") {
            REQUIRE_NARGV(3);
            string subsys_name = NEXT_STRING_ARG;
            string key = NEXT_STRING_ARG;
            string value = NEXT_STRING_ARG;
            int subsys_id = Cgroup::subsys_id_from_name(subsys_name.c_str());
            if (subsys_id >= 0) {
                if (key.find("..") != string::npos || key.find('/') != string::npos) {
                    WARNING("unsafe cgroup option '%s' = '%s' ignored",
                            key.c_str(), value.c_str());
                } else {
                    config.cgroup_options[make_pair((Cgroup::subsys_id_t)subsys_id, key)] = value;
                }
            } else {
                WARNING("cgroup option '%s' = '%s' ignored: "
                        "subsystem '%s' not found",
                        key.c_str(), value.c_str(), subsys_name.c_str());
            }
        } else if (option == "env") {
            REQUIRE_NARGV(2);
            string key = NEXT_STRING_ARG;
            string value = NEXT_STRING_ARG;
            config.arg.env_list.push_back(make_pair(key, value));
        } else if (option == "fd") {
            REQUIRE_NARGV(1);
            config.arg.keep_fds.insert((int)NEXT_LONG_LONG_ARG);
        } else if (option == "cmd") {
            REQUIRE_NARGV(1);
            string cmd = NEXT_STRING_ARG;
            config.arg.cmd_list.push_back(cmd);
        } else if (option == "help") {
            options::help();
        } else if (option == "help-syscalls" && seccomp::supported()) {
            options::help_syscalls();
        } else if (option == "help-fopen-filter") {
            options::help_fopen_filter();
        } else if (option == "version") {
            options::version();
#ifndef NDEBUG
        } else if (option == "debug") {
            DEBUG_ENABLED = 1;
            DEBUG_PID = 1;
            DEBUG_TIMESTAMP = 1;
            DEBUG_PROGRESS = 0;
            DEBUG_START_TIME = now();
        } else if (option == "status") {
            DEBUG_PROGRESS = 1;
#endif
        } else if (option == "") {
            // meet --
            break;
        } else {
            fprintf(stderr, "Unknown option: `--%s`\nUse --help for information.\n", option.c_str());
            exit(1);
        }
    }
#undef REQUIRE_NARGV
#undef REQUIRE_ROOT
#undef NEXT_STRING_ARG
#undef NEXT_LONG_LONG_ARG
#undef NEXT_DOUBLE_ARG
#undef NEXT_BOOL_ARG
}

