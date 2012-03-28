////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2012 WU Jun <quark@zju.edu.cn>
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

#include "macros.h"
#include "cgroup.h"
#include "fs.h"
#include "strconv.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <fcntl.h>

using namespace lrun;

using std::string;

static struct {
    Cgroup::spawn_arg arg;
    double cpu_time_limit;
    double real_time_limit;
    long long memory_limit;
    bool enable_devices_whitelist;
    bool enable_network;
    bool enable_user_proc_namespace;
    
    std::map<std::string, std::string> cgroup_options;
} config;

int DEBUG = 0;

static void print_help() {
    fprintf(stderr,
            "Execute commands on Linux with resources limited and show time, memory usage.\n" \
            "\n" \
            "Usage: lrun [ options ] command-args 3>stat\n" \
            "\n" \
            "Options:\n" \
            "  --max-cpu-time    seconds        Limit cpu time, seconds can be a float number.\n" \
            "  --max-real-time   seconds        Limit real time, seconds can be a float number.\n" \
            "  --max-memory      bytes          Limit memory (+swap) usage in bytes.\n" \
            "                                   This value should not be too small (<100KB).\n" \
            "  --max-nprocess    n              Set max number of tasks to n (n > 0).\n" \
            "                                   Use this with --isolate-process true\n" \
            "                                   Note: user namespace is not seperated,\n" \
            "                                         Current user's processes are counted.\n" \
            "  --min-nice        n              Set min nice to n (-20 <= n < 19).\n" \
            "  --max-rtprio      n              Set max realtime priority to n.\n" \
            "  --max-nfile       n              Set max number of file descriptors to n.\n" \
            "  --max-stack       bytes          Set max stack size per process.\n" \
            "  --isolate-process bool           Isolate pid, ipc namespace\n" \
            "  --basic-devices   bool           Enable devices whitelist:\n" \
            "                                   null, zero, full, random, urandom\n" \
            "  --reset-env       bool           Clean environment variables.\n" \
            "  --network         bool           Whether network access is permitted.\n" \
            "  --chroot          path           Chroot to specified path before exec.\n" \
            "  --nice            nice           Add nice with specified value.\n" \
            "  --uid             uid            Set uid to specified uid (uid > 0).\n" \
            "  --gid             gid            Set gid to specified gid (gid > 0).\n" \
            "  --help                           Show this help.\n" \
            "\n" \
            "Options that could be used multiple times:\n" \
            "  --bindfs          dst src        Bind src path to dest path.\n" \
            "                                   This is performed before chroot.\n" \
            "  --tmpfs           path bytes     Mount writable tmpfs to specified path to hide\n" \
            "                                   filesystem subtree. size is in bytes.\n" \
            "                                   If bytes is 0, mount read-only.\n" \
            "                                   This is performed after chroot.\n" \
            "  --cgroup-option   key value      Apply cgroup setting before exec.\n" \
            "  --env             key value      Set environment variable before exec.\n" \
            "\n" \
            "Return value:\n" \
            "  If lrun is unable to execute specified command, non-zero is returned and\n" \
            "  nothing will be written to fd 3.\n" \
            "  Otherwise, lrun will return 0 and output time, memory usage, exit status\n" \
            "  of executed command to fd 3.\n" \
            "\n" \
            "Default options:\n" \
            "  lrun --network false --basic-devices true --isolate-process true \\\n" \
            "       --reset-env true \\\n" \
            "       --max-nprocess 300 --max-nfile 200 \\\n" \
            "       --min-nice 0 --max-rtprio 1 \\\n" \
            "       --uid $UID --gid $GID\n" \
            "\n" \
            "lrun version " VERSION "\n" \
            "Copyright (C) 2012 WU Jun <quark@zju.edu.cn>\n" \
            "\n" \
           );
    exit(0);
}

static void parse_options(int argc, char * argv[]) {
    // default settings
    config.cpu_time_limit = -1;
    config.real_time_limit = -1;
    config.memory_limit = -1;
    config.enable_devices_whitelist = true;
    config.enable_network = false;
    config.enable_user_proc_namespace = true;

    // arg settings
    config.arg.nice = 0;
    config.arg.uid = getuid() > 0 ? getuid() : (uid_t)2000;
    config.arg.gid = getgid() > 0 ? getgid() : (gid_t)200;
    config.arg.chroot_path = "";
    config.arg.args = argv + 1;

    // arg.rlimits settings
    config.arg.rlimits[RLIMIT_NICE] = 20 - 0;
    config.arg.rlimits[RLIMIT_NOFILE] = 200;
    config.arg.rlimits[RLIMIT_NPROC] = 300;
    config.arg.rlimits[RLIMIT_RTPRIO] = 1;

    config.arg.reset_env = 1;

    // parse commandline options 
#define REQUIRE_NARGV(n) \
    if (i + n >= argc) { \
        fprintf(stderr, "Option '%s' requires %d argument%s.\n", option.c_str(), n, n > 1 ? "s" : ""); \
        exit(1); \
    }
#define NEXT_STRING_ARG string(argv[++i])
#define NEXT_LONG_LONG_ARG (strconv::to_longlong(NEXT_STRING_ARG))
#define NEXT_DOUBLE_ARG (strconv::to_double(NEXT_STRING_ARG))
#define NEXT_BOOL_ARG (strconv::to_bool(NEXT_STRING_ARG))
    for (int i = 1; i < argc; ++i) {
        // break if it is not option
        if (strncmp("--", argv[i], 2) != 0) {
            config.arg.args = argv + i;
            break;
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
            config.memory_limit = NEXT_LONG_LONG_ARG;
        } else if (option == "max-nprocess") {
            REQUIRE_NARGV(1);
            config.arg.rlimits[RLIMIT_NPROC] = NEXT_LONG_LONG_ARG;
        } else if (option == "max-nice") {
            REQUIRE_NARGV(1);
            config.arg.rlimits[RLIMIT_NICE] = NEXT_LONG_LONG_ARG;
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
            config.enable_user_proc_namespace = NEXT_BOOL_ARG;
        } else if (option == "basic-devices") {
            REQUIRE_NARGV(1);
            config.enable_devices_whitelist = NEXT_BOOL_ARG;
        } else if (option == "reset-env") {
            REQUIRE_NARGV(1);
            config.arg.reset_env = (int)NEXT_BOOL_ARG;
        } else if (option == "network") {
            REQUIRE_NARGV(1);
            config.enable_network = NEXT_BOOL_ARG;
        } else if (option == "chroot") {
            REQUIRE_NARGV(1);
            config.arg.chroot_path = NEXT_STRING_ARG;
        } else if (option == "nice") {
            REQUIRE_NARGV(1);
            config.arg.nice = (int)NEXT_LONG_LONG_ARG;
        } else if (option == "uid") {
            REQUIRE_NARGV(1);
            long long uid = NEXT_LONG_LONG_ARG;
            if (uid > 0) config.arg.uid = (uid_t)uid;
        } else if (option == "gid") {
            REQUIRE_NARGV(1);
            long long gid = NEXT_LONG_LONG_ARG;
            if (gid > 0) config.arg.gid = (gid_t)gid;
        } else if (option == "bindfs") {
            REQUIRE_NARGV(2);
            string dst = NEXT_STRING_ARG;
            string src = NEXT_STRING_ARG;
            config.arg.bindfs_list.push_back(make_pair(dst, src));
        } else if (option == "tmpfs") {
            REQUIRE_NARGV(2);
            string path = NEXT_STRING_ARG;
            long long bytes = NEXT_LONG_LONG_ARG;
            config.arg.tmpfs_list.push_back(make_pair(path, bytes));
        } else if (option == "cgroup-option") {
            REQUIRE_NARGV(2);
            string key = NEXT_STRING_ARG;
            string value = NEXT_STRING_ARG;
            config.cgroup_options[key] = value;
        } else if (option == "env") {
            REQUIRE_NARGV(2);
            string key = NEXT_STRING_ARG;
            string value = NEXT_STRING_ARG;
            config.arg.env_list.push_back(make_pair(key, value));
        } else if (option == "help") {
            print_help();
        } else {
            fprintf(stderr, "Unknown option: --%s\n", option.c_str());
            print_help();
        }
    }
#undef REQUIRE_NARGV
#undef NEXT_STRING_ARG
#undef NEXT_LONG_LONG_ARG
#undef NEXT_DOUBLE_ARG
#undef NEXT_BOOL_ARG
}

static void check_environment() {
    // require root
    if (geteuid() != 0 || setuid(0)) {
        fprintf(stderr, "root required.\n");
        exit(2);
    }

    // should not be in cgroup
    string proc_cg = fs::read("/proc/self/cgroup");
    if (!proc_cg.empty()) {
        for (int i = proc_cg.length() - 1; i > 0; --i) {
            switch (proc_cg.c_str()[i]) {
                case ' ': case '\n':
                    continue;
                case '/':
                    i = -1;
                    break;
                default:
                    fprintf(stderr, "can not run inside a cgroup.\n");
                    exit(2);
            }
        }
    }
}

static double now() {
    struct timeval t;
    gettimeofday(&t, 0);
    return t.tv_usec / 1e6 + t.tv_sec;
}

static void clean_cg_exit(Cgroup& cg, int exit_code = 2) {
    if (cg.destroy()) WARNING("can not destroy cgroup");
    
    exit(exit_code);
}


int main(int argc, char * argv[]) {

    DEBUG = (getenv("DEBUG") != 0);

    if (argc <= 1) print_help();
    parse_options(argc, argv);

    check_environment();
    INFO("pid = %d", (int)getpid());

    // pick an unique name and create a cgroup in filesystem 
    string group_name = "ze" + strconv::from_long((long)getpid());
    Cgroup cg = Cgroup::create(group_name);

    if (!cg.valid()) FATAL("can not create cgroup '%s'", group_name.c_str());

    // assume cg is created just now and nobody has used it before.
    
    // initialize settings
    // device limits
    if (config.enable_devices_whitelist) {
        if (cg.limit_devices()) {
            ERROR("can not enable devices whitelist");
            clean_cg_exit(cg);
        }
    }

    // memory limits
    if (config.memory_limit > 0) {
        if (cg.set_memory_limit(config.memory_limit)) {
            ERROR("can not set memory limit");
            clean_cg_exit(cg);
        }
    }

    // some cgroup options, fail quietly
    cg.set("memory.swappiness", "0\n");

    // enable oom killer now, otherwise child may enter D status before exec
    // old memory cgroup subsystem does not know this, ignore silently
    cg.set("memory.oom_control", "0\n");

    // other cgroup options
    FOR_EACH(p, config.cgroup_options) {
        if (cg.set(p.first, p.second)) {
            ERROR("can not set cgroup option '%s' to '%s'", p.first.c_str(), p.second.c_str());
            clean_cg_exit(cg);
        }
    }


    // reset cpu / memory usage and killall existing processes
    // not needed if cg can be guarnteed that is newly created
    if (cg.killall()) {
        ERROR("can not stop running processes in group.");
        clean_cg_exit(cg);
    }

    if (cg.reset_usages()) {
        ERROR("can not reset cpu time / memory usage counter.");
        clean_cg_exit(cg);
    }

    // fd 3 should not be inherited by child process
	if (fcntl(3, F_SETFD, FD_CLOEXEC)) {
        // ignore bad fd error
        if (errno != EBADF) {
            ERROR("can not set FD_CLOEXEC on fd 3");
            clean_cg_exit(cg);
        }
    }

    // rlimit time
    if (config.cpu_time_limit > 0) {
        config.arg.rlimits[RLIMIT_CPU] = (int)(config.cpu_time_limit);
    }

    // spawn child
    pid_t pid = 0;
    bool running = true;

    int clone_flags = 0;
    if (!config.enable_network) clone_flags |= CLONE_NEWNET;
    if (config.enable_user_proc_namespace) clone_flags |= CLONE_NEWPID | CLONE_NEWIPC;
    config.arg.clone_flags = clone_flags;

    pid = cg.spawn(config.arg);

    if (pid <= 0) {
        // error message is printed before
        clean_cg_exit(cg);
    }

    // no sigpipe
    signal(SIGPIPE, SIG_IGN);

    // monitor its cpu_usage and real time usage and memory usage
    double start_time = now();
    double deadline = config.real_time_limit > 0 ? start_time + config.real_time_limit : -1;

    // child process stat (set by waitpid)
    int stat = 0;

    // which limit exceed
    string excceded_limit = "";

    while (running) {
        // check stat
        int e = waitpid(pid, &stat, WNOHANG);

        if (e == pid) {
            // stat available
            if (WIFEXITED(stat) || WIFSIGNALED(stat)) {
                running = false;
                break;
            }
        } else if (e == -1) {
            // see what's wrong
            if (errno == ECHILD) {
                // strangely, this happens at the beginning (?)
                usleep(10);
            }
        }

        // clean stat
        stat = 0;

        // check time limit exceed
        if (config.cpu_time_limit > 0 && cg.cpu_usage() >= config.cpu_time_limit) {
            excceded_limit = "CPU_TIME";
            break;
        }

        // check realtime exceed
        if (deadline > 0 && now() >= deadline) {
            excceded_limit = "REAL_TIME";
            break;
        }

        // check memory limit
        long long memory_limit = cg.memory_limit();
        if (cg.memory_usage() >= memory_limit && memory_limit > 0) {
            excceded_limit = "MEMORY";
            break;
        }

        // in case SIGCHILD is unreliable
        // check zombie manually here instead of waiting SIGCHILD
        string child_proc_stat = fs::read("/proc/" + strconv::from_long((long)pid) + "/stat", 128);
        if (child_proc_stat.find(" Z ") != string::npos) {
            // a zombie !
            running = false;
            // check waitpid again
            e = waitpid(pid, &stat, WNOHANG);
            if (e == -1) {
                // something goes wrong, give up
                clean_cg_exit(cg, 3);
            }
        }

        PROGRESS_INFO("CPU %4.2f | REAL %4.2f | MEM %4.2f",
                cg.cpu_usage(), now() - start_time, cg.memory_usage() / 1.e6);
        // sleep for a while
        usleep(20);
    }

    PROGRESS_INFO("\nOUT OF RUNNING LOOP\n");

    // collect stats
    long long memory_usage = cg.memory_usage();
    if (config.memory_limit > 0 && memory_usage >= config.memory_limit) {
        memory_usage = config.memory_limit;
        excceded_limit = "MEMORY";
    }

    double cpu_time_usage = cg.cpu_usage();
    if ((WIFSIGNALED(stat) && WTERMSIG(stat) == SIGXCPU) || (config.cpu_time_limit > 0 && cpu_time_usage >= config.cpu_time_limit)) {
        cpu_time_usage = config.cpu_time_limit;
        excceded_limit = "CPU_TIME";
    }

    double real_time_usage = now() - start_time;
    if (config.real_time_limit > 0 && real_time_usage >= config.real_time_limit) {
        real_time_usage = config.real_time_limit;
        excceded_limit = "REAL_TIME";
    }

    char status_report[4096];

    snprintf(status_report, sizeof status_report,
            "MEMORY   %lld\n"
            "CPUTIME  %.3f\n"
            "REALTIME %.3f\n"
            "SIGNALED %d\n"
            "EXITCODE %d\n"
            "TERMSIG  %d\n"
            "EXCEED   %s\n",
            memory_usage, cpu_time_usage, real_time_usage,
            WIFSIGNALED(stat) ? 1 : 0,
            WEXITSTATUS(stat),
            WTERMSIG(stat),
            excceded_limit.empty() ? "none" : excceded_limit.c_str());

    write(3, status_report, strlen(status_report));

    clean_cg_exit(cg, 0);
    return 0;
}
