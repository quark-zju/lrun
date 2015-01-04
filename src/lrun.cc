////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2012-2014 Jun Wu <quark@zju.edu.cn>
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

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <string>
#include <stropts.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <signal.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include "utils/linux_only.h"
#include "utils/for_each.h"
#include "utils/log.h"
#include "utils/fs.h"
#include "utils/strconv.h"
#include "utils/ensure.h"
#include "options/options.h"
#include "config.h"
#include "cgroup.h"

using namespace lrun;

using std::string;
using std::make_pair;

lrun::MainConfig config;

static volatile sig_atomic_t signal_triggered = 0;
static pthread_t fs_tracer_thread_id;

static int check_fd(int fd) {
    if (fs::is_accessible("/proc/self/fd/" + strconv::from_long(fd))) {
        return fd;
    } else {
        FATAL("fd %d is not accessible", fd)
    };
}

static void parse_cli_options(int argc, char * argv[]) {
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
                    /* intended no break */
                case '=': case '+':
                    config.arg.syscall_list = string(syscalls.data() + 1);
                    break;
                default:
                    config.arg.syscall_list = syscalls;
            }
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
                config.cgroup_options[make_pair((Cgroup::subsys_id_t)subsys_id, key)] = value;
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

static void check_environment() {
    // require root
    if (geteuid() != 0 || setuid(0)) {
        FATAL("lrun: root required. (current euid = %d, uid = %d)", geteuid(), getuid());
    }

    // normalize group
    int e = setgid(0);
    if (e) ERROR("setgid(0) failed");

    e = setgroups(config.groups.size(), &config.groups[0]);
    if (e) ERROR("setgroups failed");
}

static void clean_cg_exit(Cgroup& cg, int exit_code) {
    INFO("cleaning and exiting with code = %d", exit_code);

    if (config.arg.fs_tracer) {
        // pre-kill
        cg.killall(false /* confirm */);
        if (fs_tracer_thread_id) {
            pthread_cancel(fs_tracer_thread_id);
            fs_tracer_thread_id = 0;
        }
        delete config.arg.fs_tracer;
        config.arg.fs_tracer = NULL;
    }

    if (config.cgname.empty()) {
        if (cg.destroy()) WARNING("can not destroy cgroup");
    } else {
        cg.killall();
    }

    exit(exit_code);
}

static char get_process_state(pid_t pid) {
    FILE * fstatus = fopen((string(fs::PROC_PATH) + "/" + strconv::from_ulong((unsigned long)pid) + "/status").c_str(), "r");
    char state = 0;
    if (!fstatus) return 0;
    int ret = fscanf(fstatus, "%*[^\n] State: %c", &state);
    (void)ret;
    fclose(fstatus);
    return state;
}

static void signal_handler(int signal) {
    signal_triggered = signal;
}

#ifndef NDEBUG
# ifndef NLIBSEGFAULT
// compile with -ldl
#include <dlfcn.h>
static struct LibSegFaultLoader {
    LibSegFaultLoader() {
        // try to load libSegFault.so
        // use `addr2line` if libSegFault doesn't resolve function names
        void *libSegFault = dlopen("libSegFault.so", RTLD_NOW);
        // log facility may not be initialized now, do not use INFO here
        (void)libSegFault;
    }
} _libSegFaultLoader;
# endif
#endif

static void setup_signal_handlers() {
    struct sigaction action;

    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    action.sa_handler = SIG_IGN;

    // ignore SIGPIPE so that a program reading fd 3 via a pipe may
    // close it earlier and lrun continues to do cleaning work
    sigaction(SIGPIPE, &action, NULL);
    sigaction(SIGALRM, &action, NULL);

    action.sa_handler = signal_handler;
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGABRT, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);
    sigaction(SIGFPE, &action, NULL);
    sigaction(SIGILL, &action, NULL);
    sigaction(SIGTRAP, &action, NULL);
}

static void create_cgroup() {
    // pick an unique name and create a cgroup in filesystem
    string cgname = config.cgname;
    if (cgname.empty()) cgname = "lrun" + strconv::from_ulong((unsigned long)getpid());
    INFO("cgname = '%s'", cgname.c_str());

    // create or reuse group
    static Cgroup new_cg = Cgroup::create(cgname);

    if (!new_cg.valid()) FATAL("can not create cgroup '%s'", cgname.c_str());
    config.active_cgroup = &new_cg;
}

static int fs_trace_callback(const char path[], int fd, pid_t pid, uint64_t mask) {
    INFO("trace %s", path);
    return 0;
}

static void * fs_tracer_thread(void *data) {
    fs::Tracer *tracer = (fs::Tracer*) data;
    if (!tracer) return 0;
    pthread_setname_np(pthread_self(), "lrun:fstracer");
    while (1) {
        tracer->process_events();
    }
    return NULL;
}

static void create_fs_tracer() {
    config.arg.fs_tracer = new fs::Tracer();
    if (config.arg.fs_tracer->init(
                FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE,
                O_RDWR | O_CLOEXEC,
                &fs_trace_callback)) {
        FATAL("can not init filesystem tracer");
    }
    INFO("starting fs tracer thread");
    pthread_attr_t attr;
    ensure_zero(pthread_attr_init(&attr));
    // the thread must be joinable so that we can reliably use pthread_kill to detect if it is alive
    ensure_zero(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE));
    pthread_create(&fs_tracer_thread_id, NULL, &fs_tracer_thread, (void*) config.arg.fs_tracer);
    ensure_zero(pthread_attr_destroy(&attr));
}

static void configure_cgroup() {
    Cgroup& cg = *config.active_cgroup;

    // assume cg is created just now and nobody has used it before.
    // initialize settings
    // device limits
    if (config.enable_devices_whitelist) {
        if (cg.limit_devices()) {
            ERROR("can not enable devices whitelist");
            clean_cg_exit(cg, 1);
        }
    }

    // memory limits
    if (config.memory_limit > 0) {
        if (cg.set_memory_limit(config.memory_limit)) {
            ERROR("can not set memory limit");
            clean_cg_exit(cg, 2);
        }
    }

    // some cgroup options, fail quietly
    cg.set(Cgroup::CG_MEMORY, "memory.swappiness", "0\n");

    // enable oom killer now so our buggy code won't freeze.
    // we will disable it later.
    cg.set(Cgroup::CG_MEMORY, "memory.oom_control", "0\n");

    // other cgroup options
    FOR_EACH(p, config.cgroup_options) {
        if (cg.set(p.first.first, p.first.second, p.second)) {
            ERROR("can not set cgroup option '%s' to '%s'", p.first.second.c_str(), p.second.c_str());
            clean_cg_exit(cg, 7);
        }
    }

    // reset cpu / memory usage and killall existing processes
    // not needed if cg can be guarnteed that is newly created
    cg.killall();

    if (cg.reset_usages()) {
        ERROR("can not reset cpu time / memory usage counter.");
        clean_cg_exit(cg, 4);
    }

    // rlimit time
    if (config.cpu_time_limit > 0) {
        config.arg.rlimits[RLIMIT_CPU] = (int)(ceil(config.cpu_time_limit));
    }
}

static int run_command() {
    Cgroup& cg = *config.active_cgroup;

    // fd 3 should not be inherited by child process
    if (fcntl(3, F_SETFD, FD_CLOEXEC)) {
        // ignore bad fd error
        if (errno != EBADF) {
            ERROR("can not set FD_CLOEXEC on fd 3");
            clean_cg_exit(cg, 5);
        }
    }

    // spawn child
    pid_t pid = 0;

    int& clone_flags = config.arg.clone_flags;
    if (!config.enable_network) clone_flags |= CLONE_NEWNET;
    if (config.enable_pidns) clone_flags |= CLONE_NEWPID | CLONE_NEWIPC;

    pid = cg.spawn(config.arg);

    if (pid <= 0) {
        // error messages are printed before
        clean_cg_exit(cg, 10 - pid);
    }

    // prepare signal handlers and make lrun "higher priority"
    setup_signal_handlers();
    if (nice(-5) == -1) ERROR("can not renice");

    INFO("entering main loop, watching pid %d", (int)pid);

    // monitor its cpu_usage and real time usage and memory usage
    double start_time = now();
    double deadline = config.real_time_limit > 0 ? start_time + config.real_time_limit : -1;

    // child process stat (set by waitpid)
    int stat = 0;

    // which limit exceed
    string exceeded_limit = "";

    for (bool running = true; running;) {
        // check signal
        if (signal_triggered) {
            fprintf(stderr, "Receive signal %d, exiting...\n", signal_triggered);
            fflush(stderr);
            clean_cg_exit(cg, 4);
        }

        // check fs tracer thread
        if (fs_tracer_thread_id && pthread_kill(fs_tracer_thread_id, 0) != 0) {
            fprintf(stderr, "Filesystem tracer thread was killed, exiting...\n");
            fflush(stderr);
            clean_cg_exit(cg, 5);
        }

        // check stat
        int e = waitpid(pid, &stat, WNOHANG);

        if (e == pid) {
            // stat available
            if (WIFEXITED(stat) || WIFSIGNALED(stat)) {
                INFO("child exited");
                break;
            }
        } else if (e == -1) {
            // see what's wrong
            if (errno == ECHILD) {
                // strangely, this happens at the beginning (?)
                usleep(config.interval);
            }
        }

        // clean stat
        stat = 0;

        // check time limit exceed
        if (config.cpu_time_limit > 0 && cg.cpu_usage() >= config.cpu_time_limit) {
            exceeded_limit = "CPU_TIME";
            break;
        }

        // check realtime exceed
        if (deadline > 0 && now() >= deadline) {
            exceeded_limit = "REAL_TIME";
            break;
        }

        // check memory limit
        if (cg.memory_peak() >= config.memory_limit && config.memory_limit > 0) {
            exceeded_limit = "MEMORY";
            break;
        }

        // in case SIGCHILD is unreliable
        // check zombie manually here instead of waiting SIGCHILD
        if (get_process_state(pid) == 'Z') {
            INFO("child becomes zombie");
            running = false;
            // check waitpid again
            e = waitpid(pid, &stat, WNOHANG);
            if (e == -1) {
                // something goes wrong, give up
                clean_cg_exit(cg, 6);
            }
        }

        if (config.output_limit > 0) {
            cg.update_output_count();
            long long output_bytes = cg.output_usage();

            if (output_bytes > config.output_limit) {
                exceeded_limit = "OUTPUT";
                break;
            }

            PROGRESS_INFO("CPU %4.2f | REAL %4.1f | MEM %4.2f / %4.2fM | OUT %LdB",
            cg.cpu_usage(), now() - start_time, cg.memory_current() / 1.e6, cg.memory_peak() / 1.e6, output_bytes);
        } else {
            PROGRESS_INFO("CPU %4.2f | REAL %4.1f | MEM %4.2f / %4.2fM",
            cg.cpu_usage(), now() - start_time, cg.memory_current() / 1.e6, cg.memory_peak() / 1.e6);
        }

        // sleep for a while
        usleep(config.interval);
    }

    PROGRESS_INFO("\nOUT OF RUNNING LOOP\n");

    // collect stats
    long long memory_usage = cg.memory_peak();
    if (config.memory_limit > 0 && memory_usage >= config.memory_limit) {
        memory_usage = config.memory_limit;
        exceeded_limit = "MEMORY";
    }

    double cpu_time_usage = cg.cpu_usage();
    if ((WIFSIGNALED(stat) && WTERMSIG(stat) == SIGXCPU) || (config.cpu_time_limit > 0 && cpu_time_usage >= config.cpu_time_limit)) {
        cpu_time_usage = config.cpu_time_limit;
        exceeded_limit = "CPU_TIME";
    }

    if (WIFSIGNALED(stat) && WTERMSIG(stat) == SIGXFSZ) {
        exceeded_limit = "OUTPUT";
    }

    double real_time_usage = now() - start_time;
    if (config.real_time_limit > 0 && real_time_usage >= config.real_time_limit) {
        real_time_usage = config.real_time_limit;
        exceeded_limit = "REAL_TIME";
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
            exceeded_limit.empty() ? "none" : exceeded_limit.c_str());

    if (config.write_result_to_3) {
        int ret = write(3, status_report, strlen(status_report));
        (void)ret;

        // close output earlier (before clean_cg_exit)
        // so the process read the status can start to do other things.
        close(3);
    }

    return config.pass_exitcode ? WEXITSTATUS(stat) : EXIT_SUCCESS;
}

int main(int argc, char * argv[]) {
    if (argc <= 1) lrun::options::help();

    parse_cli_options(argc, argv);

    config.check();
    check_environment();  // we becomes root after this line

    INFO("lrun %s pid = %d", VERSION, (int)getpid());

    create_cgroup();
    create_fs_tracer();

    {
        Cgroup& cg = *config.active_cgroup;
        // lock the cgroup so other lrun process with same cgname will wait
        fs::ScopedFileLock cg_lock(cg.subsys_path().c_str());
        configure_cgroup();
        int ret = run_command();
        clean_cg_exit(cg, ret);
    }

    return 0;
}
