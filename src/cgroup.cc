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

#include "cgroup.h"
#include "fs.h"
#include "strconv.h"
#include <cstdio>
#include <cstring>
#include <mntent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <list>


using namespace lrun;

using std::string;
using std::list;

const char Cgroup::subsys_names[4][8] = {
    "cpuacct",
    "memory",
    "devices",
    "freezer",
};

std::string Cgroup::subsys_base_paths_[sizeof(subsys_names) / sizeof(subsys_names[0])];

int Cgroup::subsys_id_from_name(const char * const name) {
    for (size_t i = 0; i < sizeof(subsys_names) / sizeof(subsys_names[0]); ++i) {
        if (strcmp(name, subsys_names[i])) return i;
    }
    return -1;
}

string Cgroup::base_path(subsys_id_t subsys_id, bool create_on_need) {
    {
        // FIXME cache may not work when user manually umount cgroup
        // check last cached path
        const string& path = subsys_base_paths_[subsys_id];
        if ((!path.empty()) && fs::is_dir(path)) return path;
    }

    // enumerate mounts
    std::map<string, string> mounts;
    FILE *fp = setmntent(fs::MOUNTS_PATH, "r");
    if (!fp) {
        FATAL("can not read %s", fs::MOUNTS_PATH);
        return "";
    }

    // no cgroups mounted, prepare one
    const char * const MNT_SRC_NAME = "cgroup_lrun";
    const char * MNT_DEST_BASE_PATH = "/sys/fs/cgroup";
    const char * subsys_name = subsys_names[subsys_id];

    for (struct mntent *ent; (ent = getmntent(fp));) {
        mounts[string(ent->mnt_dir)] = string(ent->mnt_type);
        if (strcmp(ent->mnt_type, fs::TYPE_CGROUP)) continue;
        if (strstr(ent->mnt_opts, subsys_name)) {
            INFO("found cgroup %s path = '%s'", subsys_name, ent->mnt_dir);
            return (subsys_base_paths_[subsys_id] = string(ent->mnt_dir));
        }
    }

    if (!create_on_need) return "";

    if (!fs::is_dir(MNT_DEST_BASE_PATH)) {
        // no /sys/fs/cgroup in system, try conservative location
        MNT_DEST_BASE_PATH = "/cgroup";
        mkdir(MNT_DEST_BASE_PATH, 0700);
    }

    // prepare tmpfs on MNT_DEST_BASE_PATH
    int dest_base_mounted = 0;

    if (mounts.count(string(MNT_DEST_BASE_PATH)) == 0) {
        int e = mount(NULL, MNT_DEST_BASE_PATH, fs::TYPE_TMPFS, MS_NOEXEC | MS_NOSUID, "size=16384,mode=0755");
        if (e != 0) FATAL("can not mount tmpfs on '%s'", MNT_DEST_BASE_PATH);
        dest_base_mounted = 1;
    } else {
        INFO("'%s' is already mounted, skip mounting tmpfs", MNT_DEST_BASE_PATH);
    }

    // create and mount cgroup at dest_path
    string dest_path = string(MNT_DEST_BASE_PATH) + "/" + subsys_name;
    INFO("mkdir and mounting '%s'", dest_path.c_str());
    mkdir(dest_path.c_str(), 0700);
    int e = mount(MNT_SRC_NAME, dest_path.c_str(), fs::TYPE_CGROUP, MS_NOEXEC | MS_NOSUID | MS_RELATIME | MS_NODEV, subsys_name);

    if (e != 0) {
        int last_err = errno;
        // fallback, umount tmpfs if it is just mounted
        if (dest_base_mounted) umount(MNT_DEST_BASE_PATH);
        errno = last_err;
        FATAL("can not mount cgroup %s on '%s'", subsys_name, dest_path.c_str());
    }

    return (subsys_base_paths_[subsys_id] = dest_path);
}

string Cgroup::path_from_name(subsys_id_t subsys_id, const string& name) {
    return base_path(subsys_id) + "/" + name;
}

string Cgroup::subsys_path(Cgroup::subsys_id_t subsys_id) const {
    return path_from_name(subsys_id, name_);
}


int Cgroup::exists(const string& name) {
    for (int id = 0; id < SUBSYS_COUNT; ++id) {
        if (!fs::is_dir(path_from_name((subsys_id_t)(id), name))) return false;
    }
    return true;
}

Cgroup Cgroup::create(const string& name) {
    Cgroup cg;

    if (exists(name)) {
        INFO("create cgroup '%s': already exists", name.c_str());
        cg.name_ = name;
        return cg;
    }

    int success = 1;
    for (int id = 0; id < SUBSYS_COUNT; ++id) {
        string path = path_from_name((subsys_id_t)id, name);
        if (fs::is_dir(path)) continue;
        if (mkdir(path.c_str(), 0700)) {
            INFO("mkdir '%s': failed, %s", path.c_str(), strerror(errno));
            success = 0;
            break;
        } else {
            INFO("mkdir '%s': ok", path.c_str());
        }
    }

    if (success) cg.name_ = name;

    return cg;
}

Cgroup::Cgroup() { }

bool Cgroup::valid() const {
    return !name_.empty() && exists(name_);
}

void Cgroup::update_output_count() {
    if (!valid()) return;
    string procs_path = subsys_path(CG_FREEZER) + "/cgroup.procs";

    if (fs::read(procs_path, 4).empty()) return;

    FILE * procs = fopen(procs_path.c_str(), "r");
    char spid[sizeof(pid_t) * 4];
    while (fscanf(procs, "%s", spid) == 1) {
        long pid;
        long long bytes = 0;
        sscanf(spid, "%ld", &pid);
        FILE * io = fopen((string(fs::PROC_PATH) + "/" + spid + "/io").c_str(), "r");
        int res = 0;
        res = fscanf(io, "rchar: %*s\nwchar: %Ld", &bytes);
        (void)res;
        if (output_counter_[pid] < bytes) output_counter_[pid] = bytes;
        fclose(io);
    }
    fclose(procs);
}

long long Cgroup::output_usage() const {
    long long bytes = 0;
    FOR_EACH_CONST(p, output_counter_) {
        bytes += p.second;
    }
    return bytes;
}

__attribute__((unused)) static char get_process_state(pid_t pid) {
    FILE * fstatus = fopen((string(fs::PROC_PATH) + "/" + strconv::from_longlong(pid) + "/status").c_str(), "r");
    char state = 0;
    if (!fstatus) return 0;
    fscanf(fstatus, "%*[^\n] State: %c", &state);
    fclose(fstatus);
    return state;
}

list<pid_t> Cgroup::get_pids() {
    string procs_path = subsys_path(CG_FREEZER) + "/cgroup.procs";
    FILE * procs = fopen(procs_path.c_str(), "r");
    list<pid_t> pids;

    if (procs) {
        long pid;
        while (fscanf(procs, "%ld", &pid) == 1) pids.push_back((pid_t)pid);
        fclose(procs);
    }
    return pids;
}

static const int FREEZE_INCREASE_MEM_LIMIT_STEP = 8192;  // 8 K
static const useconds_t FREEZE_KILL_WAIT_INTERVAL = 10000;  // 10 ms
static const int FREEZE_ATTEMPTS_BEFORE_ENABLE_OOM = 16;

void Cgroup::freeze(int freeze) {
    if (!valid()) return;
    string freeze_state_path = subsys_path(CG_FREEZER) + "/freezer.state";

    if (!freeze) {
        INFO("unfreeze");
        fs::write(freeze_state_path, "THAWED\n");
        return;
    } else {
        INFO("freezing");
        fs::write(freeze_state_path, "FROZEN\n");

        for (int loop = 0, mem_limit_inc = 0;; ++loop) {
            int frozen = (strncmp(fs::read(freeze_state_path, 4).c_str(), "FRO", 3) == 0);
            if (frozen) break;

            if (mem_limit_inc < FREEZE_ATTEMPTS_BEFORE_ENABLE_OOM && mem_limit_inc >= 0) {
                INFO("increase memory limit by %d to \"help\" freezer", FREEZE_INCREASE_MEM_LIMIT_STEP);
                set_memory_limit(memory_peak() + FREEZE_INCREASE_MEM_LIMIT_STEP);
                ++mem_limit_inc;
            } else if (mem_limit_inc >= 0)  {
                INFO("enable OOM killer");
                set_memory_limit(1);
                if (set(CG_MEMORY, "memory.oom_control", "0\n") == 0) mem_limit_inc = -1;
            }

            usleep(FREEZE_KILL_WAIT_INTERVAL);
        }
        INFO("confirmed frozen");
    }
}

int Cgroup::empty() {
    string procs_path = subsys_path(CG_FREEZER) + "/cgroup.procs";
    return fs::read(procs_path, 4).empty() ? 1 : 0;
}

void Cgroup::killall() {

    // return immediately if cgroup is not valid
    if (!valid()) return;

    // kill all processes
    string procs_path = subsys_path(CG_FREEZER) + "/cgroup.procs";

    // check procs_path first, return if empty
    if (fs::read(procs_path, 4).empty()) return;

    freeze(1);
    list<pid_t> pids = get_pids();
    FOR_EACH(p, pids) kill(p, SIGKILL);
    INFO("sent SIGKILLs");

    // give processes sometime to disappear
    freeze(0);
    for (int clear = 0; clear == 0;) {
        if (fs::read(procs_path, 4).empty()) break;
        usleep(FREEZE_KILL_WAIT_INTERVAL);
    }
    INFO("confirmed processes are killed");

    return;
}

int Cgroup::destroy() {
    killall();

    int ret = 0;
    for (int id = 0; id < SUBSYS_COUNT; ++id) {
        string path = subsys_path((subsys_id_t)id);
        if (path.empty()) continue;
        if (fs::is_dir(path)) ret |= rmdir(path.c_str());
    }

    return ret;
}

int Cgroup::set(subsys_id_t subsys_id, const string& property, const string& value) {
    return fs::write(subsys_path(subsys_id) + "/" + property, value);
}

string Cgroup::get(subsys_id_t subsys_id, const string& property, size_t max_length) const {
    return fs::read(subsys_path(subsys_id) + "/" + property, max_length);
}

int Cgroup::inherit(subsys_id_t subsys_id, const string& property) {
    string value = fs::read(base_path(subsys_id, false) + "/" + property);
    return fs::write(subsys_path(subsys_id) + "/" + property, value);
}

int Cgroup::attach(pid_t pid) {
    char pidbuf[32];
    snprintf(pidbuf, sizeof(pidbuf), "%ld\n", (long)pid);

    int ret = 0;
    for (int id = 0; id < SUBSYS_COUNT; ++id) {
        string path = subsys_path((subsys_id_t)id);
        ret |= fs::write(path + "/tasks", pidbuf);
    }

    return ret;
}

int Cgroup::limit_devices() {
    int e = 0;
    e += set(CG_DEVICES, "devices.deny", "a");
    e += set(CG_DEVICES, "devices.allow", "c 1:3 rwm"); // null
    e += set(CG_DEVICES, "devices.allow", "c 1:5 rwm"); // zero
    e += set(CG_DEVICES, "devices.allow", "c 1:7 rwm"); // full
    e += set(CG_DEVICES, "devices.allow", "c 1:8 rwm"); // random
    e += set(CG_DEVICES, "devices.allow", "c 1:9 rwm"); // urandom
    return e ? -1 : 0;
}

int Cgroup::reset_usages() {
    int e = 0;
    e += set(CG_CPUACCT, "cpuacct.usage", "0");
    e += set(CG_MEMORY, "memory.max_usage_in_bytes", "0") * set(CG_MEMORY, "memory.memsw.max_usage_in_bytes", "0");
    output_counter_.clear();
    return e ? -1 : 0;
}

double Cgroup::cpu_usage() const {
    string cpu_usage = get(CG_CPUACCT, "cpuacct.usage", 31);
    // convert from nanoseconds to seconds
    return strconv::to_double(cpu_usage) / 1e9;
}

long long Cgroup::memory_current() const {
    string usage = get(CG_MEMORY, "memory.memsw.usage_in_bytes");
    if (usage.empty()) usage = get(CG_MEMORY, "memory.usage_in_bytes");
    return strconv::to_longlong(usage);
}

long long Cgroup::memory_peak() const {
    string usage = get(CG_MEMORY, "memory.memsw.max_usage_in_bytes");
    if (usage.empty()) usage = get(CG_MEMORY, "memory.max_usage_in_bytes");
    return strconv::to_longlong(usage);
}

long long Cgroup::memory_limit() const {
    string limit = get(CG_MEMORY, "memory.memsw.limit_in_bytes");
    if (limit.empty()) limit = get(CG_MEMORY, "memory.limit_in_bytes");
    return strconv::to_longlong(limit);
}

int Cgroup::set_memory_limit(long long bytes) {
    int e = 1;

    if (bytes <= 0) {
        // read base (parent) cgroup properties
        e *= inherit(CG_MEMORY, "memory.limit_in_bytes");
        e *= inherit(CG_MEMORY, "memory.memsw.limit_in_bytes");
    } else {
        e *= set(CG_MEMORY, "memory.limit_in_bytes", strconv::from_longlong(bytes));
        e *= set(CG_MEMORY, "memory.memsw.limit_in_bytes", strconv::from_longlong(bytes));
    }

    return e ? -1 : 0;
}

// following functions are called by clone_fn

__attribute__((unused)) static void do_set_sysctl() {
    INFO("set sysctl settings");
    // skip slow oom scaning and do not write syslog
    fs::write("/proc/sys/vm/oom_kill_allocating_task", "1\n");
    fs::write("/proc/sys/vm/oom_dump_tasks", "0\n");
    // block dmesg access
    fs::write("/proc/sys/kernel/dmesg_restrict", "1\n");
}

static void do_privatize_filesystem(const Cgroup::spawn_arg& arg) {
    // make sure filesystem not be shared
    // ignore this step for old systems without these features
    int type = MS_PRIVATE | MS_REC;
    if (type && fs::mount_set_shared("/", MS_PRIVATE | MS_REC)) {
        FATAL("can not mount --make-rprivate /");
    }
}

static void do_mount_bindfs(const Cgroup::spawn_arg& arg) {
    // bind fs mounts
    FOR_EACH(p, arg.bindfs_list) {
        const string& dest = p.first;
        const string& src = p.second;

        INFO("mount bind %s -> %s", src.c_str(), dest.c_str());
        if (fs::mount_bind(src, dest)) {
            FATAL("mount bind '%s' -> '%s' failed", src.c_str(), dest.c_str());
        }
    }
}

static void do_chroot(const Cgroup::spawn_arg& arg) {
    // chroot to a prepared place
    if (!arg.chroot_path.empty()) {
        const string& path = arg.chroot_path;

        INFO("chroot %s", path.c_str());
        if (chroot(path.c_str())) {
            FATAL("chroot '%s' failed", path.c_str());
        }
    }
}

static void do_mount_proc(const Cgroup::spawn_arg& arg) {
    // mount /proc if pid namespace is enabled
    if ((arg.clone_flags & CLONE_NEWPID) && fs::is_dir("/proc")) {
        INFO("mount /proc");
        if (mount(NULL, "/proc", "proc", MS_NOEXEC | MS_NOSUID, NULL)) {
            FATAL("mount procfs failed");
        }
        // hide sensitive directories
        mount(NULL, "/proc/sys", "tmpfs", MS_NOSUID | MS_RDONLY, "size=0");
    }
}

static void do_close_high_fds(const Cgroup::spawn_arg& arg) {
    // close fds other than 0,1,2 and sockets[0]
    INFO("close high fds");
    close(arg.sockets[1]);
    struct dirent **namelist = 0;
    int nlist = scandir("/proc/self/fd", &namelist, 0, alphasort);
    for (int i = 0; i < nlist; ++i) {
        const char * name = namelist[i]->d_name;
        // skip . and ..
        if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            int fd;
            if (sscanf(name, "%d", &fd) == 1 && fd > 2 && fd != arg.sockets[0] && arg.keep_fds.count(fd) == 0) {
                close(fd);
            }
        }
        free(namelist[i]);
    }
    if (namelist) free(namelist);
}

static void do_mount_tmpfs(const Cgroup::spawn_arg& arg) {
    // setup other tmpfs mounts
    FOR_EACH(p, arg.tmpfs_list) {
        const char * dest = p.first.c_str();
        const long long& size = p.second;

        INFO("mount tmpfs %s (size = %lld)", dest, size);

        int e = 0;
        if (size <= 0) {
            // treat as read-only
            e = mount(NULL, dest, "tmpfs", MS_NOSUID | MS_RDONLY, "size=0");
        } else {
            e = mount(NULL, dest, "tmpfs", MS_NOSUID, ((string)("mode=0777,size=" + strconv::from_longlong(size))).c_str());
        }
        if (e) {
            FATAL("mount tmpfs '%s' failed", dest);
        }
    }
}

static void do_chdir(const Cgroup::spawn_arg& arg) {
    // chdir to a specified path
    if (!arg.chdir_path.empty()) {
        const string& path = arg.chdir_path;

        INFO("chdir %s", path.c_str());
        if (chdir(path.c_str())) {
            FATAL("chdir '%s' failed", path.c_str());
        }
    }
}

static void do_commands(const Cgroup::spawn_arg& arg) {
    // system commands
    FOR_EACH(cmd, arg.cmd_list) {
        INFO("system %s", cmd.c_str());
        int ret = system(cmd.c_str());
        if (ret) WARNING("system \"%s\" returns %d", cmd.c_str(), ret);
    }
}

static void do_renice(const Cgroup::spawn_arg& arg) {
    // nice
    if (arg.nice) {
        INFO("nice %d", (int)arg.nice);
        if (nice(arg.nice) == -1) {
            WARNING("can not set nice to %d", arg.nice);
        }
    }
}

static void do_set_umask(const Cgroup::spawn_arg& arg) {
    // set umask
    INFO("umask %d", arg.umask);
    umask(arg.umask);
}

static void do_set_uid_gid(const Cgroup::spawn_arg& arg) {
    // setup uid, gid
    INFO("setgid %d, setuid %d", (int)arg.gid, (int)arg.uid);
    if (setgid(arg.gid) || setuid(arg.uid)) {
        FATAL("setgid(%d) or setuid(%d) failed", (int)arg.gid, (int)arg.uid);
    }
}

static void do_apply_rlimits(const Cgroup::spawn_arg& arg) {
    // apply rlimit, note NPROC limit should be applied after setuid
    FOR_EACH(p, arg.rlimits) {
        int resource = p.first;
        if (resource >= RLIMIT_NLIMITS) continue;

        rlimit limit;
        limit.rlim_cur = limit.rlim_max = p.second;

        // wish to receive SIGXCPU or SIGXFSZ to know it is TLE or OLE.
        // NOTE: if pid namespace is used (--isolate-process true), pid 1
        // in the new pid ns is immune to signals (including SIGKILL) by
        // default! This means that rlimit won't work for it. Therefore,
        // a dummy init process is created if possible.
        if (resource == RLIMIT_CPU || resource == RLIMIT_FSIZE) ++limit.rlim_max;

        DEBUG_DO {
            char limit_name[16];
            switch (resource) {
#define CONVERT_NAME(x) case x: strncpy(limit_name, # x, sizeof(limit_name)); break;
                CONVERT_NAME(RLIMIT_CPU);
                CONVERT_NAME(RLIMIT_FSIZE);
                CONVERT_NAME(RLIMIT_DATA);
                CONVERT_NAME(RLIMIT_STACK);
                CONVERT_NAME(RLIMIT_CORE);
                CONVERT_NAME(RLIMIT_RSS);
                CONVERT_NAME(RLIMIT_NOFILE);
                CONVERT_NAME(RLIMIT_AS);
                CONVERT_NAME(RLIMIT_NPROC);
                CONVERT_NAME(RLIMIT_MEMLOCK);
                CONVERT_NAME(RLIMIT_LOCKS);
                CONVERT_NAME(RLIMIT_SIGPENDING);
                CONVERT_NAME(RLIMIT_MSGQUEUE);
                CONVERT_NAME(RLIMIT_NICE);
                CONVERT_NAME(RLIMIT_RTPRIO);
                CONVERT_NAME(RLIMIT_RTTIME);
#undef CONVERT_NAME
                default:
                    snprintf(limit_name, sizeof(limit_name), "0x%x", resource);
            }
            rlimit current;
            getrlimit(resource, &current);
            INFO("setrlimit %s, cur: %d => %d, max: %d => %d", limit_name,
                 (int)current.rlim_cur, (int)limit.rlim_cur,
                 (int)current.rlim_max, (int)limit.rlim_max);
        }

        if (setrlimit(resource, &limit)) {
            WARNING("can not set rlimit %d", resource);
        }
    }
}

static void do_set_env(const Cgroup::spawn_arg& arg) {
    // prepare env
    if (arg.reset_env) {
        INFO("reset ENV");
        if (clearenv()) FATAL("can not clear env");
    }

    FOR_EACH(p, arg.env_list) {
        const char * name = p.first.c_str();
        const char * value = p.second.c_str();

        if (setenv(name, value, 1)) FATAL("can not set env %s=%s", name, value);
    }
}

static void do_seccomp(const Cgroup::spawn_arg& arg) {
    // syscall whitelist
    if (seccomp::supported() && seccomp::apply_simple_filter(arg.syscall_list.c_str(), arg.syscall_action)) {
        FATAL("seccomp failed");
        exit(-1);
    }
}

static int clone_fn(void * clone_arg) {

    // this is executed in child process after clone
    // fs and uid settings should be done here
    Cgroup::spawn_arg& arg = *(Cgroup::spawn_arg*)clone_arg;

#ifdef SYSCTL_PER_NS_WORKS
    // NOTE: Do not uncomment this until sysctl per namespace works.
    // till 2014-10-09, setting vm.oom_kill_allocating_task, etc.
    // still affect outer sysctl on Linux 3.16.3
    do_set_sysctl();
#endif
    do_close_high_fds(arg);
    do_privatize_filesystem(arg);
    do_mount_bindfs(arg);
    do_chroot(arg);
    do_mount_proc(arg);
    do_mount_tmpfs(arg);
    do_chdir(arg);
    do_commands(arg);
    do_set_umask(arg);
    do_set_uid_gid(arg);
    do_apply_rlimits(arg);
    do_set_env(arg);
    do_renice(arg);

    // all prepared! blocking, wait for parent
    INFO("waiting for parent");
    char buf[4];
    int ret = read(arg.sockets[0], buf, sizeof buf);
    (void)ret;

    // let parent know we got the message, parent then can close fd without SIGPIPE child
    INFO("got from parent: '%3s'. notify parent", buf);
    strcpy(buf, "PRE");
    ret = write(arg.sockets[0], buf, sizeof buf);
    (void)ret;

    // not closing sockets[0] here, it will closed on exec
    // if exec fails, it will be closed upon process exit (aka. this function returns)
    if (fcntl(arg.sockets[0], F_SETFD, FD_CLOEXEC)) {
        FATAL("fcntl failed");
        return -1;
    }

    do_seccomp(arg);

    // exec target
    INFO("execvp %s ...", arg.args[0]);

    execvp(arg.args[0], arg.args);

    // exec failed, output to stderr
    ERROR("exec '%s' failed", arg.args[0]);

    // notify parent that exec failed
    strcpy(buf, "ERR");
    ret = write(arg.sockets[0], buf, sizeof buf);
    (void)ret;

    // wait parent
    ret = read(arg.sockets[0], buf, sizeof buf);
    (void)ret;

    return -1;
} // clone_fn

static string clone_flags_to_str(int clone_flags) {
    int v = clone_flags;
    string s;
#define TEST_FLAG(x) if ((v & x) != 0) { s += string(# x) + " | "; v ^= x; }
    TEST_FLAG(CLONE_VM);
    TEST_FLAG(CLONE_FS);
    TEST_FLAG(CLONE_FILES);
    TEST_FLAG(CLONE_SIGHAND);
    TEST_FLAG(CLONE_PTRACE);
    TEST_FLAG(CLONE_VFORK);
    TEST_FLAG(CLONE_PARENT);
    TEST_FLAG(CLONE_THREAD);
    TEST_FLAG(CLONE_NEWNS);
    TEST_FLAG(CLONE_SYSVSEM);
    TEST_FLAG(CLONE_SETTLS);
    TEST_FLAG(CLONE_PARENT_SETTID);
    TEST_FLAG(CLONE_CHILD_CLEARTID);
    TEST_FLAG(CLONE_DETACHED);
    TEST_FLAG(CLONE_UNTRACED);
    TEST_FLAG(CLONE_CHILD_SETTID);
    TEST_FLAG(CLONE_NEWUTS);
    TEST_FLAG(CLONE_NEWIPC);
    TEST_FLAG(CLONE_NEWUSER);
    TEST_FLAG(CLONE_NEWPID);
    TEST_FLAG(CLONE_NEWNET);
    TEST_FLAG(CLONE_IO);
    TEST_FLAG(SIGCHLD);

    TEST_FLAG(SIGINT);
    TEST_FLAG(SIGQUIT);
    TEST_FLAG(SIGILL);
    TEST_FLAG(SIGTRAP);
    TEST_FLAG(SIGABRT);
    TEST_FLAG(SIGIOT);
    TEST_FLAG(SIGBUS);
    TEST_FLAG(SIGFPE);
    TEST_FLAG(SIGKILL);
    TEST_FLAG(SIGUSR1);
    TEST_FLAG(SIGSEGV);
    TEST_FLAG(SIGUSR2);
    TEST_FLAG(SIGPIPE);
    TEST_FLAG(SIGALRM);
    TEST_FLAG(SIGTERM);
    TEST_FLAG(SIGSTKFLT);
    TEST_FLAG(SIGCLD);
    TEST_FLAG(SIGCHLD);
    TEST_FLAG(SIGCONT);
    TEST_FLAG(SIGSTOP);
    TEST_FLAG(SIGTSTP);
    TEST_FLAG(SIGTTIN);
    TEST_FLAG(SIGTTOU);
    TEST_FLAG(SIGURG);
    TEST_FLAG(SIGXCPU);
    TEST_FLAG(SIGXFSZ);
    TEST_FLAG(SIGVTALRM);
    TEST_FLAG(SIGPROF);
    TEST_FLAG(SIGWINCH);
    TEST_FLAG(SIGPOLL);
    TEST_FLAG(SIGIO);
    TEST_FLAG(SIGPWR);
    TEST_FLAG(SIGSYS);
    TEST_FLAG(SIGUNUSED);
#undef TEST_FLAG
    if (v) {
        s += strconv::from_long((long)v);
    } else {
        s = s.substr(0, s.length() - 3);
    }
    return s;
}

pid_t Cgroup::spawn(spawn_arg& arg) {
    // uid and gid should > 0
    if (arg.uid <= 0 || arg.gid <= 0) {
        WARNING("uid and gid can not <= 0. spawn rejected");
        return -2;
    }

    // do sync use socket pair
    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, arg.sockets)) {
        ERROR("socketpair failed");
        return -1;
    }

    // sockets fds should expire when exec
    fcntl(arg.sockets[0], F_SETFD, FD_CLOEXEC);
    fcntl(arg.sockets[1], F_SETFD, FD_CLOEXEC);

    // We need root permissions and drop root later, no CLONE_NEWUSER here
    // CLONE_NEWNS is required for private mounts
    // CLONE_NEWUSER is not used because new uid 0 may be non-root
    int clone_flags = CLONE_NEWNS | SIGCHLD | arg.clone_flags;

    long stack_size = sysconf(_SC_PAGESIZE);
    void * stack = (void*)((char*)alloca(stack_size) + stack_size);
    char buf[] = "RUN";

    DEBUG_DO {
        INFO("clone flags = 0x%x = %s", (int)clone_flags, clone_flags_to_str(clone_flags).c_str());
    }

    pid_t child_pid;
    child_pid = clone(clone_fn, stack, clone_flags, &arg);

    if (child_pid < 0) {
        FATAL("clone failed");
        goto cleanup;
    }

    INFO("child pid = %d", (int)child_pid);

    // attach child to current cgroup
    INFO("attach %d", (int)child_pid);
    attach(child_pid);

    // child is blocking, waiting us before exec, let it go
    close(arg.sockets[0]);
    send(arg.sockets[1], buf, sizeof buf, MSG_NOSIGNAL);

    // wait for child response
    INFO("reading from child");

    int ret;
    ret = read(arg.sockets[1], buf, sizeof buf);
    (void)ret;

    INFO("from child, got '%3s'", buf);
    if (buf[0] != 'P') {
        // child has problem to start
        child_pid = -3;
        goto cleanup;
    }

    // child exec may fail, confirm
    if (read(arg.sockets[1], buf, sizeof buf) > 0 && buf[0] == 'E') {
        INFO("seems child exec failed");
        child_pid = -4;
    } else {
        // disable oom killer now
        // oom killer writes a super long log, disable it
        // Note: a process can enter D (uninterruptable sleep) status
        // when oom killer disabled, killing it requires re-enable oom killer
        // or enlarge memory limit
        if (set(CG_MEMORY, "memory.oom_control", "1\n")) INFO("can not set memory.oom_control");
    }

cleanup:
    close(arg.sockets[1]);
    return child_pid;
}

