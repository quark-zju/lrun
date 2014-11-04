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
#include <list>
#include <dirent.h>
#include <fcntl.h>
#include <mntent.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


using namespace lrun;

using std::string;
using std::list;

const char Cgroup::subsys_names[4][8] = {
    "cpuacct",
    "memory",
    "devices",
    "freezer",
};

static struct {
    const char *name;
    unsigned int minor;
    // major is missing because all basic_devices have major = 1
} basic_devices[] = {
    {"null", 3},
    {"zero", 5},
    {"full", 7},
    {"random", 8},
    {"urandom", 9},
};

std::string Cgroup::subsys_base_paths_[sizeof(subsys_names) / sizeof(subsys_names[0])];

int Cgroup::subsys_id_from_name(const char * const name) {
    for (size_t i = 0; i < sizeof(Cgroup::subsys_names) / sizeof(Cgroup::subsys_names[0]); ++i) {
        if (strcmp(name, subsys_names[i])) return i;
    }
    return -1;
}

typedef struct {
    string type;
    string opts;
    string fsname;
    string dir;
} mount_entrie;

static std::map<string, mount_entrie> get_mounts() {
    std::map<string, mount_entrie> result;
    FILE *fp = setmntent(fs::MOUNTS_PATH, "r");
    if (!fp) {
        FATAL("can not read %s", fs::MOUNTS_PATH);
        return result;
    }
    for (struct mntent *ent; (ent = getmntent(fp));) {
        result[string(ent->mnt_dir)] = {
            /* .type = */ ent->mnt_type,
            /* .opts = */ ent->mnt_opts,
            /* .fsname = */ ent->mnt_fsname,
            /* .dir = */ ent->mnt_dir
        };
    }
    endmntent(fp);
    return result;
}

string Cgroup::base_path(subsys_id_t subsys_id, bool create_on_need) {
    {
        // FIXME cache may not work when user manually umount cgroup
        // check last cached path
        const string& path = subsys_base_paths_[subsys_id];
        if ((!path.empty()) && fs::is_dir(path)) return path;
    }

    const char * const MNT_SRC_NAME = "cgroup_lrun";
    const char * MNT_DEST_BASE_PATH = "/sys/fs/cgroup";
    const char * subsys_name = subsys_names[subsys_id];

    std::map<string, mount_entrie> mounts = get_mounts();
    FOR_EACH_CONST(p, mounts) {
        const mount_entrie& ent = p.second;
        if (ent.type != string(fs::TYPE_CGROUP)) continue;
        if (strstr(ent.opts.c_str(), subsys_name)) {
            INFO("cgroup %s path = '%s'", subsys_name, ent.dir.c_str());
            return (subsys_base_paths_[subsys_id] = string(ent.dir));
        }
    }

    // no cgroups mounted, prepare one
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
            ERROR("mkdir '%s': failed", path.c_str());
            success = 0;
            break;
        }
    }

    if (success) cg.name_ = name;
    cg.init_pid_ = 0;

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
    char spid[26]; // sizeof(pid_t) * 3 + 2, assuming sizeof(pid_t) is 8
    while (fscanf(procs, "%25s", spid) == 1) {
        unsigned long pid;
        unsigned long long bytes = 0;
        if (sscanf(spid, "%lu", &pid) == 0) continue;
        FILE * io = fopen((string(fs::PROC_PATH) + "/" + spid + "/io").c_str(), "r");
        if (!io) continue;
        int res = 0;
        res = fscanf(io, "rchar: %*s\nwchar: %Ld", &bytes);
        if (res == 1) {
            if (output_counter_[pid] < bytes) output_counter_[pid] = bytes;
        }
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

list<pid_t> Cgroup::get_pids() {
    string procs_path = subsys_path(CG_FREEZER) + "/cgroup.procs";
    FILE * procs = fopen(procs_path.c_str(), "r");
    list<pid_t> pids;

    if (procs) {
        unsigned long pid;
        while (fscanf(procs, "%lu", &pid) == 1) pids.push_back((pid_t)pid);
        fclose(procs);
    }
    return pids;
}

static const int FREEZE_INCREASE_MEM_LIMIT_STEP = 8192;  // 8 K
static const useconds_t FREEZE_KILL_WAIT_INTERVAL = 10000;  // 10 ms
static const int FREEZE_ATTEMPTS_BEFORE_ENABLE_OOM = 12;

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

        for (int loop = 0, attempt = 0;; ++loop) {
            int frozen = (strncmp(fs::read(freeze_state_path, 4).c_str(), "FRO", 3) == 0);
            if (frozen) break;

            if (attempt < FREEZE_ATTEMPTS_BEFORE_ENABLE_OOM && attempt >= 0) {
                INFO("increase memory limit by %d to \"help\" freezer", FREEZE_INCREASE_MEM_LIMIT_STEP);
                set_memory_limit(memory_peak() + FREEZE_INCREASE_MEM_LIMIT_STEP);
                ++attempt;
            } else if (attempt >= 0)  {
                INFO("enabling OOM killer");
                if (set(CG_MEMORY, "memory.oom_control", "0\n") == 0) attempt = -1;
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

    // check procs_path first, return if empty
    if (empty()) return;

    if (init_pid_) {
        // if init pid exists, just kill it and the kernel will kill all
        // remaining processes in the same pid ns.
        // because our init process (clone_init_fn) won't allocate memory,
        // it will not enter D state and is safe to kill.
        kill(init_pid_, SIGKILL);
        // cancel memory limit. this will wake up some D state processes,
        // which are allocating memory and reached memory limit.
        set_memory_limit(-1);
        INFO("sent SIGKILL to init process %lu", (unsigned long)init_pid_);
        init_pid_ = 0;
    } else {
        freeze(1);
        list<pid_t> pids = get_pids();
        FOR_EACH(p, pids) kill(p, SIGKILL);
        INFO("sent SIGKILLs to %lu processes", (unsigned long)pids.size());
        freeze(0);
    }

    // wait and verify that processes are gone
    for (int clear = 0; clear == 0;) {
        if (empty()) break;
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
    snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long)pid);

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
    for (size_t i = 0; i < sizeof(basic_devices) / sizeof(basic_devices[0]); ++i) {
        long minor = basic_devices[i].minor;
        string v = string("c 1:" + strconv::from_long(minor) + " rwm");
        e += set(CG_DEVICES, "devices.allow", v);
    }
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

// following functions are called by clone_main_fn

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

static void do_remounts(const Cgroup::spawn_arg& arg) {
    FOR_EACH(p, arg.remount_list) {
        const string& dest = p.first;
        unsigned long flags = p.second;
        // tricky point: if the original mount point has --bind, remount with --bind
        // can make it less likely to get "device busy" message
        if (arg.bindfs_dest_set.count(dest)) flags |= MS_BIND;

        INFO("remount %s", dest.c_str());
        for (;;) {
            if (fs::remount(dest, flags) == 0) break;
            if (flags & MS_BIND) FATAL("remount '%s' failed", dest.c_str());
            flags |= MS_BIND;
        }
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

static void do_umount_outside_chroot(const Cgroup::spawn_arg& arg) {
    if (!arg.umount_outside) return;
    if (arg.chroot_path.empty()) return;

    std::map<string, mount_entrie> mounts = get_mounts();
    list<string> umount_list;
    FOR_EACH(p, mounts) {
        const string& dest = p.second.dir;
        if (arg.chroot_path.substr(0, dest.length()) == dest) continue;
        if (dest.substr(0, arg.chroot_path.length()) == arg.chroot_path) continue;
        umount_list.push_front(dest);
    }

    // umount in reversed order
    FOR_EACH(dest, umount_list) {
        INFO("umount %s", dest.c_str());
        if (umount2(dest.c_str(), MNT_DETACH) == -1) {
            WARNING("cannot umount %s", dest.c_str());
        }
    }
}

static bool should_mount_proc(const Cgroup::spawn_arg& arg) {
    if (!fs::is_accessible(fs::join(arg.chroot_path, fs::PROC_PATH), F_OK | X_OK)) return false;
    return (arg.clone_flags & CLONE_NEWPID) != 0 || !arg.chroot_path.empty();
}

static bool should_hide_sensitive(const Cgroup::spawn_arg& arg) {
    if (!should_mount_proc(arg)) return false;

    // currently there is no option about this behavior
    // assume that --no-new-privs false users do not like this
    if (!arg.no_new_privs) return false;
    if (getenv("LRUN_DO_NOT_HIDE_SENSITIVE")) return false;
    return true;
}

static void do_mount_proc(const Cgroup::spawn_arg& arg) {
    // mount /proc if pid namespace is enabled
    if (!should_mount_proc(arg)) return;
    string dest = fs::join(arg.chroot_path, fs::PROC_PATH);
    INFO("mount procfs at %s", dest.c_str());
    if (mount(NULL, dest.c_str(), "proc", MS_NOEXEC | MS_NOSUID, NULL)) {
        FATAL("mount procfs failed");
    }
}

static void do_hide_sensitive(const Cgroup::spawn_arg& arg) {
    if (!should_hide_sensitive(arg)) return;
    if ((arg.clone_flags & CLONE_NEWPID) && getpid() != 1) {
        mount(NULL, fs::join(arg.chroot_path, "/proc/1").c_str(), "tmpfs", MS_NOSUID | MS_RDONLY, "size=0");
    }
    mount(NULL, fs::join(arg.chroot_path, "/proc/sys").c_str(), "tmpfs", MS_NOSUID | MS_RDONLY, "size=0");
}

static list<int> get_fds() {
    list<int> fds;

    struct dirent **namelist = 0;
    int nlist = scandir("/proc/self/fd", &namelist, 0, alphasort);
    for (int i = 0; i < nlist; ++i) {
        const char * name = namelist[i]->d_name;
        // skip . and ..
        if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            int fd;
            if (sscanf(name, "%d", &fd) != 1) continue;
            fds.push_back(fd);
        }
        free(namelist[i]);
    }
    if (namelist) free(namelist);

    return fds;
}

static void do_set_uts(const Cgroup::spawn_arg& arg) {
    int e;
    if (!arg.uts.domainname.empty()) {
        INFO("setdomainname: %s", arg.uts.domainname.c_str());
        e = setdomainname(arg.uts.domainname.c_str(), arg.uts.domainname.length());
        if (e == -1) {
            FATAL("setdomainname '%s' failed", arg.uts.domainname.c_str());
            exit(-1);
        }
    }
    if (!arg.uts.nodename.empty()) {
        INFO("sethostname: %s", arg.uts.nodename.c_str());
        e = sethostname(arg.uts.nodename.c_str(), arg.uts.nodename.length());
        if (e == -1) {
            FATAL("sethostname '%s' failed", arg.uts.nodename.c_str());
            exit(-1);
        }
    }

    // [[[cog
    //  import cog
    //  opts = {'release': 'osrelease', 'sysname': 'ostype', 'version': 'version'}
    //  for opt, name in opts.items():
    //    cog.out('''
    //      if (!arg.uts.%(opt)s.empty() && fs::is_accessible("/proc/sys/utsmod/%(name)s"), W_OK) {
    //          fs::write("/proc/sys/utsmod/%(name)s", arg.uts.%(opt)s);
    //      }''' % {'name': name, 'opt': opt}, trimblanklines=True)
    // ]]]
    if (!arg.uts.release.empty() && fs::is_accessible("/proc/sys/utsmod/osrelease"), W_OK) {
        fs::write("/proc/sys/utsmod/osrelease", arg.uts.release);
    }
    if (!arg.uts.sysname.empty() && fs::is_accessible("/proc/sys/utsmod/ostype"), W_OK) {
        fs::write("/proc/sys/utsmod/ostype", arg.uts.sysname);
    }
    if (!arg.uts.version.empty() && fs::is_accessible("/proc/sys/utsmod/version"), W_OK) {
        fs::write("/proc/sys/utsmod/version", arg.uts.version);
    }
    // [[[end]]]
}

static void do_close_high_fds(const Cgroup::spawn_arg& arg) {
    // close fds other than 0,1,2 and sockets[0]
    INFO("close high fds");
    close(arg.sockets[1]);
    list<int> fds = get_fds();
    FOR_EACH(fd, fds) {
        if (fd != STDERR_FILENO && fd != STDIN_FILENO && fd != STDOUT_FILENO && fd != arg.sockets[0] && arg.keep_fds.count(fd) == 0) {
            close(fd);
        }
    }
}

static void do_mount_tmpfs(const Cgroup::spawn_arg& arg) {
    // setup other tmpfs mounts
    FOR_EACH(p, arg.tmpfs_list) {
        const char * dest = p.first.c_str();
        const long long& size = p.second;

        INFO("mount tmpfs %s (size = %lld kB)", dest, size);

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

static void do_remount_dev(const Cgroup::spawn_arg& arg) {
    if (!arg.remount_dev) return;

    INFO("remount /dev");

    int e;
    // mount a minimal tmpfs to /dev
    e = mount(NULL, "/dev", "tmpfs", MS_NOSUID, "size=64,mode=0755,uid=0,gid=0");
    if (e) FATAL("remount /dev failed");

    // create basic devices
    for (size_t i = 0; i < sizeof(basic_devices) / sizeof(basic_devices[0]); ++i) {
        string path = string("/dev/") + basic_devices[i].name;
        unsigned int minor = basic_devices[i].minor;
        e = mknod(path.c_str(), S_IFCHR | 0666 /* mode */, makedev(1 /* major */, minor));
        if (!e) e = chmod(path.c_str(), 0666);
        if (e) FATAL("failed to create dev: '%s'", path.c_str());
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
        // an interesting story about not checking setuid return value:
        // https://sites.google.com/site/fullycapable/Home/thesendmailcapabilitiesissue
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
    if (seccomp::supported() && arg.syscall_list.length() > 0) {
        // apply seccomp, it will set PR_SET_NO_NEW_PRIVS
        // libseccomp actually has an option to skip setting PR_SET_NO_NEW_PRIVS to 1
        // however it makes seccomp_load error with EPERM because we just used setuid()
        // and PR_SET_SECCOMP needs root if PR_SET_NO_NEW_PRIVS is unset.
        INFO("applying syscall filters");
        seccomp::Rules rules(arg.syscall_action, (uint64_t)(void*)arg.args /* special case for execve arg1 */);

        if (rules.add_simple_filter(arg.syscall_list.c_str())) {
            FATAL("failed to parse syscall filter string");
            exit(-1);
        }
        if (rules.apply()) {
            FATAL("failed to apply seccomp rules");
            exit(-1);
        }
    }
}

static void do_set_new_privs(const Cgroup::spawn_arg& arg) {
    #ifndef PR_SET_NO_NEW_PRIVS
    # define PR_SET_NO_NEW_PRIVS 38
    #endif

    #ifndef PR_GET_NO_NEW_PRIVS
    # define PR_GET_NO_NEW_PRIVS 39
    #endif

    if (arg.no_new_privs) {
        int e = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
        if (e == -1) {
            INFO("NO_NEW_PRIVS is not supported by kernel");
        } else if (e == 0) {
            INFO("prctl PR_SET_NO_NEW_PRIVS");
            int e = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if (e) {
                FATAL("prctl PR_SET_NO_NEW_PRIVS");
                exit(-1);
            }
        }
    }
}

static void init_signal_handler(int signal) {
    if (signal == SIGCHLD) {
        int status;
        while (waitpid(-1, &status, WNOHANG) > 0);
    } else {
        exit(1);
    }
}

static int clone_init_fn(void *) {
    // a dummy init process in new pid namespace
    // intended to be killed via SIGKILL from root pid namespace
    prctl(PR_SET_PDEATHSIG, SIGHUP);

    {
        struct sigaction action;
        action.sa_handler = init_signal_handler;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
        sigaction(SIGKILL, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGABRT, &action, NULL);
        sigaction(SIGQUIT, &action, NULL);
        sigaction(SIGPIPE, &action, NULL);
        sigaction(SIGALRM, &action, NULL);
        sigaction(SIGCHLD, &action, NULL);
    }

    // close all fds
    {
        list<int> fds = get_fds();
        INFO("init is running");
        FOR_EACH(fd, fds) close(fd);
    }

    while (1) pause();
    return 0;
}

static int clone_main_fn(void * clone_arg) {
    // kill us if parent dies
    prctl(PR_SET_PDEATHSIG, SIGKILL);

    // this is executed in child process after clone
    // fs and uid settings should be done here
    Cgroup::spawn_arg& arg = *(Cgroup::spawn_arg*)clone_arg;

#ifdef SYSCTL_PER_NS_WORKS
    // NOTE: Do not uncomment this until sysctl per namespace works.
    // current kernel use global variables for vm.oom_kill_allocating_task,
    // etc.
    do_set_sysctl();
#endif
    do_set_uts(arg);
    do_close_high_fds(arg);
    do_privatize_filesystem(arg);
    do_umount_outside_chroot(arg);
    do_mount_proc(arg);
    do_hide_sensitive(arg);
    do_mount_bindfs(arg);
    do_remounts(arg);
    do_chroot(arg);
    do_mount_tmpfs(arg);
    do_remount_dev(arg);
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

    // exec target
    INFO("will execvp %s ...", arg.args[0]);

    do_set_new_privs(arg);
    do_seccomp(arg);

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
} // clone_main_fn

static int is_setns_pidns_supported() {
    string pidns_path = string(fs::PROC_PATH) + "/self/ns/pid";
    int fd = open(pidns_path.c_str(), O_RDONLY);
    if (fd == -1) return 0;
    close(fd);
    return 1;
}

#ifndef NDEBUG
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
#endif

pid_t Cgroup::spawn(spawn_arg& arg) {
    // uid and gid should > 0
    if (arg.uid <= 0 || arg.gid <= 0) {
        WARNING("uid and gid can not <= 0. spawn rejected");
        return -2;
    }

    // stack size for cloned processes
    long stack_size = sysconf(_SC_PAGESIZE);
    static const long MIN_STACK_SIZE = 8192;
    if (stack_size < MIN_STACK_SIZE) stack_size = MIN_STACK_SIZE;

    // We need root permissions and drop root later, no CLONE_NEWUSER here
    // CLONE_NEWNS is required for private mounts
    // CLONE_NEWUSER is not used because new uid 0 may be non-root
    int clone_flags = CLONE_NEWNS | SIGCHLD | arg.clone_flags;

    // older kernel (ex. Debian 7, 3.2.0) doesn't support setns(whatever, CLONE_PIDNS)
    // just do not create init process in that case.
    if (is_setns_pidns_supported() && (clone_flags & CLONE_NEWPID) == CLONE_NEWPID) {
        // create a dummy init process in a new namespace
        // CLONE_PTRACE: prevent the process being traced by another process
        INFO("spawning dummy init process");
        int init_clone_flags = CLONE_NEWPID;
        init_pid_ = clone(clone_init_fn, (void*)((char*)alloca(stack_size) + stack_size), init_clone_flags, &arg);
        if (init_pid_ < 0) {
            ERROR("can not spawn init process");
            return -3;
        }

        // switch to that pid namespace for our next clone
        string pidns_path = string(fs::PROC_PATH) + "/" + strconv::from_ulong((unsigned long)init_pid_) + "/ns/pid";
        INFO("set pid ns to %s", pidns_path.c_str());
        int pidns_fd = open(pidns_path.c_str(), O_RDONLY);
        if (pidns_fd < 0) {
            ERROR("can not open pid namespace");
            return -3;
        }

        // older glibc does not have setns
        if (syscall(SYS_setns, pidns_fd, CLONE_NEWPID)) {
            ERROR("can not set pid namespace");
            return -3;
        };
        close(pidns_fd);

        // remove CLONE_NEWPID flag because setns() will affect all new processes
        clone_flags ^= CLONE_NEWPID;
    } // spawn init process

    DEBUG_DO {
        INFO("clone flags = 0x%x = %s", (int)clone_flags, clone_flags_to_str(clone_flags).c_str());
    }

    // do sync use socket pair
    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, arg.sockets)) {
        ERROR("socketpair failed");
        return -1;
    }

    // sockets fds should expire when exec
    fcntl(arg.sockets[0], F_SETFD, FD_CLOEXEC);
    fcntl(arg.sockets[1], F_SETFD, FD_CLOEXEC);

    pid_t child_pid;
    child_pid = clone(clone_main_fn, (void*)((char*)alloca(stack_size) + stack_size), clone_flags, &arg);
    char buf[4];
    ssize_t ret;

    if (child_pid < 0) {
        FATAL("clone failed");
        goto cleanup;
    }

    INFO("child pid = %lu", (unsigned long)child_pid);

    // attach child to current cgroup
    INFO("attach %lu", (unsigned long)child_pid);
    attach(child_pid);

    // child is blocking, waiting us before exec, let it go
    strcpy(buf, "RUN");
    close(arg.sockets[0]);
    ret = send(arg.sockets[1], buf, sizeof buf, MSG_NOSIGNAL);
    if (ret < 0) {
        WARNING("can not send let-go message to child");
        goto cleanup;
    }

    // wait for child response
    INFO("reading from child");

    buf[0] = 0;
    ret = read(arg.sockets[1], buf, sizeof buf);

    INFO("from child, got '%3s'", buf);
    if (buf[0] != 'P' || ret <= 0) {  // excepting "PRE"
        // child has problem to start
        child_pid = -3;
        goto cleanup;
    }

    // child exec may fail, confirm
    if (read(arg.sockets[1], buf, sizeof buf) > 0 && buf[0] == 'E') {  // "ERR"
        INFO("seems child exec failed");
        child_pid = -4;
    } else {
        // disable oom killer because it will make dmesg noisy.
        // Note: a process can enter D (uninterruptable sleep) status
        // when oom killer disabled, killing it requires re-enable oom killer
        // or enlarge memory limit
        INFO("disabling oom killer");
        if (set(CG_MEMORY, "memory.oom_control", "1\n")) INFO("can not set memory.oom_control");
    }

cleanup:
    close(arg.sockets[1]);
    return child_pid;
}

