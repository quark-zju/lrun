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
#include <stdio.h>
#include <string.h>
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


string Cgroup::base_path(bool create_on_need) {
    // FIXME cache may not work when user manually umount cgroup
    string last_base_path;
    if (!last_base_path.empty() && fs::is_dir(last_base_path)) return last_base_path;

    // enumerate mounts
    std::map<string, string> mounts;
    FILE *fp = setmntent(fs::MOUNTS_PATH, "r");
    if (!fp) return "";

    // no cgroups mounted, prepare one
    const char * MNT_SRC_NAME = "cgroup_lrun";
    const char * MNT_DEST_BASE_PATH = "/sys/fs/cgroup";
    const char * MNT_DEST_PATH = "/sys/fs/cgroup/lrun";

    for (struct mntent *ent; (ent = getmntent(fp));) {
        mounts[string(ent->mnt_dir)] = string(ent->mnt_type);
        if (strcmp(ent->mnt_type, fs::TYPE_CGROUP) == 0 && strcmp(ent->mnt_fsname, MNT_SRC_NAME) == 0) {
            INFO("last_base_path = '%s'", ent->mnt_dir);
            fclose(fp);
            return (last_base_path = string(ent->mnt_dir));
        }
    }

    if (!create_on_need) return "";

    if (!fs::is_dir(MNT_DEST_BASE_PATH)) {
        // no /sys/fs/cgroup in system, try conservative location
        MNT_DEST_BASE_PATH = "/cgroup";
        MNT_DEST_PATH = "/cgroup/lrun";
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

    // create and mount cgroup at MNT_DEST_BASE_PATH
    INFO("mkdir and mounting '%s'", MNT_DEST_PATH);
    mkdir(MNT_DEST_PATH, 0700);
    int e = mount(MNT_SRC_NAME, MNT_DEST_PATH, fs::TYPE_CGROUP, MS_NOEXEC | MS_NOSUID, "cpuacct,memory,devices,freezer");

    if (e != 0) {
        int last_err = errno;
        // fallback, umount tmpfs if it is just mounted
        if (dest_base_mounted) umount(MNT_DEST_BASE_PATH);
        errno = last_err;
        FATAL("can not mount cgroup on '%s'", MNT_DEST_BASE_PATH);
    }

    return (last_base_path = string(MNT_DEST_PATH));
}

string Cgroup::path_from_name(const string& name) {
    return base_path() + "/" + name;
}

int Cgroup::exists(const string& name) {
    return fs::is_dir(path_from_name(name));
}

Cgroup Cgroup::create(const string& name) {
    Cgroup cg;

    string path = path_from_name(name);

    if (fs::is_dir(path)) {
        cg.path_ = path;
        return cg;
    }

    // not existed, create new
    if (mkdir(path.c_str(), 0700) == 0) cg.path_ = path;
    return cg;
}

Cgroup::Cgroup() { }

bool Cgroup::valid() {
    return !path_.empty() && fs::is_dir(path_);
}

int Cgroup::killall() {

    // return immediately if cgroup is not valid
    if (!valid()) return -1;

    // kill all processes
    string procs_path = path_ + "/cgroup.procs";
    string freeze_state_path = path_ + "/freezer.state";

    // check procs_path first, return if empty
    if (fs::read(procs_path, 4).empty()) return 0;

    PROGRESS_INFO("KILLING: STARTED");

    int nkill = 0, frozen = 0;
    for (int loop = 0; !frozen;) {
        // Freeze cgroup before send killing signals
        fs::write(freeze_state_path, "FROZEN\n");

        frozen = (strncmp(fs::read(freeze_state_path, 4).c_str(), "FRO", 3) == 0);

        // When OOM killer is disabled, processes may enter D status,
        // which prevents freezer freeze whole group,
        // OOM killer should be enabled to reach FROZEN status
        if (loop == 0) {
            PROGRESS_INFO("KILLING: ENABLING OOM");
            set_memory_limit(1);
            if (set("memory.oom_control", "0\n") == 0) ++loop;
        } else ++loop;

        // open cgroup.procs and read process ids
        PROGRESS_INFO("KILLING: LOOP %d - READING", loop);
        FILE * procs = fopen(procs_path.c_str(), "r");
        if (!procs) {
            frozen = 0;
            continue;
        }

        long pid;
        list<pid_t> pids;
        while (fscanf(procs, "%ld", &pid) == 1) pids.push_back((pid_t)pid);
        fclose(procs);

        PROGRESS_INFO("KILLING: LOOP %d - SIGNALING", loop);

        // kill pids
        FOR_EACH(p, pids) kill(p, SIGKILL);

        // count into nkill, nkill should not overflow
        if (nkill < (int)pids.size()) nkill = pids.size();
    }

    PROGRESS_INFO("\nKILLING: FROZEN, WAITING, NKILL = %d\n", nkill);

    // unfreeze and wait all processes gone
    // processes receive signals when they are alive
    fs::write(freeze_state_path, "THAWED\n");

    // give processes sometime to disappear
    for (int clear = 0; clear == 0;) {
        if (fs::read(procs_path, 4).empty()) break;
        usleep(6);
    }

    return nkill;
}

int Cgroup::destroy() {
    killall();
    rmdir(path_.c_str());
    return valid() ? -1 : 0;
}

int Cgroup::set(const string& property, const string& value) {
    return fs::write(path_ + "/" + property, value);
}

string Cgroup::get(const string& property, size_t max_length) {
    return fs::read(path_ + "/" + property, max_length);
}

int Cgroup::inherit(const string& property) {
    string value = fs::read(path_ + "/../" + property);
    return fs::write(path_ + "/" + property, value);
}

int Cgroup::attach(pid_t pid) {
    char pidbuf[32];
    snprintf(pidbuf, sizeof(pidbuf), "%ld\n", (long)pid);
    return fs::write(path_ + "/tasks", pidbuf);
}

int Cgroup::limit_devices() {
    int e = 0;
    e += set("devices.deny", "a");
    e += set("devices.allow", "c 1:3 rwm"); // null
    e += set("devices.allow", "c 1:5 rwm"); // zero
    e += set("devices.allow", "c 1:7 rwm"); // full
    e += set("devices.allow", "c 1:8 rwm"); // random
    e += set("devices.allow", "c 1:9 rwm"); // urandom
    return e ? -1 : 0;
}

int Cgroup::reset_usages() {
    int e = 0;
    e += set("cpuacct.usage", "0");
    e += set("memory.max_usage_in_bytes", "0") * set("memory.memsw.max_usage_in_bytes", "0");
    return e ? -1 : 0;
}

double Cgroup::cpu_usage() {
    string cpu_usage = get("cpuacct.usage", 31);
    // convert from nanoseconds to seconds
    return strconv::to_double(cpu_usage) / 1e9;
}

long long Cgroup::memory_usage() {
    string usage = get("memory.memsw.max_usage_in_bytes");
    if (usage.empty()) usage = get("memory.max_usage_in_bytes");
    return strconv::to_longlong(usage);
}

long long Cgroup::memory_limit() {
    string limit = get("memory.memsw.limit_in_bytes");
    if (limit.empty()) limit = get("memory.limit_in_bytes");
    return strconv::to_longlong(limit);
}

int Cgroup::set_memory_limit(long long bytes) {
    int e = 1;

    if (bytes <= 0) {
        // read base (parent) cgroup properties
        e *= inherit("memory.memsw.limit_in_bytes");
        e *= inherit("memory.limit_in_bytes");
    } else {
        e *= set("memory.memsw.limit_in_bytes", strconv::from_longlong(bytes));
        e *= set("memory.limit_in_bytes", strconv::from_longlong(bytes));
    }

    return e ? -1 : 0;
}

static int clone_fn(void * clone_arg) {

    // this is executed in child process after clone
    // fs and uid settings should be done here
    Cgroup::spawn_arg& arg = *(Cgroup::spawn_arg*)clone_arg;

    // bind fs mounts
    for (auto it = arg.bindfs_list.begin(); it != arg.bindfs_list.end(); ++it) {
        auto& p = (*it);

        const string& dest = p.first;
        const string& src = p.second;

        INFO("mount bind %s -> %s", src.c_str(), dest.c_str());
        if (fs::mount_bind(src, dest)) {
            FATAL("mount bind '%s' -> '%s' failed", src.c_str(), dest.c_str());
        }
    }

    // chroot to a prepared place
    if (!arg.chroot_path.empty()) {
        string& path = arg.chroot_path;

        INFO("chroot %s", path.c_str());
        if (chroot(path.c_str())) {
            FATAL("chroot '%s' failed", path.c_str());
        }
    }

    // mount /proc if pid namespace is enabled
    if (arg.clone_flags & CLONE_NEWPID) {
        INFO("mount /proc");
        if (mount(NULL, "/proc", "proc", MS_NOEXEC | MS_NOSUID, NULL)) {
            FATAL("mount procfs failed");
        }
    }

    // close fds other than 0,1,2 and sockets[0], since we have proper /proc now
    close(arg.sockets[1]);
    struct dirent **namelist = 0;
    int nlist = scandir("/proc/self/fd", &namelist, 0, alphasort);

    for (int i = 0; i < nlist; ++i) {
        const char * name = namelist[i]->d_name;
        // skip . and ..
        if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            int fd;
            if (sscanf(name, "%d", &fd) == 1 && fd > 2 && fd != arg.sockets[0] && arg.keep_fds.count(fd) == 0) {
                INFO("close %d", (int)fd);
                close(fd);
            }
        }
        free(namelist[i]);
    }
    if (namelist) free(namelist);

    // setup other tmpfs mounts
    for (auto it = arg.tmpfs_list.begin(); it != arg.tmpfs_list.end(); ++it) {
        auto& p = (*it);

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

    // chdir to a specified path
    if (!arg.chdir_path.empty()) {
        string& path = arg.chdir_path;

        INFO("chdir %s", path.c_str());
        if (chdir(path.c_str())) {
            FATAL("chdir '%s' failed", path.c_str());
        }
    }

    // system commands
    for (auto it = arg.cmd_list.begin(); it != arg.cmd_list.end(); ++it) {
        system(it->c_str());
    }

    // nice
    if (arg.nice) nice(arg.nice);

    // setup uid, gid
    INFO("setgid %d, setuid %d", (int)arg.gid, (int)arg.uid);
    if (setgid(arg.gid) || setuid(arg.uid)) {
        FATAL("setgid(%d) or setuid(%d) failed", (int)arg.gid, (int)arg.uid);
    }

    // apply rlimit, note NPROC limit should be applied after setuid
    for (auto it = arg.rlimits.begin(); it != arg.rlimits.end(); ++it) {
        auto& p = (*it);

        int resource = p.first;
        rlimit limit;
        limit.rlim_cur = limit.rlim_max = p.second;

        // wish to receive SIGXCPU to know it is TLE
        if (resource == RLIMIT_CPU) ++limit.rlim_max;

        INFO("setrlimit %d, [%d, %d]", resource, (int)limit.rlim_cur, (int)limit.rlim_max);
        if (setrlimit(resource, &limit)) {
            FATAL("can not set rlimit %d", resource);
        }
    }

    // prepare env
    if (arg.reset_env) {
        INFO("reset ENV");
        if (clearenv()) FATAL("can not clear env");
    }

    for (auto it = arg.env_list.begin(); it != arg.env_list.end(); ++it) {
        auto& p = (*it);

        const char * name = p.first.c_str();
        const char * value = p.second.c_str();

        if (setenv(name, value, 1)) FATAL("can not set env %s=%s", name, value);
    }

    // all prepared! blocking, wait for parent
    char buf[4];
    read(arg.sockets[0], buf, sizeof buf);

    // let parent know we got the message, parent then can close fd without SIGPIPE child
    strcpy(buf, "PRE");
    write(arg.sockets[0], buf, sizeof buf);

    // not closing sockets[0] here, it will closed on exec
    // if exec fails, it will be closed upon process exit (aka. this function returns)

    // exec target
    execvp(arg.args[0], arg.args);

    // exec failed, store errno
    int last_err = errno;

    // output to stderr
    errno = last_err;
    ERROR("exec '%s' failed", arg.args[0]);

    // notify parent that exec failed
    strcpy(buf, "ERR");
    write(arg.sockets[0], buf, sizeof buf);

    // wait parent
    read(arg.sockets[0], buf, sizeof buf);

    exit(-1);
    return -1;
} // clone_fn


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
    // CLONE_NEWS is required for private mounts
    // CLONE_NEWUSER is not used because new uid 0 may be non-root
    int clone_flags = CLONE_NEWNS | SIGCHLD | arg.clone_flags;

    long stack_size = sysconf(_SC_PAGESIZE);
    void * stack = (void*)((char*)alloca(stack_size) + stack_size);
    char buf[] = "RUN";

    INFO("clone flags = 0x%x", (int)clone_flags);

    pid_t child_pid;
    child_pid = clone(clone_fn, stack, clone_flags, &arg);

    if (child_pid < 0) {
        FATAL("clone failed");
        goto cleanup;
    }

    INFO("child pid = %d", (int)child_pid);

    // attach child to current cgroup
    attach(child_pid);

    // child is blocking, waiting us before exec, let it go
    close(arg.sockets[0]);
    write(arg.sockets[1], buf, sizeof buf);

    // wait for child response
    read(arg.sockets[1], buf, sizeof buf);
    if (buf[0] != 'P') {
        // child has problem
        WARNING("child does not work as expected (buf = '%s')", buf);
        goto cleanup;
    }

    // child exec may fail, confirm
    if (read(arg.sockets[1], buf, sizeof buf) > 0 && buf[0] == 'E') {
        child_pid = -3;
    } else {
        // disable oom killer now
        // oom killer writes a super long log, disable it
        // Note: a process can enter D (uninterruptable sleep) status
        // when oom killer disabled, killing it requires re-enable oom killer
        // or enlarge memory limit
        if (set("memory.oom_control", "1\n")) INFO("can not set memory.oom_control");
    }

cleanup:
    close(arg.sockets[1]);
    return child_pid;
}

