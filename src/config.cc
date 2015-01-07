#include <sys/resource.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include "utils/fs.h"
#include "utils/for_each.h"
#include "config.h"


using lrun::MainConfig;
using std::string;


MainConfig::MainConfig() {
    // default settings
    this->cpu_time_limit = -1;
    this->real_time_limit = -1;
    this->memory_limit = -1;
    this->output_limit = -1;
    this->enable_devices_whitelist = false;
    this->enable_network = true;
    this->enable_pidns = true;
    this->interval = (useconds_t)(0.02 * 1000000);
    this->active_cgroup = NULL;
    this->pass_exitcode = false;
    this->write_result_to_3 = fs::is_accessible("/proc/self/fd/3", F_OK);

    // arg settings
    this->arg.nice = 0;
    this->arg.uid = getuid();
    this->arg.gid = getgid();
    this->arg.umask = 022;
    this->arg.chroot_path = "";
    this->arg.chdir_path = "";
    this->arg.remount_dev = 0;
    this->arg.reset_env = 0;
    this->arg.no_new_privs = true;
    this->arg.umount_outside = false;
    this->arg.clone_flags = 0;
    this->arg.stdout_fd = STDOUT_FILENO;
    this->arg.stderr_fd = STDERR_FILENO;
    this->arg.callback_parent = NULL;
    this->arg.callback_child = NULL;

    // arg.rlimits settings
    this->arg.rlimits[RLIMIT_NOFILE] = 256;
    this->arg.rlimits[RLIMIT_NPROC] = 2048;
    this->arg.rlimits[RLIMIT_RTPRIO] = 0;
    this->arg.rlimits[RLIMIT_CORE] = 0;
    this->arg.reset_env = 0;
    this->arg.syscall_action = seccomp::action_t::OTHERS_EPERM;
    this->arg.syscall_list = "";
}

static string access_mode_to_str(int mode) {
    string result;
    if (mode & R_OK) result += "r";
    if (mode & W_OK) result += "w";
    if (mode & X_OK) result += "x";
    return result;
}

static void check_path_permission(const string& path, std::vector<string>& error_messages, int mode = R_OK) {
    // path should be absolute and accessible
    if (!fs::is_absolute(path)) {
        error_messages.push_back(
                string("Relative paths are forbidden for non-root users.\n")
                + "Please change: " + path);
        return;
    }

    if (fs::is_dir(path)) mode |= X_OK;
    if (!fs::is_accessible(path, mode)) {
        error_messages.push_back(
                string("You do not have `") + access_mode_to_str(mode)
                + "` permission on " + path);
    }
}

static string follow_binds(const std::vector<std::pair<string, string> >& binds, const string& path) {
    // only handle absolute paths
    if (!fs::is_absolute(path)) return path;
    string result = fs::expand(path);
    for (int i = binds.size() - 1; i >= 0; --i) {
        string prefix = binds[i].first + "/";
        if (result.substr(0, prefix.length()) == prefix) {
            // once is enough, because binds[i].second already followed previous binds
            result = binds[i].second + result.substr(prefix.length() - 1);
            break;
        }
    }
    return result;
}

void MainConfig::check() {
    int is_root = (getuid() == 0);
    std::vector<string> error_messages;

    if (this->arg.uid == 0) {
        error_messages.push_back(
                "For security reason, running commands with uid = 0 is not allowed.\n"
                "Please specify a user ID using `--uid`.");
    } else if (!is_root && this->arg.uid != getuid()) {
        error_messages.push_back(
                "For security reason, setting uid to other user requires root.");
    }

    if (this->arg.gid == 0) {
        error_messages.push_back(
                "For security reason, running commands with gid = 0 is not allowed.\n"
                "Please specify a group ID using `--gid`.");
    } else if (!is_root && this->arg.gid != getgid()) {
        error_messages.push_back(
                "For security reason, setting gid to other group requires root.");
    }

    if (this->arg.argc <= 0) {
        error_messages.push_back(
                "command_args cannot be empty. "
                "Use `--help` to see full options.");
    }

    if (!is_root) {
        if (this->arg.cmd_list.size() > 0) {
            error_messages.push_back(
                    "For security reason, `--cmd` requires root.");
        }

        if (this->groups.size() > 0) {
            error_messages.push_back(
                    "For security reason, `--group` requires root.");
        }

        // check paths, require absolute paths and read permissions
        // check --bindfs
        std::vector<std::pair<string, string> > binds;
        FOR_EACH(p, this->arg.bindfs_list) {
            const string& dest = p.first;
            const string& src = p.second;
            check_path_permission(follow_binds(binds, src), error_messages);
            binds.push_back(make_pair(fs::expand(dest), follow_binds(binds, fs::expand(src))));
        }

        // check --chroot
        string chroot_path = this->arg.chroot_path;
        if (!chroot_path.empty()) {
            check_path_permission(follow_binds(binds, chroot_path), error_messages);
        }

        // check --chdir
        if (!this->arg.chdir_path.empty()) {
            string chdir_path = fs::join(chroot_path, this->arg.chdir_path);
            check_path_permission(follow_binds(binds, chdir_path), error_messages);
        }

        // restrict --remount-ro, only allows dest in --bindfs
        // because something like `--remount-ro /` affects outside world
        FOR_EACH(p, this->arg.remount_list) {
            const string& dest = p.first;
            if (!this->arg.bindfs_dest_set.count(dest)) {
                error_messages.push_back(
                        "For security reason, `--remount-ro A` is only allowed "
                        "if there is a `--bindfs A B`.");
            }
        }

        if (this->arg.no_new_privs == false) {
            error_messages.push_back(
                    "For security remount, `--no-new-privs false` is forbidden "
                    "for non-root users.");
        }

        if (this->arg.nice < 0) {
            error_messages.push_back(
                    "Non-root users cannot set a negative value of `--nice`");
        }

        if (!this->cgroup_options.empty()) {
            error_messages.push_back(
                    "Non-root users cannot use `--cgroup-option`");
        }

        FOR_EACH(p, this->cgroup_options) {
            const string& key = p.first.second;
            if (key.find("..") != string::npos || key.find("/") != string::npos) {
                error_messages.push_back(
                        "Invalid cgroup option key: `" + key + "`");
            }
        }
    }

    if (this->arg.syscall_list.empty() && this->arg.syscall_action == seccomp::action_t::DEFAULT_EPERM) {
        error_messages.push_back(
                "Syscall filter forbids all syscalls, which is not allowed.");
    }

    if (error_messages.size() > 0) {
        FOR_EACH(message, error_messages) {
            fprintf(stderr, "%s\n\n", message.c_str());
        }
        fprintf(stderr, "Please fix above issues and try again.\n");
        exit(1);
    }
}
