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

#include <vector>
#include <set>
#include <map>
#include <utility>
#include <cstring>
#include <cassert>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "options.h"
#include "../utils/ensure.h"
#include "../utils/fs.h"
#include "../utils/fs_tracer.h"
#include "../utils/log.h"
#include "../utils/re.h"
#include "../config.h"


static pthread_t tracer_thread_id;
static fs::Tracer * tracer;
static lrun::Cgroup * tracer_cgroup;
static std::string child_chroot_path;


struct FilterAction {
    virtual int perform(const std::string& /* path */, int /* fd */, pid_t /* pid */, uint64_t /* mask */) { return 0; };
    virtual ~FilterAction() {};
};

    struct FilterActionAccept : FilterAction {
        int perform(const std::string& /* path */, int /* fd */, pid_t /* pid */, uint64_t /* mask */) { return 0; }
    };

    struct FilterActionDeny : FilterAction {
        int perform(const std::string& /* path */, int /* fd */, pid_t /* pid */, uint64_t /* mask */) { return 1; }
    };

    struct FilterActionResetUsage : FilterAction {
        FilterActionResetUsage(bool one_time = false) : one_time_(one_time), disabled_(false) { }
        int perform(const std::string& /* path */, int /* fd */, pid_t /* pid */, uint64_t /* mask */) {
            if (!disabled_) {
                if (tracer_cgroup) tracer_cgroup->reset_cpu_usage();
                if (one_time_) disabled_ = true;
            }
            return 0;
        }
        bool one_time_;
        bool disabled_;
    };

    struct FilterActionLog : FilterAction {
        FilterActionLog(int fd) : fd(fd) {
            if (!fs::is_fd_valid(fd)) {
                WARNING("Invalid fd %d", fd);
                this->fd = -1;
            }
        }

        int perform(const std::string& path, int /* fd */, pid_t /* pid */, uint64_t /* mask */) {
            if (fd > 0) {
                int ret = 0;
                ret |= write(fd, path.c_str(), path.length());
                ret |= write(fd, "\n", 1);
                (void) ret;
            }
            return 0;
        }

        int fd;
    };

struct FilterCondition {
    virtual bool meet(const std::string& /* path */, pid_t /* pid */, uint64_t /* mask */) { return false; };
    virtual int get_mark_flags() const { return 0; };
    virtual std::string get_mark_path() const { return ""; };
    virtual ~FilterCondition() {};
};

    struct FilterConditionMountpoint : FilterCondition {
        FilterConditionMountpoint(const std::string& mount_point, const std::string regex): mount_point(mount_point) {
            if (regex.empty()) {
                re_ = NULL;
            } else {
                re_ = new RegEx(regex.c_str());
            }
        }

        ~FilterConditionMountpoint() {
            if (re_) delete re_;
        }

        bool meet(const std::string& path, pid_t /* pid */, uint64_t /* mask */) {
            if (path.substr(0, mount_point.length()) != mount_point) return false;
            if (re_) {
                return re_->match(path.c_str());
            } else return true;
        }

        int get_mark_flags() const {
            return FAN_MARK_MOUNT;
        }

        std::string get_mark_path() const {
            return this->mount_point;
        }

        RegEx * re_;
        std::string mount_point;

    private:
        // C++ 0x 'delete' keyword is better, but we aim to support older compilers.
        FilterConditionMountpoint(const FilterConditionMountpoint&);
        const FilterConditionMountpoint& operator= (const FilterConditionMountpoint&);
    };

    struct FilterConditionFile : FilterCondition {
        FilterConditionFile(const std::string& path) : path(path) {}

        bool meet(const std::string& query_path, pid_t /* pid */, uint64_t /* mask */) {
            return (query_path == this->path);
        }

        std::string get_mark_path() const {
            return this->path;
        }

        std::string path;
    };


static std::vector<FilterCondition*> conditions;
static std::vector<FilterAction*> actions;
static std::map<int, std::set<std::string> > marked_paths;


static bool is_inside_our_cgroup(pid_t pid) {
    if (tracer_cgroup == NULL) return false;
    return tracer_cgroup->has_pid(pid);
}


static int fs_trace_callback(const char path[], int fd, pid_t pid, uint64_t mask) {
    if (!is_inside_our_cgroup(pid)) return 0;

    // strip chroot_path
    std::string parsed_path = path;
    if (!child_chroot_path.empty() && strncmp(child_chroot_path.c_str(), path, child_chroot_path.length()) == 0) {
        parsed_path = parsed_path.substr(child_chroot_path.length(), std::string::npos);
    }
    for (size_t i = 0; i < conditions.size(); ++i) {
        if (!conditions[i] || !conditions[i]->meet(parsed_path, pid, mask)) continue;
        if (actions.size() <= i || !actions[i]) continue;  // actually, should not happen
        return actions[i]->perform(parsed_path, fd, pid, mask);
    }
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

void lrun::options::fstracer::stop() {
    if (tracer_thread_id) {
        pthread_cancel(tracer_thread_id);
        tracer_thread_id = 0;
    }
    if (tracer) {
        delete tracer;
        tracer = NULL;
    }
    for (size_t i = 0; i < conditions.size(); ++i) {
        delete conditions[i];
        conditions[i] = NULL;
    }
    for (size_t i = 0; i < actions.size(); ++i) {
        delete actions[i];
        actions[i] = NULL;
    }
}

bool lrun::options::fstracer::started() {
    return tracer_thread_id != 0;
}

bool lrun::options::fstracer::alive() {
    return tracer_thread_id != 0 && pthread_kill(tracer_thread_id, 0) == 0;
}

static inline void do_create_tracer() {
    if (!tracer) {
        tracer = new fs::Tracer();
        if (tracer->init(
                    FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE,
                    O_RDONLY,
                    &fs_trace_callback)) {
            FATAL("can not init fs tracer");
        }
    }
}

static inline int do_mark_paths() {
    for (size_t i = 0; i < conditions.size(); ++i) {
        int mark_flag = conditions[i]->get_mark_flags();
        std::string path = conditions[i]->get_mark_path();

        if (!path.empty()) {
            int ret = tracer->mark(path.c_str(), mark_flag | FAN_MARK_ADD, FAN_OPEN_PERM);
            if (ret != 0) {
                ERROR("cannot mark path");
            }
            return ret;
        }
    }
    return 0;
}


static inline void do_start_tracer_thread() {
    if (!tracer_thread_id) {
        INFO("starting fs tracer thread");
        pthread_attr_t attr;
        ensure_zero(pthread_attr_init(&attr));
        // the thread must be joinable so that we can reliably use pthread_kill to detect if it is alive
        ensure_zero(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE));
        pthread_create(&tracer_thread_id, NULL, &fs_tracer_thread, (void*) tracer);
        ensure_zero(pthread_attr_destroy(&attr));
    }
}

void lrun::options::fstracer::start(lrun::Cgroup& cgroup, const std::string& chroot_path) {
    // be smart, if either conditions or actions
    if (conditions.empty() || actions.empty()) return;

    tracer_cgroup = &cgroup;
    child_chroot_path = chroot_path;

    do_create_tracer();
    do_start_tracer_thread();
}

int lrun::options::fstracer::apply_settings() {
    if (tracer) return do_mark_paths();
    else return 0;
}


void lrun::options::fopen_filter(const std::string& condition, const std::string& action) {
    std::string error;

    // parse action
    if (action == "a") {
        actions.push_back(new FilterActionAccept());
    } else if (action == "d") {
        actions.push_back(new FilterActionDeny());
    } else if (action == "r") {
        actions.push_back(new FilterActionResetUsage(false /* one time */));
    } else if (action == "R") {
        actions.push_back(new FilterActionResetUsage(true /* one time */));
    } else if (action == "l") {
        actions.push_back(new FilterActionLog(STDERR_FILENO));
    } else if (action.substr(0, 2) == "l:") {
        int fd = atoi(action.c_str() + 2);
        if (fd < 0) fd = STDERR_FILENO;
        actions.push_back(new FilterActionLog(fd));
    } else {
        error = "Unknown action";
        goto out;
    }

    // parse condition
    if (condition.substr(0, 2) == "m:") {
        std::string content = condition.substr(2, condition.length());
        std::string path, regexp;
        int is_path = 1, is_escape = 0;

        for (size_t i = 0; i < content.length(); ++i) {
            switch (content[i]) {
                case '\\':
                    is_escape = 1;
                    continue;
                case ':':
                    if (!is_escape) {
                        is_path = 0;
                        continue;
                    }
                default:
                    if (is_path) path += content[i];
                    else regexp += content[i];
                    is_escape = 0;
            }
        }
        std::string mount_point = fs::get_mount_point(path);
        conditions.push_back(new FilterConditionMountpoint(mount_point, regexp));
    } else if (condition.substr(0, 2) == "f:") {
        std::string path = condition.substr(2, condition.length());
        conditions.push_back(new FilterConditionFile(path));
    } else {
        error = "Unknown condition";
        goto out;
    }

out:
    if (!error.empty()) {
        FATAL("Cannot parse fopen filter \"%s %s\": %s", condition.c_str(), action.c_str(), error.c_str());
    }
}
