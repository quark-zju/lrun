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

#include "common.h"
#include "fs.h"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <list>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/file.h>

namespace fs = lrun::fs;
using std::string;

const char fs::PATH_SEPARATOR = '/';
const char * const fs::PROC_PATH = "/proc";
const char * const fs::MOUNTS_PATH = "/proc/mounts";
const char * const fs::TYPE_CGROUP = "cgroup";
const char * const fs::TYPE_TMPFS  = "tmpfs";

string fs::join(const string& dirname, const string& basename) {
  size_t dirname_len = dirname.length();
  size_t basename_len = basename.length();
  int offset = 0;

  if (dirname_len == 0) return basename;
  else if (dirname[dirname_len - 1] == PATH_SEPARATOR) offset++;
  if (basename_len == 0) return dirname;
  else if (basename[0] == PATH_SEPARATOR) offset++;

  switch (offset) {
    case 0:
      return dirname + PATH_SEPARATOR + basename;
    case 2:
      return dirname + basename.substr(1);
    case 1: default:
      return dirname + basename;
  }
}

bool fs::is_absolute(const string& path) {
    return path.length() > 0 && path.data()[0] == PATH_SEPARATOR;
}

string fs::expand(const string& path) {
    std::list<string> paths;
    size_t pos = string::npos, start = 0;
    for (;;) {
        pos = path.find(PATH_SEPARATOR, pos + 1);
        size_t length = (pos == string::npos ? string::npos : pos - start);
        if (length > 0) {
            string name = path.substr(start, length);
            if (name == "..") {
                if (paths.size() > 0) paths.pop_back();
            } else if (name == ".") {
                // ignored
            } else {
                paths.push_back(name);
            }
        }

        start = pos + 1;
        if (pos == string::npos) break;
    }

    string result;
    for (std::list<string>::iterator it = paths.begin(); it != paths.end(); ++it) {
        string name = *it;
        result += PATH_SEPARATOR;
        result += name;
    }
    if (fs::is_absolute(path)) {
        if (result.length() == 0) result = PATH_SEPARATOR;
    } else {
        if (result.length() > 0) result = result.substr(1);
    }
    return result;
}

string fs::resolve(const string& path, const string& work_dir) {
    string result = expand(is_absolute(path) ? path : join(work_dir, path));
    int dirfd = AT_FDCWD;
    size_t buf_size = PATH_MAX;
    char *buf = (char*) malloc(buf_size + 1);

    if (!buf) goto cleanup;

    if (!work_dir.empty() && !is_absolute(path)) {
        dirfd = open(work_dir.c_str(), O_RDONLY);
        if (dirfd == -1) goto cleanup;
    }

    for (string link = path;;) { // recursively readlink
        for (;;) {
            // readlink requires unknown space, try until we got full path
            ssize_t out_size = readlinkat(dirfd, link.c_str(), buf, buf_size);
            if (out_size < 0) {
                goto cleanup;
            } else if ((size_t) out_size >= buf_size) {
                // try bigger
                char *new_buf = (char*) realloc(buf, buf_size + PATH_MAX + 1);
                if (new_buf) {
                    buf = new_buf;
                    buf_size += PATH_MAX;
                } else {
                    // give up
                    result = buf;
                    break;
                }
            } else {
                buf[out_size] = 0;
                link = result = buf;
                break;
            }
        };
    }

cleanup:
    if (dirfd != -1 && dirfd != AT_FDCWD) close(dirfd);
    if (buf) free(buf);
    return result;
}

bool fs::is_accessible(const string& path, int mode, const string& work_dir) {
    int dirfd = AT_FDCWD;
    bool result = false;
    if (!work_dir.empty() && !is_absolute(path)) {
        dirfd = open(work_dir.c_str(), O_RDONLY);
        if (dirfd == -1) goto cleanup;
    }
    result = (faccessat(dirfd, path.c_str(), mode, 0) == 0);

cleanup:
    if (dirfd != -1 && dirfd != AT_FDCWD) close(dirfd);
    return result;
}

int fs::write(const string& path, const string& content) {
    FILE* fp = fopen(path.c_str(), "w");
    if (!fp) return -1;

    size_t wmb = fwrite(content.c_str(), content.size(), 1, fp);
    fclose(fp);

    return wmb ? 0 : -2;
}

string fs::read(const string& path, size_t max_length) {
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) return "";

    size_t buffer_size = max_length + 1;
    char buffer[buffer_size];

    int nread = fread(buffer, 1, buffer_size, fp);
    fclose(fp);

    buffer[max_length] = 0;
    if (nread >= 0 && (size_t)nread < max_length) buffer[nread] = 0;

    return buffer;
}

int fs::is_dir(const string& path) {
    struct stat buf;
    if (stat(path.c_str(), &buf) == -1) return 0;
    return S_ISDIR(buf.st_mode) ? 1 : 0;
}

int fs::mkdir_p(const string& dir, const mode_t mode) {
    // do nothing if directory exists
    if (is_dir(dir)) return 0;

    // make each dirs
    const char * head = dir.c_str();
    int nmkdir = 0;
    for (const char * p = head; *p; ++p) {
        if (*p == PATH_SEPARATOR && p > head) {
            int e = mkdir(dir.substr(0, p - head).c_str(), mode);
            if (e == 0) ++nmkdir;
        }
    }
    int e = mkdir(dir.c_str(), mode);

    if (e < 0 /* && errno != EEXIST */) return -1;
    return nmkdir;
}

int fs::rm_rf(const string& path) {
    // TODO use more efficient implement like coreutils/rm

    // try to remove single file or an empty dir
    if (unlink(path.c_str()) == 0) return 0;
    if (rmdir(path.c_str()) == 0) return 0;

    // try to list path contents
    struct dirent **namelist = 0;
    int nlist = scandir(path.c_str(), &namelist, 0, alphasort);

    for (int i = 0; i < nlist; ++i) {
        const char * name = namelist[i]->d_name;
        // skip . and ..
        if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) fs::rm_rf(join(path, name));
        free(namelist[i]);
    }

    if (namelist) free(namelist);

    // try remove empty dir again
    if (rmdir(path.c_str()) == 0) return 0;

    // otherwise something must went wrong
    return -1;
}

int fs::chmod(const std::string& path, const mode_t mode) {
    return ::chmod(path.c_str(), mode);
}

int fs::remount(const string& dest, unsigned long flags) {
    int e = mount(NULL, dest.c_str(), NULL, MS_REMOUNT | flags, NULL);
    return e;
}

int fs::mount_bind(const string& src, const string& dest) {
    int e = mount(src.c_str(),
                  dest.c_str(),
                  NULL,
                  MS_BIND | MS_NOSUID,
                  NULL);
    return e;
}

int fs::mount_tmpfs(const string& dest, size_t max_size, mode_t mode) {
    char tmpfs_opts[256];
    snprintf(tmpfs_opts, sizeof tmpfs_opts, "size=%lu,mode=0%o", (unsigned long)max_size, (unsigned int)mode);

    int e = mount(NULL,
                 dest.c_str(),
                 TYPE_TMPFS,
                 MS_NOSUID | MS_NODEV,
                 tmpfs_opts);
    return e;
}

int fs::mount_set_shared(const string& dest, int type) {
    return mount(NULL, dest.c_str(), NULL, type, NULL);
}

int fs::umount(const string& dest, bool lazy) {
    if (lazy) {
        return umount2(dest.c_str(), MNT_DETACH);
    } else {
        return umount(dest.c_str());
    }
}

fs::ScopedFileLock::ScopedFileLock(const char path[]) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    if (flock(fd, LOCK_EX) == 0) {
        this->fd_ = fd;
    } else {
        close(fd);
        this->fd_ = -1;
    }
}

fs::ScopedFileLock::~ScopedFileLock() {
    int fd = this->fd_;
    if (fd < 0) return;
    flock(fd, LOCK_UN);
    close(fd);
}

int fs::Tracer::init(unsigned int flags, unsigned int event_f_flags, fs::Tracer::tracer_cb callback) {
    cb_ = callback;
    fan_fd_ = fanotify_init(flags, event_f_flags);
    if (fan_fd_ < 0) goto failure;
    return 0;

failure:
    cb_ = NULL;
    fan_fd_ = -1;
    return -1;
}

fs::Tracer::Tracer(int fan_fd) : fan_fd_(fan_fd) {}

int fs::Tracer::mark(const char path[], unsigned int flags, uint64_t mask) {
    if (fan_fd_ < 0) return -1;
    return fanotify_mark(fan_fd_, flags, mask, /* dirfd */ 0, path);
}

void fs::Tracer::process_events() {
    if (fan_fd_ < 0) return;

    while (1) {
        char buf[4096];
        ssize_t len = ::read(fan_fd_, buf, sizeof(buf));
        if (len <= 0) return;

        struct fanotify_event_metadata *metadata = (struct fanotify_event_metadata*) buf;
        while (FAN_EVENT_OK(metadata, len)) {
            assert(metadata->vers >= 2);

            int cb_ret = 0;
            if (cb_) {
                // FIXME: longer path is not supported
                char path[4096];
                path[0] = '\0';
                if (metadata->fd >= 0) {
                    sprintf(path, "/proc/self/fd/%d", metadata->fd);
                    ssize_t path_len = readlink(path, path, sizeof(path) - 1);
                    if (path_len >= 0) path[path_len] = '\0';
                }
                cb_ret = cb_(path, metadata->fd, metadata->pid, metadata->mask);
            }

            if (metadata->mask & FAN_ALL_PERM_EVENTS) {
                struct fanotify_response response;
                response.fd = metadata->fd;
                response.response = cb_ret == 0 ? FAN_ALLOW : FAN_DENY;
                int ret = ::write(fan_fd_, &response, sizeof(response));
                (void)ret;
            }

            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}

int fs::Tracer::get_fan_fd() const {
    return fan_fd_;
}

fs::Tracer::~Tracer() {
    if (fan_fd_ >= 0) close(fan_fd_);
}

fs::PathNode::PathNode() {
    flag_ = 0;
}

fs::PathNode::~PathNode() {
    for (std::map<char, fs::PathNode*>::iterator it = this->children_.begin(); it != this->children_.end(); ++it) {
        if (it->second != NULL) {
            if (it->second != this) delete it->second;
            it->second = NULL;
        }
    }
}

fs::PathNode* fs::PathNode::walk(const char *p, int ttl) {
    if (ttl == 0) return this;

    fs::PathNode *next;
    if (children_.count(*p) == 0) {
        next = children_[*p] = new fs::PathNode();
    } else {
        next = children_[*p];
    }
    return next->walk(p + 1, ttl - 1);
}


void fs::PathNode::set(const char path[], int flag, int wildcard) {
    int ttl = strlen(path);
    if (!wildcard) ttl += 1;  // including the last char ('\0')
    walk(path, ttl)->flag_ = flag;
}

int fs::PathNode::get(const char path[]) {
    const char *p = &path[0];
    const char *p_end = path + strlen(path) + 1;
    int flag = 0;

    for (fs::PathNode *current = this; current;) {
        if (current->flag_) flag = current->flag_;
        if (p == p_end) break;  // just processed the last char, '\0'
        __typeof(current->children_.begin()) it = current->children_.find(*p++);
        if (it == current->children_.end()) current = NULL; else current = it->second;
    }
    return flag;
}
