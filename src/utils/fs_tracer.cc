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

#include <cstdlib>
#include <unistd.h>
#include <cassert>
#include <cstdio>
#include "fs_tracer.h"


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

            close(metadata->fd);
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
