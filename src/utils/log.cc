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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include "log.h"

#ifndef NDEBUG
int DEBUG_ENABLED = 0;
int DEBUG_PID = 0;
int DEBUG_TIMESTAMP = 0;
int DEBUG_PROGRESS = 0;
double DEBUG_START_TIME = now();
FILE *flog = stderr;


static char log_lock_path[80];

static char* get_log_lock_path() {
    if (!log_lock_path[0]) {
        // create lock file
        snprintf(log_lock_path, sizeof log_lock_path, "/tmp/.%lu-log.lock", (unsigned long)getpid());
        int fd = open(log_lock_path, O_CREAT | O_TRUNC | O_WRONLY, 0444);
        if (fd != -1) close(fd);
    }
    return log_lock_path;
}

ScopedLogLock::ScopedLogLock() {
    if (!DEBUG_ENABLED) return;
    this->fd_ = -1;
    int fd = open(get_log_lock_path(), O_RDONLY);
    if (fd < 0) return;
    if (flock(fd, LOCK_EX) == 0) {
        this->fd_ = fd;
    } else {
        close(fd);
    }
}

ScopedLogLock::~ScopedLogLock() {
    if (!DEBUG_ENABLED) return;
    int fd = this->fd_;
    if (fd < 0) return;
    flock(fd, LOCK_UN);
    close(fd);
}

class DebugEnvDetector {
    public:
    DebugEnvDetector() {
        if (getenv("DEBUG") != 0) {
            ::DEBUG_ENABLED = 1;
            ::DEBUG_START_TIME = now();
            ::DEBUG_PID = readEnvBool("DEBUG_PID");
            ::DEBUG_PROGRESS = readEnvBool("DEBUG_PROGRESS");
            ::DEBUG_TIMESTAMP = readEnvBool("DEBUG_TIMESTAMP");
        } else {
            ::DEBUG_PROGRESS = readEnvBool("DEBUG_PROGRESS", 0);
        }
    }

    ~DebugEnvDetector() {
        if (log_lock_path[0]) unlink(log_lock_path);
    }

    static int readEnvBool(const char * const name, int fallback = 1) {
        const char * const s = getenv(name);
        if (s == NULL) return fallback;
        switch (*s) {
            case 't': case 'T': case '1': case 'y': case 'Y':
                return 1;
            case 'f': case 'F': case '0': case 'n': case 'N':
                return 0;
        }
        return fallback;
    }
} _debug_env_detect;
#endif
