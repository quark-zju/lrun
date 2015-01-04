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
