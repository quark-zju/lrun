#include "macros.h"
#include <stdlib.h>
#include <sys/time.h>

int DEBUG_ENABLED = 0;
int DEBUG_PID = 0;
int DEBUG_TIMESTAMP = 0;
int DEBUG_PROGRESS = 0;
double DEBUG_START_TIME = 0;

class DebugEnvDetector {
    public:
    DebugEnvDetector() {
        if (getenv("DEBUG") != 0) {
            ::DEBUG_ENABLED = 1;
            ::DEBUG_PID = readEnvBool("DEBUG_PID");
            ::DEBUG_TIMESTAMP = readEnvBool("DEBUG_TIMESTAMP");
            ::DEBUG_PROGRESS = readEnvBool("DEBUG_PROGRESS");
            ::DEBUG_START_TIME = NOW;
        }
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

double now() {
    struct timeval t;
    gettimeofday(&t, 0);
    return t.tv_usec / 1e6 + t.tv_sec;
}

