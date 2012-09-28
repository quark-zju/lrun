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
            ::DEBUG_START_TIME = NOW;
            ::DEBUG_PID = readEnvBool("DEBUG_PID");
            ::DEBUG_PROGRESS = readEnvBool("DEBUG_PROGRESS");
            ::DEBUG_TIMESTAMP = readEnvBool("DEBUG_TIMESTAMP");
        } else {
            ::DEBUG_PROGRESS = readEnvBool("DEBUG_PROGRESS", 0);
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

