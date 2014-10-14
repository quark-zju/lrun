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

#include "seccomp.h"
namespace sc = lrun::seccomp;

#if defined(LIBSECCOMP_VERSION_MAJOR) && LIBSECCOMP_VERSION_MAJOR <= 2 && LIBSECCOMP_VERSION_MAJOR > 0
# define LIBSECCOMP_ENABLED
#else
# undef LIBSECCOMP_ENABLED
#endif

#undef DO_EXPAND
#undef EXPAND

#ifdef LIBSECCOMP_ENABLED
extern "C" {
#include <seccomp.h>
#include <sys/syscall.h>
}

#include <map>
#include <string>
#include <cerrno>

int sc::apply_simple_filter(const char * const filter, sc::action_t action) {
#define CHAR_FOR_SCMP_ACTION(act) (act == SCMP_ACT_KILL ? 'k' : (act == SCMP_ACT_ALLOW ? 'a' : 'e'))
    int rc = -1;

    scmp_filter_ctx ctx = NULL;
    uint32_t scmp_action = SCMP_ACT_KILL;
    uint32_t scmp_action_inverse = SCMP_ACT_ALLOW;

    // decide default action and default inverse action
    switch(action) {
        case DEFAULT_KILL:
            scmp_action = SCMP_ACT_KILL;
            scmp_action_inverse = SCMP_ACT_ALLOW;
            break;
        case DEFAULT_EPERM:
            scmp_action = SCMP_ACT_ERRNO(EPERM);
            scmp_action_inverse = SCMP_ACT_ALLOW;
            break;
        case OTHERS_KILL:
            scmp_action = SCMP_ACT_ALLOW;
            scmp_action_inverse = SCMP_ACT_KILL;
            break;
        case OTHERS_EPERM:
            scmp_action = SCMP_ACT_ALLOW;
            scmp_action_inverse = SCMP_ACT_ERRNO(EPERM);
            break;
    }

    // vars needed to parse filter
    char buf[32];
    size_t name_len = 0;
    uint8_t priority = 255;
    const char *p;

    // init seccomp filter
    INFO("seccomp init: %c '%s'", CHAR_FOR_SCMP_ACTION(scmp_action), filter);
    ctx = seccomp_init(scmp_action);
    if (ctx == NULL) {
        ERROR("seccomp_init");
        goto err;
    }

    // add seccomp rules
    p = filter - 1;
    do {
        ++p;
        if (*p != ',' && *p != ':' && *p != 0) { // not a separator
            if (name_len < (sizeof(buf) - 2)) buf[name_len++] = *p;
            continue;
        }

        if (name_len == 0) continue;

        buf[name_len] = 0;
        name_len = 0;

        // resolve syscall number
        int no = __NR_SCMP_ERROR;
        if (buf[0] >= '1' && buf[0] <= '9') {
            // syscall number
            sscanf(buf, "%d", &no);
        } else {
            // syscall name
            no = seccomp_syscall_resolve_name(buf);
        }

        if (no == __NR_SCMP_ERROR || no < 0) {
            WARNING("syscall not found: '%s'", buf);
            continue;
        }

        uint32_t act = scmp_action_inverse;

        // user specified additional action
        if (*p == ':') {
            switch (*(++p)) {
                case 'k':
                    act = SCMP_ACT_KILL;
                    break;
                case 'a':
                    act = SCMP_ACT_ALLOW;
                    break;
                case 'e':
                    act = SCMP_ACT_ERRNO(EPERM);
                    break;
            }
        }

        INFO("seccomp rule '%s' (%d), priority = %hhu, action = %c", buf, no, priority, CHAR_FOR_SCMP_ACTION(act));
        rc = seccomp_syscall_priority(ctx, no, priority);
        if (rc < 0) {
            ERROR("seccomp_syscall_priority");
            goto err;
        }

        rc = seccomp_rule_add(ctx, act, no, 0);
        if (rc < 0) {
            ERROR("seccomp_rule_add");
            goto err;
        }

        if (priority > 0) priority--;
    } while (*p);

    INFO("applying seccomp rules");
    rc = seccomp_load(ctx);

    if (rc) {
        ERROR("seccomp_load");
        goto err;
    }

    rc = 0;

err:
    if (ctx) seccomp_release(ctx);
    return rc == 1 ? -1 : rc;
#undef CHAR_FOR_SCMP_ACTION
}

int sc::supported() {
    return 1;
}

#else

# warning libseccomp version 1.x or 2.x not found

int sc::apply_simple_filter(const char * const filter, sc::action_t action) {
    return 1;
}

int sc::supported() {
    return 0;
}

#endif


