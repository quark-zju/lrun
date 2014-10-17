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
#include <sys/syscall.h>
}

#include <map>
#include <vector>
#include <string>
#include <cerrno>

using std::string;


static void get_scmp_action(uint32_t& scmp_action, uint32_t& scmp_action_inverse, sc::action_t action) {
    // decide default action and default inversed action
    switch (action) {
        case sc::DEFAULT_KILL:
            scmp_action = SCMP_ACT_KILL;
            scmp_action_inverse = SCMP_ACT_ALLOW;
            break;
        case sc::DEFAULT_EPERM:
            scmp_action = SCMP_ACT_ERRNO(EPERM);
            scmp_action_inverse = SCMP_ACT_ALLOW;
            break;
        case sc::OTHERS_KILL:
            scmp_action = SCMP_ACT_ALLOW;
            scmp_action_inverse = SCMP_ACT_KILL;
            break;
        case sc::OTHERS_EPERM:
            scmp_action = SCMP_ACT_ALLOW;
            scmp_action_inverse = SCMP_ACT_ERRNO(EPERM);
            break;
    }
}

sc::Rules::Rules(action_t default_action, scmp_datum_t execve_arg1) {
    execve_arg1_ = execve_arg1;
    ctx = NULL;
    get_scmp_action(scmp_action_, scmp_action_inverse_, default_action);
    ctx = seccomp_init(scmp_action_);
    if (ctx == NULL) ERROR("seccomp_init");
}

// return length
static int read_uint64(const char * s, uint64_t& result) {
    int len = 0;
    static const int MAX_LEN = 1023;
    while ((s[len] >= '0' && s[len] <= '9') && len < MAX_LEN) ++len;
    char * buf = (char *) malloc(len + 1);
    memcpy(buf, s, len);
    buf[len] = 0;
    result = 0;
    sscanf(buf, "%" SCNu64, &result);
    free(buf);
    return len;
}

static const int execve_no = SCMP_SYS(execve);

int sc::Rules::add_simple_filter(const char * const filter) {
    if (!ctx) return 2;

    // vars needed to parse filter string
    uint8_t priority = 255;
    bool execve_handled = false;

    enum {
        SYSCALL_NAME = 0,
        ARG_NAME,
        ARG_OP,
        ARG_RHS,
        ARG_RHS2,
    } state = SYSCALL_NAME;
    // SYSCALL_NAME
    string            current_syscall_name;
    // EXTRA_ACTION
    uint32_t          current_action;
    // ARG_RULE
    unsigned int      current_arg;
    enum scmp_compare current_op;
    uint64_t          current_arg_rhs1, current_arg_rhs2;
    // ARG_RULES
    std::vector<struct scmp_arg_cmp> current_arg_array;
    // loop
    const char *p;

#   define reset_arg_rule {\
        current_arg = current_arg_rhs1 = current_arg_rhs2 = 0; current_op = SCMP_CMP_EQ;}
#   define reset_syscall_rule {\
        current_syscall_name = ""; current_action = scmp_action_inverse_;\
        reset_arg_rule; current_arg_array.clear(); }
#   define push_arg_rule {\
        current_arg_array.push_back(SCMP_CMP(current_arg, current_op, current_arg_rhs1, current_arg_rhs2));\
        reset_arg_rule; }

    reset_syscall_rule;

    // add seccomp rules
    for (char c = *(p = filter); ; c = *(++p)) {
        if (c == 0) c = ',';  // easy way to handle last char
        if (c == '[') {
            // start ARG_RULE(S), must after SYSCALL_NAME
            if (state == SYSCALL_NAME) {
                state = ARG_NAME;
                reset_arg_rule;
            } else goto syntax_error;
        } else if (c == ']') {
            if (state == ARG_RHS || state == ARG_RHS2) {
                push_arg_rule;
                state = SYSCALL_NAME;
            } else goto syntax_error;
        } else if (c == ',') {
            if (state == SYSCALL_NAME) {
                // add the syscall to seccomp ctx
                // resolve syscall number first
                int no = __NR_SCMP_ERROR;
                if (current_syscall_name[0] >= '0' && current_syscall_name[0] <= '9') {
                    // syscall number
                    sscanf(current_syscall_name.c_str(), "%d", &no);
                } else {
                    // syscall name
                    no = seccomp_syscall_resolve_name(current_syscall_name.c_str());
                }
                if (no == __NR_SCMP_ERROR) {
                    WARNING("Skip unresolved syscall name: '%s'", current_syscall_name.c_str());
                } else {
                    INFO("seccomp rule for syscall '%s' (%d): %u args", current_syscall_name.c_str(), no, (unsigned)current_arg_array.size());
                    int ret;
                    ret = seccomp_syscall_priority(ctx, no, priority);
                    if (ret) {
                        ERROR("seccomp_syscall_priority");
                        return 3;
                    }
                    if (priority) --priority;
                    // the special case: execve
                    if (no == execve_no) {
                        execve_handled = true;
                        if (scmp_action_ != SCMP_ACT_ALLOW && current_action != SCMP_ACT_ALLOW && current_arg_array.empty()) {
                            // the user is trying to add execve to a blacklist
                            // remove our execve from blacklist
                            current_arg_array.push_back(SCMP_CMP(1, SCMP_CMP_NE, execve_arg1_));
                        } else if (!current_arg_array.empty() || current_action != SCMP_ACT_ALLOW) {
                            WARNING("can not guarntee execve by lrun is allowed");
                        }
                    }
                    ret = seccomp_rule_add_array(ctx, current_action, no, current_arg_array.size(), current_arg_array.data());
                    if (ret != 0) {
                        ERROR("seccomp_rule_add_array");
                        return 3;
                    }
                }
                reset_syscall_rule;
            } else if (state == ARG_RHS || state == ARG_RHS2) {
                push_arg_rule;
                state = ARG_NAME;
            } else goto syntax_error;
        } else if (c == ':') {
            // read EXTRA_ACTION (2 chars)
            c = *(++p);
            if (c == 'k') {
                current_action = SCMP_ACT_KILL;
            } else if (c == 'e') {
                current_action = SCMP_ACT_ERRNO(EPERM);
            } else if (c == 'a') {
                current_action = SCMP_ACT_ALLOW;
            } else goto syntax_error;
        } else if (c == '<' || c == '>' || c == '=' || c == '!' || c == '&') {
            bool next_equal = (*(p + 1) == '=');
            if (state == ARG_OP) {
                // read ARG_OP (1 to 2 chars)
                if (c == '<') {
                    current_op = next_equal ? SCMP_CMP_LE : SCMP_CMP_LT;
                } else if (c == '>') {
                    current_op = next_equal ? SCMP_CMP_GE : SCMP_CMP_GT;
                } else if (c == '=') {
                    current_op = SCMP_CMP_EQ;
                } else if (c == '!') {
                    current_op = SCMP_CMP_NE;
                } else if (c == '&') {
                    current_op = SCMP_CMP_MASKED_EQ;
                }
                state = ARG_RHS;
            } else if (state == ARG_RHS && current_op == SCMP_CMP_MASKED_EQ && c == '=') {
                // read ARG_RHS2
                state = ARG_RHS2;
            } else goto syntax_error;
            if (next_equal) ++p;
        } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c =='_')) { // a to z, 0 to 9 ...
            if (state == SYSCALL_NAME) {
                // SYSCALL_NAME
                current_syscall_name += c;
            } else if (state == ARG_NAME) {
                // read ARG_NAME (1 char)
                if (c >= 'a' && c <= 'f') {
                    current_arg = c - 'a';
                    state = ARG_OP;
                } else goto syntax_error;
            } else if (state == ARG_RHS || state == ARG_RHS2) {
                // ARG_RHS (NUMBER)
                // special case: if current_op is SCMP_CMP_MASKED_EQ, allow a&b==c syntax
                if (c >= '0' && c <= '9') {
                    int len = read_uint64(p, state == ARG_RHS ? current_arg_rhs1 : current_arg_rhs2);
                    p += len - 1;
                } else goto syntax_error;
            } else goto syntax_error;
        } else goto syntax_error;
        if (*p == 0) break;
    }

    if (!execve_handled && scmp_action_ != SCMP_ACT_ALLOW) {
        // a whitelist with no execve yet, add ours
        reset_syscall_rule;
        current_arg_array.push_back(SCMP_CMP(1, SCMP_CMP_EQ, execve_arg1_));
        int ret = seccomp_rule_add_array(ctx, SCMP_ACT_ALLOW, execve_no, current_arg_array.size(), current_arg_array.data());
        if (ret) WARNING("can not add lrun execve to syscall whitelist");
    }

    return 0;
syntax_error:
    errno = 0;
    ERROR("Syscall filter syntax error at %d: %s", (int)(p - filter), filter);
    return 1;
}

int sc::Rules::apply() {
    if (!ctx) return 2;
    int rc = seccomp_load(ctx);
    if (rc) ERROR("seccomp_load");
    return rc;
}

sc::Rules::~Rules() {
    if (ctx) {
        seccomp_release(ctx);
        ctx = NULL;
    }
}

int sc::supported() {
    return 1;
}

#else

sc::Rules::Rules(action_t action) {}
int sc::Rules::add_simple_filter(const char * const filter) { return 3; }
int sc::Rules::apply() { return 1; }
sc::Rules::~Rules() {}

# warning lrun is compiled without libseccomp support

int sc::supported() {
    return 0;
}

#endif


