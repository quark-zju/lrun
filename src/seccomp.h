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

#pragma once

#include "common.h"

#include <cinttypes>

extern "C" {
#include <seccomp.h>
}

namespace lrun {
    namespace seccomp {
        enum action_t {
            DEFAULT_KILL = 1,
            DEFAULT_EPERM,
            OTHERS_KILL,
            OTHERS_EPERM,
        };

        struct Rules {
            scmp_filter_ctx ctx;

            /**
             * @param  default_action  default action, one of: ACTION_EPERM, ACTION_KILL, ACTION_ALLOW
             */
            Rules(action_t default_action = DEFAULT_KILL, scmp_datum_t execve_arg1 = 0);

            ~Rules();

            /**
             * Add rules using a string filter.
             *
             * STRING_FILTER  := SYSCALL_RULE | STRING_FILTER + ',' + SYSCALL_RULE
             * SYSCALL_RULE   := SYSCALL_NAME + EXTRA_ARG_RULE + EXTRA_ACTION
             * EXTRA_ARG_RULE := '' | '[' + ARG_RULES + ']'
             * ARG_RULES      := ARG_RULE | ARG_RULES + ',' + ARG_RULE
             * ARG_RULE       := ARG_NAME + ARG_OP1 + NUMBER | ARG_NAME + ARG_OP2 + '=' + NUMBER
             * ARG_NAME       := 'a' | 'b' | 'c' | 'd' | 'e' | 'f'
             * ARG_OP1        := '==' | '!=' | '>' | '<' | '>=' | '<='
             * ARG_OP2        := '&'
             * EXTRA_ACTION   := '' | ':k' | ':e' | ':a'
             *
             * Note:
             *  - put most frequently used syscall first.
             *
             * Examples:
             *  - read,write,open,exit,brk
             *
             * @param  filter          syscall filter string.
             *
             * @return int      0      successful
             *                  1      syntax error
             *                  2      not compatible with previous rules
             *                  3      libseccomp error
             */
            int add_simple_filter(const char * const filter);

            /**
             * Apply the rules.
             * Do not use this for multiple times.
             *
             * @return int      0      successful
             *                  1      ignored. (libcseccomp does not exist)
             *              other      other error
             */
            int apply();

        private:
            uint32_t scmp_action_;
            uint32_t scmp_action_inverse_;
            // allow execve if its arg1 is this value, the special case
            scmp_datum_t execve_arg1_;
        };

        /**
         * Check seccomp is supported or not
         * @return int      1       seccomp is supported
         *                  0       seccomp is not supported
         */
        int supported();
    }
}

