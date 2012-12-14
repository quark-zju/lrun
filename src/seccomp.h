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

#pragma once

#include "macros.h"

namespace lrun {
    namespace seccomp {
        enum action_t {
            DEFAULT_KILL = 1,
            DEFAULT_EPERM,
            OTHERS_KILL,
            OTHERS_EPERM,
        };

        /**
         * Apply simple syscall filter.
         * Filter string format:
         *  - syscall names splitted by ','
         *  - put most frequently used syscall first.
         * Filter string examples:
         *      read,write,open,exit,brk
         *
         * @param  filter          syscall filter string.
         * @param  default_action  default action, one of: ACTION_EPERM, ACTION_KILL, ACTION_ALLOW
         *
         * @return int      0      successful
         *                  1      ignored. (libcseccomp does not exist)
         *              other      other error.
         */
        int apply_simple_filter(const char * const filter, action_t default_action = DEFAULT_KILL);

        /**
         * Check seccomp is supported or not
         * @return int      1       seccomp is supported
         *                  0       seccomp is not supported
         */
        int supported();
    }
}

