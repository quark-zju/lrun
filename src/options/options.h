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

#pragma once

#include <string>
#include "../config.h"
#include "../cgroup.h"
#include "../utils/fs_tracer.h"

namespace lrun {
    namespace options {
        void help();
        void help_syscalls();
        void help_fopen_filter();
        void version();
        void fopen_filter(const std::string& condition, const std::string& action);

        void parse(int argc, char * argv[], lrun::MainConfig& config);

        namespace fstracer {
            // fstracer need cgroup information to:
            // - check if a process belongs to this cgroup
            // - reset timer
            void setup(lrun::Cgroup& cgroup, const std::string& chroot_path);

            // start tracer process. call this after setup()
            void start();

            // stop tracer process and free related resources. call this after start()
            void stop();

            // call this before start(), after setup()
            int apply_settings();

            bool alive();
            bool started();
        }
    }
}
