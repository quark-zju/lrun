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

#include <vector>
#include <map>
#include <string>
#include "cgroup.h"

namespace lrun {

    struct MainConfig {
        Cgroup::spawn_arg arg;
        double cpu_time_limit;
        double real_time_limit;
        long long memory_limit;
        long long output_limit;
        bool enable_devices_whitelist;
        bool enable_network;
        bool enable_pidns;
        bool pass_exitcode;
        bool write_result_to_3;
        useconds_t interval;
        std::string cgname;
        Cgroup* active_cgroup;

        std::vector<gid_t> groups;
        std::map<std::pair<Cgroup::subsys_id_t, std::string>, std::string> cgroup_options;

        MainConfig();

        // check config permissions. print errors and exit
        // if anything is wrong.
        void check();
    };
}
