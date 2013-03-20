////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2012-2013 WU Jun <quark@zju.edu.cn>
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

#include "cgroup.h"
#include "test.h"

using namespace lrun;

TESTCASE(get_path) {
    CHECK(!Cgroup::base_path(Cgroup::CG_CPUACCT, true).empty());
}

TESTCASE(create_and_destroy) {
    Cgroup cg = Cgroup::create("testcreate");
    CHECK(cg.valid());
    CHECK(cg.destroy() == 0);
    CHECK(cg.valid() == false);
}

TESTCASE(set_properties) {
    Cgroup cg = Cgroup::create("testsetprop");
    // FIXME assume no swap here
    CHECK(cg.set(Cgroup::CG_MEMORY, "memory.limit_in_bytes", "1048576") == 0);
    CHECK(cg.get(Cgroup::CG_MEMORY, "memory.limit_in_bytes") == "1048576\n");
    CHECK(cg.reset_usages() == 0);
    CHECK(cg.destroy() == 0);
}

TESTCASE(create_use_exist) {
    Cgroup cg1 = Cgroup::create("testexist");
    Cgroup cg2 = Cgroup::create("testexist");
    CHECK(cg1.valid());
    CHECK(cg2.valid());
    CHECK(cg2.destroy() == 0);
    CHECK(!cg1.valid());
}


