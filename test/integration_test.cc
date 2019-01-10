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

#include "test.h"
#include <cstdlib>
#include <cstdio>
#include <cassert>
#include <string>

using std::string;

#define TMP "/tmp"
#define TMP_C TMP "/lrun-t.c"
#define TMP_EXE TMP "/lrun-t"


inline void test_c_code(string code,  string expect, string lrun_flags = "") {
    FILE *fp = fopen(TMP_C, "w");
    static string last_code;
    if (last_code.empty() || last_code != code) {
        assert(fp);
        fprintf(fp, "%s", code.c_str());
        fclose(fp);
        assert(system("gcc " TMP_C " -o " TMP_EXE " >/dev/null 2>/dev/null") == 0);
        last_code = code;
    }
    string log_path = getenv("TEST_LOG") ? getenv("TEST_LOG") : "";
    string cmd = string("lrun ")
        + (getenv("LRUN_DEBUG") ? " --debug " : "")
        + lrun_flags + " -- " TMP_EXE " 3>&1 ";
    if (log_path.empty()) {
        cmd += "1>>/dev/null 2>&1";
    } else {
        cmd += "1>>'" + string(getenv("TEST_LOG")) + "' 2>&1";
        FILE *fp = fopen(getenv("TEST_LOG"), "a");
        fprintf(fp, "\n----\nCode: %s\nRunning: %s\n", code.c_str(), cmd.c_str());
        fclose(fp);
    }
    fp = popen(cmd.c_str(), "r");
    assert(fp);
    string result;
    while (!feof(fp)) {
        char buf[1024];
        size_t bytes = fread(buf, 1, sizeof(buf) - 1, fp);
        buf[bytes] = 0;
        result += buf;
    }
    pclose(fp);
    CHECK(result.find(expect) != string::npos, 5, "code, result, expect, flags:", code.c_str(), result.c_str(), expect.c_str(), lrun_flags.c_str());
}

void test_cmd(string cmd, string expect, string lrun_flags = "") {
    cmd = string("lrun ") + lrun_flags + " -- " + cmd + " 3>&1 1>/dev/null 2>/dev/null";
    FILE* fp = popen(cmd.c_str(), "r");
    assert(fp);
    string result;
    while (!feof(fp)) {
        char buf[1024];
        size_t bytes = fread(buf, 1, sizeof(buf) - 1, fp);
        buf[bytes] = 0;
        result += buf;
    }
    pclose(fp);
    CHECK(result.find(expect) != string::npos, 5, "cmd, result, expect, flags:", cmd.c_str(), result.c_str(), expect.c_str(), lrun_flags.c_str());
}


static char flags[2][32] = {
    "--isolate-process true",
    "--isolate-process false" };

#define for_each_flag(new_flag)\
    for (struct {size_t i; string flag;} c = {0, ""}; c.i < sizeof(flags) / sizeof(flags[0]); ++c.i) if ((c.flag = string(new_flag) + " " + flags[c.i]), 1)

TESTCASE(exit_code) {
    for_each_flag("") {
        test_c_code("main(){return 2;}",
                    "EXITCODE 2",
                    c.flag);
    }
}

TESTCASE(real_time_limit) {
    for_each_flag("--max-real-time 0.05") {
        test_cmd("sleep 30",
                 "EXCEED   REAL_TIME",
                 c.flag);
    }
}

TESTCASE(signal) {
    for_each_flag("") {
        test_c_code("main(c){return 1/(c-1);}",
                    "TERMSIG  8",  // SIGFPE
                    c.flag);
        test_c_code("main(int c){char*p=main;p[-1]=c;return 0;}",
                    "TERMSIG  11",  // SIGSEGV
                    c.flag);
        // this one may fail if pid namespace is not fully supported
        // and --isolate-process is true.
        // do not report a bug if you are using linux < 3.8
        test_c_code("main(){kill(getpid(), 33);}",
                    "TERMSIG  33",
                    c.flag);
    }
}

TESTCASE(bad_progs) {
    if (getenv("SKIP_SLOW_TESTS")) return;
    for_each_flag("--max-cpu-time 0.2") {
        test_c_code("main(){while(1);return 0;}",
                    "EXCEED   CPU_TIME",
                    c.flag);
        test_c_code("main(){while(1)fork();return 0;}",
                    "EXCEED   CPU_TIME",
                    c.flag);
    }
    for_each_flag("--max-memory 64000000") {
        test_c_code("i,j,s=2048;main(){char *p;for(;++i<1<<30;){p=malloc(s);for(j=0;++j<s;)p[j]=j;}return 0;}",
                    "EXCEED   MEMORY",
                    c.flag);
        test_c_code("i,j,s=2048;main(){char *p;for(;++i<1<<30;){fork();p=malloc(s);for(j=0;++j<s;)p[j]=j;}return 0;}",
                    "EXCEED   MEMORY",
                    c.flag);
    }
    for_each_flag("--max-output 1280000") {
        test_c_code("char c[8000];main(i){for(i=0;i<sizeof(c)-1;++i)c[i]='a';while(1)puts(c);}",
                    "EXCEED   OUTPUT",
                    c.flag);
    }
}

TESTCASE(syscall_filter) {
    string create_userns_code =
            "#define _GNU_SOURCE\n#include<sched.h>\n#include<stdio.h>\n#include<errno.h>\n"
            "int foo(void* a){return 0;}\n"
            "main(a){char stack[8192];a=clone(foo, stack + sizeof(stack), CLONE_FS, 0);exit(a>0?0:errno);}";
    test_c_code(create_userns_code, "EXITCODE 0");

    // CLONE_FS = 0x00000200
    test_c_code(create_userns_code, "EXITCODE 1", "--syscalls '!clone[a&512==512]'");
    test_c_code(create_userns_code, "SIGNALED 1", "--syscalls '!clone[a&512==512]:k'");

    // test execve special case handling
    test_cmd("true", "EXITCODE 0", "--syscalls '!execve'");
    test_cmd("true", "EXITCODE 0", "--syscalls 'access,arch_prctl,brk,close,exit_group,fstat,mmap,mprotect,munmap,open,openat,read,exit'");
    test_cmd("true", "EXITCODE 0", "--syscalls '!execve:a'");
    test_cmd("true", "EXITCODE 0", "--syscalls '!open:a'");
    test_cmd("env true", "EXITCODE 1" /* 126 */, "--syscalls '!execve'");
    test_cmd("env true", "EXITCODE 1" /* 125 */, "--syscalls 'access,arch_prctl,brk,close,exit_group,fstat,mmap,mprotect,munmap,open,openat,read,exit'");
}
