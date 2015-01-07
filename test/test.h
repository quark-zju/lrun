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
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace test {
    extern int total_case;
    extern int failed_case;
    extern int at_new_line;
    extern void new_line();
    extern void print_result();
    extern void print_strings(int n = 0, ...);

    namespace term {
        namespace attr {
            const int RESET      = 0;
            const int BOLD       = 1;
            const int UNDERSCORE = 4;
            const int BLINK      = 5;
            const int REVERSE    = 7;
            const int CONCEALED  = 8;
        }

        namespace fg {
            const int  BLACK     = 30;
            const int  RED       = 31;
            const int  GREEN     = 32;
            const int  YELLOW    = 33;
            const int  BLUE      = 34;
            const int  MAGENTA   = 35;
            const int  CYAN      = 36;
            const int  WHITE     = 37;
        }

        namespace bg {
            const int  BLACK     = 40;
            const int  RED       = 41;
            const int  GREEN     = 42;
            const int  YELLOW    = 43;
            const int  BLUE      = 44;
            const int  MAGENTA   = 45;
            const int  CYAN      = 46;
            const int  WHITE     = 47;
        }

        extern void set(int attr, int fg);
        extern void set(int attr, int fg, int bg);
        extern void set(int attr = attr::RESET);
    }
}

#define TESTCASE(name) \
    void test_ ## name(); \
    __attribute__((constructor(65535))) void auto_test_ ## name() { \
        if (getenv("TESTCASE_FOCUS") && strcmp(getenv("TESTCASE_FOCUS"), #name) != 0) return;\
        test::term::set(); \
        test::new_line(); \
        printf("[%s] ", #name); \
        fflush(stdout); \
        test::at_new_line = 0; \
        test_ ## name(); \
    } \
    void test_ ## name()


#define CONCAT_HELPER(a,b) a ## b
#define CONCAT(a,b) CONCAT_HELPER(a,b)
#define CHECK(cond, ...) \
    test::total_case++; \
    test::term::set(); \
    int CONCAT(_chk_, __LINE__) = (int)(cond); \
    if (CONCAT(_chk_, __LINE__)) { \
        test::term::set(test::term::attr::RESET, test::term::fg::GREEN); \
        printf("."); \
        test::term::set(); \
        fflush(stdout); \
        test::at_new_line = 0; \
    } else { \
        test::new_line(); \
        test::term::set(test::term::attr::BOLD, test::term::fg::WHITE, test::term::bg::RED); \
        printf(" FAILED "); \
        test::term::set(); \
        printf(" at " __FILE__ " # %d : " #cond "\n", __LINE__); \
        test::failed_case++; \
        test::print_strings(__VA_ARGS__);\
        fflush(stdout); \
        test::at_new_line = 1; \
    } \
    if (!CONCAT(_chk_, __LINE__))
