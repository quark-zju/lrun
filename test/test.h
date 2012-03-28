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
#include <cstdio>

namespace test {
    extern int total_case;
    extern int failed_case;
    extern void print_result();

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
    __attribute__((constructor)) void auto_test_ ## name() { \
        test::term::set(test::term::attr::BOLD, test::term::fg::WHITE); \
        printf("TEST CASE: %s\n", #name); \
        test::term::set(); \
        test_ ## name(); \
    } \
    void test_ ## name()
        

#define CHECK(cond) \
{ \
    test::total_case++; \
    test::term::set(); \
    if (cond) { \
        test::term::set(test::term::attr::RESET, test::term::fg::GREEN); \
        printf("  PASS\n"); \
        test::term::set(); \
    } else { \
        test::term::set(test::term::attr::RESET, test::term::fg::RED); \
        printf("  FAILED: " __FILE__ " # %d : " #cond "\n", __LINE__); \
        test::failed_case++; \
        test::term::set(); \
    } \
}

 
