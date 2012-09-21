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

#include "test.h"
#include <cstdio>

int DEBUG = 1;
int test::total_case = 0;
int test::failed_case = 0;

__attribute__((destructor)) void test::print_result() {
    test::term::set(test::term::attr::BOLD, test::term::fg::WHITE);
    printf("SUMMARY\n");
    test::term::set();
    printf("  %-4d CHECKS\n", test::total_case);
    if (test::failed_case == 0) {
        test::term::set(test::term::attr::BOLD, test::term::fg::GREEN);
        printf("  ALL  PASSED\n");
    } else {
        test::term::set(test::term::attr::BOLD, test::term::fg::RED);
        printf("  %-4d FAILED\n", test::failed_case);
    }
    test::term::set();
}

void test::term::set(int attr, int fg, int bg) {
    printf("\x1b[%d;%d;%dm", attr, fg, bg);
}

void test::term::set(int attr, int fg) {
    printf("\x1b[%d;%dm", attr, fg);
}

void test::term::set(int attr) {
    printf("\x1b[%dm", attr);
}

int main(int argc, char const *argv[]) {
    return 0;
}
