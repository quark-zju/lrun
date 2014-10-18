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

#include "test.h"
#include "strconv.h"

using namespace lrun::strconv;

static long long m = 9223372036854775807LL;

TESTCASE(to_numbers) {
    CHECK(to_double("-2.00") == (double)-2);
    CHECK(to_long("4123.1") == (long)4123);
    CHECK(to_long("abcdef") == (long)0);
    CHECK(to_longlong("9223372036854775807") == m);
}

TESTCASE(from_numbers) {
    CHECK(from_double(2.560, 0) == "3");
    CHECK(from_double(2.560, 1) == "2.6");
    CHECK(from_long(-123) == "-123");
    CHECK(from_longlong(-m) == "-9223372036854775807");
}

TESTCASE(to_bool) {
    CHECK(to_bool("True") == true);
    CHECK(to_bool("true") == true);
    CHECK(to_bool("") == false);
    CHECK(to_bool("false") == false);
    CHECK(to_bool("1") == true);
    CHECK(to_bool("0") == false);
}

TESTCASE(to_bytes) {
    CHECK(to_bytes("1234") == 1234);
    CHECK(to_bytes("1099511627776b") == 1099511627776);
    CHECK(to_bytes("-1234") == -1234);
    CHECK(to_bytes("1k") == 1024);
    CHECK(to_bytes("-2K") == -2048);
    CHECK(to_bytes("0.5mb") == 524288);
    CHECK(to_bytes("0.5GB") == 536870912);
}
