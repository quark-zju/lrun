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


// old compiler does not like for (auto i : v)
#if (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
# define FOR_EACH_CONST(i, v) \
    for (const auto& i : v)
# define FOR_EACH(i, v) \
    for (auto& i : v)
#else
# define VAR_CONCAT_(a, b) a ## b
# define VAR_CONCAT(a, b) VAR_CONCAT_(a ## _, b)
# define VAR_UNIQUE(a) VAR_CONCAT(a, __LINE__)
# define FOR_EACH(i, v) \
    __typeof(v.begin()) VAR_UNIQUE(_i) = v.begin(); \
    int VAR_UNIQUE(_fes) = 0; \
    for (; VAR_UNIQUE(_fes) = 1, VAR_UNIQUE(_i) != v.end(); ++VAR_UNIQUE(_i)) \
    for (__typeof(*(v.begin()))& i = *VAR_UNIQUE(_i); VAR_UNIQUE(_fes); VAR_UNIQUE(_fes) = 0)
# define FOR_EACH_CONST(i, v) \
    __typeof(v.begin()) VAR_UNIQUE(_i) = v.begin(); \
    int VAR_UNIQUE(_fes) = 0; \
    for (; VAR_UNIQUE(_fes) = 1, VAR_UNIQUE(_i) != v.end(); ++VAR_UNIQUE(_i)) \
    for (const __typeof(*(v.begin()))& i = *VAR_UNIQUE(_i); VAR_UNIQUE(_fes); VAR_UNIQUE(_fes) = 0)
#endif
