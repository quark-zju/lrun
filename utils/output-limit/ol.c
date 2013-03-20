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

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

// Limit output size
//
// Usage:
//   Before:
//     proc1 | proc2
//   After:
//     proc1 | ol [output_limit_in_bytes=16777216] | proc2
//
// If proc1 writes more than limited, ol will output to fd 3 saying
//   EXCEED OUTPUT
// and exits with code 1
//
// If proc2 exits earlier and proc1 is writing, no SIGPIPE to proc1

const char OLE[] = "EXCEED OUTPUT\n";

#ifndef PIPE_BUF
# define PIPE_BUF 4096
#endif

int main(int argc, char const *argv[]) {
    long limit = ((unsigned long)((long)-1) >> 1);
    ssize_t size = 0;
    char buf[PIPE_BUF];

    if (argc > 1) limit = atol(argv[1]);

    signal(SIGPIPE, SIG_IGN);

    while ((size = read(0, buf, sizeof(buf))) > 0) {
        limit -= (long) size;
        if (__builtin_expect(limit < 0, 0)) {
            write(3, OLE, sizeof OLE);
            write(2, OLE, sizeof OLE);
            exit(1);
        }
        write(1, buf, size);
    }

    return 0;
}

