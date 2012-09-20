

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

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

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

