#include "now.h"
#include <sys/time.h>


double now() {
    struct timeval t;
    gettimeofday(&t, 0);
    return t.tv_usec / 1e6 + t.tv_sec;
}
