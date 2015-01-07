#include <sys/types.h>
#include "log.h"
#include "re.h"


RegEx::RegEx(const char re[]) {
    int e = regcomp(&re_, re, REG_EXTENDED | REG_NOSUB);
    if (e) {
        char buf[120];
        buf[0] = 0;
        regerror(e, &re_, buf, sizeof(buf));
        FATAL("can not compile regex \"%s\" (%d: %s)", re, e, buf);
    }
}

RegEx::~RegEx() {
    regfree(&re_);
}

bool RegEx::match(const char str[]) {
    return regexec(&re_, str, 0, NULL, 0) == 0;
}
