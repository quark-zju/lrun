#pragma once

#include <regex.h>

class RegEx {
    public:
        RegEx(const char re[]);
        ~RegEx();

        bool match(const char str[]);

    private:
        regex_t re_;
};
