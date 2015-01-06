#pragma once

#include "../config.h"  // for lrun::MainConfig

namespace lrun {
    namespace options {
        void help();
        void help_syscalls();
        void version();

        void parse(int argc, char * argv[], lrun::MainConfig& config);
    }
}
