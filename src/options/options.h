#pragma once

#include "../config.h"    // for lrun::MainConfig
#include "../utils/fs_tracer.h"

namespace lrun {
    namespace options {
        void help();
        void help_syscalls();
        void version();

        void parse(int argc, char * argv[], lrun::MainConfig& config);

        namespace fstracer {
            void start();
            void stop();
            bool dead();

            fs::Tracer * get_tracer();
        }
    }
}
