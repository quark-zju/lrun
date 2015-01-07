#pragma once

#include <string>
#include "../config.h"
#include "../cgroup.h"
#include "../utils/fs_tracer.h"

namespace lrun {
    namespace options {
        void help();
        void help_syscalls();
        void help_fopen_filter();
        void version();
        void fopen_filter(const std::string& condition, const std::string& action);

        void parse(int argc, char * argv[], lrun::MainConfig& config);

        namespace fstracer {
            // start tracer thread and apply pending settings
            // fstracer need cgroup information to:
            // - check if a process belongs to this cgroup
            // - reset timer
            void start(lrun::Cgroup& cgroup, const std::string& chroot_path);
            void stop();

            // options::fopen_filter does not actually apply any settings.
            void apply_settings();

            bool alive();
            bool started();
        }
    }
}
