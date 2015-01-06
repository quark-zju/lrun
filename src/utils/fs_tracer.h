#pragma once

#include <sys/fanotify.h>

namespace fs {

    /**
     * a thin wrapper around fanotify
     */
    class Tracer {
        public:
            typedef int tracer_cb(const char path[], int fd, pid_t pid, uint64_t mask);

            Tracer(int fan_fd = -1);

            // fanotify_init
            int init(unsigned int flags, unsigned int event_f_flags, tracer_cb callback);

            // fanotify_mark
            int mark(const char path[], unsigned int flags, uint64_t mask);

            void process_events();

            int get_fan_fd() const;

            ~Tracer();

        private:
            int fan_fd_;
            tracer_cb *cb_;
    };
}
