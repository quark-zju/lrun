////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2012-2014 Jun Wu <quark@zju.edu.cn>
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

#include "seccomp.h"
#include <string>
#include <map>
#include <set>
#include <list>
#include <sys/resource.h>

// Old system does not have RLIMIT_RTTIME, define it as invalid
#ifndef RLIMIT_RTTIME
# define RLIMIT_RTTIME RLIMIT_NLIMITS
#endif

namespace lrun {
    class Cgroup {
        public:

            // Cgroup static methods

            /**
             * cgroup subsystem ids
             */
            enum subsys_id_t {
                CG_CPUACCT = 0,
                CG_MEMORY  = 1,
                CG_DEVICES = 2,
                CG_FREEZER = 3,
            };

            /**
             * cgroup subsystem names
             */
            static const char subsys_names[4][8];
            static const int SUBSYS_COUNT = sizeof(subsys_names) / sizeof(subsys_names[0]);

            /**
             * get cgroup subsystem id from name
             * @param   name            cgroup subsystem name
             * @return  >=0             cgroup subsystem id
             *          -1              subsystem id not found
             */
            static int subsys_id_from_name(const char * const name);

            /**
             * get cgroup mounted path
             * @param   create_on_need  mount cgroup if not mounted
             * @return  cgroup mounted path (first one in mount table)
             */
            static std::string base_path(subsys_id_t subsys_id, bool create_on_need = true);


            /**
             * create a cgroup, use existing if possible
             * @return  Cgroup object
             */
            static Cgroup create(const std::string& name);

            /**
             * @return  1           exist
             *          0           not exist
             */
            static int exists(const std::string& name);

            /**
             * @param   subsys_id   cgroup subsystem id
             * @param   name        group name
             * @return  full path   "#{path_}/#{name}"
             */
            static std::string path_from_name(subsys_id_t subsys_id, const std::string& name);

            /**
             * @param   subsys_id   cgroup subsystem id
             * @return  full path
             */
            std::string subsys_path(subsys_id_t subsys_id = CG_CPUACCT) const;

            // Cgroup low level methods

            /**
             * kill all processes and destroy this cgroup
             * @return 0            success
             *         other        failed
             */
            int destroy();

            /**
             * set a cgroup property
             * @param   property    property
             * @param   value       value
             * @return  0           success
             *         <0           failed
             */
            int set(subsys_id_t subsys_id, const std::string& property, const std::string& value);

            /**
             * get property
             * @param   property    property
             * @param   max_length  max length to read (not include '\0')
             * @return  string      readed property, empty if fail
             */
            std::string get(subsys_id_t subsys_id, const std::string& property, size_t max_length = 255) const;

            /**
             * set a cgroup property to the same value as parent
             * @param   property    property
             * @return  0           success
             *         <0           failed
             */
            int inherit(subsys_id_t subsys_id, const std::string& property);

            /**
             * attach a process
             * @param   pid         process id to attach
             * @return  0           success
             *         <0           failed
             */
            int attach(pid_t pid);

            /**
             * check if Cgroup is invalid
             * @return  true        valid
             *          false       invalid
             */
            bool valid() const;


            /**
             * scan group processes and update output usage
             */
            void update_output_count();

            /**
             * return output usage
             * @return  bytes      output usage
             */
            long long output_usage() const;

            /**
             * get pid list
             * @return  pids       a list of pids in the cgroup
             */
            std::list<pid_t> get_pids();

            // Cgroup high level methods

            /**
             * test if the cgroup has zero processes attached
             * @return  1           yes, the cgroup has no processes attached
             *          0           no, the cgroup has processes attached
             */
            int empty();

            /**
             * kill all tasks until no more tasks alive.
             * the method will block until all tasks are confirmed gone.
             */
            void killall();

            /**
             * use freezer cgroup subsystem to freeze processes
             * if freeze is non-zero, the method will block until
             * all processes are frozen.
             * freezer may attempt increase memory limit and
             * enable oom to get rid of D state processes.
             *
             * @param   freeze     0: unfreeze. other: freeze
             */
            void freeze(int freeze = 1);

            /**
             * get current memory usage
             * @return  memory usage in bytes
             */
            long long memory_current() const;

            /**
             * get peak memory usage
             * @return  memory usage in bytes
             */
            long long memory_peak() const;

            /**
             * get memory limit
             * @return  memory limit in bytes
             */
            long long memory_limit() const;

            /**
             * get cpu usage
             * @return  cpu usage in seconds
             */
            double cpu_usage() const;

            /**
             * set memory usage limit
             * @param   bytes       limit, no limit if bytes <= 0
             * @return  0           success
             *         <0           failed
             */
            int set_memory_limit(long long bytes);

            /**
             * restart cpuacct and memory max_usage_in_bytes
             * @return  0           success
             *         <0           failed
             */
            int reset_usages();

            /**
             * limit devices to null, zero, full, random and urandom
             *
             * @return  0           success
             *         <0           failed
             */
            int limit_devices();

            /**
             * structure used for forked child
             */
            struct spawn_arg {
                int clone_flags;            // additional clone flags
                char * const * args;        // exec args
                int argc;                   // exec argc
                uid_t uid;                  // uid (should not be 0)
                gid_t gid;                  // gid (should not be 0)
                mode_t umask;               // umask
                int nice;                   // nice
                bool no_new_privs;          // prctl PR_SET_NO_NEW_PRIVS
                int sockets[2];             // for sync between child and parent
                std::string chroot_path;    // chroot path, empty if not need to chroot
                std::string chdir_path;     // chdir path, empty if not need to chdir
                std::string syscall_list;   // syscall whitelist or blacklist
                seccomp::action_t syscall_action;
                                            // syscall default action
                std::list<std::pair<std::string, long long> > tmpfs_list;
                                            // [(dest, bytes)] mount tmpfs in child FS (after chroot)
                std::map<std::string, std::string> bindfs_list;
                                            // [(dest, src)] mount bind in child FS (before chroot)
                std::map<std::string, unsigned long> remount_list;
                                            // [(dest, flags)] remount list (before chroot)
                std::list<std::string> cmd_list;
                                            // cp file list
                std::set<int> keep_fds;     // Do not close these fd
                std::map<int, rlim_t> rlimits;
                                            // [resource, value] rlimit list
                int reset_env;              // Do not inherit env
                int remount_dev;            // Recreate a minimal dev
                std::list<std::pair<std::string, std::string> > env_list;
                                            // environment variables whitelist
            };

            /**
             * spawn child process and exec inside cgroup
             * child process is in other namespace in FS, PID, UTS, IPC, NET
             * child process is attached to cgroup just before exec
             * @param   arg         swapn arg, @see struct spawn_arg
             * @return  pid         child pid, negative if failed
             */
            pid_t spawn(spawn_arg& arg);

        private:

            Cgroup();

            /**
             * cgroup directory name
             */
            std::string name_;

            /**
             * count output bytes
             */
            std::map<long, long long> output_counter_;

            /**
             * cached init pid (only valid if pid namespace is enabled)
             */
            pid_t init_pid_;

            /**
             * cached paths
             */
            static std::string subsys_base_paths_[SUBSYS_COUNT];
    };
}

