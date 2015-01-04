#include <vector>
#include <map>
#include <string>
#include "cgroup.h"

namespace lrun {

    struct MainConfig {
        Cgroup::spawn_arg arg;
        double cpu_time_limit;
        double real_time_limit;
        long long memory_limit;
        long long output_limit;
        bool enable_devices_whitelist;
        bool enable_network;
        bool enable_pidns;
        bool pass_exitcode;
        bool write_result_to_3;
        useconds_t interval;
        std::string cgname;
        Cgroup* active_cgroup;

        std::vector<gid_t> groups;
        std::map<std::pair<Cgroup::subsys_id_t, std::string>, std::string> cgroup_options;

        MainConfig();

        // check config permissions. print errors and exit
        // if anything is wrong.
        void check();
    };
}
