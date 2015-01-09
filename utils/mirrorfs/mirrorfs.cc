////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2012-2015 Jun Wu <quark@zju.edu.cn>
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

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "utils/fs.h"
#include "utils/ensure.h"


using std::list;
using std::string;
using std::vector;
using std::set;


#ifndef MIRRORFS_ROOT
// /run seems to be the de facto standard, instead of /var/run
// http://lwn.net/Articles/436012/
# define MIRRORFS_ROOT "/run/lrun/mirrorfs"
#endif
#define VERSION "v0.1"

#define describe_step(...) { if (fstep_log) { fprintf(fstep_log, __VA_ARGS__); fprintf(fstep_log, "\n"); } }


static bool dry_run;
static FILE * fstep_log;
static int meaningful_errno;

static int do_fs_mount_bind(const string& from, const string& to, bool is_dir) {
    describe_step("%s %s %s", is_dir ? "mount-bind-dir" : "mount-bind-file", from.c_str(), to.c_str());
    if (dry_run) return 0;

    int ret;
    ret = fs::mount_bind(from, to);
    meaningful_errno = errno;
    if (ret) return ret;

    ret = fs::mount_set_shared(to, MS_PRIVATE | MS_REC);
    meaningful_errno = errno;
    if (ret) return ret;

    unsigned long flags = MS_RDONLY | MS_NOSUID | MS_BIND;
    ret = fs::remount(to, flags);
    meaningful_errno = errno;

    return ret;
}

static int do_fs_umount(const string& path) {
    describe_step("umount %s", path.c_str());
    if (dry_run) return 0;

    int ret;
    ret = fs::umount(path, /* lazy */ false);
    meaningful_errno = errno;
    return ret;
}

static int do_fs_mkdir(const string& path) {
    describe_step("mkdir %s", path.c_str());
    if (dry_run) return 0;

    int ret;
    ret = ::mkdir(path.c_str(), 0555);
    meaningful_errno = errno;
    return ret;
}

static int do_fs_rmdir(const string& path) {
    describe_step("rmdir %s", path.c_str());
    if (dry_run) return 0;

    int ret;
    ret = ::rmdir(path.c_str());
    meaningful_errno = errno;
    return ret;
}

static int do_fs_touch(const string& path) {
    describe_step("touch %s", path.c_str());
    if (dry_run) return 0;

    int ret;
    // following mount --bind will overwrite mode,
    // 0444 is just temporary.
    ret = ::creat(path.c_str(), 0444);
    meaningful_errno = errno;
    if (ret == -1) {
        return -1;
    } else {
        close(ret);
        return 0;
    }
}

static int do_fs_symlink(const string& existing_path, const string& new_path) {
    describe_step("symlink %s -> %s", new_path.c_str(), existing_path.c_str());
    if (dry_run) return 0;

    int ret;
    ret = ::symlink(existing_path.c_str(), new_path.c_str());
    meaningful_errno = errno;
    return ret;
}

static int do_fs_unlink(const string& path) {
    describe_step("unlink %s", path.c_str());
    if (dry_run) return 0;

    int ret;
    ret = ::unlink(path.c_str());
    meaningful_errno = errno;
    return ret;
}

static int do_fs_renameat(const string& at, const string& from, const string& to) {
    describe_step("renameat %s: %s -> %s", at.c_str(), from.c_str(), to.c_str());
    if (dry_run) return 0;

    // to should not exist. renameat2 with RENAME_NOREPLACE helps but is not
    // available across common glibcs.
    if (fs::is_accessible(fs::join(at, to))) {
        meaningful_errno = EEXIST;
        return 2;
    }

    int dirfd = open(at.c_str(), O_RDONLY);
    meaningful_errno = errno;
    if (dirfd < 0) return dirfd;

    int ret;
    ret = ::renameat(dirfd, from.c_str(), dirfd, to.c_str());
    meaningful_errno = errno;
    close(dirfd);
    return ret;
}


struct Step {
    virtual int up() { return 0; }
    virtual int down() { return 0; }
};

struct StepMountBind : Step {
    StepMountBind(const string& from, const string& to, bool is_dir) : from(from), to(to), is_dir(is_dir) {}

    int up() {
        return do_fs_mount_bind(from, to, is_dir);
    }

    int down() {
        return do_fs_umount(to);
    }

    string from, to;
    bool is_dir;
};

struct StepMkdir : Step {
    StepMkdir(const string& path) : path(path) {}

    int up() {
        return do_fs_mkdir(path);
    }

    int down() {
        return do_fs_rmdir(path);
    }

    string path;
};

struct StepTouch : Step {
    StepTouch(const string& path) : path(path) {}

    int up() {
        return do_fs_touch(path);
    }

    int down() {
        return do_fs_unlink(path);
    }

    string path;
};

struct StepSymlink : Step {
    StepSymlink(const string& existing_path, const string& new_path) : existing_path(existing_path), new_path(new_path) {}

    int up() {
        return do_fs_symlink(this->existing_path, this->new_path);
    }

    int down() {
        return do_fs_unlink(this->new_path);
    }

    string existing_path, new_path;
};

struct StepRename : Step {
    StepRename(const string& dir, const string& from, const string& to) : from(from), to(to), dir(dir) {}

    int up() {
        return do_fs_renameat(this->dir, this->from, this->to);
    }

    int down() {
        return do_fs_renameat(this->dir, this->to, this->from);
    }

    string from, to, dir;
};



static string config_path;
static string name;
static bool backward;
static vector<Step*> steps;
static string dest;

static void print_version(const char arg0[]) {
    fprintf(stdout, "mirrorfs %s\n", VERSION);
    exit(0);
}

static void print_help(const char arg0[]) {
    fprintf(stdout,
            "Mirror some parts of current filesystem for chroot purpose.\n"
            "\n"
            "Usage:\n"
            "  mirrorfs [--verbose] [--dry-run] --name $name --setup $config-path\n"
            "  mirrorfs [--verbose] [--dry-run] --name $name --teardown $config-path\n"
            "  mirrorfs --list\n"
            "  mirrorfs --help\n"
            "  mirrorfs --version\n"
            "\n"
            "Config file is consist of multiple lines, each line can be:\n"
            "  - mkdir $path\n"
            "    mkdir -p $dest/$path\n"
            "    the directory will be owned by root:root and have mode 0555.\n"
            "  - mirror $path\n"
            "    mount --bind $path $dest/$path -o ro\n"
            "    if $path is a directory, it must end with '/'\n"
            "    $path can also be a glob pattern (ex. \"foo-*.{c,cc}\")\n"
            "\n"
            "Notes:\n"
            "  - $dest will be %s/$name\n"
            "  - if $path does not exist (or glob pattern matches nothing),\n"
            "    it will be ignored but a warning will be printed.\n"
            "  - if $path is (or matches) a symbol link, an equivalent symbol\n"
            "    link will be created.\n"
            "  - $dest will be printed if --setup completes without errors\n"
            , MIRRORFS_ROOT);
    exit(0);
}

static void list_names() {
    list<string> names = fs::list(MIRRORFS_ROOT);
    for (const auto& name: names) {
        printf("%s\n", name.c_str());
    }
    exit(0);
}

static void show_root() {
    printf("%s", MIRRORFS_ROOT);
    exit(0);
}

static void parse_arguments(int argc, char const *argv[]) {
    enum {
        NORMAL = 0,
        SET_CONFIG_PATH,
        SET_NAME,
    } state = NORMAL;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        switch (state) {
            case NORMAL:
                if (arg == "--help") {
                    print_help(argv[0]);
                } else if (arg == "--version") {
                    print_version(argv[0]);
                } else if (arg == "--setup") {
                    backward = false;
                    state = SET_CONFIG_PATH;
                    continue;
                } else if (arg == "--teardown") {
                    backward = true;
                    state = SET_CONFIG_PATH;
                    continue;
                } else if (arg == "--name") {
                    state = SET_NAME;
                    continue;
                } else if (arg == "--dry-run") {
                    dry_run = true;
                    fstep_log = stdout;
                } else if (arg == "--verbose") {
                    fstep_log = stdout;
                } else if (arg == "--quiet") {
                    fstep_log = NULL;
                } else if (arg == "--list") {
                    list_names();
                } else if (arg == "--show-root") {
                    show_root();
                }
                break;
            case SET_NAME:
                name = arg;
                break;
            case SET_CONFIG_PATH:
                config_path = arg;
                break;
        }
        state = NORMAL;
    }

    // check required params
    if (config_path.empty() || name.empty()) print_help(argv[0]);
    if (name.find("..") != string::npos || name.find("/") != string::npos) {
        fprintf(stderr, "--name %s is unsafe\n", name.c_str());
        exit(1);
    }
}

static void ensure_absolute_expanded_path(string path) {
    if (!fs::is_absolute(path)) {
        fprintf(stderr, "'%s' is an absolute path\n", path.c_str());
        exit(1);
    }
    if (fs::expand(path) != path) {
        fprintf(stderr, "'%s' is not expanded ('%s')\n", path.c_str(), fs::expand(path).c_str());
        exit(1);
    }
}

// paths = {"/bin", "/usr/bin", "/foo"}
// path_inside_paths("/", paths)         # false
// path_inside_paths("/bin", paths)      # true
// path_inside_paths("/bin/sh", paths)   # true
// path_inside_paths("/bin2", paths)     # false
// path_inside_paths("/usr/lib", paths)  # false
// path_inside_paths("/zoo", paths)      # false
static bool is_path_inside_paths(const string& path, const set<string>& paths) {
    if (paths.empty()) return false;

    auto it = paths.lower_bound(path);
    if (it == paths.end()) --it;
    for (int i = 0; i < 2; ++i) {
        if (*it == "/") return true;
        if (*it + "/" == (path + "/").substr(0, it->length() + 1)) return true;
        if (it == paths.begin()) break;
        --it;
    }
    return false;
}

static set<string> mounted_paths;
static set<string> mkdired_paths = {"/", ""};

static void add_mkdir_step(string path) {
    if (mkdired_paths.count(path)) return;

    ensure(fs::is_absolute(path));

    vector<string> paths;
    while (!path.empty() && path != "/") {
        if (mkdired_paths.count(path)) break;
        paths.push_back(path);
        mkdired_paths.insert(path);
        path = fs::dirname(path);
    }

    // explicitly mkdir, do not use mkdir -p, which is not reversible
    for (int i = (int)paths.size() - 1; i >= 0; --i) {
        steps.push_back(new StepMkdir(fs::join(dest, paths[i])));
    }
}

static void ensure_path_outside_mounted_paths(const string& path) {
    if (is_path_inside_paths(path, mounted_paths)) {
        fprintf(stderr, "%s is inside a previous mount point\n", path.c_str());
        exit(1);
    }
}

static void add_mount_bind_step(string path, bool is_dir) {
    ensure(fs::is_absolute(path));
    ensure_path_outside_mounted_paths(path);

    if (is_dir) {
        add_mkdir_step(path);
    } else {
        add_mkdir_step(fs::dirname(path));
        steps.push_back(new StepTouch(fs::join(dest, path)));
    }
    steps.push_back(new StepMountBind(path, fs::join(dest, path), is_dir));
    mounted_paths.insert(path);
}

static void add_symlink_step(string existing_path, string new_path) {
    ensure(fs::is_absolute(existing_path));
    ensure(fs::is_absolute(new_path));
    ensure_path_outside_mounted_paths(new_path);

    add_mkdir_step(fs::dirname(new_path));
    steps.push_back(new StepSymlink(fs::relative_path(existing_path, new_path), fs::join(dest, new_path)));
}

static void command_to_steps(string command, string argument) {
    if (argument.empty() || command.empty()) return;

    if (command == "mirror") {
        ensure_absolute_expanded_path(argument);

        if (argument.data()[argument.length() - 1] == '/') {
            // argument is a directory
            string path = argument.substr(0, argument.length() - 1);
            if (path.empty()) path = "/";
            if (!fs::is_dir(path)) {
                fprintf(stderr, "warning: %s is not a diretory and will be ignored\n", path.c_str());
                return;
            }
            if (fs::is_symlink(path)) {
                string target = fs::resolve(path);
                if (!target.empty()) add_symlink_step(target, path);
            } else {
                add_mount_bind_step(path, /* is_dir */ true);
            }
        } else if (fs::is_accessible(argument, F_OK)) {
            if (fs::is_dir(argument)) {
                fprintf(stderr, "warning: %s is a diretory, you should put a '/' at the end of it to explicitly match a directory. for now it will be ignored\n", argument.c_str());
                return;
            }
            // argument is a path (also a glob pattern)
            add_mount_bind_step(argument, /* is_dir */ false);
        } else {
            // argument is a glob pattern
            list<string> paths = fs::glob(argument);
            bool empty = true;
            for (const string& path: paths) {
                if (fs::is_regular_file(path)) {
                    empty = false;
                    add_mount_bind_step(path, /* is_dir */ false);
                } else if (fs::is_symlink(path)) {
                    string target = fs::resolve(path);
                    if (!target.empty()) {
                        empty = false;
                        add_symlink_step(target, path);
                    }
                }
            }
            if (empty) {
                fprintf(stderr, "warning: %s does not match any files and is ignored\n", argument.c_str());
            }
        }
    } else if (command == "mkdir") {
        string path = argument;
        if (path.length() > 1 && argument.data()[argument.length() - 1] == '/') {
            path = path.substr(0, path.length() - 1);
        }
        ensure_absolute_expanded_path(path);
        add_mkdir_step(path);
    }
}

static string to_hex(unsigned long value) {
    static char table[] = "0123456789abcdefg";
    string result;
    while (value > 0) {
        result = string() + table[value % 16] + result;
        value /= 16;
    }
    return result;
}

static void config_file_to_steps(string path) {
    FILE * fp = fopen(path.c_str(), "r");
    if (!fp) {
        fprintf(stderr, "cannot read %s\n", path.c_str());
        return;
    }

    enum {
        COMMAND = 0,
        ARGUMENT,
        COMMENT
    } state = COMMAND;

    // write to a temp location so that we can make finally use "rename" to
    // make the whole operations "atomic".
    string temp_name = "__" + name + "." + to_hex((unsigned long)getpid());
    dest = fs::join(MIRRORFS_ROOT, temp_name);
    steps.push_back(new StepMkdir(dest));

    string command, argument;
    for (int ch; (ch = fgetc(fp)) != EOF;) {
        switch (state) {
            case COMMENT:
                if (ch == '\n') {
                    state = COMMAND;
                }
                break;
            case COMMAND:
                if (ch == '#' && command.empty()) {
                    state = COMMENT;
                } else if (isspace(ch)) {
                    if (!command.empty()) state = ARGUMENT;
                } else {
                    command += (char)ch;
                }
                break;
            case ARGUMENT:
                if (ch == '\n') {
                    command_to_steps(command, argument);
                    command = argument = "";
                    state = COMMAND;
                } else {
                    argument += (char)ch;
                }
                break;
        }
    }
    fclose(fp);

    // last command (if the file does not end with '\n')
    command_to_steps(command, argument);

    dest = fs::join(MIRRORFS_ROOT, name);
    steps.push_back(new StepRename(MIRRORFS_ROOT, temp_name, name));
}

static void become_root() {
    if (geteuid() != 0 || setuid(0) || setgid(0)) {
        fprintf(stderr, "root required. (current euid = %d, uid = %d)\n", geteuid(), getuid());
        exit(1);
    }
}

const int STEP_BEGIN_IGNORE = -1;
const int STEP_MAX = 256;

static void check_step_limit() {
    if (steps.size() > STEP_MAX) {
        fprintf(stderr, "too many steps (%d > %d)\n", (int)steps.size(), STEP_MAX);
        exit(1);
    }
}

static void run_steps(bool backward = false, int step_begin = STEP_BEGIN_IGNORE) {
    int i_begin = backward ? (int)steps.size() - 1 : 0;
    int i_end = backward ? -1 : (int)steps.size();
    int i_step = backward ? -1 : 1;

    if (STEP_BEGIN_IGNORE != step_begin) i_begin = step_begin;

    {
        int ret;
        fs::ScopedFileLock(MIRRORFS_ROOT);
        for (int i = i_begin; i != i_end; i += i_step) {
            if (backward) {
                ret = steps[i]->down();
                if (ret != 0) {
                    fprintf(stderr, "failed: %s\n", strerror(meaningful_errno));
                }
            } else {
                ret = steps[i]->up();
                if (ret != 0) {
                    fprintf(stderr, "failed: %s\n", strerror(meaningful_errno));
                    fprintf(stderr, "start rollback\n");
                    run_steps(/* backward */ true, i);
                    exit(3);
                }
            }
        }
        describe_step("done");
    }
}

int main(int argc, char const *argv[]) {
    parse_arguments(argc, argv);
    config_file_to_steps(config_path);
    if (!dry_run) {
        check_step_limit();
        become_root();
        fs::mkdir_p(MIRRORFS_ROOT, /* mode */ 0755);
    }
    run_steps(backward);
    if (!dry_run && !backward) {
        printf("%s\n", dest.c_str());
    }
    return 0;
}
