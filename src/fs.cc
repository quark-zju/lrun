////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2012 WU Jun <quark@zju.edu.cn>
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

#include "fs.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <dirent.h>

namespace fs = lrun::fs;
using std::string;

const char * const fs::PROC_PATH = "/proc";
const char * const fs::MOUNTS_PATH = "/proc/mounts";
const char * const fs::TYPE_CGROUP = "cgroup";
const char * const fs::TYPE_TMPFS  = "tmpfs";

int fs::write(const string& path, const string& content) {
    FILE* fp = fopen(path.c_str(), "w");
    if (!fp) return -1;

    size_t wmb = fwrite(content.c_str(), content.size(), 1, fp);
    fclose(fp);

    return wmb ? 0 : -2;
}

string fs::read(const string& path, size_t max_length) {
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) return "";

    char buffer[max_length + 1];

    int nread = fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);

    buffer[max_length] = 0;
    if (nread >= 0 && (size_t)nread < max_length) buffer[nread] = 0;

    return buffer;
}

int fs::is_dir(const string& path) {
    DIR *dir = opendir(path.c_str());
    if (dir) {
        closedir(dir);
        return 1;
    }
    return 0;
}

int fs::mkdir_p(const string& dir, const mode_t mode) {
    // do nothing if directory exists
    if (is_dir(dir)) return 0;

    // make each dirs
    const char * head = dir.c_str();
    int nmkdir = 0;
    for (const char * p = head; *p; ++p) {
        if (*p == '/' && p > head) {
            int e = mkdir(dir.substr(0, p - head).c_str(), mode);
            if (e == 0) ++nmkdir;
        }
    }
    int e = mkdir(dir.c_str(), mode);

    if (e < 0 /* && errno != EEXIST */) return -1;
    return nmkdir;
}

int fs::rm_rf(const string& path) {
    // TODO use more efficient implement like coreutils/rm

    // try to remove single file or an empty dir
    if (unlink(path.c_str()) == 0) return 0;
    if (rmdir(path.c_str()) == 0) return 0;

    // try to list path contents
    struct dirent **namelist = 0;
    int nlist = scandir(path.c_str(), &namelist, 0, alphasort);

    for (int i = 0; i < nlist; ++i) {
        const char * name = namelist[i]->d_name;
        // skip . and ..
        if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) fs::rm_rf(path + "/" + name);
        free(namelist[i]);
    }

    if (namelist) free(namelist);

    // try remove empty dir again
    if (rmdir(path.c_str()) == 0) return 0;

    // otherwise something must went wrong
    return -1;
}

int fs::chmod(const std::string& path, const mode_t mode) {
    return ::chmod(path.c_str(), mode);
}

int fs::mount_bind(const string& src, const string& dest) {
    int e = mount(src.c_str(),
                  dest.c_str(),
                  NULL,
                  MS_BIND | MS_NOSUID,
                  NULL);
    return e;
}

int fs::mount_tmpfs(const string& dest, size_t max_size, mode_t mode) {
    char tmpfs_opts[256];
    snprintf(tmpfs_opts, sizeof tmpfs_opts, "size=%lu,mode=0%o", (unsigned long)max_size, (unsigned int)mode);

    int e = mount(NULL,
                 dest.c_str(),
                 TYPE_TMPFS,
                 MS_NOSUID | MS_NODEV | MS_SLAVE,
                 tmpfs_opts);
    return e;
}

int fs::mount_set_shared(const string& dest, int type) {
    return mount(NULL, dest.c_str(), NULL, type, NULL);
}

int fs::umount(const string& dest, bool lazy) {
    if (lazy) {
        return umount2(dest.c_str(), MNT_DETACH);
    } else {
        return umount(dest.c_str());
    }
}
