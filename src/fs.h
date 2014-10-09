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

#include <string>
#include <sys/stat.h>
#include <sys/mount.h>

// If kernel does not support shared mount, MS_{REC,PRIVATE,SHARED} are missing
#ifndef MS_REC
# define MS_REC 0
#endif

#ifndef MS_SHARED
# define MS_SHARED 0
#endif

#ifndef MS_PRIVATE
# define MS_PRIVATE 0
#endif

#ifndef MS_SLAVE
# define MS_SLAVE 0
#endif

#ifndef MS_RELATIME
# define MS_RELATIME 0
#endif

namespace lrun {
    namespace fs {
        /**
         * Path to file containing mounts information
         * Typically, it is "/proc/mounts"
         */
        extern const char * const MOUNTS_PATH;
        extern const char * const PROC_PATH;

        /**
         * Cgroup filesystem type name: "cgroup"
         */
        extern const char * const TYPE_CGROUP;

        /**
         * tmpfs type name: "tmpfs"
         */
        extern const char * const TYPE_TMPFS;

        /**
         * Write string content to file
         * @param  path         file path
         * @param  content      content to write
         * @return  0           success
         *         -1           file can not open
         *         -2           write error (or not complete)
         */
        int write(const std::string& path, const std::string& content);

        /**
         * Read from file
         * @param  path         file path
         * @param  max_length   max length to read (not include '\0')
         * @return string       content read, empty if failed
         */
        std::string read(const std::string& path, size_t max_length = 1024);

        /**
         * if path is a directory
         * @return   1          is a directory
         *           0          not a directory
         */
        int is_dir(const std::string& path);

        /**
         * mkdir -p
         * @param  dir          dir
         * @param  mode         dir mode
         * @return >=0          the count of directories maked
         *          -1          error
         */
        int mkdir_p(const std::string& dir, const mode_t mode = 0755);

        /**
         * rm -rf
         * @param  path         path
         * @return  0           success
         *         -1           error
         */
        int rm_rf(const std::string& path);

        /**
         * chmod
         * @return  0           success
         *         -1           failed
         */
        int chmod(const std::string& path, const mode_t mode);

        /**
         * mount --bind -o nosuid
         * @param   src         source location
         * @param   dest        target path
         * @reutrn  0           success
         *         -1           failed
         *         -2           failed to set readonly
         */
        int mount_bind(const std::string& src, const std::string& dest);

        /**
         * mount -t tmpfs
         * @param   dest        target path
         * @param   max_size    size in bytes, note that this can be rounded to block size
         * @reutrn  0           success
         *          other       failed
         */
        int mount_tmpfs(const std::string& dest, size_t max_size, mode_t mode = 0777);

        /**
         * mount --make-*
         * @param   dest        target path
         * @param   type        (MS_SLAVE | MS_PRIVATE | MS_SHARED) | [MS_REC]
         * @return  0           success
         *          other       failed
         */
        int mount_set_shared(const std::string& dest, int type = MS_SLAVE);

        /**
         * umount
         * @param   dest        target path
         * @parm    lazy        true: MNT_DETACH
         * @return  0           success
         *         -1           fail
         */
        int umount(const std::string& dest, bool lazy = true);
    }
}

