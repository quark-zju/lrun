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

#include "test.h"
#include "../src/utils/fs.h"
#include <cstdlib>
#include <errno.h>
#include <unistd.h>

#define TMP "/tmp"

TESTCASE(join) {
    CHECK(fs::join("", "") == "");
    CHECK(fs::join("a", "") == "a");
    CHECK(fs::join("", "b") == "b");
    CHECK(fs::join("a", "b") == "a/b");
    CHECK(fs::join("a/", "b") == "a/b");
    CHECK(fs::join("a", "/b") == "a/b");
    CHECK(fs::join("a/", "/b") == "a/b");
}

TESTCASE(is_absolute) {
    CHECK(!fs::is_absolute(""));
    CHECK(fs::is_absolute("/a/b"));
    CHECK(!fs::is_absolute(".."));
}

TESTCASE(expand) {
    CHECK(fs::expand("../../a") == "a");
    CHECK(fs::expand("/a/../b/c/../d") == "/b/d");
    CHECK(fs::expand("//////../../a/b/c/././../c//d") == "/a/b/c/d");
    CHECK(fs::expand("..//////../../a/b/c/././../c//d") == "a/b/c/d");
    CHECK(fs::expand("..././.../.") == ".../...");
    CHECK(fs::expand("") == "");
    CHECK(fs::expand("/") == "/");
    CHECK(fs::expand("/..") == "/");
    CHECK(fs::expand("../") == "");
}

TESTCASE(resolve) {
    system("touch " TMP "/_r1");
    system("ln -s " TMP "/_r1 " TMP "/_r2");
    system("ln -s " TMP "/_r2 " TMP "/_r3");
    system("ln -s " TMP "/_rnone " TMP "/_rn");
    system("rm -f " TMP "/_rnone");
    CHECK(fs::resolve(TMP) == TMP);
    CHECK(fs::resolve(TMP "/./_r1") == TMP "/_r1");
    CHECK(fs::resolve(TMP "/././_r2") == TMP "/_r1");
    CHECK(fs::resolve(TMP "/./_r3") == TMP "/_r1");
    CHECK(fs::resolve(TMP "/./_rn") == "");  // cannot resolve because _rnone is deleted
    CHECK(fs::resolve(TMP "/.." TMP "/./_r1") == TMP "/_r1");
    CHECK(fs::resolve(TMP "/.." TMP "/./_r2") == TMP "/_r1");
    CHECK(fs::resolve(TMP "/.." TMP "/./_r3") == TMP "/_r1");
    CHECK(fs::resolve(TMP "/.." TMP "/./_rn") == "");
    system("rm -f " TMP "/_r1 " TMP "/_r2 " TMP "/_r3 " TMP "/_rn");
}

TESTCASE(is_accessible) {
    system("touch " TMP "/_a1");
    system("rm -f " TMP "/_an");
    CHECK(fs::is_accessible(TMP));
    CHECK(fs::is_accessible("./.", R_OK, TMP));
    CHECK(fs::is_accessible(TMP "/_a1"));
    CHECK(!fs::is_accessible(TMP "/_an"));
    CHECK(fs::is_accessible("./_a1", R_OK, TMP));
    CHECK(!fs::is_accessible("./_an", R_OK, TMP));
    CHECK(fs::is_accessible(TMP "/_a1", R_OK, TMP));
    CHECK(!fs::is_accessible(TMP "/_an", R_OK, TMP));
    CHECK(fs::is_accessible("/dev/null", W_OK));
    CHECK(fs::is_accessible("/bin/bash", R_OK));
    CHECK(!fs::is_accessible("/proc/self/io", W_OK));
    CHECK(!fs::is_accessible("/proc/self/io", X_OK));
    CHECK(fs::is_accessible(TMP, X_OK));
    system("rm -f " TMP "/_a1");
}

TESTCASE(mkdir_p) {
    // mkdir -p
    CHECK(fs::mkdir_p(TMP "/_t/1/2/3") >= 0);
    CHECK(system("test -e " TMP "/_t/1/2/3") == 0);

    // mkdir on wrong path
    system("touch " TMP "/_t1");
    CHECK(fs::mkdir_p(TMP "/_t1/1/2/3/6") < 0);
    CHECK(fs::mkdir_p(TMP "/_t1") < 0);

    // clean up
    system("rm -rf " TMP "/_t1 " TMP "/_t");
}

TESTCASE(rm_rf) {
    system("mkdir -p " TMP "/_t/1/2/3");
    system("touch " TMP "/_t/2");
    system("touch " TMP "/_t/33");
    system("mkdir -p " TMP "/_t/44");
    system("touch " TMP "/_t/44/33");
    system("mkdir -p " TMP "/_t/5555");

    // rm -rf
    CHECK(fs::rm_rf(TMP "/_t") == 0);
    CHECK(system("test -e " TMP "/_t") != 0);

    // rm -rf should remove symlink only
    system("mkdir -p " TMP "/_t/1/2/3/6");
    system("ln -s " TMP "/_t/2 " TMP "/_e");
    CHECK(fs::rm_rf(TMP "/_e") == 0);
    CHECK(system("test -e " TMP "/_t/1/2/3/6") == 0);

    // rm wrong path
    CHECK(fs::rm_rf(TMP "/123thatsnotexist") < 0);

    // clean up
    system("rm -rf " TMP "/_t1 " TMP "/_t");
}

TESTCASE(write_and_read) {
    std::string s = "abcdef";
    CHECK(fs::write(TMP "/text.txt", s) == 0);
    CHECK(fs::read(TMP "/text.txt") == s);
    CHECK(fs::read(TMP "/text.txt", 2) == s.substr(0, 2));
    CHECK(fs::read(TMP "/text.txt", 0) == "");

    // write and read to wrong location
    CHECK(fs::write(TMP "/nonexist/text.txt", s) == -1);
    CHECK(fs::read(TMP "/nonexist/text.txt", 1).empty());

    // write and read permission denined
    // skip this test if user is root
    if (getuid() > 0) {
        system("touch " TMP "/text2.txt");
        system("chmod a-rwx " TMP "/text2.txt");
        CHECK(fs::write(TMP "/text2.txt", s) < 0);
        CHECK(fs::read(TMP "/text2.txt").empty());
    }

    // clean up
    system("rm -f " TMP "/text.txt " TMP "/text2.txt");
}

TESTCASE(mount_bind) {
    // since Linux counts open files on a per mount point basis,
    // a mount point can easily be busy.
    // mount a ramfs to do the tests within the ramfs
#define MB_TEST_BASE TMP "/_mb_test"
    system("mkdir -p " MB_TEST_BASE);

    if (system("mount -t ramfs none " MB_TEST_BASE " 2>/dev/null") != 0) {
        printf("Can not mount. Skipped.");
    } else {
        system("mkdir -p " MB_TEST_BASE "/_m/1/2/3");
        system("mkdir -p " MB_TEST_BASE "/_m/b");

        int e = fs::mount_bind(MB_TEST_BASE "/_m/1", MB_TEST_BASE "/_m/b");
        if (e < 0 && errno == EPERM) {
            puts("  Weird? Please try agian with privileged user");
        } else {
            CHECK(e == 0);
            CHECK(system("test -e " MB_TEST_BASE "/_m/b/2/3") == 0);
            system("umount " MB_TEST_BASE "/_m/b");
            // umount makes dir disappear
            CHECK(system("touch " MB_TEST_BASE "/_m/b/2/3/test_touch 2>/dev/null") != 0);
        }
        system("umount " MB_TEST_BASE " 2>/dev/null");
    }

    // clean up
    system("rm -rf " MB_TEST_BASE);
#undef MB_TEST_BASE
}

TESTCASE(umount) {
    system("mkdir -p " TMP "/_um");

    if (system("mount -t ramfs none " TMP "/_um 2>/dev/null") != 0) {
        printf("Can not mount. Skipped.");
    } else {
        CHECK(fs::umount(TMP "/_um") == 0);
        // in case fs::umount fails
        system("umount " TMP "/_um 2>/dev/null");
    }

    // clean up
    system("rm -rf " TMP "/_um");
}

TESTCASE(mount_tmpfs) {
    system("mkdir -p " TMP "/_mt");

    int e = fs::mount_tmpfs(TMP "/_mt", 4096);
    if (e < 0 && errno == EPERM) {
        printf("No permission to mount. Skipped.");
    } else {
        CHECK(e == 0) {
            perror("can not mount " TMP "/_mt");
        }
        CHECK(system("touch " TMP "/_mt/ee") == 0);
        // write test
        CHECK(system("echo hello > " TMP "/_mt/ee") == 0);
        // size limit test
        CHECK(system("cat /bin/bash >> " TMP "/_mt/ee 2>/dev/null") != 0);
        system("umount " TMP "/_mt");
        // file should disapper after umount
        CHECK(system("test -e " TMP "/_mt/ee") != 0);
    }

    // clean up
    system("rm -rf " TMP "/_mt");
}

TESTCASE(chmod) {
    system("touch " TMP "/_c");
    fs::chmod(TMP "/_c", 0321);
    CHECK(system("test `stat -c \045a " TMP "/_c` = 321") == 0);
    fs::chmod(TMP "/_c", 0777);
    CHECK(system("test `stat -c \045a " TMP "/_c` = 777") == 0);
    // clean up
    system("rm -f " TMP "/_c");
}

TESTCASE(is_dir) {
    CHECK(fs::is_dir("/bin"));
    CHECK(fs::is_dir("/tmp"));
    CHECK(fs::is_dir("/var/lib"));
    CHECK(fs::is_dir("/proc/self"));
    CHECK(fs::is_dir("/proc/1/fd"));
    CHECK(fs::is_dir("."));
    CHECK(fs::is_dir("/"));
    CHECK(!fs::is_dir("/proc1/self"));
    CHECK(!fs::is_dir(""));
    CHECK(!fs::is_dir("/bin/bash"));
    CHECK(!fs::is_dir("/bin/ping"));
}
