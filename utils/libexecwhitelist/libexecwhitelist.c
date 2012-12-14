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

#include <dlfcn.h>
#include <stdlib.h> // exit
#include <string.h> // strstr
#include <link.h>   // ElfW
#include <errno.h>  // EPERM
#include <unistd.h> // readlink
#include <seccomp.h>

typedef int (*main_t)(int, char **, char **);

int __libc_start_main(main_t main, int argc, 
	char *__unbounded *__unbounded ubp_av,
	ElfW(auxv_t) *__unbounded auxvec,
	__typeof (main) init,
	void (*fini) (void),
	void (*rtld_fini) (void), void *__unbounded
	stack_end)
{
    static char whitelist[][8] = {
        "/env\n",
        "/bash\n",
        "/dash\n",
        "/zsh\n",
        "/sh\n",
    };

    int s, i;
    char buf[1024];
	void *libc;
    scmp_filter_ctx ctx = NULL;
	int (*libc_start_main)(main_t main,
		int,
		char *__unbounded *__unbounded,
		ElfW(auxv_t) *,
		__typeof (main),
		void (*fini) (void),
		void (*rtld_fini) (void),
		void *__unbounded stack_end);

	libc = dlopen("libc.so.6", RTLD_LOCAL  | RTLD_LAZY);
	if (!libc) exit(-100);

	libc_start_main = dlsym(libc, "__libc_start_main");
	if (!libc_start_main) exit(-100);

    // If current exe is in whitelist, do nothing
    // otherwise apply no exec policy
    buf[0]     = '/';
    s          = (int)readlink("/proc/self/exe", buf + 1, sizeof(buf) - 4);
    buf[s + 1] = '\n';
    buf[s + 2] = 0;

    for (i = 0; i < sizeof(whitelist) / sizeof(whitelist[0]); ++i) {
        if (strstr(buf, whitelist[i])) goto out;
    }

    // apply fork, exec limit via libseccomp
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) goto out;
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(execve), 0)) goto out;
    if (seccomp_load(ctx)) goto out;

out:
    if (ctx) seccomp_release(ctx);
	return ((*libc_start_main)(main, argc, ubp_av, auxvec,
                 init, fini, rtld_fini, stack_end));
}
