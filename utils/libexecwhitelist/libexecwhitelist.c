#include <dlfcn.h>
#include <stdlib.h> // exit
#include <string.h> // strstr
#include <link.h>   // ElfW
#include <errno.h>  // EPERM
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
