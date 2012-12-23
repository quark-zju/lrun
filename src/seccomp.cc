#include "seccomp.h"
namespace sc = lrun::seccomp;


#ifndef LIBSECCOMP_VERSION_MAJOR
# define LIBSECCOMP_VERSION_MAJOR 0
#endif

#define DO_EXPAND(VAL)  VAL ## 1
#define EXPAND(VAL)     DO_EXPAND(VAL)

#if defined(LIBSECCOMP_VERSION_MAJOR) && EXPAND(LIBSECCOMP_VERSION_MAJOR) == 11
# define LIBSECCOMP_ENABLED
#else
# undef LIBSECCOMP_ENABLED
#endif

#undef DO_EXPAND
#undef EXPAND

#ifdef LIBSECCOMP_ENABLED
extern "C" {
#include <seccomp.h>
#include <sys/syscall.h>
}

#include <map>
#include <string>
#include <cerrno>

static std::map<std::string, int> syscalls;

static class SyscallListInit {
    public:
    SyscallListInit() {
# define ADD_SYSCALL(x) syscalls[std::string(#x)] = __NR_ ## x;
#ifdef __NR__llseek
    ADD_SYSCALL(_llseek);
#endif
#ifdef __NR__newselect
    ADD_SYSCALL(_newselect);
#endif
#ifdef __NR__sysctl
    ADD_SYSCALL(_sysctl);
#endif
#ifdef __NR_accept
    ADD_SYSCALL(accept);
#endif
#ifdef __NR_accept4
    ADD_SYSCALL(accept4);
#endif
#ifdef __NR_access
    ADD_SYSCALL(access);
#endif
#ifdef __NR_acct
    ADD_SYSCALL(acct);
#endif
#ifdef __NR_add_key
    ADD_SYSCALL(add_key);
#endif
#ifdef __NR_adjtimex
    ADD_SYSCALL(adjtimex);
#endif
#ifdef __NR_afs_syscall
    ADD_SYSCALL(afs_syscall);
#endif
#ifdef __NR_alarm
    ADD_SYSCALL(alarm);
#endif
#ifdef __NR_arch_prctl
    ADD_SYSCALL(arch_prctl);
#endif
#ifdef __NR_bdflush
    ADD_SYSCALL(bdflush);
#endif
#ifdef __NR_bind
    ADD_SYSCALL(bind);
#endif
#ifdef __NR_break
    ADD_SYSCALL(break);
#endif
#ifdef __NR_brk
    ADD_SYSCALL(brk);
#endif
#ifdef __NR_capget
    ADD_SYSCALL(capget);
#endif
#ifdef __NR_capset
    ADD_SYSCALL(capset);
#endif
#ifdef __NR_chdir
    ADD_SYSCALL(chdir);
#endif
#ifdef __NR_chmod
    ADD_SYSCALL(chmod);
#endif
#ifdef __NR_chown
    ADD_SYSCALL(chown);
#endif
#ifdef __NR_chown32
    ADD_SYSCALL(chown32);
#endif
#ifdef __NR_chroot
    ADD_SYSCALL(chroot);
#endif
#ifdef __NR_clock_adjtime
    ADD_SYSCALL(clock_adjtime);
#endif
#ifdef __NR_clock_getres
    ADD_SYSCALL(clock_getres);
#endif
#ifdef __NR_clock_gettime
    ADD_SYSCALL(clock_gettime);
#endif
#ifdef __NR_clock_nanosleep
    ADD_SYSCALL(clock_nanosleep);
#endif
#ifdef __NR_clock_settime
    ADD_SYSCALL(clock_settime);
#endif
#ifdef __NR_clone
    ADD_SYSCALL(clone);
#endif
#ifdef __NR_close
    ADD_SYSCALL(close);
#endif
#ifdef __NR_connect
    ADD_SYSCALL(connect);
#endif
#ifdef __NR_creat
    ADD_SYSCALL(creat);
#endif
#ifdef __NR_create_module
    ADD_SYSCALL(create_module);
#endif
#ifdef __NR_delete_module
    ADD_SYSCALL(delete_module);
#endif
#ifdef __NR_dup
    ADD_SYSCALL(dup);
#endif
#ifdef __NR_dup2
    ADD_SYSCALL(dup2);
#endif
#ifdef __NR_dup3
    ADD_SYSCALL(dup3);
#endif
#ifdef __NR_epoll_create
    ADD_SYSCALL(epoll_create);
#endif
#ifdef __NR_epoll_create1
    ADD_SYSCALL(epoll_create1);
#endif
#ifdef __NR_epoll_ctl
    ADD_SYSCALL(epoll_ctl);
#endif
#ifdef __NR_epoll_ctl_old
    ADD_SYSCALL(epoll_ctl_old);
#endif
#ifdef __NR_epoll_pwait
    ADD_SYSCALL(epoll_pwait);
#endif
#ifdef __NR_epoll_wait
    ADD_SYSCALL(epoll_wait);
#endif
#ifdef __NR_epoll_wait_old
    ADD_SYSCALL(epoll_wait_old);
#endif
#ifdef __NR_eventfd
    ADD_SYSCALL(eventfd);
#endif
#ifdef __NR_eventfd2
    ADD_SYSCALL(eventfd2);
#endif
#ifdef __NR_execve
    ADD_SYSCALL(execve);
#endif
#ifdef __NR_exit
    ADD_SYSCALL(exit);
#endif
#ifdef __NR_exit_group
    ADD_SYSCALL(exit_group);
#endif
#ifdef __NR_faccessat
    ADD_SYSCALL(faccessat);
#endif
#ifdef __NR_fadvise64
    ADD_SYSCALL(fadvise64);
#endif
#ifdef __NR_fadvise64_64
    ADD_SYSCALL(fadvise64_64);
#endif
#ifdef __NR_fallocate
    ADD_SYSCALL(fallocate);
#endif
#ifdef __NR_fanotify_init
    ADD_SYSCALL(fanotify_init);
#endif
#ifdef __NR_fanotify_mark
    ADD_SYSCALL(fanotify_mark);
#endif
#ifdef __NR_fchdir
    ADD_SYSCALL(fchdir);
#endif
#ifdef __NR_fchmod
    ADD_SYSCALL(fchmod);
#endif
#ifdef __NR_fchmodat
    ADD_SYSCALL(fchmodat);
#endif
#ifdef __NR_fchown
    ADD_SYSCALL(fchown);
#endif
#ifdef __NR_fchown32
    ADD_SYSCALL(fchown32);
#endif
#ifdef __NR_fchownat
    ADD_SYSCALL(fchownat);
#endif
#ifdef __NR_fcntl
    ADD_SYSCALL(fcntl);
#endif
#ifdef __NR_fcntl64
    ADD_SYSCALL(fcntl64);
#endif
#ifdef __NR_fdatasync
    ADD_SYSCALL(fdatasync);
#endif
#ifdef __NR_fgetxattr
    ADD_SYSCALL(fgetxattr);
#endif
#ifdef __NR_flistxattr
    ADD_SYSCALL(flistxattr);
#endif
#ifdef __NR_flock
    ADD_SYSCALL(flock);
#endif
#ifdef __NR_fork
    ADD_SYSCALL(fork);
#endif
#ifdef __NR_fremovexattr
    ADD_SYSCALL(fremovexattr);
#endif
#ifdef __NR_fsetxattr
    ADD_SYSCALL(fsetxattr);
#endif
#ifdef __NR_fstat
    ADD_SYSCALL(fstat);
#endif
#ifdef __NR_fstat64
    ADD_SYSCALL(fstat64);
#endif
#ifdef __NR_fstatat64
    ADD_SYSCALL(fstatat64);
#endif
#ifdef __NR_fstatfs
    ADD_SYSCALL(fstatfs);
#endif
#ifdef __NR_fstatfs64
    ADD_SYSCALL(fstatfs64);
#endif
#ifdef __NR_fsync
    ADD_SYSCALL(fsync);
#endif
#ifdef __NR_ftime
    ADD_SYSCALL(ftime);
#endif
#ifdef __NR_ftruncate
    ADD_SYSCALL(ftruncate);
#endif
#ifdef __NR_ftruncate64
    ADD_SYSCALL(ftruncate64);
#endif
#ifdef __NR_futex
    ADD_SYSCALL(futex);
#endif
#ifdef __NR_futimesat
    ADD_SYSCALL(futimesat);
#endif
#ifdef __NR_get_kernel_syms
    ADD_SYSCALL(get_kernel_syms);
#endif
#ifdef __NR_get_mempolicy
    ADD_SYSCALL(get_mempolicy);
#endif
#ifdef __NR_get_robust_list
    ADD_SYSCALL(get_robust_list);
#endif
#ifdef __NR_get_thread_area
    ADD_SYSCALL(get_thread_area);
#endif
#ifdef __NR_getcpu
    ADD_SYSCALL(getcpu);
#endif
#ifdef __NR_getcwd
    ADD_SYSCALL(getcwd);
#endif
#ifdef __NR_getdents
    ADD_SYSCALL(getdents);
#endif
#ifdef __NR_getdents64
    ADD_SYSCALL(getdents64);
#endif
#ifdef __NR_getegid
    ADD_SYSCALL(getegid);
#endif
#ifdef __NR_getegid32
    ADD_SYSCALL(getegid32);
#endif
#ifdef __NR_geteuid
    ADD_SYSCALL(geteuid);
#endif
#ifdef __NR_geteuid32
    ADD_SYSCALL(geteuid32);
#endif
#ifdef __NR_getgid
    ADD_SYSCALL(getgid);
#endif
#ifdef __NR_getgid32
    ADD_SYSCALL(getgid32);
#endif
#ifdef __NR_getgroups
    ADD_SYSCALL(getgroups);
#endif
#ifdef __NR_getgroups32
    ADD_SYSCALL(getgroups32);
#endif
#ifdef __NR_getitimer
    ADD_SYSCALL(getitimer);
#endif
#ifdef __NR_getpeername
    ADD_SYSCALL(getpeername);
#endif
#ifdef __NR_getpgid
    ADD_SYSCALL(getpgid);
#endif
#ifdef __NR_getpgrp
    ADD_SYSCALL(getpgrp);
#endif
#ifdef __NR_getpid
    ADD_SYSCALL(getpid);
#endif
#ifdef __NR_getpmsg
    ADD_SYSCALL(getpmsg);
#endif
#ifdef __NR_getppid
    ADD_SYSCALL(getppid);
#endif
#ifdef __NR_getpriority
    ADD_SYSCALL(getpriority);
#endif
#ifdef __NR_getresgid
    ADD_SYSCALL(getresgid);
#endif
#ifdef __NR_getresgid32
    ADD_SYSCALL(getresgid32);
#endif
#ifdef __NR_getresuid
    ADD_SYSCALL(getresuid);
#endif
#ifdef __NR_getresuid32
    ADD_SYSCALL(getresuid32);
#endif
#ifdef __NR_getrlimit
    ADD_SYSCALL(getrlimit);
#endif
#ifdef __NR_getrusage
    ADD_SYSCALL(getrusage);
#endif
#ifdef __NR_getsid
    ADD_SYSCALL(getsid);
#endif
#ifdef __NR_getsockname
    ADD_SYSCALL(getsockname);
#endif
#ifdef __NR_getsockopt
    ADD_SYSCALL(getsockopt);
#endif
#ifdef __NR_gettid
    ADD_SYSCALL(gettid);
#endif
#ifdef __NR_gettimeofday
    ADD_SYSCALL(gettimeofday);
#endif
#ifdef __NR_getuid
    ADD_SYSCALL(getuid);
#endif
#ifdef __NR_getuid32
    ADD_SYSCALL(getuid32);
#endif
#ifdef __NR_getxattr
    ADD_SYSCALL(getxattr);
#endif
#ifdef __NR_gtty
    ADD_SYSCALL(gtty);
#endif
#ifdef __NR_idle
    ADD_SYSCALL(idle);
#endif
#ifdef __NR_init_module
    ADD_SYSCALL(init_module);
#endif
#ifdef __NR_inotify_add_watch
    ADD_SYSCALL(inotify_add_watch);
#endif
#ifdef __NR_inotify_init
    ADD_SYSCALL(inotify_init);
#endif
#ifdef __NR_inotify_init1
    ADD_SYSCALL(inotify_init1);
#endif
#ifdef __NR_inotify_rm_watch
    ADD_SYSCALL(inotify_rm_watch);
#endif
#ifdef __NR_io_cancel
    ADD_SYSCALL(io_cancel);
#endif
#ifdef __NR_io_destroy
    ADD_SYSCALL(io_destroy);
#endif
#ifdef __NR_io_getevents
    ADD_SYSCALL(io_getevents);
#endif
#ifdef __NR_io_setup
    ADD_SYSCALL(io_setup);
#endif
#ifdef __NR_io_submit
    ADD_SYSCALL(io_submit);
#endif
#ifdef __NR_ioctl
    ADD_SYSCALL(ioctl);
#endif
#ifdef __NR_ioperm
    ADD_SYSCALL(ioperm);
#endif
#ifdef __NR_iopl
    ADD_SYSCALL(iopl);
#endif
#ifdef __NR_ioprio_get
    ADD_SYSCALL(ioprio_get);
#endif
#ifdef __NR_ioprio_set
    ADD_SYSCALL(ioprio_set);
#endif
#ifdef __NR_ipc
    ADD_SYSCALL(ipc);
#endif
#ifdef __NR_kcmp
    ADD_SYSCALL(kcmp);
#endif
#ifdef __NR_kexec_load
    ADD_SYSCALL(kexec_load);
#endif
#ifdef __NR_keyctl
    ADD_SYSCALL(keyctl);
#endif
#ifdef __NR_kill
    ADD_SYSCALL(kill);
#endif
#ifdef __NR_lchown
    ADD_SYSCALL(lchown);
#endif
#ifdef __NR_lchown32
    ADD_SYSCALL(lchown32);
#endif
#ifdef __NR_lgetxattr
    ADD_SYSCALL(lgetxattr);
#endif
#ifdef __NR_link
    ADD_SYSCALL(link);
#endif
#ifdef __NR_linkat
    ADD_SYSCALL(linkat);
#endif
#ifdef __NR_listen
    ADD_SYSCALL(listen);
#endif
#ifdef __NR_listxattr
    ADD_SYSCALL(listxattr);
#endif
#ifdef __NR_llistxattr
    ADD_SYSCALL(llistxattr);
#endif
#ifdef __NR_lock
    ADD_SYSCALL(lock);
#endif
#ifdef __NR_lookup_dcookie
    ADD_SYSCALL(lookup_dcookie);
#endif
#ifdef __NR_lremovexattr
    ADD_SYSCALL(lremovexattr);
#endif
#ifdef __NR_lseek
    ADD_SYSCALL(lseek);
#endif
#ifdef __NR_lsetxattr
    ADD_SYSCALL(lsetxattr);
#endif
#ifdef __NR_lstat
    ADD_SYSCALL(lstat);
#endif
#ifdef __NR_lstat64
    ADD_SYSCALL(lstat64);
#endif
#ifdef __NR_madvise
    ADD_SYSCALL(madvise);
#endif
#ifdef __NR_mbind
    ADD_SYSCALL(mbind);
#endif
#ifdef __NR_migrate_pages
    ADD_SYSCALL(migrate_pages);
#endif
#ifdef __NR_mincore
    ADD_SYSCALL(mincore);
#endif
#ifdef __NR_mkdir
    ADD_SYSCALL(mkdir);
#endif
#ifdef __NR_mkdirat
    ADD_SYSCALL(mkdirat);
#endif
#ifdef __NR_mknod
    ADD_SYSCALL(mknod);
#endif
#ifdef __NR_mknodat
    ADD_SYSCALL(mknodat);
#endif
#ifdef __NR_mlock
    ADD_SYSCALL(mlock);
#endif
#ifdef __NR_mlockall
    ADD_SYSCALL(mlockall);
#endif
#ifdef __NR_mmap
    ADD_SYSCALL(mmap);
#endif
#ifdef __NR_mmap2
    ADD_SYSCALL(mmap2);
#endif
#ifdef __NR_modify_ldt
    ADD_SYSCALL(modify_ldt);
#endif
#ifdef __NR_mount
    ADD_SYSCALL(mount);
#endif
#ifdef __NR_move_pages
    ADD_SYSCALL(move_pages);
#endif
#ifdef __NR_mprotect
    ADD_SYSCALL(mprotect);
#endif
#ifdef __NR_mpx
    ADD_SYSCALL(mpx);
#endif
#ifdef __NR_mq_getsetattr
    ADD_SYSCALL(mq_getsetattr);
#endif
#ifdef __NR_mq_notify
    ADD_SYSCALL(mq_notify);
#endif
#ifdef __NR_mq_open
    ADD_SYSCALL(mq_open);
#endif
#ifdef __NR_mq_timedreceive
    ADD_SYSCALL(mq_timedreceive);
#endif
#ifdef __NR_mq_timedsend
    ADD_SYSCALL(mq_timedsend);
#endif
#ifdef __NR_mq_unlink
    ADD_SYSCALL(mq_unlink);
#endif
#ifdef __NR_mremap
    ADD_SYSCALL(mremap);
#endif
#ifdef __NR_msgctl
    ADD_SYSCALL(msgctl);
#endif
#ifdef __NR_msgget
    ADD_SYSCALL(msgget);
#endif
#ifdef __NR_msgrcv
    ADD_SYSCALL(msgrcv);
#endif
#ifdef __NR_msgsnd
    ADD_SYSCALL(msgsnd);
#endif
#ifdef __NR_msync
    ADD_SYSCALL(msync);
#endif
#ifdef __NR_munlock
    ADD_SYSCALL(munlock);
#endif
#ifdef __NR_munlockall
    ADD_SYSCALL(munlockall);
#endif
#ifdef __NR_munmap
    ADD_SYSCALL(munmap);
#endif
#ifdef __NR_name_to_handle_at
    ADD_SYSCALL(name_to_handle_at);
#endif
#ifdef __NR_nanosleep
    ADD_SYSCALL(nanosleep);
#endif
#ifdef __NR_ned
    ADD_SYSCALL(ned);
#endif
#ifdef __NR_newfstatat
    ADD_SYSCALL(newfstatat);
#endif
#ifdef __NR_nfsservctl
    ADD_SYSCALL(nfsservctl);
#endif
#ifdef __NR_nice
    ADD_SYSCALL(nice);
#endif
#ifdef __NR_oldfstat
    ADD_SYSCALL(oldfstat);
#endif
#ifdef __NR_oldlstat
    ADD_SYSCALL(oldlstat);
#endif
#ifdef __NR_oldolduname
    ADD_SYSCALL(oldolduname);
#endif
#ifdef __NR_oldstat
    ADD_SYSCALL(oldstat);
#endif
#ifdef __NR_olduname
    ADD_SYSCALL(olduname);
#endif
#ifdef __NR_open
    ADD_SYSCALL(open);
#endif
#ifdef __NR_open_by_handle_at
    ADD_SYSCALL(open_by_handle_at);
#endif
#ifdef __NR_openat
    ADD_SYSCALL(openat);
#endif
#ifdef __NR_pause
    ADD_SYSCALL(pause);
#endif
#ifdef __NR_perf_event_open
    ADD_SYSCALL(perf_event_open);
#endif
#ifdef __NR_personality
    ADD_SYSCALL(personality);
#endif
#ifdef __NR_pipe
    ADD_SYSCALL(pipe);
#endif
#ifdef __NR_pipe2
    ADD_SYSCALL(pipe2);
#endif
#ifdef __NR_pivot_root
    ADD_SYSCALL(pivot_root);
#endif
#ifdef __NR_poll
    ADD_SYSCALL(poll);
#endif
#ifdef __NR_ppoll
    ADD_SYSCALL(ppoll);
#endif
#ifdef __NR_prctl
    ADD_SYSCALL(prctl);
#endif
#ifdef __NR_pread64
    ADD_SYSCALL(pread64);
#endif
#ifdef __NR_preadv
    ADD_SYSCALL(preadv);
#endif
#ifdef __NR_prlimit64
    ADD_SYSCALL(prlimit64);
#endif
#ifdef __NR_process_vm_readv
    ADD_SYSCALL(process_vm_readv);
#endif
#ifdef __NR_process_vm_writev
    ADD_SYSCALL(process_vm_writev);
#endif
#ifdef __NR_prof
    ADD_SYSCALL(prof);
#endif
#ifdef __NR_profil
    ADD_SYSCALL(profil);
#endif
#ifdef __NR_pselect6
    ADD_SYSCALL(pselect6);
#endif
#ifdef __NR_ptrace
    ADD_SYSCALL(ptrace);
#endif
#ifdef __NR_putpmsg
    ADD_SYSCALL(putpmsg);
#endif
#ifdef __NR_pwrite64
    ADD_SYSCALL(pwrite64);
#endif
#ifdef __NR_pwritev
    ADD_SYSCALL(pwritev);
#endif
#ifdef __NR_query_module
    ADD_SYSCALL(query_module);
#endif
#ifdef __NR_quotactl
    ADD_SYSCALL(quotactl);
#endif
#ifdef __NR_read
    ADD_SYSCALL(read);
#endif
#ifdef __NR_readahead
    ADD_SYSCALL(readahead);
#endif
#ifdef __NR_readdir
    ADD_SYSCALL(readdir);
#endif
#ifdef __NR_readlink
    ADD_SYSCALL(readlink);
#endif
#ifdef __NR_readlinkat
    ADD_SYSCALL(readlinkat);
#endif
#ifdef __NR_readv
    ADD_SYSCALL(readv);
#endif
#ifdef __NR_reboot
    ADD_SYSCALL(reboot);
#endif
#ifdef __NR_recvfrom
    ADD_SYSCALL(recvfrom);
#endif
#ifdef __NR_recvmmsg
    ADD_SYSCALL(recvmmsg);
#endif
#ifdef __NR_recvmsg
    ADD_SYSCALL(recvmsg);
#endif
#ifdef __NR_remap_file_pages
    ADD_SYSCALL(remap_file_pages);
#endif
#ifdef __NR_removexattr
    ADD_SYSCALL(removexattr);
#endif
#ifdef __NR_rename
    ADD_SYSCALL(rename);
#endif
#ifdef __NR_renameat
    ADD_SYSCALL(renameat);
#endif
#ifdef __NR_request_key
    ADD_SYSCALL(request_key);
#endif
#ifdef __NR_restart_syscall
    ADD_SYSCALL(restart_syscall);
#endif
#ifdef __NR_rmdir
    ADD_SYSCALL(rmdir);
#endif
#ifdef __NR_rt_sigaction
    ADD_SYSCALL(rt_sigaction);
#endif
#ifdef __NR_rt_sigpending
    ADD_SYSCALL(rt_sigpending);
#endif
#ifdef __NR_rt_sigprocmask
    ADD_SYSCALL(rt_sigprocmask);
#endif
#ifdef __NR_rt_sigqueueinfo
    ADD_SYSCALL(rt_sigqueueinfo);
#endif
#ifdef __NR_rt_sigreturn
    ADD_SYSCALL(rt_sigreturn);
#endif
#ifdef __NR_rt_sigsuspend
    ADD_SYSCALL(rt_sigsuspend);
#endif
#ifdef __NR_rt_sigtimedwait
    ADD_SYSCALL(rt_sigtimedwait);
#endif
#ifdef __NR_rt_tgsigqueueinfo
    ADD_SYSCALL(rt_tgsigqueueinfo);
#endif
#ifdef __NR_sched_get_priority_max
    ADD_SYSCALL(sched_get_priority_max);
#endif
#ifdef __NR_sched_get_priority_min
    ADD_SYSCALL(sched_get_priority_min);
#endif
#ifdef __NR_sched_getaffinity
    ADD_SYSCALL(sched_getaffinity);
#endif
#ifdef __NR_sched_getparam
    ADD_SYSCALL(sched_getparam);
#endif
#ifdef __NR_sched_getscheduler
    ADD_SYSCALL(sched_getscheduler);
#endif
#ifdef __NR_sched_rr_get_interval
    ADD_SYSCALL(sched_rr_get_interval);
#endif
#ifdef __NR_sched_setaffinity
    ADD_SYSCALL(sched_setaffinity);
#endif
#ifdef __NR_sched_setparam
    ADD_SYSCALL(sched_setparam);
#endif
#ifdef __NR_sched_setscheduler
    ADD_SYSCALL(sched_setscheduler);
#endif
#ifdef __NR_sched_yield
    ADD_SYSCALL(sched_yield);
#endif
#ifdef __NR_security
    ADD_SYSCALL(security);
#endif
#ifdef __NR_select
    ADD_SYSCALL(select);
#endif
#ifdef __NR_semctl
    ADD_SYSCALL(semctl);
#endif
#ifdef __NR_semget
    ADD_SYSCALL(semget);
#endif
#ifdef __NR_semop
    ADD_SYSCALL(semop);
#endif
#ifdef __NR_semtimedop
    ADD_SYSCALL(semtimedop);
#endif
#ifdef __NR_sendfile
    ADD_SYSCALL(sendfile);
#endif
#ifdef __NR_sendfile64
    ADD_SYSCALL(sendfile64);
#endif
#ifdef __NR_sendmmsg
    ADD_SYSCALL(sendmmsg);
#endif
#ifdef __NR_sendmsg
    ADD_SYSCALL(sendmsg);
#endif
#ifdef __NR_sendto
    ADD_SYSCALL(sendto);
#endif
#ifdef __NR_set_mempolicy
    ADD_SYSCALL(set_mempolicy);
#endif
#ifdef __NR_set_robust_list
    ADD_SYSCALL(set_robust_list);
#endif
#ifdef __NR_set_thread_area
    ADD_SYSCALL(set_thread_area);
#endif
#ifdef __NR_set_tid_address
    ADD_SYSCALL(set_tid_address);
#endif
#ifdef __NR_setdomainname
    ADD_SYSCALL(setdomainname);
#endif
#ifdef __NR_setfsgid
    ADD_SYSCALL(setfsgid);
#endif
#ifdef __NR_setfsgid32
    ADD_SYSCALL(setfsgid32);
#endif
#ifdef __NR_setfsuid
    ADD_SYSCALL(setfsuid);
#endif
#ifdef __NR_setfsuid32
    ADD_SYSCALL(setfsuid32);
#endif
#ifdef __NR_setgid
    ADD_SYSCALL(setgid);
#endif
#ifdef __NR_setgid32
    ADD_SYSCALL(setgid32);
#endif
#ifdef __NR_setgroups
    ADD_SYSCALL(setgroups);
#endif
#ifdef __NR_setgroups32
    ADD_SYSCALL(setgroups32);
#endif
#ifdef __NR_sethostname
    ADD_SYSCALL(sethostname);
#endif
#ifdef __NR_setitimer
    ADD_SYSCALL(setitimer);
#endif
#ifdef __NR_setns
    ADD_SYSCALL(setns);
#endif
#ifdef __NR_setpgid
    ADD_SYSCALL(setpgid);
#endif
#ifdef __NR_setpriority
    ADD_SYSCALL(setpriority);
#endif
#ifdef __NR_setregid
    ADD_SYSCALL(setregid);
#endif
#ifdef __NR_setregid32
    ADD_SYSCALL(setregid32);
#endif
#ifdef __NR_setresgid
    ADD_SYSCALL(setresgid);
#endif
#ifdef __NR_setresgid32
    ADD_SYSCALL(setresgid32);
#endif
#ifdef __NR_setresuid
    ADD_SYSCALL(setresuid);
#endif
#ifdef __NR_setresuid32
    ADD_SYSCALL(setresuid32);
#endif
#ifdef __NR_setreuid
    ADD_SYSCALL(setreuid);
#endif
#ifdef __NR_setreuid32
    ADD_SYSCALL(setreuid32);
#endif
#ifdef __NR_setrlimit
    ADD_SYSCALL(setrlimit);
#endif
#ifdef __NR_setsid
    ADD_SYSCALL(setsid);
#endif
#ifdef __NR_setsockopt
    ADD_SYSCALL(setsockopt);
#endif
#ifdef __NR_settimeofday
    ADD_SYSCALL(settimeofday);
#endif
#ifdef __NR_setuid
    ADD_SYSCALL(setuid);
#endif
#ifdef __NR_setuid32
    ADD_SYSCALL(setuid32);
#endif
#ifdef __NR_setxattr
    ADD_SYSCALL(setxattr);
#endif
#ifdef __NR_sgetmask
    ADD_SYSCALL(sgetmask);
#endif
#ifdef __NR_shmat
    ADD_SYSCALL(shmat);
#endif
#ifdef __NR_shmctl
    ADD_SYSCALL(shmctl);
#endif
#ifdef __NR_shmdt
    ADD_SYSCALL(shmdt);
#endif
#ifdef __NR_shmget
    ADD_SYSCALL(shmget);
#endif
#ifdef __NR_shutdown
    ADD_SYSCALL(shutdown);
#endif
#ifdef __NR_sigaction
    ADD_SYSCALL(sigaction);
#endif
#ifdef __NR_sigaltstack
    ADD_SYSCALL(sigaltstack);
#endif
#ifdef __NR_signal
    ADD_SYSCALL(signal);
#endif
#ifdef __NR_signalfd
    ADD_SYSCALL(signalfd);
#endif
#ifdef __NR_signalfd4
    ADD_SYSCALL(signalfd4);
#endif
#ifdef __NR_sigpending
    ADD_SYSCALL(sigpending);
#endif
#ifdef __NR_sigprocmask
    ADD_SYSCALL(sigprocmask);
#endif
#ifdef __NR_sigreturn
    ADD_SYSCALL(sigreturn);
#endif
#ifdef __NR_sigsuspend
    ADD_SYSCALL(sigsuspend);
#endif
#ifdef __NR_socket
    ADD_SYSCALL(socket);
#endif
#ifdef __NR_socketcall
    ADD_SYSCALL(socketcall);
#endif
#ifdef __NR_socketpair
    ADD_SYSCALL(socketpair);
#endif
#ifdef __NR_splice
    ADD_SYSCALL(splice);
#endif
#ifdef __NR_ssetmask
    ADD_SYSCALL(ssetmask);
#endif
#ifdef __NR_stat
    ADD_SYSCALL(stat);
#endif
#ifdef __NR_stat64
    ADD_SYSCALL(stat64);
#endif
#ifdef __NR_statfs
    ADD_SYSCALL(statfs);
#endif
#ifdef __NR_statfs64
    ADD_SYSCALL(statfs64);
#endif
#ifdef __NR_stime
    ADD_SYSCALL(stime);
#endif
#ifdef __NR_stty
    ADD_SYSCALL(stty);
#endif
#ifdef __NR_swapoff
    ADD_SYSCALL(swapoff);
#endif
#ifdef __NR_swapon
    ADD_SYSCALL(swapon);
#endif
#ifdef __NR_symlink
    ADD_SYSCALL(symlink);
#endif
#ifdef __NR_symlinkat
    ADD_SYSCALL(symlinkat);
#endif
#ifdef __NR_sync
    ADD_SYSCALL(sync);
#endif
#ifdef __NR_sync_file_range
    ADD_SYSCALL(sync_file_range);
#endif
#ifdef __NR_syncfs
    ADD_SYSCALL(syncfs);
#endif
#ifdef __NR_sysfs
    ADD_SYSCALL(sysfs);
#endif
#ifdef __NR_sysinfo
    ADD_SYSCALL(sysinfo);
#endif
#ifdef __NR_syslog
    ADD_SYSCALL(syslog);
#endif
#ifdef __NR_tee
    ADD_SYSCALL(tee);
#endif
#ifdef __NR_tgkill
    ADD_SYSCALL(tgkill);
#endif
#ifdef __NR_time
    ADD_SYSCALL(time);
#endif
#ifdef __NR_timer_create
    ADD_SYSCALL(timer_create);
#endif
#ifdef __NR_timer_delete
    ADD_SYSCALL(timer_delete);
#endif
#ifdef __NR_timer_getoverrun
    ADD_SYSCALL(timer_getoverrun);
#endif
#ifdef __NR_timer_gettime
    ADD_SYSCALL(timer_gettime);
#endif
#ifdef __NR_timer_settime
    ADD_SYSCALL(timer_settime);
#endif
#ifdef __NR_timerfd_create
    ADD_SYSCALL(timerfd_create);
#endif
#ifdef __NR_timerfd_gettime
    ADD_SYSCALL(timerfd_gettime);
#endif
#ifdef __NR_timerfd_settime
    ADD_SYSCALL(timerfd_settime);
#endif
#ifdef __NR_times
    ADD_SYSCALL(times);
#endif
#ifdef __NR_tkill
    ADD_SYSCALL(tkill);
#endif
#ifdef __NR_truncate
    ADD_SYSCALL(truncate);
#endif
#ifdef __NR_truncate64
    ADD_SYSCALL(truncate64);
#endif
#ifdef __NR_tuxcall
    ADD_SYSCALL(tuxcall);
#endif
#ifdef __NR_ugetrlimit
    ADD_SYSCALL(ugetrlimit);
#endif
#ifdef __NR_ulimit
    ADD_SYSCALL(ulimit);
#endif
#ifdef __NR_umask
    ADD_SYSCALL(umask);
#endif
#ifdef __NR_umount
    ADD_SYSCALL(umount);
#endif
#ifdef __NR_umount2
    ADD_SYSCALL(umount2);
#endif
#ifdef __NR_uname
    ADD_SYSCALL(uname);
#endif
#ifdef __NR_unlink
    ADD_SYSCALL(unlink);
#endif
#ifdef __NR_unlinkat
    ADD_SYSCALL(unlinkat);
#endif
#ifdef __NR_unshare
    ADD_SYSCALL(unshare);
#endif
#ifdef __NR_uselib
    ADD_SYSCALL(uselib);
#endif
#ifdef __NR_ustat
    ADD_SYSCALL(ustat);
#endif
#ifdef __NR_utime
    ADD_SYSCALL(utime);
#endif
#ifdef __NR_utimensat
    ADD_SYSCALL(utimensat);
#endif
#ifdef __NR_utimes
    ADD_SYSCALL(utimes);
#endif
#ifdef __NR_vfork
    ADD_SYSCALL(vfork);
#endif
#ifdef __NR_vhangup
    ADD_SYSCALL(vhangup);
#endif
#ifdef __NR_vm86
    ADD_SYSCALL(vm86);
#endif
#ifdef __NR_vm86old
    ADD_SYSCALL(vm86old);
#endif
#ifdef __NR_vmsplice
    ADD_SYSCALL(vmsplice);
#endif
#ifdef __NR_vserver
    ADD_SYSCALL(vserver);
#endif
#ifdef __NR_wait4
    ADD_SYSCALL(wait4);
#endif
#ifdef __NR_waitid
    ADD_SYSCALL(waitid);
#endif
#ifdef __NR_waitpid
    ADD_SYSCALL(waitpid);
#endif
#ifdef __NR_write
    ADD_SYSCALL(write);
#endif
#ifdef __NR_writev
    ADD_SYSCALL(writev);
#endif
#undef ADD_SYSCALL
    }
} _dummy;

int sc::apply_simple_filter(const char * const filter, sc::action_t action) {
#define CHAR_FOR_SCMP_ACTION(act) (act == SCMP_ACT_KILL ? 'k' : (act == SCMP_ACT_ALLOW ? 'a' : 'e'))
    int rc = -1;

    scmp_filter_ctx ctx = NULL;
    uint32_t scmp_action = SCMP_ACT_KILL;
    uint32_t scmp_action_inverse = SCMP_ACT_ALLOW;

    // decide default action and default inverse action
    switch(action) {
        case DEFAULT_KILL:
            scmp_action = SCMP_ACT_KILL;
            scmp_action_inverse = SCMP_ACT_ALLOW;
            break;
        case DEFAULT_EPERM:
            scmp_action = SCMP_ACT_ERRNO(EPERM);
            scmp_action_inverse = SCMP_ACT_ALLOW;
            break;
        case OTHERS_KILL:
            scmp_action = SCMP_ACT_ALLOW;
            scmp_action_inverse = SCMP_ACT_KILL;
            break;
        case OTHERS_EPERM:
            scmp_action = SCMP_ACT_ALLOW;
            scmp_action_inverse = SCMP_ACT_ERRNO(EPERM);
            break;
    }

    // vars needed to parse filter
    char     buf[32];
    int      name_len = 0;
    uint8_t  priority = 255;

    // init seccomp filter
    INFO("seccomp init: %c '%s'", CHAR_FOR_SCMP_ACTION(scmp_action), filter);
    ctx = seccomp_init(scmp_action);
    if (ctx == NULL) {
        ERROR("seccomp_init");
        goto err;
    }

    // add seccomp rules
    for (const char * p = filter; ; ++p) {
        if (*p == ',' || *p == 0 || *p == ':') {
            if (name_len == 0) {
                if (*p == 0) break; else continue;
            }
            buf[name_len] = 0;
            std::map<std::string, int>::iterator call = syscalls.find(std::string(buf));
            if (call == syscalls.end()) {
                WARNING("syscall not found: '%s'", buf);
            } else {
                int no = call->second;
                uint32_t act = scmp_action_inverse;

                // user specified additional action
                if (*p == ':') {
                    switch (*(++p)) {
                        case 'k':
                            act = SCMP_ACT_KILL;
                            break;
                        case 'a':
                            act = SCMP_ACT_ALLOW;
                            break;
                        case 'e':
                            act = SCMP_ACT_ERRNO(EPERM);
                            break;
                    }
                }

                INFO("seccomp rule '%s', priority = %hhu, action = %c", buf, priority, CHAR_FOR_SCMP_ACTION(act));
                rc = seccomp_syscall_priority(ctx, no, priority);
                if (rc < 0) {
                    ERROR("seccomp_syscall_priority");
                    goto err;
                }

                rc = seccomp_rule_add(ctx, act, no, 0);
                if (rc < 0) {
                    ERROR("seccomp_rule_add");
                    goto err;
                }

                if (priority > 0) priority--;
            }

            name_len = 0;
            if (*p == 0) break;
        } else {
            if (name_len < (int)(sizeof(buf) - 2)) buf[name_len++] = *p;
        }
    }

    INFO("applying seccomp rules");
    rc = seccomp_load(ctx);

    if (rc) {
        ERROR("seccomp_load");
        goto err;
    }

    rc = 0;

err:
    if (ctx) seccomp_release(ctx);
    return rc == 1 ? -1 : rc;
#undef CHAR_FOR_SCMP_ACTION
}

int sc::supported() {
    return 1;
}

#else

# warning libseccomp version 1.x not found

int sc::apply_simple_filter(const char * const filter, sc::action_t action) {
    return 1;
}

int sc::supported() {
    return 0;
}

#endif


