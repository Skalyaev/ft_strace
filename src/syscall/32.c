#ifdef __i386__
#include "../../include/header.h"

extern t_strace data;

t_syscall syscall32_info() {

    switch (data.syscall.id) {
    // SYSCALL_INFO(name, nargs, ret_type, arg_types...)

    case __NR_restart_syscall:
        // int restart_syscall(void);
        return SYSCALL_INFO("restart_syscall", 0, INT);

    case __NR_exit:
        // void exit(int status);
        return SYSCALL_INFO("exit", 1, INT, INT);

    case __NR_fork:
        // pid_t fork(void);
        return SYSCALL_INFO("fork", 0, INT);

    case __NR_read:
        // ssize_t read(unsigned int fd, char *buf, size_t count);
        return SYSCALL_INFO("read", 3, INT, UINT, A_CHAR, UINT);

    case __NR_write:
        // ssize_t write(unsigned int fd, const char *buf, size_t count);
        return SYSCALL_INFO("write", 3, INT, UINT, A_CHAR, UINT);

    case __NR_open:
        // int open(const char *filename, int flags, int mode);
        return SYSCALL_INFO("open", 3, INT, STR, INT, INT);

    case __NR_close:
        // int close(unsigned int fd);
        return SYSCALL_INFO("close", 1, INT, UINT);

    case __NR_waitpid:
        // pid_t waitpid(pid_t pid, int *status, int options);
        return SYSCALL_INFO("waitpid", 3, INT, INT, A_INT, INT);

    case __NR_creat:
        // int creat(const char *pathname, mode_t mode);
        return SYSCALL_INFO("creat", 2, INT, STR, UINT);

    case __NR_link:
        // int link(const char *oldpath, const char *newpath);
        return SYSCALL_INFO("link", 2, INT, STR, STR);

    case __NR_unlink:
        // int unlink(const char *pathname);
        return SYSCALL_INFO("unlink", 1, INT, STR);

    case __NR_execve:
        // int execve(const char *filename, char *const argv[], char *const envp[]);
        return SYSCALL_INFO("execve", 3, INT, STR, A_STR, A_STR);

    case __NR_chdir:
        // int chdir(const char *path);
        return SYSCALL_INFO("chdir", 1, INT, STR);

    case __NR_time:
        // time_t time(time_t *tloc);
        return SYSCALL_INFO("time", 1, LONG, A_LONG);

    case __NR_mknod:
        // int mknod(const char *pathname, mode_t mode, dev_t dev);
        return SYSCALL_INFO("mknod", 3, INT, STR, UINT, UINT);

    case __NR_chmod:
        // int chmod(const char *pathname, mode_t mode);
        return SYSCALL_INFO("chmod", 2, INT, STR, UINT);

    case __NR_lchown:
        // int lchown(const char *pathname, uid_t owner, gid_t group);
        return SYSCALL_INFO("lchown", 3, INT, STR, UINT, UINT);

    case __NR_break:
        // Obsolete: int break(...).
        return SYSCALL_INFO("break", 1, INT, ADDR);

    case __NR_oldstat:
        // int oldstat(const char *pathname, struct stat *buf);
        return SYSCALL_INFO("oldstat", 2, INT, STR, ADDR);

    case __NR_lseek:
        // off_t lseek(unsigned int fd, off_t offset, unsigned int whence);
        return SYSCALL_INFO("lseek", 3, LONG, UINT, LONG, UINT);

    case __NR_getpid:
        // pid_t getpid(void);
        return SYSCALL_INFO("getpid", 0, INT);

    case __NR_mount:
        // int mount(const char *source, const char *target,
        //           const char *filesystemtype, unsigned long mountflags,
        //           const void *data);
        return SYSCALL_INFO("mount", 5, INT, STR, STR, STR, ULONG, ADDR);

    case __NR_umount:
        // int umount(const char *target);
        return SYSCALL_INFO("umount", 1, INT, STR);

    case __NR_setuid:
        // int setuid(uid_t uid);
        return SYSCALL_INFO("setuid", 1, INT, UINT);

    case __NR_getuid:
        // uid_t getuid(void);
        return SYSCALL_INFO("getuid", 0, UINT);

    case __NR_stime:
        // int stime(const time_t *t);
        return SYSCALL_INFO("stime", 1, INT, A_LONG);

    case __NR_ptrace:
        // long ptrace(long request, long pid, long addr, long data);
        return SYSCALL_INFO("ptrace", 4, LONG, LONG, LONG, ADDR, ADDR);

    case __NR_alarm:
        // unsigned int alarm(unsigned int seconds);
        return SYSCALL_INFO("alarm", 1, UINT, UINT);

    case __NR_oldfstat:
        // int oldfstat(unsigned int fd, struct stat *buf);
        return SYSCALL_INFO("oldfstat", 2, INT, UINT, ADDR);

    case __NR_pause:
        // int pause(void);
        return SYSCALL_INFO("pause", 0, INT);

    case __NR_utime:
        // int utime(const char *filename, const struct utimbuf *times);
        return SYSCALL_INFO("utime", 2, INT, STR, ADDR);

    case __NR_stty:
        // Obsolete: int stty(int fd, struct sgttyb *params);
        return SYSCALL_INFO("stty", 2, INT, INT, ADDR);

    case __NR_gtty:
        // Obsolete: int gtty(int fd, struct sgttyb *params);
        return SYSCALL_INFO("gtty", 2, INT, INT, ADDR);

    case __NR_access:
        // int access(const char *pathname, int mode);
        return SYSCALL_INFO("access", 2, INT, STR, INT);

    case __NR_nice:
        // int nice(int inc);
        return SYSCALL_INFO("nice", 1, INT, INT);

    case __NR_ftime:
        // int ftime(struct timeb *tp);
        return SYSCALL_INFO("ftime", 1, INT, ADDR);

    case __NR_sync:
        // void sync(void);
        return SYSCALL_INFO("sync", 0, INT);

    case __NR_kill:
        // int kill(pid_t pid, int sig);
        return SYSCALL_INFO("kill", 2, INT, INT, INT);

    case __NR_rename:
        // int rename(const char *oldname, const char *newname);
        return SYSCALL_INFO("rename", 2, INT, STR, STR);

    case __NR_mkdir:
        // int mkdir(const char *pathname, int mode);
        return SYSCALL_INFO("mkdir", 2, INT, STR, INT);

    case __NR_rmdir:
        // int rmdir(const char *pathname);
        return SYSCALL_INFO("rmdir", 1, INT, STR);

    case __NR_dup:
        // int dup(unsigned int oldfd);
        return SYSCALL_INFO("dup", 1, INT, UINT);

    case __NR_pipe:
        // int pipe(int pipefd[2]);
        return SYSCALL_INFO("pipe", 1, INT, A_INT);

    case __NR_times:
        // clock_t times(struct tms *buf);
        return SYSCALL_INFO("times", 1, LONG, ADDR);

    case __NR_prof:
        // Obsolete: int prof(char *buffer, size_t size, size_t offset,
        //                    unsigned int scale);
        return SYSCALL_INFO("prof", 4, INT, A_CHAR, UINT, UINT, UINT);

    case __NR_brk:
        // void *brk(void *addr);
        return SYSCALL_INFO("brk", 1, ADDR, ADDR);

    case __NR_setgid:
        // int setgid(gid_t gid);
        return SYSCALL_INFO("setgid", 1, INT, UINT);

    case __NR_getgid:
        // gid_t getgid(void);
        return SYSCALL_INFO("getgid", 0, UINT);

    case __NR_signal:
        // Obsolete: sighandler_t signal(int signum, sighandler_t handler);
        return SYSCALL_INFO("signal", 2, ADDR, INT, ADDR);

    case __NR_geteuid:
        // uid_t geteuid(void);
        return SYSCALL_INFO("geteuid", 0, UINT);

    case __NR_getegid:
        // gid_t getegid(void);
        return SYSCALL_INFO("getegid", 0, UINT);

    case __NR_acct:
        // int acct(const char *filename);
        return SYSCALL_INFO("acct", 1, INT, STR);

    case __NR_umount2:
        // int umount2(const char *target, int flags);
        return SYSCALL_INFO("umount2", 2, INT, STR, INT);

    case __NR_lock:
        // Obsolete: int lock(void);
        return SYSCALL_INFO("lock", 0, INT);

    case __NR_ioctl:
        // int ioctl(unsigned int fd, unsigned int cmd, ...);
        return SYSCALL_INFO("ioctl", 3, INT, UINT, UINT, ADDR);

    case __NR_fcntl:
        // int fcntl(unsigned int fd, unsigned int cmd, ...);
        return SYSCALL_INFO("fcntl", 3, INT, UINT, UINT, ADDR);

    case __NR_mpx:
        // Obsolete: int mpx(void);
        return SYSCALL_INFO("mpx", 0, INT);

    case __NR_setpgid:
        // int setpgid(pid_t pid, pid_t pgid);
        return SYSCALL_INFO("setpgid", 2, INT, INT, INT);

    case __NR_ulimit:
        // Obsolete: long ulimit(int cmd, long newlimit);
        return SYSCALL_INFO("ulimit", 2, LONG, INT, LONG);

    case __NR_oldolduname:
        // int oldolduname(struct oldold_utsname *name);
        return SYSCALL_INFO("oldolduname", 1, INT, ADDR);

    case __NR_umask:
        // mode_t umask(mode_t mask);
        return SYSCALL_INFO("umask", 1, UINT, UINT);

    case __NR_chroot:
        // int chroot(const char *path);
        return SYSCALL_INFO("chroot", 1, INT, STR);

    case __NR_ustat:
        // int ustat(dev_t dev, struct ustat *ubuf);
        return SYSCALL_INFO("ustat", 2, INT, UINT, ADDR);

    case __NR_dup2:
        // int dup2(unsigned int oldfd, unsigned int newfd);
        return SYSCALL_INFO("dup2", 2, INT, UINT, UINT);

    case __NR_getppid:
        // pid_t getppid(void);
        return SYSCALL_INFO("getppid", 0, INT);

    case __NR_getpgrp:
        // pid_t getpgrp(void);
        return SYSCALL_INFO("getpgrp", 0, INT);

    case __NR_setsid:
        // pid_t setsid(void);
        return SYSCALL_INFO("setsid", 0, INT);

    case __NR_sigaction:
        // int sigaction(int sig, const struct sigaction *act,
        //               struct sigaction *oact);
        return SYSCALL_INFO("sigaction", 3, INT, INT, ADDR, ADDR);

    case __NR_sgetmask:
        // int sgetmask(void);
        return SYSCALL_INFO("sgetmask", 0, INT);

    case __NR_ssetmask:
        // int ssetmask(int newmask);
        return SYSCALL_INFO("ssetmask", 1, INT, INT);

    case __NR_setreuid:
        // int setreuid(uid_t ruid, uid_t euid);
        return SYSCALL_INFO("setreuid", 2, INT, UINT, UINT);

    case __NR_setregid:
        // int setregid(gid_t rgid, gid_t egid);
        return SYSCALL_INFO("setregid", 2, INT, UINT, UINT);

    case __NR_sigsuspend:
        // int sigsuspend(const sigset_t *mask);
        return SYSCALL_INFO("sigsuspend", 1, INT, ADDR);

    case __NR_sigpending:
        // int sigpending(sigset_t *set);
        return SYSCALL_INFO("sigpending", 1, INT, ADDR);

    case __NR_sethostname:
        // int sethostname(const char *name, size_t len);
        return SYSCALL_INFO("sethostname", 2, INT, STR, UINT);

    case __NR_setrlimit:
        // int setrlimit(int resource, const struct rlimit *rlim);
        return SYSCALL_INFO("setrlimit", 2, INT, INT, ADDR);

    case __NR_getrlimit:
        // int getrlimit(int resource, struct rlimit *rlim);
        return SYSCALL_INFO("getrlimit", 2, INT, INT, ADDR);

    case __NR_getrusage:
        // int getrusage(int who, struct rusage *usage);
        return SYSCALL_INFO("getrusage", 2, INT, INT, ADDR);

    case __NR_gettimeofday:
        // int gettimeofday(struct timeval *tv, struct timezone *tz);
        return SYSCALL_INFO("gettimeofday", 2, INT, ADDR, ADDR);

    case __NR_settimeofday:
        // int settimeofday(const struct timeval *tv, const struct timezone *tz);
        return SYSCALL_INFO("settimeofday", 2, INT, ADDR, ADDR);

    case __NR_getgroups:
        // int getgroups(int size, gid_t list[]);
        return SYSCALL_INFO("getgroups", 2, INT, INT, A_UINT);

    case __NR_setgroups:
        // int setgroups(int size, const gid_t *list);
        return SYSCALL_INFO("setgroups", 2, INT, INT, A_UINT);

    case __NR_select:
        // int select(int nfds, fd_set *readfds, fd_set *writefds,
        //            fd_set *exceptfds, struct timeval *timeout);
        return SYSCALL_INFO("select", 5, INT, INT, ADDR, ADDR, ADDR, ADDR);

    case __NR_symlink:
        // int symlink(const char *target, const char *linkpath);
        return SYSCALL_INFO("symlink", 2, INT, STR, STR);

    case __NR_oldlstat:
        // int oldlstat(const char *filename, struct stat *buf);
        return SYSCALL_INFO("oldlstat", 2, INT, STR, ADDR);

    case __NR_readlink:
        // int readlink(const char *pathname, char *buf, int bufsiz);
        return SYSCALL_INFO("readlink", 3, INT, STR, A_CHAR, INT);

    case __NR_uselib:
        // int uselib(const char *library);
        return SYSCALL_INFO("uselib", 1, INT, STR);

    case __NR_swapon:
        // int swapon(const char *path, int swapflags);
        return SYSCALL_INFO("swapon", 2, INT, STR, INT);

    case __NR_reboot:
        // int reboot(int magic1, int magic2, int cmd, void *arg);
        return SYSCALL_INFO("reboot", 4, INT, INT, INT, INT, ADDR);

    case __NR_readdir:
        // int readdir(unsigned int fd, struct old_linux_dirent *dirp,
        //             unsigned int count);
        return SYSCALL_INFO("readdir", 3, INT, UINT, ADDR, UINT);

    case __NR_mmap:
        // 32-bit: void *mmap(unsigned long addr, unsigned long length,
        //                    unsigned long prot, unsigned long flags,
        //                    unsigned long fd, unsigned long offset);
        return SYSCALL_INFO("mmap", 6, ADDR, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);

    case __NR_munmap:
        // int munmap(unsigned long addr, unsigned long length);
        return SYSCALL_INFO("munmap", 2, INT, ULONG, ULONG);

    case __NR_truncate:
        // int truncate(const char *path, long length);
        return SYSCALL_INFO("truncate", 2, INT, STR, LONG);

    case __NR_ftruncate:
        // int ftruncate(unsigned int fd, unsigned long length);
        return SYSCALL_INFO("ftruncate", 2, INT, UINT, ULONG);

    case __NR_fchmod:
        // int fchmod(unsigned int fd, mode_t mode);
        return SYSCALL_INFO("fchmod", 2, INT, UINT, UINT);

    case __NR_fchown:
        // int fchown(unsigned int fd, uid_t user, gid_t group);
        return SYSCALL_INFO("fchown", 3, INT, UINT, UINT, UINT);

    case __NR_getpriority:
        // int getpriority(int which, int who);
        return SYSCALL_INFO("getpriority", 2, INT, INT, INT);

    case __NR_setpriority:
        // int setpriority(int which, int who, int prio);
        return SYSCALL_INFO("setpriority", 3, INT, INT, INT, INT);

    case __NR_profil:
        // int profil(char *buf, size_t size, size_t offset, unsigned int scale);
        return SYSCALL_INFO("profil", 4, INT, A_CHAR, UINT, UINT, UINT);

    case __NR_statfs:
        // int statfs(const char *path, struct statfs *buf);
        return SYSCALL_INFO("statfs", 2, INT, STR, ADDR);

    case __NR_fstatfs:
        // int fstatfs(unsigned int fd, struct statfs *buf);
        return SYSCALL_INFO("fstatfs", 2, INT, UINT, ADDR);

    case __NR_ioperm:
        // int ioperm(unsigned long from, unsigned long num, int turn_on);
        return SYSCALL_INFO("ioperm", 3, INT, ULONG, ULONG, INT);

    case __NR_socketcall:
        // int socketcall(int call, unsigned long *args);
        return SYSCALL_INFO("socketcall", 2, INT, INT, A_ULONG);

    case __NR_syslog:
        // int syslog(int type, char *bufp, int len);
        return SYSCALL_INFO("syslog", 3, INT, INT, A_CHAR, INT);

    case __NR_setitimer:
        // int setitimer(int which, const struct itimerval *new_value,
        //               struct itimerval *old_value);
        return SYSCALL_INFO("setitimer", 3, INT, INT, ADDR, ADDR);

    case __NR_getitimer:
        // int getitimer(int which, struct itimerval *curr_value);
        return SYSCALL_INFO("getitimer", 2, INT, INT, ADDR);

    case __NR_stat:
        // int stat(const char *pathname, struct stat *buf);
        return SYSCALL_INFO("stat", 2, INT, STR, ADDR);

    case __NR_lstat:
        // int lstat(const char *pathname, struct stat *buf);
        return SYSCALL_INFO("lstat", 2, INT, STR, ADDR);

    case __NR_fstat:
        // int fstat(unsigned int fd, struct stat *buf);
        return SYSCALL_INFO("fstat", 2, INT, UINT, ADDR);

    case __NR_olduname:
        // int olduname(struct old_utsname *buf);
        return SYSCALL_INFO("olduname", 1, INT, ADDR);

    case __NR_iopl:
        // int iopl(int level);
        return SYSCALL_INFO("iopl", 1, INT, INT);

    case __NR_vhangup:
        // int vhangup(void);
        return SYSCALL_INFO("vhangup", 0, INT);

    case __NR_idle:
        // Obsolete: int idle(void);
        return SYSCALL_INFO("idle", 0, INT);

    case __NR_vm86old:
        // int vm86old(struct vm86_struct *info);
        return SYSCALL_INFO("vm86old", 1, INT, ADDR);

    case __NR_wait4:
        // pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage);
        return SYSCALL_INFO("wait4", 4, INT, INT, A_INT, INT, ADDR);

    case __NR_swapoff:
        // int swapoff(const char *path);
        return SYSCALL_INFO("swapoff", 1, INT, STR);

    case __NR_sysinfo:
        // int sysinfo(struct sysinfo *info);
        return SYSCALL_INFO("sysinfo", 1, INT, ADDR);

    case __NR_ipc:
        // int ipc(unsigned int call, int first, int second, int third,
        //         void *ptr, long fifth);
        return SYSCALL_INFO("ipc", 6, INT, UINT, INT, INT, INT, ADDR, LONG);

    case __NR_fsync:
        // int fsync(int fd);
        return SYSCALL_INFO("fsync", 1, INT, INT);

    case __NR_rt_sigreturn:
        // int rt_sigreturn(...);
        return SYSCALL_INFO("rt_sigreturn", 1, INT, ULONG);

    case __NR_clone:
        // long clone(unsigned long flags, void *stack, int *parent_tid,
        //            int *child_tid, unsigned long newtls);
        return SYSCALL_INFO("clone", 5, LONG, ULONG, ADDR, A_INT, A_INT, ULONG);

    case __NR_setdomainname:
        // int setdomainname(const char *name, size_t len);
        return SYSCALL_INFO("setdomainname", 2, INT, STR, UINT);

    case __NR_uname:
        // int uname(struct utsname *buf);
        return SYSCALL_INFO("uname", 1, INT, ADDR);

    case __NR_modify_ldt:
        // int modify_ldt(int func, void *ptr, unsigned long bytecount);
        return SYSCALL_INFO("modify_ldt", 3, INT, INT, ADDR, ULONG);

    case __NR_adjtimex:
        // int adjtimex(struct timex *buf);
        return SYSCALL_INFO("adjtimex", 1, INT, ADDR);

    case __NR_mprotect:
        // int mprotect(const void *addr, size_t len, int prot);
        return SYSCALL_INFO("mprotect", 3, INT, ADDR, UINT, INT);

    case __NR_sigprocmask:
        // int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
        return SYSCALL_INFO("sigprocmask", 3, INT, INT, ADDR, ADDR);

    case __NR_create_module:
        // int create_module(const char *name, size_t size);
        return SYSCALL_INFO("create_module", 2, INT, STR, UINT);

    case __NR_init_module:
        // int init_module(void *module_image, unsigned long len,
        //                 const char *param_values);
        return SYSCALL_INFO("init_module", 3, INT, ADDR, ULONG, STR);

    case __NR_delete_module:
        // int delete_module(const char *name_user, unsigned int flags);
        return SYSCALL_INFO("delete_module", 2, INT, STR, UINT);

    case __NR_get_kernel_syms:
        // int get_kernel_syms(struct kernel_sym *table);
        return SYSCALL_INFO("get_kernel_syms", 1, INT, ADDR);

    case __NR_quotactl:
        // int quotactl(const char *special, int cmd, int id, char *addr);
        return SYSCALL_INFO("quotactl", 4, INT, STR, INT, INT, STR);

    case __NR_getpgid:
        // pid_t getpgid(pid_t pid);
        return SYSCALL_INFO("getpgid", 1, INT, INT);

    case __NR_fchdir:
        // int fchdir(unsigned int fd);
        return SYSCALL_INFO("fchdir", 1, INT, UINT);

    case __NR_bdflush:
        // int bdflush(int func, long data);
        return SYSCALL_INFO("bdflush", 2, INT, INT, LONG);

    case __NR_sysfs:
        // int sysfs(int option, unsigned long arg1, unsigned long arg2);
        return SYSCALL_INFO("sysfs", 3, INT, INT, ULONG, ULONG);

    case __NR_personality:
        // int personality(unsigned long persona);
        return SYSCALL_INFO("personality", 1, INT, ULONG);

    case __NR_afs_syscall:
        // Obsolete: int afs_syscall();
        return SYSCALL_INFO("afs_syscall", 0, INT);

    case __NR_setfsuid:
        // int setfsuid(uid_t fsuid);
        return SYSCALL_INFO("setfsuid", 1, INT, UINT);

    case __NR_setfsgid:
        // int setfsgid(gid_t fsgid);
        return SYSCALL_INFO("setfsgid", 1, INT, UINT);

    case __NR__llseek:
        // off_t _llseek(unsigned int fd, unsigned long offset_high,
        //               unsigned long offset_low, loff_t *result,
        //               unsigned int whence);
        return SYSCALL_INFO("_llseek", 5, LONG, UINT, ULONG, ULONG, A_LONG, UINT);

    case __NR_getdents:
        // int getdents(unsigned int fd, struct linux_dirent *dirp,
        //              unsigned int count);
        return SYSCALL_INFO("getdents", 3, INT, UINT, ADDR, UINT);

    case __NR__newselect:
        // int _newselect(nfds_t n, fd_set *readfds, fd_set *writefds,
        //                fd_set *exceptfds, struct timeval *timeout);
        return SYSCALL_INFO("_newselect", 5, INT, UINT, ADDR, ADDR, ADDR, ADDR);

    case __NR_flock:
        // int flock(int fd, int operation);
        return SYSCALL_INFO("flock", 2, INT, INT, INT);

    case __NR_msync:
        // int msync(void *addr, size_t length, int flags);
        return SYSCALL_INFO("msync", 3, INT, ADDR, UINT, INT);

    case __NR_readv:
        // ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
        return SYSCALL_INFO("readv", 3, INT, INT, ADDR, INT);

    case __NR_writev:
        // ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
        return SYSCALL_INFO("writev", 3, INT, INT, ADDR, INT);

    case __NR_getsid:
        // pid_t getsid(pid_t pid);
        return SYSCALL_INFO("getsid", 1, INT, INT);

    case __NR_fdatasync:
        // int fdatasync(int fd);
        return SYSCALL_INFO("fdatasync", 1, INT, INT);

    case __NR__sysctl:
        // int _sysctl(struct __sysctl_args *args);
        return SYSCALL_INFO("_sysctl", 1, INT, ADDR);

    case __NR_mlock:
        // int mlock(const void *addr, size_t len);
        return SYSCALL_INFO("mlock", 2, INT, ADDR, UINT);

    case __NR_munlock:
        // int munlock(const void *addr, size_t len);
        return SYSCALL_INFO("munlock", 2, INT, ADDR, UINT);

    case __NR_mlockall:
        // int mlockall(int flags);
        return SYSCALL_INFO("mlockall", 1, INT, INT);

    case __NR_munlockall:
        // int munlockall(void);
        return SYSCALL_INFO("munlockall", 0, INT);

    case __NR_sched_setparam:
        // int sched_setparam(pid_t pid, const struct sched_param *param);
        return SYSCALL_INFO("sched_setparam", 2, INT, INT, ADDR);

    case __NR_sched_getparam:
        // int sched_getparam(pid_t pid, struct sched_param *param);
        return SYSCALL_INFO("sched_getparam", 2, INT, INT, ADDR);

    case __NR_sched_setscheduler:
        // int sched_setscheduler(pid_t pid, int policy,
        //                        const struct sched_param *param);
        return SYSCALL_INFO("sched_setscheduler", 3, INT, INT, INT, ADDR);

    case __NR_sched_getscheduler:
        // int sched_getscheduler(pid_t pid);
        return SYSCALL_INFO("sched_getscheduler", 1, INT, INT);

    case __NR_sched_yield:
        // int sched_yield(void);
        return SYSCALL_INFO("sched_yield", 0, INT);

    case __NR_sched_get_priority_max:
        // int sched_get_priority_max(int policy);
        return SYSCALL_INFO("sched_get_priority_max", 1, INT, INT);

    case __NR_sched_get_priority_min:
        // int sched_get_priority_min(int policy);
        return SYSCALL_INFO("sched_get_priority_min", 1, INT, INT);

    case __NR_sched_rr_get_interval:
        // int sched_rr_get_interval(pid_t pid, struct timespec *tp);
        return SYSCALL_INFO("sched_rr_get_interval", 2, INT, INT, ADDR);

    case __NR_nanosleep:
        // int nanosleep(const struct timespec *req, struct timespec *rem);
        return SYSCALL_INFO("nanosleep", 2, INT, ADDR, ADDR);

    case __NR_mremap:
        // void *mremap(void *old_address, size_t old_size,
        //              size_t new_size, int flags, ...);
        return SYSCALL_INFO("mremap", 5, ADDR, ADDR, UINT, UINT, INT, ADDR);

    case __NR_setresuid:
        // int setresuid(uid_t ruid, uid_t euid, uid_t suid);
        return SYSCALL_INFO("setresuid", 3, INT, UINT, UINT, UINT);

    case __NR_getresuid:
        // int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
        return SYSCALL_INFO("getresuid", 3, INT, A_UINT, A_UINT, A_UINT);

    case __NR_vm86:
        // int vm86(unsigned long fn, struct vm86plus_struct *v86);
        return SYSCALL_INFO("vm86", 2, INT, ULONG, ADDR);

    case __NR_query_module:
        // int query_module(const char *name, int which, void *buf,
        //                  size_t bufsize, size_t *ret);
        return SYSCALL_INFO("query_module", 5, INT, STR, INT, ADDR, UINT, ADDR);

    case __NR_poll:
        // int poll(struct pollfd *ufds, unsigned int nfds, int timeout);
        return SYSCALL_INFO("poll", 3, INT, ADDR, UINT, INT);

    case __NR_nfsservctl:
        // int nfsservctl(int cmd, struct nfsctl_arg *arg, void *res);
        return SYSCALL_INFO("nfsservctl", 3, INT, INT, ADDR, ADDR);

    case __NR_setresgid:
        // int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
        return SYSCALL_INFO("setresgid", 3, INT, UINT, UINT, UINT);

    case __NR_getresgid:
        // int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);
        return SYSCALL_INFO("getresgid", 3, INT, A_UINT, A_UINT, A_UINT);

    case __NR_prctl:
        // int prctl(int option, unsigned long arg2, unsigned long arg3,
        //           unsigned long arg4, unsigned long arg5);
        return SYSCALL_INFO("prctl", 5, INT, INT, ULONG, ULONG, ULONG, ULONG);

    case __NR_rt_sigreturn:
        // int rt_sigreturn(void);
        return SYSCALL_INFO("rt_sigreturn", 0, INT);

    case __NR_rt_sigaction:
        // int rt_sigaction(int sig, const struct sigaction *act,
        //                  struct sigaction *oact);
        return SYSCALL_INFO("rt_sigaction", 3, INT, INT, ADDR, ADDR);

    case __NR_rt_sigprocmask:
        // int rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
        return SYSCALL_INFO("rt_sigprocmask", 3, INT, INT, ADDR, ADDR);

    case __NR_rt_sigpending:
        // int rt_sigpending(sigset_t *set);
        return SYSCALL_INFO("rt_sigpending", 1, INT, ADDR);

    case __NR_rt_sigtimedwait:
        // int rt_sigtimedwait(const sigset_t *set, siginfo_t *info,
        //                     const struct timespec *timeout);
        return SYSCALL_INFO("rt_sigtimedwait", 3, INT, ADDR, ADDR, ADDR);

    case __NR_rt_sigqueueinfo:
        // int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *uinfo);
        return SYSCALL_INFO("rt_sigqueueinfo", 3, INT, INT, INT, ADDR);

    case __NR_rt_sigsuspend:
        // int rt_sigsuspend(const sigset_t *mask, size_t sigsetsize);
        return SYSCALL_INFO("rt_sigsuspend", 2, INT, ADDR, UINT);

    case __NR_pread64:
        // ssize_t pread64(int fd, void *buf, size_t count, off_t offset);
        return SYSCALL_INFO("pread64", 4, INT, INT, A_CHAR, UINT, LONG);

    case __NR_pwrite64:
        // ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset);
        return SYSCALL_INFO("pwrite64", 4, INT, INT, A_CHAR, UINT, LONG);

    case __NR_chown:
        // int chown(const char *pathname, uid_t owner, gid_t group);
        return SYSCALL_INFO("chown", 3, INT, STR, UINT, UINT);

    case __NR_getcwd:
        // char *getcwd(char *buf, size_t size);
        return SYSCALL_INFO("getcwd", 2, STR, A_CHAR, UINT);

    case __NR_capget:
        // int capget(cap_user_header_t header, cap_user_data_t dataptr);
        return SYSCALL_INFO("capget", 2, INT, ADDR, ADDR);

    case __NR_capset:
        // int capset(cap_user_header_t header, const cap_user_data_t data);
        return SYSCALL_INFO("capset", 2, INT, ADDR, ADDR);

    case __NR_sigaltstack:
        // int sigaltstack(const stack_t *ss, stack_t *old_ss);
        return SYSCALL_INFO("sigaltstack", 2, INT, ADDR, ADDR);

    case __NR_sendfile:
        // ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
        return SYSCALL_INFO("sendfile", 4, INT, INT, INT, A_LONG, UINT);

    case __NR_getpmsg:
        // Obsolete: int getpmsg(int fd, struct strbuf *ctl,
        //                       struct strbuf *dat, int *flags);
        return SYSCALL_INFO("getpmsg", 4, INT, INT, ADDR, ADDR, A_INT);

    case __NR_putpmsg:
        // Obsolete: int putpmsg(int fd, const struct strbuf *ctl,
        //                       const struct strbuf *dat, int flags);
        return SYSCALL_INFO("putpmsg", 4, INT, INT, ADDR, ADDR, INT);

    case __NR_vfork:
        // pid_t vfork(void);
        return SYSCALL_INFO("vfork", 0, INT);

    case __NR_ugetrlimit:
        // int ugetrlimit(int resource, struct rlimit *rlim);
        return SYSCALL_INFO("ugetrlimit", 2, INT, INT, ADDR);

    case __NR_mmap2:
        // void *mmap2(unsigned long addr, unsigned long length, int prot,
        //             int flags, int fd, unsigned long pgoffset);
        return SYSCALL_INFO("mmap2", 6, ADDR, ULONG, ULONG, INT, INT, INT, ULONG);

    case __NR_truncate64:
        // int truncate64(const char *path, off_t length);
        return SYSCALL_INFO("truncate64", 2, INT, STR, LONG);

    case __NR_ftruncate64:
        // int ftruncate64(unsigned int fd, off_t length);
        return SYSCALL_INFO("ftruncate64", 2, INT, UINT, LONG);

    case __NR_stat64:
        // int stat64(const char *path, struct stat64 *buf);
        return SYSCALL_INFO("stat64", 2, INT, STR, ADDR);

    case __NR_lstat64:
        // int lstat64(const char *path, struct stat64 *buf);
        return SYSCALL_INFO("lstat64", 2, INT, STR, ADDR);

    case __NR_fstat64:
        // int fstat64(int fd, struct stat64 *buf);
        return SYSCALL_INFO("fstat64", 2, INT, INT, ADDR);

    case __NR_lchown32:
        // int lchown32(const char *path, uid_t owner, gid_t group);
        return SYSCALL_INFO("lchown32", 3, INT, STR, UINT, UINT);

    case __NR_getuid32:
        // uid_t getuid32(void);
        return SYSCALL_INFO("getuid32", 0, UINT);

    case __NR_getgid32:
        // gid_t getgid32(void);
        return SYSCALL_INFO("getgid32", 0, UINT);

    case __NR_geteuid32:
        // uid_t geteuid32(void);
        return SYSCALL_INFO("geteuid32", 0, UINT);

    case __NR_getegid32:
        // gid_t getegid32(void);
        return SYSCALL_INFO("getegid32", 0, UINT);

    case __NR_setreuid32:
        // int setreuid32(uid_t ruid, uid_t euid);
        return SYSCALL_INFO("setreuid32", 2, INT, UINT, UINT);

    case __NR_setregid32:
        // int setregid32(gid_t rgid, gid_t egid);
        return SYSCALL_INFO("setregid32", 2, INT, UINT, UINT);

    case __NR_getgroups32:
        // int getgroups32(int size, gid_t list[]);
        return SYSCALL_INFO("getgroups32", 2, INT, INT, A_UINT);

    case __NR_setgroups32:
        // int setgroups32(int size, const gid_t *list);
        return SYSCALL_INFO("setgroups32", 2, INT, INT, A_UINT);

    case __NR_fchown32:
        // int fchown32(unsigned int fd, uid_t owner, gid_t group);
        return SYSCALL_INFO("fchown32", 3, INT, UINT, UINT, UINT);

    case __NR_setresuid32:
        // int setresuid32(uid_t ruid, uid_t euid, uid_t suid);
        return SYSCALL_INFO("setresuid32", 3, INT, UINT, UINT, UINT);

    case __NR_getresuid32:
        // int getresuid32(uid_t *ruid, uid_t *euid, uid_t *suid);
        return SYSCALL_INFO("getresuid32", 3, INT, A_UINT, A_UINT, A_UINT);

    case __NR_setresgid32:
        // int setresgid32(gid_t rgid, gid_t egid, gid_t sgid);
        return SYSCALL_INFO("setresgid32", 3, INT, UINT, UINT, UINT);

    case __NR_getresgid32:
        // int getresgid32(gid_t *rgid, gid_t *egid, gid_t *sgid);
        return SYSCALL_INFO("getresgid32", 3, INT, A_UINT, A_UINT, A_UINT);

    case __NR_chown32:
        // int chown32(const char *pathname, uid_t owner, gid_t group);
        return SYSCALL_INFO("chown32", 3, INT, STR, UINT, UINT);

    case __NR_setuid32:
        // int setuid32(uid_t uid);
        return SYSCALL_INFO("setuid32", 1, INT, UINT);

    case __NR_setgid32:
        // int setgid32(gid_t gid);
        return SYSCALL_INFO("setgid32", 1, INT, UINT);

    case __NR_setfsuid32:
        // int setfsuid32(uid_t fsuid);
        return SYSCALL_INFO("setfsuid32", 1, INT, UINT);

    case __NR_setfsgid32:
        // int setfsgid32(gid_t fsgid);
        return SYSCALL_INFO("setfsgid32", 1, INT, UINT);

    case __NR_pivot_root:
        // int pivot_root(const char *new_root, const char *put_old);
        return SYSCALL_INFO("pivot_root", 2, INT, STR, STR);

    case __NR_mincore:
        // int mincore(void *addr, size_t length, unsigned char *vec);
        return SYSCALL_INFO("mincore", 3, INT, ADDR, UINT, A_UCHAR);

    case __NR_madvise:
        // int madvise(void *addr, size_t length, int advice);
        return SYSCALL_INFO("madvise", 3, INT, ADDR, UINT, INT);

    case __NR_getdents64:
        // int getdents64(unsigned int fd, struct linux_dirent64 *dirp,
        //                unsigned int count);
        return SYSCALL_INFO("getdents64", 3, INT, UINT, ADDR, UINT);

    case __NR_fcntl64:
        // int fcntl64(unsigned int fd, unsigned int cmd, ...);
        return SYSCALL_INFO("fcntl64", 3, INT, UINT, UINT, ADDR);

    case __NR_gettid:
        // pid_t gettid(void);
        return SYSCALL_INFO("gettid", 0, INT);

    case __NR_readahead:
        // ssize_t readahead(int fd, off64_t offset, size_t count);
        return SYSCALL_INFO("readahead", 3, INT, INT, LONG, UINT);

    case __NR_setxattr:
        // int setxattr(const char *path, const char *name, const void *value,
        //              size_t size, int flags);
        return SYSCALL_INFO("setxattr", 5, INT, STR, STR, A_CHAR, UINT, INT);

    case __NR_lsetxattr:
        // int lsetxattr(const char *path, const char *name, const void *value,
        //               size_t size, int flags);
        return SYSCALL_INFO("lsetxattr", 5, INT, STR, STR, A_CHAR, UINT, INT);

    case __NR_fsetxattr:
        // int fsetxattr(int fd, const char *name, const void *value,
        //               size_t size, int flags);
        return SYSCALL_INFO("fsetxattr", 5, INT, INT, STR, A_CHAR, UINT, INT);

    case __NR_getxattr:
        // int getxattr(const char *path, const char *name, void *value, size_t size);
        return SYSCALL_INFO("getxattr", 4, INT, STR, STR, A_CHAR, UINT);

    case __NR_lgetxattr:
        // int lgetxattr(const char *path, const char *name, void *value, size_t size);
        return SYSCALL_INFO("lgetxattr", 4, INT, STR, STR, A_CHAR, UINT);

    case __NR_fgetxattr:
        // int fgetxattr(int fd, const char *name, void *value, size_t size);
        return SYSCALL_INFO("fgetxattr", 4, INT, INT, STR, A_CHAR, UINT);

    case __NR_listxattr:
        // ssize_t listxattr(const char *path, char *list, size_t size);
        return SYSCALL_INFO("listxattr", 3, INT, STR, A_CHAR, UINT);

    case __NR_llistxattr:
        // ssize_t llistxattr(const char *path, char *list, size_t size);
        return SYSCALL_INFO("llistxattr", 3, INT, STR, A_CHAR, UINT);

    case __NR_flistxattr:
        // ssize_t flistxattr(int fd, char *list, size_t size);
        return SYSCALL_INFO("flistxattr", 3, INT, INT, A_CHAR, UINT);

    case __NR_removexattr:
        // int removexattr(const char *path, const char *name);
        return SYSCALL_INFO("removexattr", 2, INT, STR, STR);

    case __NR_lremovexattr:
        // int lremovexattr(const char *path, const char *name);
        return SYSCALL_INFO("lremovexattr", 2, INT, STR, STR);

    case __NR_fremovexattr:
        // int fremovexattr(int fd, const char *name);
        return SYSCALL_INFO("fremovexattr", 2, INT, INT, STR);

    case __NR_tkill:
        // int tkill(int tid, int sig);
        return SYSCALL_INFO("tkill", 2, INT, INT, INT);

    case __NR_sendfile64:
        // ssize_t sendfile64(int out_fd, int in_fd, off_t *offset, size_t count);
        return SYSCALL_INFO("sendfile64", 4, INT, INT, INT, A_LONG, UINT);

    case __NR_futex:
        // int futex(u32 *uaddr, int op, u32 val,
        //           const struct timespec *timeout, u32 *uaddr2, u32 val3);
        return SYSCALL_INFO("futex", 6, INT, A_UINT, INT, UINT, ADDR, A_UINT, UINT);

    case __NR_sched_setaffinity:
        // int sched_setaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
        return SYSCALL_INFO("sched_setaffinity", 3, INT, INT, UINT, ADDR);

    case __NR_sched_getaffinity:
        // int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
        return SYSCALL_INFO("sched_getaffinity", 3, INT, INT, UINT, ADDR);

    case __NR_set_thread_area:
        // int set_thread_area(struct user_desc *u_info);
        return SYSCALL_INFO("set_thread_area", 1, INT, ADDR);

    case __NR_get_thread_area:
        // int get_thread_area(struct user_desc *u_info);
        return SYSCALL_INFO("get_thread_area", 1, INT, ADDR);

    case __NR_io_setup:
        // int io_setup(unsigned nr_events, aio_context_t *ctxp);
        return SYSCALL_INFO("io_setup", 2, INT, UINT, ADDR);

    case __NR_io_destroy:
        // int io_destroy(aio_context_t ctx);
        return SYSCALL_INFO("io_destroy", 1, INT, ULONG);

    case __NR_io_getevents:
        // int io_getevents(aio_context_t ctx, long min_nr, long nr,
        //                  struct io_event *events, struct timespec *timeout);
        return SYSCALL_INFO("io_getevents", 5, INT, ULONG, LONG, LONG, ADDR, ADDR);

    case __NR_io_submit:
        // int io_submit(aio_context_t ctx, long nr, struct iocb **iocbpp);
        return SYSCALL_INFO("io_submit", 3, INT, ULONG, LONG, ADDR);

    case __NR_io_cancel:
        // int io_cancel(aio_context_t ctx, struct iocb *iocb,
        //               struct io_event *result);
        return SYSCALL_INFO("io_cancel", 3, INT, ULONG, ADDR, ADDR);

    case __NR_fadvise64:
        // int fadvise64(int fd, off_t offset, size_t len, int advice);
        return SYSCALL_INFO("fadvise64", 4, INT, INT, LONG, UINT, INT);

    case __NR_exit_group:
        // void exit_group(int status);
        return SYSCALL_INFO("exit_group", 1, INT, INT);

    case __NR_lookup_dcookie:
        // int lookup_dcookie(u64 cookie64, char *buf, size_t len);
        return SYSCALL_INFO("lookup_dcookie", 3, INT, ULONG, A_CHAR, UINT);

    case __NR_epoll_create:
        // int epoll_create(int size);
        return SYSCALL_INFO("epoll_create", 1, INT, INT);

    case __NR_epoll_ctl:
        // int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
        return SYSCALL_INFO("epoll_ctl", 4, INT, INT, INT, INT, ADDR);

    case __NR_epoll_wait:
        // int epoll_wait(int epfd, struct epoll_event *events,
        //                int maxevents, int timeout);
        return SYSCALL_INFO("epoll_wait", 4, INT, INT, ADDR, INT, INT);

    case __NR_remap_file_pages:
        // int remap_file_pages(void *addr, size_t size, int prot,
        //                      size_t pgoff, int flags);
        return SYSCALL_INFO("remap_file_pages", 5, INT, ADDR, UINT, INT, UINT, INT);

    case __NR_set_tid_address:
        // long set_tid_address(int *tidptr);
        return SYSCALL_INFO("set_tid_address", 1, LONG, A_INT);

    case __NR_timer_create:
        // int timer_create(clockid_t clockid, struct sigevent *sevp,
        //                  timer_t *timerid);
        return SYSCALL_INFO("timer_create", 3, INT, INT, ADDR, ADDR);

    case __NR_timer_settime:
        // int timer_settime(timer_t timerid, int flags,
        //                   const struct itimerspec *new_value,
        //                   struct itimerspec *old_value);
        return SYSCALL_INFO("timer_settime", 4, INT, INT, INT, ADDR, ADDR);

    case __NR_timer_gettime:
        // int timer_gettime(timer_t timerid, struct itimerspec *curr_value);
        return SYSCALL_INFO("timer_gettime", 2, INT, INT, ADDR);

    case __NR_timer_getoverrun:
        // int timer_getoverrun(timer_t timerid);
        return SYSCALL_INFO("timer_getoverrun", 1, INT, INT);

    case __NR_timer_delete:
        // int timer_delete(timer_t timerid);
        return SYSCALL_INFO("timer_delete", 1, INT, INT);

    case __NR_clock_settime:
        // int clock_settime(clockid_t clk_id, const struct timespec *tp);
        return SYSCALL_INFO("clock_settime", 2, INT, INT, ADDR);

    case __NR_clock_gettime:
        // int clock_gettime(clockid_t clk_id, struct timespec *tp);
        return SYSCALL_INFO("clock_gettime", 2, INT, INT, ADDR);

    case __NR_clock_getres:
        // int clock_getres(clockid_t clk_id, struct timespec *res);
        return SYSCALL_INFO("clock_getres", 2, INT, INT, ADDR);

    case __NR_clock_nanosleep:
        // int clock_nanosleep(clockid_t clk_id, int flags,
        //                     const struct timespec *request,
        //                     struct timespec *remain);
        return SYSCALL_INFO("clock_nanosleep", 4, INT, INT, INT, ADDR, ADDR);

    case __NR_statfs64:
        // int statfs64(const char *path, size_t sz, struct statfs64 *buf);
        return SYSCALL_INFO("statfs64", 3, INT, STR, UINT, ADDR);

    case __NR_fstatfs64:
        // int fstatfs64(int fd, size_t sz, struct statfs64 *buf);
        return SYSCALL_INFO("fstatfs64", 3, INT, INT, UINT, ADDR);

    case __NR_tgkill:
        // int tgkill(int tgid, int tid, int sig);
        return SYSCALL_INFO("tgkill", 3, INT, INT, INT, INT);

    case __NR_utimes:
        // int utimes(const char *filename, const struct timeval times[2]);
        return SYSCALL_INFO("utimes", 2, INT, STR, ADDR);

    case __NR_fadvise64_64:
        // int fadvise64_64(int fd, off_t offset, off_t len, int advice);
        return SYSCALL_INFO("fadvise64_64", 4, INT, INT, LONG, LONG, INT);

    case __NR_vserver:
        // Obsolete: int vserver();
        return SYSCALL_INFO("vserver", 0, INT);

    case __NR_mbind:
        // int mbind(void *addr, unsigned long len, int mode,
        //           const unsigned long *nodemask, unsigned long maxnode,
        //           unsigned flags);
        return SYSCALL_INFO("mbind", 6, INT, ADDR, ULONG, INT, A_ULONG, ULONG, INT);

    case __NR_get_mempolicy:
        // int get_mempolicy(int *mode, unsigned long *nodemask,
        //                   unsigned long maxnode, void *addr, int flags);
        return SYSCALL_INFO("get_mempolicy", 5, INT, A_INT, A_ULONG, ULONG, ADDR, INT);

    case __NR_set_mempolicy:
        // int set_mempolicy(int mode, const unsigned long *nodemask,
        //                   unsigned long maxnode);
        return SYSCALL_INFO("set_mempolicy", 3, INT, INT, A_ULONG, ULONG);

    case __NR_mq_open:
        // mqd_t mq_open(const char *name, int oflag, mode_t mode,
        //               struct mq_attr *attr);
        return SYSCALL_INFO("mq_open", 4, INT, STR, INT, UINT, ADDR);

    case __NR_mq_unlink:
        // int mq_unlink(const char *name);
        return SYSCALL_INFO("mq_unlink", 1, INT, STR);

    case __NR_mq_timedsend:
        // int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
        //                  unsigned msg_prio, const struct timespec *abs_timeout);
        return SYSCALL_INFO("mq_timedsend", 5, INT, INT, A_CHAR, UINT, UINT, ADDR);

    case __NR_mq_timedreceive:
        // ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr,
        //                         size_t msg_len, unsigned *msg_prio,
        //                         const struct timespec *abs_timeout);
        return SYSCALL_INFO("mq_timedreceive", 5, INT, INT, A_CHAR, UINT, A_UINT, ADDR);

    case __NR_mq_notify:
        // int mq_notify(mqd_t mqdes, const struct sigevent *sevp);
        return SYSCALL_INFO("mq_notify", 2, INT, INT, ADDR);

    case __NR_mq_getsetattr:
        // int mq_getsetattr(mqd_t mqdes, const struct mq_attr *newattr,
        //                   struct mq_attr *oldattr);
        return SYSCALL_INFO("mq_getsetattr", 3, INT, INT, ADDR, ADDR);

    case __NR_kexec_load:
        // int kexec_load(unsigned long entry, unsigned long nr_segments,
        //                struct kexec_segment *segments, unsigned long flags);
        return SYSCALL_INFO("kexec_load", 4, INT, ULONG, ULONG, ADDR, ULONG);

    case __NR_waitid:
        // int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
        return SYSCALL_INFO("waitid", 4, INT, INT, INT, ADDR, INT);

    case __NR_add_key:
        // key_serial_t add_key(const char *type, const char *description,
        //                      const void *payload, size_t plen,
        //                      key_serial_t keyring);
        return SYSCALL_INFO("add_key", 5, INT, STR, STR, A_CHAR, UINT, INT);

    case __NR_request_key:
        // key_serial_t request_key(const char *type, const char *description,
        //                          const char *callout_info,
        //                          key_serial_t dest_keyring);
        return SYSCALL_INFO("request_key", 4, INT, STR, STR, STR, INT);

    case __NR_keyctl:
        // long keyctl(int cmd, unsigned long arg2, unsigned long arg3,
        //             unsigned long arg4, unsigned long arg5);
        return SYSCALL_INFO("keyctl", 5, LONG, INT, ULONG, ULONG, ULONG, ULONG);

    case __NR_ioprio_set:
        // int ioprio_set(int which, int who, int ioprio);
        return SYSCALL_INFO("ioprio_set", 3, INT, INT, INT, INT);

    case __NR_ioprio_get:
        // int ioprio_get(int which, int who);
        return SYSCALL_INFO("ioprio_get", 2, INT, INT, INT);

    case __NR_inotify_init:
        // int inotify_init(void);
        return SYSCALL_INFO("inotify_init", 0, INT);

    case __NR_inotify_add_watch:
        // int inotify_add_watch(int fd, const char *pathname, uint32_t mask);
        return SYSCALL_INFO("inotify_add_watch", 3, INT, INT, STR, UINT);

    case __NR_inotify_rm_watch:
        // int inotify_rm_watch(int fd, int wd);
        return SYSCALL_INFO("inotify_rm_watch", 2, INT, INT, INT);

    case __NR_migrate_pages:
        // long migrate_pages(int pid, unsigned long maxnode,
        //                    const unsigned long *old_nodes,
        //                    const unsigned long *new_nodes);
        return SYSCALL_INFO("migrate_pages", 4, LONG, INT, ULONG, A_ULONG, A_ULONG);

    case __NR_openat:
        // int openat(int dirfd, const char *pathname, int flags, mode_t mode);
        return SYSCALL_INFO("openat", 4, INT, INT, STR, INT, UINT);

    case __NR_mkdirat:
        // int mkdirat(int dirfd, const char *pathname, mode_t mode);
        return SYSCALL_INFO("mkdirat", 3, INT, INT, STR, UINT);

    case __NR_mknodat:
        // int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
        return SYSCALL_INFO("mknodat", 4, INT, INT, STR, UINT, UINT);

    case __NR_fchownat:
        // int fchownat(int dirfd, const char *pathname, uid_t owner,
        //              gid_t group, int flags);
        return SYSCALL_INFO("fchownat", 5, INT, INT, STR, UINT, UINT, INT);

    case __NR_futimesat:
        // int futimesat(int dirfd, const char *pathname,
        //               const struct timeval times[2]);
        return SYSCALL_INFO("futimesat", 3, INT, INT, STR, ADDR);

    case __NR_fstatat64:
        // int fstatat64(int dirfd, const char *pathname,
        //               struct stat64 *buf, int flags);
        return SYSCALL_INFO("fstatat64", 4, INT, INT, STR, ADDR, INT);

    case __NR_unlinkat:
        // int unlinkat(int dirfd, const char *pathname, int flags);
        return SYSCALL_INFO("unlinkat", 3, INT, INT, STR, INT);

    case __NR_renameat:
        // int renameat(int olddirfd, const char *oldpath,
        //              int newdirfd, const char *newpath);
        return SYSCALL_INFO("renameat", 4, INT, INT, STR, INT, STR);

    case __NR_linkat:
        // int linkat(int olddirfd, const char *oldpath, int newdirfd,
        //            const char *newpath, int flags);
        return SYSCALL_INFO("linkat", 5, INT, INT, STR, INT, STR, INT);

    case __NR_symlinkat:
        // int symlinkat(const char *target, int newdirfd, const char *linkpath);
        return SYSCALL_INFO("symlinkat", 3, INT, STR, INT, STR);

    case __NR_readlinkat:
        // ssize_t readlinkat(int dirfd, const char *pathname,
        //                    char *buf, size_t bufsiz);
        return SYSCALL_INFO("readlinkat", 4, INT, INT, STR, A_CHAR, UINT);

    case __NR_fchmodat:
        // int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
        return SYSCALL_INFO("fchmodat", 4, INT, INT, STR, UINT, INT);

    case __NR_faccessat:
        // int faccessat(int dirfd, const char *pathname, int mode, int flags);
        return SYSCALL_INFO("faccessat", 4, INT, INT, STR, INT, INT);

    case __NR_pselect6:
        // int pselect6(int nfds, fd_set *readfds, fd_set *writefds,
        //              fd_set *exceptfds, const struct timespec *timeout,
        //              void *sigmask);
        return SYSCALL_INFO("pselect6", 6, INT, INT, ADDR, ADDR, ADDR, ADDR, ADDR);

    case __NR_ppoll:
        // int ppoll(struct pollfd *fds, nfds_t nfds,
        //           const struct timespec *tmo_p, const sigset_t *sigmask,
        //           size_t sigsetsize);
        return SYSCALL_INFO("ppoll", 5, INT, ADDR, UINT, ADDR, ADDR, UINT);

    case __NR_unshare:
        // int unshare(int flags);
        return SYSCALL_INFO("unshare", 1, INT, INT);

    case __NR_set_robust_list:
        // long set_robust_list(struct robust_list_head *head, size_t len);
        return SYSCALL_INFO("set_robust_list", 2, LONG, ADDR, UINT);

    case __NR_get_robust_list:
        // long get_robust_list(int pid, struct robust_list_head **head_ptr,
        //                      size_t *len_ptr);
        return SYSCALL_INFO("get_robust_list", 3, LONG, INT, A_ADDR, A_UINT);

    case __NR_splice:
        // ssize_t splice(int fd_in, loff_t *off_in, int fd_out,
        //                loff_t *off_out, size_t len, unsigned int flags);
        return SYSCALL_INFO("splice", 6, INT, INT, A_LONG, INT, A_LONG, UINT, UINT);

    case __NR_sync_file_range:
        // int sync_file_range(int fd, off64_t offset,
        //                     off64_t nbytes, unsigned int flags);
        return SYSCALL_INFO("sync_file_range", 4, INT, INT, LONG, LONG, UINT);

    case __NR_tee:
        // ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags);
        return SYSCALL_INFO("tee", 4, INT, INT, INT, UINT, UINT);

    case __NR_vmsplice:
        // ssize_t vmsplice(int fd, const struct iovec *iov,
        //                  unsigned long nr_segs, unsigned int flags);
        return SYSCALL_INFO("vmsplice", 4, INT, INT, ADDR, ULONG, UINT);

    case __NR_move_pages:
        // long move_pages(int pid, unsigned long nr_pages, const void **pages,
        //                 const int *nodes, int *status, int flags);
        return SYSCALL_INFO("move_pages", 6, LONG, INT, ULONG, A_ADDR, A_INT, A_INT, INT);

    case __NR_getcpu:
        // int getcpu(unsigned *cpu, unsigned *node, void *cache);
        return SYSCALL_INFO("getcpu", 3, INT, A_UINT, A_UINT, ADDR);

    case __NR_epoll_pwait:
        // int epoll_pwait(int epfd, struct epoll_event *events,
        //                 int maxevents, int timeout, const sigset_t *sigmask,
        //                 size_t sigsetsize);
        return SYSCALL_INFO("epoll_pwait", 6, INT, INT, ADDR, INT, INT, ADDR, UINT);

    case __NR_utimensat:
        // int utimensat(int dirfd, const char *pathname,
        //               const struct timespec times[2], int flags);
        return SYSCALL_INFO("utimensat", 4, INT, INT, STR, ADDR, INT);

    case __NR_signalfd:
        // int signalfd(int fd, const sigset_t *mask, size_t sizemask);
        return SYSCALL_INFO("signalfd", 3, INT, INT, ADDR, UINT);

    case __NR_timerfd_create:
        // int timerfd_create(int clockid, int flags);
        return SYSCALL_INFO("timerfd_create", 2, INT, INT, INT);

    case __NR_eventfd:
        // int eventfd(unsigned int initval);
        return SYSCALL_INFO("eventfd", 1, INT, UINT);

    case __NR_fallocate:
        // int fallocate(int fd, int mode, off_t offset, off_t len);
        return SYSCALL_INFO("fallocate", 4, INT, INT, INT, LONG, LONG);

    case __NR_timerfd_settime:
        // int timerfd_settime(int fd, int flags,
        //                     const struct itimerspec *new_value,
        //                     struct itimerspec *old_value);
        return SYSCALL_INFO("timerfd_settime", 4, INT, INT, INT, ADDR, ADDR);

    case __NR_timerfd_gettime:
        // int timerfd_gettime(int fd, struct itimerspec *curr_value);
        return SYSCALL_INFO("timerfd_gettime", 2, INT, INT, ADDR);

    case __NR_signalfd4:
        // int signalfd4(int fd, const sigset_t *mask,
        //               size_t sizemask, int flags);
        return SYSCALL_INFO("signalfd4", 4, INT, INT, ADDR, UINT, INT);

    case __NR_eventfd2:
        // int eventfd2(unsigned int initval, int flags);
        return SYSCALL_INFO("eventfd2", 2, INT, UINT, INT);

    case __NR_epoll_create1:
        // int epoll_create1(int flags);
        return SYSCALL_INFO("epoll_create1", 1, INT, INT);

    case __NR_dup3:
        // int dup3(int oldfd, int newfd, int flags);
        return SYSCALL_INFO("dup3", 3, INT, INT, INT, INT);

    case __NR_pipe2:
        // int pipe2(int pipefd[2], int flags);
        return SYSCALL_INFO("pipe2", 2, INT, A_INT, INT);

    case __NR_inotify_init1:
        // int inotify_init1(int flags);
        return SYSCALL_INFO("inotify_init1", 1, INT, INT);

    case __NR_preadv:
        // ssize_t preadv(int fd, const struct iovec *iov,
        //                int iovcnt, off_t offset);
        return SYSCALL_INFO("preadv", 4, INT, INT, ADDR, INT, LONG);

    case __NR_pwritev:
        // ssize_t pwritev(int fd, const struct iovec *iov,
        //                 int iovcnt, off_t offset);
        return SYSCALL_INFO("pwritev", 4, INT, INT, ADDR, INT, LONG);

    case __NR_rt_tgsigqueueinfo:
        // int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *uinfo);
        return SYSCALL_INFO("rt_tgsigqueueinfo", 4, INT, INT, INT, INT, ADDR);

    case __NR_perf_event_open:
        // int perf_event_open(struct perf_event_attr *attr, pid_t pid,
        //                     int cpu, int group_fd, unsigned long flags);
        return SYSCALL_INFO("perf_event_open", 5, INT, ADDR, INT, INT, INT, ULONG);

    case __NR_recvmmsg:
        // int recvmmsg(int sockfd, struct mmsghdr *msgvec,
        //              unsigned int vlen, int flags, struct timespec *timeout);
        return SYSCALL_INFO("recvmmsg", 5, INT, INT, ADDR, UINT, INT, ADDR);

    case __NR_fanotify_init:
        // int fanotify_init(unsigned int flags, unsigned int event_f_flags);
        return SYSCALL_INFO("fanotify_init", 2, INT, UINT, UINT);

    case __NR_fanotify_mark:
        // int fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask,
        //                   int fd, const char *pathname);
        return SYSCALL_INFO("fanotify_mark", 5, INT, INT, UINT, ULONG, INT, STR);

    case __NR_prlimit64:
        // int prlimit64(pid_t pid, int resource,
        //               const struct rlimit *new_limit, struct rlimit *old_limit);
        return SYSCALL_INFO("prlimit64", 4, INT, INT, INT, ADDR, ADDR);

    case __NR_name_to_handle_at:
        // int name_to_handle_at(int dirfd, const char *pathname,
        //                       struct file_handle *handle, int *mount_id, int flags);
        return SYSCALL_INFO("name_to_handle_at", 5, INT, INT, STR, ADDR, A_INT, INT);

    case __NR_open_by_handle_at:
        // int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags);
        return SYSCALL_INFO("open_by_handle_at", 3, INT, INT, ADDR, INT);

    case __NR_clock_adjtime:
        // int clock_adjtime(clockid_t clk_id, struct timex *buf);
        return SYSCALL_INFO("clock_adjtime", 2, INT, INT, ADDR);

    case __NR_syncfs:
        // int syncfs(int fd);
        return SYSCALL_INFO("syncfs", 1, INT, INT);

    case __NR_sendmmsg:
        // int sendmmsg(int sockfd, struct mmsghdr *msgvec,
        //              unsigned int vlen, int flags);
        return SYSCALL_INFO("sendmmsg", 4, INT, INT, ADDR, UINT, INT);

    case __NR_setns:
        // int setns(int fd, int nstype);
        return SYSCALL_INFO("setns", 2, INT, INT, INT);

    case __NR_process_vm_readv:
        // ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov,
        //                          unsigned long liovcnt, const struct iovec *remote_iov,
        //                          unsigned long riovcnt, unsigned long flags);
        return SYSCALL_INFO("process_vm_readv", 6, INT, INT, ADDR, ULONG, ADDR, ULONG, ULONG);

    case __NR_process_vm_writev:
        // ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov,
        //                           unsigned long liovcnt, const struct iovec *remote_iov,
        //                           unsigned long riovcnt, unsigned long flags);
        return SYSCALL_INFO("process_vm_writev", 6, INT, INT, ADDR, ULONG, ADDR, ULONG, ULONG);

    case __NR_kcmp:
        // int kcmp(pid_t pid1, pid_t pid2, int type,
        //          unsigned long idx1, unsigned long idx2);
        return SYSCALL_INFO("kcmp", 5, INT, INT, INT, INT, ULONG, ULONG);

    case __NR_finit_module:
        // int finit_module(int fd, const char *param_values, int flags);
        return SYSCALL_INFO("finit_module", 3, INT, INT, STR, INT);

    case __NR_sched_setattr:
        // int sched_setattr(pid_t pid, const struct sched_attr *attr,
        //                   unsigned int flags);
        return SYSCALL_INFO("sched_setattr", 3, INT, INT, ADDR, UINT);

    case __NR_sched_getattr:
        // int sched_getattr(pid_t pid, struct sched_attr *attr,
        //                   unsigned int size, unsigned int flags);
        return SYSCALL_INFO("sched_getattr", 4, INT, INT, ADDR, UINT, UINT);

    case __NR_renameat2:
        // int renameat2(int olddirfd, const char *oldpath, int newdirfd,
        //               const char *newpath, unsigned int flags);
        return SYSCALL_INFO("renameat2", 5, INT, INT, STR, INT, STR, UINT);

    case __NR_seccomp:
        // int seccomp(unsigned int operation, unsigned int flags,
        //             const char *uargs);
        return SYSCALL_INFO("seccomp", 3, INT, UINT, UINT, STR);

    case __NR_getrandom:
        // ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
        return SYSCALL_INFO("getrandom", 3, INT, A_CHAR, UINT, UINT);

    case __NR_memfd_create:
        // int memfd_create(const char *name, unsigned int flags);
        return SYSCALL_INFO("memfd_create", 2, INT, STR, UINT);

    case __NR_bpf:
        // int bpf(int cmd, union bpf_attr *attr, unsigned int size);
        return SYSCALL_INFO("bpf", 3, INT, INT, ADDR, UINT);

    case __NR_execveat:
        // int execveat(int dirfd, const char *pathname,
        //              char *const argv[], char *const envp[], int flags);
        return SYSCALL_INFO("execveat", 5, INT, INT, STR, A_STR, A_STR, INT);

    case __NR_socket:
        // int socket(int domain, int type, int protocol);
        return SYSCALL_INFO("socket", 3, INT, INT, INT, INT);

    case __NR_socketpair:
        // int socketpair(int domain, int type, int protocol, int sv[2]);
        return SYSCALL_INFO("socketpair", 4, INT, INT, INT, INT, A_INT);

    case __NR_bind:
        // int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        return SYSCALL_INFO("bind", 3, INT, INT, ADDR, UINT);

    case __NR_connect:
        // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        return SYSCALL_INFO("connect", 3, INT, INT, ADDR, UINT);

    case __NR_listen:
        // int listen(int sockfd, int backlog);
        return SYSCALL_INFO("listen", 2, INT, INT, INT);

    case __NR_accept4:
        // int accept4(int sockfd, struct sockaddr *addr,
        //             socklen_t *addrlen, int flags);
        return SYSCALL_INFO("accept4", 4, INT, INT, ADDR, ADDR, INT);

    case __NR_getsockopt:
        // int getsockopt(int sockfd, int level, int optname,
        //                void *optval, socklen_t *optlen);
        return SYSCALL_INFO("getsockopt", 5, INT, INT, INT, INT, ADDR, ADDR);

    case __NR_setsockopt:
        // int setsockopt(int sockfd, int level, int optname,
        //                const void *optval, socklen_t optlen);
        return SYSCALL_INFO("setsockopt", 5, INT, INT, INT, INT, ADDR, UINT);

    case __NR_getsockname:
        // int getsockname(int sockfd, struct sockaddr *addr,
        //                 socklen_t *addrlen);
        return SYSCALL_INFO("getsockname", 3, INT, INT, ADDR, ADDR);

    case __NR_getpeername:
        // int getpeername(int sockfd, struct sockaddr *addr,
        //                 socklen_t *addrlen);
        return SYSCALL_INFO("getpeername", 3, INT, INT, ADDR, ADDR);

    case __NR_sendto:
        // ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
        //                const struct sockaddr *dest_addr, socklen_t addrlen);
        return SYSCALL_INFO("sendto", 6, INT, INT, A_CHAR, UINT, INT, ADDR, UINT);

    case __NR_sendmsg:
        // ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
        return SYSCALL_INFO("sendmsg", 3, INT, INT, ADDR, INT);

    case __NR_recvfrom:
        // ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
        //                  struct sockaddr *src_addr, socklen_t *addrlen);
        return SYSCALL_INFO("recvfrom", 6, INT, INT, A_CHAR, UINT, INT, ADDR, ADDR);

    case __NR_recvmsg:
        // ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
        return SYSCALL_INFO("recvmsg", 3, INT, INT, ADDR, INT);

    case __NR_shutdown:
        // int shutdown(int sockfd, int how);
        return SYSCALL_INFO("shutdown", 2, INT, INT, INT);

    case __NR_userfaultfd:
        // int userfaultfd(int flags);
        return SYSCALL_INFO("userfaultfd", 1, INT, INT);

    case __NR_membarrier:
        // int membarrier(int cmd, int flags, int cpu_id);
        return SYSCALL_INFO("membarrier", 3, INT, INT, INT, INT);

    case __NR_mlock2:
        // int mlock2(const void *addr, size_t len, int flags);
        return SYSCALL_INFO("mlock2", 3, INT, ADDR, UINT, INT);

    case __NR_copy_file_range:
        // ssize_t copy_file_range(int fd_in, loff_t *off_in, int fd_out,
        //                         loff_t *off_out, size_t len, unsigned int flags);
        return SYSCALL_INFO("copy_file_range", 6, INT, INT, A_LONG, INT, A_LONG, UINT, UINT);

    case __NR_preadv2:
        // ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt,
        //                 off_t offset, int flags);
        return SYSCALL_INFO("preadv2", 5, INT, INT, ADDR, INT, LONG, INT);

    case __NR_pwritev2:
        // ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt,
        //                  off_t offset, int flags);
        return SYSCALL_INFO("pwritev2", 5, INT, INT, ADDR, INT, LONG, INT);

    case __NR_pkey_mprotect:
        // int pkey_mprotect(void *addr, size_t len, int prot, int pkey);
        return SYSCALL_INFO("pkey_mprotect", 4, INT, ADDR, UINT, INT, INT);

    case __NR_pkey_alloc:
        // int pkey_alloc(unsigned int flags, unsigned int access_rights);
        return SYSCALL_INFO("pkey_alloc", 2, INT, UINT, UINT);

    case __NR_pkey_free:
        // int pkey_free(int pkey);
        return SYSCALL_INFO("pkey_free", 1, INT, INT);

    case __NR_statx:
        // int statx(int dirfd, const char *pathname,
        //           int flags, unsigned int mask, struct statx *statxbuf);
        return SYSCALL_INFO("statx", 5, INT, INT, STR, INT, UINT, ADDR);

    case __NR_arch_prctl:
        // int arch_prctl(int code, unsigned long addr);
        return SYSCALL_INFO("arch_prctl", 2, INT, INT, ULONG);

    case __NR_io_pgetevents:
        // int io_pgetevents(aio_context_t ctx_id, long min_nr, long nr,
        //                   struct io_event *events, struct timespec *timeout,
        //                   const struct __aio_sigset *usig);
        return SYSCALL_INFO("io_pgetevents", 6, INT, ULONG, LONG, LONG, ADDR, ADDR, ADDR);

    case __NR_rseq:
        // int rseq(struct rseq *rseq, uint32_t rseq_len, int flags, uint32_t sig);
        return SYSCALL_INFO("rseq", 4, INT, ADDR, UINT, INT, UINT);

    case __NR_semget:
        // int semget(key_t key, int nsems, int semflg);
        return SYSCALL_INFO("semget", 3, INT, INT, INT, INT);

    case __NR_semctl:
        // int semctl(int semid, int semnum, int cmd, ...);
        return SYSCALL_INFO("semctl", 4, INT, INT, INT, INT, ADDR);

    case __NR_shmget:
        // int shmget(key_t key, size_t size, int shmflg);
        return SYSCALL_INFO("shmget", 3, INT, INT, UINT, INT);

    case __NR_shmctl:
        // int shmctl(int shmid, int cmd, struct shmid_ds *buf);
        return SYSCALL_INFO("shmctl", 3, INT, INT, INT, ADDR);

    case __NR_shmat:
        // void *shmat(int shmid, const void *shmaddr, int shmflg);
        return SYSCALL_INFO("shmat", 3, ADDR, INT, ADDR, INT);

    case __NR_shmdt:
        // int shmdt(const void *shmaddr);
        return SYSCALL_INFO("shmdt", 1, INT, ADDR);

    case __NR_msgget:
        // int msgget(key_t key, int msgflg);
        return SYSCALL_INFO("msgget", 2, INT, INT, INT);

    case __NR_msgsnd:
        // int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
        return SYSCALL_INFO("msgsnd", 4, INT, INT, A_CHAR, UINT, INT);

    case __NR_msgrcv:
        // ssize_t msgrcv(int msqid, void *msgp, size_t msgsz,
        //                long msgtyp, int msgflg);
        return SYSCALL_INFO("msgrcv", 5, INT, INT, A_CHAR, UINT, LONG, INT);

    case __NR_msgctl:
        // int msgctl(int msqid, int cmd, struct msqid_ds *buf);
        return SYSCALL_INFO("msgctl", 3, INT, INT, INT, ADDR);

    case __NR_clock_gettime64:
        // int clock_gettime64(clockid_t clk_id, struct __timespec64 *tp);
        return SYSCALL_INFO("clock_gettime64", 2, INT, INT, ADDR);

    case __NR_clock_settime64:
        // int clock_settime64(clockid_t clk_id, const struct __timespec64 *tp);
        return SYSCALL_INFO("clock_settime64", 2, INT, INT, ADDR);

    case __NR_clock_adjtime64:
        // int clock_adjtime64(clockid_t clk_id, struct __timex64 *buf);
        return SYSCALL_INFO("clock_adjtime64", 2, INT, INT, ADDR);

    case __NR_clock_getres_time64:
        // int clock_getres_time64(clockid_t clk_id, struct __timespec64 *res);
        return SYSCALL_INFO("clock_getres_time64", 2, INT, INT, ADDR);

    case __NR_clock_nanosleep_time64:
        // int clock_nanosleep_time64(clockid_t clk_id, int flags,
        //                            const struct __timespec64 *request,
        //                            struct __timespec64 *remain);
        return SYSCALL_INFO("clock_nanosleep_time64", 4, INT, INT, INT, ADDR, ADDR);

    case __NR_timer_gettime64:
        // int timer_gettime64(timer_t timerid, struct __itimerspec64 *curr_value);
        return SYSCALL_INFO("timer_gettime64", 2, INT, INT, ADDR);

    case __NR_timer_settime64:
        // int timer_settime64(timer_t timerid, int flags,
        //                     const struct __timespec64 *new_value,
        //                     struct __timespec64 *old_value);
        return SYSCALL_INFO("timer_settime64", 4, INT, INT, INT, ADDR, ADDR);

    case __NR_timerfd_gettime64:
        // int timerfd_gettime64(int fd, struct __itimerspec64 *curr_value);
        return SYSCALL_INFO("timerfd_gettime64", 2, INT, INT, ADDR);

    case __NR_timerfd_settime64:
        // int timerfd_settime64(int fd, int flags,
        //                       const struct __timespec64 *new_value,
        //                       struct __timespec64 *old_value);
        return SYSCALL_INFO("timerfd_settime64", 4, INT, INT, INT, ADDR, ADDR);

    case __NR_utimensat_time64:
        // int utimensat_time64(int dirfd, const char *pathname,
        //                      const struct __timespec64 times[2], int flags);
        return SYSCALL_INFO("utimensat_time64", 4, INT, INT, STR, ADDR, INT);

    case __NR_pselect6_time64:
        // int pselect6_time64(int nfds, fd_set *readfds, fd_set *writefds,
        //                     fd_set *exceptfds, const struct __timespec64 *timeout,
        //                     void *sigmask);
        return SYSCALL_INFO("pselect6_time64", 6, INT, INT, ADDR, ADDR, ADDR, ADDR, ADDR);

    case __NR_ppoll_time64:
        // int ppoll_time64(struct pollfd *fds, nfds_t nfds,
        //                  const struct __timespec64 *tmo_p,
        //                  const sigset_t *sigmask, size_t sigsetsize);
        return SYSCALL_INFO("ppoll_time64", 5, INT, ADDR, UINT, ADDR, ADDR, UINT);

    case __NR_io_pgetevents_time64:
        // int io_pgetevents_time64(aio_context_t ctx_id, long min_nr, long nr,
        //                          struct io_event *events,
        //                          struct __timespec64 *timeout,
        //                          const struct __aio_sigset *usig);
        return SYSCALL_INFO("io_pgetevents_time64", 6, INT, ULONG, LONG, LONG, ADDR, ADDR, ADDR);

    case __NR_recvmmsg_time64:
        // int recvmmsg_time64(int sockfd, struct mmsghdr *msgvec,
        //                     unsigned int vlen, int flags,
        //                     struct __timespec64 *timeout);
        return SYSCALL_INFO("recvmmsg_time64", 5, INT, INT, ADDR, UINT, INT, ADDR);

    case __NR_mq_timedsend_time64:
        // int mq_timedsend_time64(mqd_t mqdes, const char *msg_ptr,
        //                         size_t msg_len, unsigned msg_prio,
        //                         const struct __timespec64 *abs_timeout);
        return SYSCALL_INFO("mq_timedsend_time64", 5, INT, INT, A_CHAR, UINT, UINT, ADDR);

    case __NR_mq_timedreceive_time64:
        // int mq_timedreceive_time64(mqd_t mqdes, char *msg_ptr,
        //                            size_t msg_len, unsigned *msg_prio,
        //                            const struct __timespec64 *abs_timeout);
        return SYSCALL_INFO("mq_timedreceive_time64", 5, INT, INT, A_CHAR, UINT, A_UINT, ADDR);

    case __NR_semtimedop_time64:
        // int semtimedop_time64(int semid, struct sembuf *sops,
        //                       size_t nsops, const struct __timespec64 *timeout);
        return SYSCALL_INFO("semtimedop_time64", 4, INT, INT, ADDR, UINT, ADDR);

    case __NR_rt_sigtimedwait_time64:
        // int rt_sigtimedwait_time64(const sigset_t *set, siginfo_t *info,
        //                            const struct __timespec64 *timeout,
        //                            size_t sigsetsize);
        return SYSCALL_INFO("rt_sigtimedwait_time64", 4, INT, ADDR, ADDR, ADDR, UINT);

    case __NR_futex_time64:
        // int futex_time64(int *uaddr, int futex_op, int val,
        //                  const struct __timespec64 *timeout,
        //                  int *uaddr2, int val3);
        return SYSCALL_INFO("futex_time64", 6, INT, A_INT, INT, INT, ADDR, A_INT, INT);

    case __NR_sched_rr_get_interval_time64:
        // int sched_rr_get_interval_time64(pid_t pid,
        //                                  struct __timespec64 *tp);
        return SYSCALL_INFO("sched_rr_get_interval_time64", 2, INT, INT, ADDR);

    case __NR_pidfd_send_signal:
        // int pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
        //                       unsigned int flags);
        return SYSCALL_INFO("pidfd_send_signal", 4, INT, INT, INT, ADDR, UINT);

    case __NR_io_uring_setup:
        // int io_uring_setup(unsigned int entries, struct io_uring_params *p);
        return SYSCALL_INFO("io_uring_setup", 2, INT, UINT, ADDR);

    case __NR_io_uring_enter:
        // int io_uring_enter(int fd, unsigned int to_submit,
        //                    unsigned int min_complete, unsigned int flags,
        //                    const sigset_t *sig, size_t sigsz);
        return SYSCALL_INFO("io_uring_enter", 6, INT, INT, UINT, UINT, UINT, ADDR, UINT);

    case __NR_io_uring_register:
        // int io_uring_register(int fd, unsigned int opcode,
        //                       void *arg, unsigned int nr_args);
        return SYSCALL_INFO("io_uring_register", 4, INT, INT, UINT, ADDR, UINT);

    case __NR_open_tree:
        // int open_tree(int dfd, const char *filename, unsigned flags);
        return SYSCALL_INFO("open_tree", 3, INT, INT, STR, UINT);

    case __NR_move_mount:
        // int move_mount(int from_dfd, const char *from_path,
        //                int to_dfd, const char *to_path, unsigned int flags);
        return SYSCALL_INFO("move_mount", 5, INT, INT, STR, INT, STR, UINT);

    case __NR_fsopen:
        // int fsopen(const char *fs_name, unsigned int flags);
        return SYSCALL_INFO("fsopen", 2, INT, STR, UINT);

    case __NR_fsconfig:
        // int fsconfig(int fs_fd, unsigned int cmd, const char *key,
        //              const void *value, int aux);
        return SYSCALL_INFO("fsconfig", 5, INT, INT, UINT, STR, ADDR, INT);

    case __NR_fsmount:
        // int fsmount(int fs_fd, int fd, unsigned int flags,
        //             unsigned int ms_flags);
        return SYSCALL_INFO("fsmount", 4, INT, INT, INT, UINT, UINT);

    case __NR_fspick:
        // int fspick(int dfd, const char *path, unsigned int flags);
        return SYSCALL_INFO("fspick", 3, INT, INT, STR, UINT);

    case __NR_pidfd_open:
        // int pidfd_open(pid_t pid, unsigned int flags);
        return SYSCALL_INFO("pidfd_open", 2, INT, INT, UINT);

    case __NR_clone3:
        // pid_t clone3(struct clone_args *cl_args, size_t size);
        return SYSCALL_INFO("clone3", 2, INT, ADDR, UINT);

    case __NR_close_range:
        // int close_range(unsigned int first, unsigned int last,
        //                 unsigned int flags);
        return SYSCALL_INFO("close_range", 3, INT, UINT, UINT, UINT);

    case __NR_openat2:
        // int openat2(int dfd, const char *filename,
        //             struct open_how *how, size_t size);
        return SYSCALL_INFO("openat2", 4, INT, INT, STR, ADDR, UINT);

    case __NR_pidfd_getfd:
        // int pidfd_getfd(int pidfd, int fd, unsigned int flags);
        return SYSCALL_INFO("pidfd_getfd", 3, INT, INT, INT, UINT);

    case __NR_faccessat2:
        // int faccessat2(int dirfd, const char *pathname,
        //                int mode, int flags);
        return SYSCALL_INFO("faccessat2", 4, INT, INT, STR, INT, INT);

    case __NR_process_madvise:
        // int process_madvise(int pidfd, const struct iovec *iovec,
        //                     size_t vlen, int behavior, unsigned int flags);
        return SYSCALL_INFO("process_madvise", 5, INT, INT, ADDR, UINT, INT, UINT);

    case __NR_epoll_pwait2:
        // int epoll_pwait2(int epfd, struct epoll_event *events,
        //                  int maxevents, const struct timespec *timeout,
        //                  const sigset_t *sigmask, size_t sigsetsize);
        return SYSCALL_INFO("epoll_pwait2", 6, INT, INT, ADDR, INT, ADDR, ADDR, UINT);

    case __NR_mount_setattr:
        // int mount_setattr(int dfd, const char *path, unsigned int flags,
        //                   struct mount_attr *uattr, size_t size);
        return SYSCALL_INFO("mount_setattr", 5, INT, INT, STR, UINT, ADDR, UINT);

    case __NR_quotactl_fd:
        // int quotactl_fd(int fd, unsigned int cmd, qid_t id, void *addr);
        return SYSCALL_INFO("quotactl_fd", 4, INT, INT, UINT, INT, ADDR);

    case __NR_landlock_create_ruleset:
        // int landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
        //                             size_t size, __u32 flags);
        return SYSCALL_INFO("landlock_create_ruleset", 3, INT, ADDR, UINT, UINT);

    case __NR_landlock_add_rule:
        // int landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type,
        //                       const void *rule_attr, __u32 flags);
        return SYSCALL_INFO("landlock_add_rule", 4, INT, INT, INT, ADDR, UINT);

    case __NR_landlock_restrict_self:
        // int landlock_restrict_self(int ruleset_fd, __u32 flags);
        return SYSCALL_INFO("landlock_restrict_self", 2, INT, INT, UINT);

    case __NR_memfd_secret:
        // int memfd_secret(unsigned int flags);
        return SYSCALL_INFO("memfd_secret", 1, INT, UINT);

    case __NR_process_mrelease:
        // int process_mrelease(int pidfd, unsigned int flags);
        return SYSCALL_INFO("process_mrelease", 2, INT, INT, UINT);

    default:
        break;
    }
    char unknown[1024] = {0};
    sprintf(unknown, "syscall_0x%ld", data.syscall.id);
    return SYSCALL_INFO(unknown, 6, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);
}
#endif
