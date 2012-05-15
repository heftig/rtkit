/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of RealtimeKit.

  Copyright 2009 Lennart Poettering
  Copyright 2010 Maarten Lankhorst

  RealtimeKit is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  RealtimeKit is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with RealtimeKit. If not, see <http://www.gnu.org/licenses/>.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <inttypes.h>
#include <dbus/dbus.h>
#include <pwd.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <time.h>
#include <assert.h>
#include <getopt.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include <dirent.h>
#include <syslog.h>
#include <grp.h>

#include "rtkit.h"
#include "sd-daemon.h"

#ifndef __linux__
#error "This stuff only works on Linux!"
#endif

#ifndef SCHED_RESET_ON_FORK
/* "Your libc lacks the definition of SCHED_RESET_ON_FORK. We'll now define it ourselves, however make sure your kernel is new enough! */
#define SCHED_RESET_ON_FORK 0x40000000
#endif

#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME 15
#endif

#define INTROSPECT_XML                                                  \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        "        <interface name=\"org.freedesktop.RealtimeKit1\">\n"   \
        "                <method name=\"MakeThreadRealtime\">\n"        \
        "                        <arg name=\"thread\" type=\"t\" direction=\"in\"/>\n" \
        "                        <arg name=\"priority\" type=\"u\" direction=\"in\"/>\n" \
        "                </method>\n"                                   \
        "                <method name=\"MakeThreadRealtimeWithPID\">\n"        \
        "                        <arg name=\"process\" type=\"t\" direction=\"in\"/>\n" \
        "                        <arg name=\"thread\" type=\"t\" direction=\"in\"/>\n" \
        "                        <arg name=\"priority\" type=\"u\" direction=\"in\"/>\n" \
        "                </method>\n"                                   \
        "                <method name=\"MakeThreadHighPriority\">\n"          \
        "                        <arg name=\"thread\" type=\"t\" direction=\"in\"/>\n" \
        "                        <arg name=\"priority\" type=\"i\" direction=\"in\"/>\n" \
        "                </method>\n"                                   \
        "                <method name=\"MakeThreadHighPriorityWithPID\">\n"          \
        "                        <arg name=\"process\" type=\"t\" direction=\"in\"/>\n" \
        "                        <arg name=\"thread\" type=\"t\" direction=\"in\"/>\n" \
        "                        <arg name=\"priority\" type=\"i\" direction=\"in\"/>\n" \
        "                </method>\n"                                   \
        "                <method name=\"ResetKnown\"/>\n"               \
        "                <method name=\"ResetAll\"/>\n"                 \
        "                <method name=\"Exit\"/>\n"                     \
        "                <property name=\"RTTimeUSecMax\" type=\"x\" access=\"read\"/>\n" \
        "                <property name=\"MaxRealtimePriority\" type=\"i\" access=\"read\"/>\n" \
        "                <property name=\"MinNiceLevel\" type=\"i\" access=\"read\"/>\n" \
        "        </interface>\n"                                        \
        "        <interface name=\"org.freedesktop.DBus.Properties\">\n"\
        "                <method name=\"Get\">"                         \
        "                       <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n" \
        "                       <arg name=\"property\" direction=\"in\" type=\"s\"/>\n" \
        "                       <arg name=\"value\" direction=\"out\" type=\"v\"/>\n" \
        "                </method>\n"                                   \
        "        </interface>\n"                                        \
        "        <interface name=\"org.freedesktop.DBus.Introspectable\">\n" \
        "                <method name=\"Introspect\">\n"                \
        "                        <arg name=\"data\" type=\"s\" direction=\"out\"/>\n" \
        "                </method>\n"                                   \
        "        </interface>\n"                                        \
        "</node>\n"

/* Similar to assert(), but has side effects, and hence shall never be optimized away, regardless of NDEBUG */
#define assert_se(expr)                                                 \
        do {                                                            \
                if (__builtin_expect(!(expr), 0)) {                     \
                        fprintf(stderr, "Assertion %s failed at %s:%u, function %s(). Aborting.\n", #expr, __FILE__, __LINE__, __PRETTY_FUNCTION__); \
                        abort();                                        \
                }                                                       \
        } while(0)

#define ELEMENTSOF(x) (sizeof(x)/sizeof(x[0]))

#define TIMESPEC_MSEC(ts) (((int64_t) (ts).tv_sec * 1000LL) + ((int64_t) (ts).tv_nsec / 1000000LL))

/* If we actually execute a request we temporarily upgrade our realtime priority to this level */
static unsigned our_realtime_priority = 21;

/* Normally we run at this nice level */
static int our_nice_level = 1;

/* The maximum realtime priority to hand out */
static unsigned max_realtime_priority = 20;

/* The minimum nice level to hand out */
static int min_nice_level = -15;

/* Username we shall run under */
static const char *username = "rtkit";

/* Enforce that clients have RLIMIT_RTTIME set to a value <= this */
static unsigned long long rttime_usec_max = 200000ULL; /* 200 ms */

/* How many users do we supervise at max? */
static unsigned users_max = 2048;

/* How many processes of a single user do we supervise at max? */
static unsigned processes_per_user_max = 15;

/* How many threads of a single user do we supervise at max? */
static unsigned threads_per_user_max = 25;

/* Refuse further requests if one user issues more than ACTIONS_PER_BURST_MAX in this time */
static unsigned actions_burst_sec = 20;

/* Refuse further requests if one user issues more than this many in ACTIONS_BURST_SEC time */
static unsigned actions_per_burst_max = 25;

/* Drop privileges */
static bool do_drop_privileges = TRUE;

/* Change root directory to /proc */
static bool do_chroot = TRUE;

/* Limit resources */
static bool do_limit_resources = TRUE;

/* Run a canary watchdog */
static bool do_canary = TRUE;

/* Canary cheep interval */
static unsigned canary_cheep_msec = 5000; /* 5s */

/* Canary watchdog interval */
static unsigned canary_watchdog_msec = 10000; /* 10s */

/* Watchdog realtime priority */
static unsigned canary_watchdog_realtime_priority = 99;

/* How long after the canary died shall we refuse further RT requests? */
static unsigned canary_refusal_sec = 5*60;

/* Demote root processes? */
static bool canary_demote_root = FALSE;

/* Demote unknown processes? */
static bool canary_demote_unknown = FALSE;

/* Log to stderr? */
static bool log_stderr = FALSE;

/* Scheduling policy to use */
static int sched_policy = SCHED_RR;

struct thread {
        /* We use the thread id plus its starttime as a unique identifier for threads */
        pid_t pid;
        unsigned long long starttime;

        struct thread *next;
};

struct process {
        /* We use the process id plus its starttime as a unique identifier for processes */
        pid_t pid;
        unsigned long long starttime;

        struct thread *threads;
        struct process *next;
};

struct rtkit_user {
        uid_t uid;

        time_t timestamp;
        unsigned n_actions;

        struct process *processes;
        unsigned n_processes;
        unsigned n_threads;

        struct rtkit_user *next;
};

static struct rtkit_user *users = NULL;
static unsigned n_users = 0;
static unsigned n_total_processes = 0;
static unsigned n_total_threads = 0;
static const char *proc = NULL;
static int quit_fd = -1, canary_fd = -1;
static pthread_t canary_thread_id = 0, watchdog_thread_id = 0;
static volatile uint32_t refuse_until = 0;

static const char *get_proc_path(void) {
        /* Useful for chroot environments */

        if (proc)
                return proc;

        return "/proc";
}

static char* get_user_name(uid_t uid, char *user, size_t len) {
        struct passwd *pw;

        if ((pw = getpwuid(uid))) {
                strncpy(user, pw->pw_name, len-1);
                user[len-1] = 0;
                return user;
        }

        snprintf(user, len-1, "%llu", (unsigned long long) uid);
        user[len-1] = 0;
        return user;
}

static int read_starttime(pid_t pid, pid_t tid, unsigned long long *st) {
        char fn[128], line[256], *p;
        int r;
        FILE *f;

        if (tid != 0)
                assert_se(snprintf(fn, sizeof(fn)-1, "%s/%llu/task/%llu/stat", get_proc_path(), (unsigned long long) pid, (unsigned long long) tid) < (int) (sizeof(fn)-1));
        else
                assert_se(snprintf(fn, sizeof(fn)-1, "%s/%llu/stat", get_proc_path(), (unsigned long long) pid) < (int) (sizeof(fn)-1));
        fn[sizeof(fn)-1] = 0;

        if (!(f = fopen(fn, "r")))
                return -errno;

        if (!(fgets(line, sizeof(line), f))) {
                r = -errno;
                fclose(f);
                return r;
        }

        fclose(f);

        /* Let's skip the pid and comm fields. The latter is enclosed
         * in () but does not escape any () in its value, so let's
         * skip over it manually */

        if (!(p = strrchr(line, ')')))
                return -EIO;

        p++;

        if (sscanf(p, " "
                   "%*c "  /* state */
                   "%*d "  /* ppid */
                   "%*d "  /* pgrp */
                   "%*d "  /* session */
                   "%*d "  /* tty_nr */
                   "%*d "  /* tpgid */
                   "%*u "  /* flags */
                   "%*u "  /* minflt */
                   "%*u "  /* cminflt */
                   "%*u "  /* majflt */
                   "%*u "  /* cmajflt */
                   "%*u "  /* utime */
                   "%*u "  /* stime */
                   "%*d "  /* cutime */
                   "%*d "  /* cstime */
                   "%*d "  /* priority */
                   "%*d "  /* nice */
                   "%*d "  /* num_threads */
                   "%*d "  /* itrealvalue */
                   "%llu "  /* starttime */,
                   st) != 1)
                return -EIO;

        return 0;
}

static void free_thread(struct thread *t) {
        free(t);
}

static void free_process(struct process *p) {
        struct thread *t;

        while ((t = p->threads)) {
                p->threads = t->next;
                free_thread(t);
        }

        free(p);
}

static void free_user(struct rtkit_user *u) {
        struct process *p;

        while ((p = u->processes)) {
                u->processes = p->next;
                free_process(p);
        }

        free(u);
}

static bool user_in_burst(struct rtkit_user *u) {
        time_t now = time(NULL);

        return now < u->timestamp + (time_t) actions_burst_sec;
}

static bool verify_burst(struct rtkit_user *u) {

        if (!user_in_burst(u)) {
                /* Restart burst phase */
                time(&u->timestamp);
                u->n_actions = 0;
                return true;
        }

        if (u->n_actions >= actions_per_burst_max) {
                char user[64];
                syslog(LOG_WARNING, "Warning: Reached burst limit for user '%s', denying request.\n", get_user_name(u->uid, user, sizeof(user)));
                return false;
        }

        u->n_actions++;
        return true;
}

static int find_user(struct rtkit_user **_u, uid_t uid) {
        struct rtkit_user *u;

        for (u = users; u; u = u->next)
                if (u->uid == uid) {
                        *_u = u;
                        return 0;
                }

        if (n_users >= users_max)  {
                syslog(LOG_WARNING, "Warning: Reached maximum concurrent user limit, denying request.\n");
                return -EBUSY;
        }

        if (!(u = malloc(sizeof(struct rtkit_user))))
                return -ENOMEM;

        u->uid = uid;
        u->timestamp = time(NULL);
        u->n_actions = 0;
        u->processes = NULL;
        u->n_processes = u->n_threads = 0;
        u->next = users;
        users = u;
        n_users++;

        *_u = u;
        return 0;
}

static int find_process(struct process** _p, struct rtkit_user *u, pid_t pid, unsigned long long starttime) {
        struct process *p;

        for (p = u->processes; p; p = p->next)
                if (p->pid == pid && p->starttime == starttime) {
                        *_p = p;
                        return 0;
                }

        if (u->n_processes >= processes_per_user_max) {
                char user[64];
                syslog(LOG_WARNING, "Warning: Reached maximum concurrent process limit for user '%s', denying request.\n", get_user_name(u->uid, user, sizeof(user)));
                return -EBUSY;
        }

        if (!(p = malloc(sizeof(struct process))))
                return -ENOMEM;

        p->pid = pid;
        p->starttime = starttime;
        p->threads = NULL;
        p->next = u->processes;
        u->processes = p;
        u->n_processes++;
        n_total_processes++;

        *_p = p;
        return 0;
}

static int find_thread(struct thread** _t, struct rtkit_user *u, struct process *p, pid_t pid, unsigned long long starttime) {
        struct thread *t;

        for (t = p->threads; t; t = t->next)
                if (t->pid == pid && t->starttime == starttime)  {
                        *_t = t;
                        return 0;
                }

        if (u->n_threads >= threads_per_user_max) {
                char user[64];
                syslog(LOG_WARNING, "Warning: Reached maximum concurrent threads limit for user '%s', denying request.\n", get_user_name(u->uid, user, sizeof(user)));
                return -EBUSY;
        }

        if (!(t = malloc(sizeof(struct thread))))
                return -ENOMEM;

        t->pid = pid;
        t->starttime = starttime;
        t->next = p->threads;
        p->threads = t;
        u->n_threads++;
        n_total_threads++;

        *_t = t;
        return 0;
}

static bool thread_relevant(struct process *p, struct thread *t) {
        unsigned long long st;
        int r;

        /* This checks if a thread still matters to us, i.e. if its
         * PID still refers to the same thread and if it is still high
         * priority or real time */

        if ((r = read_starttime(p->pid, t->pid, &st)) < 0) {

                /* Did the thread die? */
                if (r == -ENOENT)
                        return FALSE;

                syslog(LOG_WARNING, "Warning: failed to read start time: %s\n", strerror(-r));
                return FALSE;
        }

        /* Did the thread get replaced by another thread? */
        if (st != t->starttime)
                return FALSE;

        if ((r = sched_getscheduler(t->pid)) < 0) {

                /* Maybe it died right now? */
                if (errno == ESRCH)
                        return FALSE;

                syslog(LOG_WARNING, "Warning: failed to read scheduler policy: %s\n", strerror(errno));
                return FALSE;
        }

        /* Is this a realtime thread? */
        r &= ~SCHED_RESET_ON_FORK;
        if (r == SCHED_RR || r == SCHED_FIFO)
                return TRUE;

        errno = 0;
        r = getpriority(PRIO_PROCESS, t->pid);
        if (errno != 0) {

                /* Maybe it died right now? */
                if (errno == ESRCH)
                        return FALSE;

                syslog(LOG_WARNING, "Warning: failed to read nice level: %s\n", strerror(errno));
                return FALSE;
        }

        /* Is this a high priority thread? */
        if (r < 0)
                return TRUE;

        return FALSE;
}

static void thread_gc(struct rtkit_user *u, struct process *p) {
        struct thread *t, *n, *l;

        /* Cleanup dead theads of a specific user we don't need to keep track about anymore */

        for (l = NULL, t = p->threads; t; t = n) {
                n = t->next;

                if (!thread_relevant(p, t)) {
                        free_thread(t);
                        if (l)
                                l->next = n;
                        else
                                p->threads = n;

                        assert(u->n_threads >= 1);
                        u->n_threads--;

                        assert(n_total_threads >= 1);
                        n_total_threads--;
                } else
                        l = t;
        }

        assert(!p->threads || u->n_threads);
}

static void process_gc(struct rtkit_user *u) {
        struct process *p, *n, *l;

        /* Cleanup dead processes of a specific user we don't need to keep track about anymore */

        for (l = NULL, p = u->processes; p; p = n) {
                n = p->next;
                thread_gc(u, p);

                if (!p->threads) {
                        free_process(p);
                        if (l)
                                l->next = n;
                        else
                                u->processes = n;

                        assert(u->n_processes >= 1);
                        u->n_processes--;

                        assert(n_total_processes >= 1);
                        n_total_processes--;
                } else
                        l = p;
        }

        assert(!u->processes == !u->n_processes);
}

static void user_gc(void) {
        struct rtkit_user *u, *n, *l;

        /* Cleanup all users we don't need to keep track about anymore */

        for (l = NULL, u = users; u; u = n) {
                n = u->next;
                process_gc(u);

                if (!u->processes && !user_in_burst(u)) {
                        free_user(u);
                        if (l)
                                l->next = n;
                        else
                                users = n;

                        assert(n_users >= 1);
                        n_users--;
                } else
                        l = u;
        }

        assert(!users == !n_users);
}

static bool startswith(const char *s, const char *prefix) {
        return strncmp(s, prefix, strlen(prefix)) == 0;
}

static int self_set_realtime(unsigned priority) {
        struct sched_param param;
        int r;

        memset(&param, 0, sizeof(param));
        param.sched_priority = priority;

        if (sched_setscheduler(0, sched_policy|SCHED_RESET_ON_FORK, &param) < 0) {
                r = -errno;
                syslog(LOG_ERR, "Failed to make ourselves RT: %s\n", strerror(errno));
                goto finish;
        }

        r = 0;

finish:
        return r;
}

static void self_drop_realtime(int nice_level) {
        struct sched_param param;

        memset(&param, 0, sizeof(param));

        if (sched_setscheduler(0, SCHED_OTHER, &param) < 0)
                syslog(LOG_WARNING, "Warning: Failed to reset scheduling to SCHED_OTHER: %s\n", strerror(errno));

        if (setpriority(PRIO_PROCESS, 0, nice_level) < 0)
                syslog(LOG_WARNING, "Warning: Failed to reset nice level to %u: %s\n", our_nice_level, strerror(errno));
}

/* Verifies that RLIMIT_RTTIME is set for the specified process */
static int verify_process_rttime(struct process *p) {
        char fn[128];
        FILE *f;
        int r;
        bool good = false;

        assert_se(snprintf(fn, sizeof(fn)-1, "%s/%llu/limits", get_proc_path(), (unsigned long long) p->pid) < (int) (sizeof(fn)-1));
        fn[sizeof(fn)-1] = 0;

        if (!(f = fopen(fn, "r"))) {
                r = -errno;
                syslog(LOG_ERR, "Failed to open '%s': %s\n", fn, strerror(errno));
                return r;
        }

        for (;;) {
                char line[128];
                char soft[32], hard[32];
                unsigned long long rttime;
                char *e = NULL;

                if (!fgets(line, sizeof(line), f))
                        break;

                if (!startswith(line, "Max realtime timeout"))
                        continue;

                if (sscanf(line + 20, "%s %s", soft, hard) != 2) {
                        syslog(LOG_WARNING, "Warning: parse failure in %s.\n", fn);
                        break;
                }

                errno = 0;
                rttime = strtoll(hard, &e, 10);

                if (errno != 0 || !e || *e != 0)
                        break;

                if (rttime <= rttime_usec_max)
                        good = true;

                break;
        }

        fclose(f);

        return good ? 0 : -EPERM;
}

static int verify_process_user(struct rtkit_user *u, struct process *p) {
        char fn[128];
        int r;
        struct stat st;

        assert_se(snprintf(fn, sizeof(fn)-1, "%s/%llu", get_proc_path(), (unsigned long long) p->pid) < (int) (sizeof(fn)-1));
        fn[sizeof(fn)-1] = 0;

        memset(&st, 0, sizeof(st));
        if (stat(fn, &st) < 0) {
                r = -errno;

                if (r != -ENOENT)
                        syslog(LOG_WARNING, "Warning: Failed to stat() file '%s': %s\n", fn, strerror(-r));

                return r;
        }

        return st.st_uid == u->uid ? 0 : -EPERM;
}

static int verify_process_starttime(struct process *p) {
        unsigned long long st;
        int r;

        if ((r = read_starttime(p->pid, 0, &st)) < 0) {

                if (r != -ENOENT)
                        syslog(LOG_WARNING, "Warning: Failed to read start time of process %llu: %s\n", (unsigned long long) p->pid, strerror(-r));

                return r;
        }

        return st == p->starttime ? 0 : -EPERM;
}

static int verify_thread_starttime(struct process *p, struct thread *t) {
        unsigned long long st;
        int r;

        if ((r = read_starttime(p->pid, t->pid, &st)) < 0) {

                if (r != -ENOENT)
                        syslog(LOG_WARNING, "Warning: Failed to read start time of thread %llu: %s\n", (unsigned long long) t->pid, strerror(-r));

                return r;
        }

        return st == t->starttime ? 0 : -EPERM;
}

static int thread_reset(pid_t tid) {
        struct sched_param param;
        int r = 0;

        memset(&param, 0, sizeof(param));
        param.sched_priority = 0;

        if (sched_setscheduler(tid, SCHED_OTHER, &param) < 0) {
                if (errno != ESRCH)
                        syslog(LOG_WARNING, "Warning: Failed to reset scheduling to SCHED_OTHER for thread %llu: %s\n", (unsigned long long) tid, strerror(errno));
                r = -1;
        }

        if (setpriority(PRIO_PROCESS, tid, 0) < 0) {
                if (errno != ESRCH)
                        syslog(LOG_WARNING, "Warning: Failed to reset nice level to 0 for thread %llu: %s\n", (unsigned long long) tid, strerror(errno));
                r = -1;
        }

        return r;
}

static char* get_exe_name(pid_t pid, char *exe, size_t len) {
        char fn[128];
        ssize_t n;

        assert_se(snprintf(fn, sizeof(fn)-1, "%s/%llu/exe", get_proc_path(), (unsigned long long) pid) < (int) (sizeof(fn)-1));
        fn[sizeof(fn)-1] = 0;

        if ((n = readlink(fn, exe, len-1)) < 0) {
                snprintf(exe, len-1, "n/a");
                exe[len-1] = 0;
        } else
                exe[n] = 0;

        return exe;
}

static int process_set_realtime(struct rtkit_user *u, struct process *p, struct thread *t, unsigned priority) {
        int r;
        struct sched_param param;
        char user[64], exe[128];

        if ((int) priority < sched_get_priority_min(sched_policy) ||
            (int) priority > sched_get_priority_max(sched_policy))
                return -EINVAL;

        /* We always want to be able to get a higher RT priority than
         * the client */
        if (priority >= our_realtime_priority ||
            priority > max_realtime_priority)
                return -EPERM;

        /* Make sure users don't flood us with requests */
        if (!verify_burst(u))
                return -EBUSY;

        /* Temporarily become a realtime process. We do this to make
         * sure that our verification code is not preempted by an evil
         * client's code which might have gotten RT through
         * us. */
        if ((r = self_set_realtime(our_realtime_priority)) < 0)
                return r;

        /* Let's make sure that everything is alright before we make
         * the process realtime */
        if ((r = verify_process_user(u, p)) < 0 ||
            (r = verify_process_starttime(p)) < 0 ||
            (r = verify_process_rttime(p)) < 0 ||
            (r = verify_thread_starttime(p, t)) < 0)
                goto finish;

        /* Ok, everything seems to be in order, now, let's do it */
        memset(&param, 0, sizeof(param));
        param.sched_priority = (int) priority;
        if (sched_setscheduler(t->pid, sched_policy|SCHED_RESET_ON_FORK, &param) < 0) {
                r = -errno;
                syslog(LOG_ERR, "Failed to make thread %llu RT: %s\n", (unsigned long long) t->pid, strerror(errno));
                goto finish;
        }

        /* We do some sanity checks afterwards, to verify that the
         * caller didn't play games with us and replaced the process
         * behind the PID */
        if ((r = verify_thread_starttime(p, t)) < 0 ||
            (r = verify_process_rttime(p)) < 0 ||
            (r = verify_process_starttime(p)) < 0 ||
            (r = verify_process_user(u, p)) < 0) {

                thread_reset(t->pid);
                goto finish;
        }

        syslog(LOG_INFO, "Successfully made thread %llu of process %llu (%s) owned by '%s' RT at priority %u.\n",
               (unsigned long long) t->pid,
               (unsigned long long) p->pid,
               get_exe_name(p->pid, exe, sizeof(exe)),
               get_user_name(u->uid, user, sizeof(user)),
               priority);

        r = 0;

finish:
        self_drop_realtime(our_nice_level);

        return r;
}

static int process_set_high_priority(struct rtkit_user *u, struct process *p, struct thread *t, int priority) {
        int r;
        struct sched_param param;
        char user[64], exe[128];

        if (priority < PRIO_MIN || priority >= PRIO_MAX)
                return -EINVAL;

        if (priority < min_nice_level)
                return -EPERM;

        /* Make sure users don't flood us with requests */
        if (!verify_burst(u))
                return -EBUSY;

        /* Temporarily become a realtime process */
        if ((r = self_set_realtime(our_realtime_priority)) < 0)
                return r;

        /* Let's make sure that everything is alright before we make
         * the process high priority */
        if ((r = verify_process_user(u, p)) < 0 ||
            (r = verify_process_starttime(p)) < 0 ||
            (r = verify_thread_starttime(p, t)) < 0)
                goto finish;

        /* Ok, everything seems to be in order, now, let's do it */
        memset(&param, 0, sizeof(param));
        param.sched_priority = 0;
        if (sched_setscheduler(t->pid, SCHED_OTHER|SCHED_RESET_ON_FORK, &param) < 0) {
                r = -errno;
                syslog(LOG_ERR, "Failed to make process %llu SCHED_NORMAL: %s\n", (unsigned long long) t->pid, strerror(errno));
                goto finish;
        }

        if (setpriority(PRIO_PROCESS, t->pid, priority) < 0) {
                r = -errno;
                syslog(LOG_ERR, "Failed to set nice level of process %llu to %i: %s\n", (unsigned long long) t->pid, priority, strerror(errno));
                goto finish;
        }

        if ((r = verify_thread_starttime(p, t)) < 0 ||
            (r = verify_process_starttime(p)) < 0 ||
            (r = verify_process_user(u, p)) < 0) {

                thread_reset(t->pid);
                goto finish;
        }

        syslog(LOG_INFO, "Successfully made thread %llu of process %llu (%s) owned by '%s' high priority at nice level %i.\n",
               (unsigned long long) t->pid,
               (unsigned long long) p->pid,
               get_exe_name(p->pid, exe, sizeof(exe)),
               get_user_name(u->uid, user, sizeof(user)),
               priority);

        r = 0;

finish:
        self_drop_realtime(our_nice_level);

        return r;
}

static void reset_known(void) {
        struct rtkit_user *u;
        struct process *p;
        struct thread *t;
        unsigned n_demoted = 0;

        syslog(LOG_INFO, "Demoting known real-time threads.\n");

        for (u = users; u; u = u->next)
                for (p = u->processes; p; p = p->next)
                        for (t = p->threads; t; t = t->next)
                                if (verify_process_user(u, p) >= 0 &&
                                    verify_process_starttime(p) >= 0 &&
                                    verify_thread_starttime(p, t) >= 0)
                                        if (thread_reset(t->pid) >= 0) {
                                                char exe[64];
                                                syslog(LOG_NOTICE, "Successfully demoted thread %llu of process %llu (%s).\n",
                                                       (unsigned long long) t->pid,
                                                       (unsigned long long) p->pid,
                                                       get_exe_name(p->pid, exe, sizeof(exe)));
                                                n_demoted++;
                                        }

        syslog(LOG_NOTICE, "Demoted %u threads.\n", n_demoted);
}

static int reset_all(void) {
        DIR *pd;
        int r;
        unsigned n_demoted = 0;

        /* Goes through /proc and demotes *all* threads to
         * SCHED_OTHER */

        syslog(LOG_INFO, "Demoting known and unknown real-time threads.\n");

        if (!(pd = opendir(get_proc_path()))) {
                r = -errno;
                syslog(LOG_ERR, "opendir(%s) failed: %s\n", get_proc_path(), strerror(errno));
                return r;
        }

        for (;;) {
                const struct dirent *pde;
                char *e = NULL;
                unsigned long long pid;
                char fn[128];
                DIR *td;
                struct stat st;

                if (!(pde = readdir(pd)))
                        break;

                if (!(pde->d_type & DT_DIR))
                        continue;

                errno = 0;
                pid = strtoull(pde->d_name, &e, 10);
                if (errno != 0 || !e || *e != 0)
                        continue;

                if ((pid_t) pid == getpid() ||
                    pid == 1)
                        continue;

                assert_se(snprintf(fn, sizeof(fn)-1, "%s/%llu", get_proc_path(), pid) < (int) (sizeof(fn)-1));
                fn[sizeof(fn)-1] = 0;

                if (stat(fn, &st) < 0) {
                        if (errno != ENOENT)
                                syslog(LOG_WARNING, "Warning: stat(%s) failed: %s\n", fn, strerror(errno));
                        continue;
                }

                if (!S_ISDIR(st.st_mode))
                        continue;

                if (!canary_demote_root && st.st_uid == 0)
                        continue;

                assert_se(snprintf(fn, sizeof(fn)-1, "%s/%llu/task", get_proc_path(), pid) < (int) (sizeof(fn)-1));
                fn[sizeof(fn)-1] = 0;

                if (!(td = opendir(fn)))
                        continue;

                for (;;) {
                        const struct dirent *tde;
                        unsigned long long tid;

                        if (!(tde = readdir(td)))
                                break;

                        if (!(tde->d_type & DT_DIR))
                                continue;

                        e = NULL;
                        errno = 0;
                        tid = strtoull(tde->d_name, &e, 10);
                        if (errno != 0 || !e || *e != 0)
                                continue;

                        if ((r = sched_getscheduler(tid)) < 0) {
                                if (errno != ESRCH)
                                        syslog(LOG_WARNING, "Warning: sched_getscheduler() failed: %s\n", strerror(errno));
                                continue;
                        }

                        if (r == SCHED_FIFO || r == SCHED_RR ||
                            r == (SCHED_FIFO|SCHED_RESET_ON_FORK) || r == (SCHED_RR|SCHED_RESET_ON_FORK))
                                if (thread_reset((pid_t) tid) >= 0) {
                                        char exe[64];
                                        syslog(LOG_NOTICE, "Successfully demoted thread %llu of process %llu (%s).\n",
                                               (unsigned long long) tid,
                                               (unsigned long long) pid,
                                               get_exe_name(pid, exe, sizeof(exe)));
                                        n_demoted++;
                                }
                }

                closedir(td);
        }

        closedir(pd);

        syslog(LOG_NOTICE, "Demoted %u threads.\n", n_demoted);

        return 0;
}

/* This mimics dbus_bus_get_unix_user() */
static unsigned long get_unix_process_id(
                DBusConnection *connection,
                const char *name,
                DBusError *error) {

        DBusMessage *m, *r;
        uint32_t pid = (uint32_t) -1;

        assert_se(m = dbus_message_new_method_call(
                                  DBUS_SERVICE_DBUS,
                                  DBUS_PATH_DBUS,
                                  DBUS_INTERFACE_DBUS,
                                  "GetConnectionUnixProcessID"));

        assert_se(dbus_message_append_args(
                                  m,
                                  DBUS_TYPE_STRING, &name,
                                  DBUS_TYPE_INVALID));

        r = dbus_connection_send_with_reply_and_block(connection, m, -1, error);
        dbus_message_unref (m);

        if (!r)
                goto finish;

        if (dbus_set_error_from_message(error, r))
                goto finish;

        if (!dbus_message_get_args(
                            r, error,
                            DBUS_TYPE_UINT32, &pid,
                            DBUS_TYPE_INVALID)) {
                pid = (uint32_t) -1;
                goto finish;
        }

finish:

        if (r)
                dbus_message_unref(r);

        return (unsigned long) pid;
}

static int lookup_client(
                struct rtkit_user **_u,
                struct process **_p,
                struct thread **_t,
                DBusConnection *c,
                DBusMessage *m,
                pid_t pid,
                pid_t tid) {

        DBusError error;
        int r;
        unsigned long uid;
        unsigned long long starttime;
        struct rtkit_user *u;
        struct process *p;
        struct thread *t;

        dbus_error_init(&error);

        /* Determine caller credentials */
        if ((uid = dbus_bus_get_unix_user(c, dbus_message_get_sender(m), &error)) == (unsigned long) -1) {
                syslog(LOG_ERR, "dbus_message_get_unix_user() failed: %s\n", error.message);
                r = -EIO;
                goto fail;
        }

        if (pid == (pid_t) -1 &&
            (pid = get_unix_process_id(c, dbus_message_get_sender(m), &error)) == (pid_t) -1) {
                syslog(LOG_ERR, "get_unix_process_id() failed: %s\n", error.message);
                r = -EIO;
                goto fail;
        }

        /* Find or create user structure */
        if ((r = find_user(&u, (uid_t) uid) < 0))
                goto fail;

        /* Find or create process structure */
        if ((r = read_starttime((pid_t) pid, 0, &starttime)) < 0)
                goto fail;

        if ((r = find_process(&p, u, (pid_t) pid, starttime)) < 0)
                goto fail;

        /* Find or create thread structure */
        if (tid == 0)
                tid = p->pid;

        if ((r = read_starttime(p->pid, tid, &starttime)) < 0)
                goto fail;

        if ((r = find_thread(&t, u, p, (pid_t) tid, starttime)) < 0)
                goto fail;

        *_u = u;
        *_p = p;
        *_t = t;

        return 0;

fail:
        dbus_error_free(&error);

        return r;
}

static const char *translate_error_forward(int error) {
        switch (error) {
                case -EPERM:
                case -EACCES:
                case -EBUSY:
                        return DBUS_ERROR_ACCESS_DENIED;

                case -ENOMEM:
                        return DBUS_ERROR_NO_MEMORY;

                default:
                        return DBUS_ERROR_FAILED;
        }
}

static int translate_error_backwards(const char *name) {
        if (strcmp(name, DBUS_ERROR_NO_MEMORY) == 0)
                return -ENOMEM;
        if (strcmp(name, DBUS_ERROR_SERVICE_UNKNOWN) == 0 ||
            strcmp(name, DBUS_ERROR_NAME_HAS_NO_OWNER) == 0)
                return -ENOENT;
        if (strcmp(name, DBUS_ERROR_ACCESS_DENIED) == 0 ||
            strcmp(name, DBUS_ERROR_AUTH_FAILED) == 0)
                return -EACCES;

        return -EIO;
}

static int verify_polkit(DBusConnection *c, struct rtkit_user *u, struct process *p, const char *action) {
        DBusError error;
        DBusMessage *m = NULL, *r = NULL;
        const char *unix_process = "unix-process";
        const char *pid = "pid";
        const char *start_time = "start-time";
        const char *cancel_id = "";
        uint32_t flags = 0;
        uint32_t pid_u32 = p->pid;
        uint64_t start_time_u64 = p->starttime;
        DBusMessageIter iter_msg, iter_struct, iter_array, iter_dict, iter_variant;
        int ret;
        dbus_bool_t authorized = FALSE;

        dbus_error_init(&error);

        assert_se(m = dbus_message_new_method_call(
                                  "org.freedesktop.PolicyKit1",
                                  "/org/freedesktop/PolicyKit1/Authority",
                                  "org.freedesktop.PolicyKit1.Authority",
                                  "CheckAuthorization"));

        dbus_message_iter_init_append(m, &iter_msg);
        assert_se(dbus_message_iter_open_container(&iter_msg, DBUS_TYPE_STRUCT, NULL, &iter_struct));
        assert_se(dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &unix_process));
        assert_se(dbus_message_iter_open_container(&iter_struct, DBUS_TYPE_ARRAY, "{sv}", &iter_array));

        assert_se(dbus_message_iter_open_container(&iter_array, DBUS_TYPE_DICT_ENTRY, NULL, &iter_dict));
        assert_se(dbus_message_iter_append_basic(&iter_dict, DBUS_TYPE_STRING, &pid));
        assert_se(dbus_message_iter_open_container(&iter_dict, DBUS_TYPE_VARIANT, "u", &iter_variant));
        assert_se(dbus_message_iter_append_basic(&iter_variant, DBUS_TYPE_UINT32, &pid_u32));
        assert_se(dbus_message_iter_close_container(&iter_dict, &iter_variant));
        assert_se(dbus_message_iter_close_container(&iter_array, &iter_dict));

        assert_se(dbus_message_iter_open_container(&iter_array, DBUS_TYPE_DICT_ENTRY, NULL, &iter_dict));
        assert_se(dbus_message_iter_append_basic(&iter_dict, DBUS_TYPE_STRING, &start_time));
        assert_se(dbus_message_iter_open_container(&iter_dict, DBUS_TYPE_VARIANT, "t", &iter_variant));
        assert_se(dbus_message_iter_append_basic(&iter_variant, DBUS_TYPE_UINT64, &start_time_u64));
        assert_se(dbus_message_iter_close_container(&iter_dict, &iter_variant));
        assert_se(dbus_message_iter_close_container(&iter_array, &iter_dict));

        assert_se(dbus_message_iter_close_container(&iter_struct, &iter_array));
        assert_se(dbus_message_iter_close_container(&iter_msg, &iter_struct));

        assert_se(dbus_message_iter_append_basic(&iter_msg, DBUS_TYPE_STRING, &action));

        assert_se(dbus_message_iter_open_container(&iter_msg, DBUS_TYPE_ARRAY, "{ss}", &iter_array));
        assert_se(dbus_message_iter_close_container(&iter_msg, &iter_array));

        assert_se(dbus_message_iter_append_basic(&iter_msg, DBUS_TYPE_UINT32, &flags));
        assert_se(dbus_message_iter_append_basic(&iter_msg, DBUS_TYPE_STRING, &cancel_id));

        if (!(r = dbus_connection_send_with_reply_and_block(c, m, -1, &error))) {
                ret = translate_error_backwards(error.name);
                goto finish;
        }

        if (dbus_set_error_from_message(&error, r)) {
                ret = translate_error_backwards(error.name);
                goto finish;
        }

        if (!dbus_message_iter_init(r, &iter_msg) ||
            dbus_message_iter_get_arg_type(&iter_msg) != DBUS_TYPE_STRUCT) {
                ret = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter_msg, &iter_struct);

        if (dbus_message_iter_get_arg_type(&iter_struct) != DBUS_TYPE_BOOLEAN) {
                ret = -EIO;
                goto finish;
        }

        dbus_message_iter_get_basic(&iter_struct, &authorized);

        ret = authorized ? 0 : -EPERM;

finish:

        if (m)
                dbus_message_unref(m);

        if (r)
                dbus_message_unref(r);

        if (error.message)
                syslog(LOG_WARNING, "Warning: PolicyKit call failed: %s\n", error.message);

        dbus_error_free(&error);

        return ret;
}

static int verify_canary_refusal(void) {
        struct timespec now;

        assert_se(clock_gettime(CLOCK_MONOTONIC, &now) == 0);

        if (now.tv_sec < (time_t) refuse_until) {
                syslog(LOG_WARNING, "Recovering from system lockup, not allowing further RT threads.\n");
                return -EPERM;
        }

        return 0;
}

static void add_variant(
        DBusMessage *m,
        int type,
        const void *data) {

        DBusMessageIter iter, sub;
        char t[2];

        t[0] = (char) type;
        t[1] = 0;

        dbus_message_iter_init_append(m, &iter);

        assert_se(dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, t, &sub));
        assert_se(dbus_message_iter_append_basic(&sub, type, data));
        assert_se(dbus_message_iter_close_container(&iter, &sub));
}

static int handle_dbus_prop_get(const char* property, DBusMessage *r) {
        if (strcmp(property, "RTTimeUSecMax") == 0)
                add_variant(r, DBUS_TYPE_INT64, &rttime_usec_max);
        else if (strcmp(property, "MaxRealtimePriority") == 0)
                add_variant(r, DBUS_TYPE_INT32, &max_realtime_priority);
        else if (strcmp(property, "MinNiceLevel") == 0)
                add_variant(r, DBUS_TYPE_INT32, &min_nice_level);
        else
                return -1;

        return 0;
}

static DBusHandlerResult dbus_handler(DBusConnection *c, DBusMessage *m, void *userdata) {
        DBusError error;
        DBusMessage *r = NULL;
        int is2 = 0;

        dbus_error_init(&error);

        /* We garbage collect on every user call */
        user_gc();

        if (dbus_message_is_method_call(m, "org.freedesktop.RealtimeKit1", "MakeThreadRealtime") ||
            (is2 = dbus_message_is_method_call(m, "org.freedesktop.RealtimeKit1", "MakeThreadRealtimeWithPID"))) {
                uint64_t thread, process = (uint64_t) -1;
                uint32_t priority;
                struct rtkit_user *u;
                struct process *p;
                struct thread *t;
                int ret;

                if ((ret = verify_canary_refusal()) < 0) {
                        assert_se(r = dbus_message_new_error_printf(m, translate_error_forward(ret), strerror(-ret)));
                        goto finish;
                }

                if (is2)
                        ret = dbus_message_get_args(m, &error,
                                                    DBUS_TYPE_UINT64, &process,
                                                    DBUS_TYPE_UINT64, &thread,
                                                    DBUS_TYPE_UINT32, &priority,
                                                    DBUS_TYPE_INVALID);
                else
                        ret = dbus_message_get_args(m, &error,
                                                    DBUS_TYPE_UINT64, &thread,
                                                    DBUS_TYPE_UINT32, &priority,
                                                    DBUS_TYPE_INVALID);

                if (!ret) {
                        syslog(LOG_DEBUG, "Failed to parse MakeThreadRealtime() method call: %s\n", error.message);
                        assert_se(r = dbus_message_new_error(m, error.name, error.message));

                        goto finish;
                }

                if ((ret = lookup_client(&u, &p, &t, c, m, (pid_t)process, (pid_t) thread)) < 0) {
                        syslog(LOG_DEBUG, "Failed to look up client: %s\n", strerror(-ret));
                        assert_se(r = dbus_message_new_error_printf(m, translate_error_forward(ret), strerror(-ret)));
                        goto finish;
                }

                if ((ret = verify_polkit(c, u, p, "org.freedesktop.RealtimeKit1.acquire-real-time")) < 0) {
                        assert_se(r = dbus_message_new_error_printf(m, translate_error_forward(ret), strerror(-ret)));
                        goto finish;
                }

                if ((ret = process_set_realtime(u, p, t, priority))) {
                        assert_se(r = dbus_message_new_error_printf(m, translate_error_forward(ret), strerror(-ret)));
                        goto finish;
                }

                assert_se(r = dbus_message_new_method_return(m));

        } else if (dbus_message_is_method_call(m, "org.freedesktop.RealtimeKit1", "MakeThreadHighPriority")
                   || (is2 = dbus_message_is_method_call(m, "org.freedesktop.RealtimeKit1", "MakeThreadHighPriorityWithPID"))) {

                uint64_t thread, process = (uint64_t) -1;
                int32_t priority;
                struct rtkit_user *u;
                struct process *p;
                struct thread *t;
                int ret;

                if ((ret = verify_canary_refusal()) < 0) {
                        assert_se(r = dbus_message_new_error_printf(m, translate_error_forward(ret), strerror(-ret)));
                        goto finish;
                }

                if (is2)
                        ret = dbus_message_get_args(m, &error,
                                                    DBUS_TYPE_UINT64, &process,
                                                    DBUS_TYPE_UINT64, &thread,
                                                    DBUS_TYPE_INT32, &priority,
                                                    DBUS_TYPE_INVALID);
                else
                        ret = dbus_message_get_args(m, &error,
                                                    DBUS_TYPE_UINT64, &thread,
                                                    DBUS_TYPE_INT32, &priority,
                                                    DBUS_TYPE_INVALID);

                if (!ret) {
                        syslog(LOG_DEBUG, "Failed to parse MakeThreadHighPriority() method call: %s\n", error.message);
                        assert_se(r = dbus_message_new_error(m, error.name, error.message));

                        goto finish;
                }

                if ((ret = lookup_client(&u, &p, &t, c, m, (pid_t)process, (pid_t) thread)) < 0) {
                        syslog(LOG_DEBUG, "Failed to look up client: %s\n", strerror(-ret));
                        assert_se(r = dbus_message_new_error_printf(m, translate_error_forward(ret), strerror(-ret)));
                        goto finish;
                }

                if ((ret = verify_polkit(c, u, p, "org.freedesktop.RealtimeKit1.acquire-high-priority")) < 0) {
                        assert_se(r = dbus_message_new_error_printf(m, translate_error_forward(ret), strerror(-ret)));
                        goto finish;
                }

                if ((ret = process_set_high_priority(u, p, t, priority))) {
                        assert_se(r = dbus_message_new_error_printf(m, translate_error_forward(ret), strerror(-ret)));
                        goto finish;
                }

                assert_se(r = dbus_message_new_method_return(m));

        } else if (dbus_message_is_method_call(m, "org.freedesktop.RealtimeKit1", "ResetAll")) {

                reset_all();
                user_gc();
                assert_se(r = dbus_message_new_method_return(m));

        } else if (dbus_message_is_method_call(m, "org.freedesktop.RealtimeKit1", "ResetKnown")) {

                reset_known();
                user_gc();
                assert_se(r = dbus_message_new_method_return(m));

        } else if (dbus_message_is_method_call(m, "org.freedesktop.RealtimeKit1", "Exit")) {

                assert_se(r = dbus_message_new_method_return(m));
                assert_se(dbus_connection_send(c, r, NULL));
                dbus_message_unref(r);
                r = NULL;

                dbus_connection_close(c);

        } else if (dbus_message_is_method_call(m, "org.freedesktop.DBus.Properties", "Get")) {
                const char *interface, *property;

                if (!dbus_message_get_args(m, &error,
                                           DBUS_TYPE_STRING, &interface,
                                           DBUS_TYPE_STRING, &property,
                                           DBUS_TYPE_INVALID)) {

                        syslog(LOG_DEBUG, "Failed to parse property get call: %s\n", error.message);
                        assert_se(r = dbus_message_new_error(m, error.name, error.message));
                        goto finish;
                }

                if (strcmp(interface, "org.freedesktop.RealtimeKit1") == 0) {
                        assert_se(r = dbus_message_new_method_return(m));

                        if (!handle_dbus_prop_get(property, r) < 0) {
                                dbus_message_unref(r);
                                assert_se(r = dbus_message_new_error_printf(
                                          m,
                                          DBUS_ERROR_UNKNOWN_METHOD,
                                          "Unknown property %s",
                                          property));
                        }
                } else
                        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

        } else if (dbus_message_is_method_call(m, "org.freedesktop.DBus.Introspectable", "Introspect")) {
                const char *xml = INTROSPECT_XML;

                assert_se(r = dbus_message_new_method_return(m));
                assert_se(dbus_message_append_args(
                                          r,
                                          DBUS_TYPE_STRING, &xml,
                                          DBUS_TYPE_INVALID));
        } else
                return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

        syslog(LOG_DEBUG, "Supervising %u threads of %u processes of %u users.\n",
                n_total_threads,
                n_total_processes,
                n_users);

        sd_notifyf(0,
                   "STATUS=Supervising %u threads of %u processes of %u users.",
                   n_total_threads,
                   n_total_processes,
                   n_users);

finish:
        if (r) {
                assert_se(dbus_connection_send(c, r, NULL));
                dbus_message_unref(r);
        }

        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_HANDLED;
}

static int setup_dbus(DBusConnection **c) {
        static const DBusObjectPathVTable vtable = {
                .message_function = dbus_handler,
        };

        DBusError error;

        dbus_error_init(&error);

        if (!(*c = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error))) {
                syslog(LOG_ERR, "Failed to connect to system bus: %s\n", error.message);
                goto fail;
        }

        if (dbus_bus_request_name(*c, RTKIT_SERVICE_NAME, DBUS_NAME_FLAG_DO_NOT_QUEUE, &error) < 0) {
                syslog(LOG_ERR, "Failed to register name on bus: %s\n", error.message);
                goto fail;
        }

        assert_se(dbus_connection_register_object_path(*c, RTKIT_OBJECT_PATH, &vtable, NULL));

        return 0;

fail:
        dbus_error_free(&error);
        return -EIO;
}


static void block_all_signals(void) {
        sigset_t set;

        assert_se(sigfillset(&set) == 0);
        assert_se(pthread_sigmask(SIG_BLOCK, &set, NULL) == 0);
}

static void* canary_thread(void *data) {
        struct timespec last_cheep, now;
        struct pollfd pollfd;

        assert(canary_fd >= 0);
        assert(quit_fd >= 0);

        /* Make sure we are not disturbed by any signal */
        block_all_signals();
        self_drop_realtime(0);

        memset(&pollfd, 0, sizeof(pollfd));
        pollfd.fd = quit_fd;
        pollfd.events = POLLIN;

        assert_se(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        last_cheep = now;

        syslog(LOG_DEBUG, "Canary thread running.\n");

        for (;;) {
                int r;
                int64_t msec;

                msec = TIMESPEC_MSEC(last_cheep) + canary_cheep_msec - TIMESPEC_MSEC(now);

                if (msec < 0)
                        msec = 0;

                r = poll(&pollfd, 1, (int) msec);

                assert_se(clock_gettime(CLOCK_MONOTONIC, &now) == 0);

                if (r < 0) {
                        if (errno == EINTR || errno == EAGAIN)
                                continue;

                        syslog(LOG_ERR, "poll() failed: %s\n", strerror(errno));
                        break;
                }

                if (pollfd.revents) {
                        syslog(LOG_DEBUG, "Exiting canary thread.\n");
                        break;
                }

                if (TIMESPEC_MSEC(last_cheep) + canary_cheep_msec <= TIMESPEC_MSEC(now)) {
                        eventfd_t value = 1;

                        if (eventfd_write(canary_fd, value) < 0) {
                                syslog(LOG_ERR, "eventfd_write() failed: %s\n", strerror(errno));
                                break;
                        }

                        last_cheep = now;
                        continue;
                }
        }

        return NULL;
}

static void* watchdog_thread(void *data) {
        enum {
                POLLFD_CANARY,
                POLLFD_QUIT,
                _POLLFD_MAX
        };
        struct timespec last_cheep, now;
        struct pollfd pollfd[_POLLFD_MAX];

        assert(canary_fd >= 0);
        assert(quit_fd >= 0);

        /* Make sure we are not disturbed by any signal */
        block_all_signals();
        self_set_realtime(canary_watchdog_realtime_priority);

        memset(pollfd, 0, sizeof(pollfd));
        pollfd[POLLFD_CANARY].fd = canary_fd;
        pollfd[POLLFD_CANARY].events = POLLIN;
        pollfd[POLLFD_QUIT].fd = quit_fd;
        pollfd[POLLFD_QUIT].events = POLLIN;

        assert_se(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        last_cheep = now;

        syslog(LOG_DEBUG, "Watchdog thread running.\n");

        for (;;) {
                int r;
                int64_t msec;

                msec = TIMESPEC_MSEC(last_cheep) + canary_watchdog_msec - TIMESPEC_MSEC(now);

                if (msec < 0)
                        msec = 0;

                r = poll(pollfd, _POLLFD_MAX, (int) msec);

                assert_se(clock_gettime(CLOCK_MONOTONIC, &now) == 0);

                if (r < 0) {
                        if (errno == EINTR || errno == EAGAIN)
                                continue;

                        syslog(LOG_ERR, "poll() failed: %s\n", strerror(errno));
                        break;
                }

                if (pollfd[POLLFD_QUIT].revents) {
                        syslog(LOG_DEBUG, "Exiting watchdog thread.\n");
                        break;
                }

                if (pollfd[POLLFD_CANARY].revents) {
                        eventfd_t value;

                        if (eventfd_read(canary_fd, &value) < 0) {
                                syslog(LOG_ERR, "eventfd_read() failed: %s\n", strerror(errno));
                                break;
                        }

                        last_cheep = now;
                        continue;
                }

                if (TIMESPEC_MSEC(last_cheep) + canary_watchdog_msec <= TIMESPEC_MSEC(now)) {
                        last_cheep = now;
                        syslog(LOG_WARNING, "The canary thread is apparently starving. Taking action.\n");
                        refuse_until = (uint32_t) now.tv_sec + canary_refusal_sec;
                        __sync_synchronize();

                        if (canary_demote_unknown)
                                reset_all();
                        else
                                reset_known();
                        continue;
                }
        }

        return NULL;
}

static void stop_canary(void) {
        int r;

        if (quit_fd >= 0) {
                eventfd_t value = 1;
                if (eventfd_write(quit_fd, value) < 0)
                        syslog(LOG_WARNING, "Warning: eventfd_write() failed: %s\n", strerror(errno));
        }

        if (canary_thread_id != 0) {
                if ((r = pthread_join(canary_thread_id, NULL)) != 0)
                        syslog(LOG_WARNING, "Warning: pthread_join() failed: %s\n", strerror(r));
                canary_thread_id = 0;
        }

        if (watchdog_thread_id != 0) {
                if ((r = pthread_join(watchdog_thread_id, NULL)) != 0)
                        syslog(LOG_WARNING, "Warning: pthread_join() failed: %s\n", strerror(r));
                watchdog_thread_id = 0;
        }

        if (canary_fd >= 0) {
                close(canary_fd);
                canary_fd = -1;
        }

        if (quit_fd >= 0) {
                close(quit_fd);
                quit_fd = -1;
        }
}

static int start_canary(void) {
        int r;

        if (!do_canary)
                return 0;

        if ((canary_fd = eventfd(0, EFD_NONBLOCK|EFD_CLOEXEC)) < 0 ||
            (quit_fd = eventfd(0, EFD_NONBLOCK|EFD_CLOEXEC)) < 0) {
                r = -errno;
                syslog(LOG_ERR, "eventfd() failed: %s\n", strerror(errno));
                goto fail;
        }

        if ((r = -pthread_create(&canary_thread_id, NULL, canary_thread, NULL)) < 0 ||
            (r = -pthread_create(&watchdog_thread_id, NULL, watchdog_thread, NULL)) < 0) {
                syslog(LOG_ERR, "pthread_create failed: %s\n", strerror(-r));
                goto fail;
        }

        return 0;

fail:
        stop_canary();
        return r;
}

static int drop_privileges(void) {
        struct passwd *pw = NULL;
        int r;

        if (do_drop_privileges) {

                /* First, get user data */
                if (!(pw = getpwnam(username))) {
                        syslog(LOG_ERR, "Failed to find user '%s'.\n", username);
                        return -ENOENT;
                }
        }

        if (do_chroot) {

                /* Second, chroot() */
                if (chroot("/proc") < 0 ||
                    chdir("/") < 0) {
                        r = -errno;
                        syslog(LOG_ERR, "Failed to chroot() to /proc: %s\n", strerror(errno));
                        return r;
                }
                proc = "/";

                syslog(LOG_DEBUG, "Successfully called chroot.\n");
        }

        if (do_drop_privileges) {
                static const cap_value_t cap_values[] = {
                        CAP_SYS_NICE,             /* Needed for obvious reasons */
                        CAP_DAC_READ_SEARCH,      /* Needed so that we can verify resource limits */
                        CAP_SYS_PTRACE            /* Needed so that we can read /proc/$$/exe. Linux is weird. */
                };

                cap_value_t c, m;
                cap_t caps;

                m = CAP_LAST_CAP;
                /* In case the number of caps in the kernel is increased, drop them too */
                if (m < 63)
                        m = 63;

                /* Third, reduce bounding set */
                for (c = 0; c <= m; c++) {
                        unsigned u;
                        bool keep = false;

                        for (u = 0; u < ELEMENTSOF(cap_values); u++)
                                if (cap_values[u] == c) {
                                        keep = true;
                                        break;
                                }

                        if (!keep)
                                assert_se(prctl(PR_CAPBSET_DROP, c) == 0 || errno == EINVAL || errno == EPERM);
                }

                /* Fourth, say that we want to keep caps */
                if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
                        r = -errno;
                        syslog(LOG_ERR, "PR_SET_KEEPCAPS failed: %s\n", strerror(errno));
                        return r;
                }

                /* Fifth, drop privs */
                if (setgroups(0, NULL) < 0 ||
                    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) < 0 ||
                    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) < 0) {
                        r = -errno;
                        syslog(LOG_ERR, "Failed to become %s: %s\n", username, strerror(errno));
                        return r;
                }

                /* Sixth, reset caps flag */
                if (prctl(PR_SET_KEEPCAPS, 0) < 0) {
                        r = -errno;
                        syslog(LOG_ERR, "PR_SET_KEEPCAPS failed: %s\n", strerror(errno));
                        return r;
                }

                /* Seventh, reduce caps */
                assert_se(caps = cap_init());
                assert_se(cap_clear(caps) == 0);
                assert_se(cap_set_flag(caps, CAP_EFFECTIVE, ELEMENTSOF(cap_values), cap_values, CAP_SET) == 0);
                assert_se(cap_set_flag(caps, CAP_PERMITTED, ELEMENTSOF(cap_values), cap_values, CAP_SET) == 0);

                if (cap_set_proc(caps) < 0) {
                        r = -errno;
                        syslog(LOG_ERR, "cap_set_proc() failed: %s\n", strerror(errno));
                        return r;
                }

                assert_se(cap_free(caps) == 0);

                /* Eigth, update environment */
                setenv("USER", username, 1);
                setenv("USERNAME", username, 1);
                setenv("LOGNAME", username, 1);
                setenv("HOME", get_proc_path(), 1);

                syslog(LOG_DEBUG, "Successfully dropped privileges.\n");
        }

        return 0;
}

static int set_resource_limits(void) {

        static struct {
                int id;
                const char *name;
                rlim_t value;
        } table[] = {
                { .id = RLIMIT_FSIZE,    .name = "RLIMIT_FSIZE",    .value =  0 },
                { .id = RLIMIT_MEMLOCK,  .name = "RLIMIT_MEMLOCK",  .value =  0 },
                { .id = RLIMIT_MSGQUEUE, .name = "RLIMIT_MSGQUEUE", .value =  0 },
                { .id = RLIMIT_NICE,     .name = "RLIMIT_NICE",     .value = 20 },
                { .id = RLIMIT_NOFILE,   .name = "RLIMIT_NOFILE",   .value = 50 },
                { .id = RLIMIT_NPROC,    .name = "RLIMIT_NPROC",    .value =  3 },
                { .id = RLIMIT_RTPRIO,   .name = "RLIMIT_RTPRIO",   .value =  0 }, /* Since we have CAP_SYS_NICE we don't need this */
                { .id = RLIMIT_RTTIME,   .name = "RLIMIT_RTTIME",   .value =  0 }
        };

        unsigned u;
        int r;

        assert(table[7].id == RLIMIT_RTTIME);
        table[7].value = rttime_usec_max; /* Do as I say AND do as I do */

        if (!do_limit_resources)
                return 0;

        for (u = 0; u < ELEMENTSOF(table); u++) {
                struct rlimit rlim;

                if (getrlimit(table[u].id, &rlim) < 0) {
                        r = -errno;
                        syslog(LOG_ERR, "Failed to get %s: %s\n", table[u].name, strerror(errno));
                        return r;
                }

                if (rlim.rlim_max < table[u].value)
                        continue;

                rlim.rlim_cur = rlim.rlim_max = table[u].value;

                if (setrlimit(table[u].id, &rlim) < 0) {
                        r = -errno;
                        syslog(LOG_ERR, "Failed to set %s: %s\n", table[u].name, strerror(errno));
                        return r;
                }
        }

        syslog(LOG_DEBUG, "Successfully limited resources.\n");

        return 0;
}

enum {
        ARG_HELP = 256,
        ARG_VERSION,
        ARG_SCHEDULING_POLICY,
        ARG_OUR_REALTIME_PRIORITY,
        ARG_OUR_NICE_LEVEL,
        ARG_MAX_REALTIME_PRIORITY,
        ARG_MIN_NICE_LEVEL,
        ARG_USER_NAME,
        ARG_RTTIME_USEC_MAX,
        ARG_USERS_MAX,
        ARG_PROCESSES_PER_USER_MAX,
        ARG_THREADS_PER_USER_MAX,
        ARG_ACTIONS_BURST_SEC,
        ARG_ACTIONS_PER_BURST_MAX,
        ARG_NO_DROP_PRIVILEGES,
        ARG_NO_CHROOT,
        ARG_NO_LIMIT_RESOURCES,
        ARG_NO_CANARY,
        ARG_CANARY_CHEEP_MSEC,
        ARG_CANARY_WATCHDOG_MSEC,
        ARG_CANARY_DEMOTE_ROOT,
        ARG_CANARY_DEMOTE_UNKNOWN,
        ARG_CANARY_REFUSE_SEC,
        ARG_STDERR,
        ARG_INTROSPECT
};

/* Table for getopt_long() */
static const struct option long_options[] = {
    { "help",                        no_argument,       0, ARG_HELP },
    { "version",                     no_argument,       0, ARG_VERSION },
    { "scheduling-policy",           required_argument, 0, ARG_SCHEDULING_POLICY },
    { "our-realtime-priority",       required_argument, 0, ARG_OUR_REALTIME_PRIORITY },
    { "our-nice-level",              required_argument, 0, ARG_OUR_NICE_LEVEL },
    { "max-realtime-priority",       required_argument, 0, ARG_MAX_REALTIME_PRIORITY },
    { "min-nice-level",              required_argument, 0, ARG_MIN_NICE_LEVEL },
    { "user-name",                   required_argument, 0, ARG_USER_NAME },
    { "rttime-usec-max",             required_argument, 0, ARG_RTTIME_USEC_MAX },
    { "users-max",                   required_argument, 0, ARG_USERS_MAX },
    { "processes-per-user-max",      required_argument, 0, ARG_PROCESSES_PER_USER_MAX },
    { "threads-per-user-max",        required_argument, 0, ARG_THREADS_PER_USER_MAX },
    { "actions-burst-sec",           required_argument, 0, ARG_ACTIONS_BURST_SEC },
    { "actions-per-burst-max",       required_argument, 0, ARG_ACTIONS_PER_BURST_MAX },
    { "no-drop-privileges",          no_argument,       0, ARG_NO_DROP_PRIVILEGES },
    { "no-chroot",                   no_argument,       0, ARG_NO_CHROOT },
    { "no-limit-resources",          no_argument,       0, ARG_NO_LIMIT_RESOURCES },
    { "no-canary",                   no_argument,       0, ARG_NO_CANARY },
    { "canary-cheep-msec",           required_argument, 0, ARG_CANARY_CHEEP_MSEC },
    { "canary-watchdog-msec",        required_argument, 0, ARG_CANARY_WATCHDOG_MSEC },
    { "canary-demote-root",          no_argument,       0, ARG_CANARY_DEMOTE_ROOT },
    { "canary-demote-unknown",       no_argument,       0, ARG_CANARY_DEMOTE_UNKNOWN },
    { "canary-refuse-sec",           required_argument, 0, ARG_CANARY_REFUSE_SEC },
    { "stderr",                      no_argument,       0, ARG_STDERR },
    { "introspect",                  no_argument,       0, ARG_INTROSPECT },
    { NULL, 0, 0, 0}
};

static char* get_file_name(const char *p) {
        char *e;

        if ((e = strrchr(p, '/')))
                return e + 1;
        else
                return (char*) p;
}

static void show_help(const char *exe) {

        static const char * const sp_names[] =  {
                [SCHED_OTHER] = "OTHER",
                [SCHED_BATCH] = "BATCH",
                [SCHED_FIFO] = "FIFO",
                [SCHED_RR] = "RR"
        };

        printf("%s [options]\n\n"
               "COMMANDS:\n"
               "  -h, --help                          Show this help\n"
               "      --version                       Show version\n\n"
               "OPTIONS:\n"
               "      --stderr                        Log to STDERR in addition to syslog\n"
               "      --user-name=USER                Run daemon as user (%s)\n\n"
               "      --scheduling-policy=(RR|FIFO)   Choose scheduling policy (%s)\n"
               "      --our-realtime-priority=[%i..%i] Realtime priority for the daemon (%u)\n"
               "      --our-nice-level=[%i..%i]      Nice level for the daemon (%i)\n"
               "      --max-realtime-priority=[%i..%i] Max realtime priority for clients (%u)\n"
               "      --min-nice-level=[%i..%i]      Min nice level for clients (%i)\n\n"
               "      --rttime-usec-max=USEC          Require clients to have set RLIMIT_RTTIME\n"
               "                                      not greater than this (%llu)\n\n"
               "      --users-max=INT                 How many users this daemon will serve at\n"
               "                                      max at the same time (%u)\n"
               "      --processes-per-user-max=INT    How many processes this daemon will serve\n"
               "                                      at max per user at the same time (%u)\n"
               "      --threads-per-user-max=INT      How many threads this daemon will serve\n"
               "                                      at max per user at the same time (%u)\n\n"
               "      --actions-burst-sec=SEC         Enforce requests limits in this time (%u)\n"
               "      --actions-per-burst-max=INT     Allow this many requests per burst (%u)\n\n"
               "      --canary-cheep-msec=MSEC        Canary cheep interval (%u)\n"
               "      --canary-watchdog-msec=MSEC     Watchdog action delay (%u)\n"
               "      --canary-demote-unknown         When the canary dies demote unknown\n"
               "                                      processes too?\n"
               "      --canary-demote-root            When the canary dies demote root\n"
               "                                      processes too?\n"
               "      --canary-refuse-sec=SEC         How long to refuse further requests\n"
               "                                      after the canary died (%u)\n\n"
               "      --no-canary                     Don't run a canary-based RT watchdog\n\n"
               "      --no-drop-privileges            Don't drop privileges\n"
               "      --no-chroot                     Don't chroot\n"
               "      --no-limit-resources            Don't limit daemon's resources\n",
               exe,
               username,
               sp_names[sched_policy],
               sched_get_priority_min(sched_policy), sched_get_priority_max(sched_policy), our_realtime_priority,
               PRIO_MIN, PRIO_MAX-1, our_nice_level,
               sched_get_priority_min(sched_policy), sched_get_priority_max(sched_policy), max_realtime_priority,
               PRIO_MIN, PRIO_MAX-1, min_nice_level,
               rttime_usec_max,
               users_max,
               processes_per_user_max,
               threads_per_user_max,
               actions_burst_sec,
               actions_per_burst_max,
               canary_cheep_msec,
               canary_watchdog_msec,
               canary_refusal_sec);
}

static int parse_command_line(int argc, char *argv[], int *ret) {

        int c;

        while ((c = getopt_long(argc, argv, "h", long_options, NULL)) >= 0) {

                switch (c) {
                        case 'h':
                        case ARG_HELP:
                                show_help(get_file_name(argv[0]));
                                *ret = 0;
                                return 0;

                        case ARG_VERSION:
                                printf("%s " PACKAGE_VERSION "\n", get_file_name(argv[0]));
                                *ret = 0;
                                return 0;

                        case ARG_USER_NAME:
                                username = optarg;
                                break;

                        case ARG_SCHEDULING_POLICY:  {
                                if (strcasecmp(optarg, "rr") == 0)
                                        sched_policy = SCHED_RR;
                                else if (strcasecmp(optarg, "fifo") == 0)
                                        sched_policy = SCHED_FIFO;
                                else {
                                        fprintf(stderr, "--scheduling-policy parameter invalid.\n");
                                        return -1;
                                }

                                break;
                        }

                        case ARG_OUR_REALTIME_PRIORITY: {
                                char *e = NULL;
                                unsigned long u;

                                errno = 0;
                                u = strtoul(optarg, &e, 0);
                                if (errno != 0 || !e || *e || u < (unsigned) sched_get_priority_min(sched_policy) || u > (unsigned) sched_get_priority_max(sched_policy)) {
                                        fprintf(stderr, "--our-realtime-priority parameter invalid.\n");
                                        return -1;
                                }
                                our_realtime_priority = u;
                                break;
                        }

                        case ARG_OUR_NICE_LEVEL: {
                                char *e = NULL;
                                long i;

                                errno = 0;
                                i = strtol(optarg, &e, 0);
                                if (errno != 0 || !e || *e || i < PRIO_MIN || i > PRIO_MAX*2) {
                                        fprintf(stderr, "--our-nice-level parameter invalid.\n");
                                        return -1;
                                }
                                our_nice_level = i;
                                break;
                        }

                        case ARG_MAX_REALTIME_PRIORITY: {
                                char *e = NULL;
                                unsigned long u;

                                errno = 0;
                                u = strtoul(optarg, &e, 0);
                                if (errno != 0 || !e || *e || u < (unsigned) sched_get_priority_min(sched_policy) || u > (unsigned) sched_get_priority_max(sched_policy)) {
                                        fprintf(stderr, "--max-realtime-priority parameter invalid.\n");
                                        return -1;
                                }
                                max_realtime_priority = u;
                                break;
                        }

                        case ARG_MIN_NICE_LEVEL: {
                                char *e = NULL;
                                long i;

                                errno = 0;
                                i = strtol(optarg, &e, 0);
                                if (errno != 0 || !e || *e || i < PRIO_MIN || i >= PRIO_MAX) {
                                        fprintf(stderr, "--min-nice-level parameter invalid.\n");
                                        return -1;
                                }
                                min_nice_level = i;
                                break;
                        }

                        case ARG_RTTIME_USEC_MAX: {
                                char *e = NULL;

                                errno = 0;
                                rttime_usec_max = strtoull(optarg, &e, 0);
                                if (errno != 0 || !e || *e || rttime_usec_max <= 0) {
                                        fprintf(stderr, "--rttime-usec-max parameter invalid.\n");
                                        return -1;
                                }
                                break;
                        }

                        case ARG_USERS_MAX: {
                                char *e = NULL;
                                unsigned long u;

                                errno = 0;
                                u = strtoul(optarg, &e, 0);
                                if (errno != 0 || !e || *e || u <= 0) {
                                        fprintf(stderr, "--users-max parameter invalid.\n");
                                        return -1;
                                }
                                users_max = u;
                                break;
                        }

                        case ARG_PROCESSES_PER_USER_MAX: {
                                char *e = NULL;
                                unsigned long u;

                                errno = 0;
                                u = strtoul(optarg, &e, 0);
                                if (errno != 0 || !e || *e || u <= 0) {
                                        fprintf(stderr, "--processes-per-user-max parameter invalid.\n");
                                        return -1;
                                }
                                processes_per_user_max = u;
                                break;
                        }

                        case ARG_THREADS_PER_USER_MAX: {
                                char *e = NULL;
                                unsigned long u;

                                errno = 0;
                                u = strtoul(optarg, &e, 0);
                                if (errno != 0 || !e || *e || u <= 0) {
                                        fprintf(stderr, "--threads-per-user-max parameter invalid.\n");
                                        return -1;
                                }
                                threads_per_user_max = u;
                                break;
                        }

                        case ARG_ACTIONS_BURST_SEC: {
                                char *e = NULL;
                                unsigned long u;

                                errno = 0;
                                u = strtoul(optarg, &e, 0);
                                if (errno != 0 || !e || *e || u <= 0) {
                                        fprintf(stderr, "--actions-burst-sec parameter invalid.\n");
                                        return -1;
                                }
                                actions_burst_sec = u;
                                break;
                        }

                        case ARG_ACTIONS_PER_BURST_MAX: {
                                char *e = NULL;
                                unsigned long u;

                                errno = 0;
                                u = strtoul(optarg, &e, 0);
                                if (errno != 0 || !e || *e || u <= 0) {
                                        fprintf(stderr, "--actions-per-burst-max parameter invalid.\n");
                                        return -1;
                                }
                                actions_per_burst_max = u;
                                break;
                        }

                        case ARG_NO_DROP_PRIVILEGES:
                                do_drop_privileges = FALSE;
                                break;

                        case ARG_NO_CHROOT:
                                do_chroot = FALSE;
                                break;

                        case ARG_NO_LIMIT_RESOURCES:
                                do_limit_resources = FALSE;
                                break;

                        case ARG_NO_CANARY:
                                do_canary = FALSE;
                                break;

                        case ARG_CANARY_WATCHDOG_MSEC: {
                                char *e = NULL;
                                unsigned long u;

                                errno = 0;
                                u = strtoul(optarg, &e, 0);
                                if (errno != 0 || !e || *e || u <= 0) {
                                        fprintf(stderr, "--canary-watchdog-msec parameter invalid.\n");
                                        return -1;
                                }
                                canary_watchdog_msec = u;
                                break;
                        }

                        case ARG_CANARY_CHEEP_MSEC: {
                                char *e = NULL;
                                unsigned long u;

                                errno = 0;
                                u = strtoul(optarg, &e, 0);
                                if (errno != 0 || !e || *e || u <= 0) {
                                        fprintf(stderr, "--canary-cheep-msec parameter invalid.\n");
                                        return -1;
                                }
                                canary_cheep_msec = u;
                                break;
                        }

                        case ARG_CANARY_DEMOTE_ROOT:
                                canary_demote_root = TRUE;
                                break;

                        case ARG_CANARY_DEMOTE_UNKNOWN:
                                canary_demote_unknown = TRUE;
                                break;

                        case ARG_CANARY_REFUSE_SEC: {
                                char *e = NULL;
                                unsigned long u;

                                errno = 0;
                                u = strtoul(optarg, &e, 0);
                                if (errno != 0 || !e || *e) {
                                        fprintf(stderr, "--canary-refuse-sec parameter invalid.\n");
                                        return -1;
                                }
                                canary_refusal_sec = (uint32_t) u;
                                break;
                        }

                        case ARG_STDERR:
                                log_stderr = TRUE;
                                break;

                        case ARG_INTROSPECT:
                                fputs(INTROSPECT_XML, stdout);
                                *ret = 0;
                                return 0;

                        case '?':
                        default:
                                fprintf(stderr, "Unknown command.\n");
                                return -1;
                }
        }

        if (optind < argc) {
                fprintf(stderr, "Too many arguments.\n");
                return -1;
        }

        if (max_realtime_priority >= our_realtime_priority) {
                fprintf(stderr, "The maximum realtime priority (%u) handed out to clients cannot be higher then our own (%u).\n",
                        max_realtime_priority,
                        our_realtime_priority);
                return -1;
        }

        if (canary_cheep_msec >= canary_watchdog_msec) {
                fprintf(stderr, "The canary watchdog interval must be larger than the cheep interval.\n");
                return -1;
        }

        assert(our_realtime_priority >= (unsigned) sched_get_priority_min(sched_policy));
        assert(our_realtime_priority <= (unsigned) sched_get_priority_max(sched_policy));

        assert(max_realtime_priority >= (unsigned) sched_get_priority_min(sched_policy));
        assert(max_realtime_priority <= (unsigned) sched_get_priority_max(sched_policy));

        assert(canary_watchdog_realtime_priority >= (unsigned) sched_get_priority_min(sched_policy));
        assert(canary_watchdog_realtime_priority <= (unsigned) sched_get_priority_max(sched_policy));

        assert(our_nice_level >= PRIO_MIN);
        assert(our_nice_level < PRIO_MAX);

        assert(min_nice_level >= PRIO_MIN);
        assert(min_nice_level < PRIO_MAX);

        return 1;
}

int main(int argc, char *argv[]) {
        DBusConnection *bus = NULL;
        int ret = 1;
        struct rtkit_user *u;
        unsigned long slack_ns;

        if (parse_command_line(argc, argv, &ret) <= 0)
                goto finish;

        if (getuid() != 0) {
                fprintf(stderr, "Need to be run as root.\n");
                goto finish;
        }

        openlog(get_file_name(argv[0]),
                LOG_NDELAY|LOG_PID|(log_stderr ? LOG_PERROR : 0),
                LOG_DAEMON);

        /* Raise our timer slack, we don't really need to be woken up
         * on time. */
        slack_ns = (((unsigned long) canary_watchdog_msec - (unsigned long) canary_cheep_msec) / 2UL) * 1000000UL;
        if (prctl(PR_SET_TIMERSLACK, slack_ns) < 0)
                syslog(LOG_WARNING, "PRT_SET_TIMERSLACK failed: %s\n", strerror(errno));

        self_drop_realtime(our_nice_level);

        if (setup_dbus(&bus) < 0)
                goto finish;

        if (drop_privileges() < 0)
                goto finish;

        if (set_resource_limits() < 0)
                goto finish;

        if (start_canary() < 0)
                goto finish;

        umask(0777);

        syslog(LOG_DEBUG, "Running.\n");

        sd_notify(0, "STATUS=Running.");

        dbus_connection_set_exit_on_disconnect(bus, FALSE);

        while (dbus_connection_read_write_dispatch(bus, -1))
                ;

        ret = 0;

        syslog(LOG_DEBUG, "Exiting cleanly.\n");

finish:

        if (bus) {
                if (dbus_connection_get_is_connected(bus))
                        dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        reset_known();

        while ((u = users)) {
                users = u->next;
                free_user(u);
        }

        stop_canary();

        dbus_shutdown();

        return ret;
}
