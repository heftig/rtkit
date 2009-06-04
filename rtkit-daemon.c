/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of RealtimeKit.

  Copyright 2009 Lennart Poettering

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

#define _GNU_SOURCE

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

#include "rtkit.h"

#ifndef __linux__
#error "This stuff only works on Linux!"
#endif

#ifndef SCHED_RESET_ON_FORK
#warning "Your libc lacks the definition of SCHED_RESET_ON_FORK. We'll now define it ourselves, however make sure your kernel is new enough!"
#define SCHED_RESET_ON_FORK 0x40000000
#endif

#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME 15
#endif

#define INTROSPECT_XML                                                  \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>"                                                        \
        " <interface name=\"org.freedesktop.RealtimeKit1\">"            \
        "  <method name=\"MakeThreadRealtime\">"                        \
        "   <arg name=\"thread\" type=\"t\" direction=\"in\"/>"         \
        "   <arg name=\"priority\" type=\"u\" direction=\"in\"/>"       \
        "  </method>"                                                   \
        "  <method name=\"MakeHighPriority\">"                          \
        "   <arg name=\"thread\" type=\"t\" direction=\"in\"/>"         \
        "   <arg name=\"priority\" type=\"i\" direction=\"in\"/>"       \
        "  </method>"                                                   \
        "  <method name=\"ResetAll\"/>"                                 \
        "  <method name=\"Exit\"/>"                                     \
        " </interface>"                                                 \
        " <interface name=\"org.freedesktop.DBus.Introspectable\">"     \
        "  <method name=\"Introspect\">"                                \
        "   <arg name=\"data\" type=\"s\" direction=\"out\"/>"          \
        "  </method>"                                                   \
        " </interface>"                                                 \
        "</node>"

/* Similar to assert(), but has side effects, and hence shall never be optimized away, regardless of NDEBUG */
#define assert_se(expr)                                                 \
        do {                                                            \
                if (__builtin_expect(!(expr), 0)) {                     \
                        fprintf(stderr, "Asssertion %s failed at %s:%u, function %s(). Aborting.\n", #expr, __FILE__, __LINE__, __PRETTY_FUNCTION__); \
                        abort();                                        \
                }                                                       \
        } while(0)

#define ELEMENTSOF(x) (sizeof(x)/sizeof(x[0]))

/* If we actually execute a request we temporarily upgrade our realtime priority to this level */
static unsigned our_realtime_priority = 30;

/* Normally we run at this nice level */
static int our_nice_level = 1;

/* The maximum realtime priority to hand out */
static unsigned max_realtime_priority = 29;

/* The minimum nice level to hand out */
static int min_nice_level = -15;

/* Username we shall run under */
static const char *username = "rtkit";

/* Enforce that clients have RLIMIT_RTTIME set to a value <= this */
static unsigned long long rttime_ns_max = 200000000ULL; /* 200 ms */

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

/* Drop priviliges */
static bool do_drop_priviliges = TRUE;

/* Change root directory to /proc */
static bool do_chroot = TRUE;

/* Limit resources */
static bool do_limit_resources = TRUE;

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

struct user {
        uid_t uid;

        time_t timestamp;
        unsigned n_actions;

        struct process *processes;
        unsigned n_processes;
        unsigned n_threads;

        struct user *next;
};

static struct user *users = NULL;
static unsigned n_users = 0;
static unsigned n_total_processes = 0;
static unsigned n_total_threads = 0;
static const char *proc = NULL;

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
        char fn[128];
        int r;
        FILE *f;

        if (tid != 0)
                assert_se(snprintf(fn, sizeof(fn)-1, "%s/%llu/task/%llu/stat", get_proc_path(), (unsigned long long) pid, (unsigned long long) tid) < (int) (sizeof(fn)-1));
        else
                assert_se(snprintf(fn, sizeof(fn)-1, "%s/%llu/stat", get_proc_path(), (unsigned long long) pid) < (int) (sizeof(fn)-1));
        fn[sizeof(fn)-1] = 0;

        if (!(f = fopen(fn, "r"))) {
                r = -errno;
                return r;
        }

        if (fscanf(f,
                   "%*d "  /* pid */
                   "%*s "  /* comm */
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
                   st) != 1) {
                fclose(f);
                return -EIO;
        }

        fclose(f);
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

static void free_user(struct user *u) {
        struct process *p;

        while ((p = u->processes)) {
                u->processes = p->next;
                free_process(p);
        }

        free(u);
}

static bool user_in_burst(struct user *u) {
        time_t now = time(NULL);

        return now < u->timestamp + actions_burst_sec;
}

static bool verify_burst(struct user *u) {

        if (!user_in_burst(u)) {
                /* Restart burst phase */
                time(&u->timestamp);
                u->n_actions = 0;
                return true;
        }

        if (u->n_actions >= actions_per_burst_max) {
                char user[64];
                fprintf(stderr, "Warning: Reached burst limit for user '%s', denying request.\n", get_user_name(u->uid, user, sizeof(user)));
                return false;
        }

        u->n_actions++;
        return true;
}

static int find_user(struct user **_u, uid_t uid) {
        struct user *u;

        for (u = users; u; u = u->next)
                if (u->uid == uid) {
                        *_u = u;
                        return 0;
                }

        if (n_users >= users_max)  {
                fprintf(stderr, "Warning: Reached maximum concurrent user limit, denying request.\n");
                return -EBUSY;
        }

        if (!(u = malloc(sizeof(struct user))))
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

static int find_process(struct process** _p, struct user *u, pid_t pid, unsigned long long starttime) {
        struct process *p;

        for (p = u->processes; p; p = p->next)
                if (p->pid == pid && p->starttime == starttime) {
                        *_p = p;
                        return 0;
                }

        if (u->n_processes >= processes_per_user_max) {
                char user[64];
                fprintf(stderr, "Warning: Reached maximum concurrent process limit for user '%s', denying request.\n", get_user_name(u->uid, user, sizeof(user)));
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

static int find_thread(struct thread** _t, struct user *u, struct process *p, pid_t pid, unsigned long long starttime) {
        struct thread *t;

        for (t = p->threads; t; t = t->next)
                if (t->pid == pid && t->starttime == starttime)  {
                        *_t = t;
                        return 0;
                }

        if (u->n_threads >= threads_per_user_max) {
                char user[64];
                fprintf(stderr, "Warning: Reached maximum concurrent threads limit for user '%s', denying request.\n", get_user_name(u->uid, user, sizeof(user)));
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

                fprintf(stderr, "Warning: failed to read start time: %s\n", strerror(-r));
                return FALSE;
        }

        /* Did the thread get replaced by another thread? */
        if (st != t->starttime)
                return FALSE;

        if ((r = sched_getscheduler(t->pid)) < 0) {

                /* Maybe it died right now? */
                if (errno == ESRCH)
                        return FALSE;

                fprintf(stderr, "Warning: failed to read scheduler policy: %s\n", strerror(errno));
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

                fprintf(stderr, "Warning: failed to read nice level: %s\n", strerror(errno));
                return FALSE;
        }

        /* Is this a high priority thread? */
        if (r < 0)
                return TRUE;

        return FALSE;
}

static void thread_gc(struct user *u, struct process *p) {
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

static void process_gc(struct user *u) {
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
        struct user *u, *n, *l;

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

static int self_set_realtime(void) {
        struct sched_param param;
        int r;

        memset(&param, 0, sizeof(param));
        param.sched_priority = our_realtime_priority;

        if (sched_setscheduler(0, SCHED_RR|SCHED_RESET_ON_FORK, &param) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to make ourselves SCHED_RR: %s\n", strerror(errno));
                goto finish;
        }

        r = 0;

finish:
        return r;
}

static void self_drop_realtime(void) {
        struct sched_param param;

        memset(&param, 0, sizeof(param));

        if (sched_setscheduler(0, SCHED_OTHER, &param) < 0)
                fprintf(stderr, "Warning: Failed to reset scheduling to SCHED_OTHER: %s\n", strerror(errno));

        if (setpriority(PRIO_PROCESS, 0, our_nice_level) < 0)
                fprintf(stderr, "Warning: Failed to reset nice level to %u: %s\n", our_nice_level, strerror(errno));
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
                fprintf(stderr, "Failed to open '%s': %s\n", fn, strerror(errno));
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
                        fprintf(stderr, "Warning: parse failure in %s.\n", fn);
                        break;
                }

                errno = 0;
                rttime = strtoll(hard, &e, 10);

                if (errno != 0 || !e || *e != 0)
                        break;

                if (rttime <= rttime_ns_max)
                        good = true;

                break;
        }

        fclose(f);

        return good ? 0 : -EPERM;
}

static int verify_process_user(struct user *u, struct process *p) {
        char fn[128];
        int r;
        struct stat st;

        assert_se(snprintf(fn, sizeof(fn)-1, "%s/%llu", get_proc_path(), (unsigned long long) p->pid) < (int) (sizeof(fn)-1));
        fn[sizeof(fn)-1] = 0;

        memset(&st, 0, sizeof(st));
        if (stat(fn, &st) < 0) {
                r = -errno;

                if (r != -ENOENT)
                        fprintf(stderr, "Warning: Failed to stat() file '%s': %s\n", fn, strerror(-r));

                return r;
        }

        return st.st_uid == u->uid ? 0 : -EPERM;
}

static int verify_process_starttime(struct process *p) {
        unsigned long long st;
        int r;

        if ((r = read_starttime(p->pid, 0, &st)) < 0) {

                if (r != -ENOENT)
                        fprintf(stderr, "Warning: Failed to read start time of process %llu: %s\n", (unsigned long long) p->pid, strerror(-r));

                return r;
        }

        return st == p->starttime ? 0 : -EPERM;
}

static int verify_thread_starttime(struct process *p, struct thread *t) {
        unsigned long long st;
        int r;

        if ((r = read_starttime(p->pid, t->pid, &st)) < 0) {

                if (r != -ENOENT)
                        fprintf(stderr, "Warning: Failed to read start time of thread %llu: %s\n", (unsigned long long) t->pid, strerror(-r));

                return r;
        }

        return st == t->starttime ? 0 : -EPERM;
}

static void thread_reset(struct thread *t) {
        struct sched_param param;

        memset(&param, 0, sizeof(param));
        param.sched_priority = 0;

        if (sched_setscheduler(t->pid, SCHED_OTHER, &param) < 0)
                if (errno != ESRCH)
                        fprintf(stderr, "Warning: Failed to reset scheduling to SCHED_OTHER for thread %llu: %s\n", (unsigned long long) t->pid, strerror(errno));

        if (setpriority(PRIO_PROCESS, t->pid, 0) < 0)
                if (errno != ESRCH)
                        fprintf(stderr, "Warning: Failed to reset nice level to 0 for thread %llu: %s\n", (unsigned long long) t->pid, strerror(errno));
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

static int process_set_realtime(struct user *u, struct process *p, struct thread *t, unsigned priority) {
        int r;
        struct sched_param param;
        char user[64], exe[128];

        if ((int) priority < sched_get_priority_min(SCHED_RR) ||
            (int) priority > sched_get_priority_max(SCHED_RR))
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
         * client's code which might have gotten SCHED_RR through
         * us. */
        if ((r = self_set_realtime()) < 0)
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
        if (sched_setscheduler(t->pid, SCHED_RR|SCHED_RESET_ON_FORK, &param) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to make thread %llu SCHED_RR: %s\n", (unsigned long long) t->pid, strerror(errno));
                goto finish;
        }

        /* We do some sanity checks afterwards, to verify that the
         * caller didn't play games with us and replaced the process
         * behind the PID */
        if ((r = verify_thread_starttime(p, t)) < 0 ||
            (r = verify_process_rttime(p)) < 0 ||
            (r = verify_process_starttime(p)) < 0 ||
            (r = verify_process_user(u, p)) < 0) {

                thread_reset(t);
                goto finish;
        }

        fprintf(stderr, "Sucessfully made thread %llu of process %llu (%s) owned by '%s' SCHED_RR at priority %u.\n",
                (unsigned long long) t->pid,
                (unsigned long long) p->pid,
                get_exe_name(p->pid, exe, sizeof(exe)),
                get_user_name(u->uid, user, sizeof(user)),
                priority);

        r = 0;

finish:
        self_drop_realtime();

        return r;
}

static int process_set_high_priority(struct user *u, struct process *p, struct thread *t, int priority) {
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
        if ((r = self_set_realtime()) < 0)
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
                fprintf(stderr, "Failed to make process %llu SCHED_NORMAL: %s\n", (unsigned long long) t->pid, strerror(errno));
                goto finish;
        }

        if (setpriority(PRIO_PROCESS, t->pid, priority) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to set nice level of process %llu to %i: %s\n", (unsigned long long) t->pid, priority, strerror(errno));
                goto finish;
        }

        if ((r = verify_thread_starttime(p, t)) < 0 ||
            (r = verify_process_starttime(p)) < 0 ||
            (r = verify_process_user(u, p)) < 0) {

                thread_reset(t);
                goto finish;
        }

        fprintf(stderr, "Sucessfully made thread %llu of process %llu (%s) owned by '%s' high priority at nice level %i.\n",
                (unsigned long long) t->pid,
                (unsigned long long) p->pid,
                get_exe_name(p->pid, exe, sizeof(exe)),
                get_user_name(u->uid, user, sizeof(user)),
                priority);

        r = 0;

finish:
        self_drop_realtime();

        return r;
}

static void reset_all(void) {
        struct user *u;
        struct process *p;
        struct thread *t;

        for (u = users; u; u = u->next)
                for (p = u->processes; p; p = p->next)
                        for (t = p->threads; t; t = t->next)
                                if (verify_process_user(u, p) >= 0 &&
                                    verify_process_starttime(p) >= 0 &&
                                    verify_thread_starttime(p, t) >= 0)
                                        thread_reset(t);
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
                struct user **_u,
                struct process **_p,
                struct thread **_t,
                DBusConnection *c,
                DBusMessage *m,
                pid_t tid) {

        DBusError error;
        int r;
        unsigned long pid, uid;
        unsigned long long starttime;
        struct user *u;
        struct process *p;
        struct thread *t;

        dbus_error_init(&error);

        /* Determine caller credentials */
        if ((uid = dbus_bus_get_unix_user(c, dbus_message_get_sender(m), &error)) == (unsigned long) -1) {
                fprintf(stderr, "dbus_message_get_unix_user() failed: %s\n", error.message);
                r = -EIO;
                goto fail;
        }

        if ((pid = get_unix_process_id(c, dbus_message_get_sender(m), &error)) == (unsigned long) -1) {
                fprintf(stderr, "get_unix_process_id() failed: %s\n", error.message);
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

static const char *translate_error(int error) {
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

static DBusHandlerResult dbus_handler(DBusConnection *c, DBusMessage *m, void *userdata) {
        DBusError error;
        DBusMessage *r = NULL;

        dbus_error_init(&error);

        /* We garbage collect on every user call */
        user_gc();

        if (dbus_message_is_method_call(m, "org.freedesktop.RealtimeKit1", "MakeThreadRealtime")) {

                uint64_t thread;
                uint32_t priority;
                struct user *u;
                struct process *p;
                struct thread *t;
                int ret;

                if (!dbus_message_get_args(m, &error,
                                           DBUS_TYPE_UINT64, &thread,
                                           DBUS_TYPE_UINT32, &priority,
                                           DBUS_TYPE_INVALID)) {

                        fprintf(stderr, "Failed to parse MakeThreadRealtime() method call: %s\n", error.message);
                        assert_se(r = dbus_message_new_error(m, error.name, error.message));

                        goto finish;
                }

                if ((ret = lookup_client(&u, &p, &t, c, m, (pid_t) thread)) < 0) {
                        assert_se(r = dbus_message_new_error_printf(m, translate_error(ret), strerror(-ret)));
                        goto finish;
                }

                if ((ret = process_set_realtime(u, p, t, priority))) {
                        assert_se(r = dbus_message_new_error_printf(m, translate_error(ret), strerror(-ret)));
                        goto finish;
                }

                assert_se(r = dbus_message_new_method_return(m));

        } else if (dbus_message_is_method_call(m, "org.freedesktop.RealtimeKit1", "MakeThreadHighPriority")) {

                uint64_t thread;
                int32_t priority;
                struct user *u;
                struct process *p;
                struct thread *t;
                int ret;

                if (!dbus_message_get_args(m, &error,
                                           DBUS_TYPE_UINT64, &thread,
                                           DBUS_TYPE_INT32, &priority,
                                           DBUS_TYPE_INVALID)) {

                        fprintf(stderr, "Failed to parse MakeThreadHighPriority() method call: %s\n", error.message);
                        assert_se(r = dbus_message_new_error(m, error.name, error.message));

                        goto finish;
                }

                if ((ret = lookup_client(&u, &p, &t, c, m, (pid_t) thread)) < 0) {
                        assert_se(r = dbus_message_new_error_printf(m, translate_error(ret), strerror(-ret)));
                        goto finish;
                }

                if ((ret = process_set_high_priority(u, p, t, priority))) {
                        assert_se(r = dbus_message_new_error_printf(m, translate_error(ret), strerror(-ret)));
                        goto finish;
                }

                assert_se(r = dbus_message_new_method_return(m));

        } else if (dbus_message_is_method_call(m, "org.freedesktop.RealtimeKit1", "ResetAll")) {

                reset_all();
                user_gc();
                assert_se(r = dbus_message_new_method_return(m));

        } else if (dbus_message_is_method_call(m, "org.freedesktop.RealtimeKit1", "Exit")) {

                assert_se(r = dbus_message_new_method_return(m));
                assert_se(dbus_connection_send(c, r, NULL));
                dbus_message_unref(r);
                r = NULL;

                dbus_connection_close(c);

        } else if (dbus_message_is_method_call(m, "org.freedesktop.DBus.Introspectable", "Introspect")) {
                const char *xml = INTROSPECT_XML;

                assert_se(r = dbus_message_new_method_return(m));
                assert_se(dbus_message_append_args(
                                          r,
                                          DBUS_TYPE_STRING, &xml,
                                          DBUS_TYPE_INVALID));
        } else
                return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

        fprintf(stderr, "Supervising %u threads of %u processes of %u users.\n",
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
                fprintf(stderr, "Failed to connect to system bus: %s\n", error.message);
                goto fail;
        }

        if (dbus_bus_request_name(*c, RTKIT_SERVICE_NAME, DBUS_NAME_FLAG_DO_NOT_QUEUE, &error) < 0) {
                fprintf(stderr, "Failed to register name on bus: %s\n", error.message);
                goto fail;
        }

        assert_se(dbus_connection_register_object_path(*c, RTKIT_OBJECT_PATH, &vtable, NULL));

        return 0;

fail:
        dbus_error_free(&error);
        return -EIO;
}

static int drop_priviliges(void) {
        struct passwd *pw = NULL;
        int r;

        if (do_drop_priviliges) {

                /* First, get user data */
                if (!(pw = getpwnam(username))) {
                        fprintf(stderr, "Failed to find user '%s'.\n", username);
                        return -ENOENT;
                }
        }

        if (do_chroot) {

                /* Second, chroot() */
                if (chroot("/proc") < 0 ||
                    chdir("/") < 0) {
                        r = -errno;
                        fprintf(stderr, "Failed to chroot() to /proc: %s\n", strerror(errno));
                        return r;
                }
                proc = "/";

                fprintf(stderr, "Sucessfully called chroot.\n");
        }

        if (do_drop_priviliges) {
                cap_t caps;
                const cap_value_t cap_values[] = {
                        CAP_SYS_NICE,             /* Needed for obvious reasons */
                        CAP_DAC_READ_SEARCH,      /* Needed so that we can verify resource limits */
                        CAP_SYS_PTRACE            /* Needed so that we can read /proc/$$/exe. Linux is weird. */
                };

                /* Third, say that we want to keep caps */
                if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
                        r = -errno;
                        fprintf(stderr, "PR_SET_KEEPCAPS failed: %s\n", strerror(errno));
                        return r;
                }

                /* Fourth, drop privs */
                if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) < 0 ||
                    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) < 0) {
                        r = -errno;
                        fprintf(stderr, "Failed to become %s: %s\n", username, strerror(errno));
                        return r;
                }

                /* Fifth, reset caps flag */
                if (prctl(PR_SET_KEEPCAPS, 0) < 0) {
                        r = -errno;
                        fprintf(stderr, "PR_SET_KEEPCAPS failed: %s\n", strerror(errno));
                        return r;
                }

                /* Sixth, reduce caps */
                assert_se(caps = cap_init());
                assert_se(cap_clear(caps) == 0);
                assert_se(cap_set_flag(caps, CAP_EFFECTIVE, ELEMENTSOF(cap_values), cap_values, CAP_SET) == 0);
                assert_se(cap_set_flag(caps, CAP_PERMITTED, ELEMENTSOF(cap_values), cap_values, CAP_SET) == 0);

                if (cap_set_proc(caps) < 0) {
                        r = -errno;
                        fprintf(stderr, "cap_set_proc() failed: %s\n", strerror(errno));
                        return r;
                }

                assert_se(cap_free(caps) == 0);

                /* Seventh, update environment */
                setenv("USER", username, 1);
                setenv("USERNAME", username, 1);
                setenv("LOGNAME", username, 1);
                setenv("HOME", get_proc_path(), 1);

                fprintf(stderr, "Sucessfully dropped priviliges.\n");
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
                { .id = RLIMIT_NPROC,    .name = "RLIMIT_NPROC",    .value =  1 },
                { .id = RLIMIT_RTPRIO,   .name = "RLIMIT_RTPRIO",   .value =  0 }, /* Since we have CAP_SYS_NICE we don't need this */
                { .id = RLIMIT_RTTIME,   .name = "RLIMIT_RTTIME",   .value =  0 }
        };

        unsigned u;
        int r;

        assert(table[7].id == RLIMIT_RTTIME);
        table[7].value = rttime_ns_max; /* Do as I say AND do as I do */

        if (!do_limit_resources)
                return 0;

        for (u = 0; u < ELEMENTSOF(table); u++) {
                struct rlimit rlim;

                if (getrlimit(table[u].id, &rlim) < 0) {
                        r = -errno;
                        fprintf(stderr, "Failed to get %s: %s\n", table[u].name, strerror(errno));
                        return r;
                }

                if (rlim.rlim_max < table[u].value)
                        continue;

                rlim.rlim_cur = rlim.rlim_max = table[u].value;

                if (setrlimit(table[u].id, &rlim) < 0) {
                        r = -errno;
                        fprintf(stderr, "Failed to set %s: %s\n", table[u].name, strerror(errno));
                        return r;
                }
        }

        fprintf(stderr, "Sucessfully limited resources.\n");

        return 0;
}

enum {
        ARG_HELP = 256,
        ARG_VERSION,
        ARG_OUR_REALTIME_PRIORITY,
        ARG_OUR_NICE_LEVEL,
        ARG_MAX_REALTIME_PRIORITY,
        ARG_MIN_NICE_LEVEL,
        ARG_USER_NAME,
        ARG_RTTIME_NS_MAX,
        ARG_USERS_MAX,
        ARG_PROCESSES_PER_USER_MAX,
        ARG_THREADS_PER_USER_MAX,
        ARG_ACTIONS_BURST_SEC,
        ARG_ACTIONS_PER_BURST_MAX,
        ARG_NO_DROP_PRIVILIGES,
        ARG_NO_CHROOT,
        ARG_NO_LIMIT_RESOURCES,
};

/* Table for getopt_long() */
static const struct option long_options[] = {
    { "help",                        no_argument,       0, ARG_HELP },
    { "version",                     no_argument,       0, ARG_VERSION},
    { "our-realtime-priority",       required_argument, 0, ARG_OUR_REALTIME_PRIORITY },
    { "our-nice-level",              required_argument, 0, ARG_OUR_NICE_LEVEL },
    { "max-realtime-priority",       required_argument, 0, ARG_MAX_REALTIME_PRIORITY },
    { "min-nice-level",              required_argument, 0, ARG_MIN_NICE_LEVEL },
    { "user-name",                   required_argument, 0, ARG_USER_NAME },
    { "rttime-ns-max",               required_argument, 0, ARG_RTTIME_NS_MAX },
    { "users-max",                   required_argument, 0, ARG_USERS_MAX },
    { "processes-per-user-max",      required_argument, 0, ARG_PROCESSES_PER_USER_MAX },
    { "threads-per-user-max",        required_argument, 0, ARG_THREADS_PER_USER_MAX },
    { "actions-burst-sec",           required_argument, 0, ARG_ACTIONS_BURST_SEC },
    { "actions-per-burst-max",       required_argument, 0, ARG_ACTIONS_PER_BURST_MAX },
    { "no-drop-priviliges",          no_argument,       0, ARG_NO_DROP_PRIVILIGES },
    { "no-chroot",                   no_argument,       0, ARG_NO_CHROOT },
    { "no-limit-resources",          no_argument,       0, ARG_NO_LIMIT_RESOURCES },
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

        printf("%s [options]\n\n"
               "COMMANDS:\n"
               "  -h, --help                          Show this help\n"
               "      --version                       Show version\n\n"
               "OPTIONS:\n"
               "      --our-realtime-priority=[%i..%i] Realtime priority for the daemon (%u)\n"
               "      --our-nice-level=[%i..%i]      Nice level for the daemon (%i)\n"
               "      --max-realtime-priority=[%i..%i] Max realtime priority for clients (%u)\n"
               "      --min-nice-level=[%i..%i]      Min nice level for clients (%i)\n"
               "      --user-name=USER                Run daemon as user (%s)\n"
               "      --rttime-ns-max=NSEC            Require clients to have set RLIMIT_RTTIME\n"
               "                                      not greater than this (%llu)\n"
               "      --users-max=INT                 How many users this daemon will serve at\n"
               "                                      max at the same time (%u)\n"
               "      --processes-per-user-max=INT    How many processes this daemon will serve\n"
               "                                      at max per user at the same time (%u)\n"
               "      --threads-per-user-max=INT      How many threads this daemon will serve\n"
               "                                      at max per user at the same time (%u)\n"
               "      --actions-burst-sec=SEC         Enforce requests limits in this time (%u)\n"
               "      --actions-per-burst-max=INT     Allow this many requests per burst (%u)\n"
               "      --no-drop-priviliges            Don't drop priviliges\n"
               "      --no-chroot                     Don't chroot\n"
               "      --no-limit-resources            Don't limit daemon's resources\n",
               exe,
               sched_get_priority_min(SCHED_RR), sched_get_priority_max(SCHED_RR), our_realtime_priority,
               PRIO_MIN, PRIO_MAX-1, our_nice_level,
               sched_get_priority_min(SCHED_RR), sched_get_priority_max(SCHED_RR), max_realtime_priority,
               PRIO_MIN, PRIO_MAX-1, min_nice_level,
               username,
               rttime_ns_max,
               users_max,
               processes_per_user_max,
               threads_per_user_max,
               actions_burst_sec,
               actions_per_burst_max);
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
                                printf("%s 0.1\n", get_file_name(argv[0]));
                                *ret = 0;
                                return 0;

                        case ARG_USER_NAME:
                                username = optarg;
                                break;

                        case ARG_OUR_REALTIME_PRIORITY: {
                                char *e = NULL;
                                unsigned long u;

                                errno = 0;
                                u = strtoul(optarg, &e, 0);
                                if (errno != 0 || !e || *e || u < (unsigned) sched_get_priority_min(SCHED_RR) || u > (unsigned) sched_get_priority_max(SCHED_RR)) {
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
                                if (errno != 0 || !e || *e || u < (unsigned) sched_get_priority_min(SCHED_RR) || u > (unsigned) sched_get_priority_max(SCHED_RR)) {
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

                        case ARG_RTTIME_NS_MAX: {
                                char *e = NULL;

                                errno = 0;
                                rttime_ns_max = strtoull(optarg, &e, 0);
                                if (errno != 0 || !e || *e || rttime_ns_max <= 0) {
                                        fprintf(stderr, "--rttime-ns-max parameter invalid.\n");
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

                        case ARG_NO_DROP_PRIVILIGES:
                                do_drop_priviliges = FALSE;
                                break;

                        case ARG_NO_CHROOT:
                                do_chroot = FALSE;
                                break;

                        case ARG_NO_LIMIT_RESOURCES:
                                do_limit_resources = FALSE;
                                break;

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

        return 1;
}

int main(int argc, char *argv[]) {
        DBusConnection *bus = NULL;
        int ret = 1;
        struct user *u;

        if (parse_command_line(argc, argv, &ret) <= 0)
                goto finish;

        if (getuid() != 0) {
                fprintf(stderr, "Need to be run as root.\n");
                goto finish;
        }

        self_drop_realtime();

        if (setup_dbus(&bus) < 0)
                goto finish;

        if (drop_priviliges() < 0)
                goto finish;

        if (set_resource_limits() < 0)
                goto finish;

        umask(0777);

        fprintf(stderr, "Running.\n");

        dbus_connection_set_exit_on_disconnect(bus, FALSE);

        while (dbus_connection_read_write_dispatch(bus, -1))
                ;

        ret = 0;

        fprintf(stderr, "Exiting cleanly.\n");

finish:

        if (bus) {
                if (dbus_connection_get_is_connected(bus))
                        dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        reset_all();

        while ((u = users)) {
                users = u->next;
                free_user(u);
        }

        dbus_shutdown();

        return ret;
}
