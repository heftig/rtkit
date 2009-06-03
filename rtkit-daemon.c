/*-*- Mode: C; c-basic-offset: 8 -*-*/

#define _GNU_SOURCE

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

#define OUR_RR_PRIORITY 30
#define OUR_NICE_LEVEL 1

#define USERNAME "rtkit"

#define RTKIT_RTTIME_MAX_NS 200000000ULL /* 200 ms */

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

struct process {
        pid_t pid;
        uid_t uid;
        unsigned long long starttime;
};

static int startswith(const char *s, const char *prefix) {
        return strncmp(s, prefix, strlen(prefix)) == 0;
}

static int self_set_realtime(void) {
        struct sched_param param;
        int r;

        memset(&param, 0, sizeof(param));
        param.sched_priority = OUR_RR_PRIORITY;

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

        if (setpriority(PRIO_PROCESS, 0, OUR_NICE_LEVEL) < 0)
                fprintf(stderr, "Warning: Failed to reset nice level to %u: %s\n", OUR_NICE_LEVEL, strerror(errno));
}

static int verify_rttime(struct process *p) {
        char fn[128];
        FILE *f;
        int r, good = 0;

        /* Verifies that RLIMIT_RTTIME is set for the specified process */

        assert_se(snprintf(fn, sizeof(fn)-1, "/proc/%llu/limits", (unsigned long long) p->pid) < (int) (sizeof(fn)-1));
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

                if (sscanf(line + 20, "%s %s", soft, hard) != 2)
                        break;

                errno = 0;
                rttime = strtoll(hard, &e, 10);

                if (errno != 0 || !e || *e != 0)
                        break;

                if (rttime <= RTKIT_RTTIME_MAX_NS)
                        good = 1;

                break;
        }

        fclose(f);

        return good ? 0 : -EPERM;
}

static int verify_user(struct process *p) {
        char fn[128];
        int r;
        struct stat st;

        assert_se(snprintf(fn, sizeof(fn)-1, "/proc/%llu", (unsigned long long) p->pid) < (int) (sizeof(fn)-1));
        fn[sizeof(fn)-1] = 0;

        memset(&st, 0, sizeof(st));
        if (stat(fn, &st) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to stat() file '%s': %s\n", fn, strerror(errno));
                return r;
        }

        return st.st_uid == p->uid ? 0 : -EPERM;
}

static int read_starttime(pid_t pid, unsigned long long *st) {
        char fn[128];
        int r;
        FILE *f;

        assert_se(snprintf(fn, sizeof(fn)-1, "/proc/%llu/stat", (unsigned long long) pid) < (int) (sizeof(fn)-1));
        fn[sizeof(fn)-1] = 0;

        if (!(f = fopen(fn, "r"))) {
                r = -errno;
                fprintf(stderr, "Failed to open '%s': %s\n", fn, strerror(errno));
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

static int verify_starttime(struct process *p) {
        unsigned long long st;
        int r;

        if ((r = read_starttime(p->pid, &st)) < 0)
                return r;

        return st == p->starttime ? 0 : -EPERM;
}

static int verify_thread(struct process *p, pid_t thread) {
        char fn[128];

        /* Verifies that the specified thread exists in the specified
         * process */

        assert_se(snprintf(fn, sizeof(fn)-1, "/proc/%llu/task/%llu", (unsigned long long) p->pid, (unsigned long long) thread) < (int) (sizeof(fn)-1));
        fn[sizeof(fn)-1] = 0;

        return access(fn, F_OK) == 0 ? 0 : -errno;
}

static void thread_reset(pid_t thread) {
        struct sched_param param;

        memset(&param, 0, sizeof(param));
        param.sched_priority = 0;

        if (sched_setscheduler(thread, SCHED_OTHER, &param) < 0)
                fprintf(stderr, "Warning: Failed to reset scheduling to SCHED_OTHER for thread %llu: %s\n", (unsigned long long) thread, strerror(errno));

        if (setpriority(PRIO_PROCESS, thread, 0) < 0)
                fprintf(stderr, "Warning: Failed to reset nice level to 0 for thread %llu: %s\n", (unsigned long long) thread, strerror(errno));
}

static char* get_exe_name(pid_t pid, char *exe, size_t len) {
        char fn[128];
        ssize_t n;

        assert_se(snprintf(fn, sizeof(fn)-1, "/proc/%llu/exe", (unsigned long long) pid) < (int) (sizeof(fn)-1));
        fn[sizeof(fn)-1] = 0;

        if ((n = readlink(fn, exe, len-1)) < 0) {
                snprintf(exe, len-1, "n/a");
                exe[len-1] = 0;
        } else
                exe[n] = 0;

        return exe;
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

static int process_set_realtime(struct process *p, pid_t thread, unsigned priority) {
        int r;
        struct sched_param param;
        char user[64], exe[128];

        if (thread < 0)
                return -EINVAL;

        if ((int) priority < sched_get_priority_min(SCHED_RR) ||
            (int) priority > sched_get_priority_max(SCHED_RR))
                return -EINVAL;

        if (priority >= OUR_RR_PRIORITY)
                return -EPERM;

        if (thread == 0)
                thread = p->pid;

        /* Temporarily become a realtime process. We do this to make
         * sure that our verification code is not preempted by an evil
         * client's code which might have gotten SCHED_RR through
         * us. */
        if ((r = self_set_realtime()) < 0)
                return r;

        /* Let's make sure that everything is alright before we make
         * the process realtime */
        if ((r = verify_user(p)) < 0 ||
            (r = verify_starttime(p)) < 0 ||
            (r = verify_rttime(p)) < 0 ||
            (r = verify_thread(p, thread)) < 0)
                goto finish;

        /* Ok, everything seems to be in order, now, let's do it */
        memset(&param, 0, sizeof(param));
        param.sched_priority = (int) priority;
        if (sched_setscheduler(thread, SCHED_RR|SCHED_RESET_ON_FORK, &param) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to make thread %llu SCHED_RR: %s\n", (unsigned long long) thread, strerror(errno));
                goto finish;
        }

        /* We do some sanity checks afterwards, to verify that the
         * caller didn't play games with us and replaced the process
         * behind the PID */
        if ((r = verify_thread(p, thread)) < 0 ||
            (r = verify_rttime(p)) < 0 ||
            (r = verify_starttime(p)) < 0 ||
            (r = verify_user(p)) < 0) {

                thread_reset(thread);
                goto finish;
        }

        fprintf(stderr, "Sucessfully made thread %llu of process %llu (%s) owned by '%s' SCHED_RR at priority %u.\n",
                (unsigned long long) thread,
                (unsigned long long) p->pid,
                get_exe_name(p->pid, exe, sizeof(exe)),
                get_user_name(p->uid, user, sizeof(user)),
                priority);

        r = 0;

finish:
        self_drop_realtime();

        return r;
}

static int process_set_high_priority(struct process *p, pid_t thread, int priority) {
        int r;
        struct sched_param param;
        char user[64], exe[128];

        if (thread < 0)
                return -EINVAL;

        if (priority < -20 || priority > 19)
                return -EINVAL;

        if (thread == 0)
                thread = p->pid;

        /* Temporarily become a realtime process */
        if ((r = self_set_realtime()) < 0)
                return r;

        /* Let's make sure that everything is alright before we make
         * the process high priority */
        if ((r = verify_user(p)) < 0 ||
            (r = verify_starttime(p)) < 0 ||
            (r = verify_thread(p, thread)) < 0)
                goto finish;

        /* Ok, everything seems to be in order, now, let's do it */
        memset(&param, 0, sizeof(param));
        param.sched_priority = 0;
        if (sched_setscheduler(thread, SCHED_OTHER|SCHED_RESET_ON_FORK, &param) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to make process %llu SCHED_NORMAL: %s\n", (unsigned long long) thread, strerror(errno));
                goto finish;
        }

        if (setpriority(PRIO_PROCESS, thread, priority) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to set nice level of process %llu to %i: %s\n", (unsigned long long) thread, priority, strerror(errno));
                goto finish;
        }

        if ((r = verify_thread(p, thread)) < 0 ||
            (r = verify_starttime(p)) < 0 ||
            (r = verify_user(p)) < 0) {

                thread_reset(thread);
                goto finish;
        }

        fprintf(stderr, "Sucessfully made thread %llu of process %llu (%s) owned by '%s' high priority at nice level %i.\n",
                (unsigned long long) thread,
                (unsigned long long) p->pid,
                get_exe_name(p->pid, exe, sizeof(exe)),
                get_user_name(p->uid, user, sizeof(user)),
                priority);

        r = 0;

finish:
        self_drop_realtime();

        return r;
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

static int process_fill(struct process *p, DBusConnection *c, DBusMessage *m) {
        DBusError error;
        int r;
        unsigned long pid, uid;

        dbus_error_init(&error);

        if ((uid = dbus_bus_get_unix_user(c, dbus_message_get_sender(m), &error)) == (unsigned long) -1) {
                fprintf(stderr, "dbus_message_get_unix_user() failed: %s\n", error.message);
                r = -EIO;
                goto fail;
        }

        p->uid = (uid_t) uid;

        if ((pid = get_unix_process_id(c, dbus_message_get_sender(m), &error)) == (unsigned long) -1) {
                fprintf(stderr, "get_unix_process_id() failed: %s\n", error.message);
                r = -EIO;
                goto fail;
        }

        p->pid = (uid_t) pid;

        if ((r = read_starttime(p->pid, &p->starttime)) < 0)
                goto fail;

        return 0;

fail:
        dbus_error_free(&error);

        return r;
}

static DBusHandlerResult dbus_handler(DBusConnection *c, DBusMessage *m, void *userdata) {
        DBusError error;
        DBusMessage *r = NULL;

        dbus_error_init(&error);

        if (dbus_message_is_method_call(m, "org.freedesktop.RealtimeKit1", "MakeThreadRealtime")) {

                uint64_t thread;
                uint32_t priority;
                struct process p;
                int ret;

                if (!dbus_message_get_args(m, &error,
                                           DBUS_TYPE_UINT64, &thread,
                                           DBUS_TYPE_UINT32, &priority,
                                           DBUS_TYPE_INVALID)) {

                        fprintf(stderr, "Failed to parse MakeThreadRealtime() method call: %s\n", error.message);
                        assert_se(r = dbus_message_new_error(m, error.name, error.message));

                        goto finish;
                }

                if ((ret = process_fill(&p, c, m)) < 0) {
                        assert_se(r = dbus_message_new_error_printf(m, DBUS_ERROR_FAILED, strerror(-ret)));
                        goto finish;
                }

                if ((ret = process_set_realtime(&p, (pid_t) thread, priority))) {
                        assert_se(r = dbus_message_new_error_printf(m, DBUS_ERROR_FAILED, strerror(-ret)));
                        goto finish;
                }

                assert_se(r = dbus_message_new_method_return(m));

        } else if (dbus_message_is_method_call(m, "org.freedesktop.RealtimeKit1", "MakeThreadHighPriority")) {

                uint64_t thread;
                int32_t priority;
                struct process p;
                int ret;

                if (!dbus_message_get_args(m, &error,
                                           DBUS_TYPE_UINT64, &thread,
                                           DBUS_TYPE_INT32, &priority,
                                           DBUS_TYPE_INVALID)) {

                        fprintf(stderr, "Failed to parse MakeThreadHighPriority() method call: %s\n", error.message);
                        assert_se(r = dbus_message_new_error(m, error.name, error.message));

                        goto finish;
                }

                if ((ret = process_fill(&p, c, m)) < 0) {
                        assert_se(r = dbus_message_new_error_printf(m, DBUS_ERROR_FAILED, strerror(-ret)));
                        goto finish;
                }

                if ((ret = process_set_high_priority(&p, (pid_t) thread, priority))) {
                        assert_se(r = dbus_message_new_error_printf(m, DBUS_ERROR_FAILED, strerror(-ret)));
                        goto finish;
                }

                assert_se(r = dbus_message_new_method_return(m));

        } else if (dbus_message_is_method_call(m, "org.freedesktop.DBus.Introspectable", "Introspect")) {
                const char *xml = INTROSPECT_XML;

                assert_se(r = dbus_message_new_method_return(m));
                assert_se(dbus_message_append_args(
                                          r,
                                          DBUS_TYPE_STRING, &xml,
                                          DBUS_TYPE_INVALID));
        } else
                return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

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

        if (!(*c = dbus_bus_get(DBUS_BUS_SYSTEM, &error))) {
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
        struct passwd *pw;
        int r;
        cap_t caps;
        const cap_value_t cap_values[] = {
                CAP_SYS_NICE,             /* Needed for obvious reasons */
                CAP_DAC_READ_SEARCH,      /* Needed so that we can verify resource limits */
                CAP_SYS_PTRACE            /* Needed so that we can read /proc/$$/exe. Linux is weird. */
        };

        if (!(pw = getpwnam(USERNAME))) {
                fprintf(stderr, "Failed to find user '%s'.\n", USERNAME);
                return -ENOENT;
        }

        /* First, say that we want to keep caps */
        if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
                r = -errno;
                fprintf(stderr, "PR_SET_KEEPCAPS failed: %s\n", strerror(errno));
                return r;
        }

        /* Second, drop privs */
        if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) < 0 ||
            setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to become %s: %s\n", USERNAME, strerror(errno));
                return r;
        }

        /* Third, reset caps flag */
        if (prctl(PR_SET_KEEPCAPS, 0) < 0) {
                r = -errno;
                fprintf(stderr, "PR_SET_KEEPCAPS failed: %s\n", strerror(errno));
                return r;
        }

        /* Fourth, reduce caps */
        assert_se(caps = cap_init());
        assert_se(cap_clear(caps) == 0);
        assert_se(cap_set_flag(caps, CAP_EFFECTIVE, ELEMENTSOF(cap_values), cap_values, CAP_SET) == 0);
        assert_se(cap_set_flag(caps, CAP_PERMITTED, ELEMENTSOF(cap_values), cap_values, CAP_SET) == 0);

        if (cap_set_proc(caps) < 0) {
                r = -errno;
                fprintf(stderr, "cap_set_proc() failed: %s\n", strerror(errno));
                return r;
        }

        /* Fifth, update environment */
        setenv("USER", USERNAME, 1);
        setenv("USERNAME", USERNAME, 1);
        setenv("LOGNAME", USERNAME, 1);
        setenv("HOME", pw->pw_dir, 1);

        fprintf(stderr, "Sucessfully dropped priviliges.\n");

        return 0;
}

static int set_resource_limits(void) {

        static const struct {
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
                { .id = RLIMIT_RTTIME,   .name = "RLIMIT_RTTIME",   .value = RTKIT_RTTIME_MAX_NS } /* Do as I say AND do as I do */
        };

        unsigned u;
        int r;

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

        return 0;
}

int main(int argc, char *argv[]) {
        DBusConnection *bus = NULL;
        int ret = 1;

        self_drop_realtime();

        if (drop_priviliges() < 0)
                goto finish;

        if (set_resource_limits() < 0)
                goto finish;

        assert_se(chdir("/") == 0);
        umask(0777);

        if (setup_dbus(&bus) < 0)
                goto finish;

        fprintf(stderr, "Running.\n");

        while (dbus_connection_read_write_dispatch(bus, -1))
                ;

        ret = 0;

finish:

        if (bus)
                dbus_connection_unref(bus);

        return ret;
}
