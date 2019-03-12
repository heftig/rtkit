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

#include <errno.h>
#include <string.h>
#include <sched.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "rtkit.h"

#ifndef SCHED_RESET_ON_FORK
#define SCHED_RESET_ON_FORK 0x40000000
#endif

#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME 15
#endif

static void print_status(const char *t) {
        int ret;

        if ((ret = sched_getscheduler(0)) < 0) {
                fprintf(stderr, "sched_getscheduler() failed: %s\n", strerror(errno));
                return;
        }

        printf("%s:\n"
               "\tSCHED_RESET_ON_FORK: %s\n",
               t,
               (ret & SCHED_RESET_ON_FORK) ? "yes" : "no");

        if ((ret & ~SCHED_RESET_ON_FORK) == SCHED_RR) {
                struct sched_param param;

                if (sched_getparam(0, &param) < 0) {
                        fprintf(stderr, "sched_getschedparam() failed: %s\n", strerror(errno));
                        return;
                }

                printf("\tSCHED_RR with priority %i\n", param.sched_priority);

        } else if ((ret & ~SCHED_RESET_ON_FORK) == SCHED_OTHER) {
                errno = 0;
                ret = getpriority(PRIO_PROCESS, 0);
                if (errno != 0) {
                        fprintf(stderr, "getpriority() failed: %s\n", strerror(errno));
                        return;
                }

                printf("\tSCHED_OTHER with nice level: %i\n", ret);

        } else
                fprintf(stderr, "Neither SCHED_RR nor SCHED_OTHER.\n");
}

int main(int argc, char *argv[]) {
        DBusError error;
        DBusConnection *bus;
        int r, max_realtime_priority, min_nice_level;
        long long rttime_usec_max;
        struct rlimit rlim;

        dbus_error_init(&error);

        if (!(bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error))) {
                fprintf(stderr, "Failed to connect to system bus: %s\n", error.message);
                return 1;
        }

        if ((max_realtime_priority = rtkit_get_max_realtime_priority(bus)) < 0)
                fprintf(stderr, "Failed to retrieve max realtime priority: %s\n", strerror(-max_realtime_priority));
        else
                printf("Max realtime priority is: %d\n", max_realtime_priority);

        if ((r = rtkit_get_min_nice_level(bus, &min_nice_level)))
                fprintf(stderr, "Failed to retrieve min nice level: %s\n", strerror(-r));
        else
                printf("Min nice level is: %d\n", min_nice_level);

        if ((rttime_usec_max = rtkit_get_rttime_usec_max(bus)) < 0)
                fprintf(stderr, "Failed to retrieve rttime limit: %s\n", strerror(-rttime_usec_max));
        else
                printf("Rttime limit is: %lld ns\n", rttime_usec_max);

        memset(&rlim, 0, sizeof(rlim));
        rlim.rlim_cur = rlim.rlim_max = 100000ULL; /* 100ms */
        if ((setrlimit(RLIMIT_RTTIME, &rlim) < 0))
                fprintf(stderr, "Failed to set RLIMIT_RTTIME: %s\n", strerror(errno));

        print_status("before");

        if ((r = rtkit_make_high_priority(bus, 0, -10)) < 0)
                fprintf(stderr, "Failed to become high priority: %s\n", strerror(-r));
        else
                printf("Successfully became high priority.\n");

        print_status("after high priority");

        if ((r = rtkit_make_realtime(bus, 0, 10)) < 0)
                fprintf(stderr, "Failed to become realtime: %s\n", strerror(-r));
        else
                printf("Successfully became realtime.\n");

        print_status("after realtime");

        dbus_connection_unref(bus);

        return 0;
}
