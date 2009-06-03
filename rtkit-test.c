/*-*- Mode: C; c-basic-offset: 8 -*-*/

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
    int r;

    dbus_error_init(&error);

    if (!(bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error))) {
        fprintf(stderr, "Failed to connect to system bus: %s\n", error.message);
        return 1;
    }

    print_status("before");

    if ((r = rtkit_make_high_priority(bus, 0, -10)) < 0)
        fprintf(stderr, "Failed to become high priority: %s\n", strerror(-r));
    else
        printf("Sucessfully became high priority.\n");

    print_status("after high priority");

    if ((r = rtkit_make_realtime(bus, 0, 10)) < 0)
        fprintf(stderr, "Failed to become realtime: %s\n", strerror(-r));
    else
        printf("Sucessfully became realtime.\n");

    print_status("after realtime");

    dbus_connection_unref(bus);

    return 0;
}
