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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <getopt.h>
#include <stdio.h>

#include "rtkit.h"

static char* get_file_name(const char *p) {
        char *e;

        if ((e = strrchr(p, '/')))
                return e + 1;
        else
                return (char*) p;
}

static void show_help(const char *exe) {

        printf("%s [options]\n\n"
               "  -h, --help         Show this help\n"
               "      --version      Show version\n\n"
               "      --reset-known  Reset real-time status of known threads\n"
               "      --reset-all    Reset real-time status of all threads\n"
               "      --start        Start RealtimeKit if it is not running already\n"
               "  -k, --exit         Terminate running RealtimeKit daemon\n",
               exe);
}

int main (int argc, char*argv[]) {
        enum {
                ARG_HELP = 256,
                ARG_VERSION,
                ARG_START,
                ARG_EXIT,
                ARG_RESET_KNOWN,
                ARG_RESET_ALL,
        };

        static const struct option long_options[] = {
                { "help",        no_argument, 0, ARG_HELP },
                { "version",     no_argument, 0, ARG_VERSION },
                { "start",       no_argument, 0, ARG_START },
                { "exit",        no_argument, 0, ARG_EXIT },
                { "reset-known", no_argument, 0, ARG_RESET_KNOWN },
                { "reset-all",   no_argument, 0, ARG_RESET_ALL },
                { NULL, 0, 0, 0}
        };

        enum {
                OPERATION_START,
                OPERATION_EXIT,
                OPERATION_RESET_KNOWN,
                OPERATION_RESET_ALL,
                _OPERATION_MAX
        };

        static const char *method[_OPERATION_MAX] = {
                [OPERATION_START] = "StartServiceByName",
                [OPERATION_EXIT] = "Exit",
                [OPERATION_RESET_KNOWN] = "ResetKnown",
                [OPERATION_RESET_ALL] = "ResetAll"
        };

        DBusError error;
        DBusConnection *bus = NULL;
        int operation = -1;
        int ret = 1;
        DBusMessage *m = NULL, *r = NULL;
        int c;

        dbus_error_init(&error);

        while ((c = getopt_long(argc, argv, "hk", long_options, NULL)) >= 0) {

                switch (c) {
                        case 'h':
                        case ARG_HELP:
                                show_help(get_file_name(argv[0]));
                                ret = 0;
                                goto finish;

                        case ARG_VERSION:
                                printf("%s " PACKAGE_VERSION "\n", get_file_name(argv[0]));
                                ret = 0;
                                goto finish;

                        case ARG_START:
                                operation = OPERATION_START;
                                break;

                        case 'k':
                        case ARG_EXIT:
                                operation = OPERATION_EXIT;
                                break;

                        case ARG_RESET_KNOWN:
                                operation = OPERATION_RESET_KNOWN;
                                break;

                        case ARG_RESET_ALL:
                                operation = OPERATION_RESET_ALL;
                                break;

                        case '?':
                        default:
                                fprintf(stderr, "Unknown command.\n");
                                goto finish;
                }
        }

        if (optind < argc) {
                fprintf(stderr, "Too many arguments.\n");
                goto finish;
        }

        if (operation < 0) {
                fprintf(stderr, "Need to specify operation.\n");
                goto finish;
        }

        if (!(bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error))) {
                fprintf(stderr, "Failed to connect to system bus: %s\n", error.message);
                goto finish;
        }

        if (operation == OPERATION_START) {
                const char *service = RTKIT_SERVICE_NAME;
                dbus_uint32_t flags = 0;

                if (!(m = dbus_message_new_method_call(
                                      DBUS_SERVICE_DBUS,
                                      DBUS_PATH_DBUS,
                                      DBUS_INTERFACE_DBUS,
                                      method[operation]))) {
                        fprintf(stderr, "Failed to allocated message.\n");
                        goto finish;
                }

                if (!(dbus_message_append_args(
                                      m,
                                      DBUS_TYPE_STRING, &service,
                                      DBUS_TYPE_UINT32, &flags,
                                      DBUS_TYPE_INVALID))) {
                        fprintf(stderr, "Failed to append to message.\n");
                        goto finish;
                }
        } else {
                if (!(m = dbus_message_new_method_call(
                                      RTKIT_SERVICE_NAME,
                                      RTKIT_OBJECT_PATH,
                                      "org.freedesktop.RealtimeKit1",
                                      method[operation]))) {
                        fprintf(stderr, "Failed to allocated message.\n");
                        goto finish;
                }
        }

        if (!(r = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                fprintf(stderr, "Failed to send %s request: %s\n", method[operation], error.message);
                goto finish;
        }


        if (dbus_set_error_from_message(&error, r)) {
                fprintf(stderr, "%s request failed: %s\n", method[operation], error.message);
                goto finish;
        }

        ret = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (r)
                dbus_message_unref(r);

        if (bus)
                dbus_connection_unref(bus);

        return ret;
}
