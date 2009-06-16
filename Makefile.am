# This file is part of RealtimeKit.
#
# Copyright 2009 Lennart Poettering
#
# RealtimeKit is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# RealtimeKit is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with RealtimeKit. If not, see <http://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I m4

policykitdir = $(datadir)/polkit-1/actions/
dbussystemdir = $(sysconfdir)/dbus-1/system.d/
dbusservicedir = $(datadir)/dbus-1/system-services/

EXTRA_DIST = \
	README \
	GPL \
	LICENSE \
	org.freedesktop.RealtimeKit1.policy \
	org.freedesktop.RealtimeKit1.conf \
	org.freedesktop.RealtimeKit1.service.in

CLEANFILES = \
	org.freedesktop.RealtimeKit1.service

libexec_PROGRAMS = \
	rtkit-daemon
sbin_PROGRAMS = \
	rtkitctl
noinst_PROGRAMS = \
	rtkit-test
policykit_DATA = \
	org.freedesktop.RealtimeKit1.policy
dbussystem_DATA = \
	org.freedesktop.RealtimeKit1.conf
dbusservice_DATA = \
	org.freedesktop.RealtimeKit1.service

rtkit_daemon_SOURCES = \
	rtkit-daemon.c rtkit.h
rtkit_daemon_LDADD = \
	$(DBUS_LIBS)
rtkit_daemon_CFLAGS = \
	$(DBUS_CFLAGS)

rtkitctl_SOURCES = \
	rtkitctl.c rtkit.h
rtkitctl_LDADD = \
	$(DBUS_LIBS)
rtkitctl_CFLAGS = \
	$(DBUS_CFLAGS)

rtkit_test_SOURCES = \
	rtkit-test.c rtkit.c rtkit.h
rtkit_test_LDADD = \
	$(DBUS_LIBS)
rtkit_test_CFLAGS = \
	$(DBUS_CFLAGS)

org.freedesktop.RealtimeKit1.service: org.freedesktop.RealtimeKit1.service.in
	sed -e 's,@LIBEXECDIR\@,$(libexecdir),g' < $< > $@
