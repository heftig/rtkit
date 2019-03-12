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

AM_CFLAGS = $(WARNINGFLAGS) $(PTHREAD_CFLAGS)
AM_LDFLAGS = $(GCLDFLAGS)

ACLOCAL_AMFLAGS = -I m4

policykitdir = $(datadir)/polkit-1/actions/
dbussystemdir = $(datadir)/dbus-1/system.d/
dbusservicedir = $(datadir)/dbus-1/system-services/
dbusinterfacedir = $(datadir)/dbus-1/interfaces/
installedtestsdir = $(libexecdir)/installed-tests/rtkit/

EXTRA_DIST = \
	README \
	GPL \
	LICENSE \
	org.freedesktop.RealtimeKit1.policy \
	org.freedesktop.RealtimeKit1.conf \
	org.freedesktop.RealtimeKit1.service.in \
	org.freedesktop.RealtimeKit1.xml \
	rtkit-daemon.service.in

CLEANFILES = \
	org.freedesktop.RealtimeKit1.service \
	rtkit-daemon.service

libexec_PROGRAMS = \
	rtkit-daemon
sbin_PROGRAMS = \
	rtkitctl
installedtests_PROGRAMS = \
	rtkit-test
policykit_DATA = \
	org.freedesktop.RealtimeKit1.policy
dbussystem_DATA = \
	org.freedesktop.RealtimeKit1.conf
dbusservice_DATA = \
	org.freedesktop.RealtimeKit1.service
dbusinterface_DATA = \
	org.freedesktop.RealtimeKit1.xml

if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	rtkit-daemon.service
endif

rtkit_daemon_SOURCES = \
	rtkit-daemon.c \
	rtkit.h \
	xml-introspection.c
rtkit_daemon_LDADD = \
	$(DBUS_LIBS) \
	$(LIBSYSTEMD_LIBS)
rtkit_daemon_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(LIBSYSTEMD_CFLAGS)

rtkitctl_SOURCES = \
	rtkitctl.c rtkit.h
rtkitctl_LDADD = \
	$(DBUS_LIBS)
rtkitctl_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

rtkit_test_SOURCES = \
	rtkit-test.c rtkit.c rtkit.h
rtkit_test_LDADD = \
	$(DBUS_LIBS)
rtkit_test_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

org.freedesktop.RealtimeKit1.service: org.freedesktop.RealtimeKit1.service.in
	$(AM_V_GEN)$(SED) -e 's,@LIBEXECDIR\@,$(libexecdir),g' < $< > $@

rtkit-daemon.service: rtkit-daemon.service.in
	$(AM_V_GEN)$(SED) -e 's,@LIBEXECDIR\@,$(libexecdir),g' < $< > $@

xml-introspection.c: org.freedesktop.RealtimeKit1.xml
	@echo 'const char introspect_xml[] = {' > $@
	$(AM_V_GEN)$(XXD) -i < $< >> $@
	@echo '};' >> $@

man8_MANS = rtkitctl.8

EXTRA_DIST += \
	$(man8_MANS)

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)
