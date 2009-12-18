# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

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

AC_PREREQ(2.63)

AC_INIT([rtkit], 0.5, [mzegxvg (at) 0pointer (dot) net])
AC_CONFIG_SRCDIR([rtkit-daemon.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR(m4)

AM_INIT_AUTOMAKE([foreign 1.11 -Wno-portability silent-rules -Wall])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_SUBST(PACKAGE_URL, [http://git.0pointer.de/?p=rtkit.git])

AC_CANONICAL_HOST

if type -p stow > /dev/null && test -d /usr/local/stow ; then
   AC_MSG_NOTICE([*** Found /usr/local/stow: default install prefix set to /usr/local/stow/${PACKAGE_NAME}-${PACKAGE_VERSION} ***])
   ac_default_prefix="/usr/local/stow/${PACKAGE_NAME}-${PACKAGE_VERSION}"
fi

#### Checks for programs. ####

# CC

AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_GCC_TRADITIONAL
AC_USE_SYSTEM_EXTENSIONS

# GCC flags

test_gcc_flag() {
    AC_LANG_CONFTEST([int main(int argc, char*argv[]) {}])
    $CC -c conftest.c $CFLAGS "$1" -o conftest.o > /dev/null 2> /dev/null
    ret=$?
    rm -f conftest.o
    return $ret
}

# If using GCC specify some additional parameters
if test "x$GCC" = "xyes" ; then

    # We use gnu99 instead of c99 because many have interpreted the standard
    # in a way that int64_t isn't defined on non-64 bit platforms.
    DESIRED_FLAGS="-std=gnu99 -Wall -W -Wextra -pedantic -pipe -Wformat -Wold-style-definition -Wdeclaration-after-statement -Wfloat-equal -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls -Wmissing-noreturn -Wshadow -Wendif-labels -Wpointer-arith -Wcast-align -Wwrite-strings -Winline -Wno-unused-parameter -ffast-math"

    for flag in $DESIRED_FLAGS ; do
        AC_MSG_CHECKING([whether $CC accepts $flag])
        if test_gcc_flag $flag ; then
           CFLAGS="$CFLAGS $flag"
           CXXFLAGS="$CXXFLAGS $flag"
           AC_MSG_RESULT([yes])
        else
           AC_MSG_RESULT([no])
        fi
    done
fi

ACX_PTHREAD
LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

AC_SYS_LARGEFILE

AC_SEARCH_LIBS([sched_setscheduler], [rt])
AC_SEARCH_LIBS([clock_gettime], [rt])
AC_SEARCH_LIBS([cap_init], [cap])

PKG_CHECK_MODULES(DBUS, dbus-1)

###################################
#            Output               #
###################################

AC_CONFIG_FILES([
Makefile
])
AC_OUTPUT

echo "
 ---{ $PACKAGE_NAME $VERSION }---

    prefix:                 ${prefix}
    sysconfdir:             ${sysconfdir}
    localstatedir:          ${localstatedir}
    Compiler:               ${CC}
    CFLAGS:                 ${CFLAGS}
"
