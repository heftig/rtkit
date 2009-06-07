CFLAGS=-Wextra -Wall -O0 -g `pkg-config --cflags dbus-1` -pthread
LIBS= `pkg-config --libs dbus-1` -lrt

all: rtkit-daemon rtkit-test rtkitctl

rtkit-daemon: rtkit-daemon.o rtkit.h
	$(CC) $(CFLAGS) $(LIBS) -o rtkit-daemon $^

rtkit-test: rtkit-test.o rtkit.o rtkit.h
	$(CC) $(CFLAGS) $(LIBS) -o rtkit-test $^

rtkitctl: rtkitctl.o rtkit.h
	$(CC) $(CFLAGS) $(LIBS) -o rtkitctl $^

clean:
	rm -rf rtkit-daemon rtkit-test rtkitctl *.o
