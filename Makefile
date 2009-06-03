CFLAGS=-Wextra -Wall -O0 -g `pkg-config --cflags dbus-1`
LIBS= `pkg-config --libs dbus-1`

all: rtkit-daemon rtkit-test

rtkit-daemon: rtkit-daemon.o
	$(CC) $(CFLAGS) $(LIBS) -o rtkit-daemon $^

rtkit-test: rtkit-test.o rtkit.o rtkit.h
	$(CC) $(CFLAGS) $(LIBS) -o rtkit-test $^

clean:
	rm -rf rtkit-daemon *.o
