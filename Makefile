CC=clang
CFLAGS=-Wall

all: main.c net.c
	$(CC) $(CFLAGS) main.c net.c -o cosic
