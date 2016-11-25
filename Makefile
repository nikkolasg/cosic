CC=clang
CFLAGS=-Wall

all: main.c net.c utils.c
	$(CC) $(CFLAGS) main.c net.c utils.c -o cosic
