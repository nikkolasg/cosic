CC=clang
CFLAGS=-Wall

all: main.c net.c utils.c ed25519.c
	$(CC) $(CFLAGS) main.c net.c utils.c ed25519.c -o cosic
