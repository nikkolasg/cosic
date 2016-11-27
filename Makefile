CC=clang
CFLAGS=-Wall

all: main.c net.c utils.c ed25519.c cosi.c
	$(CC) $(CFLAGS) main.c net.c utils.c ed25519.c cosi.c -o cosic
