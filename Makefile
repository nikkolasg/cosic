CC=clang
CFLAGS=-Wall -levent -levent_core -lprotobuf-c  -lcrypto


all: main.c net.c utils.c ed25519.c cosi.c uuid.c cosi.pb-c.c 
	$(CC) $(CFLAGS) main.c net.c utils.c ed25519.c cosi.c cosi.pb-c.c uuid.c -o cosic -g
