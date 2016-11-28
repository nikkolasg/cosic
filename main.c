/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *        Version:  1.0
 *        Created:  11/25/2016 02:16:32 PM
 *       Revision:  none
 *       Compiler:  clang
 *
 *         Author:  nikkolasg (), nikkolasg@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "utils.h"
#include "net.h"
#include "ed25519.h"

const char * banner = "cosic - Collective Signing protocol in C";

void usage() {
    printf("%s\n\n",banner);
    printf("WARNING: This software is purely experimental and has not been audited in\n"
           "any professional way. Moreover, it only provides a small subset of the CoSi"
           "protocol for the moment, merely for language compatibility testing."
           "USE AT YOUR OWN RISK.\n\n");
    printf("./cosic <address> <private file>\n"
           " - port is the port you want cosic to bind on for incoming connections. It"
           "   binds on the \"0.0.0.0:port\" address.\n"
           " - private file is the path of the file which contains your private ed25519\n"
           "   key.\n");
}

int main(int argc, char *argv[]) {
    if (argc != 3) { 
        usage();
        fail;
    }
    int port;

    pout("%s",banner);
    
    port = atoi(argv[1]);
    if (port <= 0  || port > 65535) {
        pfail("port given \"%d\" not valid.",port);
    } 

    // read private key
    // XXX move that into ed25519 file
    uint8_t *private[ED25519_PRIVATE_SIZE] = {0};
    char *filename = argv[2];
    if (!read_file(filename, private, ED25519_PRIVATE_SIZE)) {
        pfail("could not read properly private key.",NULL);
    }
    material mat;
    mat.pk = (uint8_t*)private;
    mat.len = ED25519_PRIVATE_SIZE;

    // XXX Change to print public key of course
    print_hexa("[+] private key: ",private,ED25519_PRIVATE_SIZE);

    run(port,(void *)&mat);

}
