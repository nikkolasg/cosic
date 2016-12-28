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
#include "cosi.h"

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

void read_key_material(const char * filename,material *mat) {
    if (!read_file(filename, mat->sk, ED25519_PRIVATE_SIZE)) {
        pfail("could not read properly private key.",NULL);
    }
    ed25519_mulbase(mat->pk,mat->sk);

    // XXX it's a PoC so I really WANT to print the private ;)
    print_hexa("[+] private key: ",mat->sk,ED25519_PRIVATE_SIZE);
    print_hexa("[+] public key: ",mat->pk,ED25519_PUBLIC_SIZE);

}

/*
 * init_platforms will create all platforms to give to the network layer.
 * XXX This PoC only has one platform, namely cosi, but later it might be useful.
 */
void init_platforms(net_platform_list *list, const material * mat) {
    list->platforms = cosi_platform_new(mat); 
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

    // read key material
    uint8_t private[ED25519_PRIVATE_SIZE] = {0};
    uint8_t public[ED25519_PUBLIC_SIZE] = {0};
    char *filename = argv[2];
    material mat;
    mat.sk = (uint8_t*)private;
    mat.pk = (uint8_t*)public;

    read_key_material(filename,&mat);
    
    // init all platforms == processors
    net_platform_list l;
    init_platforms(&l,&mat); 
    // run the machine !
    run(port,(void *)&mat);
}

